// Cœur du démon `noortrace` (CT-2 §3) : il assemble configuration,
// signataire, bail, stockage, écrivain unique, reprise, clôture des
// périodes, fichiers des approbations et supervision, exécute la séquence de
// démarrage (EX-15.4 pas 5 à 7, EX-9.8), et offre aux frontaux (lots
// suivants) l'interface décrite dans INTERFACES.md : pièces, scellement d'un
// échange, évaluation, retenue, refus, relais en deux temps (intention
// durable avant relais, événement durable avant réponse), remises, expiration,
// rotation, clôture, export de dossier, attente du mode dégradé.

import fs from "node:fs/promises";
import path from "node:path";
import { decoderHorodatage, ecrireHorodatage, encoderBase64, sha256Hex } from "@noortrace/noyau";
import { ErreurConstruction, ErreurEnregistreur } from "./erreurs.mjs";
import { JournalExploitation } from "./journal-exploitation.mjs";
import { Metriques, servirSupervision, sante } from "./supervision.mjs";
import { EtatDegrade } from "./degrade.mjs";
import { ControleurHorloge, HORLOGE_SYSTEME } from "./horloge.mjs";
import { SignataireFichier, SignataireVerifie } from "./signataires.mjs";
import { magasinBailDepuisConfiguration, controleCleMac, taillesAnterieures, SurveillanceFourche, verifierEpoqueOuverture } from "./ha/index.mjs";
import { MagasinPieces, empreintePolitique, piecePolitique, pieceReprise, pieceAttentePerdue, Piece } from "./pieces.mjs";
import { ecrireAtomique, existe, creerRepertoire, FichierAjout, decouperLignes } from "./fichiers.mjs";
import { relireJournal, planifierReprise, partielReprise, ErreurRelecture } from "./reprise.mjs";
import { relireIntentions, ErreurIntentions, objetContexte } from "./intentions.mjs";
import { Ecrivain } from "./ecrivain.mjs";
import { partielAppelOutil, partielDecision, partielEchange, partielPolitique, repriseDeRetenue } from "./capture.mjs";
import { evaluerEffets } from "./effets.mjs";
import {
  FichiersApprobations, ErreurServiceApprobation, approvalExpiration, delaiExpiration, macRelais, validerReponseEvaluer,
  verifierRelais, verifierRemise, E_MAX_MS, ligneRemise,
} from "./approbations.mjs";
import { decisionPolitique, echeanceExpiration } from "./lui-meme.mjs";
import { exporterDossier } from "./dossier.mjs";
import { jcsIntegral, jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { validerConfiguration, resoudreSecrets, differencesHorsPolitique } from "./configuration.mjs";
import { MoteurPolitique } from "./politique/moteur.mjs";
import { verifierRepertoireJournal } from "./verification.mjs";
import { SupervisionIntegrite } from "./controles.mjs";

/** Version du logiciel (`code.recorder`, `serverInfo`). */
export const VERSION_ENREGISTREUR = "0.1.0";

const sansPrefixe = (h) => h.slice(2);

/** Envois `consommer` simultanés au plus (EX-7.20 : reprise sans rafale). */
export const CONCURRENCE_CONSOMMER = 4;

/**
 * Raisons de CT-3 §12.8 émises par le service : une erreur qui porte l'une
 * d'elles est une réponse ; toute autre (`indisponible`, réponse illisible,
 * pair non vérifié…) est une absence de réponse, réessayée (CT-3 12.7).
 */
const RAISONS_SERVICE = new Set([
  "requete_invalide", "non_pret", "politique_invalide", "politique_inconnue", "ticket_inconnu", "ticket_deja_ouvert",
  "ticket_non_ouvert", "ticket_clos_aux_votes", "jeu_non_fige", "signature_invalide", "hors_jeu", "auto_approbation",
  "recuse", "motif_trop_long", "plafond_atteint", "vote_identique", "retrait_non_autorise",
]);

export class Coeur {
  /**
   * Démarre le cœur sur une configuration validée (pas 1 à 3 faits) dont les
   * secrets sont résolus (pas 4) : pas 5 à 7 d'EX-15.4, séquence d'EX-9.8.
   * @param {object} o
   * @param {object} o.config document validé
   * @param {Map<string, Uint8Array>} o.secrets secrets résolus par pointeur
   * @param {Uint8Array} [o.octetsConfig] octets du document tel que lu (sha256 consigné)
   * @param {{murale: () => number, monotone: () => number}} [o.horloge]
   * @param {import("./signataires.mjs").Signataire} [o.signataire] backend (défaut : selon signer.backend)
   * @param {import("./bail.mjs").MagasinBail} [o.bail]
   * @param {import("./approbations.mjs").ServiceApprobation|null} [o.service]
   * @param {import("./ancrage.mjs").ComposantAncrage|null} [o.ancrage]
   * @param {import("./worm.mjs").SupportWorm|null} [o.worm]
   * @param {(periodStart: number) => string} [o.nonce]
   * @param {boolean} [o.minuteurs] tic, remises et expirations par minuteur (démon)
   * @param {boolean} [o.supervision] servir /healthz, /readyz, /metrics
   * @param {boolean} [o.attendreBail] bail détenu par une autre instance : attendre en
   *   instance passive (`lease_standby`, santé `standby`, 13.4 pas 1) au lieu de refuser le démarrage
   * @param {(coeur: Coeur) => Promise<void>|void} [o.surAttente] appelé une fois à l'entrée en
   *   instance passive (le démon y ouvre ses frontaux, qui rendent `-31010 bail_non_detenu`)
   * @param {{redigerMotif?: (motif: string|null) => string|null,
   *   executerExtract?: (motif: string, texte: string) => string|null}} [o.redaction] crochets du lot de rédaction
   * @returns {Promise<Coeur>}
   */
  static async demarrer(o) {
    if (o.attendreBail) {
      // Instance passive admise (13.4) : la promesse se résout dès que le cœur
      // est actif OU passif ; la fin du démarrage (prise du bail, pas 5 à 7)
      // continue alors en arrière-plan : `coeur.demarrage`.
      let passif;
      const enAttente = new Promise((r) => (passif = r));
      const c = new Coeur({ ...o, surAttente: async (x) => { await o.surAttente?.(x); passif(); } });
      c.demarrage = c._demarrer().catch(async (e) => {
        await c.arreter().catch(() => {});
        throw e;
      });
      c.demarrage.catch(() => {});
      await Promise.race([c.demarrage, enAttente]);
      return c;
    }
    const c = new Coeur(o);
    try {
      await c._demarrer();
    } catch (e) {
      // Démarrage refusé : rien n'écoute ; fichiers fermés, bail libéré.
      await c.arreter().catch(() => {});
      throw e;
    }
    return c;
  }

  constructor(o) {
    this.o = o;
    this.config = o.config;
    this.secrets = o.secrets ?? new Map();
    this.horlogeBrute = o.horloge ?? HORLOGE_SYSTEME;
    this.org_id = this.config.recorder.org_id;
    this.journal_id = this.config.recorder.journal_id;
    this.repertoire = path.join(this.config.storage.root, sansPrefixe(this.org_id), sansPrefixe(this.journal_id));
    this.metriques = new Metriques();
    const ops = this.config.supervision.ops_log;
    this.journal = new JournalExploitation({
      chemin: ops.path,
      niveau: ops.level,
      rotation: ops.rotate_max_bytes,
      conserver: ops.keep_files,
      org_id: this.org_id,
      journal_id: this.journal_id,
      murale: () => this.horlogeBrute.murale(),
      metriques: this.metriques,
    });
    this.degrade = new EtatDegrade(this.journal, this.metriques, () => this.horlogeBrute.murale());
    this.horloge = new ControleurHorloge(this.horlogeBrute, this.config.clock, this.degrade, this.journal);
    this.service = o.service ?? null;
    this.candidats = null;
    this.relaisEnCours = new Set();
    this.attente = [];
    this.compteurAttente = 0;
    this.minuteurs = [];
    this.bailDetenu = false;
    this.pret = false;
    this.politiquesParVersion = new Map();
    // Moteur de politique (INTERFACES.md, section d) : matrice de 14.2 pour le
    // service, modes d'attente et observation, boucle `decisions`.
    this.politique = new MoteurPolitique(this);
    // Rédaction (INTERFACES.md, section e) : journal d'exploitation et métriques du cœur.
    o.redaction?.lier?.(this);
    // WORM (INTERFACES.md, section f) : copies, registre, contrôles périodiques.
    this.passif = false;
    o.worm?.lier?.(this);
    // Contrôles périodiques d'EX-17.5 qui ne dépendent pas d'un support WORM.
    this.controles = new SupervisionIntegrite(this);
  }

  // ------------------------------------------------------------ démarrage

  async _demarrer() {
    const cfg = this.config;
    await creerRepertoire(this.repertoire);
    const journalJson = path.join(this.repertoire, "journal.json");
    if (!(await existe(journalJson))) {
      const octets = new TextEncoder().encode(
        JSON.stringify({ version: 0, org_id: this.org_id, journal_id: this.journal_id, created_at: ecrireHorodatage(this.horlogeBrute.murale()), recorder: VERSION_ENREGISTREUR }, null, 2) + "\n",
      );
      await ecrireAtomique(journalJson, octets, { jamaisReecrire: true });
    }
    this.journalJson = JSON.parse(await fs.readFile(journalJson, "utf8"));

    // Pas 5 : signataire (EX-11.8, EX-11.6), bail (13), stockage (12.4).
    const backend =
      this.o.signataire ??
      (cfg.signer.backend.type === "file"
        ? SignataireFichier.charger({
            environment: cfg.recorder.environment,
            keyId: cfg.signer.key_id,
            chemin: cfg.signer.backend.path,
            nextKeyId: cfg.signer.rotation.next_key_id,
            phrase: this.secrets.get("/signer/backend/passphrase") ?? null,
          })
        : null);
    if (!backend) throw new ErreurEnregistreur("cle", `backend ${cfg.signer.backend.type} non fourni par ce lot du démon`);
    this.signataire = new SignataireVerifie(backend, cfg.signer, { metriques: this.metriques, journal: this.journal });
    // Bail (13) : magasin `file`, `postgresql` ou `etcd` (lot de haute disponibilité).
    this.bail = this.o.bail ?? magasinBailDepuisConfiguration(cfg, this.secrets);
    this.bail.lier?.(this);
    const epoque = await this._acquerirBail();
    this.bailDetenu = true;
    this.metriques.jauge("noortrace_lease_epoch", {}, epoque);
    this.journal.consigner("info", "bail", "lease_acquired", { epoch: epoque, store: this.bail.type, fencing: cfg.lease.fencing ?? null });

    this.pieces = new MagasinPieces(this.repertoire, { minOctetsLibres: cfg.storage.min_free_bytes });
    let etat;
    try {
      // Journal reconstruit depuis les copies WORM (EX-12.17, CT-8 §11.4 chemin
      // B : segments présents, journal d'intention jamais ouvert ici) : avant
      // d'écrire, tout est relu et vérifié, segments fermés compris, avec les
      // clés de la chaîne (signatures, manifestes, séries, pièces).
      await this._verifierJournalReconstruit();
      etat = await relireJournal(this.repertoire, {
        clePublique: (id) => this.signataire.clePublique(id),
        journal: this.journal,
        intervalle: cfg.checkpoint_interval_s,
      });
    } catch (e) {
      if (!(e instanceof ErreurRelecture)) throw e;
      this.degrade.entrer("stockage", { event: e.evenement });
      this.intervention = e;
      this.passif = false;
      this.pret = true;
      await this._servirSupervision();
      return;
    }
    // EX-13.10 (3) : taille finale des fichiers d'époque inférieure, après la
    // relecture (et sa troncature éventuelle) ; toute croissance ultérieure est
    // une fourche (`journal_fork`), contrôlée au tic.
    const tailles = await taillesAnterieures(this.repertoire, epoque);
    if (tailles.length) this.journal.consigner("info", "bail", "lease_predecessor_files", { epoch: epoque, files: tailles });
    this.fourche = new SurveillanceFourche(this.repertoire, tailles, this.journal, { maintenant: () => this.horlogeBrute.monotone() });
    this.index = etat.index;
    const cleCourante = etat.cleCourante ?? cfg.signer.key_id;
    await this.signataire.clePublique(cleCourante);
    await this.signataire.signatureDeTest(cleCourante);

    this.ecrivain = new Ecrivain({
      repertoire: this.repertoire,
      org_id: this.org_id,
      journal_id: this.journal_id,
      instance_id: cfg.recorder.instance_id,
      recorder: VERSION_ENREGISTREUR,
      signataire: this.signataire,
      bail: this.bail,
      horloge: this.horloge,
      degrade: this.degrade,
      journal: this.journal,
      metriques: this.metriques,
      index: this.index,
      pieces: this.pieces,
      fsync: cfg.storage.fsync,
      segment_max_bytes: cfg.storage.segment_max_bytes,
      checkpoint_interval_s: cfg.checkpoint_interval_s,
      nonce: this.o.nonce,
      ancrage: this.o.ancrage ?? null,
      worm: this.o.worm ?? null,
      prefixeWorm: cfg.storage.seal.worm?.prefix ?? "",
    });
    await this.ecrivain.demarrer({ ...etat, cleCourante }, epoque);

    // Fichiers des approbations (EX-12.23) et clé du MAC de relais (EX-7.22).
    this.cleMac = this.secrets.get("/storage/relay_mac_key") ?? null;
    if (!this.cleMac) throw new ErreurEnregistreur("cle", "clé du MAC de relais non résolue (EX-7.22)");
    this.approbations = new FichiersApprobations(this.repertoire, epoque, this.cleMac);
    await this.approbations.relire().catch(() => {});
    const concorde = this.approbations.controleConcorde();
    if (concorde === false) this.journal.consigner("warning", "noyau", "relay_mac_key_changed", {});
    this.approbations = new FichiersApprobations(this.repertoire, epoque, this.cleMac);
    await this.approbations.ouvrir();

    // Politiques des versions annoncées (EX-15.5 : SG-4, SG-7, RL-4, EX-9.4).
    for (const [version, sha] of this.index.politiques) {
      const octets = await this.pieces.lire(sha);
      if (octets) {
        try {
          this.politiquesParVersion.set(version, analyserJsonIntegral(octets));
          continue;
        } catch {
          // pièce illisible : la version reste sans document
        }
      }
      // Sans document, SG-4, SG-7 et RL-4 échouent pour les tickets de cette version
      // et l'expiration par le noyau seul attend la borne de E (approbations.mjs).
      this.journal.consigner("warning", "politique", "policy_piece_unavailable", { policy_version: version, policy_sha256: sha });
    }

    // EX-9.8 (2) : intentions restées ouvertes.
    await this._reprendreIntentions(etat);
    if (this.intervention) {
      // EX-12.22, EX-12.13 : intention corrompue ou irreconstructible → mode
      // dégradé « stockage » jusqu'à intervention, comme EX-12.11 : rien de plus
      // n'est écrit (ni attente, ni politique : l'ordre unique d'EX-9.8 ne peut
      // pas être tenu sans le pas 2).
      this.passif = false;
      this.pret = true;
      await this._servirSupervision();
      return;
    }
    // EX-9.8 (3) : événements en attente d'un arrêt précédent.
    await this._reprendreAttente(epoque, etat);
    // EX-15.8 : pas d'entrée en mode observation avec un ticket ouvert.
    const refusObservation = this.politique.refusEntreeObservation(cfg.policy);
    if (refusObservation) throw new ErreurEnregistreur("politique", `${refusObservation} (EX-15.8)`, { code: 2 });
    // EX-9.8 (4) : événement de politique.
    await this._annoncerPolitique(cfg.policy);

    // Instance passive : en service seulement ici, après la reprise des
    // intentions et des événements en attente et l'événement de politique
    // (EX-9.8 ; 13.4 pas 6 et 7) ; jusque-là, -31010 bail_non_detenu.
    this.passif = false;
    // Pas 6 (suite) : charger, ouvrir, consommer.
    if (this.service) {
      this._charger();
      for (const [ticket] of this.index.retenues) {
        const r = this.index.retenueSansDecision(ticket);
        if (r) this._ouvrir(r).catch(() => {});
      }
      // EX-7.20 : `consommer` au redémarrage pour les seuls tickets dont le délai de
      // reconnaissance (`approval.at + E`) court encore ; envois en concurrence bornée.
      const maintenant = this.horlogeBrute.murale();
      for (const [ticket, e] of this.index.premiersExecutes) {
        if (this._reconnaissanceCourt(e, maintenant)) this._consommer(ticket, e);
      }
    }

    // Pas 7 : startup, puis ouverture (supervision ; les frontaux sont des lots suivants).
    this.journal.consigner("info", "noyau", "startup", {
      config_sha256: this.o.octetsConfig ? sha256Hex(this.o.octetsConfig) : null,
      class: this.signataire.classe,
      backend: this.signataire.typeBackend,
      recorder_key_id: this.ecrivain.cleCourante,
      servers: Object.keys(cfg.policy.servers ?? {}),
      model_mode: cfg.model.mode,
      epoch: epoque,
    });
    this.metriques.jauge("noortrace_build_info", { version: VERSION_ENREGISTREUR, protocol_versions: "2026-07-28" }, 1);
    this.pret = true;
    await this._servirSupervision();
    if (this.o.minuteurs) this._armerMinuteurs();
  }

  /**
   * Acquisition du bail (EX-15.4 pas 5, 13.4 pas 1) : la ligne de contrôle de
   * la clé du MAC de relais est d'abord comparée à celle du dernier fichier
   * `mac-*` (EX-7.22) ; une différence est une erreur de configuration
   * (`relay_mac_key_mismatch`) et l'instance ne prend pas le bail. Un bail
   * détenu par une autre instance : avec `attendreBail`, instance passive
   * (`lease_standby`, santé `standby`, frontaux ouverts par `surAttente`, qui
   * rendent `-31010 bail_non_detenu`), nouvel essai toutes les `renew_ms` ;
   * sans, le démarrage est refusé.
   * @returns {Promise<number>} époque
   */
  /**
   * Premier démarrage sur un journal reconstruit (segments présents, aucun
   * répertoire `intentions/` : l'écrivain le crée avant son premier segment,
   * la reconstruction ne le restaure jamais, CT-8 §11.4) : vérification
   * complète avant d'écrire (EX-12.10 « avant d'écrire » ; CT-8 EX-11.6 :
   * fichiers identiques à ce que les copies désignent). Une anomalie lève
   * ErreurRelecture : mode dégradé « stockage » jusqu'à intervention.
   */
  async _verifierJournalReconstruit() {
    const segs = await fs.readdir(path.join(this.repertoire, "segments")).catch(() => []);
    if (!segs.some((n) => n.startsWith("seg-")) || (await existe(path.join(this.repertoire, "intentions")))) return;
    const v = await verifierRepertoireJournal(this.repertoire, {
      org_id: this.org_id,
      journal_id: this.journal_id,
      clePublique: (id) => this.signataire.clePublique(id),
      dernierOuvert: true,
      signatureAbsenteAdmise: () => true,
    });
    this.journal.consigner(v.incidents.length ? "error" : "info", "stockage", "journal_reconstruit_verifie", { incidents: v.incidents, last_seq: v.lastSeq });
    if (v.incidents.length) {
      this.journal.consigner("error", "stockage", "segment_corrupted", { incidents: v.incidents });
      throw new ErreurRelecture("segment_corrupted", { incidents: v.incidents });
    }
  }

  async _acquerirBail() {
    const cleMac = this.secrets.get("/storage/relay_mac_key") ?? null;
    let signale = false;
    for (;;) {
      if (this.arrete) throw new ErreurEnregistreur("bail_non_detenu", "noortrace: arret pendant l'attente du bail");
      const concorde = cleMac ? await controleCleMac(this.repertoire, cleMac) : null;
      if (concorde === false) {
        if (!signale) this.journal.consigner("error", "noyau", "relay_mac_key_mismatch", {});
        signale = true;
        if (!this.o.attendreBail) throw new ErreurEnregistreur("bail", "noortrace: cle du MAC de relais differente de celle du journal (relay_mac_key_mismatch)", { code: 2 });
      } else {
        try {
          return await this.bail.acquerir();
        } catch (e) {
          if (!(e instanceof ErreurEnregistreur) || e.raison !== "bail_non_detenu" || !this.o.attendreBail) throw e;
        }
      }
      if (!this.passif) {
        this.passif = true;
        this.journal.consigner("info", "bail", "lease_standby", { store: this.bail.type });
        this.metriques.jauge("noortrace_lease_epoch", {}, 0);
        await this._servirSupervision();
        await this.o.surAttente?.(this);
      }
      await new Promise((r) => {
        this.reveilAttente = r;
        const t = setTimeout(r, this.config.lease.renew_ms);
        t.unref?.();
      });
    }
  }

  async _servirSupervision() {
    if (!this.o.supervision || this.serveur) return;
    const [hote, port] = this.config.supervision.health_listen.split(/:(?=[0-9]+$)/);
    this.serveur = await servirSupervision({
      adresse: hote.replace(/^\[|\]$/g, ""),
      port: Number(port),
      etat: () => this.etatSante(),
      pret: () => this.pret && this.bailDetenu && !this.passif,
      metriques: this.config.supervision.metrics ? this.metriques : null,
    });
  }

  _armerMinuteurs() {
    // Un tic 50 ms après chaque seconde pleine : les instants alignés sont des
    // secondes pleines, et la tolérance d'alignement est d'1 s (EX-12.24).
    const planifier = () => {
      if (this.arrete) return;
      const d = 1000 - (this.horlogeBrute.murale() % 1000) + 50;
      const t = setTimeout(async () => {
        await this.tic().catch(() => {});
        planifier();
      }, d);
      t.unref?.();
      this.minuteurs[0] = t;
    };
    planifier();
    // Boucle `decisions` (EX-7.19) : moteur de politique.
    this.politique.demarrerBoucle();
    // Contrôles périodiques d'EX-17.5 (période close, signataire, relecture
    // quotidienne), avec ou sans WORM ; puis ceux des copies WORM (EX-17.5 à EX-17.7).
    this.controles.armer();
    this.o.worm?.armer?.();
  }

  /**
   * Confirmation de l'exploitant après un saut en avant de l'horloge murale
   * (`noortrace-ctl clock --accept`, EX-7.13 ; consignée). Elle ne s'applique
   * qu'au mode dégradé « horloge » d'un saut en avant : après un recul
   * (EX-7.9), l'accepter daterait les événements au `ts` précédent, donc dans
   * le futur de l'horloge, ce qu'EX-7.13 exclut ; le mode se lève quand
   * l'horloge a rejoint le `ts` précédent.
   * @returns {{accepte: boolean, raison?: string}}
   */
  accepterHorloge() {
    if (!this.degrade.actif("horloge") || !this.horloge.saut) {
      const raison = this.degrade.actif("horloge") ? "recul" : "hors_mode_horloge";
      this.journal.consigner("warning", "noyau", "clock_accept_refused", { raison });
      return { accepte: false, raison };
    }
    this.horloge.accepter();
    return { accepte: true };
  }

  /**
   * Raisons de santé d'un frontal (EX-4.18, EX-17.1 : `serveur:<alias>`),
   * hors mode dégradé du cœur : elles ne bloquent ni appel ni remise.
   * @param {() => string[]} f
   */
  brancherSante(f) {
    this.raisonsFrontal = f;
  }

  /**
   * Rétention d'une requête par le frontal (mode `retenir`, EX-4.50) :
   * `retient(ticket)` dit si une requête de ce ticket est retenue (membre
   * `held` d'`acquitter`, EX-7.19) ; `decidee(ticket, evenement)` est appelé,
   * sans être attendu, après le scellement durable d'une décision.
   * @param {{retient: (ticket: string) => boolean, decidee: (ticket: string, evenement: object) => void}} r
   */
  brancherRetention(r) {
    this.retention = r;
  }

  _decidee(ticket, e) {
    const r = this.retention;
    if (r?.decidee) setImmediate(() => Promise.resolve(r.decidee(ticket, e)).catch(() => {}));
  }

  /**
   * `held` d'un `acquitter` `scelle` (EX-7.19 pas 3 : vrai si et seulement si
   * le noyau retient une requête de ce ticket ET va la relayer), établi à
   * l'instant même où la décision est remise à la rétention : la requête
   * retenue est réclamée (`decidee`) dans le même tour, sans attente entre le
   * constat et la réclamation, de sorte qu'une fin de rétention
   * (`hold_timeout_ms`) ne puisse plus s'intercaler. Seule une décision
   * `approuve` est relayée.
   * @returns {boolean}
   */
  _reclamerRetention(ticket, e) {
    const r = this.retention;
    if (!r) return false;
    let retenue = false;
    try {
      retenue = r.retient?.(ticket) === true;
    } catch {
      retenue = false;
    }
    if (r.decidee) {
      try {
        Promise.resolve(r.decidee(ticket, e)).catch(() => {});
      } catch {
        // la rétention ne bloque jamais le scellement
      }
    }
    return retenue && e.approval.decision === "approuve";
  }

  /**
   * Message réessayé jusqu'au succès (CT-3 §12.7, CT-2 EX-7.14 : `ouvrir`,
   * `charger`, `consommer`, `expiration`) : délai croissant plafonné à 5 s,
   * sans borne de nombre ; un seul envoi en cours par clé ; l'arrêt du démon
   * met fin aux essais. `tache` rend vrai quand la réponse est finale.
   * @param {string} cle
   * @param {() => Promise<boolean>} tache
   * @param {{attendreAvant?: boolean}} [o]
   * @returns {Promise<void>}
   */
  _jusquAuSucces(cle, tache, o = {}) {
    this._essais ??= new Map();
    const enCours = this._essais.get(cle);
    if (enCours) return enCours;
    const dormir = (n) => new Promise((r) => {
      const t = setTimeout(r, Math.min(50 * 2 ** Math.min(n, 7), 5000));
      t.unref?.();
    });
    const p = (async () => {
      for (let n = 0; ; n++) {
        if (n > 0 || o.attendreAvant) await dormir(n);
        if (this.arrete) return;
        let fini = false;
        try {
          fini = await tache();
        } catch {
          fini = false;
        }
        if (fini || this.arrete) return;
      }
    })().finally(() => this._essais.delete(cle));
    this._essais.set(cle, p);
    return p;
  }

  /**
   * Sérialise par ticket la vérification et le scellement d'une décision
   * (remise, expiration par le noyau seul) : SG-3 est vérifiée sous ce verrou,
   * après le scellement de toute décision concurrente du même ticket (CT-3 14.2,
   * « le noyau est le seul scelleur »).
   * @template T
   * @param {string} ticket
   * @param {() => Promise<T>} f
   * @returns {Promise<T>}
   */
  async _sousVerrouTicket(ticket, f) {
    this._verrous ??= new Map();
    const avant = this._verrous.get(ticket) ?? Promise.resolve();
    let liberer;
    const tenu = new Promise((r) => (liberer = r));
    const chaine = avant.then(() => tenu);
    this._verrous.set(ticket, chaine);
    await avant;
    try {
      return await f();
    } finally {
      liberer();
      if (this._verrous.get(ticket) === chaine) this._verrous.delete(ticket);
    }
  }

  /** Le délai de reconnaissance (`approval.at + E`, E de la version de la `retenue`) court-il encore ? */
  _reconnaissanceCourt(executee, maintenant) {
    const at = executee.approval?.at ? decoderHorodatage(executee.approval.at) : null;
    if (at === null) return false;
    const retenue = this.index.retenuesParHash.get(executee.approval.request_hash) ?? null;
    const E = delaiExpiration(retenue ? (this.politiquesParVersion.get(retenue.code.policy_version) ?? null) : null) ?? E_MAX_MS;
    return at + E > maintenant;
  }

  /** État de santé (EX-17.1). */
  etatSante() {
    const d = this.degrade.depuis();
    return {
      passive: this.passif,
      bailDetenu: this.bailDetenu && this.bail?.valide?.() !== false,
      raisons: [...this.degrade.raisons(), ...(this.raisonsFrontal?.() ?? [])],
      depuis: d === null ? null : ecrireHorodatage(d),
      cleIndisponible: this.degrade.actif("cle"),
    };
  }

  /** Corps de `/healthz`. */
  sante() {
    return sante(this.etatSante());
  }

  _bloquerSiIntervention() {
    // Instance passive (13.4 pas 1) : `-31010`, raison `bail_non_detenu` (14.2).
    if (this.passif) throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu");
    if (this.intervention || !this.ecrivain) {
      throw new ErreurEnregistreur("stockage", "noortrace: enregistreur en mode degrade (stockage)");
    }
  }

  // ------------------------------------------------------------ politique

  /** Version de politique en vigueur. */
  get versionPolitique() {
    return this.config.policy.version;
  }

  /** Nom des règles de rédaction en vigueur (`policy.redaction.name`). */
  get nomRedaction() {
    return this.config.policy.redaction?.name ?? null;
  }

  async _annoncerPolitique(politique) {
    // EX-10.21 : des règles de rédaction changées changent redaction.name.
    const refusRedaction = this.o.redaction?.verifierPolitique?.(politique, this.politiquesParVersion) ?? null;
    if (refusRedaction) throw new ErreurEnregistreur("politique", refusRedaction, { code: 2 });
    const emp = empreintePolitique(politique);
    const d = decisionPolitique(this.index, emp);
    if (d.refus) throw new ErreurEnregistreur("politique", d.refus, { code: 2 });
    this.politiquesParVersion.set(emp.policy_version, politique);
    if (!d.annoncer) return null;
    await this.pieces.ecrire(piecePolitique(politique));
    const e = await this.ecrivain.sceller(partielPolitique({ policy_version: emp.policy_version, policy_sha256: emp.policy_sha256, recorder: VERSION_ENREGISTREUR }));
    this.journal.consigner("info", "config", "policy_announced", { policy_version: emp.policy_version, policy_sha256: emp.policy_sha256 }, { seq: e.seq });
    return e;
  }

  /**
   * Rechargement (EX-15.5) : pas 1 à 4 sur le nouveau document ; refusé en
   * mode dégradé, ou si un membre hors `policy` a changé, ou si
   * `policy.version` n'a pas changé ; sinon l'événement de politique est
   * scellé, puis la nouvelle politique appliquée.
   * @param {Uint8Array} octets
   * @param {{env?: object, uid?: number|null}} [contexte]
   * @returns {Promise<{accepte: boolean, raison?: string, pointeurs?: string[], evenement?: object}>}
   */
  async recharger(octets, contexte = {}) {
    const refus = (raison, extra = {}) => {
      this.journal.consigner("warning", "config", "config_reload_rejected", { raison, ...extra });
      return { accepte: false, raison, ...extra };
    };
    const v = validerConfiguration(octets, { reglesSupplementaires: this.o.reglesSupplementaires ?? [] });
    if (v.pas) return refus("configuration_invalide", { erreurs: v.erreurs.length });
    const s = resoudreSecrets(v.config, contexte);
    if (s.erreurs.length) return refus("secrets", { erreurs: s.erreurs.length });
    if (this.degrade.enModeDegrade) return refus("mode_degrade");
    const diff = differencesHorsPolitique(this.config, v.config);
    if (diff.length) return refus("redemarrage_requis", { pointeurs: diff });
    if (v.config.policy.version === this.config.policy.version) return refus("version_inchangee");
    // EX-15.8 : entrée en mode observation refusée tant qu'un ticket est ouvert.
    const refusObservation = this.politique.refusEntreeObservation(v.config.policy, { depuisMode: this.config.policy.approval?.mode ?? null });
    if (refusObservation) return refus(refusObservation);
    const e = await this._annoncerPolitique(v.config.policy);
    this.config = { ...this.config, policy: v.config.policy };
    this.politique.actualiser();
    this.o.redaction?.recharger?.(this.config, s.secrets);
    this.candidats = null;
    this.journal.consigner("info", "config", "config_reloaded", { policy_version: v.config.policy.version });
    if (this.service) this._charger();
    return { accepte: true, evenement: e };
  }

  // ------------------------------------------------------------ pièces et échanges

  /**
   * Écrit une pièce sous son sha256, forcée sur disque (EX-8.9, EX-12.6).
   * @param {Piece} piece
   * @returns {Promise<object>} sa référence
   */
  async ecrirePiece(piece) {
    this._bloquerSiIntervention();
    try {
      return (await this.pieces.ecrire(piece)).reference;
    } catch (e) {
      if (e instanceof ErreurEnregistreur) this.degrade.entrer("stockage", { event: e.donnees?.event ?? "storage_unavailable" });
      throw e;
    }
  }

  /**
   * Scelle un échange de modèle (9.1, 5.3) ; pièces déjà écrites.
   * @param {{delegation: object, code: {model: string|null, prompt_version: string|null}, intent: unknown,
   *   requete: object, reponse: object, duration_ms: number, is_error: boolean, context?: object[], policy_version?: string}} c
   * @returns {Promise<object>} événement durable
   */
  async scellerEchange(c) {
    this._bloquerSiIntervention();
    const e = await this.ecrivain.sceller(
      partielEchange({
        ...c,
        code: { ...c.code, policy_version: c.policy_version ?? this.versionPolitique, recorder: VERSION_ENREGISTREUR },
        nomRedaction: this.nomRedaction,
      }),
    );
    // Registre de recouvrement de l'ingestion OpenTelemetry (EX-6.34) : `c.host`
    // est l'`id` de la connexion d'hôte de l'échange (frontal modèle, SDK).
    this._notifierScelle({ genre: "echange", host: c.host ?? null, evenement: e });
    return e;
  }

  /**
   * Scelle un événement partiel déjà construit par un frontal selon sa
   * table (ingestion OpenTelemetry, EX-6.36) ; pièces déjà écrites.
   * Avec `priorite: "basse"`, l'événement n'est remis à l'écrivain que
   * lorsqu'aucun événement d'un autre frontal n'y attend (EX-6.28 : les
   * frontaux interposés sont servis avant l'ingestion).
   * @param {object} partiel les huit champs de CT-1 §5.3
   * @param {{priorite?: "basse"}} [o]
   * @returns {Promise<object>}
   */
  async scellerPartiel(partiel, o = {}) {
    this._bloquerSiIntervention();
    if (o.priorite === "basse") {
      while (!this.arrete && this.ecrivain.file.some((x) => x.type === "evenement" && x.options?.priorite !== "basse")) {
        await new Promise((r) => setTimeout(r, 1));
      }
      return this.ecrivain.sceller(partiel, { priorite: "basse" });
    }
    return this.ecrivain.sceller(partiel);
  }

  /**
   * Écoute des scellements des frontaux (registre de recouvrement de
   * l'ingestion OpenTelemetry, EX-6.34) : `f({ genre: "appel" | "echange",
   * host, appel?, evenement })` est appelé, sans être attendu, après chaque
   * appel d'outil (relais, reprise à chaud) et chaque échange de modèle
   * rendus durables par le cœur.
   * @param {(x: object) => void} f
   */
  ecouterScellements(f) {
    (this.ecouteursScelle ??= []).push(f);
  }

  _notifierScelle(x) {
    for (const f of this.ecouteursScelle ?? []) {
      try {
        f(x);
      } catch {
        // un écouteur ne bloque jamais le scellement
      }
    }
  }

  // ------------------------------------------------------------ approbation (7.5)

  _decisionScellee(ticket) {
    return this.index.decisions.get(ticket) ?? null;
  }

  /**
   * Message `evaluer` (EX-7.4) et validation de la réponse (EX-7.16). Une
   * réponse invalide, une erreur ou l'absence du service lèvent
   * ErreurEnregistreur(`approbation`) ; le frontal applique la matrice de 14.2.
   * @param {object} requete l'objet d'EX-7.4 (arguments en clair)
   * @returns {Promise<object>} la réponse validée
   */
  async evaluer(requete) {
    // Instance passive : elle n'échange avec le service qu'après la prise du bail (13.4 pas 6).
    if (this.passif) throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu");
    if (!this.service) throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation indisponible");
    // Mode observation (EX-7.23, EX-14.15) : réponse sans ticket, aucun nouvel essai qui retarde l'appel.
    const observation = this.config.policy.approval?.mode === "observation";
    const delai = this.config.policy.approval?.timeout_ms ?? 2000;
    let r;
    for (let essai = 0; essai < 2; essai++) {
      let minuteur;
      try {
        // EX-7.4 : réponse dans policy.approval.timeout_ms, sinon service indisponible.
        r = await Promise.race([
          this.service.evaluer(requete),
          new Promise((_, rej) => {
            minuteur = setTimeout(() => rej(new ErreurServiceApprobation("indisponible", { delai_ms: delai })), delai);
            minuteur.unref?.();
          }),
        ]);
        break;
      } catch (e) {
        if (e instanceof ErreurServiceApprobation && e.code === "politique_inconnue" && essai === 0) {
          if (observation) {
            this._charger().catch(() => {});
          } else {
            await this._charger(true).catch(() => {});
            continue;
          }
        }
        this.journal.consigner("warning", "politique", "approval_service_unavailable", { code: e?.code ?? "indisponible" });
        throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation indisponible", { cause: e });
      } finally {
        clearTimeout(minuteur);
      }
    }
    const v = validerReponseEvaluer(r, { decisionScellee: (t) => this._decisionScellee(t), observation });
    if (!v.valide) {
      this.journal.consigner("warning", "politique", "approval_response_invalid", { raison: v.raison });
      throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation indisponible", { donnees: { raison: v.raison } });
    }
    return r;
  }

  /**
   * Outil susceptible d'approbation (EX-7.4) : toujours vrai tant que la
   * liste du dernier `charger` réussi manque, et pour un nom qui n'y est pas.
   * @param {string} nom
   */
  susceptible(nom) {
    if (!this.candidats) return true;
    if (!this.candidats.envoyes.has(nom)) return true;
    return this.candidats.liste.has(nom);
  }

  /**
   * Message `charger` (EX-7.15) ; `tools` vient du frontal MCP (lot suivant)
   * par `definirOutils`.
   */
  async _charger(attendreReponse = false) {
    if (!this.service || this.passif) return;
    const pol = this.config.policy;
    const emp = empreintePolitique(pol);
    const { service, ...approval } = pol.approval;
    void service;
    const outils = [...(this.outils ?? [])].sort((a, b) => (a.tool_announced < b.tool_announced ? -1 : a.tool_announced > b.tool_announced ? 1 : 0));
    const requesters = [...new Set([...(this.config.mcp.hosts ?? []), ...(this.config.sdk.hosts ?? [])].map((h) => h.launched_by).filter((l) => !l.includes("${")))].sort();
    // Seule la réponse au dernier `charger` envoyé est adoptée : celle d'un
    // `charger` remplacé (rechargement, nouvelle liste d'outils) arrive pour une
    // version ou une liste qui n'est plus en vigueur et est ignorée (EX-7.4 ;
    // CT-3 EX-12.5 : tant que le noyau n'a pas la liste, tout outil est susceptible).
    const generation = (this._generationCharger = (this._generationCharger ?? 0) + 1);
    const requete = { org_id: this.org_id, journal_id: this.journal_id, environment: this.config.recorder.environment, policy_version: emp.policy_version, policy_sha256: emp.policy_sha256, approval, tools: outils, requesters };
    const essai = async () => {
      if (generation !== this._generationCharger) return true;
      try {
        const r = await this.service.charger(requete);
        if (generation !== this._generationCharger || this.config.policy.version !== emp.policy_version) return true;
        if (r.policy_version !== emp.policy_version || r.policy_sha256 !== emp.policy_sha256) throw new Error("charger : version ou empreinte différente");
        this.candidats = { envoyes: new Set(outils.map((t) => t.tool_announced)), liste: new Set(r.approval_candidates) };
        this.journal.consigner("info", "politique", "approval_candidates", { candidates: r.approval_candidates });
        return true;
      } catch (e) {
        if (generation !== this._generationCharger) return true;
        this.journal.consigner("warning", "politique", "approval_service_unavailable", { message: "charger", code: e?.code ?? null });
        // CT-3 12.7 : sans réponse, nouvel essai ; une erreur du service est une réponse (EX-7.15).
        return e instanceof ErreurServiceApprobation && RAISONS_SERVICE.has(e.code);
      }
    };
    const premier = essai();
    premier.then((fini) => {
      if (!fini) this._jusquAuSucces(`charger:${generation}`, essai, { attendreAvant: true });
    });
    if (attendreReponse) await premier;
  }

  /**
   * Liste agrégée des outils (EX-7.15), fournie par le frontal MCP ; renvoie
   * `charger`.
   * @param {{tool_announced: string, tool_original: string, server_alias: string, class: string, effects: object[]|null}[]} outils
   */
  definirOutils(outils) {
    this.outils = outils;
    this.candidats = null;
    if (this.service) this._charger();
  }

  _gabarit(alias, nom) {
    return this.config.policy.servers?.[alias]?.tools?.[nom]?.effects ?? null;
  }

  _partielAppel(appel, extra) {
    return partielAppelOutil({
      delegation: appel.delegation,
      code: { model: appel.code?.model ?? null, prompt_version: appel.code?.prompt_version ?? null, policy_version: appel.policy_version ?? this.versionPolitique, recorder: VERSION_ENREGISTREUR },
      intent: appel.intent ?? null,
      tool: appel.tool_announced,
      arguments: appel.arguments,
      context: appel.context ?? [],
      nomRedaction: this.nomRedaction,
      ...extra,
    });
  }

  /**
   * Refus (4.4 pas 5) : réponse `refuse` sans ticket, ou d'un ticket décidé
   * `refuse` ou `expire` (reprise de la `retenue`, EX-7.12).
   * @param {object} appel capture d'appel (INTERFACES.md)
   * @param {object} reponse réponse validée d'`evaluer`
   * @returns {Promise<object>}
   */
  async scellerRefus(appel, reponse) {
    this._bloquerSiIntervention();
    if (reponse.ticket_state === null) {
      return this.ecrivain.sceller(this._partielAppel(appel, { policy: { rule: reponse.rule, decision: "refuse", ticket: null }, approval: null, status: "refusee" }));
    }
    const decision = this._decisionScellee(reponse.ticket);
    const retenue = decision && this.index.retenuesParHash.get(decision.approval.request_hash);
    if (!retenue) throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation en defaut");
    const rep = repriseDeRetenue(retenue, decision);
    return this.ecrivain.sceller(
      this._partielAppel({ ...appel, intent: rep.intent, code: rep.code }, { policy: rep.policy, approval: rep.approval, status: "refusee" }),
    );
  }

  /**
   * Retenue (4.4 pas 6, EX-7.17, EX-7.18, EX-12.23) pour une réponse
   * `nouveau` : refus de sceller la retenue d'un ticket décidé ; pas de
   * seconde retenue sans décision ; sinon événement `retenue`, lignes des
   * fichiers des approbations et MAC avant l'ajout au segment, puis `ouvrir`.
   * @param {object} appel
   * @param {object} reponse
   * @param {unknown} argumentsEnClair
   * @returns {Promise<{evenement: object|null, signal: "en_attente"}>}
   */
  async scellerRetenue(appel, reponse, argumentsEnClair) {
    this._bloquerSiIntervention();
    const ticket = reponse.ticket;
    const decision = this._decisionScellee(ticket);
    if (decision) {
      this.journal.consigner("error", "politique", "identifiant_en_collision", { ticket_seq: decision.seq });
      this.metriques.compter("noortrace_approval_relays_refused_total", { check: "retenue_decidee" });
      throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation en defaut");
    }
    const deja = this.index.retenueSansDecision(ticket);
    if (deja) {
      this._ouvrir(deja).catch(() => {});
      this.journal.consigner("info", "politique", "approval_pending", {});
      return { evenement: null, signal: "en_attente" };
    }
    const mac = macRelais(this.cleMac, argumentsEnClair);
    const e = await this.ecrivain.sceller(
      this._partielAppel(appel, { policy: { rule: reponse.rule, decision: "a_approuver", ticket }, approval: null, status: "retenue" }),
      {
        avantAjout: (evt) =>
          this.approbations.inscrireRetenue({ ticket, request_seq: evt.seq, request_hash: evt.hash, approver_set: reponse.approver_set, mac }),
      },
    );
    this._ouvrir(e).catch(() => {});
    return { evenement: e, signal: "en_attente" };
  }

  /**
   * `ouvrir` (EX-7.18) : réessayé jusqu'au succès ; `ticket_deja_ouvert` et
   * `ticket_inconnu` sont consignés et mettent fin aux essais.
   */
  async _ouvrir(retenue) {
    if (!this.service) return;
    const octets = await this.pieces.lire(retenue.execution.arguments.sha256);
    const requete = {
      ticket: retenue.policy.ticket,
      request_hash: retenue.hash,
      request_seq: retenue.seq,
      request_ts: retenue.ts,
      request_event: retenue,
      arguments_piece: octets ? encoderBase64(octets) : null,
    };
    return this._jusquAuSucces(`ouvrir:${retenue.hash}`, async () => {
      try {
        const r = await this.service.ouvrir(requete);
        this.journal.consigner("info", "politique", "approval_opened", { state: r.state ?? null, deadline: r.deadline ?? null }, { seq: retenue.seq });
        return true;
      } catch (e) {
        if (e instanceof ErreurServiceApprobation && (e.code === "ticket_deja_ouvert" || e.code === "ticket_inconnu")) {
          this.journal.consigner("warning", "politique", "approval_open_refused", { code: e.code }, { seq: retenue.seq });
          return true;
        }
        return false;
      }
    });
  }

  /**
   * Relais, premier temps (4.4 pas 7 et 8) : vérifications de relais RL-1 à
   * RL-4 pour un ticket approuvé (EX-7.21), puis intention durable pour une
   * écriture ou un appel soumis à approbation (EX-12.12). Le frontal ne relaie
   * qu'après le retour de cette méthode.
   * @param {object} appel capture d'appel
   * @param {{reponse: object, argumentsEnClair: unknown, upstream_id: string, timeout_ms?: number, effetsDeclares?: object[]}} o
   *   `upstream_id` : `id` amont (frontal MCP) ou identifiant `call` (SDK) ; `effetsDeclares` : effets du SDK (EX-12.12)
   * @returns {Promise<object>} poignée de relais à passer à `terminerRelais`
   */
  async preparerRelais(appel, o) {
    this._bloquerSiIntervention();
    let fixe = { policy: { rule: o.reponse.rule, decision: "autorise", ticket: null }, approval: null };
    let a = appel;
    const ticket = o.reponse.ticket_state === "approuve" ? o.reponse.ticket : null;
    if (ticket) {
      const mac = macRelais(this.cleMac, o.argumentsEnClair);
      const intentionsOuvertes = new Set([...this.relaisEnCours]);
      const v = verifierRelais(
        {
          ticket,
          tool: appel.tool_announced,
          delegation: appel.delegation,
          arguments: appel.arguments,
          mac,
          approvalReponse: o.reponse.approval,
          instant: this.horlogeBrute.murale(),
          timeoutOutil: o.timeout_ms ?? this.config.tools.default_timeout_ms,
        },
        { index: this.index, macs: this.approbations.macs, intentionsOuvertes, relaisEnCours: this.relaisEnCours, politique: (v2) => this.politiquesParVersion.get(v2) ?? null },
      );
      if (!v.ok) {
        this.journal.consigner("error", "politique", "approval_relay_refused", { check: v.verification });
        this.metriques.compter("noortrace_approval_relays_refused_total", { check: v.verification });
        throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation en defaut", { donnees: { verification: v.verification } });
      }
      const rep = repriseDeRetenue(v.retenue, v.decision);
      fixe = { policy: rep.policy, approval: rep.approval };
      a = { ...appel, intent: rep.intent, code: rep.code };
      this.relaisEnCours.add(ticket);
    }
    const base = this._partielAppel(a, { ...fixe, status: "executee", result: null, duration_ms: 0, is_error: false });
    let intention = null;
    const partielIntention = { ...base, effects: o.effetsDeclares ?? [] };
    if (appel.class === "ecriture" || ticket) {
      try {
        intention = await this.ecrivain.inscrireIntention(
          { upstream_id: o.upstream_id, host: appel.host.id, tool: appel.tool_announced, arguments: appel.arguments, ticket },
          partielIntention,
        );
      } catch (e) {
        if (ticket) this.relaisEnCours.delete(ticket);
        throw e;
      }
    }
    return { appel: a, fixe, ticket, intention, partielIntention, debut: this.horlogeBrute.monotone() };
  }

  /**
   * Reprise à chaud (EX-12.15, EX-6.13, table de 6.2 `fermer`) : une session
   * SDK close ou perdue, le démon tournant, avec un `debutAppel` qui a écrit
   * une intention et sans `finAppel`. Même construction que la reprise au
   * démarrage (EX-12.14 pas 2 et 3, `partielReprise`) : événement `executee`,
   * `is_error: true`, pièce « résultat » de reprise, levée, `intent_recovered` ;
   * l'approbation d'un ticket approuvé est consommée (EX-6.7, EX-7.20).
   * @param {object} relais poignée de `preparerRelais`
   * @returns {Promise<object|null>} l'événement de reprise, ou null sans intention
   */
  async reprendreRelais(relais) {
    const i = relais?.intention;
    if (!i) return null;
    this._bloquerSiIntervention();
    const a = relais.appel;
    const entree = { intention: i.intention, sha256: i.intention_sha256, contexte: objetContexte(i.intent_id, relais.partielIntention).event };
    try {
      const piece = pieceReprise(i.intention_sha256);
      await this.ecrirePiece(piece);
      // EX-12.15 : « c'est la relecture du journal d'intention qui fait le
      // travail » : même construction qu'au démarrage, classe et origine
      // tirées du nom d'outil de l'intention et de la configuration, jamais
      // de la session (lecture 117).
      const { partiel } = this._partielReprise(entree, piece);
      const e = await this.ecrivain.sceller(partiel, { leverIntention: i.intent_id, sorteMetrique: "reprise" });
      this.journal.consigner("info", "noyau", "intent_recovered", { intent_id: i.intent_id, written_at: i.intention.written_at, session_closed: true }, { seq: e.seq, host: a.host?.id ?? null });
      this._notifierScelle({ genre: "appel", host: a.host?.id ?? null, appel: a, evenement: e });
      if (relais.ticket && this.index.premiersExecutes.get(relais.ticket)?.seq === e.seq) this._consommer(relais.ticket, e);
      return e;
    } finally {
      if (relais.ticket) this.relaisEnCours.delete(relais.ticket);
    }
  }

  /**
   * Relais, second temps (4.4 pas 12 et 13) : pièce « résultat » écrite,
   * effets évalués sur les valeurs rédigées (EX-7.6), événement `executee`
   * scellé et durable, intention levée ; `consommer` pour le premier relais
   * d'une approbation (EX-7.20). Une panne ici, après le relais, garde
   * l'événement en attente et lève une erreur -31017 (EX-4.46).
   * @param {object} relais poignée de `preparerRelais`
   * @param {{resultat: Piece, resultatRedige: unknown, argumentsRediges: unknown, duration_ms: number,
   *   is_error: boolean, sourceNonRedigeable?: boolean, effetsDeclares?: object[]}} r
   * @returns {Promise<object>}
   */
  async terminerRelais(relais, r) {
    const a = relais.appel;
    // Effets déclarés par le SDK (EX-6.6, EX-7.6 : pas 2 et 4 déjà appliqués
    // par le point d'entrée), à défaut gabarit de la configuration.
    const { effets, omis } = r.effetsDeclares
      ? { effets: r.effetsDeclares, omis: [] }
      : await (this.o.redaction?.evaluerEffets ?? evaluerEffets)({
          gabarit: this._gabarit(a.server_alias, a.tool_original),
          classe: a.class,
          alias: a.server_alias,
          nomOrigine: a.tool_original,
          arguments: r.argumentsRediges,
          resultat: r.resultatRedige,
          sourceNonRedigeable: r.sourceNonRedigeable,
          executerExtract: this.o.redaction?.executerExtract,
        });
    for (const x of omis) this.journal.consigner("info", "noyau", "effect_omitted", { gabarit: x.index, raison: x.raison });
    const partiel = this._partielAppel(a, {
      ...relais.fixe,
      status: "executee",
      result: r.resultat.reference,
      duration_ms: r.duration_ms,
      is_error: r.is_error,
      effects: effets,
    });
    try {
      await this.ecrirePiece(r.resultat);
      const e = await this.ecrivain.sceller(partiel, { leverIntention: relais.intention?.intent_id });
      this._notifierScelle({ genre: "appel", host: a.host?.id ?? null, appel: a, evenement: e });
      if (relais.ticket) {
        this.relaisEnCours.delete(relais.ticket);
        if (this.index.premiersExecutes.get(relais.ticket)?.seq === e.seq) this._consommer(relais.ticket, e);
      }
      return e;
    } catch (err) {
      if (relais.ticket) this.relaisEnCours.delete(relais.ticket);
      if (err instanceof ErreurEnregistreur || err instanceof ErreurConstruction) {
        this.mettreEnAttente(partiel, [r.resultat], { intent_id: relais.intention?.intent_id ?? null, host: a.host?.id ?? null, genre: "appel" });
        this.metriques.compter("noortrace_calls_executed_not_durable_total", { class: a.class });
        this.journal.consigner("error", "noyau", "call_executed_not_durable", { intent_id: relais.intention?.intent_id ?? null });
        throw new ErreurEnregistreur(err.raison ?? "stockage", "noortrace: appel execute, evenement non durable", { code: -31017, cause: err });
      }
      throw err;
    }
  }

  /**
   * `consommer` (EX-7.20) : réessayé jusqu'à une réponse finale (`consomme`,
   * `clos`, `requete_invalide`, `ticket_inconnu`), au plus
   * CONCURRENCE_CONSOMMER envois à la fois ; envoyé après l'`acquitter` de la
   * décision quand celui-ci est en cours (la décision arrive au service avant sa
   * consommation, CT-3 T11 puis T18).
   */
  _consommer(ticket, e) {
    if (!this.service) return;
    this._jusquAuSucces(`consommer:${ticket}`, async () => {
      await this._acquittements?.get(ticket);
      await this._prendreJeton();
      try {
        const r = await this.service.consommer({ ticket, seq: e.seq, hash: e.hash });
        this.journal.consigner("info", "politique", "approval_consume_final", { state: r.state }, { seq: e.seq });
        return true;
      } catch (err) {
        if (err instanceof ErreurServiceApprobation && ["requete_invalide", "ticket_inconnu"].includes(err.code)) {
          this.journal.consigner("info", "politique", "approval_consume_final", { raison: err.code }, { seq: e.seq });
          return true;
        }
        return false;
      } finally {
        this._rendreJeton();
      }
    });
  }

  async _prendreJeton() {
    this._jetons ??= { libres: CONCURRENCE_CONSOMMER, file: [] };
    if (this._jetons.libres > 0) {
      this._jetons.libres--;
      return;
    }
    await new Promise((r) => this._jetons.file.push(r));
  }

  _rendreJeton() {
    const suivant = this._jetons.file.shift();
    if (suivant) suivant();
    else this._jetons.libres++;
  }

  /**
   * Remises de décisions (EX-7.19) : un message `decisions`, puis, pour
   * chaque remise : acquittement `temporaire` en mode dégradé ; sinon ligne
   * `remise` durable, SG-1 à SG-7, et décision scellée ou refusée.
   * @param {{wait_ms?: number}} [o]
   * @returns {Promise<object[]>} résultats des acquittements
   */
  async traiterRemises(o = {}) {
    if (!this.service) return [];
    const r = await this.service.decisions({ wait_ms: o.wait_ms ?? 0 });
    const sortie = [];
    // `held` est établi au scellement de chaque décision (_reclamerRetention), pas ici.
    for (const remise of r.remises ?? []) sortie.push(await this.traiterRemise(remise));
    return sortie;
  }

  /**
   * Traite une remise (EX-7.19 pas 1 à 3).
   * @param {object} remise
   * @param {{held?: boolean}} [o] valeur imposée de `held` ; par défaut, établie au
   *   scellement par la rétention branchée (EX-4.50, `_reclamerRetention`)
   * @returns {Promise<object>} la requête `acquitter` envoyée
   */
  async traiterRemise(remise, o = {}) {
    // Forme contrôlée avant tout usage : un message qui n'a pas les membres
    // d'une remise n'est pas inscrit et SG-1 le refuse (EX-7.19, EX-9.11).
    const ticket = ligneRemise(remise) ? remise.ticket : null;
    return ticket === null ? this._traiterRemise(remise, o) : this._sousVerrouTicket(ticket, () => this._traiterRemise(remise, o));
  }

  async _traiterRemise(remise, o = {}) {
    const acq = { remise_id: remise?.remise_id ?? null, ticket: remise?.ticket ?? null, result: null, reason: null, seq: null, hash: null, at: null, decision: null, held: null, approval: null };
    const envoyer = async (x) => {
      try {
        await this.service?.acquitter(x);
      } catch {
        // réessayé à la prochaine présentation de la remise
      }
      return x;
    };
    if (this.degrade.enModeDegrade || this.intervention) {
      this.journal.consigner("warning", "politique", "approval_deferred", {});
      return envoyer({ ...acq, result: "temporaire", reason: "mode_degrade" });
    }
    if (ligneRemise(remise)) {
      try {
        await this.approbations.inscrireRemise(remise);
      } catch (e) {
        if (e instanceof ErreurEnregistreur && e.raison === "stockage") {
          // EX-7.19 pas 2 : échec d'écriture du fichier des approbations → mode
          // dégradé « stockage » ; le segment est fermé comme après toute panne de
          // stockage (EX-12.8), pour que la sortie suive EX-14.11 (nouveau segment).
          this.journal.consigner("error", "politique", "approval_files_unavailable", { errno: e.cause?.code ?? null });
          await this.ecrivain.signalerPanneStockage(e.cause ?? e).catch(() => {});
          if (!this.degrade.actif("stockage")) this.degrade.entrer("stockage");
        } else {
          this.journal.consigner("error", "politique", "approval_remise_unwritable", { message: e?.message ?? null });
        }
        return envoyer({ ...acq, result: "temporaire", reason: "mode_degrade" });
      }
    }
    const politique = (v) => this.politiquesParVersion.get(v) ?? null;
    const v = verifierRemise(remise, { index: this.index, org_id: this.org_id, journal_id: this.journal_id, instant: this.horlogeBrute.murale(), politique });
    const refuser = (verification, raison, deja) => {
      this.journal.consigner("error", "politique", "approval_remise_refused", { check: verification, raison });
      this.metriques.compter("noortrace_approval_remises_refused_total", { check: verification });
      const x = { ...acq, result: "refuse", reason: raison };
      if (deja) Object.assign(x, { seq: deja.seq, hash: deja.hash, at: deja.approval.at, decision: deja.approval.decision, approval: deja.approval });
      return envoyer(x);
    };
    if (!v.ok) return refuser(v.verification, v.raison, v.decision);
    const E = delaiExpiration(politique(v.retenue.code.policy_version));
    const motif = this.o.redaction?.redigerMotif ? await this.o.redaction.redigerMotif(remise.approval.reason) : remise.approval.reason;
    // SG-3 de nouveau, juste avant le scellement (verrou du ticket tenu).
    const deja = this.index.decisions.get(remise.ticket);
    if (deja) return refuser("SG-3", "ticket_deja_decide", deja);
    let e;
    try {
      e = await this.ecrivain.sceller(
        partielDecision({ retenue: v.retenue, approval: { ...remise.approval, reason: motif }, policy_version: this.versionPolitique, recorder: VERSION_ENREGISTREUR, org_id: this.org_id, journal_id: this.journal_id }),
        {
          completer: (evt, tsIso) => {
            // SG-4 revérifiée à l'instant d'écriture, qui devient approval.at (EX-7.11).
            const d = remise.approval.decision;
            if ((d === "approuve" || d === "refuse") && (E === null || !(decoderHorodatage(tsIso) < decoderHorodatage(v.retenue.ts) + E))) {
              throw new ErreurConstruction("echeance_depassee", []);
            }
            evt.approval.at = tsIso;
          },
          avantAjout: (evt) => this.approbations.inscrireDecision({ ticket: remise.ticket, seq: evt.seq, hash: evt.hash, approver_set: remise.approver_set }),
        },
      );
    } catch (err) {
      if (err instanceof ErreurConstruction && err.message === "echeance_depassee") return refuser("SG-4", "echeance_depassee");
      return envoyer({ ...acq, result: "temporaire", reason: "mode_degrade" });
    }
    // `held` constaté et requête retenue réclamée dans le même tour (EX-7.19 pas 3) ;
    // `consommer` du relais attend la fin de cet `acquitter`.
    const held = typeof o.held === "boolean" ? o.held : this._reclamerRetention(remise.ticket, e);
    if (typeof o.held === "boolean") this._decidee(remise.ticket, e);
    this._acquittements ??= new Map();
    const envoi = envoyer({ ...acq, result: "scelle", seq: e.seq, hash: e.hash, at: e.approval.at, decision: e.approval.decision, held, approval: e.approval });
    this._acquittements.set(remise.ticket, envoi);
    try {
      return await envoi;
    } finally {
      if (this._acquittements.get(remise.ticket) === envoi) this._acquittements.delete(remise.ticket);
    }
  }

  /**
   * Expiration par le noyau seul (EX-9.4) des tickets sans décision dont
   * l'échéance plus `timeout_ms` est passée ; annonce par `expiration`.
   * @returns {Promise<object[]>} décisions scellées
   */
  async expirerTickets() {
    this._bloquerSiIntervention();
    const maintenant = this.horlogeBrute.murale();
    const scellees = [];
    for (const [ticket] of this.index.retenues) {
      const echue = (retenue) => {
        // E de la version de la `retenue` ; politique introuvable : borne de E (lui-meme.mjs).
        const E = delaiExpiration(this.politiquesParVersion.get(retenue.code.policy_version) ?? null);
        return maintenant >= echeanceExpiration(retenue, E, this.config.policy.approval.timeout_ms);
      };
      const r0 = this.index.retenueSansDecision(ticket);
      if (!r0 || !echue(r0)) continue;
      // SG-3 : vérifiée de nouveau sous le verrou du ticket, après toute remise en cours.
      const e = await this._sousVerrouTicket(ticket, async () => {
        const retenue = this.index.retenueSansDecision(ticket);
        if (!retenue || !echue(retenue)) return null;
        const x = approvalExpiration(ticket, retenue, this.approbations);
        if (!x) return null;
        if (this.degrade.enModeDegrade) {
          this.journal.consigner("warning", "politique", "approval_expired_deferred", {});
          return null;
        }
        return this.ecrivain.sceller(
          partielDecision({ retenue, approval: x.approval, policy_version: this.versionPolitique, recorder: VERSION_ENREGISTREUR, org_id: this.org_id, journal_id: this.journal_id }),
          {
            completer: (evt, tsIso) => {
              evt.approval.at = tsIso;
            },
            avantAjout: (evt) => this.approbations.inscrireDecision({ ticket, seq: evt.seq, hash: evt.hash, approver_set: x.approver_set }),
          },
        );
      });
      if (!e) continue;
      scellees.push(e);
      this._decidee(ticket, e);
      this._annoncerExpiration(ticket, e);
    }
    return scellees;
  }

  /** `expiration` (EX-9.4, CT-3 EX-12.11) : réessayé jusqu'à une réponse du service (CT-3 12.7). */
  _annoncerExpiration(ticket, e) {
    if (!this.service) return;
    const requete = { ticket, seq: e.seq, hash: e.hash, at: e.approval.at, approval: e.approval };
    this._jusquAuSucces(`expiration:${ticket}`, async () => {
      try {
        const r = await this.service.expiration(requete);
        this.journal.consigner("info", "politique", "approval_expiration_sent", { state: r?.state ?? null }, { seq: e.seq });
        return true;
      } catch (err) {
        if (err instanceof ErreurServiceApprobation && RAISONS_SERVICE.has(err.code)) {
          this.journal.consigner("warning", "politique", "approval_expiration_refused", { code: err.code }, { seq: e.seq });
          return true;
        }
        return false;
      }
    });
  }

  // ------------------------------------------------------------ rotation, clôture

  /**
   * Rotation de clé (EX-11.15, EX-11.16) vers une clé que le signataire
   * détient ; la nouvelle paire est inscrite au registre avant (CT-4, lot
   * suivant).
   * @param {string} nouvelleCle
   * @returns {Promise<object>}
   */
  async tournerCle(nouvelleCle) {
    this._bloquerSiIntervention();
    await this.signataire.clePublique(nouvelleCle);
    const e = await this.ecrivain.tournerCle({ nouvelleCle, policy_version: this.versionPolitique });
    this.journal.consigner("info", "signataire", "key_rotated", { old_key_id: e.recorder_key_id, new_key_id: nouvelleCle }, { seq: e.seq });
    return e;
  }

  /**
   * Minuteur : points de contrôle alignés, clôtures échues, sortie du mode
   * dégradé « stockage » et scellement des événements en attente (EX-14.10),
   * expirations par le noyau seul.
   */
  async tic() {
    if (this.intervention || !this.ecrivain) return;
    // EX-13.10 (3) : croissance d'un fichier d'époque inférieure (fourche).
    await this.fourche?.controler().catch(() => {});
    if (this.degrade.enModeDegrade) this.politique.noterExpirationsDifferees();
    if (this.degrade.actif("horloge")) this._sortirHorloge();
    if (this.degrade.actif("cle")) {
      // Sortie du mode « clé » : health() réussi et signature de test vérifiée (EX-14.11).
      try {
        if ((await this.signataire.sante()) === "ok") {
          await this.signataire.signatureDeTest(this.ecrivain.cleCourante);
          this.degrade.sortir("cle");
        }
      } catch {
        return;
      }
    }
    if (this.degrade.actif("stockage")) {
      try {
        await this.ecrivain.reprendreStockage();
      } catch {
        return;
      }
    }
    await this.ecrivain.tic().catch(() => {});
    // La raison « attente » se lève en vidant la file (EX-14.9, EX-14.10) : elle n'empêche pas le scellement.
    if (this.degrade.raisons().every((r) => r === "attente") && this.attente.length) await this.viderAttente();
    // Expirations par le noyau seul (EX-9.4), après les événements en attente (EX-9.8) ;
    // en mode dégradé, différées et consignées (approval_expired_deferred).
    if (!this.degrade.enModeDegrade) await this.expirerTickets().catch(() => {});
  }

  /**
   * Sortie du mode dégradé « horloge » au tic (EX-7.9, EX-7.13, EX-14.11) :
   * l'horloge murale a rejoint le `ts` précédent et, après un saut en avant,
   * est revenue dans la tolérance de l'avance monotone. Sans ce contrôle, la
   * sortie n'était constatée qu'au scellement suivant, qu'aucun appel bloqué,
   * aucune remise (acquittée `temporaire`) et aucune expiration (différée)
   * ne pouvait produire.
   */
  _sortirHorloge() {
    const h = this.horloge;
    const lu = this.horlogeBrute.murale();
    const mono = this.horlogeBrute.monotone();
    const precedent = this.ecrivain.lastTs ?? null;
    if (precedent !== null && lu < precedent) return;
    if (h.saut && h.dernierLu !== null && h.dernierMonotone !== null && lu - h.dernierLu > mono - h.dernierMonotone + h.reglages.max_forward_ms) return;
    h.saut = false;
    this.degrade.sortir("horloge");
  }

  // ------------------------------------------------------------ attente (14.5)

  /**
   * Met un événement partiel en attente (EX-14.8, EX-4.46) : file en mémoire
   * et, au mieux, `attente/attente-<epoch>.ndjson`. Bornes d'EX-14.9.
   * @param {object} partiel
   * @param {Piece[]} pieces pièces à écrire au scellement
   * @param {{intent_id?: string|null, captured_at?: number, host?: string|null, genre?: "appel"|"echange"}} [o]
   *   `host` et `genre` : connexion d'hôte et nature de l'événement, gardés en
   *   mémoire seulement, pour inscrire l'événement au registre de
   *   recouvrement quand il est scellé (EX-6.34, lecture 125)
   * @returns {string} pending_id
   */
  mettreEnAttente(partiel, pieces, o = {}) {
    const f = this.config.policy.failure ?? {};
    const maxEvenements = f.pending_max_events ?? 10000;
    const maxOctets = this.config.limits.pending_max_bytes ?? 268435456;
    const octets = this.attente.reduce((s, x) => s + x.pieces.reduce((t, p) => t + p.octets.length, 0), 0);
    if (this.attente.length >= maxEvenements || octets >= maxOctets) {
      this.degrade.entrer("attente");
      this.journal.consigner("error", "noyau", "pending_limit_reached", { events: this.attente.length });
      throw new ErreurEnregistreur("attente", "noortrace: enregistreur en mode degrade (attente)");
    }
    this.compteurAttente++;
    const pending_id = `p-${String(this.ecrivain?.epoque ?? 0).padStart(20, "0")}-${String(this.compteurAttente).padStart(12, "0")}`;
    const captured_at = o.captured_at ?? this.horlogeBrute.murale();
    this.attente.push({ pending_id, captured_at, partiel, pieces, intent_id: o.intent_id ?? null, host: o.host ?? null, genre: o.genre ?? "appel" });
    this.metriques.jauge("noortrace_pending_events", {}, this.attente.length);
    this._ecrireAttente({ pending_id, captured_at: ecrireHorodatage(captured_at), event: partiel, pieces: pieces.map((p) => p.sha256), intent_id: o.intent_id ?? null });
    return pending_id;
  }

  async _ecrireAttente(ligne) {
    try {
      const dir = path.join(this.repertoire, "attente");
      await creerRepertoire(dir);
      // EX-13.5 (1) : aucun fichier d'attente sous une époque supérieure présente.
      await verifierEpoqueOuverture(this.repertoire, "attente", this.ecrivain.epoque);
      const f = await FichierAjout.ouvrir(path.join(dir, `attente-${String(this.ecrivain.epoque).padStart(20, "0")}.ndjson`), { creer: true, existantAdmis: true });
      const o = jcsIntegralOctets(ligne);
      const l = new Uint8Array(o.length + 1);
      l.set(o);
      l[o.length] = 10;
      await f.ajouter(l);
      await f.synchroniser().catch(() => {});
      await f.fermer();
    } catch {
      // au mieux (EX-14.8) : le stockage est précisément ce qui est en panne
    }
  }

  /**
   * Scelle les événements en attente (EX-14.10), dans l'ordre de
   * `captured_at`, `ts = max(captured_at, ts précédent)`.
   */
  async viderAttente() {
    const liste = this.attente.splice(0).sort((x, y) => x.captured_at - y.captured_at);
    let n = 0;
    let maxDelai = 0;
    for (const x of liste) {
      try {
        let partiel = x.partiel;
        const manquantes = [];
        for (const p of x.pieces) {
          try {
            await this.pieces.ecrire(p);
          } catch {
            manquantes.push(p);
          }
        }
        if (manquantes.length) {
          const perdue = pieceAttentePerdue(x.pending_id);
          await this.pieces.ecrire(perdue);
          partiel = { ...partiel, execution: { ...partiel.execution, result: perdue.reference, is_error: true } };
        }
        const e = await this.ecrivain.sceller(partiel, { captureA: x.captured_at, leverIntention: x.intent_id ?? undefined, sorteMetrique: "attente" });
        // Scellé depuis l'attente, démon en marche : inscrit au registre de
        // recouvrement comme tout appel ou échange scellé (EX-6.34, lecture 125).
        if (x.host) this._notifierScelle({ genre: x.genre, host: x.host, appel: null, evenement: e });
        n++;
        maxDelai = Math.max(maxDelai, this.horlogeBrute.murale() - x.captured_at);
      } catch {
        this.attente.unshift(x);
        break;
      }
    }
    this.metriques.jauge("noortrace_pending_events", {}, this.attente.length);
    if (n) this.journal.consigner("info", "noyau", "pending_flushed", { count: n, max_delay_ms: maxDelai });
    if (!this.attente.length) this.degrade.sortir("attente");
  }

  /**
   * Événements en attente d'un arrêt précédent (EX-9.8 pas 3, EX-14.10),
   * scellés une seule fois. Le fichier d'attente n'est supprimé qu'après le
   * scellement : un arrêt entre les deux, ou un événement déjà scellé depuis
   * la file en mémoire (sortie du mode dégradé sans redémarrage, dont la ligne
   * reste au fichier), laisse au fichier une ligne dont l'événement est déjà
   * dans la chaîne. Chaque ligne est donc d'abord cherchée dans la chaîne
   * durable (relecture d'EX-12.10) : l'événement scellé depuis l'attente porte
   * les huit champs de l'événement partiel de la ligne (ou le résultat perdu
   * d'EX-14.10) ; s'il a une intention, c'est l'événement que désigne sa
   * levée, ou à défaut un événement de `ts` au moins égal à `written_at` ;
   * sans intention, son `ts` vaut `max(captured_at, ts précédent)` (ou le
   * début de période qui suit une clôture). Une ligne retrouvée n'est pas
   * scellée de nouveau ; son intention est levée si elle ne l'est pas.
   * @param {number} epoque
   * @param {object} etat état relu (`evenements`)
   */
  async _reprendreAttente(epoque, etat = { evenements: [] }) {
    const dir = path.join(this.repertoire, "attente");
    let noms = [];
    try {
      noms = (await fs.readdir(dir)).filter((n) => /^attente-[0-9]{20}\.ndjson$/.test(n)).sort();
    } catch {
      return;
    }
    const lignes = [];
    for (const nom of noms) {
      if (Number(nom.slice(8, 28)) >= epoque) continue;
      for (const l of decouperLignes(new Uint8Array(await fs.readFile(path.join(dir, nom))))) {
        if (!l.complete) continue;
        try {
          lignes.push(analyserJsonIntegral(l.octets));
        } catch {
          // ligne illisible d'un fichier au mieux : ignorée
        }
      }
    }
    lignes.sort((a, b) => decoderHorodatage(a.captured_at) - decoderHorodatage(b.captured_at));
    const chaine = etat.evenements ?? [];
    const parSeq = new Map(chaine.map((e) => [e.seq, e]));
    const pris = new Set();
    const intentions = this._intentionsRelues ?? { intentions: [], levees: new Map() };
    const ecritesA = new Map(intentions.intentions.map((i) => [i.intention.intent_id, decoderHorodatage(i.intention.written_at)]));
    const huit = (e) => jcsIntegral({ delegation: e.delegation, code: e.code, intent: e.intent, policy: e.policy, approval: e.approval, execution: e.execution, effects: e.effects, context: e.context });
    let n = 0;
    let deja = 0;
    for (const x of lignes) {
      let partiel = x.event;
      const presentes = await Promise.all((x.pieces ?? []).map((s) => existe(this.pieces.chemin(s))));
      const perdue = pieceAttentePerdue(x.pending_id);
      const variante = { ...partiel, execution: { ...partiel.execution, result: perdue.reference, is_error: true } };
      if (presentes.some((p) => !p)) partiel = variante;
      const formes = new Set([huit(x.event), huit(variante)]);
      const capture = decoderHorodatage(x.captured_at);
      const conforme = (e) => !pris.has(e.seq) && formes.has(huit(e));
      let trouve = null;
      if (x.intent_id) {
        const s = intentions.levees.get(x.intent_id);
        if (typeof s === "number" && parSeq.get(s) && conforme(parSeq.get(s))) trouve = parSeq.get(s);
        const designes = new Set(intentions.levees.values());
        const ecrite = ecritesA.get(x.intent_id) ?? capture;
        trouve ??= chaine.find((e) => !designes.has(e.seq) && conforme(e) && decoderHorodatage(e.ts) >= ecrite) ?? null;
      } else {
        trouve = chaine.find((e) => {
          if (!conforme(e)) return false;
          const ts = decoderHorodatage(e.ts);
          const prec = parSeq.get(e.seq - 1);
          const attendu = Math.max(capture, prec ? decoderHorodatage(prec.ts) : capture);
          return ts === attendu || (ts > attendu && ts % 3600000 === 0);
        }) ?? null;
      }
      if (trouve) {
        pris.add(trouve.seq);
        deja++;
        if (x.intent_id && intentions.levees.get(x.intent_id) !== trouve.seq) await this.ecrivain.lever(x.intent_id, trouve.seq);
        this.journal.consigner("info", "noyau", "pending_already_sealed", { pending_id: x.pending_id }, { seq: trouve.seq });
        continue;
      }
      if (partiel === variante) await this.pieces.ecrire(perdue);
      await this.ecrivain.sceller(partiel, { captureA: capture, leverIntention: x.intent_id ?? undefined, sorteMetrique: "attente" });
      n++;
    }
    for (const nom of noms) if (Number(nom.slice(8, 28)) < epoque) await fs.rm(path.join(dir, nom), { force: true });
    if (n) this.journal.consigner("info", "noyau", "pending_flushed", { count: n });
  }

  // ------------------------------------------------------------ reprise des intentions

  _hote(id) {
    return [...(this.config.mcp.hosts ?? []), ...(this.config.sdk.hosts ?? [])].find((h) => h.id === id) ?? null;
  }

  /**
   * Événement partiel de reprise (EX-12.14 pas 2), commun à la reprise au
   * démarrage et à la reprise à chaud du SDK (EX-12.15, lecture 117).
   * @param {{intention: object, sha256: string, contexte: object|null}} entree
   * @param {{reference: object}} piece pièce « résultat » de reprise
   */
  _partielReprise(entree, piece) {
    return partielReprise(entree, {
      index: this.index,
      hote: (id) => this._hote(id),
      classe: (t) => this._classe(t),
      origine: (t) => this._origine(t),
      nomRedaction: this.nomRedaction,
      recorder: VERSION_ENREGISTREUR,
      resultat: piece.reference,
    });
  }

  _origine(tool) {
    // Outil déclaré par le SDK : préfixe `<alias>__` d'une entrée de sdk.hosts
    // (EX-6.6), quel que soit `tools.prefix`.
    for (const h of this.config.sdk?.hosts ?? []) {
      if (typeof h.alias === "string" && tool.startsWith(`${h.alias}__`)) return { alias: h.alias, nom: tool.slice(h.alias.length + 2) };
    }
    const serveurs = Object.keys(this.config.policy.servers ?? {});
    if (this.config.tools.prefix === false && serveurs.length === 1) return { alias: serveurs[0], nom: tool };
    const k = tool.indexOf("__");
    return k > 0 ? { alias: tool.slice(0, k), nom: tool.slice(k + 2) } : { alias: serveurs[0] ?? "inconnu", nom: tool };
  }

  _classe(tool) {
    // Outil du SDK : aucune classe configurée (lecture 111) et la classe
    // déclarée n'est pas dans le journal d'intention (EX-12.12) : « à défaut
    // ecriture » (table de 6.2, debutAppel) ; un alias du SDK n'est jamais un
    // alias de serveur (EX-6.6), d'où `ecriture` ci-dessous.
    const o = this._origine(tool);
    const s = this.config.policy.servers?.[o.alias];
    return s?.tools?.[o.nom]?.class ?? s?.class_default ?? "ecriture";
  }

  async _intentionsEnAttente() {
    const ids = new Set();
    const dir = path.join(this.repertoire, "attente");
    let noms = [];
    try {
      noms = (await fs.readdir(dir)).filter((n) => /^attente-[0-9]{20}\.ndjson$/.test(n));
    } catch {
      return ids;
    }
    for (const nom of noms) {
      for (const l of decouperLignes(new Uint8Array(await fs.readFile(path.join(dir, nom))))) {
        try {
          const o = analyserJsonIntegral(l.octets);
          if (typeof o?.intent_id === "string") ids.add(o.intent_id);
        } catch {
          // ligne illisible d'un fichier au mieux
        }
      }
    }
    return ids;
  }

  async _reprendreIntentions(etat) {
    let r;
    try {
      r = await relireIntentions(path.join(this.repertoire, "intentions"));
    } catch (e) {
      if (e instanceof ErreurIntentions) {
        this.journal.consigner("error", "stockage", "intention_corrompue", { fichier: path.basename(e.fichier), ligne: e.ligne });
        this.degrade.entrer("stockage", { event: "intention_corrompue" });
        this.intervention = e;
        return;
      }
      throw e;
    }
    this._intentionsRelues = r;
    // Une intention dont l'événement complet est gardé dans un fichier
    // d'attente est scellée au pas 3, à la place d'un événement de reprise
    // (14.2, « Panne après relais », EX-4.46).
    const enAttente = await this._intentionsEnAttente();
    const leveesOuAttente = new Map(r.levees);
    for (const id of enAttente) if (!leveesOuAttente.has(id)) leveesOuAttente.set(id, null);
    const plan = planifierReprise(r.intentions, leveesOuAttente, etat.evenements);
    for (const p of plan) {
      if (p.candidat) {
        await this.ecrivain.lever(p.intentId, p.candidat.seq);
        this.journal.consigner("info", "noyau", "intention_levee_implicite", { intent_id: p.intentId }, { seq: p.candidat.seq });
        continue;
      }
      const piece = pieceReprise(p.entree.sha256);
      await this.pieces.ecrire(piece);
      const { partiel, note } = this._partielReprise(p.entree, piece);
      if (!partiel) {
        this.journal.consigner("error", "stockage", "intention_irreconstructible", { intent_id: p.intentId });
        this.degrade.entrer("stockage", { event: "intention_irreconstructible" });
        this.intervention = new Error("intention_irreconstructible");
        return;
      }
      if (note) this.journal.consigner("warning", "noyau", note, { intent_id: p.intentId });
      const e = await this.ecrivain.sceller(partiel, { leverIntention: p.intentId, sorteMetrique: "reprise" });
      this.journal.consigner("info", "noyau", "intent_recovered", { intent_id: p.intentId, written_at: p.entree.intention.written_at }, { seq: e.seq });
    }
    // Rotation des fichiers d'intention (EX-12.13) : un fichier d'une époque
    // antérieure dont toutes les intentions sont levées est supprimé.
    const levees = new Set([...r.levees.keys(), ...plan.map((p) => p.intentId)]);
    for (const f of r.fichiers) {
      if (f.epoch >= this.ecrivain.epoque) continue;
      const toutes = r.intentions.filter((i) => i.fichier === f.chemin).every((i) => levees.has(i.intention.intent_id));
      if (!toutes) continue;
      // Avec storage.seal.append_only_attribute, le compagnon a posé `a` sur ce
      // fichier (CT-2 EX-12.18) : il ne peut plus être supprimé ; il est gardé.
      await fs.unlink(f.chemin).catch((e) => {
        if (e.code === "ENOENT") return;
        if (e.code !== "EPERM") throw e;
        this.journal.consigner("warning", "stockage", "intention_file_kept", { fichier: path.basename(f.chemin), raison: "append_only" });
      });
    }
  }

  // ------------------------------------------------------------ dossier, arrêt

  /**
   * Exporte le dossier CT-1 d'un événement (période close).
   * @param {number} seq
   * @param {string} destination
   * @returns {Promise<object>} l'index dossier.json
   */
  async exporterDossier(seq, destination) {
    const { dossier } = await exporterDossier({
      repertoire: this.repertoire,
      seq,
      destination,
      generated_at: this.horlogeBrute.murale(),
      clePublique: (id) => this.signataire.clePubliqueHex(id),
      jeuDecision: (d) => this.approbations.jeuDecision(d),
    });
    return dossier;
  }

  /** Arrêt propre : file vidée, fichiers fermés, bail libéré, graines effacées. */
  async arreter() {
    this.arrete = true;
    this.reveilAttente?.();
    this.o.worm?.arreter?.();
    this.controles?.arreter();
    this.politique?.arreter();
    for (const t of this.minuteurs) clearInterval(t);
    if (this.serveur) await new Promise((r) => this.serveur.close(() => r()));
    if (this.ecrivain) await this.ecrivain.fermer().catch(() => {});
    await this.approbations?.fermer();
    await this.bail?.liberer();
    this.bailDetenu = false;
    this.signataire?.backend?.effacer?.();
    this.journal.consigner("info", "noyau", "shutdown", {});
  }
}
