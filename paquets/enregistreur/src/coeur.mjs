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
import { MagasinBailFichier } from "./bail.mjs";
import { MagasinPieces, empreintePolitique, piecePolitique, pieceReprise, pieceAttentePerdue, Piece } from "./pieces.mjs";
import { ecrireAtomique, existe, creerRepertoire, FichierAjout, decouperLignes } from "./fichiers.mjs";
import { relireJournal, planifierReprise, partielReprise, ErreurRelecture } from "./reprise.mjs";
import { relireIntentions, ErreurIntentions } from "./intentions.mjs";
import { Ecrivain } from "./ecrivain.mjs";
import { partielAppelOutil, partielDecision, partielEchange, partielPolitique, repriseDeRetenue } from "./capture.mjs";
import { evaluerEffets } from "./effets.mjs";
import {
  FichiersApprobations, ErreurServiceApprobation, approvalExpiration, delaiExpiration, macRelais, validerReponseEvaluer,
  verifierRelais, verifierRemise,
} from "./approbations.mjs";
import { decisionPolitique, echeanceExpiration } from "./lui-meme.mjs";
import { exporterDossier } from "./dossier.mjs";
import { jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { validerConfiguration, resoudreSecrets, differencesHorsPolitique } from "./configuration.mjs";

/** Version du logiciel (`code.recorder`, `serverInfo`). */
export const VERSION_ENREGISTREUR = "0.1.0";

const sansPrefixe = (h) => h.slice(2);

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
   * @param {{redigerMotif?: (motif: string|null) => string|null,
   *   executerExtract?: (motif: string, texte: string) => string|null}} [o.redaction] crochets du lot de rédaction
   * @returns {Promise<Coeur>}
   */
  static async demarrer(o) {
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
    this.bail = this.o.bail ?? (cfg.lease.store.type === "file" ? new MagasinBailFichier(cfg.lease.store.path) : null);
    if (!this.bail) throw new ErreurEnregistreur("bail", `magasin de bail ${cfg.lease.store.type} non fourni par ce lot du démon`);
    const epoque = await this.bail.acquerir();
    this.bailDetenu = true;
    this.metriques.jauge("noortrace_lease_epoch", {}, epoque);
    this.journal.consigner("info", "bail", "lease_acquired", { epoch: epoque, store: this.bail.type });

    this.pieces = new MagasinPieces(this.repertoire, { minOctetsLibres: cfg.storage.min_free_bytes });
    let etat;
    try {
      etat = await relireJournal(this.repertoire, {
        clePublique: (id) => this.signataire.clePublique(id),
        journal: this.journal,
        intervalle: cfg.checkpoint_interval_s,
      });
    } catch (e) {
      if (!(e instanceof ErreurRelecture)) throw e;
      this.degrade.entrer("stockage", { event: e.evenement });
      this.intervention = e;
      this.pret = true;
      await this._servirSupervision();
      return;
    }
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
        } catch {
          // pièce illisible : la version reste sans document
        }
      }
    }

    // EX-9.8 (2) : intentions restées ouvertes.
    await this._reprendreIntentions(etat);
    // EX-9.8 (3) : événements en attente d'un arrêt précédent.
    await this._reprendreAttente(epoque);
    // EX-9.8 (4) : événement de politique.
    await this._annoncerPolitique(cfg.policy);

    // Pas 6 (suite) : charger, ouvrir, consommer.
    if (this.service) {
      this._charger();
      for (const [ticket] of this.index.retenues) {
        const r = this.index.retenueSansDecision(ticket);
        if (r) this._ouvrir(r).catch(() => {});
      }
      for (const [ticket, e] of this.index.premiersExecutes) this._consommer(ticket, e);
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

  async _servirSupervision() {
    if (!this.o.supervision) return;
    const [hote, port] = this.config.supervision.health_listen.split(/:(?=[0-9]+$)/);
    this.serveur = await servirSupervision({
      adresse: hote.replace(/^\[|\]$/g, ""),
      port: Number(port),
      etat: () => this.etatSante(),
      pret: () => this.pret && this.bailDetenu,
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
    if (this.service) {
      const boucle = async () => {
        while (!this.arrete) {
          try {
            await this.traiterRemises({ wait_ms: 25000 });
          } catch {
            await new Promise((r) => setTimeout(r, 1000));
          }
        }
      };
      boucle();
    }
  }

  /** État de santé (EX-17.1). */
  etatSante() {
    const d = this.degrade.depuis();
    return {
      bailDetenu: this.bailDetenu && this.bail?.valide?.() !== false,
      raisons: this.degrade.raisons(),
      depuis: d === null ? null : ecrireHorodatage(d),
      cleIndisponible: this.degrade.actif("cle"),
    };
  }

  /** Corps de `/healthz`. */
  sante() {
    return sante(this.etatSante());
  }

  _bloquerSiIntervention() {
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
    const v = validerConfiguration(octets);
    if (v.pas) return refus("configuration_invalide", { erreurs: v.erreurs.length });
    const s = resoudreSecrets(v.config, contexte);
    if (s.erreurs.length) return refus("secrets", { erreurs: s.erreurs.length });
    if (this.degrade.enModeDegrade) return refus("mode_degrade");
    const diff = differencesHorsPolitique(this.config, v.config);
    if (diff.length) return refus("redemarrage_requis", { pointeurs: diff });
    if (v.config.policy.version === this.config.policy.version) return refus("version_inchangee");
    const e = await this._annoncerPolitique(v.config.policy);
    this.config = { ...this.config, policy: v.config.policy };
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
  scellerEchange(c) {
    this._bloquerSiIntervention();
    return this.ecrivain.sceller(
      partielEchange({
        ...c,
        code: { ...c.code, policy_version: c.policy_version ?? this.versionPolitique, recorder: VERSION_ENREGISTREUR },
        nomRedaction: this.nomRedaction,
      }),
    );
  }

  /**
   * Scelle un événement partiel déjà construit par un frontal selon sa
   * table (ingestion OpenTelemetry, EX-6.36) ; pièces déjà écrites.
   * @param {object} partiel les huit champs de CT-1 §5.3
   * @returns {Promise<object>}
   */
  scellerPartiel(partiel) {
    this._bloquerSiIntervention();
    return this.ecrivain.sceller(partiel);
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
    if (!this.service) throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation indisponible");
    let r;
    for (let essai = 0; essai < 2; essai++) {
      try {
        r = await this.service.evaluer(requete);
        break;
      } catch (e) {
        if (e instanceof ErreurServiceApprobation && e.code === "politique_inconnue" && essai === 0) {
          await this._charger(true).catch(() => {});
          continue;
        }
        this.journal.consigner("warning", "politique", "approval_service_unavailable", { code: e?.code ?? "indisponible" });
        throw new ErreurEnregistreur("approbation", "noortrace: service d'approbation indisponible", { cause: e });
      }
    }
    const v = validerReponseEvaluer(r, { decisionScellee: (t) => this._decisionScellee(t) });
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
    if (!this.service) return;
    const pol = this.config.policy;
    const emp = empreintePolitique(pol);
    const { service, ...approval } = pol.approval;
    void service;
    const outils = [...(this.outils ?? [])].sort((a, b) => (a.tool_announced < b.tool_announced ? -1 : a.tool_announced > b.tool_announced ? 1 : 0));
    const requesters = [...new Set([...(this.config.mcp.hosts ?? []), ...(this.config.sdk.hosts ?? [])].map((h) => h.launched_by).filter((l) => !l.includes("${")))].sort();
    const p = this.service
      .charger({ org_id: this.org_id, journal_id: this.journal_id, environment: this.config.recorder.environment, policy_version: emp.policy_version, policy_sha256: emp.policy_sha256, approval, tools: outils, requesters })
      .then((r) => {
        if (r.policy_version !== emp.policy_version || r.policy_sha256 !== emp.policy_sha256) throw new Error("charger : version ou empreinte différente");
        this.candidats = { envoyes: new Set(outils.map((t) => t.tool_announced)), liste: new Set(r.approval_candidates) };
        this.journal.consigner("info", "politique", "approval_candidates", { candidates: r.approval_candidates });
      })
      .catch((e) => this.journal.consigner("warning", "politique", "approval_service_unavailable", { message: "charger", code: e?.code ?? null }));
    if (attendreReponse) await p;
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

  async _ouvrir(retenue) {
    if (!this.service) return;
    const octets = await this.pieces.lire(retenue.execution.arguments.sha256);
    for (let essai = 0; essai < 5; essai++) {
      try {
        const r = await this.service.ouvrir({
          ticket: retenue.policy.ticket,
          request_hash: retenue.hash,
          request_seq: retenue.seq,
          request_ts: retenue.ts,
          request_event: retenue,
          arguments_piece: octets ? encoderBase64(octets) : null,
        });
        this.journal.consigner("info", "politique", "approval_opened", { state: r.state ?? null }, { seq: retenue.seq });
        return;
      } catch (e) {
        if (e instanceof ErreurServiceApprobation && e.code === "ticket_deja_ouvert") return;
        if (e instanceof ErreurServiceApprobation && e.code === "ticket_inconnu") return;
        await new Promise((r) => setTimeout(r, 50 * (essai + 1)));
      }
    }
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
    if (appel.class === "ecriture" || ticket) {
      try {
        intention = await this.ecrivain.inscrireIntention(
          { upstream_id: o.upstream_id, host: appel.host.id, tool: appel.tool_announced, arguments: appel.arguments, ticket },
          { ...base, effects: o.effetsDeclares ?? [] },
        );
      } catch (e) {
        if (ticket) this.relaisEnCours.delete(ticket);
        throw e;
      }
    }
    return { appel: a, fixe, ticket, intention, debut: this.horlogeBrute.monotone() };
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
      : evaluerEffets({
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
      if (relais.ticket) {
        this.relaisEnCours.delete(relais.ticket);
        if (this.index.premiersExecutes.get(relais.ticket)?.seq === e.seq) this._consommer(relais.ticket, e);
      }
      return e;
    } catch (err) {
      if (relais.ticket) this.relaisEnCours.delete(relais.ticket);
      if (err instanceof ErreurEnregistreur || err instanceof ErreurConstruction) {
        this.mettreEnAttente(partiel, [r.resultat], { intent_id: relais.intention?.intent_id ?? null });
        this.metriques.compter("noortrace_calls_executed_not_durable_total", { class: a.class });
        this.journal.consigner("error", "noyau", "call_executed_not_durable", { intent_id: relais.intention?.intent_id ?? null });
        throw new ErreurEnregistreur(err.raison ?? "stockage", "noortrace: appel execute, evenement non durable", { code: -31017, cause: err });
      }
      throw err;
    }
  }

  _consommer(ticket, e) {
    if (!this.service) return;
    const essayer = async (n) => {
      try {
        const r = await this.service.consommer({ ticket, seq: e.seq, hash: e.hash });
        this.journal.consigner("info", "politique", "approval_consume_final", { state: r.state }, { seq: e.seq });
      } catch (err) {
        if (err instanceof ErreurServiceApprobation && ["requete_invalide", "ticket_inconnu"].includes(err.code)) {
          this.journal.consigner("info", "politique", "approval_consume_final", { raison: err.code }, { seq: e.seq });
          return;
        }
        if (n < 5) setTimeout(() => essayer(n + 1), 200 * (n + 1)).unref?.();
      }
    };
    essayer(0);
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
    for (const remise of r.remises ?? []) sortie.push(await this.traiterRemise(remise));
    return sortie;
  }

  /**
   * Traite une remise (EX-7.19 pas 1 à 3).
   * @param {object} remise
   * @param {{held?: boolean}} [o] le frontal retient une requête de ce ticket (EX-4.50)
   * @returns {Promise<object>} la requête `acquitter` envoyée
   */
  async traiterRemise(remise, o = {}) {
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
    try {
      await this.approbations.inscrireRemise(remise);
    } catch {
      this.degrade.entrer("stockage");
      return envoyer({ ...acq, result: "temporaire", reason: "mode_degrade" });
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
    const motif = this.o.redaction?.redigerMotif ? this.o.redaction.redigerMotif(remise.approval.reason) : remise.approval.reason;
    let e;
    try {
      e = await this.ecrivain.sceller(
        partielDecision({ retenue: v.retenue, approval: { ...remise.approval, reason: motif }, policy_version: this.versionPolitique, recorder: VERSION_ENREGISTREUR, org_id: this.org_id, journal_id: this.journal_id }),
        {
          completer: (evt, tsIso) => {
            // SG-4 revérifiée à l'instant d'écriture, qui devient approval.at (EX-7.11).
            const d = remise.approval.decision;
            if ((d === "approuve" || d === "refuse") && E !== null && !(decoderHorodatage(tsIso) < decoderHorodatage(v.retenue.ts) + E)) {
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
    return envoyer({ ...acq, result: "scelle", seq: e.seq, hash: e.hash, at: e.approval.at, decision: e.approval.decision, held: o.held === true, approval: e.approval });
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
      const retenue = this.index.retenueSansDecision(ticket);
      if (!retenue) continue;
      const E = delaiExpiration(this.politiquesParVersion.get(retenue.code.policy_version) ?? null);
      const echeance = echeanceExpiration(retenue, E, this.config.policy.approval.timeout_ms);
      if (echeance === null || maintenant < echeance) continue;
      const x = approvalExpiration(ticket, retenue, this.approbations);
      if (!x) continue;
      if (this.degrade.enModeDegrade) {
        this.journal.consigner("warning", "politique", "approval_expired_deferred", {});
        continue;
      }
      const e = await this.ecrivain.sceller(
        partielDecision({ retenue, approval: x.approval, policy_version: this.versionPolitique, recorder: VERSION_ENREGISTREUR, org_id: this.org_id, journal_id: this.journal_id }),
        {
          completer: (evt, tsIso) => {
            evt.approval.at = tsIso;
          },
          avantAjout: (evt) => this.approbations.inscrireDecision({ ticket, seq: evt.seq, hash: evt.hash, approver_set: x.approver_set }),
        },
      );
      scellees.push(e);
      this.service?.expiration({ ticket, seq: e.seq, hash: e.hash, at: e.approval.at, approval: e.approval }).catch(() => {});
    }
    return scellees;
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
    if (!this.degrade.enModeDegrade && this.attente.length) await this.viderAttente();
    // Expirations par le noyau seul (EX-9.4), après les événements en attente (EX-9.8).
    if (!this.degrade.enModeDegrade) await this.expirerTickets().catch(() => {});
  }

  // ------------------------------------------------------------ attente (14.5)

  /**
   * Met un événement partiel en attente (EX-14.8, EX-4.46) : file en mémoire
   * et, au mieux, `attente/attente-<epoch>.ndjson`. Bornes d'EX-14.9.
   * @param {object} partiel
   * @param {Piece[]} pieces pièces à écrire au scellement
   * @param {{intent_id?: string|null, captured_at?: number}} [o]
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
    this.attente.push({ pending_id, captured_at, partiel, pieces, intent_id: o.intent_id ?? null });
    this.metriques.jauge("noortrace_pending_events", {}, this.attente.length);
    this._ecrireAttente({ pending_id, captured_at: ecrireHorodatage(captured_at), event: partiel, pieces: pieces.map((p) => p.sha256), intent_id: o.intent_id ?? null });
    return pending_id;
  }

  async _ecrireAttente(ligne) {
    try {
      const dir = path.join(this.repertoire, "attente");
      await creerRepertoire(dir);
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
        await this.ecrivain.sceller(partiel, { captureA: x.captured_at, leverIntention: x.intent_id ?? undefined, sorteMetrique: "attente" });
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

  async _reprendreAttente(epoque) {
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
    for (const x of lignes) {
      let partiel = x.event;
      const presentes = await Promise.all((x.pieces ?? []).map((s) => existe(this.pieces.chemin(s))));
      if (presentes.some((p) => !p)) {
        const perdue = pieceAttentePerdue(x.pending_id);
        await this.pieces.ecrire(perdue);
        partiel = { ...partiel, execution: { ...partiel.execution, result: perdue.reference, is_error: true } };
      }
      await this.ecrivain.sceller(partiel, { captureA: decoderHorodatage(x.captured_at), leverIntention: x.intent_id ?? undefined, sorteMetrique: "attente" });
    }
    for (const nom of noms) if (Number(nom.slice(8, 28)) < epoque) await fs.rm(path.join(dir, nom), { force: true });
    if (lignes.length) this.journal.consigner("info", "noyau", "pending_flushed", { count: lignes.length });
  }

  // ------------------------------------------------------------ reprise des intentions

  _hote(id) {
    return [...(this.config.mcp.hosts ?? []), ...(this.config.sdk.hosts ?? [])].find((h) => h.id === id) ?? null;
  }

  _origine(tool) {
    const serveurs = Object.keys(this.config.policy.servers ?? {});
    if (this.config.tools.prefix === false && serveurs.length === 1) return { alias: serveurs[0], nom: tool };
    const k = tool.indexOf("__");
    return k > 0 ? { alias: tool.slice(0, k), nom: tool.slice(k + 2) } : { alias: serveurs[0] ?? "inconnu", nom: tool };
  }

  _classe(tool) {
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
      const { partiel, note } = partielReprise(p.entree, {
        index: this.index,
        hote: (id) => this._hote(id),
        classe: (t) => this._classe(t),
        origine: (t) => this._origine(t),
        nomRedaction: this.nomRedaction,
        recorder: VERSION_ENREGISTREUR,
        resultat: piece.reference,
      });
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
      if (toutes) await fs.rm(f.chemin, { force: true });
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
