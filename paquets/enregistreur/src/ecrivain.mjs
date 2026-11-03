// Écrivain unique d'un journal (CT-2 §3.4, EX-7.8, §12, §12.10, §13). Il
// sérialise, dans l'ordre d'arrivée : l'attribution de `seq`, `ts` (7.4) et
// `prev_hash`, la validation (EX-7.1), la signature par le signataire
// (EX-11.6), l'ajout au segment, le fdatasync (validation groupée, EX-12.7),
// les lignes du journal d'intention (EX-12.12, EX-12.13), les points de
// contrôle (EX-12.24) et la clôture des périodes. Aucune décision de `seq`
// n'est prise hors de lui. Un appelant ne reçoit l'événement qu'une fois le
// fdatasync qui couvre sa ligne rendu (EX-12.6).

import path from "node:path";
import fs from "node:fs/promises";
import {
  ZERO32, decoderHorodatage, ecrireHorodatage, hacherEvenement, hacherManifeste, hacherPoint, messageRotation,
  messageSignatureEvenement, messageSignatureManifeste, octetsVersHex, NOMS_RESERVES, referencesEvenement,
} from "@noortrace/noyau";
import { envelopper, validerAvantSignature, partielRotation } from "./capture.mjs";
import { ErreurConstruction, ErreurEnregistreur } from "./erreurs.mjs";
import { FichierAjout, creerRepertoire, existe, ecrireAtomique, nettoyerTemporaires, tronquer } from "./fichiers.mjs";
import { enteteSegment, ligneSegment, listerSegments, nomSegment, relireSegment } from "./segments.mjs";
import { idIntention, ligneIntention, nomFichierIntentions, objetContexte, objetIntention, empreinteIntention } from "./intentions.mjs";
import { construireEtSignerManifeste, debutPeriode, nomsManifeste, octetsJsonLisible, nonceAleatoire } from "./periodes.mjs";
import { corpsPointDeControle, instantAligne, ligneSerie, nomSerie, signerPointDeControle } from "./points.mjs";
import { remiseCloture, remisePoint } from "./ancrage.mjs";
import { cleObjetWorm } from "./worm.mjs";
import { verifierEpoqueOuverture } from "./ha/cloture.mjs";

const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Écrivain unique.
 */
export class Ecrivain {
  /**
   * @param {object} o
   * @param {string} o.repertoire répertoire du journal `<root>/<org>/<journal>`
   * @param {string} o.org_id
   * @param {string} o.journal_id
   * @param {string} o.instance_id
   * @param {string} o.recorder version du logiciel
   * @param {import("./signataires.mjs").SignataireVerifie} o.signataire
   * @param {import("./bail.mjs").MagasinBail} o.bail
   * @param {import("./horloge.mjs").ControleurHorloge} o.horloge
   * @param {import("./degrade.mjs").EtatDegrade} o.degrade
   * @param {import("./journal-exploitation.mjs").JournalExploitation} o.journal
   * @param {import("./supervision.mjs").Metriques|null} [o.metriques]
   * @param {import("./index-chaine.mjs").IndexChaine} o.index
   * @param {import("./pieces.mjs").MagasinPieces} o.pieces
   * @param {{group_max_events?: number, group_max_wait_ms?: number}} [o.fsync]
   * @param {number} [o.segment_max_bytes]
   * @param {number} [o.checkpoint_interval_s]
   * @param {() => string} [o.nonce]
   * @param {import("./ancrage.mjs").ComposantAncrage|null} [o.ancrage]
   * @param {import("./worm.mjs").SupportWorm|null} [o.worm]
   * @param {string} [o.prefixeWorm]
   */
  constructor(o) {
    Object.assign(this, {
      repertoire: o.repertoire,
      org_id: o.org_id,
      journal_id: o.journal_id,
      instance_id: o.instance_id,
      recorder: o.recorder,
      signataire: o.signataire,
      bail: o.bail,
      horloge: o.horloge,
      degrade: o.degrade,
      journal: o.journal,
      metriques: o.metriques ?? null,
      index: o.index,
      pieces: o.pieces,
      groupeMax: o.fsync?.group_max_events ?? 64,
      attenteMs: o.fsync?.group_max_wait_ms ?? 5,
      segmentMax: o.segment_max_bytes ?? 268435456,
      intervalle: o.checkpoint_interval_s ?? 60,
      nonce: o.nonce ?? nonceAleatoire,
      ancrage: o.ancrage ?? null,
      worm: o.worm ?? null,
      prefixeWorm: o.prefixeWorm ?? "",
    });
    this.file = [];
    this.pompe = false;
    this.enAttenteSync = [];
    this.leveesEnAttente = [];
    this.segment = null;
    this.intentions = null;
    this.compteurIntention = 0;
    this.ferme = false;
    this.premiereOuverture = true;
  }

  // ------------------------------------------------------------ démarrage

  /**
   * Fixe l'état relu (EX-12.10 pas 4) et l'époque du bail, puis ouvre un
   * nouveau segment et un nouveau fichier d'intention (EX-13.9).
   * @param {object} etat état relu par `relireJournal`
   * @param {number} epoque
   */
  async demarrer(etat, epoque) {
    this.epoque = epoque;
    this.lastSeq = etat.lastSeq;
    this.lastHash = etat.lastHash;
    this.lastTs = etat.lastTs;
    this.cleCourante = etat.cleCourante;
    this.plancher = etat.plancherTs ?? null;
    this.periode = etat.periode;
    this.prevPeriodHash = etat.prevPeriodHash;
    this.serie = etat.serie;
    this.segmentsFermes = [];
    if (etat.epoqueMax !== null && epoque <= etat.epoqueMax) {
      throw new ErreurEnregistreur("bail", "noortrace: epoque du bail non superieure aux segments presents (EX-13.5)");
    }
    await creerRepertoire(path.join(this.repertoire, "segments"));
    await creerRepertoire(path.join(this.repertoire, "intentions"));
    await creerRepertoire(path.join(this.repertoire, "manifestes"));
    await creerRepertoire(path.join(this.repertoire, "points"));
    // Fichiers temporaires d'écritures atomiques interrompues (EX-12.6) : rien
    // de durable ; supprimés avant toute écriture de cette instance.
    let temporaires = await nettoyerTemporaires(this.repertoire);
    temporaires += await nettoyerTemporaires(path.join(this.repertoire, "manifestes"));
    for (const xx of await fs.readdir(path.join(this.repertoire, "pieces")).catch(() => [])) {
      temporaires += await nettoyerTemporaires(path.join(this.repertoire, "pieces", xx));
    }
    if (temporaires) this.journal.consigner("info", "stockage", "temporary_files_removed", { count: temporaires });
    if (etat.dernierSegment) {
      // Le dernier segment de l'instance précédente est fermé par sa seule
      // existence (EX-13.9) : il est copié comme un segment fermé (EX-12.16).
      this.segmentsFermes.push(etat.dernierSegment);
      this._copierWorm(`segments/${etat.dernierSegment}`, "segment");
    }
    // Clôtures incomplètes (manifeste écrit, signature absente : arrêt brutal
    // entre les deux écritures) : complétées avant toute nouvelle écriture.
    for (const x of etat.manifestesSansSignature ?? []) await this._completerCloture(x.manifeste);
    await this._ouvrirSegment(this.lastSeq + 1);
    // EX-13.5 (1) : aucun fichier d'intention sous une époque supérieure présente (lot HA).
    await verifierEpoqueOuverture(this.repertoire, "intentions", epoque);
    this.intentions = await FichierAjout.ouvrir(path.join(this.repertoire, "intentions", nomFichierIntentions(epoque)), {
      creer: true,
      existantAdmis: true,
    });
  }

  /**
   * Complète la clôture d'une période dont le manifeste a été écrit sans sa
   * signature (CT-1 §10.2 ; contrôle P-5) : la signature est calculée sur les
   * octets du manifeste présent, par la clé qu'il nomme, puis écrite ; la
   * remise au composant d'ancrage (EX-12.27, CT-5 §8) et les copies WORM du
   * manifeste, de la signature et de la série (EX-12.16) sont refaites, comme
   * à la clôture. Le manifeste a été contrôlé contre la chaîne par la
   * relecture (`relireJournal`).
   * @param {object} manifeste
   */
  async _completerCloture(manifeste) {
    const P = manifeste.period_start;
    const noms = nomsManifeste(P);
    const dir = path.join(this.repertoire, "manifestes");
    this._verifierBail();
    const sig = await this.signataire.signer(manifeste.recorder_key_id, messageSignatureManifeste(manifeste));
    const periodHash = hacherManifeste(manifeste);
    const signature = { version: 0, period_hash: periodHash, recorder_key_id: manifeste.recorder_key_id, sig: octetsVersHex(sig) };
    await ecrireAtomique(path.join(dir, noms.signature), octetsJsonLisible(signature), { jamaisReecrire: true });
    this.journal.consigner("warning", "cloture", "period_signature_restored", { period_start: P, period_hash: periodHash });
    this._remettreCloture({ manifeste, signature, periodHash, P });
    this._copierWorm(`manifestes/${noms.manifeste}`, "manifeste");
    this._copierWorm(`manifestes/${noms.signature}`, "signature");
    this._copierWorm(`points/${nomSerie(P)}`, "points");
  }

  /** Remise de la clôture au composant d'ancrage, sans attendre (EX-12.27, 14.2). */
  _remettreCloture({ manifeste, signature, periodHash, P }) {
    if (!this.ancrage) return;
    const noms = nomsManifeste(P);
    const dir = path.join(this.repertoire, "manifestes");
    const remise = remiseCloture({
      manifeste,
      signature,
      periodHash,
      cheminManifeste: path.join(dir, noms.manifeste),
      cheminSignature: path.join(dir, noms.signature),
      cheminSerie: path.join(this.repertoire, "points", nomSerie(P)),
    });
    Promise.resolve()
      .then(() => this.ancrage.remettreCloture(remise))
      .catch((e) => this.journal.consigner("warning", "cloture", "anchor_pending", { period_start: P, erreur: String(e?.message ?? e) }));
  }

  async _ouvrirSegment(firstSeq) {
    this._verifierBail();
    const nom = nomSegment(firstSeq, this.epoque);
    const dir = path.join(this.repertoire, "segments");
    // EX-13.5 (1) : l'époque de l'en-tête n'est jamais inférieure à la plus
    // grande époque présente dans les noms.
    for (const s of await listerSegments(dir)) {
      if (s.epoch > this.epoque) throw new ErreurEnregistreur("bail", "noortrace: un ecrivain d'epoque superieure existe (EX-13.5)");
    }
    const ouvertA = this.horloge.murale();
    const entete = enteteSegment({
      epoch: this.epoque,
      first_seq: firstSeq,
      instance_id: this.instance_id,
      journal_id: this.journal_id,
      org_id: this.org_id,
      opened_at: this.premierOpenedAt ?? ouvertA,
      prev_hash: this.lastHash,
      recorder: this.recorder,
      recorder_key_id: this.cleCourante,
    });
    this.premierOpenedAt = undefined;
    const fichier = await FichierAjout.ouvrir(path.join(dir, nom), { creer: true });
    await fichier.ajouter(ligneSegment(entete));
    await fichier.synchroniser();
    // `synchronise` : longueur couverte par le dernier fdatasync rendu (EX-12.8).
    this.segment = { fichier, entete, nom, firstSeq, nb: 0, synchronise: fichier.taille };
    this._noterDurable();
    this.metriques?.jauge("noortrace_segment_bytes", {}, fichier.taille);
  }

  /**
   * État de l'écrivain à la fin du contenu durable (dernier fdatasync rendu) :
   * c'est l'état auquel il revient quand une erreur d'écriture ou de
   * fdatasync rend fatale la suite du segment (EX-12.8).
   */
  _noterDurable() {
    this.durable = {
      lastSeq: this.lastSeq,
      lastHash: this.lastHash,
      lastTs: this.lastTs,
      cleCourante: this.cleCourante,
      politiquesEcrites: new Set(this.politiquesEcrites ?? []),
    };
  }

  async _fermerSegment() {
    if (!this.segment) return;
    const s = this.segment;
    await s.fichier.fermer();
    this.segment = null;
    this.segmentsFermes.push(s.nom);
    this.journal.consigner("info", "stockage", "segment_rotated", { segment: s.nom, events: s.nb, bytes: s.fichier.taille });
    this._copierWorm(`segments/${s.nom}`, "segment");
  }

  _copierWorm(relatif, nature) {
    if (!this.worm) return;
    Promise.resolve()
      .then(() => this.worm.copier({ cle: cleObjetWorm(this.prefixeWorm, relatif), chemin: path.join(this.repertoire, relatif), nature }))
      .catch((e) => this.journal.consigner("warning", "worm", "worm_copy_failed", { cle: relatif, erreur: String(e?.message ?? e) }));
  }

  /** Le fdatasync qui précède a échoué (EX-12.8) : rien ne s'écrit avant la sortie du mode « stockage ». */
  _exigerSegment() {
    if (!this.segment) throw new ErreurEnregistreur("stockage", "noortrace: enregistreur en mode degrade (stockage)");
  }

  _verifierBail() {
    if (!this.bail.valide()) {
      this.journal.consigner("error", "bail", "lease_lost", {});
      this.degrade.entrer("bail");
      throw new ErreurEnregistreur("bail", "noortrace: enregistreur en mode degrade (bail)");
    }
  }

  // ------------------------------------------------------------ file

  /**
   * Scelle un événement partiel : seq, ts, prev_hash, validation, signature,
   * ajout, fdatasync. Rend l'événement complet une fois durable.
   * @param {object} partiel les huit champs de CT-1 §5.3
   * @param {{completer?: (e: object, tsIso: string) => void, avantAjout?: (e: object) => Promise<void>,
   *   leverIntention?: string, captureA?: number, verifierPieces?: boolean}} [options]
   * @returns {Promise<object>}
   */
  sceller(partiel, options = {}) {
    return this._enfiler({ type: "evenement", partiel, options });
  }

  /**
   * Rotation de clé (EX-11.15) : annonce construite à l'instant où `ts` est
   * fixé (`valid_from = ts`), contresignée par la nouvelle clé, événement
   * signé par l'ancienne ; `recorder_key_id` bascule pour l'événement suivant.
   * @param {{nouvelleCle: string, policy_version: string}} p
   * @returns {Promise<object>}
   */
  tournerCle(p) {
    return this._enfiler({ type: "rotation", p });
  }

  /**
   * Inscrit une intention (deux lignes, fdatasync, EX-12.12) avant un relais.
   * @param {{upstream_id: string, host: string, tool: string, arguments: object, ticket: string|null}} p
   * @param {object} partiel l'événement partiel déjà construit
   * @returns {Promise<{intent_id: string, intention: object, intention_sha256: string}>}
   */
  inscrireIntention(p, partiel) {
    return this._enfiler({ type: "intention", p, partiel });
  }

  /**
   * Inscrit une ligne levée sans fdatasync propre (EX-12.13, levée implicite
   * de la reprise, EX-12.14).
   * @param {string} intentId
   * @param {number} seq
   */
  lever(intentId, seq) {
    return this._enfiler({ type: "levee", intentId, seq });
  }

  /** Points de contrôle alignés et clôtures échues, à l'instant de l'horloge. */
  tic() {
    return this._enfiler({ type: "tic" });
  }

  /** Attend que la file soit vide et ferme les fichiers. */
  async fermer() {
    await this._enfiler({ type: "noop" });
    this.ferme = true;
    if (this.segment) await this.segment.fichier.fermer();
    if (this.intentions) {
      await this.intentions.synchroniser().catch(() => {});
      await this.intentions.fermer();
    }
  }

  _enfiler(op) {
    if (this.ferme) return Promise.reject(new ErreurEnregistreur("stockage", "noortrace: ecrivain ferme"));
    return new Promise((res, rej) => {
      this.file.push({ ...op, res, rej });
      this._pomper();
    });
  }

  async _pomper() {
    if (this.pompe) return;
    this.pompe = true;
    try {
      while (this.file.length) {
        if (this.file.length < this.groupeMax && this.attenteMs > 0 && this.file.some((o) => o.type === "evenement")) {
          await attendre(this.attenteMs);
        }
        const lot = this.file.splice(0, this.groupeMax);
        await this._traiterLot(lot);
      }
    } finally {
      this.pompe = false;
    }
  }

  async _traiterLot(lot) {
    for (const op of lot) {
      try {
        switch (op.type) {
          case "evenement":
          case "rotation":
            this.enAttenteSync.push({ op, evt: await this._ecrireEvenement(op) });
            break;
          case "intention":
            op.res(await this._ecrireIntention(op.p, op.partiel));
            break;
          case "levee":
            await this.intentions.ajouter(ligneIntention({ lifted: op.intentId, seq: op.seq }));
            op.res();
            break;
          case "tic":
            await this._synchroniser();
            await this._tic();
            op.res();
            break;
          case "reprise_stockage":
            if (!this.segment) await this._ouvrirApresPanne();
            op.res();
            break;
          case "panne_stockage":
            await this._synchroniser();
            throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: op.cause });
          default:
            await this._synchroniser();
            op.res();
        }
      } catch (e) {
        op.rej(e);
        if (e instanceof ErreurEnregistreur && e.raison === "stockage") await this._panneStockage(e);
      }
    }
    await this._synchroniser();
  }

  async _synchroniser() {
    const liste = this.enAttenteSync;
    if (!liste.length) return;
    this.enAttenteSync = [];
    let couvert = null;
    try {
      this._verifierBail();
      const t0 = performance.now();
      couvert = this.segment.fichier.taille;
      await this.segment.fichier.synchroniser();
      this.segment.synchronise = couvert;
      this._noterDurable();
      this.metriques?.observer("noortrace_fsync_duration_ms", {}, performance.now() - t0);
      this.metriques?.observer("noortrace_fsync_group_size", {}, liste.length, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096]);
      this.metriques?.jauge("noortrace_segment_bytes", {}, this.segment.fichier.taille);
      if (!(await this.bail.verifierApresEcriture())) {
        this.journal.consigner("error", "bail", "lease_lost_after_write", { seq: liste[liste.length - 1].evt.seq });
        this.degrade.entrer("bail");
        throw new ErreurEnregistreur("bail", "noortrace: enregistreur en mode degrade (bail)");
      }
    } catch (e) {
      const err = e instanceof ErreurEnregistreur ? e : new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: e });
      for (const { op } of liste) op.rej(err);
      if (err.raison === "stockage") await this._panneStockage(err);
      return;
    }
    for (const { op, evt } of liste) {
      this.index.ajouter(evt);
      this.metriques?.compter("noortrace_events_total", { kind: sorteMetrique(evt, op.options), status: evt.execution.status, is_error: String(evt.execution.is_error) });
      if (op.options?.leverIntention) {
        await this.intentions.ajouter(ligneIntention({ lifted: op.options.leverIntention, seq: evt.seq })).catch(() => {});
      }
      op.res(evt);
    }
  }

  /**
   * Panne de stockage (EX-12.8) : erreur de `write` ou de `fdatasync`, fatale
   * pour le segment. « Les lignes dont la durabilité n'est pas établie sont
   * tenues pour perdues » : leurs appelants reçoivent un refus (`-31010`, ou
   * `-31017` pour un appel déjà relayé, dont l'événement est gardé en
   * attente, EX-4.46) ; elles ne doivent donc pas rester dans la chaîne. Le
   * segment est fermé et tronqué à la fin du dernier fdatasync rendu (longueur
   * connue de l'écrivain), puis relu depuis le début pour établir sa dernière
   * ligne valide (12.4) ; l'état revient à cette ligne ; l'écrivain entre en
   * mode dégradé « stockage ». Si la troncature échoue (le stockage est en
   * panne), elle est retentée avant l'ouverture du segment suivant, qui
   * n'a pas lieu sans elle.
   */
  async _panneStockage(e) {
    this.journal.consigner("error", "stockage", "storage_unavailable", { errno: e?.cause?.code ?? null });
    this.degrade.entrer("stockage");
    // Lignes écrites, non couvertes par un fdatasync rendu : refusées ici, avant
    // que l'ouverture d'un segment suivant ne puisse les couvrir.
    const liste = this.enAttenteSync;
    this.enAttenteSync = [];
    for (const { op } of liste) op.rej(e);
    if (!this.segment) return;
    const s = this.segment;
    this.segment = null;
    await s.fichier.fermer();
    const d = this.durable;
    this.lastSeq = d.lastSeq;
    this.lastHash = d.lastHash;
    this.lastTs = d.lastTs;
    this.cleCourante = d.cleCourante;
    this.politiquesEcrites = new Set(d.politiquesEcrites);
    if (this.periode) this.periode.evenements = this.periode.evenements.filter((x) => x.seq <= this.lastSeq);
    this.segmentsFermes.push(s.nom);
    this.troncature = { chemin: s.fichier.chemin, nom: s.nom, longueur: s.synchronise };
    await this._tronquerApresPanne();
  }

  /**
   * Troncature du segment en panne à sa longueur durable, puis relecture
   * (EX-12.8, EX-12.10 pas 2 et 3) ; rend vrai quand elle est faite.
   */
  async _tronquerApresPanne() {
    const t = this.troncature;
    if (!t) return true;
    try {
      const taille = (await fs.stat(t.chemin)).size;
      if (taille > t.longueur) {
        await tronquer(t.chemin, t.longueur);
        this.journal.consigner("warning", "stockage", "segment_truncated", {
          segment: t.nom,
          removed_bytes: taille - t.longueur,
          expected_seq: this.lastSeq + 1,
          raison: "durabilite_non_etablie",
        });
      }
      const r = relireSegment(new Uint8Array(await fs.readFile(t.chemin)), {});
      const dernier = r.evenements[r.evenements.length - 1];
      const seqRelu = dernier ? dernier.seq : r.entete ? r.entete.first_seq - 1 : null;
      if (seqRelu !== null && seqRelu < this.lastSeq) {
        // Moins de lignes valides que l'écrivain n'en a vu durables : la relecture fait foi.
        this.lastSeq = seqRelu;
        this.lastHash = dernier ? dernier.hash : r.entete.prev_hash;
        if (dernier) this.lastTs = decoderHorodatage(dernier.ts);
        if (this.periode) this.periode.evenements = this.periode.evenements.filter((x) => x.seq <= this.lastSeq);
      }
      this.troncature = null;
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Ouverture d'un nouveau segment à la sortie du mode « stockage »
   * (EX-12.8, EX-14.11), après la troncature du segment en panne.
   */
  async _ouvrirApresPanne() {
    if (!(await this._tronquerApresPanne())) throw new ErreurEnregistreur("stockage", "noortrace: enregistreur en mode degrade (stockage)");
    await this._ouvrirSegment(this.lastSeq + 1);
    this.degrade.sortir("stockage");
  }

  /**
   * Sortie du mode dégradé « stockage » (EX-14.11) : un nouveau segment est
   * ouvert et synchronisé, `first_seq` = dernier seq valide + 1 (EX-12.8).
   */
  reprendreStockage() {
    return this._enfiler({ type: "reprise_stockage" });
  }

  /**
   * Panne de stockage constatée hors de l'écrivain (fichiers des approbations,
   * EX-7.19 pas 2) : traitée dans la file comme une panne du segment (EX-12.8 ;
   * segment fermé, mode dégradé « stockage »), de sorte que la sortie du mode
   * suive EX-14.11 (ouverture et fdatasync d'un nouveau segment). La promesse
   * rendue est rejetée avec l'erreur de panne.
   * @param {unknown} cause
   */
  signalerPanneStockage(cause) {
    return this._enfiler({ type: "panne_stockage", cause });
  }

  // ------------------------------------------------------------ écriture

  async _ecrireEvenement(op) {
    if (!this.segment) {
      // Sortie du mode « stockage » : nouveau segment ouvert et synchronisé
      // (EX-12.8, EX-14.11) ; une corruption attend une intervention.
      if (this.intervention) throw new ErreurEnregistreur("stockage", "noortrace: enregistreur en mode degrade (stockage)");
      await this._ouvrirApresPanne();
    }
    if (this.degrade.actif("cle") || this.degrade.actif("bail")) {
      // « clé » et « bail » bloquent tout (14.2, EX-14.4).
      const r = this.degrade.actif("cle") ? "cle" : "bail";
      throw new ErreurEnregistreur(r, `noortrace: enregistreur en mode degrade (${r})`);
    }
    const options = op.options ?? {};
    let tsMs = this.horloge.fixerTs(this.lastTs, { captureA: options.captureA });
    if (this.plancher !== null && tsMs < this.plancher) tsMs = this.plancher;
    // Changement de période : clôture de la période courante d'abord
    // (EX-7.11 : un événement appartient à la période de son ts).
    if (this.periode && tsMs >= (this.periode.start + 3600) * 1000) {
      await this._synchroniser();
      this._exigerSegment();
      await this._cloreJusqua(tsMs);
    }
    if (!this.periode) {
      this.periode = { start: debutPeriode(tsMs), firstSeq: this.lastSeq + 1, hashAvant: this.lastHash, evenements: [] };
      this.serie = { prev: ZERO32, dernierTs: null, dernierTreeSize: 0, prochainJ: Math.floor((tsMs - this.periode.start * 1000) / (this.intervalle * 1000)) + 1 };
    }
    const tsIso = ecrireHorodatage(tsMs);
    let partiel = op.partiel;
    let cleSignature = this.cleCourante;
    let nouvelleCle = null;
    if (op.type === "rotation") {
      nouvelleCle = op.p.nouvelleCle;
      const R = {
        journal_id: this.journal_id,
        new_key_id: nouvelleCle,
        new_public_key: await this.signataire.clePubliqueHex(nouvelleCle),
        old_key_id: this.cleCourante,
        org_id: this.org_id,
        valid_from: tsIso,
      };
      this._verifierBail();
      const contre = await this.signataire.signer(nouvelleCle, messageRotation(R));
      partiel = partielRotation({ ...R, counter_sig: octetsVersHex(contre) }, { policy_version: op.p.policy_version, recorder: this.recorder });
    }
    const e = envelopper(partiel, {
      seq: this.lastSeq + 1,
      ts: tsIso,
      org_id: this.org_id,
      journal_id: this.journal_id,
      recorder_key_id: cleSignature,
      prev_hash: this.lastHash,
    });
    options.completer?.(e, tsIso);
    // EX-9.1 : aucun événement ne porte une policy_version non annoncée.
    if (e.execution.tool !== NOMS_RESERVES.POLITIQUE && !this.index.politiques.has(e.code.policy_version) && !this.politiquesEcrites?.has(e.code.policy_version)) {
      throw new ErreurConstruction("policy_version non annoncée dans le journal (EX-9.1)", [e.code.policy_version]);
    }
    if (options.verifierPieces !== false) {
      for (const { reference } of referencesEvenement(e)) {
        if ("value" in reference) continue;
        if (!(await existe(this.pieces.chemin(reference.sha256)))) {
          throw new ErreurConstruction("pièce non stockée avant le scellement (EX-8.9)", [reference.sha256]);
        }
      }
    }
    e.hash = hacherEvenement(e);
    try {
      validerAvantSignature(e);
    } catch (err) {
      this.journal.consigner("error", "noyau", "event_invalid", { ecarts: err.ecarts ?? [] });
      throw err;
    }
    // Rotation du segment par taille (EX-12.4 (b)), calculée sur la ligne finale.
    const longueurEstimee = ligneSegment({ ...e, sig: "0x" + "00".repeat(64) }).length;
    if (this.segment.nb > 0 && this.segment.fichier.taille + longueurEstimee > this.segmentMax) {
      await this._synchroniser();
      this._exigerSegment();
      await this._fermerSegment();
      await this._ouvrirSegment(this.lastSeq + 1);
    }
    this._verifierBail();
    let sig;
    try {
      sig = await this.signataire.signer(cleSignature, messageSignatureEvenement(e), { rotation: op.type === "rotation" });
    } catch (err) {
      this.degrade.entrer("cle");
      throw err;
    }
    e.sig = octetsVersHex(sig);
    if (options.avantAjout) await options.avantAjout(e);
    try {
      await this.segment.fichier.ajouter(ligneSegment(e));
    } catch (err) {
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: err });
    }
    this.segment.nb++;
    this.lastSeq = e.seq;
    this.lastHash = e.hash;
    this.lastTs = tsMs;
    this.periode.evenements.push({ seq: e.seq, ts: tsMs, hash: e.hash });
    if (e.execution.tool === NOMS_RESERVES.POLITIQUE) {
      (this.politiquesEcrites ??= new Set()).add(e.code.policy_version);
    }
    if (nouvelleCle) this.cleCourante = nouvelleCle;
    return e;
  }

  async _ecrireIntention(p, partiel) {
    this.compteurIntention++;
    const intent_id = idIntention(this.epoque, this.compteurIntention);
    const intention = objetIntention({
      intent_id,
      upstream_id: p.upstream_id,
      host: p.host,
      written_at: ecrireHorodatage(p.written_at ?? this.horloge.murale()),
      org_id: this.org_id,
      journal_id: this.journal_id,
      tool: p.tool,
      arguments: p.arguments,
      ticket: p.ticket ?? null,
    });
    // EX-12.13 : un arrêt entre la ligne intention et la ligne contexte est
    // « impossible par construction » : les deux lignes partent dans une seule
    // écriture (la boucle d'EX-12.5 ne la réitère que sur une écriture
    // partielle, dont la fin incomplète est coupée à la relecture, EX-12.22).
    const l1 = ligneIntention(intention);
    const l2 = ligneIntention(objetContexte(intent_id, partiel));
    const deux = new Uint8Array(l1.length + l2.length);
    deux.set(l1);
    deux.set(l2, l1.length);
    const avant = this.intentions.taille;
    try {
      await this.intentions.ajouter(deux);
      this._verifierBail();
      await this.intentions.synchroniser();
    } catch (e) {
      // Intention non durable : l'appel ne sera pas relayé (EX-12.12) ; ses
      // lignes sont retirées pour qu'aucune reprise ne la tienne pour un relais
      // en vol (EX-12.8 : les lignes dont la durabilité n'est pas établie sont
      // tenues pour perdues). Au mieux : le stockage est en panne. Un écrivain
      // qui a perdu son bail n'écrit plus rien, pas même cette troncature (EX-13.6).
      if (!(e instanceof ErreurEnregistreur && e.raison === "bail")) {
        await tronquer(this.intentions.chemin, avant).then(() => (this.intentions.taille = avant), () => {});
      }
      if (e instanceof ErreurEnregistreur) throw e;
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: e });
    }
    return { intent_id, intention, intention_sha256: empreinteIntention(intention) };
  }

  // ------------------------------------------------------------ périodes et points

  async _tic() {
    if (!this.periode || !this.segment) return;
    // EX-7.13, EX-12.24 : l'instant d'un point ou d'une clôture est lu sur
    // l'horloge de 7.4 ; en mode dégradé « horloge », ou quand la comparaison
    // de l'avance murale à l'avance monotone révèle un saut en avant, rien
    // n'est clos ni pointé (un point manqué n'est pas rattrapé) : clore des
    // périodes futures daterait ensuite les événements dans le futur.
    if (this.degrade.actif("horloge")) return;
    const maintenant = this.horloge.murale();
    if (!this.horloge.controlerAvance(maintenant)) return;
    if (maintenant >= (this.periode.start + 3600) * 1000) await this._cloreJusqua(maintenant);
    const r = instantAligne(this.periode.start * 1000, this.intervalle, this.serie.prochainJ, maintenant);
    this.serie.prochainJ = r.prochainJ;
    if (r.j !== null) await this._produirePoint(maintenant);
  }

  /**
   * Clôt la période courante et les périodes vides suivantes jusqu'à celle
   * qui contient `instant` (CT-1 §10.3 : continuité).
   * @param {number} instant ms
   */
  async _cloreJusqua(instant) {
    while (this.periode && instant >= (this.periode.start + 3600) * 1000) {
      await this._clore();
    }
  }

  async _clore() {
    const P = this.periode;
    const maintenant = Math.max(this.horloge.murale(), (P.start + 3600) * 1000);
    // Point de clôture, avant le manifeste (CT-1 §10.5 règle 4).
    await this._produirePoint(maintenant, { cloture: true });
    const cle = this.cleCourante;
    this._verifierBail();
    const { manifeste, signature, periodHash } = await construireEtSignerManifeste(
      {
        org_id: this.org_id,
        journal_id: this.journal_id,
        period_start: P.start,
        first_seq: P.firstSeq,
        hashes: P.evenements.map((x) => x.hash),
        prev_period_hash: this.prevPeriodHash,
        recorder_key_id: cle,
        nonce: this.nonce(P.start),
        generated_at: maintenant,
      },
      this.signataire,
    );
    const noms = nomsManifeste(P.start);
    const dir = path.join(this.repertoire, "manifestes");
    await ecrireAtomique(path.join(dir, noms.manifeste), octetsJsonLisible(manifeste), { jamaisReecrire: true });
    await ecrireAtomique(path.join(dir, noms.signature), octetsJsonLisible(signature), { jamaisReecrire: true });
    this.journal.consigner("info", "cloture", "period_closed", { period_start: P.start, count: manifeste.count, period_hash: periodHash });
    this.prevPeriodHash = periodHash;
    this.plancher = (P.start + 3600) * 1000;
    const relatifSerie = `points/${nomSerie(P.start)}`;
    this._remettreCloture({ manifeste, signature, periodHash, P: P.start });
    // Segment aligné sur la période (EX-12.4 (a)).
    if (this.segment && this.segment.nb > 0) {
      await this._fermerSegment();
      this.premierOpenedAt = maintenant;
      await this._ouvrirSegment(this.lastSeq + 1);
    }
    this._copierWorm(`manifestes/${noms.manifeste}`, "manifeste");
    this._copierWorm(`manifestes/${noms.signature}`, "signature");
    this._copierWorm(relatifSerie, "points");
    this.periode = { start: P.start + 3600, firstSeq: this.lastSeq + 1, hashAvant: this.lastHash, evenements: [] };
    this.serie = { prev: ZERO32, dernierTs: null, dernierTreeSize: 0, prochainJ: 0 };
  }

  async _produirePoint(instant, options = {}) {
    const P = this.periode;
    const n = P.evenements.length;
    const ts = Math.max(instant, this.serie.dernierTs ?? 0, P.start * 1000);
    const corps = corpsPointDeControle({
      org_id: this.org_id,
      journal_id: this.journal_id,
      period_start: P.start,
      hashes: P.evenements.map((x) => x.hash),
      tree_size: n,
      first_seq: P.firstSeq,
      hash_avant: P.hashAvant,
      checkpoint_ts: ts,
      prev_checkpoint_hash: this.serie.prev,
      key_id: this.cleCourante,
    });
    this._verifierBail();
    const point = await signerPointDeControle(corps, this.signataire);
    const chemin = path.join(this.repertoire, "points", nomSerie(P.start));
    const f = await FichierAjout.ouvrir(chemin, { creer: true, existantAdmis: true });
    try {
      await f.ajouter(ligneSerie(point));
      await f.synchroniser();
    } finally {
      await f.fermer();
    }
    this.serie.prev = hacherPoint(point);
    this.serie.dernierTs = ts;
    this.serie.dernierTreeSize = n;
    this.journal.consigner("debug", "cloture", "checkpoint_written", { period_start: P.start, tree_size: n, cloture: options.cloture === true });
    if (this.ancrage) {
      const remise = remisePoint(point, chemin);
      Promise.resolve()
        .then(() => this.ancrage.remettrePoint(remise))
        .catch((e) => this.journal.consigner("warning", "cloture", "anchor_pending", { period_start: P.start, erreur: String(e?.message ?? e) }));
    }
    return point;
  }
}

function sorteMetrique(e, options) {
  if (options?.sorteMetrique) return options.sorteMetrique;
  switch (e.execution.tool) {
    case NOMS_RESERVES.ECHANGE: return "echange_modele";
    case NOMS_RESERVES.DECISION: return "decision";
    case NOMS_RESERVES.ROTATION: return "rotation";
    case NOMS_RESERVES.POLITIQUE: return "politique";
    default: return "appel_outil";
  }
}
