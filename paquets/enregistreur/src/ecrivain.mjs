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
  ZERO32, decoderHorodatage, ecrireHorodatage, hacherEvenement, hacherPoint, messageRotation,
  messageSignatureEvenement, octetsVersHex, NOMS_RESERVES, referencesEvenement,
} from "@noortrace/noyau";
import { envelopper, validerAvantSignature, partielRotation } from "./capture.mjs";
import { ErreurConstruction, ErreurEnregistreur } from "./erreurs.mjs";
import { FichierAjout, creerRepertoire, existe, ecrireAtomique } from "./fichiers.mjs";
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
    if (etat.dernierSegment) {
      // Le dernier segment de l'instance précédente est fermé par sa seule
      // existence (EX-13.9) : il est copié comme un segment fermé (EX-12.16).
      this.segmentsFermes.push(etat.dernierSegment);
      this._copierWorm(`segments/${etat.dernierSegment}`, "segment");
    }
    await this._ouvrirSegment(this.lastSeq + 1);
    // EX-13.5 (1) : aucun fichier d'intention sous une époque supérieure présente (lot HA).
    await verifierEpoqueOuverture(this.repertoire, "intentions", epoque);
    this.intentions = await FichierAjout.ouvrir(path.join(this.repertoire, "intentions", nomFichierIntentions(epoque)), {
      creer: true,
      existantAdmis: true,
    });
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
    this.segment = { fichier, entete, nom, firstSeq, nb: 0 };
    this.metriques?.jauge("noortrace_segment_bytes", {}, fichier.taille);
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
            if (!this.segment) {
              await this._ouvrirSegment(this.lastSeq + 1);
              this.degrade.sortir("stockage");
            }
            op.res();
            break;
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
    try {
      this._verifierBail();
      const t0 = performance.now();
      await this.segment.fichier.synchroniser();
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
   * Panne de stockage (EX-12.8) : le segment est fermé, relu depuis le début
   * pour établir sa dernière ligne valide ; l'état revient à cette ligne et
   * l'écrivain entre en mode dégradé « stockage ».
   */
  async _panneStockage(e) {
    this.journal.consigner("error", "stockage", "storage_unavailable", { errno: e?.cause?.code ?? null });
    this.degrade.entrer("stockage");
    if (!this.segment) return;
    const chemin = this.segment.fichier.chemin;
    await this.segment.fichier.fermer();
    try {
      const r = relireSegment(new Uint8Array(await fs.readFile(chemin)), {});
      const dernier = r.evenements[r.evenements.length - 1];
      if (dernier) {
        this.lastSeq = dernier.seq;
        this.lastHash = dernier.hash;
        this.lastTs = decoderHorodatage(dernier.ts);
      } else if (r.entete) {
        this.lastSeq = r.entete.first_seq - 1;
        this.lastHash = r.entete.prev_hash;
      }
      if (this.periode) this.periode.evenements = this.periode.evenements.filter((x) => x.seq <= this.lastSeq);
    } catch {
      // relecture impossible : l'état reste celui de la dernière écriture.
    }
    this.segmentsFermes.push(this.segment.nom);
    this.segment = null;
  }

  /**
   * Sortie du mode dégradé « stockage » (EX-14.11) : un nouveau segment est
   * ouvert et synchronisé, `first_seq` = dernier seq valide + 1 (EX-12.8).
   */
  reprendreStockage() {
    return this._enfiler({ type: "reprise_stockage" });
  }

  // ------------------------------------------------------------ écriture

  async _ecrireEvenement(op) {
    if (!this.segment) {
      // Sortie du mode « stockage » : nouveau segment ouvert et synchronisé
      // (EX-12.8, EX-14.11) ; une corruption attend une intervention.
      if (this.intervention) throw new ErreurEnregistreur("stockage", "noortrace: enregistreur en mode degrade (stockage)");
      await this._ouvrirSegment(this.lastSeq + 1);
      this.degrade.sortir("stockage");
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
    try {
      await this.intentions.ajouter(ligneIntention(intention));
      await this.intentions.ajouter(ligneIntention(objetContexte(intent_id, partiel)));
      this._verifierBail();
      await this.intentions.synchroniser();
    } catch (e) {
      if (e instanceof ErreurEnregistreur) throw e;
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: e });
    }
    return { intent_id, intention, intention_sha256: empreinteIntention(intention) };
  }

  // ------------------------------------------------------------ périodes et points

  async _tic() {
    if (!this.periode || !this.segment) return;
    const maintenant = this.horloge.murale();
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
    if (this.ancrage) {
      const remise = remiseCloture({
        manifeste,
        signature,
        periodHash,
        cheminManifeste: path.join(dir, noms.manifeste),
        cheminSignature: path.join(dir, noms.signature),
        cheminSerie: path.join(this.repertoire, relatifSerie),
      });
      Promise.resolve()
        .then(() => this.ancrage.remettreCloture(remise))
        .catch((e) => this.journal.consigner("warning", "cloture", "anchor_pending", { period_start: P.start, erreur: String(e?.message ?? e) }));
    }
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
