// Outil de gel juridique des copies WORM (CT-2 §12.11) : actions `poser`,
// `demander-levee`, `lever`, `reprendre` et `etat` de
// `noortrace-ctl worm gel`, exécutées HORS du démon avec les identifiants d'un
// exploitant (EX-12.36). L'outil ne lit que le document de configuration
// (`recorder.org_id`, `recorder.journal_id`, `storage.seal.worm`, sans
// résoudre ses identifiants), les copies WORM et, sur Azure et GCS, la copie
// du registre des copies passée par `--registre-copies` ; il n'ouvre ni
// `storage.root`, ni le bail, ni le signataire, et n'envoie rien au démon.
// Registre des gels (EX-12.37), règle de garde (EX-12.38), pas à pas et
// pannes (EX-12.40), lignes du journal d'exploitation (composant `worm`).
// Codes de sortie : 0 tout est fait ; 1 fait en partie ; 2 usage ou
// configuration ; 3 règle de garde refusée ; 4 support injoignable ou
// refusant la première requête : rien n'a été changé.

import { randomBytes } from "node:crypto";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { jcsIntegralOctets } from "../jcs-integral.mjs";
import { calculerPerimetre, cleManifeste, lireListeObjets } from "./perimetre.mjs";
import {
  verifierGarde, etatGel, versionsALever, empreinteEnregistrement, octetsEnregistrement, nomEnregistrement, identifiantGel,
} from "./garde.mjs";
import { piecesReferencees } from "./registre.mjs";
import { lireSegmentFerme } from "../segments.mjs";
import { ErreurTransport } from "./s3.mjs";
import { ErreurNonFixe } from "./support.mjs";

/** Codes de sortie d'EX-12.36. */
export const CODES = Object.freeze({ FAIT: 0, PARTIEL: 1, USAGE: 2, GARDE: 3, SUPPORT: 4 });

/** Arrêt de l'outil avec un code (usage interne). */
export class ArretOutil extends Error {
  constructor(code, raison, data = {}) {
    super(raison);
    this.name = "ArretOutil";
    this.code = code;
    this.raison = raison;
    this.data = data;
  }
}

const MOTIF_ENREGISTREMENT = /^([0-9]{4})-(pose|pose_resultat|demande_levee|levee|levee_resultat)\.json$/;

/**
 * Contexte d'une exécution de l'outil.
 * @typedef {object} ContexteGel
 * @property {object} config document de configuration validé
 * @property {object} operations opérations du support avec les identifiants de l'exploitant
 * @property {{consigner: (niveau: string, evenement: string, data: object) => void}} journal lignes du composant `worm`
 * @property {(texte: string) => void} sortie sortie standard
 * @property {() => number} [murale] horloge de l'outil
 * @property {(n: number) => Uint8Array} [aleatoire]
 * @property {{key: string, version_id: string}[]|null} [registreCopies] lignes de `--registre-copies` (Azure, GCS)
 */

function enregistrement(base, champs) {
  return {
    version: 0,
    gel_id: base.gel_id,
    n: champs.n,
    kind: champs.kind,
    org_id: base.org_id,
    journal_id: base.journal_id,
    periods: base.periods,
    support: base.support,
    objects: base.objects,
    actor: champs.actor,
    at: champs.at,
    reason: champs.reason ?? null,
    reference: base.reference ?? null,
    request_sha256: champs.request_sha256 ?? null,
    results: champs.results ?? null,
    anomalies: champs.anomalies ?? [],
    prev_sha256: champs.prev_sha256 ?? null,
  };
}

export class OutilGel {
  /** @param {ContexteGel} ctx */
  constructor(ctx) {
    this.ctx = ctx;
    this.config = ctx.config;
    this.worm = ctx.config.storage.seal.worm;
    this.prefixe = this.worm.prefix;
    this.ops = ctx.operations;
    this.murale = ctx.murale ?? (() => Date.now());
    this.aleatoire = ctx.aleatoire ?? ((n) => randomBytes(n));
    this.premiereRequete = true;
  }

  _journal(niveau, evenement, data) {
    this.ctx.journal.consigner(niveau, evenement, data);
  }

  _cleGel(gel_id, nom) {
    return `${this.prefixe}gels/${gel_id}/${nom}`;
  }

  /** Une requête : la première qui échoue (injoignable, 403, non prise en charge) arrête l'outil, code 4. */
  async _requete(f, { premiere = false } = {}) {
    try {
      const r = await f();
      if (premiere && (r.statut === 403 || r.statut === 501 || r.code === "NotImplemented")) {
        throw new ArretOutil(CODES.SUPPORT, r.statut === 403 ? "droit_manquant" : "gel_non_pris_en_charge", { http_status: r.statut });
      }
      return r;
    } catch (e) {
      if (e instanceof ErreurNonFixe) throw new ArretOutil(CODES.SUPPORT, "operation_non_fixee", { operation: e.operation });
      if (e instanceof ErreurTransport && premiere) throw new ArretOutil(CODES.SUPPORT, "injoignable", {});
      throw e;
    }
  }

  // ---------------------------------------------------------------- registre

  /**
   * Relit le registre d'un gel : enregistrements triés par `<nnnn>`, version
   * courante de chaque clé.
   * @param {string} gel_id
   * @param {{premiere?: boolean}} [o]
   * @returns {Promise<{records: object[], cles: string[]}>}
   */
  async relireGel(gel_id, o = {}) {
    const l = await this._requete(() => this.ops.listerVersions(this._cleGel(gel_id, "")), o);
    if (l.statut !== 200) throw new ArretOutil(o.premiere ? CODES.SUPPORT : CODES.PARTIEL, "liste_registre", { http_status: l.statut });
    return this._lireRecords(l.versions, gel_id);
  }

  async _lireRecords(versions, gel_id) {
    const parN = [];
    for (const v of versions) {
      if (!v.is_latest || v.delete_marker) continue;
      const nom = v.key.slice(this._cleGel(gel_id, "").length);
      const m = MOTIF_ENREGISTREMENT.exec(nom);
      if (!m) continue;
      const r = await this._requete(() => this.ops.lire(v.key, v.version_id));
      if (r.statut !== 200) throw new ArretOutil(CODES.PARTIEL, "lecture_registre", { http_status: r.statut });
      let o;
      try {
        o = JSON.parse(r.corps.toString("utf8"));
      } catch {
        o = { illisible: true };
      }
      parN.push({ n: Number(m[1]), record: o, cle: v.key });
    }
    parN.sort((a, b) => a.n - b.n);
    return { records: parN.map((x) => x.record), cles: parN.map((x) => x.cle) };
  }

  /** Relit les registres de tous les gels du préfixe : `gel_id` → suite. */
  async relireTousLesGels() {
    const l = await this._requete(() => this.ops.listerVersions(`${this.prefixe}gels/`));
    if (l.statut !== 200) throw new ArretOutil(CODES.PARTIEL, "liste_registre", { http_status: l.statut });
    const parGel = new Map();
    for (const v of l.versions) {
      const reste = v.key.slice(`${this.prefixe}gels/`.length);
      const k = reste.indexOf("/");
      if (k < 0) continue;
      const g = reste.slice(0, k);
      if (!parGel.has(g)) parGel.set(g, []);
      parGel.get(g).push(v);
    }
    const r = new Map();
    for (const [g, vs] of parGel) r.set(g, (await this._lireRecords(vs, g)).records);
    return r;
  }

  /** Liste des objets d'un gel, vérifiée contre son empreinte (EX-12.37 `objects`). */
  async lireObjets(objects) {
    const r = await this._requete(() => this.ops.lire(objects.key));
    if (r.statut !== 200) throw new ArretOutil(CODES.PARTIEL, "liste_objets", { http_status: r.statut });
    if (sha256Hex(new Uint8Array(r.corps)) !== objects.sha256) throw new ArretOutil(CODES.GARDE, "objets_differents", { code: "objets_differents" });
    const liste = lireListeObjets(new Uint8Array(r.corps));
    if (liste.length !== objects.count) throw new ArretOutil(CODES.GARDE, "objets_differents", { code: "objets_differents" });
    return liste;
  }

  /** Écrit un enregistrement, conditionnel à l'absence (EX-12.37) ; rend le statut. */
  async _ecrireRecord(record) {
    const cle = this._cleGel(record.gel_id, nomEnregistrement(record.n, record.kind));
    const r = await this._requete(() => this.ops.ecrireConditionnel(cle, octetsEnregistrement(record)));
    return r.statut;
  }

  /** Garde sur une suite ; code 3 et ligne `worm_legal_hold_guard_refused` si elle échoue. */
  _garde(records, gel_id) {
    const g = verifierGarde(records);
    if (!g.valid) {
      this._journal("error", "worm_legal_hold_guard_refused", { gel_id, code: g.errors[0].code, errors: g.errors });
      throw new ArretOutil(CODES.GARDE, "garde", { code: g.errors[0].code });
    }
    return g;
  }

  // ---------------------------------------------------------------- gel des versions

  /** Pose ou levée sur une liste ; relecture et exigence de l'état attendu (EX-12.40 pas 5). */
  async _appliquer(objets, pose, { premiere = false } = {}) {
    let ok = 0;
    const failed = [];
    const attendu = pose ? "on" : "off";
    let premier = premiere;
    for (const o of objets) {
      let r;
      try {
        r = await this._requete(() => this.ops.poserGel(o.key, o.version_id, pose), { premiere: premier });
      } catch (e) {
        if (e instanceof ArretOutil) throw e;
        if (!(e instanceof ErreurTransport)) throw e;
        failed.push({ key: o.key, version_id: o.version_id, status: "echec", http_status: null });
        premier = false;
        continue;
      }
      premier = false;
      if (r.statut !== 200) {
        const status = r.statut === 403 ? "refuse" : r.statut === 404 ? "absent" : "echec";
        failed.push({ key: o.key, version_id: o.version_id, status, http_status: r.statut });
        continue;
      }
      let lu;
      try {
        lu = await this.ops.lireGel(o.key, o.version_id);
      } catch {
        lu = null;
      }
      // Une version sans gel est levée : sur Azure, l'en-tête est absent sans gel (R13-F19).
      const etat = lu && lu.statut === 200 ? this.ops.etatGel(lu) : null;
      if (!(etat === attendu || (!pose && etat === "jamais"))) {
        failed.push({ key: o.key, version_id: o.version_id, status: "non_confirme", http_status: lu?.statut ?? null });
        continue;
      }
      ok++;
    }
    return { ok, failed };
  }

  /** Gels actifs autres que `gel_id`, avec leur liste d'objets (EX-12.40, EX-17.7). */
  async _autresGelsActifs(gel_id) {
    const tous = await this.relireTousLesGels();
    const autres = [];
    for (const [g, records] of tous) {
      if (g === gel_id || !records.length) continue;
      if (!etatGel(records).actif) continue;
      try {
        autres.push({ gel_id: g, objects: await this.lireObjets(records[0].objects) });
      } catch {
        // liste illisible : ce gel ne protège rien de connu
      }
    }
    return autres;
  }

  // ---------------------------------------------------------------- actions

  /**
   * `poser` (EX-12.40) : périmètre, liste des objets, enregistrement `pose`,
   * requêtes de gel, relecture, `pose_resultat`.
   * @param {{identite: string, de: number, a: number, motif: string, reference: string|null}} p
   */
  async poser(p) {
    const org_id = this.config.recorder.org_id;
    const journal_id = this.config.recorder.journal_id;
    const perim = await this._perimetre(p.de, p.a);
    const unexpected = perim.anomalies.filter((a) => ["versions_multiples", "marqueur_de_suppression", "manifeste_absent", "objet_absent", "segment_absent"].includes(a.kind));
    for (const a of unexpected) this._journal("warning", "worm_versions_unexpected", { key: a.key, kind: a.kind });
    let gel_id = identifiantGel(this.murale(), this.aleatoire(4));
    let base;
    let pose;
    for (let essai = 0; ; essai++) {
      const cleObjets = this._cleGel(gel_id, "objets-0001.ndjson");
      base = {
        gel_id, org_id, journal_id,
        periods: { from: p.de, to: p.a },
        support: { type: this.worm.type, bucket: this.worm.bucket, prefix: this.prefixe },
        objects: { key: cleObjets, sha256: perim.objects_sha256, count: perim.count },
        reference: p.reference ?? null,
      };
      const e1 = await this._requete(() => this.ops.ecrireConditionnel(cleObjets, perim.octets));
      if (e1.statut === 412 && essai === 0) {
        gel_id = identifiantGel(this.murale(), this.aleatoire(4));
        continue;
      }
      if (e1.statut !== 200) throw new ArretOutil(CODES.SUPPORT, "ecriture_registre", { http_status: e1.statut });
      pose = enregistrement(base, { n: 1, kind: "pose", actor: p.identite, at: ecrireHorodatage(this.murale()), reason: p.motif, anomalies: perim.anomalies });
      const e2 = await this._ecrireRecord(pose);
      if (e2 === 412 && essai === 0) {
        gel_id = identifiantGel(this.murale(), this.aleatoire(4));
        continue;
      }
      if (e2 !== 200) throw new ArretOutil(CODES.SUPPORT, "ecriture_registre", { http_status: e2 });
      break;
    }
    this.ctx.sortie(`${gel_id}\n`);
    const res = await this._appliquer(perim.objects, true, { premiere: true });
    const resultat = enregistrement(base, {
      n: 2, kind: "pose_resultat", actor: p.identite, at: ecrireHorodatage(this.murale()), results: res, prev_sha256: empreinteEnregistrement(pose),
    });
    const e3 = await this._ecrireRecord(resultat);
    if (e3 !== 200) {
      this._journal("error", "worm_legal_hold_failed", { gel_id, raison: "ecriture_registre", http_status: e3, objects: perim.count });
      return CODES.PARTIEL;
    }
    this._journal("info", "worm_legal_hold_set", {
      gel_id, n: 2, kind: "pose_resultat", record_sha256: empreinteEnregistrement(resultat),
      objects: perim.count, ok: res.ok, failed: res.failed.length, anomalies: perim.anomalies.length,
    });
    if (res.failed.length) this._journal("error", "worm_legal_hold_failed", { gel_id, raison: "objets", objects: res.failed.length });
    return res.failed.length || perim.anomalies.length ? CODES.PARTIEL : CODES.FAIT;
  }

  /** Périmètre (EX-12.35) depuis la liste des versions du support, ou le registre des copies (Azure, GCS). */
  async _perimetre(de, a) {
    let versions;
    if (this.worm.type === "s3-object-lock") {
      const l = await this._requete(() => this.ops.listerVersions(this.prefixe), { premiere: true });
      if (l.statut !== 200) throw new ArretOutil(CODES.SUPPORT, l.statut === 403 ? "droit_manquant" : "liste", { http_status: l.statut });
      versions = l.versions;
    } else {
      if (!this.ctx.registreCopies) throw new ArretOutil(CODES.USAGE, "registre_copies_requis");
      versions = this.ctx.registreCopies.filter((x) => x.version_id !== null).map((x) => ({ key: x.key, version_id: x.version_id, is_latest: true, delete_marker: false }));
    }
    this.premiereRequete = false;
    const manifests = [];
    for (let P = de; P <= a; P += 3600) {
      const km = cleManifeste(this.prefixe, P);
      for (const v of versions.filter((x) => x.key === km && !x.delete_marker)) {
        let r;
        try {
          r = await this._requete(() => this.ops.lire(km, v.version_id));
        } catch (e) {
          if (e instanceof ArretOutil) throw e;
          continue;
        }
        if (r.statut !== 200) continue;
        try {
          const m = JSON.parse(r.corps.toString("utf8"));
          if (Number.isSafeInteger(m.first_seq) && Number.isSafeInteger(m.last_seq)) {
            manifests.push({ period_start: P, first_seq: m.first_seq, last_seq: m.last_seq });
            break;
          }
        } catch {
          // version illisible : la suivante est essayée
        }
      }
    }
    let pieces = null;
    const piecesPurgeables = this.config.storage.retention?.pieces_days !== null && this.config.storage.retention?.pieces_days !== undefined;
    if (this.worm.copy_pieces === true) {
      const prelim = calculerPerimetre({ prefix: this.prefixe, from: de, to: a, versions, manifests, pieces: null, piecesPurgeables: false });
      pieces = [];
      const vues = new Set();
      for (const k of prelim.segments) {
        for (const v of versions.filter((x) => x.key === k && !x.delete_marker)) {
          const r = await this._requete(() => this.ops.lire(k, v.version_id)).catch(() => null);
          if (!r || r.statut !== 200) continue;
          let evts = [];
          try {
            evts = lireSegmentFerme(new Uint8Array(r.corps)).evenements;
          } catch {
            continue;
          }
          for (const s of piecesReferencees(evts)) if (!vues.has(s)) {
            vues.add(s);
            pieces.push(s);
          }
        }
      }
    }
    return calculerPerimetre({ prefix: this.prefixe, from: de, to: a, versions, manifests, pieces, piecesPurgeables });
  }

  /**
   * `demander-levee` : garde sur ce qui existe, dernier enregistrement
   * `pose_resultat` ou `demande_levee`, enregistrement écrit, empreinte imprimée.
   * @param {{identite: string, gel: string, motif: string}} p
   */
  async demanderLevee(p) {
    for (let essai = 0; essai < 2; essai++) {
      const { records } = await this.relireGel(p.gel, { premiere: true });
      this._garde(records, p.gel);
      const dernier = records.at(-1);
      if (!["pose_resultat", "demande_levee"].includes(dernier.kind)) {
        this._journal("error", "worm_legal_hold_guard_refused", { gel_id: p.gel, code: "ordre_invalide" });
        throw new ArretOutil(CODES.GARDE, "garde", { code: "ordre_invalide" });
      }
      const d = enregistrement(records[0], {
        n: records.length + 1, kind: "demande_levee", actor: p.identite, at: ecrireHorodatage(this.murale()), reason: p.motif,
        prev_sha256: empreinteEnregistrement(dernier),
      });
      this._garde([...records, d], p.gel);
      const s = await this._ecrireRecord(d);
      if (s === 412) continue;
      if (s !== 200) throw new ArretOutil(CODES.SUPPORT, "ecriture_registre", { http_status: s });
      const h = empreinteEnregistrement(d);
      this.ctx.sortie(`${h}\n`);
      this._journal("info", "worm_legal_hold_release_requested", { gel_id: p.gel, n: d.n, kind: d.kind, record_sha256: h });
      return CODES.FAIT;
    }
    this._journal("error", "worm_legal_hold_guard_refused", { gel_id: p.gel, code: "chaine_rompue" });
    throw new ArretOutil(CODES.GARDE, "garde", { code: "chaine_rompue" });
  }

  /**
   * `lever` : garde avec l'enregistrement `levee` à écrire, `levee` écrit
   * avant toute requête, exclusion des versions couvertes par un autre gel
   * actif, requêtes, relecture, `levee_resultat`, puis vérification qu'aucun
   * gel posé entre-temps n'a été levé par erreur.
   * @param {{identite: string, gel: string, demande: string}} p
   */
  async lever(p) {
    let records;
    let levee;
    for (let essai = 0; ; essai++) {
      ({ records } = await this.relireGel(p.gel, { premiere: essai === 0 }));
      if (!records.length) this._garde(records, p.gel);
      levee = enregistrement(records[0], {
        n: records.length + 1, kind: "levee", actor: p.identite, at: ecrireHorodatage(this.murale()),
        request_sha256: p.demande, prev_sha256: empreinteEnregistrement(records.at(-1)),
      });
      this._garde([...records, levee], p.gel);
      const s = await this._ecrireRecord(levee);
      if (s === 200) break;
      if (s === 412 && essai === 0) continue;
      if (s === 412) {
        this._journal("error", "worm_legal_hold_guard_refused", { gel_id: p.gel, code: "chaine_rompue" });
        throw new ArretOutil(CODES.GARDE, "garde", { code: "chaine_rompue" });
      }
      throw new ArretOutil(CODES.SUPPORT, "ecriture_registre", { http_status: s });
    }
    return this._executerLevee(p.identite, [...records, levee]);
  }

  async _executerLevee(identite, records) {
    const gel_id = records[0].gel_id;
    const objets = await this.lireObjets(records[0].objects);
    const autres = await this._autresGelsActifs(gel_id);
    const { lift, keep } = versionsALever(objets, autres);
    const res = await this._appliquer(lift, false);
    const resultat = enregistrement(records[0], {
      n: records.length + 1, kind: "levee_resultat", actor: identite, at: ecrireHorodatage(this.murale()),
      results: { ok: res.ok, failed: res.failed, kept: keep }, prev_sha256: empreinteEnregistrement(records.at(-1)),
    });
    const s = await this._ecrireRecord(resultat);
    // Après les requêtes : un gel posé entre-temps qui couvre une version mise à off reçoit la pose de nouveau.
    const apres = await this._autresGelsActifs(gel_id);
    const leves = lift.filter((o) => !res.failed.some((f) => f.key === o.key && f.version_id === o.version_id));
    const reposes = leves.filter((o) => apres.some((g) => g.objects.some((x) => x.key === o.key && x.version_id === o.version_id)));
    if (reposes.length) {
      await this._appliquer(reposes, true);
      this._journal("warning", "worm_legal_hold_failed", { gel_id, raison: "pose_concurrente_reposee", objects: reposes.length });
    }
    if (s !== 200) {
      this._journal("error", "worm_legal_hold_failed", { gel_id, raison: "ecriture_registre", http_status: s, objects: objets.length });
      return CODES.PARTIEL;
    }
    this._journal("info", "worm_legal_hold_released", {
      gel_id, n: resultat.n, kind: resultat.kind, record_sha256: empreinteEnregistrement(resultat),
      objects: objets.length, ok: res.ok, failed: res.failed.length, kept: keep.length,
    });
    if (res.failed.length) this._journal("error", "worm_legal_hold_failed", { gel_id, raison: "objets", objects: res.failed.length });
    return res.failed.length ? CODES.PARTIEL : CODES.FAIT;
  }

  /**
   * `reprendre` : complète une pose ou une levée interrompue ou partielle.
   * @param {{identite: string, gel: string}} p
   */
  async reprendre(p) {
    const { records } = await this.relireGel(p.gel, { premiere: true });
    this._garde(records, p.gel);
    const dernier = records.at(-1);
    const enCours = dernier.kind === "pose" || dernier.kind === "levee" || (["pose_resultat", "levee_resultat"].includes(dernier.kind) && dernier.results?.failed?.length > 0);
    if (!enCours) {
      this.ctx.sortie("rien a reprendre\n");
      return CODES.FAIT;
    }
    const pose = dernier.kind === "pose" || dernier.kind === "pose_resultat";
    const objets = await this.lireObjets(records[0].objects);
    let cibles = objets;
    let keep = [];
    if (!pose) {
      const autres = await this._autresGelsActifs(p.gel);
      ({ lift: cibles, keep } = versionsALever(objets, autres));
    }
    const aRenvoyer = [];
    let ok = 0;
    for (const o of cibles) {
      const lu = await this.ops.lireGel(o.key, o.version_id).catch(() => null);
      const etat = lu && lu.statut === 200 ? this.ops.etatGel(lu) : null;
      if (etat === (pose ? "on" : "off") || (!pose && etat === "jamais")) ok++;
      else aRenvoyer.push(o);
    }
    const res = await this._appliquer(aRenvoyer, pose);
    const results = { ok: ok + res.ok, failed: res.failed };
    if (!pose) results.kept = keep;
    const r = enregistrement(records[0], {
      n: records.length + 1, kind: pose ? "pose_resultat" : "levee_resultat", actor: p.identite, at: ecrireHorodatage(this.murale()),
      results, prev_sha256: empreinteEnregistrement(dernier),
    });
    this._garde([...records, r], p.gel);
    const s = await this._ecrireRecord(r);
    if (s !== 200) {
      this._journal("error", "worm_legal_hold_failed", { gel_id: p.gel, raison: "ecriture_registre", http_status: s, objects: objets.length });
      return CODES.PARTIEL;
    }
    this._journal("info", pose ? "worm_legal_hold_set" : "worm_legal_hold_released", {
      gel_id: p.gel, n: r.n, kind: r.kind, record_sha256: empreinteEnregistrement(r), objects: objets.length, ok: results.ok, failed: res.failed.length,
    });
    return res.failed.length ? CODES.PARTIEL : CODES.FAIT;
  }

  /**
   * `etat` : relit le registre et l'état de chaque objet, imprime, n'écrit
   * rien (contre-vérification du rôle Lecteur, EX-12.41, EX-17.7) ; code 1 si
   * la garde échoue ou qu'une version attendue `on` ne l'est pas.
   * @param {{gel: string}} p
   */
  async etat(p) {
    const { records } = await this.relireGel(p.gel, { premiere: true });
    const garde = verifierGarde(records);
    const e = etatGel(records);
    const objets = records.length ? await this.lireObjets(records[0].objects) : [];
    const versions = [];
    let ecarts = garde.valid ? 0 : 1;
    for (const o of objets) {
      const lu = await this.ops.lireGel(o.key, o.version_id).catch(() => null);
      const etat = lu && lu.statut === 200 ? this.ops.etatGel(lu) : "illisible";
      const attenduOn = e.actif && (!e.leveeEnCours || e.kept.some((k) => k.key === o.key && k.version_id === o.version_id));
      if (attenduOn && etat !== "on") ecarts++;
      versions.push({ key: o.key, version_id: o.version_id, legal_hold: etat, attendu: attenduOn ? "on" : e.actif ? "on_ou_off" : null });
    }
    this.ctx.sortie(`${Buffer.from(jcsIntegralOctets({
      gel_id: p.gel, actif: e.actif, levee_en_cours: e.leveeEnCours, garde: garde.valid ? "respectee" : garde.errors,
      records: records.map((r, k) => ({ n: r.n, kind: r.kind, record_sha256: garde.record_sha256[k] })), versions,
    })).toString("utf8")}\n`);
    return ecarts ? CODES.PARTIEL : CODES.FAIT;
  }
}
