// Contrôles périodiques de la supervision propres au support WORM (CT-2
// EX-17.5), relevé de verrouillage (EX-17.6) et lecture du registre des gels
// (EX-17.7) :
//   - toutes les heures : comparaison SHA-256 de chaque segment copié dans
//     l'heure avec sa copie WORM (EX-12.17), balayage des copies manquantes
//     (EX-12.16) ;
//   - une fois par jour : rétention par défaut du support
//     (`worm_lock_config_check`), registre des gels et état de gel des
//     versions des gels actifs ;
//   - tous les `lock_audit_interval_days` jours (et au premier tour après le
//     démarrage, aucun état mutable ne gardant l'instant du dernier relevé,
//     EX-12.1) : le relevé de verrouillage.
// Les contrôles d'EX-17.5 qui ne dépendent pas du support (manifeste,
// signature et continuité de la période close, `health()` du signataire,
// relecture quotidienne des segments fermés avec toutes les clés de la
// chaîne) sont faits par le cœur, avec ou sans WORM (`src/controles.mjs`).
// Résultats : `integrity_check` et `noortrace_integrity_check_failures_total`
// ; lignes et jauges `worm_*` de 17.2 et 17.3. Ces contrôles n'écrivent
// jamais sur le support et ne bloquent aucun appel (14.2).

import fs from "node:fs/promises";
import path from "node:path";
import { decoderHorodatage, ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { controlerVerrou, echeanceMinimale, lireEcheance } from "./verrou.mjs";
import { lireRegistres, inscrireCopie, SOUS_PREFIXES_ECRIVAIN } from "./registre.mjs";
import { verifierGarde, etatGel } from "./garde.mjs";
import { lireListeObjets } from "./perimetre.mjs";

const JOUR_MS = 86400000;

/**
 * Lecture du registre des gels (EX-17.7) : liste de `<prefix>gels/`,
 * enregistrements non encore vus consignés (`worm_legal_hold_observed`),
 * règle de garde recalculée sur toute la suite, gels actifs et état attendu.
 * @param {{operations: object, worm: object, journal: object, metriques?: object, vus?: Set<string>}} c
 * @returns {Promise<{ok: boolean, gels: {gel_id: string, records: object[], etat: object, objets: {key: string, version_id: string}[]}[]}>}
 */
export async function lireRegistreGels(c) {
  const prefixe = `${c.worm.prefix}gels/`;
  let l;
  try {
    l = await c.operations.listerVersions(prefixe);
  } catch {
    l = { statut: null };
  }
  if (l.statut !== 200) return { ok: false, gels: [] };
  const parGel = new Map();
  for (const v of l.versions) {
    if (!v.is_latest || v.delete_marker) continue;
    const reste = v.key.slice(prefixe.length);
    const k = reste.indexOf("/");
    if (k < 0) continue;
    const g = reste.slice(0, k);
    const m = /^([0-9]{4})-[a-z_]+\.json$/.exec(reste.slice(k + 1));
    if (!m) continue;
    if (!parGel.has(g)) parGel.set(g, []);
    parGel.get(g).push({ n: Number(m[1]), v });
  }
  const gels = [];
  let ok = true;
  for (const [gel_id, liste] of [...parGel].sort()) {
    liste.sort((a, b) => a.n - b.n);
    const records = [];
    for (const { v } of liste) {
      let r;
      try {
        r = await c.operations.lire(v.key, v.version_id);
      } catch {
        r = { statut: null };
      }
      if (r.statut !== 200) {
        ok = false;
        records.push({ illisible: true });
        continue;
      }
      try {
        records.push(JSON.parse(r.corps.toString("utf8")));
      } catch {
        records.push({ illisible: true });
      }
    }
    const garde = verifierGarde(records);
    records.forEach((r, k) => {
      const cle = `${liste[k].v.key}#${liste[k].v.version_id}`;
      if (c.vus?.has(cle)) return;
      c.vus?.add(cle);
      const codes = garde.errors.filter((e) => e.n === k + 1).map((e) => e.code);
      c.journal.consigner(codes.length || !garde.valid ? "error" : "info", "worm", "worm_legal_hold_observed", {
        gel_id, n: r.n ?? null, kind: r.kind ?? null, record_sha256: garde.record_sha256[k], garde: garde.valid ? "respectee" : codes[0] ?? garde.errors[0].code,
      });
    });
    const etat = etatGel(records);
    let objets = [];
    if (etat.actif && records[0]?.objects?.key) {
      try {
        const r = await c.operations.lire(records[0].objects.key);
        if (r.statut === 200 && sha256Hex(new Uint8Array(r.corps)) === records[0].objects.sha256) objets = lireListeObjets(new Uint8Array(r.corps));
        else ok = false;
      } catch {
        ok = false;
      }
    }
    gels.push({ gel_id, records, etat, objets });
  }
  c.metriques?.jauge("noortrace_worm_legal_holds_active", {}, gels.filter((g) => g.etat.actif).length);
  return { ok, gels };
}

/**
 * Versions dont l'état de gel attendu est `on` (EX-17.6 pas 2, EX-17.7) :
 * versions d'un gel actif sans `levee` valide, ou de `results.kept`.
 * @param {{etat: object, objets: {key: string, version_id: string}[]}[]} gels
 * @returns {Set<string>} `<key>#<version_id>`
 */
export function versionsAttenduesGelees(gels) {
  const s = new Set();
  for (const g of gels) {
    if (!g.etat.actif) continue;
    for (const o of g.objets) if (!g.etat.leveeEnCours) s.add(`${o.key}#${o.version_id}`);
    for (const k of g.etat.kept) s.add(`${k.key}#${k.version_id}`);
  }
  return s;
}

/**
 * Relevé de verrouillage (EX-17.6), avec les seuls droits de lecture des
 * identifiants de l'écrivain. N'écrit jamais sur le support ; une version
 * sans ligne au registre des copies y est inscrite (registre local).
 * @param {{operations: object, worm: object, repertoire: string, epoque: number|null, journal: object,
 *   metriques?: object, murale: () => number, gels?: object[]}} c
 */
export async function releverVerrouillage(c) {
  const t0 = c.murale();
  const l = await c.operations.listerVersions(c.worm.prefix);
  if (l.statut !== 200) throw new Error(`liste des versions : statut ${l.statut}`);
  const gelees = versionsAttenduesGelees(c.gels ?? []);
  const registres = await lireRegistres(path.join(c.repertoire, "worm"));
  const parCle = new Map();
  for (const { ligne } of registres) {
    if (!parCle.has(ligne.key)) parCle.set(ligne.key, new Map());
    parCle.get(ligne.key).set(ligne.version_id, ligne);
  }
  const listees = new Map();
  for (const v of l.versions) {
    if (!listees.has(v.key)) listees.set(v.key, []);
    listees.get(v.key).push(v);
  }
  let nonConformes = 0;
  let inattendues = 0;
  let lues = 0;
  for (const [cle, vs] of listees) {
    const relatif = cle.slice(c.worm.prefix.length);
    const copie = SOUS_PREFIXES_ECRIVAIN.some((s) => relatif.startsWith(s));
    const reelles = vs.filter((v) => !v.delete_marker);
    const marqueur = vs.some((v) => v.delete_marker);
    // Pas 3 : comparaison au registre des copies (copies de l'écrivain seulement).
    if (copie) {
      const inscrites = parCle.get(cle);
      const manquante = inscrites && [...inscrites.keys()].some((id) => id !== null && !reelles.some((v) => v.version_id === id));
      if (reelles.length > 1 || marqueur || manquante) {
        inattendues++;
        c.journal.consigner("warning", "worm", "worm_versions_unexpected", { key: cle, versions: reelles.length, marqueur, version_inscrite_absente: Boolean(manquante) });
      }
    }
    // Pas 2 : verrou et gel de chaque version.
    for (const v of reelles) {
      let et;
      try {
        et = await c.operations.etat(cle, v.version_id);
      } catch {
        et = null;
      }
      if (!et || et.statut !== 200) throw new Error(`état de ${cle} : statut ${et?.statut ?? "injoignable"}`);
      lues++;
      const ligne = parCle.get(cle)?.get(v.version_id) ?? null;
      const copieA = ligne ? decoderHorodatage(ligne.copied_at) : lireEcheance(v.last_modified);
      const verdict = controlerVerrou({
        type: c.worm.type,
        entetes: et.entetes,
        json: et.json,
        mode: c.worm.mode,
        echeanceMin: copieA === null ? 0 : echeanceMinimale(copieA, c.worm.retain_days),
        gelAttendu: gelees.has(`${cle}#${v.version_id}`) || (copie && c.worm.legal_hold_on_write === true),
      });
      c.metriques?.compter("noortrace_worm_lock_checks_total", { verdict: verdict.verdict, when: "releve" });
      if (verdict.verdict !== "conforme") {
        nonConformes++;
        c.journal.consigner("error", "worm", "worm_lock_check", { key: cle, version_id: v.version_id, verdict: verdict.verdict, reasons: verdict.reasons, notes: verdict.notes, when: "releve" });
      }
      if (copie && !ligne && reelles.length === 1 && c.epoque) {
        // Version sans ligne au registre (registre perdu ou incomplet) : inscrite,
        // sans alerte, avec l'empreinte relue et la date de création du support.
        try {
          const e = await c.operations.empreinte(cle, v.version_id);
          const cree = lireEcheance(v.last_modified ?? e.last_modified);
          if (e.statut === 200 && cree !== null) {
            await inscrireCopie(path.join(c.repertoire, "worm"), c.epoque, {
              key: cle,
              version_id: v.version_id,
              sha256: e.sha256,
              length: e.longueur,
              copied_at: ecrireHorodatage(cree),
              lock: { verdict: verdict.verdict, retain_until: verdict.retain_until, legal_hold: verdict.legal_hold },
            });
          }
        } catch {
          // inscription au mieux : le registre ne fait foi de rien
        }
      }
    }
  }
  const duree = c.murale() - t0;
  c.journal.consigner(nonConformes || inattendues ? "warning" : "info", "worm", "worm_lock_audit", { versions: lues, non_conformes: nonConformes, inattendues, duree_ms: duree });
  c.metriques?.jauge("noortrace_worm_lock_nonconforming", {}, nonConformes);
  c.metriques?.jauge("noortrace_worm_versions_unexpected", {}, inattendues);
  c.metriques?.jauge("noortrace_worm_last_audit_age_s", {}, 0);
  return { versions: lues, non_conformes: nonConformes, inattendues, duree_ms: duree };
}

/**
 * Rétention par défaut du support (EX-17.5) : `Mode` égal au mode configuré,
 * `Days` égal à `retain_days`, ou `Years × 365` au moins égal.
 * @returns {Promise<{verdict: string, mode: string|null, days: number|null, years: number|null}>}
 */
export async function controlerConfigurationVerrou(c) {
  const r = await c.operations.configurationVerrou();
  if (r.statut !== 200 || !r.config) {
    c.journal.consigner("error", "worm", "worm_lock_config_check", { verdict: "non_conforme", mode: null, days: null, years: null, statut: r.statut });
    return { verdict: "non_conforme", mode: null, days: null, years: null };
  }
  const k = r.config;
  const attendu = c.worm.mode === "governance" ? "GOVERNANCE" : "COMPLIANCE";
  const duree = k.days !== null ? k.days === c.worm.retain_days : k.years !== null && k.years * 365 >= c.worm.retain_days;
  const verdict = k.enabled === "Enabled" && k.mode === attendu && duree ? "conforme" : "non_conforme";
  c.journal.consigner(verdict === "conforme" ? "info" : "error", "worm", "worm_lock_config_check", { verdict, mode: k.mode, days: k.days, years: k.years });
  return { verdict, mode: k.mode, days: k.days, years: k.years };
}

/**
 * Supervision des copies dans le démon : planifie les contrôles d'EX-17.5 à
 * EX-17.7 sur l'horloge murale du cœur.
 */
export class SupervisionWorm {
  /**
   * @param {import("./copies.mjs").ServiceCopiesWorm} copies
   * @param {{intervalleMs?: number}} [o]
   */
  constructor(copies, o = {}) {
    this.copies = copies;
    this.intervalle = o.intervalleMs ?? 60000;
    this.vus = new Set();
    this.dernierReleve = null;
    this.heure = null;
    this.jour = null;
    this.gels = [];
  }

  get coeur() {
    return this.copies.coeur;
  }

  _ctx() {
    const c = this.coeur;
    return {
      operations: this.copies.operations,
      worm: this.copies.worm,
      repertoire: c.repertoire,
      epoque: c.ecrivain?.epoque ?? null,
      journal: c.journal,
      metriques: c.metriques,
      murale: () => c.horlogeBrute.murale(),
      vus: this.vus,
      gels: this.gels,
    };
  }

  _resultat(check, ok, data = {}) {
    this.coeur.journal.consigner(ok ? "info" : "error", "supervision", "integrity_check", { check, ok, ...data });
    if (!ok) this.coeur.metriques.compter("noortrace_integrity_check_failures_total", { check });
  }

  armer() {
    const tour = async () => {
      if (this.arrete) return;
      await this.tic().catch(() => {});
      this.minuteur = setTimeout(tour, this.intervalle);
      this.minuteur.unref?.();
    };
    this.minuteur = setTimeout(tour, Math.min(this.intervalle, 5000));
    this.minuteur.unref?.();
  }

  arreter() {
    this.arrete = true;
    clearTimeout(this.minuteur);
  }

  /** Un tour : contrôles échus selon l'horloge murale. */
  async tic() {
    const c = this.coeur;
    if (!c?.ecrivain || c.passif) return;
    const t = c.horlogeBrute.murale();
    if (this.copies.enAttente.size) await this.copies.balayer().catch(() => {});
    const heure = Math.floor(t / 3600000);
    const jour = Math.floor(t / JOUR_MS);
    if (this.heure === null || heure !== this.heure) {
      this.heure = heure;
      await this.horaire(t).catch(() => {});
    }
    if (this.jour === null || jour !== this.jour) {
      this.jour = jour;
      await this.quotidien(t).catch(() => {});
    }
    const periode = (this.copies.worm.lock_audit_interval_days ?? 30) * JOUR_MS;
    if (this.dernierReleve === null || t - this.dernierReleve >= periode) {
      await this.releve().catch((e) => this._resultat("copie_worm", false, { releve: "echec", message: String(e?.message ?? e) }));
    }
    if (this.dernierReleve !== null) c.metriques.jauge("noortrace_worm_last_audit_age_s", {}, Math.floor((c.horlogeBrute.murale() - this.dernierReleve) / 1000));
  }

  /** Relevé de verrouillage (EX-17.6), précédé de la lecture du registre des gels. */
  async releve() {
    const g = await lireRegistreGels(this._ctx());
    if (!g.ok) this._resultat("registre_gels", false);
    this.gels = g.gels;
    const r = await releverVerrouillage(this._ctx());
    this.dernierReleve = this.coeur.horlogeBrute.murale();
    return r;
  }

  /** Contrôles horaires d'EX-17.5 propres au support (copies). */
  async horaire(t) {
    const c = this.coeur;
    await this.copies.balayer().catch(() => {});
    // Segments copiés dans l'heure : SHA-256 de la copie WORM (EX-12.17).
    const lignes = (await lireRegistres(path.join(c.repertoire, "worm"))).map((x) => x.ligne).filter((l) => l.copied_at && decoderHorodatage(l.copied_at) >= t - 3600000);
    for (const l of lignes.filter((x) => x.key.slice(this.copies.prefixe.length).startsWith("segments/"))) {
      const local = path.join(c.repertoire, l.key.slice(this.copies.prefixe.length));
      let shaLocal = null;
      try {
        shaLocal = sha256Hex(new Uint8Array(await fs.readFile(local)));
      } catch {
        shaLocal = null;
      }
      let ok = false;
      try {
        const e = await this.copies.operations.empreinte(l.key, l.version_id);
        ok = e.statut === 200 && e.sha256 === l.sha256 && (shaLocal === null || shaLocal === e.sha256);
      } catch {
        ok = false;
      }
      this._resultat("copie_worm", ok, { key: l.key, version_id: l.version_id });
    }
  }

  /** Contrôles quotidiens d'EX-17.5 (rétention du support) et d'EX-17.7. */
  async quotidien(t) {
    const c = this.coeur;
    void t;
    // Rétention par défaut du support.
    try {
      const v = await controlerConfigurationVerrou({ operations: this.copies.operations, worm: this.copies.worm, journal: c.journal });
      this._resultat("configuration_worm", v.verdict === "conforme", { mode: v.mode, days: v.days, years: v.years });
    } catch {
      this._resultat("configuration_worm", false);
    }
    // Registre des gels et état de gel des versions des gels actifs.
    const g = await lireRegistreGels(this._ctx());
    if (!g.ok) this._resultat("registre_gels", false);
    this.gels = g.gels;
    const attendues = versionsAttenduesGelees(g.gels);
    for (const gel of g.gels.filter((x) => x.etat.actif)) {
      for (const o of gel.objets) {
        if (!attendues.has(`${o.key}#${o.version_id}`)) continue;
        let etat = "illisible";
        try {
          const lu = await this.copies.operations.lireGel(o.key, o.version_id);
          etat = lu.statut === 200 ? this.copies.operations.etatGel(lu) : "illisible";
        } catch {
          etat = "illisible";
        }
        if (etat !== "on") {
          c.journal.consigner("error", "worm", "worm_lock_check", { key: o.key, version_id: o.version_id, verdict: "non_conforme", reasons: [etat === "illisible" ? "gel_illisible" : "gel_absent"], notes: [], when: "registre_gels", gel_id: gel.gel_id });
          c.metriques.compter("noortrace_worm_lock_checks_total", { verdict: "non_conforme", when: "releve" });
        }
      }
    }
  }
}
