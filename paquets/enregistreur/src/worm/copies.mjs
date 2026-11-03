// Copies WORM de l'écrivain (CT-2 §12.6) : implémentation de `SupportWorm`
// (INTERFACES.md, section f). L'écrivain appelle `copier` sans attendre pour
// chaque segment fermé, et à chaque clôture pour le manifeste, sa signature et
// la série des points (EX-12.16, EX-12.27). Pour chaque fichier, dans l'ordre :
//   1. garde de clé : la clé est sous `<prefix>` et jamais sous
//      `<prefix>gels/`, où seuls les gardiens écrivent (EX-12.32) ;
//   2. jeton de clôture au scellement (EX-13.5 (2)) : un segment d'époque
//      inférieure à celle du dernier segment scellé est refusé ;
//   3. copie conditionnelle à l'absence, `Content-MD5`, gel à l'écriture avec
//      `legal_hold_on_write` (EX-12.16, EX-12.31, EX-12.39) ; `409` réessayé ;
//      `412` : un autre écrivain a gagné, ou une copie antérieure de cette
//      instance a abouti sans réponse : la version courante est relue et
//      comparée au fichier local (SHA-256), jamais réécrite ;
//   4. contrôle du verrou de la version écrite (EX-12.33), `worm_lock_check`,
//      `noortrace_worm_lock_checks_total{when="copie"}` ; un verdict
//      `non_conforme` ne fait ni réécrire ni supprimer (le rôle ne le peut
//      pas) : il est consigné en erreur (alerte critique) ;
//   5. ligne du registre des copies (EX-12.29) ;
//   6. avec `copy_pieces`, copie des pièces référencées par le segment.
// Une copie en échec est consignée (`worm_copy_failed`) et réessayée par le
// balayage de la supervision ; elle ne bloque jamais un appel (14.2).

import fs from "node:fs/promises";
import path from "node:path";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { SupportWorm, cleObjetWorm } from "../worm.mjs";
import { lireSegmentFerme } from "../segments.mjs";
import { controlerVerrou, echeanceMinimale, lireEcheance } from "./verrou.mjs";
import { lireRegistres, inscrireCopie, piecesReferencees, SOUS_PREFIXES_ECRIVAIN } from "./registre.mjs";
import { SupervisionWorm } from "./controles.mjs";
import { ErreurTransport } from "./s3.mjs";

const MOTIF_SEGMENT = /^seg-([0-9]{16})-([0-9]{20})\.ndjson$/;


export class ServiceCopiesWorm extends SupportWorm {
  /**
   * @param {object} o
   * @param {object} o.worm membre `storage.seal.worm`
   * @param {object} o.operations opérations du support (support.mjs), identifiants de l'écrivain
   */
  constructor(o) {
    super();
    this.worm = o.worm;
    this.prefixe = o.worm.prefix;
    this.operations = o.operations;
    this.file = Promise.resolve();
    this.enAttente = new Map();
    this.nonConformes = 0;
  }

  /**
   * Crochet lu par le cœur : répertoire du journal, journal d'exploitation,
   * métriques, horloge murale, époque de l'écrivain.
   * @param {import("../coeur.mjs").Coeur} coeur
   */
  lier(coeur) {
    this.coeur = coeur;
    this.repertoire = coeur.repertoire;
    this.journal = coeur.journal;
    this.metriques = coeur.metriques;
    this.murale = () => coeur.horlogeBrute.murale();
  }

  get dirWorm() {
    return path.join(this.repertoire, "worm");
  }

  /**
   * Copie un fichier fermé (interface `SupportWorm`) : ne rejette jamais ;
   * rend la version écrite, ou `null` si la copie est en échec (consignée).
   * @param {{cle: string, chemin: string, nature: string}} demande
   * @returns {Promise<{version_id: string|null}>}
   */
  copier(demande) {
    const p = this.file.then(() => this._copier(demande));
    this.file = p.catch(() => {});
    return p.catch((e) => {
      this._echec(demande, "erreur", { message: String(e?.message ?? e) });
      return { version_id: null };
    });
  }

  _echec(d, raison, extra = {}) {
    this.enAttente.set(d.cle, d);
    this.journal?.consigner("warning", "worm", "worm_copy_failed", { key: d.cle, nature: d.nature, raison, ...extra });
    return { version_id: null };
  }

  async _registres() {
    return lireRegistres(this.dirWorm);
  }

  /** Plus grande époque des segments scellés (registres de toutes les époques). */
  async epoqueScellee() {
    let max = 0;
    for (const { ligne } of await this._registres()) {
      const k = ligne.key.startsWith(this.prefixe) ? ligne.key.slice(this.prefixe.length) : null;
      const r = k && k.startsWith("segments/") ? MOTIF_SEGMENT.exec(k.slice(9)) : null;
      if (r) max = Math.max(max, Number(r[2]));
    }
    return max;
  }

  async _copier(d) {
    const relatif = d.cle.startsWith(this.prefixe) ? d.cle.slice(this.prefixe.length) : null;
    if (relatif === null || relatif.startsWith("gels/") || !SOUS_PREFIXES_ECRIVAIN.some((s) => relatif.startsWith(s))) {
      return this._echec(d, "cle_refusee");
    }
    const epoque = this.coeur?.ecrivain?.epoque ?? null;
    if (!epoque) return this._echec(d, "ecrivain_absent");
    if (d.nature === "segment") {
      const r = MOTIF_SEGMENT.exec(path.basename(relatif));
      if (r && Number(r[2]) < (await this.epoqueScellee())) {
        this.enAttente.delete(d.cle);
        this.journal?.consigner("error", "worm", "worm_copy_failed", { key: d.cle, nature: d.nature, raison: "epoque_inferieure" });
        return { version_id: null };
      }
    }
    let octets;
    try {
      octets = new Uint8Array(await fs.readFile(d.chemin));
    } catch {
      return this._echec(d, "fichier_illisible");
    }
    const sha256 = sha256Hex(octets);
    const deja = (await this._registres()).find((x) => x.ligne.key === d.cle && x.ligne.sha256 === sha256);
    if (deja) {
      this.enAttente.delete(d.cle);
      return { version_id: deja.ligne.version_id };
    }
    let r;
    try {
      r = await this.operations.copier(d.cle, octets, this.worm.legal_hold_on_write === true);
    } catch (e) {
      if (e instanceof ErreurTransport) return this._echec(d, "injoignable", { message: e.message });
      throw e;
    }
    let version_id;
    let copieA;
    if (r.statut === 200) {
      version_id = r.version_id;
      copieA = this.murale();
    } else if (r.statut === 412) {
      // Un objet existe déjà sous cette clé : il n'est jamais réécrit.
      const lu = await this.operations.empreinte(d.cle).catch(() => null);
      if (!lu || lu.statut !== 200) return this._echec(d, "precondition", { statut: 412 });
      if (lu.sha256 !== sha256) {
        this.enAttente.delete(d.cle);
        this.journal?.consigner("error", "worm", "worm_copy_failed", { key: d.cle, nature: d.nature, raison: "objet_present_different", statut: 412 });
        return { version_id: null };
      }
      version_id = lu.version_id;
      copieA = lireEcheance(lu.last_modified) ?? this.murale();
    } else {
      return this._echec(d, r.statut === 403 ? "refuse" : "statut", { statut: r.statut, code: r.code ?? null });
    }
    // Contrôle du verrou de la version écrite (EX-12.33).
    let et;
    try {
      et = await this.operations.etat(d.cle, version_id);
    } catch {
      et = null;
    }
    if (!et || et.statut !== 200) return this._echec(d, "controle_impossible", { statut: et?.statut ?? null });
    const lock = controlerVerrou({
      type: this.worm.type,
      entetes: et.entetes,
      json: et.json,
      mode: this.worm.mode,
      echeanceMin: echeanceMinimale(copieA, this.worm.retain_days),
      gelAttendu: this.worm.legal_hold_on_write === true,
    });
    this.metriques?.compter("noortrace_worm_lock_checks_total", { verdict: lock.verdict, when: "copie" });
    this.journal?.consigner(lock.verdict === "conforme" ? "info" : "error", "worm", "worm_lock_check", {
      key: d.cle, version_id, verdict: lock.verdict, reasons: lock.reasons, notes: lock.notes, when: "copie",
    });
    if (lock.verdict !== "conforme") {
      this.nonConformes++;
      this.metriques?.jauge("noortrace_worm_lock_nonconforming", {}, this.nonConformes);
    }
    await inscrireCopie(this.dirWorm, epoque, {
      key: d.cle,
      version_id,
      sha256,
      length: octets.length,
      copied_at: ecrireHorodatage(copieA),
      lock: { verdict: lock.verdict, retain_until: lock.retain_until, legal_hold: lock.legal_hold },
    });
    this.enAttente.delete(d.cle);
    // Pièces référencées par le segment (copy_pieces, EX-12.16).
    if (d.nature === "segment" && this.worm.copy_pieces === true) {
      let evts = [];
      try {
        evts = lireSegmentFerme(octets).evenements;
      } catch {
        evts = [];
      }
      for (const s of piecesReferencees(evts)) {
        const h = s.slice(2);
        const rel = `pieces/${h.slice(0, 2)}/${h}`;
        const chemin = path.join(this.repertoire, rel);
        if (await fs.stat(chemin).then(() => true, () => false)) {
          this.file = this.file.then(() => this._copier({ cle: cleObjetWorm(this.prefixe, rel), chemin, nature: "piece" })).catch(() => {});
        }
      }
    }
    return { version_id };
  }

  /**
   * Fichiers locaux fermés qui doivent avoir une copie (EX-12.16, EX-12.27) :
   * segments fermés, manifestes et signatures, séries des périodes closes,
   * fichiers d'ancres, et pièces référencées avec `copy_pieces`.
   * @returns {Promise<{cle: string, chemin: string, nature: string}[]>}
   */
  async fichiersACopier() {
    const r = [];
    const lister = async (d) => (await fs.readdir(path.join(this.repertoire, d)).catch(() => [])).sort();
    const courant = this.coeur?.ecrivain?.segment?.nom ?? null;
    const ajouter = (rel, nature) => r.push({ cle: cleObjetWorm(this.prefixe, rel), chemin: path.join(this.repertoire, rel), nature });
    const segments = (await lister("segments")).filter((n) => MOTIF_SEGMENT.test(n) && n !== courant);
    for (const n of segments) ajouter(`segments/${n}`, "segment");
    const manifestes = await lister("manifestes");
    for (const n of manifestes) {
      if (/^periode-[0-9]{10}\.json$/.test(n)) ajouter(`manifestes/${n}`, "manifeste");
      else if (/^periode-[0-9]{10}\.sig$/.test(n)) {
        ajouter(`manifestes/${n}`, "signature");
        const serie = `points/${n.replace(/\.sig$/, ".ndjson")}`;
        if (await fs.stat(path.join(this.repertoire, serie)).then(() => true, () => false)) ajouter(serie, "points");
      }
    }
    const parcourir = async (rel) => {
      for (const n of await lister(rel)) {
        const sous = `${rel}/${n}`;
        const st = await fs.stat(path.join(this.repertoire, sous)).catch(() => null);
        if (st?.isDirectory()) await parcourir(sous);
        else if (st?.isFile()) ajouter(sous, "ancre");
      }
    };
    await parcourir("ancres");
    if (this.worm.copy_pieces === true) {
      const vues = new Set();
      for (const n of segments) {
        let evts = [];
        try {
          evts = lireSegmentFerme(new Uint8Array(await fs.readFile(path.join(this.repertoire, "segments", n)))).evenements;
        } catch {
          continue;
        }
        for (const s of piecesReferencees(evts)) {
          const h = s.slice(2);
          if (vues.has(h)) continue;
          vues.add(h);
          const rel = `pieces/${h.slice(0, 2)}/${h}`;
          if (await fs.stat(path.join(this.repertoire, rel)).then(() => true, () => false)) ajouter(rel, "piece");
        }
      }
    }
    return r;
  }

  /**
   * Balayage de la supervision (EX-12.16 : « réessayée par la supervision ») :
   * copie ce qui manque au registre et met à jour
   * `noortrace_worm_copy_pending` (segments fermés sans copie vérifiée).
   * @returns {Promise<{copies: number, manquantes: number}>}
   */
  async balayer() {
    if (!this.coeur?.ecrivain) return { copies: 0, manquantes: 0 };
    const inscrites = new Set((await this._registres()).map((x) => x.ligne.key));
    const manquants = (await this.fichiersACopier()).filter((f) => !inscrites.has(f.cle));
    let copies = 0;
    for (const f of manquants) {
      const r = await this.copier(f);
      if (r.version_id !== null) copies++;
    }
    const inscrites2 = new Set((await this._registres()).map((x) => x.ligne.key));
    const restants = (await this.fichiersACopier()).filter((f) => f.nature === "segment" && !inscrites2.has(f.cle)).length;
    this.metriques?.jauge("noortrace_worm_copy_pending", {}, restants);
    return { copies, manquantes: restants };
  }

  /** Crochet du cœur (`_armerMinuteurs`) : contrôles périodiques d'EX-17.5 à EX-17.7. */
  armer() {
    this.supervision ??= new SupervisionWorm(this);
    this.supervision.armer();
  }

  /** Crochet du cœur (`arreter`). */
  arreter() {
    this.supervision?.arreter();
  }

  /** Attend la fin des copies en cours (tests, arrêt). */
  async vider() {
    await this.file;
  }
}
