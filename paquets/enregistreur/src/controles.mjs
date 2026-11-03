// Contrôles périodiques de la supervision (CT-2 EX-17.5), part qui ne dépend
// pas d'un support WORM : « toutes les heures, après la clôture de période,
// la vérification que la période close a son manifeste et sa signature et que
// la continuité de CT-1 §10.3 tient, [...] et le health() du signataire ; une
// fois par jour, la relecture et la vérification complètes des segments
// fermés de la journée (EX-12.10, pas 2, sur tout le segment) ». Ces
// contrôles tournent avec ou sans `storage.seal.worm` ; la comparaison des
// copies WORM, la rétention du support et le registre des gels restent au
// lot WORM (`worm/controles.mjs`). Les signatures sont vérifiées avec les clés
// de la chaîne : clés annoncées par les rotations, puis clé initiale du
// signataire (jamais la seule clé courante, qui ne vérifie pas les segments
// signés avant une rotation). Résultats : lignes `integrity_check` et
// `noortrace_integrity_check_failures_total` ; rien ne bloque un appel (14.2).

import fs from "node:fs/promises";
import path from "node:path";
import { ZERO32, hacherManifeste, hexVersOctets, verifierContinuite, verifierSignatureManifeste, decoderUtf8 } from "@noortrace/noyau";
import { listerSegments } from "./segments.mjs";
import { lireManifeste, nomsManifeste } from "./periodes.mjs";
import { ClesChaine, verifierSegment } from "./verification.mjs";

const HEURE_MS = 3600000;
const JOUR_MS = 86400000;
/** Délai après l'heure pleine avant le contrôle horaire : la clôture a lieu au tic de l'écrivain (1 s). */
const APRES_CLOTURE_MS = 10000;

/** Dernier `hash` d'un segment fermé (dernière ligne), ou `prev_hash` de son en-tête s'il est vide. */
async function dernierHash(chemin) {
  const lignes = decoderUtf8(new Uint8Array(await fs.readFile(chemin))).split("\n").filter(Boolean);
  const derniere = JSON.parse(lignes[lignes.length - 1]);
  return lignes.length > 1 ? derniere.hash : derniere.prev_hash;
}

export class SupervisionIntegrite {
  /**
   * @param {import("./coeur.mjs").Coeur} coeur
   * @param {{intervalleMs?: number}} [o]
   */
  constructor(coeur, o = {}) {
    this.coeur = coeur;
    this.intervalle = o.intervalleMs ?? 60000;
    this.heure = null;
    this.jour = null;
    /** Segments fermés déjà relus en entier par ce processus. */
    this.verifies = new Set();
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

  _resultat(check, ok, data = {}) {
    this.coeur.journal.consigner(ok ? "info" : "error", "supervision", "integrity_check", { check, ok, ...data });
    if (!ok) this.coeur.metriques.compter("noortrace_integrity_check_failures_total", { check });
  }

  /** Clé publique d'un `key_id` : annoncée par une rotation de la chaîne, sinon celle du signataire. */
  async _clePublique(id) {
    const c = this.coeur;
    const annoncee = c.index?.cles?.get(id)?.public_key ?? null;
    if (annoncee) return hexVersOctets(annoncee, 32);
    try {
      const p = await c.signataire.clePublique(id);
      return p instanceof Uint8Array ? p : hexVersOctets(p, 32);
    } catch {
      return null;
    }
  }

  /** Un tour : contrôles échus selon l'horloge murale du cœur. */
  async tic() {
    const c = this.coeur;
    if (!c?.ecrivain || c.passif || c.intervention) return;
    const t = c.horlogeBrute.murale();
    const heure = Math.floor(t / HEURE_MS);
    const jour = Math.floor(t / JOUR_MS);
    if (heure !== this.heure && t % HEURE_MS >= APRES_CLOTURE_MS) {
      this.heure = heure;
      await this.horaire(t).catch(() => {});
    }
    if (jour !== this.jour) {
      this.jour = jour;
      await this.quotidien(t).catch(() => {});
    }
  }

  /** Contrôles horaires d'EX-17.5 : période close (manifeste, signature, continuité), signataire. */
  async horaire(t) {
    const c = this.coeur;
    const P = Math.floor(t / HEURE_MS) * 3600 - 3600;
    const dir = path.join(c.repertoire, "manifestes");
    const m = await lireManifeste(dir, P).catch(() => null);
    if (!m) {
      // Aucune période close encore (journal plus jeune qu'une heure) : rien à contrôler.
      const existe = (await fs.readdir(dir).catch(() => [])).some((n) => n.endsWith(".json") && Number(n.slice(8, 18)) < P);
      if (existe) this._resultat("manifeste", false, { period_start: P });
    } else {
      let sig = false;
      try {
        const pub = await this._clePublique(m.manifeste.recorder_key_id);
        sig = Boolean(pub) && m.signature.recorder_key_id === m.manifeste.recorder_key_id && m.signature.period_hash === hacherManifeste(m.manifeste) && verifierSignatureManifeste(m.manifeste, m.signature.sig, pub);
      } catch {
        sig = false;
      }
      this._resultat("manifeste", true, { period_start: P });
      this._resultat("signature", sig, { period_start: P });
      const premier = !(await fs.stat(path.join(dir, nomsManifeste(P - 3600).manifeste)).then(() => true, () => false));
      if (!premier) {
        const p = await lireManifeste(dir, P - 3600).catch(() => null);
        this._resultat("continuite", Boolean(p) && verifierContinuite(p.manifeste, m.manifeste).valide, { period_start: P });
      }
    }
    let sante = "erreur";
    try {
      sante = await c.signataire.sante();
    } catch {
      sante = "erreur";
    }
    this._resultat("signataire", sante === "ok");
  }

  /**
   * Contrôle quotidien d'EX-17.5 : relecture et vérification complètes
   * (EX-12.10 pas 2 sur tout le segment) des segments fermés de la journée :
   * ceux dont la dernière écriture date de moins d'un jour, et ceux que cet
   * écrivain a fermés (par rotation, ou le dernier de l'instance précédente,
   * fermé par sa seule existence, EX-13.9), non encore relus.
   */
  async quotidien(t) {
    const c = this.coeur;
    const segments = await listerSegments(path.join(c.repertoire, "segments"));
    const courant = c.ecrivain?.segment?.nom ?? null;
    const fermesIci = new Set(c.ecrivain?.segmentsFermes ?? []);
    const cles = new ClesChaine((id) => this._clePublique(id));
    for (let k = 0; k < segments.length; k++) {
      const s = segments[k];
      if (s.nom === courant || this.verifies.has(s.nom)) continue;
      let recent = false;
      try {
        recent = (await fs.stat(s.chemin)).mtimeMs >= t - JOUR_MS;
      } catch {
        recent = false;
      }
      if (!recent && !fermesIci.has(s.nom)) continue;
      let ok = false;
      let raison = null;
      try {
        const prevHash = k > 0 ? await dernierHash(segments[k - 1].chemin) : s.first_seq === 1 ? ZERO32 : null;
        const v = await verifierSegment(new Uint8Array(await fs.readFile(s.chemin)), {
          nom: s.nom, prevHash, firstSeq: s.first_seq, cles, id: { org_id: c.org_id, journal_id: c.journal_id },
        });
        ok = v.incident === null;
        raison = v.incident?.raison ?? v.incident?.kind ?? null;
      } catch (e) {
        ok = false;
        raison = String(e?.message ?? e);
      }
      if (ok) this.verifies.add(s.nom);
      this._resultat("relecture", ok, { segment: s.nom, ...(raison ? { raison } : {}) });
    }
  }
}
