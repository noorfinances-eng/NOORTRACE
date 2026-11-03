// Vérification complète d'un répertoire de journal (disposition de CT-2
// EX-12.1), sans réseau : chaque segment ligne à ligne comme le dernier à la
// reprise (EX-12.10 pas 2 : schéma, `seq`, `prev_hash`, `hash` recalculé,
// signature sous la clé en vigueur), la suite des segments (`first_seq`,
// `prev_hash` d'en-tête, époques non décroissantes, EX-12.10 pas 1), la chaîne
// entière par le noyau (CT-1 E-1 à E-11, C-1 à C-3) avec les clés de la chaîne
// (clé initiale fournie, puis chaque clé annoncée par une rotation), chaque
// manifeste recalculé sur ses événements, sa signature (CT-1 §10.2, P-5) et la
// continuité (§10.3), chaque série de points de contrôle (CT-1 §10.5), et le
// SHA-256 de chaque pièce contre son nom (8.4).
//
// Employée par la reconstruction depuis les copies WORM (EX-12.17, CT-8 §11.4
// chemin B : « les fichiers restaurés sont identiques octet pour octet » à ce
// que les copies désignent ; sans registre des copies, seule la chaîne et ses
// signatures le prouvent), par le démon au premier démarrage sur un journal
// reconstruit (relecture d'EX-12.10 « avant d'écrire »), et par la
// supervision quotidienne (EX-17.5).

import fs from "node:fs/promises";
import path from "node:path";
import {
  ZERO32, annonceRotation, construireManifeste, egaliteJson, hacherManifeste, hacherPoint, hexVersOctets, octetsVersHex,
  sha256Hex, verifierContinuite, verifierJournal, verifierSeriePointsDeControle, verifierSignatureManifeste,
  verifierSignaturePoint, analyserJson,
} from "@noortrace/noyau";
import { listerSegments, relireSegment } from "./segments.mjs";
import { clesDuJournal } from "./dossier.mjs";
import { decouperLignes } from "./fichiers.mjs";
import { analyserJsonIntegral } from "./jcs-integral.mjs";

const versOctets = (p) => (p === null || p === undefined ? null : p instanceof Uint8Array ? p : hexVersOctets(p, 32));

/**
 * Résout les clés publiques d'un journal : clés annoncées par les rotations
 * de la chaîne, puis, pour les autres (la clé initiale), la fonction fournie.
 */
export class ClesChaine {
  /** @param {(keyId: string) => Promise<Uint8Array|string|null>} [externe] */
  constructor(externe) {
    this.externe = externe ?? null;
    /** @type {Map<string, Uint8Array>} */
    this.connues = new Map();
    this.essayees = new Set();
  }

  /** Inscrit les clés annoncées par les rotations d'une liste d'événements. */
  noterRotations(evenements) {
    for (const e of evenements) {
      const a = e?.execution?.tool === "noortrace.journal.rotation-cle" ? annonceRotation(e) : null;
      if (a) this.connues.set(a.new_key_id, hexVersOctets(a.new_public_key, 32));
    }
  }

  /** @param {string} id @returns {Promise<Uint8Array|null>} */
  async resoudre(id) {
    if (this.connues.has(id)) return this.connues.get(id);
    if (!this.externe || this.essayees.has(id)) return null;
    this.essayees.add(id);
    let p = null;
    try {
      p = versOctets(await this.externe(id));
    } catch {
      p = null;
    }
    if (p) this.connues.set(id, p);
    return p;
  }

  /** @param {string} id @returns {Uint8Array|null} */
  connue(id) {
    return this.connues.get(id) ?? null;
  }
}

async function lireSiPresent(chemin) {
  try {
    return new Uint8Array(await fs.readFile(chemin));
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw e;
  }
}

/**
 * Vérifie un segment fermé ou le dernier, ligne à ligne (EX-12.10 pas 2).
 * Une fin incomplète n'est admise que pour le dernier segment (`dernier`).
 * @param {Uint8Array} octets
 * @param {{nom: string, prevHash: string|null, firstSeq: number, cles: ClesChaine, id: {org_id: string, journal_id: string}, dernier?: boolean}} o
 * @returns {Promise<{incident: object|null, entete: object|null, evenements: object[]}>}
 */
export async function verifierSegment(octets, o) {
  const premiere = decouperLignes(octets)[0];
  let entete = null;
  try {
    entete = premiere?.complete ? analyserJson(premiere.octets) : null;
  } catch {
    entete = null;
  }
  if (!entete || entete.org_id !== o.id.org_id || entete.journal_id !== o.id.journal_id) {
    return { incident: { key: `segments/${o.nom}`, kind: "entete_invalide" }, entete: null, evenements: [] };
  }
  // Clé de l'en-tête et clés des rotations du segment : la clé publique de
  // l'en-tête est résolue avant la lecture (relireSegment est synchrone).
  await o.cles.resoudre(entete.recorder_key_id);
  const r = relireSegment(octets, {
    verifierSignatures: true,
    clePublique: (id) => o.cles.connue(id),
    prevHashAttendu: o.prevHash,
    firstSeqAttendu: o.firstSeq,
  });
  o.cles.noterRotations(r.evenements);
  if (r.corruption) {
    const kind = r.corruption.raison === "cle_inconnue" ? "cle_inconnue" : "copie_alteree";
    return { incident: { key: `segments/${o.nom}`, kind, raison: r.corruption.raison, seq: r.corruption.seq ?? null }, entete, evenements: r.evenements };
  }
  if (r.tronque && !o.dernier) {
    return { incident: { key: `segments/${o.nom}`, kind: "copie_alteree", raison: "fin_incomplete" }, entete, evenements: r.evenements };
  }
  return { incident: null, entete, evenements: r.evenements };
}

/**
 * Vérifie tout un répertoire de journal.
 * @param {string} rep répertoire `<root>/<org>/<journal>`
 * @param {{org_id: string, journal_id: string, clePublique?: (keyId: string) => Promise<Uint8Array|string|null>,
 *   signatureAbsenteAdmise?: (nom: string) => boolean, dernierOuvert?: boolean}} o
 *   `signatureAbsenteAdmise` : manifeste dont la signature manquante est complétée par l'appelant (EX-12.24, reprise) ;
 *   `dernierOuvert` : le dernier segment peut finir par une écriture tronquée (relecture du démon)
 * @returns {Promise<{incidents: object[], evenements: object[], lastSeq: number, lastHash: string, cles: object|null}>}
 */
export async function verifierRepertoireJournal(rep, o) {
  const incidents = [];
  const id = { org_id: o.org_id, journal_id: o.journal_id };
  const cles = new ClesChaine(o.clePublique);
  const evenements = [];
  const hashes = new Map();
  let attendu = 1;
  let prev = ZERO32;
  let epoque = 0;
  const segments = await listerSegments(path.join(rep, "segments"));
  for (let k = 0; k < segments.length; k++) {
    const s = segments[k];
    if (s.epoch < epoque) incidents.push({ key: `segments/${s.nom}`, kind: "epoque_decroissante" });
    epoque = Math.max(epoque, s.epoch);
    if (s.first_seq !== attendu) {
      incidents.push({ key: `segments/${s.nom}`, kind: "segment_absent", attendu });
      break;
    }
    const v = await verifierSegment(new Uint8Array(await fs.readFile(s.chemin)), {
      nom: s.nom, prevHash: prev, firstSeq: attendu, cles, id, dernier: o.dernierOuvert === true && k === segments.length - 1,
    });
    if (v.incident) {
      incidents.push(v.incident);
      break;
    }
    for (const e of v.evenements) {
      evenements.push(e);
      hashes.set(e.seq, e.hash);
    }
    if (v.evenements.length) {
      attendu = v.evenements.at(-1).seq + 1;
      prev = v.evenements.at(-1).hash;
    }
  }

  // Chaîne entière par le noyau, clés de la chaîne (cles.json de CT-1 §11.2).
  let clesJson = null;
  if (!incidents.length && evenements.length) {
    let creeLe = evenements[0].ts;
    try {
      creeLe = JSON.parse(await fs.readFile(path.join(rep, "journal.json"), "utf8")).created_at ?? creeLe;
    } catch {
      // journal.json absent : la création est au plus tard le premier événement
    }
    const initiale = await cles.resoudre(evenements[0].recorder_key_id);
    if (!initiale) {
      incidents.push({ key: "segments/", kind: "cle_inconnue", key_id: evenements[0].recorder_key_id });
    } else {
      clesJson = await clesDuJournal({ org_id: o.org_id, journal_id: o.journal_id, evenements, creeLe, clePublique: async () => octetsVersHex(initiale) });
      const j = verifierJournal(evenements, clesJson);
      if (!j.valide) incidents.push({ key: "segments/", kind: "copie_alteree", raison: "chaine", diagnostics: j.diagnostics.slice(0, 5).map((d) => `${d.controle} ${d.message}`) });
    }
  }

  // Manifestes, signatures, continuité, séries de points.
  const dirM = path.join(rep, "manifestes");
  const nomsM = (await fs.readdir(dirM).catch(() => [])).filter((n) => /^periode-[0-9]{10}\.json$/.test(n)).sort();
  let precedent = null;
  const closes = new Set();
  for (const n of nomsM) {
    const start = Number(n.slice(8, 18));
    closes.add(start);
    let m;
    try {
      m = analyserJson(new Uint8Array(await fs.readFile(path.join(dirM, n))));
    } catch {
      incidents.push({ key: `manifestes/${n}`, kind: "copie_alteree", raison: "manifeste_illisible" });
      precedent = null;
      continue;
    }
    const h = [];
    for (let s = m.first_seq; s < m.first_seq + m.count; s++) {
      if (!hashes.has(s)) break;
      h.push(hashes.get(s));
    }
    if (h.length !== m.count) {
      incidents.push({ key: `manifestes/${n}`, kind: "segment_absent", seq: m.first_seq + h.length });
      precedent = null;
      continue;
    }
    let recalcule = null;
    try {
      recalcule = construireManifeste({ ...m, hashes: h });
    } catch {
      recalcule = null;
    }
    if (!recalcule || !egaliteJson(recalcule, m)) {
      incidents.push({ key: `manifestes/${n}`, kind: "copie_alteree", raison: "manifeste_recalcule" });
      precedent = null;
      continue;
    }
    if (precedent && !verifierContinuite(precedent, m).valide) incidents.push({ key: `manifestes/${n}`, kind: "copie_alteree", raison: "continuite" });
    const nomSig = n.replace(/\.json$/, ".sig");
    const octetsSig = await lireSiPresent(path.join(dirM, nomSig));
    if (!octetsSig) {
      if (!o.signatureAbsenteAdmise?.(n)) incidents.push({ key: `manifestes/${nomSig}`, kind: "copie_absente", raison: "signature_absente" });
    } else {
      let sig = null;
      try {
        sig = analyserJson(octetsSig);
      } catch {
        sig = null;
      }
      const pub = sig && sig.recorder_key_id === m.recorder_key_id ? await cles.resoudre(m.recorder_key_id) : null;
      if (sig && sig.recorder_key_id === m.recorder_key_id && !pub) {
        incidents.push({ key: `manifestes/${nomSig}`, kind: "cle_inconnue", key_id: m.recorder_key_id });
      } else {
        let ok = false;
        try {
          ok = Boolean(sig) && sig.period_hash === hacherManifeste(m) && verifierSignatureManifeste(m, sig.sig, pub);
        } catch {
          ok = false;
        }
        if (!ok) incidents.push({ key: `manifestes/${nomSig}`, kind: "copie_alteree", raison: "signature_manifeste" });
      }
    }
    // Série des points de la période close (CT-1 §10.5, EX-12.26).
    const octetsSerie = await lireSiPresent(path.join(rep, "points", `periode-${String(start).padStart(10, "0")}.ndjson`));
    if (!octetsSerie) {
      incidents.push({ key: `points/periode-${String(start).padStart(10, "0")}.ndjson`, kind: "copie_absente", raison: "serie_absente" });
    } else if (clesJson) {
      let serie = null;
      try {
        serie = decouperLignes(octetsSerie).map((l) => analyserJsonIntegral(l.octets));
      } catch {
        serie = null;
      }
      let v = null;
      try {
        v = serie ? verifierSeriePointsDeControle(serie, m, evenements, clesJson) : null;
      } catch {
        v = null;
      }
      if (!v?.valide) incidents.push({ key: `points/periode-${String(start).padStart(10, "0")}.ndjson`, kind: "copie_alteree", raison: "serie_points", erreurs: v?.errors?.slice(0, 3) ?? null });
    }
    precedent = m;
  }

  // Séries des périodes non closes : chaînage et signature de chaque point.
  for (const n of (await fs.readdir(path.join(rep, "points")).catch(() => [])).filter((x) => /^periode-[0-9]{10}\.ndjson$/.test(x)).sort()) {
    if (closes.has(Number(n.slice(8, 18)))) continue;
    const octets = await lireSiPresent(path.join(rep, "points", n));
    let chaine = ZERO32;
    for (const l of decouperLignes(octets ?? new Uint8Array())) {
      if (!l.complete) break; // dernière ligne en cours d'écriture : tronquée par l'écrivain à la reprise
      let p = null;
      let ok = false;
      try {
        p = analyserJsonIntegral(l.octets);
        const pub = await cles.resoudre(p.key_id);
        ok = Boolean(pub) && p.prev_checkpoint_hash === chaine && verifierSignaturePoint(p, pub);
      } catch {
        ok = false;
      }
      if (!ok) {
        incidents.push({ key: `points/${n}`, kind: "copie_alteree", raison: "serie_points" });
        break;
      }
      chaine = hacherPoint(p);
    }
  }

  // Pièces : SHA-256 du contenu égal au nom (8.4).
  const dirP = path.join(rep, "pieces");
  for (const xx of (await fs.readdir(dirP).catch(() => [])).sort()) {
    for (const nom of (await fs.readdir(path.join(dirP, xx)).catch(() => [])).sort()) {
      if (nom.startsWith(".tmp-")) continue;
      const octets = await lireSiPresent(path.join(dirP, xx, nom));
      if (!/^[0-9a-f]{64}$/.test(nom) || nom.slice(0, 2) !== xx || !octets || sha256Hex(octets) !== `0x${nom}`) {
        incidents.push({ key: `pieces/${xx}/${nom}`, kind: "copie_alteree", raison: "sha256_piece" });
      }
    }
  }
  return { incidents, evenements, lastSeq: attendu - 1, lastHash: prev, cles: clesJson };
}
