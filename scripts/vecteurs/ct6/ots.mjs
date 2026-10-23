// Vecteurs CT-6, famille ots (spec/CT-6-verificateur.md, annexe A.4) : chaîne
// d'en-têtes Bitcoin SYNTHÉTIQUE au réseau regtest (preuve de travail réelle
// à la cible minimale 0x207fffff), preuves OpenTimestamps au format officiel
// engageant le periodHash des trois manifestes de CT-1, et une variante
// invalide par vérification O- que le format permet de viser.
//
//   import { genererOts } from "./ct6/ots.mjs";
//   genererOts({ racine: "spec/vecteurs/ct-6" });
//   node scripts/vecteurs/ct6/ots.mjs [--sortie <répertoire ct-6>]
//
// Tout est déterministe : arguments des opérations, racines des blocs et
// horodatages sont dérivés d'étiquettes documentées ; nNonce est le plus petit
// entier qui satisfait la cible. Le module vérifie chaque cas avec
// scripts/lib/ots.mjs avant d'écrire attendu.json : un statut qui ne
// correspond pas à la conception du vecteur arrête la génération.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as O from "../../lib/ots.mjs";
import { manifestesCT1 } from "./rfc3161.mjs";

const PROJECT_ROOT = fileURLToPath(new URL("../../../", import.meta.url));

// ---------------------------------------------------------------------------
// Constantes (EX-A.6, EX-A.7)
// ---------------------------------------------------------------------------

export const RESEAU = "regtest";
export const HAUTEUR_DEBUT = 990;
export const HAUTEUR_FIN = 1020;
export const HAUTEUR_POINT_CONTROLE = 1000;
export const MIN_CONFIRMATIONS = 6;
export const N_VERSION = 0x20000000;
export const N_TIME_990 = 1793880000; // 2026-11-05T12:00:00Z, après la fin des trois périodes
export const ECART = 600;
export const HAUTEUR_SANS_TRAVAIL = 1010;
export const HAUTEUR_FIN_COURTE = 1003;
export const URI_CALENDRIER = "https://alice.btc.calendar.opentimestamps.org";

const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const etiquette = (texte) => sha256(Buffer.from(texte, "utf8"));
/** Flux d'octets SHA-256(UTF-8(« étiquette/i »)), i = 0, 1, … */
function flux(texte, n) {
  const parties = [];
  for (let i = 0, total = 0; total < n; i++, total += 32) parties.push(etiquette(`${texte}/${i}`));
  return Buffer.concat(parties).subarray(0, n);
}
const ETIQ = {
  nonce: (n) => `noortrace/vecteurs/v0/ct-6/ots/nonce/periode-${n}`,
  calendrier: (n, k) => `noortrace/vecteurs/v0/ct-6/ots/calendrier/periode-${n}/${k}`,
  transactionAvant: (n) => `noortrace/vecteurs/v0/ct-6/ots/transaction/periode-${n}/avant`,
  transactionApres: (n) => `noortrace/vecteurs/v0/ct-6/ots/transaction/periode-${n}/apres`,
  bloc: (n, k) => `noortrace/vecteurs/v0/ct-6/ots/bloc/periode-${n}/${k}`,
  racine: (i) => `noortrace/vecteurs/v0/ct-6/bitcoin/racine/${i}`,
  argumentLong: "noortrace/vecteurs/v0/ct-6/ots/argument-long",
};
const { append: F0, prepend: F1, sha256: S8 } = O.OP;

// ---------------------------------------------------------------------------
// Preuves
// ---------------------------------------------------------------------------

/**
 * Opérations de la preuve de la période n, toutes du profil { f0, f1, 08 } :
 * nonce ajouté puis SHA-256 (comme ots stamp), deux niveaux d'agrégation de
 * calendrier, une transaction Bitcoin imitée (préfixe, suffixe, double
 * SHA-256), deux niveaux de l'arbre de Merkle du bloc (double SHA-256).
 */
export function operationsPeriode(n) {
  return {
    calendrier: [
      { op: F0, argument: etiquette(ETIQ.nonce(n)).subarray(0, 16) },
      { op: S8 },
      { op: F1, argument: etiquette(ETIQ.calendrier(n, 0)) },
      { op: S8 },
      { op: F0, argument: etiquette(ETIQ.calendrier(n, 1)) },
      { op: S8 },
    ],
    bitcoin: [
      { op: F1, argument: flux(ETIQ.transactionAvant(n), 45) },
      { op: F0, argument: flux(ETIQ.transactionApres(n), 27) },
      { op: S8 },
      { op: S8 },
      { op: F1, argument: etiquette(ETIQ.bloc(n, 0)) },
      { op: S8 },
      { op: S8 },
      { op: F0, argument: etiquette(ETIQ.bloc(n, 1)) },
      { op: S8 },
      { op: S8 },
    ],
  };
}
/** Résultat d'une suite d'opérations appliquée à un message. */
export const rejouer = (operations, message) => operations.reduce((m, o) => O.appliquer(o.op, o.argument ?? null, m), message);
const bitcoin = (hauteur) => ({ type: "attestation", attestation: { genre: "bitcoin", hauteur } });
const enAttente = (uri) => ({ type: "attestation", attestation: { genre: "en_attente", uri } });

/** Les preuves de ots/preuves (EX-A.7) et le résultat de chaque attestation Bitcoin. */
export function preuvesTest(manifestes) {
  const preuves = {};
  const racines = {};
  for (const { n, periodHash } of manifestes) {
    const ops = operationsPeriode(n);
    const empreinte = Buffer.from(periodHash.slice(2), "hex");
    racines[1000 + n] = rejouer([...ops.calendrier, ...ops.bitcoin], empreinte);
    preuves[`periode-${n}`] = { octets: O.encoderOts(empreinte, O.chemin([...ops.calendrier, ...ops.bitcoin], [bitcoin(1000 + n)])), alteration: null, cible: null, periode: n };
  }
  const p1 = manifestes[0];
  const e1 = Buffer.from(p1.periodHash.slice(2), "hex");
  const ops1 = operationsPeriode(1);
  const tout1 = [...ops1.calendrier, ...ops1.bitcoin];
  preuves["o1-octet-en-trop"] = { octets: Buffer.concat([preuves["periode-1"].octets, Buffer.from([0x00])]), alteration: "un octet 00 après l'arbre", cible: "O-1", periode: 1 };
  preuves["o3-resultat-trop-long"] = {
    octets: O.encoderOts(e1, [...O.chemin(tout1, [bitcoin(1001)]), ...O.chemin([{ op: F0, argument: flux(ETIQ.argumentLong, 4096) }, { op: S8 }], [enAttente(URI_CALENDRIER)])]),
    alteration: "branche supplémentaire f0 d'un argument de 4096 octets sur l'empreinte (résultat de 4128 octets), puis 08 et une attestation en attente",
    cible: "O-3",
    periode: 1,
  };
  preuves["o4-mauvaise-hauteur"] = { octets: O.encoderOts(e1, O.chemin(tout1, [bitcoin(1002)])), alteration: "attestation Bitcoin à la hauteur 1002 au lieu de 1001", cible: "O-4", periode: 1 };
  preuves["o7-en-attente"] = { octets: O.encoderOts(e1, O.chemin(ops1.calendrier, [enAttente(URI_CALENDRIER)])), alteration: `seulement une attestation en attente du calendrier ${URI_CALENDRIER}`, cible: "O-7", periode: 1 };
  preuves["deux-attestations"] = { octets: O.encoderOts(e1, O.chemin(tout1, [bitcoin(1001), bitcoin(1002)])), alteration: "attestations Bitcoin aux hauteurs 1001 et 1002", cible: null, periode: 1 };
  preuves["attente-uri-vide"] = {
    octets: O.encoderOts(e1, O.chemin(ops1.calendrier, [enAttente(""), ...O.chemin(ops1.bitcoin, [bitcoin(1001)])])),
    alteration: "au bout des opérations du calendrier, une attestation en attente d'URI vide (0 octet), que la bibliothèque de référence admet (EX-10.2), à côté de la branche Bitcoin attestée à 1001",
    cible: null,
    periode: 1,
  };
  preuves["branche-hors-profil"] = {
    octets: O.encoderOts(e1, [...O.chemin(tout1, [bitcoin(1001)]), ...O.chemin([{ op: O.OP.ripemd160 }], [bitcoin(1003)])]),
    alteration: "attestation Bitcoin à 1001 par le profil, et une seconde branche 03 (ripemd160, hors profil) finie par une attestation Bitcoin à 1003, non exécutée (EX-10.7)",
    cible: null,
    periode: 1,
  };
  return { preuves, racines };
}

// ---------------------------------------------------------------------------
// En-têtes
// ---------------------------------------------------------------------------

/** En-tête de 80 octets (R2-F43) ; nNonce le plus petit qui satisfait (ou non) la cible. */
export function miner({ prev, racine, nTime, nBits = O.NBITS_REGTEST, version = N_VERSION, satisfaire = true }) {
  const h = Buffer.alloc(80);
  h.writeInt32LE(version | 0, 0);
  Buffer.from(prev).copy(h, 4);
  Buffer.from(racine).copy(h, 36);
  h.writeUInt32LE(nTime, 68);
  h.writeUInt32LE(nBits, 72);
  const { cible } = O.setCompact(nBits);
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    h.writeUInt32LE(nonce, 76);
    if ((O.entierLE(O.dSHA(h)) <= cible) === satisfaire) return h;
  }
  throw new Error("aucun nNonce");
}

/** Chaîne de HAUTEUR_DEBUT à `fin` ; `sansTravail` : hauteur dont nNonce ne satisfait pas la cible. */
export function chaineTest(racines, { fin = HAUTEUR_FIN, sansTravail = null } = {}) {
  const entetes = [];
  let prev = Buffer.alloc(32);
  for (let i = HAUTEUR_DEBUT; i <= fin; i++) {
    const racine = racines[i] ?? O.dSHA(Buffer.from(ETIQ.racine(i), "utf8"));
    const h = miner({ prev, racine, nTime: N_TIME_990 + ECART * (i - HAUTEUR_DEBUT), satisfaire: i !== sansTravail });
    entetes.push(h);
    prev = O.dSHA(h);
  }
  return entetes;
}
const fichierEntetes = (entetes, source) => ({ version: 0, network: RESEAU, start_height: HAUTEUR_DEBUT, source, headers: entetes.map((h) => "0x" + h.toString("hex")) });

/** Ancre bitcoin des fichiers d'ancres de test (EX-A.10). */
export function ancreBitcoin(entetes) {
  return {
    network: RESEAU,
    checkpoint: { height: HAUTEUR_POINT_CONTROLE, hash: O.hachageAffiche(entetes[HAUTEUR_POINT_CONTROLE - HAUTEUR_DEBUT]) },
    min_confirmations: MIN_CONFIRMATIONS,
    source: "point de contrôle de la chaîne regtest synthétique des vecteurs CT-6 (spec/vecteurs/ct-6/ots/entetes/chaine.json, hauteur 1000), sans valeur hors des tests",
  };
}
const ancresBitcoin = (bitcoinAncre) => ({ version: 0, label: "ancre Bitcoin de test CT-6", prepared_by: "générateur des vecteurs CT-6", prepared_at: "2026-11-10T08:00:00.000Z", tsa_authorities: [], revocation: { crls: [], statements: [] }, bitcoin: bitcoinAncre, registry: null, recorders: [] });

// ---------------------------------------------------------------------------
// Génération
// ---------------------------------------------------------------------------

// Lecture attendue par python-opentimestamps 0.4.5 (R2-F67 : octet en trop et
// message trop long rejetés) ; les autres preuves sont au format officiel.
const PYTHON_PRESUME = {
  "o1-octet-en-trop": { parsing: "refusee", source: "R2-F67 (TrailingGarbageError)" },
  "o3-resultat-trop-long": { parsing: "refusee", source: "R2-F13, R2-F67 (message de plus de 4096 octets)" },
};

/**
 * Écrit la famille ots dans `<racine>/ots` : entetes/, preuves/, attendu.json.
 * Rend { preuves, entetes, ancre, attendu } pour le générateur principal.
 */
export function genererOts({ racine = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6"), repertoireCT1 } = {}) {
  const dossier = path.join(racine, "ots");
  fs.rmSync(dossier, { recursive: true, force: true });
  fs.mkdirSync(path.join(dossier, "entetes"), { recursive: true });
  fs.mkdirSync(path.join(dossier, "preuves"));

  const manifestes = manifestesCT1(repertoireCT1);
  const { preuves, racines } = preuvesTest(manifestes);
  const chaine = chaineTest(racines);
  const source = "chaîne regtest synthétique des vecteurs CT-6 (scripts/vecteurs/ct6/ots.mjs), sans valeur hors des tests";
  const entetes = {
    chaine: fichierEntetes(chaine, source),
    "chaine-sans-travail": fichierEntetes(chaineTest(racines, { sansTravail: HAUTEUR_SANS_TRAVAIL }), `${source} ; nNonce de l'en-tête ${HAUTEUR_SANS_TRAVAIL} sans preuve de travail, chaînage refait au-dessus`),
    "chaine-courte": fichierEntetes(chaine.slice(0, HAUTEUR_FIN_COURTE - HAUTEUR_DEBUT + 1), `${source} ; hauteurs ${HAUTEUR_DEBUT} à ${HAUTEUR_FIN_COURTE}`),
    "chaine-depuis-1001": { ...fichierEntetes(chaine.slice(HAUTEUR_POINT_CONTROLE + 1 - HAUTEUR_DEBUT), `${source} ; hauteurs ${HAUTEUR_POINT_CONTROLE + 1} à ${HAUTEUR_FIN} : le point de contrôle ${HAUTEUR_POINT_CONTROLE} n'y est pas (EX-10.9, règle 3)`), start_height: HAUTEUR_POINT_CONTROLE + 1 },
  };
  for (const [id, e] of Object.entries(entetes)) fs.writeFileSync(path.join(dossier, "entetes", `${id}.json`), JSON.stringify(e, null, 2) + "\n");
  for (const [id, p] of Object.entries(preuves)) fs.writeFileSync(path.join(dossier, "preuves", `${id}.ots`), p.octets);

  const ancre = ancreBitcoin(chaine);
  const ancres = ancresBitcoin(ancre);
  const sha = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");

  // Conception des cas : vérifications en échec, statut et raison du contrôle 5.
  const cas = [
    ["periode-1", 1, "chaine", ancres, [], "reussi", null],
    ["periode-2", 2, "chaine", ancres, [], "reussi", null],
    ["periode-3", 3, "chaine", ancres, [], "reussi", null],
    ["periode-2", 1, "chaine", ancres, ["O-2"], "echoue", null],
    ["periode-1", 1, "chaine-sans-travail", ancres, ["O-5"], "echoue", null],
    ["periode-1", 1, "chaine-courte", ancres, [], "non_execute", "ancre_absente"],
    ["periode-1", 1, null, ancres, [], "non_execute", "partie_absente"],
    ["periode-1", 1, "chaine", null, [], "non_execute", "ancre_absente"],
    ["o1-octet-en-trop", 1, "chaine", ancres, ["O-1"], "echoue", null],
    ["o3-resultat-trop-long", 1, "chaine", ancres, ["O-3"], "echoue", null],
    ["o4-mauvaise-hauteur", 1, "chaine", ancres, ["O-4"], "echoue", null],
    ["o7-en-attente", 1, "chaine", ancres, [], "non_execute", "partie_absente"],
    ["deux-attestations", 1, "chaine", ancres, [], "reussi", null],
    ["attente-uri-vide", 1, "chaine", ancres, [], "reussi", null],
    ["branche-hors-profil", 1, "chaine", ancres, [], "reussi", null],
    ["periode-1", 1, "chaine-depuis-1001", ancres, [], "non_execute", "ancre_absente"],
  ].map(([preuve, periode, nomEntetes, a, echecs, statut, raison]) => {
    const ph = manifestes[periode - 1].periodHash;
    const r = O.evaluerPreuve(preuves[preuve].octets, { periodHash: ph, entetes: nomEntetes ? entetes[nomEntetes] : null, ancres: a });
    const obtenus = r.checks.filter((x) => x.status === "echoue").map((x) => x.id);
    if (JSON.stringify(obtenus) !== JSON.stringify(echecs) || r.status !== statut || r.reason !== raison) throw new Error(`vecteur ots ${preuve} (période ${periode}, ${nomEntetes}) : échecs ${JSON.stringify(obtenus)}, contrôle ${r.status}/${r.reason}, attendus ${JSON.stringify(echecs)} ${statut}/${raison}`);
    return {
      proof: `preuves/${preuve}.ots`,
      dossier_period_hash: ph,
      headers: nomEntetes ? `entetes/${nomEntetes}.json` : null,
      anchors: a ? "bitcoin de ancres/ancres-test.json" : null,
      checks: r.checks.map((x) => ({ id: x.id, status: x.status, reason: x.reason })),
      failed_checks: obtenus,
      control_status: r.status,
      control_reason: r.reason,
      warnings: r.warnings.map((w) => w.id),
      facts: r.facts,
    };
  });

  const attendu = {
    description: "Vecteurs CT-6 de la famille ots (spec/CT-6-verificateur.md, annexe A.4). Les statuts sont ceux de l'implémentation de référence (scripts/lib/ots.mjs) avec la seule ancre bitcoin des fichiers d'ancres de test.",
    bitcoin_anchor: ancre,
    headers: Object.fromEntries(
      Object.entries(entetes).map(([id, e]) => {
        const brut = fs.readFileSync(path.join(dossier, "entetes", `${id}.json`));
        return [`entetes/${id}.json`, { sha256: sha(brut), start_height: e.start_height, end_height: e.start_height + e.headers.length - 1, hashes: Object.fromEntries(e.headers.map((h, k) => [String(e.start_height + k), O.hachageAffiche(Buffer.from(h.slice(2), "hex"))])) }];
      }),
    ),
    proofs: Object.entries(preuves).map(([id, p]) => {
      const lu = (() => {
        try {
          return O.lireOts(p.octets);
        } catch {
          return null;
        }
      })();
      const attestations = lu ? O.executer(lu).attestations : [];
      return {
        file: `preuves/${id}.ots`,
        sha256: sha(p.octets),
        size: p.octets.length,
        file_digest: "0x" + p.octets.subarray(33, 65).toString("hex"),
        alteration: p.alteration,
        target: p.cible,
        attestations: attestations.map((a) => ({ kind: a.genre, height: a.hauteur ?? null, uri: a.uri ?? null, result: a.resultat ? "0x" + a.resultat.toString("hex") : null })),
        python_opentimestamps: PYTHON_PRESUME[id] ?? { parsing: "acceptee", source: "format officiel (R2-F01 à R2-F21)" },
      };
    }),
    cases: cas,
  };
  fs.writeFileSync(path.join(dossier, "attendu.json"), JSON.stringify(attendu, null, 2) + "\n");
  return { preuves, entetes, ancre, attendu, racines };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const i = process.argv.indexOf("--sortie");
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : undefined;
  const r = genererOts({ racine });
  process.stdout.write(`ots : ${Object.keys(r.preuves).length} preuves, ${Object.keys(r.entetes).length} fichiers d'en-têtes, ${r.attendu.cases.length} cas vérifiés\n`);
}
