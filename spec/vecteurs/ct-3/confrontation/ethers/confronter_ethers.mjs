#!/usr/bin/env node
// Confrontation des signatures des vecteurs CT-3 par ethers
// (spec/CT-3-approbations.md, révision 0.3, EX-A.14, EX-A.18, EX-9.22).
//
//   node spec/vecteurs/ct-3/confrontation/ethers/confronter_ethers.mjs spec/vecteurs/ct-3
//
// Le programme n'importe rien de scripts/ : il relit les vecteurs, recalcule
// lui-même D_A (JCS des cinq chaînes de A, puis SHA-256 de
// « noortrace/approbation/v0\n » ‖ JCS(A), CT-1 §6.3) et porte sa propre
// référence de CT-3 (contrôle de forme d'EX-9.22, normalisation d'EX-9.3,
// Keccak-256 et recouvrement secp256k1 écrits ici, sans bibliothèque). La
// seule bibliothèque employée est ethers, celle de node_modules du dépôt, dont
// la version est lue dans node_modules/ethers/package.json. Pour chaque
// signature des vecteurs, le programme :
//
//   1. contrôle la forme avant la bibliothèque (EX-9.22) : 65 octets, r et s
//      dans [1, n − 1], v ∈ {0, 1, 27, 28} là où CT-3 normalise (service,
//      console), v ∈ {27, 28} et s ≤ n/2 là où il ne normalise pas (noyau,
//      réviseur d'un annuaire exporté) ;
//   2. recouvre l'adresse par verifyMessage d'ethers, avec la signature telle
//      que le vecteur la porte, sur les 32 octets de D_A (getBytes, jamais la
//      chaîne « 0x… », EX-9.7) pour un vote, ou sur le texte d'un message
//      d'inscription (texte ASCII : ses octets UTF-8 sont ses octets) ;
//   3. compare à l'adresse attendue : celle que le vecteur nomme (approbateur
//      d'un vote dont la signature a passé le contrôle, adresse inscrite,
//      adresse recouvrée attendue), ou, à défaut, celle que recouvre la
//      référence de ce programme sur la forme normalisée.
//
// Verdicts (EX-A.18) : concorde, acceptee_par_la_bibliotheque,
// refusee_par_la_bibliotheque, discordance. Les fichiers de clé valides de
// console/fichiers-cle/ sont déchiffrés par decryptKeystoreJsonSync. Le code
// de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un usage
// incorrect. La sortie ne porte aucun chemin local.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decryptKeystoreJsonSync, getBytes, verifyMessage } from "ethers";

const ICI = path.dirname(fileURLToPath(import.meta.url));
// Version lue dans node_modules/ethers/package.json du dépôt (EX-A.18).
const versionEthers = JSON.parse(fs.readFileSync(path.join(ICI, "..", "..", "..", "..", "..", "node_modules", "ethers", "package.json"), "utf8")).version;

// ---------------------------------------------------------------------------
// Référence de ce programme : Keccak-256 et secp256k1 (sans bibliothèque).
// ---------------------------------------------------------------------------

const M64 = (1n << 64n) - 1n;
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]].map((l) => l.map(BigInt));
const RC = (() => {
  const rc = [];
  let r = 1;
  for (let i = 0; i < 24; i++) {
    let c = 0n;
    for (let j = 0; j < 7; j++) {
      r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;
      if (r & 2) c ^= 1n << BigInt((1 << j) - 1);
    }
    rc.push(c);
  }
  return rc;
})();
const rotl = (x, k) => (k === 0n ? x : ((x << k) | (x >> (64n - k))) & M64);

function keccakF(a) {
  for (const rc of RC) {
    const c = [0, 1, 2, 3, 4].map((x) => a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4]);
    const d = [0, 1, 2, 3, 4].map((x) => c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1n));
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[x][y] ^= d[x];
    const b = [0, 1, 2, 3, 4].map(() => [0n, 0n, 0n, 0n, 0n]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y][(2 * x + 3 * y) % 5] = rotl(a[x][y], ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[x][y] = b[x][y] ^ (~b[(x + 1) % 5][y] & M64 & b[(x + 2) % 5][y]);
    a[0][0] ^= rc;
  }
}

/** Keccak-256 (remplissage 0x01 … 0x80, débit 136 octets), pas SHA3-256. */
function keccak256(octets) {
  const taux = 136;
  const longueur = Math.ceil((octets.length + 1) / taux) * taux;
  const m = new Uint8Array(longueur);
  m.set(octets);
  m[octets.length] ^= 0x01;
  m[longueur - 1] ^= 0x80;
  const a = [0, 1, 2, 3, 4].map(() => [0n, 0n, 0n, 0n, 0n]);
  for (let i = 0; i < longueur; i += taux) {
    for (let k = 0; k < taux / 8; k++) {
      let lane = 0n;
      for (let o = 7; o >= 0; o--) lane = (lane << 8n) | BigInt(m[i + 8 * k + o]);
      a[k % 5][Math.floor(k / 5)] ^= lane;
    }
    keccakF(a);
  }
  const sortie = new Uint8Array(32);
  for (let k = 0; k < 4; k++) {
    let lane = a[k % 5][Math.floor(k / 5)];
    for (let o = 0; o < 8; o++) {
      sortie[8 * k + o] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return sortie;
}

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n, 1n];
const mod = (x, m) => ((x % m) + m) % m;
function puissance(b, e, m) {
  let r = 1n;
  b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
function doubler(q) {
  if (q === null || q[1] === 0n) return null;
  const [x, y, z] = q;
  const a = (x * x) % P, b = (y * y) % P;
  const c = (b * b) % P;
  const d = mod(2n * ((x + b) ** 2n - a - c), P);
  const e = (3n * a) % P;
  const x3 = mod(e * e - 2n * d, P);
  return [x3, mod(e * (d - x3) - 8n * c, P), (2n * y * z) % P];
}
function ajouter(q1, q2) {
  if (q1 === null) return q2;
  if (q2 === null) return q1;
  const [x1, y1, z1] = q1;
  const [x2, y2, z2] = q2;
  const z1z1 = (z1 * z1) % P, z2z2 = (z2 * z2) % P;
  const u1 = (x1 * z2z2) % P, u2 = (x2 * z1z1) % P;
  const s1 = (y1 * z2 * z2z2) % P, s2 = (y2 * z1 * z1z1) % P;
  const h = mod(u2 - u1, P), r = mod(s2 - s1, P);
  if (h === 0n) return r === 0n ? doubler(q1) : null;
  const hh = (h * h) % P;
  const hhh = (h * hh) % P;
  const x3 = mod(r * r - hhh - 2n * u1 * hh, P);
  return [x3, mod(r * (u1 * hh - x3) - s1 * hhh, P), (z1 * z2 * h) % P];
}
/** k1·q1 + k2·q2 (Shamir). */
function somme(k1, q1, k2, q2) {
  const q12 = ajouter(q1, q2);
  let acc = null;
  const bits = Math.max(k1.toString(2).length, k2.toString(2).length);
  for (let i = BigInt(bits - 1); i >= 0n; i--) {
    acc = doubler(acc);
    const b1 = (k1 >> i) & 1n, b2 = (k2 >> i) & 1n;
    if (b1 && b2) acc = ajouter(acc, q12);
    else if (b1) acc = ajouter(acc, q1);
    else if (b2) acc = ajouter(acc, q2);
  }
  return acc;
}
const versHex = (u8) => Buffer.from(u8).toString("hex");
const enOctets32 = (x) => Buffer.from(x.toString(16).padStart(64, "0"), "hex");

/** H = keccak256(0x19 ‖ « Ethereum Signed Message:\n » ‖ longueur décimale ‖ octets) (EIP-191, version 0x45). */
const condenseEIP191 = (octets) => keccak256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n" + octets.length, "latin1"), Buffer.from(octets)]));

/** Adresse recouvrée par la référence sur une forme normalisée (v ∈ {27, 28}), ou null. */
function recouvrerReference(octets, forme) {
  const r = BigInt("0x" + forme.slice(2, 66)), s = BigInt("0x" + forme.slice(66, 130)), v = parseInt(forme.slice(130), 16);
  const y2 = (puissance(r, 3n, P) + 7n) % P;
  let y = puissance(y2, (P + 1n) / 4n, P);
  if ((y * y) % P !== y2) return null;
  if (Number(y & 1n) !== v - 27) y = P - y;
  const e = BigInt("0x" + versHex(condenseEIP191(octets)));
  const rinv = puissance(r, N - 2n, N);
  const q = somme(mod(-e * rinv, N), G, (s * rinv) % N, [r, y, 1n]);
  if (q === null) return null;
  const zi = puissance(q[2], P - 2n, P);
  const qx = (q[0] * zi * zi) % P, qy = (((q[1] * zi * zi) % P) * zi) % P;
  return "0x" + versHex(keccak256(Buffer.concat([enOctets32(qx), enOctets32(qy)]))).slice(24);
}

/** Forme de CT-3 (EX-9.22, EX-9.3) : la forme normalisée en minuscules, ou null si CT-3 la refuse. */
function formeCt3(sig, normalise) {
  if (typeof sig !== "string" || !/^0x[0-9a-fA-F]*$/.test(sig)) return null;
  const s0 = sig.toLowerCase();
  if (s0.length !== 132) return null;
  const r = BigInt("0x" + s0.slice(2, 66));
  let s = BigInt("0x" + s0.slice(66, 130));
  let v = parseInt(s0.slice(130), 16);
  if (r < 1n || r >= N || s < 1n || s >= N) return null;
  if (!normalise) return (v === 27 || v === 28) && s <= N / 2n ? s0 : null;
  if (v === 0 || v === 1) v += 27;
  if (v !== 27 && v !== 28) return null;
  if (s > N / 2n) {
    s = N - s;
    v = 55 - v;
  }
  return "0x" + s0.slice(2, 66) + s.toString(16).padStart(64, "0") + v.toString(16);
}

// ---------------------------------------------------------------------------
// D_A (CT-1 §6.3).
// ---------------------------------------------------------------------------

/** D_A = SHA-256(« noortrace/approbation/v0\n » ‖ JCS(A)), A de cinq chaînes. */
function condenseA(a) {
  const cles = ["decision", "journal_id", "org_id", "request_hash", "ticket"];
  const jcs = "{" + cles.map((k) => JSON.stringify(k) + ":" + JSON.stringify(a[k])).join(",") + "}";
  return "0x" + crypto.createHash("sha256").update("noortrace/approbation/v0\n" + jcs, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// Parcours des vecteurs.
// ---------------------------------------------------------------------------

const racine = process.argv[2];
if (process.argv.length !== 3 || !fs.existsSync(path.join(racine, "INDEX.md"))) {
  process.stderr.write("usage : node confronter_ethers.mjs <chemin de spec/vecteurs/ct-3>\n");
  process.exit(2);
}
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(racine, ...p), "utf8"));
const fichiers = (...p) => (fs.existsSync(path.join(racine, ...p)) ? fs.readdirSync(path.join(racine, ...p)).filter((f) => f.endsWith(".json")).sort() : []);

const lignes = [];
const comptes = { concorde: 0, acceptee_par_la_bibliotheque: 0, refusee_par_la_bibliotheque: 0, discordance: 0 };

/**
 * Une signature : `dA` (vote) ou `texte` (inscription) ; `attendue` (adresse que
 * le vecteur nomme, ou null : celle de la référence) ; `coherent` faux si le
 * vecteur contredit la référence ; `admises` borne l'adresse de la référence.
 */
function confronter(famille, cas, indice, signature, normalise, { dA = null, texte = null, attendue = null, coherent = true, admises = null }) {
  const forme = formeCt3(signature, normalise);
  let recouvree = null;
  try {
    recouvree = verifyMessage(texte !== null ? texte : getBytes(dA), signature).toLowerCase();
  } catch {
    recouvree = null;
  }
  const octets = texte !== null ? Buffer.from(texte, "utf8") : getBytes(dA);
  const ref = forme ? recouvrerReference(octets, forme) : null;
  const cible = attendue ?? ref;
  let verdict;
  if (!coherent) verdict = "discordance";
  else if (!forme) verdict = recouvree === null ? "concorde" : "acceptee_par_la_bibliotheque";
  else if (recouvree === null) verdict = forme === signature.toLowerCase() ? "discordance" : "refusee_par_la_bibliotheque";
  else verdict = recouvree === cible && ref === cible ? "concorde" : "discordance";
  if (forme && admises && !admises.has(ref)) verdict = "discordance";
  comptes[verdict]++;
  lignes.push(`${famille} | ${cas} | ${indice} | ${recouvree ?? "refusée"} | ${forme ? cible : "forme refusée par CT-3"} | ${verdict}`);
}

// tickets/ : entrées voter (le service normalise, EX-9.3). La signature passe
// le contrôle d'EX-9.10 dès que le vote est accepté ou refusé pour une raison
// qui le suit.
const avantSignature = new Set(["ticket_inconnu", "ticket_non_ouvert", "ticket_clos_aux_votes", "jeu_non_fige", "signature_invalide"]);
for (const f of fichiers("tickets")) {
  const t = lire("tickets", f);
  const rh = {};
  t.steps.forEach((p, i) => {
    if (p.input.kind === "ouvrir") rh[p.input.data.ticket] = p.input.data.request_hash;
    if (p.input.kind !== "voter") return;
    const d = p.input.data;
    if (!(d.ticket in rh)) return;
    const passe = p.expected.accepted || !avantSignature.has(p.expected.reason);
    const a = { decision: d.decision, journal_id: t.journal_id, org_id: t.org_id, request_hash: rh[d.ticket], ticket: d.ticket };
    confronter("tickets", f, i, d.signature, true, { dA: condenseA(a), attendue: passe ? d.approver : null });
  });
}

// decisions/ : signatures des remises (le noyau ne normalise pas, SG-5). Les
// approbateurs sont attendus pour une remise scellée ou refusée après SG-5
// (SG-6, SG-7).
const apresSG5 = new Set(["approbateur_double", "approbateur_hors_jeu", "seuil_different_du_jeu", "expire_avec_signatures", "seuil_non_atteint", "auto_approbation"]);
for (const rep of ["valides", "invalides"]) {
  for (const f of fichiers("decisions", rep)) {
    const c = lire("decisions", rep, f);
    const ap = c.remise?.approval;
    if (!ap || !Array.isArray(ap.signatures)) continue;
    const nomme = (c.expected.result === "scelle" || apresSG5.has(c.expected.reason)) && ap.approvers.length === ap.signatures.length;
    const a = { decision: ap.decision, journal_id: c.context.journal_id, org_id: c.context.org_id, request_hash: ap.request_hash, ticket: ap.ticket };
    ap.signatures.forEach((s, i) => confronter("decisions", `${rep}/${f}`, i, s, false, { dA: condenseA(a), attendue: nomme ? ap.approvers[i] : null }));
  }
}

// signatures/normalisation.json : vote approuve d'apr-0001 (demande 1,
// journal-approbations), signé par l'un des comptes de test (A.8) ; la forme
// normalisée de la référence doit être celle du vecteur.
{
  const k = lire("constantes.json");
  const comptesTest = new Set(k.accounts.map((c) => c.address));
  const rh1 = "0x" + crypto.createHash("sha256").update(k.labels.request.replace("<k>", "1"), "utf8").digest("hex");
  const a1 = { decision: "approuve", journal_id: k.journal.journal_id, org_id: k.organization.org_id, request_hash: rh1, ticket: "apr-0001" };
  for (const c of lire("signatures", "normalisation.json").cases) {
    confronter("signatures", `normalisation.json#${c.id}`, 0, c.signature, true, { dA: condenseA(a1), coherent: formeCt3(c.signature, true) === c.expected, admises: comptesTest });
  }
}

// console/requetes/ et console/reponses/ (la console normalise, EX-9.21).
for (const f of fichiers("console", "requetes")) {
  const c = lire("console", "requetes", f);
  const dA = condenseA(c.input.a);
  confronter("console/requetes", f, 0, c.expected.signature, true, { dA, attendue: c.input.approver, coherent: dA === c.expected.digests.d_a });
}
for (const f of fichiers("console", "reponses")) {
  const c = lire("console", "reponses", f);
  const r = c.input.response.result;
  if (typeof r !== "string" || !/^0x[0-9a-fA-F]+$/.test(r)) continue;
  const coherent = c.expected.outcome !== "accepte" || formeCt3(r, true) === c.expected.signature;
  confronter("console/reponses", f, 0, r, true, { dA: condenseA(c.input.a), attendue: c.expected.recovered ?? null, coherent });
}

// annuaire/ : inscriptions (le service normalise, EX-13.15), domaines (AN-5),
// preuves des annuaires et des exports (le réviseur exige la forme canonique,
// EX-13.19), requêtes inscrire des traces. messages.json ne porte aucune
// signature.
{
  const apresSignature = new Set(["identite_desactivee", "adresse_deja_attribuee"]);
  for (const c of lire("annuaire", "inscriptions.json").cases) {
    const passe = c.expected.accepted || apresSignature.has(c.expected.reason);
    confronter("annuaire/inscriptions", c.id, 0, c.request.signature, true, { texte: c.request.message, attendue: passe ? c.request.address : null });
  }
  for (const c of lire("annuaire", "domaines.json").cases) {
    if (c.kind === "inscription_comme_vote") confronter("annuaire/domaines", c.id, 0, c.signature, true, { dA: condenseA(c.A), attendue: c.expected.recovered });
    else confronter("annuaire/domaines", c.id, 0, c.signature, true, { texte: c.message, attendue: c.expected.recovered });
  }
  const preuvesInvalides = new Set();
  for (const c of lire("annuaire", "exports", "attendu.json").cases) for (const e of c.errors) if (e.code === "preuve_invalide") preuvesInvalides.add(`${c.file}#${e.pointer}`);
  for (const rep of ["annuaires", "exports"]) {
    for (const f of fichiers("annuaire", rep).filter((x) => x !== "attendu.json")) {
      (lire("annuaire", rep, f).entries ?? []).forEach((e, i) =>
        e.addresses.forEach((ad, j) => {
          const pointeur = `/entries/${i}/addresses/${j}`;
          const nomme = rep === "exports" ? !preuvesInvalides.has(`${f}#${pointeur}/proof`) : true;
          confronter(`annuaire/${rep}`, `${f}#${pointeur}`, 0, ad.proof.signature, false, { texte: ad.proof.message, attendue: nomme ? ad.address : null });
        }),
      );
    }
  }
  for (const f of fichiers("annuaire", "traces")) {
    lire("annuaire", "traces", f).steps.forEach((p, i) => {
      if (p.method !== "inscrire" || typeof p.request.message !== "string") return;
      const passe = p.expected.accepted || apresSignature.has(p.expected.reason);
      confronter("annuaire/traces", f, i, p.request.signature, true, { texte: p.request.message, attendue: passe ? p.request.address : null });
    });
  }
}

// console/fichiers-cle/ : fichiers que CT-3 accepte, ou dont il refuse
// seulement l'adresse, déchiffrés par decryptKeystoreJsonSync.
const lignesCles = [];
for (const f of fichiers("console", "fichiers-cle")) {
  const c = lire("console", "fichiers-cle", f);
  if (!(c.expected.outcome === "accepte" || c.expected.reason === "adresse_differente")) continue;
  let adresse = null;
  try {
    adresse = decryptKeystoreJsonSync(JSON.stringify(c.input.keystore), c.input.password).address.toLowerCase();
  } catch {
    adresse = null;
  }
  const verdict = adresse === c.expected.address ? "concorde" : "discordance";
  comptes[verdict]++;
  lignesCles.push(`console/fichiers-cle | ${f} | 0 | ${adresse ?? "refusé"} | ${c.expected.address} | ${verdict}`);
}

const sortie = [
  `# Confrontation des signatures des vecteurs CT-3 par ethers ${versionEthers} (verifyMessage, decryptKeystoreJsonSync)`,
  "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
  ...lignes,
  ...lignesCles,
  `# bilan : ${lignes.length + lignesCles.length} signatures et fichiers ; concorde ${comptes.concorde}, acceptee_par_la_bibliotheque ${comptes.acceptee_par_la_bibliotheque}, refusee_par_la_bibliotheque ${comptes.refusee_par_la_bibliotheque}, discordance ${comptes.discordance}`,
  "",
].join("\n");
process.stdout.write(sortie);
process.exit(comptes.discordance > 0 ? 1 : 0);
