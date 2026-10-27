#!/usr/bin/env node
// Confrontation des signatures d'attestation de périmètre des vecteurs CT-7,
// CT-1 et CT-6 par ethers (spec/CT-7-securite-et-conformite.md, version 0.1,
// §7.2, EX-7.6, EX-7.7, AT-3, EX-A.25).
//
//   node spec/vecteurs/ct-7/confrontation/attestations/confronter_ethers.mjs spec/vecteurs/ct-7 spec/vecteurs/ct-1 spec/vecteurs/ct-6
//
// Le programme n'importe rien de scripts/ : il relit les vecteurs, recalcule
// lui-même D_P = Keccak-256(P_P ‖ JCS(P)) (JCS v0 de CT-1 §4) et porte sa
// propre référence de CT-7 (contrôle de forme d'EX-7.6, Keccak-256 et
// recouvrement secp256k1 écrits ici, sans bibliothèque). La seule
// bibliothèque employée est ethers, celle de node_modules du dépôt, dont la
// version est lue dans node_modules/ethers/package.json. Signatures
// confrontées : attestations/exemple/ (condense.json et
// attestation-signee.json), chaque cas de attestations/attestations.json,
// chaque cas de attestations/croises.json (indice 0 : sur le message signé ;
// indice 1 : sur le message que le cas lui fait présenter), et la partie
// attestation-perimetre.json de chaque dossier de ct-1 et de ct-6 qui la
// porte. Pour chacune, le programme :
//
//   1. contrôle la forme avant la bibliothèque (EX-7.6) : 65 octets, r et s
//      dans [1, n − 1], s ≤ n/2, v ∈ {27, 28} ; CT-7 ne normalise jamais ;
//   2. recouvre l'adresse par verifyMessage d'ethers, avec la signature telle
//      que le vecteur la porte, sur les 32 octets du condensé (getBytes,
//      jamais la chaîne « 0x… »), ou sur le texte d'inscription de CT-3 d'un
//      cas croisé ;
//   3. compare à l'adresse attendue : celle que le vecteur nomme (adresse
//      déclarée quand AT-3 réussit, expected.recovered d'un cas, compte 1
//      pour le message signé d'un cas croisé), ou, à défaut, celle que
//      recouvre la référence de ce programme.
//
// Une attestation dont AT-1 échoue (texte JSON refusé par l'analyse stricte,
// forme refusée) n'a pas de D_P selon CT-7 ; ses signatures sont recouvertes
// sur le D_P d'une lecture permissive (0.0 lu comme 0, schéma non vérifié),
// adresse attendue celle de la référence.
//
// Verdicts (ceux de la confrontation de CT-3) : concorde,
// acceptee_par_la_bibliotheque, refusee_par_la_bibliotheque, discordance. Le
// code de sortie est 0 sans discordance, 1 avec au moins une, 2 pour un usage
// incorrect. La sortie ne porte aucun chemin local.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getBytes, verifyMessage } from "ethers";

const ICI = path.dirname(fileURLToPath(import.meta.url));
// Version lue dans node_modules/ethers/package.json du dépôt.
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

/** M = keccak256(0x19 ‖ « Ethereum Signed Message:\n » ‖ longueur décimale ‖ octets) (EIP-191, version 0x45). */
const condenseEIP191 = (octets) => keccak256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n" + octets.length, "latin1"), Buffer.from(octets)]));

/** Adresse recouvrée par la référence sur une forme canonique (v ∈ {27, 28}), ou null. */
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

/** Forme de CT-7 (CR-11, EX-7.6) : la signature en minuscules si elle est canonique, sinon null ; jamais normalisée. */
function formeCt7(sig) {
  if (typeof sig !== "string" || !/^0x[0-9a-fA-F]*$/.test(sig)) return null;
  const s0 = sig.toLowerCase();
  if (s0.length !== 132) return null;
  const r = BigInt("0x" + s0.slice(2, 66)), s = BigInt("0x" + s0.slice(66, 130)), v = parseInt(s0.slice(130), 16);
  if (r < 1n || r >= N || s < 1n || s >= N) return null;
  return (v === 27 || v === 28) && s <= N / 2n ? s0 : null;
}


// ---------------------------------------------------------------------------
// JCS v0 (CT-1 §4) et D_P (CT-7 §7.2).
// ---------------------------------------------------------------------------

/** JCS v0 : clés triées par unités UTF-16, chaînes comme JSON.stringify, entiers sûrs seulement. */
function jcs(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("nombre hors de JCS v0");
    return String(v === 0 ? 0 : v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
}

const P_P = Buffer.from("noortrace/attestation-perimetre/v0\n", "utf8");

/** D_P = Keccak-256(P_P ‖ JCS(P)). */
const condenseP = (p) => "0x" + versHex(keccak256(Buffer.concat([P_P, Buffer.from(jcs(p), "utf8")])));

// ---------------------------------------------------------------------------
// Parcours des vecteurs.
// ---------------------------------------------------------------------------

const [racine7, racine1, racine6] = process.argv.slice(2);
if (process.argv.length !== 5 || ![racine7, racine1, racine6].every((r) => fs.existsSync(path.join(r, "INDEX.md"))) || !fs.existsSync(path.join(racine7, "attestations"))) {
  process.stderr.write("usage : node confronter_ethers.mjs <chemin de spec/vecteurs/ct-7> <chemin de spec/vecteurs/ct-1> <chemin de spec/vecteurs/ct-6>\n");
  process.exit(2);
}
// Lecture permissive : JSON.parse lit 0.0 comme 0.
const lireTexte = (...p) => fs.readFileSync(path.join(...p), "utf8");
const lire = (...p) => JSON.parse(lireTexte(...p));

const lignes = [];
const comptes = { concorde: 0, acceptee_par_la_bibliotheque: 0, refusee_par_la_bibliotheque: 0, discordance: 0 };

/**
 * Une signature sur un condensé `d` (« 0x » et 32 octets) ou sur un `texte` ;
 * `attendue` : adresse que le vecteur nomme, ou null (celle de la
 * référence) ; `coherent` faux si le vecteur contredit la référence.
 */
function confronter(famille, cas, indice, signature, { d = null, texte = null, attendue = null, coherent = true }) {
  const forme = formeCt7(signature);
  let recouvree = null;
  try {
    recouvree = verifyMessage(texte !== null ? texte : getBytes(d), signature).toLowerCase();
  } catch {
    recouvree = null;
  }
  const octets = texte !== null ? Buffer.from(texte, "utf8") : getBytes(d);
  const ref = forme ? recouvrerReference(octets, forme) : null;
  const cible = attendue ?? ref;
  let verdict;
  if (!coherent) verdict = "discordance";
  else if (!forme) verdict = recouvree === null ? "concorde" : "acceptee_par_la_bibliotheque";
  else if (recouvree === null) verdict = "discordance";
  else verdict = recouvree === cible && ref === cible ? "concorde" : "discordance";
  comptes[verdict]++;
  lignes.push(`${famille} | ${cas} | ${indice} | ${recouvree ?? "refusée"} | ${forme ? cible : "forme refusée par CT-7"} | ${verdict}`);
}

const statut = (checks, id) => checks.find((c) => c.id === id)?.status ?? null;

// attestations/exemple/ : l'exemple de CT-7 §7.2, signé par les comptes 1 et 2.
const exemple = lire(racine7, "attestations", "exemple", "attestation.json");
const dP = condenseP(exemple);
{
  const jcsExemple = Buffer.from(jcs(exemple), "utf8");
  const condense = lire(racine7, "attestations", "exemple", "condense.json");
  const coherent =
    jcsExemple.equals(fs.readFileSync(path.join(racine7, "attestations", "exemple", "jcs.txt"))) &&
    condense.jcs_length === jcsExemple.length &&
    condense.digest === dP &&
    condense.message === "0x" + versHex(condenseEIP191(getBytes(dP)));
  condense.signatures.forEach((s, i) => confronter("attestations/exemple", "condense.json", i, s.signature, { d: dP, attendue: s.address, coherent }));
  const signee = lire(racine7, "attestations", "exemple", "attestation-signee.json");
  const coherentSignee = signee.digest === dP && jcs(signee.attestation) === jcs(exemple);
  signee.signatures.forEach((s, i) => confronter("attestations/exemple", "attestation-signee.json", i, s.signature, { d: dP, attendue: s.address, coherent: coherentSignee }));
}

// attestations/attestations.json : AT-1 réussie, l'adresse attendue est
// expected.recovered[i] (nulle pour une forme que CT-7 refuse) ; AT-1 en
// échec, celle de la référence sur le D_P de la lecture permissive.
for (const c of lire(racine7, "attestations", "attestations.json").cases) {
  const signee = typeof c.input.signed === "string" ? JSON.parse(c.input.signed) : c.input.signed;
  const d = condenseP(signee.attestation);
  const e = c.expected;
  const at1 = statut(e.checks, "AT-1") === "reussi";
  const at3 = statut(e.checks, "AT-3") === "reussi";
  signee.signatures.forEach((s, i) => {
    const attendue = at1 ? e.recovered[i] : null;
    const coherent = at1 ? d === e.digest && e.recovered.length === signee.signatures.length && (!at3 || e.recovered[i] === s.address) : e.recovered === null;
    confronter("attestations/cas", c.name, i, s.signature, { d, attendue, coherent });
  });
}

// attestations/croises.json : indice 0, la signature sur le message que le
// compte 1 a signé (adresse attendue : celle du compte 1) ; indice 1, la même
// signature sur le message que le cas lui fait présenter (adresse attendue :
// expected.recovered, qui n'est pas celle du compte 1).
{
  const croises = lire(racine7, "attestations", "croises.json");
  const dC = lire(racine7, "ceremonies", "valide-creation-enregistreur", "attendu.json").digest;
  const message = (m) => (m.kind === "inscription" ? { texte: m.text } : { d: m.digest });
  const coherentMessage = (m) => (m.kind === "attestation" ? m.digest === dP : m.kind === "ceremonie" ? m.digest === dC : true);
  const coherentBase = croises.attestation_digest === dP;
  for (const c of croises.cases) {
    const presente = c.presented_as === "attestation" ? { kind: "attestation", digest: croises.attestation_digest } : { kind: c.presented_as, ...c.target };
    const coherent = coherentBase && coherentMessage(c.message) && coherentMessage(presente) && c.expected.recovered !== croises.address;
    confronter("attestations/croises", c.name, 0, c.signature, { ...message(c.message), attendue: croises.address, coherent });
    confronter("attestations/croises", c.name, 1, c.signature, { ...message(presente), attendue: c.expected.recovered, coherent });
  }
}

// Dossiers de ct-1 et de ct-6 qui portent la partie attestation-perimetre.json
// (CT-7 A.7) : adresse déclarée attendue quand AT-3 réussit ; sinon, celle de
// la référence. AT-2 réussie, D_P recalculé doit égaler le digest déclaré.
for (const [famille, racine] of [["ct-1/dossiers", racine1], ["ct-6/dossiers", racine6]]) {
  const noms = fs.readdirSync(path.join(racine, "dossiers")).filter((n) => fs.existsSync(path.join(racine, "dossiers", n, "attestation-perimetre.json"))).sort();
  for (const n of noms) {
    const partie = lire(racine, "dossiers", n, "attestation-perimetre.json");
    if (partie === null || typeof partie !== "object" || !partie.signed || !Array.isArray(partie.signed.signatures)) continue;
    const checks = lire(racine, "dossiers", n, "attendu.json").perimeter_checks;
    const d = condenseP(partie.signed.attestation);
    const coherent = statut(checks, "AT-2") !== "reussi" || d === partie.signed.digest;
    const at3 = statut(checks, "AT-3") === "reussi";
    partie.signed.signatures.forEach((s, i) => confronter(famille, n, i, s.signature, { d, attendue: at3 ? s.address : null, coherent }));
  }
}

const sortie = [
  `# Confrontation des signatures d'attestation des vecteurs CT-7, CT-1 et CT-6 par ethers ${versionEthers} (verifyMessage, getBytes)`,
  "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
  ...lignes,
  `# bilan : ${lignes.length} signatures ; concorde ${comptes.concorde}, acceptee_par_la_bibliotheque ${comptes.acceptee_par_la_bibliotheque}, refusee_par_la_bibliotheque ${comptes.refusee_par_la_bibliotheque}, discordance ${comptes.discordance}`,
  "",
].join("\n");
process.stdout.write(sortie);
process.exit(comptes.discordance > 0 ? 1 : 0);
