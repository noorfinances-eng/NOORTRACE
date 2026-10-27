#!/usr/bin/env node
// Confrontation des signatures des procès-verbaux de cérémonie des vecteurs
// CT-7 par ethers (spec/CT-7-securite-et-conformite.md, version 0.1, §5.7,
// CR-11 de §5.8, EX-A.24).
//
//   node spec/vecteurs/ct-7/confrontation/ceremonies/confronter_ethers.mjs spec/vecteurs/ct-7
//
// Le programme n'importe rien de scripts/ : il relit les vecteurs, recalcule
// lui-même D_C = Keccak-256(P_C ‖ JCS(V)) (V : le procès-verbal privé de son
// membre signatures ; JCS v0 de CT-1 §4) et porte sa propre référence de CT-7
// (contrôle de forme de CR-11, Keccak-256 et recouvrement secp256k1 écrits
// ici, sans bibliothèque). La seule bibliothèque employée est ethers, celle
// de node_modules du dépôt, dont la version est lue dans
// node_modules/ethers/package.json. Pour chaque signature de chaque
// procès-verbal de ceremonies/, le programme :
//
//   1. contrôle la forme avant la bibliothèque (CR-11) : 65 octets, r et s
//      dans [1, n − 1], s ≤ n/2, v ∈ {27, 28} ; CT-7 ne normalise jamais ;
//   2. recouvre l'adresse par verifyMessage d'ethers, avec la signature telle
//      que le vecteur la porte, sur les 32 octets de D_C (getBytes, jamais la
//      chaîne « 0x… ») ;
//   3. compare à l'adresse attendue : celle du participant quand attendu.json
//      la range parmi les signataires (signers), ou, à défaut, celle que
//      recouvre la référence de ce programme.
//
// Pour les cas où CR-1 échoue (attendu.json : digest nul), CT-7 ne définit pas
// D_C ; les signatures y sont recouvertes sur le D_C d'une lecture permissive
// (dernière occurrence d'une clé en double, 0.0 lu comme l'entier 0, schéma
// non vérifié), famille ceremonies/cr1-lecture-permissive, adresse attendue
// celle de la référence.
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
// JCS v0 (CT-1 §4) et D_C (CT-7 §5.7).
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

const P_C = Buffer.from("noortrace/ceremonie-cles/v0\n", "utf8");

/** D_C = Keccak-256(P_C ‖ JCS(V)), V le procès-verbal privé de son membre signatures. */
function condenseC(pv) {
  const v = Object.fromEntries(Object.entries(pv).filter(([k]) => k !== "signatures"));
  return "0x" + versHex(keccak256(Buffer.concat([P_C, Buffer.from(jcs(v), "utf8")])));
}

// ---------------------------------------------------------------------------
// Parcours des vecteurs.
// ---------------------------------------------------------------------------

const racine = process.argv[2];
if (process.argv.length !== 3 || !fs.existsSync(path.join(racine, "INDEX.md")) || !fs.existsSync(path.join(racine, "ceremonies"))) {
  process.stderr.write("usage : node confronter_ethers.mjs <chemin de spec/vecteurs/ct-7>\n");
  process.exit(2);
}
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(racine, ...p), "utf8"));

const lignes = [];
const comptes = { concorde: 0, acceptee_par_la_bibliotheque: 0, refusee_par_la_bibliotheque: 0, discordance: 0 };

/**
 * Une signature sur le condensé `d` (« 0x » et 32 octets) ; `attendue` :
 * adresse que le vecteur nomme, ou null (celle de la référence) ; `coherent`
 * faux si le vecteur contredit la référence ; `exclue` : adresse que la
 * référence ne doit pas recouvrir (participant que le vecteur ne range pas
 * parmi les signataires).
 */
function confronter(famille, cas, indice, signature, d, { attendue = null, coherent = true, exclue = null }) {
  const forme = formeCt7(signature);
  let recouvree = null;
  try {
    recouvree = verifyMessage(getBytes(d), signature).toLowerCase();
  } catch {
    recouvree = null;
  }
  const ref = forme ? recouvrerReference(getBytes(d), forme) : null;
  const cible = attendue ?? ref;
  let verdict;
  if (!coherent || (forme && exclue !== null && ref === exclue)) verdict = "discordance";
  else if (!forme) verdict = recouvree === null ? "concorde" : "acceptee_par_la_bibliotheque";
  else if (recouvree === null) verdict = "discordance";
  else verdict = recouvree === cible && ref === cible ? "concorde" : "discordance";
  comptes[verdict]++;
  lignes.push(`${famille} | ${cas} | ${indice} | ${recouvree ?? "refusée"} | ${forme ? cible : "forme refusée par CT-7"} | ${verdict}`);
}

const cas = fs.readdirSync(path.join(racine, "ceremonies")).filter((n) => fs.existsSync(path.join(racine, "ceremonies", n, "proces-verbal.json"))).sort();
for (const nom of cas) {
  const attendu = lire("ceremonies", nom, "attendu.json");
  // Lecture permissive : JSON.parse garde la dernière occurrence d'une clé et lit 0.0 comme 0.
  const pv = lire("ceremonies", nom, "proces-verbal.json");
  const d = condenseC(pv);
  const permissive = attendu.digest === null;
  const famille = permissive ? "ceremonies/cr1-lecture-permissive" : "ceremonies";
  const adresses = new Map();
  for (const p of pv.participants) if (!adresses.has(p.id)) adresses.set(p.id, p.address);
  pv.signatures.forEach((s, i) => {
    const adresse = adresses.get(s.participant) ?? null;
    const signataire = !permissive && adresse !== null && attendu.signers.includes(adresse);
    confronter(famille, nom, i, s.signature, d, {
      attendue: signataire ? adresse : null,
      coherent: permissive ? attendu.signers.length === 0 : d === attendu.digest,
      exclue: !permissive && !signataire ? adresse : null,
    });
  });
}

const sortie = [
  `# Confrontation des signatures des procès-verbaux des vecteurs CT-7 par ethers ${versionEthers} (verifyMessage, getBytes)`,
  "# famille | cas | indice | adresse recouvrée par la bibliothèque | adresse attendue | verdict",
  ...lignes,
  `# bilan : ${lignes.length} signatures ; concorde ${comptes.concorde}, acceptee_par_la_bibliotheque ${comptes.acceptee_par_la_bibliotheque}, refusee_par_la_bibliotheque ${comptes.refusee_par_la_bibliotheque}, discordance ${comptes.discordance}`,
  "",
].join("\n");
process.stdout.write(sortie);
process.exit(comptes.discordance > 0 ? 1 : 0);
