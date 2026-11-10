// Utilitaires des tests du lot B (client OpenTimestamps) : chemins des
// vecteurs, lecture, chaîne regtest synthétique, horloge fixe, transport
// factice, détection de python-opentimestamps et du vérificateur Go.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const VECTEURS = path.join(RACINE, "spec", "vecteurs");
export const CT5_OTS = path.join(VECTEURS, "ct-5", "ots");
export const CT6_OTS = path.join(VECTEURS, "ct-6", "ots");
export const CT6_DOSSIERS = path.join(VECTEURS, "ct-6", "dossiers");
export const SCRIPT_PYTHON = path.join(RACINE, "test", "fixtures", "ancrage-ots", "reserialiser.py");

export const lireOctets = (p) => new Uint8Array(fs.readFileSync(p));
export const lireJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
export const hex = (o) => "0x" + Buffer.from(o).toString("hex");
export const sha256 = (o) => Uint8Array.from(createHash("sha256").update(o).digest());
export const sha256Hex = (o) => hex(sha256(o));
export const dsha = (o) => sha256(sha256(o));
export const utf8 = (t) => new TextEncoder().encode(t);
export const memesOctets = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
export const repertoireTemporaire = (prefixe) => fs.mkdtempSync(path.join(os.tmpdir(), prefixe));

/** Horloge injectée fixe : murale constante, monotone qui avance d'une milliseconde par lecture. */
export function horlogeFixe(muraleMs = 1793714400000) {
  let mono = 1000;
  return { murale: () => muraleMs, monotone: () => (mono += 1) };
}

/**
 * Transport factice : `repondre(methode, url, corps)` rend `{status, entetes, corps}`
 * ou lève ; chaque appel est consigné dans `appels`.
 */
export function transportFactice(repondre) {
  const appels = [];
  return {
    appels,
    async post(url, octets, entetes, delaiMs) {
      appels.push({ methode: "POST", url, corps: Uint8Array.from(octets), entetes, delaiMs });
      return repondre("POST", url, octets, entetes);
    },
    async get(url, entetes, delaiMs) {
      appels.push({ methode: "GET", url, corps: null, entetes, delaiMs });
      return repondre("GET", url, null, entetes);
    },
  };
}

/** Réponse HTTP factice. */
export const reponseHttp = (status, corps, entetes = {}) => ({ status, entetes, corps: corps instanceof Uint8Array ? corps : utf8(String(corps)) });

/** Entier petit-boutiste sur n octets. */
function petitBoutiste(valeur, n) {
  const o = new Uint8Array(n);
  let v = valeur;
  for (let i = 0; i < n; i += 1) {
    o[i] = v % 256;
    v = Math.floor(v / 256);
  }
  return o;
}

const CIBLE_REGTEST = 0x7fffffn << 232n; // SetCompact(0x207fffff)

function hachageEnEntier(h) {
  let v = 0n;
  for (let i = 31; i >= 0; i -= 1) v = (v << 8n) | BigInt(h[i]);
  return v;
}

/**
 * Chaîne regtest synthétique au format entetes-bitcoin-v0 : en-têtes de 80
 * octets minés à la cible regtest (`nBits` 0x207fffff, plus petit nonce qui
 * satisfait la cible), `nTime` croissant de 600 s, `racine(i)` donnée par
 * `racines` (Map hauteur → 32 octets) ou dérivée de la hauteur.
 * @param {{debut: number, nombre: number, racines?: Map<number, Uint8Array>, nTime0?: number, prev0?: Uint8Array, nBits?: number}} p
 */
export function chaineRegtest({ debut, nombre, racines = new Map(), nTime0 = 1793880000, prev0 = new Uint8Array(32), nBits = 0x207fffff }) {
  const headers = [];
  const enTetes = [];
  let prev = prev0;
  for (let k = 0; k < nombre; k += 1) {
    const hauteur = debut + k;
    const racine = racines.get(hauteur) ?? dsha(utf8(`noortrace/ancrage/lot-b/racine/${hauteur}`));
    const base = new Uint8Array(80);
    base.set(petitBoutiste(0x20000000, 4), 0);
    base.set(prev, 4);
    base.set(racine, 36);
    base.set(petitBoutiste(nTime0 + 600 * k, 4), 68);
    base.set(petitBoutiste(nBits, 4), 72);
    let nonce = 0;
    let hash;
    for (;;) {
      base.set(petitBoutiste(nonce, 4), 76);
      hash = dsha(base);
      if (hachageEnEntier(hash) <= CIBLE_REGTEST) break;
      nonce += 1;
    }
    headers.push(hex(base));
    enTetes.push({ hauteur, octets: Uint8Array.from(base), hash, hashAffiche: hex(Uint8Array.from(hash).reverse()) });
    prev = hash;
  }
  return {
    document: { version: 0, network: "regtest", start_height: debut, source: "chaîne regtest synthétique des tests du lot B, sans valeur hors des tests", headers },
    enTetes,
  };
}

/** Interpréteur Python qui importe `opentimestamps`, ou null (condition d'essai en attente). */
export function pythonOts() {
  const candidats = [process.env.NOORTRACE_OTS_PYTHON, "python3"].filter(Boolean);
  for (const py of candidats) {
    const r = spawnSync(py, ["-I", "-c", "import opentimestamps"], { encoding: "utf8" });
    if (r.status === 0) return py;
  }
  return null;
}

/**
 * Relit et resérialise un fichier avec python-opentimestamps.
 * @returns {{status: number, description: object|null, octets: Uint8Array|null, erreur: string}}
 */
export function reserialiserPython(py, fichier, message = null) {
  const args = ["-I", SCRIPT_PYTHON, ...(message ? ["--timestamp", message.replace(/^0x/, "")] : []), fichier];
  const r = spawnSync(py, args, { maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0) return { status: r.status, description: null, octets: null, erreur: String(r.stderr) };
  const sortie = r.stdout;
  const fin = sortie.indexOf(0x0a);
  const description = JSON.parse(sortie.subarray(0, fin).toString("utf8"));
  return { status: 0, description, octets: new Uint8Array(sortie.subarray(fin + 1)), erreur: "" };
}

/** Vérificateur Go de CT-6 construit avec go1.27.3, ou null (NOORTRACE_GO_BIN absent, go absent, échec de construction). */
export function construireVerificateurGo(dir) {
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  if (!dirGo) return null;
  const env = { ...process.env, GOTOOLCHAIN: "local", PATH: `${dirGo}${path.delimiter}${process.env.PATH}` };
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(dir, "noortrace-verifier");
  const c = spawnSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env: { ...env, GOFLAGS: "-mod=vendor" }, cwd: path.join(RACINE, "verificateur"), encoding: "utf8" });
  if (c.status !== 0) return null;
  return sortie;
}

/** Marque un essai en attente avec sa condition dans le titre. */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Copie d'un fichier avec un octet remplacé (entrée hostile). */
export function muter(octets, position, valeur) {
  const m = Uint8Array.from(octets);
  m[position] = valeur;
  return m;
}

/** Concatène des suites d'octets. */
export function concat(...parties) {
  const total = parties.reduce((n, p) => n + p.length, 0);
  const o = new Uint8Array(total);
  let d = 0;
  for (const p of parties) {
    o.set(p, d);
    d += p.length;
  }
  return o;
}
