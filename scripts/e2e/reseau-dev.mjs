// Outils communs aux épreuves qui tournent sur le réseau de développement
// noorcore (chain/scripts/dev-net.sh) : parcours du registre (TE-4 de CT-9,
// scripts/e2e/parcours-registre.mjs) et mesure de la capture d'un bloc plein
// (TM-31, scripts/e2e/mesure-capture-bloc-plein.mjs).
//
// - répertoire d'exécution : NOORTRACE_RUNTIME_DIR, sinon chain/runtime (le
//   même que dev-net.sh et build-noorcore.sh) ;
// - binaire : <exécution>/bin/noorcore, avec la méthode
//   noor_getCommitCertificate (cherchée dans les octets du binaire : le
//   binaire de retour arrière noorcore.618fcef ne la porte pas) ;
// - réseau : dev-net.sh status / start / stop ; une épreuve n'arrête que ce
//   qu'elle a démarré ;
// - vérificateur Go de CT-6 §14 : --verificateur-go, NOORTRACE_VERIFICATEUR_GO,
//   verificateur/dist/noortrace-verifier-linux-amd64, ou construction par
//   verificateur/scripts/construire.sh quand go1.27.3 est dans le PATH.
//
// Rien ici n'écrit dans le dépôt : les seules écritures sont celles de
// dev-net.sh sous le répertoire d'exécution et le binaire Go construit dans
// le répertoire de travail que l'appelant désigne.

import fs from "node:fs";
import path from "node:path";
import { spawnSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const RACINE = fileURLToPath(new URL("../../", import.meta.url));
export const RPC_DEV = "http://127.0.0.1:8645";
/** Points JSON-RPC des quatre validateurs (chain/scripts/dev-net.sh, RPC_PORTS). */
export const RPC_VALIDATEURS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
export const METHODE_CERTIFICAT = "noor_getCommitCertificate";
/** Version de Go qu'impose verificateur/go.mod (CT-6 EX-14.3). */
export const GO_VERIFICATEUR = "go1.27.3";
const DEV_NET = path.join(RACINE, "chain", "scripts", "dev-net.sh");

/** Répertoire d'exécution du réseau de développement (même règle que dev-net.sh). */
export function repertoireExecution() {
  const r = process.env.NOORTRACE_RUNTIME_DIR;
  if (!r) return path.join(RACINE, "chain", "runtime");
  return path.isAbsolute(r) ? r : path.resolve(process.cwd(), r);
}

/**
 * Le binaire noorcore du répertoire d'exécution porte-t-il la méthode du
 * certificat de commit ? Rend { ok, binaire, condition } ; `condition` nomme
 * ce qui manque (EX-3.11 de CT-9) quand ok est faux.
 */
export function binaireAvecCertificat(runtime = repertoireExecution()) {
  const binaire = path.join(runtime, "bin", "noorcore");
  const nom = path.relative(RACINE, binaire).startsWith("..") ? "<NOORTRACE_RUNTIME_DIR>/bin/noorcore" : path.relative(RACINE, binaire);
  let st;
  try {
    st = fs.statSync(binaire);
  } catch {
    return { ok: false, binaire, condition: `binaire noorcore absent (${nom}) : le construire avec le correctif du certificat de commit (chain/scripts/build-noorcore.sh, chain/patches/LISEZMOI.md)` };
  }
  if (!st.isFile() || (st.mode & 0o111) === 0) return { ok: false, binaire, condition: `${nom} n'est pas un exécutable` };
  const octets = fs.readFileSync(binaire);
  if (octets.indexOf(Buffer.from(METHODE_CERTIFICAT, "utf8")) === -1) {
    return { ok: false, binaire, condition: `${nom} ne porte pas la méthode ${METHODE_CERTIFICAT} : binaire construit sans le correctif de chain/patches/ (CT-4 4.7, 9.1)` };
  }
  return { ok: true, binaire, condition: null };
}

/** Appel JSON-RPC direct (fetch de Node, boucle locale : aucun mandataire). Rend { result } ou { error }. */
let idRpc = 0;
export async function rpc(url, method, params = [], { delaiMs = 10_000 } = {}) {
  const ctl = AbortSignal.timeout(delaiMs);
  const reponse = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++idRpc, method, params }), signal: ctl });
  const corps = await reponse.json();
  if (corps.error) return { error: corps.error };
  return { result: corps.result };
}

/** Comme rpc, mais lève sur une erreur JSON-RPC. */
export async function rpcResultat(url, method, params = [], options = {}) {
  const r = await rpc(url, method, params, options);
  if (r.error) throw new Error(`${method} : ${r.error.code} ${r.error.message}`);
  return r.result;
}

/** `dev-net.sh <commande>` : rend { code, sortie } ; la sortie est recopiée sur `journal` (sortie d'erreur par défaut). */
export function devNet(commande, { journal = process.stderr } = {}) {
  const r = spawnSync("bash", [DEV_NET, commande], { cwd: RACINE, encoding: "utf8", env: process.env, maxBuffer: 16 * 1024 * 1024, timeout: 10 * 60 * 1000 });
  const sortie = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  if (journal) journal.write(sortie.replace(/^/gm, "  | ").replace(/ {2}\| $/, ""));
  return { code: r.status ?? (r.error ? 2 : 1), sortie };
}

/** Hauteur de tête lue sur le premier validateur, ou null s'il ne répond pas. */
export async function hauteurTete(url = RPC_DEV) {
  try {
    const r = await rpc(url, "eth_blockNumber", [], { delaiMs: 3000 });
    return r.error ? null : Number(BigInt(r.result));
  } catch {
    return null;
  }
}

/**
 * Démarre le réseau s'il n'est pas déjà debout. Rend { demarre, deja_debout,
 * partiel } : `demarre` vrai si l'épreuve a lancé au moins un nœud (elle
 * l'arrêtera), `partiel` vrai si une partie des nœuds tournait déjà (elle ne
 * les arrêtera pas : dev-net.sh n'arrête que les quatre ensemble).
 */
export function assurerReseau({ journal = process.stderr } = {}) {
  const avant = devNet("status", { journal });
  if (avant.code === 0) return { demarre: false, deja_debout: true, partiel: false };
  const partiel = /:\s+en marche \(pid/.test(avant.sortie);
  const r = devNet("start", { journal });
  if (r.code !== 0) throw new Error(`dev-net.sh start a échoué (code ${r.code})`);
  return { demarre: !partiel, deja_debout: false, partiel };
}

/** Arrête le réseau (dev-net.sh stop) et vérifie qu'aucun validateur ne reste debout. */
export function arreterReseau({ journal = process.stderr } = {}) {
  const r = devNet("stop", { journal });
  const apres = devNet("status", { journal: null });
  return { code: r.code, arrete: /0\/4 validateurs debout/.test(apres.sortie) };
}

/** Version de `go` dans le PATH (« go1.27.3 »), ou null. */
function versionGo() {
  const r = spawnSync("go", ["env", "GOVERSION"], { encoding: "utf8", env: { ...process.env, GOTOOLCHAIN: "local" } });
  if (r.status !== 0) return null;
  return r.stdout.trim() || null;
}

/**
 * Binaire du vérificateur Go (CT-6 §14). `option` : chemin donné par
 * --verificateur-go ; `repTravail` : où construire le binaire s'il faut le
 * construire. Rend { ok, chemin, origine, condition }.
 */
export function verificateurGo({ option = null, repTravail = null } = {}) {
  const candidat = option ?? process.env.NOORTRACE_VERIFICATEUR_GO ?? null;
  if (candidat) {
    const c = path.resolve(candidat);
    if (fs.existsSync(c)) return { ok: true, chemin: c, origine: option ? "--verificateur-go" : "NOORTRACE_VERIFICATEUR_GO", condition: null };
    return { ok: false, chemin: c, origine: null, condition: `vérificateur Go introuvable : ${candidat}` };
  }
  const dist = path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64");
  if (fs.existsSync(dist)) return { ok: true, chemin: dist, origine: "verificateur/dist", condition: null };
  const v = versionGo();
  if (v !== GO_VERIFICATEUR) {
    return { ok: false, chemin: null, origine: null, condition: `vérificateur Go de CT-6 §14 indisponible : ni --verificateur-go, ni NOORTRACE_VERIFICATEUR_GO, ni verificateur/dist/noortrace-verifier-linux-amd64, et ${v ? `${v} au lieu de ${GO_VERIFICATEUR}` : `aucun go ${GO_VERIFICATEUR}`} dans le PATH pour le construire` };
  }
  if (!repTravail) return { ok: true, chemin: null, origine: "a_construire", condition: null };
  const sortie = path.join(repTravail, "noortrace-verifier");
  const r = spawnSync("bash", [path.join(RACINE, "verificateur", "scripts", "construire.sh"), "-o", sortie], { cwd: path.join(RACINE, "verificateur"), encoding: "utf8", env: process.env, timeout: 10 * 60 * 1000 });
  if (r.status !== 0 || !fs.existsSync(sortie)) return { ok: false, chemin: null, origine: null, condition: `construction du vérificateur Go en échec : ${(r.stderr || r.stdout || "").trim().slice(-400)}` };
  return { ok: true, chemin: sortie, origine: "construit par verificateur/scripts/construire.sh", condition: null };
}

/** Lance une commande et rend { code, stdout, stderr, duree_ms } (horloge monotone). */
export function lancer(commande, args, { cwd = RACINE, env = process.env, timeout = 10 * 60 * 1000 } = {}) {
  const t0 = process.hrtime.bigint();
  const r = spawnSync(commande, args, { cwd, env, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout });
  const duree_ms = Number(process.hrtime.bigint() - t0) / 1e6;
  return { code: r.status ?? 2, stdout: r.stdout ?? "", stderr: r.stderr ?? (r.error ? String(r.error) : ""), duree_ms };
}

/** Variante asynchrone (sortie recopiée au fil de l'eau sur la sortie d'erreur). */
export function lancerAsync(commande, args, { cwd = RACINE, env = process.env } = {}) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const p = spawn(commande, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => {
      stderr += d;
      process.stderr.write(d);
    });
    p.on("close", (code) => resolve({ code: code ?? 2, stdout, stderr, duree_ms: Number(process.hrtime.bigint() - t0) / 1e6 }));
  });
}

export const dormir = (ms) => new Promise((r) => setTimeout(r, ms));
