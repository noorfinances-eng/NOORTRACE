// Outils communs aux tests du cœur de l'enregistreur
// (test/enregistreur-coeur*.test.js) : chemins des vecteurs, clés de test de
// CT-1 §13 (graines publiques, sans valeur), configuration de développement
// tirée de l'exemple de CT-2 §15.3, répertoires temporaires sous
// os.tmpdir().

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sha256, utf8, octetsVersHex } from "@noortrace/noyau";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const SPEC = path.join(RACINE, "spec");
export const VECTEURS_CT2 = path.join(SPEC, "vecteurs", "ct-2");
export const BIN_NOORTRACE = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace");

/** Graine Ed25519 d'une clé de test de CT-1 §13 (rec-test-01, rec-test-02). */
export function graine(label) {
  return sha256(utf8(`noortrace/vecteurs/v0/cle-enregistreur/${label}`));
}

/** Fichier PKCS#8 PEM d'une graine (CT-1 §13 : 302e020100300506032b657004220420 ‖ graine). */
export function pemPkcs8(g) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(g)]);
  const b64 = der.toString("base64");
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

/** Répertoire temporaire neuf. */
export function repertoireTemporaire(prefixe = "noortrace-coeur-") {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
}

/**
 * Blocs ```json (ou ```text) qui suivent une ligne marqueur dans un texte de
 * la spécification.
 */
export function blocApres(texte, marqueur, debutRecherche = 0) {
  const lignes = texte.split("\n");
  let i = lignes.findIndex((l, k) => k >= debutRecherche && l.includes(marqueur));
  if (i < 0) throw new Error(`marqueur introuvable : ${marqueur}`);
  while (!lignes[i].startsWith("```")) i++;
  const debut = i + 1;
  let fin = debut;
  while (lignes[fin] !== "```") fin++;
  return { texte: lignes.slice(debut, fin).join("\n"), ligne: fin };
}

/** Texte de CT-2. */
export function texteCT2() {
  return fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
}

/** Exemple complet de configuration de CT-2 §15.3. */
export function configurationExemple() {
  return JSON.parse(blocApres(texteCT2(), "<!-- schema: configuration-enregistreur -->").texte);
}

/** Clé du MAC de relais des tests (32 octets, hexadécimal). */
export const CLE_MAC_HEX = octetsVersHex(sha256(utf8("noortrace/tests/coeur/cle-mac-relais"))).slice(2);

/**
 * Configuration de développement : l'exemple de 15.3 adapté (classe D,
 * bail de fichier, stockage et journal d'exploitation sous `dir`, aucune
 * copie WORM, registre désactivé, secrets en variables d'environnement).
 * Écrit les clés rec-test-01 et rec-test-02 en PKCS#8 sous `dir/cles`.
 */
export function configurationDev(dir, o = {}) {
  const c = configurationExemple();
  fs.mkdirSync(path.join(dir, "cles"), { recursive: true });
  for (const l of ["rec-test-01", "rec-test-02"]) {
    fs.writeFileSync(path.join(dir, "cles", `${l}.pem`), pemPkcs8(graine(l)), { mode: 0o600 });
  }
  c.recorder.environment = o.environment ?? "developpement";
  c.recorder.instance_id = o.instance_id ?? "enregistreur-test";
  if (o.journal_id) c.recorder.journal_id = o.journal_id;
  c.signer = {
    class: "D",
    key_id: "rec-test-01",
    backend: { type: "file", path: path.join(dir, "cles", "rec-test-01.pem"), passphrase: null },
    verify_after_sign: true,
    max_message_bytes: null,
    timeout_ms: 5000,
    health_interval_ms: 10000,
    rotation: { planned_every_days: null, next_key_id: "rec-test-02" },
  };
  // Frontal MCP (lot du frontal) : désactivé sauf demande ; les serveurs
  // d'outils de l'exemple de 15.3 ne sont pas joignables depuis les tests.
  c.mcp.enabled = o.mcp === true;
  c.mcp.socket = path.join(dir, "prise", "mcp.sock");
  // Frontal modèle (lot du frontal modèle) : désactivé sauf demande ; activé,
  // la passerelle écoute sur un port libre choisi par le système et garde la
  // connexion d'hôte de l'exemple de 15.3 (aucun test ne dépend de 8400).
  c.model.mode = o.modele === true ? "passerelle" : "desactive";
  if (o.modele === true) c.model.listen = "127.0.0.1:0";
  c.storage.root = path.join(dir, "stockage");
  c.storage.min_free_bytes = 1024;
  c.storage.seal = { append_only_attribute: false, worm: null };
  c.storage.relay_mac_key = { env: "NOORTRACE_TEST_CLE_MAC", encoding: "hex" };
  c.lease = { store: { type: "file", path: path.join(dir, "bail", "verrou") }, ttl_ms: 10000, renew_ms: 3000, acquire_wait_ms: 1000, fencing: null };
  c.supervision.health_listen = "127.0.0.1:0";
  c.supervision.ops_log.path = path.join(dir, "exploitation.ndjson");
  c.anchoring.registry = { enabled: false, rpc_url: null, chain_key: null, next_chain_key: null };
  c.anchoring.opentimestamps = { enabled: false, calendars: [] };
  if (o.checkpoint_interval_s) c.checkpoint_interval_s = o.checkpoint_interval_s;
  // Secrets restants : variables d'environnement de test.
  let n = 0;
  const env = { NOORTRACE_TEST_CLE_MAC: CLE_MAC_HEX };
  const remplacer = (v) => {
    if (Array.isArray(v)) return v.forEach(remplacer);
    if (v === null || typeof v !== "object") return;
    for (const [k, x] of Object.entries(v)) {
      if (x && typeof x === "object" && !Array.isArray(x) && (typeof x.file === "string" || typeof x.env === "string") && Object.keys(x).every((y) => ["file", "env", "encoding"].includes(y))) {
        if (x.env === "NOORTRACE_TEST_CLE_MAC") continue;
        const nom = `NOORTRACE_TEST_SECRET_${++n}`;
        env[nom] = `secret-de-test-${n}`;
        v[k] = x.encoding ? { env: nom, encoding: "utf8" } : { env: nom };
      } else {
        remplacer(x);
      }
    }
  };
  remplacer(c);
  return { config: c, env };
}

/** Secrets résolus d'une configuration de développement (clé du MAC seule). */
export function secretsDev() {
  return new Map([["/storage/relay_mac_key", new Uint8Array(Buffer.from(CLE_MAC_HEX, "hex"))]]);
}

/** Lit un fichier JSON des vecteurs CT-2. */
export function lireVecteur(rel) {
  return JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, rel), "utf8"));
}
