#!/usr/bin/env node
// Serveur d'outils de fichiers minimal, en stdio (MCP, ère héritée), pour le
// pont d'exemple `pont-fichiers` de production.yaml (CT-8 §3.4 ; décision
// D-13 de l'étape 7 : écrit dans le dépôt, sans code tiers dans l'image).
//
//   serveur-fichiers <racine absolue>
//
// Dans l'image noortrace/pont-stdio, il est installé au chemin que
// production.yaml donne au pont : /opt/mcp/server-filesystem/bin/server-filesystem.
//
// Messages JSON-RPC, un par ligne, sur l'entrée et la sortie standard.
// Méthodes : `initialize` (versions 2025-11-25, 2025-06-18, 2025-03-26 et
// 2024-11-05 ; une autre version demandée reçoit la plus récente), `ping`,
// `tools/list`, `tools/call` ; toute autre requête : -32601 ; les
// notifications sont ignorées. Trois outils, aux noms et arguments de la
// configuration modèle de production (`policy.servers.fichiers.tools`) :
//   - `list_directory` { path } : une ligne par entrée, triée,
//     `[DIR] <nom>`, `[FILE] <nom>` ou `[LINK] <nom>` (lien symbolique, non suivi) ;
//   - `read_file` { path } : contenu UTF-8 d'un fichier de 1 Mio au plus ;
//   - `write_file` { path, content } : écrit (crée ou remplace) un fichier
//     de 1 Mio au plus, par un fichier temporaire du même répertoire puis un
//     renommage, en mode 0640.
// Un chemin est relatif à la racine, ou absolu sous elle ; après résolution
// des liens symboliques, il DOIT rester sous la racine (refus sinon, sans rien
// lire ni écrire). Une erreur d'outil est rendue en résultat `isError: true`
// (MCP), jamais en erreur JSON-RPC.

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { fileURLToPath } from "node:url";

export const NOM = "noortrace-serveur-fichiers";
export const VERSION = "0.1.0";
export const VERSIONS = Object.freeze(["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]);
export const OCTETS_MAX = 1024 * 1024;

export const OUTILS = Object.freeze([
  {
    name: "list_directory",
    description: "Liste les entrées d'un répertoire sous la racine du serveur.",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
  },
  {
    name: "read_file",
    description: "Lit un fichier texte (UTF-8, 1 Mio au plus) sous la racine du serveur.",
    inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false },
  },
  {
    name: "write_file",
    description: "Écrit un fichier texte (UTF-8, 1 Mio au plus) sous la racine du serveur.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
      required: ["path", "content"],
      additionalProperties: false,
    },
  },
]);

class RefusOutil extends Error {}

const dans = (racine, p) => p === racine || p.startsWith(racine + path.sep);

/**
 * Chemin admis sous la racine (racine déjà résolue par realpath). Pour une
 * écriture, le fichier peut ne pas exister : son répertoire parent doit
 * exister et rester sous la racine, et un lien symbolique existant à sa place
 * est refusé.
 */
export function cheminAdmis(racine, demande, o = {}) {
  if (typeof demande !== "string" || demande === "" || demande.includes("\0")) throw new RefusOutil("chemin invalide");
  const brut = path.resolve(racine, demande);
  if (!dans(racine, brut)) throw new RefusOutil("chemin hors de la racine");
  if (o.ecriture) {
    let parent;
    try {
      parent = fs.realpathSync(path.dirname(brut));
    } catch {
      throw new RefusOutil("répertoire parent absent");
    }
    if (!dans(racine, parent)) throw new RefusOutil("chemin hors de la racine");
    const cible = path.join(parent, path.basename(brut));
    if (cible === racine) throw new RefusOutil("la racine n'est pas un fichier");
    let st = null;
    try {
      st = fs.lstatSync(cible);
    } catch {
      st = null;
    }
    if (st && !st.isFile()) throw new RefusOutil("la cible existe et n'est pas un fichier ordinaire");
    return cible;
  }
  let reel;
  try {
    reel = fs.realpathSync(brut);
  } catch {
    throw new RefusOutil("chemin absent");
  }
  if (!dans(racine, reel)) throw new RefusOutil("chemin hors de la racine");
  return reel;
}

/** Exécute un outil ; rend le texte du résultat ou lève RefusOutil. */
export function executerOutil(racine, nom, args) {
  if (args === null || typeof args !== "object" || Array.isArray(args)) throw new RefusOutil("arguments attendus en objet");
  if (nom === "list_directory") {
    const rep = cheminAdmis(racine, args.path);
    let entrees;
    try {
      entrees = fs.readdirSync(rep, { withFileTypes: true });
    } catch (e) {
      throw new RefusOutil(e.code === "ENOTDIR" ? "pas un répertoire" : `lecture impossible (${e.code ?? "erreur"})`);
    }
    return entrees
      .map((e) => `${e.isDirectory() ? "[DIR]" : e.isSymbolicLink() ? "[LINK]" : "[FILE]"} ${e.name}`)
      .sort()
      .join("\n");
  }
  if (nom === "read_file") {
    const f = cheminAdmis(racine, args.path);
    let st;
    try {
      st = fs.statSync(f);
    } catch (e) {
      throw new RefusOutil(`lecture impossible (${e.code ?? "erreur"})`);
    }
    if (!st.isFile()) throw new RefusOutil("pas un fichier ordinaire");
    if (st.size > OCTETS_MAX) throw new RefusOutil(`fichier de plus de ${OCTETS_MAX} octets`);
    const octets = fs.readFileSync(f);
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(octets);
    } catch {
      throw new RefusOutil("contenu non UTF-8");
    }
  }
  if (nom === "write_file") {
    if (typeof args.content !== "string") throw new RefusOutil("content : texte attendu");
    const octets = Buffer.from(args.content, "utf8");
    if (octets.length > OCTETS_MAX) throw new RefusOutil(`contenu de plus de ${OCTETS_MAX} octets`);
    const cible = cheminAdmis(racine, args.path, { ecriture: true });
    const temporaire = path.join(path.dirname(cible), `.${path.basename(cible)}.${process.pid}.${Date.now()}.partiel`);
    try {
      fs.writeFileSync(temporaire, octets, { flag: "wx", mode: 0o640 });
      fs.renameSync(temporaire, cible);
    } catch (e) {
      try {
        fs.unlinkSync(temporaire);
      } catch {
        // absent
      }
      throw new RefusOutil(`écriture impossible (${e.code ?? "erreur"})`);
    }
    return `${octets.length} octets écrits dans ${path.relative(racine, cible)}`;
  }
  return null;
}

/**
 * Traite un message ; rend la réponse (objet) ou null.
 * @param {string} racine racine résolue
 * @param {unknown} m
 */
export function traiterMessage(racine, m) {
  if (m === null || typeof m !== "object" || Array.isArray(m)) return { jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } };
  if (typeof m.method !== "string") return null;
  if (!Object.hasOwn(m, "id")) return null;
  const id = m.id;
  const ok = (result) => ({ jsonrpc: "2.0", id, result });
  const erreur = (code, message) => ({ jsonrpc: "2.0", id, error: { code, message } });
  switch (m.method) {
    case "initialize": {
      const demandee = m.params?.protocolVersion;
      return ok({
        protocolVersion: VERSIONS.includes(demandee) ? demandee : VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: NOM, version: VERSION },
      });
    }
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: OUTILS });
    case "tools/call": {
      const nom = m.params?.name;
      if (!OUTILS.some((o) => o.name === nom)) return erreur(-32602, `outil inconnu : ${String(nom)}`);
      try {
        const texte = executerOutil(racine, nom, m.params?.arguments ?? {});
        return ok({ content: [{ type: "text", text: texte }], isError: false });
      } catch (e) {
        if (!(e instanceof RefusOutil)) throw e;
        return ok({ content: [{ type: "text", text: e.message }], isError: true });
      }
    }
    default:
      return erreur(-32601, "Method not found");
  }
}

/** Point d'entrée : lit l'entrée standard ligne à ligne jusqu'à sa fin. */
export async function principal(argv, io = {}) {
  const entree = io.stdin ?? process.stdin;
  const sortie = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  if (argv.length !== 1 || !path.isAbsolute(argv[0])) {
    stderr.write("usage : serveur-fichiers <racine absolue>\n");
    return 2;
  }
  let racine;
  try {
    racine = fs.realpathSync(argv[0]);
    if (!fs.statSync(racine).isDirectory()) throw new Error("pas un répertoire");
  } catch (e) {
    stderr.write(`serveur-fichiers : racine ${argv[0]} inutilisable (${e.code ?? e.message})\n`);
    return 2;
  }
  const lignes = readline.createInterface({ input: entree, crlfDelay: Infinity });
  for await (const ligne of lignes) {
    if (ligne.trim() === "") continue;
    let m;
    try {
      m = JSON.parse(ligne);
    } catch {
      sortie.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } })}\n`);
      continue;
    }
    const r = traiterMessage(racine, m);
    if (r) sortie.write(`${JSON.stringify(r)}\n`);
  }
  return 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  principal(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e) => {
      process.stderr.write(`serveur-fichiers : ${e.stack ?? e.message}\n`);
      process.exit(1);
    },
  );
}
