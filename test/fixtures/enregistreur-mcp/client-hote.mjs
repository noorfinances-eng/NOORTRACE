// Client MCP de test qui joue l'hôte : il lance le connecteur stdio
// `noortrace-connecteur` (comme un hôte de 19.5.1) et lui parle en
// JSON-RPC, une ligne par message, sur son entrée et sa sortie standard.

import { spawn } from "node:child_process";
import path from "node:path";
import readline from "node:readline";
import { RACINE } from "../enregistreur-coeur/outils.mjs";

export const BIN_CONNECTEUR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace-connecteur");

/** Métadonnées d'une requête moderne (EX-4.4). */
export function metaModerne(extra = {}) {
  return {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": { name: "hote-test", version: "0.1.0" },
    ...extra,
  };
}

export class ClientHote {
  /**
   * @param {string[]} args arguments du connecteur
   * @param {NodeJS.ProcessEnv} [env]
   */
  constructor(args, env = process.env) {
    this.p = spawn(process.execPath, [BIN_CONNECTEUR, ...args], { stdio: ["pipe", "pipe", "pipe"], env });
    this.attentes = new Map();
    this.lignes = [];
    this.notifications = [];
    this.stderr = "";
    this.p.stderr.on("data", (c) => (this.stderr += c));
    readline.createInterface({ input: this.p.stdout, crlfDelay: Infinity }).on("line", (l) => {
      this.lignes.push(l);
      let m;
      try {
        m = JSON.parse(l);
      } catch {
        return;
      }
      if (m.method) {
        this.notifications.push(m);
        return;
      }
      const a = this.attentes.get(JSON.stringify(m.id));
      if (a) {
        this.attentes.delete(JSON.stringify(m.id));
        a(m);
      }
    });
    this.fin = new Promise((r) => this.p.on("exit", (code) => r(code)));
    this.n = 0;
  }

  /** Envoie une ligne brute. */
  envoyerLigne(l) {
    this.p.stdin.write(l + "\n");
  }

  /**
   * Requête JSON-RPC ; rend la réponse.
   * @param {string} methode
   * @param {object} params
   * @param {string|number} [id]
   */
  requete(methode, params, id) {
    const i = id ?? `h-${++this.n}`;
    const r = new Promise((res) => this.attentes.set(JSON.stringify(i), res));
    this.envoyerLigne(JSON.stringify({ jsonrpc: "2.0", id: i, method: methode, params }));
    return r;
  }

  /** Attend la réponse d'un id déjà envoyé. */
  reponse(id) {
    return new Promise((res) => this.attentes.set(JSON.stringify(id), res));
  }

  async fermer() {
    this.p.stdin.end();
    return this.fin;
  }
}
