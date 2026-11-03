// Pilote du banc (`banc.mjs`) pour les essais mocha : lance le banc comme
// processus, lit sa ligne `{"pret": true, …}`, puis envoie ses commandes JSON
// une par ligne et attend chaque réponse. Utilisé par
// test/enregistreur-sdk-adaptateurs.test.js (adaptateurs JavaScript).

import path from "node:path";
import readline from "node:readline";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

export const BANC = path.join(path.dirname(fileURLToPath(import.meta.url)), "banc.mjs");

/**
 * Lance le banc et rend son pilote.
 * @returns {Promise<{info: object, commande: (m: object) => Promise<object>, evenements: () => Promise<object[]>, fermer: () => Promise<void>}>}
 */
export async function lancerBanc() {
  const p = spawn(process.execPath, [BANC], { stdio: ["pipe", "pipe", "inherit"] });
  const lignes = readline.createInterface({ input: p.stdout });
  const attente = [];
  const recues = [];
  lignes.on("line", (l) => {
    const a = attente.shift();
    if (a) a(l);
    else recues.push(l);
  });
  const suivante = () => (recues.length ? Promise.resolve(recues.shift()) : new Promise((r) => attente.push(r)));
  const info = JSON.parse(await suivante());
  if (!info.pret) throw new Error(`banc non pret : ${JSON.stringify(info)}`);
  let file = Promise.resolve();
  const commande = (m) => {
    const r = file.then(async () => {
      p.stdin.write(JSON.stringify(m) + "\n");
      const x = JSON.parse(await suivante());
      if (x.erreur) throw new Error(`banc : ${x.erreur}`);
      return x;
    });
    file = r.catch(() => {});
    return r;
  };
  return {
    info,
    commande,
    evenements: async () => (await commande({ cmd: "evenements" })).evenements,
    async fermer() {
      p.stdin.end();
      await new Promise((r) => (p.exitCode !== null ? r() : p.once("exit", r)));
    },
  };
}
