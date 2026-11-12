// Interface d'exploitant pour les essais : construction par `next build`
// (sans réseau extérieur), fichier des comptes (scrypt), configuration, binaire
// `noortrace-inscription-web` lancé en processus séparé, et petit client HTTP
// qui joue le navigateur (cookie de session, en-tête Origin).

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { RACINE } from "./reseau-essai.mjs";

export const WEB = path.join(RACINE, "paquets", "inscription", "src", "web");
export const BIN_WEB = path.join(RACINE, "paquets", "inscription", "bin", "noortrace-inscription-web");
const NEXT = path.join(RACINE, "node_modules", "next", "dist", "bin", "next");

/** Construit l'interface (`next build` du répertoire src/web) ; rend `{ code, sortie }`. */
export function construire() {
  const b = spawnSync(process.execPath, [NEXT, "build", WEB], { cwd: RACINE, env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" }, encoding: "utf8", timeout: 600000 });
  return { code: b.status, sortie: `${b.stdout}\n${b.stderr}` };
}

/** Port TCP libre de la boucle locale. */
export const portLibre = () => new Promise((ok) => {
  const s = net.createServer();
  s.listen(0, "127.0.0.1", () => {
    const p = s.address().port;
    s.close(() => ok(p));
  });
});

/** Lance l'interface devant un agent ; rend `{ url, origine, processus, journal(), arreter(), client }`. */
export async function lancerInterface({ dir, prise, donnees, nom = "operateur-1", motDePasse = "mot de passe du compte d'essai", nature = "developpement" }) {
  const sel = crypto.randomBytes(16);
  const cle = crypto.scryptSync(Buffer.from(motDePasse, "utf8"), sel, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
  const comptes = path.join(dir, "comptes.json");
  fs.writeFileSync(comptes, JSON.stringify({ version: 0, accounts: [{ name: nom, salt: sel.toString("hex"), key: cle.toString("hex") }] }));
  const port = await portLibre();
  const origine = `http://127.0.0.1:${port}`;
  const config = path.join(dir, "interface.json");
  fs.writeFileSync(config, JSON.stringify({ version: 0, ecoute: { hote: "127.0.0.1", port }, origine, prise, donnees, comptes: `fichier:${comptes}`, nature }));
  let journal = "";
  const processus = spawn(process.execPath, [BIN_WEB, "--config", config], { cwd: RACINE, env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" }, stdio: ["ignore", "pipe", "pipe"] });
  const pret = await new Promise((ok, ko) => {
    processus.stdout.on("data", (d) => {
      journal += d;
      const ligne = journal.split("\n").find((l) => l.startsWith('{"pret"'));
      if (ligne) ok(JSON.parse(ligne));
    });
    processus.stderr.on("data", (d) => (journal += d));
    processus.on("exit", (c) => ko(new Error(`interface arrêtée (${c}) : ${journal}`)));
  });
  let cookie = null;
  const requete = async (chemin, { methode = "GET", corps } = {}) => {
    const h = {};
    if (cookie) h.cookie = cookie;
    if (methode !== "GET") h.origin = origine;
    if (corps !== undefined) h["content-type"] = "application/json";
    const r = await fetch(`${pret.url}${chemin}`, { method: methode, headers: h, body: corps === undefined ? undefined : JSON.stringify(corps), redirect: "manual" });
    const texte = await r.text();
    let json = null;
    try {
      json = JSON.parse(texte);
    } catch {
      json = null;
    }
    return { statut: r.status, entetes: r.headers, texte, json };
  };
  return {
    url: pret.url, origine, processus, journal: () => journal,
    requete,
    async connecter() {
      const r = await fetch(`${pret.url}/api/connexion`, { method: "POST", headers: { origin: origine, "content-type": "application/json" }, body: JSON.stringify({ name: nom, password: motDePasse }) });
      if (r.status !== 204) throw new Error(`connexion refusée : ${r.status}`);
      cookie = r.headers.get("set-cookie").split(";")[0];
    },
    /** Remet un travail par POST /api/travaux et attend sa fin ; rend l'enregistrement. */
    async travail(t) {
      const r = await requete("/api/travaux", { methode: "POST", corps: t });
      if (r.statut !== 200) return { refus: r.json };
      for (;;) {
        const s = await requete(`/api/travaux/${r.json.id}`);
        if (["fini", "refuse", "abandonne"].includes(s.json.etat)) return s.json;
        await new Promise((ok) => setTimeout(ok, 250));
      }
    },
    async arreter() {
      if (processus.exitCode !== null) return;
      const fin = new Promise((ok) => processus.once("exit", ok));
      processus.kill("SIGTERM");
      await fin;
    },
  };
}
