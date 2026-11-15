// Montage du harnais de mesure de CT-2 EX-16.2 : la configuration de mesure
// publiée, ses membres propres à une exécution (chemins et ports), et les
// quatre processus de la mesure, tous sur la même machine (EX-16.1) :
// l'enregistreur (`noortrace --config`), le service d'approbation de CT-3
// (tout appel d'outil passe par son `evaluer`, CT-2 EX-7.4), le serveur
// d'outils nul et le fournisseur de modèle simulé.
//
// La configuration publiée fixe ce qui se mesure (classe D, bail `file`,
// politique `pii-v1`, validation groupée 64 / 5 ms, outil de classe
// `ecriture` autorisé par une règle automatique, passerelle de modèle). Le
// harnais n'y remplace que les membres de `MEMBRES_REMPLACES` : répertoires
// (stockage, bail, journal d'exploitation, prise, clé) et adresses de la
// boucle locale. Le SHA-256 du rapport est celui des octets du fichier publié.

import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { RACINE, sha256Hex } from "./commun.mjs";

export const CONFIGURATION_PUBLIEE = path.join(RACINE, "spec", "vecteurs", "ct-2", "mesures", "configuration-mesure.json");
const ICI = path.join(RACINE, "scripts", "mesures");
const BIN_ENREGISTREUR = path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace");
const BIN_APPROBATION = path.join(RACINE, "paquets", "approbation", "bin", "noortrace-approbation");

/** Membres de la configuration publiée que le harnais remplace à chaque exécution (pointeurs JSON). */
export const MEMBRES_REMPLACES = Object.freeze([
  "/mcp/socket", "/mcp/http/listen", "/model/listen", "/signer/backend/path", "/storage/root", "/lease/store/path",
  "/supervision/health_listen", "/supervision/ops_log/path", "/policy/approval/service/url", "/policy/servers/nul/transport/url", "/policy/model/routes/0/upstream",
]);
/** Membres que les options du harnais remplacent (dits dans `conditions`) : mode observation, taille du segment. */
export const MEMBRES_D_OPTION = Object.freeze(["/policy/version", "/policy/approval/mode", "/storage/segment_max_bytes"]);

export const attendre = async (cond, delaiMs = 30000, pasMs = 20, quoi = "condition") => {
  const limite = Date.now() + delaiMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() > limite) throw new Error(`${quoi} non atteinte en ${delaiMs} ms`);
    await new Promise((r) => setTimeout(r, pasMs));
  }
};

export function portLibre() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

export function requeteJson({ port, chemin, methode = "GET", delaiMs = 5000 }) {
  return new Promise((res, rej) => {
    const r = http.request({ host: "127.0.0.1", port, path: chemin, method: methode, agent: false, timeout: delaiMs }, (x) => {
      const m = [];
      x.on("data", (k) => m.push(k));
      x.on("end", () => {
        try {
          res({ statut: x.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8") || "null") });
        } catch (e) {
          rej(e);
        }
      });
    });
    r.on("timeout", () => r.destroy(new Error("délai")));
    r.on("error", rej);
    r.end();
  });
}

/** Lit la configuration publiée ; rend { octets, sha256, config }. */
export function lireConfigurationPubliee(chemin = CONFIGURATION_PUBLIEE) {
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    throw new Error(`configuration de mesure introuvable : ${chemin} (CT-2 EX-16.2, pas 1 ; --configuration <fichier>)`);
  }
  return { octets, sha256: sha256Hex(octets), config: JSON.parse(octets.toString("utf8")) };
}

/** Lance un processus Node et attend sa première ligne JSON sur la sortie standard. */
function lancerService(programme, args, { env = {}, delaiMs = 30000 } = {}) {
  return new Promise((resoudre, rejeter) => {
    const proc = spawn(process.execPath, [programme, ...args], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
    let sortie = "";
    let erreurs = "";
    let pret = false;
    const fin = new Promise((ok) => proc.once("exit", (code, signal) => ok({ code, signal })));
    const minuteur = setTimeout(() => {
      if (!pret) {
        proc.kill("SIGKILL");
        rejeter(new Error(`${path.basename(programme)} : aucune ligne d'écoute en ${delaiMs} ms : ${erreurs.slice(-500)}`));
      }
    }, delaiMs);
    proc.stderr.on("data", (x) => (erreurs += x));
    proc.stdout.on("data", (x) => {
      if (pret) return;
      sortie += x;
      const l = sortie.split("\n").find((y) => y.startsWith("{") && y.endsWith("}"));
      if (!l) return;
      pret = true;
      clearTimeout(minuteur);
      resoudre({ proc, info: JSON.parse(l), fin, sortie: () => sortie + erreurs });
    });
    fin.then(({ code, signal }) => {
      clearTimeout(minuteur);
      if (!pret) rejeter(new Error(`${path.basename(programme)} arrêté (${code ?? signal}) : ${erreurs.slice(-1000)}`));
    });
  });
}

export async function arreter(s, delaiMs = 15000) {
  if (!s || !s.proc || s.proc.exitCode !== null || s.proc.signalCode !== null) return;
  s.proc.kill("SIGTERM");
  const t = setTimeout(() => s.proc.kill("SIGKILL"), delaiMs);
  await s.fin;
  clearTimeout(t);
}

/**
 * Monte la mesure sous `repertoire` (répertoire vide du disque à mesurer).
 * `options` : `observation` (mode observation, CT-2 EX-15.8), `segmentOctets`,
 * `resultatOctets`, `reponseOctets`, `intervalleMs`, `evenementsFlux`.
 * Rend l'objet du montage : ports, jetons, chemins, `demarrerEnregistreur`,
 * `arreterEnregistreur`, `fermer`.
 */
export async function monter({ repertoire, configuration = CONFIGURATION_PUBLIEE, options = {} }) {
  const publiee = lireConfigurationPubliee(configuration);
  fs.mkdirSync(repertoire, { recursive: true });
  if (fs.readdirSync(repertoire).length) throw new Error(`répertoire de mesure non vide : ${repertoire}`);
  // Une prise Unix a un chemin borné (108 octets) : elle vit sous un répertoire court du système, détruit à la fermeture.
  const prises = fs.mkdtempSync(path.join(os.tmpdir().length < 40 ? os.tmpdir() : "/tmp", "ntmes-"));
  const secret = () => randomBytes(32).toString("hex");
  const env = {
    NOORTRACE_MESURE_JETON_HOTE: secret(), NOORTRACE_MESURE_JETON_PASSERELLE: secret(), NOORTRACE_MESURE_CLE_MAC_RELAIS: secret(),
    NOORTRACE_MESURE_JETON_APPROBATION: secret(), NOORTRACE_MESURE_CLE_MODELE: secret(), NOORTRACE_MESURE_CLE_STOCKAGE_APPROBATION: `0x${secret()}`,
  };
  const m = { repertoire, prises, env, publiee, options, services: {}, enregistreur: null };
  const fermer = async () => {
    await arreter(m.enregistreur);
    for (const s of Object.values(m.services)) await arreter(s);
    fs.rmSync(prises, { recursive: true, force: true });
  };
  try {
    // Clé de classe D : Ed25519, PKCS#8 en PEM, éphémère, détruite avec le répertoire de mesure.
    const cle = path.join(repertoire, "cles", `${publiee.config.signer.key_id}.pem`);
    fs.mkdirSync(path.dirname(cle), { recursive: true, mode: 0o700 });
    fs.writeFileSync(cle, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

    m.services.outils = await lancerService(path.join(ICI, "serveur-nul.mjs"), ["servir", "--ecoute", "127.0.0.1:0", "--resultat-octets", String(options.resultatOctets ?? 16384)]);
    m.services.modele = await lancerService(path.join(ICI, "fournisseur-simule.mjs"), ["servir", "--ecoute", "127.0.0.1:0", "--reponse-octets", String(options.reponseOctets ?? 16384), "--intervalle-ms", String(options.intervalleMs ?? 50), "--evenements", String(options.evenementsFlux ?? 6)]);

    const c = structuredClone(publiee.config);
    const approbation = {
      version: 0, environment: c.recorder.environment, org: "campagne-de-mesure", org_id: c.recorder.org_id, journal_id: c.recorder.journal_id,
      state_dir: path.join(repertoire, "approbation"), storage_key: { env: "NOORTRACE_MESURE_CLE_STOCKAGE_APPROBATION" },
      noyau: { tcp: { host: "127.0.0.1", port: 0 }, token: { env: "NOORTRACE_MESURE_JETON_APPROBATION" } }, console: null,
      administrators: ["oidc https://idp.mesure.example admin-1"], console_origin: "https://console.mesure.example", rpc: null,
    };
    m.configurationApprobation = path.join(repertoire, "approbation.json");
    fs.writeFileSync(m.configurationApprobation, JSON.stringify(approbation, null, 2) + "\n");
    m.services.approbation = await lancerService(BIN_APPROBATION, ["--config", m.configurationApprobation], { env });

    c.mcp.socket = path.join(prises, "mcp.sock");
    c.signer.backend.path = cle;
    c.storage.root = path.join(repertoire, "stockage");
    c.lease.store.path = path.join(repertoire, "bail", "verrou");
    c.supervision.ops_log.path = path.join(repertoire, "journal", "exploitation.ndjson");
    c.policy.approval.service.url = `http://127.0.0.1:${m.services.approbation.info.noyau.port}`;
    c.policy.servers.nul.transport.url = `http://127.0.0.1:${m.services.outils.info.port}/mcp`;
    c.policy.model.routes[0].upstream = `http://127.0.0.1:${m.services.modele.info.port}`;
    if (options.observation) {
      c.policy.approval.mode = "observation";
      c.policy.version = `${c.policy.version}-observation`;
    }
    if (options.segmentOctets) c.storage.segment_max_bytes = options.segmentOctets;
    fs.mkdirSync(path.dirname(c.lease.store.path), { recursive: true });
    m.config = c;
    m.fichierConfiguration = path.join(repertoire, "configuration.json");
    m.journalExploitation = c.supervision.ops_log.path;
    m.repertoireJournal = path.join(c.storage.root, c.recorder.org_id.slice(2), c.recorder.journal_id.slice(2));
    m.jetonHote = env.NOORTRACE_MESURE_JETON_HOTE;
    m.jetonPasserelle = env.NOORTRACE_MESURE_JETON_PASSERELLE;
    m.portOutils = m.services.outils.info.port;
    m.portFournisseur = m.services.modele.info.port;
  } catch (e) {
    await fermer();
    throw e;
  }

  /** Lignes du journal d'exploitation (toutes, ou depuis un décalage en octets). */
  m.lignesExploitation = (depuis = 0) => {
    if (!fs.existsSync(m.journalExploitation)) return [];
    const t = fs.readFileSync(m.journalExploitation).subarray(depuis).toString("utf8");
    return t.split("\n").filter(Boolean).map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    }).filter(Boolean);
  };

  /**
   * Démarre l'enregistreur et attend qu'il serve (santé `ok`, frontal MCP et
   * passerelle à l'écoute). Rend { pid, lance_ns, ports }. Un port pris entre
   * son choix et son ouverture relance le démon sur d'autres ports (3 essais).
   */
  m.demarrerEnregistreur = async ({ delaiMs = 600000 } = {}) => {
    for (let essai = 1; ; essai++) {
      const [pMcp, pModele, pSante] = [await portLibre(), await portLibre(), await portLibre()];
      m.config.mcp.http.listen = `127.0.0.1:${pMcp}`;
      m.config.model.listen = `127.0.0.1:${pModele}`;
      m.config.supervision.health_listen = `127.0.0.1:${pSante}`;
      fs.writeFileSync(m.fichierConfiguration, JSON.stringify(m.config, null, 2) + "\n");
      const lance = process.hrtime.bigint();
      const proc = spawn(process.execPath, [BIN_ENREGISTREUR, "--config", m.fichierConfiguration], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
      let sortie = "";
      proc.stdout.on("data", (d) => (sortie += d));
      proc.stderr.on("data", (d) => (sortie += d));
      const fin = new Promise((ok) => proc.once("exit", (code, signal) => ok({ code, signal })));
      const e = { proc, fin, sortie: () => sortie, pid: proc.pid, lance_ns: lance, ports: { mcp: pMcp, modele: pModele, sante: pSante } };
      m.enregistreur = e;
      const vivant = (f) => async () => {
        if (proc.exitCode !== null || proc.signalCode !== null) throw new Error(`enregistreur arrêté (${proc.exitCode ?? proc.signalCode}) : ${sortie.slice(-2000)}`);
        return f();
      };
      const ecoute = (port) => new Promise((res) => {
        const s = net.connect({ host: "127.0.0.1", port }, () => {
          s.destroy();
          res(true);
        });
        s.on("error", () => res(false));
      });
      try {
        await attendre(vivant(async () => (await requeteJson({ port: pSante, chemin: "/healthz", delaiMs: 2000 }).catch(() => null))?.corps?.status === "ok"), delaiMs, 20, "santé de l'enregistreur");
        await attendre(vivant(() => ecoute(pMcp)), 30000, 20, "écoute du frontal MCP");
        await attendre(vivant(() => ecoute(pModele)), 30000, 20, "écoute de la passerelle de modèle");
        return e;
      } catch (err) {
        await fin.catch(() => {});
        if (essai < 3 && /EADDRINUSE/.test(sortie)) continue;
        proc.kill("SIGKILL");
        throw err;
      }
    }
  };
  m.arreterEnregistreur = async () => {
    await arreter(m.enregistreur);
    m.enregistreur = null;
  };
  m.fermer = fermer;
  return m;
}
