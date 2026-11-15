// Revue de sécurité interne de l'étape 8 : pont stdio et serveur de
// fichiers (conteneurs/pont-stdio/), CT-8 EX-3.7 (correction).
//
// - message glissé : le pont transmet à l'enfant le message analysé, resérialisé sur
//   une seule ligne ; un saut de ligne dans le corps ne glisse aucun second
//   message ;
// - CT-8 EX-3.7 : un identifiant abandonné par le client reste « en cours »
//   jusqu'à la réponse de l'enfant ou au délai : une seconde requête de même
//   identifiant reçoit 400, la réponse de la première est jetée, l'enfant
//   reçoit notifications/cancelled, et le minuteur de la première ne retire
//   pas l'attente d'une autre requête ;
// - CT-8 EX-3.7 : un initialize abandonné par le client ne laisse aucune session ;
//   --inactivite-ms clôt une session inactive ; /sante expose sessions_max ;
// - erreurs du serveur de fichiers : il rend -32602 pour un nom d'outil non
//   textuel, un refus d'outil pour une lecture impossible (EIO, EACCES), et
//   une erreur -32603 pour toute exception d'un message, sans se terminer.
// Aucun réseau hors 127.0.0.1 ; tout fichier va sous NOORTRACE_TMP (ou
// os.tmpdir()).

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { creerPont, analyserOptions, DEFAUTS } from "../conteneurs/pont-stdio/noortrace-pont-stdio.mjs";
import { executerOutil, traiterMessage } from "../conteneurs/pont-stdio/serveur-fichiers.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SERVEUR_FICHIERS = path.join(RACINE, "conteneurs", "pont-stdio", "serveur-fichiers.mjs");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const JETON = "jeton-d-essai-0123456789";
const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-pont-revue-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

/** Enfant d'essai : répond à initialize tout de suite, à « echo » après params.attente_ms ; consigne chaque ligne reçue dans le fichier argv[2]. */
const ENFANT = `import readline from "node:readline";
import fs from "node:fs";
const journal = process.argv[2];
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (l) => {
  fs.appendFileSync(journal, l + "\\n");
  let m; try { m = JSON.parse(l); } catch { return; }
  if (!("id" in m)) return;
  const d = m.params?.attente_ms ?? 0;
  setTimeout(() => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { marque: m.params?.marque ?? m.method } }) + "\\n"), d);
});
`;

function requete(port, { method = "POST", chemin = "/mcp", corps, entetes = {}, abandonApresMs = null }) {
  return new Promise((res) => {
    const req = http.request({ host: "127.0.0.1", port, path: chemin, method, agent: false, headers: { authorization: `Bearer ${JETON}`, "content-type": "application/json", ...(corps !== undefined ? { "content-length": Buffer.byteLength(corps) } : {}), ...entetes } }, (r) => {
      const m = [];
      r.on("data", (c) => m.push(c));
      r.on("end", () => res({ statut: r.statusCode, entetes: r.headers, corps: Buffer.concat(m).toString() }));
    });
    req.on("error", (e) => res({ erreur: e.code }));
    if (corps !== undefined) req.write(corps);
    req.end();
    if (abandonApresMs !== null) setTimeout(() => req.destroy(), abandonApresMs);
  });
}
const init = (id, extra = {}) => JSON.stringify({ jsonrpc: "2.0", id, method: "initialize", params: { protocolVersion: "2025-06-18", ...extra } });

/** Pont sur un port libre, journal du pont capturé. */
async function pont(nom, commande, options = {}) {
  const lignes = [];
  const journal = new Writable({ write(c, _e, cb) { lignes.push(c.toString()); cb(); } });
  const p = creerPont({ ecoute: { hote: "127.0.0.1", port: 0 }, jeton: JETON, chemin: "/mcp", sessionsMax: 2, delaiMs: 1500, octetsMax: 1 << 20, inactiviteMs: 0, commande, ...options }, { journal });
  const { port } = await p.ecouter();
  return { p, port, lignes, evenements: () => lignes.map((l) => JSON.parse(l).evenement) };
}

describe("Revue de sécurité de l'étape 8, pont stdio (CT-8 EX-3.7)", function () {
  this.timeout(30000);
  let enfant;
  let journalEnfant;
  before(function () {
    enfant = path.join(TRAVAIL, "enfant.mjs");
    fs.writeFileSync(enfant, ENFANT);
    journalEnfant = path.join(TRAVAIL, "enfant.log");
  });

  it("CT-8 EX-3.7 : un corps « ping » qui porte, entre deux sauts de ligne, un tools/call write_file complet est transmis resérialisé sur une seule ligne : 200 pour ping, aucun fichier écrit, aucune ligne invalide ni réponse sans attente au journal du pont", async function () {
    const racine = path.join(TRAVAIL, "racine-fichiers");
    fs.mkdirSync(racine, { recursive: true });
    const { p, port, evenements } = await pont("fichiers", [process.execPath, SERVEUR_FICHIERS, racine]);
    try {
      const sid = (await requete(port, { corps: init("i") })).entetes["mcp-session-id"];
      expect(sid).to.match(/^[0-9a-f]{32}$/);
      const cache = { jsonrpc: "2.0", id: "cache", method: "tools/call", params: { name: "write_file", arguments: { path: "contrebande.txt", content: "ecrit sans requete relayee" } } };
      const corps = `{"jsonrpc":"2.0","id":"a","method":"ping","params":\n${JSON.stringify(cache)}\n}`;
      JSON.parse(corps);
      const r = await requete(port, { corps, entetes: { "mcp-session-id": sid } });
      expect(r.statut).to.equal(200);
      expect(JSON.parse(r.corps)).to.deep.equal({ jsonrpc: "2.0", id: "a", result: {} });
      expect(fs.existsSync(path.join(racine, "contrebande.txt")), "fichier écrit par le message caché").to.equal(false);
      expect(evenements().filter((e) => e === "ligne_invalide" || e === "reponse_sans_attente")).to.deep.equal([]);
    } finally {
      await p.fermer();
    }
  });

  it("CT-8 EX-3.7 : requête id 1 abandonnée par le client, puis requête id 1 sur la même session : 400 « identifiant déjà en cours » ; la réponse de la première est jetée (reponse_abandonnee) ; l'enfant a reçu notifications/cancelled ; après la réponse de l'enfant, un nouvel id 1 est servi ; le minuteur de la première ne retire pas l'attente de la suivante", async function () {
    fs.writeFileSync(journalEnfant, "");
    const { p, port, evenements } = await pont("delai", [process.execPath, enfant, journalEnfant], { delaiMs: 600 });
    try {
      const sid = (await requete(port, { corps: init("i") })).entetes["mcp-session-id"];
      const echo = (marque, attente_ms) => JSON.stringify({ jsonrpc: "2.0", id: 1, method: "echo", params: { marque, attente_ms } });
      await requete(port, { corps: echo("PREMIERE", 300), entetes: { "mcp-session-id": sid }, abandonApresMs: 50 });
      const seconde = await requete(port, { corps: echo("SECONDE", 10), entetes: { "mcp-session-id": sid } });
      expect(seconde.statut).to.equal(400);
      expect(JSON.parse(seconde.corps).error.message).to.equal("identifiant déjà en cours");
      await attendre(400);
      expect(evenements()).to.include("reponse_abandonnee");
      const recu = fs.readFileSync(journalEnfant, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      expect(recu.some((m) => m.method === "notifications/cancelled" && m.params.requestId === 1), JSON.stringify(recu)).to.equal(true);
      // L'identifiant est libre après la réponse de l'enfant : la requête suivante est servie, et le minuteur
      // de la première (600 ms) ne retire pas son attente.
      const troisieme = await requete(port, { corps: echo("TROISIEME", 450), entetes: { "mcp-session-id": sid } });
      expect(troisieme.statut).to.equal(200);
      expect(JSON.parse(troisieme.corps).result.marque).to.equal("TROISIEME");
    } finally {
      await p.fermer();
    }
  });

  it("CT-8 EX-3.7 : deux initialize abandonnés par le client (sessions-max 2) ne laissent aucune session (session_abandonnee) et l'initialize suivant est servi ; --inactivite-ms 300 clôt une session sans message (session_inactive) ; /sante expose sessions et sessions_max ; option hors bornes refusée", async function () {
    fs.writeFileSync(journalEnfant, "");
    const { p, port, evenements } = await pont("inactivite", [process.execPath, enfant, journalEnfant], { inactiviteMs: 300, delaiMs: 60000 });
    try {
      const sante = async () => JSON.parse((await requete(port, { method: "GET", chemin: "/sante" })).corps);
      await requete(port, { corps: init("x1", { attente_ms: 300 }), abandonApresMs: 50 });
      await requete(port, { corps: init("x2", { attente_ms: 300 }), abandonApresMs: 50 });
      await attendre(600);
      expect((await sante()).sessions, "sessions orphelines").to.equal(0);
      expect(evenements().filter((e) => e === "session_abandonnee")).to.have.length(2);
      const r = await requete(port, { corps: init("x3") });
      expect(r.statut).to.equal(200);
      expect(await sante()).to.include({ status: "ok", sessions: 1, sessions_max: 2 });
      await attendre(700);
      expect((await sante()).sessions, "session inactive close").to.equal(0);
      expect(evenements()).to.include("session_inactive");
      expect(DEFAUTS.inactiviteMs).to.equal(0);
      expect(analyserOptions(["--ecoute", "127.0.0.1:0", "--jeton", "/x", "--inactivite-ms", "250", "--", "/bin/true"]).inactiviteMs).to.equal(250);
      expect(() => analyserOptions(["--ecoute", "127.0.0.1:0", "--jeton", "/x", "--inactivite-ms", "86400001", "--", "/bin/true"])).to.throw(/--inactivite-ms/);
    } finally {
      await p.fermer();
    }
  });
});

describe("Revue de sécurité de l'étape 8, serveur de fichiers du pont", function () {
  this.timeout(30000);

  it("tools/call avec params.name = {toString: 1} rend -32602 sans conversion ; read_file sur un fichier que statSync accepte mais que la lecture refuse (EIO sur /proc/self/mem) rend un refus d'outil « lecture impossible » ; le processus continue de répondre après ces deux messages et après une exception interne (-32603)", async function () {
    const r = traiterMessage("/", { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: { toString: 1 }, arguments: {} } });
    expect(r).to.deep.equal({ jsonrpc: "2.0", id: 7, error: { code: -32602, message: "outil inconnu : nom non textuel" } });
    const proc = fs.realpathSync("/proc/self");
    let refus = null;
    try {
      executerOutil(proc, "read_file", { path: "mem" });
    } catch (e) {
      refus = e;
    }
    expect(refus, "refus d'outil attendu").to.not.equal(null);
    expect(refus.constructor.name).to.equal("RefusOutil");
    expect(refus.message).to.match(/^lecture impossible \(E[A-Z]+\)$/);
    // Processus réel : un message qui lève, puis un ping encore servi.
    const racine = path.join(TRAVAIL, "racine-liens");
    fs.mkdirSync(racine, { recursive: true });
    const s = spawn(process.execPath, [SERVEUR_FICHIERS, racine], { stdio: ["pipe", "pipe", "pipe"] });
    const sorties = [];
    const erreurs = [];
    s.stdout.on("data", (d) => sorties.push(d.toString()));
    s.stderr.on("data", (d) => erreurs.push(d.toString()));
    const fini = new Promise((res) => s.once("exit", (code) => res(code)));
    s.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: { toString: 1 } } })}\n`);
    // Objet à prototype nul en params : m.params?.name lit sans lever ; arguments non objet : refus ; puis un ping.
    s.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "read_file", arguments: [] } })}\n`);
    s.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping" })}\n`);
    await attendre(800);
    expect(s.exitCode, `serveur terminé : ${erreurs.join("")}`).to.equal(null);
    const reponses = sorties.join("").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    expect(reponses.map((x) => x.id)).to.deep.equal([1, 2, 3]);
    expect(reponses[0].error.code).to.equal(-32602);
    expect(reponses[1].result.isError).to.equal(true);
    expect(reponses[2]).to.deep.equal({ jsonrpc: "2.0", id: 3, result: {} });
    s.stdin.end();
    expect(await fini).to.equal(0);
  });
});
