// Les huit intégrations de la porte 2 (CT-9 EX-8.2) : TI-4 Anthropic, TI-5
// OpenAI, TI-6 Gemini, TI-7 LangChain et LangGraph, TI-8 CrewAI, TI-9
// LlamaIndex, TI-10 LiteLLM, TI-11 OpenTelemetry. Chaque scénario est celui de
// CT-2 §19.2 (lecture, écriture approuvée, échanges de modèle dont un en
// flux), joué par le SDK ou le cadre à la version épinglée par CT-2 §6.4,
// contre le démon réel lancé avec la configuration de démonstration de §19.1
// et les simulateurs (jamais une interface réelle de fournisseur, jamais une
// clé réelle : test/fixtures/integrations/banc.mjs), puis clos par la commande
// d'exploitation `noortrace-ctl close-period --now`, le dossier de chaque appel
// et de chaque échange exporté par `noortrace-ctl dossier exporter` et vérifié
// sans réseau (`unshare -rn`) par les deux vérificateurs de CT-6 (JavaScript de
// référence et binaire Go). Les connexions sortantes de l'hôte sont relevées
// par `strace -f -e trace=connect` : seul l'enregistreur est joint.
//
// Un environnement absent (interpréteur d'un cadre, SDK JavaScript non
// installé à sa version exacte, strace, binaire Go) met l'essai en attente avec
// sa condition nommée (CT-9 EX-3.11) ; jamais une réussite factice. Le travail
// `integrations` de l'intégration continue les fournit (les deux SDK
// JavaScript à version exacte, hors de package.json : CT-2 19.5.7) ; le
// travail `tests` ne les fournit pas.

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import zlib from "node:zlib";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { jcsIntegral } from "@noortrace/enregistreur";
import { lancerBanc, lancerAgent, interpreteur, executable, straceDisponible, adresseDe, attendre, AGENTS, PREPARER, PREPARER_ADAPTATEURS, RACINE } from "./fixtures/integrations/outils.mjs";
import { CLE_MODELE, CLE_FOURNISSEUR_MANDATAIRE, JETON_PASSERELLE, binaireGo, unshareDisponible } from "./fixtures/integrations/banc.mjs";
import { lot, spanOutil, encoderProtobuf } from "./fixtures/enregistreur-otel/lots.mjs";

const sha16 = (v) => createHash("sha256").update(v, "utf8").digest("hex").slice(0, 16);
const utf8 = (o) => {
  const r = jcsIntegral(o);
  return typeof r === "string" ? r : new TextDecoder().decode(r);
};
/** Les trois valeurs fictives que la politique pii-v1 de la démonstration rédige, et leurs jetons. */
const REDACTION = [
  ["CH93 0076 2011 6238 5295 7", "[REDIGE:iban]"],
  ["j.dupont@assure.example", "[REDIGE:email]"],
  ["+41 44 123 45 67", "[REDIGE:telephone]"],
];
const rediger = (t) => REDACTION.reduce((s, [v, j]) => s.split(v).join(j), t);
const APPROBATEURS_DEMO = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"];
/**
 * Émissions de chaque appel : une pour une lecture ou un outil local ; au moins deux pour l'écriture soumise à
 * approbation (redemandée après le signal `en_attente` ; leur nombre dépend du moment où l'approbateur décide).
 */
function emissionsAttendues(trace) {
  const vues = trace.appels.map((a) => [a.outil, a.emissions]);
  for (const a of trace.appels) {
    if (outilDuJournal(a.outil) === "demo__payments.create") expect(a.emissions, `émissions de ${a.outil} : ${JSON.stringify(vues)}`).to.be.at.least(2);
    else expect(a.emissions, `émissions de ${a.outil} : ${JSON.stringify(vues)}`).to.equal(1);
  }
}

/** Nom d'outil du journal pour un nom vu dans un cadre (annoncé, assaini ou préfixé par le cadre). */
function outilDuJournal(nom) {
  if (/claims[._]get$/.test(nom)) return "demo__claims.get";
  if (/payments[._]create$/.test(nom)) return "demo__payments.create";
  if (/calculer_franchise$/.test(nom)) return "agent-py__calculer_franchise";
  return nom;
}

/**
 * Un module JavaScript tel que l'agent le charge (`charger` de
 * agents/anthropic_agent.mjs) : résolu depuis le dépôt, où le travail
 * `integrations` l'installe hors de package.json (`npm install --no-save`, la
 * résolution de Node ne lit pas les dépendances déclarées), sinon depuis
 * NOORTRACE_MODULES_INTEGRATION ; { chemin, version } (version lue dans le
 * package.json du paquet), ou null s'il est absent.
 */
function moduleJs(nom) {
  for (const base of [path.join(RACINE, "package.json"), process.env.NOORTRACE_MODULES_INTEGRATION ? path.join(process.env.NOORTRACE_MODULES_INTEGRATION, "package.json") : null].filter(Boolean)) {
    let chemin;
    try {
      chemin = createRequire(base).resolve(nom);
    } catch {
      continue; // absent de ce répertoire
    }
    let d = path.dirname(chemin);
    for (let k = 0; k < 8; k++, d = path.dirname(d)) {
      try {
        const pj = JSON.parse(fs.readFileSync(path.join(d, "package.json"), "utf8"));
        if (pj.name === nom) return { chemin, version: pj.version };
      } catch {
        // pas de package.json à ce niveau
      }
    }
    return { chemin, version: null };
  }
  return null;
}

/** Condition d'un SDK JavaScript : null s'il est installé à la version exacte attendue. */
function conditionSdk(nom, version) {
  const m = moduleJs(nom);
  if (m && m.version === version) return null;
  return `SDK ${nom} ${version} non installé (${m ? `version ${m.version} trouvée` : "absent"} ; installé à cette version, hors de package.json, par le travail integrations de l'intégration continue : npm install --no-save ; ou NOORTRACE_MODULES_INTEGRATION)`;
}

function enAttente(ctx, condition) {
  ctx.test.title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Conditions communes à tous les scénarios : strace, binaire Go, unshare. */
function conditionCommune() {
  if (!straceDisponible()) return "strace absent (relevé des connexions sortantes de l'hôte ; installé par le travail integrations)";
  if (!binaireGo()) return "binaire noortrace-verifier absent (NOORTRACE_VERIFIER_BIN, ou verificateur/dist/noortrace-verifier-linux-amd64 ; construit par le travail integrations)";
  if (!unshareDisponible()) return "unshare -rn indisponible (vérification sans réseau)";
  return null;
}

function envAgent(i, extra = {}) {
  return {
    NOORTRACE_MCP_URL: i.mcp_url,
    NOORTRACE_MCP_TOKEN: i.mcp_jeton,
    NOORTRACE_GATEWAY_URL: i.passerelle_url,
    NOORTRACE_GATEWAY_TOKEN: i.passerelle_jeton,
    NOORTRACE_RUN_ID: "run-integration-0001",
    NOORTRACE_SDK_SOCKET: i.socket_sdk,
    NOORTRACE_OTEL_URL: i.otel_url,
    NOORTRACE_OTEL_TOKEN: i.otel_jeton,
    NOORTRACE_MANDATAIRE_URL: i.mandataire_url ?? "",
    NOORTRACE_MANDATAIRE_CLE: i.mandataire_cle ?? "",
    ...extra,
  };
}

const PYTHON = (env) => interpreteur(env);
const agent = (nom) => path.join(AGENTS, nom);

/** Lit les événements jusqu'à en avoir au moins `n` (les événements d'échange sont scellés après le relais de la réponse). */
async function evenementsAuMoins(banc, n, ms = 20000) {
  const e = await attendre(async () => {
    const x = await banc.evenements();
    return x.length >= n ? x : null;
  }, ms);
  return e ?? banc.evenements();
}

/**
 * Oracles communs de TI-4 à TI-10 sur un scénario joué : un événement par
 * appel et par échange, pièces égales (après rédaction) à ce que l'hôte a vu,
 * approbation par les comptes 1 et 2, clé du fournisseur jamais celle de
 * l'hôte, connexions sortantes bornées à l'enregistreur ; puis clôture,
 * export et vérification de chaque dossier par les deux vérificateurs.
 */
async function verifierScenario(banc, r, o) {
  const i = banc.info;
  expect(r.erreur, "lancement de l'agent").to.equal(null);
  expect(r.code, `agent (code ${r.code}, signal ${r.signal}) :\n${r.stderr.slice(-3000)}\n${r.stdout.slice(-1500)}`).to.equal(0);
  expect(r.trace, "trace de l'agent (ligne noortrace-agent)").to.be.an("object");
  const trace = r.trace;
  const appels = trace.appels.map((a) => ({ ...a, journal: outilDuJournal(a.outil) }));
  expect(appels.map((a) => a.journal), "appels d'outils du scénario").to.include.members(["demo__claims.get", "demo__payments.create"]);
  if (o.local) expect(appels.map((a) => a.journal)).to.include("agent-py__calculer_franchise");
  // Nombre d'événements attendu : un par échange (requêtes reçues par les simulateurs), un par appel de lecture
  // ou local, trois par écriture approuvée (retenue, décision, exécution), plus l'événement de politique.
  const usage = await banc.commande({ cmd: "usage" });
  const echanges = [...usage.modele_demo, ...usage.formats].reduce((s, u) => s + u.requests, 0);
  const ecritures = appels.filter((a) => a.journal === "demo__payments.create").length;
  const attendu = 1 + echanges + (appels.length - ecritures) + 3 * ecritures;
  const evts = await evenementsAuMoins(banc, attendu);
  expect(evts.length, `événements : ${evts.map((e) => `${e.seq} ${e.execution.tool} ${e.execution.status}`).join(" ; ")}`).to.equal(attendu);
  expect(evts[0].execution.tool).to.equal("noortrace.journal.politique");
  const parOutil = (n) => evts.filter((e) => e.execution.tool === n);
  // Échanges : un événement par requête vue par le simulateur, journalisés par la passerelle (context vide), libellé de la route.
  const ech = parOutil("noortrace.modele.echange");
  expect(ech.length).to.equal(echanges);
  for (const e of ech) {
    expect(e.context).to.deep.equal([]);
    expect(e.code.model, `code.model de seq ${e.seq}`).to.match(o.modele);
    expect(e.execution.status).to.equal("executee");
    expect(e.execution.is_error).to.equal(false);
  }
  // Appels : lecture autorisée, exécutée ; écriture retenue, décidée, exécutée ; outil local déclaré par le SDK.
  const lectures = parOutil("demo__claims.get");
  expect(lectures.length).to.equal(appels.filter((a) => a.journal === "demo__claims.get").length);
  for (const e of lectures) {
    expect(e.policy.decision).to.equal("autorise");
    expect(e.execution.status).to.equal("executee");
    expect(e.execution.is_error).to.equal(false);
  }
  const paiements = parOutil("demo__payments.create");
  expect(paiements.filter((e) => e.execution.status === "retenue").length).to.equal(ecritures);
  expect(paiements.filter((e) => e.execution.status === "executee").length).to.equal(ecritures);
  for (const e of paiements) expect(e.policy.decision).to.equal("a_approuver");
  const decisions = parOutil("noortrace.approbation.decision");
  expect(decisions.length).to.equal(ecritures);
  for (const e of decisions) {
    const d = e.execution.arguments.value;
    expect(d.decision).to.equal("approuve");
    expect(d.ticket).to.match(/^apr-test-\d{4}$/);
  }
  for (const e of paiements.filter((x) => x.execution.status === "executee")) {
    expect(e.approval, `approbation de seq ${e.seq}`).to.be.an("object");
    expect(e.approval.decision).to.equal("approuve");
    expect(e.approval.threshold).to.deep.equal({ required: 2, size: 3 });
    expect([...e.approval.approvers].sort()).to.deep.equal([...APPROBATEURS_DEMO].sort());
  }
  const locaux = parOutil("agent-py__calculer_franchise");
  expect(locaux.length).to.equal(appels.filter((a) => a.journal === "agent-py__calculer_franchise").length);
  for (const e of locaux) {
    expect(e.policy.decision).to.equal("autorise");
    expect(e.execution.status).to.equal("executee");
  }
  // Aucun outil MCP déclaré deux fois (EX-6.17, EX-19.5) : aucun événement agent-py__demo__… ni autre nom.
  const noms = new Set(evts.map((e) => e.execution.tool));
  for (const n of noms) expect(["noortrace.journal.politique", "noortrace.modele.echange", "noortrace.approbation.decision", "demo__claims.get", "demo__payments.create", "agent-py__calculer_franchise"], `outil inattendu ${n}`).to.include(n);
  // Les approbateurs : le service a décidé chaque ticket ouvert, par les comptes 1 et 2.
  const ap = await banc.commande({ cmd: "approbations" });
  expect(ap.decides.length).to.equal(ecritures);
  for (const d of ap.decides) expect(d.approvers).to.deep.equal([0, 1]);
  const tickets = appels.filter((a) => a.journal === "demo__payments.create").flatMap((a) => a.tickets);
  if (tickets.length) expect(ap.decides.map((d) => d.ticket)).to.include.members([...new Set(tickets)]);
  // Pièces égales aux octets vus par l'hôte (après rédaction, EX-8.2 : JCS intégral de la valeur) : arguments
  // de chaque appel ; résultat de chaque appel exécuté.
  const shas = evts.flatMap((e) => [e.execution.arguments?.sha256, e.execution.result?.sha256]).filter(Boolean);
  const pieces = (await banc.commande({ cmd: "pieces", sha256: shas })).pieces;
  // Appariement dans l'ordre : le k-ième appel d'un outil est le k-ième événement exécuté de cet outil.
  const files = {};
  for (const e of evts.filter((x) => x.execution.status === "executee" && !x.execution.tool.startsWith("noortrace."))) (files[e.execution.tool] ??= []).push(e);
  for (const a of appels) {
    const argsAttendus = rediger(utf8(a.arguments));
    const retenus = evts.filter((e) => e.execution.tool === a.journal && e.execution.status === "retenue" && pieces[e.execution.arguments.sha256] === argsAttendus);
    if (a.journal === "demo__payments.create") expect(retenus.length, `événement retenu de ${a.journal}`).to.be.greaterThan(0);
    const e = (files[a.journal] ?? []).shift();
    expect(e, `appel exécuté de ${a.journal}`).to.be.an("object");
    expect(pieces[e.execution.arguments.sha256], `pièce « arguments » de seq ${e.seq}`).to.equal(argsAttendus);
    const piece = pieces[e.execution.result.sha256];
    expect(piece, `pièce « résultat » de seq ${e.seq}`).to.be.a("string");
    if (a.journal === "agent-py__calculer_franchise") {
      expect(JSON.parse(piece)).to.equal(a.resultat);
      continue;
    }
    const res = JSON.parse(piece);
    expect(res.isError).to.equal(a.is_error);
    expect(res.content[0].type).to.equal("text");
    if (o.resultatsExacts) {
      const attenduRes = { content: [{ text: a.resultat, type: "text" }], isError: a.is_error, resultType: "complete", ...(a.structured ? { structuredContent: a.structured } : {}) };
      expect(piece, `pièce « résultat » de seq ${e.seq}`).to.equal(rediger(utf8(attenduRes)));
    } else {
      expect(rediger(a.resultat), `résultat vu par l'hôte pour seq ${e.seq}`).to.include(res.content[0].text);
    }
  }
  for (const [n, reste] of Object.entries(files)) expect(reste.length, `événements exécutés de ${n} sans appel de l'hôte`).to.equal(0);
  // Le fournisseur n'a vu que la clé de la route, jamais le jeton de l'hôte (CT-2 §19.5.2) ; aucune clé réelle.
  // (derrière un mandataire LiteLLM, c'est la clé que le mandataire présente au fournisseur.)
  for (const u of [...usage.modele_demo, ...usage.formats]) {
    expect(u.key_sha256_16).to.equal(sha16(o.cleFournisseur ?? CLE_MODELE));
    expect(u.key_sha256_16).to.not.equal(sha16(JETON_PASSERELLE));
  }
  // Connexions sortantes de l'hôte : le frontal MCP et la passerelle, et rien d'autre.
  const admises = new Set([adresseDe(i.mcp_url), adresseDe(i.passerelle_url), ...(o.admises ?? [])]);
  expect(r.connexions, "connexions sortantes relevées par strace").to.not.be.empty;
  for (const c of r.connexions) expect([...admises], `connexion hors de l'enregistreur : ${c}`).to.include(c);
  expect(r.connexions).to.include(adresseDe(i.mcp_url));
  // Clôture par la commande d'exploitation, export et vérification de chaque dossier.
  await cloreEtVerifier(banc, evts);
  return { evts, trace, pieces };
}

async function cloreEtVerifier(banc, evts) {
  const c = await banc.commande({ cmd: "cloturer" });
  expect(c.code, `close-period : ${c.stderr}`).to.equal(0);
  expect(c.ligne?.event).to.equal("period_closed_early");
  let verifies = 0;
  for (const e of evts.filter((x) => x.seq >= 2)) {
    const x = await banc.commande({ cmd: "exporter", seq: e.seq });
    expect(x.code, `dossier exporter --seq ${e.seq} : ${x.stderr}`).to.equal(0);
    expect(x.ligne?.event).to.equal("dossier_exported");
    expect(fs.existsSync(path.join(x.destination, "dossier.json"))).to.equal(true);
    const v = await banc.commande({ cmd: "verifier", dossier: x.destination });
    for (const [nom, rap] of [["JavaScript", v.js], ["Go", v.go]]) {
      expect(rap, `vérificateur ${nom}`).to.be.an("object");
      expect(rap.sans_reseau, `${nom} sans réseau`).to.equal(true);
      expect(rap.code, `${nom} seq ${e.seq} : ${rap.stderr}`).to.equal(0);
      expect(rap.rapport?.verdict, `${nom} seq ${e.seq}`).to.equal("valide");
      const statuts = Object.fromEntries((rap.rapport.controls ?? []).map((k) => [k.number, k.status]));
      // Contrôles 1 à 3 (forme, chaîne, manifeste) réussis pour tout événement ; 4 et 5 (date, Bitcoin) non exécutés
      // (démonstration hors ligne, aucune ancre) ; 6 à 8 réussis ou sans objet selon l'événement, jamais en échec ;
      // 7 (approbation) réussi pour l'écriture approuvée.
      for (const k of [1, 2, 3]) expect(statuts[k], `${nom} seq ${e.seq} contrôle ${k}`).to.equal("reussi");
      for (const k of [4, 5]) expect(statuts[k], `${nom} seq ${e.seq} contrôle ${k}`).to.equal("non_execute");
      for (const k of [6, 7, 8]) expect(["reussi", "non_execute"], `${nom} seq ${e.seq} contrôle ${k} : ${statuts[k]}`).to.include(statuts[k]);
      if (e.execution.tool === "demo__payments.create" && e.execution.status === "executee") expect(statuts[7], `${nom} seq ${e.seq} contrôle 7`).to.equal("reussi");
    }
    verifies++;
  }
  expect(verifies).to.equal(evts.length - 1);
  return verifies;
}

/** Joue un scénario : banc, agent sous strace, oracles communs ; rend ce que les oracles ont lu. */
async function jouer(o) {
  const banc = await lancerBanc(o.envBanc ?? {});
  try {
    const i = banc.info;
    const r = lancerAgent({ commande: o.commande(i), env: envAgent(i, o.env?.(i) ?? {}), fichierTrace: path.join(i.dir, `strace-${o.nom}.txt`), delaiMs: o.delaiMs ?? 300000 });
    const resultat = await verifierScenario(banc, r, { modele: o.modele, local: o.local ?? false, resultatsExacts: o.resultatsExacts ?? false, admises: o.admises?.(i) ?? [], cleFournisseur: o.cleFournisseur });
    return { ...resultat, r, info: i, banc };
  } finally {
    await banc.fermer();
  }
}

/** Requête HTTP brute (en-têtes libres) ; rend { statut, entetes, corps, json }. */
function requete(url, { methode = "POST", entetes = {}, corps = null } = {}) {
  const u = new URL(url);
  const octets = corps === null ? null : Buffer.isBuffer(corps) || corps instanceof Uint8Array ? Buffer.from(corps) : Buffer.from(typeof corps === "string" ? corps : JSON.stringify(corps));
  return new Promise((resoudre, rejeter) => {
    const req = http.request({ host: u.hostname, port: u.port, path: `${u.pathname}${u.search}`, method: methode, headers: { ...(octets ? { "content-length": String(octets.length) } : {}), ...entetes } }, (res) => {
      const m = [];
      res.on("data", (x) => m.push(x));
      res.on("end", () => {
        const b = Buffer.concat(m);
        let json = null;
        try {
          json = JSON.parse(b.toString("utf8"));
        } catch {
          json = null;
        }
        resoudre({ statut: res.statusCode, entetes: res.headers, corps: b, json });
      });
    });
    req.on("error", rejeter);
    req.end(octets ?? undefined);
  });
}

describe("CT-9 TI-4 à TI-11 : les huit intégrations de la porte 2 (EX-8.2), scénario de CT-2 §19.2 contre les simulateurs, configuration de démonstration de §19.1", function () {
  this.timeout(900000);
  const commune = conditionCommune();

  // ------------------------------------------------------------------ TI-4
  describe("TI-4 — Intégration Anthropic : SDK officiel avec ANTHROPIC_BASE_URL vers la passerelle (hors flux et flux)", function () {
    const python = PYTHON("integration-anthropic");
    const condition = commune ?? (python ? null : `environnement integration-anthropic absent (anthropic 2.3.0 ; ${PREPARER} anthropic)`);

    it("TI-4 : SDK anthropic 2.3.0 (Python) par ANTHROPIC_BASE_URL, jeton de l'hôte en X-Noortrace-Token, client MCP de référence : scénario de §19.2 (échange hors flux, lecture, échange en flux SSE, écriture retenue puis approuvée par les comptes 1 et 2, échange de clôture) ; un événement par appel et par échange, pièces égales aux octets vus par l'hôte après rédaction, clé de la route seule vue par le simulateur, connexions sortantes bornées au frontal MCP et à la passerelle, période close par noortrace-ctl, chaque dossier valide pour les deux vérificateurs sans réseau", async function () {
      if (condition) return enAttente(this, condition);
      const { trace } = await jouer({ nom: "anthropic-py", commande: () => [python, "-I", agent("anthropic_agent.py")], env: (i) => ({ ANTHROPIC_BASE_URL: i.passerelle_url, ANTHROPIC_API_KEY: i.passerelle_jeton, AGENT_JETON_ENTETE: "x-noortrace-token" }), modele: /^demo\/modele-demo-1$/, resultatsExacts: true });
      expect(trace.sdk).to.equal("anthropic 2.3.0");
      expect(trace.echanges.map((e) => e.flux)).to.deep.equal([false, true, false]);
      expect(trace.echanges.map((e) => e.id)).to.deep.equal(["msg_demo_0001", "msg_demo_0002", "msg_demo_0003"]);
      expect(trace.appels.map((a) => [a.outil, a.nom_modele])).to.deep.equal([["demo__claims.get", "demo__claims_get"], ["demo__payments.create", "demo__payments_create"]]);
      emissionsAttendues(trace);
      expect(trace.notes.entetes_auth).to.deep.equal({ Authorization: `Bearer ${JETON_PASSERELLE}` });
    });

    it("TI-4 : le jeton de l'hôte dans la seule ANTHROPIC_API_KEY (voie de CT-2 §19.5.2) : le SDK anthropic 2.3.0 l'envoie en « Authorization: Bearer », que la route x-api-key de la démonstration retire sans le lire : 401 « hote non authentifie », ligne auth_failed, aucun événement (CT-2 §19.5.5, série 2.x)", async function () {
      if (condition) return enAttente(this, condition);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const r = lancerAgent({ commande: [python, "-I", agent("anthropic_agent.py")], env: envAgent(i, { ANTHROPIC_BASE_URL: i.passerelle_url, ANTHROPIC_API_KEY: i.passerelle_jeton }), fichierTrace: path.join(i.dir, "strace-anthropic-cle.txt") });
        expect(r.code).to.equal(1);
        expect(r.stderr).to.match(/AuthenticationError: Error code: 401/);
        expect(r.stderr).to.include("noortrace: hote non authentifie");
        const refus = await banc.exploitation("auth_failed");
        expect(refus.length).to.be.greaterThan(0);
        const evts = await banc.evenements();
        expect(evts.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique"]);
        for (const c of r.connexions) expect([adresseDe(i.mcp_url), adresseDe(i.passerelle_url)]).to.include(c);
      } finally {
        await banc.fermer();
      }
    });

    const sdkJs = moduleJs("@anthropic-ai/sdk");
    const conditionJs = commune ?? conditionSdk("@anthropic-ai/sdk", "1.3.0");

    it("TI-4 : SDK @anthropic-ai/sdk 1.3.0 (TypeScript) par ANTHROPIC_BASE_URL, jeton en X-Noortrace-Token, client MCP de référence @modelcontextprotocol/client 2.4.0 : même scénario, mêmes oracles", async function () {
      if (conditionJs) return enAttente(this, conditionJs);
      const { trace } = await jouer({ nom: "anthropic-js", commande: () => [process.execPath, agent("anthropic_agent.mjs")], env: (i) => ({ ANTHROPIC_BASE_URL: i.passerelle_url, ANTHROPIC_API_KEY: i.passerelle_jeton, AGENT_JETON_ENTETE: "x-noortrace-token" }), modele: /^demo\/modele-demo-1$/, resultatsExacts: true });
      expect(trace.sdk).to.equal("@anthropic-ai/sdk 1.3.0");
      expect(trace.echanges.map((e) => e.flux)).to.deep.equal([false, true, false]);
      expect(trace.appels.map((a) => a.outil)).to.deep.equal(["demo__claims.get", "demo__payments.create"]);
      emissionsAttendues(trace);
    });

    it("TI-4 : @anthropic-ai/sdk 1.3.0 avec la seule ANTHROPIC_API_KEY : « Authorization: Bearer » (client.js, ligne de l'en-tête), 401 de la route x-api-key, aucun événement", async function () {
      if (conditionJs) return enAttente(this, conditionJs);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const r = lancerAgent({ commande: [process.execPath, agent("anthropic_agent.mjs")], env: envAgent(i, { ANTHROPIC_BASE_URL: i.passerelle_url, ANTHROPIC_API_KEY: i.passerelle_jeton }), fichierTrace: path.join(i.dir, "strace-anthropic-js-cle.txt") });
        expect(r.code).to.equal(1);
        expect(r.stderr).to.match(/401/);
        expect(r.stderr).to.include("noortrace: hote non authentifie");
        expect((await banc.evenements()).length).to.equal(1);
        const source = fs.readFileSync(path.join(path.dirname(sdkJs.chemin), "client.js"), "utf8");
        expect(source).to.match(/Authorization: `Bearer \$\{apiKey\}`/);
      } finally {
        await banc.fermer();
      }
    });
  });

  // ------------------------------------------------------------------ 19.5.2
  describe("CT-2 §19.5.2 — Claude Code branché sans clé réelle sur le frontal MCP (.mcp.json) et la passerelle (ANTHROPIC_BASE_URL) de la configuration de démonstration", function () {
    const claude = (() => {
      const r = spawnSync("claude", ["--version"], { encoding: "utf8", timeout: 20000 });
      return r.status === 0 ? r.stdout.trim() : null;
    })();
    const condition = commune ?? (claude ? null : "Claude Code (commande `claude`) absent de l'environnement");

    it("19.5.2 : Claude Code (commande claude -p, --mcp-config du fichier .mcp.json de 19.5.2, bloc env de 19.5.2 avec le jeton de l'hôte aussi dans ANTHROPIC_CUSTOM_HEADERS en X-Noortrace-Token) ne joint que le frontal MCP et la passerelle : connexion d'hôte MCP établie, échanges de modèle relayés par la route /v1/messages et scellés sous la connexion d'hôte de la démonstration ; le scénario fixe de §19.2 ne se joue pas (les noms d'outils et la forme de la conversation de Claude Code ne sont pas ceux de l'agent scénarisé), ce qui est consigné", async function () {
      if (condition) return enAttente(this, condition);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const dir = fs.mkdtempSync(path.join(i.dir, "claude-code-"));
        fs.mkdirSync(path.join(dir, "home"));
        fs.writeFileSync(path.join(dir, ".mcp.json"), JSON.stringify({ mcpServers: { noortrace: { type: "http", url: i.mcp_url, headers: { Authorization: `Bearer ${i.mcp_jeton}` } } } }, null, 2));
        const r = lancerAgent({
          commande: ["claude", "-p", "Traite le sinistre 2026-81044.", "--mcp-config", path.join(dir, ".mcp.json"), "--strict-mcp-config", "--permission-mode", "bypassPermissions", "--output-format", "json", "--model", "modele-demo-1", "--max-turns", "6"],
          cwd: dir,
          env: { HOME: path.join(dir, "home"), ANTHROPIC_BASE_URL: i.passerelle_url, ANTHROPIC_API_KEY: i.passerelle_jeton, ANTHROPIC_CUSTOM_HEADERS: `X-Noortrace-Run-Id: run-claude-code-0001\nX-Noortrace-Token: ${i.passerelle_jeton}`, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1", DISABLE_TELEMETRY: "1", DISABLE_AUTOUPDATER: "1" },
          delaiMs: 240000,
          fichierTrace: path.join(i.dir, "strace-claude-code.txt"),
        });
        expect(r.erreur).to.equal(null);
        for (const c of r.connexions) expect([adresseDe(i.mcp_url), adresseDe(i.passerelle_url)], `connexion hors de l'enregistreur : ${c}`).to.include(c);
        expect(r.connexions).to.include(adresseDe(i.mcp_url));
        expect(r.connexions).to.include(adresseDe(i.passerelle_url));
        const evts = await banc.evenements();
        const ech = evts.filter((e) => e.execution.tool === "noortrace.modele.echange");
        expect(ech.length).to.be.greaterThan(0);
        // Les outils du frontal MCP, listés par Claude Code par le fichier .mcp.json, sont présentés au modèle sous
        // le nom mcp__noortrace__<nom annoncé> avec le point remplacé (19.5.2) : la requête d'un échange relayé les porte.
        const pieces = (await banc.commande({ cmd: "pieces", sha256: ech.map((e) => e.execution.arguments.sha256) })).pieces;
        const outilsVus = new Set(ech.flatMap((e) => (JSON.parse(pieces[e.execution.arguments.sha256]).tools ?? []).map((t) => t.name)));
        expect([...outilsVus], "outils MCP du frontal vus par le modèle").to.include.members(["mcp__noortrace__demo__claims_get", "mcp__noortrace__demo__claims_search", "mcp__noortrace__demo__payments_create"]);
        for (const e of ech) {
          expect(e.code.model).to.equal("demo/modele-demo-1");
          expect(e.delegation.launched_by).to.equal("agent-demo");
          expect(e.context).to.deep.equal([]);
        }
        expect(await banc.exploitation("auth_failed")).to.deep.equal([]);
        const sortie = (() => {
          try {
            return JSON.parse(r.stdout.trim().split("\n").at(-1));
          } catch {
            return null;
          }
        })();
        expect(sortie, r.stdout.slice(-1000)).to.be.an("object");
        // Le scénario fixe n'aboutit pas avec cet hôte : l'issue est consignée dans le titre du passage (rapport).
        this.test.title += ` — constaté : Claude Code ${claude}, ${ech.length} échange(s) relayé(s), issue ${sortie.is_error ? `erreur (${String(sortie.result).slice(0, 80)})` : "succès"}`;
      } finally {
        await banc.fermer();
      }
    });
  });

  // ------------------------------------------------------------------ TI-5
  describe("TI-5 — Intégration OpenAI : Chat Completions et Responses par le SDK officiel vers la passerelle", function () {
    const python = PYTHON("openai-agents");
    const condition = commune ?? (python ? null : `environnement openai-agents absent (openai-agents 0.24.0 et openai ; ${PREPARER_ADAPTATEURS} openai-agents)`);

    it("TI-5 : SDK openai (Python, verrou d'openai-agents 0.24.0) : Chat Completions (/v1/chat/completions, hors flux, flux, hors flux) puis Responses (/v1/responses, dont un échange en flux), puis SDK Agents 0.24.0 avec MCPServerStreamableHttp (CT-2 §19.5.4) : trois fois le scénario de §19.2, un événement par appel et par échange, pièces égales aux octets vus par l'hôte, approbations par les comptes 1 et 2, connexions bornées à l'enregistreur, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts } = await jouer({ nom: "openai", commande: () => [python, "-I", agent("openai_agent.py")], env: (i) => ({ OPENAI_BASE_URL: `${i.passerelle_url}/v1`, OPENAI_API_KEY: i.passerelle_jeton }), modele: /^openai\/modele-demo-1$/, delaiMs: 400000 });
      expect(trace.sdk).to.match(/^openai \d+\.\d+\.\d+ ; openai-agents 0\.24\.0$/);
      expect(trace.notes.parties).to.deep.equal(["chat", "responses", "agents"]);
      const chat = trace.echanges.filter((e) => e.partie === "chat");
      const responses = trace.echanges.filter((e) => e.partie === "responses");
      expect(chat.map((e) => [e.format, e.flux])).to.deep.equal([["openai-chat", false], ["openai-chat", true], ["openai-chat", false]]);
      expect(responses.map((e) => [e.format, e.flux])).to.deep.equal([["openai-responses", false], ["openai-responses", true], ["openai-responses", false]]);
      expect(trace.appels.filter((a) => a.outil === "demo__payments.create").length).to.equal(3);
      expect(trace.appels.filter((a) => a.outil === "demo__claims.get").length).to.equal(3);
      // Les deux premières parties redemandent elles-mêmes l'appel retenu ; le SDK Agents mène sa boucle et le
      // modèle simulé le redemande : au moins deux émissions chaque fois.
      emissionsAttendues(trace);
      expect(evts.filter((e) => e.execution.tool === "demo__payments.create" && e.execution.status === "executee").length).to.equal(3);
    });
  });

  // ------------------------------------------------------------------ TI-6
  describe("TI-6 — Intégration Gemini : google-genai vers la passerelle (route gemini, x-goog-api-key)", function () {
    const python = PYTHON("integration-gemini");
    const condition = commune ?? (python ? null : `environnement integration-gemini absent (google-genai 2.33.0 ; ${PREPARER} gemini)`);

    it("TI-6 : google-genai 2.33.0 (Python) par les deux voies de CT-2 §19.5.7 (GOOGLE_GEMINI_BASE_URL et GEMINI_API_KEY ; puis HttpOptions(base_url, headers X-Noortrace-Run-Id)), generateContent puis streamGenerateContent?alt=sse, appel automatique de fonctions désactivé (EX-19.6), chaque functionCall exécuté par le frontal MCP sous le nom annoncé : un événement par appel et par échange (code.model gemini/…), pièces égales aux octets vus par l'hôte, connexions bornées, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts } = await jouer({ nom: "gemini-py", commande: () => [python, "-I", agent("gemini_agent.py")], env: (i) => ({ GOOGLE_GEMINI_BASE_URL: i.passerelle_url, GEMINI_API_KEY: i.passerelle_jeton, GOOGLE_API_KEY: undefined }), modele: /^gemini\/modele-demo-1-001$/, resultatsExacts: true });
      expect(trace.sdk).to.equal("google-genai 2.33.0");
      expect(trace.echanges.map((e) => [e.voie, e.flux])).to.deep.equal([["environnement", false], ["code", true], ["code", false]]);
      expect(trace.appels.map((a) => [a.outil, a.nom_modele])).to.deep.equal([["demo__claims.get", "demo__claims.get"], ["demo__payments.create", "demo__payments.create"]]);
      emissionsAttendues(trace);
      // Corrélation d'EX-5.22 : chaque appel porte l'intention de l'échange qui l'a demandé, même par la voie de l'environnement (groupe d'hôte).
      for (const e of evts.filter((x) => x.execution.tool.startsWith("demo__"))) expect(e.intent, `intent de seq ${e.seq}`).to.not.equal(null);
    });

    it("TI-6 : refus de la route gemini (EX-5.29) : une clé dans la requête (?key=) et un flux sans alt=sse reçoivent 400 ; countTokens reçoit 404 (EX-5.28) ; aucun événement", async function () {
      if (commune) return enAttente(this, commune);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const corps = { contents: [{ role: "user", parts: [{ text: "Traite le sinistre 2026-81044." }] }] };
        const entetes = { "content-type": "application/json", "x-goog-api-key": i.passerelle_jeton };
        const cle = await requete(`${i.passerelle_url}/v1beta/models/modele-demo-1:generateContent?key=${i.passerelle_jeton}`, { entetes, corps });
        expect(cle.statut).to.equal(400);
        const flux = await requete(`${i.passerelle_url}/v1beta/models/modele-demo-1:streamGenerateContent`, { entetes, corps });
        expect(flux.statut).to.equal(400);
        const compte = await requete(`${i.passerelle_url}/v1beta/models/modele-demo-1:countTokens`, { entetes, corps });
        expect(compte.statut).to.equal(404);
        expect((await banc.evenements()).length).to.equal(1);
        const u = await banc.commande({ cmd: "usage" });
        expect(u.formats).to.deep.equal([]);
      } finally {
        await banc.fermer();
      }
    });

    const conditionJs = commune ?? conditionSdk("@google/genai", "2.31.0");

    it("TI-6 : @google/genai 2.31.0 (JavaScript) : new GoogleGenAI({ apiKey, httpOptions: { baseUrl, headers } }), generateContent puis generateContentStream, automaticFunctionCalling désactivé, client MCP de référence : même scénario, mêmes oracles", async function () {
      if (conditionJs) return enAttente(this, conditionJs);
      const { trace } = await jouer({ nom: "gemini-js", commande: () => [process.execPath, agent("gemini_agent.mjs")], env: () => ({}), modele: /^gemini\/modele-demo-1-001$/, resultatsExacts: true });
      expect(trace.sdk).to.equal("@google/genai 2.31.0");
      expect(trace.echanges.map((e) => e.flux)).to.deep.equal([false, true, false]);
      expect(trace.appels.map((a) => a.outil)).to.deep.equal(["demo__claims.get", "demo__payments.create"]);
      emissionsAttendues(trace);
    });
  });

  // ------------------------------------------------------------------ TI-7
  describe("TI-7 — Intégration LangChain et LangGraph : intergiciel MiddlewareNoortrace, wrap_tool_call", function () {
    const python = PYTHON("integration-langchain");
    const condition = commune ?? (python ? null : `environnement integration-langchain absent (langchain 1.4.7, langgraph 1.2.17, langchain-openai 1.7.3 ; ${PREPARER} langchain)`);

    it("TI-7 : agent create_agent de LangChain 1.4.7 / LangGraph 1.2.17, ChatOpenAI(base_url=passerelle) en flux, outils MCP par langchain.mcp.MCPAdapter (frontal), outil local déclaré par MiddlewareNoortrace (wrap_tool_call, dernier intergiciel) : scénario de §19.2 plus l'outil local ; un événement par appel et par échange, aucun outil MCP déclaré deux fois (EX-6.17, EX-19.5), écriture approuvée après que le modèle a redemandé l'appel, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts } = await jouer({ nom: "langchain", commande: () => [python, "-I", agent("langchain_agent.py")], modele: /^openai\/modele-demo-1$/, local: true });
      expect(trace.sdk).to.equal("langchain 1.4.7");
      expect(trace.echanges.every((e) => e.flux === true && e.format === "openai-chat")).to.equal(true);
      expect(trace.echanges.length).to.be.at.least(5);
      expect(trace.appels.map((a) => a.outil)).to.deep.equal(["demo__claims.get", "calculer_franchise", "demo__payments.create"]);
      emissionsAttendues(trace);
      expect(trace.notes.local).to.deep.equal([{ claim_id: "2026-81044", amount: "7400.00" }]);
      const local = evts.find((e) => e.execution.tool === "agent-py__calculer_franchise");
      expect(local.delegation.run_id).to.equal("run-integration-0001");
    });
  });

  // ------------------------------------------------------------------ TI-8
  describe("TI-8 — Intégration CrewAI : crochets before_tool_call et after_tool_call enregistrés en dernier", function () {
    const python = PYTHON("crewai");
    const condition = commune ?? (python ? null : `environnement crewai absent (crewai 1.15.30 ; ${PREPARER_ADAPTATEURS} crewai)`);

    it("TI-8 : équipage CrewAI 1.15.30, LLM(model=\"openai/…\", base_url=passerelle) (fournisseur natif, appels de fonctions), mcps=[MCPServerHTTP(frontal)], outil local enveloppé et crochets de l'adaptateur installés en dernier : scénario de §19.2 plus l'outil local ; un événement par appel et par échange, outils de mcps reconnus et non déclarés par l'adaptateur, écriture approuvée, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts } = await jouer({ nom: "crewai", commande: () => [python, "-I", agent("crewai_agent.py")], env: () => ({ CREWAI_DISABLE_TELEMETRY: "true", OTEL_SDK_DISABLED: "true", CREWAI_TRACING_ENABLED: "false" }), modele: /^openai\/modele-demo-1$/, local: true, delaiMs: 400000 });
      expect(trace.sdk).to.equal("crewai 1.15.30");
      expect(trace.notes.fonctions_natives).to.equal(true);
      expect(trace.appels.map((a) => outilDuJournal(a.outil))).to.deep.equal(["demo__claims.get", "agent-py__calculer_franchise", "demo__payments.create"]);
      emissionsAttendues(trace);
      expect(trace.notes.local).to.deep.equal([{ claim_id: "2026-81044", amount: "7400.00" }]);
      // CrewAI présente les outils de `mcps` au modèle sous un nom qu'il forme lui-même (préfixe du serveur) :
      // le frontal reçoit le nom annoncé, mais la corrélation d'EX-5.22 (nom vu par le modèle) ne s'applique pas
      // sans un tool_name_template de la connexion d'hôte qui reproduise ce préfixe (observation, rapport).
      expect(trace.appels[0].outil).to.match(/claims_get$/);
      expect(evts.filter((e) => e.execution.tool === "demo__claims.get").length).to.equal(1);
    });
  });

  // ------------------------------------------------------------------ TI-9
  describe("TI-9 — Intégration LlamaIndex : enveloppe de chaque outil", function () {
    const python = PYTHON("integration-llamaindex");
    const condition = commune ?? (python ? null : `environnement integration-llamaindex absent (llama-index-core 0.14.25, llama-index-tools-mcp 0.6.0, llama-index-llms-openai 0.8.3 ; ${PREPARER} llamaindex)`);

    it("TI-9 : FunctionAgent de llama-index-core 0.14.25, OpenAI(api_base=passerelle) de llama-index-llms-openai 0.8.3, outils MCP par McpToolSpec(BasicMCPClient(frontal)) déclarés au modèle sous leur nom assaini, outil local enveloppé par l'adaptateur (envelopper) : scénario de §19.2 plus l'outil local ; un événement par appel et par échange, outils de McpToolSpec non enveloppés, écriture approuvée, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace } = await jouer({ nom: "llamaindex", commande: () => [python, "-I", agent("llamaindex_agent.py")], modele: /^openai\/modele-demo-1$/, local: true });
      expect(trace.sdk).to.equal("llama-index-core 0.14.25");
      expect(trace.appels.map((a) => outilDuJournal(a.outil))).to.deep.equal(["demo__claims.get", "agent-py__calculer_franchise", "demo__payments.create"]);
      emissionsAttendues(trace);
      expect(trace.notes.local).to.deep.equal([{ claim_id: "2026-81044", amount: "7400.00" }]);
    });
  });

  // ------------------------------------------------------------------ TI-10
  describe("TI-10 — Intégration LiteLLM : CustomLogger en bibliothèque et LiteLLM en mandataire devant la passerelle", function () {
    // L'environnement du mandataire (litellm[proxy] 1.106.4) sert aux trois dispositions : en 1.106.4,
    // `litellm.completion(tools=…)` importe le module `mcp`, absent du verrou de la seule bibliothèque (rapport).
    const python = PYTHON("litellm-mandataire");
    const litellm = executable("litellm-mandataire", "litellm");
    const condition = commune ?? (python && litellm ? null : `environnement litellm-mandataire absent (litellm[proxy] 1.106.4 ; ${PREPARER_ADAPTATEURS} litellm-mandataire)`);
    const envLitellm = { LITELLM_LOCAL_MODEL_COST_MAP: "True", LITELLM_TELEMETRY: "False", DO_NOT_TRACK: "1" };

    it("TI-10 : LiteLLM 1.106.4 en bibliothèque, litellm.completion(model=\"openai/…\", api_base=passerelle) (hors flux, flux consolidé par stream_chunk_builder, hors flux), outils par le frontal MCP, puis rappel CustomLogger de l'adaptateur pour un échange hors passerelle (mock_response, modele=\"declarer\") : scénario de §19.2 ; un événement par appel et par échange, l'échange déclaré en plus avec sa pièce de déclaration de source, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const r = lancerAgent({ commande: [python, "-I", agent("litellm_agent.py"), "--cible", "passerelle"], env: envAgent(i, envLitellm), fichierTrace: path.join(i.dir, "strace-litellm.txt") });
        expect(r.code, r.stderr.slice(-3000)).to.equal(0);
        const trace = r.trace;
        expect(trace.sdk).to.equal("litellm 1.106.4");
        expect(trace.echanges.map((e) => e.flux)).to.deep.equal([false, true, false]);
        expect(trace.notes.declare).to.include({ modele: "openai/modele-local", file_vide: true, echanges_perdus: 0 });
        // L'échange déclaré (hors passerelle) est un événement de plus, de context non vide (pièce de déclaration de source) : le retirer des oracles communs.
        const evts = await evenementsAuMoins(banc, 1 + 4 + 1 + 3);
        const declares = evts.filter((e) => e.execution.tool === "noortrace.modele.echange" && e.context.length > 0);
        expect(declares.length).to.equal(1);
        expect(declares[0].code.model).to.equal("openai/modele-local");
        const u = await banc.commande({ cmd: "usage" });
        expect(u.formats.reduce((s, x) => s + x.requests, 0)).to.equal(3);
        // Oracles communs sur les événements de la passerelle et du frontal.
        const sansDeclare = { evenements: async () => (await banc.evenements()).filter((e) => !(e.execution.tool === "noortrace.modele.echange" && e.context.length > 0)), commande: banc.commande, exploitation: banc.exploitation, info: banc.info };
        await verifierScenario(sansDeclare, r, { modele: /^openai\/modele-demo-1$/, local: false, resultatsExacts: true, admises: [] });
      } finally {
        await banc.fermer();
      }
    });

    it("TI-10 : LiteLLM 1.106.4 en mandataire derrière la passerelle (EX-6.22, topologie 1, recommandée) : agent → passerelle → mandataire LiteLLM → simulateur ; l'enregistreur voit la requête de l'agent sous la délégation de l'agent ; scénario de §19.2, dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts, info } = await jouer({ nom: "litellm-derriere", envBanc: { NOORTRACE_INTEGRATION_LITELLM: litellm, NOORTRACE_INTEGRATION_MANDATAIRE: "derriere", ...envLitellm }, commande: () => [python, "-I", agent("litellm_agent.py"), "--cible", "passerelle"], env: () => ({ ...envLitellm, NOORTRACE_SDK_SOCKET: "" }), modele: /^openai\/modele-demo-1$/, resultatsExacts: true, cleFournisseur: CLE_FOURNISSEUR_MANDATAIRE, delaiMs: 400000 });
      expect(info.topologie).to.equal("derriere");
      expect(info.mandataire_url).to.match(/^http:\/\/127\.0\.0\.1:\d+$/);
      expect(trace.echanges.length).to.equal(3);
      // Délégation de l'agent : la connexion d'hôte de la passerelle (agent-demo) ; la configuration de démonstration
      // n'admet pas de délégation déclarée (accept_declared_delegation: false), run_id reste nul.
      for (const e of evts.filter((x) => x.execution.tool === "noortrace.modele.echange")) expect(e.delegation.launched_by).to.equal("agent-demo");
    });

    it("TI-10 : LiteLLM 1.106.4 en mandataire devant la passerelle (EX-6.22, topologie 2) : agent → mandataire LiteLLM (clé maîtresse) → passerelle (jeton de l'hôte dans la configuration du mandataire) → simulateur ; l'enregistreur voit ce que LiteLLM émet, sous la seule connexion d'hôte du mandataire (run_id nul) ; l'hôte ne joint que le frontal MCP et le mandataire ; dossiers valides pour les deux vérificateurs", async function () {
      if (condition) return enAttente(this, condition);
      const { trace, evts, info } = await jouer({ nom: "litellm-devant", envBanc: { NOORTRACE_INTEGRATION_LITELLM: litellm, NOORTRACE_INTEGRATION_MANDATAIRE: "devant", ...envLitellm }, commande: () => [python, "-I", agent("litellm_agent.py"), "--cible", "mandataire"], env: () => ({ ...envLitellm, NOORTRACE_SDK_SOCKET: "" }), admises: (i) => [adresseDe(i.mandataire_url)], modele: /^openai\/modele-demo-1$/, resultatsExacts: true, delaiMs: 400000 });
      expect(info.topologie).to.equal("devant");
      expect(trace.notes.api_base).to.equal(info.mandataire_url);
      expect(trace.echanges.length).to.equal(3);
      for (const e of evts.filter((x) => x.execution.tool === "noortrace.modele.echange")) {
        expect(e.delegation.launched_by).to.equal("agent-demo");
        expect(e.delegation.run_id).to.equal(null);
      }
    });

    it("TI-10 : sans LITELLM_LOCAL_MODEL_COST_MAP, la bibliothèque LiteLLM 1.106.4 tente de joindre un hôte public (sa table des modèles) pendant le scénario : connexions relevées hors de l'enregistreur (résolution DNS, hôte public), ce que l'intégration doit interdire (CT-2 §19.5.10, EX-6.2)", async function () {
      if (condition) return enAttente(this, condition);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const r = lancerAgent({ commande: [python, "-I", agent("litellm_agent.py"), "--cible", "passerelle"], env: envAgent(i, { LITELLM_TELEMETRY: "False", DO_NOT_TRACK: "1", NOORTRACE_SDK_SOCKET: "", LITELLM_LOCAL_MODEL_COST_MAP: undefined }), fichierTrace: path.join(i.dir, "strace-litellm-sans-table-locale.txt") });
        const hors = r.connexions.filter((c) => ![adresseDe(i.mcp_url), adresseDe(i.passerelle_url)].includes(c));
        expect(hors, `connexions relevées : ${r.connexions.join(", ")}`).to.not.be.empty;
        expect(hors.some((c) => !c.startsWith("127.0.0.1:") && !c.startsWith("[::1]:"))).to.equal(true);
      } finally {
        await banc.fermer();
      }
    });
  });

  // ------------------------------------------------------------------ TI-11
  describe("TI-11 — Intégration OpenTelemetry : agent instrumenté par un SDK OpenTelemetry vers le point d'entrée OTLP de l'enregistreur", function () {
    const python = PYTHON("integration-otel");
    const condition = commune ?? (python ? null : `environnement integration-otel absent (opentelemetry-sdk 1.45.1, opentelemetry-exporter-otlp-proto-http 1.45.1 ; ${PREPARER} otel)`);
    const VECTEURS = path.join(RACINE, "spec", "vecteurs", "ct-2", "otel");

    it("TI-11 : agent Python (opentelemetry-sdk 1.45.1, OTLPSpanExporter protobuf, le code de CT-2 §19.5.11) puis agent JavaScript (@opentelemetry/sdk-trace-base 2.12.0, exporter-trace-otlp-http 0.223.0 en JSON, configuré par le seul environnement de 6.8.15) : spans du scénario de §19.2 scellés en événements déclaratifs (trois inférences, deux outils, racine invoke_agent ignorée), un seul point joint ; le même lot rejoué octet pour octet est un doublon ; spans_per_request dépassé : 413 sans rien sceller ; sans jeton : 401 ; période close, chaque dossier valide pour les deux vérificateurs sans réseau", async function () {
      if (condition) return enAttente(this, condition);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        const octets = path.join(i.dir, "otel-python.pb");
        const py = lancerAgent({ commande: [python, "-I", agent("otel_agent.py")], env: envAgent(i, { AGENT_OCTETS: octets }), fichierTrace: path.join(i.dir, "strace-otel-py.txt") });
        expect(py.code, py.stderr.slice(-3000)).to.equal(0);
        expect(py.trace.sdk).to.equal("opentelemetry-sdk 1.45.1");
        expect(py.trace.notes.envois).to.equal(1);
        expect(py.connexions).to.deep.equal([adresseDe(i.otel_url)]);
        const js = lancerAgent({ commande: [process.execPath, agent("otel_agent.mjs")], env: { OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: i.otel_url, OTEL_EXPORTER_OTLP_TRACES_PROTOCOL: "http/json", OTEL_EXPORTER_OTLP_TRACES_HEADERS: `x-noortrace-token=${i.otel_jeton}`, OTEL_TRACES_SAMPLER: "always_on", OTEL_EXPORTER_OTLP_TRACES_TIMEOUT: "30000" }, fichierTrace: path.join(i.dir, "strace-otel-js.txt") });
        expect(js.code, js.stderr.slice(-3000)).to.equal(0);
        expect(js.trace.sdk).to.equal("@opentelemetry/sdk-trace-base 2.12.0 ; @opentelemetry/exporter-trace-otlp-http 0.223.0");
        expect(js.connexions).to.deep.equal([adresseDe(i.otel_url)]);
        const evts = await evenementsAuMoins(banc, 11);
        expect(evts.length).to.equal(11);
        const requetes = await banc.exploitation("otel_request");
        expect(requetes.map((l) => [l.data.content_type, l.data.status, l.data.issues.scelle, l.data.issues.ignore, l.data.reasons?.operation_non_retenue ?? 0])).to.deep.equal([["application/x-protobuf", 200, 5, 1, 1], ["application/json", 200, 5, 1, 1]]);
        for (const agentTrace of [py.trace, js.trace]) {
          expect(agentTrace.echanges.length).to.equal(3);
          expect(agentTrace.appels.map((a) => a.outil)).to.deep.equal(["claims.get", "payments.create"]);
        }
        const outils = evts.filter((e) => !e.execution.tool.startsWith("noortrace."));
        expect(outils.map((e) => e.execution.tool)).to.deep.equal(["otel-sinistres__claims.get", "otel-sinistres__payments.create", "otel-sinistres__claims.get", "otel-sinistres__payments.create"]);
        const inferences = evts.filter((e) => e.execution.tool === "noortrace.modele.echange");
        expect(inferences.length).to.equal(6);
        for (const e of [...outils, ...inferences]) {
          // Rang déclaratif (CT-2 6.7) : pièce de déclaration de source en tête du context, décision autorise sans règle.
          expect(e.context.length).to.be.greaterThan(0);
          expect(e.policy.rule).to.equal(null);
          expect(e.policy.decision).to.equal(e.execution.tool === "noortrace.modele.echange" ? "sans_objet" : "autorise");
          expect(e.policy.ticket).to.equal(null);
          expect(e.execution.status).to.equal("executee");
        }
        for (const e of inferences) expect(e.code.model).to.equal("anthropic/modele-demo-1");
        // Pièces : arguments du span d'outil égaux (après rédaction) à ce que l'agent a enregistré.
        const shas = outils.flatMap((e) => [e.execution.arguments.sha256, e.execution.result.sha256]);
        const pieces = (await banc.commande({ cmd: "pieces", sha256: shas })).pieces;
        expect(pieces[outils[0].execution.arguments.sha256]).to.equal(utf8({ claim_id: "2026-81044" }));
        expect(pieces[outils[1].execution.arguments.sha256]).to.equal(rediger(utf8({ claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" })));
        expect(pieces[outils[0].execution.result.sha256]).to.equal(rediger(utf8("Sinistre 2026-81044 : collision du 2026-11-02, dommages 7400.00 CHF, assuré joignable à j.dupont@assure.example ou au +41 44 123 45 67")));
        // Doublon : la requête protobuf de l'agent Python, rejouée octet pour octet (EX-6.32).
        expect(fs.existsSync(octets)).to.equal(true);
        const rejeu = await requete(i.otel_url, { entetes: { "content-type": "application/x-protobuf", "x-noortrace-token": i.otel_jeton }, corps: fs.readFileSync(octets) });
        expect(rejeu.statut).to.equal(200);
        const derniere = (await banc.exploitation("otel_request")).at(-1).data;
        expect(derniere.issues).to.deep.equal({ scelle: 0, ignore: 1, doublon: 5, recouvrement: 0, rejete: 0 });
        expect((await banc.evenements()).length).to.equal(11);
        // spans_per_request (16 dans le banc) dépassé : 413, rien de scellé.
        const trop = await requete(i.otel_url, { entetes: { "content-type": "application/json", "x-noortrace-token": i.otel_jeton }, corps: lot(Array.from({ length: 17 }, (_, k) => spanOutil(`outil.${k}`))) });
        expect(trop.statut).to.equal(413);
        expect((await banc.exploitation("otel_refused")).at(-1).data.reason).to.equal("spans_par_requete");
        expect((await banc.evenements()).length).to.equal(11);
        // Sans jeton : 401, ligne auth_failed.
        const sans = await requete(i.otel_url, { entetes: { "content-type": "application/json" }, corps: lot([spanOutil("claims.get")]) });
        expect(sans.statut).to.equal(401);
        expect((await banc.exploitation("auth_failed")).length).to.be.greaterThan(0);
        expect((await banc.evenements()).length).to.equal(11);
        await cloreEtVerifier(banc, await banc.evenements());
      } finally {
        await banc.fermer();
      }
    });

    it("TI-11 : les requêtes des vecteurs otel/ de l'annexe B (JSON, protobuf, gzip) rejouées telles quelles sur le point d'entrée du démon réel donnent, pour chaque span, la même issue, le même outil, les mêmes pièces (sha256, taille, rédaction) et la même pièce normalisée (envelope) que attendu.json", async function () {
      if (commune) return enAttente(this, commune);
      const banc = await lancerBanc();
      try {
        const i = banc.info;
        // Cas rejouables sur ce démon : réception sans état préalable (seen, recorded vides), sans gabarit
        // d'outil propre au vecteur, prompt système en référence, chaîne neuve ; un seul des deux jumeaux
        // (json/pb de l'exemple 6.8.16, le second serait un doublon ; il est joué juste après pour le constater).
        const cas = fs.readdirSync(VECTEURS).filter((c) => {
          const s = JSON.parse(fs.readFileSync(path.join(VECTEURS, c, "source.json"), "utf8"));
          const a = JSON.parse(fs.readFileSync(path.join(VECTEURS, c, "attendu.json"), "utf8"));
          return s.seen.length === 0 && s.recorded.length === 0 && Object.keys(s.policy_source.tools).length === 0 && JSON.stringify(s.policy_source.ingest) === '["inference","outil"]' && s.policy_source.class_default === null && s.host.accept_declared_delegation === true && s.host.prompt_version_name === null && s.options.prompt_in_request === "reference" && s.options.prompt_system === "redige" && a.status === 200 && a.spans.every((x) => ["scelle", "ignore"].includes(x.issue)) && !/^pb-exemple|^pb-identifiants|recouvrement|^json-identifiants-invalides$/.test(c);
        }).sort();
        expect(cas.length).to.be.greaterThan(8);
        let compares = 0;
        for (const c of cas) {
          const entetes = JSON.parse(fs.readFileSync(path.join(VECTEURS, c, "requete-entetes.json"), "utf8"));
          const fichier = ["requete.json", "requete.pb", "requete.brut"].map((f) => path.join(VECTEURS, c, f)).find((f) => fs.existsSync(f));
          const avant = (await banc.evenements()).length;
          const h = { "content-type": entetes["content-type"], "x-noortrace-token": i.otel_jeton };
          if (entetes["content-encoding"]) h["content-encoding"] = entetes["content-encoding"];
          const rep = await requete(`${i.otel_url.replace(/\/v1\/traces$/, "")}${entetes.path}`, { methode: entetes.method, entetes: h, corps: fs.readFileSync(fichier) });
          const attendu = JSON.parse(fs.readFileSync(path.join(VECTEURS, c, "attendu.json"), "utf8"));
          expect(rep.statut, `cas ${c}`).to.equal(attendu.status);
          const scelles = attendu.spans.filter((x) => x.issue === "scelle");
          const evts = await evenementsAuMoins(banc, avant + scelles.length);
          const nouveaux = evts.slice(avant);
          expect(nouveaux.length, `cas ${c} : événements scellés`).to.equal(scelles.length);
          const ligne = (await banc.exploitation("otel_request")).at(-1).data;
          expect(ligne.issues.scelle, `cas ${c}`).to.equal(attendu.counts.scelle);
          expect(ligne.issues.ignore, `cas ${c}`).to.equal(attendu.counts.ignore);
          for (const [k, s] of scelles.entries()) {
            const e = nouveaux[k];
            const ev = s.event;
            expect(e.execution.tool, `cas ${c} span ${k}`).to.equal(ev.execution.tool);
            expect(e.execution.status).to.equal(ev.execution.status);
            expect(e.execution.is_error).to.equal(ev.execution.is_error);
            expect(e.execution.arguments, `cas ${c} span ${k} arguments`).to.deep.equal(ev.execution.arguments);
            expect(e.execution.result, `cas ${c} span ${k} résultat`).to.deep.equal(ev.execution.result);
            expect(e.code.model).to.equal(ev.code.model);
            expect(e.intent).to.deep.equal(ev.intent);
            // Pièce normalisée du span (envelope, EX-6.31) : même référence dans le context.
            const env = s.pieces.envelope;
            expect(e.context.some((x) => x.sha256 === env.sha256 && x.length === env.length), `cas ${c} span ${k} : pièce normalisée ${env.sha256}`).to.equal(true);
            compares++;
          }
        }
        expect(compares).to.be.greaterThan(8);
        // Le jumeau protobuf de l'exemple 6.8.16 : mêmes identifiants, doublons.
        const pb = path.join(VECTEURS, "pb-exemple-6-8-16");
        const avant = (await banc.evenements()).length;
        const rep = await requete(i.otel_url, { entetes: { "content-type": "application/x-protobuf", "x-noortrace-token": i.otel_jeton }, corps: fs.readFileSync(path.join(pb, "requete.pb")) });
        expect(rep.statut).to.equal(200);
        expect((await banc.exploitation("otel_request")).at(-1).data.issues.doublon).to.equal(2);
        expect((await banc.evenements()).length).to.equal(avant);
        // gzip : le cas gzip-json, s'il n'est pas déjà dans la liste, par le codage gzip d'un lot.
        const g = await requete(i.otel_url, { entetes: { "content-type": "application/json", "content-encoding": "gzip", "x-noortrace-token": i.otel_jeton }, corps: zlib.gzipSync(Buffer.from(JSON.stringify(lot([spanOutil("archives.lire")])))) });
        expect(g.statut).to.equal(200);
        // Protobuf d'un lot de test : même réponse vide, même scellement.
        const p = await requete(i.otel_url, { entetes: { "content-type": "application/x-protobuf", "x-noortrace-token": i.otel_jeton }, corps: encoderProtobuf(lot([spanOutil("archives.lister")])) });
        expect(p.statut).to.equal(200);
        expect(p.corps.length).to.equal(0);
      } finally {
        await banc.fermer();
      }
    });
  });
});
