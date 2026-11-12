// Outils communs aux tests du service d'approbation
// (test/approbation-service-*.test.js) : chemins des vecteurs, comptes de
// test de CT-3 A.2 (clés publiques, sans valeur), machine réglée comme une
// trace de l'annexe A.6, configuration et lancement du service comme
// processus, événements `retenue` scellés par la clé de test rec-test-01 de
// CT-1 §13, pont JSON-RPC vers le réseau Hardhat en mémoire.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { Machine, lireJsonStrict, completer } from "@noortrace/approbation";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const SPEC = path.join(RACINE, "spec");
export const VECTEURS_CT3 = path.join(SPEC, "vecteurs", "ct-3");
export const VECTEURS_CT2 = path.join(SPEC, "vecteurs", "ct-2");
export const BIN_APPROBATION = path.join(RACINE, "paquets", "approbation", "bin", "noortrace-approbation");
export const ANNUAIRE_REFERENCE = path.join(VECTEURS_CT3, "annuaire", "annuaires", "reference.json");

/** Lit un vecteur JSON de CT-3 (lecture stricte ; substituts admis pour les politiques invalides). */
export function lireCt3(rel) {
  return lireJsonStrict(fs.readFileSync(path.join(VECTEURS_CT3, rel)), { substituts: "admis" });
}

/** Constantes de CT-3 A.2. */
export const CONSTANTES = JSON.parse(fs.readFileSync(path.join(VECTEURS_CT3, "constantes.json"), "utf8"));
export const ORG_ID = CONSTANTES.organization.org_id;
export const JOURNAL_ID = CONSTANTES.journal.journal_id;
export const DEMANDEUR = CONSTANTES.requester.launched_by;
/** Adresse du compte i (1 à 4). */
export const adresse = (i) => CONSTANTES.accounts[i - 1].address;
/** Clé privée du compte i (1 à 4). */
export const clePrivee = (i) => N.hexVersOctets(CONSTANTES.accounts[i - 1].private_key, 32);
/** Identités de session de l'annuaire de référence. */
export const SESSIONS = Object.freeze({
  1: "oidc https://idp.assureur-demo.example approbateur-1",
  2: "oidc https://idp.assureur-demo.example approbateur-2",
  3: "oidc https://idp.assureur-demo.example u.martin",
  admin: "oidc https://idp.assureur-demo.example admin-1",
});

/** Signature EIP-191 du compte i sur D_A (CT-1 §6.3). */
export function signerVote(i, { decision, ticket, request_hash, org_id = ORG_ID, journal_id = JOURNAL_ID }) {
  return N.signerApprobation(clePrivee(i), { decision, journal_id, org_id, request_hash, ticket });
}

/** Répertoire temporaire neuf (mode 0700). */
export function repertoireTemporaire(prefixe = "noortrace-approbation-") {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
  fs.chmodSync(d, 0o700);
  return d;
}

/** Hachage synthétique d'une demande k (CT-3 A.2). */
export const hashDemande = (k) => N.sha256Hex(N.utf8(`noortrace/vecteurs/ct3/demande/${k}`));
/** Hachage synthétique d'un événement seq (CT-3 A.2). */
export const hashEvenement = (seq) => N.sha256Hex(N.utf8(`noortrace/vecteurs/ct3/evenement/${seq}`));

/**
 * Machine réglée comme une trace de l'annexe A.6 (service vide, compteur sans
 * époque, version de la trace en vigueur).
 * @param {object} tr trace `tickets/<nom>.json`
 * @param {object} [extra] options de Machine
 */
export function machineDeTrace(tr, extra = {}) {
  const p = {
    org_id: tr.org_id, journal_id: tr.journal_id, identifiants: { mode: "compteur" }, max_open_tickets: tr.service.max_open_tickets,
    escalation: tr.service.escalation, administrators: tr.service.administrators, ...extra,
  };
  const version = (pv) => ({
    policy_version: pv, environment: tr.environment,
    approval: { rules: { approver_set: tr.approver_set, separation: tr.separation }, mode: "erreur", expire_after_ms: tr.expire_after_ms, timeout_ms: 2000 },
  });
  const m = new Machine(p);
  m.ajouterVersion(version(tr.policy_version));
  m.fixerEnVigueur(tr.policy_version);
  return { m, p, version };
}

/** Jeu statique des comptes 1 à 3, seuil 2 (comptes de A.2). */
export const JEU_STATIQUE = Object.freeze({
  source: "statique", chain_id: null, registry: null, set: null,
  members: [adresse(1), adresse(2), adresse(3)], threshold: { required: 2, size: 3 },
});

/**
 * Politique de parcours : paiements CHF (revue au-delà de 5000, fenêtre de
 * 1000 à 5000 par bénéficiaire, autorisation en deçà), lecture autorisée,
 * suppression sous fenêtre de contestation, refus hors CHF, défaut revue.
 * @param {object} [o] { approver_set, contest_ms, self_approval }
 */
export function politiqueParcours(o = {}) {
  return {
    version: 0,
    default: { name: "defaut : revue", description: null, level: "revue", decision: null, contest_ms: 0 },
    rules: [
      { name: "lecture autorisee", description: null, tools: ["sap__claims.get"], when: null, level: "automatique", decision: "autorise", window: null, contest_ms: null },
      {
        name: "paiement hors CHF", description: null, tools: ["sap__payments.create"],
        when: { none: [{ path: "/arguments/currency", op: "egal", value: "CHF" }] }, level: "automatique", decision: "refuse", window: null, contest_ms: null,
      },
      {
        name: "paiement <= 1000 CHF", description: null, tools: ["sap__payments.create"],
        when: { all: [{ path: "/arguments/amount", op: "strictement_superieur", value: "0" }, { path: "/arguments/amount", op: "inferieur_ou_egal", value: "1000" }] },
        level: "automatique", decision: "autorise", window: null, contest_ms: null,
      },
      {
        name: "paiement de 1000 a 5000 CHF", description: "Fenêtre par bénéficiaire.", tools: ["sap__payments.create"],
        when: { all: [{ path: "/arguments/amount", op: "strictement_superieur", value: "1000" }, { path: "/arguments/amount", op: "inferieur_ou_egal", value: "5000" }] },
        level: "fenetre", decision: null, window: { duration_ms: 3600000, max_calls: 2, same_arguments: ["/arguments/beneficiary_iban"] }, contest_ms: 0,
      },
      {
        name: "paiement > 5000 CHF", description: null, tools: ["sap__payments.create"],
        when: { path: "/arguments/amount", op: "strictement_superieur", value: "5000" }, level: "revue", decision: null, window: null, contest_ms: 0,
      },
      { name: "suppression", description: null, tools: ["sap__claims.delete"], when: null, level: "revue", decision: null, window: null, contest_ms: o.contest_ms ?? 1500 },
    ],
    approver_set: o.approver_set ?? JEU_STATIQUE,
    separation: { self_approval: o.self_approval ?? "interdite", identities: [{ launched_by: DEMANDEUR, addresses: [adresse(3)] }] },
  };
}

/** Outils de la liste agrégée du parcours (triés). */
export const OUTILS_PARCOURS = Object.freeze([
  { tool_announced: "sap__claims.delete", tool_original: "claims.delete", server_alias: "sap", class: "ecriture", effects: null },
  { tool_announced: "sap__claims.get", tool_original: "claims.get", server_alias: "sap", class: "lecture", effects: null },
  { tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture", effects: null },
]);

/**
 * Outils du parcours, pris dans OUTILS_PARCOURS (essais de l'étape 6) : les
 * essais lisent le nom annoncé, le nom d'origine et l'alias du serveur ici,
 * sans les écrire de nouveau.
 */
const outilParcours = (original) => OUTILS_PARCOURS.find((t) => t.tool_original === original);
export const OUTIL_PAIEMENT = outilParcours("payments.create");
export const OUTIL_LECTURE = outilParcours("claims.get");
export const OUTIL_SUPPRESSION = outilParcours("claims.delete");

/** Message `charger` (12.2). */
export function messageCharger({ policy_version, rules, expire_after_ms = 3600000, mode = "erreur", environment = "developpement", org_id = ORG_ID, journal_id = JOURNAL_ID }) {
  return {
    org_id, journal_id, environment, policy_version,
    policy_sha256: N.sha256Hex(N.utf8(`ensemble de politique ${policy_version}`)),
    approval: { rules, mode, hold_timeout_ms: 50000, expire_after_ms, timeout_ms: 2000 },
    tools: OUTILS_PARCOURS.map((t) => ({ ...t })),
    requesters: [DEMANDEUR],
  };
}

/** Requête `evaluer` (CT-2 EX-7.4) d'un appel d'outil du parcours. */
export function requeteEvaluer(outil, args, { policy_version = "parcours-1", launched_by = DEMANDEUR } = {}) {
  const [alias, origine] = outil.split("__");
  return {
    tool_announced: outil, tool_original: origine, server_alias: alias, arguments: args,
    class: outil.endsWith(".get") ? "lecture" : "ecriture",
    delegation: { launched_by, on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-parcours-0001" },
    intent: "Régler un sinistre", code: { model: "fournisseur/modele@2026-09", prompt_version: null, policy_version, recorder: "0.1.0" }, context: [],
  };
}

/** Graine Ed25519 de la clé de test rec-test-01 (CT-1 §13). */
export const GRAINE_TEST = N.sha256(N.utf8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01"));

/**
 * Événement `retenue` scellé (clé de test) d'une requête evaluer et sa pièce
 * « arguments » (JCS intégral des arguments, ici sans rédaction), avec le
 * message `ouvrir` de 12.4 ; `intentParReference` : intention portée par une
 * référence (révision 0.6 de CT-3, EX-7.24).
 */
export function retenue({ requete, rule, ticket, seq, ts, org_id = ORG_ID, journal_id = JOURNAL_ID, prev_hash = N.ZERO32, intentParReference = false }) {
  const octets = N.utf8(JSON.stringify(trierCles(requete.arguments)));
  // intentParReference : l'événement porte l'intention par une référence sans valeur (CT-1 §5.4)
  const intent = intentParReference && typeof requete.intent === "string" ? N.creerReference(N.utf8(requete.intent)) : requete.intent;
  const e = N.scellerEvenement({
    version: 0, seq, ts, org_id, journal_id, recorder_key_id: "rec-test-01", prev_hash,
    delegation: requete.delegation, code: requete.code, intent,
    policy: { rule, decision: "a_approuver", ticket, redaction: null }, approval: null,
    execution: { tool: requete.tool_announced, arguments: N.creerReference(octets), status: "retenue", result: null, duration_ms: null, is_error: null },
    effects: [], context: [],
  }, GRAINE_TEST);
  return {
    evenement: e,
    ouvrir: { ticket, request_hash: e.hash, request_seq: seq, request_ts: ts, request_event: e, arguments_piece: Buffer.from(octets).toString("base64") },
  };
}

function trierCles(v) {
  if (Array.isArray(v)) return v.map(trierCles);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, trierCles(v[k])]));
  return v;
}

/**
 * Écrit une configuration de service et ses secrets sous `dir`.
 * @param {string} dir
 * @param {object} [o] { socket: boolean, console: boolean, rpc, epoch, environment, escalation, max_open_tickets, set_poll_interval_ms }
 * @returns {{chemin: string, config: object, jetonNoyau: string, jetonConsole: string, socket: string|null}}
 */
export function ecrireConfiguration(dir, o = {}) {
  const jetonNoyau = "jeton-noyau-" + N.octetsVersHex(N.sha256(N.utf8(dir))).slice(2, 26);
  const jetonConsole = "jeton-console-" + N.octetsVersHex(N.sha256(N.utf8(dir + "/c"))).slice(2, 26);
  fs.writeFileSync(path.join(dir, "cle-stockage"), N.octetsVersHex(N.sha256(N.utf8(dir + "/k"))) + "\n", { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "jeton-noyau"), jetonNoyau, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, "jeton-console"), jetonConsole, { mode: 0o600 });
  const socket = o.socket === false ? null : path.join(dir, "approbation.sock");
  const config = {
    version: 0,
    environment: o.environment ?? "developpement",
    org: "assureur-demo",
    org_id: o.org_id ?? ORG_ID,
    journal_id: o.journal_id ?? JOURNAL_ID,
    state_dir: path.join(dir, "service"),
    storage_key: { file: "cle-stockage" },
    noyau: socket ? { socket, socket_mode: "0660", token: { file: "jeton-noyau" } } : { tcp: { host: "127.0.0.1", port: 0 }, token: { file: "jeton-noyau" } },
    console: o.console === false ? null : { tcp: { host: "127.0.0.1", port: 0 }, token: { file: "jeton-console" }, annuaire: ANNUAIRE_REFERENCE },
    tickets: { epoch: o.epoch ?? null },
    max_open_tickets: o.max_open_tickets ?? 20,
    escalation: o.escalation ?? [],
    set_poll_interval_ms: o.set_poll_interval_ms ?? 1000,
    administrators: [SESSIONS.admin],
    console_origin: "https://console.assureur-demo.example",
    rpc: o.rpc ?? null,
    remise_representation_ms: o.remise_representation_ms ?? 30000,
  };
  const chemin = path.join(dir, "approbation.json");
  fs.writeFileSync(chemin, JSON.stringify(config, null, 2));
  return { chemin, config: completer(config), jetonNoyau, jetonConsole, socket };
}

/**
 * Lance le service comme processus ; attend sa ligne « pret ».
 * @param {string} cheminConfig
 * @returns {Promise<{proc: import("node:child_process").ChildProcess, noyau: object, console: object|null,
 *   arreter: () => Promise<number>, tuer: () => Promise<void>, sortie: () => string}>}
 */
export function lancerService(cheminConfig, env = {}) {
  return new Promise((resoudre, rejeter) => {
    const proc = spawn(process.execPath, [BIN_APPROBATION, "--config", cheminConfig], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ...env } });
    let sortie = "";
    let erreurs = "";
    const fin = new Promise((ok) => proc.once("exit", (code, signal) => ok({ code, signal })));
    proc.stderr.on("data", (x) => (erreurs += x));
    proc.stdout.on("data", (x) => {
      sortie += x;
      const l = sortie.split("\n").find((y) => y.startsWith("{"));
      if (l && !proc._pret) {
        proc._pret = true;
        const info = JSON.parse(l);
        resoudre({
          proc,
          noyau: info.noyau,
          console: info.console,
          sortie: () => sortie + erreurs,
          arreter: async () => {
            proc.kill("SIGTERM");
            return (await fin).code;
          },
          tuer: async () => {
            proc.kill("SIGKILL");
            await fin;
          },
        });
      }
    });
    fin.then(({ code }) => {
      if (!proc._pret) rejeter(new Error(`service arrêté (${code}) : ${erreurs}`));
    });
  });
}

/** Appel d'une méthode du canal de la console (fetch, jeton porteur). */
export async function appelConsole(ecoute, jeton, methode, corps) {
  const r = await fetch(`http://${ecoute.host}:${ecoute.port}/v0/${methode}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${jeton}` },
    body: JSON.stringify(corps),
  });
  return { statut: r.status, corps: await r.json() };
}

/** Requête HTTP brute sur une prise Unix ou en TCP (entrées hostiles). */
export function requeteBrute({ socket, host, port }, { methode = "POST", chemin, entetes = {}, corps = "" }) {
  return new Promise((resoudre, rejeter) => {
    const octets = Buffer.isBuffer(corps) ? corps : Buffer.from(corps, "utf8");
    const req = http.request(
      { method: methode, path: chemin, headers: { "content-length": octets.length, ...entetes }, ...(socket ? { socketPath: socket } : { host, port }) },
      (res) => {
        const m = [];
        res.on("data", (x) => m.push(x));
        res.on("end", () => {
          const texte = Buffer.concat(m).toString("utf8");
          let json = null;
          try {
            json = JSON.parse(texte);
          } catch {
            json = null;
          }
          resoudre({ statut: res.statusCode, texte, json });
        });
      },
    );
    req.on("error", rejeter);
    req.end(octets);
  });
}

/**
 * Pont JSON-RPC HTTP vers un fournisseur EIP-1193 (réseau Hardhat en mémoire),
 * pour le lecteur du jeu du service lancé comme processus.
 * @param {{request: (a: {method: string, params: unknown[]}) => Promise<unknown>}} fournisseur
 */
export async function pontRpc(fournisseur) {
  const serveur = http.createServer((req, res) => {
    const m = [];
    req.on("data", (x) => m.push(x));
    req.on("end", async () => {
      const r = JSON.parse(Buffer.concat(m).toString("utf8"));
      let corps;
      try {
        corps = { jsonrpc: "2.0", id: r.id, result: await fournisseur.request({ method: r.method, params: r.params }) };
      } catch (e) {
        corps = { jsonrpc: "2.0", id: r.id, error: { code: -32000, message: String(e.message).slice(0, 200) } };
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(corps));
    });
  });
  await new Promise((ok) => serveur.listen(0, "127.0.0.1", ok));
  return { url: `http://127.0.0.1:${serveur.address().port}`, fermer: () => new Promise((ok) => serveur.close(ok)) };
}

/** Attend qu'une condition asynchrone soit vraie (au plus `ms`). */
export async function attendre(condition, ms = 10000, pas = 50) {
  const fin = Date.now() + ms;
  for (;;) {
    const v = await condition();
    if (v) return v;
    if (Date.now() > fin) throw new Error("délai d'attente dépassé");
    await new Promise((ok) => setTimeout(ok, pas));
  }
}
