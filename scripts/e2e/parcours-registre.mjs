#!/usr/bin/env node
// Parcours rejouable du registre sur le réseau de développement noorcore :
// épreuve TE-4 de CT-9 (EX-9.2), qui rejoue la section 7 de CT-4 pour un client
// fictif et fait vérifier le contrôle 8 de CT-6 par les deux vérificateurs.
//
//   node scripts/e2e/parcours-registre.mjs [--sortie <répertoire>] [--org <slug>]
//        [--verificateur-go <binaire>] [--garder-reseau]
//   npm run e2e:registre
//
// Ce que fait le parcours, dans l'ordre :
//   1. préalables : binaire <exécution>/bin/noorcore portant
//      noor_getCommitCertificate, vérificateur Go de CT-6 §14 (construit par
//      verificateur/scripts/construire.sh si go1.27.3 est dans le PATH), ABI de
//      hh-artifacts/ (compilées si elles manquent) ;
//   2. réseau : chain/scripts/dev-net.sh start s'il n'est pas debout ;
//   3. contrats : déployés par scripts/deploy/deploy-noortrace.mjs avec le
//      compte Hardhat 0 si deployments/noorcore.json manque (CT-4 7.4), jamais
//      redéployés par-dessus un fichier existant ;
//   4. CT-4 7.4 à 7.9 par l'outil de référence (scripts/registre/
//      noortrace-registre.mjs, appelé dans le même processus) : etat ;
//      inscrire-client --preparer puis --dossier (jeu d'approbateurs,
//      assignation, lecture du jeu, approvisionnement de la clé de chaîne) ;
//      condense inscription, signer × 2, inscrire-cle ; journal de la
//      première période ; ancrer ; condense cloture, signer × 2, clore ;
//      exporter ; verifier ; puis scripts/verify/certificat-commit.mjs sur
//      chaque certificat capturé ;
//   5. dossier de la période : un événement du journal, ses voisins, son
//      chemin, le manifeste et sa signature, cles.json, et les trois parties
//      du registre exportées (registre.json, certificat-commit.json,
//      validateurs.json) ; fichier d'ancres du réviseur (ancres-confiance-v0) ;
//      chaque document validé contre son schéma ;
//   6. contrôle 8 par l'implémentation de référence (scripts/verify/dossier.mjs)
//      ET par le binaire Go, avec le même fichier d'ancres ;
//   7. arrêt du réseau s'il a été démarré par le parcours (sauf
//      --garder-reseau).
//
// Client fictif : organisation demo-registre-<horodatage UTC> (un slug neuf à
// chaque exécution, EX-7.6), journal « journal-demo », clé d'enregistreur
// « rec-demo-01 ». Clés de test PUBLIÉES, sans aucune valeur : chaque secret
// est SHA-256(UTF-8("noortrace/parcours-registre/v0/<nom>")), <nom> étant
// admin-jeu, approbateur-1, approbateur-2, approbateur-3,
// cle-chaine-rec-demo-01 (clés secp256k1) et rec-demo-01 (graine Ed25519) ;
// l'exploitant est le compte Hardhat 0 de la mnémonique publique (EX-7.3).
// Ces clés n'ont de sens que sur le réseau de développement 2124.
//
// Journal de la période : à la place de « manifeste-essai » (hachages
// d'essai sans événement), le parcours écrit trois événements CT-1 fictifs
// scellés par la clé rec-demo-01 (scripts/lib/journal.mjs, le rôle de
// l'enregistreur de CT-2) et leur manifeste signé ; le dossier porte ainsi un
// événement réel, ce que le vérificateur Go exige pour examiner un dossier.
// Les parties RFC 3161 et OpenTimestamps (CT-5) sont déclarées absentes : les
// contrôles 4 et 5 ne sont pas exécutés, ce que le verdict rapporte.
//
// Sorties : tout ce que le parcours crée va dans --sortie (défaut : un
// répertoire neuf sous le répertoire temporaire du système, jamais dans le
// dépôt, EX-7.14) : cles/, dossier.json (d'inscription), captures/,
// demande-*.json, periode-1/, parties-1/, dossier-1/, ancres.json, sorties/
// (sortie JSON de chaque commande, numérotée), verificateurs/ et verdict.json,
// que la sortie standard reprend. Codes : 0 parcours réussi et contrôle 8
// réussi pour les deux vérificateurs ; 1 échec d'une étape ou d'un
// vérificateur ; 2 préalable absent (binaire, vérificateur Go), rien n'est
// envoyé.
//
// Variables : NOORTRACE_RUNTIME_DIR (répertoire d'exécution du réseau, comme
// dev-net.sh ; le jeu de validateurs lu par l'outil est alors celui de ce
// répertoire, NOORTRACE_VALIDATORS_FILE) ; NOORTRACE_VERIFICATEUR_GO (binaire
// du vérificateur Go) ; NOORTRACE_DEPLOYMENTS_DIR (fichiers de déploiement).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";
import { SigningKey, Wallet, computeAddress } from "ethers";
import * as J from "../lib/journal.mjs";
import * as C from "../lib/conventions-registre.mjs";
import { executer } from "../registre/noortrace-registre.mjs";
import { deploymentsDir } from "../lib/noortrace.mjs";
import { RACINE, RPC_DEV, arreterReseau, assurerReseau, binaireAvecCertificat, hauteurTete, lancer, repertoireExecution, verificateurGo } from "./reseau-dev.mjs";

export const ORGANISATION_PREFIXE = "demo-registre";
export const NOM_JOURNAL = "journal-demo";
export const KEY_ID = "rec-demo-01";
export const PREFIXE_GRAINE = "noortrace/parcours-registre/v0/";
const MNEMONIQUE_TEST = "test test test test test test test test test test test junk";
const SCHEMAS_ID = {
  registre: "https://noortrace.example/schemas/v0/registre.schema.json",
  validateurs: "https://noortrace.example/schemas/v0/validateurs.schema.json",
  ancres: "https://noortrace.example/schemas/v0/ancres-confiance.schema.json",
  dossier: "https://noortrace.example/schemas/v0/dossier.schema.json",
  evenement: "https://noortrace.example/schemas/v0/evenement.schema.json",
  manifeste: "https://noortrace.example/schemas/v0/manifeste.schema.json",
};
const RAISON_CT5 = "ancrage RFC 3161 et OpenTimestamps hors du parcours du registre (CT-5, étape 5 de la phase 2)";

/** Secret de test publié : SHA-256(UTF-8(PREFIXE_GRAINE + nom)), en hexadécimal 0x. */
export function secretPublie(nom) {
  return J.sha256(Buffer.from(PREFIXE_GRAINE + nom, "utf8"));
}

let SCHEMAS = null;
function schemas() {
  if (SCHEMAS) return SCHEMAS;
  const rep = path.join(RACINE, "spec", "schemas");
  SCHEMAS = {};
  for (const f of fs.readdirSync(rep).filter((x) => x.endsWith(".schema.json"))) {
    const s = JSON.parse(fs.readFileSync(path.join(rep, f), "utf8"));
    SCHEMAS[s.$id] = s;
  }
  return SCHEMAS;
}
function conforme(valeur, id, fragment = "") {
  return J.validerSchema(valeur, schemas()[id], { registre: schemas(), fragment });
}

const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const horodatageUTC = () => new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
const ms = (ns) => Math.round(Number(ns) / 1e4) / 100;

class EchecEtape extends Error {
  constructor(message, code = 1) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Clés de test publiées (même disposition que « cles-essai », CT-4 7.5)
// ---------------------------------------------------------------------------

function ecrireClesPubliees(rep, journalId) {
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const ecrire = (nom, contenu) => fs.writeFileSync(path.join(rep, nom), contenu, { mode: 0o600 });
  const noms = ["admin-jeu", "approbateur-1", "approbateur-2", "approbateur-3", `cle-chaine-${KEY_ID}`];
  const adresses = {};
  for (const nom of noms) {
    const k = secretPublie(nom);
    ecrire(`${nom}.cle`, k + "\n");
    adresses[nom] = computeAddress(new SigningKey(k).publicKey).toLowerCase();
  }
  const graine = secretPublie(KEY_ID);
  ecrire(`${KEY_ID}.graine`, graine + "\n");
  const pub = J.cleEd25519DepuisGraine(graine).clePublique;
  const cle = { key_id: KEY_ID, journal_id: journalId, algorithm: "ed25519", public_key: pub, custody_class: "D", backend_type: "fichier", created_at: new Date().toISOString(), chain_key: adresses[`cle-chaine-${KEY_ID}`], chain_key_class: "D", origin_proof: null };
  ecrire(`${KEY_ID}.json`, J.texteJSON(cle));
  const publiques = {
    version: 0,
    description: `Clés de test publiées du parcours du registre : chaque secret est SHA-256(UTF-8("${PREFIXE_GRAINE}<nom>")) ; adresses et clé publique seulement ici.`,
    journal: { name: NOM_JOURNAL, journal_id: journalId },
    set_admin: adresses["admin-jeu"],
    approvers: [1, 2, 3].map((i) => adresses[`approbateur-${i}`]),
    recorders: [{ key_id: KEY_ID, file: `${KEY_ID}.json`, public_key: pub, chain_key: cle.chain_key }],
  };
  ecrire("cles-essai.json", J.texteJSON(publiques));
  return { publiques, graine, clePublique: pub };
}

// ---------------------------------------------------------------------------
// Journal de démonstration de la période (rôle de l'enregistreur, CT-1)
// ---------------------------------------------------------------------------

/** Trois événements fictifs scellés par rec-demo-01, dans l'heure UTC précédente, et leur manifeste signé. */
export function periodeDemo({ org_id, journal_id, graine, maintenantMs = Date.now(), n = 3 }) {
  const t = Math.floor(maintenantMs / 1000);
  const periodStart = t - (t % 3600) - 3600;
  const run = `run-${new Date(periodStart * 1000).toISOString().slice(0, 13).replace(/[-T]/g, "")}`;
  const entrees = Array.from({ length: n }, (_, i) => ({
    ts: J.horodatage(periodStart * 1000 + 600_000 + i * 60_000),
    recorder_key_id: KEY_ID,
    delegation: { launched_by: "operateur@client-fictif.example", on_behalf_of: "service-demonstration", scope: "demonstration:lecture", run_id: run },
    code: { model: null, prompt_version: null, policy_version: "demonstration-v0", recorder: "0.1.0" },
    intent: `Lire la fiche fictive F-${i + 1} du client de démonstration`,
    policy: { rule: "lecture de fiche autorisee", decision: "autorise", ticket: null, redaction: null },
    approval: null,
    execution: { tool: "demonstration.fiche.lire", arguments: J.referenceEnLigne({ fiche: `F-${i + 1}` }), status: "executee", result: J.referenceEnLigne({ fiche: `F-${i + 1}`, contenu: "contenu fictif" }), duration_ms: 12 + i, is_error: false },
    effects: [{ system: "DEMONSTRATION", action: "lecture", object: `F-${i + 1}`, amount: null, currency: null }],
    context: [],
  }));
  const evenements = J.chainer(entrees, { org_id, journal_id, cles: { [KEY_ID]: graine } });
  const hashes = evenements.map((e) => e.hash);
  const nonce = J.sha256(Buffer.from(`${PREFIXE_GRAINE}nonce/${org_id}/${periodStart}`, "utf8"));
  const manifeste = J.construireManifeste({ org_id, journal_id, period_start: periodStart, first_seq: 1, hashes, recorder_key_id: KEY_ID, nonce, generated_at: new Date(maintenantMs).toISOString() });
  const sig = J.signerManifeste(manifeste, J.cleEd25519DepuisGraine(graine).clePrivee);
  return { evenements, hashes, manifeste, sig };
}

// ---------------------------------------------------------------------------
// Parcours
// ---------------------------------------------------------------------------

export async function parcours(argv = process.argv.slice(2), { stdout = process.stdout, stderr = process.stderr } = {}) {
  const { values: o } = parseArgs({ args: argv, options: { sortie: { type: "string" }, org: { type: "string" }, "verificateur-go": { type: "string" }, "garder-reseau": { type: "boolean" }, aide: { type: "boolean" } }, strict: true });
  if (o.aide) {
    stdout.write(fs.readFileSync(fileURLToPath(import.meta.url), "utf8").split("\n").slice(1, 70).filter((l) => l.startsWith("//")).map((l) => l.replace(/^\/\/ ?/, "")).join("\n") + "\n");
    return { code: 0, verdict: null };
  }
  const log = (m) => stderr.write(`parcours-registre : ${m}\n`);
  const t0 = process.hrtime.bigint();
  const E = path.resolve(o.sortie ?? fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-parcours-registre-")));
  if (fs.existsSync(E) && fs.readdirSync(E).length) throw new EchecEtape(`${E} n'est pas vide`, 2);
  fs.mkdirSync(path.join(E, "sorties"), { recursive: true });
  const slug = o.org ?? `${ORGANISATION_PREFIXE}-${horodatageUTC()}`;
  const runtime = repertoireExecution();
  if (process.env.NOORTRACE_RUNTIME_DIR && !process.env.NOORTRACE_VALIDATORS_FILE) process.env.NOORTRACE_VALIDATORS_FILE = path.join(runtime, "validators.json");
  const rel = (p) => (p.startsWith(E + path.sep) ? path.relative(E, p) : p.startsWith(RACINE) ? path.relative(RACINE, p) : p);

  const verdict = {
    version: 0,
    kind: "verdict-parcours-registre",
    test_id: "TE-4",
    spec: "CT-4 §7 (7.4 à 7.9) ; CT-6 §11 (contrôle 8) ; CT-9 EX-9.2",
    started_at: new Date().toISOString(),
    finished_at: null,
    result: "echoue",
    exit_code: 1,
    error: null,
    essai: E,
    organisation: { slug, org_id: null },
    journal: { name: NOM_JOURNAL, journal_id: null },
    recorder_key_id: KEY_ID,
    keys: `clés de test publiées : SHA-256(UTF-8("${PREFIXE_GRAINE}<nom>")) ; exploitant : compte Hardhat 0`,
    network: { rpc: RPC_DEV, runtime: process.env.NOORTRACE_RUNTIME_DIR ? "NOORTRACE_RUNTIME_DIR" : "chain/runtime", started_by_run: false, already_up: false, partial: false, stopped: false, head_start: null, head_end: null },
    steps: [],
    transactions: [],
    blocks: [],
    certificates: [],
    dossier: null,
    verifiers: { reference: null, go: null, parity: null },
    durations_ms: { total: null, network_start: null, registry: null, verification: null, network_stop: null },
  };
  let numero = 0;
  let reseau = null;

  const etape = async (nom, f) => {
    numero++;
    const debut = process.hrtime.bigint();
    const e = { number: numero, name: nom, command: null, exit_code: null, result: null, error: null, duration_ms: null, output: null };
    verdict.steps.push(e);
    try {
      const r = await f(e);
      if (e.exit_code === null) e.exit_code = 0;
      if (e.result === null) e.result = "reussi";
      return r;
    } catch (err) {
      e.exit_code = e.exit_code ?? (typeof err.code === "number" ? err.code : 1);
      e.result = e.result && e.result !== "reussi" ? e.result : "echoue";
      e.error = e.error ?? String(err.message ?? err).slice(0, 2000);
      throw err;
    } finally {
      e.duration_ms = ms(process.hrtime.bigint() - debut);
    }
  };

  /** Une commande de l'outil de référence, dans ce processus ; sortie JSON écrite dans sorties/. */
  const outil = (nom, args, { attendu = ["reussi", "deja_fait"] } = {}) =>
    etape(nom, async (e) => {
      e.command = `noortrace-registre ${args.map((a) => (path.isAbsolute(a) ? rel(a) : a)).join(" ")}`;
      let texte = "";
      const flux = { stdout: { write: (s) => ((texte += s), true) }, stderr: { write: (s) => (stderr.write(s), true) } };
      const { code, sortie } = await executer(args, flux);
      const f = path.join(E, "sorties", `${String(numero).padStart(2, "0")}-${args[0]}${args[0] === "condense" || args[0] === "inscrire-client" ? "-" + args[1].replace(/^--/, "") : ""}.json`);
      fs.writeFileSync(f, texte);
      e.output = rel(f);
      e.exit_code = code;
      e.result = sortie.result;
      if (!attendu.includes(sortie.result)) {
        e.error = sortie.error ? `${sortie.error.code} (${sortie.error.check ?? "-"}) : ${sortie.error.message}` : `résultat ${sortie.result}`;
        throw new EchecEtape(`${args[0]} : ${e.error}`);
      }
      return sortie;
    });

  let code = 1;
  try {
    // --- 1. préalables --------------------------------------------------------
    let go;
    await etape("prealables", async (e) => {
      e.command = "binaire noorcore, vérificateur Go, ABI";
      const b = binaireAvecCertificat(runtime);
      if (!b.ok) throw new EchecEtape(b.condition, 2);
      go = verificateurGo({ option: o["verificateur-go"] ?? null, repTravail: path.join(E, "bin") });
      if (!go.ok) throw new EchecEtape(go.condition, 2);
      if (!fs.existsSync(path.join(RACINE, "hh-artifacts", "contracts", "CuratorSet.sol", "CuratorSet.json"))) {
        log("ABI absentes de hh-artifacts/ : compilation…");
        const r = lancer(process.execPath, [path.join(RACINE, "node_modules", "hardhat", "dist", "src", "cli.js"), "--config", "hardhat.config.mjs", "compile"]);
        if (r.code !== 0) throw new EchecEtape(`compilation en échec : ${r.stderr.slice(-400)}`, 2);
      }
      e.result = "reussi";
    });
    verdict.verifiers.go = { binary: rel(go.chemin), origin: go.origine };

    // --- 2. réseau ------------------------------------------------------------
    const tReseau = process.hrtime.bigint();
    await etape("reseau", async (e) => {
      e.command = "bash chain/scripts/dev-net.sh status, puis start s'il le faut";
      reseau = assurerReseau({ journal: stderr });
      Object.assign(verdict.network, { started_by_run: reseau.demarre, already_up: reseau.deja_debout, partial: reseau.partiel });
      verdict.network.head_start = await hauteurTete();
    });
    verdict.durations_ms.network_start = ms(process.hrtime.bigint() - tReseau);

    // --- 3. contrats ----------------------------------------------------------
    const tRegistre = process.hrtime.bigint();
    await etape("contrats", async (e) => {
      const fDep = path.join(deploymentsDir(), "noorcore.json");
      if (fs.existsSync(fDep)) {
        e.command = `${rel(fDep)} présent : déploiement existant (jamais redéployé, CT-4 7.4)`;
        return;
      }
      e.command = "node scripts/deploy/deploy-noortrace.mjs --network noorcore (compte Hardhat 0)";
      const r = lancer(process.execPath, [path.join(RACINE, "scripts", "deploy", "deploy-noortrace.mjs"), "--network", "noorcore"], { env: { ...process.env, NOOR_PRIVATE_KEY: Wallet.fromPhrase(MNEMONIQUE_TEST).privateKey } });
      fs.writeFileSync(path.join(E, "sorties", `${String(numero).padStart(2, "0")}-deploiement.txt`), r.stdout + r.stderr);
      e.output = `sorties/${String(numero).padStart(2, "0")}-deploiement.txt`;
      if (r.code !== 0) throw new EchecEtape(`déploiement en échec (code ${r.code})`);
    });

    // --- 4. CT-4 7.4 à 7.9 ----------------------------------------------------
    const etat = await outil("etat", ["etat"]);
    const journalId = C.journalIdDuNom(NOM_JOURNAL);
    verdict.journal.journal_id = journalId;
    const cles = path.join(E, "cles");
    const k = (nom) => `fichier:${path.join(cles, `${nom}.cle`)}`;
    await etape("cles-de-test-publiees", async (e) => {
      e.command = `écriture de cles/ (secrets SHA-256(UTF-8("${PREFIXE_GRAINE}<nom>")))`;
      ecrireClesPubliees(cles, journalId);
      e.output = "cles/cles-essai.json";
    });
    const dossier = path.join(E, "dossier.json");
    const caps = path.join(E, "captures");
    const prep = await outil("inscrire-client --preparer", ["inscrire-client", "--preparer", "--org", slug, "--journal", NOM_JOURNAL, "--seuil", "2", "--cles-essai", path.join(cles, "cles-essai.json"), "--exploitant", "hardhat:0", "--prepare-par", "parcours du registre (scripts/e2e/parcours-registre.mjs)", "--sortie", dossier]);
    verdict.organisation.org_id = prep.outputs.org_id;
    await outil("inscrire-client --dossier", ["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps]);
    const demInsc = path.join(E, "demande-inscription.json");
    await outil("condense inscription", ["condense", "inscription", "--dossier", dossier, "--key-id", KEY_ID, "--sortie", demInsc]);
    await outil("signer (approbateur-1)", ["signer", "--demande", demInsc, "--cle", k("approbateur-1")]);
    await outil("signer (approbateur-2)", ["signer", "--demande", demInsc, "--cle", k("approbateur-2")]);
    await outil("inscrire-cle", ["inscrire-cle", "--demande", demInsc, "--cle-chaine", k(`cle-chaine-${KEY_ID}`), "--dossier", dossier, "--captures", caps]);

    const per = path.join(E, "periode-1");
    const fMan = path.join(per, "manifeste.json");
    let periode;
    await etape("journal de la periode (enregistreur de demonstration)", async (e) => {
      e.command = `3 événements CT-1 scellés par ${KEY_ID}, manifeste signé (scripts/lib/journal.mjs)`;
      periode = periodeDemo({ org_id: prep.outputs.org_id, journal_id: journalId, graine: secretPublie(KEY_ID) });
      fs.mkdirSync(per, { recursive: true });
      fs.writeFileSync(path.join(per, "evenements.json"), J.texteJSON(periode.evenements));
      fs.writeFileSync(fMan, J.texteJSON(periode.manifeste));
      fs.writeFileSync(path.join(per, "manifeste.sig"), J.texteJSON(periode.sig));
      for (const ev of periode.evenements) {
        const err = conforme(ev, SCHEMAS_ID.evenement);
        if (err.length) throw new EchecEtape(`événement ${ev.seq} non conforme : ${err[0].chemin} : ${err[0].message}`);
      }
      const em = conforme(periode.manifeste, SCHEMAS_ID.manifeste);
      if (em.length) throw new EchecEtape(`manifeste non conforme : ${em[0].chemin} : ${em[0].message}`);
      e.output = "periode-1/manifeste.json";
    });
    await outil("ancrer", ["ancrer", "--manifeste", fMan, "--cle-chaine", k(`cle-chaine-${KEY_ID}`), "--dossier", dossier, "--captures", caps]);
    const demClo = path.join(E, "demande-cloture-1.json");
    await outil("condense cloture", ["condense", "cloture", "--manifeste", fMan, "--captures", caps, "--sortie", demClo]);
    await outil("signer (approbateur-1)", ["signer", "--demande", demClo, "--cle", k("approbateur-1")]);
    await outil("signer (approbateur-3)", ["signer", "--demande", demClo, "--cle", k("approbateur-3")]);
    await outil("clore", ["clore", "--demande", demClo, "--manifeste", fMan, "--cle-chaine", k(`cle-chaine-${KEY_ID}`), "--dossier", dossier, "--captures", caps]);
    const parties = path.join(E, "parties-1");
    await outil("exporter", ["exporter", "--manifeste", fMan, "--dossier", dossier, "--captures", caps, "--sortie", parties]);
    const verif = await outil("verifier", ["verifier", "--parties", parties, "--manifeste", fMan, "--dossier", dossier]);
    verdict.durations_ms.registry = ms(process.hrtime.bigint() - tRegistre);

    // Transactions et blocs, depuis le dossier d'inscription et les captures.
    const d = lireJSON(dossier);
    for (const s of d.steps) {
      if (!["capturee", "faite"].includes(s.state)) throw new EchecEtape(`étape ${s.step} du dossier à l'état ${s.state}`);
      if (!s.transaction_hash) continue;
      const recu = lireJSON(path.join(caps, `recu-${s.transaction_hash}.json`)).result;
      verdict.transactions.push({ step: s.step, subject: s.subject, transaction_hash: s.transaction_hash, block_number: s.block_number, block_hash: s.block_hash, transaction_index: Number(BigInt(recu.transactionIndex)), gas_used: Number(BigInt(recu.gasUsed)), status: recu.status, capture: s.capture });
    }
    verdict.blocks = [...new Set(verdict.transactions.map((t) => t.block_number))].sort((a, b) => a - b);

    // --- certificat-commit.mjs sur chaque certificat capturé (7.9) ------------
    const jeuReseau = process.env.NOORTRACE_VALIDATORS_FILE || path.join(RACINE, "chain", "runtime", "validators.json");
    await etape("certificat-commit.mjs sur chaque certificat capture", async (e) => {
      e.command = `node scripts/verify/certificat-commit.mjs captures/certificat-<h>.json --validateurs ${rel(jeuReseau)} --chaine ${etat.outputs.bft_chain_id}`;
      const fichiers = fs.readdirSync(caps).filter((f) => /^certificat-\d+\.json$/.test(f)).sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]));
      let texte = "";
      for (const f of fichiers) {
        const r = lancer(process.execPath, [path.join(RACINE, "scripts", "verify", "certificat-commit.mjs"), path.join(caps, f), "--validateurs", jeuReseau, "--chaine", etat.outputs.bft_chain_id]);
        const ligne = (r.stdout.split("\n").find((l) => l.startsWith("Résultat")) ?? "").replace(/^Résultat\s*:\s*/, "");
        verdict.certificates.push({ height: Number(f.match(/\d+/)[0]), file: `captures/${f}`, exit_code: r.code, result: ligne });
        texte += `== ${f} (code ${r.code})\n${r.stdout}${r.stderr}`;
      }
      fs.writeFileSync(path.join(E, "sorties", `${String(numero).padStart(2, "0")}-certificats.txt`), texte);
      e.output = `sorties/${String(numero).padStart(2, "0")}-certificats.txt`;
      const attendus = new Set(verdict.blocks);
      const manquants = [...attendus].filter((h) => !verdict.certificates.some((c) => c.height === h));
      if (manquants.length) throw new EchecEtape(`certificat non capturé pour les blocs ${manquants.join(", ")}`);
      const ko = verdict.certificates.filter((c) => c.exit_code !== 0);
      if (ko.length) throw new EchecEtape(`certificat non valide : ${ko.map((c) => c.file).join(", ")}`);
    });

    // --- 5. dossier de la période et fichier d'ancres -------------------------
    const tVerif = process.hrtime.bigint();
    const repDossier = path.join(E, "dossier-1");
    const fAncres = path.join(E, "ancres.json");
    await etape("dossier de la periode et fichier d'ancres", async (e) => {
      e.command = "assemblerDossier (CT-1 §11) + parties du registre exportées ; ancres-confiance-v0";
      const rec = d.recorders.find((r) => r.key_id === KEY_ID);
      const evs = periode.evenements;
      const ev = evs[1];
      const a = J.assemblerDossier({
        evenement: ev,
        previous: evs[0],
        next: evs[2],
        hashesPeriode: periode.hashes,
        manifeste: periode.manifeste,
        manifesteSig: periode.sig,
        cles: [{ key_id: KEY_ID, algorithm: "ed25519", public_key: rec.public_key, valid_from: J.horodatage(periode.manifeste.period_start * 1000), valid_to: null, source: "dossier d'inscription du parcours du registre (CT-4 §7.10), clé de test publiée ; validité depuis le début de la période" }],
        generated_at: new Date().toISOString(),
        raisons: { jeton_rfc3161: RAISON_CT5, preuve_ots: RAISON_CT5 },
      });
      const fichiers = { ...a.fichiers };
      delete fichiers["dossier.json"];
      for (const n of ["registre.json", "certificat-commit.json", "validateurs.json"]) fichiers[n] = fs.readFileSync(path.join(parties, n));
      const index = J.indexDossier({ evenement: ev, generated_at: a.index.generated_at, fichiers, raisons: { jeton_rfc3161: RAISON_CT5, preuve_ots: RAISON_CT5 } });
      fs.mkdirSync(repDossier, { recursive: true });
      fs.writeFileSync(path.join(repDossier, "dossier.json"), J.texteJSON(index));
      for (const [n, contenu] of Object.entries(fichiers)) fs.writeFileSync(path.join(repDossier, n), contenu);
      // Ancres du réviseur : chaîne, adresses du dossier d'inscription, jeu du réseau (publication de l'exploitant, CT-6 §12.5).
      const val = lireJSON(jeuReseau);
      const ancres = {
        version: 0,
        label: `Ancres du parcours du registre ${slug}`,
        prepared_by: "scripts/e2e/parcours-registre.mjs",
        prepared_at: new Date().toISOString(),
        tsa_authorities: [],
        revocation: { crls: [], statements: [] },
        bitcoin: null,
        registry: {
          chain_id: etat.outputs.bft_chain_id,
          contracts: { period_registry: d.instance.contracts.period_registry, attestation_registry: d.instance.contracts.attestation_registry, recorder_registry: d.instance.contracts.recorder_registry },
          validator_sets: [{ from_height: 1, to_height: null, validators: val.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })), source: "validators.json du réseau de développement, clés publiques, publié par l'exploitant" }],
          source: "réseau de développement noortrace-2124-dev ; adresses du dossier d'inscription (CT-4 §7.10) ; publication de l'exploitant, pas une ancre indépendante (CT-6 §12.5)",
        },
        recorders: [{ org_id: d.organisation.org_id, journal_id: rec.journal_id, key_id: rec.key_id, public_key: rec.public_key, chain_key: rec.chain_key, source: "dossier d'inscription du parcours du registre (CT-4 §7.10)" }],
      };
      fs.writeFileSync(fAncres, J.texteJSON(ancres));
      // Conformité de chaque document à son schéma.
      const controles = [
        ["registre.json", lireJSON(path.join(repDossier, "registre.json")), SCHEMAS_ID.registre, ""],
        ["certificat-commit.json", lireJSON(path.join(repDossier, "certificat-commit.json")), SCHEMAS_ID.registre, "#/$defs/certificat_commit"],
        ["validateurs.json", lireJSON(path.join(repDossier, "validateurs.json")), SCHEMAS_ID.validateurs, ""],
        ["ancres.json", ancres, SCHEMAS_ID.ancres, ""],
        ["dossier.json", index, SCHEMAS_ID.dossier, ""],
        ["cles.json", lireJSON(path.join(repDossier, "cles.json")), SCHEMAS_ID.dossier, "#/$defs/cles"],
        ["evenement.json", ev, SCHEMAS_ID.evenement, ""],
        ["manifeste.json", periode.manifeste, SCHEMAS_ID.manifeste, ""],
      ];
      const schemasOk = {};
      for (const [nom, v, id, frag] of controles) {
        const err = conforme(v, id, frag);
        schemasOk[nom] = err.length ? `${err[0].chemin} : ${err[0].message}` : "conforme";
        if (err.length) throw new EchecEtape(`${nom} non conforme : ${err[0].chemin} : ${err[0].message}`);
      }
      verdict.dossier = { directory: "dossier-1", anchors: "ancres.json", event_seq: ev.seq, period_hash: J.hachageManifeste(periode.manifeste), parts_present: index.parts.filter((p) => p.present).map((p) => p.file), parts_absent: index.parts.filter((p) => !p.present).map((p) => ({ file: p.file, reason: p.reason_if_absent })), schemas: schemasOk };
      e.output = "dossier-1/dossier.json";
    });

    // --- 6. contrôle 8 par les deux vérificateurs -----------------------------
    const repV = path.join(E, "verificateurs");
    fs.mkdirSync(repV, { recursive: true });
    const lireRapport = (nom, r) => {
      fs.writeFileSync(path.join(repV, `${nom}.json`), r.stdout);
      if (r.stderr) fs.writeFileSync(path.join(repV, `${nom}.err`), r.stderr);
      let j;
      try {
        j = JSON.parse(r.stdout);
      } catch {
        return { exit_code: r.code, report: `verificateurs/${nom}.json`, verdict: null, control_8: null, checks: [], controls: [], duration_ms: Math.round(r.duree_ms) };
      }
      const c8 = j.controls.find((c) => c.number === 8) ?? null;
      const ids = new Set(c8?.checks ?? []);
      return {
        exit_code: r.code,
        report: `verificateurs/${nom}.json`,
        verdict: j.verdict,
        control_8: c8 ? { status: c8.status, reason: c8.reason, summary: c8.summary ?? null } : null,
        checks: j.checks.filter((x) => ids.has(x.id) || x.controls?.includes(8)).map((x) => ({ id: x.id, status: x.status, reason: x.reason })),
        controls: j.controls.map((c) => ({ number: c.number, status: c.status, reason: c.reason })),
        statement: j.statement ?? null,
        duration_ms: Math.round(r.duree_ms),
      };
    };
    await etape("controle 8 : implementation de reference", async (e) => {
      e.command = "node scripts/verify/dossier.mjs dossier-1 --ancres ancres.json --json";
      const r = lancer(process.execPath, [path.join(RACINE, "scripts", "verify", "dossier.mjs"), repDossier, "--ancres", fAncres, "--json"]);
      verdict.verifiers.reference = lireRapport("reference", r);
      e.output = "verificateurs/reference.json";
      e.exit_code = r.code;
      e.result = verdict.verifiers.reference.control_8?.status === "reussi" ? "reussi" : "echoue";
      if (e.result !== "reussi") throw new EchecEtape(`contrôle 8 de l'implémentation de référence : ${JSON.stringify(verdict.verifiers.reference.control_8)}`);
    });
    await etape("controle 8 : verificateur Go", async (e) => {
      e.command = `${path.basename(go.chemin)} dossier-1 --ancres ancres.json --json`;
      const r = lancer(go.chemin, [repDossier, "--ancres", fAncres, "--json"]);
      verdict.verifiers.go = { binary: rel(go.chemin), origin: go.origine, ...lireRapport("go", r) };
      e.output = "verificateurs/go.json";
      e.exit_code = r.code;
      e.result = verdict.verifiers.go.control_8?.status === "reussi" ? "reussi" : "echoue";
      if (e.result !== "reussi") throw new EchecEtape(`contrôle 8 du vérificateur Go : ${JSON.stringify(verdict.verifiers.go.control_8)}`);
    });
    const ref = verdict.verifiers.reference;
    const gov = verdict.verifiers.go;
    const parChecks = (v) => Object.fromEntries(v.checks.map((c) => [c.id, c.status]));
    const ecarts = [];
    for (const [id, s] of Object.entries(parChecks(ref))) if (parChecks(gov)[id] !== s) ecarts.push(`${id} : référence ${s}, Go ${parChecks(gov)[id] ?? "absent"}`);
    if (ref.exit_code !== gov.exit_code) ecarts.push(`code de sortie : référence ${ref.exit_code}, Go ${gov.exit_code}`);
    if (ref.verdict !== gov.verdict) ecarts.push(`verdict : référence ${ref.verdict}, Go ${gov.verdict}`);
    verdict.verifiers.parity = { equal: ecarts.length === 0, differences: ecarts };
    verdict.verifiers.tool_verifier = { status: verif.outputs.status, verifications: verif.outputs.verifications.map((v) => ({ id: v.id, status: v.status })) };
    verdict.durations_ms.verification = ms(process.hrtime.bigint() - tVerif);
    code = 0;
    verdict.result = "reussi";
  } catch (err) {
    code = err instanceof EchecEtape ? err.code : 1;
    verdict.result = code === 2 ? "inutilisable" : "echoue";
    verdict.error = String(err?.message ?? err).slice(0, 2000);
    if (!(err instanceof EchecEtape)) stderr.write(`parcours-registre : erreur : ${err?.stack ?? err}\n`);
  } finally {
    // --- 7. arrêt de ce que le parcours a démarré -----------------------------
    verdict.network.head_end = await hauteurTete();
    if (reseau?.demarre && !o["garder-reseau"]) {
      const tStop = process.hrtime.bigint();
      log("arrêt du réseau démarré par le parcours…");
      const a = arreterReseau({ journal: stderr });
      verdict.network.stopped = a.arrete;
      verdict.durations_ms.network_stop = ms(process.hrtime.bigint() - tStop);
      if (!a.arrete && code === 0) {
        code = 1;
        verdict.result = "echoue";
        verdict.error = "le réseau démarré par le parcours n'a pas pu être arrêté";
      }
    }
    verdict.exit_code = code;
    verdict.finished_at = new Date().toISOString();
    verdict.durations_ms.total = ms(process.hrtime.bigint() - t0);
    fs.writeFileSync(path.join(E, "verdict.json"), J.texteJSON(verdict));
    stdout.write(J.texteJSON(verdict));
  }
  return { code, verdict };
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  parcours().then(
    ({ code }) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`parcours-registre : ${err?.message ?? err}\n`);
      process.exitCode = err instanceof EchecEtape ? err.code : 2;
    },
  );
}
