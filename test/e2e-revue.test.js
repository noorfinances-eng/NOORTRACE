import { expect } from "chai";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Wallet } from "ethers";

// Revue de sécurité interne de l'étape 8 : outils de bout en bout
// (scripts/e2e/), vérificateur de renvois et outil d'attestation
// (scripts/conformite/), amorçage d'une organisation (scripts/deploy/).
// Constats : (garde de lancement : code 0 sans rien faire par un lien
// symbolique), (clé mal saisie et URL à secret recopiées), 
// (mesure-finalite.mjs sans garde de réseau), EX-11.11 (valeurs inventées,
// collecte interrompue rendue 0), (parcours-registre.mjs rend reussi
// quand les vérificateurs divergent, CT-9 EX-9.2), CT-7 EX-7.3 (attestation.mjs :
// --forme d'une attestation signée, document qui n'est pas un objet, fichier
// de clé lisible par d'autres), TE-4 (textes plus forts que le code),
// CT-4 EX-7.2 (bootstrap-org.mjs remplace un jeu hors du développement). Aucun
// réseau réel : faux point JSON-RPC local, réseau Hardhat en mémoire ; fichiers
// sous NOORTRACE_TMP (ou os.tmpdir()). NOORTRACE_RACINE désigne un autre arbre
// (rejeu sur une copie figée). Mutants : copies sous NOORTRACE_TMP, règle
// retirée par un remplacement textuel unique, détruites à la fin.

const RACINE = process.env.NOORTRACE_RACINE ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const S = (...p) => path.join(RACINE, "scripts", ...p);
const importer = (abs) => import(pathToFileURL(abs).href);
const noeudJs = (script, args, { env = {}, cwd = RACINE, input } = {}) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8", cwd, env: { ...process.env, ...env }, input, timeout: 180000 });
/** Même chose, sans bloquer la boucle d'événements (un faux serveur de cet essai doit répondre à l'enfant) ; tué après `delaiMs`. */
function noeudAsync(script, args, { env = {}, cwd = RACINE, delaiMs = 60000 } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [script, ...args], { cwd, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    const minuteur = setTimeout(() => p.kill("SIGKILL"), delaiMs);
    p.on("close", (code, signal) => {
      clearTimeout(minuteur);
      resolve({ status: code, signal, stdout, stderr });
    });
  });
}

let TRAVAIL;
const MUTANTS = [];
let LIEN;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-e2e-revue-"));
  LIEN = path.join(TRAVAIL, "lien-depot");
  fs.symlinkSync(RACINE, LIEN);
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
  for (const m of MUTANTS.splice(0)) fs.rmSync(m, { recursive: true, force: true });
});

/** Copie mutante : racine temporaire où tout est lié symboliquement sauf le fichier muté, recopié avec le remplacement (unique) appliqué. */
function racineMutante(nom, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-mutant-${nom}-`));
  MUTANTS.push(racine);
  for (const n of fs.readdirSync(RACINE)) if (n !== "scripts" && !n.startsWith(".")) fs.symlinkSync(path.join(RACINE, n), path.join(racine, n));
  fs.mkdirSync(path.join(racine, "scripts"));
  const [, dossier] = fichier.split("/");
  for (const d of fs.readdirSync(S())) {
    if (d !== dossier) {
      fs.symlinkSync(S(d), path.join(racine, "scripts", d));
      continue;
    }
    fs.mkdirSync(path.join(racine, "scripts", d));
    for (const f of fs.readdirSync(S(d))) {
      if (`scripts/${d}/${f}` === fichier) {
        const texte = fs.readFileSync(S(d, f), "utf8");
        expect(texte.split(ancien), `motif unique dans ${fichier}`).to.have.length(2);
        fs.writeFileSync(path.join(racine, "scripts", d, f), texte.replace(ancien, nouveau));
      } else fs.symlinkSync(S(d, f), path.join(racine, "scripts", d, f));
    }
  }
  return racine;
}

/** Faux point JSON-RPC : `repondre(method, params)` rend le result. */
function fauxRpc(repondre) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const q = JSON.parse(corps);
    let reponse;
    try {
      reponse = { jsonrpc: "2.0", id: q.id, result: repondre(q.method, q.params) };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: q.id, error: { code: -32000, message: err.message } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((resolve) => serveur.listen(0, "127.0.0.1", () => resolve({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

// ---------------------------------------------------------------------------
// garde de lancement par un lien symbolique
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8 : lancés par un chemin qui passe par un lien symbolique, le vérificateur de renvois et les outils e2e s'exécutent (code et sortie attendus) au lieu de rendre 0 sans rien faire ; mutant (ancienne garde) : code 0 et aucune sortie", function () {
  this.timeout(120000);

  it("verifier-renvois.mjs <argument> → code 2 et le message d'usage ; parcours-registre.mjs --aide → code 0 et l'aide ; mesure-ancrage.mjs sans action → code 2 et l'usage ; mesure-capture-bloc-plein.mjs --repetitions 0 → code 2 et le refus", function () {
    const parLien = (...rel) => path.join(LIEN, "scripts", ...rel);
    const r1 = noeudJs(parLien("conformite", "verifier-renvois.mjs"), ["x"]);
    expect(r1.status, r1.stderr).to.equal(2);
    expect(r1.stderr).to.include("argument inattendu");
    const r2 = noeudJs(parLien("e2e", "parcours-registre.mjs"), ["--aide"]);
    expect(r2.status, r2.stderr).to.equal(0);
    expect(r2.stdout).to.include("Parcours rejouable du registre");
    const r3 = noeudJs(parLien("e2e", "mesure-ancrage.mjs"), []);
    expect(r3.status, r3.stderr).to.equal(2);
    expect(r3.stderr).to.include("usage : node scripts/e2e/mesure-ancrage.mjs");
    const r4 = noeudJs(parLien("e2e", "mesure-capture-bloc-plein.mjs"), ["--repetitions", "0"]);
    expect(r4.status, r4.stderr).to.equal(2);
    expect(r4.stderr).to.include("--repetitions");
    // Mutant : l'ancienne garde (chemin de argv[1] non résolu) remise dans verifier-renvois.mjs ; par le lien, code 0 et 0 octet.
    const racine = racineMutante("garde-renvois", "scripts/conformite/verifier-renvois.mjs", "if (process.argv[1] && fileURLToPath(import.meta.url) === cheminReel(process.argv[1])) {", "if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {");
    const lienM = path.join(TRAVAIL, "lien-mutant");
    fs.symlinkSync(racine, lienM);
    const rm = noeudJs(path.join(lienM, "scripts", "conformite", "verifier-renvois.mjs"), ["x"]);
    expect(rm.status === 2 && rm.stderr.includes("argument inattendu"), `mutant : code ${rm.status}, ${rm.stderr.length} octets (le mutant est tué)`).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
// mesure-finalite.mjs et dev-roundtrip.mjs
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8 : outils de mesure sans secret dans les sorties et bornés au registre de développement", function () {
  this.timeout(180000);
  const CLE_FAUTIVE = `0x${"c3".repeat(32)}"`; // guillemet resté collé : clé presque entière
  const CLE_OK = Wallet.createRandom().privateKey;
  const APPROBATEURS = [0, 1, 2].map(() => Wallet.createRandom().privateKey).join(",");
  const FINALITE = S("e2e", "mesure-finalite.mjs");

  it("une clé NOOR_PRIVATE_KEY ou NOORTRACE_APPROVER_KEYS mal saisie est refusée (code 2) sans que la saisie soit recopiée ; une NOOR_RPC_URL à identifiants ou à chaîne de requête est refusée sans que le secret soit recopié", function () {
    const r1 = noeudJs(FINALITE, [], { env: { NOOR_PRIVATE_KEY: CLE_FAUTIVE, NOORTRACE_APPROVER_KEYS: APPROBATEURS, NOOR_RPC_URL: "http://127.0.0.1:1" } });
    expect(r1.status, r1.stderr).to.equal(2);
    expect(r1.stderr).to.include("NOOR_PRIVATE_KEY");
    expect(r1.stderr + r1.stdout).to.not.include("c3c3c3c3");
    const r2 = noeudJs(FINALITE, [], { env: { NOOR_PRIVATE_KEY: CLE_OK, NOORTRACE_APPROVER_KEYS: `${APPROBATEURS},${CLE_FAUTIVE}`, NOOR_RPC_URL: "http://127.0.0.1:1" } });
    expect(r2.status, r2.stderr).to.equal(2);
    expect(r2.stderr).to.include("NOORTRACE_APPROVER_KEYS, clé de rang 4");
    expect(r2.stderr + r2.stdout).to.not.include("c3c3c3c3");
    const r3 = noeudJs(FINALITE, [], { env: { NOOR_PRIVATE_KEY: CLE_OK, NOORTRACE_APPROVER_KEYS: APPROBATEURS, NOOR_RPC_URL: "http://utilisateur:jeton-factice-secret@127.0.0.1:1/rpc?cle=autre-secret" } });
    expect(r3.status, r3.stderr).to.equal(2);
    expect(r3.stderr).to.include("NOOR_RPC_URL");
    expect(r3.stderr + r3.stdout).to.not.include("jeton-factice-secret");
    expect(r3.stderr + r3.stdout).to.not.include("autre-secret");
  });

  it("une URL hors de la boucle locale est refusée sans --reseau-distant ; un point dont eth_chainId n'est ni 2121 à 2124 ni 31337 est refusé (code 2) avant toute écriture, même avec --reseau-distant ; mutant (garde de l'identifiant retirée) : l'outil continue", async function () {
    const r1 = noeudJs(FINALITE, [], { env: { NOOR_PRIVATE_KEY: CLE_OK, NOORTRACE_APPROVER_KEYS: APPROBATEURS, NOOR_RPC_URL: "http://192.0.2.1:1" } });
    expect(r1.status, r1.stderr).to.equal(2);
    expect(r1.stderr).to.include("boucle locale");
    // Faux point d'un réseau d'identifiant 1, avec un déploiement et une organisation qui le déclarent : refus par l'identifiant.
    const dep = path.join(TRAVAIL, "deployments-identifiant");
    fs.mkdirSync(dep, { recursive: true });
    const adresse = "0x" + "11".repeat(20);
    fs.writeFileSync(path.join(dep, "prod.json"), JSON.stringify({ reseau: "prod", chainId: "1", deployeur: adresse, contrats: Object.fromEntries(["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n) => [n, { adresse, bloc: 1, tx: "0x" + "00".repeat(32) }])) }));
    fs.writeFileSync(path.join(dep, "prod-orgs.json"), JSON.stringify({ reseau: "prod", chainId: "1", curatorSetRegistry: adresse, organisations: { client: { slug: "client", orgId: "0x" + "22".repeat(32), curatorSet: adresse, approbateurs: APPROBATEURS.split(",").map((k) => new Wallet(k).address), seuil: 2 } } }));
    let appels = [];
    const faux = await fauxRpc((m, p) => {
      appels.push(m);
      if (m === "eth_chainId") return "0x1";
      if (m === "eth_getCode") return "0x6080";
      throw new Error(`${m} non servi`);
    });
    try {
      const env = { NOOR_PRIVATE_KEY: CLE_OK, NOORTRACE_APPROVER_KEYS: APPROBATEURS, NOOR_RPC_URL: faux.url, NOORTRACE_DEPLOYMENTS_DIR: dep };
      const r2 = await noeudAsync(FINALITE, ["--network", "prod", "--reseau-distant"], { env });
      expect(r2.status, r2.stderr).to.equal(2);
      expect(r2.stderr).to.match(/hors des réseaux de développement/);
      expect(appels.filter((m) => m === "eth_sendRawTransaction"), "rien n'est envoyé").to.deep.equal([]);
      expect(appels.filter((m) => m !== "eth_chainId"), "la garde arrête l'outil au premier appel").to.deep.equal([]);
      // Mutant : la garde de l'identifiant retirée ; l'outil continue vers les contrats (oracle : code 2 par la garde).
      const racine = racineMutante("garde-reseau", "scripts/e2e/mesure-finalite.mjs", "  if (!RESEAUX_DEVELOPPEMENT.has(chainId)) throw new Refus(", "  if (false) throw new Refus(");
      appels = [];
      const rm = await noeudAsync(path.join(racine, "scripts", "e2e", "mesure-finalite.mjs"), ["--network", "prod", "--reseau-distant"], { env });
      expect(rm.status === 2 && /hors des réseaux de développement/.test(rm.stderr), `mutant : code ${rm.status}, ${rm.stderr.slice(0, 200)} (le mutant est tué)`).to.equal(false);
      expect(appels.length, "mutant : l'outil a continué au-delà de l'identifiant").to.be.greaterThan(1);
    } finally {
      faux.serveur.close();
    }
  });

  it("CT-4 EX-7.2 : dev-roundtrip.mjs refuse une clé d'approbateur mal saisie sans la recopier (réseau Hardhat en mémoire)", function () {
    const r = noeudJs(S("e2e", "dev-roundtrip.mjs"), ["--network", "hardhat"], { env: { NOORTRACE_APPROVER_KEYS: `${APPROBATEURS},${CLE_FAUTIVE}`.split(",").slice(1).join(",") } });
    expect(r.status, r.stderr).to.equal(1);
    expect(r.stderr).to.include("NOORTRACE_APPROVER_KEYS, clé de rang 3");
    expect(r.stderr + r.stdout).to.not.include("c3c3c3c3");
    expect(fs.readFileSync(S("e2e", "dev-roundtrip.mjs"), "utf8")).to.include("RESEAUX_DEVELOPPEMENT.has(BigInt(chainId))");
  });
});

// ---------------------------------------------------------------------------
// CT-9 EX-11.11, CT-9 EX-9.2, CT-9 TE-4 : mesures et parcours
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8, CT-9 EX-11.11, CT-9 EX-9.2 : rien d'inventé dans les rapports de mesure, verdict de TE-4, textes des en-têtes", function () {
  this.timeout(60000);

  it("CT-9 EX-11.11 : nombreCalendriers lit la preuve du manifeste (null sans preuve lisible, jamais 2 d'office) ; descriptionMachine dérive du système relevé ; codeDeCollecte rend 1 quand les exports ont été interrompus ; typeDisque rend une valeur de l'énumération, mesurée ; mesure-capture-bloc-plein lit spec_version dans le catalogue ; mutant (code de collecte constant) : l'oracle échoue", async function () {
    const R = await importer(S("e2e", "mesure-ancrage-rapport.mjs"));
    expect(R.nombreCalendriers([{ fichier: "manifeste-abc.ots", attestations_en_attente: 1, hauteurs_attestees: null }])).to.equal(1);
    expect(R.nombreCalendriers([{ fichier: "manifeste-abc.ots", attestations_en_attente: 1, hauteurs_attestees: 1 }])).to.equal(2);
    expect(R.nombreCalendriers([{ fichier: "point-1.ots", attestations_en_attente: 2 }]), "une preuve de point ne compte pas pour le manifeste").to.equal(null);
    expect(R.nombreCalendriers([{ fichier: "manifeste-abc.ots", attestations_en_attente: null, hauteurs_attestees: null }])).to.equal(null);
    expect(R.nombreCalendriers([])).to.equal(null);
    expect(R.descriptionMachine({ virtualized: true, disk: { type: "virtuel" }, load_avg_1m: 0.5 })).to.include("machine virtuelle, disque virtuel, charge moyenne sur une minute relevée à la collecte : 0.5");
    expect(R.descriptionMachine({ virtualized: null, disk: { type: "inconnu" } })).to.include("virtualisation non établie");
    expect(R.descriptionMachine(null)).to.not.include("KVM");
    const A = await importer(S("e2e", "mesure-ancrage.mjs"));
    expect(A.codeDeCollecte({ evenements: { exports_erreur: null } })).to.equal(0);
    expect(A.codeDeCollecte({ evenements: { exports_erreur: "seq 12 : export interrompu" } })).to.equal(1);
    const D = await importer(S("e2e", "reseau-dev.mjs"));
    expect(["nvme", "ssd", "hdd", "virtuel", "memoire", "inconnu"]).to.include(D.typeDisque(RACINE));
    expect(D.typeDisque("/chemin/qui/n/existe/pas")).to.equal("inconnu");
    expect(A.systeme().disk).to.deep.equal({ type: D.typeDisque(RACINE), fsync: null });
    const source = fs.readFileSync(S("e2e", "mesure-capture-bloc-plein.mjs"), "utf8");
    expect(source).to.not.match(/spec_version: "0\.1"/);
    expect(source).to.include("spec_version: lireJson(CATALOGUE).spec_version");
    expect(source).to.not.include("non encore commité");
    expect(source).to.match(/existe déjà : un rapport n'est jamais remplacé/);
    expect(fs.readFileSync(S("e2e", "mesure-ancrage-rapport.mjs"), "utf8")).to.match(/existe déjà : un rapport n'est jamais remplacé/);
    // Mutant : codeDeCollecte rend toujours 0 (oracle : 1 sur une collecte interrompue).
    const racine = racineMutante("code-collecte", "scripts/e2e/mesure-ancrage.mjs", "  return collecte?.evenements?.exports_erreur ? 1 : 0;", "  return 0;");
    const M = await importer(path.join(racine, "scripts", "e2e", "mesure-ancrage.mjs"));
    expect(M.codeDeCollecte({ evenements: { exports_erreur: "seq 12 : export interrompu" } }), "mutant (le mutant est tué)").to.not.equal(1);
  });

  it("CT-9 EX-9.2 : verdictFinal rend echoue et code 1 quand les deux vérificateurs divergent, quand l'un rend un code non nul, ou quand aucun bloc n'a exigé de certificat ; reussi et 0 sinon ; mutant (divergence ignorée) : reussi malgré la divergence", async function () {
    const P = await importer(S("e2e", "parcours-registre.mjs"));
    const bon = { reference: { exit_code: 0 }, go: { exit_code: 0 }, parity: { equal: true, differences: [] }, blocks: [10, 11] };
    expect(P.verdictFinal(bon)).to.deep.equal({ code: 0, result: "reussi", error: null });
    const d1 = P.verdictFinal({ ...bon, parity: { equal: false, differences: ["R-4 : référence reussi, Go echoue"] } });
    expect(d1.code).to.equal(1);
    expect(d1.result).to.equal("echoue");
    expect(d1.error).to.include("R-4 : référence reussi, Go echoue");
    expect(P.verdictFinal({ ...bon, go: { exit_code: 1 } }).code).to.equal(1);
    expect(P.verdictFinal({ ...bon, reference: null }).code).to.equal(1);
    expect(P.verdictFinal({ ...bon, blocks: [] }).error).to.include("aucun bloc");
    expect(P.verdictFinal({ ...bon, parity: null }).code).to.equal(1);
    // Le parcours emploie ce verdict et verdict.json ne porte que le nom du répertoire d'essai.
    const source = fs.readFileSync(S("e2e", "parcours-registre.mjs"), "utf8");
    expect(source).to.include("const fin = verdictFinal({ reference: ref, go: gov, parity: verdict.verifiers.parity, blocks: verdict.blocks });");
    expect(source).to.include("essai: path.basename(E),");
    const racine = racineMutante("parite", "scripts/e2e/parcours-registre.mjs", "  if (!parity || parity.equal !== true) motifs.push(", "  if (false) motifs.push(");
    const M = await importer(path.join(racine, "scripts", "e2e", "parcours-registre.mjs"));
    expect(M.verdictFinal({ ...bon, parity: { equal: false, differences: ["R-4"] } }).result, "mutant (le mutant est tué)").to.not.equal("echoue");
  });

  it("CT-9 TE-4 : les en-têtes de parcours-registre.mjs et reseau-dev.mjs disent ce que le code écrit (rien de suivi par git ; hh-artifacts/, deployments/, chain/runtime/ ignorés de git)", function () {
    const p = fs.readFileSync(S("e2e", "parcours-registre.mjs"), "utf8");
    expect(p).to.not.include("jamais dans le\n// dépôt");
    expect(p).to.include("Rien de suivi par git n'est écrit");
    expect(p).to.include("hh-artifacts/");
    expect(p).to.include("deployments/");
    expect(p).to.include("chain/runtime/");
    const r = fs.readFileSync(S("e2e", "reseau-dev.mjs"), "utf8");
    expect(r).to.not.include("Rien ici n'écrit dans le dépôt");
    expect(r).to.include("Rien de suivi par git n'est écrit");
  });
});

// ---------------------------------------------------------------------------
// CT-7 EX-7.3 : attestation.mjs
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8 (CT-7 EX-7.3, §7.4) : attestation.mjs", function () {
  this.timeout(60000);
  const ATT = S("conformite", "attestation.mjs");
  const EXEMPLE = path.join(RACINE, "spec", "vecteurs", "ct-7", "attestations", "exemple");

  it("(a) verifier --forme d'une attestation signée rend 0 sans exiger --jeu et sans exécuter AT-2 à AT-4 ; sans --forme, --jeu reste exigé (code 2)", function () {
    const r = noeudJs(ATT, ["verifier", path.join(EXEMPLE, "attestation-signee.json"), "--forme"]);
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.include("Forme : AT-1 réussie");
    expect(r.stdout).to.not.match(/AT-4/);
    const r2 = noeudJs(ATT, ["verifier", path.join(EXEMPLE, "attestation-signee.json")]);
    expect(r2.status).to.equal(2);
    expect(r2.stderr).to.include("--jeu");
    expect(noeudJs(ATT, ["verifier", path.join(EXEMPLE, "attestation.json"), "--forme"]).status).to.equal(0);
  });

  it("(b) un fichier dont le JSON est null, un nombre ou une liste rend 2 (entrée illisible) avec un message, jamais 1 ni une exception", function () {
    for (const [nom, contenu] of [["nul.json", "null"], ["nombre.json", "12"], ["liste.json", "[]"]]) {
      const f = path.join(TRAVAIL, nom);
      fs.writeFileSync(f, contenu);
      const r = noeudJs(ATT, ["verifier", f]);
      expect(r.status, `${nom} : ${r.stderr}`).to.equal(2);
      expect(r.stderr).to.include("un objet JSON est attendu");
      expect(r.stderr).to.not.include("TypeError");
      const c = noeudJs(ATT, ["condenser", f]);
      expect(c.status, `condenser ${nom}`).to.equal(2);
    }
  });

  it("(c) signer --cle fichier: refuse un fichier de clé lisible par le groupe ou les autres (code 2, chmod 600), rien n'est signé ; un fichier en 0600 est signé (--oui) ; le mode est contrôlé avant la clé", function () {
    const cle = Wallet.createRandom().privateKey;
    const ouvert = path.join(TRAVAIL, "cle-ouverte.hex");
    fs.writeFileSync(ouvert, cle + "\n", { mode: 0o644 });
    fs.chmodSync(ouvert, 0o644);
    const r = noeudJs(ATT, ["signer", path.join(EXEMPLE, "attestation.json"), "--cle", `fichier:${ouvert}`, "--oui"]);
    expect(r.status, r.stderr).to.equal(2);
    expect(r.stderr).to.include("chmod 600");
    expect(r.stdout).to.not.include('"signature"');
    const ferme = path.join(TRAVAIL, "cle-fermee.hex");
    fs.writeFileSync(ferme, cle + "\n", { mode: 0o600 });
    fs.chmodSync(ferme, 0o600);
    const ok = noeudJs(ATT, ["signer", path.join(EXEMPLE, "attestation.json"), "--cle", `fichier:${ferme}`, "--oui"]);
    expect(ok.status, ok.stderr).to.equal(0);
    const sortie = JSON.parse(ok.stdout.slice(ok.stdout.indexOf("{\n  \"address\"")));
    expect(sortie.address.toLowerCase()).to.equal(new Wallet(cle).address.toLowerCase());
    expect(sortie.signature).to.match(/^0x[0-9a-f]{130}$/);
    const mauvaise = path.join(TRAVAIL, "cle-mauvaise.hex");
    fs.writeFileSync(mauvaise, "0x1234\n", { mode: 0o600 });
    fs.chmodSync(mauvaise, 0o600);
    expect(noeudJs(ATT, ["signer", path.join(EXEMPLE, "attestation.json"), "--cle", `fichier:${mauvaise}`, "--oui"]).status).to.equal(2);
  });
});

// ---------------------------------------------------------------------------
// CT-4 EX-7.2 : bootstrap-org.mjs
// ---------------------------------------------------------------------------

describe("Revue de sécurité de l'étape 8, CT-4 EX-7.2 : bootstrap-org.mjs ne remplace le jeu d'une organisation inscrite que sur un réseau de développement ou d'essai, ou avec --remplacer", function () {
  this.timeout(60000);

  it("refusRemplacement : organisation non inscrite → admis ; inscrite sur 2124, 31337 → admis ; inscrite sur 1 → refus nommé sans --remplacer, admis avec ; identifiant illisible → refus ; le module n'exécute rien à l'import ; mutant (refus retiré) : admis sur 1", async function () {
    const B = await importer(S("deploy", "bootstrap-org.mjs"));
    expect(B.refusRemplacement({ chainId: "1", inscrite: false, remplacer: false })).to.equal(null);
    expect(B.refusRemplacement({ chainId: "2124", inscrite: true, remplacer: false })).to.equal(null);
    expect(B.refusRemplacement({ chainId: 31337n, inscrite: true, remplacer: false })).to.equal(null);
    const refus = B.refusRemplacement({ chainId: "1", inscrite: true, remplacer: false });
    expect(refus).to.be.a("string");
    expect(refus).to.include("--remplacer");
    expect(refus).to.include("EX-8.10");
    expect(B.refusRemplacement({ chainId: "1", inscrite: true, remplacer: true })).to.equal(null);
    expect(B.refusRemplacement({ chainId: "abc", inscrite: true, remplacer: true })).to.include("illisible");
    const source = fs.readFileSync(S("deploy", "bootstrap-org.mjs"), "utf8");
    expect(source).to.include("const refus = refusRemplacement({ chainId: deployment.chainId, inscrite, remplacer: args.remplacer === true });");
    const racine = racineMutante("remplacement", "scripts/deploy/bootstrap-org.mjs", "  if (remplacer === true) return null;\n  return `l'organisation est déjà inscrite", "  return null;\n  return `l'organisation est déjà inscrite");
    const M = await importer(path.join(racine, "scripts", "deploy", "bootstrap-org.mjs"));
    expect(M.refusRemplacement({ chainId: "1", inscrite: true, remplacer: false }), "mutant (le mutant est tué)").to.equal(null);
  });
});
