// Garde des essais en attente du travail `tests` de l'intégration continue
// (scripts/tests/attentes.mjs ; revue de sécurité de l'étape 8, CT-9
// EX-5.4) : un essai en attente ne passe que pour une condition
// nommée et admise ; un échec, une attente sans condition ou hors de la liste
// font échouer le travail. La condition admise est la condition principale
// (début du texte jusqu'au premier « ; », « : » ou « ( ») : une attente sans
// condition réelle qui cite une ressource au passage est refusée.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { controler, ADMISES, admise, conditionPrincipale } from "../scripts/tests/attentes.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUTIL = path.join(RACINE, "scripts", "tests", "attentes.mjs");

const rapport = ({ reussis = 3, attentes = [], echecs = 0 }) =>
  [
    "  CT-9 : essais",
    "    ✔ un essai",
    ...attentes.map((t) => `    - ${t}`),
    "",
    `  ${reussis} passing (2s)`,
    ...(attentes.length ? [`  ${attentes.length} pending`] : []),
    ...(echecs ? [`  ${echecs} failing`] : []),
    "",
  ].join("\n");

function lancer(texte) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-attentes-"));
  try {
    const f = path.join(d, "sortie.txt");
    fs.writeFileSync(f, texte);
    return spawnSync(process.execPath, [OUTIL, f], { encoding: "utf8" });
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
}

describe("scripts/tests/attentes.mjs : garde des essais en attente du travail tests (CT-9 EX-5.4)", function () {
  it("attentes nommées et admises (Docker, Chromium, go1.27.3, réseau de développement, compte 0) : code 0 ; la liste admise est nommée dans l'outil", function () {
    const attentes = [
      "TA-29 (MN-29) : … — en attente : Docker absent ou démon dockerd injoignable",
      "TA-35 (MN-35) : … — en attente : Chromium par Playwright indisponible (navigateur absent) (CT-3 EX-13.36)",
      "binaire : … — en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN ou PATH)",
      "TM-31 : … — en attente : réseau de développement arrêté (bash chain/scripts/dev-net.sh start)",
      "parcours : … — en attente : compte 0 requis pour chown",
    ];
    const r = lancer(rapport({ attentes }));
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stdout).to.include("3 réussis, 0 échec(s), 5 en attente (5 titres lus)");
    expect(ADMISES.length).to.be.at.least(10);
  });

  it("un essai en attente sans condition nommée, ou pour une condition hors de la liste, fait échouer (code 1) et est nommé sur la sortie d'erreur", function () {
    const sansCondition = lancer(rapport({ attentes: ["un essai vidé"] }));
    expect(sansCondition.status).to.equal(1);
    expect(sansCondition.stderr).to.include("attente non admise : un essai vidé");
    const horsListe = lancer(rapport({ attentes: ["x — en attente : variable NOORTRACE_INCONNUE absente"] }));
    expect(horsListe.status).to.equal(1);
    expect(horsListe.stderr).to.include("variable NOORTRACE_INCONNUE absente");
  });

  it("condition principale : début du texte jusqu'au premier « ; », « : » ou « ( » précédé d'une espace, sans crochet fermant final", function () {
    expect(conditionPrincipale("Docker absent ou démon dockerd injoignable")).to.equal("Docker absent ou démon dockerd injoignable");
    expect(conditionPrincipale("démon Docker injoignable (docker info)")).to.equal("démon Docker injoignable");
    expect(conditionPrincipale("Chromium indisponible : import(\"playwright\") a échoué (ERR)")).to.equal("Chromium indisponible");
    expect(conditionPrincipale("go1.27.3 absent (NOORTRACE_GO_BIN ou PATH) : aucune page à servir")).to.equal("go1.27.3 absent");
    expect(conditionPrincipale("Docker absent ou démon dockerd injoignable ; image noortrace/x:1 absente")).to.equal("Docker absent ou démon dockerd injoignable");
    expect(conditionPrincipale("compte 0 requis pour chown]")).to.equal("compte 0 requis pour chown");
    expect(conditionPrincipale("le validateur http://127.0.0.1:8545 ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)")).to.equal("le validateur http://127.0.0.1:8545 ne répond pas eth_chainId 0x84c");
  });

  it("attente inconditionnelle qui cite Docker au passage (TE-9, chemin B et chemin C hors de l'essai) : refusée, code 1, condition principale nommée ; une ressource citée après « ; », « : » ou « ( », ou hors du début du texte, n'est pas admise", function () {
    const te9 = "TE-9 : chemin B (copies WORM) et chemin C (journal neuf) — hors de cet essai — en attente : chemin B éprouvé par test/enregistreur-worm-restauration.test.js (simulateur S3 à verrouillage, Docker) ; chemin C : rotation de chaîne et journal neuf au registre, étape 8 ; TM-37 sur le système de référence de CT-9 §11.1";
    const r = lancer(rapport({ attentes: [te9] }));
    expect(r.status).to.equal(1);
    expect(r.stderr).to.include("(condition principale : « chemin B éprouvé par test/enregistreur-worm-restauration.test.js »)");
    for (const c of [
      "essai écrit plus tard (Docker absent)",
      "hors de cet essai ; Docker absent ou démon dockerd injoignable",
      "partie non jouée : go1.27.3 absent",
      "rattaché ailleurs, Docker absent",
      "voir le travail images : Docker",
      "le parcours npm run e2e:registre a échoué (code 1)",
      "procès-verbal du banc absent sous NOORTRACE_BANC_CLIENT (/x)",
      "composition non lancée",
      "contexte non préparé",
    ]) expect(admise(c), c).to.equal(false);
  });

  it("chaque condition d'environnement des essais de la suite est admise par sa condition principale (textes relevés dans test/, détails compris)", function () {
    // Textes tels que les essais les écrivent (substitutions remplacées par une valeur plausible) : relevé statique des
    // appels enAttente, des conditions des fixtures et des titres « en attente : » de test/ (étape 8).
    const legitimes = [
      "Docker absent ou démon dockerd injoignable",
      "démon Docker injoignable (docker info)",
      "Docker Compose absent",
      "greffon docker compose absent",
      "image(s) absente(s) du magasin local : noortrace/enregistreur:0.1.0 (node scripts/deploiement/construire-images.mjs ; node demo/construire-images.mjs)",
      "images absentes du magasin local (noortrace/enregistreur:0.1.0) : node scripts/deploiement/construire-images.mjs (la construction joint les registres publics ; un essai ne construit pas)",
      "image absente du magasin local : noortrace/tsa-interne:0.1.0 (node scripts/deploiement/construire-images.mjs --images tsa-interne)",
      "image noortrace/squid:6.13 non construite (docker build en échec : refus)",
      "image minio/minio:RELEASE.2025 indisponible (docker pull en échec)",
      "image noortrace/enregistreur:0.1.0 absente (étape 7 : docker load de noortrace-images-0.1.0.tar ; images d'essai)",
      "Docker absent ou démon dockerd injoignable ; KMS simulé indisponible",
      "serveur S3 appliquant les politiques IAM indisponible",
      "procès-verbal du banc absent : lancer node scripts/deploiement/banc-client-fictif.mjs --travail <rép.> (plus d'une heure) ; ou NOORTRACE_BANC_LANCER=1",
      "Chromium indisponible : import(\"playwright\") a échoué (ERR_MODULE_NOT_FOUND)",
      "Chromium ne se lance pas (browserType.launch: Executable doesn't exist)",
      "Chromium par Playwright indisponible (navigateur absent) (CT-3 EX-13.36)",
      "firefox ne se lance pas : browserType.launch: Executable doesn't exist",
      "Playwright absent (require(\"playwright\") : MODULE_NOT_FOUND)",
      "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)",
      "go1.27.3 introuvable (NOORTRACE_GO_BIN ou PATH), dossier non soumis au binaire Go",
      "chaîne de compilation Go 1.27.3 introuvable (NOORTRACE_GO_BIN) pour construire noortrace-verifier",
      "NOORTRACE_GO_BIN désigne un répertoire avec go1.27.3 et verificateur/scripts/construire.sh réussit",
      "binaire du vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérificateur JavaScript jugé seul",
      "binaire Go de CT-6 absent (NOORTRACE_VERIFIER_BIN)",
      "vérificateur Go de CT-6 (NOORTRACE_VERIFIER_BIN, NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64) : vérification JavaScript faite, vérification Go non faite",
      "vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérification JavaScript faite, vérification Go non faite",
      "binaire noortrace-verifier absent (NOORTRACE_VERIFIER_BIN)",
      "environnement Python 3.12 absent (paquets/sdk-python/.environnements/py312 ; paquets/sdk-python/outils/environnements.sh preparer py312)",
      "environnement du cadre CrewAI absent (paquets/sdk-python/.environnements/crewai ; preparer crewai)",
      "environnement du cadre absent (paquets/sdk-python/.environnements/langchain ; preparer langchain)",
      "environnement du mandataire absent (paquets/sdk-python/.environnements/litellm, litellm[proxy]==1.106.4 ; preparer litellm)",
      "environnement absent (paquets/sdk-python/.environnements/py310 ; paquets/sdk-python/outils/environnements.sh preparer py310)",
      "environnement integration-anthropic absent (paquets/sdk-python/.environnements/integration-anthropic ; preparer integration-anthropic)",
      "strace absent (relevé des connexions sortantes de l'hôte ; installé par le travail integrations)",
      "binaire noortrace-verifier absent (NOORTRACE_VERIFIER_BIN, ou verificateur/dist/noortrace-verifier-linux-amd64 ; construit par le travail integrations)",
      "SDK @anthropic-ai/sdk 1.3.0 non installé (absent ; installé à cette version, hors de package.json, par le travail integrations de l'intégration continue : npm install --no-save ; ou NOORTRACE_MODULES_INTEGRATION)",
      "SDK @google/genai 2.31.0 non installé (version 2.30.0 trouvée ; installé à cette version, hors de package.json, par le travail integrations de l'intégration continue : npm install --no-save ; ou NOORTRACE_MODULES_INTEGRATION)",
      "interpréteur Python aux versions d'exigences.txt absent (NOORTRACE_PYTHON_CONFRONTATION ou python3 ; travail confrontation)",
      "module github.com/transparency-dev/merkle absent du cache de modules Go (GOPROXY=off ; travail confrontation)",
      "NOORTRACE_CT8_SORTIES absent (sorties rejouées hors du test par le travail confrontation)",
      "python-opentimestamps absent (variable NOORTRACE_OTS_PYTHON, ou python3 qui importe « opentimestamps » ; travail ancrage)",
      "relevé de deux constructions absent (node scripts/deploiement/construire-images.mjs --double --sortie <rép>, puis NOORTRACE_IMAGES_CONDENSES=<rép>/condenses.json)",
      "compte 0 (CAP_LINUX_IMMUTABLE) requis pour poser a et i",
      "compte 0 requis pour chown]",
      "compte 0 requis (chown vers 0:10010)",
      "setpriv absent (démon sans CAP_LINUX_IMMUTABLE)",
      "superutilisateur requis : préparation du répertoire du pont (chown 10101)",
      "superutilisateur requis : propriétaire et groupe du répertoire des exports",
      "l'essai sous un second compte exige le superutilisateur",
      "le démon doit être lancé par le superutilisateur pour lancer le serveur stdio sous un utilisateur distinct (EX-3.5)",
      "essai hors du compte root : l'attribut immuable et la réécriture de la configuration possédée par le compte 10001 exigent root sur l'hôte",
      "le réseau de développement n'est pas debout (fetch failed) : bash chain/scripts/dev-net.sh start",
      "le réseau de développement ne répond pas eth_chainId 0x84c sur http://127.0.0.1:8545 (bash chain/scripts/dev-net.sh start)",
      "réseau de développement 2124 absent (bash chain/scripts/dev-net.sh start)",
      "réseau de développement arrêté (bash chain/scripts/dev-net.sh start)",
      "le validateur http://127.0.0.1:8545 ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)",
      "le validateur http://127.0.0.1:8546 ne répond pas (quatre validateurs attendus)",
      "le binaire noorcore ne sert pas noor_getCommitCertificate (CT-4 §9.1)",
      "binaire noorcore absent (chain/runtime/bin/noorcore) : le construire avec le correctif du certificat de commit (chain/scripts/build-noorcore.sh, chain/patches/LISEZMOI.md) (EX-3.11 de CT-9)",
      "aucun parcours d'inscription (NOORTRACE_PARCOURS_REGISTRE) et vérificateur Go de CT-6 absent pour exécuter npm run e2e:registre",
      "NOORTRACE_RESEAU_PUBLIC=1 (réseau public joignable : soumission réelle aux agrégateurs OpenTimestamps)",
      "NOORTRACE_TSA_PUBLIQUE=1 (prestataire RFC 3161 public)",
      "réseau public joignable (NOORTRACE_TSA_PUBLIQUE=1)",
      "machine vierge Ubuntu 24.04 avec ses sources de paquets (flux FL-31, réseau public) et l'archive node-v22.23.4-linux-x64.tar.xz ; NOORTRACE_ESSAI_HOTE_VIERGE=1 et NOORTRACE_ARCHIVE_NODE",
      "SoftHSM2 absent (softhsm2-util)",
      "swtpm absent",
      "tpm2-tools absent (tpm2_startup)",
      "binaire prometheus 3.5.0 absent (même archive que promtool, CT-8 EX-10.10 : Prometheus 3.5.0 pour Linux amd64 à SHA-256 fixé ; variable NOORTRACE_PROMETHEUS ou PATH)",
      "bibliothèque libfaketime 0.9.10-2.1 (Debian 12, libfaketime.so.1 à SHA-256 45c4822a…6629a0) absente : variable NOORTRACE_LIBFAKETIME",
      "la machine n'offre pas d'IPv6 (::1 injoignable)",
      "IPv6 indisponible (la machine n'offre pas d'IPv6)",
      "les essais précédents n'ont pas abouti",
    ];
    for (const c of legitimes) expect(admise(c), `${c} → « ${conditionPrincipale(c)} »`).to.equal(true);
    // Sur un rapport : les mêmes conditions en suffixe de titre (« — en attente : »), code 0.
    const r = lancer(rapport({ attentes: legitimes.map((c, k) => `essai ${k} — en attente : ${c}`) }));
    expect(r.status, r.stderr).to.equal(0);
    // Chaque attente admise est ancrée au début de la condition principale.
    for (const a of ADMISES) expect(a.source.startsWith("^"), a.source).to.equal(true);
  });

  it("la suite entière se charge : le lanceur d'essai de l'agent d'inscription et l'agent OpenTelemetry (fichiers JavaScript de test/, chargés par Hardhat) ne terminent pas le processus et ne se connectent à rien au chargement ; un rapport coupé, sans « N passing », fait échouer la garde", function () {
    for (const f of ["test/fixtures/inscription/agent-essai.mjs", "test/fixtures/integrations/agents/otel_agent.mjs"]) {
      // Même argv que Hardhat (hardhat test) : le module est importé, rien ne s'exécute.
      const code = `process.argv = [process.argv[0], ${JSON.stringify(path.join(RACINE, "node_modules", ".bin", "hardhat"))}, "test"]; await import(${JSON.stringify(path.join(RACINE, f))}); process.stdout.write("chargé\\n");`;
      const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { cwd: RACINE, encoding: "utf8", timeout: 60000, env: { ...process.env, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: "http://127.0.0.1:9/v1/traces" } });
      expect([r.status, r.stdout, r.stderr], f).to.deep.equal([0, "chargé\n", ""]);
    }
    expect(lancer("Running Mocha tests\nusage : agent-essai.mjs --config <fichier>\n").status).to.equal(1);
  });

  it("un échec, un nombre d'attentes différent des titres lus, un rapport sans ligne passing : code 1 ; usage incorrect : code 2", function () {
    expect(lancer(rapport({ echecs: 1 })).status).to.equal(1);
    const texte = rapport({ attentes: ["x — en attente : Docker absent ou démon dockerd injoignable"] }).replace("  1 pending", "  2 pending");
    expect(lancer(texte).status).to.equal(1);
    expect(lancer("rien\n").status).to.equal(1);
    expect(spawnSync(process.execPath, [OUTIL], { encoding: "utf8" }).status).to.equal(2);
    // Les comptes de plusieurs fichiers (sorties concaténées) s'additionnent.
    const deux = controler(rapport({ reussis: 2 }) + rapport({ reussis: 5, attentes: ["y — en attente : IPv6 indisponible (la machine n'offre pas d'IPv6)"] }));
    expect([deux.reussis, deux.nAttente, deux.nonAdmises]).to.deep.equal([7, 1, []]);
  });
});
