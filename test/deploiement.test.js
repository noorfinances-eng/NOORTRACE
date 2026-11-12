import { expect } from "chai";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as D from "../scripts/lib/deploiement.mjs";
import * as V from "../scripts/vecteurs/ct8/deploiement.mjs";
import { configurationRapide } from "../scripts/deploiement/configurer-rapide.mjs";
import { verifierRenvois, identifiantsCites, definisCT8, tableTC } from "../scripts/deploiement/renvois.mjs";

// DÉPLOIEMENT DE RÉFÉRENCE DE CT-8 (spec/CT-8-deploiement-et-exploitation.md,
// sections 4, 6, 7.3, 9 et 0.2 ; annexes A.2 à A.5, EX-A.17), sans réseau ni
// moteur de conteneurs : fichiers de deploiement/ (SHA-256, contenu égal aux
// blocs de CT-8, CO-1 à CO-14), configuration de l'installation rapide,
// familles conteneurs/, controle-prealable/ et dimensionnement/ rejouées
// (sorties et codes des trois outils), exemples et tables de 6.3, 9.5, 9.6 et
// d'EX-14.2, renvois de §0.2, chaînes interdites, mesures de 9.2, collecte
// du contrôle préalable sur la machine qui exécute les tests.

const SPEC = path.join(PROJECT_ROOT, "spec");
const DEP = path.join(PROJECT_ROOT, "deploiement");
const VECT = path.join(SPEC, "vecteurs", "ct-8");
const OUTILS = path.join(PROJECT_ROOT, "scripts", "deploiement");
const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const lireJSON = (...p) => JSON.parse(lire(...p));
const sha = (t) => crypto.createHash("sha256").update(t).digest("hex");
const blocs = (md, marque) => [...md.matchAll(new RegExp(`<!-- schema: ${marque.replace("/", "\\/")} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g"))].map((m) => m[1]);
/** Section de CT-8 entre deux titres. */
const section = (debut, fin) => {
  const i = CT8.indexOf(debut);
  return CT8.slice(i, CT8.indexOf(fin, i + debut.length));
};
const SCHEMAS = Object.fromEntries(["conteneurs", "controle-prealable", "dimensionnement"].map((n) => [n, D.chargerSchema(n)]));
const DESCRIPTION = lireJSON(DEP, "images", "images.json");

const TRAVAIL = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-test-deploiement-"));
after(() => fs.rmSync(TRAVAIL, { recursive: true, force: true }));

/** Lance un outil de scripts/deploiement/ ; rend { status, stdout, stderr }. */
const outil = (nom, args) => spawnSync(process.execPath, [path.join(OUTILS, nom), ...args], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 16 * 1024 * 1024 });

/** Parcours récursif des fichiers d'un répertoire. */
function* fichiers(rep) {
  for (const e of fs.readdirSync(rep, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = path.join(rep, e.name);
    if (e.isDirectory()) yield* fichiers(p);
    else yield p;
  }
}

describe("CT-8 §4 : fichiers de conteneur de référence", function () {
  for (const [nom, sec, fin] of [["rapide.yaml", "### 4.2 ", "### 4.3 "], ["production.yaml", "### 4.3 ", "### 4.4 "]]) {
    it(`${nom} : SHA-256 et contenu égaux à CT-8 ${sec.trim().slice(4)}, CO-1 à CO-14 réussies`, function () {
      const texte = lire(DEP, "compose", nom);
      const s = section(sec, fin);
      const h = sha(texte);
      expect(s).to.include(`\`${h}\``);
      const bloc = /```yaml\n([\s\S]*?)\n```/.exec(s)[1] + "\n";
      expect(bloc).to.equal(texte);
      const r = D.verifierConteneurs(texte, DESCRIPTION, nom);
      expect(r.verdict, JSON.stringify(r.checks.filter((c) => c.status !== "reussi"))).to.equal("conforme");
      expect(r.checks.map((c) => c.id)).to.deep.equal(Array.from({ length: 14 }, (_, i) => `CO-${i + 1}`));
      expect(D.validerSchemaDeploiement(r, SCHEMAS.conteneurs, { fragment: "#/$defs/rapport" })).to.deep.equal([]);
    });
  }

  it("le bloc `<!-- schema: conteneurs -->` de 4.1 égale images.json, conforme à conteneurs-v0 ; chaque service des fichiers Compose est décrit, et inversement", function () {
    const [bloc] = blocs(CT8, "conteneurs");
    expect(bloc + "\n").to.equal(lire(DEP, "images", "images.json"));
    expect(D.validerSchemaDeploiement(DESCRIPTION, SCHEMAS.conteneurs)).to.deep.equal([]);
    const services = new Set();
    for (const f of ["rapide.yaml", "production.yaml"]) {
      for (const p of D.portsPublies(lire(DEP, "compose", f))) services.add(p.service);
      const m = lire(DEP, "compose", f).match(/^services:\n([\s\S]*?)\n(?=[a-z])/m)[1];
      for (const s of m.matchAll(/^ {2}([a-z][a-z0-9-]*):$/gm)) {
        expect(DESCRIPTION.services, `${f} : ${s[1]}`).to.have.property(s[1]);
        services.add(s[1]);
      }
    }
    expect([...services].sort()).to.deep.equal(Object.keys(DESCRIPTION.services).sort());
  });

  it("CO-14, espace réseau partagé (CT-8 révision 0.7) : horodatage décrit network_mode service:enregistreur est conforme ; un autre service hôte, un service hôte absent, des ports ou des réseaux propres, ou une description sans espace partagé échouent à la seule CO-14", function () {
    const texte = lire(DEP, "compose", "rapide.yaml");
    const codes = (yaml, desc = DESCRIPTION) => D.verifierConteneurs(yaml, desc, "rapide.yaml").checks.filter((c) => c.status !== "reussi").map((c) => [c.id, c.findings.map((f) => `${f.service}:${f.code}`)]);
    expect(codes(texte)).to.deep.equal([]);
    const sansEspace = structuredClone(DESCRIPTION);
    sansEspace.services.horodatage.network_mode = null;
    expect(codes(texte, sansEspace)).to.deep.equal([["CO-14", ["horodatage:reseau_par_defaut"]]]);
    const ligne = '    network_mode: "service:enregistreur"\n';
    expect(texte.split(ligne)).to.have.lengthOf(2);
    for (const [variante, quoi] of [
      ['    network_mode: "service:approbation"\n', "autre service hôte"],
      ['    network_mode: "service:absent"\n', "service hôte absent"],
      [`${ligne}    ports:\n      - "127.0.0.1:2020:2020"\n`, "port propre"],
    ]) {
      const r = codes(texte.replace(ligne, variante));
      expect(r.map((x) => x[0]), quoi).to.include("CO-14");
      expect(r.find((x) => x[0] === "CO-14")[1], quoi).to.deep.equal(["horodatage:espace_reseau_non_conforme"]);
    }
  });

  it("deploiement/LISEZMOI.md existe ; aucun fichier secrets/ ni de configuration de production dans le dépôt", function () {
    expect(lire(DEP, "LISEZMOI.md")).to.include("npm run deploiement:conteneurs");
    expect(fs.existsSync(path.join(DEP, "secrets"))).to.equal(false);
    expect(fs.existsSync(path.join(DEP, "config", "production"))).to.equal(false);
  });

  it("validerSchemaDeploiement applique contains, maxContains, maxProperties et exclusiveMinimum (A.16)", function () {
    const test = { type: "array", contains: { const: "CMD" }, maxContains: 1 };
    expect(D.validerSchemaDeploiement(["CMD", "x"], test)).to.deep.equal([]);
    expect(D.validerSchemaDeploiement(["x"], test).map((e) => e.message).join(" ")).to.include("contains");
    expect(D.validerSchemaDeploiement(["CMD", "CMD"], test).map((e) => e.message).join(" ")).to.include("plus de 1");
    const sonde = JSON.parse(JSON.stringify(DESCRIPTION));
    for (const t of [["/usr/local/bin/noortrace-ctl", "sonde"], ["CMD", "CMD"]]) {
      sonde.services.enregistreur.probe.test = t;
      expect(D.validerSchemaDeploiement(sonde, SCHEMAS.conteneurs).map((e) => e.chemin), JSON.stringify(t)).to.deep.equal(["/services/enregistreur/probe"]);
    }
    const e = V.entreesExemple();
    e.coefficients = { blocs_par_s: 0 };
    expect(D.validerSchemaDeploiement(e, SCHEMAS.dimensionnement).map((x) => x.chemin)).to.deep.equal(["/coefficients/blocs_par_s"]);
    const verif = { id: "IP-1", status: "reussi", reason: null, measured: null, expected: Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`k${i}`, i])), blocking: true };
    expect(D.validerSchemaDeploiement(verif, SCHEMAS["controle-prealable"], { fragment: "#/$defs/verification" }).map((x) => x.message).join(" ")).to.include("membres");
    expect(() => D.validerSchemaDeploiement(1, { format: "date" })).to.throw(/non pris en charge/);
  });
});

describe("CT-8 §7.3 : configuration de l'installation rapide", function () {
  const texte = lire(DEP, "config", "rapide", "configuration.json");
  const config = JSON.parse(texte);

  it("SHA-256 et nombre de lignes de 7.3 ; valide contre configuration-enregistreur-v0 et les deux schémas de politique ; mode observation", function () {
    const s = section("### 7.3 ", "## 8. ");
    expect(s).to.include(`\`${sha(texte)}\``);
    expect(s).to.include(`${texte.split("\n").length - 1} lignes`);
    const schemas = ["configuration-enregistreur", "politique-redaction", "politique-approbation"].map(D.chargerSchema);
    expect(J.validerSchema(config, schemas[0], { registre: J.registreSchemas(schemas) })).to.deep.equal([]);
    expect(config.policy.approval.mode).to.equal("observation");
    expect(config.recorder.environment).to.equal("developpement");
  });

  it("ne diffère de l'exemple de CT-2 §15.3 que par les membres de la table de 7.3", function () {
    const exemple = C.analyserJSONIntegral(blocs(CT2, "configuration-enregistreur")[0]);
    const diffs = [];
    const estObjet = (v) => v && typeof v === "object" && !Array.isArray(v);
    const comparer = (a, b, p) => {
      if (J.egalJSON(a ?? null, b ?? null) && (a === undefined) === (b === undefined)) return;
      if (estObjet(a) && estObjet(b)) for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) comparer(a[k], b[k], p ? `${p}.${k}` : k);
      else diffs.push(p);
    };
    comparer(exemple, config, "");
    const s = section("### 7.3 ", "## 8. ");
    const membres = [...s.matchAll(/^\| (`[^|]+) \|/gm)].flatMap((m) => [...m[1].matchAll(/`([^`]+)`/g)].map((x) => x[1]));
    expect(membres.length).to.equal(19);
    const prefixe = (m, d) => d === m || d.startsWith(m + ".");
    for (const d of diffs) expect(membres.some((m) => prefixe(m, d)), `membre changé sans ligne : ${d}`).to.equal(true);
    const valeur = (o, m) => m.split(".").reduce((x, k) => (x === undefined ? undefined : x[k]), o);
    for (const m of membres) {
      const absentDesDeux = valeur(exemple, m) === undefined && valeur(config, m) === undefined;
      expect(absentDesDeux || diffs.some((d) => prefixe(m, d)), `ligne sans changement : ${m}`).to.equal(true);
    }
  });

  it("configurer-rapide.mjs la reproduit à l'octet avec les options d'exemple d'IR-3 ; codes 0 et 2", function () {
    expect(configurationRapide({ org: "organisation-exemple", journal: "journal-rapide", serveurOutils: "https://outils.interne.example/mcp" })).to.equal(texte);
    const sortie = path.join(TRAVAIL, "configuration.json");
    const r = outil("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", sortie]);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(sortie, "utf8")).to.equal(texte);
    expect(r.stdout).to.equal(`org_id ${config.recorder.org_id}\njournal_id ${config.recorder.journal_id}\nsha256 ${sha(texte)}\nconfiguration valide\n`);
    const autre = configurationRapide({ org: "assureur-demo", journal: "sinistres", serveurOutils: "https://outils.assureur-demo.example/mcp" });
    expect(JSON.parse(autre).recorder.org_id).to.not.equal(config.recorder.org_id);
    expect(outil("configurer-rapide.mjs", ["--org", "x"]).status).to.equal(2);
    expect(outil("configurer-rapide.mjs", ["--org", "x", "--journal", "y", "--serveur-outils", "http://non-chiffre.example/mcp", "--sortie", path.join(TRAVAIL, "refus.json")]).status).to.equal(2);
    expect(fs.existsSync(path.join(TRAVAIL, "refus.json"))).to.equal(false);
  });
});

describe("CT-8 annexe A.3 : famille conteneurs/", function () {
  const cas = fs.readdirSync(path.join(VECT, "conteneurs")).filter((f) => f.endsWith(".attendu.json")).map((f) => f.replace(".attendu.json", "")).sort();

  it("36 cas, images.json égal à deploiement/images/images.json ; chaque cas conforme à $defs/cas ; un seul échec par cas invalide", function () {
    expect(cas).to.have.length(36);
    expect(lire(VECT, "conteneurs", "images.json")).to.equal(lire(DEP, "images", "images.json"));
    const table = section("### A.3 ", "### A.4 ");
    for (const n of cas) {
      const doc = lireJSON(VECT, "conteneurs", `${n}.attendu.json`);
      expect(D.validerSchemaDeploiement(doc, SCHEMAS.conteneurs, { fragment: "#/$defs/cas" }), n).to.deep.equal([]);
      const echecs = doc.attendu.checks.filter((c) => c.status === "echoue");
      if (n.startsWith("valide")) expect(echecs, n).to.deep.equal([]);
      else {
        expect(echecs, n).to.have.length(1);
        const ligne = table.split("\n").find((l) => l.startsWith(`| \`${n}\` |`));
        expect(ligne, n).to.be.a("string");
        expect(ligne, n).to.include(echecs[0].id);
        const code = /CO-[0-9]+ `([a-z_]+)`/.exec(ligne);
        if (code) expect(echecs[0].findings.map((f) => f.code), n).to.include(code[1]);
      }
    }
  });

  it("chaque cas rejoué par verifierConteneurs et par l'outil (--json) rend son attendu, code 0 ou 1", function () {
    for (const n of cas) {
      const doc = lireJSON(VECT, "conteneurs", `${n}.attendu.json`);
      const texte = lire(VECT, "conteneurs", `${n}.yaml`);
      expect(D.verifierConteneurs(texte, DESCRIPTION, `${n}.yaml`), n).to.deep.equal(doc.attendu);
      const r = outil("verifier-conteneurs.mjs", [path.join(VECT, "conteneurs", `${n}.yaml`), "--images", path.join(VECT, "conteneurs", "images.json"), "--json"]);
      expect(r.status, n).to.equal(doc.attendu.verdict === "conforme" ? 0 : 1);
      expect(r.stdout, n).to.equal(D.texteJSON(doc.attendu));
    }
  });

  it("valide-production-condenses : toutes les images par condensé fictif ; les deux fichiers de référence non", function () {
    expect(lireJSON(VECT, "conteneurs", "valide-production-condenses.attendu.json").attendu.all_images_by_digest).to.equal(true);
    expect(lireJSON(VECT, "conteneurs", "valide-production.attendu.json").attendu.all_images_by_digest).to.equal(false);
  });

  it("outil : option inconnue, description invalide, fichier absent → code 2 ; npm run deploiement:conteneurs → code 0", function () {
    expect(outil("verifier-conteneurs.mjs", ["--inconnue"]).status).to.equal(2);
    expect(outil("verifier-conteneurs.mjs", ["--inconnue"]).stderr).to.include("option inconnue : --inconnue");
    expect(outil("verifier-conteneurs.mjs", [path.join(DEP, "compose", "rapide.yaml")]).status).to.equal(2);
    const fausse = path.join(TRAVAIL, "images-fausses.json");
    fs.writeFileSync(fausse, JSON.stringify({ version: 1, description: "x", services: {} }));
    expect(outil("verifier-conteneurs.mjs", [path.join(DEP, "compose", "rapide.yaml"), "--images", fausse]).status).to.equal(2);
    expect(outil("verifier-conteneurs.mjs", [path.join(TRAVAIL, "absent.yaml"), "--images", path.join(DEP, "images", "images.json")]).status).to.equal(2);
    const r = spawnSync("npm", ["run", "-s", "deploiement:conteneurs"], { cwd: PROJECT_ROOT, encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(r.stdout).to.include("rapide.yaml : conforme").and.to.include("production.yaml : conforme");
  });
});

describe("CT-8 §6 et annexe A.4 : contrôle préalable", function () {
  const cas = fs.readdirSync(path.join(VECT, "controle-prealable")).map((f) => f.replace(".json", "")).sort();

  it("33 cas conformes à $defs/cas ; verdicts de la table d'A.4 ; évaluation rejouée égale à attendu", function () {
    expect(cas).to.have.length(33);
    const table = section("### A.4 ", "### A.5 ");
    for (const n of cas) {
      const c = lireJSON(VECT, "controle-prealable", `${n}.json`);
      expect(D.validerSchemaDeploiement(c, SCHEMAS["controle-prealable"], { fragment: "#/$defs/cas" }), n).to.deep.equal([]);
      const ex = D.exigencesProfil(c.profile, { storageFreeMinBytes: c.profile === "production" ? c.storage_free_min_bytes ?? null : undefined, only: c.only ?? null });
      expect(D.evaluerControle(c.observations, ex), n).to.deep.equal(c.attendu);
      const ligne = table.split("\n").find((l) => l.startsWith(`| \`${n}\` |`));
      expect(ligne, n).to.include(`| \`${c.attendu.verdict}\``);
      expect(ligne, n).to.include(`| ${c.profile} |`);
    }
  });

  it("chaque cas rejoué par controle-prealable.mjs --observations <cas> --json : sortie égale à attendu, code d'EX-6.3", function () {
    for (const n of cas) {
      const c = lireJSON(VECT, "controle-prealable", `${n}.json`);
      const r = outil("controle-prealable.mjs", ["--profil", c.profile, "--observations", path.join(VECT, "controle-prealable", `${n}.json`), "--json"]);
      expect(r.status, `${n} : ${r.stderr}`).to.equal(c.attendu.exit_code);
      expect(r.stdout, n).to.equal(D.texteJSON(c.attendu));
    }
  });

  it("l'exemple de 6.3 : le rapport imprimé égale l'évaluation des observations imprimées ; les deux blocs suivent leur schéma", function () {
    const [obs] = blocs(CT8, "controle-prealable/observations").map((t) => JSON.parse(t));
    const [rap] = blocs(CT8, "controle-prealable").map((t) => JSON.parse(t));
    expect(D.validerSchemaDeploiement(obs, SCHEMAS["controle-prealable"], { fragment: "#/$defs/observations" })).to.deep.equal([]);
    expect(D.validerSchemaDeploiement(rap, SCHEMAS["controle-prealable"])).to.deep.equal([]);
    expect(D.evaluerControle(obs, D.exigencesProfil("rapide"))).to.deep.equal(rap);
    expect(obs).to.deep.equal(V.OBSERVATIONS_RAPIDE);
    expect(rap.verdict).to.equal("pret_avec_avertissements");
  });

  it("observations seules, seuil par --dimensionnement, --seulement, --date, --ecrire-observations exclusif ; erreurs d'usage → code 2", function () {
    const fobs = path.join(TRAVAIL, "obs-production.json");
    fs.writeFileSync(fobs, D.texteJSON(V.observationsProduction()));
    // Sans dimensionnement : IP-3 non exécutée, non prêt.
    let r = outil("controle-prealable.mjs", ["--profil", "production", "--observations", fobs, "--json"]);
    expect(r.status).to.equal(1);
    expect(JSON.parse(r.stdout).checks[2]).to.include({ status: "non_execute", reason: "dimensionnement_absent" });
    // Seuil tiré de la sortie du calculateur (exemple de 9.5) : prêt.
    const fdim = path.join(TRAVAIL, "dimensionnement.json");
    fs.writeFileSync(fdim, D.texteJSON(D.dimensionner(V.entreesExemple())));
    r = outil("controle-prealable.mjs", ["--profil", "production", "--observations", fobs, "--dimensionnement", fdim, "--json", "--date", "2026-11-05T08:00:00.000Z"]);
    expect(r.status, r.stderr).to.equal(0);
    const rap = JSON.parse(r.stdout);
    expect(rap).to.deep.equal({ ...lireJSON(VECT, "controle-prealable", "pret-production.json").attendu, checked_at: "2026-11-05T08:00:00.000Z" });
    r = outil("controle-prealable.mjs", ["--profil", "production", "--observations", fobs, "--seulement", "IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13", "--json"]);
    expect([r.status, JSON.parse(r.stdout)]).to.deep.equal([0, lireJSON(VECT, "controle-prealable", "systeme-seulement-production.json").attendu]);
    // Résumé lisible.
    r = outil("controle-prealable.mjs", ["--profil", "rapide", "--observations", path.join(VECT, "controle-prealable", "pret-rapide.json")]);
    expect(r.status).to.equal(0);
    expect(r.stdout).to.include("profil rapide : pret_avec_avertissements (code 0)").and.to.include("IP-13 non_execute (declaration_absente), non bloquante");
    for (const args of [
      ["--inconnue"],
      ["--profil", "intermediaire", "--observations", fobs],
      ["--profil", "rapide"],
      ["--profil", "rapide", "--observations", fobs, "--seulement", "IP-14"],
      ["--profil", "rapide", "--observations", fobs, "--seulement", "IP-1,IP-1"],
      ["--profil", "rapide", "--observations", fobs, "--declare", "disque-chiffre"],
      ["--profil", "rapide", "--observations", fobs, "--date", "hier"],
      ["--profil", "rapide", "--observations", fobs, "--ecrire-observations", path.join(TRAVAIL, "x.json")],
      ["--profil", "rapide", "--observations", path.join(TRAVAIL, "absent.json")],
      ["--profil", "rapide", "--observations", path.join(VECT, "controle-prealable", "pret-production.json")],
      ["--profil", "production", "--observations", fobs, "--dimensionnement", path.join(VECT, "dimensionnement", "refus-retention-ancres.json")],
      // Collecte : répertoire des secrets illisible, relevé avant tout essai de réseau.
      ["--profil", "rapide", "--configuration", path.join(DEP, "config", "rapide", "configuration.json"), "--compose", path.join(DEP, "compose", "rapide.yaml"), "--images", path.join(DEP, "images", "images.json"), "--secrets", path.join(TRAVAIL, "secrets-absents"), "--stockage", TRAVAIL],
      ["--profil", "rapide", "--configuration", path.join(DEP, "config", "rapide", "configuration.json"), "--compose", path.join(DEP, "compose", "rapide.yaml"), "--images", path.join(DEP, "images", "images.json"), "--stockage", TRAVAIL],
    ]) {
      const e = outil("controle-prealable.mjs", args);
      expect(e.status, args.join(" ")).to.equal(2);
      expect(e.stderr, args.join(" ")).to.match(/^Erreur : /);
    }
    const ko = JSON.parse(JSON.stringify(V.OBSERVATIONS_RAPIDE));
    ko.cpus = -1;
    fs.writeFileSync(path.join(TRAVAIL, "obs-invalides.json"), JSON.stringify(ko));
    expect(outil("controle-prealable.mjs", ["--profil", "rapide", "--observations", path.join(TRAVAIL, "obs-invalides.json")]).status).to.equal(2);
  });

  it("destinations d'EX-6.5 tirées de la configuration rapide : FL-7, FL-8 et FL-18, dans l'ordre des observations de 6.3 ; ponts et hôtes en double exclus", function () {
    const config = lireJSON(DEP, "config", "rapide", "configuration.json");
    expect(D.destinations(config)).to.deep.equal(V.OBSERVATIONS_RAPIDE.egress.map(({ flow, host, port }) => ({ flow, host, port })));
    const c2 = JSON.parse(JSON.stringify(config));
    c2.policy.servers.pont = { ...c2.policy.servers.outils, transport: { ...c2.policy.servers.outils.transport, url: "http://pont-fichiers:8080/mcp" } };
    c2.anchoring.registry.rpc_url = "https://validateur-1.registre-test.example/rpc";
    c2.policy.approval.service.url = "https://approbation.interne.example:8600";
    const ancrage = { rfc3161: { providers: [{ url: "https://tsa.prestataire.example/tsa" }, { url: "http://127.0.0.1:3180/tsa" }] }, opentimestamps: { calendars: ["https://a.pool.opentimestamps.org"], upgrade: { whitelist: ["https://c.pool.opentimestamps.org"] } } };
    const d = D.destinations(c2, ancrage, { env: {} });
    expect(d.map((x) => `${x.flow} ${x.host}:${x.port}`)).to.deep.equal([
      "FL-7 outils.interne.example:443",
      "FL-8 api.anthropic.com:443",
      "FL-8 api.openai.com:443",
      "FL-12 approbation.interne.example:8600",
      "FL-17 tsa.prestataire.example:443",
      "FL-17 127.0.0.1:3180",
      "FL-18 a.pool.opentimestamps.org:443",
      "FL-18 b.pool.opentimestamps.org:443",
      "FL-18 c.pool.opentimestamps.org:443",
      "FL-19 validateur-1.registre-test.example:443",
    ]);
  });

  it("collecte : type de système de fichiers (mountinfo), borne d'horloge de chronyc, UID attendu des secrets", function () {
    const mi = [
      "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw",
      "30 22 0:40 / /var/lib/docker rw,relatime shared:2 - xfs /dev/sdb1 rw",
      "31 22 0:41 / /srv/nfs rw shared:3 - nfs4 serveur:/export rw",
      "32 22 0:42 / /srv/avec\\040espace rw shared:4 - btrfs /dev/sdc1 rw",
    ].join("\n");
    expect(D.typeSystemeFichiers("/var/lib/docker/volumes", mi)).to.equal("xfs");
    expect(D.typeSystemeFichiers("/var/lib/dockerx", mi)).to.equal("ext4");
    expect(D.typeSystemeFichiers("/srv/nfs/a", mi)).to.equal("nfs4");
    expect(D.typeSystemeFichiers("/srv/avec espace/b", mi)).to.equal("btrfs");
    expect(D.lireChronyc("C0A80001,serveur,3,1793059200.000000000,-0.000012000,0.000003000,0.000010000,-1.5,0.001,0.02,0.004000000,0.000500000,64.5,Normal\n")).to.deep.equal({ synchronized: true, error_bound_ms: 2.512 });
    expect(D.lireChronyc("0,,0,0,0,0,0,0,0,0,0,0,0,Not synchronised\n")).to.deep.equal({ synchronized: false, error_bound_ms: null });
    expect(D.lireChronyc("illisible")).to.equal(null);
    expect(D.uidAttenduSecret("cle-enregistreur", DESCRIPTION)).to.equal(10001);
    expect(D.uidAttenduSecret("jeton-hote-poste-1", DESCRIPTION)).to.equal(10001);
  });

  it("collecte réelle sur la machine des tests (profil rapide, configuration sans destination : aucun accès au réseau) : observations et rapport conformes à leur schéma", async function () {
    this.timeout(60000);
    const secrets = path.join(TRAVAIL, "secrets");
    fs.mkdirSync(secrets, { mode: 0o700 });
    fs.writeFileSync(path.join(secrets, "cle-mac-relais"), "0".repeat(64), { mode: 0o400 });
    const config = lireJSON(DEP, "config", "rapide", "configuration.json");
    config.policy.servers = {};
    config.policy.model.routes = [];
    config.anchoring.opentimestamps.calendars = [];
    expect(D.destinations(config)).to.deep.equal([]);
    const fconf = path.join(TRAVAIL, "configuration-collecte.json");
    fs.writeFileSync(fconf, JSON.stringify(config), { mode: 0o600 });
    const obs = await D.collecterObservations({ profil: "rapide", configuration: config, cheminConfiguration: fconf, texteCompose: lire(DEP, "compose", "rapide.yaml"), nomCompose: "rapide.yaml", description: DESCRIPTION, secrets, stockage: TRAVAIL, date: "2026-10-27T09:00:00.000Z", env: {} });
    expect(D.validerSchemaDeploiement(obs, SCHEMAS["controle-prealable"], { fragment: "#/$defs/observations" })).to.deep.equal([]);
    expect(obs.platform).to.equal(os.platform());
    expect(obs.cpus).to.equal(os.availableParallelism());
    expect(obs.storage.free_bytes).to.be.above(0);
    expect(obs.dns).to.deep.equal([]);
    expect(obs.egress).to.deep.equal([]);
    expect(obs.ports.map((p) => p.port)).to.deep.equal([8300, 8400, 8500]);
    expect(obs.rights.secrets_dir_mode).to.equal(0o700);
    expect(obs.rights.secret_files).to.deep.equal([{ name: "cle-mac-relais", mode: 0o400, uid: fs.statSync(path.join(secrets, "cle-mac-relais")).uid, expected_uid: 10001 }]);
    expect(obs.rights.config_mode).to.equal(0o600);
    expect(obs.compose).to.deep.equal({ file_sha256: sha(lire(DEP, "compose", "rapide.yaml")), failed: [], all_images_by_digest: false });
    expect(obs.proxy).to.deep.equal({ declared: false, environment_set: false });
    const rap = D.evaluerControle(obs, D.exigencesProfil("rapide"));
    expect(D.validerSchemaDeploiement(rap, SCHEMAS["controle-prealable"])).to.deep.equal([]);
    expect(rap.checks.find((c) => c.id === "IP-12").status).to.equal("reussi");
    // Production : ports publiés du fichier Compose, adresse interne lue dans NOORTRACE_IP_INTERNE (requise).
    const prod = { profil: "production", configuration: config, cheminConfiguration: fconf, texteCompose: lire(DEP, "compose", "production.yaml"), nomCompose: "production.yaml", description: DESCRIPTION, secrets, stockage: TRAVAIL, date: "2026-10-27T09:00:00.000Z" };
    let erreur = null;
    await D.collecterObservations({ ...prod, env: {} }).catch((e) => { erreur = e; });
    expect(erreur?.message).to.include("NOORTRACE_IP_INTERNE");
    const obsProd = await D.collecterObservations({ ...prod, env: { NOORTRACE_IP_INTERNE: "127.0.0.1" } });
    expect(obsProd.ports.map((p) => `${p.address}:${p.port}`)).to.deep.equal(["8300", "8400", "1344", "4318", "8500", "8601", "8700", "8545", "8080", "9090"].map((p) => `127.0.0.1:${p}`));
    expect(D.validerSchemaDeploiement(obsProd, SCHEMAS["controle-prealable"], { fragment: "#/$defs/observations" })).to.deep.equal([]);
    expect(obsProd.compose.failed).to.deep.equal([]);
  });
});

describe("CT-8 §9 et annexe A.5 : dimensionnement", function () {
  const cas = fs.readdirSync(path.join(VECT, "dimensionnement")).map((f) => f.replace(".json", "")).sort();
  const lireCas = (n) => lireJSON(VECT, "dimensionnement", `${n}.json`);

  it("16 cas conformes à $defs/cas ; dimensionner rend attendu ; l'outil rend la même sortie et le code 0 ou 1", function () {
    expect(cas).to.have.length(16);
    for (const n of cas) {
      const c = lireCas(n);
      expect(D.validerSchemaDeploiement(c, SCHEMAS.dimensionnement, { fragment: "#/$defs/cas" }), n).to.deep.equal([]);
      expect(D.dimensionner(c.entrees), n).to.deep.equal(c.attendu);
      const r = outil("dimensionner.mjs", ["--entrees", path.join(VECT, "dimensionnement", `${n}.json`), "--json"]);
      expect(r.status, n).to.equal(c.attendu.valid ? 0 : 1);
      expect(r.stdout, n).to.equal(D.texteJSON(c.attendu));
    }
  });

  it("l'exemple de 9.5 : sortie imprimée égale au calcul des entrées imprimées, conformes à leur schéma ; entrées égales au cas reference", function () {
    const [e] = blocs(CT8, "dimensionnement").map((t) => JSON.parse(t));
    const [s] = blocs(CT8, "dimensionnement/sorties").map((t) => JSON.parse(t));
    expect(D.validerSchemaDeploiement(e, SCHEMAS.dimensionnement)).to.deep.equal([]);
    expect(D.validerSchemaDeploiement(s, SCHEMAS.dimensionnement, { fragment: "#/$defs/sorties" })).to.deep.equal([]);
    expect(D.dimensionner(e)).to.deep.equal(s);
    expect(e).to.deep.equal(V.entreesExemple());
    expect(lireCas("reference").entrees).to.deep.equal(e);
  });

  it("la table de 9.5 se recalcule depuis le cas reference", function () {
    const j = lireCas("reference").attendu.journals[0];
    const t = lireCas("reference").attendu.totals;
    const s = section("### 9.5 ", "### 9.6 ");
    const g = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
    const fr = (x) => D.gio(x).replace(".", ",");
    expect(s).to.include(`${g(j.events_per_year)} événements par an`);
    expect(s).to.include(`${String(j.mean_events_per_s).replace(".", ",")} et ${String(j.peak_events_per_s).replace(".", ",")} événement par seconde`);
    expect(s).to.include(`${g(j.segment_bytes_per_year)} octets (${fr(j.segment_bytes_per_year)} Gio)`);
    expect(s).to.include(`${g(j.piece_bytes_per_year)} octets (${fr(j.piece_bytes_per_year)} Gio)`);
    expect(s).to.include(`${g(j.tokens_qualified_per_year)} jetons qualifiés ; ${g(j.tokens_other_per_year)} de second rang`);
    expect(s).to.include(`${g(j.registry_anchors_per_year_max)} ancres au plus ; ${g(j.gas_per_year_max)} gaz`);
    expect(s).to.include(`${g(j.anchor_bytes_per_year)} octets par an (${fr(j.anchor_bytes_per_year)} Gio)`);
    expect(s).to.include(`${g(j.checkpoint_bytes_per_year)} ; ${g(j.manifest_bytes_per_year)} octets par an`);
    expect(s).to.include(`${g(j.capture_bytes_per_year)} octets par an (${fr(j.capture_bytes_per_year)} Gio)`);
    expect(s).to.include(`${g(j.local_bytes)} octets (${fr(j.local_bytes)} Gio)`);
    expect(s).to.include(`${g(j.worm_bytes)} octets (${fr(j.worm_bytes)} Gio)`);
    expect(s).to.include(`${g(j.ops_archive_bytes)} octets (${fr(j.ops_archive_bytes)} Gio)`);
    expect(s).to.include(`${g(j.peak_write_bytes_per_s)} octets par seconde ; ${String(j.peak_fsync_per_s_max).replace(".", ",")} et ${String(j.peak_fsync_per_s_min).replace(".", ",")} vidage par seconde`);
    expect(s).to.include(`${g(j.memory_buffers_max_bytes)} octets (3 Gio)`);
    expect(s).to.include(`${j.registry_tx_per_hour_max} transactions par heure ; ${g(j.registry_journals_max)} journaux ; ${String(t.registry_capacity_share).replace(".", ",")}`);
  });

  it("la table de 9.6 se recalcule depuis les cas (Gio à trois décimales, jetons, transactions, parts, refus)", function () {
    const s = section("### 9.6 ", "## 10. ");
    const index = lire(VECT, "INDEX.md");
    for (const n of cas) {
      const ligne = s.split("\n").find((l) => l.startsWith(`| \`${n}\` |`));
      expect(ligne, n).to.be.a("string");
      const c = lireCas(n).attendu;
      if (!c.valid) {
        for (const e of c.errors) expect(ligne, n).to.include(`\`${e.code}\``);
        continue;
      }
      const t = c.totals;
      const g = (x) => String(x).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
      const fr = (x) => { const [e, f] = D.gio(x).split("."); return `${g(e)},${f}`; };
      expect(ligne, n).to.include(`| ${fr(t.local_bytes)} |`);
      expect(ligne, n).to.include(t.worm_bytes === 0 ? "| 0 |" : `| ${fr(t.worm_bytes)} |`);
      expect(ligne, n).to.include(`| ${g(t.tokens_qualified_per_year)} / ${g(t.tokens_other_per_year)} |`);
      expect(ligne, n).to.include(`| ${g(t.registry_tx_per_hour_max)} ; ${String(t.registry_capacity_share).replace(".", ",")}`);
      // INDEX.md reprend les mêmes nombres.
      expect(index, n).to.include(`| ${fr(t.local_bytes)} | ${t.worm_bytes === 0 ? "0" : fr(t.worm_bytes)} | ${g(t.tokens_qualified_per_year)} / ${g(t.tokens_other_per_year)} |`);
    }
    expect(lireCas("debit-au-dela-de-la-cible").attendu.journals[0]).to.include({ peak_events_per_s: 555.556, peak_over_target: true });
    expect(lireCas("points-toutes-les-dix-secondes").attendu.journals[0].registry_journals_max).to.equal(698);
  });

  it("épreuve (a), EX-14.2 point 3 : le cas d'EX-14.1 (exemple de 9.5 plus le type souscription) rend les valeurs attendues", function () {
    const e = V.entreesExemple();
    const j2 = structuredClone(e.journals[0]);
    Object.assign(j2, { id: "souscription", count: 4 });
    Object.assign(j2.activity, { agents: 5, events_per_hour: 60 });
    j2.storage.pieces_days = 365;
    Object.assign(j2.storage.worm, { copies: 2, pieces_in_worm: true });
    Object.assign(j2.anchoring, { provider_role: "principal", rfc3161_interval_s: 600 });
    e.journals.push(j2);
    const t = D.dimensionner(e).totals;
    expect(t).to.include({ local_bytes: 3951222228000, worm_bytes: 7632427515552, ops_archive_bytes: 39498547200, tokens_qualified_per_year: 219000, tokens_other_per_year: 96360, registry_tx_per_hour_max: 315, registry_capacity_share: 0.001243 });
    const s = section("### 14.1 ", "### 14.2 ");
    for (const v of ["3 951 222 228 000", "7 632 427 515 552", "39 498 547 200", "219 000", "96 360", "= 315", "0,001243"]) expect(s).to.include(v);
  });

  it("outil : refus d'EX-9.3 (code 1, toutes les raisons), entrées invalides et options → code 2 ; résumé lisible sans --json", function () {
    const r = outil("dimensionner.mjs", ["--entrees", path.join(VECT, "dimensionnement", "refus-cadence-non-diviseur.json")]);
    expect(r.status).to.equal(1);
    expect(r.stdout).to.include("refus : journal sinistres : checkpoint_interval_s_non_diviseur\nrefus : journal sinistres : rfc3161_interval_s_invalide\n");
    const ok = outil("dimensionner.mjs", ["--entrees", path.join(VECT, "dimensionnement", "reference.json")]);
    expect(ok.status).to.equal(0);
    expect(ok.stdout).to.include("espace local : 967.655 Gio (1039011288480 octets)");
    const e = V.entreesExemple();
    e.journals[0].storage.worm.retain_days = 3000;
    expect(D.dimensionner(e)).to.deep.equal({ version: 0, valid: false, errors: [{ journal: "sinistres", code: "retain_days_insuffisant" }] });
    const invalide = path.join(TRAVAIL, "dim-invalide.json");
    fs.writeFileSync(invalide, JSON.stringify({ version: 0, hours_per_year: 8760, coefficients: {}, journals: [] }));
    expect(outil("dimensionner.mjs", ["--entrees", invalide]).status).to.equal(2);
    expect(outil("dimensionner.mjs", ["--inconnue"]).status).to.equal(2);
    expect(outil("dimensionner.mjs", []).status).to.equal(2);
    expect(outil("dimensionner.mjs", ["--entrees", path.join(TRAVAIL, "absent.json")]).status).to.equal(2);
  });

  it("coefficients remplacés membre à membre ; mêmes entrées, mêmes octets", function () {
    const e = V.entreesExemple();
    e.coefficients = { b_cap: 200000 };
    const a = D.dimensionner(e);
    const b = D.dimensionner(V.entreesExemple());
    expect(a.journals[0].capture_bytes_per_year).to.be.above(b.journals[0].capture_bytes_per_year);
    expect(a.journals[0].segment_bytes_per_year).to.equal(b.journals[0].segment_bytes_per_year);
    expect(D.texteJSON(D.dimensionner(V.entreesExemple()))).to.equal(D.texteJSON(b));
  });

  it("mesures de 9.2 rejouées sur les vecteurs : b_pt = 682, b_man = 916, b_tsr_sup = 9 ; b_cap = 123 761 relu dans le rapport de TM-31", function () {
    let b_pt = 0;
    for (const p of ["periode-1", "periode-2", "periode-3"]) for (const x of lireJSON(SPEC, "vecteurs", "ct-1", "points-de-controle", `${p}.json`)) b_pt = Math.max(b_pt, J.octetsJCS(x).length + 1);
    expect(b_pt).to.equal(D.COEFFICIENTS.b_pt).and.to.equal(682);
    const man = path.join(SPEC, "vecteurs", "ct-1", "manifestes");
    const b_man = Math.max(...["periode-1", "periode-2", "periode-3"].map((p) => fs.statSync(path.join(man, `${p}.json`)).size + fs.statSync(path.join(man, `${p}.sig`)).size));
    expect(b_man).to.equal(D.COEFFICIENTS.b_man).and.to.equal(916);
    const rep = path.join(SPEC, "vecteurs", "ct-5", "reponses");
    const ecarts = new Set(fs.readdirSync(rep).filter((f) => f.endsWith(".der")).map((f) => fs.statSync(path.join(rep, f.replace(/\.der$/, ".tsr"))).size - fs.statSync(path.join(rep, f)).size));
    expect([...ecarts]).to.deep.equal([D.COEFFICIENTS.b_tsr_sup]);
    // b_cap (CT-8 révision 0.2) : capture d'une transaction d'un bloc plein (CT-4 EX-9.2), relue dans le rapport de TM-31 (A.5).
    const R = lireJSON(SPEC, "vecteurs", "ct-9", "mesures", "rapport-2026-11-02-capture-bloc-plein.json");
    const ligne = R.results.find((l) => l.name === "b_cap_bloc_plein");
    expect([ligne.test_id, ligne.unit, ligne.samples, ligne.max]).to.deep.equal(["TM-31", "octets", [109479, 109479, 109479], 109479]);
    const decomp = [...R.notes.matchAll(/= (\d+) octets = en-tête (\d+) \+ certificat (\d+) \+ (\d+) reçus (\d+) /g)].map((m) => m.slice(1).map(Number));
    expect(decomp).to.deep.equal(Array(3).fill([109479, 5846, 32587, 64, 71046]));
    for (const [total, e, c, , r] of decomp) expect(e + c + r).to.equal(total);
    const index = Math.max(...[...R.notes.matchAll(/index de capture (\d+) octets/g)].map((m) => Number(m[1])));
    const unRecu = Math.max(...[...R.notes.matchAll(/un seul reçu \(forme de CT-8 §9\.2\) : au plus (\d+) octets/g)].map((m) => Number(m[1])));
    expect([index, unRecu]).to.deep.equal([14282, 39544]);
    expect(ligne.max + index).to.equal(D.COEFFICIENTS.b_cap).and.to.equal(123761);
    // Réserves de 9.2 : fichiers des blocs d'une transaction de la capture de CT-6.
    const cap = path.join(SPEC, "vecteurs", "ct-6", "registre", "capture");
    const max = (prefixe) => Math.max(...fs.readdirSync(cap).filter((f) => f.startsWith(prefixe)).map((f) => fs.statSync(path.join(cap, f)).size));
    expect([max("bloc-"), max("certificat-"), max("recu-")]).to.deep.equal([1498, 7782, 1816]);
  });
});

describe("CT-8 §0.2 et annexe A.2 : renvois vers CT-8", function () {
  it("renvois.mjs : chaque occurrence a sa ligne, TC- consécutifs, réponses citant des identifiants de CT-8 ; code 0", function () {
    const r = verifierRenvois();
    expect(r.erreurs).to.deep.equal([]);
    expect([r.occurrences, r.lignes]).to.deep.equal([115, 115]);
    const s = spawnSync(process.execPath, [path.join(OUTILS, "renvois.mjs")], { encoding: "utf8", cwd: PROJECT_ROOT });
    expect(s.status, s.stdout).to.equal(0);
    expect(s.stdout).to.include("total : 115 occurrence(s), 115 ligne(s)");
    expect(spawnSync(process.execPath, [path.join(OUTILS, "renvois.mjs"), "--x"], { encoding: "utf8" }).status).to.equal(2);
  });

  it("les identifiants cités sont vérifiés (un identifiant précédé de « CT-n » est d'une autre spécification)", function () {
    expect(identifiantsCites("Section 12 (EX-12.1 à EX-12.16) ; CT-7 EX-4.6 ; IP-13, DM-22, FL-7")).to.deep.equal(["EX-12.1", "EX-12.16", "IP-13", "DM-22", "FL-7"]);
    const definis = definisCT8(CT8);
    for (const id of ["EX-12.16", "IP-13", "DM-22", "FL-28", "FL-31", "CO-14", "IR-8", "IC-18", "EX-A.36", "EX-0.1"]) expect(definis.has(id), id).to.equal(true);
    for (const id of ["EX-12.99", "IP-14", "DM-23", "FL-32"]) expect(definis.has(id), id).to.equal(false);
    const table = tableTC(CT8);
    expect(table.map((t) => t.n)).to.deep.equal(Array.from({ length: 115 }, (_, i) => i + 1));
  });
});

describe("CT-8 EX-A.17 : chaînes interdites dans deploiement/ et spec/vecteurs/ct-8/", function () {
  it("aucun chemin personnel ou temporaire, aucune adresse IPv4 hors de 127.0.0.1, 0.0.0.0 et de la RFC 5737, aucun condensé autre que le fictif", function () {
    const admises = (ip) => ip === "127.0.0.1" || ip === "0.0.0.0" || /^(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]{1,3}$/.test(ip);
    let n = 0;
    for (const rep of [DEP, VECT]) {
      for (const f of fichiers(rep)) {
        const t = fs.readFileSync(f).toString("latin1");
        const rel = path.relative(PROJECT_ROOT, f);
        expect(/\/home\/|\/tmp\/|\/root\//.test(t), rel).to.equal(false);
        for (const m of t.matchAll(/(?<![0-9.])([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?![0-9.])/g)) expect(admises(m[1]), `${rel} : ${m[1]}`).to.equal(true);
        for (const m of t.matchAll(/@sha256:([0-9a-f]+)/g)) expect(m[1], rel).to.equal("ab".repeat(32));
        n += 1;
      }
    }
    expect(n).to.be.at.least(5 + 53 + 26 + 15);
  });
});

describe("CT-8 EX-A.1 : générateur des familles de déploiement", function () {
  it("deux générations dans des répertoires neufs donnent les mêmes octets que spec/vecteurs/ct-8 (conteneurs, controle-prealable, dimensionnement)", function () {
    for (const [nom, gen] of [["conteneurs", V.genererConteneurs], ["controle-prealable", V.genererControle], ["dimensionnement", V.genererDimensionnement]]) {
      const a = path.join(TRAVAIL, `gen-a-${nom}`);
      const b = path.join(TRAVAIL, `gen-b-${nom}`);
      gen(a);
      gen(b);
      const liste = (r) => [...fichiers(r)].map((f) => path.relative(r, f));
      expect(liste(a), nom).to.deep.equal(liste(b));
      expect(liste(a), nom).to.deep.equal(liste(path.join(VECT, nom)));
      for (const f of liste(a)) {
        expect(fs.readFileSync(path.join(a, f)).equals(fs.readFileSync(path.join(b, f))), `${nom}/${f}`).to.equal(true);
        expect(fs.readFileSync(path.join(a, f)).equals(fs.readFileSync(path.join(VECT, nom, f))), `${nom}/${f}`).to.equal(true);
      }
    }
  });
});

describe("CT-8 EX-3.6 : archive de déploiement autonome", function () {
  this.timeout(120_000);

  it("construire-archive.mjs écrit un répertoire qui suffit aux outils : IR-3 (configurer-rapide), IR-4 (controle-prealable --observations), dimensionner, verifier-conteneurs, sans npm, sans le dépôt, PATH réduit", function () {
    const rep = path.join(TRAVAIL, "archive");
    const r = outil("construire-archive.mjs", ["--sortie", rep]);
    expect(r.status, r.stderr).to.equal(0);
    expect(outil("construire-archive.mjs", ["--sortie", rep]).status).to.equal(2);
    const sommes = fs.readFileSync(path.join(rep, "SHA256SUMS"), "utf8").trim().split("\n");
    for (const l of sommes) {
      const [h, rel] = l.split("  ");
      expect(sha(fs.readFileSync(path.join(rep, rel))), rel).to.equal(h);
    }
    expect(sommes.map((l) => l.split("  ")[1])).to.include.members(["deploiement/compose/production.yaml", "scripts/lib/deploiement.mjs", "spec/schemas/configuration-enregistreur-v0.schema.json", "node_modules/js-yaml/dist/js-yaml.mjs", "node_modules/ethers/dist/ethers.js"]);
    expect(sommes.some((l) => l.endsWith("scripts/deploiement/renvois.mjs"))).to.equal(false);
    const env = { PATH: "/usr/bin:/bin" };
    const lancer = (o, args) => spawnSync(process.execPath, [path.join(rep, "scripts", "deploiement", o), ...args], { encoding: "utf8", cwd: rep, env });
    for (const o of D.OUTILS_ARCHIVE) {
      const s = lancer(o, ["-h"]);
      expect(s.status, o).to.equal(2);
      expect(s.stderr, o).to.match(/^Erreur : option inconnue : -h\nUsage : /);
    }
    const sortie = path.join(TRAVAIL, "archive-configuration.json");
    const ir3 = lancer("configurer-rapide.mjs", ["--org", "organisation-exemple", "--journal", "journal-rapide", "--serveur-outils", "https://outils.interne.example/mcp", "--sortie", sortie]);
    expect(ir3.status, ir3.stderr).to.equal(0);
    expect(fs.readFileSync(sortie, "utf8")).to.equal(lire(DEP, "config", "rapide", "configuration.json"));
    const obs = path.join(VECT, "controle-prealable", "pret-rapide.json");
    const ir4 = lancer("controle-prealable.mjs", ["--profil", "rapide", "--observations", obs, "--json"]);
    expect(ir4.status, ir4.stderr).to.equal(0);
    expect(ir4.stdout).to.equal(D.texteJSON(lireJSON(obs).attendu));
    const dim = lancer("dimensionner.mjs", ["--entrees", path.join(VECT, "dimensionnement", "reference.json"), "--json"]);
    expect(dim.status, dim.stderr).to.equal(0);
    const co = lancer("verifier-conteneurs.mjs", ["deploiement/compose/rapide.yaml", "deploiement/compose/production.yaml", "--images", "deploiement/images/images.json"]);
    expect(co.status, co.stdout + co.stderr).to.equal(0);
  });

  it("IC-5 : la commande du pas, avec --compose et NOORTRACE_IP_INTERNE, s'exécute sans configuration ni secrets (code 0 ou 1, jamais 2)", function () {
    const stockage = path.join(TRAVAIL, "stockage-ic5");
    fs.mkdirSync(stockage);
    const r = spawnSync(process.execPath, [path.join(OUTILS, "controle-prealable.mjs"), "--profil", "production", "--seulement", "IP-1,IP-2,IP-4,IP-5,IP-6,IP-11,IP-13", "--compose", path.join(DEP, "compose", "production.yaml"), "--declare", "cache-protege", "--stockage", stockage, "--json"], { encoding: "utf8", cwd: PROJECT_ROOT, env: { ...process.env, NOORTRACE_IP_INTERNE: "127.0.0.1" } });
    expect([0, 1], r.stderr).to.include(r.status);
    const rap = JSON.parse(r.stdout);
    expect(rap.checks.filter((c) => c.reason === "non_demandee").map((c) => c.id)).to.deep.equal(["IP-3", "IP-7", "IP-8", "IP-9", "IP-10", "IP-12"]);
    expect(rap.checks.find((c) => c.id === "IP-6").status).to.not.equal("non_execute");
  });
});
