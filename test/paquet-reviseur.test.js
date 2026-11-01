import { expect } from "chai";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as P from "../scripts/lib/paquet.mjs";
import { construire } from "../scripts/paquet-reviseur/construire.mjs";
import { marqueObservation } from "../scripts/paquet-reviseur/verifier.mjs";
import * as Paquets from "../scripts/vecteurs/ct8/paquets.mjs";

// LE PAQUET RÉVISEUR DE CT-8 (spec/CT-8-deploiement-et-exploitation.md, §13,
// annexes A.10 à A.12, EX-A.19 et EX-A.20) : chaque cas de
// spec/vecteurs/ct-8/paquets/cas.json rejoué par l'outil de vérification de
// référence ; archive déterministe (deux constructions, recette GNU tar
// d'EX-13.15) ; rapports conformes à $defs/rapport ; rien d'écrit pour un
// paquet non conforme ; erreurs d'usage ; paquet complet et PR-11 ;
// instructions égales aux blocs de 13.11 ; vocabulaire des résumés ; exemples
// annotés de CT-8 conformes à leur schéma.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
const VECT = path.join(SPEC, "vecteurs", "ct-8", "paquets");
const OUTIL = path.join(PROJECT_ROOT, "scripts", "paquet-reviseur", "verifier.mjs");
const CONSTRUIRE = path.join(PROJECT_ROOT, "scripts", "paquet-reviseur", "construire.mjs");
const SCHEMA = P.chargerSchema();
const CAS = J.analyserJSONStrict(fs.readFileSync(path.join(VECT, "cas.json"))).cases;
const json = (v) => JSON.stringify(v, null, 2) + "\n";

/** Répertoire de travail du test, sous le répertoire temporaire du système ; effacé à la fin. */
const TRAVAIL = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-test-paquet-"));
after(() => fs.rmSync(TRAVAIL, { recursive: true, force: true }));
let numero = 0;
/** Répertoire neuf et vide, donné à l'outil comme TMPDIR. */
const neuf = () => {
  const d = path.join(TRAVAIL, `t${++numero}`);
  fs.mkdirSync(d);
  return d;
};

/** Lance l'outil de vérification ; rend { status, stdout, stderr, rapport (si --json) }. */
function verifier(args, { tmp = neuf() } = {}) {
  const r = spawnSync(process.execPath, [OUTIL, ...args], { encoding: "utf8", env: { TMPDIR: tmp }, maxBuffer: 64 * 1024 * 1024 });
  let rapport = null;
  if (args.includes("--json")) rapport = JSON.parse(r.stdout);
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, rapport, tmp };
}
const argsCas = (c) => {
  const a = [path.join(VECT, c.archive)];
  if (c.options.expected_sha256) a.push("--empreinte", c.options.expected_sha256);
  if (c.options.anchors) a.push("--ancres", path.join(PROJECT_ROOT, c.options.anchors));
  return a;
};
const conformeRapport = (r) => J.validerSchema(r, SCHEMA, { fragment: "#/$defs/rapport" });
/** Blocs JSON annotés `<!-- schema: paquet-reviseur… -->` de CT-8 : [nom de définition ou "", valeur]. */
const annotes = [...CT8.matchAll(/<!-- schema: paquet-reviseur(?:\/([a-z_]+))? -->\n```json\n([\s\S]*?)\n```/g)].map((m) => [m[1] ?? "", J.analyserJSONStrict(m[2])]);
/** Bloc `<!-- fichier: nom -->` de 13.11, avec son saut de ligne final. */
const blocFichier = (nom) => new RegExp(`<!-- fichier: ${nom.replace(".", "\\.")} -->\\n\`\`\`text\\n([\\s\\S]*?)\\n\`\`\`\\n`).exec(CT8)[1] + "\n";

/** Description de valide.tar aux chemins absolus, vérificateur joint au choix (comme la CI, EX-A.29). */
function descriptionAbsolue(include_verifier) {
  const abs = (p) => (p === null ? null : path.resolve(Paquets.REPERTOIRE_PAQUETS, p));
  const d = structuredClone(Paquets.DESCRIPTION);
  d.dossiers = d.dossiers.map((x) => ({ source: abs(x.source), anchors: abs(x.anchors), bitcoin_headers: abs(x.bitcoin_headers) }));
  d.attestation = { signed: abs(d.attestation.signed), approver_set: abs(d.attestation.approver_set) };
  d.pieces = d.pieces.map(abs);
  d.include_verifier = include_verifier;
  return d;
}
/** Archive canonique rebâtie après modification de ses entrées, manifeste recalculé. */
function rebatir(archive, modifier) {
  const entrees = P.lireArchive(archive).entrees.map((e) => ({ nom: e.nom, octets: Buffer.from(e.donnees) }));
  const m = J.analyserJSONStrict(entrees.find((e) => e.nom === P.MANIFESTE).octets);
  const autres = modifier(entrees.filter((e) => e.nom !== P.MANIFESTE), m);
  m.files = autres.map((e) => {
    const p = e.nom.slice(P.RACINE.length + 1);
    const ancien = m.files.find((f) => f.path === p);
    return { path: p, size: e.octets.length, sha256: P.sha256(e.octets), role: ancien ? ancien.role : P.roleAttendu(p) };
  }).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
  return P.ecrireArchive([...autres, { nom: P.MANIFESTE, octets: Buffer.from(json(m)) }], Date.parse(m.created_at) / 1000);
}

describe("CT-8 : paquet réviseur, vecteurs de la famille paquets (annexe A.10, EX-A.19)", function () {
  this.timeout(600_000);

  it("cas.json suit $defs/fichier_cas : dix-sept cas dans l'ordre d'EX-A.13, treize archives dont le SHA-256 est celui que cas.json déclare", function () {
    const fichier = J.analyserJSONStrict(fs.readFileSync(path.join(VECT, "cas.json")));
    expect(J.validerSchema(fichier, SCHEMA, { fragment: "#/$defs/fichier_cas" })).to.deep.equal([]);
    expect(CAS.map((c) => c.name)).to.deep.equal(["valide", "valide-empreinte", "empreinte-fausse", "fichier-altere", "fichier-manquant", "fichier-en-trop", "manifeste-altere", "contrefacon-coherente", "chemin-hors-archive", "chemin-absolu", "lien-symbolique", "lien-physique", "nom-en-double", "metadonnees-non-fixees", "ancres-du-reviseur-discordantes", "ancres-non-conformes", "observation"]);
    const tars = fs.readdirSync(VECT).filter((f) => f.endsWith(".tar")).sort();
    expect(tars).to.have.length(13);
    expect([...new Set(CAS.map((c) => c.archive))].sort()).to.deep.equal(tars);
    for (const c of CAS) expect(P.sha256(fs.readFileSync(path.join(VECT, c.archive))), c.name).to.equal(c.archive_sha256);
    // Valeurs imprimées par CT-8 (13.3, EX-A.13).
    const valide = fs.readFileSync(path.join(VECT, "valide.tar"));
    expect(valide.length).to.equal(296_960);
    expect(P.sha256(valide)).to.equal("0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982");
    expect(P.sha256(fs.readFileSync(path.join(VECT, "cas.json")))).to.equal("0x0e44622a66a79180a61f72ad90490c427c1c8bbab9c628ee650630337e3cb746");
    expect(tars.reduce((s, f) => s + fs.statSync(path.join(VECT, f)).size, 0)).to.equal(3_624_960);
  });

  it("chaque cas rejoué par l'outil de vérification rend son code, l'état du paquet, le statut et la raison des douze PR-, les avertissements et le code de chaque dossier ; le rapport --json suit $defs/rapport", function () {
    for (const c of CAS) {
      const r = verifier([...argsCas(c), "--json"]);
      expect(r.status, c.name).to.equal(c.expected.exit_code);
      expect(r.rapport.exit_code, c.name).to.equal(c.expected.exit_code);
      expect(conformeRapport(r.rapport), c.name).to.deep.equal([]);
      expect(r.rapport.package_status, c.name).to.equal(c.expected.package_status);
      expect(r.rapport.checks.map((x) => ({ id: x.id, status: x.status, reason: x.reason })), c.name).to.deep.equal(c.expected.checks);
      expect(r.rapport.warnings.map((w) => w.id), c.name).to.deep.equal(c.expected.warnings);
      expect(r.rapport.dossiers.map((d) => ({ path: d.path, exit_code: d.exit_code, observation_mode: d.observation_mode, observation: d.observation })), c.name).to.deep.equal(c.expected.dossiers);
      expect(r.rapport.summary.observation, c.name).to.deep.equal(c.expected.observation);
      expect(r.rapport.error, c.name).to.equal(null);
      // EX-A.19 : rien n'est écrit pour un paquet non conforme ; le répertoire d'extraction est effacé sinon.
      expect(fs.readdirSync(r.tmp).filter((f) => f !== "node-compile-cache"), c.name).to.deep.equal([]);
    }
  });

  it("le rapport du cas fichier-altere égale l'exemple annoté de 13.7, aux chemins et à tool.runtime près ; deux exécutions écrivent les mêmes octets (EX-13.29)", function () {
    const c = CAS.find((x) => x.name === "fichier-altere");
    const a = verifier([...argsCas(c), "--json"]);
    const b = verifier([...argsCas(c), "--json"]);
    expect(a.stdout).to.equal(b.stdout);
    const exemple = annotes.find(([def]) => def === "rapport")[1];
    const r = structuredClone(a.rapport);
    r.inputs.archive.path = exemple.inputs.archive.path;
    r.tool.runtime = exemple.tool.runtime;
    expect(r).to.deep.equal(exemple);
  });

  it("résumés lisibles de 13.7 : valide.tar (fr), valide.tar en anglais avec --empreinte et --ancres, fichier-altere.tar, contrefacon-coherente.tar ; lignes égales au texte, chemins abrégés, version de Node et lignes Énoncé omises par le texte exceptées", function () {
    const section = CT8.slice(CT8.indexOf("### 13.7 "), CT8.indexOf("### 13.8 "));
    const blocs = [...section.matchAll(/```text\n(\$ node scripts\/paquet-reviseur\/verifier\.mjs[\s\S]*?)\n```/g)].map((m) => m[1]);
    expect(blocs).to.have.length(4);
    const invocations = [
      [path.join(VECT, "valide.tar")],
      [path.join(VECT, "valide.tar"), "--langue", "en", "--empreinte", "8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982", "--ancres", path.join(SPEC, "vecteurs", "ct-6", "ancres", "ancres-test.json")],
      [path.join(VECT, "fichier-altere.tar")],
      [path.join(VECT, "contrefacon-coherente.tar")],
    ];
    blocs.forEach((bloc, i) => {
      const sansVersionNode = (l) => l.replace(/\(node v[0-9.]+\)$/, "(node)");
      const attendu = bloc.split("\n").filter((l) => !l.startsWith("$") && !l.startsWith("    --") && !/^[0-9]$/.test(l)).map(sansVersionNode);
      const avecEnonce = attendu.some((l) => /^ +(Énoncé|Statement) : /.test(l));
      const r = verifier(invocations[i]);
      const lignes = r.stdout.replace(/\n$/, "").split("\n").map((l) => sansVersionNode(l.split(path.resolve(PROJECT_ROOT)).join("…"))).filter((l) => avecEnonce || !/^ +(Énoncé|Statement) : /.test(l));
      expect(lignes, `bloc ${i + 1}`).to.deep.equal(attendu);
      const derniere = bloc.split("\n").at(-1);
      const code = /^[0-9]$/.test(derniere) ? Number(derniere) : Number(/code ([0-9])$/.exec(attendu.at(-1))[1]);
      expect(r.status, `bloc ${i + 1}`).to.equal(code);
    });
  });

  it("deux constructions de valide.tar depuis la description de 13.5 sont identiques et égales au fichier des vecteurs ; description.json égale le bloc de 13.5", function () {
    const a = construire(Paquets.DESCRIPTION, Paquets.REPERTOIRE_PAQUETS).archive;
    const b = construire(J.analyserJSONStrict(fs.readFileSync(path.join(VECT, "description.json"))), VECT).archive;
    expect(a.equals(b)).to.equal(true);
    expect(a.equals(fs.readFileSync(path.join(VECT, "valide.tar")))).to.equal(true);
    const bloc = annotes.find(([def]) => def === "description_source")[1];
    expect(J.analyserJSONStrict(fs.readFileSync(path.join(VECT, "description.json")))).to.deep.equal(bloc);
    expect(fs.readFileSync(path.join(VECT, "description.json"), "utf8")).to.equal(json(bloc));
  });

  it("le manifeste de valide.tar égale l'exemple annoté de 13.3 (49 fichiers, 241 340 octets, 11 274 octets et SHA-256 imprimés) ; la longueur suit la formule d'EX-13.14", function () {
    const valide = fs.readFileSync(path.join(VECT, "valide.tar"));
    const lu = P.lireArchive(valide);
    const man = lu.entrees.find((e) => e.nom === P.MANIFESTE).donnees;
    expect(man.length).to.equal(11_274);
    expect(P.sha256(man)).to.equal("0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1");
    const exemple = annotes.find(([def]) => def === "")[1];
    expect(J.analyserJSONStrict(man)).to.deep.equal(exemple);
    expect(man.toString("utf8")).to.equal(json(exemple));
    expect(exemple.files).to.have.length(49);
    expect(exemple.files.reduce((s, f) => s + f.size, 0)).to.equal(241_340);
    expect(valide.length).to.equal(P.longueurCanonique(lu.entrees.map((e) => e.taille)));
    expect(lu.entrees.every((e) => e.mtime === 1_793_059_200)).to.equal(true);
  });

  it("la recette GNU tar d'EX-13.15 reproduit valide.tar octet pour octet (sautée si tar n'est pas GNU tar)", function () {
    const v = spawnSync("tar", ["--version"], { encoding: "utf8" });
    if (v.status !== 0 || !/GNU tar/.test(v.stdout)) this.skip();
    const rep = neuf();
    expect(spawnSync("tar", ["-xf", path.join(VECT, "valide.tar"), "-C", rep]).status).to.equal(0);
    const r = spawnSync("bash", ["-c", "find paquet-reviseur -type f | LC_ALL=C sort > liste.txt && LC_ALL=C tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner --mode=0644 --mtime=@1793059200 -cf paquet.tar -T liste.txt"], { cwd: rep, encoding: "utf8" });
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(path.join(rep, "paquet.tar")).equals(fs.readFileSync(path.join(VECT, "valide.tar")))).to.equal(true);
  });

  it("le générateur, rejoué dans un répertoire neuf, écrit les mêmes octets que les vecteurs publiés (EX-A.10)", function () {
    const rep = path.join(neuf(), "paquets");
    Paquets.genererPaquets(rep);
    const publies = fs.readdirSync(VECT).sort();
    expect(fs.readdirSync(rep).sort()).to.deep.equal(publies);
    for (const f of publies) expect(fs.readFileSync(path.join(rep, f)).equals(fs.readFileSync(path.join(VECT, f))), f).to.equal(true);
  });
});

describe("CT-8 : outil de vérification du paquet réviseur, cas des tests (13.7, 13.8, EX-A.19)", function () {
  this.timeout(600_000);
  const valide = fs.readFileSync(path.join(VECT, "valide.tar"));

  it("erreurs d'usage : code 2, type usage, rapport JSON avec --json, avant toute lecture de l'archive (EX-13.24)", function () {
    const archive = path.join(VECT, "valide.tar");
    const existant = neuf();
    const cas = [
      [["--inconnue", archive, "--json"], /option inconnue/],
      [[archive, "--json", "--json"], /option répétée/],
      [[archive, "--empreinte", "--json"], /--empreinte/],
      [[archive, "--json", "--empreinte"], /sans valeur/],
      [[archive, "--json", "--langue", "de"], /--langue/],
      [[archive, "--json", "--exiger", "0,9"], /--exiger/],
      [["--json"], /exactement une archive/],
      [[archive, archive, "--json"], /exactement une archive/],
      [["--version", archive, "--json"], /--version et --aide/],
      [["--version", "--json"], /--version et --aide/],
      [["--aide", "--version", "--json"], /--version et --aide/],
      [[archive, "--json", "--conserver", existant], /existe déjà/],
      [[path.join(TRAVAIL, "absente.tar"), "--json", "--ancres", path.join(TRAVAIL, "absent.json")], /--ancres/],
    ];
    for (const [args, motif] of cas) {
      const r = verifier(args);
      expect(r.status, args.join(" ")).to.equal(2);
      expect(conformeRapport(r.rapport), args.join(" ")).to.deep.equal([]);
      expect(r.rapport.error.type, args.join(" ")).to.equal("usage");
      expect(r.rapport.error.message, args.join(" ")).to.match(motif);
      expect(r.rapport.inputs.archive, args.join(" ")).to.equal(null);
      expect(r.rapport.checks, args.join(" ")).to.deep.equal([]);
    }
    // --conserver vers un répertoire existant : rien n'y est écrit.
    expect(fs.readdirSync(existant)).to.deep.equal([]);
    // Sans --json : une ligne « Erreur : » sur la sortie d'erreur, en anglais avec --langue en.
    const fr = verifier(["--inconnue"]);
    expect([fr.status, fr.stdout, fr.stderr]).to.deep.equal([2, "", "Erreur : option inconnue : --inconnue\n"]);
    const en = verifier([archive, "--langue", "en", "--conserver", existant]);
    expect(en.status).to.equal(2);
    expect(en.stderr).to.match(/^Error: --conserver /);
  });

  it("archive absente : code 2, type archive_illisible ; --aide et --version : code 0", function () {
    const r = verifier([path.join(TRAVAIL, "absente.tar"), "--json"]);
    expect(r.status).to.equal(2);
    expect(r.rapport.error.type).to.equal("archive_illisible");
    expect(r.rapport.package_status).to.equal(null);
    expect(conformeRapport(r.rapport)).to.deep.equal([]);
    for (const langue of ["fr", "en"]) {
      const a = verifier(["--aide", "--langue", langue]);
      expect(a.status).to.equal(0);
      for (const o of ["--empreinte", "--ancres", "--exiger", "--langue", "--json", "--conserver", "--version", "--aide"]) expect(a.stdout, `${langue} ${o}`).to.include(o);
    }
    const v = verifier(["--version"]);
    expect(v.status).to.equal(0);
    const lignes = v.stdout.trim().split("\n");
    expect(lignes[0]).to.equal(`scripts/paquet-reviseur/verifier.mjs 0.1.0 (node ${process.version})`);
    const chemins = lignes.slice(1).map((l) => l.split("  ")[1]);
    expect(chemins).to.deep.equal([...P.FICHIERS_VERIFICATEUR.map((f) => `verificateur/${f}`), "verificateur/node_modules/ethers/package.json", "verificateur/node_modules/ethers/dist/ethers.js", "verificateur/node_modules/ethers/LICENSE.md"]);
  });

  it("archive compressée par gzip -n : code 4 ; PR-3 dit « décompressez-la d'abord » quand la longueur est un multiple de 512, PR-1 le dit sinon (EX-13.16)", function () {
    const z = spawnSync("gzip", ["-n", "-c"], { input: valide, maxBuffer: 64 * 1024 * 1024 });
    if (z.status !== 0) this.skip();
    const brut = z.stdout;
    const bourre = Buffer.concat([brut, Buffer.alloc((512 - (brut.length % 512)) % 512, 0)]);
    for (const [octets, id] of [[bourre, "PR-3"], ...(brut.length % 512 ? [[brut, "PR-1"]] : [])]) {
      const f = path.join(neuf(), "paquet.tar.gz");
      fs.writeFileSync(f, octets);
      const r = verifier([f, "--json"]);
      expect(r.status).to.equal(4);
      const c = r.rapport.checks.find((x) => x.status === "echoue");
      expect(c.id).to.equal(id);
      expect(c.detail).to.match(/gzip.*décompressez-la d'abord/);
      expect(fs.readdirSync(r.tmp).filter((x) => x !== "node-compile-cache")).to.deep.equal([]);
    }
  });

  it("PR-1, PR-3, PR-7 et PR-9 (« — (tests) » de la table de 13.8) : chacune échoue seule sur une archive faite pour elle, et arrête les suivantes", function () {
    const premierEchec = (octets) => {
      const r = P.lireEtVerifier(octets, { langue: "fr" });
      expect(r.intact).to.equal(false);
      const i = r.checks.findIndex((c) => c.status === "echoue");
      for (const c of r.checks.slice(i + 1)) expect([c.status, c.reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
      return r.checks[i];
    };
    // PR-1 : longueur hors des bornes ou non multiple de 512.
    expect(premierEchec(Buffer.alloc(512)).id).to.equal("PR-1");
    expect(premierEchec(valide.subarray(0, valide.length - 100)).id).to.equal("PR-1");
    // PR-3 : somme de contrôle fausse ; magie autre que ustar ; données tronquées ; octets après la fin.
    const somme = Buffer.from(valide);
    somme[148] = somme[148] === 0x30 ? 0x31 : 0x30;
    expect(premierEchec(somme)).to.include({ id: "PR-3" });
    const magie = Buffer.from(valide);
    magie.write("ustaR", 257, "ascii");
    expect(premierEchec(magie).detail).to.match(/magie/);
    const apres = Buffer.from(valide);
    apres[apres.length - 1] = 1;
    expect(premierEchec(apres).detail).to.match(/après la fin d'archive/);
    // PR-7 : pas de manifeste (archive canonique, sinon conforme).
    const entrees = P.lireArchive(valide).entrees.filter((e) => e.nom !== P.MANIFESTE).map((e) => ({ nom: e.nom, octets: Buffer.from(e.donnees) }));
    expect(premierEchec(P.ecrireArchive(entrees, 1_793_059_200))).to.include({ id: "PR-7" });
    // PR-7 : created_at différent de la date des entrées.
    const decale = P.ecrireArchive(P.lireArchive(valide).entrees.map((e) => ({ nom: e.nom, octets: Buffer.from(e.donnees) })), 1_793_059_201);
    expect(premierEchec(decale).detail).to.match(/created_at/);
    // PR-9 : un fichier de pièce déclaré au rôle « ancres », manifeste recalculé ; PR-8 réussit.
    const roles = rebatir(valide, (e, m) => {
      m.files.find((f) => f.path === "pieces/instance-r1.json").role = "ancres";
      return e;
    });
    const r9 = premierEchec(roles);
    expect(r9.id).to.equal("PR-9");
    expect(r9.detail).to.match(/pieces\/instance-r1\.json : rôle ancres au lieu de pieces/);
    expect(P.lireEtVerifier(roles, { langue: "en" }).checks.find((c) => c.id === "PR-9").detail).to.match(/pieces\/instance-r1\.json: role ancres instead of pieces/);
  });

  it("PR-5 : un nom de plus de 100 octets se découpe en préfixe et nom (EX-13.14) et passe ; deux noms égaux à la casse près échouent", function () {
    const long = `${P.RACINE}/pieces/${"a".repeat(60)}/${"b".repeat(60)}.json`;
    expect(P.decouper(long)).to.deep.equal({ prefix: `${P.RACINE}/pieces/${"a".repeat(60)}`, name: `${"b".repeat(60)}.json` });
    const lu = P.lireArchive(P.ecrireArchive([{ nom: long, octets: Buffer.from("{}\n") }], 0));
    expect(lu.entrees[0].nom).to.equal(long);
    expect(P.verifierNoms(lu.entrees)).to.equal(null);
    expect(P.verifierForme(lu.entrees, 10240)).to.equal(null);
    const casse = P.lireArchive(P.ecrireArchive([{ nom: `${P.RACINE}/A.txt`, octets: Buffer.from("1") }, { nom: `${P.RACINE}/a.txt`, octets: Buffer.from("2") }], 0)).entrees;
    expect(P.verifierNoms(casse).fr).to.match(/égaux à la casse près/);
  });

  it("PR-10 en échec (répertoire --conserver dont le parent n'existe pas) : code 2, type extraction_impossible, PR-11 et PR-12 non exécutées", function () {
    const r = verifier([path.join(VECT, "valide.tar"), "--json", "--conserver", path.join(TRAVAIL, "absent", "extrait")]);
    expect(r.status).to.equal(2);
    expect(conformeRapport(r.rapport)).to.deep.equal([]);
    expect(r.rapport.package_status).to.equal("intact");
    expect(r.rapport.error.type).to.equal("extraction_impossible");
    expect(r.rapport.checks.slice(9).map((c) => [c.id, c.status, c.reason])).to.deep.equal([
      ["PR-10", "echoue", null],
      ["PR-11", "non_execute", "prerequis_en_echec"],
      ["PR-12", "non_execute", "prerequis_en_echec"],
    ]);
  });

  it("--conserver vers un chemin neuf : le paquet y est extrait (mode 0700 et 0600) et gardé ; code 0", function () {
    const dest = path.join(neuf(), "extrait");
    const r = verifier([path.join(VECT, "valide.tar"), "--conserver", dest]);
    expect(r.status).to.equal(0);
    expect(fs.statSync(dest).mode & 0o777).to.equal(0o700);
    const man = path.join(dest, P.RACINE, "MANIFESTE.json");
    expect(fs.statSync(man).mode & 0o777).to.equal(0o600);
    expect(P.sha256(fs.readFileSync(man))).to.equal("0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1");
  });

  it("paquet complet construit dans le test : code 0, PR-11 réussie ; un fichier de verificateur/ changé et le manifeste recalculé : code 0, PR-11 en échec, AV-PR-1 (EX-13.34)", function () {
    const { archive, manifeste } = construire(descriptionAbsolue(true), PROJECT_ROOT);
    expect(construire(descriptionAbsolue(true), PROJECT_ROOT).archive.equals(archive)).to.equal(true);
    expect(manifeste.verifier).to.deep.equal({ tool: "verificateur/scripts/paquet-reviseur/verifier.mjs", dossier_verifier: "verificateur/scripts/verify/dossier.mjs", version: "0.1.0", runtime: "Node.js 22 ou ultérieur" });
    expect(manifeste.files.filter((f) => f.role === "verificateur")).to.have.length(P.FICHIERS_VERIFICATEUR.length + 3);
    const f = path.join(neuf(), "complet.tar");
    fs.writeFileSync(f, archive);
    const r = verifier([f, "--json", "--empreinte", P.sha256(archive)]);
    expect(r.status).to.equal(0);
    expect(r.rapport.checks.map((c) => c.status)).to.deep.equal(Array(12).fill("reussi"));
    expect(r.rapport.warnings.map((w) => w.id)).to.deep.equal(["AV-PR-3"]);
    const change = rebatir(archive, (e) => e.map((x) => (x.nom === `${P.RACINE}/verificateur/scripts/lib/paquet.mjs` ? { nom: x.nom, octets: Buffer.concat([x.octets, Buffer.from("// ajout\n")]) } : x)));
    const g = path.join(neuf(), "change.tar");
    fs.writeFileSync(g, change);
    const s = verifier([g, "--json"]);
    expect(s.status).to.equal(0);
    expect(s.rapport.package_status).to.equal("intact");
    const pr11 = s.rapport.checks.find((c) => c.id === "PR-11");
    expect([pr11.status, pr11.detail]).to.deep.equal(["echoue", "vérificateur joint différent de l'outil exécuté : verificateur/scripts/lib/paquet.mjs"]);
    expect(s.rapport.warnings.map((w) => w.id)).to.deep.equal(["AV-PR-1", "AV-PR-3"]);
  });

  it("marque d'observation (EX-13.28) : la décision est lue après la dernière occurrence de « [observation » ; exemples de la section 12", function () {
    const exemples = [
      ["lectures autorisees [observation autorise]", "autorise"],
      ["paiement > 5000 CHF [observation a_approuver]", "a_approuver"],
      ["paiement hors CHF [observation refuse]", "refuse"],
      ["defaut : revue [observation a_approuver]", "a_approuver"],
      ["paiement > 5000 CHF [indetermine] [observation a_approuver]", "a_approuver"],
      ["evaluation impossible [observation inconnu]", "inconnu"],
      ["paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z] [observation autorise]", "autorise"],
      ["paiement > 5000 CHF", null],
      ["regle [observation autorise] [observation refusee]", null],
      ["regle [observation autre]", null],
      ["regle [observation autorise] suite", null],
      [null, null],
    ];
    for (const [regle, attendu] of exemples) expect(marqueObservation(regle), String(regle)).to.equal(attendu);
    // Les exemples de la table de 12.3 sont repris du texte.
    for (const [regle] of exemples.slice(0, 6)) expect(CT8).to.include(`\`${regle}\``);
  });

  it("le package.json engendré pour ethers égale le texte exact d'EX-13.21 ; dist/ethers.js est celui de la version du dépôt", function () {
    const bloc = /qui fait désigner ce fichier par le nom `ethers`, au texte exact :\n\n```json\n([\s\S]*?)\n```/.exec(CT8)[1] + "\n";
    const version = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "node_modules", "ethers", "package.json"), "utf8")).version;
    expect(P.paquetEthers(version).toString("utf8")).to.equal(bloc.replace("6.17.0", version));
    const v = P.fichiersVerificateur();
    expect(v.get("verificateur/node_modules/ethers/dist/ethers.js").equals(fs.readFileSync(path.join(PROJECT_ROOT, "node_modules", "ethers", "dist", "ethers.js")))).to.equal(true);
  });
});

describe("CT-8 : outil de construction du paquet réviseur (13.5)", function () {
  this.timeout(120_000);
  const construireCli = (args) => spawnSync(process.execPath, [CONSTRUIRE, ...args], { encoding: "utf8" });

  it("la CLI écrit l'archive de la description des vecteurs (égale à valide.tar), imprime tailles et SHA-256, et refuse une sortie existante avant tout travail", function () {
    const rep = neuf();
    const sortie = path.join(rep, "p.tar");
    const r = construireCli(["--description", path.join(VECT, "description.json"), "--sortie", sortie]);
    expect(r.status, r.stderr).to.equal(0);
    expect(fs.readFileSync(sortie).equals(fs.readFileSync(path.join(VECT, "valide.tar")))).to.equal(true);
    expect(r.stdout).to.include("296960 octets, SHA-256 0x8b977c10452e6a2c0b61319360834e3c06aa5e2a2b6208c9580c96b4dac33982");
    expect(r.stdout).to.include("49 fichiers, 3 dossier(s), SHA-256 0x5667fad9e2d6f8da8e3960304a8bb227638834f3e9319da20241f1f86a353fb1");
    expect(r.stdout).to.match(/par un autre canal/);
    const s = construireCli([`--description=${path.join(TRAVAIL, "absente.json")}`, "--sortie", sortie]);
    expect(s.status).to.equal(2);
    expect(s.stderr).to.match(/existe déjà/);
  });

  it("refus en code 2, sans rien écrire : option inconnue, répétée ou sans valeur, description absente ou non conforme, partie absente d'un dossier", function () {
    const rep = neuf();
    const sortie = path.join(rep, "p.tar");
    const desc = (d) => {
      const f = path.join(neuf(), "d.json");
      fs.writeFileSync(f, json(d));
      return f;
    };
    const dossierIncomplet = path.join(neuf(), "dossier-incomplet");
    fs.cpSync(path.resolve(Paquets.REPERTOIRE_PAQUETS, Paquets.DESCRIPTION.dossiers[0].source), dossierIncomplet, { recursive: true });
    fs.rmSync(path.join(dossierIncomplet, "voisins.json"));
    const incomplet = descriptionAbsolue(false);
    incomplet.dossiers[0].source = dossierIncomplet;
    const cas = [
      [["--description", path.join(VECT, "description.json"), "--sortie", sortie, "--x"], /option inconnue/],
      [["--description", path.join(VECT, "description.json"), "--description", path.join(VECT, "description.json"), "--sortie", sortie], /option répétée/],
      [["--description", path.join(VECT, "description.json"), "--sortie"], /sans valeur/],
      [["--sortie", sortie], /obligatoires/],
      [["--description", path.join(TRAVAIL, "absente.json"), "--sortie", sortie], /illisible/],
      [["--description", desc({ ...Paquets.DESCRIPTION, version: 1 }), "--sortie", sortie], /description non conforme/],
      [["--description", desc(incomplet), "--sortie", sortie], /voisins\.json : illisible/],
    ];
    for (const [args, motif] of cas) {
      const r = construireCli(args);
      expect(r.status, args.join(" ")).to.equal(2);
      expect(r.stderr, args.join(" ")).to.match(motif);
    }
    expect(fs.readdirSync(rep)).to.deep.equal([]);
    const aide = construireCli(["--aide"]);
    expect(aide.status).to.equal(0);
    expect(aide.stdout).to.include("--description");
  });
});

describe("CT-8 : instructions au réviseur et textes des résumés (13.10, 13.11, EX-A.20)", function () {
  this.timeout(600_000);
  const INSTR = path.join(PROJECT_ROOT, "scripts", "paquet-reviseur", "instructions");

  it("LISEZMOI.md et README.md égalent, octet pour octet, les blocs de 13.11 et les SHA-256 d'EX-13.36", function () {
    expect(fs.readFileSync(path.join(INSTR, "LISEZMOI.md"), "utf8")).to.equal(blocFichier("LISEZMOI.md"));
    expect(fs.readFileSync(path.join(INSTR, "README.md"), "utf8")).to.equal(blocFichier("README.md"));
    expect(P.sha256(fs.readFileSync(path.join(INSTR, "LISEZMOI.md")))).to.equal("0x858905b068fdf7cb3db303e3d614e8ac8712e2833f8c13522325c22a44aeac14");
    expect(P.sha256(fs.readFileSync(path.join(INSTR, "README.md")))).to.equal("0x4874a8613621cd372cfe8fef9bacb391d4772d4ee1bd9bfe74a421b8f2743d34");
  });

  it("les deux instructions ont la même structure : titres de niveau 1 et 2 en même nombre, mêmes blocs de commande indentés (aux noms de paramètres près), table des codes de cinq lignes 0 à 4", function () {
    const fr = fs.readFileSync(path.join(INSTR, "LISEZMOI.md"), "utf8").split("\n");
    const en = fs.readFileSync(path.join(INSTR, "README.md"), "utf8").split("\n");
    const titres = (l, n) => l.filter((x) => x.startsWith("#".repeat(n) + " ")).length;
    for (const n of [1, 2]) expect(titres(fr, n), `niveau ${n}`).to.equal(titres(en, n));
    expect(titres(fr, 1)).to.equal(1);
    expect(titres(fr, 2)).to.equal(5);
    const commandes = (l) => l.filter((x) => /^ {7,}\S/.test(x)).map((x) => x.replace(/<[^>]*>/g, "<>").trim());
    expect(commandes(fr)).to.deep.equal(commandes(en));
    expect(commandes(fr)).to.have.length(3);
    expect(commandes(fr)[0]).to.equal("node <>/scripts/paquet-reviseur/verifier.mjs <> \\");
    // Les deux premières lignes finissent par une barre oblique de continuation : copiée telle quelle, la commande transmet --empreinte et --ancres.
    expect(commandes(fr)[1].endsWith(" \\")).to.equal(true);
    expect(commandes(fr)[2].endsWith("\\")).to.equal(false);
    const codes = (l) => l.filter((x) => /^\| [0-9] \|/.test(x)).map((x) => x.slice(0, 5));
    expect(codes(fr)).to.deep.equal(["| 0 |", "| 1 |", "| 2 |", "| 3 |", "| 4 |"]);
    expect(codes(en)).to.deep.equal(codes(fr));
  });

  it("aucun résumé ni rapport des vecteurs ne présente comme prouvés le périmètre ou les ancres du paquet (lignes Attestation, Avertissements, AV-PR-3 ; PR-12 et avertissements du rapport)", function () {
    // « prouvé », « prouve », « proven » ne s'emploient qu'avec leur négation.
    const affirme = /(?<!non |not )\b(prouvé|prouve|proven)\b/i;
    for (const c of CAS) {
      for (const langue of ["fr", "en"]) {
        const lisible = verifier([...argsCas(c), "--langue", langue]).stdout.split("\n");
        let dansAvert = false;
        for (const l of lisible) {
          if (/^(Avertissements :|Warnings:)$/.test(l)) dansAvert = true;
          else if (!l.startsWith("  ")) dansAvert = false;
          if (dansAvert || /^Attestation +:/.test(l) || l.includes("AV-PR-3")) expect(affirme.test(l), `${c.name} ${langue} : ${l}`).to.equal(false);
        }
        const r = verifier([...argsCas(c), "--json", "--langue", langue]).rapport;
        for (const w of r.warnings) expect(affirme.test(w.detail), `${c.name} ${langue} ${w.id}`).to.equal(false);
        const pr12 = r.checks.find((x) => x.id === "PR-12");
        expect(affirme.test(pr12.detail), `${c.name} ${langue} PR-12`).to.equal(false);
      }
    }
  });

  it("chaque exemple JSON annoté <!-- schema: paquet-reviseur… --> de CT-8 suit son schéma ou son $defs", function () {
    expect(annotes.map(([def]) => def).sort()).to.deep.equal(["", "cas", "description_source", "rapport"]);
    for (const [def, valeur] of annotes) expect(J.validerSchema(valeur, SCHEMA, def ? { fragment: `#/$defs/${def}` } : {}), def || "paquet-reviseur").to.deep.equal([]);
    // L'exemple de cas égale le cas fichier-altere de cas.json.
    expect(annotes.find(([def]) => def === "cas")[1]).to.deep.equal(CAS.find((c) => c.name === "fichier-altere"));
  });
});

describe("CT-8 : corrections du paquet réviseur (découpage GNU tar, dates, casse, terminal, extraction, langues, copie jointe)", function () {
  this.timeout(600_000);
  const valide = fs.readFileSync(path.join(VECT, "valide.tar"));
  const gnuTar = () => {
    const v = spawnSync("tar", ["--version"], { encoding: "utf8" });
    return v.status === 0 && /GNU tar/.test(v.stdout);
  };

  it("EX-13.14 : un nom de plus de 100 octets prend le plus long préfixe de 155 octets au plus, comme GNU tar (en-tête comparé à celui de GNU tar quand il est présent)", function () {
    const nom = `${P.RACINE}/dossiers/${"d".repeat(60)}/jeton-rfc3161.der`;
    expect(Buffer.byteLength(nom)).to.equal(103);
    expect(P.decouper(nom)).to.deep.equal({ prefix: `${P.RACINE}/dossiers/${"d".repeat(60)}`, name: "jeton-rfc3161.der" });
    // Aucun « / » parmi les 156 premiers octets dont le reste tienne en 100 : non représentable.
    expect(() => P.decouper(`${P.RACINE}/${"x".repeat(150)}`)).to.throw(/non représentable/);
    if (!gnuTar()) this.skip();
    const rep = neuf();
    fs.mkdirSync(path.join(rep, path.dirname(nom)), { recursive: true });
    fs.writeFileSync(path.join(rep, nom), "x\n");
    const r = spawnSync("bash", ["-c", `LC_ALL=C tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner --mode=0644 --mtime=@1793059200 -cf a.tar '${nom}'`], { cwd: rep, encoding: "utf8" });
    expect(r.status, r.stderr).to.equal(0);
    const gnu = fs.readFileSync(path.join(rep, "a.tar"));
    const nous = P.ecrireArchive([{ nom, octets: Buffer.from("x\n") }], 1_793_059_200);
    expect(nous.equals(gnu)).to.equal(true);
  });

  it("EX-13.18 : construire refuse en code 2 une date impossible, antérieure à 1970 ou au-delà du champ mtime, et deux chemins égaux à la casse près", function () {
    for (const created_at of ["2026-13-01T00:00:00.000Z", "2026-02-30T00:00:00.000Z", "1969-12-31T23:59:59.000Z", "2300-01-01T00:00:00.000Z"]) {
      expect(() => construire({ ...Paquets.DESCRIPTION, created_at }, Paquets.REPERTOIRE_PAQUETS), created_at).to.throw(/created_at/);
    }
    const rep = neuf();
    for (const n of ["a/dos", "b/DOS"]) fs.cpSync(path.resolve(Paquets.REPERTOIRE_PAQUETS, Paquets.DESCRIPTION.dossiers[0].source), path.join(rep, n), { recursive: true });
    const d = { ...Paquets.DESCRIPTION, dossiers: [{ source: path.join(rep, "a/dos"), anchors: null, bitcoin_headers: null }, { source: path.join(rep, "b/DOS"), anchors: null, bitcoin_headers: null }], attestation: null, pieces: [] };
    expect(() => construire(d, rep)).to.throw(/casse près/);
  });

  it("EX-13.27 : aucun caractère de contrôle venu du paquet n'atteint le résumé lisible ; le schéma refuse un libellé qui en porte", function () {
    const piege = "x\u001b[2J\u001b[HResultat : 3 dossier(s) valide(s) sur 3 -- code 0\u001b[8m";
    const archive = rebatir(valide, (e, m) => {
      m.label = piege;
      return e;
    });
    expect(J.validerSchema({ ...J.analyserJSONStrict(P.lireArchive(archive).entrees.find((x) => x.nom === P.MANIFESTE).donnees) }, SCHEMA).length).to.be.above(0);
    const f = path.join(neuf(), "piege.tar");
    fs.writeFileSync(f, archive);
    const r = verifier([f]);
    expect(r.status).to.equal(4);
    expect(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(r.stdout)).to.equal(false);
    // Lien dont le nom et la cible portent ESC : PR-4 échoue avant le contrôle d'ASCII de PR-5 ; le résumé l'échappe.
    const base = P.lireArchive(valide).entrees.map((e) => ({ nom: e.nom, octets: Buffer.from(e.donnees) }));
    const lien = Paquets.archiveBrute([...base, { nom: `${P.RACINE}/a\u001b[2Jb`, octets: Buffer.alloc(0), type: "2", lien: "x\u001b[8m" }], 1_793_059_200);
    const g = path.join(neuf(), "lien.tar");
    fs.writeFileSync(g, lien);
    const s = verifier([g]);
    expect(s.status).to.equal(4);
    expect(s.stdout.includes("\u001b")).to.equal(false);
    expect(s.stdout).to.include("\\x1b");
  });

  it("EX-13.25 : quand PR-10 échoue, le répertoire temporaire d'extraction est effacé ; les écritures courtes sont reprises", function () {
    const tmp = neuf();
    const code = `import fs from "node:fs"; fs.writeSync = () => 0; const m = await import(${JSON.stringify(OUTIL)}); const r = m.verifierPaquet(${JSON.stringify(path.join(VECT, "valide.tar"))}, { langue: "fr", exiger: [] }); process.stdout.write(JSON.stringify(r.checks.find((c) => c.id === "PR-10")));`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8", env: { TMPDIR: tmp } });
    expect(r.status, r.stderr).to.equal(0);
    expect(JSON.parse(r.stdout).status).to.equal("echoue");
    expect(fs.readdirSync(tmp).filter((f) => f !== "node-compile-cache")).to.deep.equal([]);
    // Écritures d'au plus 1000 octets : l'extraction réussit quand même.
    const tmp2 = neuf();
    const code2 = `import fs from "node:fs"; const w = fs.writeSync; fs.writeSync = (fd, b, o, l) => w(fd, b, o, Math.min(l, 1000)); const m = await import(${JSON.stringify(OUTIL)}); const r = m.verifierPaquet(${JSON.stringify(path.join(VECT, "valide.tar"))}, { langue: "fr", exiger: [] }); process.stdout.write(String(r.exit_code));`;
    const s = spawnSync(process.execPath, ["--input-type=module", "-e", code2], { encoding: "utf8", env: { TMPDIR: tmp2 } });
    expect(s.stdout, s.stderr).to.equal("0");
  });

  it("13.7 : les messages d'usage suivent --langue (fr, en)", function () {
    const en = verifier(["--langue", "en", "--bogus"]);
    expect([en.status, en.stderr]).to.deep.equal([2, "Error: unknown option: --bogus\n"]);
    const j = verifier(["--langue", "en", "--json"]);
    expect(j.rapport.error.message).to.equal("exactly one archive expected");
    const fr = verifier(["--json"]);
    expect(fr.rapport.error.message).to.equal("exactement une archive attendue");
  });

  it("13.11 : une entrée en double fait échouer « tar -xkf » au lieu de remplacer le premier fichier (GNU tar)", function () {
    if (!gnuTar()) this.skip();
    const rep = neuf();
    const r = spawnSync("tar", ["-xkf", path.join(VECT, "nom-en-double.tar"), "-C", rep], { encoding: "utf8" });
    expect(r.status).to.equal(2);
    expect(r.stderr).to.match(/exists/);
    const premier = P.lireArchive(fs.readFileSync(path.join(VECT, "nom-en-double.tar"))).entrees.find((e) => e.nom === `${P.RACINE}/LISEZMOI.md`);
    expect(fs.readFileSync(path.join(rep, P.RACINE, "LISEZMOI.md")).equals(premier.donnees)).to.equal(true);
  });

  it("PR-11 : la copie jointe exécutée depuis un paquet extrait ne se compare pas à elle-même (raison auto_comparaison)", function () {
    if (!gnuTar()) this.skip();
    const { archive } = construire(descriptionAbsolue(true), PROJECT_ROOT);
    const rep = neuf();
    const f = path.join(rep, "complet.tar");
    fs.writeFileSync(f, archive);
    expect(spawnSync("tar", ["-xkf", f, "-C", rep]).status).to.equal(0);
    const copie = path.join(rep, P.RACINE, "verificateur", "scripts", "paquet-reviseur", "verifier.mjs");
    const r = spawnSync(process.execPath, [copie, f, "--json"], { encoding: "utf8", env: { TMPDIR: neuf() } });
    const rapport = JSON.parse(r.stdout);
    const pr11 = rapport.checks.find((c) => c.id === "PR-11");
    expect([pr11.status, pr11.reason]).to.deep.equal(["non_execute", "auto_comparaison"]);
    expect(conformeRapport(rapport)).to.deep.equal([]);
  });

  it("EX-12.9 : observation.tar déclare ses deux dossiers en mode observation et compte la marque de seq 3 ; le résumé l'affiche", function () {
    const r = verifier([path.join(VECT, "observation.tar"), "--json"]);
    expect(r.status).to.equal(0);
    expect(r.rapport.dossiers.map((d) => [d.path, d.observation_mode, d.observation])).to.deep.equal([["dossiers/seq-1", true, null], ["dossiers/seq-3", true, "a_approuver"]]);
    expect(r.rapport.summary.observation).to.deep.equal({ dossiers: 2, autorise: 0, a_approuver: 1, refuse: 0, inconnu: 0 });
    const l = verifier([path.join(VECT, "observation.tar")]).stdout;
    expect(l).to.include("Observation   : 2 dossier(s) en mode observation ; marques : autorise 0, a_approuver 1, refuse 0, inconnu 0");
  });
});
