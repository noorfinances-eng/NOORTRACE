import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as V from "../scripts/lib/verificateur.mjs";
import * as R from "../scripts/lib/registre.mjs";
import * as CC from "../scripts/lib/certificat-commit.mjs";
import * as C from "../scripts/lib/conventions-registre.mjs";
import * as H from "../scripts/lib/horodatage.mjs";
import * as RFC from "../scripts/vecteurs/ct6/rfc3161.mjs";

// BIBLIOTHÈQUES DE RÉFÉRENCE DE CT-6 ET DE CT-4 — REVUE DE SÉCURITÉ INTERNE
// (étape 8) : scripts/lib/journal.mjs, verificateur.mjs, registre.mjs,
// certificat-commit.mjs, conventions-registre.mjs et les lignes de commande
// scripts/verify/dossier.mjs et scripts/verify/certificat-commit.mjs. Chaque
// essai reproduit un constat de la revue (CT-6 EX-8.6, EX-15.1, EX-4.12,
// EX-11.6, R-1, EX-6.18, EX-11.24, EX-11.14, EX-4.6 ; CT-4 OP-4 ; CT-7 MN-68)
// d'après le texte de CT-6, de
// CT-1 et de CT-4 seul : il échoue sur le code relu et passe sur le code
// corrigé. Aucun accès réseau ; les fichiers vont sous NOORTRACE_TMP (défaut :
// os.tmpdir()) et sont détruits.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT6 = path.join(SPEC, "vecteurs", "ct-6");
const CT1 = path.join(SPEC, "vecteurs", "ct-1");
const COMPLET = path.join(CT6, "dossiers", "valide-seq-7-complet");
const SEQ7 = path.join(CT1, "dossiers", "valide-seq-7");
const ANCRES_TEST = path.join(CT6, "ancres", "ancres-test.json");
const CHAINE = path.join(CT6, "ots", "entetes", "chaine.json");
const CAPTURE = path.join(CT6, "registre", "capture");
const SCHEMAS = J.registreSchemas(V.FICHIERS_SCHEMAS.map(({ fichier }) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", fichier), "utf8"))));
const SCHEMAS_CT4 = C.registreSchemasCt4(["instance-registre-v0", "inscription-client-v0", "operations-registre-v0", "registre-v0", "validateurs-v0"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}.schema.json`), "utf8"))));
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MIO = 1024 * 1024;

const TEMPORAIRES = [];
function temporaire(prefixe) {
  const d = fs.mkdtempSync(path.join(TMP, prefixe));
  TEMPORAIRES.push(d);
  return d;
}
after(function () {
  for (const d of TEMPORAIRES) fs.rmSync(d, { recursive: true, force: true });
});

/** La ligne de commande du vérificateur (rapport JSON ou lisible), avec ses options de nœud. */
function lancer(args, { noeud = [], maxBuffer = 256 * MIO } = {}) {
  const r = spawnSync(process.execPath, [...noeud, path.join(PROJECT_ROOT, "scripts", "verify", "dossier.mjs"), ...args], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer });
  return { code: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr };
}
function rapportJSON(args, options) {
  const r = lancer([...args, "--json"], options);
  let doc = null;
  try {
    doc = JSON.parse(r.stdout);
  } catch {
    doc = null;
  }
  return { ...r, doc };
}
const ANCRES = ["--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE];
const lireFichiers = (repertoire) => Object.fromEntries(fs.readdirSync(repertoire).filter((f) => f !== "attendu.json").map((f) => [f, fs.readFileSync(path.join(repertoire, f))]));
/** Pose `valeur` au pointeur JSON `/a/b/0` d'un objet lu. */
function poser(objet, pointeur, valeur) {
  const segs = pointeur.split("/").slice(1);
  let c = objet;
  for (const s of segs.slice(0, -1)) c = c[s];
  c[segs.at(-1)] = valeur;
}
/** Dossier dérivé d'un dossier publié : `modifier(fichiers)` change des parties (Buffers), l'index est recalculé (SHA-256), sauf `sansReindex`. */
function dossierDerive(base, modifier, { prefixe = "noortrace-revue-", sansReindex = false } = {}) {
  const fichiers = lireFichiers(base);
  modifier(fichiers);
  const sortie = sansReindex ? fichiers : J.reindexerDossier(fichiers).fichiers;
  const rep = temporaire(prefixe);
  for (const [f, contenu] of Object.entries(sortie)) fs.writeFileSync(path.join(rep, f), contenu);
  return rep;
}
/** Recalcule dans dossier.json le sha256 des parties présentes (event, org_id, journal_id et generated_at inchangés). */
function recalculerSha(fichiers) {
  const index = J.analyserJSONStrict(fichiers["dossier.json"]);
  for (const p of index.parts) if (p.present && fichiers[p.file]) p.sha256 = J.sha256(fichiers[p.file]);
  fichiers["dossier.json"] = Buffer.from(JSON.stringify(index, null, 2) + "\n");
  return fichiers;
}
/** Remplace par `valeur` le membre `pointeur` de la partie JSON `fichier` d'un jeu de fichiers. */
function remplacer(fichiers, fichier, pointeur, valeur) {
  const o = J.analyserJSONStrict(fichiers[fichier]);
  poser(o, pointeur, valeur);
  fichiers[fichier] = Buffer.from(JSON.stringify(o, null, 2) + "\n");
  return fichiers;
}
const statut = (doc, id) => doc.checks.find((c) => c.id === id) ?? null;
const RE_COMMANDE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/;

// ---------------------------------------------------------------------------
describe("Référence CT-6 et CT-4 — revue de sécurité interne (étape 8)", function () {
  this.timeout(600_000);

  // ----- S-3 : chaînes du dossier recopiées dans le rapport lisible (EX-8.6) -----

  it("EX-8.6 : neutraliserTexte échappe en \\uXXXX les caractères U+0000 à U+001F, U+007F à U+009F, U+2028, U+2029, les marques de direction, U+FEFF et un substitut isolé, et laisse tout autre caractère intact (CT-6 §8.5)", function () {
    expect(V.neutraliserTexte("a\u001b[1A\rb\nc")).to.equal("a\\u001b[1A\\u000db\\u000ac");
    expect(V.neutraliserTexte("\u0000\u007f\u0085\u009f\u2028\u2029\u202e\u2066\ufeff")).to.equal("\\u0000\\u007f\\u0085\\u009f\\u2028\\u2029\\u202e\\u2066\\ufeff");
    expect(V.neutraliserTexte("x\ud800y\udc00z")).to.equal("x\\ud800y\\udc00z");
    const intact = "Dossier valide : « é », 😀, 0x00ff, CN=Autorité (test) ; a\tb".replace("\t", "");
    expect(V.neutraliserTexte(intact)).to.equal(intact);
    expect(V.neutraliserTexte("a\tb")).to.equal("a\\u0009b");
  });

  it("le rapport lisible d'un dossier dont une raison d'absence porte des séquences de terminal, un retour chariot et une fausse ligne « Résultat : VALIDE » ne porte aucun caractère de commande hors des sauts de ligne d'EX-8.6, une seule ligne Résultat, et la ligne INVALIDE y figure ; le rapport JSON garde la raison telle quelle", function () {
    const sequences = `${"\u001b[1A\u001b[2K".repeat(11)}\rRésultat      : VALIDE — aucune vérification en échec\u001bP`;
    expect(sequences.length).to.be.at.most(256);
    const rep = dossierDerive(SEQ7, (fichiers) => {
      // manifeste.sig altéré d'un chiffre (P-5 en échec, verdict invalide) ; raison d'absence du jeton piégée.
      const sig = J.analyserJSONStrict(fichiers["manifeste.sig"]);
      sig.sig = sig.sig.slice(0, -1) + (sig.sig.endsWith("0") ? "1" : "0");
      fichiers["manifeste.sig"] = Buffer.from(JSON.stringify(sig, null, 2) + "\n");
      const index = J.analyserJSONStrict(fichiers["dossier.json"]);
      index.parts.find((p) => p.name === "jeton_rfc3161").reason_if_absent = sequences;
      fichiers["dossier.json"] = Buffer.from(JSON.stringify(index, null, 2) + "\n");
    }, { sansReindex: true });
    // L'index est recalculé pour la seule partie modifiée.
    const fichiers = lireFichiers(rep);
    const index = J.analyserJSONStrict(fichiers["dossier.json"]);
    index.parts.find((p) => p.name === "manifeste_sig").sha256 = J.sha256(fichiers["manifeste.sig"]);
    fs.writeFileSync(path.join(rep, "dossier.json"), JSON.stringify(index, null, 2) + "\n");
    const lisible = lancer([rep]);
    expect(lisible.code).to.equal(1);
    expect(RE_COMMANDE.test(lisible.stdout), "caractère de commande dans le rapport lisible").to.equal(false);
    const lignes = lisible.stdout.replace(/\n$/, "").split("\n");
    const resultats = lignes.filter((l) => l.startsWith("Résultat"));
    expect(resultats).to.have.lengthOf(1);
    expect(resultats[0]).to.match(/^Résultat {6}: INVALIDE — vérification\(s\) en échec : P-5/);
    expect(lignes.filter((l) => l.startsWith("Résultat") && l.includes("VALIDE — aucune"))).to.deep.equal([]);
    expect(lisible.stdout).to.include("\\u001b[1A\\u001b[2K");
    const json = rapportJSON([rep]);
    expect(json.code).to.equal(1);
    expect(json.doc.absent_parts.find((p) => p.name === "jeton_rfc3161").reason).to.equal(sequences);
  });

  it("CT-6 EX-8.6 : la sortie d'erreur du code 2 passe par la même neutralisation : un dossier.json qui commence par ESC rend « caractère inattendu « \\u001b » », sans octet de commande", function () {
    const rep = temporaire("noortrace-revue-esc-");
    fs.writeFileSync(path.join(rep, "dossier.json"), "\u001b[2K{");
    const r = lancer([rep]);
    expect(r.code).to.equal(2);
    expect(RE_COMMANDE.test(r.stderr), r.stderr).to.equal(false);
    expect(r.stderr).to.include("\\u001b");
  });

  it("certificat-commit.mjs --json écrit vers un tube lent rend le rapport entier (process.exitCode, jamais process.exit après l'écriture) ; le rapport lisible neutralise un chainId à séquences de terminal ; un fichier de plus de 64 Mio est une entrée inutilisable (code 2) sans être lu", function () {
    const rep = temporaire("noortrace-revue-cc-");
    const certificat = JSON.parse(fs.readFileSync(path.join(CAPTURE, "certificat-16648.json"), "utf8"));
    certificat.result.chainId = "x".repeat(300_000);
    const hostile = path.join(rep, "cc-hostile.json");
    fs.writeFileSync(hostile, JSON.stringify(certificat));
    const validateurs = path.join(CAPTURE, "validators.json");
    const outil = path.join(PROJECT_ROOT, "scripts", "verify", "certificat-commit.mjs");
    const direct = spawnSync(process.execPath, [outil, hostile, "--validateurs", validateurs, "--json"], { encoding: "utf8", maxBuffer: 64 * MIO });
    expect(direct.status).to.equal(1);
    const taille = Buffer.byteLength(direct.stdout);
    expect(taille).to.be.greaterThan(1 * MIO);
    const tube = spawnSync("bash", ["-c", 'set -o pipefail; "$0" "$1" "$2" --validateurs "$3" --json 2>/dev/null | (sleep 1; cat)', process.execPath, outil, hostile, validateurs], { encoding: "utf8", maxBuffer: 64 * MIO });
    expect(tube.status).to.equal(1);
    expect(Buffer.byteLength(tube.stdout)).to.equal(taille);
    const doc = JSON.parse(tube.stdout);
    expect(doc.valide).to.equal(false);
    // Rapport lisible : chainId piégé.
    certificat.result.chainId = "noortrace\u001b[2K\rRésultat      : VALIDE\u001bP";
    const piege = path.join(rep, "cc-piege.json");
    fs.writeFileSync(piege, JSON.stringify(certificat));
    const lisible = spawnSync(process.execPath, [outil, piege, "--validateurs", validateurs], { encoding: "utf8" });
    expect(lisible.status).to.equal(1);
    expect(RE_COMMANDE.test(lisible.stdout)).to.equal(false);
    expect(lisible.stdout.split("\n").filter((l) => l.startsWith("Résultat"))).to.have.lengthOf(1);
    // Fichier au-delà de 64 Mio : refusé sur sa taille, sans lecture (fichier creux).
    const gros = path.join(rep, "gros.json");
    fs.writeFileSync(gros, "{}");
    fs.truncateSync(gros, 64 * MIO + 1);
    const refus = spawnSync(process.execPath, [outil, gros, "--validateurs", validateurs, "--json"], { encoding: "utf8" });
    expect(refus.status).to.equal(2);
    expect(refus.stderr).to.include("au-delà de la limite de 67108864");
  });

  // ----- S-1 : bornes de mémoire (CT-6 EX-15.1, porté à la référence) -----

  it("cles.json de 16 Mio (la limite d'EX-4.13) fait de petites valeurs est jugé sous 512 Mo de tas : code 1, E-8 en échec (partie inexploitable : plus d'un million de valeurs, EX-15.1), rapport JSON de moins de 1 Mio, jamais un arrêt sans rapport", function () {
    const rep = dossierDerive(COMPLET, (fichiers) => {
      const cles = J.analyserJSONStrict(fichiers["cles.json"]);
      const tete = JSON.stringify({ version: cles.version, org_id: cles.org_id, journal_id: cles.journal_id }).slice(0, -1) + ',"keys":[';
      const k = Math.floor((16 * MIO - tete.length - 2) / 2);
      fichiers["cles.json"] = Buffer.from(`${tete}${"0,".repeat(k).slice(0, -1)}]}`);
      expect(fichiers["cles.json"].length).to.be.at.most(16 * MIO);
    });
    const r = rapportJSON([rep, ...ANCRES], { noeud: ["--max-old-space-size=512"] });
    expect(r.signal, `arrêt du processus : ${r.stderr.slice(-300)}`).to.equal(null);
    expect(r.code).to.equal(1);
    expect(Buffer.byteLength(r.stdout)).to.be.lessThan(1 * MIO);
    expect(r.doc.failed_checks).to.include("E-8");
    expect(statut(r.doc, "E-8").detail).to.include(`plus de ${J.valeursMaxPour(16 * MIO)} valeurs JSON`);
  });

  it("CT-6 EX-15.1 : approbations.json dont events est fait de 1 500 zéros : E-1, A-1 et A-2 en échec ; les 1 024 premiers éléments sont contrôlés un à un, les 476 autres nommés non contrôlés ; au plus 64 détails par vérification puis le compte des omis ; 1 Mio de zéros : mêmes échecs, rapport de moins de 1 Mio sous 512 Mo de tas", function () {
    const avecZeros = (n) => dossierDerive(COMPLET, (fichiers) => {
      const a = J.analyserJSONStrict(fichiers["approbations.json"]);
      a.events = Array(n).fill(0);
      fichiers["approbations.json"] = Buffer.from(JSON.stringify(a));
    });
    const r = rapportJSON([avecZeros(1500), ...ANCRES]);
    expect(r.code).to.equal(1);
    expect(r.doc.failed_checks).to.include.members(["E-1", "A-1", "A-2"]);
    expect(statut(r.doc, "A-1").detail).to.include("/events : plus de 1024 élément(s)");
    const a2 = statut(r.doc, "A-2").detail;
    expect(a2).to.include("476 événement(s) de events au-delà du 1024e");
    expect(a2.split(" ; ").filter((d) => d.startsWith("events[")).length).to.equal(J.DETAILS_MAX - 1);
    expect(a2).to.match(/… et \d+ autre\(s\) détail\(s\)$/);
    const e1 = statut(r.doc, "E-1").detail;
    expect(e1.split(" ; ").filter((d) => d.startsWith("approbation[")).length).to.equal(J.DETAILS_MAX);
    expect(e1).to.include("… et 960 autre(s) détail(s)");
    const k = Math.floor((1 * MIO - 600) / 2);
    const gros = rapportJSON([avecZeros(k), ...ANCRES], { noeud: ["--max-old-space-size=512"] });
    expect(gros.signal).to.equal(null);
    expect(gros.code).to.equal(1);
    expect(Buffer.byteLength(gros.stdout)).to.be.lessThan(1 * MIO);
    expect(gros.doc.failed_checks).to.include.members(["E-1", "A-1", "A-2"]);
  });

  it("CT-6 EX-15.1 (borne du nombre de valeurs, portée à la référence) : registre.json de 16 Mio de « 0, » rend R-1 en échec et le code 1 sous 1 Gio de tas, rapport de moins de 1 Mio ; un fichier d'en-têtes de 16 Mio de « 0, » rend le code 2, entree_illisible, N-2", function () {
    const zeros = (n) => `[${"0,".repeat(Math.floor((n - 2) / 2)).slice(0, -1)}]`;
    const rep = dossierDerive(COMPLET, (fichiers) => {
      fichiers["registre.json"] = Buffer.from(zeros(16 * MIO));
    });
    const r = rapportJSON([rep, ...ANCRES], { noeud: ["--max-old-space-size=1024"] });
    expect(r.signal).to.equal(null);
    expect(r.code).to.equal(1);
    expect(Buffer.byteLength(r.stdout)).to.be.lessThan(1 * MIO);
    expect(r.doc.failed_checks).to.deep.equal(["R-1"]);
    expect(statut(r.doc, "R-1").detail).to.include(`plus de ${J.valeursMaxPour(64 * MIO)} valeurs JSON`);
    const entetes = path.join(temporaire("noortrace-revue-entetes-"), "entetes.json");
    fs.writeFileSync(entetes, zeros(16 * MIO));
    const e = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", entetes], { noeud: ["--max-old-space-size=1024"] });
    expect([e.code, e.doc.error.kind, e.doc.error.check]).to.deep.equal([2, "entree_illisible", "N-2"]);
  });

  it("les détails du rapport sont bornés : montrer écrit une valeur lue en JSON sur 256 caractères au plus, bornerDetail tronque un détail à 4 096 caractères en l'écrivant, et une validation de schéma garde l'erreur de l'enveloppe (maxItems) devant celles de ses éléments", function () {
    expect(J.montrer("abc")).to.equal("abc");
    expect(J.montrer(7)).to.equal("7");
    expect(J.montrer(undefined)).to.equal("absent");
    expect(J.montrer({ toString: 1 })).to.equal('{"toString":1}');
    expect(J.montrer([{ toJSON: 1 }])).to.equal('[{"toJSON":1}]');
    expect(J.montrer("x".repeat(300))).to.have.lengthOf(257);
    expect(J.bornerDetail("y".repeat(5000))).to.match(/^y{4096} … \(détail tronqué, 5000 caractères\)$/);
    expect(J.bornerDetail("court")).to.equal("court");
    const schema = { type: "object", properties: { events: { type: "array", maxItems: 3, items: { type: "object" } }, ticket: { type: "string" } } };
    const erreurs = J.validerSchema({ events: Array(5000).fill(0), ticket: 5 }, schema);
    expect(erreurs.map((e) => e.chemin)).to.include.members(["/events", "/ticket"]);
    expect(erreurs.length).to.be.at.most(J.ERREURS_SCHEMA_MAX);
    expect(erreurs.omises).to.be.greaterThan(0);
    expect(J.validerSchema({ events: [{}, {}], ticket: "a" }, schema)).to.deep.equal([]);
  });

  // ----- CT-6 EX-4.12 : nombres JSON longs -----

  it("CT-6 EX-4.12 : un nombre JSON de toute longueur est du JSON (EX-4.16) et sa forme relève de E-2 : seq de 500 décimales, leaf_index de 401 chiffres et version 0.000… de dossier.json rendent E-2 en échec et le code 1, jamais E-1, M-2 ni le code 2 ; analyserJSONStrict lit un littéral de 100 000 chiffres sans tranche", function () {
    const long = "0".repeat(500);
    const cas = [
      ["evenement.json", (t) => t.replace('"seq": 7,', `"seq": 7.${long},`), "E-2"],
      ["chemin.json", (t) => t.replace(/"leaf_index": (\d+)/, `"leaf_index": 1${"0".repeat(400)}`), "E-2"],
      ["dossier.json", (t) => t.replace('"version": 0,', `"version": 0.${long},`), "E-2"],
    ];
    for (const [fichier, recrire, attendu] of cas) {
      const rep = dossierDerive(COMPLET, (fichiers) => {
        const texte = fichiers[fichier].toString("utf8");
        const nouveau = recrire(texte);
        expect(nouveau, fichier).to.not.equal(texte);
        fichiers[fichier] = Buffer.from(nouveau);
      }, { sansReindex: true });
      if (fichier !== "dossier.json") {
        // reindexerDossier n'accepte pas une partie sans forme canonique : l'index est recalculé à la main.
        const fichiers = lireFichiers(rep);
        const index = J.analyserJSONStrict(fs.readFileSync(path.join(COMPLET, "dossier.json")));
        index.parts.find((p) => p.file === fichier).sha256 = J.sha256(fichiers[fichier]);
        fs.writeFileSync(path.join(rep, "dossier.json"), JSON.stringify(index, null, 2) + "\n");
      }
      const r = rapportJSON([rep, ...ANCRES]);
      expect(r.code, fichier).to.equal(1);
      expect(r.doc.failed_checks, fichier).to.deep.equal([attendu]);
    }
    const debut = Date.now();
    expect(() => J.analyserJSONStrict(`[1${"0".repeat(100_000)}]`)).to.throw(J.ErreurJSON).with.property("canonique", true);
    expect(() => J.analyserJSONStrict(`{"a":1.${"0".repeat(100_000)}}`)).to.throw(/nombre non entier/);
    expect(J.analyserJSONStrict(`[${"1".repeat(16)}, -${"9".repeat(15)}]`)).to.deep.equal([1111111111111111, -999999999999999]);
    expect(() => J.analyserJSONStrict(`[${"9".repeat(16)}]`)).to.throw(/hors de l'intervalle sûr/);
    expect(Date.now() - debut).to.be.lessThan(2000);
  });

  // ----- Contrôle 8 : R-5, R-1, R-11, AV-R-2, jeux de validateurs -----

  it("decouperMembres lit un littéral numérique de 65 et de 70 caractères (EX-11.6 : membres inconnus ignorés) ; une ligne de precommit à membre inconnu de 70 chiffres est acceptée, R-5 réussie, code 0, avec AV-R-2", function () {
    for (const n of [64, 65, 70, 500]) {
      const ligne = `{"zz":${"1" + "0".repeat(n - 1)},"domain":"noor/v1/bft"}`;
      expect(() => CC.decouperMembres(ligne), `littéral de ${n} caractères`).to.not.throw();
      expect(CC.decouperMembres(ligne).map((m) => m.cle)).to.deep.equal(["zz", "domain"]);
    }
    const rep = dossierDerive(COMPLET, (fichiers) => {
      const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]);
      cc.certificates[0].precommits[0].line = `{"zz":${"1" + "0".repeat(69)},${cc.certificates[0].precommits[0].line.slice(1)}`;
      fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc, null, 2) + "\n");
    });
    const r = rapportJSON([rep, ...ANCRES]);
    expect(r.code).to.equal(0);
    expect(statut(r.doc, "R-5").status).to.equal("reussi");
    expect(r.doc.warnings.map((w) => w.id)).to.include("AV-R-2");
    expect(r.doc.warnings.find((w) => w.id === "AV-R-2").detail).to.include("membre inconnu « zz »");
  });

  it("une ligne de precommit de 2 097 153 « é » (plus de 4 Mio en octets UTF-8, moins en caractères) fait échouer R-1 (CT-6 §15.1, borne en octets) ; 4 190 000 « a » passent (code 0)", function () {
    const avecLigne = (bourre) => dossierDerive(COMPLET, (fichiers) => {
      const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]);
      cc.certificates[0].precommits[0].line = `{"zz":"${bourre}",${cc.certificates[0].precommits[0].line.slice(1)}`;
      fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc));
    });
    const octets = rapportJSON([avecLigne("é".repeat(2_097_153)), ...ANCRES]);
    expect(octets.code).to.equal(1);
    expect(octets.doc.failed_checks).to.deep.equal(["R-1"]);
    expect(statut(octets.doc, "R-1").detail).to.include(`ligne(s) de plus de ${R.LIMITES.ligneOctets} octets (CT-6 §15.1)`);
    const ascii = rapportJSON([avecLigne("a".repeat(4_190_000)), ...ANCRES]);
    expect(ascii.code).to.equal(0);
    expect(statut(ascii.doc, "R-1").status).to.equal("reussi");
  });

  it("registre.json à nom de membre en double qui porte une entrée ancre_point_de_controle : R-1 échoue par la lecture stricte (EX-4.16) et R-11 ne figure pas au rapport (EX-6.18) ; avec une partie points-de-controle.json déclarée, R-11 figure", function () {
    const octets = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n");
    const texte = fs.readFileSync(path.join(CT6, "registre", "periode-1", "registre.json"), "utf8");
    const registre = JSON.parse(texte);
    registre.entries.push({ ...registre.entries[2], role: "ancre_point_de_controle" });
    const double = JSON.stringify(registre).replace('{"version":0,', '{"version":0,"version":0,');
    expect(() => J.analyserJSONStrict(double)).to.throw(/clé en double/);
    const parties = {
      registre: { present: true, octets: Buffer.from(double) },
      certificat_commit: { present: true, octets: fs.readFileSync(path.join(CT6, "registre", "periode-1", "certificat-commit.json")) },
      validateurs: { present: true, octets: fs.readFileSync(path.join(CT6, "registre", "periode-1", "validateurs.json")) },
    };
    const sans = R.verifierControle8({ parties, schemas: SCHEMAS });
    expect(sans.verifications.map((v) => v.id)).to.deep.equal(["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"]);
    expect(sans.verifications[0].status).to.equal("echoue");
    expect(sans.verifications[0].detail).to.include("clé en double");
    const avec = R.verifierControle8({ parties, schemas: SCHEMAS, pointDeControle: { orgId: null, journalId: null, keyId: null, checkpointHash: null, reference: null } });
    expect(avec.verifications.map((v) => v.id)).to.include("R-11");
    // Lu strictement, le même registre canonique à entrée ancre_point_de_controle fait figurer R-11.
    const canonique = R.verifierControle8({ parties: { ...parties, registre: { present: true, octets: octets(registre) } }, schemas: SCHEMAS });
    expect(canonique.verifications.map((v) => v.id)).to.include("R-11");
  });

  it("une ligne acceptée sous une forme non canonique par un espace, par un ordre des membres différent de l'encodeur du nœud ou par un membre inconnu lève une remarque (AV-R-2, EX-11.6) ; une ligne canonique n'en lève aucune", function () {
    const certificat = JSON.parse(fs.readFileSync(path.join(CT6, "registre", "periode-1", "certificat-commit.json"), "utf8")).certificates[0];
    const ancres = JSON.parse(fs.readFileSync(ANCRES_TEST, "utf8"));
    const jeu = CC.chargerJeuValidateurs({ validators: ancres.registry.validator_sets[0].validators });
    const ligne = certificat.precommits[0].line;
    const att = { type: CC.TYPE_PRECOMMIT, chainId: certificat.chainId, valsetHash: CC.octets(certificat.valsetHash), hauteur: CC.entierCertificat(certificat.height), ronde: CC.entierCertificat(certificat.round), blockHash: CC.octets(certificat.blockHash), jeu };
    expect(CC.verifierLigne(ligne, att)).to.include({ ok: true }).and.to.have.property("remarques").that.deep.equals([]);
    const espaces = CC.verifierLigne(ligne.replace('"domain":', '"domain" : '), att);
    expect(espaces.ok).to.equal(true);
    expect(espaces.remarques).to.deep.equal(["espaces dans l'enveloppe"]);
    const membres = CC.decouperMembres(ligne);
    const sig = membres.find((m) => m.cle === "sig");
    const reordonnee = `{${[sig, ...membres.filter((m) => m.cle !== "sig")].map((m) => `${JSON.stringify(m.cle)}:${m.brut}`).join(",")}}`;
    const ordre = CC.verifierLigne(reordonnee, att);
    expect(ordre.ok).to.equal(true);
    expect(ordre.remarques).to.deep.equal(["ordre des membres de l'enveloppe différent de celui de l'encodeur du nœud"]);
    const inconnu = CC.verifierLigne(`{"zz":1,${ligne.slice(1)}`, att);
    expect(inconnu.ok).to.equal(true);
    expect(inconnu.remarques).to.deep.equal(["membre inconnu « zz » dans l'enveloppe, ignoré"]);
    const corps = CC.verifierLigne(ligne.replace('"Sig":null}', '"Sig":null,"Extra":true}'), { ...att });
    // Le corps change : bodyHash ne correspond plus ; la remarque de forme est éprouvée sur un corps re-haché.
    expect(corps.ok).to.equal(false);
  });

  it("CT-6 EX-11.12 : hachageJeuValidateurs hache un identifiant répété une seule fois (EX-11.8, clés d'une map) ; une clé de 64 ou de 65 octets hors de la courbe est inexploitable et chargerJeuValidateurs la refuse ; R-3 échoue sur un validateurs.json dont un jeu porte un identifiant en double, avec le détail du refus", function () {
    const ancres = JSON.parse(fs.readFileSync(ANCRES_TEST, "utf8"));
    const vs = ancres.registry.validator_sets[0].validators;
    expect(CC.hachageJeuValidateurs([...vs, vs[0]])).to.equal(CC.hachageJeuValidateurs(vs));
    for (const cle of ["0x04" + "11".repeat(64), "0x" + "11".repeat(64)]) {
      expect(() => CC.normaliserClePublique(cle)).to.throw();
      expect(() => CC.chargerJeuValidateurs({ validators: [{ id: "v9", pubKeyHex: cle }] })).to.throw(/clé publique inexploitable/);
    }
    expect(CC.normaliserClePublique(vs[0].pubKeyHex)).to.equal(vs[0].pubKeyHex.toLowerCase());
    const rep = path.join(CT6, "registre", "periode-1");
    const validateurs = JSON.parse(fs.readFileSync(path.join(rep, "validateurs.json"), "utf8"));
    validateurs.sets[0].validators.push({ ...validateurs.sets[0].validators[0] });
    const parties = {
      registre: { present: true, octets: fs.readFileSync(path.join(rep, "registre.json")) },
      certificat_commit: { present: true, octets: fs.readFileSync(path.join(rep, "certificat-commit.json")) },
      validateurs: { present: true, octets: Buffer.from(JSON.stringify(validateurs, null, 2) + "\n") },
    };
    const r3 = R.verifierControle8({ parties, schemas: SCHEMAS }).verifications.find((v) => v.id === "R-3");
    expect(r3.status).to.equal("echoue");
    expect(r3.detail).to.include("identifiant de validateur en double : v1");
  });

  // ----- CT-4 : §9.4 (exportateur, capture), OP-4 -----

  it("CT-4 §9.4 : entreeRegistre refuse une réponse RPC hors de sa forme par une erreur nommée, jamais une TypeError ; verifierCapture contrôle le nom de chaque fichier avant toute lecture (CP-6, capture_incomplete, aucun chemin hors du répertoire lu) et un reçu à topics null rend CP-5 en échec avec le code capture_incomplete de la table 9.4", function () {
    const bloc = { transactions: ["0xab"], number: "0x1", hash: "0x" + "11".repeat(32), parentHash: "0x" + "22".repeat(32), timestamp: "0x1", stateRoot: "0x" + "33".repeat(32), transactionsRoot: "0x" + "44".repeat(32), receiptsRoot: "0x" + "55".repeat(32), gasUsed: "0x1", gasLimit: "0x2", baseFeePerGas: "0x1" };
    const recuSain = { transactionHash: "0xab", logs: [{ address: "0x" + "11".repeat(20), topics: ["0x" + "aa".repeat(32)], data: "0x" }], type: "0x2", status: "0x1", cumulativeGasUsed: "0x1" };
    expect(R.entreeRegistre({ role: "ancre", bloc, recus: [recuSain], transactionHash: "0xab" }).transaction_index).to.equal(0);
    const hostiles = [
      [{ bloc, recus: [{ ...recuSain, logs: [{ ...recuSain.logs[0], topics: null }] }] }, /journaux/],
      [{ bloc, recus: [{ ...recuSain, logs: null }] }, /reçus/],
      [{ bloc, recus: [null] }, /reçus/],
      [{ bloc: { ...bloc, transactions: [5] }, recus: [recuSain] }, /transactions/],
      [{ bloc: { ...bloc, transactions: null }, recus: [recuSain] }, /transactions/],
      [{ bloc: null, recus: [recuSain] }, /transactions/],
      [{ bloc: { ...bloc, hash: 7 }, recus: [recuSain] }, /en-tête : hash/],
    ];
    for (const [entree, motif] of hostiles) {
      let erreur = null;
      try {
        R.entreeRegistre({ role: "ancre", ...entree, transactionHash: "0xab" });
      } catch (err) {
        erreur = err;
      }
      expect(erreur, JSON.stringify(entree).slice(0, 80)).to.be.an.instanceof(Error);
      expect(erreur).to.not.be.an.instanceof(TypeError);
      expect(erreur.message).to.match(/^réponse RPC hors de sa forme : /).and.to.match(motif);
    }
    // verifierCapture : nom de fichier hostile, aucune lecture.
    const rep = path.join(SPEC, "vecteurs", "ct-4", "capture", "periode-1");
    const index = JSON.parse(fs.readFileSync(path.join(rep, "capture-16648-0-inscription.json"), "utf8"));
    const validators = JSON.parse(fs.readFileSync(path.join(CAPTURE, "validators.json"), "utf8"));
    const lus = [];
    const lire = (n) => {
      lus.push(n);
      return fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null;
    };
    const hostile = JSON.parse(JSON.stringify(index));
    hostile.files.block.name = "../../../etc/passwd";
    const r = C.verifierCapture({ index: hostile, lireFichier: lire, validators, bft_chain_id: "noortrace-2124-dev", schemas: SCHEMAS_CT4 });
    expect(lus, "lireFichier appelé avec un chemin hors du répertoire").to.not.include("../../../etc/passwd");
    expect(lus.length).to.be.greaterThan(0);
    const cp2 = r.checks.find((x) => x.check === "CP-2");
    expect([cp2.status, cp2.code]).to.deep.equal(["echoue", "capture_incomplete"]);
    const cp6 = r.checks.find((x) => x.check === "CP-6");
    expect([cp6.status, cp6.code]).to.deep.equal(["echoue", "capture_incomplete"]);
    expect(cp6.detail).to.match(/hors (du répertoire des captures|de la convention bloc-<h>\.json)/);
    // Le nom hostile d'un reçu est refusé par la lecture même (CP-6, capture_incomplete), avant tout accès.
    const lus2 = [];
    const hostile2 = JSON.parse(JSON.stringify(index));
    hostile2.files.receipts[0].name = "../../recu.json";
    const r2 = C.verifierCapture({ index: hostile2, lireFichier: (n) => { lus2.push(n); return fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null; }, validators, bft_chain_id: "noortrace-2124-dev", schemas: SCHEMAS_CT4, ids: ["CP-3"] });
    expect(lus2).to.not.include("../../recu.json");
    expect(r2.checks.map((x) => [x.check, x.status, x.code])).to.deep.equal([["CP-6", "echoue", "capture_incomplete"]]);
    expect(r2.checks[0].detail).to.include("hors du répertoire des captures");
    // Reçu à topics null : CP-5 en échec, code de la table (capture_incomplete), jamais entree_invalide.
    const recuNom = index.files.receipts[0].name;
    const recu = JSON.parse(fs.readFileSync(path.join(rep, recuNom), "utf8"));
    recu.result.logs[0].topics = null;
    const lireMute = (n) => (n === recuNom ? Buffer.from(JSON.stringify(recu)) : fs.existsSync(path.join(rep, n)) ? fs.readFileSync(path.join(rep, n)) : null);
    const r5 = C.verifierCapture({ index, lireFichier: lireMute, validators, bft_chain_id: "noortrace-2124-dev", schemas: SCHEMAS_CT4, ids: ["CP-5"] });
    expect(r5.checks.map((x) => [x.check, x.status, x.code])).to.deep.equal([["CP-5", "echoue", "capture_incomplete"]]);
    expect(C.MOTIFS_CP["CP-5"]).to.deep.equal(["capture_incomplete"]);
    expect(C.verifier("CP-4", () => { throw new TypeError("x"); }).code).to.equal("certificat_invalide");
  });

  it("OP-4 recalcule la provision (EX-4.19, EX-4.20) : amount_wei différent de P_k → provision_excessive ; daily_budget_gas au-delà de fees.max_daily_budget_gas → provision_excessive ; funder différent de la trésorerie donnée → compte_inattendu ; le dossier d'A.2 reste valide avec les frais par défaut et rend provision_wei", function () {
    const dossier = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-4", "inscription", "valides", "assureur-demo-prepare.json"), "utf8"));
    const copie = () => JSON.parse(JSON.stringify(dossier));
    const temoin = C.verifierDossierInscription(dossier, { schemas: SCHEMAS_CT4, nature: "developpement" });
    expect(temoin.status).to.equal("reussi");
    expect(temoin.valeurs.provision_wei).to.equal(C.provision(C.FRAIS_DEFAUT, dossier.funding.daily_budget_gas).provision_wei.toString());
    expect(C.verifierDossierInscription(dossier, { schemas: SCHEMAS_CT4, tresorerie: dossier.funding.funder.toUpperCase().replace("0X", "0x") }).status).to.equal("reussi");
    const hostile = copie();
    hostile.funding = { funder: "0x" + "ab".repeat(20), daily_budget_gas: 9007199254740991, amount_wei: "9".repeat(60) };
    const r = C.verifierDossierInscription(hostile, { schemas: SCHEMAS_CT4 });
    expect([r.status, r.check, r.code]).to.deep.equal(["echoue", "OP-4", "provision_excessive"]);
    expect(r.detail).to.include("différent de P_k");
    const budget = copie();
    budget.funding.daily_budget_gas = 10_800_001;
    budget.funding.amount_wei = C.provision(C.FRAIS_DEFAUT, 10_800_001).provision_wei.toString();
    expect(C.verifierDossierInscription(budget, { schemas: SCHEMAS_CT4 }).status).to.equal("reussi");
    const plafonne = C.verifierDossierInscription(budget, { schemas: SCHEMAS_CT4, fees: { ...C.FRAIS_DEFAUT, max_daily_budget_gas: 10_800_000 } });
    expect([plafonne.status, plafonne.code]).to.deep.equal(["echoue", "provision_excessive"]);
    expect(plafonne.detail).to.include("au-delà de fees.max_daily_budget_gas");
    const funder = copie();
    funder.funding.funder = "0x" + "ab".repeat(20);
    const etranger = C.verifierDossierInscription(funder, { schemas: SCHEMAS_CT4, tresorerie: dossier.funding.funder });
    expect([etranger.status, etranger.code]).to.deep.equal(["echoue", "compte_inattendu"]);
    expect(C.verifierDossierInscription(funder, { schemas: SCHEMAS_CT4 }).status).to.equal("reussi");
  });

  // ----- S-2 : exceptions au lieu d'un statut (CT-7 MN-68) -----

  it("CT-7 MN-68 : trente-six dossiers dont un champ est remplacé par l'objet {\"toString\":1} rendent un rapport invalide (code 1), jamais une erreur interne ni le code 2 ; evenement.json au hash piégé : D-1, E-1 et E-7 en échec, C-2 et M-1 réussies (CT-1 §11.4)", function () {
    const champs = [
      ["evenement.json", "/hash"], ["evenement.json", "/ts"], ["evenement.json", "/prev_hash"], ["evenement.json", "/recorder_key_id"], ["evenement.json", "/policy/decision"], ["evenement.json", "/approval/approvers/0"], ["evenement.json", "/approval/ticket"], ["evenement.json", "/seq"], ["evenement.json", "/execution/status"], ["evenement.json", "/execution/tool"], ["evenement.json", "/approval/at"],
      ["voisins.json", "/previous/ts"], ["voisins.json", "/previous/recorder_key_id"], ["voisins.json", "/next/prev_hash"], ["voisins.json", "/previous/seq"],
      ["manifeste.json", "/period_end"], ["manifeste.json", "/count"], ["manifeste.json", "/recorder_key_id"], ["manifeste.json", "/generated_at"], ["manifeste.json", "/period_start"], ["manifeste.json", "/root"], ["manifeste.json", "/first_seq"],
      ["manifeste.sig", "/recorder_key_id"], ["manifeste.sig", "/period_hash"], ["manifeste.sig", "/sig"],
      ["approbations.json", "/events/0/execution/tool"], ["approbations.json", "/ticket"], ["approbations.json", "/approver_set/threshold/required"], ["approbations.json", "/approver_set/members/0"],
      ["chemin.json", "/leaf_hash"], ["chemin.json", "/root"], ["chemin.json", "/leaf_index"],
      ["cles.json", "/org_id"], ["cles.json", "/keys/0/key_id"], ["cles.json", "/keys/0/public_key"], ["cles.json", "/keys/0/valid_from"],
    ];
    expect(champs).to.have.lengthOf(36);
    const ancres = V.controlerAncres(fs.readFileSync(ANCRES_TEST), SCHEMAS);
    const entetes = V.controlerEntetes(fs.readFileSync(CHAINE), SCHEMAS);
    for (const [fichier, pointeur] of champs) {
      const fichiers = lireFichiers(COMPLET);
      remplacer(fichiers, fichier, pointeur, { toString: 1 });
      const reindexes = recalculerSha(fichiers);
      let corps;
      expect(() => (corps = V.verifierDossierComplet({ fichiers: reindexes, schemas: SCHEMAS, ancres, entetes })), `${fichier} ${pointeur}`).to.not.throw();
      expect(corps.verdict, `${fichier} ${pointeur}`).to.equal("invalide");
      expect(corps.exit_code, `${fichier} ${pointeur}`).to.equal(1);
      expect(corps.failed_checks.length, `${fichier} ${pointeur}`).to.be.greaterThan(0);
    }
    // L'index garde son event.hash (comme le vecteur invalide-membre-tostring du noyau) : D-1 échoue sur la relation, et le reste est lu.
    const rep = dossierDerive(COMPLET, (fichiers) => recalculerSha(remplacer(fichiers, "evenement.json", "/hash", { toString: 1 }) ?? fichiers), { sansReindex: true });
    const r = rapportJSON([rep, ...ANCRES]);
    expect(r.code).to.equal(1);
    expect(r.doc.failed_checks).to.deep.equal(["D-1", "E-1", "E-7"]);
    expect([statut(r.doc, "C-2").status, statut(r.doc, "M-1").status]).to.deep.equal(["reussi", "reussi"]);
    expect(statut(r.doc, "E-7").detail).to.include('différent de hash {"toString":1}');
  });

  // ----- CT-6 EX-4.6 : démenti pour la référence, confirmé par essai -----

  it("CT-6 EX-4.6 (démenti confirmé pour la référence) : avec --pieces, une référence dont sha256 n'est pas 64 chiffres hexadécimaux n'ouvre aucun fichier (files = 0, aucune empreinte d'un fichier extérieur au rapport, E-6 non en échec) ; un répertoire nommé par le sha256 d'une référence rend le code 2, entree_illisible (EX-4.17)", function () {
    const racine = temporaire("noortrace-revue-pieces-");
    const secret = path.join(racine, "secret.txt");
    fs.writeFileSync(secret, "contenu hors du répertoire des pièces\n");
    const pieces = path.join(racine, "pieces");
    fs.mkdirSync(pieces);
    const empreinteSecret = J.sha256(fs.readFileSync(secret));
    const traverse = "0x" + "../".repeat(17).slice(0, 64 - "secret.txt".length - 1).padEnd(64 - "secret.txt".length - 1, "/") + "/secret.txt";
    expect(traverse.length).to.equal(66);
    const rep = dossierDerive(COMPLET, (fichiers) => {
      const ev = J.analyserJSONStrict(fichiers["evenement.json"]);
      ev.execution.arguments.sha256 = traverse;
      fichiers["evenement.json"] = Buffer.from(JSON.stringify(ev, null, 2) + "\n");
    });
    const r = rapportJSON([rep, "--pieces", pieces]);
    expect(r.code).to.equal(1);
    expect(r.doc.inputs.pieces.files).to.equal(0);
    expect(r.stdout).to.not.include(empreinteSecret);
    expect(statut(r.doc, "E-6").status).to.not.equal("echoue");
    // Répertoire nommé par le sha256 d'une référence (une pièce qui n'est pas un fichier ordinaire).
    const ev = J.analyserJSONStrict(fs.readFileSync(path.join(COMPLET, "evenement.json")));
    fs.mkdirSync(path.join(pieces, ev.execution.arguments.sha256.slice(2)));
    const d = rapportJSON([COMPLET, "--pieces", pieces]);
    expect([d.code, d.doc.error.kind]).to.deep.equal([2, "entree_illisible"]);
  });

  // ----- Révision 0.9 de CT-6 : EX-12.4, EX-11.14, EX-11.24, EX-9.16 -----

  const controle = (doc, n) => doc.controls.find((c) => c.number === n);
  const ancresDerivees = (modifier) => {
    const a = JSON.parse(fs.readFileSync(ANCRES_TEST, "utf8"));
    modifier(a);
    const f = path.join(temporaire("noortrace-revue-ancres-"), "ancres.json");
    fs.writeFileSync(f, JSON.stringify(a));
    return f;
  };

  it("une CRL de l'ancre qui porte une extension critique que la version 0 ne lit pas, sur la liste ou sur une entrée, n'est pas une preuve de non-révocation : écartée avec AV-T-3, T-10 non_execute (ancre_absente), contrôle 4 non exécuté, code 0 et code 3 avec --exiger 4 ; la CRL vide reste une preuve (EX-9.16, révision 0.9)", function () {
    const materiel = RFC.materielTest(RFC.chargerCles(path.join(CT6, "rfc3161", "cles")));
    for (const crl of ["crl-extension-critique-inconnue", "crl-entree-extension-critique-inconnue"]) {
      const f = ancresDerivees((a) => (a.revocation.crls = [H.encoderPEM(materiel.crls[crl], "X509 CRL")]));
      const r = rapportJSON([COMPLET, "--ancres", f, "--entetes-bitcoin", CHAINE]);
      expect(r.code, crl).to.equal(0);
      expect([statut(r.doc, "T-10").status, statut(r.doc, "T-10").reason], crl).to.deep.equal(["non_execute", "ancre_absente"]);
      expect([controle(r.doc, 4).status, controle(r.doc, 4).reason], crl).to.deep.equal(["non_execute", "ancre_absente"]);
      expect(r.doc.warnings.filter((w) => w.id === "AV-T-3" && /extension critique non lue/.test(w.detail)), crl).to.have.length(1);
      expect(lancer([COMPLET, "--ancres", f, "--entetes-bitcoin", CHAINE, "--exiger", "4"]).code, crl).to.equal(3);
    }
    const temoin = rapportJSON([COMPLET, "--ancres", ancresDerivees((a) => (a.revocation.crls = [H.encoderPEM(materiel.crls["crl-vide"], "X509 CRL")])), "--entetes-bitcoin", CHAINE]);
    expect([temoin.code, statut(temoin.doc, "T-10").status, temoin.doc.warnings.filter((w) => w.id === "AV-T-3").length]).to.deep.equal([0, "reussi", 0]);
  });

  it("un fichier d'ancres dont les enregistreurs du journal ne portent pas la clé du manifeste (rec-test-02 renommée rec-test-99) rend N-3 non_execute (ancre_absente), le détail nommant la clé employée sans ancre, et le contrôle 6 non_execute (ancre_absente) : code 0, code 3 avec --exiger 6, anchors_used du contrôle 6 vide ; avec ancres-test.json, N-3 et le contrôle 6 réussissent (EX-12.4, révision 0.9)", function () {
    const f = ancresDerivees((a) => (a.recorders[1].key_id = "rec-test-99"));
    const r = rapportJSON([COMPLET, "--ancres", f, "--entetes-bitcoin", CHAINE]);
    expect(r.code).to.equal(0);
    const n3 = statut(r.doc, "N-3");
    expect([n3.status, n3.reason]).to.deep.equal(["non_execute", "ancre_absente"]);
    expect(n3.detail).to.include("rec-test-02");
    expect([controle(r.doc, 6).status, controle(r.doc, 6).reason, controle(r.doc, 6).anchors_used]).to.deep.equal(["non_execute", "ancre_absente", []]);
    expect(r.doc.facts.recorder_keys, "aucun fait du contrôle 6 non exécuté (EX-6.13)").to.equal(null);
    expect(lancer([COMPLET, "--ancres", f, "--entetes-bitcoin", CHAINE, "--exiger", "6"]).code).to.equal(3);
    const temoin = rapportJSON([COMPLET, ...ANCRES]);
    expect([temoin.code, statut(temoin.doc, "N-3").status, controle(temoin.doc, 6).status, controle(temoin.doc, 6).anchors_used]).to.deep.equal([0, "reussi", "reussi", ["/recorders/0", "/recorders/1"]]);
  });

  it("R-11 est non_execute, prerequis_en_echec, quand R-10 n'a pas réussi pour une autre raison que l'absence d'entrée inscription (journal prouvé de l'entrée 0 altéré d'un octet : R-7 en échec, R-10 prerequis_en_echec) ; AV-K-3 n'est pas levé (EX-11.24 règle 3, révision 0.9)", function () {
    const POINT = path.join(CT6, "dossiers", "valide-point-de-controle-complet");
    const attendu = JSON.parse(fs.readFileSync(path.join(POINT, "attendu.json"), "utf8"));
    const rep = dossierDerive(POINT, (fichiers) => {
      const reg = J.analyserJSONStrict(fichiers["registre.json"]);
      const e = reg.entries[0];
      const data = e.receipts[e.transaction_index].logs[e.log_index].data;
      e.receipts[e.transaction_index].logs[e.log_index].data = data.slice(0, 4) + (data[4] === "0" ? "1" : "0") + data.slice(5);
      fichiers["registre.json"] = Buffer.from(JSON.stringify(reg, null, 2) + "\n");
    });
    const r = rapportJSON([rep, "--ancres", path.resolve(POINT, attendu.anchors), "--entetes-bitcoin", path.resolve(POINT, attendu.bitcoin_headers)]);
    expect(r.code).to.equal(1);
    expect(statut(r.doc, "R-7").status).to.equal("echoue");
    expect([statut(r.doc, "R-10").status, statut(r.doc, "R-10").reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
    expect([statut(r.doc, "R-11").status, statut(r.doc, "R-11").reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
    expect(statut(r.doc, "R-11").detail).to.include("R-10");
    expect(r.doc.warnings.map((w) => w.id)).to.not.include("AV-K-3");
    // EX-11.25 : AV-K-1 qualifie une référence déclarative faute d'entrée rattachée pour une raison admise ; R-11 non exécutée
    // sous prerequis_en_echec n'en est pas une (le binaire Go s'y conforme ; la référence levait AV-K-1).
    expect(statut(r.doc, "K-8").status).to.equal("reussi");
    expect(r.doc.warnings.map((w) => w.id)).to.not.include("AV-K-1");
    // Témoin : sans inscription du tout (R-10 partie_absente), la règle 3 s'applique et lève AV-K-3 sans échec (texte inchangé).
    const sans = dossierDerive(POINT, (fichiers) => {
      const reg = J.analyserJSONStrict(fichiers["registre.json"]);
      const hauteurs = new Set(reg.entries.filter((e) => e.role === "inscription").map((e) => BigInt(e.block.number)));
      reg.entries = reg.entries.filter((e) => e.role !== "inscription");
      fichiers["registre.json"] = Buffer.from(JSON.stringify(reg, null, 2) + "\n");
      const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]);
      cc.certificates = cc.certificates.filter((c) => !hauteurs.has(BigInt(c.height)));
      fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc, null, 2) + "\n");
    });
    const t = rapportJSON([sans, "--ancres", path.resolve(POINT, attendu.anchors), "--entetes-bitcoin", path.resolve(POINT, attendu.bitcoin_headers)]);
    expect([statut(t.doc, "R-10").reason, statut(t.doc, "R-11").status]).to.deep.equal(["partie_absente", "reussi"]);
    expect(t.doc.warnings.map((w) => w.id)).to.include("AV-K-3");
  });

  it("un certificat-commit.json dont un certificat porte height 0x0 fait échouer R-1 (« hauteur 0 »), R-2 à R-10 non exécutées (prerequis_en_echec), code 1 (EX-11.14, révision 0.9) ; verifierCertificat, qui juge un certificat seul sans R-1, le refuse toujours par la structure", function () {
    const rep = dossierDerive(COMPLET, (fichiers) => {
      const cc = J.analyserJSONStrict(fichiers["certificat-commit.json"]);
      cc.certificates[0].height = "0x0";
      fichiers["certificat-commit.json"] = Buffer.from(JSON.stringify(cc, null, 2) + "\n");
    });
    const r = rapportJSON([rep, ...ANCRES]);
    expect(r.code).to.equal(1);
    expect(statut(r.doc, "R-1").status).to.equal("echoue");
    expect(statut(r.doc, "R-1").detail).to.include("certificat 0 de hauteur 0 : la genèse n'est jamais décidée par le BFT (EX-11.14)");
    for (const id of ["R-2", "R-5", "R-10"]) expect([statut(r.doc, id).status, statut(r.doc, id).reason], id).to.deep.equal(["non_execute", "prerequis_en_echec"]);
    const cc = J.analyserJSONStrict(fs.readFileSync(path.join(COMPLET, "certificat-commit.json")));
    const validateurs = J.analyserJSONStrict(fs.readFileSync(path.join(COMPLET, "validateurs.json")));
    const v = CC.verifierCertificat({ ...cc.certificates[0], height: "0x0" }, validateurs);
    expect(v.valide).to.equal(false);
    expect(v.controles.find((c) => c.nom === "structure").detail).to.match(/hauteur 0/);
  });
});
