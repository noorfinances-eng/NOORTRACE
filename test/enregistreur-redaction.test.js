// Rédaction avant hachage du démon `noortrace` (CT-2 §10, lot « rédaction »),
// écrite d'après le seul texte de la spécification : vecteurs
// spec/vecteurs/ct-2/redaction rejoués contre leur attendu, pièces rédigées
// des vecteurs pieces-mcp/appels et evenements/journal-demo, chaque exigence
// EX-10.1 à EX-10.24 (et EX-3.6, EX-7.2, EX-7.6 pas 3, EX-8.5 à EX-8.7,
// EX-6.6, EX-15.4 pas 3 et 4, EX-15.5, EX-15.7 pour la rédaction) en
// réussite et en échec, entrées hostiles, coffre des originaux (EX-10.22,
// CT-7 EX-3.11). Le parcours de bout en bout est dans
// enregistreur-redaction-parcours.test.js.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as N from "@noortrace/noyau";
import {
  Redacteur, PolitiqueCompilee, produirePiece, redigerValeur, controlerMotif, premiereCorrespondance, analyserMotif,
  validerPolitiqueRedaction, controlerPolitiqueRedaction, controleRedaction, controleSecretsRedaction, verifierChangementRedaction,
  jetonsPossibles, jetonPseudonyme, executerSousBorne, DepassementBudget, executerExtract, evaluerEffets, examinerValeurLigne,
  redigerMotifDecision, CoffreOriginaux, AccesCoffreRefuse, JournalExploitation, Metriques, validerConfiguration, resoudreSecrets,
  pieceJson, pieceTexte, Piece, analyserJsonIntegral, pieceErreurJsonRpc, jcsIntegral, JETON_PROMPT_SYSTEME, ErreurEnregistreur,
  detecterIban, detecterAvs, detecterCarte, detecterEmail, detecterTelephone, principal, Coeur, HorlogeReglable,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, configurationExemple, configurationDev, repertoireTemporaire, texteCT2, blocApres, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const R = path.join(VECTEURS_CT2, "redaction");
const json = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const texte = (p) => Buffer.from(p.octets).toString("utf8");
const CLE_TEST = new Uint8Array(crypto.createHash("sha256").update("noortrace/vecteurs/v0/cle-pseudonyme/test").digest());
const PII = json(path.join(R, "politique-pii-v1.json"));
const POLITIQUES = Object.fromEntries(
  ["politique-pii-v1", "politique-pseudonyme-test", "politique-regles-test"].map((f) => {
    const d = json(path.join(R, `${f}.json`));
    return [d.name, d];
  }),
);
const compilee = (doc, cle = CLE_TEST) => new PolitiqueCompilee(doc, { cle: doc.pseudonym_key ? cle : null });
const pol = (nom) => compilee(POLITIQUES[nom]);
const O = { budgetMs: 1000, avecValeur: true };

function demandeCas(c) {
  return typeof c.input === "string"
    ? { genre: "texte", portee: c.scope, outil: c.tool, texte: c.input }
    : { genre: "json", portee: c.scope, outil: c.tool, valeur: c.input };
}

function egalAttendu(r, e, nom) {
  expect(texte(r.piece), nom).to.equal(e.piece);
  expect(r.piece.reference.sha256, nom).to.equal(e.sha256);
  expect(r.piece.reference.length, nom).to.equal(e.length);
  expect(r.piece.reference.redacted, nom).to.equal(e.redacted);
  if (e.media_type) expect(r.piece.reference.media_type, nom).to.equal(e.media_type);
  else expect(r.piece.reference, nom).to.not.have.property("media_type");
  expect(r.comptes, nom).to.deep.equal(e.matches);
}

/** Politique de test minimale. */
function politique(regles, motifs = {}, extra = {}) {
  return { version: 0, name: "essai-v1", pseudonym_key: null, named_patterns: motifs, rules: regles, ...extra };
}
const regle = (o) => ({ id: "r", scopes: ["arguments", "resultat", "contexte", "requete", "reponse", "prompt_systeme"], tools: "*", detectors: [{ type: "iban" }], action: { kind: "remplacer" }, ...o });

describe("enregistreur, rédaction (§10) : vecteurs, exigences, entrées hostiles", function () {
  this.timeout(120000);

  // ------------------------------------------------------------------ vecteurs
  describe("vecteurs redaction/ (B.3)", function () {
    it("politique-pii-v1.json est le document de 10.9 ; JCS intégral de 1462 octets, SHA-256 de 10.6 (EX-10.21)", function () {
      const imprime = JSON.parse(blocApres(texteCT2(), "<!-- schema: politique-redaction -->").texte);
      expect(N.egaliteJson(imprime, PII)).to.equal(true);
      const octets = N.utf8(jcsIntegral(PII));
      expect(octets.length).to.equal(1462);
      expect(N.sha256Hex(octets)).to.equal("0x9116aac6ee1d124d155ffb22acd39b1cf2270cac07b30b239e9996012d787f4e");
    });

    it("les trois politiques valident contre politique-redaction-v0 et EX-10.6", function () {
      for (const d of Object.values(POLITIQUES)) {
        const r = validerPolitiqueRedaction(d);
        expect(r.erreurs, d.name).to.deep.equal([]);
        expect(r.valide).to.equal(true);
      }
    });

    it("motifs.json : chaque motif admis ou refusé comme publié ; première correspondance des motifs admis (EX-10.6)", function () {
      const motifs = json(path.join(R, "motifs.json"));
      expect(motifs.length).to.be.greaterThan(30);
      for (const m of motifs) {
        const c = controlerMotif(m.pattern);
        expect(c.admis, `${m.pattern} (${c.raison ?? ""})`).to.equal(m.admis);
        for (const x of m.matches ?? []) expect(premiereCorrespondance(c.regexp, x.input, { entiere: true }), `${m.pattern} sur ${x.input}`).to.equal(x.first);
      }
    });

    it("cas.json : octets, référence et comptes de chaque cas, dans le fil appelant et par les fils de calcul", async function () {
      const cas = json(path.join(R, "cas.json"));
      expect(cas.length).to.equal(73);
      for (const c of cas) egalAttendu(produirePiece(pol(c.policy), demandeCas(c), O), c.expected, c.name);
      const fils = Object.fromEntries(
        Object.entries(POLITIQUES).map(([n, d]) => [n, new Redacteur({ politique: d, cle: d.pseudonym_key ? CLE_TEST : null, fils: 2 })]),
      );
      try {
        const r = await Promise.all(cas.map((c) => fils[c.policy].redigerPiece(demandeCas(c))));
        cas.forEach((c, k) => egalAttendu(r[k], c.expected, `${c.name} (fil)`));
      } finally {
        for (const f of Object.values(fils)) await f.fermer();
      }
    });

    it("cas.json : réappliquer la politique à la pièce stockée redonne les mêmes octets (EX-10.15)", function () {
      for (const c of json(path.join(R, "cas.json"))) {
        const e = c.expected;
        const d = typeof c.input === "string" ? { genre: "texte", portee: c.scope, outil: c.tool, texte: e.piece } : { genre: "json", portee: c.scope, outil: c.tool, valeur: analyserJsonIntegral(e.piece) };
        const r = produirePiece(pol(c.policy), d, O);
        expect(texte(r.piece), c.name).to.equal(e.piece);
        expect(r.redacted, c.name).to.equal(false);
      }
    });
  });

  describe("pièces rédigées des vecteurs pieces-mcp/appels et evenements/journal-demo (pii-v1)", function () {
    const pii = compilee(PII);
    const lignes = (f) => fs.readFileSync(f, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));

    it("pieces-mcp/appels : pièce « arguments » de chaque appel, et « résultat » reçu de l'amont", function () {
      const dirs = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-mcp", "appels")).sort();
      let arguments_ = 0;
      let redigees = 0;
      for (const cas of dirs) {
        const D = path.join(VECTEURS_CT2, "pieces-mcp", "appels", cas);
        const a = json(path.join(D, "attendu.json"));
        if (a.rejected || !a.pieces?.arguments) continue;
        const appel = lignes(path.join(D, "hote.jsonl")).filter((x) => x.dir === "in" && x.line).map((x) => analyserJsonIntegral(x.line)).find((m) => m.method === "tools/call");
        const r = produirePiece(pii, { genre: "json", portee: "arguments", outil: a.tool_announced, valeur: appel.params.arguments ?? {} }, O);
        expect(r.piece.reference.sha256, cas).to.equal(a.pieces.arguments.sha256);
        expect(r.redacted, cas).to.equal(a.pieces.arguments.redacted);
        arguments_++;
        if (r.redacted) redigees++;
        const amont = lignes(path.join(D, "amont.jsonl"));
        const sortant = amont.filter((x) => x.dir === "out" && x.line).map((x) => analyserJsonIntegral(x.line)).find((m) => m.method === "tools/call");
        const reponse = amont.filter((x) => x.dir === "in" && x.line).map((x) => analyserJsonIntegral(x.line)).find((m) => m.id === sortant?.id && "result" in m);
        // Issue sans réponse exploitable (délai, taille, perte) : forme d'erreur de l'enregistreur (frontal MCP).
        const issueEnregistreur = [-31010, -31011, -31013, -31014, -31017].includes(analyserJsonIntegral(a.pieces.result?.bytes ?? "{}")?.noortrace_jsonrpc_error?.code);
        if (a.pieces.result && reponse && !issueEnregistreur && reponse.result !== null && typeof reponse.result === "object" && !Array.isArray(reponse.result)) {
          const rr = produirePiece(pii, { genre: "json", portee: "resultat", outil: a.tool_announced, valeur: reponse.result }, O);
          expect(rr.piece.reference.sha256, `${cas} résultat`).to.equal(a.pieces.result.sha256);
          expect(rr.redacted).to.equal(a.pieces.result.redacted);
        }
      }
      expect(arguments_).to.be.greaterThan(10);
      expect(redigees).to.be.greaterThan(4);
    });

    it("journal-demo : arguments de seq 3, 5, 7 ; prompt système (prompt_version, EX-8.6), requête en mode `reference` (EX-8.5, EX-10.16), réponse hors flux", function () {
      const D = path.join(VECTEURS_CT2, "evenements", "journal-demo");
      const entrees = json(path.join(D, "entrees.json"));
      const ev = json(path.join(D, "evenements.json"));
      for (const c of entrees.calls) {
        const l = JSON.parse(c.host_line);
        const r = produirePiece(pii, { genre: "json", portee: "arguments", outil: l.params.name, valeur: l.params.arguments }, O);
        expect(r.piece.reference).to.deep.equal(ev[c.seq - 1].execution.arguments);
      }
      for (const x of entrees.exchanges) {
        const e = ev[x.seq - 1];
        const p = produirePiece(pii, { genre: "texte", portee: "prompt_systeme", texte: x.request.system }, O);
        expect(p.piece.sha256, `prompt seq ${x.seq}`).to.equal(e.code.prompt_version);
        expect(p.redacted).to.equal(true);
        // Mode `reference` : le prompt devient le jeton ; la comparaison d'EX-10.16 se fait avec le corps reçu.
        const req = produirePiece(pii, { genre: "json", portee: "requete", valeur: { ...x.request, system: JETON_PROMPT_SYSTEME }, origine: x.request }, O);
        expect(req.piece.reference, `requête seq ${x.seq}`).to.deep.equal(e.execution.arguments);
        if (x.response_content_type === "application/json") {
          const rep = produirePiece(pii, { genre: "json", portee: "reponse", valeur: JSON.parse(x.response_body) }, O);
          expect(rep.piece.reference, `réponse seq ${x.seq}`).to.deep.equal(e.execution.result);
        }
      }
    });
  });

  // ------------------------------------------------------------------ 10.1, 10.2
  describe("principes (10.1)", function () {
    it("EX-10.1 : la pièce stockée est la valeur rédigée ; sans règle applicable, les octets sont ceux de la valeur reçue", function () {
      const p = compilee(PII);
      const r = produirePiece(p, { genre: "json", portee: "arguments", outil: "x__y", valeur: { iban: "CH9300762011623852957" } }, O);
      expect(texte(r.piece)).to.equal('{"iban":"[REDIGE:iban]"}');
      expect(r.piece.reference.length).to.equal(r.piece.octets.length);
      // Échec : une portée sans règle (aucune règle de pii-v1 ne vise `arguments` d'une politique sans elle) laisse le clair.
      const vide = compilee(politique([regle({ scopes: ["reponse"] })]));
      const r2 = produirePiece(vide, { genre: "json", portee: "arguments", outil: "x__y", valeur: { iban: "CH9300762011623852957" } }, O);
      expect(texte(r2.piece)).to.include("CH9300762011623852957");
      expect(r2.redacted).to.equal(false);
    });

    it("EX-10.2 : ni clair ni hachage sans clé dans la pièce, le journal d'exploitation et les métriques ; seul le pseudonyme à clé", async function () {
      const journal = new JournalExploitation({});
      const metriques = new Metriques();
      const d = POLITIQUES["pii-pseudo-test"];
      const red = new Redacteur({ politique: d, cle: CLE_TEST, fils: 0, journal, metriques });
      const clair = "CH9300762011623852957";
      const r = await red.redigerArguments({ beneficiary_iban: clair, note: "j.dupont@example.ch" }, { outil: "demo__payments.create", id: "req-7" });
      const traces = [texte(r.piece), JSON.stringify(journal.lignes), metriques.exposer()].join("\n");
      const hachages = [clair, "j.dupont@example.ch"].flatMap((v) => [N.sha256Hex(N.utf8(v)).slice(2), N.octetsVersHex(N.keccak256(N.utf8(v))).slice(2)]);
      for (const v of [clair, "j.dupont@example.ch", ...hachages]) expect(traces).to.not.include(v);
      expect(texte(r.piece)).to.match(/\[PSEUDO:iban:[0-9a-f]{12}\]/);
      // Échec : sans clé, l'action pseudonyme est refusée (une empreinte sans secret se renverse).
      expect(() => new PolitiqueCompilee(d, { cle: null })).to.throw(/sans clé/);
    });

    it("EX-10.3 : document validé contre son schéma ; un document hors schéma est refusé (pas 2 de 15.4)", function () {
      expect(validerPolitiqueRedaction(PII).valide).to.equal(true);
      const mauvais = { ...PII, name: "PII V1" };
      expect(validerPolitiqueRedaction(mauvais).valide).to.equal(false);
      const c = configurationExemple();
      c.policy.redaction = { ...PII, rules: [] };
      const v = validerConfiguration(N.utf8(JSON.stringify(c)), { reglesSupplementaires: [controleRedaction] });
      expect(v.pas).to.equal(2);
    });

    it("EX-10.4 : déterministe (deux exécutions, fil appelant et fil de calcul, mêmes octets) ; seul le dépassement de la borne en dépend", async function () {
      const v = { note: "Virement CH93 0076 2011 6238 5295 7, +41 44 123 45 67, 756.1234.5678.97, 3782 822463 10005, j.dupont@example.ch" };
      const a = produirePiece(compilee(PII), { genre: "json", portee: "resultat", outil: "a__b", valeur: v }, O);
      const b = produirePiece(compilee(PII), { genre: "json", portee: "resultat", outil: "a__b", valeur: v }, O);
      expect(Buffer.compare(Buffer.from(a.piece.octets), Buffer.from(b.piece.octets))).to.equal(0);
      const red = new Redacteur({ politique: PII, fils: 1 });
      try {
        const c = await red.redigerResultat(v, { outil: "a__b" });
        expect(c.piece.sha256).to.equal(a.piece.sha256);
      } finally {
        await red.fermer();
      }
      const lent = compilee(politique([regle({ detectors: [{ type: "regex", name: "fin" }] })], { fin: { pattern: "[0-9]+$" } }));
      const x = produirePiece(lent, { genre: "json", portee: "resultat", valeur: { n: `${"1".repeat(60000)}x` } }, { budgetMs: 5 });
      expect(x.non_redigeable).to.equal("budget_redaction");
    });

    it("EX-10.5 : seules les chaînes sont examinées (nombres, booléens, null, noms de membres jamais)", function () {
      const r = produirePiece(compilee(PII), { genre: "json", portee: "arguments", outil: "a__b", valeur: { CH9300762011623852957: 378282246310005, ok: true, rien: null } }, O);
      expect(r.redacted).to.equal(false);
      // La règle `champ` à sélecteur couvre le nombre quand le client connaît le champ (cas champ-sur-nombre).
      const champ = compilee(politique([regle({ path: "/n", detectors: [{ type: "champ", label: "carte" }] })]));
      expect(texte(produirePiece(champ, { genre: "json", portee: "arguments", valeur: { n: 378282246310005 } }, O).piece)).to.equal('{"n":"[REDIGE:carte]"}');
    });
  });

  // ------------------------------------------------------------------ 10.2 : contrôles d'EX-10.6
  describe("politique (10.2) : contrôles d'EX-10.6", function () {
    const erreurs = (d, o) => controlerPolitiqueRedaction(d, o).erreurs.map((e) => e.regle);

    it("champ exige path ; supprimer exige path et le seul champ ; pseudonyme exige la clé ; regex nomme une clé ; id unique", function () {
      expect(erreurs(politique([regle({ detectors: [{ type: "champ", label: "x" }] })]))).to.deep.equal(["un détecteur champ exige path (EX-10.6)"]);
      expect(erreurs(politique([regle({ action: { kind: "supprimer" }, detectors: [{ type: "champ", label: "x" }] })]))).to.include("l'action supprimer exige path (EX-10.6)");
      expect(erreurs(politique([regle({ path: "/a", action: { kind: "supprimer" }, detectors: [{ type: "iban" }] })]))).to.include("l'action supprimer exige le seul détecteur champ (EX-10.6)");
      expect(erreurs(politique([regle({ action: { kind: "pseudonyme" } })]))).to.include("l'action pseudonyme exige pseudonym_key non nul (EX-10.6)");
      expect(erreurs(politique([regle({ detectors: [{ type: "regex", name: "absent" }] })]))).to.include("motif nommé inexistant (EX-10.6)");
      expect(erreurs(politique([regle({}), regle({})]))).to.include("identifiant de règle en double (EX-10.6)");
      // Réussite : les mêmes règles bien formées.
      expect(erreurs(politique([regle({ path: "/a", action: { kind: "supprimer" }, detectors: [{ type: "champ", label: "x" }] })]))).to.deep.equal([]);
    });

    it("motif hors du sous-ensemble ou qui fait correspondre un jeton de la politique : refusé", function () {
      expect(erreurs(politique([regle({})], { m: { pattern: "." } }))[0]).to.match(/hors du sous-ensemble commun/);
      // `IBAN` est dans le jeton `[REDIGE:iban]` ? non (casse) ; `REDIGE` l'est.
      expect(erreurs(politique([regle({})], { m: { pattern: "REDIGE" } }))[0]).to.match(/fait correspondre le jeton \[REDIGE:iban\]/);
      expect(erreurs(politique([regle({})], { m: { pattern: "0{12}" } }))[0]).to.match(/PSEUDO/);
      // Le jeton d'une étiquette `champ` employée compte aussi.
      expect(jetonsPossibles(politique([regle({ path: "/a", detectors: [{ type: "champ", label: "patient" }] })]))).to.include("[REDIGE:patient]");
      expect(erreurs(politique([regle({ path: "/a", detectors: [{ type: "champ", label: "zz9" }] })], { m: { pattern: "zz9" } }))[0]).to.match(/zz9/);
      expect(erreurs(PII)).to.deep.equal([]);
    });

    it("EX-10.23 opération 4 : un motif trop coûteux sur les jetons est refusé, motif par motif", function () {
      // [^x]* répété huit fois puis x : retour arrière polynomial sur les jetons.
      const lent = "[^x]*".repeat(8) + "x";
      expect(controlerMotif(lent).admis).to.equal(true);
      const e = erreurs(politique([regle({})], { lent: { pattern: lent } }), { budgetMs: 5 });
      expect(e).to.deep.equal(["motif trop coûteux sur les jetons (EX-10.23 opération 4)"]);
    });

    it("sous-ensemble : ouvertures (?P< réécrites seulement quand l'analyse les reconnaît", function () {
      expect(analyserMotif("(?P<a>x)|[(?P<]").sourceEcma).to.equal("(?<a>x)|[(?P<]");
      expect(analyserMotif("\\\\(?P<x>a)").sourceEcma).to.equal("\\\\(?<x>a)");
      expect(analyserMotif("a\\(?P<b").sourceEcma).to.equal("a\\(?P<b");
    });

    it("entrées hostiles : motifs mal formés, profonds ou démesurés refusés sans exception non attendue", function () {
      for (const m of ["(", ")", "[a", "a{", "a{2,1}", "[z-a]", "(?<1a>x)", "(?<=a)b", "(?P<a>x)(?P<a>y)", "\\", "a**", "x{1,}{2}", "(".repeat(1001) + "a" + ")".repeat(1001), "a".repeat(1001), "[a-\\d]", "a{0,1001}"]) {
        const c = controlerMotif(m);
        expect(c.admis, m.slice(0, 40)).to.equal(false);
        expect(c.raison).to.be.a("string");
      }
      expect(controlerMotif("(".repeat(500) + "a" + ")".repeat(500)).admis).to.equal(true);
    });
  });

  // ------------------------------------------------------------------ 10.3 : détecteurs
  describe("détecteurs exacts (10.3)", function () {
    const un = (f, s) => f(s, 0, s.length).map((m) => s.slice(m.debut, m.fin));

    it("EX-10.8 : aucune normalisation (pleine chasse, minuscules, espace fine non admise) ; séparateurs isolés seulement", function () {
      expect(un(detecterIban, "ＣＨ9300762011623852957")).to.deep.equal([]);
      expect(un(detecterIban, "CH9300762011623852957")).to.deep.equal(["CH9300762011623852957"]);
      expect(un(detecterIban, "CH93 0076 2011 6238 5295 7")).to.have.length(1);
      expect(un(detecterIban, "CH93  0076 2011 6238 5295 7")).to.deep.equal([]);
      expect(un(detecterIban, "CH93 0076 2011 6238 5295 7")).to.deep.equal([]);
      expect(un(detecterCarte, "3782 822463  10005")).to.deep.equal([]);
      expect(un(detecterCarte, "3782 822463 10005-")).to.deep.equal(["3782 822463 10005"]);
      expect(un(detecterAvs, "756.1234.5678.97")).to.have.length(1);
      expect(un(detecterAvs, "756..1234.5678.97")).to.deep.equal([]);
    });

    it("EX-10.9 : frontières, non-chevauchement, fin de correspondance frontière, jetons opaques", function () {
      expect(un(detecterTelephone, "+41441234567+41441234567")).to.have.length(2);
      expect(un(detecterTelephone, "x+41441234567")).to.deep.equal([]);
      expect(un(detecterEmail, "a@example.ch@b.example.ch")).to.deep.equal(["a@example.ch"]);
      const p = compilee(PII);
      // Un pseudonyme dont les douze chiffres passent Luhn n'est pas une carte.
      const r = produirePiece(p, { genre: "texte", portee: "contexte", texte: "[PSEUDO:iban:378282246313] 378282246310005" }, O);
      expect(texte(r.piece)).to.equal("[PSEUDO:iban:378282246313] [REDIGE:carte]");
      // Un jeton d'un type que la politique n'emploie pas n'est pas opaque.
      const r2 = produirePiece(p, { genre: "texte", portee: "contexte", texte: "[REDIGE:inconnu:378282246310005]" }, O);
      expect(texte(r2.piece)).to.equal("[REDIGE:inconnu:[REDIGE:carte]]");
    });

    it("sommes de contrôle : IBAN MOD 97-10, clé AVS, Luhn ; un candidat qui échoue n'est pas rédigé", function () {
      expect(un(detecterIban, "GB19LOYD30961700709943")).to.have.length(1);
      expect(un(detecterIban, "GB19LOYD30961700709944")).to.deep.equal([]);
      expect(un(detecterAvs, "7561234567897")).to.have.length(1);
      expect(un(detecterAvs, "7561234567890")).to.deep.equal([]);
      expect(un(detecterCarte, "4111111111111111")).to.have.length(1);
      expect(un(detecterCarte, "4111111111111112")).to.deep.equal([]);
      expect(un(detecterCarte, "41111111111111111111")).to.deep.equal([]);
    });

    it("courriel : domaine à deux labels, dernier label de lettres, point ou trait final hors du domaine", function () {
      expect(un(detecterEmail, "x@a-.example.ch")).to.deep.equal([]);
      expect(un(detecterEmail, "x@exemple.c1")).to.deep.equal([]);
      expect(un(detecterEmail, "Ecrire a x@exemple.com.")).to.deep.equal(["x@exemple.com"]);
      expect(un(detecterEmail, ".x@exemple.com")).to.deep.equal([]);
      expect(un(detecterEmail, `x@${"a".repeat(64)}.ch`)).to.deep.equal([]);
      expect(un(detecterEmail, `x@${"a.".repeat(127)}ch`)).to.deep.equal([]);
    });

    it("téléphone : groupe entre parenthèses compté seulement suivi d'un chiffre ; 8 à 15 chiffres ; frontière à la fin", function () {
      expect(un(detecterTelephone, "+41 (0)44 123 45 67")).to.deep.equal(["+41 (0)44 123 45 67"]);
      expect(un(detecterTelephone, "+41 (0)(1)44 123 45 67")).to.deep.equal([]);
      expect(un(detecterTelephone, "+41 44 123 45 67a")).to.deep.equal([]);
      expect(un(detecterTelephone, "+0 44 123 45 67")).to.deep.equal([]);
      expect(un(detecterTelephone, "+41--44 123 45 67")).to.deep.equal([]);
    });

    it("EX-10.23 : détecteurs nommés en temps linéaire (entrées hostiles de grande taille)", function () {
      const t0 = Date.now();
      for (const s of ["@".repeat(200000), "a".repeat(100000) + "@", "+1".repeat(100000), "7".repeat(200000), "CH93".repeat(50000), "756.".repeat(50000), "1 ".repeat(100000)]) {
        produirePiece(compilee(PII), { genre: "texte", portee: "contexte", texte: s }, { budgetMs: 60000 });
      }
      expect(Date.now() - t0).to.be.below(20000);
    });

    it("entrées hostiles : membre __proto__, imbrication extrême, substituts, chaînes vides", function () {
      const p = compilee(PII);
      const v = analyserJsonIntegral('{"__proto__":{"iban":"CH9300762011623852957"},"a":[""]}');
      const r = produirePiece(p, { genre: "json", portee: "arguments", valeur: v }, O);
      expect(texte(r.piece)).to.equal('{"__proto__":{"iban":"[REDIGE:iban]"},"a":[""]}');
      expect({}.iban).to.equal(undefined);
      expect(JSON.stringify(v)).to.include("CH93");
      let profond = "CH9300762011623852957";
      for (let k = 0; k < 200000; k++) profond = [profond];
      const x = produirePiece(p, { genre: "json", portee: "arguments", valeur: profond }, { budgetMs: 60000 });
      expect(x.non_redigeable).to.equal("budget_redaction");
      const s = produirePiece(p, { genre: "texte", portee: "contexte", texte: "\u{1F600}+41 44 123 45 67\u{1F600}" }, O);
      expect(texte(s.piece)).to.equal("\u{1F600}[REDIGE:telephone]\u{1F600}");
    });

    it("EX-10.10 : motif nommé, correspondance vide ignorée, aucune frontière implicite", function () {
      const p = compilee(politique([regle({ detectors: [{ type: "regex", name: "chiffres" }] })], { chiffres: { pattern: "[0-9]*" } }));
      expect(texte(produirePiece(p, { genre: "texte", portee: "contexte", texte: "ab12c3" }, O).piece)).to.equal("ab[REDIGE:chiffres]c[REDIGE:chiffres]");
      const q = compilee(politique([regle({ detectors: [{ type: "regex", name: "n" }] })], { n: { pattern: "20[0-9]{2}" } }));
      expect(texte(produirePiece(q, { genre: "texte", portee: "contexte", texte: "x2026y" }, O).piece)).to.equal("x[REDIGE:n]y");
    });

    it("EX-10.11 : champ sur une valeur déjà jeton laissée telle quelle ; pseudonyme sur la chaîne, sur le JCS intégral sinon", function () {
      const p = compilee(politique([regle({ path: "/v", detectors: [{ type: "champ", label: "x" }], action: { kind: "pseudonyme" } })], {}, { pseudonym_key: { env: "K", encoding: "hex" } }));
      const s = produirePiece(p, { genre: "json", portee: "arguments", valeur: { v: "abc" } }, O);
      expect(texte(s.piece)).to.equal(`{"v":"${jetonPseudonyme(CLE_TEST, "x", "abc")}"}`);
      const o = produirePiece(p, { genre: "json", portee: "arguments", valeur: { v: { b: 1, a: [2] } } }, O);
      expect(texte(o.piece)).to.equal(`{"v":"${jetonPseudonyme(CLE_TEST, "x", '{"a":[2],"b":1}')}"}`);
      const j = produirePiece(p, { genre: "json", portee: "arguments", valeur: { v: "[REDIGE:iban]" } }, O);
      expect(j.redacted).to.equal(false);
    });

    it("EX-10.12 : pseudonymes publiés de 10.9 ; encodages de la clé ; moins de 32 octets refusés (pas 4)", function () {
      expect(jetonPseudonyme(CLE_TEST, "iban", "CH9300762011623852957")).to.equal("[PSEUDO:iban:50d46ea9a82b]");
      expect(jetonPseudonyme(CLE_TEST, "email", "j.dupont@example.ch")).to.equal("[PSEUDO:email:b8ac789204a6]");
      const c = configurationExemple();
      c.policy.redaction = POLITIQUES["pii-pseudo-test"];
      const hex = Buffer.from(CLE_TEST).toString("hex");
      for (const [encoding, valeur] of [["hex", hex], ["hex", `0x${hex}`], ["base64", Buffer.from(CLE_TEST).toString("base64")]]) {
        c.policy.redaction = { ...POLITIQUES["pii-pseudo-test"], pseudonym_key: { env: "NOORTRACE_VECTEURS_CLE_PSEUDO", encoding } };
        const s = resoudreSecrets(c, { env: { NOORTRACE_VECTEURS_CLE_PSEUDO: valeur } });
        expect(Buffer.from(s.secrets.get("/policy/redaction/pseudonym_key")).equals(Buffer.from(CLE_TEST)), encoding).to.equal(true);
      }
      c.policy.redaction = { ...POLITIQUES["pii-pseudo-test"], pseudonym_key: { env: "NOORTRACE_VECTEURS_CLE_PSEUDO", encoding: "utf8" } };
      const court = resoudreSecrets(c, { env: { NOORTRACE_VECTEURS_CLE_PSEUDO: "trop-courte" } });
      expect(court.erreurs.map((e) => e.pointeur)).to.include("/policy/redaction/pseudonym_key");
    });

    it("EX-10.13 : même valeur, même jeton sous une clé ; une autre clé rompt l'intégrité référentielle", function () {
      const a = jetonPseudonyme(CLE_TEST, "email", "j.dupont@example.ch");
      expect(jetonPseudonyme(CLE_TEST, "email", "j.dupont@example.ch")).to.equal(a);
      expect(jetonPseudonyme(new Uint8Array(32).fill(7), "email", "j.dupont@example.ch")).to.not.equal(a);
    });
  });

  // ------------------------------------------------------------------ 10.4
  describe("ordre, idempotence, marquage (10.4)", function () {
    it("EX-10.14 : règles retenues par portée et par outil (nom exact, <alias>__*, alias fourni) ; pointeur non résolu sans effet, noté", async function () {
      const p = compilee(politique([regle({ id: "a", tools: ["demo__x"] }), regle({ id: "b", tools: ["sap__*"], detectors: [{ type: "email" }] })]));
      expect(p.retenues("arguments", "demo__x").map((r) => r.id)).to.deep.equal(["a"]);
      expect(p.retenues("arguments", "sap__payments.create").map((r) => r.id)).to.deep.equal(["b"]);
      expect(p.retenues("arguments", "payments.create", "sap").map((r) => r.id)).to.deep.equal(["b"]);
      expect(p.retenues("reponse", "sap__payments.create").map((r) => r.id)).to.deep.equal([]);
      const journal = new JournalExploitation({});
      const red = new Redacteur({ politique: POLITIQUES["pii-regles-test"], fils: 0, journal });
      const r = await red.redigerArguments({ claim_id: "2026-77812" }, { outil: "demo__payments.create", id: "req-1" });
      expect(r.redacted).to.equal(false);
      expect(journal.trouver("redaction_path_unresolved").map((l) => l.data.rule)).to.include("montant-champ");
    });

    it("EX-10.16 : redacted si et seulement si les octets diffèrent ; règle applicable sans correspondance : false", function () {
      const p = compilee(PII);
      expect(produirePiece(p, { genre: "json", portee: "arguments", valeur: { a: "rien" } }, O).redacted).to.equal(false);
      expect(produirePiece(p, { genre: "json", portee: "arguments", valeur: { a: "x@exemple.com" } }, O).redacted).to.equal(true);
      // Le jeton du prompt système compte comme une rédaction de la requête (EX-8.5, EX-10.16).
      const req = { model: "m", system: "secret de fabrication", messages: [] };
      const r = produirePiece(p, { genre: "json", portee: "requete", valeur: { ...req, system: JETON_PROMPT_SYSTEME }, origine: req }, O);
      expect(r.redacted).to.equal(true);
      expect(r.comptes).to.deep.equal([]);
    });

    it("EX-10.17 : `redaction_applied` avec l'id de l'appel, la portée, les règles et les comptes, sans valeur ni position ; métriques par type", async function () {
      const journal = new JournalExploitation({});
      const metriques = new Metriques();
      const red = new Redacteur({ politique: PII, fils: 0, journal, metriques });
      await red.redigerResultat({ note: "x@exemple.com et y@exemple.com, +41 44 123 45 67" }, { outil: "sap__claims.get", id: "e-000000000001" });
      const [l] = journal.trouver("redaction_applied");
      expect(l.request_id).to.equal("e-000000000001");
      expect(l.data).to.deep.equal({
        scope: "resultat",
        rules: ["identifiants-arguments-resultat"],
        matches: [{ rule: "identifiants-arguments-resultat", detector: "email", count: 2 }, { rule: "identifiants-arguments-resultat", detector: "telephone", count: 1 }],
      });
      expect(JSON.stringify(l)).to.not.match(/exemple\.com|\+41/);
      expect(metriques.valeur("noortrace_redactions_total", { type: "email", scope: "resultat" })).to.equal(2);
    });

    it("EX-10.18 : intention tirée de la réponse rédigée, comparée au texte en clair ; pièce texte : seul le pointeur vide résout ; valeur en ligne : path non résolu", function () {
      const p = compilee(PII);
      const clair = "Je verse sur CH9300762011623852957.";
      const rep = produirePiece(p, { genre: "json", portee: "reponse", valeur: { content: [{ type: "text", text: clair }] } }, O);
      const intention = rep.valeur.content[0].text;
      const ref = produirePiece(p, { genre: "texte", portee: "reponse", texte: intention, origine: clair }, O);
      expect(texte(ref.piece)).to.equal("Je verse sur [REDIGE:iban].");
      expect(ref.redacted).to.equal(true);
      const chemin = compilee(politique([regle({ path: "/x", detectors: [{ type: "champ", label: "c" }] }), regle({ id: "s", path: "", detectors: [{ type: "email" }] })]));
      const t = produirePiece(chemin, { genre: "texte", portee: "contexte", texte: "a@exemple.com" }, O);
      expect(texte(t.piece)).to.equal("[REDIGE:email]");
      // Valeur en ligne : une règle à path quelconque s'applique à la chaîne entière.
      expect(examinerValeurLigne(compilee(politique([regle({ path: "/beneficiary_iban" })])), "CH9300762011623852957", 1000).admise).to.equal(false);
    });

    it("EX-10.19 : règle champ de portée prompt_systeme, pointeur vide : le prompt devient le jeton, prompt_version constant", function () {
      const p = compilee(politique([regle({ scopes: ["prompt_systeme"], path: "", detectors: [{ type: "champ", label: "prompt-systeme" }] })]));
      const a = produirePiece(p, { genre: "texte", portee: "prompt_systeme", texte: "prompt A" }, O);
      const b = produirePiece(p, { genre: "texte", portee: "prompt_systeme", texte: "prompt B" }, O);
      expect(texte(a.piece)).to.equal("[REDIGE:prompt-systeme]");
      expect(a.piece.sha256).to.equal(b.piece.sha256);
      expect(a.piece.reference.media_type).to.equal("text/plain");
    });

    it("EX-10.21 : des règles changées sans changer redaction.name sont refusées ; même document ou nom nouveau, admis", function () {
      const annoncees = new Map([["v1", { version: "v1", redaction: PII }]]);
      expect(verifierChangementRedaction({ version: "v2", redaction: PII }, annoncees)).to.equal(null);
      const change = { ...PII, rules: PII.rules.slice(0, 1) };
      expect(verifierChangementRedaction({ version: "v2", redaction: change }, annoncees)).to.match(/EX-10.21/);
      expect(verifierChangementRedaction({ version: "v2", redaction: { ...change, name: "pii-v2" } }, annoncees)).to.equal(null);
    });
  });

  // ------------------------------------------------------------------ 10.7 coffre
  describe("coffre des originaux (10.7, EX-10.22 ; CT-7 EX-3.11)", function () {
    let dir;
    before(function () {
      dir = repertoireTemporaire("noortrace-redaction-coffre-");
    });

    it("désactivé (défaut) : aucun original stocké ; activé : homologue AES-256-GCM lié au sha256 de la pièce rédigée", async function () {
      const sans = new Redacteur({ politique: PII, fils: 0 });
      await sans.redigerArguments({ iban: "CH9300762011623852957" }, { outil: "a__b" });
      expect(sans.coffre).to.equal(null);
      const cle = new Uint8Array(crypto.randomBytes(32));
      const coffre = new CoffreOriginaux({ chemin: path.join(dir, "coffre"), cle });
      const red = new Redacteur({ politique: PII, fils: 1, coffre });
      try {
        const r = await red.redigerArguments({ iban: "CH9300762011623852957" }, { outil: "a__b" });
        const f = coffre.fichier(r.piece.sha256);
        const brut = fs.readFileSync(f);
        expect(brut.length).to.equal(12 + Buffer.byteLength('{"iban":"CH9300762011623852957"}') + 16);
        expect(brut.toString("latin1")).to.not.include("CH93");
        // Une pièce non rédigée n'a pas d'homologue.
        const n = await red.redigerArguments({ a: "rien" }, { outil: "a__b" });
        expect(fs.existsSync(coffre.fichier(n.piece.sha256))).to.equal(false);
        // Déchiffrement à deux personnes, consigné hors du coffre.
        const registre = path.join(dir, "acces", "registre.ndjson");
        const demande = { par: "alice", motif: "requête du tribunal 2026-17" };
        const original = await coffre.dechiffrer({ sha256: r.piece.sha256, demande, approbation: { par: "bob", sha256: r.piece.sha256, motif: demande.motif }, autorises: ["alice", "bob"], registre });
        expect(Buffer.from(original).toString()).to.equal('{"iban":"CH9300762011623852957"}');
        const lignes = fs.readFileSync(registre, "utf8").trim().split("\n").map((l) => JSON.parse(l));
        expect(lignes[0]).to.include({ sha256: r.piece.sha256, requester: "alice", approver: "bob", result: "accorde", refusal: null });
        // Échecs : sans seconde approbation, même personne, non autorisée, autre pièce, registre dans le coffre.
        const essais = [
          [{ approbation: null }, "seconde_approbation_absente"],
          [{ approbation: { par: "alice", sha256: r.piece.sha256, motif: demande.motif } }, "approbateur_identique_au_demandeur"],
          [{ approbation: { par: "eve", sha256: r.piece.sha256, motif: demande.motif } }, "approbateur_non_autorise"],
          [{ approbation: { par: "bob", sha256: n.piece.sha256, motif: demande.motif } }, "approbation_d_une_autre_demande"],
          [{ approbation: { par: "bob", sha256: r.piece.sha256, motif: "autre motif" } }, "approbation_d_une_autre_demande"],
        ];
        for (const [x, raison] of essais) {
          let err = null;
          try {
            await coffre.dechiffrer({ sha256: r.piece.sha256, demande, autorises: ["alice", "bob"], registre, ...x });
          } catch (e) {
            err = e;
          }
          expect(err, raison).to.be.instanceOf(AccesCoffreRefuse);
          expect(err.raison).to.equal(raison);
        }
        let e2 = null;
        try {
          await coffre.dechiffrer({ sha256: r.piece.sha256, demande, approbation: { par: "bob", sha256: r.piece.sha256, motif: demande.motif }, autorises: ["alice", "bob"], registre: path.join(dir, "coffre", "r.ndjson") });
        } catch (e) {
          e2 = e;
        }
        expect(e2).to.be.instanceOf(AccesCoffreRefuse);
        expect(fs.readFileSync(registre, "utf8").trim().split("\n")).to.have.length(1 + essais.length);
        // Données associées : un homologue déplacé sous le nom d'une autre pièce ne se déchiffre pas.
        fs.copyFileSync(f, coffre.fichier(n.piece.sha256));
        let e3 = null;
        try {
          await coffre.dechiffrer({ sha256: n.piece.sha256, demande, approbation: { par: "bob", sha256: n.piece.sha256, motif: demande.motif }, autorises: ["alice", "bob"], registre });
        } catch (e) {
          e3 = e;
        }
        expect(e3?.raison).to.equal("dechiffrement_en_echec");
      } finally {
        await red.fermer();
      }
    });

    it("configuration : chemin et clé exigés, hors de storage.root, clé de 32 octets (pas 3 et 4)", function () {
      const c = configurationExemple();
      c.storage.vault = { enabled: true, path: null, key: null };
      expect(controleRedaction(c).erreurs.map((e) => e.pointeur)).to.deep.equal(["/storage/vault/path", "/storage/vault/key"]);
      c.storage.vault = { enabled: true, path: path.join(c.storage.root, "coffre"), key: { env: "CLE_COFFRE", encoding: "hex" } };
      expect(controleRedaction(c).erreurs.map((e) => e.regle)).to.include("coffre hors du répertoire des segments et des pièces (EX-10.22)");
      c.storage.vault.path = path.join(path.dirname(c.storage.root), "noortrace-coffre");
      expect(controleRedaction(c).erreurs).to.deep.equal([]);
      expect(controleSecretsRedaction(c, new Map([["/storage/vault/key", new Uint8Array(16)]]))).to.have.length(1);
      expect(controleSecretsRedaction(c, new Map([["/storage/vault/key", new Uint8Array(32)]]))).to.deep.equal([]);
      expect(() => new CoffreOriginaux({ chemin: path.resolve("coffre-essai"), cle: new Uint8Array(31) })).to.throw(/32 octets/);
    });
  });

  // ------------------------------------------------------------------ EX-10.23, EX-10.24, EX-3.6
  describe("coût borné (EX-10.23), motif d'une décision (EX-10.24), fils de calcul (EX-3.6)", function () {
    const lente = politique([regle({ detectors: [{ type: "regex", name: "fin" }] })], { fin: { pattern: "[0-9]+$" } });
    const lourd = `${"1".repeat(80000)}x`;

    it("opération 1 : pièce remplacée par la pièce non rédigeable (longueur du JCS intégral du clair), consigné et compté", async function () {
      const journal = new JournalExploitation({});
      const metriques = new Metriques();
      const red = new Redacteur({ politique: lente, fils: 0, budgetMs: 20, journal, metriques });
      const v = { n: lourd };
      const r = await red.redigerResultat(v, { outil: "a__b" });
      expect(analyserJsonIntegral(texte(r.piece))).to.deep.equal({ noortrace_non_redigeable: { content_type: null, length: jcsIntegral(v).length, reason: "budget_redaction" } });
      expect(r.redacted).to.equal(true);
      expect(journal.trouver("redaction_budget_exceeded")[0].data).to.deep.equal({ operation: "piece", scope: "resultat", rule: "r" });
      expect(metriques.valeur("noortrace_redaction_budget_exceeded_total", { operation: "piece", scope: "resultat" })).to.equal(1);
      // Une lecture suit son cours ; les arguments d'une écriture ou d'un outil susceptible sont refusés avant relais.
      const a = await red.redigerArguments(v, { outil: "a__b" });
      expect(() => red.bloquerArgumentsNonRedigeables(a, { classe: "lecture", susceptible: false })).to.not.throw();
      for (const o of [{ classe: "ecriture", susceptible: false }, { classe: "lecture", susceptible: true }]) {
        let err = null;
        try {
          red.bloquerArgumentsNonRedigeables(a, o);
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurEnregistreur);
        expect([err.raison, err.code]).to.deep.equal(["redaction", -31010]);
      }
      expect(metriques.valeur("noortrace_calls_blocked_total", { code: "-31010", reason: "redaction", class: "ecriture" })).to.equal(1);
      // Réussite : avec une borne suffisante, la même pièce est rédigée.
      const ok = new Redacteur({ politique: lente, fils: 0, budgetMs: 60000 });
      expect(texte((await ok.redigerResultat({ n: "abc 123" }, { outil: "a__b" })).piece)).to.equal('{"n":"abc [REDIGE:fin]"}');
    });

    it("EX-8.7 : corps non JSON — UTF-8 rédigé comme texte (marque d'ordre conservée), binaire non rédigeable, codage inconnu, sans règle stocké tel quel", async function () {
      const p = compilee(PII);
      const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from("<html>rien</html>")]);
      const a = produirePiece(p, { genre: "octets", portee: "reponse", octets: new Uint8Array(bom), content_type: "Text/HTML; charset=utf-8" }, O);
      expect(Buffer.from(a.piece.octets).equals(bom)).to.equal(true);
      expect(a.piece.reference).to.include({ redacted: false, media_type: "text/html" });
      const b = produirePiece(p, { genre: "octets", portee: "reponse", octets: new Uint8Array(Buffer.from("erreur pour x@exemple.com")), content_type: "text/plain" }, O);
      expect(texte(b.piece)).to.equal("erreur pour [REDIGE:email]");
      const bin = new Uint8Array([0xff, 0xfe, 0x00, 0x41]);
      const c = produirePiece(p, { genre: "octets", portee: "reponse", octets: bin, content_type: "application/octet-stream" }, O);
      expect(analyserJsonIntegral(texte(c.piece))).to.deep.equal({ noortrace_non_redigeable: { content_type: "application/octet-stream", length: 4, reason: "non_utf8" } });
      expect(c.piece.reference).to.not.have.property("media_type");
      const d = produirePiece(p, { genre: "octets", portee: "reponse", octets: new Uint8Array(Buffer.from("abc")), content_type: null, codage_inconnu: true }, O);
      expect(analyserJsonIntegral(texte(d.piece)).noortrace_non_redigeable.reason).to.equal("codage_inconnu");
      const sans = compilee(politique([regle({ scopes: ["arguments"] })]));
      const e = produirePiece(sans, { genre: "octets", portee: "reponse", octets: bin, content_type: null }, O);
      expect(Buffer.from(e.piece.octets).equals(Buffer.from(bin))).to.equal(true);
      expect(e.piece.reference.media_type).to.equal("application/octet-stream");
      // Document de contexte JSON (8.2, EX-8.8) : JCS intégral, application/json.
      const f = produirePiece(p, { genre: "contexte", octets: N.utf8('{"b":1,"a":"+41 44 123 45 67"}'), media_type: "application/vnd.x+json" }, O);
      expect(texte(f.piece)).to.equal('{"a":"[REDIGE:telephone]","b":1}');
      expect(f.piece.reference.media_type).to.equal("application/json");
    });

    it("opération 2 : extract sous la borne, effet omis `budget_redaction`, effet par défaut d'une écriture sans effet ; sous-ensemble contrôlé", function () {
      expect(executerExtract("PAY-([0-9]+)", "x PAY-42 y", 1000)).to.equal("42");
      expect(executerExtract(".", "x", 1000)).to.equal(null);
      expect(() => executerExtract("[0-9]+$", lourd, 10)).to.throw(DepassementBudget);
      const p = { gabarit: [{ system: "SAP", action: "ecriture", object: "/arguments/r", extract: "[0-9]+$", amount: null, currency: null }], classe: "ecriture", alias: "sap", nomOrigine: "payments.create", arguments: { r: lourd }, resultat: {} };
      const r = evaluerEffets({ ...p, executerExtract: (m, t) => executerExtract(m, t, 10) });
      expect(r.omis).to.deep.equal([{ index: 0, raison: "budget_redaction" }]);
      expect(r.effets).to.deep.equal([{ system: "sap", action: "ecriture", object: "payments.create", amount: null, currency: null }]);
      // Une lecture n'a pas d'effet par défaut ; un extract ordinaire donne l'effet.
      expect(evaluerEffets({ ...p, classe: "lecture", executerExtract: (m, t) => executerExtract(m, t, 10) }).effets).to.deep.equal([]);
      expect(evaluerEffets({ ...p, arguments: { r: "abc 12" }, executerExtract: (m, t) => executerExtract(m, t, 1000) }).effets[0].object).to.equal("12");
      const c = configurationExemple();
      c.policy.servers.sap.tools["payments.create"].effects[0].extract = "\\s+";
      expect(controleRedaction(c).erreurs[0].pointeur).to.equal("/policy/servers/sap/tools/payments.create/effects/0/extract");
    });

    it("opération 3 et EX-7.2, EX-8.6 : valeurs en ligne examinées par tous les détecteurs de texte ; dépassement = correspondance", async function () {
      const red = new Redacteur({ politique: POLITIQUES["pii-regles-test"], fils: 0 });
      expect(await red.admettreRunId("run-demo-0001")).to.equal(true);
      expect(await red.admettreRunId("run+41441234567")).to.equal(false);
      expect(await red.admettreRunId("run-2026-81044")).to.equal(false);
      expect(await red.admettreRunId("r".repeat(129))).to.equal(false);
      expect(await red.admettreNomPrompt("sinistres-v3")).to.equal(true);
      expect(await red.admettreNomPrompt("x@exemple.com")).to.equal(false);
      // La règle numero-sinistre (portées resultat, reponse) s'applique quand même à la valeur en ligne.
      expect(await red.admettreValeurLigne("dossier 2026-81044")).to.equal(false);
      expect(examinerValeurLigne(compilee(lente), lourd, 5)).to.deep.equal({ admise: false, depassement: true });
    });

    it("EX-6.6 : effets déclarés par le SDK rédigés par les règles de portée arguments de l'outil, la chaîne étant la racine", async function () {
      const red = new Redacteur({ politique: PII, fils: 0 });
      const r = await red.redigerEffetsDeclares([{ system: "banque", action: "ecriture", object: "virement CH9300762011623852957", amount: "10.00", currency: "CHF" }], { outil: "agent__payer" });
      expect(r.effets[0].object).to.equal("virement [REDIGE:iban]");
      const lent = new Redacteur({ politique: lente, fils: 0, budgetMs: 5 });
      const x = await lent.redigerEffetsDeclares([{ system: "s", action: "ecriture", object: lourd, amount: null, currency: null }], { outil: "agent__payer" });
      expect(x).to.deep.equal({ effets: [], omis: [{ index: 0, raison: "budget_redaction" }] });
    });

    it("EX-10.24 : motif rédigé par les détecteurs de texte de toutes les règles, path ignoré, champ et supprimer exclus, tronqué à 1024, null au dépassement", async function () {
      const p = compilee(POLITIQUES["pii-regles-test"]);
      expect(redigerMotifDecision(p, "Montant 740000 ; IBAN CH93 0076 2011 6238 5295 7 ; dossier 2026-81044", 1000).motif).to.equal("Montant 740000 ; IBAN [REDIGE:iban] ; dossier [REDIGE:numero-sinistre]");
      expect(redigerMotifDecision(p, null, 1000).motif).to.equal(null);
      const long = `${"é".repeat(1020)} x@exemple.com`;
      const m = redigerMotifDecision(p, long, 1000).motif;
      expect(Array.from(m)).to.have.length(1024);
      expect(m).to.not.include("exemple");
      expect(redigerMotifDecision(compilee(lente), lourd, 5)).to.include({ motif: null, depassement: true });
      const pseudo = new Redacteur({ politique: POLITIQUES["pii-pseudo-test"], cle: CLE_TEST, fils: 1 });
      try {
        expect(await pseudo.redigerMotif("vu j.dupont@example.ch")).to.equal("vu [PSEUDO:email:b8ac789204a6]");
      } finally {
        await pseudo.fermer();
      }
    });

    it("EX-3.6 : la rédaction coûteuse s'exécute hors du fil appelant, qui reste libre ; la garde arrête et relance un fil", async function () {
      const red = new Redacteur({ politique: lente, fils: 1, budgetMs: 300 });
      try {
        await red.redigerResultat({ n: "1" }, { outil: "a__b" });
        let tics = 0;
        const iv = setInterval(() => tics++, 10);
        const t0 = Date.now();
        const r = await red.redigerResultat({ n: lourd }, { outil: "a__b" });
        clearInterval(iv);
        expect(r.non_redigeable).to.equal("budget_redaction");
        expect(Date.now() - t0).to.be.below(300 + 2000);
        expect(tics).to.be.greaterThan(5);
      } finally {
        await red.fermer();
      }
      // Échec contrôlé : dans le fil appelant (fils: 0), le même travail occupe le fil jusqu'à la borne.
      const local = new Redacteur({ politique: lente, fils: 0, budgetMs: 200 });
      let tics = 0;
      const iv = setInterval(() => tics++, 10);
      await local.redigerResultat({ n: lourd }, { outil: "a__b" });
      clearInterval(iv);
      expect(tics).to.equal(0);
      // Garde : un travail au-delà de la garde arrête le fil, qui est relancé.
      const g = new Redacteur({ politique: lente, fils: 1, budgetMs: 60000, gardeMs: 150 });
      try {
        await g.redigerResultat({ n: "1" }, { outil: "a__b" });
        const x = await g.redigerResultat({ n: lourd }, { outil: "a__b" });
        expect(analyserJsonIntegral(texte(x.piece)).noortrace_non_redigeable).to.deep.equal({ content_type: null, length: jcsIntegral({ n: lourd }).length, reason: "budget_redaction" });
        const y = await g.redigerResultat({ n: "ok 7" }, { outil: "a__b" });
        expect(texte(y.piece)).to.equal('{"n":"ok [REDIGE:fin]"}');
      } finally {
        await g.fermer();
      }
    });

    it("executerSousBorne interrompt une recherche en cours et rend la main", function () {
      const t0 = Date.now();
      expect(() => executerSousBorne(() => /[0-9]+$/u.test(lourd), 30, "piece")).to.throw(DepassementBudget);
      expect(Date.now() - t0).to.be.below(30 + 1000);
    });
  });

  // ------------------------------------------------------------------ §15 : validation, commande, rechargement
  describe("configuration (EX-15.4 pas 3 et 4, EX-15.5, EX-15.7)", function () {
    it("validate-config : l'exemple de 15.3 passe ; une politique de rédaction fautive est rapportée et rend 2", async function () {
      const dir = repertoireTemporaire("noortrace-redaction-cfg-");
      const sortie = { t: "", write(s) { this.t += s; } };
      const f = path.join(dir, "ok.json");
      fs.writeFileSync(f, JSON.stringify(configurationExemple()));
      expect(await principal(["validate-config", f], { stdout: sortie, stderr: sortie })).to.equal(0);
      const c = configurationExemple();
      c.policy.redaction.named_patterns["numero-sinistre"].pattern = "(a|aa)+$";
      c.policy.redaction.rules[0].action = { kind: "pseudonyme" };
      const g = path.join(dir, "ko.json");
      fs.writeFileSync(g, JSON.stringify(c));
      const s2 = { t: "", write(s) { this.t += s; } };
      expect(await principal(["validate-config", g], { stdout: s2, stderr: s2 })).to.equal(2);
      expect(s2.t).to.include("/policy/redaction/named_patterns/numero-sinistre/pattern : motif hors du sous-ensemble commun (EX-10.6) : règle a)");
      expect(s2.t).to.include("/policy/redaction/rules/0/action/kind : l'action pseudonyme exige pseudonym_key non nul (EX-10.6)");
    });

    it("rechargement (EX-15.5) : règles fautives refusées ; règles changées sous le même nom refusées (EX-10.21) ; nom nouveau appliqué aux pièces suivantes", async function () {
      const dir = repertoireTemporaire("noortrace-redaction-rech-");
      const { config, env } = configurationDev(dir);
      const v = validerConfiguration(N.utf8(JSON.stringify(config)), { reglesSupplementaires: [controleRedaction] });
      expect(v.erreurs).to.deep.equal([]);
      const red = Redacteur.depuisConfiguration(v.config, secretsDev(), { fils: 0 });
      const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge: new HorlogeReglable(N.decoderHorodatage("2026-11-10T10:00:01.000Z")), redaction: red, reglesSupplementaires: [controleRedaction] });
      try {
        const doc = (c) => N.utf8(JSON.stringify(c));
        const mauvais = JSON.parse(JSON.stringify(v.config));
        mauvais.policy.version = "2026-11-02";
        mauvais.policy.redaction.named_patterns["numero-sinistre"].pattern = ".";
        expect((await coeur.recharger(doc(mauvais), { env })).raison).to.equal("configuration_invalide");
        const meme = JSON.parse(JSON.stringify(v.config));
        meme.policy.version = "2026-11-03";
        meme.policy.redaction.rules = meme.policy.redaction.rules.filter((r) => r.id !== "identifiants-contexte");
        let err = null;
        try {
          await coeur.recharger(doc(meme), { env });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurEnregistreur);
        expect(err.message).to.match(/EX-10.21/);
        meme.policy.redaction.name = "pii-v2";
        meme.policy.redaction.rules = [{ id: "courriel", scopes: ["arguments"], tools: "*", detectors: [{ type: "email" }], action: { kind: "remplacer" } }];
        const ok = await coeur.recharger(doc(meme), { env });
        expect(ok.accepte).to.equal(true);
        expect(red.nom).to.equal("pii-v2");
        const r = await red.redigerArguments({ a: "CH9300762011623852957 x@exemple.com" }, { outil: "sap__payments.create" });
        expect(texte(r.piece)).to.equal('{"a":"CH9300762011623852957 [REDIGE:email]"}');
        expect(coeur.nomRedaction).to.equal("pii-v2");
      } finally {
        await coeur.arreter();
        await red.fermer();
      }
    });
  });
});
