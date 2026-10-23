import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { network } from "hardhat";
import { HDNodeWallet, Signature, getBytes, hashMessage, keccak256, toUtf8Bytes } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as A from "../scripts/lib/approbation.mjs";
import { spawnSync } from "node:child_process";
import { ENTREES_GENEREES, genererCt3, POLITIQUE_ASSUREUR } from "../scripts/vecteurs/generer-ct3.mjs";

// L'IMPLÉMENTATION DE RÉFÉRENCE DE CT-3 (spec/CT-3-approbations.md) :
// scripts/lib/approbation.mjs. Les tests rejouent chaque famille de vecteurs
// de spec/vecteurs/ct-3 (politiques, évaluation, candidats, épreuve
// d'acceptation, traces de tickets, remises, normalisation), confrontent les
// exemples et les valeurs citées par la spécification (exemples annotés
// <!-- schema: … -->, table de 6.7, liste de 4.12, constantes de A.2, source
// de 8.4, remise de 12.5, mesure d'EX-9.7, texte d'EX-11.8), vérifient la
// reprise d'un service depuis son état persisté (TK-12), lisent un vrai
// CuratorSet sur le réseau Hardhat en mémoire (section 8), et exigent la
// génération déterministe (EX-A.1). La matrice de couverture en fin de
// fichier rattache chaque règle EX- de CT-3 à ses tests, ou dit pourquoi elle
// n'est pas testable par cette implémentation.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT3 = path.join(SPEC, "vecteurs", "ct-3");
const MD = fs.readFileSync(path.join(SPEC, "CT-3-approbations.md"), "utf8");
const SCHEMAS = A.registreSchemas(A.FICHIERS_SCHEMAS.map((f) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", f), "utf8"))));
// JSON.parse et non l'analyseur strict : politiques-invalides/substitut-isole.json porte un substitut isolé (AP-4).
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(CT3, ...p), "utf8"));
const fichiers = (...p) => fs.readdirSync(path.join(CT3, ...p)).filter((f) => f.endsWith(".json")).sort();
const tmp = (prefixe) => fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
/** Ordre des pointeurs d'EX-4.2 : unités UTF-16 comparées une à une, comme Array.prototype.sort (et non localeCompare). */
const avant = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const CONSTANTES = lire("constantes.json");
const COMPTE = Object.fromEntries(CONSTANTES.accounts.map((c) => [c.index, HDNodeWallet.fromPhrase(CONSTANTES.mnemonic, undefined, c.derivation_path)]));
const ADR = (i) => CONSTANTES.accounts[i - 1].address;
const E = CONSTANTES.expire_after_ms;
const ORG_ID = CONSTANTES.organization.org_id;
const JOURNAL_ID = CONSTANTES.journal.journal_id;
const V1 = CONSTANTES.policy_versions[0];
const T = (hms) => `2026-11-12T${hms}Z`;

/** Une requête evaluer minimale pour les tests unitaires. */
function demande(outil, args, { demandeur = "u.martin@assureur-demo.example", version = V1, run = "run-test" } = {}) {
  return { tool_announced: outil, tool_original: outil, server_alias: "test", arguments: args, class: "ecriture", delegation: { launched_by: demandeur, on_behalf_of: null, scope: "test", run_id: run }, intent: null, code: { model: null, prompt_version: null, policy_version: version, recorder: "0.1.0" }, context: [] };
}
const politique = (rules, defaut = { name: "defaut : revue", description: null, level: "revue", decision: null, contest_ms: 0 }) => ({ version: 0, default: defaut, rules, approver_set: { source: "registre", chain_id: 2124, registry: CONSTANTES.registry, set: CONSTANTES.sets["1"], members: null, threshold: null }, separation: { self_approval: "interdite", identities: [] } });
const regle = (name, tools, when, level = "automatique", decision = level === "automatique" ? "refuse" : null, extra = {}) => ({ name, description: null, tools, when, level, decision, window: null, contest_ms: level === "automatique" ? null : 0, ...extra });

// ---------------------------------------------------------------------------
// Récupération secp256k1 indépendante (arithmétique BigInt), pour les formes
// non canoniques qu'ethers refuse de recouvrer (EX-9.3, annexe A.8).
// ---------------------------------------------------------------------------
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m) => ((a % m) + m) % m;
const puissance = (b, e, m) => {
  let r = 1n;
  b = mod(b, m);
  for (; e > 0n; e >>= 1n, b = (b * b) % m) if (e & 1n) r = (r * b) % m;
  return r;
};
const inverse = (a, m) => puissance(a, m - 2n, m);
function ajouter(p, q) {
  if (p === null) return q;
  if (q === null) return p;
  if (p[0] === q[0] && mod(p[1] + q[1], P) === 0n) return null;
  const l = p[0] === q[0] ? mod(3n * p[0] * p[0] * inverse(2n * p[1], P), P) : mod((q[1] - p[1]) * inverse(q[0] - p[0], P), P);
  const x = mod(l * l - p[0] - q[0], P);
  return [x, mod(l * (p[0] - x) - p[1], P)];
}
function multiplier(k, p) {
  let r = null;
  for (let q = p; k > 0n; k >>= 1n, q = ajouter(q, q)) if (k & 1n) r = ajouter(r, q);
  return r;
}
/** Adresse recouvrée de (r, s, v) sur le condensé `m`, sans exiger s bas ; v ∈ {0, 1, 27, 28}. */
function recouvrer(m, sig) {
  const r = BigInt("0x" + sig.slice(2, 66));
  const s = BigInt("0x" + sig.slice(66, 130));
  const v = parseInt(sig.slice(130, 132), 16) % 27;
  const y0 = puissance(r * r * r + 7n, (P + 1n) / 4n, P);
  const R = [r, (y0 & 1n) === BigInt(v) ? y0 : P - y0];
  const e = BigInt(m);
  const Q = multiplier(inverse(r, N), ajouter(multiplier(s, R), multiplier(mod(-e, N), G)));
  const pub = Buffer.concat([Buffer.from(Q[0].toString(16).padStart(64, "0"), "hex"), Buffer.from(Q[1].toString(16).padStart(64, "0"), "hex")]);
  return "0x" + keccak256(pub).slice(26);
}

// ---------------------------------------------------------------------------
describe("CT-3 : schémas et exemples de la spécification", function () {
  it("chaque exemple JSON annoté <!-- schema: … --> de CT-3 est conforme à son schéma ou à son $defs", function () {
    const exemples = [...MD.matchAll(/<!-- schema: ([a-z-]+)(?:\/([a-z_]+))? -->\n```json\n([\s\S]*?)\n```/g)];
    expect(exemples.length).to.be.at.least(3);
    for (const [, nom, def, texte] of exemples) {
      const valeur = JSON.parse(texte);
      const erreurs = nom === "politique-approbation" ? A.erreursSchema(valeur, SCHEMAS) : A.erreursSchema(valeur, SCHEMAS, def);
      expect(nom === "politique-approbation" || nom === "ticket", nom).to.equal(true);
      expect(erreurs, `${nom}/${def ?? ""}`).to.deep.equal([]);
    }
  });

  it("4.3 : l'exemple complet est politiques/assureur.json, valide en production (EX-4.2)", function () {
    const exemple = JSON.parse(/<!-- schema: politique-approbation -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
    expect(exemple).to.deep.equal(lire("politiques", "assureur.json"));
    expect(exemple).to.deep.equal(POLITIQUE_ASSUREUR);
    expect(A.erreursPolitique(exemple, { schemas: SCHEMAS, environment: "production", expire_after_ms: E })).to.deep.equal([]);
  });

  it("6.7 : chaque ligne de la table est l'attendu du cas correspondant de evaluation/assureur.json", function () {
    const section = MD.split("### 6.7 Cas limites")[1].split("### 6.8")[0];
    const lignes = section.split("\n").filter((l) => l.startsWith("| `") || l.startsWith("| idem") || l.startsWith("| `amount`"));
    const ids = ["lecture-inconditionnelle", "paiement-7400", "beneficiaire-hors-liste", "paiement-800", "paiement-2500-sans-fenetre", "paiement-2500-fenetre-ouverte", "paiement-2500-autre-beneficiaire", "paiement-5000-borne", "paiement-5000-dix-huit-decimales", "paiement-nombre-entier", "paiement-nombre-non-entier", "paiement-hors-grammaire", "paiement-montant-absent", "paiement-devise-absente", "paiement-devise-minuscules", "paiement-iban-absent-fenetre", ["paiement-zero", "paiement-moins-zero"], "courriel-assure", ["courriel-garage", "courriel-sans-role"], "outil-sans-regle", "outil-casse", "suppression"];
    expect(lignes.length).to.equal(ids.length);
    const cas = Object.fromEntries(lire("evaluation", "assureur.json").cases.map((c) => [c.id, c]));
    lignes.forEach((l, i) => {
      const cellules = l.split(" | ");
      const decision = cellules.at(-2).replace(/`/g, "").trim();
      const rule = cellules.at(-1).replace(/`/g, "").replace(/\|$/, "").trim();
      for (const id of [ids[i]].flat()) {
        expect(cas[id].expected.decision, `${id} (ligne ${i + 1})`).to.equal(decision);
        expect(cas[id].expected.rule, `${id} (ligne ${i + 1})`).to.equal(rule);
      }
    });
  });

  it("4.12 : la liste de l'exemple est celle de candidats/assureur.json", function () {
    const texte = /la liste est ((?:`[^`]+`(?:,\s*)?)+)\./.exec(MD)[1];
    const attendus = [...texte.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    expect(lire("candidats", "assureur.json").cases.find((c) => c.id === "exemple-4-12").approval_candidates).to.deep.equal(attendus);
  });

  it("A.2 et 8.4 : constantes, comptes et source d'exemple recalculés", function () {
    const sha = (s) => J.sha256(Buffer.from(s, "utf8"));
    expect(CONSTANTES.organization.org_id).to.equal(keccak256(toUtf8Bytes("assureur-demo")));
    expect(CONSTANTES.journal.journal_id).to.equal(keccak256(toUtf8Bytes("journal-approbations")));
    expect(MD).to.include(CONSTANTES.organization.org_id).and.to.include(CONSTANTES.journal.journal_id);
    expect(CONSTANTES.registry).to.equal(sha("noortrace/vecteurs/ct3/registre").slice(0, 42));
    expect(CONSTANTES.sets["1"]).to.equal(sha("noortrace/vecteurs/ct3/jeu/1").slice(0, 42));
    for (const c of CONSTANTES.accounts) {
      expect(HDNodeWallet.fromPhrase(CONSTANTES.mnemonic, undefined, c.derivation_path).address.toLowerCase()).to.equal(c.address);
      expect(MD, `compte ${c.index}`).to.include(c.address);
    }
    const exemple = /```text\n(CuratorSet c=2124 [^\n]+)\n```/.exec(MD)[1];
    const jeu = { chain_id: 2124, registry: CONSTANTES.registry, set: CONSTANTES.sets["1"], height: 1200, block_hash: sha("noortrace/vecteurs/ct3/bloc/1200"), threshold: { required: 2, size: 3 }, members: [] };
    expect(A.sourceJeu(jeu, { hauteurConfirmation: 1214, blocConfirmation: sha("noortrace/vecteurs/ct3/bloc/1214") })).to.equal(exemple);
    expect(exemple).to.match(A.RE_SOURCE_REGISTRE);
  });

  it("12.5 : la remise d'exemple est decisions/valides/ct1-apr-2201.json ; avec at, l'approval de CT-1 seq 6 clé pour clé (EX-A.8)", function () {
    const exemple = JSON.parse(/<!-- schema: ticket\/remise -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
    const cas = lire("decisions", "valides", "ct1-apr-2201.json");
    expect(cas.remise).to.deep.equal(exemple);
    const seq6 = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-1", "journal-valide", "evenements.json"), "utf8")).find((e) => e.seq === 6);
    const scelle = A.approvalScelle(exemple.approval, seq6.approval.at);
    expect(JSON.stringify(scelle)).to.equal(JSON.stringify(seq6.approval));
    expect(A.verifierRemise(exemple, cas.context, { schemas: SCHEMAS }).result).to.equal("scelle");
  });

  it("A.4 : l'exemple d'attendu des politiques invalides est un cas de politiques-invalides/attendu.json", function () {
    const exemple = JSON.parse(/<!-- schema: ticket\/attendu_politiques_invalides -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
    const attendu = lire("politiques-invalides", "attendu.json");
    for (const c of exemple.cases) expect(attendu.cases.find((x) => x.file === c.file)).to.deep.equal(c);
  });

  it("EX-9.7 : la mesure de la spécification sur D_A de CT-1 §6.4 (condensés EIP-191 des octets et de la chaîne « 0x… »)", function () {
    const Aex = { decision: "approuve", journal_id: "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b", org_id: ORG_ID, request_hash: "0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0", ticket: "apr-1192" };
    const D = J.condenseApprobation(Aex);
    const octets = hashMessage(getBytes(D));
    const chaine = hashMessage(D);
    expect(octets).to.equal(J.condenseEIP191Approbation(Aex));
    const [o1, o2, c1, c2] = /donne `(0x[0-9a-f]+)…([0-9a-f]+)` en octets et `(0x[0-9a-f]+)…([0-9a-f]+)`/.exec(MD).slice(1, 5);
    expect(octets.startsWith(o1) && octets.endsWith(o2), octets).to.equal(true);
    expect(chaine.startsWith(c1) && chaine.endsWith(c2), chaine).to.equal(true);
  });

  it("EX-11.8 : le résultat d'un refus sans ticket est exactement le texte de la spécification, _meta serverInfo compris (CT-2 EX-4.4)", function () {
    const attendu = /l'ère moderne, `([^`]+)`/.exec(MD)[1];
    const refus = { rule: "x", decision: "refuse", ticket: null, ticket_state: null, approval: null, approver_set: null };
    const r = A.actionMandataire(refus);
    expect(JSON.stringify(r.result)).to.equal(attendu);
    expect(JSON.parse(attendu)._meta["io.modelcontextprotocol/serverInfo"]).to.deep.equal(C.IDENTITE_ENREGISTREUR);
    const herite = A.actionMandataire(refus, { hoteModerne: false });
    const { resultType, ...sansResultType } = JSON.parse(attendu);
    expect(resultType).to.equal("complete");
    expect(JSON.stringify(herite.result)).to.equal(JSON.stringify(sansResultType));
    expect(A.actionMandataire(refus, { recorder: "0.2.0" }).result._meta["io.modelcontextprotocol/serverInfo"]).to.deep.equal({ name: "noortrace-enregistreur", version: "0.2.0" });
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : validation de la politique (EX-4.2, EX-8.2, AP-1 à AP-4)", function () {
  it("politiques-invalides : chaque document donne exactement la liste complète attendue, triée", function () {
    const attendu = lire("politiques-invalides", "attendu.json");
    expect(A.erreursSchema(attendu, SCHEMAS, "attendu_politiques_invalides")).to.deep.equal([]);
    expect(fichiers("politiques-invalides").filter((f) => f !== "attendu.json")).to.deep.equal(attendu.cases.map((c) => c.file).sort());
    for (const c of attendu.cases) {
      const r = A.erreursPolitique(lire("politiques-invalides", c.file), { schemas: SCHEMAS, environment: c.environment, expire_after_ms: c.expire_after_ms });
      expect(r, c.file).to.deep.equal(c.errors);
      const tries = [...r].sort((a, b) => avant(a.pointer ?? "", b.pointer ?? "") || avant(a.code, b.code));
      expect(r.map((e) => e.pointer)).to.deep.equal(tries.map((e) => e.pointer));
      // EX-4.2 : une non-conformité au schéma donne exactement l'entrée schema, et rien d'autre.
      if (r.some((e) => e.code === "schema")) expect(r.map((e) => e.code), c.file).to.deep.equal(["schema"]);
    }
    // Pointeurs d'indice à deux chiffres : /rules/10/name avant /rules/2/name (ordre des unités UTF-16).
    expect(attendu.cases.find((c) => c.file === "ordre-des-pointeurs.json").errors.map((e) => e.pointer)).to.deep.equal(["/rules/10/name", "/rules/2/name"]);
    for (const id of ["AP-1", "AP-2", "AP-3", "AP-4"]) expect(attendu.cases.some((c) => c.checks.includes(id)), id).to.equal(true);
    for (const code of A.CODES_ERREUR_POLITIQUE) expect(attendu.cases.some((c) => c.errors.some((e) => e.code === code)), code).to.equal(true);
  });

  it("politiques/ : chaque politique valide passe, schéma et règles d'EX-4.2 ; substitut isolé lu tel quel", function () {
    for (const f of fichiers("politiques")) expect(A.erreursPolitique(lire("politiques", f), { schemas: SCHEMAS, environment: "developpement", expire_after_ms: E }), f).to.deep.equal([]);
    const texte = fs.readFileSync(path.join(CT3, "politiques-invalides", "substitut-isole.json"), "utf8");
    expect(texte).to.include("\\ud800");
    expect(() => J.analyserJSONStrict(texte)).to.throw();
  });

  it("bornes d'EX-4.2 : 32 jetons, 8 niveaux, 64 prédicats, contest_ms = E − 1 admis ; un de plus refusé", function () {
    const ok = lire("politiques", "bornes.json");
    expect(A.erreursPolitique(ok, { schemas: SCHEMAS, environment: "developpement", expire_after_ms: 3600000 })).to.deep.equal([]);
    expect(A.erreursPolitique(ok, { schemas: SCHEMAS, environment: "developpement", expire_after_ms: 3599999 }).map((e) => e.code)).to.deep.equal(["contest_ms_trop_long", "contest_ms_trop_long"]);
    expect(A.jetonsPointeur(ok.rules[0].when.path)).to.have.length(32);
    expect(A.profondeurCondition(ok.rules[1].when)).to.equal(8);
    expect(A.predicatsCondition(ok.rules[2].when)).to.have.length(64);
  });

  it("EX-4.2 : un document refusé n'est jamais appliqué ; charger rend politique_invalide avec toutes les erreurs (EX-12.5)", function () {
    const s = new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, parametres: { expire_after_ms: E, approver_set: POLITIQUE_ASSUREUR.approver_set, separation: POLITIQUE_ASSUREUR.separation }, schemas: SCHEMAS });
    const doc = lire("politiques-invalides", "erreurs-multiples.json");
    const r = s.traiter({ kind: "charger", at: T("08:00:00.000"), data: { policy_version: "v-invalide", environment: "production", approval: { rules: doc, mode: "erreur", hold_timeout_ms: 50000, expire_after_ms: E, timeout_ms: 2000 }, tools: [] } });
    expect(r.accepted).to.equal(false);
    expect(r.reason).to.equal("politique_invalide");
    expect(r.errors).to.have.length(5);
    expect(s.version("v-invalide")).to.equal(undefined);
    expect(s.vigueur).to.equal(V1);
    const ok = s.traiter({ kind: "charger", at: T("08:00:01.000"), data: { policy_version: "v-ok", environment: "production", policy_sha256: "0x" + "ab".repeat(32), approval: { rules: POLITIQUE_ASSUREUR, mode: "erreur", hold_timeout_ms: 50000, expire_after_ms: E, timeout_ms: 2000 }, tools: ["crm.claims.delete", "crm.claims.get", "documents.search", "mail.send", "sap.payments.create", "sap.payments.list"].map((t) => ({ tool_announced: t })) } });
    expect(ok.response).to.deep.equal({ policy_version: "v-ok", policy_sha256: "0x" + "ab".repeat(32), approval_candidates: ["crm.claims.delete", "mail.send", "sap.payments.create", "sap.payments.list"] });
  });

  it("EX-4.14 : avertissements sans refus (sélecteur sans outil, pointeur rédigé, fenêtre large, liste d'exclusion, demandeur sans identité)", function () {
    const av = A.avertissementsPolitique(POLITIQUE_ASSUREUR, { outils: ["crm.claims.get", "sap.payments.create"], cheminsRediges: ["/arguments/beneficiary_iban"], demandeurs: ["u.martin@assureur-demo.example", "agent-nuit"] });
    expect(av.some((x) => x.includes("documents.search"))).to.equal(true);
    expect(av.some((x) => x.includes("/arguments/beneficiary_iban"))).to.equal(true);
    expect(av.filter((x) => x.startsWith("/separation/identities"))).to.deep.equal(["/separation/identities : aucune entrée pour le demandeur agent-nuit ; la séparation des tâches n'est pas vérifiable pour lui (EX-10.5)"]);
    expect(A.erreursPolitique(POLITIQUE_ASSUREUR, { schemas: SCHEMAS, environment: "developpement", expire_after_ms: E })).to.deep.equal([]);
    // Fenêtre à plusieurs outils, sans same_arguments ni condition ; refus automatique par liste d'exclusion.
    const fenetre = regle("large", ["pay__*"], null, "fenetre", null, { contest_ms: 0, window: { duration_ms: 60000, max_calls: 2, same_arguments: [] } });
    const exclusion = regle("exclusion", ["pay__virement"], { path: "/arguments/iban", op: "dans", value: ["CH00"] });
    const P = politique([fenetre, exclusion]);
    expect(A.erreursPolitique(P, { schemas: SCHEMAS, environment: "developpement", expire_after_ms: E })).to.deep.equal([]);
    const av2 = A.avertissementsPolitique(P);
    for (const debut of ["/rules/0/tools : règle fenetre à plusieurs outils", "/rules/0/window/same_arguments : vide", "/rules/0/when : nulle", "/rules/1/when : liste d'exclusion (dans)"]) expect(av2.some((x) => x.startsWith(debut)), debut).to.equal(true);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : évaluation (sections 4 à 6, AP-5 à AP-17)", function () {
  const fichiersEvaluation = fichiers("evaluation");

  it("evaluation/ : chaque cas rend exactement rule, decision, opening et l'état des fenêtres attendus", function () {
    let n = 0;
    for (const f of fichiersEvaluation) {
      const doc = lire("evaluation", f);
      expect(A.erreursSchema(doc, SCHEMAS, "fichier_evaluation"), f).to.deep.equal([]);
      const P = lire(doc.policy);
      for (const c of doc.cases) {
        const r = A.evaluer(P, c.request, { fenetres: c.windows, t: c.t, policy_version: doc.policy_version });
        expect({ rule: r.rule, decision: r.decision, contest_ms: r.contest_ms, opening: r.opening, windows: r.fenetres }, `${f}/${c.id}`).to.deep.equal(c.expected);
        n += 1;
      }
    }
    expect(n).to.be.at.least(150);
  });

  it("chaque vérification AP-5 à AP-17 a au moins un cas", function () {
    const vues = new Set();
    for (const f of fichiersEvaluation) for (const c of lire("evaluation", f).cases) c.checks.forEach((x) => vues.add(x));
    for (const f of fichiers("candidats")) for (const c of lire("candidats", f).cases) c.checks.forEach((x) => vues.add(x));
    for (let i = 5; i <= 17; i++) expect(vues.has(`AP-${i}`), `AP-${i}`).to.equal(true);
  });

  it("EX-4.4 : pointeurs RFC 6901 (exemples de la RFC, ~01, indices, -, zéro de tête, neuf chiffres)", function () {
    const R = { arguments: { foo: ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3, "g|h": 4, "i\\j": 5, 'k"l': 6, " ": 7, "m~n": 8, "~1": 9, t: Array.from({ length: 12 }, (_, i) => i) } };
    const v = (p) => A.resoudre(R, p);
    expect(v("/arguments/foo")).to.deep.equal({ resolu: true, valeur: ["bar", "baz"] });
    expect(v("/arguments/foo/0").valeur).to.equal("bar");
    for (const [p, x] of [["/arguments/", 0], ["/arguments/a~1b", 1], ["/arguments/c%d", 2], ["/arguments/e^f", 3], ["/arguments/g|h", 4], ["/arguments/i\\j", 5], ['/arguments/k"l', 6], ["/arguments/ ", 7], ["/arguments/m~0n", 8], ["/arguments/~01", 9], ["/arguments/t/11", 11]]) expect(v(p), p).to.deep.equal({ resolu: true, valeur: x });
    for (const p of ["/arguments/foo/-", "/arguments/foo/01", "/arguments/foo/2", "/arguments/t/000000011", "/arguments/foo/0/x", "/arguments/absent", "/arguments/t/1234567890"]) expect(v(p).resolu, p).to.equal(false);
    expect(A.resoudre({ arguments: { n: null } }, "/arguments/n")).to.deep.equal({ resolu: true, valeur: null });
  });

  it("EX-4.5, EX-4.6 : nombres exacts en entiers de précision arbitraire, sans flottant", function () {
    const num = (x) => A.valeurNumerique(x);
    expect(num("5000.00")).to.deep.equal({ m: 500000n, e: 2 });
    expect(num("-0.000000000000000001")).to.deep.equal({ m: -1n, e: 18 });
    expect(num(9007199254740991)).to.deep.equal({ m: 9007199254740991n, e: 0 });
    for (const x of [9007199254740992, -9007199254740992, 0.5, 7400.5, "1e3", "0x10", "", " 1", "+1", "01", ".5", "5.", "1,0", "1".repeat(31), "0." + "0".repeat(18) + "1", true, null, {}, []]) expect(num(x), JSON.stringify(x)).to.equal(null);
    const cmp = (a, b) => A.comparerNumeriques(num(a), num(b));
    expect(cmp("5000", "5000.00")).to.equal(0);
    expect(cmp(5000, "5000.000")).to.equal(0);
    expect(cmp("-0", "0.00")).to.equal(0);
    expect(cmp("10.00", "9.00")).to.equal(1);
    expect(cmp("5000.000000000000000001", "5000")).to.equal(1);
    expect(cmp("-1.5", "-1.49")).to.equal(-1);
    expect(cmp("999999999999999999999999999999.999999999999999999", "999999999999999999999999999999.999999999999999998")).to.equal(1);
    expect(0.1 + 0.2 === 0.3).to.equal(false); // le motif de 4.7
    expect(cmp("0.3", "0.30")).to.equal(0);
  });

  it("EX-4.8 : tables de Kleene de all, any, none, exhaustives et indépendantes de l'ordre", function () {
    const V = [A.VRAI, A.FAUX, A.INDETERMINE];
    const rang = { [A.FAUX]: 0, [A.INDETERMINE]: 1, [A.VRAI]: 2 };
    const deRang = [A.FAUX, A.INDETERMINE, A.VRAI];
    for (const a of V) for (const b of V) for (const c of V) {
      const xs = [a, b, c];
      const et = deRang[Math.min(...xs.map((x) => rang[x]))];
      const ou = deRang[Math.max(...xs.map((x) => rang[x]))];
      const non = { [A.VRAI]: A.FAUX, [A.FAUX]: A.VRAI, [A.INDETERMINE]: A.INDETERMINE };
      for (const perm of [[a, b, c], [c, b, a], [b, c, a]]) {
        expect(A.combiner("all", perm)).to.equal(et);
        expect(A.combiner("any", perm)).to.equal(ou);
        expect(A.combiner("none", perm)).to.equal(non[ou]);
      }
    }
  });

  it("EX-4.3 : sélecteurs — nom exact, casse, préfixe p*, * seul, aucun autre joker", function () {
    expect(A.selectionne(["sap__payments.create"], "sap__payments.create")).to.equal(true);
    expect(A.selectionne(["sap__payments.create"], "SAP__payments.create")).to.equal(false);
    expect(A.selectionne(["sap__*"], "sap__payments.list")).to.equal(true);
    expect(A.selectionne(["sap__*"], "sapx__payments.list")).to.equal(false);
    expect(A.selectionne(["*"], "n'importe")).to.equal(true);
    const schema = (tools) => A.erreursSchema(politique([regle("r", tools, null, "automatique", "autorise")]), SCHEMAS).length > 0;
    expect(schema(["sap*create"])).to.equal(true);
    expect(schema(["sap?"])).to.equal(true);
    expect(schema(["sap__*"])).to.equal(false);
  });

  it("EX-4.9, AP-12 : à rang égal, l'ordre des règles désigne la règle retenue (nom, contest_ms, fenêtre), jamais la décision", function () {
    const a = lire("evaluation", "ordre.json").cases;
    const b = lire("evaluation", "ordre-inverse.json").cases;
    expect(a.map((c) => c.id)).to.deep.equal(b.map((c) => c.id));
    a.forEach((c, i) => {
      expect(c.request, c.id).to.deep.equal(b[i].request);
      expect(c.expected.decision, c.id).to.equal(b[i].expected.decision);
      expect(c.expected.rule, c.id).to.not.equal(b[i].expected.rule);
    });
    const revue = (cs) => cs.find((c) => c.id === "revue-meme-rang").expected.contest_ms;
    expect([revue(a), revue(b)]).to.deep.equal([0, 900000]);
  });

  it("EX-4.9, EX-6.6, AP-17 : la décision ne dépend ni de l'ordre des membres, ni des membres hors évaluation (EX-3.5)", function () {
    for (const f of fichiersEvaluation) {
      const doc = lire("evaluation", f);
      const P = lire(doc.policy);
      const Pinverse = JSON.parse(JSON.stringify(P, (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).reverse()) : v)));
      for (const c of doc.cases) {
        const d = { ...c.request, arguments: JSON.parse(JSON.stringify(c.request.arguments, (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).reverse()) : v))), intent: "autre intention", context: [], class: "lecture", tool_original: "x", delegation: { ...c.request.delegation, run_id: "autre-run", on_behalf_of: "autre" } };
        const r = A.evaluer(Pinverse, d, { fenetres: c.windows, t: c.t, policy_version: doc.policy_version });
        expect({ rule: r.rule, decision: r.decision }, `${f}/${c.id}`).to.deep.equal({ rule: c.expected.rule, decision: c.expected.decision });
      }
    }
  });

  it("EX-6.5 : l'évaluation n'a d'effet que sur la copie des fenêtres qu'elle rend", function () {
    const doc = lire("evaluation", "niveaux.json");
    const c = doc.cases.find((x) => x.id === "fenetre-couverte");
    const avant = JSON.stringify(c.windows);
    const gele = (o) => (o && typeof o === "object" ? Object.freeze(Object.values(o).forEach(gele) ?? o) : o);
    const P = gele(lire(doc.policy));
    const r = A.evaluer(P, gele(JSON.parse(JSON.stringify(c.request))), { fenetres: gele(JSON.parse(avant)), t: c.t, policy_version: V1 });
    expect(r.fenetres[0].remaining).to.equal(c.windows[0].remaining - 1);
    expect(JSON.stringify(c.windows)).to.equal(avant);
  });

  it("EX-6.4 : forme de policy.rule — nom, marque [indetermine], marque [fenetre <ticket> <fin>], longueur", function () {
    for (const f of fichiersEvaluation) for (const c of lire("evaluation", f).cases) {
      const r = c.expected.rule;
      expect(r.length).to.be.at.most(1024);
      const i = r.lastIndexOf(" [");
      if (i === -1) continue;
      expect(r.slice(i), `${f}/${c.id}`).to.match(/^ \[(indetermine|fenetre apr-[0-9a-z]+(-[0-9a-z]+)* [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z)\]$/);
    }
  });

  it("EX-5.8 : seules les valeurs de CT-1 ; contest_ms et opening ne valent que pour a_approuver ; INDETERMINE n'ouvre jamais (EX-6.3)", function () {
    for (const f of fichiersEvaluation) {
      const doc = lire("evaluation", f);
      const P = lire(doc.policy);
      for (const c of doc.cases) {
        const r = A.evaluer(P, c.request, { fenetres: c.windows, t: c.t, policy_version: doc.policy_version });
        expect(["autorise", "a_approuver", "refuse"]).to.include(r.decision);
        if (r.decision !== "a_approuver") expect([r.contest_ms, r.opening], `${f}/${c.id}`).to.deep.equal([null, null]);
        else expect(Number.isInteger(r.contest_ms), `${f}/${c.id}`).to.equal(true);
        if (r.rule.endsWith(" [indetermine]")) expect(r.opening).to.equal(null);
      }
    }
  });

  it("EX-4.13, EX-6.7 : évaluation linéaire, sans expression régulière — une chaîne d'un million de caractères", function () {
    const P = politique([regle("prefixe", ["t"], { all: [{ path: "/arguments/s", op: "commence_par", value: "a".repeat(1024) }, { path: "/arguments/s", op: "finit_par", value: "a".repeat(1023) + "b" }] })]);
    const debut = process.hrtime.bigint();
    const r = A.evaluer(P, demande("t", { s: "a".repeat(1_000_000) }), { t: T("10:00:00.000") });
    expect(r.decision).to.equal("a_approuver");
    expect(Number(process.hrtime.bigint() - debut) / 1e6).to.be.below(2000);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : outils susceptibles d'approbation (EX-4.11, AP-16)", function () {
  it("candidats/ : CANDIDATS(P, L) rend la liste attendue", function () {
    for (const f of fichiers("candidats")) {
      const doc = lire("candidats", f);
      expect(A.erreursSchema(doc, SCHEMAS, "fichier_candidats"), f).to.deep.equal([]);
      for (const c of doc.cases) expect(A.candidats(lire(doc.policy), c.tools), `${f}/${c.id}`).to.deep.equal(c.approval_candidates);
    }
  });

  it("sur-ensemble sûr : tout outil qu'un cas d'évaluation retient ou refuse est candidat", function () {
    for (const f of fichiers("evaluation")) {
      const doc = lire("evaluation", f);
      const P = lire(doc.policy);
      for (const c of doc.cases) if (c.expected.decision !== "autorise" || c.expected.rule.includes(" [fenetre ")) expect(A.candidats(P, [c.request.tool_announced]), `${f}/${c.id}`).to.deep.equal([c.request.tool_announced]);
    }
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : épreuve d'acceptation (annexe A.5, EX-A.4, EX-A.5)", function () {
  const attendu = lire("acceptation-attendu.json");

  it("le répertoire remis aux relecteurs ne contient aucun attendu ; l'attendu est à part et conforme", function () {
    const contenu = fs.readdirSync(path.join(CT3, "acceptation"), { recursive: true }).map(String).sort();
    expect(contenu).to.deep.equal(["cas", ...Array.from({ length: 10 }, (_, i) => `cas/cas-${String(i + 1).padStart(2, "0")}.json`), "consigne.md", "gabarit-reponse.json", "politique.json"].sort());
    for (const f of fichiers("acceptation", "cas")) expect(Object.keys(lire("acceptation", "cas", f))).to.deep.equal(["id", "request"]);
    const gabarit = lire("acceptation", "gabarit-reponse.json");
    expect(Object.keys(gabarit)).to.deep.equal(["role", "reviewer", "answers"]);
    expect(gabarit.answers.every((a) => a.decision === null)).to.equal(true);
    expect(A.erreursSchema(attendu, SCHEMAS, "attendu_acceptation")).to.deep.equal([]);
    const consigne = fs.readFileSync(path.join(CT3, "acceptation", "consigne.md"), "utf8");
    for (const m of ["seul", "approbateur", "auditeur", "developpeur", "n'exécutent aucun code", "égales entre elles"]) expect(consigne).to.include(m);
  });

  it("l'implémentation de référence rend les dix décisions attendues ; EX-A.4 est respectée", function () {
    const P = lire("acceptation", "politique.json");
    expect(A.erreursPolitique(P, { schemas: SCHEMAS, environment: "developpement", expire_after_ms: E })).to.deep.equal([]);
    const reponses = fichiers("acceptation", "cas").map((f) => {
      const c = lire("acceptation", "cas", f);
      const r = A.evaluer(P, c.request, { fenetres: [], t: CONSTANTES.base_instant });
      return { id: c.id, rule: r.rule, decision: r.decision, c };
    });
    expect(reponses.map(({ id, rule, decision }) => ({ id, rule, decision }))).to.deep.equal(attendu.expected);
    for (const d of ["autorise", "a_approuver", "refuse"]) expect(reponses.filter((r) => r.decision === d).length, d).to.be.at.least(2);
    const outils = new Set(P.rules.flatMap((r) => r.tools));
    expect(reponses.some((r) => !outils.has(r.c.request.tool_announced)), "autre outil").to.equal(true);
    expect(reponses.some((r) => !Object.hasOwn(r.c.request.arguments, "currency") || !Object.hasOwn(r.c.request.arguments, "amount")), "argument absent").to.equal(true);
    expect(reponses.some((r) => typeof r.c.request.arguments.currency === "number" || (typeof r.c.request.arguments.amount === "number" && !Number.isInteger(r.c.request.arguments.amount))), "autre type").to.equal(true);
    expect(reponses.some((r) => r.c.request.arguments.amount === "1000"), "égalité à la borne").to.equal(true);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : tickets (section 7, TK-1 à TK-13)", function () {
  this.timeout(120_000);
  const noms = fichiers("tickets");
  const traces = Object.fromEntries(noms.map((f) => [f, lire("tickets", f)]));

  it("les traces de l'annexe A.7 sont présentes, conformes à $defs/trace, et TK-1 à TK-13 sont tous visés", function () {
    const requises = ["approuve-sans-contestation", "refuse-seuil", "expire-sans-vote", "vote-remplace", "contestation-sans-objection", "contestation-objection-levee", "contestation-objection-maintenue", "contestation-refus-anterieur", "contestation-apres-echeance", "separation-auto-approbation", "separation-auto-permise", "seuil-inatteignable", "recusation", "jeu-change-membre-retire", "jeu-reassigne", "jeu-illisible", "jeu-statique", "signature-hors-jeu", "reemission-en-attente", "retrait", "acquittement-temporaire", "deja-decide", "reservation-abandonnee", "plafond", "fenetre-ouvrante", "fenetre-politique-changee", "politique-changee", "jeu-change-pendant-contestation", "recusation-refus-maintenu", "jeu-seuil-abaisse", "ordre-des-raisons-de-vote", "retrait-administrateur", "deja-decide-autre-demande", "acquittements-noyau", "expiration-noyau", "retenir-double-reemission"];
    expect(noms).to.include.members(requises.map((n) => `${n}.json`));
    const vues = new Set();
    for (const [f, t] of Object.entries(traces)) {
      expect(A.erreursSchema(t, SCHEMAS, "trace"), f).to.deep.equal([]);
      expect(`${t.id}.json`).to.equal(f);
      t.checks.forEach((x) => vues.add(x));
    }
    for (let i = 1; i <= 13; i++) expect(vues.has(`TK-${i}`), `TK-${i}`).to.equal(true);
  });

  it("chaque trace rejouée sur un service vide redonne chaque attendu, pas à pas (EX-7.9, EX-A.6)", function () {
    for (const [f, t] of Object.entries(traces)) {
      const { pas } = A.rejouerTrace(t, { schemas: SCHEMAS });
      pas.forEach((r, i) => expect(r, `${f}, pas ${i + 1}`).to.deep.equal(t.steps[i].expected));
    }
  });

  it("TK-12 (EX-7.22, EX-7.23) : reprise depuis l'état persisté après chaque pas, documents ticket-v0 conformes et rejouables", function () {
    const CLES_ETAT = ["org_id", "journal_id", "environment", "parametres", "service", "versions", "vigueur", "compteur", "epoque", "fenetres", "repli", "dernier", "tickets"];
    for (const [f, t] of Object.entries(traces)) {
      for (let k = 0; k < t.steps.length; k++) {
        const { service } = A.rejouerTrace({ ...t, steps: t.steps.slice(0, k + 1) }, { schemas: SCHEMAS });
        const etat = JSON.parse(JSON.stringify(service.instantane()));
        // Rien d'autre que les documents ticket-v0, les fenêtres et la configuration : aucun état interne caché.
        expect(Object.keys(etat), f).to.deep.equal(CLES_ETAT);
        for (const w of etat.fenetres) expect(A.erreursSchema(w, SCHEMAS, "fenetre_ouverte"), f).to.deep.equal([]);
        for (const doc of etat.tickets) {
          expect(J.validerSchema(doc, SCHEMAS[A.ID_SCHEMA_TICKET], { registre: SCHEMAS }), `${f} pas ${k + 1} ${doc.ticket}`).to.deep.equal([]);
          expect(A.ecartsTransitions(doc), `${f} pas ${k + 1} ${doc.ticket}`).to.deep.equal([]);
        }
        const repris = A.ServiceApprobation.restaurer(etat, { schemas: SCHEMAS });
        for (let i = k + 1; i < t.steps.length; i++) expect(repris.traiter(t.steps[i].input), `${f} reprise après le pas ${k + 1}, pas ${i + 1}`).to.deep.include(t.steps[i].expected);
      }
    }
  });

  it("TK-1, EX-7.1, EX-7.2 : identifiants conformes, uniques, attribués dans l'ordre des réservations ; époque après une perte d'état", function () {
    for (const [f, t] of Object.entries(traces)) {
      const ids = Object.keys(t.steps.at(-1).expected.tickets);
      ids.forEach((id, i) => {
        expect(id, f).to.match(A.RE_IDENTIFIANT_TICKET);
        expect(id).to.equal(`apr-${String(i + 1).padStart(4, "0")}`);
      });
    }
    // Un service reconstruit sans son état reçoit une autre époque : ses identifiants ne reprennent pas ceux d'avant (EX-7.1).
    const s = new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, epoque: "k7", parametres: { expire_after_ms: E, approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [ADR(1), ADR(2), ADR(3)], threshold: { required: 2, size: 3 } }, separation: { self_approval: "interdite", identities: [] } } });
    const r = s.traiter({ kind: "evaluer", at: T("09:00:00.000"), data: { request: demande("t", {}), evaluation: { rule: "r", decision: "a_approuver", contest_ms: 0, opening: null } } });
    expect(r.response.ticket).to.equal("apr-k7-0001");
    expect(r.response.ticket).to.match(A.RE_IDENTIFIANT_TICKET);
    expect(() => new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, epoque: "K-7", parametres: { expire_after_ms: E, approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [ADR(1)], threshold: { required: 1, size: 1 } }, separation: { self_approval: "interdite", identities: [] } } })).to.throw();
  });

  it("EX-12.6 : chaque réponse à evaluer est l'une des sept combinaisons d'EX-7.16 ; EX-3.1 : autorise lié à un ticket seulement après scellement approuve", function () {
    const vues = new Set();
    for (const [f, t] of Object.entries(traces)) {
      const scelles = new Set();
      t.steps.forEach((s, i) => {
        const r = s.expected.response;
        if (["acquitter", "expiration"].includes(s.input.kind) && s.expected.tickets[s.input.data.ticket] === "approuve") scelles.add(s.input.data.ticket);
        if (s.input.kind !== "evaluer" || r === null) return;
        expect(A.combinaisonAdmise(r), `${f} pas ${i + 1} : ${JSON.stringify(r)}`).to.equal(true);
        expect(Object.keys(r)).to.deep.equal(["rule", "decision", "ticket", "ticket_state", "approval", "approver_set"]);
        vues.add(`${r.decision}/${r.ticket_state}`);
        if (r.ticket_state === "nouveau") expect(A.erreursSchema(r.approver_set, SCHEMAS, "approver_set"), `${f} pas ${i + 1}`).to.deep.equal([]);
        if (r.ticket !== null && r.decision === "autorise") expect(scelles.has(r.ticket), `${f} pas ${i + 1}`).to.equal(true);
      });
    }
    expect([...vues].sort()).to.deep.equal(["a_approuver/en_attente", "a_approuver/nouveau", "autorise/approuve", "autorise/null", "refuse/expire", "refuse/null", "refuse/refuse"]);
    // Toute autre forme est refusée.
    const ok = { rule: "r", decision: "a_approuver", ticket: "apr-0001", ticket_state: "en_attente", approval: null, approver_set: null };
    expect(A.combinaisonAdmise(ok)).to.equal(true);
    for (const mauvaise of [{ ...ok, ticket_state: "nouveau" }, { ...ok, decision: "autorise" }, { ...ok, approval: { decision: "approuve", ticket: "apr-0001" } }, { ...ok, ticket: "APR-1" }, { rule: "r", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null }, { rule: "r", decision: "autorise", ticket: "apr-0001", ticket_state: "approuve", approval: { decision: "approuve", ticket: "apr-0002" }, approver_set: null }, (({ approver_set, ...r }) => r)(ok)]) expect(A.combinaisonAdmise(mauvaise), JSON.stringify(mauvaise)).to.equal(false);
  });

  it("remises des traces : forme d'EX-8.8, exactement t signatures (EX-7.28, t = effective_required), acceptées par SG-1 à SG-6 (EX-9.11)", function () {
    let auDessusDuSeuil = 0;
    for (const [f, t] of Object.entries(traces)) {
      const retenues = t.steps.filter((s) => s.input.kind === "ouvrir").map((s) => ({ seq: s.input.data.request_seq, ticket: s.input.data.ticket, hash: s.input.data.request_hash, ts: s.input.data.request_ts }));
      t.steps.forEach((s, k) => {
        if (s.expected.remises.length === 0) return;
        const { service } = A.rejouerTrace({ ...t, steps: t.steps.slice(0, k + 1) }, { schemas: SCHEMAS });
        for (const remise of s.expected.remises) {
          if (remise.approval.decision === "expire") continue;
          const doc = service.documentTicket(remise.ticket);
          expect(remise.approval.approvers.length, `${f} ${remise.remise_id}`).to.equal(doc.effective_required);
          expect(remise.approval.threshold, `${f} ${remise.remise_id}`).to.deep.equal(doc.approver_set.threshold);
          if (doc.effective_required > remise.approval.threshold.required) auDessusDuSeuil += 1;
        }
      });
      for (const s of t.steps) for (const remise of s.expected.remises) {
        expect(A.erreursSchema(remise, SCHEMAS, "remise")).to.deep.equal([]);
        const a = remise.approval;
        expect(remise.approver_set.source.match(A.RE_SOURCE_REGISTRE) || remise.approver_set.source.match(A.RE_SOURCE_STATIQUE), f).to.not.equal(null);
        const context = { org_id: t.org_id, journal_id: t.journal_id, retained: retenues.filter((x) => x.ticket === remise.ticket && x.hash === a.request_hash), decided: [], expire_after_ms: t.expire_after_ms, write_at: s.input.at };
        expect(A.verifierRemise(remise, context, { schemas: SCHEMAS }), `${f} ${remise.remise_id}`).to.deep.equal({ result: "scelle", reason: null, check: null });
      }
    }
    // Trace jeu-seuil-abaisse : seuil ramené à 1 pendant l'attente, deux signatures exigées (EX-8.6).
    expect(auDessusDuSeuil).to.be.at.least(1);
  });

  it("EX-A.6 : les votes acceptés portent de vraies signatures EIP-191 des comptes de A.2 sur D_A", function () {
    for (const [f, t] of Object.entries(traces)) {
      const hachages = Object.fromEntries(t.steps.filter((s) => s.input.kind === "ouvrir").map((s) => [s.input.data.ticket, s.input.data.request_hash]));
      for (const s of t.steps.filter((x) => x.input.kind === "voter" && x.expected.accepted)) {
        const d = s.input.data;
        const n = A.normaliserSignature(d.signature);
        const Aobj = A.objetA({ decision: d.decision, journal_id: t.journal_id, org_id: t.org_id, request_hash: hachages[d.ticket], ticket: d.ticket });
        expect(J.verifierSignatureApprobation(Aobj, n.signature, d.approver).ok, `${f} ${s.input.at}`).to.equal(true);
        expect(CONSTANTES.accounts.map((c) => c.address)).to.include(d.approver);
      }
    }
  });

  it("EX-7.10, EX-7.11 : échéance = request_ts + E ; raisons d'expiration de la table, dans les traces", function () {
    const raisons = new Set();
    for (const [f, t] of Object.entries(traces)) for (const s of t.steps) {
      // Un ouvrir tardif sur un ticket que le noyau a expiré avant toute ouverture (T17 depuis reserve) rend l'état courant, sans échéance.
      if (s.input.kind === "ouvrir" && s.expected.response) expect(s.expected.response.deadline, f).to.equal(s.expected.response.state === "expire" && s.expected.response.deadline === null ? null : J.horodatage(Date.parse(s.input.data.request_ts) + t.expire_after_ms));
      for (const r of s.expected.remises) if (r.approval.decision === "expire") raisons.add(r.approval.reason);
    }
    expect([...raisons].sort()).to.deep.equal(Object.values(A.RAISONS_EXPIRATION).sort());
  });

  it("EX-7.24 : arguments, événement retenue, pièce et valeurs de portée effacés au passage en consomme, clos ou abandonne ; aucun condensé des arguments en clair dans la trace", function () {
    for (const [f, t] of Object.entries(traces)) {
      const { service } = A.rejouerTrace(t, { schemas: SCHEMAS });
      for (const id of Object.keys(service.etats())) {
        const doc = service.documentTicket(id);
        const evaluer = t.steps.find((s) => s.input.kind === "evaluer" && s.expected.response?.ticket === id);
        if (["consomme", "clos", "abandonne"].includes(doc.state)) {
          expect([doc.request.arguments, doc.request.retained_event, doc.request.arguments_piece, doc.opening?.scope.values ?? null], `${f} ${id}`).to.deep.equal([null, null, null, null]);
          for (const v of Object.values(evaluer.input.data.request.arguments)) if (typeof v === "string" && v.length > 8) expect(JSON.stringify(doc), `${f} ${id}`).to.not.include(v);
        }
        const condense = J.sha256(Buffer.from(J.canonicaliserJCSIntegral(evaluer.input.data.request.arguments), "utf8"));
        expect(JSON.stringify(doc), `${f} ${id}`).to.not.include(condense.slice(2));
      }
    }
  });

  it("EX-7.13 : une escalade est inscrite dans la trace du ticket et ne change ni l'état ni l'échéance", function () {
    const t = traces["expire-sans-vote.json"];
    const { service } = A.rejouerTrace({ ...t, steps: t.steps.slice(0, 6) }, { schemas: SCHEMAS });
    const doc = service.documentTicket("apr-0001");
    expect(doc.transitions.filter((x) => x.input === "escalade").map((x) => [x.at, x.from, x.to])).to.deep.equal([[T("09:30:00.200"), "ouvert", "ouvert"], [T("09:50:00.200"), "ouvert", "ouvert"]]);
    expect(doc.deadline).to.equal(T("10:00:00.200"));
  });

  it("EX-5.4, EX-5.6 : la fenêtre s'ouvre à approval.at pour duration_ms et max_calls ; une fenêtre de même portée est remplacée ; épuisée ou finie, elle est retirée", function () {
    const t = traces["fenetre-ouvrante.json"];
    const fenetres = (kind, ticket) => t.steps.find((s) => s.input.kind === kind && s.input.data.ticket === ticket).expected.windows;
    const portee = { policy_version: V1, rule: "paiement de 1000 a 5000 CHF", tool: "sap.payments.create", launched_by: "u.martin@assureur-demo.example", values: ["CH9300762011623852957"] };
    expect(fenetres("acquitter", "apr-0002")).to.deep.equal([]);
    expect(fenetres("acquitter", "apr-0001")).to.deep.equal([{ scope: portee, start: T("09:15:02.950"), end: T("09:25:02.950"), remaining: 3, ticket: "apr-0001" }]);
    expect(fenetres("acquitter", "apr-0003")).to.deep.equal([{ scope: portee, start: T("09:15:03.950"), end: T("09:25:03.950"), remaining: 3, ticket: "apr-0003" }]);
    const couverts = t.steps.filter((s) => s.input.kind === "evaluer" && s.expected.response?.decision === "autorise");
    expect(couverts.map((s) => s.expected.windows.map((w) => w.remaining))).to.deep.equal([[2], [1], []]);
    expect(t.steps.find((s) => s.input.kind === "horloge" && s.input.at === T("09:31:01.899")).expected.windows.map((w) => w.ticket)).to.deep.equal(["apr-0004"]);
    expect(t.steps.at(-1).expected.windows).to.deep.equal([]);
  });

  it("EX-9.10 : ordre des raisons de refus d'un vote", function () {
    const s = new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, parametres: { expire_after_ms: E, approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [ADR(1), ADR(2), ADR(3)], threshold: { required: 2, size: 3 } }, separation: { self_approval: "interdite", identities: [{ launched_by: "u.martin@assureur-demo.example", addresses: [ADR(3)] }] } } });
    const ev = { rule: "r", decision: "a_approuver", contest_ms: 0, opening: null };
    const vote = (at, ticket, compte, decision, o = {}) => ({ kind: "voter", at: T(at), data: { ticket, approver: ADR(compte), decision, signature: o.signature ?? A.signerVote(COMPTE[compte], { decision, journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: o.hash ?? "0x" + "11".repeat(32), ticket }), reason: o.reason ?? null, session_identity: null } });
    const raison = (e) => s.traiter(e).reason;
    expect(raison(vote("09:00:00.000", "apr-0001", 1, "approuve"))).to.equal("ticket_inconnu");
    s.traiter({ kind: "evaluer", at: T("09:00:00.000"), data: { request: demande("t", {}), evaluation: ev } });
    expect(raison(vote("09:00:01.000", "apr-0001", 1, "approuve"))).to.equal("ticket_non_ouvert");
    s.traiter({ kind: "ouvrir", at: T("09:00:02.000"), data: { ticket: "apr-0001", request_hash: "0x" + "11".repeat(32), request_seq: 1, request_ts: T("09:00:01.500") } });
    expect(raison(vote("09:00:03.000", "apr-0001", 1, "approuve", { hash: "0x" + "22".repeat(32) }))).to.equal("signature_invalide");
    expect(raison(vote("09:00:04.000", "apr-0001", 4, "approuve"))).to.equal("hors_jeu");
    expect(raison(vote("09:00:05.000", "apr-0001", 3, "approuve"))).to.equal("auto_approbation");
    expect(raison(vote("09:00:06.000", "apr-0001", 1, "approuve", { reason: "x".repeat(1025) }))).to.equal("motif_trop_long");
    expect(raison(vote("09:00:07.000", "apr-0001", 1, "approuve", { reason: "é".repeat(1024) }))).to.equal(null);
    expect(raison(vote("09:00:08.000", "apr-0001", 1, "approuve"))).to.equal("vote_identique");
    expect(raison(vote("09:00:09.000", "apr-0001", 2, "approuve"))).to.equal(null);
    expect(s.etats()).to.deep.equal({ "apr-0001": "a_remettre" });
    expect(raison(vote("09:00:10.000", "apr-0001", 2, "refuse"))).to.equal("ticket_clos_aux_votes");
  });

  it("service avec la politique de 4.3 : évaluation, ticket ouvrant, fenêtre ouverte puis consommée par le service (EX-6.1, EX-5.5, EX-7.22)", function () {
    const s = new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, politique: POLITIQUE_ASSUREUR, parametres: { expire_after_ms: E, approver_set: { source: "statique", chain_id: null, registry: null, set: null, members: [ADR(1), ADR(2), ADR(3)], threshold: { required: 2, size: 3 } }, separation: POLITIQUE_ASSUREUR.separation } });
    const args = (amount) => ({ claim_id: "2026-1", amount, currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
    const r1 = s.traiter({ kind: "evaluer", at: T("09:00:00.000"), data: { request: demande("sap.payments.create", args("2500.00")) } });
    expect(r1.response).to.deep.include({ rule: "paiement de 1000 a 5000 CHF", decision: "a_approuver", ticket: "apr-0001", ticket_state: "nouveau" });
    expect(s.documentTicket("apr-0001").opening.scope.values).to.deep.equal(["CH9300762011623852957"]);
    s.traiter({ kind: "ouvrir", at: T("09:00:01.000"), data: { ticket: "apr-0001", request_hash: "0x" + "33".repeat(32), request_seq: 5, request_ts: T("09:00:00.500") } });
    const remises = [[1, 1], [2, 2]].flatMap(([i, c]) => s.traiter({ kind: "voter", at: T(`09:0${i}:00.000`), data: { ticket: "apr-0001", approver: ADR(c), decision: "approuve", signature: A.signerVote(COMPTE[c], { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: "0x" + "33".repeat(32), ticket: "apr-0001" }), reason: null, session_identity: null } }).remises);
    expect(s.etats()).to.deep.equal({ "apr-0001": "a_remettre" });
    expect(remises.map((r) => r.remise_id)).to.deep.equal(["apr-0001/1"]);
    const approval = A.approvalScelle(remises[0].approval, T("09:02:59.000"));
    const sc = s.traiter({ kind: "acquitter", at: T("09:03:00.000"), data: { remise_id: "apr-0001/1", ticket: "apr-0001", result: "scelle", reason: null, seq: 6, hash: "0x" + "44".repeat(32), at: T("09:02:59.000"), decision: "approuve", held: false, approval } });
    expect(sc.windows).to.have.length(1);
    expect(s.documentTicket("apr-0001").sealed.approval).to.deep.equal(approval);
    const r2 = s.traiter({ kind: "evaluer", at: T("09:10:00.000"), data: { request: demande("sap.payments.create", args("3000.00")) } });
    expect(r2.response).to.deep.equal({ rule: "paiement de 1000 a 5000 CHF [fenetre apr-0001 2026-11-12T17:02:59.000Z]", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });
    expect(r2.windows[0].remaining).to.equal(19);
  });

  it("EX-8.3 : un service à jeu registre jamais lu répond non_pret ; EX-14.1 : le plafond ne vaut que pour a_approuver", function () {
    const t = traces["non-pret.json"];
    expect(t.steps[0].expected).to.deep.include({ accepted: false, reason: "non_pret", response: null });
    const p = traces["plafond.json"];
    expect(p.steps.map((s) => s.expected.reason)).to.deep.equal([null, null, null, "plafond_atteint", null, null, null, null]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : remises et signatures (section 9, SG-1 à SG-6, annexe A.7 et A.8)", function () {
  const cas = ["valides", "invalides"].flatMap((rep) => fichiers("decisions", rep).map((f) => [rep, f, lire("decisions", rep, f)]));

  it("decisions/ : chaque remise reçoit le résultat et la raison attendus, dans l'ordre de SG-1 à SG-6", function () {
    for (const [rep, f, c] of cas) {
      expect(A.erreursSchema(c, SCHEMAS, "cas_remise"), f).to.deep.equal([]);
      const r = A.verifierRemise(c.remise, c.context, { schemas: SCHEMAS });
      expect({ result: r.result, reason: r.reason }, `${rep}/${f}`).to.deep.equal(c.expected);
      expect(r.check, `${rep}/${f}`).to.equal(c.check);
      if (rep === "valides") expect(A.erreursSchema(c.remise, SCHEMAS, "remise"), f).to.deep.equal([]);
    }
  });

  it("EX-A.8 : au moins un cas par raison de refus du noyau, et les cas particuliers exigés", function () {
    const raisons = new Set(cas.filter(([rep]) => rep === "invalides").map(([, , c]) => c.expected.reason));
    for (const r of ["remise_mal_formee", "ticket_inconnu", "request_hash_different", "ticket_deja_decide", "echeance_depassee", "signature_invalide", "approbateur_hors_jeu", "approbateur_double", "seuil_different_du_jeu", "expire_avec_signatures", "seuil_non_atteint"]) expect(raisons.has(r), r).to.equal(true);
    const ids = new Set(cas.map(([, , c]) => c.id));
    for (const id of ["approbation-2-sur-3", "refus-2-sur-3", "expiration-sans-signature", "jeu-statique", "ct1-apr-2201", "sg5-signature-sur-la-chaine", "sg5-approuve-pour-refuse", "sg5-autre-journal", "sg5-s-haut", "sg4-ecriture-a-l-echeance", "sg1-remise-id-autre-ticket", "sg6-taille-differente-des-membres"]) expect(ids.has(id), id).to.equal(true);
    // Ordre de SG-1 à SG-6 et des raisons de SG-6 : chaque paire de vérifications voisines en échec a son cas.
    const ordre = Object.fromEntries(cas.filter(([, , c]) => c.id.startsWith("ordre-")).map(([, , c]) => [c.id, c.expected.reason]));
    expect(ordre).to.deep.equal({ "ordre-sg1-sg2": "remise_mal_formee", "ordre-sg2-sg3": "request_hash_different", "ordre-sg3-sg4": "ticket_deja_decide", "ordre-sg4-sg5": "echeance_depassee", "ordre-sg5-sg6": "signature_invalide", "ordre-sg6-double-hors-jeu": "approbateur_double", "ordre-sg6-hors-jeu-seuil": "approbateur_hors_jeu", "ordre-sg6-seuil-expire": "seuil_different_du_jeu", "ordre-sg6-seuil-non-atteint": "seuil_different_du_jeu" });
    const echeance = cas.find(([, , c]) => c.id === "sg4-ecriture-a-l-echeance")[2];
    expect(Date.parse(echeance.context.write_at)).to.equal(Date.parse(echeance.context.retained[0].ts) + echeance.context.expire_after_ms);
  });

  it("A.8 : normalisation d'EX-9.3 ; chaque forme normalisée recouvre la même adresse que la forme d'entrée", function () {
    const doc = lire("signatures", "normalisation.json");
    expect(Object.keys(doc)).to.deep.equal(["version", "cases"]);
    const M = A.condensesVote({ decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: J.sha256(Buffer.from("noortrace/vecteurs/ct3/demande/1", "utf8")), ticket: "apr-0001" }).M;
    for (const c of doc.cases) {
      expect(Object.keys(c)).to.deep.equal(["id", "signature", "expected", "reason"]);
      expect(A.normaliserSignature(c.signature), c.id).to.deep.equal({ signature: c.expected, reason: c.reason });
      if (c.expected === null) continue;
      const adresse = recouvrer(M, c.signature);
      expect(recouvrer(M, c.expected), c.id).to.equal(adresse);
      expect(CONSTANTES.accounts.map((x) => x.address)).to.include(adresse);
      expect(J.verifierSignatureApprobation(A.objetA({ decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: J.sha256(Buffer.from("noortrace/vecteurs/ct3/demande/1", "utf8")), ticket: "apr-0001" }), c.expected, adresse).ok).to.equal(true);
    }
    for (const id of ["canonique", "s-haut-v27", "s-haut-v28", "v-0", "v-1", "v-29", "longueur-64", "r-nul", "r-egal-n", "s-nul", "s-egal-n"]) expect(doc.cases.some((c) => c.id === id), id).to.equal(true);
  });

  it("EX-9.1, EX-9.2 : A de CT-1 §6.3 inchangé ; approuve et refuse ne diffèrent que par decision ; signerVote = signerApprobation de journal.mjs", function () {
    const champs = { journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: "0x" + "55".repeat(32), ticket: "apr-0007" };
    const ap = A.objetA({ ...champs, decision: "approuve" });
    const re = A.objetA({ ...champs, decision: "refuse" });
    expect(Object.keys(ap)).to.deep.equal(["decision", "journal_id", "org_id", "request_hash", "ticket"]);
    expect(J.canonicaliserJCS(ap).replace('"approuve"', '"refuse"')).to.equal(J.canonicaliserJCS(re));
    expect(A.condensesVote({ ...champs, decision: "approuve" }).D_A).to.equal(J.condenseApprobation(ap));
    expect(A.signerVote(COMPTE[1], { ...champs, decision: "approuve" })).to.equal(J.signerApprobation(COMPTE[1], ap));
    expect(J.verifierSignatureApprobation(re, A.signerVote(COMPTE[1], { ...champs, decision: "approuve" }), ADR(1)).ok).to.equal(false);
  });

  it("EX-9.7 : une signature des 66 caractères « 0x… » ne recouvre pas l'approbateur ; celle des 32 octets, si", function () {
    const champs = { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: "0x" + "66".repeat(32), ticket: "apr-0008" };
    const { A: Aobj, D_A } = A.condensesVote(champs);
    const surChaine = Signature.from(COMPTE[2].signingKey.sign(hashMessage(D_A))).serialized;
    const surOctets = Signature.from(COMPTE[2].signingKey.sign(hashMessage(getBytes(D_A)))).serialized;
    expect(J.verifierSignatureApprobation(Aobj, surOctets, ADR(2)).ok).to.equal(true);
    expect(J.verifierSignatureApprobation(Aobj, surChaine, ADR(2)).ok).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : jeu d'approbateurs lu dans un CuratorSet réel (section 8, réseau Hardhat en mémoire)", function () {
  this.timeout(120_000);

  async function deployer() {
    const { ethers } = await network.create();
    const [admin] = await ethers.getSigners();
    const membres = [1, 2, 3].map((i) => COMPTE[i].address);
    const set = await (await ethers.getContractFactory("CuratorSet")).deploy(admin.address, membres, 2);
    const registre = await (await ethers.getContractFactory("CuratorSetRegistry")).deploy(admin.address);
    await set.waitForDeployment();
    await registre.waitForDeployment();
    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const source = { requete: (m, p) => ethers.provider.send(m, p) };
    const approver_set = { source: "registre", chain_id: chainId, registry: (await registre.getAddress()).toLowerCase(), set: (await set.getAddress()).toLowerCase(), members: null, threshold: null };
    return { ethers, admin, set, registre, source, approver_set };
  }

  it("EX-8.1 : organisation sans jeu, chaîne différente, jeu non attendu, jeu sans code, puis lecture complète à une hauteur", async function () {
    const { ethers, set, registre, source, approver_set } = await deployer();
    expect(await A.lireJeu(source, { approver_set, org_id: ORG_ID })).to.deep.equal({ status: "illisible", jeu: null, cause: "organisation_sans_jeu" });
    expect((await A.lireJeu(source, { approver_set: { ...approver_set, chain_id: 2124 }, org_id: ORG_ID })).cause).to.equal("chaine_differente");
    const autreOrg = keccak256(toUtf8Bytes("organisation-sans-code"));
    const sansCode = ethers.Wallet.createRandom().address;
    await (await registre.setCuratorSet(autreOrg, sansCode)).wait();
    // Le registre désigne un autre jeu que celui que la politique épingle : illisible, jeu_non_attendu (pas 2).
    expect((await A.lireJeu(source, { approver_set, org_id: autreOrg })).cause).to.equal("jeu_non_attendu");
    expect((await A.lireJeu(source, { approver_set: { ...approver_set, set: sansCode.toLowerCase() }, org_id: autreOrg })).cause).to.equal("jeu_sans_code");
    await (await registre.setCuratorSet(ORG_ID, await set.getAddress())).wait();
    const lu = await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: [1, 2, 3].map(ADR) });
    expect(lu.status).to.equal("lu");
    const H = await ethers.provider.getBlockNumber();
    expect(lu.jeu).to.deep.equal({ chain_id: approver_set.chain_id, registry: approver_set.registry, set: (await set.getAddress()).toLowerCase(), height: H, block_hash: (await ethers.provider.getBlock(H)).hash, threshold: { required: 2, size: 3 }, members: A.trierAdresses([1, 2, 3].map(ADR)) });
    expect(A.erreursSchema(lu.jeu, SCHEMAS, "jeu")).to.deep.equal([]);
    // Sans adresse connue, la liste est reconstituée par CuratorAdded et CuratorRemoved.
    expect(await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: [] })).to.deep.equal(lu);
    // Une adresse connue non membre ne change rien.
    expect(await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: [ADR(1), ADR(4)] })).to.deep.equal(lu);
  });

  it("EX-8.5, EX-8.6 : surveillance du jeu figé ; un membre retiré donne un nouveau gel ; une réassignation donne une lecture illisible jeu_non_attendu, sans nouveau gel", async function () {
    const { ethers, set, registre, source, approver_set } = await deployer();
    await (await registre.setCuratorSet(ORG_ID, await set.getAddress())).wait();
    const gel = (await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: [1, 2, 3, 4].map(ADR) })).jeu;
    expect(await A.changementsJeu(source, { jeu: gel, org_id: ORG_ID, jusqua: await ethers.provider.getBlockNumber() })).to.deep.equal([]);
    // Service : un ticket figé sur ce jeu, approuvé par les comptes 1 et 2.
    const s = new A.ServiceApprobation({ org_id: ORG_ID, journal_id: JOURNAL_ID, policy_version: V1, parametres: { expire_after_ms: E, approver_set, separation: { self_approval: "interdite", identities: [] } } });
    s.traiter({ kind: "jeu_lu", at: T("09:00:00.000"), data: { status: "lu", jeu: gel, cause: null } });
    s.traiter({ kind: "evaluer", at: T("09:00:01.000"), data: { request: demande("t", {}), evaluation: { rule: "r", decision: "a_approuver", contest_ms: 0, opening: null } } });
    const h = "0x" + "77".repeat(32);
    s.traiter({ kind: "ouvrir", at: T("09:00:02.000"), data: { ticket: "apr-0001", request_hash: h, request_seq: 1, request_ts: T("09:00:01.500") } });
    s.traiter({ kind: "jeu_lu", at: T("09:00:03.000"), data: { status: "lu", jeu: gel, cause: null } });
    for (const [i, c] of [[4, 1], [5, 2]]) s.traiter({ kind: "voter", at: T(`09:00:0${i}.000`), data: { ticket: "apr-0001", approver: ADR(c), decision: "approuve", signature: A.signerVote(COMPTE[c], { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: h, ticket: "apr-0001" }), reason: null, session_identity: null } });
    expect(s.etats()).to.deep.equal({ "apr-0001": "verification" });
    // Le compte 2 est retiré, le compte 4 ajouté : changements constatés, nouvelle lecture différente.
    await (await set.addCurator(COMPTE[4].address)).wait();
    await (await set.removeCurator(COMPTE[2].address)).wait();
    const changements = await A.changementsJeu(source, { jeu: gel, org_id: ORG_ID, jusqua: await ethers.provider.getBlockNumber() });
    expect(changements.map((c) => c.event)).to.deep.equal(["CuratorAdded", "CuratorRemoved"]);
    const relu = (await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: gel.members })).jeu;
    expect(relu.members).to.deep.equal(A.trierAdresses([1, 3, 4].map(ADR)));
    const r = s.traiter({ kind: "jeu_lu", at: T("09:00:06.000"), data: { status: "lu", jeu: relu, cause: null } });
    expect(r.tickets).to.deep.equal({ "apr-0001": "ouvert" });
    expect(s.documentTicket("apr-0001").votes.find((v) => v.approver === ADR(2))).to.deep.include({ status: "ecarte", cause: "hors_jeu" });
    // Réassignation de l'organisation : CuratorSetAssigned.
    const set2 = await (await ethers.getContractFactory("CuratorSet")).deploy((await ethers.getSigners())[0].address, [1, 2, 4].map((i) => COMPTE[i].address), 3);
    await set2.waitForDeployment();
    await (await registre.setCuratorSet(ORG_ID, await set2.getAddress())).wait();
    expect((await A.changementsJeu(source, { jeu: relu, org_id: ORG_ID, jusqua: await ethers.provider.getBlockNumber() })).map((c) => c.event)).to.deep.equal(["CuratorSetAssigned"]);
    const lecture = await A.lireJeu(source, { approver_set, org_id: ORG_ID, adresses: [] });
    expect(lecture).to.deep.equal({ status: "illisible", jeu: null, cause: "jeu_non_attendu" });
    const avantReassignation = s.documentTicket("apr-0001").approver_set;
    const r2 = s.traiter({ kind: "jeu_lu", at: T("09:00:07.000"), data: lecture });
    expect(r2.tickets).to.deep.equal({ "apr-0001": "ouvert" });
    expect(s.documentTicket("apr-0001").approver_set).to.deep.equal(avantReassignation);
    expect(s.documentTicket("apr-0001").set_reassigned).to.equal(true);
    // Lu sans épinglage, le jeu 2 serait un autre jeu (adresse, seuil 3 sur 3).
    const jeu2 = (await A.lireJeu(source, { approver_set: { ...approver_set, set: (await set2.getAddress()).toLowerCase() }, org_id: ORG_ID, adresses: [] })).jeu;
    expect(jeu2.threshold).to.deep.equal({ required: 3, size: 3 });
    expect(A.memeJeu(jeu2, relu)).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : comportement du mandataire pendant l'attente (section 11, décision ouverte 4)", function () {
  const JEU = { threshold: { required: 2, size: 3 }, members: A.trierAdresses([ADR(1), ADR(2), ADR(3)]), source: "jeu statique de la politique vecteurs-ct3-1" };
  const reponse = (decision, ticket, ticket_state, approval = null) => ({ rule: "r", decision, ticket, ticket_state, approval, approver_set: ticket_state === "nouveau" ? JEU : null });
  const scelle = (decision, ticket = "apr-0001") => ({ decision, ticket });

  it("EX-11.1 : le mode par défaut est erreur ; retenir est signalé, et hors du délai des hôtes (EX-11.2)", function () {
    expect(A.MODE_ATTENTE_DEFAUT).to.equal("erreur");
    expect(A.avertissementsModeAttente({ mode: "erreur", hold_timeout_ms: 50000 })).to.deep.equal([]);
    expect(A.avertissementsModeAttente({ mode: "retenir", hold_timeout_ms: 4000 }, { delaisHotesMs: [5000, 60000] })).to.have.length(1);
    expect(A.avertissementsModeAttente({ mode: "retenir", hold_timeout_ms: 50000 }, { delaisHotesMs: [5000, 60000] })).to.have.length(2);
  });

  it("EX-11.3, EX-11.7 : en mode erreur, -32015 aussitôt, data exactement { ticket, state }, sans changer les codes de CT-2", function () {
    const e = A.actionMandataire(reponse("a_approuver", "apr-0001", "nouveau"));
    expect(e).to.deep.equal({ action: "erreur", error: { code: -32015, message: "noortrace: approbation requise", data: { ticket: "apr-0001", state: "en_attente" } } });
    expect(e.error.code).to.equal(C.ERREURS.APPROBATION.code);
    expect(A.actionMandataire(reponse("a_approuver", "apr-0001", "en_attente")).error.data.state).to.equal("en_attente");
    expect(A.actionMandataire(reponse("refuse", "apr-0001", "refuse", scelle("refuse"))).error.data).to.deep.equal({ ticket: "apr-0001", state: "refuse" });
    expect(A.actionMandataire(reponse("refuse", "apr-0001", "expire", scelle("expire"))).error.data).to.deep.equal({ ticket: "apr-0001", state: "expire" });
    expect(A.actionMandataire(reponse("autorise", "apr-0001", "approuve", scelle("approuve")))).to.deep.equal({ action: "relayer", approval: scelle("approuve") });
    expect(A.actionMandataire(reponse("autorise", null, null))).to.deep.equal({ action: "relayer", approval: null });
  });

  it("EX-12.6 : une réponse hors des sept combinaisons est une indisponibilité du service : -32010, raison approbation, jamais un relais", function () {
    const degrade = { action: "erreur", error: C.erreurEnregistreur("MODE_DEGRADE", { reason: "approbation" }) };
    expect(degrade.error.code).to.equal(-32010);
    for (const r of [reponse("autorise", "apr-0001", "approuve", scelle("approuve", "apr-0002")), reponse("autorise", "apr-0001", "approuve", scelle("refuse")), reponse("autorise", "apr-0001", "en_attente"), { ...reponse("a_approuver", "apr-0001", "nouveau"), approver_set: null }, reponse("refuse", "apr-0001", "refuse", null), { rule: "r", decision: "autorise", ticket: null, ticket_state: null, approval: null }]) {
      expect(A.actionMandataire(r), JSON.stringify(r)).to.deep.equal(degrade);
      expect(A.actionMandataire(r, { mode: "retenir" }), JSON.stringify(r)).to.deep.equal(degrade);
    }
  });

  it("EX-11.4 : en mode retenir, au plus une requête retenue par ticket ; les autres reçoivent -32015 en_attente", function () {
    expect(A.actionMandataire(reponse("a_approuver", "apr-0001", "nouveau"), { mode: "retenir" })).to.deep.equal({ action: "retenir", ticket: "apr-0001" });
    expect(A.actionMandataire(reponse("a_approuver", "apr-0001", "en_attente"), { mode: "retenir", requeteDejaRetenue: true }).action).to.equal("erreur");
    expect(A.actionMandataire(reponse("refuse", "apr-0001", "refuse", scelle("refuse")), { mode: "retenir" }).error.data).to.deep.equal({ ticket: "apr-0001", state: "refuse" });
  });
});

// ---------------------------------------------------------------------------
describe("CT-3 : génération déterministe des vecteurs (EX-A.1, EX-A.2, EX-A.3)", function () {
  this.timeout(300_000);

  function lister(racine) {
    const out = [];
    const parcourir = (rel) => {
      for (const e of fs.readdirSync(path.join(racine, rel), { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
        const r = path.join(rel, e.name);
        if (e.isDirectory()) {
          if (r !== "verificateur-independant") parcourir(r);
        } else out.push(r);
      }
    };
    parcourir("");
    return out;
  }

  it("deux générations dans des répertoires vides donnent les mêmes octets, ceux de spec/vecteurs/ct-3 ; verificateur-independant/ est conservé", function () {
    const a = tmp("noortrace-ct3-a-");
    const b = tmp("noortrace-ct3-b-");
    try {
      fs.mkdirSync(path.join(b, "verificateur-independant"));
      fs.writeFileSync(path.join(b, "verificateur-independant", "temoin.txt"), "conservé\n");
      fs.mkdirSync(path.join(b, "tickets"));
      fs.writeFileSync(path.join(b, "tickets", "trace-perimee.json"), "{}\n");
      genererCt3({ racine: a });
      genererCt3({ racine: b });
      expect(fs.readFileSync(path.join(b, "verificateur-independant", "temoin.txt"), "utf8")).to.equal("conservé\n");
      expect(fs.existsSync(path.join(b, "tickets", "trace-perimee.json"))).to.equal(false);
      const fa = lister(a);
      expect(fa).to.deep.equal(lister(b));
      expect(fa).to.deep.equal(lister(CT3));
      expect([...new Set(fa.map((f) => f.split(path.sep)[0]))].sort()).to.deep.equal([...ENTREES_GENEREES].sort());
      for (const f of fa) {
        const octets = fs.readFileSync(path.join(a, f));
        expect(octets.equals(fs.readFileSync(path.join(b, f))), f).to.equal(true);
        expect(octets.equals(fs.readFileSync(path.join(CT3, f))), `${f} diffère de spec/vecteurs/ct-3`).to.equal(true);
      }
    } finally {
      fs.rmSync(a, { recursive: true, force: true });
      fs.rmSync(b, { recursive: true, force: true });
    }
  });

  it("EX-A.1 : une racine qui porte une entrée que le générateur n'écrit pas est refusée sans rien effacer ; --sortie sans répertoire est refusé", function () {
    const c = tmp("noortrace-ct3-c-");
    try {
      fs.writeFileSync(path.join(c, "notes.txt"), "à garder\n");
      fs.mkdirSync(path.join(c, "tickets"));
      fs.writeFileSync(path.join(c, "tickets", "x.json"), "{}\n");
      expect(() => genererCt3({ racine: c })).to.throw(/notes\.txt/);
      expect(fs.readFileSync(path.join(c, "notes.txt"), "utf8")).to.equal("à garder\n");
      expect(fs.existsSync(path.join(c, "tickets", "x.json"))).to.equal(true);
      const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "vecteurs", "generer-ct3.mjs"), "--sortie"], { encoding: "utf8" });
      expect(r.status).to.equal(2);
      expect(r.stderr).to.include("--sortie demande un répertoire");
    } finally {
      fs.rmSync(c, { recursive: true, force: true });
    }
  });

  it("INDEX.md dit qu'il est produit par le générateur et ne doit pas être édité ; les JSON sont écrits comme ceux de CT-1", function () {
    const index = fs.readFileSync(path.join(CT3, "INDEX.md"), "utf8");
    expect(index.split("\n")[2]).to.match(/^Produit par `scripts\/vecteurs\/generer-ct3\.mjs` .*ne pas l'éditer à la main/);
    for (const f of lister(CT3).filter((x) => x.endsWith(".json"))) {
      const texte = fs.readFileSync(path.join(CT3, f), "utf8");
      expect(texte, f).to.equal(JSON.stringify(JSON.parse(texte), null, 2) + "\n");
    }
  });
});

// ---------------------------------------------------------------------------
// Matrice de couverture : chaque règle EX- de CT-3 et le test qui l'exerce,
// ou la raison pour laquelle cette implémentation ne peut pas la tester (elle
// vise la console, le noyau de CT-2, l'organisation ou un document).
// ---------------------------------------------------------------------------

const HORS = (raison) => `hors de cette implémentation : ${raison}`;
const COUVERTURE = {
  "EX-3.1": "EX-12.6, EX-3.1 (traces) ; ticket-v0 : autorise lié à un ticket après scellement approuve",
  "EX-3.2": "traces expire-* : échéance donne expire, jamais approuve ; EX-7.10",
  "EX-3.3": HORS("propriété de déploiement du service (aucune clé) ; la bibliothèque ne signe rien hors des tests"),
  "EX-3.4": HORS("garde des clés d'approbateur, console (CT-7)"),
  "EX-3.5": "EX-4.9, EX-6.6, AP-17 : membres hors évaluation sans effet",
  "EX-4.1": "4.3 : exemple complet ; EX-4.2 : charger",
  "EX-4.2": "politiques-invalides ; bornes d'EX-4.2 ; charger rend politique_invalide",
  "EX-4.3": "EX-4.3 : sélecteurs ; evaluation/selection.json",
  "EX-4.4": "EX-4.4 : pointeurs ; evaluation/pointeurs.json",
  "EX-4.5": "EX-4.5, EX-4.6 ; evaluation/nombres.json",
  "EX-4.6": "EX-4.5, EX-4.6 ; evaluation/nombres.json",
  "EX-4.7": "evaluation/chaines.json",
  "EX-4.8": "EX-4.8 : tables de Kleene ; evaluation/logique.json",
  "EX-4.9": "evaluation/ordre.json et ordre-inverse.json (règle retenue, contest_ms, fenêtre) ; EX-4.9, AP-12 ; EX-4.9, EX-6.6",
  "EX-4.10": "evaluation/niveaux.json (règle par défaut seulement si aucune règle ne s'applique)",
  "EX-4.11": "candidats/ ; sur-ensemble sûr",
  "EX-4.12": "traces fenetre-politique-changee et politique-changee ; evaluation/niveaux.json (fenetre-autre-version)",
  "EX-4.13": "EX-4.13, EX-6.7 ; politiques-invalides/schema-expression-reguliere.json",
  "EX-4.14": "EX-4.14 : avertissements (sélecteur, pointeur rédigé, fenêtre large, liste d'exclusion, demandeur sans identité)",
  "EX-5.1": "evaluation/assureur.json (automatique autorise et refuse) ; EX-5.8",
  "EX-5.2": "evaluation/niveaux.json (portée, outil, autre demandeur, autre bénéficiaire, portée indéterminée, fenetre-autre-outil)",
  "EX-5.3": "evaluation/niveaux.json (ouvrant ou non) ; trace fenetre-ouvrante",
  "EX-5.4": "EX-5.4, EX-5.6 ; traces fenetre-ouvrante et fenetre-politique-changee",
  "EX-5.5": "evaluation/niveaux.json (couverture, consommation) ; service avec la politique de 4.3",
  "EX-5.6": "evaluation/niveaux.json (fin, épuisée, autre version) ; traces fenetre-ouvrante (retrait à l'épuisement et à la fin), fenetre-politique-changee",
  "EX-5.7": "traces approuve-sans-contestation, jeu-reassigne (le seuil ne vient que du jeu)",
  "EX-5.8": "EX-5.8 ; EX-12.6",
  "EX-5.9": "traces contestation-*, jeu-change-pendant-contestation",
  "EX-5.10": "politiques-invalides/contest-ms-* ; bornes d'EX-4.2",
  "EX-6.1": "evaluation/ ; service avec la politique de 4.3 ; trace non-pret",
  "EX-6.2": "evaluation/ (table 6.3) ; EX-5.8",
  "EX-6.3": "evaluation/ (INDETERMINE) ; EX-5.8",
  "EX-6.4": "EX-6.4",
  "EX-6.5": "EX-6.5 ; evaluation/niveaux.json (fenetre-non-consommee)",
  "EX-6.6": "EX-4.9, EX-6.6, AP-17 ; evaluation/assureur-permute.json",
  "EX-6.7": "EX-4.13, EX-6.7 ; bornes d'EX-4.2",
  "EX-7.1": "TK-1, EX-7.1, EX-7.2 (époque) ; trace deja-decide-autre-demande",
  "EX-7.2": "TK-1, EX-7.1, EX-7.2",
  "EX-7.3": "trace reemission-en-attente (clé) ; trace politique-changee",
  "EX-7.4": "trace reemission-en-attente (run_id et intent hors de la clé)",
  "EX-7.5": "traces approuve-sans-contestation, refuse-seuil (actif pendant la reconnaissance), reservation-abandonnee",
  "EX-7.6": "traces reemission-en-attente, approuve-sans-contestation",
  "EX-7.7": "traces expire-sans-vote, contestation-apres-echeance, fenetre-ouvrante (minuteurs avant l'entrée, ordre, fin de fenêtre)",
  "EX-7.8": "traces (entrées refusées sans changement, requete_invalide dans acquittements-noyau) ; TK-12 (transitions)",
  "EX-7.9": "chaque trace rejouée",
  "EX-7.10": "EX-7.10, EX-7.11 ; trace acquittement-temporaire ; decisions/invalides/sg4-*",
  "EX-7.11": "EX-7.10, EX-7.11 : les huit raisons dans les traces",
  "EX-7.12": HORS("contenu des notifications, console (13.2)"),
  "EX-7.13": "EX-7.13",
  "EX-7.14": HORS("annulation par l'hôte, mandataire de CT-2 ; le service n'en est pas informé en v0, le ticket reste ouvert (traces reemission-en-attente)"),
  "EX-7.15": "traces retrait, retrait-administrateur",
  "EX-7.16": "EX-12.6 ; traces reemission-en-attente, approuve-sans-contestation, refuse-seuil, retrait, plafond (refus sans ticket)",
  "EX-7.17": "traces approuve-sans-contestation (une seule réponse approuve, puis en_attente, puis consomme), retenir-double-reemission (held)",
  "EX-7.18": "traces refuse-seuil, retrait (répétition à l'identique) ; reemission-en-attente (un argument différent fait une autre demande)",
  "EX-7.19": "trace reemission-en-attente (reserve : nouveau ; ouvrir d'un autre hachage refusé)",
  "EX-7.20": "trace reemission-en-attente (evaluer et ouvrir répétés) ; traces deja-decide, acquittements-noyau, expiration-noyau (acquitter et expiration répétés)",
  "EX-7.21": "traces politique-changee, fenetre-politique-changee",
  "EX-7.22": "TK-12 (documents ticket-v0 seuls) ; service avec la politique de 4.3",
  "EX-7.23": "TK-12",
  "EX-7.24": "EX-7.24 (arguments, événement, pièce, valeurs de portée)",
  "EX-7.25": "trace reservation-abandonnee (ouvrir tardif) ; HORS : redémarrage du noyau (CT-2)",
  "EX-7.26": "trace vote-remplace",
  "EX-7.27": "traces vote-remplace, contestation-*, recusation-refus-maintenu, jeu-seuil-abaisse",
  "EX-7.28": "remises des traces (exactement le seuil effectif de signatures) ; traces vote-remplace (ordre d'acceptation, motif), jeu-seuil-abaisse",
  "EX-7.29": "trace seuil-inatteignable",
  "EX-8.1": "EX-8.1 (réseau Hardhat, jeu_non_attendu) ; trace jeu-reassigne",
  "EX-8.2": "politiques-invalides/statique-* (AP-4) ; trace jeu-statique",
  "EX-8.3": "EX-8.3 ; trace non-pret ; trace jeu-illisible (jeu de repli)",
  "EX-8.4": "trace jeu-illisible ; EX-9.10 (jeu_non_fige dans la trace jeu-illisible)",
  "EX-8.5": "EX-8.5, EX-8.6 (réseau Hardhat)",
  "EX-8.6": "EX-8.5, EX-8.6 ; traces jeu-change-membre-retire, jeu-reassigne, jeu-seuil-abaisse, jeu-change-pendant-contestation",
  "EX-8.7": "traces (T8 seulement sur une lecture égale postérieure) ; trace jeu-statique",
  "EX-8.8": "A.2 et 8.4 ; remises des traces",
  "EX-8.9": "remises des traces (members triés, threshold de la lecture)",
  "EX-8.10": HORS("CT-6 inchangé"),
  "EX-8.11": HORS("obligation de l'organisation, non vérifiable en v0"),
  "EX-9.1": "EX-9.1, EX-9.2",
  "EX-9.2": "EX-9.1, EX-9.2",
  "EX-9.3": "A.8 (r et s hors de [1, n − 1] compris) ; trace signature-hors-jeu",
  "EX-9.4": HORS("affichage de la console (13.2)"),
  "EX-9.5": HORS("console"),
  "EX-9.6": HORS("console ; condensesVote fournit A, D_A et M (EX-9.1)"),
  "EX-9.7": "EX-9.7 ; decisions/invalides/sg5-signature-sur-la-chaine.json ; trace signature-hors-jeu",
  "EX-9.8": HORS("console"),
  "EX-9.9": HORS("conduite de l'approbateur"),
  "EX-9.10": "EX-9.10 ; traces ordre-des-raisons-de-vote, signature-hors-jeu, recusation, separation-auto-approbation, vote-remplace",
  "EX-9.11": "decisions/ (cas ordre-*)",
  "EX-9.12": "decisions/valides/separation-non-verifiee-par-le-noyau.json",
  "EX-9.13": "decisions/invalides/sg6-refus-seuil-non-atteint.json ; trace refuse-seuil",
  "EX-9.14": "traces (reason du t-ième vote) ; HORS : avertissement de la console et détecteurs de rédaction du noyau",
  "EX-10.1": "traces separation-* ; EX-9.10",
  "EX-10.2": "traces separation-*, recusation",
  "EX-10.3": "trace jeu-change-membre-retire (vote écarté au nouveau gel) ; trace seuil-inatteignable ; trace recusation-refus-maintenu (refus d'un récusé gardé)",
  "EX-10.4": "traces recusation, recusation-refus-maintenu, contestation-objection-maintenue",
  "EX-10.5": "trace separation-auto-permise ; HORS : refus de la console",
  "EX-10.6": "trace refuse-seuil (C = 0 : refus compté)",
  "EX-10.7": "traces contestation-objection-levee, contestation-objection-maintenue, contestation-refus-anterieur (refus avant le seuil)",
  "EX-10.8": "traces contestation-objection-levee, contestation-objection-maintenue",
  "EX-10.9": "trace contestation-apres-echeance",
  "EX-10.10": "traces (service : max_open_tickets, escalation) ; HORS : configuration de la console",
  "EX-10.11": "EX-7.13 (escalade sans effet sur l'état et l'échéance)",
  "EX-11.1": "EX-11.1",
  "EX-11.2": "EX-11.1",
  "EX-11.3": "EX-11.3, EX-11.7",
  "EX-11.4": "EX-11.4 ; trace retenir-double-reemission",
  "EX-11.5": "trace retenir-double-reemission (held) ; HORS : relais de la requête retenue par le noyau de CT-2",
  "EX-11.6": HORS("notifications/progress du mandataire de CT-2"),
  "EX-11.7": "EX-11.3, EX-11.7 (a_approuver et refuse portent -32015, autorise d'un ticket approuvé est relayé)",
  "EX-11.8": "EX-11.8 (_meta serverInfo, deux ères)",
  "EX-11.9": HORS("fichiers d'intégration des hôtes (CT-2 §19.5)"),
  "EX-11.10": HORS("l'enregistreur de CT-2 ; actionMandataire ne produit ni tâche ni InputRequiredResult"),
  "EX-12.1": HORS("transport HTTP du service (phase 2)"),
  "EX-12.2": HORS("authentification du canal (phase 2, CT-7)"),
  "EX-12.3": HORS("propriété de déploiement du service"),
  "EX-12.5": "EX-4.2 : charger",
  "EX-12.6": "EX-12.6 (combinaisonAdmise, approver_set de nouveau) ; EX-12.6 : réponse hors des sept combinaisons, -32010",
  "EX-12.7": HORS("délai de réponse du service déployé ; evaluer ne lit pas le registre (EX-8.3)"),
  "EX-12.8": HORS("attente longue decisions (phase 2)"),
  "EX-12.9": "traces (acquitter : T11 à T16, T20 ; held, approval) ; decisions/",
  "EX-12.10": "trace approuve-sans-contestation (consommer)",
  "EX-12.11": "traces deja-decide, expiration-noyau (expiration avec approval) ; approver_set de la réponse nouveau (EX-12.6)",
  "EX-12.12": HORS("point GET /v0/etat (phase 2)"),
  "EX-12.4": HORS("canal console → service authentifié (phase 2) ; session_identity inscrite dans les transitions"),
  "EX-13.1": HORS("console (phase 2)"),
  "EX-13.2": HORS("console (phase 2) ; session_identity inscrite dans les votes"),
  "EX-13.3": HORS("console (phase 2) ; notification indépendante de chaque vote inscrit"),
  "EX-13.4": HORS("console (phase 2)"),
  "EX-13.5": HORS("console (phase 2) ; les actions sont les entrées voter, recuser, retirer des traces"),
  "EX-13.6": HORS("console (phase 2)"),
  "EX-14.1": "trace plafond (défaut 20, par launched_by) ; EX-8.3, EX-14.1",
  "EX-14.2": HORS("regroupement des notifications, console (tickets refusés récents du même demandeur et du même outil)"),
  "EX-A.1": "génération déterministe ; racine étrangère et --sortie sans répertoire refusées",
  "EX-A.2": "les attendus de chaque famille sont dans ses propres fichiers (acceptation-attendu.json à part)",
  "EX-A.3": "chaque famille validée par son $defs",
  "EX-A.4": "épreuve d'acceptation",
  "EX-A.5": "épreuve d'acceptation (consigne, répertoire sans attendu)",
  "EX-A.6": "chaque trace rejouée ; EX-A.6 (signatures)",
  "EX-A.7": "traces de l'annexe A.7 présentes",
  "EX-A.8": "decisions/ ; EX-A.8",
  "EX-A.9": "ce fichier",
  "EX-A.10": HORS("vérificateur Go indépendant (spec/vecteurs/ct-3/verificateur-independant), exécuté à part"),
  "EX-A.11": HORS("intégration continue (.github/workflows/ci.yml)"),
};

describe("CT-3 : matrice de couverture des règles EX-", function () {
  it("chaque règle EX- de la spécification a une entrée, et aucune entrée n'est orpheline", function () {
    const regles = [...MD.matchAll(/\*\*(EX-[0-9A]+\.[0-9]+)\*\*/g)].map((m) => m[1]);
    expect(regles.length).to.be.at.least(141);
    expect(Object.keys(COUVERTURE).sort()).to.deep.equal([...new Set(regles)].sort());
    const testables = Object.values(COUVERTURE).filter((v) => !v.startsWith("hors de cette implémentation")).length;
    expect(testables).to.be.at.least(100);
  });
});
