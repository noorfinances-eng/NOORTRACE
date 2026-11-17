// Annuaire des approbateurs : rejeu d'un annuaire exporté et entrées échues
// (CT-3 EX-13.17, EX-13.19 points 2 et 6, EX-13.32, A.10 ; complément du
// 2026-11-16). Chaque règle est jouée sur la bibliothèque de référence
// (`scripts/lib/console.mjs`) et sur le module d'annuaire qu'exécute le
// service (`@noortrace/console/annuaire`) :
//   - un instant d'opération qui respecte le motif sans se décoder (CT-1 §3)
//     est un écart `revision_incoherente` à son pointeur (point 2) ;
//   - la preuve d'une inscription rejouée est reconstruite comme EX-13.15
//     l'inscrit (signature normalisée, nonce et instants du message,
//     `received_at` égal à l'instant de l'opération) : un document qui en
//     porte une autre aboutit à d'autres entrées (point 6, révision 0.6) ;
//   - une inscription dont l'entrée est retirée par une opération `expirer`
//     placée plus loin dans le journal se rejoue sans preuve, même si le
//     document porte encore l'entrée ; une opération `expirer` placée plus
//     haut a déjà retiré l'entrée, et l'inscription qui la recréerait ne se
//     rejoue pas (point 6) ;
//   - une entrée dont `created_at` ne se décode pas n'est jamais échue
//     (`expirer` : `etat_incompatible`) ;
//   - dans les traces publiées, aucune entrée n'est échue avant un pas, sauf
//     l'entrée d'un pas `expirer` accepté, seule (A.10).
// La référence est lue dans le dépôt, ou sous NOORTRACE_REVUE_RACINE (code
// d'avant : essai rouge). Chaque règle retirée de la référence (copie sous
// NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin) fait échouer son cas
// (mutant tué).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as A from "@noortrace/approbation";
import * as B from "@noortrace/console/annuaire";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const ANNUAIRE = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3", "annuaire");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(ANNUAIRE, ...p), "utf8"));
const copie = (x) => JSON.parse(JSON.stringify(x));
const conforme = (d) => A.annuaireConforme(d);
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const COPIES = [];

const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "console.mjs")).href + `?t=${Date.now()}-${Math.random()}`);

/** La référence de RACINE, un remplacement unique appliqué (copie sous TMP). */
async function mutant(nom, ancien, nouveau) {
  const rep = fs.mkdtempSync(path.join(TMP, `noortrace-annuaire-rejeu-${nom}-`));
  COPIES.push(rep);
  const texte = fs.readFileSync(path.join(RACINE, "scripts", "lib", "console.mjs"), "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien.slice(0, 120)} » trouvé ${n} fois`);
  fs.mkdirSync(path.join(rep, "scripts", "lib"), { recursive: true });
  fs.writeFileSync(path.join(rep, "scripts", "lib", "console.mjs"), texte.replace(ancien, () => nouveau));
  return reference(rep);
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

// -------------------------------------------------------------------------
// Cas, chacun avec ses écarts attendus (EX-13.19).
// -------------------------------------------------------------------------

const ILLISIBLE = "2026-02-30T08:00:30.000Z";

/** Point 2 : instant de l'opération 1 et created_at de son entrée au 30 février (motif respecté, instant indécodable). */
function instantIndecodable() {
  const d = copie(lire("exports", "reference.json"));
  d.operations[0].at = ILLISIBLE;
  d.entries[0].created_at = ILLISIBLE;
  return d;
}

/** Point 6 (révision 0.6) : la preuve du compte 1 porte un received_at d'une seconde après l'opération. */
function receptionDecalee() {
  const d = copie(lire("exports", "reference.json"));
  const p = d.entries[0].addresses[0].proof;
  p.received_at = new Date(Date.parse(p.received_at) + 1000).toISOString();
  return d;
}

/** Point 6 (révision 0.6) : la preuve du compte 1 porte la signature sous sa forme s haut (point 4 : preuve_invalide). */
function signatureSHaut() {
  const d = copie(lire("exports", "reference.json"));
  const p = d.entries[0].addresses[0].proof;
  const s = BigInt("0x" + p.signature.slice(66, 130));
  const v = p.signature.slice(130) === "1b" ? "1c" : "1b";
  p.signature = p.signature.slice(0, 66) + (N - s).toString(16).padStart(64, "0") + v;
  return d;
}

const CAS_EXPORTS = [
  [
    "EX-13.19, point 2 : un instant d'opération qui respecte le motif sans se décoder (CT-1 §3) est revision_incoherente à son pointeur",
    instantIndecodable,
    [{ code: "operations_incoherentes", pointer: "/entries" }, { code: "revision_incoherente", pointer: "/operations/0/at" }],
  ],
  [
    "EX-13.19, point 6 (révision 0.6) : la preuve rejouée porte received_at égal à l'instant de l'opération ; un autre received_at donne d'autres entrées",
    receptionDecalee,
    [{ code: "operations_incoherentes", pointer: "/entries" }],
  ],
  [
    "EX-13.19, point 6 (révision 0.6) : la preuve rejouée porte la signature normalisée ; une preuve en s haut est preuve_invalide et donne d'autres entrées",
    signatureSHaut,
    [{ code: "operations_incoherentes", pointer: "/entries" }, { code: "preuve_invalide", pointer: "/entries/0/addresses/0/proof" }],
  ],
];

/** Entrée d'identité inventée, jamais validée, créée à `cree`. */
const entreeEnAttente = (cree) => ({
  id: "apb-0009", session_identity: "oidc https://idp.assureur-demo.example approbateur-9", external_id: null, display_name: null, active: true, requester_identities: [], created_at: cree,
  addresses: [{ address: "0x" + "ab".repeat(20), state: "en_attente", proof: { message: "x", signature: "0x", nonce: "0".repeat(32), issued_at: cree, expires_at: cree, received_at: cree }, validated_at: null, validated_by: null, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null, replaced_by: null }],
});

function verifierBibliotheque(nom, charger) {
  describe(`annuaire, ${nom} : rejeu d'un annuaire exporté et entrées échues (complément du 2026-11-16)`, function () {
    this.timeout(60000);
    let L;
    before(async function () {
      L = await charger();
    });

    for (const [titre, doc, attendu] of CAS_EXPORTS) {
      it(titre, function () {
        const d = doc();
        expect(conforme(d), "document conforme au schéma").to.equal(true);
        expect(L.verifierAnnuaireExporte(d, { conforme })).to.deep.equal(attendu);
      });
    }

    it("EX-13.19, point 6 : l'inscription d'une entrée retirée par un expirer placé plus loin se rejoue sans preuve, même si le document porte encore l'entrée (/entries, non /operations/0)", function () {
      const d = copie(lire("exports", "expiration-entree-portee.json"));
      expect(L.verifierAnnuaireExporte(d, { conforme })).to.deep.equal(lire("exports", "attendu.json").cases.find((c) => c.file === "expiration-entree-portee.json").errors);
      expect(L.verifierAnnuaireExporte(d, { conforme })).to.deep.equal([{ code: "operations_incoherentes", pointer: "/entries" }, { code: "preuve_invalide", pointer: "/entries/0/addresses/0/proof" }]);
    });

    it("EX-13.19, point 6 : un expirer placé plus haut que l'inscription de la même entrée l'a déjà retirée ; l'inscription qui la recréerait ne se rejoue pas", function () {
      const d = copie(lire("exports", "expiration-rejouee.json"));
      const j = d.operations.findIndex((o) => o.op === "expirer");
      const reinscription = d.operations.findIndex((o, k) => k > j && o.op === "inscrire");
      d.operations[reinscription].entry = d.operations[j].entry;
      d.entries.find((e) => e.id === "apb-0003").id = d.operations[j].entry;
      expect(L.verifierAnnuaireExporte(d, { conforme })).to.deep.equal([{ code: "operations_incoherentes", pointer: `/operations/${reinscription}` }]);
    });

    it("EX-13.17, A.10 : une entrée dont created_at ne se décode pas n'est jamais échue (expirer : etat_incompatible ; expirerEntrees la laisse)", function () {
      const d = copie(lire("annuaires", "vide.json"));
      d.entries.push(entreeEnAttente("2026-02-30T08:00:00.000Z"));
      const loin = "2036-01-01T00:00:00.000Z";
      expect(L.appliquerOperation(d, "expirer", { entry: "apb-0009" }, loin).reason).to.equal("etat_incompatible");
      expect(L.expirerEntrees(d, loin).expirees).to.deep.equal([]);
      // la même entrée, created_at lisible : échue
      const lisible = copie(d);
      lisible.entries[0].created_at = "2026-02-28T08:00:00.000Z";
      expect(L.appliquerOperation(lisible, "expirer", { entry: "apb-0009" }, loin).accepted).to.equal(true);
      expect(L.expirerEntrees(lisible, loin).expirees).to.deep.equal(["apb-0009"]);
    });

    it("A.10 : dans chaque trace publiée, aucune entrée n'est échue avant un pas, sauf l'entrée d'un pas expirer accepté, seule", function () {
      const traces = fs.readdirSync(path.join(ANNUAIRE, "traces")).filter((f) => f.endsWith(".json")).sort();
      let expirations = 0;
      for (const f of traces) {
        const t = lire("traces", f);
        let doc = lire(t.initial);
        let defis = [];
        for (const [i, p] of t.steps.entries()) {
          const attendu = p.method === "expirer" && p.expected.accepted ? [p.request.entry] : [];
          expect(L.expirerEntrees(doc, p.at).expirees, `${f} pas ${i + 1} (${p.method})`).to.deep.equal(attendu);
          expirations += attendu.length;
          const r = L.appliquerOperation(doc, p.method, p.request, p.at, { defis, identifiant: "compteur", ...(p.challenges.length ? { nonce: p.challenges[0] } : {}) });
          expect([r.accepted, r.reason], `${f} pas ${i + 1}`).to.deep.equal([p.expected.accepted, p.expected.reason]);
          doc = r.annuaire;
          defis = r.defis;
        }
      }
      expect(expirations).to.be.at.least(1);
    });
  });
}

verifierBibliotheque("bibliothèque de référence (scripts/lib/console.mjs)", () => reference(RACINE));
verifierBibliotheque("module d'annuaire du service (@noortrace/console/annuaire)", async () => B);

describe("annuaire, bibliothèque de référence : chaque règle retirée fait échouer son cas (mutants)", function () {
  this.timeout(60000);
  const MUTANTS = [
    ["instant-indecodable", "if (Number.isNaN(t) || t < precedent) ecart(", instantIndecodable, "if (t < precedent) ecart("],
    ["reception", "received_at: op.at };", receptionDecalee, "received_at: source.proof.received_at };"],
    ["signature-normalisee", "signature: verif.signature,", signatureSHaut, "signature: source.proof.signature,"],
  ];
  for (const [nom, ancien, doc, nouveau] of MUTANTS) {
    it(`mutant ${nom} : la référence s'écarte de l'attendu`, async function () {
      const attendu = CAS_EXPORTS.find(([, d]) => d === doc)[2];
      const M = await mutant(nom, ancien, nouveau);
      expect(M.verifierAnnuaireExporte(doc(), { conforme })).not.to.deep.equal(attendu);
    });
  }
  it("mutant preuve-du-document : l'inscription d'une entrée encore portée par le document y cherche sa preuve (/operations/0)", async function () {
    const M = await mutant("preuve-du-document", "if (etat.expirees.has(op.entry)) {", "if (etat.expirees.has(op.entry) && !doc.entries.some((x) => x.id === op.entry)) {");
    expect(M.verifierAnnuaireExporte(lire("exports", "expiration-entree-portee.json"), { conforme })).to.deep.equal([{ code: "preuve_invalide", pointer: "/entries/0/addresses/0/proof" }, { code: "operations_incoherentes", pointer: "/operations/0" }]);
  });
  it("mutant created-at-illisible : une entrée au created_at indécodable tenue pour échue", async function () {
    const M = await mutant("created-at-illisible", "return !e.addresses.some((a) => a.validated_at !== null) && msHorodatage(at) >= msHorodatage(e.created_at) + ttl;", "return !e.addresses.some((a) => a.validated_at !== null) && !(msHorodatage(at) < msHorodatage(e.created_at) + ttl);");
    const d = copie(lire("annuaires", "vide.json"));
    d.entries.push(entreeEnAttente("2026-02-30T08:00:00.000Z"));
    expect(M.expirerEntrees(d, "2036-01-01T00:00:00.000Z").expirees).to.deep.equal(["apb-0009"]);
  });
});
