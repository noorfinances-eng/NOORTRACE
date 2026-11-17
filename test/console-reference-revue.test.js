// Bibliothèque de référence de la console (scripts/lib/console.mjs, CT-3
// révision 0.6) : corrections de la revue de sécurité interne de l'étape 8
// (constat EX-13.22 : uuid comparés à la casse près, actionRetrait sur l'entrée
// active, limite_annuaire ; défaut J-§7.2 : controleCanal et related_to).
//
// Chaque essai éprouve ensuite un mutant de la règle (copie de scripts/lib sous
// NOORTRACE_TMP, règle retirée, oracle en échec, copie détruite). Racine des
// scripts éprouvés : le dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { Wallet } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT3 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const lireJSON = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));

const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "console.mjs")).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-console-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  const f = path.join(racine, "scripts", "lib", "console.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

const ANNUAIRE = () => lireJSON(CT3, "annuaire", "annuaires", "reference.json");
const ICONE = "data:image/svg+xml;base64,PHN2Zy8+";
const annonce = (uuid, provider) => ({ info: { uuid, name: `Portefeuille ${uuid.slice(0, 4)}`, icon: ICONE, rdns: "com.exemple.portefeuille" }, provider });
const UUID = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

describe("CT-3, référence : découverte EIP-6963, uuid à la casse près (EX-13.22 point 3, révision 0.6)", function () {
  let K;
  before(async function () {
    K = await importer(RACINE);
  });
  const oracle = (M) => {
    // Deux objets distincts annoncent le même uuid, l'un en minuscules, l'autre en majuscules : les deux sont écartés
    // et l'uuid est exclu pour la vie de la page, quelle qu'en soit la casse.
    const r = M.decouvrir([annonce(UUID, "p1"), annonce(UUID.toUpperCase(), "p2"), annonce(UUID, "p1"), annonce(UUID.toUpperCase(), "p3")]);
    return r.providers.length === 0 && JSON.stringify(r.rejected.map((x) => [x.index, x.reason])) === JSON.stringify([[0, "annonce_en_double"], [1, "annonce_en_double"], [2, "annonce_en_double"], [3, "annonce_en_double"]]);
  };
  it("CT-3 EX-13.22 : une annonce du même uuid en majuscules par un autre objet est une annonce en double : les deux fournisseurs sont écartés et l'uuid exclu quelle que soit sa casse ; une réannonce par le même objet avec une autre casse reste sans effet", function () {
    expect(oracle(K)).to.equal(true);
    const r = K.decouvrir([annonce(UUID, "p1"), annonce(UUID.toUpperCase(), "p1")]);
    expect(r.providers.map((p) => p.provider)).to.deep.equal(["p1"]);
    expect(r.rejected).to.deep.equal([]);
    // Les cas publiés de decouverte/ gardent leur attendu.
    for (const f of fs.readdirSync(path.join(CT3, "console", "decouverte")).filter((x) => x.endsWith(".json"))) {
      const cas = lireJSON(CT3, "console", "decouverte", f);
      const res = K.decouvrir(cas.input.announcements);
      expect(res, f).to.deep.equal(cas.expected);
    }
  });
  it("mutant CT-3 EX-13.22 (uuid) : comparés tels quels, les deux uuid passent pour distincts et l'imitation en majuscules est proposée (tué par l'oracle)", async function () {
    const M = await importer(mutant("uuid", "const cle = uuid.toLowerCase();", "const cle = uuid;"));
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-3, référence : actionRetrait sur l'entrée active (EX-13.32, révision 0.6, comme EX-12.19 ; EX-13.22)", function () {
  let K;
  before(async function () {
    K = await importer(RACINE);
  });
  const avecDemandeur = () => {
    const a = ANNUAIRE();
    const e = a.entries.find((x) => x.requester_identities.length > 0) ?? a.entries[0];
    const demandeur = e.requester_identities[0] ?? "agent-essai";
    if (!e.requester_identities.includes(demandeur)) e.requester_identities.push(demandeur);
    return { a, e, demandeur };
  };
  const oracle = (M) => {
    const { a, e, demandeur } = avecDemandeur();
    const actif = M.actionRetrait(a, e.session_identity, { launched_by: demandeur });
    e.active = false;
    const inactif = M.actionRetrait(a, e.session_identity, { launched_by: demandeur });
    return actif === demandeur && inactif === null;
  };
  it("CT-3 EX-13.22 : le demandeur dont l'entrée est désactivée n'a plus l'action de retrait (null) ; l'entrée active la garde ; un administrateur la garde par son identité", function () {
    expect(oracle(K)).to.equal(true);
    const { a, e, demandeur } = avecDemandeur();
    e.active = false;
    expect(K.actionRetrait(a, a.administrators[0], { launched_by: demandeur })).to.equal(a.administrators[0]);
    // Même règle que le service sur le canal (EX-12.19) : controleCanal refuse le retrait du demandeur désactivé.
    expect(K.controleCanal(a, "retirer", { ticket: "apr-0001", by: demandeur, reason: null, session_identity: e.session_identity }, { launched_by: demandeur, eligible: [] })).to.equal("session_non_autorisee");
  });
  it("mutant CT-3 EX-13.22 (actionRetrait) : sans la condition d'entrée active, le demandeur désactivé garde l'action (tué par l'oracle)", async function () {
    const M = await importer(mutant("retrait", "if (e && e.active && e.requester_identities.includes(ticket.launched_by)) return ticket.launched_by;", "if (e && e.requester_identities.includes(ticket.launched_by)) return ticket.launched_by;"));
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-3, référence : bornes de l'annuaire, limite_annuaire (EX-13.17, révision 0.6 ; EX-13.22)", function () {
  this.timeout(60000);
  let K;
  before(async function () {
    K = await importer(RACINE);
  });
  const ADMIN = (a) => a.administrators[0];
  const T = "2026-11-13T10:00:00.000Z";
  const oracleAlias = (M) => {
    const a = ANNUAIRE();
    const e = a.entries.find((x) => x.active);
    let doc = a;
    for (let i = e.requester_identities.length; i < M.BORNES_ANNUAIRE.alias; i++) {
      const r = M.appliquerOperation(doc, "lier_demandeur", { session_identity: ADMIN(a), entry: e.id, launched_by: `agent-${i}@assureur-demo.example` }, T);
      if (!r.accepted) return false;
      doc = r.annuaire;
    }
    const refus = M.appliquerOperation(doc, "lier_demandeur", { session_identity: ADMIN(a), entry: e.id, launched_by: "agent-de-trop@assureur-demo.example" }, T);
    return refus.accepted === false && refus.reason === "limite_annuaire" && JSON.stringify(refus.annuaire) === JSON.stringify(doc) && doc.entries.find((x) => x.id === e.id).requester_identities.length === M.BORNES_ANNUAIRE.alias;
  };
  it("CT-3 EX-13.22 : le 65e alias de demandeur d'une entrée est refusé limite_annuaire et l'annuaire ne change pas ; les 64 premiers sont acceptés ; un refus antérieur de la ligne (demandeur_deja_lie) passe avant la borne", function () {
    expect(K.BORNES_ANNUAIRE).to.deep.equal({ entrees: 10000, adresses: 64, alias: 64 });
    expect(oracleAlias(K)).to.equal(true);
    const a = ANNUAIRE();
    const e = a.entries.find((x) => x.active && x.requester_identities.length > 0);
    const r = K.appliquerOperation(a, "lier_demandeur", { session_identity: ADMIN(a), entry: e.id, launched_by: e.requester_identities[0] }, T);
    expect(r.reason).to.equal("demandeur_deja_lie");
  });
  it("CT-3 EX-13.22 : un inscrire qui créerait la 65e adresse d'une entrée, ou la 10 001e entrée, est refusé limite_annuaire après les pas d'EX-13.15 (signature valide) ; le défi présenté est retiré (EX-13.13, complément du 2026-11-16) ; l'annuaire ne change pas ; une signature fausse est refusée pour sa propre raison, avant la borne", async function () {
    const portefeuille = Wallet.createRandom();
    const adresse = portefeuille.address.toLowerCase();
    const inscrire = async (annuaire, identite) => {
      const prep = K.appliquerOperation(annuaire, "preparer_inscription", { session_identity: identite, address: adresse }, T, { nonce: "0123456789abcdef0123456789abcdef" });
      expect(prep.accepted, "preparer_inscription").to.equal(true);
      const signature = await portefeuille.signMessage(prep.response.message);
      return { prep, r: K.appliquerOperation(annuaire, "inscrire", { session_identity: identite, address: adresse, message: prep.response.message, signature }, T, { defis: prep.defis, identifiant: "compteur" }) };
    };
    // 64 adresses déjà attribuées à l'entrée (adresses fictives distinctes, en_attente).
    const a = ANNUAIRE();
    const e = a.entries.find((x) => x.active);
    for (let i = e.addresses.length; i < K.BORNES_ANNUAIRE.adresses; i++) e.addresses.push({ address: `0x${String(i).padStart(2, "0")}${"00".repeat(19)}`, state: "en_attente", proof: null, validated_at: null, validated_by: null, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null, replaced_by: null });
    const { prep, r } = await inscrire(a, e.session_identity);
    expect(r.accepted).to.equal(false);
    expect(r.reason).to.equal("limite_annuaire");
    expect(JSON.stringify(r.annuaire)).to.equal(JSON.stringify(a));
    expect(r.defis.some((d) => d.fields.identity === e.session_identity && d.fields.address === adresse)).to.equal(false);
    const faux = K.appliquerOperation(a, "inscrire", { session_identity: e.session_identity, address: adresse, message: prep.response.message, signature: "0x" + "11".repeat(65) }, T, { defis: prep.defis });
    expect(faux.accepted).to.equal(false);
    expect(faux.reason).to.not.equal("limite_annuaire");
    // La 10 001e entrée.
    const b = ANNUAIRE();
    for (let i = b.entries.length; i < K.BORNES_ANNUAIRE.entrees; i++) b.entries.push({ ...structuredClone(b.entries[0]), id: `apb-${String(i).padStart(4, "0")}`, session_identity: `oidc https://idp.assureur-demo.example personne-${i}`, requester_identities: [], addresses: [] });
    expect(b.entries).to.have.length(10000);
    const { r: r2 } = await inscrire(b, "oidc https://idp.assureur-demo.example nouvelle");
    expect(r2.accepted).to.equal(false);
    expect(r2.reason).to.equal("limite_annuaire");
    expect(r2.annuaire.entries).to.have.length(10000);
    // Sous la borne, la même inscription est acceptée.
    const c = ANNUAIRE();
    const { r: r3 } = await inscrire(c, "oidc https://idp.assureur-demo.example nouvelle");
    expect(r3.accepted, JSON.stringify(r3.reason)).to.equal(true);
  });
  it("mutant CT-3 EX-13.22 (limite_annuaire) : sans la borne des alias, le 65e est accepté (tué par l'oracle)", async function () {
    const M = await importer(mutant("alias", 'if (e.requester_identities.length >= BORNES_ANNUAIRE.alias) return refus("limite_annuaire");\n', ""));
    expect(oracleAlias(M)).to.equal(false);
  });
});

describe("CT-3, référence : controleCanal et related_to (EX-12.21, EX-12.14 ; J-§7.2)", function () {
  let K;
  let canal;
  before(async function () {
    K = await importer(RACINE);
    canal = lireJSON(CT3, "annuaire", "controles-canal.json");
  });
  const oracle = (M) => {
    const a = lireJSON(CT3, "annuaire", canal.annuaire);
    const consulter = canal.cases.filter((c) => c.method === "consulter");
    // Avec related_to, tickets rend pour chaque session la raison que consulter rend sur le même ticket.
    return consulter.length > 0 && consulter.every((c) => M.controleCanal(a, "tickets", { session_identity: c.request.session_identity, related_to: c.request.ticket }, c.ticket) === c.expected.reason);
  };
  it("J-§7.2 : tickets avec related_to applique au ticket désigné l'ordre des refus de consulter (session hors de l'organisation, ticket inconnu, session qui ne voit pas les arguments) ; sans related_to, le point 1 seul ; les cas publiés de controles-canal.json gardent leur attendu", function () {
    expect(oracle(K)).to.equal(true);
    const a = lireJSON(CT3, "annuaire", canal.annuaire);
    for (const c of canal.cases) expect(K.controleCanal(a, c.method, c.request, c.ticket), c.id).to.equal(c.expected.reason);
    const tickets = canal.cases.filter((c) => c.method === "tickets" && c.expected.reason === null);
    expect(tickets.length).to.be.greaterThan(0);
    for (const c of tickets) {
      expect(K.controleCanal(a, "tickets", { ...c.request, related_to: "apr-9999" }, null), `${c.id} + related_to inconnu`).to.equal("ticket_inconnu");
      expect(K.controleCanal(a, "tickets", { ...c.request, related_to: null }, null), `${c.id} + related_to nul`).to.equal(null);
    }
  });
  it("mutant J-§7.2 : controleCanal qui ignore related_to rend null pour un ticket désigné inconnu (tué par l'oracle)", async function () {
    const M = await importer(mutant("related", 'if (methode === "tickets" && (requete.related_to === undefined || requete.related_to === null)) return null;', 'if (methode === "tickets") return null;'));
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-3, référence : bornes des défis non expirés de preparer_inscription (EX-13.13, révision 0.8)", function () {
  this.timeout(120000);
  let K;
  before(async function () {
    K = await importer(RACINE);
  });
  const T = "2026-11-13T10:00:00.000Z";
  const identite = (i) => `oidc https://idp.assureur-demo.example demandeur-${i}`;
  const adresse = (i) => `0x${"ab".repeat(18)}${i.toString(16).padStart(4, "0")}`;
  const nonce = (i) => i.toString(16).padStart(32, "0");
  const preparer = (M, annuaire, defis, id, adr, k) => M.appliquerOperation(annuaire, "preparer_inscription", { session_identity: id, address: adr }, T, { defis, nonce: nonce(k) });
  /** Un défi expiré de la même identité, qui ne compte pas dans la borne. */
  const expire = { fields: { origin: "https://console.assureur-demo.example", org: "x", org_id: "0x" + "00".repeat(32), identity: identite(1), address: adresse(900), issued_at: "2026-11-13T09:00:00.000Z", expires_at: "2026-11-13T09:10:00.000Z", nonce: nonce(9000) }, used: false };
  // Quatre défis non expirés d'une identité ; le cinquième est refusé limite_annuaire, les défis inchangés ; le remplacement du
  // défi de la même identité et de la même adresse est admis et ne compte pas ; une autre identité est admise.
  const oracleParIdentite = (M) => {
    const a = ANNUAIRE();
    let defis = [expire];
    for (let i = 1; i <= 4; i++) {
      const r = preparer(M, a, defis, identite(1), adresse(i), i);
      if (!r.accepted) return false;
      defis = r.defis;
    }
    const refus = preparer(M, a, defis, identite(1), adresse(5), 5);
    if (refus.accepted || refus.reason !== "limite_annuaire" || JSON.stringify(refus.defis) !== JSON.stringify(defis) || JSON.stringify(refus.annuaire) !== JSON.stringify(a)) return false;
    const remplacement = preparer(M, a, defis, identite(1), adresse(2), 6);
    if (!remplacement.accepted || remplacement.defis.length !== defis.length || !remplacement.defis.some((d) => d.fields.nonce === nonce(6))) return false;
    return preparer(M, a, defis, identite(2), adresse(7), 7).accepted === true;
  };
  // 1 024 défis non expirés au total (256 identités, 4 adresses chacune) ; le 1 025e est refusé limite_annuaire.
  const oracleTotal = (M) => {
    const a = ANNUAIRE();
    let defis = [expire];
    let k = 10;
    for (let i = 1; i <= 256; i++) for (let j = 1; j <= 4; j++) {
      const r = preparer(M, a, defis, identite(i), adresse(k), k);
      if (!r.accepted) return false;
      defis = r.defis;
      k++;
    }
    if (defis.filter((d) => d.fields.nonce !== expire.fields.nonce).length !== 1024) return false;
    const refus = preparer(M, a, defis, identite(257), adresse(k), k);
    return refus.accepted === false && refus.reason === "limite_annuaire" && refus.defis.length === defis.length;
  };
  it("CT-3 EX-13.13 : le cinquième défi non expiré d'une identité est refusé limite_annuaire, les défis inchangés ; un défi expiré ne compte pas ; le remplacement du défi de la même identité et de la même adresse est admis ; BORNES_DEFIS vaut { par_identite: 4, total: 1024 }", function () {
    expect(K.BORNES_DEFIS).to.deep.equal({ par_identite: 4, total: 1024 });
    expect(oracleParIdentite(K)).to.equal(true);
  });
  it("CT-3 EX-13.13 : le 1 025e défi non expiré, toutes identités confondues, est refusé limite_annuaire", function () {
    expect(oracleTotal(K)).to.equal(true);
  });
  it("mutant CT-3 EX-13.13 (par identité) : sans la borne par identité, le cinquième défi est accepté (tué par l'oracle)", async function () {
    const M = await importer(mutant("defis-identite", "if (vivants.filter((d) => d.fields.identity === session).length >= BORNES_DEFIS.par_identite || vivants.length >= BORNES_DEFIS.total) return refus(\"limite_annuaire\");", "if (vivants.length >= BORNES_DEFIS.total) return refus(\"limite_annuaire\");"));
    expect(oracleParIdentite(M)).to.equal(false);
  });
  it("mutant CT-3 EX-13.13 (total) : sans la borne totale, le 1 025e défi est accepté (tué par l'oracle)", async function () {
    const M = await importer(mutant("defis-total", "if (vivants.filter((d) => d.fields.identity === session).length >= BORNES_DEFIS.par_identite || vivants.length >= BORNES_DEFIS.total) return refus(\"limite_annuaire\");", "if (vivants.filter((d) => d.fields.identity === session).length >= BORNES_DEFIS.par_identite) return refus(\"limite_annuaire\");"));
    expect(oracleTotal(M)).to.equal(false);
  });
});
