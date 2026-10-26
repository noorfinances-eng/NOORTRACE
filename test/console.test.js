import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { Signature, Wallet, decryptKeystoreJsonSync, getBytes, hashMessage, keccak256, recoverAddress, toUtf8Bytes } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as K from "../scripts/lib/console.mjs";
import { COMPTES, ADR, genererCt3, validateurSchemas } from "../scripts/vecteurs/generer-ct3.mjs";
import { empreintesConsole } from "../scripts/console/empreintes.mjs";

// CONSOLE DE RÉFÉRENCE DE CT-3 (spec/CT-3-approbations.md, révision 0.3,
// 13.15, annexes A.10 et A.11) : bibliothèque scripts/lib/console.mjs, page
// console/ et vecteurs annuaire/ et console/.
//
// Partie Node, toujours exécutée : régénération des familles annuaire/ et
// console/ et égalité des octets, validation de chaque fichier par son $defs,
// rejeu de chaque cas par console.mjs, concordance des primitives avec
// node:crypto, ethers et journal.mjs, propriétés statiques de la
// bibliothèque et de la page (EX-13.32 à EX-13.35).
//
// Partie Chromium (EX-13.36) : Playwright, chargé par createRequire (il est
// installé hors du dépôt) ; la page est servie par un serveur local sur
// 127.0.0.1 (port libre) qui simule le serveur de console et le service, et
// le navigateur la charge depuis l'origine HTTPS fictive des vecteurs
// (https://console.assureur-demo.example), chaque requête de cette origine
// étant relayée par interception vers le serveur local ; toute autre origine
// est refusée et comptée. Un fournisseur EIP-1193 gelé, annoncé par EIP-6963,
// signe dans Node avec les clés de test de A.2. Si Playwright ou Chromium ne
// se chargent pas, ces tests sont sautés avec la raison, sauf sous
// NOORTRACE_EXIGER_CHROMIUM=1 (travail console-chromium de l'intégration
// continue, EX-13.36), où ils échouent ; aucun navigateur n'est installé.

const CT3 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3");
const MD = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-3-approbations.md"), "utf8");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(CT3, ...p), "utf8"));
const fichiers = (...p) => fs.readdirSync(path.join(CT3, ...p)).filter((f) => f.endsWith(".json")).sort();
const valider = validateurSchemas();
const conforme = (doc) => valider(doc, "annuaire-approbateurs", null).length === 0;
const avant = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const ORIGINE = "https://console.assureur-demo.example";

function lister(racine, rel = "") {
  const out = [];
  for (const e of fs.readdirSync(path.join(racine, rel), { withFileTypes: true }).sort((a, b) => avant(a.name, b.name))) {
    const r = path.join(rel, e.name);
    if (e.isDirectory()) out.push(...lister(racine, r));
    else out.push(r);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Partie Node
// ---------------------------------------------------------------------------

describe("CT-3 0.3 : vecteurs annuaire/ et console/ (EX-A.12 à EX-A.17)", function () {
  this.timeout(120_000);

  it("régénérés dans un répertoire temporaire : mêmes octets que spec/vecteurs/ct-3 pour annuaire/, console/ et l'épreuve de lecture ; deux générations identiques", function () {
    const a = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct3-console-a-"));
    const b = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ct3-console-b-"));
    try {
      genererCt3({ racine: a });
      genererCt3({ racine: b });
      for (const entree of ["annuaire", "console", "acceptation-console"]) {
        const fa = lister(path.join(a, entree));
        expect(fa, entree).to.deep.equal(lister(path.join(CT3, entree)));
        expect(fa, entree).to.deep.equal(lister(path.join(b, entree)));
        for (const f of fa) {
          const o = fs.readFileSync(path.join(a, entree, f));
          expect(o.equals(fs.readFileSync(path.join(b, entree, f))), f).to.equal(true);
          expect(o.equals(fs.readFileSync(path.join(CT3, entree, f))), `${entree}/${f}`).to.equal(true);
        }
      }
      expect(fs.readFileSync(path.join(a, "acceptation-console-attendu.json")).equals(fs.readFileSync(path.join(CT3, "acceptation-console-attendu.json")))).to.equal(true);
    } finally {
      fs.rmSync(a, { recursive: true, force: true });
      fs.rmSync(b, { recursive: true, force: true });
    }
  });

  it("EX-A.3, EX-A.16 : chaque fichier est conforme à sa définition (annuaire-approbateurs-v0, console-approbation-v0)", function () {
    for (const f of fichiers("annuaire", "annuaires")) expect(valider(lire("annuaire", "annuaires", f), "annuaire-approbateurs"), f).to.deep.equal([]);
    for (const [f, def] of [["messages.json", "fichier_messages"], ["inscriptions.json", "fichier_inscriptions"], ["domaines.json", "fichier_domaines"], ["controles-vote.json", "fichier_controles_vote"], ["controles-canal.json", "fichier_controles_canal"]]) expect(valider(lire("annuaire", f), "annuaire-approbateurs", def), f).to.deep.equal([]);
    for (const f of fichiers("annuaire", "traces")) expect(valider(lire("annuaire", "traces", f), "annuaire-approbateurs", "trace_annuaire"), f).to.deep.equal([]);
    const exports = lire("annuaire", "exports", "attendu.json");
    expect(valider(exports, "annuaire-approbateurs", "attendu_exports")).to.deep.equal([]);
    for (const c of exports.cases) expect(conforme(lire("annuaire", "exports", c.file)), c.file).to.equal(c.errors[0]?.code !== "schema");
    for (const [rep, def] of [["modeles", "cas_modele"], ["requetes", "cas_requete"], ["reponses", "cas_reponse"], ["decouverte", "cas_decouverte"], ["fichiers-cle", "cas_fichier_cle"]]) {
      expect(fichiers("console", rep).length, rep).to.be.at.least(5);
      for (const f of fichiers("console", rep)) expect(valider(lire("console", rep, f), "console-approbation", def), `${rep}/${f}`).to.deep.equal([]);
    }
    expect(valider(lire("acceptation-console-attendu.json"), "console-approbation", "attendu_acceptation_console")).to.deep.equal([]);
  });

  it("EX-A.17 : le répertoire remis aux lecteurs ne contient que la consigne et le gabarit ; la grille cite des règles de CT-3 et couvre chaque question", function () {
    expect(fs.readdirSync(path.join(CT3, "acceptation-console")).sort()).to.deep.equal(["consigne.md", "gabarit-reponse.md"]);
    const regles = new Set([...MD.matchAll(/\*\*(EX-[0-9A]+\.[0-9]+)\*\*/g)].map((m) => m[1]));
    const grille = lire("acceptation-console-attendu.json");
    expect(grille.roles.map((r) => [r.role, r.sections, r.questions.length])).to.deep.equal([["approbateur", ["9", "13"], 4], ["integrateur", ["7.4", "9", "12", "13"], 2]]);
    const consigne = fs.readFileSync(path.join(CT3, "acceptation-console", "consigne.md"), "utf8").replace(/\s+/g, " ");
    for (const r of grille.roles) for (const q of r.questions) {
      expect(consigne, q.question).to.include(q.question);
      for (const e of q.elements) for (const regle of e.rules) expect(regles.has(regle), regle).to.equal(true);
    }
    expect(consigne).not.to.match(/EX-9\.20|empreinte_divergente/);
  });
});

describe("CT-3 0.3 : annuaire/ rejoué par console.mjs (AN-1 à AN-10)", function () {
  const annuaire = (rel) => lire("annuaire", ...rel.split("/"));

  it("EX-13.9, A.10 : annuaires/reference.json est l'exemple de 13.4 (même valeur JSON) et n'a aucun écart d'export ; vide.json n'a ni entrée ni opération", function () {
    const ref = annuaire("annuaires/reference.json");
    const exemple = /<!-- schema: annuaire-approbateurs -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1];
    expect(ref).to.deep.equal(JSON.parse(exemple));
    expect(K.verifierAnnuaireExporte(ref, { conforme })).to.deep.equal([]);
    expect(annuaire("annuaires/vide.json")).to.include({ revision: 0, updated_at: null });
  });

  it("AN-1, AN-2 (EX-13.7, EX-13.12) : messages.json — texte exact depuis les champs, octets, condensé EIP-191, préimage ; toute variante refusée", function () {
    for (const c of annuaire("messages.json").cases) {
      expect(K.mesuresMessage(c.message), c.id).to.deep.equal({ length: c.expected.length, personal_sign_data: c.expected.personal_sign_data, eip191_digest: c.expected.eip191_digest, preimage_length: c.expected.preimage_length });
      expect(c.expected.eip191_digest, c.id).to.equal(hashMessage(toUtf8Bytes(c.message)));
      if (c.expected.valid) {
        expect(K.messageInscription(c.fields), c.id).to.equal(c.message);
        expect(K.analyserMessageInscription(c.message), c.id).to.deep.equal(c.expected.fields);
      } else expect(() => K.analyserMessageInscription(c.message), c.id).to.throw(K.ErreurConsole).with.property("code", "message_invalide");
    }
    // Exemple d'EX-13.12 : 516 octets, préimage de 545 octets.
    const m1 = annuaire("messages.json").cases.find((c) => c.id === "message-compte-1");
    expect([m1.expected.length, m1.expected.preimage_length, m1.expected.eip191_digest]).to.deep.equal([516, 545, "0xaf9b14a62489fc34643813436d932180470bbfa1cb197aea3de5fe54f871c5ef"]);
  });

  it("AN-1 (EX-13.7) : identité canonique — oidc et utilisateur, longueur, caractères, émetteur sans « ? » ni « # »", function () {
    expect(K.identiteCanonique({ kind: "oidc", iss: "https://idp.assureur-demo.example", sub: "approbateur-1" })).to.equal("oidc https://idp.assureur-demo.example approbateur-1");
    expect(K.identiteCanonique({ kind: "utilisateur", domain: "ldap.assureur-demo.example", name: "u12345" })).to.equal("utilisateur ldap.assureur-demo.example u12345");
    expect(K.analyserIdentite("oidc https://idp.example a")).to.deep.equal({ kind: "oidc", iss: "https://idp.example", sub: "a" });
    for (const mauvaise of ["oidc http://idp.example a", "oidc https://idp.example?x a", "oidc https://idp.example#f a", "oidc https://idp.example a b", "oidc https://idp.example", "oidc https://idp.example sujét", "approbateur-1@assureur-demo.example", `oidc https://idp.example ${"s".repeat(256)}`, `utilisateur ${"d".repeat(129)} n`, `oidc https://${"i".repeat(200)} ${"s".repeat(60)}`])
      expect(() => K.analyserIdentite(mauvaise), mauvaise).to.throw(K.ErreurConsole).with.property("code", "identite_invalide");
    expect(K.estIdentite(`oidc https://i ${"s".repeat(241)}`)).to.equal(true);
    expect(K.estIdentite(`oidc https://i ${"s".repeat(242)}`)).to.equal(false);
  });

  it("AN-3, AN-4, AN-7 (EX-13.13, EX-13.15) : inscriptions.json — chaque raison dans l'ordre, défi présenté dès le pas 4, signature gardée normalisée", function () {
    const doc = annuaire("inscriptions.json");
    const depart = annuaire(doc.annuaire);
    for (const c of doc.cases) {
      const r = K.verifierInscription(depart, c.challenges, c.request, c.received_at, { identifiant: "compteur" });
      expect({ accepted: r.accepted, reason: r.reason, entry: r.entry, signature: r.signature }, c.id).to.deep.equal(c.expected);
      if (c.expected.accepted) {
        expect(recoverAddress(hashMessage(toUtf8Bytes(c.request.message)), c.expected.signature).toLowerCase(), c.id).to.equal(c.request.address);
        const app = K.appliquerOperation(depart, "inscrire", c.request, c.received_at, { defis: c.challenges, identifiant: "compteur" });
        expect(app.response, c.id).to.deep.equal({ entry: c.expected.entry, address: c.request.address, state: "en_attente", revision: depart.revision + 1 });
        expect(app.annuaire.entries.find((e) => e.id === c.expected.entry).addresses.at(-1).proof.signature, c.id).to.equal(c.expected.signature);
        expect(app.defis.find((d) => d.used)?.fields.nonce, c.id).to.equal(K.analyserMessageInscription(c.request.message).nonce);
      }
    }
    const raisons = new Set(doc.cases.map((c) => c.expected.reason));
    for (const r of ["identite_invalide", "message_invalide", "nonce_inconnu", "nonce_deja_utilise", "inscription_expiree", "origine_differente", "organisation_differente", "identite_differente", "adresse_differente", "signature_invalide", "identite_desactivee", "adresse_deja_attribuee"]) expect(raisons.has(r), r).to.equal(true);
  });

  it("AN-5 (EX-13.16) : domaines.json — une signature d'inscription n'est pas un vote, une signature de vote n'est pas une inscription ; préimages de 60 et d'au moins 468 octets", function () {
    for (const c of annuaire("domaines.json").cases) {
      const octets = c.kind === "inscription_comme_vote" ? getBytes(K.condenses(c.A).d_a) : K.utf8(c.message);
      const v = K.verifierSignature(octets, c.signature, c.claimed_address);
      expect([v.ok, v.recovered], c.id).to.deep.equal([false, c.expected.recovered]);
      expect(v.recovered).not.to.equal(c.claimed_address);
    }
    expect(K.preimageEIP191(new Uint8Array(32)).length).to.equal(60);
    const plusCourt = annuaire("messages.json").cases.filter((c) => c.expected.valid).map((c) => c.expected.preimage_length);
    expect(Math.min(...plusCourt)).to.be.at.least(468);
  });

  it("AN-6, AN-7 (EX-13.10, EX-13.17, EX-12.17) : chaque trace rejouée redonne sort, raison, réponse, revision et état résumé, pas à pas", function () {
    const traces = fichiers("annuaire", "traces");
    expect(traces.length).to.be.at.least(9);
    for (const f of traces) {
      const t = annuaire(`traces/${f}`);
      let doc = annuaire(t.initial);
      let defis = [];
      for (const [i, p] of t.steps.entries()) {
        const r = K.appliquerOperation(doc, p.method, p.request, p.at, { defis, nonce: p.challenges[0] ?? null, identifiant: "compteur" });
        expect({ accepted: r.accepted, reason: r.reason, response: r.response, revision: r.annuaire.revision, entries: K.resumeEntrees(r.annuaire) }, `${f} pas ${i + 1}`).to.deep.equal(p.expected);
        if (!r.accepted) expect(r.annuaire, `${f} pas ${i + 1} : un refus ne change pas l'annuaire`).to.deep.equal(doc);
        // EX-13.10 : une adresse dans une seule entrée, au plus une adresse active par entrée, une entrée par identité, alias uniques.
        const adresses = r.annuaire.entries.flatMap((e) => e.addresses.map((a) => a.address));
        expect(new Set(adresses).size).to.equal(adresses.length);
        for (const e of r.annuaire.entries) expect(e.addresses.filter((a) => a.state === "active").length).to.be.at.most(1);
        expect(new Set(r.annuaire.entries.map((e) => e.session_identity)).size).to.equal(r.annuaire.entries.length);
        const alias = r.annuaire.entries.flatMap((e) => e.requester_identities);
        expect(new Set(alias).size).to.equal(alias.length);
        expect(K.verifierAnnuaireExporte(r.annuaire, { conforme })).to.deep.equal([]);
        doc = r.annuaire;
        defis = r.defis;
      }
    }
    // La trace de référence redonne annuaires/reference.json, noms affichés mis à part.
    const t = annuaire("traces/annuaire-de-reference.json");
    expect(t.steps.at(-1).expected.entries).to.deep.equal(K.resumeEntrees(annuaire("annuaires/reference.json")));
  });

  it("AN-8 (EX-13.18) : controles-vote.json — première raison dans l'ordre, avertissement separation_incomplete ; actionRetrait d'EX-7.15", function () {
    const doc = annuaire("controles-vote.json");
    const depart = annuaire(doc.annuaire);
    for (const c of doc.cases) expect(K.controleVote(depart, c.session_identity, c.action, c.address, c.ticket), c.id).to.deep.equal(c.expected);
    const ref = annuaire("annuaires/reference.json");
    const tk = { launched_by: "u.martin@assureur-demo.example" };
    expect(K.actionRetrait(ref, "oidc https://idp.assureur-demo.example u.martin", tk)).to.equal("u.martin@assureur-demo.example");
    expect(K.actionRetrait(ref, "oidc https://idp.assureur-demo.example admin-1", tk)).to.equal("oidc https://idp.assureur-demo.example admin-1");
    expect(K.actionRetrait(ref, "oidc https://idp.assureur-demo.example approbateur-1", tk)).to.equal(null);
    // EX-12.17 : annuaire réduit pour une session ordinaire.
    const reduit = K.annuaireDeSession(ref, "oidc https://idp.assureur-demo.example approbateur-2");
    expect(reduit.entries.map((e) => e.id)).to.deep.equal(["apb-0002"]);
    expect(reduit.operations.map((o) => o.seq)).to.deep.equal([3, 4, 5, 6]);
    expect(K.annuaireDeSession(ref, "oidc https://idp.assureur-demo.example admin-1")).to.deep.equal(ref);
  });

  it("AN-10 (EX-12.14, EX-12.16, EX-12.19) : controles-canal.json — contrôle de la session par le service ; chaque requête conforme à sa définition ; un approbateur ne retire pas le ticket du demandeur", function () {
    const doc = annuaire("controles-canal.json");
    const depart = annuaire(doc.annuaire);
    const defs = { tickets: ["console-service", "requete_tickets"], consulter: ["console-approbation", "requete_consulter"], voter: ["console-approbation", "requete_voter"], recuser: ["console-service", "requete_recuser"], retirer: ["console-service", "requete_retirer"] };
    for (const c of doc.cases) {
      expect(valider(c.request, ...defs[c.method]), c.id).to.deep.equal([]);
      expect(K.controleCanal(depart, c.method, c.request, c.ticket), c.id).to.equal(c.expected.reason);
    }
    const parRaison = (m, r) => doc.cases.some((c) => c.method === m && c.expected.reason === r);
    for (const m of ["tickets", "consulter", "voter", "recuser", "retirer"]) for (const r of [null, "session_non_autorisee"]) expect(parRaison(m, r), `${m} ${r}`).to.equal(true);
    for (const m of ["consulter", "voter", "retirer"]) expect(parRaison(m, "ticket_inconnu"), `${m} ticket_inconnu`).to.equal(true);
    expect(doc.cases.some((c) => c.expected.reason === "identite_invalide")).to.equal(true);
    // EX-12.14 : (a) session hors de l'organisation, (b) ticket inconnu, (c) session qui ne peut pas voir les arguments.
    const cas = (id) => doc.cases.find((c) => c.id === id);
    expect(cas("consulter-ticket-inconnu-hors-organisation").expected.reason).to.equal("session_non_autorisee");
    expect([cas("consulter-ticket-inconnu-non-eligible").expected.reason, cas("consulter-demandeur").expected.reason]).to.deep.equal(["ticket_inconnu", "session_non_autorisee"]);
    expect(cas("consulter-ticket-inconnu-non-eligible").request.session_identity).to.equal(cas("consulter-demandeur").request.session_identity);
    expect(cas("consulter-ticket-inconnu").ticket).to.equal(null);
    // Le même ordre, sur un annuaire où la session de u.martin est désactivée : (a) passe avant (b).
    const desactive = K.appliquerOperation(depart, "desactiver", { session_identity: "oidc https://idp.assureur-demo.example admin-1", entry: "apb-0003", reason: null }, "2026-11-10T11:00:00.000Z").annuaire;
    expect(K.controleCanal(desactive, "consulter", { ticket: "apr-0999", session_identity: "oidc https://idp.assureur-demo.example u.martin" }, null)).to.equal("session_non_autorisee");
    expect(K.controleCanal(desactive, "tickets", { session_identity: "oidc https://idp.assureur-demo.example u.martin" }, null)).to.equal("session_non_autorisee");
    // Le scénario du retrait par un approbateur qui n'est pas le demandeur : le corps seul (by = launched_by) ne suffit pas.
    const abusif = doc.cases.find((c) => c.id === "retirer-approbateur-par-alias");
    expect([abusif.request.by, abusif.ticket.launched_by, abusif.expected.reason]).to.deep.equal(["u.martin@assureur-demo.example", "u.martin@assureur-demo.example", "session_non_autorisee"]);
    // Une adresse EIP-55 se compare en minuscules (controleVote, modeleAffichage).
    const ref = annuaire("annuaires/reference.json");
    const tk = { launched_by: "u.martin@assureur-demo.example", self_approval: "interdite", policy_requester_addresses: [ADR(3)], directory_requester_addresses: [ADR(3)], members: [ADR(1), ADR(2), ADR(3)].sort() };
    expect(K.controleVote(ref, "oidc https://idp.assureur-demo.example approbateur-1", "voter", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", tk).allowed).to.equal(true);
  });

  it("AN-9 (EX-13.19) : exports/ — liste complète des écarts, triée par pointeur puis par code ; schéma non conforme : une seule erreur", function () {
    const att = annuaire("exports/attendu.json");
    for (const c of att.cases) {
      const r = K.verifierAnnuaireExporte(annuaire(`exports/${c.file}`), { conforme });
      expect(r, c.file).to.deep.equal(c.errors);
      expect([...r].sort((a, b) => avant(a.pointer ?? "", b.pointer ?? "") || avant(a.code, b.code)), c.file).to.deep.equal(r);
    }
    const codes = new Set(att.cases.flatMap((c) => c.errors.map((e) => e.code)));
    for (const code of ["schema", "revision_incoherente", "operations_incoherentes", "identifiant_double", "identite_double", "adresse_double", "deux_adresses_actives", "preuve_invalide", "preuve_discordante", "auto_validation"]) expect(codes.has(code), code).to.equal(true);
    // Sans validation de schéma fournie, un document que la vérification ne peut pas parcourir donne aussi la seule erreur schema.
    expect(K.verifierAnnuaireExporte({ version: 0 })).to.deep.equal([{ code: "schema", pointer: null }]);
  });

  it("EX-13.37, EX-13.19 (point 6) : la recopie d'un nouveau réglage administrators est une opération de l'annuaire, rejouée par la vérification d'un export", function () {
    const ref = annuaire("annuaires/reference.json");
    const A1 = "oidc https://idp.assureur-demo.example admin-1";
    const A2 = "oidc https://idp.assureur-demo.example admin-2";
    // Liste inchangée : aucune opération.
    const meme = K.recopierAdministrateurs(ref, [A1], "2026-11-10T10:35:00.000Z");
    expect([meme.changed, meme.annuaire.revision]).to.deep.equal([false, ref.revision]);
    const r = K.recopierAdministrateurs(ref, [A1, A2], "2026-11-10T10:35:00.000Z");
    expect(r.changed).to.equal(true);
    expect([r.annuaire.revision, r.annuaire.updated_at, r.annuaire.administrators]).to.deep.equal([10, "2026-11-10T10:35:00.000Z", [A1, A2]]);
    expect(r.annuaire.operations.at(-1)).to.deep.equal({ seq: 10, at: "2026-11-10T10:35:00.000Z", op: "changer_administrateurs", by: "configuration", entry: null, address: null, launched_by: null, reason: null, administrators: { before: [A1], after: [A1, A2] } });
    expect(ref.revision, "argument non modifié").to.equal(9);
    expect(conforme(r.annuaire)).to.equal(true);
    expect(K.verifierAnnuaireExporte(r.annuaire, { conforme })).to.deep.equal([]);
    // Chaque autre opération porte administrators nul ; le document réduit d'une session ordinaire n'a pas l'opération.
    expect(ref.operations.every((o) => o.administrators === null)).to.equal(true);
    expect(K.annuaireDeSession(r.annuaire, "oidc https://idp.assureur-demo.example approbateur-1").operations.some((o) => o.op === "changer_administrateurs")).to.equal(false);
    // admin-2 n'est administrateur qu'à partir de l'opération 10 ; une liste invalide n'est pas recopiée.
    const avantRecopie = K.appliquerOperation(ref, "desactiver", { session_identity: A2, entry: "apb-0002", reason: null }, "2026-11-10T10:40:00.000Z");
    expect(avantRecopie.reason).to.equal("non_administrateur");
    expect(K.appliquerOperation(r.annuaire, "desactiver", { session_identity: A2, entry: "apb-0002", reason: null }, "2026-11-10T10:40:00.000Z").accepted).to.equal(true);
    for (const mauvaise of [[], [A1, A1], ["admin-2@assureur-demo.example"]]) expect(() => K.recopierAdministrateurs(ref, mauvaise, "2026-11-10T10:35:00.000Z"), JSON.stringify(mauvaise)).to.throw(K.ErreurConsole).with.property("code", "identite_invalide");
    // Les trois cas d'export (A.10).
    const att = annuaire("exports/attendu.json");
    expect(att.cases.filter((c) => c.file.startsWith("administrateurs-")).map((c) => [c.file, c.errors])).to.deep.equal([
      ["administrateurs-recopies.json", []],
      ["administrateurs-sans-operation.json", [{ code: "operations_incoherentes", pointer: "/operations/1" }]],
      ["administrateurs-differents-du-rejeu.json", [{ code: "operations_incoherentes", pointer: "/administrators" }]],
    ]);
  });
});

describe("CT-3 0.3 : exemples de la spécification et vecteurs (13.5, 13.6, 13.10, 13.15)", function () {
  const exemple = (nom) => JSON.parse(new RegExp(`<!-- schema: ${nom.replace("/", "\\/")} -->\n\`\`\`json\n([\\s\\S]*?)\n\`\`\``).exec(MD)[1]);
  const ref = lire("annuaire", "annuaires", "reference.json");

  it("EX-13.24 : la requête d'exemple est celle du vecteur apr-2201-approuve-compte-1 ; EX-13.12, EX-13.13 : défi, requête inscrire et réponses d'exemple tirés de l'annuaire de référence", function () {
    expect(exemple("console-approbation/requete_signature")).to.deep.equal(lire("console", "requetes", "apr-2201-approuve-compte-1.json").expected.request);
    const p1 = ref.entries[0].addresses[0].proof;
    const prep = exemple("console-service/reponse_preparer_inscription");
    expect(prep.message).to.equal(p1.message);
    expect(K.messageInscription(prep.fields)).to.equal(prep.message);
    expect(exemple("console-service/requete_inscrire")).to.deep.equal({ session_identity: ref.entries[0].session_identity, address: ref.entries[0].addresses[0].address, message: p1.message, signature: p1.signature });
    // Rejouées sur l'annuaire vide, la préparation, l'inscription et la validation d'exemple redonnent les réponses de 13.5 et 13.6.
    const vide = lire("annuaire", "annuaires", "vide.json");
    const a = K.appliquerOperation(vide, "preparer_inscription", exemple("console-service/requete_preparer_inscription"), prep.fields.issued_at, { nonce: prep.fields.nonce, identifiant: "compteur" });
    expect(a.response).to.deep.equal(prep);
    const b = K.appliquerOperation(a.annuaire, "inscrire", exemple("console-service/requete_inscrire"), p1.received_at, { defis: a.defis, identifiant: "compteur" });
    expect(b.response).to.deep.equal({ entry: "apb-0001", address: p1.message.match(/Adresse: (0x[0-9a-f]{40})/)[1], state: "en_attente", revision: 1 });
    const c = K.appliquerOperation(b.annuaire, "valider", exemple("console-service/requete_valider"), "2026-11-10T08:30:00.000Z", { identifiant: "compteur" });
    expect(c.response.state).to.equal("active");
    const d = K.appliquerOperation(b.annuaire, "valider", { ...exemple("console-service/requete_valider"), session_identity: ref.entries[0].session_identity }, "2026-11-10T08:30:00.000Z");
    expect(d.reason).to.equal("non_administrateur");
    const admin = { ...b.annuaire, administrators: [...b.annuaire.administrators, ref.entries[0].session_identity] };
    expect(K.appliquerOperation(admin, "valider", { ...exemple("console-service/requete_valider"), session_identity: ref.entries[0].session_identity }, "2026-11-10T08:30:00.000Z").reason).to.equal(exemple("console-service/erreur").error.code);
  });
});

describe("CT-3 0.3 : console/ rejoué par console.mjs (CS-1 à CS-9)", function () {
  it("CS-1 à CS-4 (EX-9.15 à EX-9.19) : modeleAffichage rend exactement le modèle attendu de chaque cas", function () {
    for (const f of fichiers("console", "modeles")) {
      const c = lire("console", "modeles", f);
      const { view, ...contexte } = c.input;
      const m = K.modeleAffichage(view, contexte);
      expect(m, f).to.deep.equal(c.expected);
      expect(m.signable, f).to.equal(m.blocking.length === 0);
    }
  });

  it("EX-9.15 (contrôle 4), EX-9.4 : intention portée par une référence (intent_status) ; EX-12.14 : effet dont un membre est tiré du résultat (unresolved, valeur nulle)", function () {
    const ref = lire("console", "modeles", "intention-par-reference.json");
    expect(ref.input.view.retained_event.intent).to.be.an("object");
    expect(ref.input.view.retained_event.intent).to.have.keys(["sha256", "length", "redacted"]);
    expect([ref.expected.intent_status, ref.expected.signable, ref.expected.intent]).to.deep.equal(["reference_non_verifiable", true, ref.input.view.request.intent]);
    for (const f of fichiers("console", "modeles").filter((x) => x !== "intention-par-reference.json")) expect(lire("console", "modeles", f).expected.intent_status, f).to.equal("en_clair");
    // Une intention nulle dans l'événement est en clair (rien à vérifier).
    const sans = JSON.parse(JSON.stringify(lire("console", "modeles", "apr-2201-approuve.json").input));
    expect(K.modeleAffichage({ ...sans.view, retained_event: { ...sans.view.retained_event, intent: null } }, sans).intent_status).to.equal("en_clair");
    const eff = lire("console", "modeles", "effet-connu-apres-execution.json");
    expect(eff.expected.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: null, amount: "12500.00", currency: "CHF", unresolved: [{ member: "object", pointer: "/result/document_id" }] }]);
    expect([eff.expected.signable, eff.expected.blocking]).to.deep.equal([true, []]);
    for (const f of fichiers("console", "modeles")) for (const e of lire("console", "modeles", f).expected.effects) for (const u of e.unresolved) expect(e[u.member], f).to.equal(null);
  });

  it("EX-9.17, EX-9.18, 12.9 : apr-2201 — D_A, H, empreintes et groupes de la spécification ; remaining_ms 2 829 904 ; feuilles de l'exemple d'EX-9.16", function () {
    const c = lire("console", "modeles", "apr-2201-approuve.json").expected;
    expect(c.digests.approuve.jcs).to.equal('{"decision":"approuve","journal_id":"0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d","ticket":"apr-2201"}');
    expect([c.digests.approuve.d_a, c.digests.approuve.h, c.digests.refuse.d_a, c.digests.refuse.h]).to.deep.equal(["0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c", "0xe9f3d8812e1fc736cd7957efb20093bfb3655c6568fc56e6133b2cc41d2cf6ea", "0xd2cace7b1eded2643785e99e2f5316ee6cb4fad6ea468426d30d76538ccab300", "0xde5123ed1281dbf3fa4f923b14c96db3481c460e7ed324b2943fffbec2f04811"]);
    expect([c.digests.approuve.fingerprint, c.digests.approuve.groups, c.digests.approuve.h_fingerprint, c.digests.refuse.fingerprint]).to.deep.equal(["a57cbdad…64f7df7c", "a57cbdad 280b5cb2 e9f6ee87 b85d8bc0 5e76a596 6377e7d5 80465194 64f7df7c", "e9f3d881…1d2cf6ea", "d2cace7b…8ccab300"]);
    expect(c.remaining_ms).to.equal(2829904);
    expect(c.arguments.map((a) => [a.pointer, a.status])).to.deep.equal([["/amount", "verifie"], ["/beneficiary_iban", "non_verifiable"], ["/claim_id", "verifie"], ["/currency", "verifie"]]);
    expect(lire("console", "modeles", "argument-different.json").expected.blocking).to.deep.equal(["argument_different"]);
    // L'empreinte n'a qu'une forme : 17 caractères, U+2026 au milieu.
    expect(K.empreinte("0x" + "ab".repeat(32))).to.equal("abababab…abababab");
    expect(() => K.empreinte("0x1234")).to.throw(K.ErreurConsole);
  });

  it("EX-9.19 : condenses() marque un D_A qui est de l'UTF-8 valide ; aucun D_A des vecteurs ne l'est, et le modèle n'a l'avertissement condense_utf8 que pour un tel D_A", function () {
    expect(K.estUtf8(K.utf8("élan"))).to.equal(true);
    expect(K.estUtf8(Uint8Array.from([0xc3, 0x28]))).to.equal(false);
    expect(K.estUtf8(new Uint8Array(32))).to.equal(true);
    for (const rep of ["modeles", "requetes"]) for (const f of fichiers("console", rep)) {
      const c = lire("console", rep, f);
      const digests = rep === "modeles" ? c.expected.digests : { x: c.expected.digests };
      if (!digests) continue;
      for (const d of Object.values(digests)) {
        expect(d.utf8, f).to.equal(K.estUtf8(getBytes(d.d_a)));
        expect(d.utf8, f).to.equal(false);
      }
      if (rep === "modeles") expect(c.expected.warnings.includes("condense_utf8"), f).to.equal(false);
    }
  });

  it("CS-3, CS-5 (EX-13.24, EX-9.22) : requetes/ — condensés, préimage de 60 octets, requête personal_sign exacte, signature RFC 6979 égale à celle d'ethers", function () {
    for (const f of fichiers("console", "requetes")) {
      const c = lire("console", "requetes", f);
      expect(K.condenses(c.input.a), f).to.deep.equal(c.expected.digests);
      expect(K.enHex(K.preimageEIP191(getBytes(c.expected.digests.d_a))), f).to.equal(c.expected.preimage);
      expect(K.requetePersonalSign(c.expected.digests.d_a, c.input.approver), f).to.deep.equal(c.expected.request);
      expect(c.expected.request.params.map((p) => p.length), f).to.deep.equal([66, 42]);
      expect(K.signerHachage(getBytes(COMPTES[c.input.account].privateKey), getBytes(c.expected.digests.h)), f).to.equal(c.expected.signature);
      expect(J.signerApprobation(COMPTES[c.input.account], c.input.a), f).to.equal(c.expected.signature);
      expect(recoverAddress(c.expected.digests.h, c.expected.signature).toLowerCase(), f).to.equal(c.input.approver);
    }
    const zero = fichiers("console", "requetes").map((f) => lire("console", "requetes", f)).find((c) => c.expected.digests.d_a.startsWith("0x00"));
    expect(zero.input.a.ticket).to.equal("apr-c0-542");
  });

  it("CS-6, CS-7 (EX-9.21, EX-13.29, EX-12.16) : reponses/ — verdict, signature normalisée, adresse recouvrée et vote construit", function () {
    for (const f of fichiers("console", "reponses")) {
      const c = lire("console", "reponses", f);
      const d = K.condenses(c.input.a).d_a;
      const r = K.verifierReponse(c.input.response, d, c.input.approver);
      const vote = r.outcome === "accepte" ? K.requeteVoter({ ticket: c.input.a.ticket }, c.input.a.decision, r.signature, c.input.approver, c.input.reason, c.input.session_identity) : null;
      expect({ ...r, vote }, f).to.deep.equal(c.expected);
      if (vote) expect(J.verifierSignatureApprobation(c.input.a, vote.signature, c.input.approver).ok, f).to.equal(true);
    }
    const codes = new Set(fichiers("console", "reponses").map((f) => lire("console", "reponses", f).expected.reason));
    for (const code of ["refus_approbateur", "non_autorise", "methode_non_prise_en_charge", "deconnecte", "chaine_deconnectee", "erreur_portefeuille", "reponse_invalide", "signature_invalide", "adresse_differente", null]) expect(codes.has(code), String(code)).to.equal(true);
  });

  it("CS-8 (EX-13.22) : decouverte/ — validation des annonces, réannonce, uuid en double, ordre, aucun choix", function () {
    for (const f of fichiers("console", "decouverte")) {
      const c = lire("console", "decouverte", f);
      expect(K.decouvrir(c.input.announcements), f).to.deep.equal(c.expected);
    }
    // Avec de vrais objets : la classe exige une fonction request et compare les objets, pas les noms.
    const p1 = { request() {} };
    const d = new K.Decouverte();
    const info = { uuid: "6f1c2a1e-8a4b-4c7d-9e2f-0a1b2c3d4e5f", name: "A", icon: "data:,", rdns: "a" };
    d.annoncer({ info, provider: p1 });
    d.annoncer({ info, provider: p1 });
    d.annoncer({ info: { ...info, uuid: "0b7d5c3a-1e2f-4a6b-8c9d-7e6f5a4b3c2d" }, provider: {} });
    expect(d.fournisseurs().map((x) => x.provider)).to.deep.equal([p1]);
    expect(d.rejets()).to.deep.equal([{ index: 2, reason: "annonce_invalide" }]);
    d.annoncer({ info, provider: { request() {} } });
    expect(d.fournisseurs()).to.deep.equal([]);
  });

  it("CS-9 (EX-13.28) : fichiers-cle/ — format, dérivation admise, MAC, déchiffrement, intervalle, adresse, avertissement ; signerCondense efface la clé", function () {
    for (const f of fichiers("console", "fichiers-cle")) {
      const c = lire("console", "fichiers-cle", f);
      const r = K.lireFichierCle(c.input.keystore, c.input.password, c.input.approver);
      expect({ outcome: r.outcome, reason: r.reason, address: r.address, warnings: r.warnings }, f).to.deep.equal(c.expected);
      if (r.outcome === "accepte") {
        expect(J.hex(Buffer.from(r.cle)), f).to.equal(decryptKeystoreJsonSync(JSON.stringify(c.input.keystore), c.input.password).privateKey);
        const sig = K.signerCondense(r.cle, "0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c");
        expect(r.cle.every((x) => x === 0), f).to.equal(true);
        expect(sig).to.equal(lire("console", "requetes", "apr-2201-approuve-compte-1.json").expected.signature);
      } else expect(r.cle, f).to.equal(null);
    }
    // Le texte du fichier est lu par l'analyseur strict : clé en double refusée.
    expect(K.lireFichierCle('{"version":3,"version":3}', "x", ADR(1)).reason).to.equal("fichier_cle_invalide");
    const exemple = /<!-- schema: console-approbation\/fichier_cle -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1];
    expect(JSON.parse(exemple)).to.deep.equal(lire("console", "fichiers-cle", "pbkdf2-valide.json").input.keystore);
  });
});

describe("CT-3 0.3 : primitives de console.mjs contre node:crypto, ethers et journal.mjs (EX-13.32)", function () {
  this.timeout(60_000);
  const graine = (n) => crypto.createHash("sha256").update(`noortrace/tests/console/${n}`).digest();
  const octets = (n, l) => {
    const out = Buffer.alloc(l);
    for (let i = 0; i < l; i += 32) graine(`${n}/${i}`).copy(out, i);
    return out;
  };

  it("SHA-256, HMAC-SHA-256 et Keccak-256 sur des longueurs autour des blocs", function () {
    for (const l of [0, 1, 55, 56, 63, 64, 65, 119, 135, 136, 137, 271, 272, 1000]) {
      const m = octets(`m${l}`, l);
      expect(K.enHex(K.sha256(new Uint8Array(m))), `sha ${l}`).to.equal(J.sha256(m));
      expect(K.enHex(K.keccak256(new Uint8Array(m))), `keccak ${l}`).to.equal(keccak256(m));
      const k = octets(`k${l}`, l % 100);
      expect(K.enHex(K.hmacSha256(new Uint8Array(k), new Uint8Array(m))), `hmac ${l}`).to.equal("0x" + crypto.createHmac("sha256", k).update(m).digest("hex"));
    }
  });

  it("PBKDF2-HMAC-SHA-256, scrypt (RFC 7914) et AES-128-CTR", function () {
    const mdp = Buffer.from("mot de passe é", "utf8");
    const sel = octets("sel", 32);
    expect(K.enHex(K.pbkdf2Sha256(new Uint8Array(mdp), new Uint8Array(sel), 1000, 32))).to.equal("0x" + crypto.pbkdf2Sync(mdp, sel, 1000, 32, "sha256").toString("hex"));
    expect(K.enHex(K.pbkdf2Sha256(new Uint8Array(mdp), new Uint8Array(sel), 3, 70))).to.equal("0x" + crypto.pbkdf2Sync(mdp, sel, 3, 70, "sha256").toString("hex"));
    expect(K.enHex(K.scrypt(new Uint8Array(mdp), new Uint8Array(sel), 1024, 8, 1, 32))).to.equal("0x" + crypto.scryptSync(mdp, sel, 32, { N: 1024, r: 8, p: 1 }).toString("hex"));
    expect(K.enHex(K.scrypt(new Uint8Array(mdp), new Uint8Array(sel), 16, 2, 3, 64))).to.equal("0x" + crypto.scryptSync(mdp, sel, 64, { N: 16, r: 2, p: 3 }).toString("hex"));
    for (const iv of [octets("iv", 16), Buffer.from("ffffffffffffffffffffffffffffffff", "hex"), Buffer.from("000000000000000000000000fffffffe", "hex")]) {
      const cle = octets("cle", 16);
      const donnees = octets("donnees", 70);
      const c = crypto.createCipheriv("aes-128-ctr", cle, iv);
      expect(K.enHex(K.aes128Ctr(new Uint8Array(cle), new Uint8Array(iv), new Uint8Array(donnees)))).to.equal("0x" + Buffer.concat([c.update(donnees), c.final()]).toString("hex"));
    }
  });

  it("secp256k1 : signature RFC 6979 à s bas égale à celle d'ethers, recouvrement, adresse ; EIP-191 sur des octets", function () {
    for (let i = 0; i < 12; i++) {
      const cle = octets(`secp/${i}`, 32);
      const h = octets(`h/${i}`, 32);
      const w = new Wallet("0x" + cle.toString("hex"));
      const s = Signature.from(w.signingKey.sign(h)).serialized;
      expect(K.signerHachage(new Uint8Array(cle), new Uint8Array(h))).to.equal(s);
      expect(K.adresseDeCle(new Uint8Array(cle))).to.equal(w.address.toLowerCase());
      const m = octets(`message/${i}`, i * 7);
      expect(K.enHex(K.condenseEIP191(new Uint8Array(m)))).to.equal(hashMessage(m));
      const sig = Signature.from(w.signingKey.sign(hashMessage(m)));
      expect(K.verifierSignature(new Uint8Array(m), sig.serialized, w.address)).to.deep.equal({ ok: true, reason: null, signature: sig.serialized, recovered: w.address.toLowerCase() });
    }
    expect(K.adresseDeCle(new Uint8Array(32))).to.equal(null);
  });

  it("JCS v0 et hachage d'un événement égaux à journal.mjs sur tous les événements de CT-1 ; base64 strict ; JSON strict", function () {
    for (const d of ["journal-valide"]) {
      for (const ev of JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", d, "evenements.json"), "utf8"))) {
        expect(K.hachageEvenement(ev), `seq ${ev.seq}`).to.equal(J.hachageEvenement(ev));
        expect(K.jcs(ev)).to.equal(J.canonicaliserJCS(ev));
      }
    }
    expect(() => K.jcs({ a: 1.5 })).to.throw(K.ErreurConsole);
    expect(() => K.jcs("\ud800")).to.throw(K.ErreurConsole);
    for (const s of ["", "f", "fo", "foo", "foob", "fooba", "foobar"]) expect(Buffer.from(K.base64Strict(Buffer.from(s).toString("base64"))).toString()).to.equal(s);
    for (const mauvais of ["Zh==", "Zm9=", "Zg=", "Z===", "Zg==Zg==", "Zm9v\n", "Zm-v"]) expect(K.base64Strict(mauvais), mauvais).to.equal(null);
    for (const t of ['{"a":1.5,"b":[true,null,"é\\u00e9"]}', '{"a":{"b":{}}}', "[1e3,-0.25]"]) expect(K.analyserJSONStrict(t)).to.deep.equal(C.analyserJSONIntegral(t));
    for (const t of ['{"a":1,"a":2}', '"\\ud800"', "[1,]", "01", "1e400", "{} x"]) expect(() => K.analyserJSONStrict(t), t).to.throw(K.ErreurConsole);
    expect(() => K.analyserJSONStrict(Uint8Array.from([0xef, 0xbb, 0xbf, 0x31]))).to.throw(K.ErreurConsole);
    expect(() => K.analyserJSONStrict(Uint8Array.from([0x22, 0xff, 0x22]))).to.throw(K.ErreurConsole);
  });
});

describe("CT-3 0.3 : bibliothèque et page de référence, propriétés statiques (EX-13.31 à EX-13.35)", function () {
  const LIB = fs.readFileSync(path.join(PROJECT_ROOT, "scripts", "lib", "console.mjs"), "utf8");
  const PAGE = fs.readFileSync(path.join(PROJECT_ROOT, "console", "console.js"), "utf8");
  const sansCommentaires = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`\\])\/\/.*$/gm, "$1");

  it("EX-13.32 : console.mjs n'importe rien et n'emploie ni eval, ni Function, ni réseau, ni DOM, ni stockage", function () {
    const code = sansCommentaires(LIB);
    expect(code).not.to.match(/^\s*import\s|\bimport\s*\(|\brequire\s*\(/m);
    expect(code).not.to.match(/\beval\s*\(|\bnew Function\b|\bFunction\s*\(/);
    expect(code).not.to.match(/\bfetch\s*\(|XMLHttpRequest|WebSocket|\bdocument\.|\bwindow\.|localStorage|sessionStorage|indexedDB|innerHTML/);
    // Aucun état global mutable : les déclarations de premier niveau sont des const, des fonctions ou des classes.
    expect(code).not.to.match(/^(let|var)\s/m);
  });

  it("EX-13.33, EX-13.34 : la page construit le DOM par createElement et textContent, sans innerHTML, sans stockage, sans window.ethereum, sans autre méthode de signature", function () {
    const code = sansCommentaires(PAGE);
    expect(code).to.include("createElement").and.to.include("textContent");
    expect(code).not.to.match(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function/);
    expect(code).not.to.match(/localStorage|sessionStorage|indexedDB|document\.cookie/);
    expect(code).not.to.match(/window\.ethereum|\bethereum\b/);
    expect(code).not.to.match(/eth_sign\b|eth_signTypedData|eth_sendTransaction|wallet_switchEthereumChain|eth_chainId/);
    // Seules méthodes EIP-1193 : eth_requestAccounts, et personal_sign construite par requetePersonalSign (EX-13.20).
    expect([...code.matchAll(/method: "([a-zA-Z_]+)"/g)].map((m) => m[1]).filter((m) => m !== "POST")).to.deep.equal(["eth_requestAccounts"]);
    expect(code.match(/\.request\(/g).length).to.equal(1);
    expect(code.match(/K\.requetePersonalSign\(/g).length).to.equal(2);
    expect(code).not.to.match(/https?:\/\//);
    // EX-13.22 : l'écouteur EIP-6963 est posé avant toute autre opération de la page.
    expect(code.indexOf("decouverte.ecouter(window, Event)")).to.be.lessThan(code.indexOf("demarrer();"));
    expect(code.indexOf("decouverte.ecouter(window, Event)")).to.be.lessThan(code.indexOf("appel(\"session\""));
  });

  it("EX-13.33, EX-13.35 : console/index.html est à jour (intégrité sha384 du script d'entrée et de la bibliothèque, carte d'importation, condensé sha256 dans script-src) ; aucune copie de la bibliothèque dans console/", function () {
    const e = empreintesConsole();
    expect(fs.readFileSync(path.join(PROJECT_ROOT, "console", "index.html"), "utf8")).to.equal(e.html);
    const sri = (f) => "sha384-" + crypto.createHash("sha384").update(fs.readFileSync(f)).digest("base64");
    expect(e.bibliotheque).to.equal(sri(path.join(PROJECT_ROOT, "scripts", "lib", "console.mjs")));
    expect(e.entree).to.equal(sri(path.join(PROJECT_ROOT, "console", "console.js")));
    expect(e.html).to.include(`<script type="importmap">${e.carte}</script>`);
    expect(e.entetes["content-security-policy"]).to.equal(`default-src 'none'; script-src 'self' '${e.carteSha256}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'`);
    expect(e.entetes["content-security-policy"]).not.to.match(/unsafe-inline|unsafe-eval|strict-dynamic|script-src[^;]*(data:|\*)/);
    expect(e.entetes["integrity-policy"]).to.equal("blocked-destinations=(script)");
    expect(fs.readdirSync(path.join(PROJECT_ROOT, "console")).sort()).to.deep.equal(["LISEZMOI.md", "console.css", "console.js", "index.html"]);
    // Le seul script en ligne est la carte d'importation ; aucun gestionnaire en ligne, aucune ressource tierce.
    expect(e.html.match(/<script/g).length).to.equal(2);
    expect(e.html).not.to.match(/\son[a-z]+=|https?:\/\/|style=/);
    const lisezmoi = fs.readFileSync(path.join(PROJECT_ROOT, "console", "LISEZMOI.md"), "utf8");
    expect(lisezmoi).to.include("Integrity-Policy: blocked-destinations=(script)").and.to.include("frame-ancestors 'none'").and.to.include("node scripts/console/empreintes.mjs");
  });
});

// ---------------------------------------------------------------------------
// Partie Chromium (EX-13.36)
// ---------------------------------------------------------------------------

const ID = (nom) => `oidc https://idp.assureur-demo.example ${nom}`;
const ICONE = "data:image/svg+xml;base64," + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>').toString("base64");
const FOURNISSEURS = [
  { nom: "a", uuid: "3d0c5f3e-9a7b-4c1d-8e2f-1a2b3c4d5e6f", name: "Portefeuille de test A", rdns: "example.portefeuille.a" },
  { nom: "b", uuid: "7b8e2d1c-4f5a-4b6c-9d7e-8f9a0b1c2d3e", name: "Portefeuille de test B", rdns: "example.portefeuille.b" },
];

/**
 * Script injecté avant la page : fournisseurs EIP-1193 gelés, annoncés par
 * EIP-6963 (et réannoncés à chaque eip6963:requestProvider, de façon
 * synchrone), piège sur window.ethereum, et __emettre pour émettre un
 * événement EIP-1193 (accountsChanged) depuis le test.
 */
function injecter({ fournisseurs, doublon, icone }) {
  const lectures = { n: 0 };
  const ecouteursParFournisseur = {};
  Object.defineProperty(window, "__lecturesEthereum", { value: lectures });
  Object.defineProperty(window, "__emettre", { value: (nom, ev, arg) => (ecouteursParFournisseur[nom]?.[ev] ?? []).forEach((fn) => fn(arg)) });
  Object.defineProperty(window, "ethereum", { configurable: false, get() {
    lectures.n++;
    return undefined;
  } });
  const creer = (f) => {
    const ecouteurs = (ecouteursParFournisseur[f.nom] = {});
    const provider = Object.freeze({
      request: (args) =>
        window.__portefeuille(f.nom, args?.method ?? null, args?.params ?? null).then((r) => {
          if (r && r.error) {
            const e = new Error(r.error.message);
            e.code = r.error.code;
            throw e;
          }
          return r.result;
        }),
      on: (ev, fn) => {
        (ecouteurs[ev] = ecouteurs[ev] || []).push(fn);
      },
      removeListener: () => {},
    });
    const detail = Object.freeze({ info: Object.freeze({ uuid: f.uuid, name: f.name, icon: icone, rdns: f.rdns }), provider });
    const annoncer = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail }));
    window.addEventListener("eip6963:requestProvider", annoncer);
    annoncer();
  };
  fournisseurs.forEach(creer);
  if (doublon) creer({ ...fournisseurs[0], nom: "imitation", name: fournisseurs[0].name });
}

describe("CT-3 0.3 : console de référence dans Chromium (EX-13.36)", function () {
  this.timeout(240_000);
  let chromium = null;
  let navigateur = null;
  let serveur = null;
  let base = null;
  let raisonSaut = null;
  const etat = {};

  const vecteurVue = (f) => lire("console", "modeles", f).input.view;
  const VOTE = lire("console", "reponses", "canonique.json").expected.vote;
  const REF = lire("annuaire", "annuaires", "reference.json");
  const VUE_2201 = vecteurVue("apr-2201-approuve.json");
  const VUE_0901 = vecteurVue("reference-en-ligne.json");

  /** Service et serveur de console simulés : chaque corps reçu est enregistré ; une réponse à consulter peut être retenue. */
  function repondre(methode, corps) {
    const s = etat.scenario;
    etat.recus.push({ methode, corps });
    const ok = (v) => [200, v];
    const err = (code) => [400, { error: { code, message: code, data: {} } }];
    const vues = s.vues ?? (s.vue ? [s.vue] : []);
    switch (methode) {
      case "session":
        return ok({ session_identity: s.session, auth_time: "2026-11-05T09:20:00.000Z", administrator: false, reauth_max_age_s: 900 });
      case "annuaire":
        return corps.session_identity === s.session ? ok(K.annuaireDeSession(s.annuaire, s.session)) : err("session_non_autorisee");
      case "tickets":
        return ok({ tickets: vues.map((v) => ({ ticket: v.ticket, state: v.state, tool_announced: v.request.tool_announced, launched_by: v.request.delegation.launched_by, deadline: v.deadline, votes_approuve: 1, votes_refuse: 0, effective_required: v.effective_required })) });
      case "consulter": {
        const vue = vues.find((v) => v.ticket === corps.ticket);
        if (corps.session_identity !== s.session || !vue) return err("ticket_inconnu");
        if (s.retenir && s.retenir.ticket === corps.ticket && ++s.retenir.vus === s.retenir.n) return new Promise((r) => (etat.liberer = () => r(ok(vue))));
        return ok(vue);
      }
      case "voter":
        return ok({ ticket: corps.ticket, state: "verification" });
      case "preparer_inscription":
        return s.preparer ? ok(s.preparer) : err("requete_invalide");
      case "inscrire":
        return s.inscrireErreur ? err(s.inscrireErreur) : ok({ entry: "apb-0003", address: corps.address, state: "en_attente", revision: 9 });
      default:
        return [404, { error: { code: "requete_invalide", message: "methode inconnue", data: {} } }];
    }
  }

  function demarrerServeur() {
    return new Promise((ok) => {
      const s = http.createServer((req, res) => {
        const url = new URL(req.url, "http://127.0.0.1");
        if (req.method === "POST" && url.pathname.startsWith("/v0/")) {
          const morceaux = [];
          req.on("data", (d) => morceaux.push(d));
          req.on("end", async () => {
            let corps;
            try {
              corps = J.analyserJSONStrict(Buffer.concat(morceaux));
            } catch {
              corps = null;
            }
            const [statut, valeur] = await Promise.resolve(repondre(url.pathname.slice(4), corps));
            res.writeHead(statut, { "content-type": "application/json" });
            res.end(JSON.stringify(valeur));
          });
          return;
        }
        const statiques = { "/console/": ["console/index.html", "text/html; charset=utf-8"], "/console/console.js": ["console/console.js", "text/javascript"], "/console/console.css": ["console/console.css", "text/css"], "/scripts/lib/console.mjs": ["scripts/lib/console.mjs", "text/javascript"] };
        const f = statiques[url.pathname];
        if (!f || req.method !== "GET") {
          res.writeHead(404, { "content-type": "text/plain" });
          res.end("introuvable");
          return;
        }
        let octets = fs.readFileSync(path.join(PROJECT_ROOT, f[0]));
        if (url.pathname === "/scripts/lib/console.mjs" && etat.scenario?.bibliothequeAlteree) octets = Buffer.concat([octets, Buffer.from("\n")]);
        if (url.pathname === "/console/console.js" && etat.scenario?.entreeAlteree) octets = Buffer.concat([octets, Buffer.from("\n")]);
        const entetes = { "content-type": f[1], "cache-control": "no-store" };
        if (f[1].startsWith("text/html")) Object.assign(entetes, empreintesConsole().entetes);
        if (url.pathname === "/console/" && etat.scenario?.page) {
          octets = Buffer.from(etat.scenario.page.html, "utf8");
          Object.assign(entetes, etat.scenario.page.entetes);
        }
        res.writeHead(200, entetes);
        res.end(octets);
      });
      s.listen(0, "127.0.0.1", () => ok(s));
    });
  }

  /** Portefeuille simulé, côté Node : signe avec les clés de test de A.2 selon le scénario. */
  async function portefeuille(nom, method, params) {
    etat.appels.push({ fournisseur: nom, method, params });
    const p = etat.scenario.portefeuille ?? {};
    if (method === "eth_requestAccounts") return { result: (p.comptes ?? [1]).map(ADR) };
    if (method !== "personal_sign") return { error: { code: 4200, message: "méthode non prise en charge" } };
    const mode = p.signature ?? "canonique";
    if (mode === "4001") return { error: { code: 4001, message: "User rejected the request." } };
    if (mode === "attendre") return new Promise((r) => (etat.resoudre = r));
    const compte = mode === "autre-compte" ? 2 : p.signataire ?? 1;
    const sig = Signature.from(COMPTES[compte].signingKey.sign(hashMessage(getBytes(params[0])))).serialized;
    const n = K.N_SECP256K1;
    const formes = {
      canonique: sig,
      "autre-compte": sig,
      "v-0-1": sig.slice(0, 130) + (sig.endsWith("1b") ? "00" : "01"),
      "s-haut": sig.slice(0, 66) + (n - BigInt("0x" + sig.slice(66, 130))).toString(16).padStart(64, "0") + (sig.endsWith("1b") ? "1c" : "1b"),
      "v-29": sig.slice(0, 130) + "1d",
      "v-37": sig.slice(0, 130) + "25",
      "longueur-64": sig.slice(0, 130),
    };
    return { result: formes[mode] };
  }

  /** Ouvre la page pour un scénario : fournisseurs injectés, horloge fixée (et suspendue sur demande), requêtes hors de l'origine refusées et comptées, erreurs de script relevées. */
  async function ouvrir(scenario, { fournisseurs = FOURNISSEURS, doublon = false, url = `${ORIGINE}/console/`, suspendre = false } = {}) {
    etat.scenario = scenario;
    etat.recus = [];
    etat.appels = [];
    etat.requetes = [];
    etat.refusees = [];
    etat.erreursPage = [];
    etat.resoudre = null;
    etat.liberer = null;
    const contexte = await navigateur.newContext();
    const page = await contexte.newPage();
    page.on("pageerror", (e) => etat.erreursPage.push(String(e?.message ?? e)));
    await page.clock.install({ time: new Date("2026-11-05T09:24:00.000Z") });
    if (suspendre) await page.clock.pauseAt(new Date("2026-11-05T09:24:00.010Z"));
    await page.exposeFunction("__portefeuille", portefeuille);
    await page.addInitScript(injecter, { fournisseurs, doublon, icone: ICONE });
    await contexte.route("**/*", async (route) => {
      const u = new URL(route.request().url());
      etat.requetes.push(u.href);
      try {
        if (u.origin === ORIGINE) {
          const reponse = await route.fetch({ url: `${base}${u.pathname}${u.search}` });
          return await route.fulfill({ response: reponse });
        }
        if (u.origin === "https://autre.example" && u.pathname === "/cadre") return await route.fulfill({ status: 200, contentType: "text/html", body: `<!doctype html><html><body><iframe src="${ORIGINE}/console/"></iframe></body></html>` });
        etat.refusees.push(u.href);
        return await route.abort();
      } catch {
        // Contexte fermé pendant une requête en cours : rien à servir.
        return undefined;
      }
    });
    const reponse = await page.goto(url);
    return { contexte, page, reponse };
  }

  const texte = (page, testid) => page.getByTestId(testid).first().textContent();
  const codes = async (page, testid = "raison") => page.locator(`[data-testid="${testid}"]`).evaluateAll((ns) => ns.map((n) => n.getAttribute("data-code")));
  const attendre = async (condition) => {
    for (let i = 0; i < 500 && !condition(); i++) await new Promise((r) => setTimeout(r, 20));
    expect(condition()).to.equal(true);
  };
  async function choisir(page, uuid = FOURNISSEURS[0].uuid) {
    await page.locator(`[data-testid="fournisseur"][data-uuid="${uuid}"] [data-testid="choisir-fournisseur"]`).click();
    await page.getByTestId("fournisseur-choisi").waitFor();
  }
  async function ouvrirLeTicket(page, ticket = null) {
    await (ticket ? page.locator(`[data-ticket="${ticket}"] [data-testid="ouvrir-ticket"]`) : page.getByTestId("ouvrir-ticket").first()).click();
    await page.getByTestId("modele").waitFor();
    if (ticket) await page.locator("h2", { hasText: `Ticket ${ticket} ` }).waitFor();
  }
  async function choisirEtOuvrir(page, uuid = FOURNISSEURS[0].uuid) {
    await choisir(page, uuid);
    await ouvrirLeTicket(page);
  }
  async function decider(page, bouton, motif = null) {
    if (motif !== null) await page.getByTestId("motif").fill(motif);
    await page.getByTestId(bouton).click();
    await page.getByTestId("confirmer").click();
  }
  const personalSign = () => etat.appels.filter((a) => a.method === "personal_sign");
  const recus = (m) => etat.recus.filter((r) => r.methode === m);

  before(async function () {
    try {
      chromium = createRequire(import.meta.url)("playwright").chromium;
      navigateur = await chromium.launch();
    } catch (e) {
      raisonSaut = `Playwright ou Chromium indisponible : ${String(e?.message ?? e).split("\n")[0]}`;
      // EX-13.36 : sous NOORTRACE_EXIGER_CHROMIUM=1 (travail console-chromium de l'intégration continue), le saut est impossible.
      if (process.env.NOORTRACE_EXIGER_CHROMIUM === "1") throw new Error(`NOORTRACE_EXIGER_CHROMIUM=1 : ${raisonSaut}`);
      console.log(`      (tests Chromium sautés : ${raisonSaut})`);
      this.skip();
    }
    serveur = await demarrerServeur();
    base = `http://127.0.0.1:${serveur.address().port}`;
  });

  after(async function () {
    if (navigateur) await navigateur.close();
    if (serveur) await new Promise((ok) => serveur.close(ok));
  });

  it("nominal : deux fournisseurs listés, aucun appel avant le choix ; modèle d'EX-9.4 et marques ; empreinte de la décision ; un seul personal_sign [D_A, adresse] ; voter exact ; aucune autre origine ; aucune erreur de script", async function () {
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      expect(await page.getByTestId("nom-fournisseur").allTextContents()).to.deep.equal([" Portefeuille de test A ", " Portefeuille de test B "]);
      expect(await page.getByTestId("fournisseur-choisi").count()).to.equal(0);
      await ouvrirLeTicket(page);
      expect(etat.appels).to.deep.equal([]);
      expect(await page.getByTestId("approuver").isDisabled()).to.equal(true);
      expect(await codes(page)).to.deep.equal(["fournisseur_non_choisi"]);
      await choisirEtOuvrir(page);
      expect(etat.appels.map((a) => [a.fournisseur, a.method])).to.deep.equal([["a", "eth_requestAccounts"]]);
      const args = await page.getByTestId("argument").evaluateAll((ns) => ns.map((n) => [n.getAttribute("data-pointer"), n.getAttribute("data-statut"), n.lastChild.textContent]));
      expect(args).to.deep.equal([["/amount", "verifie", "vérifié"], ["/beneficiary_iban", "non_verifiable", "non vérifiable par la console"], ["/claim_id", "verifie", "vérifié"], ["/currency", "verifie", "vérifié"]]);
      expect(await texte(page, "intention")).to.include("déclarée par l'agent, non vérifiée");
      expect(await page.getByTestId("intention").getAttribute("data-statut")).to.equal("en_clair");
      expect(await texte(page, "effets")).to.include("SAP, ecriture ; objet 2026-81044 ; montant 12500.00 CHF");
      expect(await codes(page)).to.deep.equal([]);
      // Refuser : l'empreinte de D_refuse ; puis on revient en arrière sans signer.
      await decider(page, "refuser");
      await page.getByTestId("ecran-signature").waitFor();
      expect(await texte(page, "empreinte")).to.equal("d2cace7b…8ccab300");
      await decider(page, "approuver", VOTE.reason);
      await page.locator('[data-testid="ecran-signature"][data-decision="approuve"]').waitFor();
      expect(await texte(page, "empreinte")).to.equal("a57cbdad…64f7df7c");
      expect(await texte(page, "groupes")).to.include("a57cbdad 280b5cb2 e9f6ee87 b85d8bc0 5e76a596 6377e7d5 80465194 64f7df7c");
      expect(await texte(page, "empreinte-h")).to.equal("e9f3d881…1d2cf6ea");
      expect(await texte(page, "d-a")).to.include("0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c");
      // Consignes d'EX-9.20, points 1 à 7, dont la console saine ouverte à son origine (point 5).
      const consignes = await page.getByTestId("consignes").locator("li").allTextContents();
      expect(consignes.length).to.equal(7);
      expect(consignes[4]).to.include(`la console de l'organisation ouverte à son origine (${ORIGINE}), sur un autre poste ou dans un autre profil de navigateur sans extension que celui où l'écart est apparu, ou après que l'administrateur prévenu a écarté la cause`);
      expect(consignes[4]).to.include("La concordance des empreintes ne prouve pas qu'une console est saine.");
      expect(consignes[0]).to.include("« non vérifiable par la console » quand l'événement la porte par une référence");
      expect(consignes[6]).to.include("une décision déjà scellée ne s'annule pas");
      expect(personalSign()).to.deep.equal([]);
      await page.getByTestId("signer").click();
      await page.locator('[data-testid="resultat"][data-code="vote_inscrit"]').waitFor();
      expect(personalSign()).to.deep.equal([{ fournisseur: "a", method: "personal_sign", params: ["0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c", ADR(1)] }]);
      expect(recus("voter").map((r) => r.corps)).to.deep.equal([VOTE]);
      expect(await page.getByTestId("resultat").getAttribute("data-etat")).to.equal("verification");
      expect(recus("consulter").map((r) => r.corps)).to.deep.include({ ticket: "apr-2201", session_identity: ID("approbateur-1") });
      expect(etat.refusees).to.deep.equal([]);
      expect(etat.requetes.every((u) => u.startsWith(ORIGINE + "/"))).to.equal(true);
      expect(await page.evaluate(() => window.__lecturesEthereum.n)).to.equal(0);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("intention et effets (EX-9.4, EX-9.15 contrôle 4, EX-12.14) : intention portée par une référence marquée « non vérifiable par la console » ; effet tiré du résultat affiché « connu après exécution » ; aucun blocage", async function () {
    const vueRef = vecteurVue("intention-par-reference.json");
    const vueEffet = vecteurVue("effet-connu-apres-execution.json");
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vues: [vueRef, vueEffet] });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisir(page);
      await ouvrirLeTicket(page, "apr-0902");
      expect(await page.getByTestId("intention").getAttribute("data-statut")).to.equal("reference_non_verifiable");
      const intention = await texte(page, "intention");
      expect(intention).to.include("non vérifiable par la console").and.not.to.include("déclarée par l'agent");
      expect(intention).to.include(vueRef.request.intent);
      expect(await codes(page)).to.deep.equal([]);
      expect(await page.getByTestId("approuver").isDisabled()).to.equal(false);
      await ouvrirLeTicket(page, "apr-2201");
      expect(await page.getByTestId("intention").getAttribute("data-statut")).to.equal("en_clair");
      expect(await texte(page, "effets")).to.include("SAP, ecriture ; objet connu après exécution (/result/document_id) ; montant 12500.00 CHF");
      expect(await codes(page)).to.deep.equal([]);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("refus 4001 : aucun voter, la page dit que la signature a été refusée, les deux boutons restent offerts", async function () {
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, portefeuille: { signature: "4001" } });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      await decider(page, "approuver");
      await page.getByTestId("signer").click();
      await page.locator('[data-testid="resultat"][data-code="refus_approbateur"]').waitFor();
      expect(await texte(page, "resultat")).to.include("signature refusée dans le portefeuille ; aucun vote n'a été envoyé");
      expect(recus("voter")).to.deep.equal([]);
      expect(await page.getByTestId("approuver").isEnabled()).to.equal(true);
      expect(await page.getByTestId("refuser").isEnabled()).to.equal(true);
    } finally {
      await contexte.close();
    }
  });

  it("mauvaise adresse : signature d'un autre compte, aucun voter, adresse_differente et adresse recouvrée affichées", async function () {
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, portefeuille: { signature: "autre-compte" } });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      await decider(page, "approuver");
      await page.getByTestId("signer").click();
      await page.locator('[data-testid="resultat"][data-code="adresse_differente"]').waitFor();
      expect(await texte(page, "resultat")).to.include(ADR(2));
      expect(recus("voter")).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("empreinte divergente (EX-9.17) : digests du service faux, aucun personal_sign, raison affichée avec les deux empreintes abrégées de chaque décision, boutons inactifs", async function () {
    for (const [f, differe] of [["condense-service-faux-approuve.json", "approuve"], ["condense-service-faux-refuse.json", "refuse"]]) {
      const vue = vecteurVue(f);
      const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue });
      try {
        await page.getByTestId("fournisseur").nth(1).waitFor();
        await choisirEtOuvrir(page);
        expect(await codes(page), f).to.include("empreinte_divergente");
        expect(await texte(page, "raisons"), f).to.include("le service a calculé un autre condensé que la console : aucune signature n'est demandée");
        const lignes = await page.getByTestId("empreintes-decision").evaluateAll((ns) => ns.map((n) => [n.getAttribute("data-decision"), n.getAttribute("data-differe"), n.textContent]));
        expect(lignes.map(([d, x]) => [d, x]), f).to.deep.equal([["approuve", String(differe === "approuve")], ["refuse", String(differe === "refuse")]]);
        expect(lignes[0][2], f).to.include("console a57cbdad…64f7df7c ; service " + K.empreinte(vue.digests.approuve));
        expect(lignes[1][2], f).to.include("console d2cace7b…8ccab300 ; service " + K.empreinte(vue.digests.refuse));
        expect(await page.getByTestId("approuver").isDisabled(), f).to.equal(true);
        expect(await page.getByTestId("refuser").isDisabled(), f).to.equal(true);
        expect(personalSign(), f).to.deep.equal([]);
        expect(recus("voter"), f).to.deep.equal([]);
        expect(etat.erreursPage, f).to.deep.equal([]);
      } finally {
        await contexte.close();
      }
    }
  });

  for (const [mode, attendu] of [["v-0-1", "envoyé"], ["s-haut", "envoyé"], ["v-29", "signature_invalide"], ["v-37", "signature_invalide"], ["longueur-64", "signature_invalide"]]) {
    it(`formes de signature : ${mode} — ${attendu === "envoyé" ? "vote envoyé avec la forme normalisée" : "aucun voter (signature_invalide)"}`, async function () {
      const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, portefeuille: { signature: mode } });
      try {
        await page.getByTestId("fournisseur").nth(1).waitFor();
        await choisirEtOuvrir(page);
        await decider(page, "approuver", VOTE.reason);
        await page.getByTestId("signer").click();
        if (attendu === "envoyé") {
          await page.locator('[data-testid="resultat"][data-code="vote_inscrit"]').waitFor();
          expect(recus("voter").map((r) => r.corps)).to.deep.equal([VOTE]);
        } else {
          await page.locator('[data-testid="resultat"][data-code="signature_invalide"]').waitFor();
          expect(recus("voter")).to.deep.equal([]);
        }
      } finally {
        await contexte.close();
      }
    });
  }

  it("délai (EX-13.30) : sans réponse dans delai_signature_ms, delai_depasse ; la signature tardive n'est pas envoyée", async function () {
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, portefeuille: { signature: "attendre" } });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      await decider(page, "approuver");
      await page.getByTestId("signer").click();
      await attendre(() => etat.resoudre !== null);
      await page.clock.fastForward(K.DELAI_SIGNATURE_MS.defaut + 1000);
      await page.locator('[data-testid="resultat"][data-code="delai_depasse"]').waitFor();
      const sig = Signature.from(COMPTES[1].signingKey.sign(hashMessage(getBytes(personalSign()[0].params[0])))).serialized;
      etat.resoudre({ result: sig });
      await page.waitForTimeout(300);
      expect(recus("voter")).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("changement de ticket (EX-9.21, point 8 ; EX-13.21) : un autre ticket ouvert pendant l'écran de signature, ou pendant les attentes qui suivent le choix ou la signature — aucun écran périmé, aucun voter avec la signature de l'ancien ticket", async function () {
    const scenario = () => ({ session: ID("approbateur-1"), annuaire: REF, vues: [VUE_2201, VUE_0901] });
    // a) Écran de signature d'apr-2201 affiché, puis apr-0901 ouvert : l'écran disparaît, rien n'est signé.
    let { contexte, page } = await ouvrir(scenario());
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisir(page);
      await ouvrirLeTicket(page, "apr-2201");
      await decider(page, "approuver");
      await page.locator('[data-testid="ecran-signature"][data-ticket="apr-2201"]').waitFor();
      await ouvrirLeTicket(page, "apr-0901");
      expect(await page.getByTestId("ecran-signature").count()).to.equal(0);
      expect(personalSign()).to.deep.equal([]);
      expect(recus("voter")).to.deep.equal([]);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
    // b) apr-0901 ouvert pendant le consulter de la confirmation d'apr-2201 : aucun écran de signature, le titre reste apr-0901.
    ({ contexte, page } = await ouvrir({ ...scenario(), retenir: { ticket: "apr-2201", n: 2, vus: 0 } }));
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisir(page);
      await ouvrirLeTicket(page, "apr-2201");
      await decider(page, "approuver");
      await attendre(() => etat.liberer !== null);
      await ouvrirLeTicket(page, "apr-0901");
      etat.liberer();
      await page.waitForTimeout(300);
      expect(await page.locator("h2", { hasText: "Ticket apr-0901 " }).count()).to.equal(1);
      expect(await page.getByTestId("ecran-signature").count()).to.equal(0);
      expect(personalSign()).to.deep.equal([]);
      expect(recus("voter")).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
    // c) apr-0901 ouvert pendant le consulter qui suit la signature d'apr-2201 : aucun voter.
    ({ contexte, page } = await ouvrir({ ...scenario(), retenir: { ticket: "apr-2201", n: 3, vus: 0 } }));
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisir(page);
      await ouvrirLeTicket(page, "apr-2201");
      await decider(page, "approuver");
      await page.locator('[data-testid="ecran-signature"][data-ticket="apr-2201"]').waitFor();
      await page.getByTestId("signer").click();
      await attendre(() => etat.liberer !== null);
      expect(personalSign().map((a) => a.params[0])).to.deep.equal([VUE_2201.digests.approuve]);
      await ouvrirLeTicket(page, "apr-0901");
      etat.liberer();
      await page.waitForTimeout(300);
      expect(recus("voter")).to.deep.equal([]);
      expect(await page.getByTestId("ecran-signature").count()).to.equal(0);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("annuaire (EX-13.18) : adresse révoquée, entrée inactive, session du demandeur, adresse hors jeu — boutons inactifs et raison ; separation_incomplete affiché", async function () {
    const revoque = K.appliquerOperation(REF, "revoquer", { session_identity: ID("approbateur-1"), entry: "apb-0001", address: ADR(1), reason: "Clé perdue" }, "2026-11-10T11:00:00.000Z").annuaire;
    const inactif = K.appliquerOperation(REF, "desactiver", { session_identity: ID("admin-1"), entry: "apb-0002", reason: null }, "2026-11-10T11:00:00.000Z").annuaire;
    const horsJeu = JSON.parse(JSON.stringify(VUE_2201));
    horsJeu.approver_set.members = [ADR(2), ADR(3), ADR(4)].sort();
    const cas = [
      [{ session: ID("approbateur-1"), annuaire: revoque, vue: VUE_2201, portefeuille: { comptes: [1] } }, "adresse_non_attribuee"],
      [{ session: ID("approbateur-2"), annuaire: inactif, vue: VUE_2201, portefeuille: { comptes: [2] } }, "identite_desactivee"],
      [{ session: ID("u.martin"), annuaire: REF, vue: VUE_2201, portefeuille: { comptes: [3] } }, "session_du_demandeur"],
      [{ session: ID("approbateur-1"), annuaire: REF, vue: horsJeu, portefeuille: { comptes: [1] } }, "hors_jeu"],
    ];
    for (const [scenario, raison] of cas) {
      const { contexte, page } = await ouvrir(scenario);
      try {
        await page.getByTestId("fournisseur").nth(1).waitFor();
        await choisirEtOuvrir(page);
        expect(await codes(page), raison).to.include(raison);
        expect(await page.getByTestId("approuver").isDisabled(), raison).to.equal(true);
        expect(await page.getByTestId("refuser").isDisabled(), raison).to.equal(true);
        expect(personalSign()).to.deep.equal([]);
      } finally {
        await contexte.close();
      }
    }
    const { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: vecteurVue("separation-incomplete.json") });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      expect(await codes(page, "avertissement")).to.deep.equal(["separation_incomplete"]);
      expect(await page.getByTestId("approuver").isEnabled()).to.equal(true);
    } finally {
      await contexte.close();
    }
  });

  it("comptes (EX-13.23, 13.14) : adresse active non exposée, affichée, puis retenue après accountsChanged ; accountsChanged qui retire l'adresse retire l'écran de signature, sans erreur de script", async function () {
    let { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, portefeuille: { comptes: [2] } });
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      expect(await codes(page)).to.deep.equal(["adresse_non_exposee", "adresse_non_attribuee"]);
      expect(await page.getByTestId("adresse-attribuee").getAttribute("data-adresse")).to.equal(ADR(1));
      expect(await page.getByTestId("approuver").isDisabled()).to.equal(true);
      await page.evaluate((a) => window.__emettre("a", "accountsChanged", [a]), ADR(1));
      await page.locator('[data-testid="approuver"]:not([disabled])').waitFor();
      expect(await codes(page)).to.deep.equal([]);
      expect(await page.getByTestId("adresse-attribuee").count()).to.equal(0);
      expect(personalSign()).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 }));
    try {
      await page.getByTestId("fournisseur").nth(1).waitFor();
      await choisirEtOuvrir(page);
      await decider(page, "approuver");
      await page.getByTestId("ecran-signature").waitFor();
      await page.evaluate(() => window.__emettre("a", "accountsChanged", []));
      await page.locator('[data-testid="raison"][data-code="adresse_non_exposee"]').waitFor();
      expect(await page.getByTestId("ecran-signature").count()).to.equal(0);
      expect(await page.getByTestId("approuver").isDisabled()).to.equal(true);
      expect(personalSign()).to.deep.equal([]);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("inscription (EX-13.13, EX-13.15, 13.14) : personal_sign sur [texte en hexadécimal, adresse], puis inscrire exact ; texte altéré ou d'une autre origine : aucun appel au portefeuille ; inscription_expiree : consigne de recommencer", async function () {
    const cas = lire("annuaire", "inscriptions.json").cases.find((c) => c.id === "cree-entree");
    const depart = lire("annuaire", "annuaires", "avant-inscriptions.json");
    const preparer = { fields: cas.challenges[0].fields, message: cas.request.message };
    const ouvrirInscription = async (prep, extra = {}) => {
      const r = await ouvrir({ session: cas.request.session_identity, annuaire: depart, vue: null, preparer: prep, portefeuille: { comptes: [3], signataire: 3 }, ...extra });
      await r.page.getByTestId("fournisseur").nth(1).waitFor();
      await r.page.locator(`[data-testid="fournisseur"][data-uuid="${FOURNISSEURS[0].uuid}"] [data-testid="choisir-fournisseur"]`).click();
      await r.page.getByTestId("choisir-compte").click();
      return r;
    };
    let { contexte, page } = await ouvrirInscription(preparer);
    try {
      await page.getByTestId("ligne-message").nth(9).waitFor();
      expect(await page.getByTestId("ligne-message").allTextContents()).to.deep.equal(cas.request.message.split("\n"));
      expect(recus("preparer_inscription").map((r) => r.corps)).to.deep.equal([{ session_identity: cas.request.session_identity, address: ADR(3) }]);
      await page.getByTestId("signer-inscription").click();
      await page.locator('[data-testid="resultat-inscription"][data-code="en_attente"]').waitFor();
      expect(personalSign()).to.deep.equal([{ fournisseur: "a", method: "personal_sign", params: [K.donneesPersonalSign(cas.request.message), ADR(3)] }]);
      expect(recus("inscrire").map((r) => r.corps)).to.deep.equal([cas.request]);
    } finally {
      await contexte.close();
    }
    const altere = { ...preparer, message: preparer.message.replace("Ce message n'est pas un vote.", "Ce message n'est pas un vote!") };
    const autreOrigine = { ...preparer.fields, origin: "https://console.autre-demo.example" };
    for (const [prep, code] of [[altere, "message_invalide"], [{ fields: autreOrigine, message: K.messageInscription(autreOrigine) }, "origine_differente"]]) {
      ({ contexte, page } = await ouvrirInscription(prep));
      try {
        await page.locator(`[data-testid="resultat-inscription"][data-code="${code}"]`).waitFor();
        expect(await texte(page, "resultat-inscription"), code).to.include("aucune signature n'est demandée : prévenez l'administrateur");
        expect(personalSign(), code).to.deep.equal([]);
        expect(recus("inscrire"), code).to.deep.equal([]);
      } finally {
        await contexte.close();
      }
    }
    ({ contexte, page } = await ouvrirInscription(preparer, { inscrireErreur: "inscription_expiree" }));
    try {
      await page.getByTestId("signer-inscription").click();
      await page.locator('[data-testid="resultat-inscription"][data-code="inscription_expiree"]').waitFor();
      expect(await texte(page, "resultat-inscription")).to.include("demandez un nouveau message");
      expect(recus("inscrire").length).to.equal(1);
    } finally {
      await contexte.close();
    }
  });

  it("aucun portefeuille puis annonce en double : la page le dit 1 000 ms après la découverte et pas avant, window.ethereum n'est pas lu, une réannonce est sans effet, un uuid revendiqué par deux objets est écarté", async function () {
    let { contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 }, { fournisseurs: [], suspendre: true });
    try {
      await page.getByTestId("session").waitFor();
      await page.getByTestId("ouvrir-ticket").waitFor();
      expect(await page.getByTestId("aucun-fournisseur").count()).to.equal(0);
      await page.clock.runFor(500);
      expect(await page.getByTestId("aucun-fournisseur").count()).to.equal(0);
      await page.clock.runFor(600);
      await page.getByTestId("aucun-fournisseur").waitFor();
      expect(await page.getByTestId("aucun-fournisseur").getAttribute("data-code")).to.equal("aucun_fournisseur");
      expect(await page.evaluate(() => window.__lecturesEthereum.n)).to.equal(0);
    } finally {
      await contexte.close();
    }
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 }, { doublon: true }));
    try {
      await page.getByTestId("annonce-ecartee").nth(1).waitFor();
      await page.evaluate(() => window.dispatchEvent(new Event("eip6963:requestProvider")));
      await page.waitForTimeout(200);
      expect(await page.getByTestId("nom-fournisseur").allTextContents()).to.deep.equal([" Portefeuille de test B "]);
      const ecartees = await codes(page, "annonce-ecartee");
      expect(ecartees.length).to.be.at.least(2);
      expect(new Set(ecartees)).to.deep.equal(new Set(["annonce_en_double"]));
      expect(await page.evaluate(() => window.__lecturesEthereum.n)).to.equal(0);
      expect(etat.appels).to.deep.equal([]);
      expect(etat.erreursPage).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });

  it("politique du contenu (EX-13.35) : en-têtes exacts ; script en ligne non exécuté ; innerHTML refusé ; bibliothèque ou script d'entrée altérés, module sans intégrité dans la carte : la page ne s'initialise pas ; page encadrée : non chargée", async function () {
    const e = empreintesConsole();
    const nonInitialisee = async (page) => {
      await page.waitForTimeout(1000);
      expect(await page.getByTestId("session").count()).to.equal(0);
      expect(await page.locator("#console").evaluate((n) => n.childElementCount)).to.equal(0);
      expect(recus("session")).to.deep.equal([]);
    };
    let { contexte, page, reponse } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 });
    try {
      await page.getByTestId("session").waitFor();
      expect(reponse.headers()["content-security-policy"]).to.equal(e.entetes["content-security-policy"]);
      expect(reponse.headers()["integrity-policy"]).to.equal(e.entetes["integrity-policy"]);
      expect(await page.evaluate(() => {
        try {
          document.body.innerHTML = "<b>x</b>";
          return "accepte";
        } catch (x) {
          return x.name;
        }
      })).to.equal("TypeError");
    } finally {
      await contexte.close();
    }
    // Script en ligne ajouté au document servi, sous la même politique : il n'est pas exécuté, la page fonctionne.
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, page: { html: e.html.replace("</head>", "<script>window.__enLigne = 1;</script>\n</head>"), entetes: e.entetes } }));
    try {
      await page.getByTestId("session").waitFor();
      expect(await page.evaluate(() => typeof window.__enLigne)).to.equal("undefined");
    } finally {
      await contexte.close();
    }
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, bibliothequeAlteree: true }));
    try {
      await nonInitialisee(page);
    } finally {
      await contexte.close();
    }
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, entreeAlteree: true }));
    try {
      await nonInitialisee(page);
    } finally {
      await contexte.close();
    }
    // Carte d'importation sans intégrité pour la bibliothèque, autorisée par son condensé : Integrity-Policy bloque le module.
    const carteSans = JSON.stringify(JSON.parse(e.carte).imports ? { imports: JSON.parse(e.carte).imports } : {});
    const condenseSans = "sha256-" + crypto.createHash("sha256").update(carteSans, "utf8").digest("base64");
    const pageSans = { html: e.html.replace(e.carte, carteSans), entetes: { ...e.entetes, "content-security-policy": e.entetes["content-security-policy"].replace(e.carteSha256, condenseSans) } };
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201, page: pageSans }));
    try {
      await nonInitialisee(page);
    } finally {
      await contexte.close();
    }
    ({ contexte, page } = await ouvrir({ session: ID("approbateur-1"), annuaire: REF, vue: VUE_2201 }, { url: "https://autre.example/cadre" }));
    try {
      await page.waitForTimeout(1000);
      const cadre = page.frames()[1];
      expect(cadre).to.not.equal(undefined);
      expect(cadre.url().startsWith(ORIGINE)).to.equal(false);
      expect(recus("session")).to.deep.equal([]);
    } finally {
      await contexte.close();
    }
  });
});
