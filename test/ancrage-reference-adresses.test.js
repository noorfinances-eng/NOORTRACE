import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as A from "../scripts/lib/ancrage.mjs";

// CT-5 EX-4.9 (AN-1), règle 4, révision 0.9 ; AN-27 ; 5.2 (authentification) :
// règles d'adresse et d'authentification des prestataires RFC 3161, dans la
// bibliothèque de référence scripts/lib/ancrage.mjs (verifierConfiguration).
//
//   - le serveur RFC 3161 interne (rôle interne ; hors production, principal
//     sans statut qualified) : http:// vers une adresse locale (127.0.0.1,
//     ::1, localhost) sans authentification, ou https:// avec basic ou
//     certificat_client ;
//   - un principal qualifié, un secours ou un second_rang : https:// avec
//     authentification, dans tout profil ;
//   - en production, un principal non qualifié est refusé, et chacune des
//     formes « http:// » et « sans authentification » l'est avec la raison
//     « le serveur RFC 3161 interne n'est admis comme principal que hors
//     production ».
//
// Défaut reproduit : la bibliothèque n'appliquait les règles d'adresse qu'en
// production ; hors production, elle acceptait une adresse http:// non
// locale pour tout prestataire, et ne contrôlait l'authentification dans
// aucun profil.

const MD = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8");
const exemple = () => JSON.parse(/<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
const SANS = { method: "aucune", secret: null };
const BASIC = { method: "basic", secret: { env: "NOORTRACE_TSA_ESSAI" } };
const CERTIFICAT = { method: "certificat_client", secret: { file: "/run/secrets/tsa-essai" } };
const PROFILS = ["developpement", "test", "production"];

/** Les violations de l'exemple d'EX-4.8 modifié, pour un profil. */
function violations(profil, modifier) {
  const doc = exemple();
  const de = (role) => doc.rfc3161.providers.find((p) => p.role === role);
  modifier(de, doc);
  return A.verifierConfiguration(doc, { profil, checkpoint_interval_s: 60, lecteurCertificat: () => true }).violations;
}
const messages = (profil, modifier) => violations(profil, modifier).map((v) => `${v.rule} ${v.message}`);

describe("CT-5 EX-4.9, règle 4 (AN-1, AN-27) : adresse et authentification des prestataires dans tout profil (verifierConfiguration de la référence)", function () {
  it("l'exemple d'EX-4.8 (principal et secours en https:// avec basic, serveur interne en http://127.0.0.1 sans authentification) est accepté dans les trois profils", function () {
    for (const profil of PROFILS) expect(violations(profil, () => {}), profil).to.deep.equal([]);
  });

  it("défaut reproduit : hors production, une adresse http:// non locale est refusée par la règle 4 pour le serveur interne, le principal qualifié, le secours et le second rang", function () {
    for (const profil of ["developpement", "test"]) {
      expect(messages(profil, (de) => (de("interne").url = "http://tsa.interne.example:2020/")), profil).to.deep.equal(["4 prestataire interne tsa-interne : http:// admis vers une adresse locale seulement"]);
      expect(messages(profil, (de) => (de("principal").url = "http://tsa.principal.example/")), profil).to.deep.equal(["4 prestataire qtsa-principal (principal) : url en https:// exigée"]);
      expect(messages(profil, (de) => (de("secours").url = "http://tsa.secours.example/")), profil).to.deep.equal(["4 prestataire qtsa-secours (secours) : url en https:// exigée"]);
      const secondRang = (de, doc) => {
        Object.assign(de("interne"), { id: "tsa-second-rang", role: "second_rang", url: "http://tsa.second.example/", auth: BASIC });
        doc.rfc3161.checkpoints.provider_role = "second_rang";
      };
      expect(messages(profil, secondRang), profil).to.deep.equal(["4 prestataire tsa-second-rang (second_rang) : url en https:// exigée"]);
    }
  });

  it("adresses locales du serveur interne : 127.0.0.1, ::1 et localhost admis en http:// ; une adresse RFC 5737, une adresse RFC 3849 et un nom refusés, dans les trois profils", function () {
    for (const profil of PROFILS) {
      for (const url of ["http://127.0.0.1:2020/", "http://[::1]:2020/", "http://localhost:2020/tsa"]) expect(violations(profil, (de) => (de("interne").url = url)), `${profil} ${url}`).to.deep.equal([]);
      for (const url of ["http://192.0.2.10:2020/", "http://[2001:db8::1]:2020/", "http://localhost.example:2020/", "http://tsa.interne.example/"]) expect(violations(profil, (de) => (de("interne").url = url)).map((v) => v.rule), `${profil} ${url}`).to.deep.equal([4]);
    }
  });

  it("hors production, un principal sans statut qualified suit les règles du serveur interne : http:// local sans authentification ou https:// avec basic ou certificat_client ; toute autre forme est refusée", function () {
    const principal = (o) => (de) => Object.assign(de("principal"), { qualified: null }, o);
    for (const profil of ["developpement", "test"]) {
      expect(violations(profil, principal({ url: "http://127.0.0.1:2020/", auth: SANS })), profil).to.deep.equal([]);
      expect(violations(profil, principal({ url: "https://tsa.interne.example/", auth: BASIC })), profil).to.deep.equal([]);
      expect(violations(profil, principal({ url: "https://tsa.interne.example/", auth: CERTIFICAT })), profil).to.deep.equal([]);
      expect(messages(profil, principal({ url: "http://tsa.interne.example:2020/", auth: SANS })), profil).to.deep.equal(["4 principal non qualifié qtsa-principal : http:// admis vers une adresse locale seulement"]);
      expect(messages(profil, principal({ url: "http://127.0.0.1:2020/", auth: BASIC })), profil).to.deep.equal(["4 principal non qualifié qtsa-principal : http:// vers une adresse locale admis sans authentification seulement"]);
      expect(messages(profil, principal({ url: "https://tsa.interne.example/", auth: SANS })), profil).to.deep.equal(["4 principal non qualifié qtsa-principal : authentification basic ou certificat_client exigée en https://"]);
    }
  });

  it("en production, un serveur interne désigné comme principal est refusé avec trois raisons : sans qualified, http://, sans authentification ; en https:// avec basic, la seule raison est l'absence de qualified", function () {
    const raison = "le serveur RFC 3161 interne n'est admis comme principal que hors production";
    expect(MD).to.include("« le serveur RFC 3161 interne n'est admis comme principal que hors").and.to.include("production » ;");
    expect(messages("production", (de) => Object.assign(de("principal"), { qualified: null, url: "http://127.0.0.1:2020/", auth: SANS }))).to.deep.equal([
      "4 le principal qtsa-principal n'a pas de statut qualified",
      `4 principal qtsa-principal désigné en http:// : ${raison}`,
      `4 principal qtsa-principal désigné sans authentification : ${raison}`,
    ]);
    expect(messages("production", (de) => (de("principal").qualified = null))).to.deep.equal(["4 le principal qtsa-principal n'a pas de statut qualified"]);
  });

  it("authentification, dans tout profil : un principal qualifié ou un secours sans authentification est refusé ; le serveur interne est refusé en https:// sans authentification et en http:// local avec basic (5.2 : basic seulement sur TLS)", function () {
    for (const profil of PROFILS) {
      expect(messages(profil, (de) => (de("principal").auth = SANS)), profil).to.deep.equal(["4 prestataire qtsa-principal (principal) : authentification exigée"]);
      expect(messages(profil, (de) => (de("secours").auth = SANS)), profil).to.deep.equal(["4 prestataire qtsa-secours (secours) : authentification exigée"]);
      expect(messages(profil, (de) => (de("interne").url = "https://tsa.interne.example/")), profil).to.deep.equal(["4 prestataire interne tsa-interne : authentification basic ou certificat_client exigée en https://"]);
      expect(messages(profil, (de) => (de("interne").auth = BASIC)), profil).to.deep.equal(["4 prestataire interne tsa-interne : http:// vers une adresse locale admis sans authentification seulement"]);
      expect(violations(profil, (de) => Object.assign(de("interne"), { url: "https://tsa.interne.example/", auth: CERTIFICAT })), profil).to.deep.equal([]);
    }
  });

  it("le reste de la règle 4 ne s'applique qu'en production : un secours sans statut qualified, en https:// avec basic, est accepté hors production et refusé en production", function () {
    const sansQualification = (de) => (de("secours").qualified = null);
    expect(violations("developpement", sansQualification)).to.deep.equal([]);
    expect(messages("production", sansQualification)).to.deep.equal(["4 le secours qtsa-secours n'a pas de statut qualified"]);
  });
});
