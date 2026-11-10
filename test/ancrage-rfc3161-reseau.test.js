// Lot A du composant d'ancrage : épreuve d'acceptation (CT-5 EX-11.4, AN-57)
// jouée sur deux autorités d'horodatage publiques qui répondent sans compte,
// par le transport de production (`transportHttps`, EX-5.5). Aucune de ces
// autorités n'est déclarée `qualified` : l'épreuve vaut pour l'interface, la
// qualification se recoupe sur une liste de confiance (EX-5.9).
//
// Condition : réseau public joignable, déclarée par NOORTRACE_TSA_PUBLIQUE=1 ;
// sinon chaque essai est en attente, sa condition dans le titre. Depuis une
// machine qui n'a d'accès que par un mandataire (HTTPS_PROXY), l'agent de la
// fixture tunnelle la connexion TLS par CONNECT ; le transport lui-même
// n'emploie aucun mandataire.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  acquerir, epreuveAcceptation, transportHttps, construireFiche, verifierFiche, certificatVersPem, lireReponse, lireJeton, lireCrl, capturerCrls, verifierRevocation,
  verifierJeton, VERIFICATIONS_ACQUISITION,
} from "@noortrace/ancrage/rfc3161";
import { AC_TEST_PEM, agentDepuisEnvironnement, agentHttpDepuisEnvironnement, enAttente, opensslDisponible, repertoireTemporaire } from "./fixtures/ancrage-rfc3161/outils.mjs";

const AUTORITES = [
  { id: "swisssign-public", url: "https://tsa.swisssign.net", policy_oid: null },
  { id: "dfn-zeitstempel", url: "https://zeitstempel.dfn.de", policy_oid: null },
];

const condition = () => (process.env.NOORTRACE_TSA_PUBLIQUE === "1" ? null : "réseau public joignable (NOORTRACE_TSA_PUBLIQUE=1)");
const horloge = { murale: () => Date.now(), monotone: () => performance.now() };
const aleatoire = (n) => new Uint8Array(randomBytes(n));

describe("ancrage rfc3161 : épreuve d'acceptation sur des autorités publiques (EX-11.4, AN-57, EX-5.5)", function () {
  this.timeout(120000);
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-ancrage-a-public-");
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  for (const a of AUTORITES) {
    it(`${a.id} (${a.url}) : jeton obtenu, nonce repris, T-1 à T-9 réussies avec la chaîne reçue pour ancres, openssl ts -verify OK, T-10 sur la CRL capturée`, async function () {
      const c = condition();
      if (c) return enAttente(this, c);
      const transport = transportHttps({ agent: agentDepuisEnvironnement(), agentHttp: agentHttpDepuisEnvironnement() });
      const base = {
        id: a.id, role: "second_rang", url: a.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: a.policy_oid, accepted_policies: null,
        anchor_certificates: [AC_TEST_PEM], qualified: null, min_interval_ms: 15000, request_timeout_ms: 20000, correlation_header: null,
        source: `autorité publique, essai d'interface du ${new Date().toISOString().slice(0, 10)} ; non déclarée qualified`,
      };
      // Premier passage : la chaîne de l'unité n'est pas connue d'avance (ancre de test) ; T-7 échoue, la réponse est lue.
      const premier = await epreuveAcceptation({ prestataire: base, transport, horloge, aleatoire });
      expect([200]).to.include(premier.http_status);
      expect(premier.pki_status).to.be.oneOf([0, 1]);
      expect(premier.nonce_in_response).to.equal(premier.nonce, "nonce repris (EX-5.10 étape 4)");
      expect(premier.imprint_matches).to.equal(true);
      // Second passage : les certificats d'AC lus dans le jeton reçu servent d'anchor_certificates (essai d'interface).
      const chaine = await acquerir({ prestataire: base, imprint: premier.imprint, objet: "point", attempt: 2, horloge, aleatoire, depot: null, transport });
      expect(chaine.jeton, "jeton reçu").to.not.equal(null);
      const jeton = lireJeton(chaine.jeton);
      const ac = jeton.certificats.filter((x) => x.contraintesBase && x.contraintesBase.ca);
      const ancres = (ac.length > 0 ? ac : jeton.certificats).map((x) => certificatVersPem(x.octets));
      const prestataire = { ...base, anchor_certificates: ancres };
      const epreuve = await epreuveAcceptation({ prestataire, transport, horloge, aleatoire });
      console.log(`      ${a.id} : ${JSON.stringify({ outcome: epreuve.outcome, error_code: epreuve.error_code, checks: epreuve.checks, gen_time: epreuve.gen_time, policy: epreuve.policy, tsu: epreuve.tsu_subject_cn, authority: epreuve.authority, warnings: epreuve.warnings })}`);
      expect(epreuve.outcome).to.equal("obtenue");
      expect(VERIFICATIONS_ACQUISITION.every((id) => epreuve.checks[id] === "reussi")).to.equal(true, JSON.stringify(epreuve.checks));
      const fiche = construireFiche(prestataire, { epreuve });
      expect(verifierFiche(fiche).ecarts).to.deep.equal([]);
      fs.writeFileSync(path.join(dir, `prestataire-${a.id}.json`), JSON.stringify(fiche, null, 2) + "\n");
      // T-10 : CRL capturées aux points de distribution des certificats du chemin, lues par le lecteur borné.
      const v = verifierJeton({ octets: chaine.jeton, imprintAttendue: premier.imprint, ancres: { certificatsPem: ancres, politiquesAdmises: null } });
      // Les CRL publiées se lisent par le lecteur borné et sont émises par les émetteurs du chemin ; une CRL dont
      // thisUpdate précède genTime n'est pas encore une preuve (EX-5.10 étape 10 : capture différée de delay_s, crl_indisponible réessayée).
      const brutes = await capturerCrls({ chemin: v.chemin, transport, horloge });
      for (const c of brutes.filter((x) => x.crl)) {
        const crl = lireCrl(c.crl);
        expect(crl.complete).to.equal(true);
        expect(v.chemin.some((x) => Buffer.from(x.emetteur.octets).equals(Buffer.from(crl.emetteur.octets))) || Buffer.from(v.autorite.certificat.emetteur.octets).equals(Buffer.from(crl.emetteur.octets))).to.equal(true, "émetteur de la CRL dans le chemin");
      }
      const captures = await capturerCrls({ chemin: v.chemin, transport, horloge, apresInstant: v.tstInfo.genTime });
      const crls = captures.filter((x) => x.crl).map((x) => x.crl);
      const dix = verifierRevocation({ chemin: v.chemin, autorite: { nom: v.autorite.nom, certificat: v.autorite.certificat, identite: v.identite }, crls, crlsJeton: v.jeton.crls, aInstant: v.tstInfo.genTime });
      console.log(`      ${a.id} T-10 : ${JSON.stringify({ statut: dix.statut, raison: dix.raison, crls_lues: brutes.filter((x) => x.crl).length, captures: captures.map((x) => ({ sources: x.sources, erreur: x.erreur })) })}`);
      if (crls.length === v.chemin.length) expect(dix.statut).to.equal("reussi");
      else expect(dix).to.include({ statut: "non_execute", raison: "ancre_absente" });
      // Confrontation : openssl ts -verify -queryfile sur la requête et la réponse telles qu'envoyée et reçue.
      if (!opensslDisponible()) return;
      const q = path.join(dir, `${a.id}.tsq`);
      const s = path.join(dir, `${a.id}.tsr`);
      const ca = path.join(dir, `${a.id}-ancres.pem`);
      const untrusted = path.join(dir, `${a.id}-chaine.pem`);
      fs.writeFileSync(q, chaine.requete);
      fs.writeFileSync(s, chaine.reponse);
      fs.writeFileSync(ca, ancres.join(""));
      fs.writeFileSync(untrusted, jeton.certificats.map((x) => certificatVersPem(x.octets)).join(""));
      const sortie = execFileSync("openssl", ["ts", "-verify", "-queryfile", q, "-in", s, "-CAfile", ca, "-untrusted", untrusted, "-partial_chain"], { stdio: "pipe" }).toString();
      console.log(`      ${a.id} openssl : ${sortie.trim()}`);
      expect(sortie).to.include("Verification: OK");
      expect(lireReponse(chaine.reponse).status).to.be.oneOf([0, 1]);
    });
  }
});
