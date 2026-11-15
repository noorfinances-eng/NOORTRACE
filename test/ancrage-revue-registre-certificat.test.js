// Revue de sécurité interne de l'étape 8 : certificat de commit
// borné à la capture (CT-4 CP-4 ; CT-6 §15.1). Un certificat rendu par un
// validateur avec un membre inconnu de 2 Mio passait CP-1 à CP-6 et grossissait
// `certificat-commit.json` du dossier ; il est refusé à CP-4 (`certificat_invalide`),
// aucun fichier n'est écrit, et la capture réussit dès qu'un validateur honnête
// répond.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { sha256, utf8 } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const lireJson = (p) => JSON.parse(fs.readFileSync(path.join(RACINE, p), "utf8"));
const CONSTANTES = lireJson("spec/vecteurs/ct-4/constantes.json");
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
const ORG4 = CONSTANTES.organisation.org_id;
const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const K2 = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
const CLE = new R.SignataireChaineFichier(sha256(utf8("noortrace/ancrage/test/cle-chaine-certificat")));
const ED25519_01 = CONSTANTES.recorders[0].public_key;

describe("ancrage, revue de sécurité de l'étape 8 : certificat de commit borné à la capture (CT-4 CP-4)", function () {
  this.timeout(60000);
  const REPERTOIRES = [];
  after(function () {
    for (const r of REPERTOIRES) fs.rmSync(r, { recursive: true, force: true });
  });

  it("un certificat gonflé d'un membre inconnu de 2 Mio est refusé à CP-4 (certificat_invalide, borne nommée), rien n'est écrit ; les validateurs redevenus honnêtes : capture", async function () {
    const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
    const honnete = noeud.transport();
    const etat = { ment: true };
    const transport = async ({ url, octets, delaiMs, tailleMax }) => {
      const requete = JSON.parse(Buffer.from(octets).toString("utf8"));
      const reponse = JSON.parse(Buffer.from((await honnete({ url, octets, delaiMs, tailleMax })).octets).toString("utf8"));
      const finale = etat.ment && requete.method === "noor_getCommitCertificate" && reponse.result ? { ...reponse, result: { ...reponse.result, inconnu: "x".repeat(2 * 1024 * 1024) } } : reponse;
      return { status: 200, octets: new TextEncoder().encode(JSON.stringify(finale)) };
    };
    const rpc = new R.ClientRpc({ points: POINTS, transport, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
    const repertoire = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-revue-certificat-"));
    REPERTOIRES.push(repertoire);
    let monotone = 0;
    const horloge = { murale: () => Date.UTC(2026, 10, 9, 12, 0, 0) + monotone, monotone: () => monotone };
    const attendre = async (ms) => { monotone += ms; };
    const jeux = { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" };
    const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux };
    const nouvelEnvoyeur = () => new R.Envoyeur({ rpc, repertoireEnvois: repertoire, instance, horloge, attendre, delais: { recuMs: 60000, sondageMs: 500 }, journal: () => {} });
    noeud.approvisionner(CLE.adresse(), 4719000000n);
    noeud.inscrire({ orgId: ORG4, chainKey: CLE.adresse(), ed25519PubKey: ED25519_01, journalId: JOURNAL_REF });
    const ancre = (envoyeur) => envoyeur.ancrer({ orgId: ORG4, journalId: JOURNAL_REF, objet: K2, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE });

    expect(R.BORNES_CAPTURE.certificat).to.equal(1024 * 1024);
    const r1 = await ancre(nouvelEnvoyeur());
    expect(r1.type, JSON.stringify(r1).slice(0, 400)).to.equal("echec_registre");
    expect(r1.data.code).to.equal("certificat_invalide");
    expect(r1.outputs?.message ?? "").to.match(/au-delà de 1048576/);
    expect(fs.readdirSync(repertoire).filter((n) => n.startsWith("certificat-")), "aucun certificat gonflé n'est écrit").to.deep.equal([]);
    etat.ment = false;
    const r2 = await ancre(nouvelEnvoyeur());
    expect(r2.type, JSON.stringify(r2).slice(0, 400)).to.equal("inclusion_registre");
    const certificat = fs.readdirSync(repertoire).find((n) => n.startsWith("certificat-"));
    expect(certificat).to.not.equal(undefined);
    expect(fs.statSync(path.join(repertoire, certificat)).size).to.be.below(R.BORNES_CAPTURE.certificat);
  });
});
