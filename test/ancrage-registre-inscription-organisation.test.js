// CT-4 OP-8, EX-8.22 (complément du 2026-11-16 ; CT-5 EX-9.4) : le relais
// d'inscription du composant d'ancrage (`Envoyeur.inscrire`, qui sert au
// démon pendant une rotation de la clé de chaîne, CT-2 EX-11.16) refuse,
// avant tout envoi, une clé de chaîne déjà inscrite sous une autre
// organisation, active ou révoquée (`cle_chaine_autre_organisation`), comme
// `inscrire-cle` de l'outil de référence et de l'agent d'inscription : même
// lecture des événements `RecorderRegistered` (`eth_getLogs`, deuxième sujet
// indexé = clé de chaîne), du bloc de déploiement du contrat à la tête, en
// tranches de 16 384 blocs ; une lecture impossible rend `noeud_injoignable`,
// sans envoi.
//
// Sur le nœud noorcore factice de test/fixtures/ancrage-registre. Le code
// éprouvé est celui de paquets/ancrage/src, ou d'une autre racine sous
// NOORTRACE_REVUE_RACINE (code d'avant : essai rouge). Les mutants sont des
// copies de paquets/ancrage/src sous NOORTRACE_TMP (défaut os.tmpdir()),
// détruites à la fin.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sha256, utf8, hexVersOctets, octetsVersHex } from "@noortrace/noyau";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";

const DEPOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : DEPOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const CONSTANTES = JSON.parse(fs.readFileSync(path.join(DEPOT, "spec/vecteurs/ct-4/constantes.json"), "utf8"));
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646"];
const CONTRATS = {
  attestation_registry: CONSTANTES.contracts.attestation_registry,
  period_registry: CONSTANTES.contracts.period_registry,
  recorder_registry: CONSTANTES.contracts.recorder_registry,
};
const ORG = CONSTANTES.organisation.org_id;
const JOURNAL = CONSTANTES.journal.journal_id;
const graine = (nom) => sha256(utf8(`noortrace/essai/ancrage/inscription-organisation/${nom}`));
const ORG_AUTRE = octetsVersHex(graine("autre-organisation"));
const ed25519 = (nom) => octetsVersHex(graine(`ed25519-${nom}`));
const SIGNER_SET = { curator_set: "0x" + "a1".repeat(20), threshold: 2, height: 1000, block_hash: "0x" + "9d".repeat(32) };
const COPIES = [];
const DIRS = [];

/** Module « registre » du composant lu dans une racine (dépôt, code d'avant, ou copie mutante). */
const registreDe = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "registre", "index.mjs")).href);

/** Copie de paquets/ancrage/src où chaque remplacement, unique, est appliqué ; rend sa racine. */
function copieMutante(nom, remplacements) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-op8-mutant-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, "paquets", "ancrage"), { recursive: true });
  fs.cpSync(path.join(RACINE, "paquets", "ancrage", "src"), path.join(racine, "paquets", "ancrage", "src"), { recursive: true });
  fs.symlinkSync(path.join(DEPOT, "node_modules"), path.join(racine, "node_modules"));
  fs.symlinkSync(path.join(DEPOT, "paquets", "ancrage", "node_modules"), path.join(racine, "paquets", "ancrage", "node_modules"));
  for (const r of remplacements) {
    const f = path.join(racine, "paquets", "ancrage", "src", "registre", r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    expect(texte.split(r.ancien).length - 1, `mutant ${nom} : « ${r.ancien} » dans ${r.fichier}`).to.equal(1);
    fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
  }
  return racine;
}

/** Nœud factice, client et `Envoyeur` du module `R` ; `deploiement` : bloc de déploiement du RecorderRegistry de l'instance. */
function contexte(R, { deploiement } = {}) {
  const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
  const rpc = new R.ClientRpc({ points: POINTS, transport: noeud.transport(), identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const repertoire = fs.mkdtempSync(path.join(TMP, "noortrace-op8-envois-"));
  DIRS.push(repertoire);
  let monotone = 0;
  const horloge = { murale: () => Date.UTC(2026, 10, 16, 12, 0, 0) + monotone, monotone: () => monotone };
  const jeux = { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" };
  const instance = {
    evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux,
    ...(deploiement !== undefined ? { deploiements: { recorder_registry: { block_number: deploiement } } } : {}),
  };
  const journal = [];
  const envoyeur = new R.Envoyeur({
    rpc, repertoireEnvois: repertoire, instance, horloge, attendre: async (ms) => { monotone += ms; }, delais: { recuMs: 60000, sondageMs: 500 },
    journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }),
  });
  const relais = new R.SignataireChaineFichier(graine("relais"));
  noeud.approvisionner(relais.adresse(), 4719000000n);
  const approbateurs = [1, 2].map((k) => new R.SignataireChaineFichier(graine(`approbateur-${k}`)));
  /** Demande d'inscription signée au seuil (CT-4 §7.7). */
  const demande = (orgId, chainKey, cleEd25519) => {
    const digest = R.registerDigest(2124, CONTRATS.recorder_registry, orgId, JOURNAL, chainKey, cleEd25519);
    const h = R.hachageSigne(digest);
    return {
      version: 0, operation: "inscription", evm_chain_id: 2124, contract: CONTRATS.recorder_registry,
      fields: { org_id: orgId, journal_id: JOURNAL, chain_key: chainKey, ed25519_public_key: cleEd25519 },
      digest, eip191_digest: octetsVersHex(h), signer_set: { ...SIGNER_SET },
      signatures: approbateurs.map((a) => ({ signer: a.adresse(), ...a.signerCondense(h) })).sort((x, y) => (x.signer < y.signer ? -1 : 1)),
      prepared_at: "2026-11-16T12:00:00.000Z",
    };
  };
  // Transactions distinctes soumises (les mêmes octets vont à chaque point, CT-4 EX-8.15).
  const envois = () => new Set(noeud.appels.filter((a) => a.method === "eth_sendRawTransaction").map((a) => a.params[0])).size;
  const lectures = () => noeud.appels.filter((a) => a.method === "eth_getLogs").map((a) => a.params[0]);
  return { R, noeud, envoyeur, relais, demande, envois, lectures, journal };
}

/** Clé de chaîne d'essai (adresse) d'un nom. */
const cleChaine = (R, nom) => new R.SignataireChaineFichier(graine(`chaine-${nom}`)).adresse();

/** Attend un refus d'OP-8 de l'autre organisation, sans envoi, et la ligne `registry_send_failed`. */
function refusAutreOrganisation(c, r, avant, { bloc } = {}) {
  expect(r.type, JSON.stringify(r)).to.equal("echec_registre");
  expect(r.data.code).to.equal("cle_chaine_autre_organisation");
  expect(r.outputs.org_id).to.equal(ORG_AUTRE);
  if (bloc !== undefined) expect(r.outputs.block_number).to.equal(bloc);
  expect(r.outputs.transaction_hash).to.match(/^0x[0-9a-f]{64}$/);
  expect(r.outputs.message).to.include(ORG_AUTRE);
  expect(c.envois(), "aucune transaction envoyée").to.equal(avant);
  expect(c.journal.some((l) => l.evenement === "registry_send_failed" && l.champs.code === "cle_chaine_autre_organisation" && l.champs.org_id === ORG_AUTRE)).to.equal(true);
}

/** Cas : inscription relayée d'une clé neuve (incluse), puis la même clé de chaîne demandée sous une autre organisation (refusée). */
async function casAllerRetour(R) {
  const c = contexte(R);
  const x = cleChaine(R, "aller-retour");
  const ok = await c.envoyeur.inscrire({ demande: c.demande(ORG_AUTRE, x, ed25519("aller")), cle: c.relais });
  expect(ok.type, JSON.stringify(ok)).to.equal("inclusion_registre");
  const avant = c.envois();
  const r = await c.envoyeur.inscrire({ demande: c.demande(ORG, x, ed25519("retour")), cle: c.relais });
  return { c, r, avant, bloc: ok.data.block_number };
}

/** Cas : la clé de chaîne inscrite sous l'autre organisation puis révoquée ; l'inscription est encore refusée (EX-8.8). */
async function casRevoquee(R) {
  const c = contexte(R);
  const x = cleChaine(R, "revoquee");
  c.noeud.inscrire({ orgId: ORG_AUTRE, chainKey: x, ed25519PubKey: ed25519("revoquee-ailleurs"), journalId: JOURNAL });
  c.noeud.enregistreurs.get(ORG_AUTRE + x).revokedAt = BigInt(c.noeud.horodatage + 1);
  const avant = c.envois();
  const r = await c.envoyeur.inscrire({ demande: c.demande(ORG, x, ed25519("revoquee")), cle: c.relais });
  return { c, r, avant };
}

/** Cas : l'inscription de l'autre organisation est au-delà de la première tranche de 16 384 blocs. */
async function casSecondeTranche(R) {
  const c = contexte(R, { deploiement: 0 });
  const x = cleChaine(R, "tranche");
  c.noeud.hauteur = 20000;
  c.noeud.inscrire({ orgId: ORG_AUTRE, chainKey: x, ed25519PubKey: ed25519("tranche-ailleurs"), journalId: JOURNAL });
  c.noeud.hauteur = 40000;
  const avant = c.envois();
  const r = await c.envoyeur.inscrire({ demande: c.demande(ORG, x, ed25519("tranche")), cle: c.relais });
  return { c, r, avant };
}

/** Cas : journaux illisibles (borne de plage du nœud) ; la vérification n'est pas sautée. */
async function casJournauxIllisibles(R) {
  const c = contexte(R);
  c.noeud.journauxRefuses = "query exceeds max block range 16384";
  const avant = c.envois();
  const r = await c.envoyeur.inscrire({ demande: c.demande(ORG, cleChaine(R, "illisible"), ed25519("illisible")), cle: c.relais });
  return { c, r, avant };
}

describe("composant d'ancrage, relais d'inscription : clé de chaîne d'une autre organisation (CT-4 OP-8, EX-8.22, complément du 2026-11-16 ; CT-5 EX-9.4)", function () {
  this.timeout(120000);
  let R;

  before(async function () {
    R = await registreDe(RACINE);
  });

  after(function () {
    for (const d of [...COPIES, ...DIRS]) fs.rmSync(d, { recursive: true, force: true });
  });

  it("clé de chaîne inscrite sous une autre organisation par une transaction relayée (journal du reçu) : cle_chaine_autre_organisation, l'organisation, le bloc et la transaction nommés, aucune transaction, ligne registry_send_failed", async function () {
    const { c, r, avant, bloc } = await casAllerRetour(R);
    refusAutreOrganisation(c, r, avant, { bloc });
  });

  it("inscrite sous l'autre organisation puis révoquée : refusée de même (une clé de chaîne n'est jamais réinscrite, EX-8.8)", async function () {
    const { c, r, avant } = await casRevoquee(R);
    refusAutreOrganisation(c, r, avant);
  });

  it("lecture en tranches de 16 384 blocs au plus (CT-4 EX-5.11), du bloc de déploiement à la tête lue : une inscription de la seconde tranche est vue", async function () {
    const { c, r, avant } = await casSecondeTranche(R);
    refusAutreOrganisation(c, r, avant, { bloc: 20000 });
    const l = c.lectures();
    expect(l.length).to.equal(2);
    expect(l.map((f) => [f.fromBlock, f.toBlock])).to.deep.equal([["0x0", "0x3fff"], ["0x4000", "0x7fff"]]);
    for (const f of l) {
      expect(f.address).to.equal(CONTRATS.recorder_registry);
      expect(f.topics).to.deep.equal([R.SUJETS.RecorderRegistered, null, "0x" + "00".repeat(12) + cleChaine(R, "tranche").slice(2)]);
    }
  });

  it("la lecture part du bloc de déploiement du RecorderRegistry que porte l'instance (deploiements.recorder_registry.block_number, manifeste) ; une clé neuve est relayée et incluse", async function () {
    const c = contexte(R, { deploiement: 1000 });
    const r = await c.envoyeur.inscrire({ demande: c.demande(ORG, cleChaine(R, "neuve"), ed25519("neuve")), cle: c.relais });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    expect(c.lectures().map((f) => f.fromBlock)).to.deep.equal(["0x3e8"]);
    expect(c.envois()).to.equal(1);
  });

  it("journaux illisibles : noeud_injoignable, aucune transaction (la vérification n'est jamais sautée)", async function () {
    const { c, r, avant } = await casJournauxIllisibles(R);
    expect(r.type, JSON.stringify(r)).to.equal("echec_registre");
    expect(r.data.code).to.equal("noeud_injoignable");
    expect(r.outputs.message).to.include("OP-8");
    expect(c.envois()).to.equal(avant);
  });

  it("mutants de la lecture partagée (lookup.mjs) : une seule tranche lue ; une erreur JSON-RPC prise pour « aucune inscription » : la clé passe et l'inscription est envoyée (tués)", async function () {
    const tranche = await registreDe(copieMutante("tranche", [{ fichier: "lookup.mjs", ancien: "for (; de <= tete; de += TRANCHE_JOURNAUX) {", nouveau: "for (; de <= tete; de = tete + 1n) {" }]));
    const t = await casSecondeTranche(tranche);
    expect(t.r.type, "mutant « une seule tranche » : inscription envoyée").to.equal("inclusion_registre");
    expect(t.c.envois()).to.equal(t.avant + 1);
    const saute = await registreDe(copieMutante("saute", [{ fichier: "lookup.mjs", ancien: 'if (j.erreur) throw echec(j.erreur.message ?? "erreur JSON-RPC");', nouveau: "if (j.erreur) return null;" }]));
    const s = await casJournauxIllisibles(saute);
    expect(s.r.type, "mutant « lecture sautée » : inscription envoyée").to.equal("inclusion_registre");
    expect(s.c.envois()).to.equal(s.avant + 1);
  });
});
