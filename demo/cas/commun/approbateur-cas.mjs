#!/usr/bin/env node
// Détenteur des clés de chaîne des cas de démonstration (CT-9 TE-1, TE-2) :
// il tourne dans l'image `approbateur-demo` de la démonstration de référence,
// seule image qui détienne les clés de démonstration des comptes Hardhat 1 à
// 3, et n'en fait que deux gestes :
//   1. l'inscription de la clé de l'enregistreur au registre (CT-4 §7.7,
//      §8.7), signée au seuil par les comptes 1 et 2, avec sa capture ;
//   2. la signature au seuil de la demande de clôture de chaque manifeste que
//      l'exploitation dépose dans le répertoire d'échange (CT-4 §8.2).
// Il ne vote JAMAIS : dans les cas de démonstration, les approbateurs
// décident depuis la console d'exploitation de CT-3, avec deux comptes de
// test (TE-1, pas 2), et c'est leur portefeuille qui signe. Il n'inscrit rien
// à l'annuaire : les approbateurs s'y inscrivent eux-mêmes par preuve de
// possession (CT-3 §13.5).
//
//   approbateur-cas.mjs servir
//
// Mêmes variables que l'approbateur de la démonstration (`APPROBATEUR_*`) ;
// la marque « prêt » est écrite après l'inscription de la clé, pour la sonde
// de l'image.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

/** Le module commun de la démonstration : dans l'image (/opt/noortrace/conteneurs/demo-commun), ou dans le dépôt pour les essais. */
const ICI = path.dirname(fileURLToPath(import.meta.url));
const { attendre, attendreChaine, clientRpc, rpc, envoyer, jeuPour, seuilDe } = await import(fs.existsSync(path.join(ICI, "..", "demo-commun", "chaine.mjs")) ? "../demo-commun/chaine.mjs" : "../../../conteneurs/demo-commun/chaine.mjs");

function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

/**
 * Comptes Hardhat 1 à 3 (`m/44'/60'/0'/0/1` à `/3`), clés publiques de test de CT-3 A.2 : celles du programme de
 * l'image (`approbateur-demo.mjs`, à côté de ce fichier dans l'image, ou dans `conteneurs/` du dépôt pour les essais),
 * seul fichier de la démonstration qui les écrive (CT-3 EX-3.4).
 */
const { CLES_APPROBATEURS } = await import(fs.existsSync(path.join(ICI, "approbateur-demo.mjs")) ? "./approbateur-demo.mjs" : "../../../conteneurs/approbateur-demo/approbateur-demo.mjs");

const env = (nom, defaut) => process.env[nom] ?? defaut;

function journal(evenement, donnees = {}) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), service: "approbateur-cas", event: evenement, ...donnees })}\n`);
}

/** Signatures au seuil d'un condensé interne du registre, rangées par adresse croissante (RG-13). */
function signerAuSeuil(signataires, seuil, condense) {
  const hache = R.hachageSigne(condense);
  const signatures = signataires.slice(0, seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hache) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
  return { hache, signatures };
}

async function lireJeu(client, contrat, orgId) {
  const tete = await rpc(client, "eth_getBlockByNumber", ["latest", false]);
  const curatorSet = await jeuPour(client, contrat, orgId);
  return { curator_set: curatorSet, threshold: await seuilDe(client, curatorSet), height: Number(BigInt(tete.number)), block_hash: tete.hash };
}

/** Pas 1 : inscription de la clé de l'enregistreur (demande signée au seuil, transaction du compte 1), capture déposée. */
async function inscrireCle(o) {
  const { client, instance, signataires, orgId, journalId, cleChaine, cleEd25519 } = o;
  fs.mkdirSync(path.join(o.demandes, "inscription"), { recursive: true });
  const deja = await R.recorderOf({ rpc: client, contrat: instance.recorderRegistry, orgId, chainKey: cleChaine });
  if (deja.registeredAt !== 0n) {
    if (deja.revokedAt !== 0n || deja.ed25519PubKey !== cleEd25519 || deja.journalId !== journalId) throw new Error("la clé de chaîne est déjà inscrite pour une autre clé, un autre journal, ou révoquée");
    journal("cle_deja_inscrite", { chain_key: cleChaine });
    return;
  }
  const jeu = await lireJeu(client, instance.recorderRegistry, orgId);
  const fields = { org_id: orgId, journal_id: journalId, chain_key: cleChaine, ed25519_public_key: cleEd25519 };
  const digest = R.registerDigest(instance.evmChainId, instance.recorderRegistry, orgId, journalId, cleChaine, cleEd25519);
  const { hache, signatures } = signerAuSeuil(signataires, jeu.threshold, digest);
  const demande = { version: 0, operation: "inscription", evm_chain_id: instance.evmChainId, contract: instance.recorderRegistry, fields, digest, eip191_digest: N.octetsVersHex(hache), signer_set: jeu, signatures, prepared_at: N.ecrireHorodatage(Date.now()) };
  const v = R.verifierDemande(demande, { complete: true });
  if (v.resultat !== "valide") throw new Error(`demande d'inscription refusée par son propre contrôle (${v.check} ${v.code})`);
  const envoi = await envoyer({ client, evmChainId: instance.evmChainId, signataire: signataires[0], to: instance.recorderRegistry, data: R.encoderRegisterRecorder({ ...fields, signatures }), gasLimit: 500000n });
  const lue = await R.recorderOf({ rpc: client, contrat: instance.recorderRegistry, orgId, chainKey: cleChaine });
  if (lue.registeredAt === 0n || lue.ed25519PubKey !== cleEd25519) throw new Error("inscription envoyée mais non lue au registre");
  const capture = await R.capturer({
    rpc: client, transactionHash: envoi.hash, role: "inscription", contrat: instance.recorderRegistry, horloge: { murale: () => Date.now() },
    repertoire: path.join(o.demandes, "inscription"), instance: { evmChainId: instance.evmChainId, bftChainId: instance.bftChainId, jeux: instance.manifeste }, attendre,
  });
  if (capture.erreur) throw new Error(`capture de l'inscription en échec (${capture.erreur.code} ${capture.erreur.check ?? ""}) : ${capture.erreur.message}`);
  journal("cle_inscrite", { registre: "RecorderRegistry", chain_key: cleChaine, ed25519_public_key: cleEd25519, journal_id: journalId, signataires: signatures.map((s) => s.signer), seuil: jeu.threshold, transaction: envoi.hash, bloc: Number(BigInt(envoi.recu.blockNumber)), capture: capture.nom });
}

/** Pas 2 : demande de clôture signée au seuil pour un manifeste déposé par l'exploitation. */
async function signerCloture(o, fichier) {
  const depot = JSON.parse(fs.readFileSync(fichier, "utf8"));
  const m = depot.manifeste;
  if (m.org_id !== o.orgId || m.journal_id !== o.journalId) throw new Error("manifeste d'un autre journal");
  const periodHash = N.hacherManifeste(m);
  if (depot.signature?.period_hash !== periodHash) throw new Error("la signature déposée n'est pas celle de ce manifeste");
  if (!N.verifierSignatureManifeste(m, depot.signature.sig, N.hexVersOctets(o.cleEd25519, 32))) throw new Error("signature du manifeste invalide pour la clé inscrite");
  const periodMeta = {
    org_id: m.org_id, journal_id: m.journal_id, period_hash: periodHash, root: m.root,
    period_start: String(m.period_start), period_end: String(m.period_end), first_seq: String(m.first_seq), last_seq: String(m.last_seq), version: m.version, uri: "",
  };
  const jeu = await lireJeu(o.client, o.instance.periodRegistry, o.orgId);
  const digest = R.periodDigest(o.instance.evmChainId, o.instance.periodRegistry, periodMeta);
  const { hache, signatures } = signerAuSeuil(o.signataires, jeu.threshold, digest);
  const demande = { version: 0, operation: "cloture", evm_chain_id: o.instance.evmChainId, contract: o.instance.periodRegistry, fields: { period_meta: periodMeta }, digest, eip191_digest: N.octetsVersHex(hache), signer_set: jeu, signatures, prepared_at: N.ecrireHorodatage(Date.now()) };
  const v = R.verifierDemande(demande, { complete: true });
  if (v.resultat !== "valide") throw new Error(`demande de clôture refusée par son propre contrôle (${v.check} ${v.code})`);
  const sortie = path.join(path.dirname(fichier), `demande-cloture-${periodHash}.json`);
  fs.writeFileSync(`${sortie}.partiel`, `${JSON.stringify(demande, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(`${sortie}.partiel`, sortie);
  journal("cloture_signee", { period_hash: periodHash, period_start: m.period_start, period_end: m.period_end, signataires: signatures.map((s) => s.signer), seuil: jeu.threshold });
}

function lireInstance(chemin) {
  const d = JSON.parse(fs.readFileSync(chemin, "utf8"));
  const adresse = (nom) => d.contracts.find((c) => c.name === nom)?.address;
  return { manifeste: d, bftChainId: d.bft_chain_id, evmChainId: d.evm_chain_id, attestationRegistry: adresse("AttestationRegistry"), periodRegistry: adresse("PeriodRegistry"), recorderRegistry: adresse("RecorderRegistry") };
}

async function servir() {
  const etat = env("APPROBATEUR_ETAT", "/run/temporaire");
  const pret = path.join(etat, "pret");
  fs.rmSync(pret, { force: true });
  const instance = lireInstance(env("APPROBATEUR_INSTANCE", "/etc/noortrace-demo/instance-registre.json"));
  const o = {
    client: clientRpc(env("APPROBATEUR_RPC_URL", "http://registre-dev:8545")),
    instance,
    signataires: CLES_APPROBATEURS.map((k) => R.SignataireChaineFichier.depuisOctets(k)),
    orgId: env("APPROBATEUR_ORG_ID", ""), journalId: env("APPROBATEUR_JOURNAL_ID", ""),
    cleChaine: env("APPROBATEUR_CLE_CHAINE", "").toLowerCase(), cleEd25519: env("APPROBATEUR_CLE_ED25519", "").toLowerCase(),
    demandes: env("APPROBATEUR_DEMANDES", "/var/lib/noortrace-demandes"),
  };
  for (const [nom, v, motif] of [["APPROBATEUR_ORG_ID", o.orgId, /^0x[0-9a-f]{64}$/], ["APPROBATEUR_JOURNAL_ID", o.journalId, /^0x[0-9a-f]{64}$/], ["APPROBATEUR_CLE_CHAINE", o.cleChaine, /^0x[0-9a-f]{40}$/], ["APPROBATEUR_CLE_ED25519", o.cleEd25519, /^0x[0-9a-f]{64}$/]]) {
    if (!motif.test(v)) throw new Error(`${nom} absent ou hors forme`);
  }
  let arret = false;
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => (arret = true));
  await attendreChaine(o.client, instance.evmChainId);
  await inscrireCle(o);
  fs.mkdirSync(etat, { recursive: true });
  fs.writeFileSync(pret, "pret\n");
  journal("pret", { role: "clés de chaîne seulement : aucun vote, les approbateurs décident depuis la console", comptes: o.signataires.slice(0, 2).map((s) => s.adresse()) });
  const signees = new Set();
  while (!arret) {
    try {
      for (const nom of fs.existsSync(o.demandes) ? fs.readdirSync(o.demandes) : []) {
        if (!/^manifeste-[0-9]+\.json$/.test(nom) || signees.has(nom)) continue;
        signees.add(nom);
        await signerCloture(o, path.join(o.demandes, nom));
      }
    } catch (e) {
      journal("erreur", { message: e.message });
    }
    await attendre(300);
  }
  process.exit(0);
}

if (estProgramme(import.meta.url)) {
  if (process.argv[2] === "servir") {
    servir().catch((e) => {
      journal("echec", { message: e.message });
      process.exit(1);
    });
  } else {
    process.stderr.write("usage : approbateur-cas.mjs servir\n");
    process.exit(2);
  }
}
