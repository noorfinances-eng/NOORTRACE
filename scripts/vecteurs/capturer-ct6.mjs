#!/usr/bin/env node
// Capture UNIQUE des données du registre pour les vecteurs CT-6
// (spec/CT-6-verificateur.md, annexe A.5, EX-A.8).
//
// Le script s'exécute contre le réseau de développement local de noorcore
// (bash chain/scripts/dev-net.sh start), sur lequel les contrats de
// deployments/noorcore.json sont déjà déployés. Il :
//
//   1. amorce l'organisation « assureur-demo » (org_id de CT-1 §13) avec un
//      CuratorSet des comptes Hardhat 1 à 3 au seuil de 2 ;
//   2. inscrit rec-test-01, rec-test-02 et rec-test-03 (clé étrangère aux
//      dossiers) pour le journal « journal-sinistres », sous les clés de
//      chaîne de graine SHA-256(UTF-8("noortrace/vecteurs/v0/cle-chaine/rec-test-0N")) ;
//   3. ancre les périodes 1 puis 2 des vecteurs de CT-1 (émetteur : la clé de
//      chaîne de rec-test-02, qui signe les deux manifestes) ;
//   4. soumet les périodes 1 puis 2 (approbateurs : comptes Hardhat 1 et 2) ;
//      toutes les transactions sont relayées par le compte Hardhat 0 ;
//   5. pour chaque transaction, dès son reçu : eth_getBlockByNumber(h, false),
//      eth_getTransactionReceipt de chaque transaction du bloc et
//      noor_getCommitCertificate(h), écrits tels que reçus (octets de la
//      réponse JSON-RPC) dans bloc-<h>.json, recu-<hash>.json et
//      certificat-<h>.json ; puis validators.json (copie octet pour octet de
//      chain/runtime/validators.json, clés publiques seulement) et capture.json.
//
//   node scripts/vecteurs/capturer-ct6.mjs [--rpc http://127.0.0.1:8645]
//        [--sortie spec/vecteurs/ct-6/registre/capture]
//        [--deploiement deployments/noorcore.json] [--remplacer]
//
// La capture est une ENTRÉE des vecteurs : le générateur
// (scripts/vecteurs/ct6/registre.mjs) la lit et ne la réécrit jamais. On ne la
// recapture que si elle doit changer, sur un réseau où ni l'organisation, ni
// ces empreintes, ni ces periodHash ne sont déjà enregistrés (procédure dans
// spec/vecteurs/ct-6/registre/capture/CAPTURE.md). Sans --remplacer, le script
// refuse d'écrire dans un répertoire de capture non vide.
//
// Toutes les clés employées sont des clés de TEST publiques : comptes Hardhat
// dérivés de la mnémonique publique « test … junk », clés de chaîne et clés
// Ed25519 dérivées d'étiquettes publiées. Aucune clé de validateur n'est lue :
// validators.json ne porte que les clés publiques.
//
// Codes de retour : 0 capture écrite ; 1 refus (précondition non remplie) ou
// échec d'une transaction ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { Contract, ContractFactory, HDNodeWallet, JsonRpcProvider, Wallet } from "ethers";
import { clePubliqueEd25519, hachageManifeste } from "../lib/journal.mjs";
import { DOC_TYPE_PERIODE, anchorFingerprint, journalIdOf, orgIdOf, periodDigest, periodMetaDuManifeste, registerDigest, signDigest, signDigestBy } from "../lib/noortrace.mjs";

const RACINE = fileURLToPath(new URL("../../", import.meta.url));
const MNEMONIQUE_TEST = "test test test test test test test test test test test junk";
const CHAIN_ID_EVM = 2124n;
const CHAIN_ID_BFT = "noortrace-2124-dev";
const LIMITE_GAZ = 3_000_000n;
const SLUG = "assureur-demo";
const JOURNAL = "journal-sinistres";
const COMMIT_NOORCORE = "618fcef8805ef5b4cb9291a3dd97be710e489297";
const CORRECTIF = "0001-noor_getCommitCertificate.patch";

/** Clés d'enregistreur de la capture : étiquettes et valeurs attendues (annexe A.5). */
const ENREGISTREURS = [
  { key_id: "rec-test-01", adresseAttendue: "0xaa2a59656361352e96ef2eed355316ef8b29dab7", publicAttendue: "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045" },
  { key_id: "rec-test-02", adresseAttendue: "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49", publicAttendue: "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3" },
  { key_id: "rec-test-03", adresseAttendue: "0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22", publicAttendue: "0x7fcebb9e8efd62d13a17c830ad33739c1de7fe9f1458701cb739ae15e9e62cd6" },
];

class Refus extends Error {}

function sha256Hex(octets) {
  return "0x" + createHash("sha256").update(octets).digest("hex");
}

function analyserArguments(argv) {
  const options = { rpc: "http://127.0.0.1:8645", sortie: path.join(RACINE, "spec/vecteurs/ct-6/registre/capture"), deploiement: path.join(RACINE, "deployments", "noorcore.json"), remplacer: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const [nom, valeurEgal] = a.startsWith("--") ? a.slice(2).split(/=(.*)/s, 2) : [null, null];
    if (nom === "remplacer") options.remplacer = true;
    else if (nom === "rpc" || nom === "sortie" || nom === "deploiement") {
      const v = valeurEgal ?? argv[++i];
      if (!v) throw new Refus(`--${nom} attend une valeur`);
      options[nom] = v;
    } else {
      const e = new Refus(`argument inconnu : ${a}`);
      e.usage = true;
      throw e;
    }
  }
  return options;
}

/** Appel JSON-RPC brut : rend le texte exact de la réponse et sa valeur analysée. */
async function rpcBrut(url, method, params) {
  const corps = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const reponse = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: corps });
  const octets = Buffer.from(await reponse.arrayBuffer());
  const valeur = JSON.parse(octets.toString("utf8"));
  return { octets, valeur };
}

function artefact(nom) {
  const fichier = path.join(RACINE, "hh-artifacts", "contracts", `${nom}.sol`, `${nom}.json`);
  if (!fs.existsSync(fichier)) throw new Refus(`artefact absent : ${fichier} (lancer d'abord npm run compile)`);
  return JSON.parse(fs.readFileSync(fichier, "utf8"));
}

/**
 * Code déployé comparé au code compilé de contracts/ : octets des immuables
 * (adresse du CuratorSetRegistry) et métadonnées CBOR finales (empreinte des
 * sources, commentaires compris) masqués. Constat local, consigné dans
 * capture.json ; il ne prouve rien au réviseur (CT-6 H7).
 */
function codeEgalCompilation(codeDeploye, art) {
  const a = Buffer.from(art.deployedBytecode.slice(2), "hex");
  const b = Buffer.from(codeDeploye.slice(2), "hex");
  if (a.length !== b.length) return false;
  const masque = new Uint8Array(a.length);
  for (const refs of Object.values(art.immutableReferences ?? {})) for (const { start, length } of refs) masque.fill(1, start, start + length);
  const lgMeta = a.readUInt16BE(a.length - 2) + 2;
  masque.fill(1, a.length - lgMeta);
  for (let i = 0; i < a.length; i++) if (!masque[i] && a[i] !== b[i]) return false;
  return true;
}

async function principal() {
  const options = analyserArguments(process.argv.slice(2));
  const sortie = path.resolve(options.sortie);
  if (fs.existsSync(sortie) && fs.readdirSync(sortie).some((f) => f !== "CAPTURE.md") && !options.remplacer) {
    throw new Refus(`${sortie} n'est pas vide : la capture est une entrée, on ne la remplace qu'en connaissance de cause (--remplacer)`);
  }

  const fournisseur = new JsonRpcProvider(options.rpc, Number(CHAIN_ID_EVM), { staticNetwork: true, batchMaxCount: 1 });
  const reseau = await rpcBrut(options.rpc, "eth_chainId", []);
  if (BigInt(reseau.valeur.result) !== CHAIN_ID_EVM) throw new Refus(`le nœud ${options.rpc} sert la chaîne ${reseau.valeur.result}, pas ${CHAIN_ID_EVM}`);

  // Déploiement en place (fichier gitignoré du réseau de développement).
  const deploiement = JSON.parse(fs.readFileSync(path.resolve(options.deploiement), "utf8"));
  if (String(deploiement.chainId) !== String(CHAIN_ID_EVM)) throw new Refus(`${options.deploiement} ne décrit pas la chaîne 2124`);
  const contrats = {};
  const constatCode = {};
  for (const nom of ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]) {
    const adresse = deploiement.contrats[nom].adresse;
    const code = await fournisseur.getCode(adresse);
    if (code === "0x") throw new Refus(`aucun code à l'adresse de ${nom} (${adresse})`);
    contrats[nom] = adresse;
    constatCode[nom] = { adresse: adresse.toLowerCase(), bloc_deploiement: deploiement.contrats[nom].bloc, egal_compilation_hors_immuables_et_metadonnees: codeEgalCompilation(code, artefact(nom)) };
  }

  // Comptes : relayeur (compte 0) et approbateurs (comptes 1 à 3) de la mnémonique publique de test.
  const compte = (i) => HDNodeWallet.fromPhrase(MNEMONIQUE_TEST, undefined, `m/44'/60'/0'/0/${i}`).connect(fournisseur);
  const relayeur = compte(0);
  const approbateurs = [compte(1), compte(2), compte(3)];
  const signataires = [approbateurs[0], approbateurs[1]];

  // Clés d'enregistreur : clé de chaîne et clé publique Ed25519 dérivées d'étiquettes publiées.
  const enregistreurs = ENREGISTREURS.map((e) => {
    const cleChaine = new Wallet(sha256Hex(Buffer.from(`noortrace/vecteurs/v0/cle-chaine/${e.key_id}`, "utf8")));
    const publique = clePubliqueEd25519(sha256Hex(Buffer.from(`noortrace/vecteurs/v0/cle-enregistreur/${e.key_id}`, "utf8")));
    if (cleChaine.address.toLowerCase() !== e.adresseAttendue) throw new Refus(`${e.key_id} : clé de chaîne ${cleChaine.address} au lieu de ${e.adresseAttendue}`);
    if (publique !== e.publicAttendue) throw new Refus(`${e.key_id} : clé Ed25519 ${publique} au lieu de ${e.publicAttendue}`);
    return { ...e, cleChaine, publique };
  });

  const orgId = orgIdOf(SLUG);
  const journalId = journalIdOf(JOURNAL);
  const manifestes = [1, 2].map((n) => JSON.parse(fs.readFileSync(path.join(RACINE, `spec/vecteurs/ct-1/manifestes/periode-${n}.json`), "utf8")));
  for (const m of manifestes) if (m.org_id !== orgId || m.journal_id !== journalId) throw new Refus("manifeste de CT-1 d'une autre organisation ou d'un autre journal");

  const instance = (nom) => new Contract(contrats[nom], artefact(nom).abi, relayeur);
  const attestation = instance("AttestationRegistry");
  const curatorSets = instance("CuratorSetRegistry");
  const periodes = instance("PeriodRegistry");
  const inscriptions = instance("RecorderRegistry");

  // Préconditions : rien de ce que la capture écrit n'existe déjà sur la chaîne.
  if (await curatorSets.isRegistered(orgId)) throw new Refus(`l'organisation ${SLUG} est déjà amorcée sur ce réseau : recapturer sur un réseau neuf (CAPTURE.md)`);
  for (const m of manifestes) {
    const ph = hachageManifeste(m);
    if (await periodes.isKnown(orgId, ph)) throw new Refus(`periodHash ${ph} déjà connu`);
    if (await attestation.isAnchored(anchorFingerprint({ orgId, journalId, periodHash: ph }))) throw new Refus(`empreinte de ${ph} déjà ancrée`);
  }
  if ((await curatorSets.admin()).toLowerCase() !== relayeur.address.toLowerCase()) throw new Refus("le compte 0 n'administre pas CuratorSetRegistry");

  fs.mkdirSync(sortie, { recursive: true });
  const transactions = [];
  const blocsCaptures = new Set();
  const surcharges = { gasLimit: LIMITE_GAZ };

  // Capture immédiate d'un bloc : en-tête, reçus de toutes ses transactions, certificat.
  async function capturer(hauteur) {
    const h = "0x" + hauteur.toString(16);
    const bloc = await rpcBrut(options.rpc, "eth_getBlockByNumber", [h, false]);
    if (!bloc.valeur.result) throw new Refus(`bloc ${hauteur} introuvable`);
    fs.writeFileSync(path.join(sortie, `bloc-${hauteur}.json`), bloc.octets);
    const fichiersRecus = [];
    for (const tx of bloc.valeur.result.transactions) {
      const recu = await rpcBrut(options.rpc, "eth_getTransactionReceipt", [tx]);
      if (!recu.valeur.result) throw new Refus(`reçu de ${tx} introuvable`);
      const nom = `recu-${tx}.json`;
      fs.writeFileSync(path.join(sortie, nom), recu.octets);
      fichiersRecus.push(nom);
    }
    // Le certificat est écrit juste après que le bloc devient durable : réessayer
    // sur la réponse transitoire « not yet persisted » (chain/README.md).
    let certificat;
    for (let essai = 0; essai < 100; essai++) {
      certificat = await rpcBrut(options.rpc, "noor_getCommitCertificate", [h]);
      if (certificat.valeur.result) break;
      const message = String(certificat.valeur.error?.message ?? "");
      if (!message.includes("not yet persisted")) throw new Refus(`certificat du bloc ${hauteur} : ${message}`);
      await new Promise((r) => setTimeout(r, 200));
    }
    if (!certificat.valeur.result) throw new Refus(`certificat du bloc ${hauteur} toujours absent`);
    fs.writeFileSync(path.join(sortie, `certificat-${hauteur}.json`), certificat.octets);
    blocsCaptures.add(hauteur);
    return { bloc: `bloc-${hauteur}.json`, recus: fichiersRecus, certificat: `certificat-${hauteur}.json`, transactions_du_bloc: bloc.valeur.result.transactions.length };
  }

  async function envoyer(role, description, promesse, extra = {}) {
    const tx = await promesse;
    const recu = await tx.wait();
    if (recu.status !== 1) throw new Refus(`${description} : transaction ${tx.hash} en échec (status ${recu.status})`);
    const fichiers = await capturer(recu.blockNumber);
    transactions.push({ role, description, hash: tx.hash.toLowerCase(), bloc: recu.blockNumber, indice: recu.index, ...extra, fichiers });
    console.error(`${description} : ${tx.hash} au bloc ${recu.blockNumber}`);
  }

  // 1. L'organisation (non capturée : elle n'entre dans aucun dossier).
  const art = artefact("CuratorSet");
  const usine = new ContractFactory(art.abi, art.bytecode, relayeur);
  const jeu = await usine.deploy(relayeur.address, approbateurs.map((a) => a.address), 2, surcharges);
  await jeu.waitForDeployment();
  const adresseJeu = await jeu.getAddress();
  const recuJeu = await jeu.deploymentTransaction().wait();
  const recuAssignation = await (await curatorSets.setCuratorSet(orgId, adresseJeu, surcharges)).wait();
  console.error(`CuratorSet de ${SLUG} : ${adresseJeu} (blocs ${recuJeu.blockNumber} et ${recuAssignation.blockNumber})`);

  // 2. Les inscriptions.
  for (const e of enregistreurs) {
    const condense = await inscriptions.registerDigest(orgId, journalId, e.cleChaine.address, e.publique);
    if (condense !== registerDigest({ chainId: CHAIN_ID_EVM, registry: contrats.RecorderRegistry, orgId, journalId, chainKey: e.cleChaine.address, ed25519PubKey: e.publique })) throw new Refus("registerDigest du contrat différent du calcul local");
    const sigs = await signDigestBy(signataires, condense);
    await envoyer("inscription", `inscription de ${e.key_id}`, inscriptions.registerRecorder(orgId, journalId, e.cleChaine.address, e.publique, sigs, surcharges), {
      key_id: e.key_id,
      chain_key: e.cleChaine.address.toLowerCase(),
      ed25519_public_key: e.publique,
    });
  }

  // 3. Les ancres, signées par la clé de chaîne de rec-test-02.
  const emetteur = enregistreurs[1].cleChaine;
  for (const [i, m] of manifestes.entries()) {
    const periodHash = hachageManifeste(m);
    const empreinte = anchorFingerprint({ orgId, journalId, periodHash });
    const condense = await attestation.anchorDigest(empreinte, DOC_TYPE_PERIODE);
    const sig = await signDigest(emetteur, condense);
    await envoyer("ancre", `ancre de la période ${i + 1}`, attestation.anchor(empreinte, DOC_TYPE_PERIODE, emetteur.address, sig, surcharges), {
      periode: i + 1,
      period_hash: periodHash,
      fingerprint: empreinte,
      issuer: emetteur.address.toLowerCase(),
    });
  }

  // 4. Les clôtures, signées par les approbateurs 1 et 2.
  for (const [i, m] of manifestes.entries()) {
    const meta = periodMetaDuManifeste(m, { uri: "" });
    const condense = await periodes.periodDigest(meta);
    if (condense !== periodDigest({ chainId: CHAIN_ID_EVM, registry: contrats.PeriodRegistry, meta })) throw new Refus("periodDigest du contrat différent du calcul local");
    const sigs = await signDigestBy(signataires, condense);
    await envoyer("cloture", `clôture de la période ${i + 1}`, periodes.submitPeriod(meta, sigs, surcharges), { periode: i + 1, period_hash: meta.periodHash, uri: "" });
  }

  // 5. Jeu de validateurs du réseau (clés publiques seulement) et description.
  const validateurs = fs.readFileSync(path.join(RACINE, "chain/runtime/validators.json"));
  fs.writeFileSync(path.join(sortie, "validators.json"), validateurs);
  let binaire = null;
  try {
    binaire = sha256Hex(fs.readFileSync(path.join(RACINE, "chain/runtime/bin/noorcore")));
  } catch {
    binaire = null;
  }
  let commitDepot = null;
  try {
    commitDepot = execFileSync("git", ["-C", RACINE, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  } catch {
    commitDepot = null;
  }
  const description = {
    version: 0,
    description: "Capture unique du registre pour les vecteurs CT-6 (annexe A.5) : réponses JSON-RPC brutes du réseau de développement, clés publiques seulement.",
    date: new Date().toISOString(),
    depot_noortrace_commit: commitDepot,
    noorcore: { commit: COMMIT_NOORCORE, correctif: CORRECTIF, binaire_sha256: binaire },
    rpc: `nœud node1 (validateur v1) du réseau de développement, JSON-RPC en boucle locale, port ${new URL(options.rpc).port}`,
    chain_id: CHAIN_ID_BFT,
    evm_chain_id: Number(CHAIN_ID_EVM),
    contrats: {
      period_registry: contrats.PeriodRegistry.toLowerCase(),
      attestation_registry: contrats.AttestationRegistry.toLowerCase(),
      recorder_registry: contrats.RecorderRegistry.toLowerCase(),
      curator_set_registry: contrats.CuratorSetRegistry.toLowerCase(),
    },
    code_contrats: constatCode,
    organisation: {
      slug: SLUG,
      org_id: orgId,
      curator_set: adresseJeu.toLowerCase(),
      approbateurs: approbateurs.map((a) => a.address.toLowerCase()),
      seuil: 2,
      signataires: signataires.map((a) => a.address.toLowerCase()),
      relayeur: relayeur.address.toLowerCase(),
      blocs_amorcage: [recuJeu.blockNumber, recuAssignation.blockNumber],
    },
    journal: { nom: JOURNAL, journal_id: journalId },
    transactions,
    validateurs: { fichier: "validators.json", source: "copie de chain/runtime/validators.json (clés publiques seulement)", sha256: sha256Hex(validateurs) },
  };
  fs.writeFileSync(path.join(sortie, "capture.json"), JSON.stringify(description, null, 2) + "\n");
  console.error(`Capture écrite sous ${sortie} : ${transactions.length} transactions, ${blocsCaptures.size} blocs.`);
  return 0;
}

principal()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`Erreur : ${err instanceof Refus ? err.message : err?.stack ?? err}\n`);
    process.exit(err?.usage ? 2 : 1);
  });
