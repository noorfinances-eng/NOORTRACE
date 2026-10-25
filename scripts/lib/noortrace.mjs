// Fonctions partagées par les scripts et les tests de NOORTRACE : déploiement
// des contrats, amorçage d'une organisation, lecture et écriture des fichiers
// deployments/<réseau>.json, calcul des identifiants et des condensés signés.
//
// Ces fonctions reçoivent l'objet `ethers` d'une connexion Hardhat
// (`network.connect()`), pour fonctionner aussi bien sur le réseau Hardhat en
// mémoire que sur l'instance dédiée de noorcore.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AbiCoder, Signature, ZeroAddress, getBytes, hashMessage, keccak256, solidityPacked, toUtf8Bytes } from "ethers";
import { hachageManifeste } from "./journal.mjs";

/** Racine du projet (le dossier qui contient hardhat.config.mjs). */
export const PROJECT_ROOT = fileURLToPath(new URL("../../", import.meta.url));

/** Dossier des fichiers de déploiement, redirigeable par NOORTRACE_DEPLOYMENTS_DIR. */
export function deploymentsDir() {
  return process.env.NOORTRACE_DEPLOYMENTS_DIR || path.join(PROJECT_ROOT, "deployments");
}

/** Les quatre contrats du déploiement, dans l'ordre où ils sont déployés. */
export const CONTRACT_NAMES = ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"];

/**
 * Limite de gaz explicite des transactions envoyées à un réseau distant.
 *
 * L'instance de développement de noorcore n'a pas de simulation EVM derrière
 * eth_estimateGas : elle rend une valeur fixe (21000 pour un transfert, 300000
 * pour tout appel de contrat, 5000000 pour une création). Or submitPeriod
 * consomme de 234 079 à 314 256 gaz mesurés selon l'URI et l'état (douze
 * emplacements de stockage, deux ecrecover ; spec/CT-4-registre.md, 4.5) :
 * laissé à l'estimation automatique de Hardhat, l'appel tombe en épuisement de
 * gaz (status 0, gasUsed = 300000). On reprend donc la convention des scripts
 * de noorchain-core (gas: 3_000_000n), réglable par NOORTRACE_GAS_LIMIT ; le
 * prix du gaz de l'instance (1 wei) rend la réservation sans conséquence.
 * Sur le réseau Hardhat en mémoire, l'estimation d'EDR est exacte et aucune
 * limite n'est imposée.
 */
export const GAS_LIMIT_RESEAU_DISTANT = 3_000_000n;

/** La limite de gaz des réseaux distants, après prise en compte de NOORTRACE_GAS_LIMIT. */
export function gasLimitReseauDistant() {
  const brut = process.env.NOORTRACE_GAS_LIMIT;
  if (!brut) return GAS_LIMIT_RESEAU_DISTANT;
  if (!/^\d+$/.test(brut) || BigInt(brut) <= 0n) throw new Error(`NOORTRACE_GAS_LIMIT invalide : ${brut} (entier positif attendu)`);
  return BigInt(brut);
}

/**
 * Surcharges de transaction (gasLimit) à passer aux appels sur la connexion
 * Hardhat `conn` : vides sur le réseau en mémoire, limite explicite ailleurs.
 */
export function txOverrides(conn) {
  if (conn?.networkConfig?.type === "edr-simulated") return {};
  return { gasLimit: gasLimitReseauDistant() };
}

/** Type de document des ancres de période dans AttestationRegistry. */
export const DOC_TYPE_PERIODE = keccak256(toUtf8Bytes("noortrace/periode/v0"));

/** Étiquettes de domaine des condensés, identiques à celles des contrats. */
export const TAG_PERIODE = "noortrace-periode";
export const TAG_ENREGISTREUR_INSCRIT = "noortrace-enregistreur-inscrit";
export const TAG_ENREGISTREUR_REVOQUE = "noortrace-enregistreur-revoque";

/** Type ABI de PeriodRegistry.PeriodMeta, pour `abi.encode(meta)`. */
export const PERIOD_META_TYPE =
  "tuple(bytes32 orgId,bytes32 journalId,bytes32 periodHash,bytes32 root,uint64 periodStart,uint64 periodEnd,uint64 firstSeq,uint64 lastSeq,uint32 version,string uri)";

/** Identifiant d'organisation : keccak256 du slug. */
export function orgIdOf(slug) {
  return keccak256(toUtf8Bytes(slug));
}

/** Identifiant de journal : keccak256 de son nom. */
export function journalIdOf(name) {
  return keccak256(toUtf8Bytes(name));
}

/** `abi.encode(meta)` tel que le contrat le calcule. */
export function encodePeriodMeta(meta) {
  return AbiCoder.defaultAbiCoder().encode(
    [PERIOD_META_TYPE],
    [[meta.orgId, meta.journalId, meta.periodHash, meta.root, meta.periodStart, meta.periodEnd, meta.firstSeq, meta.lastSeq, meta.version, meta.uri]],
  );
}

/** Condensé interne de PeriodRegistry.periodDigest, recalculé côté client. */
export function periodDigest({ chainId, registry, meta }) {
  return keccak256(solidityPacked(["uint256", "address", "string", "bytes32"], [chainId, registry, TAG_PERIODE, keccak256(encodePeriodMeta(meta))]));
}

/** Condensé interne de RecorderRegistry.registerDigest, recalculé côté client. */
export function registerDigest({ chainId, registry, orgId, journalId, chainKey, ed25519PubKey }) {
  return keccak256(
    solidityPacked(
      ["uint256", "address", "string", "bytes32", "bytes32", "address", "bytes32"],
      [chainId, registry, TAG_ENREGISTREUR_INSCRIT, orgId, journalId, chainKey, ed25519PubKey],
    ),
  );
}

/**
 * Condensé interne de RecorderRegistry.revokeDigest, recalculé côté client.
 * `registeredAt` est l'instant d'inscription de la clé visée, lu dans
 * `recorderOf(orgId, chainKey).registeredAt` : une révocation signée pour une
 * autre inscription (ou avant toute inscription, registeredAt = 0) ne vérifie pas.
 */
export function revokeDigest({ chainId, registry, orgId, chainKey, registeredAt }) {
  return keccak256(
    solidityPacked(["uint256", "address", "string", "bytes32", "address", "uint64"], [chainId, registry, TAG_ENREGISTREUR_REVOQUE, orgId, chainKey, registeredAt]),
  );
}

/**
 * Empreinte ancrée dans AttestationRegistry pour une période :
 * keccak256(orgId || journalId || periodHash). AttestationRegistry n'ancre
 * chaque empreinte qu'une fois pour toute la chaîne et refuse l'empreinte nulle ;
 * la racine de Merkle, elle, se répète (racine nulle d'une période vide, deux
 * périodes aux événements identiques, chez le même client ou un autre). Le
 * manifeste porte un nonce, donc periodHash est unique par construction, et le
 * préfixe (orgId, journalId) rattache l'ancre au journal qu'elle clôture.
 */
export function anchorFingerprint({ orgId, journalId, periodHash }) {
  return keccak256(solidityPacked(["bytes32", "bytes32", "bytes32"], [orgId, journalId, periodHash]));
}

/**
 * PeriodMeta attendu par PeriodRegistry.submitPeriod, champ pour champ, depuis
 * un manifeste de période v0 de CT-1 (§10.4) : periodHash est le SHA-256 du
 * manifeste canonique préfixé (hachageManifeste de scripts/lib/journal.mjs),
 * jamais un keccak256 ; version est celle du manifeste (0). `uri` est
 * l'emplacement du manifeste, libre et hors du manifeste (il ne peut pas se
 * contenir). Les bornes sont rendues en BigInt, comme le contrat les relit.
 */
export function periodMetaDuManifeste(manifeste, { uri = "" } = {}) {
  return {
    orgId: manifeste.org_id,
    journalId: manifeste.journal_id,
    periodHash: hachageManifeste(manifeste),
    root: manifeste.root,
    periodStart: BigInt(manifeste.period_start),
    periodEnd: BigInt(manifeste.period_end),
    firstSeq: BigInt(manifeste.first_seq),
    lastSeq: BigInt(manifeste.last_seq),
    version: manifeste.version,
    uri,
  };
}

/**
 * Signe un condensé interne au format EIP-191 (`personal_sign`) et rend la
 * signature sous la forme {v, r, s} attendue par les contrats. `signer` est un
 * Wallet ethers ou un signataire Hardhat : les deux exposent `signMessage`.
 */
export async function signDigest(signer, digest) {
  const sig = Signature.from(await signer.signMessage(getBytes(digest)));
  return { v: sig.v, r: sig.r, s: sig.s };
}

/** Signe un condensé par plusieurs signataires, dans l'ordre donné. */
export async function signDigestBy(signers, digest) {
  const out = [];
  for (const s of signers) out.push(await signDigest(s, digest));
  return out;
}

/** Signature SANS préfixe EIP-191, pour vérifier qu'elle est refusée. Wallet seulement. */
export function signRawDigest(wallet, digest) {
  const sig = Signature.from(wallet.signingKey.sign(digest));
  return { v: sig.v, r: sig.r, s: sig.s };
}

/** Remplace les BigInt par des chaînes pour JSON.stringify. */
export function jsonReplacer(_key, value) {
  return typeof value === "bigint" ? value.toString() : value;
}

/** Attend la transaction de déploiement d'un contrat et rend son reçu. */
async function deployReceipt(contract) {
  await contract.waitForDeployment();
  return contract.deploymentTransaction().wait();
}

/**
 * Déploie les quatre contrats de NOORTRACE, liés entre eux :
 *   AttestationRegistry, CuratorSetRegistry(admin = déployeur),
 *   PeriodRegistry(curatorSetRegistry), RecorderRegistry(curatorSetRegistry).
 * Rend les instances et un enregistrement sérialisable (adresses, blocs, tx).
 * `overrides` (gasLimit…) s'applique aux quatre transactions : voir txOverrides.
 */
export async function deployNoortrace(ethers, { deployer, networkName = "inconnu", log = () => {}, overrides = {} } = {}) {
  const signer = deployer ?? (await ethers.getSigners())[0];
  if (!signer) throw new Error("deployNoortrace : aucun compte de déploiement (NOOR_PRIVATE_KEY absent ?)");
  const chainId = (await ethers.provider.getNetwork()).chainId;
  log(`Réseau ${networkName} (chainId ${chainId}), déployeur ${signer.address}`);

  const contrats = {};
  const record = (name, address, receipt) => {
    contrats[name] = { adresse: address, bloc: receipt.blockNumber, tx: receipt.hash };
    log(`${name} : ${address} (bloc ${receipt.blockNumber})`);
  };

  const AttestationRegistry = await ethers.getContractFactory("AttestationRegistry", signer);
  const attestationRegistry = await AttestationRegistry.deploy(overrides);
  record("AttestationRegistry", await attestationRegistry.getAddress(), await deployReceipt(attestationRegistry));

  const CuratorSetRegistry = await ethers.getContractFactory("CuratorSetRegistry", signer);
  const curatorSetRegistry = await CuratorSetRegistry.deploy(signer.address, overrides);
  const curatorSetRegistryAddress = await curatorSetRegistry.getAddress();
  record("CuratorSetRegistry", curatorSetRegistryAddress, await deployReceipt(curatorSetRegistry));

  const PeriodRegistry = await ethers.getContractFactory("PeriodRegistry", signer);
  const periodRegistry = await PeriodRegistry.deploy(curatorSetRegistryAddress, overrides);
  record("PeriodRegistry", await periodRegistry.getAddress(), await deployReceipt(periodRegistry));

  const RecorderRegistry = await ethers.getContractFactory("RecorderRegistry", signer);
  const recorderRegistry = await RecorderRegistry.deploy(curatorSetRegistryAddress, overrides);
  record("RecorderRegistry", await recorderRegistry.getAddress(), await deployReceipt(recorderRegistry));

  const deployment = {
    reseau: networkName,
    chainId: chainId.toString(),
    deployeur: signer.address,
    horodatage: new Date().toISOString(),
    bloc: Math.max(...Object.values(contrats).map((c) => c.bloc)),
    contrats,
  };

  return { deployer: signer, attestationRegistry, curatorSetRegistry, periodRegistry, recorderRegistry, deployment };
}

/** Chemin du fichier de déploiement d'un réseau. */
export function deploymentPath(networkName, dir = deploymentsDir()) {
  return path.join(dir, `${networkName}.json`);
}

/** Chemin du fichier des organisations d'un réseau. */
export function orgsPath(networkName, dir = deploymentsDir()) {
  return path.join(dir, `${networkName}-orgs.json`);
}

/**
 * Écrit deployments/<réseau>.json et rend son chemin.
 *
 * Un fichier existant n'est JAMAIS écrasé en silence : il porte les adresses du
 * registre en service, et un redéploiement par erreur le remplacerait par
 * quatre contrats vides, où aucune organisation n'existe. Sans `force`, l'appel
 * refuse ; avec `force`, l'ancien fichier est d'abord archivé sous
 * <réseau>.<horodatage>.json (sauf `archive: false`, pour les réseaux en
 * mémoire dont le fichier n'est qu'une trace) et chaque adresse qui change est
 * signalée par `log`.
 */
export function writeDeployment(deployment, dir = deploymentsDir(), { force = false, archive = true, log = () => {} } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const file = deploymentPath(deployment.reseau, dir);
  if (fs.existsSync(file)) {
    if (!force) {
      throw new Error(
        `${file} existe déjà : il porte les adresses du registre en service. Relancer avec --force (ou NOORTRACE_FORCE=1) pour l'archiver et le remplacer.`,
      );
    }
    let previous = null;
    try {
      previous = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      previous = null;
    }
    if (archive) {
      const horodatage = String(previous?.horodatage ?? new Date().toISOString()).replace(/[:.]/g, "-");
      const archived = path.join(dir, `${deployment.reseau}.${horodatage}.json`);
      fs.renameSync(file, archived);
      log(`Ancien fichier de déploiement archivé : ${archived}`);
    }
    for (const name of CONTRACT_NAMES) {
      const avant = previous?.contrats?.[name]?.adresse;
      const apres = deployment.contrats?.[name]?.adresse;
      if (avant && apres && avant.toLowerCase() !== apres.toLowerCase()) log(`${name} : ${avant} -> ${apres} (adresse changée)`);
    }
  }
  fs.writeFileSync(file, JSON.stringify(deployment, jsonReplacer, 2) + "\n");
  return file;
}

/** Lit deployments/<réseau>.json, ou rend null s'il n'existe pas. */
export function readDeployment(networkName, dir = deploymentsDir()) {
  const file = deploymentPath(networkName, dir);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Lit deployments/<réseau>-orgs.json, ou rend une structure vide. */
export function readOrgs(networkName, dir = deploymentsDir()) {
  const file = orgsPath(networkName, dir);
  if (!fs.existsSync(file)) return { reseau: networkName, organisations: {} };
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

/** Écrit deployments/<réseau>-orgs.json et rend son chemin. */
export function writeOrgs(orgs, dir = deploymentsDir()) {
  fs.mkdirSync(dir, { recursive: true });
  const file = orgsPath(orgs.reseau, dir);
  fs.writeFileSync(file, JSON.stringify(orgs, jsonReplacer, 2) + "\n");
  return file;
}

/**
 * Rattache les instances de contrats d'un enregistrement de déploiement, et
 * vérifie que du code existe bien à chaque adresse sur le réseau connecté.
 */
export async function attachDeployment(ethers, deployment, signer) {
  const instances = {};
  for (const name of CONTRACT_NAMES) {
    const entry = deployment.contrats?.[name];
    if (!entry?.adresse) throw new Error(`Déploiement incomplet : ${name} absent`);
    const code = await ethers.provider.getCode(entry.adresse);
    if (code === "0x") throw new Error(`Aucun code à l'adresse de ${name} (${entry.adresse}) sur ce réseau`);
    instances[name] = await ethers.getContractAt(name, entry.adresse, signer);
  }
  return {
    attestationRegistry: instances.AttestationRegistry,
    curatorSetRegistry: instances.CuratorSetRegistry,
    periodRegistry: instances.PeriodRegistry,
    recorderRegistry: instances.RecorderRegistry,
  };
}

/**
 * Rend les contrats utilisables sur la connexion `conn` : sur le réseau Hardhat
 * en mémoire, un déploiement frais (rien n'y survit d'une exécution à l'autre) ;
 * sur un réseau distant, les adresses de deployments/<réseau>.json.
 */
export async function ensureDeployment(conn, { dir = deploymentsDir(), log = () => {} } = {}) {
  const { ethers, networkName, networkConfig } = conn;
  const simulated = networkConfig?.type === "edr-simulated";
  const [signer] = await ethers.getSigners();
  if (simulated) {
    log(`Réseau ${networkName} en mémoire : déploiement frais des contrats.`);
    const result = await deployNoortrace(ethers, { deployer: signer, networkName, log, overrides: txOverrides(conn) });
    return { ...result, deployment: result.deployment, fresh: true };
  }
  const deployment = readDeployment(networkName, dir);
  if (!deployment) {
    throw new Error(`Aucun fichier ${deploymentPath(networkName, dir)} : déployez d'abord avec scripts/deploy/deploy-noortrace.mjs`);
  }
  // Le fichier doit décrire LA chaîne connectée : un fichier copié d'un autre
  // nœud, ou survivant à une réinitialisation de la chaîne (mêmes adresses par
  // nonce du déployeur), ferait travailler les scripts sur la mauvaise chaîne.
  const chainId = (await ethers.provider.getNetwork()).chainId;
  if (String(deployment.chainId) !== chainId.toString()) {
    throw new Error(`chainId du réseau ${networkName} (${chainId}) différent de celui de ${deploymentPath(networkName, dir)} (${deployment.chainId})`);
  }
  if (!signer) throw new Error("ensureDeployment : aucun compte de déploiement (NOOR_PRIVATE_KEY absent ?)");
  const instances = await attachDeployment(ethers, deployment, signer);
  return { deployer: signer, ...instances, deployment, fresh: false };
}

/**
 * Amorce une organisation : déploie un CuratorSet (admin, approbateurs, seuil)
 * et l'assigne à `orgIdOf(slug)` dans le CuratorSetRegistry. `admin` doit être
 * l'administrateur du registre (le déployeur, sauf transfert). `setAdmin`,
 * facultatif, est l'administrateur du CuratorSet (la clé de gouvernance de
 * l'organisation, spec/CT-4-registre.md EX-5.6, EX-7.7) ; par défaut, celui
 * de l'amorçage de développement, `admin`. `overrides` (gasLimit…)
 * s'applique aux deux transactions : voir txOverrides.
 */
export async function bootstrapOrg(ethers, { curatorSetRegistry, admin, setAdmin = null, slug, approvers, threshold, log = () => {}, overrides = {} }) {
  if (!slug) throw new Error("bootstrapOrg : slug manquant");
  if (!Array.isArray(approvers) || approvers.length === 0) throw new Error("bootstrapOrg : au moins un approbateur est requis");
  const seuil = Number(threshold);
  if (!Number.isInteger(seuil) || seuil < 1 || seuil > approvers.length) {
    throw new Error(`bootstrapOrg : seuil invalide (${threshold}) pour ${approvers.length} approbateur(s)`);
  }
  const orgId = orgIdOf(slug);

  const CuratorSet = await ethers.getContractFactory("CuratorSet", admin);
  const administrateurDuJeu = setAdmin ?? admin.address;
  const curatorSet = await CuratorSet.deploy(administrateurDuJeu, approvers, seuil, overrides);
  const deployRcpt = await deployReceipt(curatorSet);
  const curatorSetAddress = await curatorSet.getAddress();
  log(`CuratorSet de « ${slug} » : ${curatorSetAddress} (bloc ${deployRcpt.blockNumber})`);

  const assignRcpt = await (await curatorSetRegistry.connect(admin).setCuratorSet(orgId, curatorSetAddress, overrides)).wait();
  log(`Assigné dans CuratorSetRegistry (bloc ${assignRcpt.blockNumber})`);

  return {
    orgId,
    curatorSet,
    record: {
      slug,
      orgId,
      curatorSet: curatorSetAddress,
      admin: administrateurDuJeu,
      approbateurs: approvers,
      seuil,
      txDeploiement: deployRcpt.hash,
      txAssignation: assignRcpt.hash,
      bloc: assignRcpt.blockNumber,
      horodatage: new Date().toISOString(),
    },
  };
}

/**
 * Les signataires à employer pour une organisation DÉJÀ amorcée : lit le
 * CuratorSet assigné à `orgId`, son seuil, et retient parmi `wallets` (Wallets
 * ethers) ceux qui en sont membres, jusqu'au seuil. Refuse si le seuil n'est pas
 * couvert. C'est la voie qui permet à un script d'agir sur une organisation
 * existante SANS remplacer son jeu d'approbateurs.
 */
export async function signatairesDuJeuEnPlace(ethers, { curatorSetRegistry, orgId, wallets }) {
  const curatorSetAddress = await curatorSetRegistry.curatorSetOf(orgId);
  if (curatorSetAddress === ZeroAddress) throw new Error(`signatairesDuJeuEnPlace : l'organisation ${orgId} n'a aucun jeu assigné`);
  const curatorSet = await ethers.getContractAt("CuratorSet", curatorSetAddress);
  const threshold = Number(await curatorSet.getThreshold());
  const signataires = [];
  for (const w of wallets) {
    if (signataires.length >= threshold) break;
    if (await curatorSet.isCurator(w.address)) signataires.push(w);
  }
  if (signataires.length < threshold) {
    throw new Error(`Il faut ${threshold} clé(s) d'approbateur membre(s) du jeu en place (${curatorSetAddress}) ; ${signataires.length} fournie(s)`);
  }
  return { curatorSet, curatorSetAddress, threshold, signataires };
}

/** Analyse `--cle valeur` et `--cle=valeur` dans argv ; rend un objet. */
export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const eq = a.indexOf("=");
    if (eq !== -1) {
      out[a.slice(2, eq)] = a.slice(eq + 1);
    } else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
      out[a.slice(2)] = argv[++i];
    } else {
      out[a.slice(2)] = true;
    }
  }
  return out;
}

/** Compile le projet si besoin (utile quand un script est lancé avec `node`). */
export async function ensureCompiled(hre) {
  await hre.tasks.getTask("build").run({ quiet: true });
}
