#!/usr/bin/env node
// Service `registre-dev` de la démonstration de référence (CT-2 §19.1) :
// instance de développement du registre, neuve à chaque lancement.
//
//   registre-dev.mjs servir   quatre validateurs noorcore (BFT, quorum 3) dans
//                             ce conteneur, puis déploiement des contrats,
//                             jeu d'approbateurs de l'organisation de
//                             démonstration et provision de la clé de chaîne
//                             de l'enregistreur ; reste en marche
//   registre-dev.mjs sonde    code 0 quand l'instance est prête, 1 sinon
//
// Ce que le service détient : les clés des quatre validateurs de test de CT-4,
// dérivées de libellés publics, et la clé du compte Hardhat 0, trésorerie
// et déployeur du réseau de développement (CT-4, vecteurs de `ct-4`). Ce sont
// des clés de démonstration publiques : elles ne protègent rien. Il ne détient
// aucune clé d'approbateur : les comptes Hardhat 1 à 3 ne sont ici que des
// adresses, membres du jeu de l'organisation.
//
// L'instance est déterministe : mêmes clés de validateur, même genèse, même
// déployeur parti du nonce 0, donc mêmes adresses de contrats à chaque
// lancement. Le manifeste d'instance `instance-registre.json` de la
// démonstration est un fichier fixe ; le service le recalcule et refuse de se
// dire prêt s'il diffère de ce qu'il a déployé.

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { createECDH, createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { SignataireChaineFichier, adresseCreation } from "@noortrace/ancrage/registre";
import { attendreChaine, clientRpc, rpc, soumettre, attendreRecu, aDuCode, jeuDe, seuilDe, estMembre, selecteur, motAdresse, motEntier, concatener, hexVersOctets } from "../demo-commun/chaine.mjs";

/** Identité de l'instance de développement (CT-4 §10 : 2124 est réservé au développement). */
export const BFT_CHAIN_ID = "noortrace-2124-dev";
export const EVM_CHAIN_ID = 2124;
/** Compte Hardhat 0 (`m/44'/60'/0'/0/0` de la mnémonique publique de test) : trésorerie et déployeur du développement. */
const CLE_TRESORERIE = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/** Comptes Hardhat 1 à 3 : adresses seulement. */
export const APPROBATEURS = Object.freeze([
  "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
  "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
]);
export const SEUIL = 2;
/** Ordre de déploiement : celui de `deployments/noorcore.json` du réseau de développement. */
export const CONTRATS = Object.freeze(["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"]);
/** Provision de la clé de chaîne de l'enregistreur (CT-4 §8.7), en wei : frais nominaux d'un wei par unité de gaz. */
const PROVISION_WEI = 10n ** 17n;

const env = (nom, defaut) => process.env[nom] ?? defaut;

/**
 * Clé privée du validateur i (1 à 4) : SHA-256 du libellé public des validateurs de test de CT-4
 * (`spec/vecteurs/ct-4/constantes.json`, `test_validators`) ; clé publique non compressée.
 */
export function cleValidateur(i) {
  const privee = createHash("sha256").update(`noortrace/vecteurs/ct4/validateur/v${i}`).digest();
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(privee);
  return { privee: privee.toString("hex"), publique: `0x${ecdh.getPublicKey("hex", "uncompressed")}` };
}

/** Jeu de validateurs de l'instance (`validators.json` de noorcore). */
export const jeuValidateurs = () => [1, 2, 3, 4].map((i) => ({ id: `v${i}`, pubKeyHex: cleValidateur(i).publique }));

/** Adresses des contrats : `CREATE(déployeur, nonce)` pour les nonces 0 à 3, puis le jeu de l'organisation au nonce 4. */
export function adressesAttendues() {
  const deployeur = SignataireChaineFichier.depuisOctets(CLE_TRESORERIE).adresse();
  const r = { deployeur };
  CONTRATS.forEach((nom, k) => (r[nom] = adresseCreation(deployeur, k)));
  r.CuratorSet = adresseCreation(deployeur, CONTRATS.length);
  return r;
}

/** Manifeste d'instance (CT-4 §4.8) que lit l'enregistreur à côté de son document d'ancrage. */
export function manifesteInstance() {
  const a = adressesAttendues();
  return {
    version: 0,
    bft_chain_id: BFT_CHAIN_ID,
    evm_chain_id: EVM_CHAIN_ID,
    contracts: ["AttestationRegistry", "PeriodRegistry", "RecorderRegistry"].map((name) => ({ name, address: a[name] })),
    fees: { gas_limit: 3000000, gas_limit_max: 16777216 },
    validator_sets: [{ from_height: 1, to_height: null, validators: jeuValidateurs(), source: "registre-dev de la démonstration de référence : validateurs de test de CT-4 (libellés publics), clés publiques seulement" }],
    source: "registre-dev de la démonstration de référence (CT-2 §19.1) : instance de développement neuve à chaque lancement, adresses déterministes",
  };
}

function journal(evenement, donnees = {}) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), service: "registre-dev", event: evenement, ...donnees })}\n`);
}

function lancerValidateurs({ binaire, donnees, genese, ecoute }) {
  fs.mkdirSync(path.join(donnees, "cles"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(donnees, "validators.json"), `${JSON.stringify({ validators: jeuValidateurs() }, null, 2)}\n`);
  const p2p = (i) => `127.0.0.1:${30302 + i}`;
  const enfants = [];
  for (const i of [1, 2, 3, 4]) {
    const cle = path.join(donnees, "cles", `node${i}.key`);
    fs.writeFileSync(cle, `${cleValidateur(i).privee}\n`, { mode: 0o600 });
    const args = [
      "-chain-id", BFT_CHAIN_ID, "-evm-chain-id", String(EVM_CHAIN_ID),
      "-data-dir", path.join(donnees, `node${i}`),
      "-p2p-addr", p2p(i),
      // Seul le validateur 1 écoute hors de la boucle locale : c'est le point JSON-RPC du réseau `registre`.
      "-rpc-addr", i === 1 ? `${ecoute}:8545` : `127.0.0.1:${8545 + i - 1}`,
      "-health-addr", `127.0.0.1:${8080 + i - 1}`,
      "-role", i === 1 ? "leader" : "follower",
      "-consensus", "bft", "-validator-id", `v${i}`,
      "-validators-file", path.join(donnees, "validators.json"),
      "-validator-key-file", cle,
      "-boot-peers", [1, 2, 3, 4].filter((j) => j !== i).map(p2p).join(","),
      "-network-profile", "dev",
      "-alloc-file", genese,
    ];
    if (i === 1 && ecoute !== "127.0.0.1") args.push("-allow-public-bind");
    fs.mkdirSync(path.join(donnees, `node${i}`), { recursive: true });
    const sortie = fs.openSync(path.join(donnees, `node${i}.log`), "a");
    // Aucune règle d'émission ne vient de l'environnement : la genèse déclare une chaîne sans émission.
    const p = spawn(binaire, args, { stdio: ["ignore", sortie, sortie], env: { PATH: process.env.PATH ?? "" } });
    p.on("exit", (code, signal) => {
      journal("validateur_arrete", { validateur: `v${i}`, code, signal });
      if (!arret) terminer(1);
    });
    enfants.push(p);
  }
  return enfants;
}

let arret = false;
let enfantsLances = [];
function terminer(code) {
  if (arret) return;
  arret = true;
  for (const p of enfantsLances) p.kill("SIGTERM");
  const fin = setTimeout(() => {
    for (const p of enfantsLances) p.kill("SIGKILL");
    process.exit(code);
  }, 8000);
  Promise.all(enfantsLances.map((p) => (p.exitCode !== null || p.signalCode !== null ? null : new Promise((r) => p.once("exit", r))))).then(() => {
    clearTimeout(fin);
    process.exit(code);
  });
}

/** Code de création d'un contrat, lu dans le fichier des codes de l'image. */
function codeCreation(codes, nom) {
  const c = codes[nom];
  if (typeof c !== "string" || !/^0x([0-9a-f]{2})+$/.test(c)) throw new Error(`code de création de ${nom} absent`);
  return hexVersOctets(c);
}

/**
 * Déploie ce qui manque : les quatre contrats, le jeu d'approbateurs de l'organisation, son assignation et la provision
 * de la clé de chaîne de l'enregistreur. Les transactions manquantes sont soumises à la suite, aux nonces consécutifs de la
 * trésorerie, puis leurs reçus sont attendus : sur une chaîne neuve, tout tient en quelques blocs.
 */
async function deployer(o) {
  const { client, tresorerie, codes, attendues } = o;
  const arguments_ = {
    AttestationRegistry: new Uint8Array(0),
    CuratorSetRegistry: motAdresse(tresorerie.adresse()),
    PeriodRegistry: motAdresse(attendues.CuratorSetRegistry),
    RecorderRegistry: motAdresse(attendues.CuratorSetRegistry),
    // Jeu de l'organisation : administrateur = trésorerie de développement, comptes Hardhat 1 à 3, seuil 2.
    CuratorSet: concatener(motAdresse(tresorerie.adresse()), motEntier(0x60), motEntier(SEUIL), motEntier(APPROBATEURS.length), ...APPROBATEURS.map(motAdresse)),
  };
  let nonce = BigInt(await rpc(client, "eth_getTransactionCount", [tresorerie.adresse(), "pending"]));
  const soumises = [];
  const soumettreSuivante = async (quoi, tx) => soumises.push({ quoi, ...(await soumettre({ client, evmChainId: EVM_CHAIN_ID, signataire: tresorerie, nonce: nonce++, ...tx })) });
  for (const nom of [...CONTRATS, "CuratorSet"]) {
    if (await aDuCode(client, attendues[nom])) continue;
    if (adresseCreation(tresorerie.adresse(), nonce) !== attendues[nom]) throw new Error(`${nom} absent alors que la trésorerie est au nonce ${nonce} : instance incohérente, repartir d'une chaîne neuve`);
    await soumettreSuivante({ contrat: nom }, { to: null, data: concatener(codeCreation(codes, nom), arguments_[nom]) });
  }
  const jeuAssigne = soumises.length === 0 && (await jeuDe(client, attendues.CuratorSetRegistry, o.orgId)) === attendues.CuratorSet;
  if (!jeuAssigne) await soumettreSuivante({ assignation: o.orgId }, { to: attendues.CuratorSetRegistry, data: concatener(selecteur("setCuratorSet(bytes32,address)"), hexVersOctets(o.orgId, 32), motAdresse(attendues.CuratorSet)), gasLimit: 300000n });
  // Provision de la clé de chaîne de l'enregistreur (CT-4 §8.7) : elle paie le gaz de ses ancres et du relais de la clôture.
  if (BigInt(await rpc(client, "eth_getBalance", [o.cleChaine, "latest"])) < PROVISION_WEI) await soumettreSuivante({ provision: o.cleChaine }, { to: o.cleChaine, value: PROVISION_WEI, gasLimit: 21000n });
  for (const s of soumises) {
    const r = await attendreRecu(client, s.hash);
    if (s.quoi.contrat && r.adresseContrat !== attendues[s.quoi.contrat]) throw new Error(`${s.quoi.contrat} déployé à ${r.adresseContrat}, attendu ${attendues[s.quoi.contrat]}`);
    journal(s.quoi.contrat ? "contrat_deploye" : s.quoi.assignation ? "jeu_assigne" : "cle_chaine_approvisionnee", { ...s.quoi, adresse: r.adresseContrat ?? undefined, bloc: Number(BigInt(r.recu.blockNumber)) });
  }
  // Relecture : l'instance est celle que le manifeste décrit.
  if ((await jeuDe(client, attendues.CuratorSetRegistry, o.orgId)) !== attendues.CuratorSet) throw new Error("jeu de l'organisation non assigné");
  if ((await seuilDe(client, attendues.CuratorSet)) !== SEUIL) throw new Error("seuil du jeu différent de celui de la démonstration");
  for (const a of APPROBATEURS) if (!(await estMembre(client, attendues.CuratorSet, a))) throw new Error(`${a} absent du jeu`);
}

async function servir() {
  const donnees = env("REGISTRE_DEV_DONNEES", "/var/lib/noorcore");
  const pret = path.join(donnees, "pret.json");
  fs.rmSync(pret, { force: true });
  const manifesteFixe = env("REGISTRE_DEV_MANIFESTE", "/etc/noortrace-demo/instance-registre.json");
  const orgId = env("REGISTRE_DEV_ORG_ID", "");
  const cleChaine = env("REGISTRE_DEV_CLE_CHAINE", "").toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(orgId) || !/^0x[0-9a-f]{40}$/.test(cleChaine)) throw new Error("REGISTRE_DEV_ORG_ID (32 octets) et REGISTRE_DEV_CLE_CHAINE (adresse) attendus");
  const codes = JSON.parse(fs.readFileSync(env("REGISTRE_DEV_CODES", "/opt/noortrace-demo/codes-creation.json"), "utf8"));
  const calcule = manifesteInstance();
  const fixe = JSON.parse(fs.readFileSync(manifesteFixe, "utf8"));
  if (JSON.stringify(fixe) !== JSON.stringify(calcule)) throw new Error(`${manifesteFixe} diffère du manifeste que cette instance déploie : régénérer par « registre-dev.mjs manifeste »`);
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => terminer(0));
  enfantsLances = lancerValidateurs({ binaire: env("NOORCORE_BIN", "/usr/local/bin/noorcore"), donnees, genese: env("REGISTRE_DEV_GENESE", "/opt/noortrace-demo/alloc-dev.json"), ecoute: env("REGISTRE_DEV_ECOUTE", "0.0.0.0") });
  const client = clientRpc("http://127.0.0.1:8545");
  const hauteur = await attendreChaine(client, EVM_CHAIN_ID);
  journal("chaine_en_marche", { bft_chain_id: BFT_CHAIN_ID, evm_chain_id: EVM_CHAIN_ID, hauteur: Number(hauteur), validateurs: 4 });
  const attendues = adressesAttendues();
  await deployer({ client, tresorerie: SignataireChaineFichier.depuisOctets(CLE_TRESORERIE), codes, attendues, orgId, cleChaine });
  fs.writeFileSync(pret, `${JSON.stringify({ pret: true, contrats: attendues, org_id: orgId, cle_chaine: cleChaine })}\n`);
  journal("pret", { contrats: attendues, org_id: orgId });
}

async function sonde() {
  const donnees = env("REGISTRE_DEV_DONNEES", "/var/lib/noorcore");
  if (!fs.existsSync(path.join(donnees, "pret.json"))) return 1;
  const client = clientRpc("http://127.0.0.1:8545", 2000);
  const h1 = BigInt(await rpc(client, "eth_blockNumber"));
  return h1 > 0n ? 0 : 1;
}

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

if (estProgramme(import.meta.url)) {
  const commande = process.argv[2];
  if (commande === "servir") {
    servir().catch((e) => {
      journal("echec", { message: e.message });
      terminer(1);
    });
  } else if (commande === "sonde") {
    sonde().then((c) => process.exit(c), () => process.exit(1));
  } else if (commande === "manifeste") {
    process.stdout.write(`${JSON.stringify(manifesteInstance(), null, 2)}\n`);
  } else {
    process.stderr.write("usage : registre-dev.mjs servir | sonde | manifeste\n");
    process.exit(2);
  }
}
