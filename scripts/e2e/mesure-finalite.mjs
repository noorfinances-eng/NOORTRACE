// Mesure de la finalité observée et du gaz consommé sur un réseau noorcore où
// NOORTRACE est déployé et une organisation amorcée. Le script envoie trois
// transactions (registerRecorder, anchor, submitPeriod) et, pour chacune :
//   - note l'instant d'envoi (eth_sendRawTransaction) et l'instant où
//     eth_getTransactionReceipt rend un reçu, en scrutant toutes les
//     --intervalle ms (50 par défaut) en JSON-RPC direct — sans la scrutation
//     à 4 s d'ethers, qui masquerait la finalité réelle ;
//   - vérifie que le reçu est dans un bloc (status 1), que l'événement attendu
//     (RecorderRegistered, Anchored, PeriodSubmitted) figure dans ses journaux
//     avec le bon topic0, qu'eth_getLogs le retrouve sur ce bloc, et que le
//     bloc est toujours canonique à la fin de la mesure ;
//   - relève le gaz consommé (gasUsed) et la limite envoyée (gasLimit).
// Imprime un JSON de résultat ; code de sortie 1 si une vérification échoue.
//
//   NOOR_PRIVATE_KEY=0x… NOORTRACE_APPROVER_KEYS=0x…,0x…,0x… \
//     node scripts/e2e/mesure-finalite.mjs [--network noorcore] [--org assureur-demo] \
//       [--journal journal-principal] [--intervalle 50]
//
// Ne dépend pas de Hardhat (ethers seul) : lit deployments/<réseau>.json,
// deployments/<réseau>-orgs.json et les ABI de hh-artifacts/ (compiler d'abord).
// NOOR_RPC_URL remplace l'URL JSON-RPC (http://127.0.0.1:8645 par défaut).
// Les approbateurs (NOORTRACE_APPROVER_KEYS : clés privées membres du jeu de
// l'organisation, au moins « seuil ») signent hors chaîne ; seul le compte
// NOOR_PRIVATE_KEY paie le gaz. Chaque exécution enregistre un nouvel
// enregistreur, ancre l'empreinte d'une nouvelle période
// (keccak256(orgId || journalId || periodHash)) et enchaîne cette période à la
// suite de la précédente (continuité par journal), ce qui permet de répéter la
// mesure.
//
// OUTIL DE MESURE DU RÉSEAU DE DÉVELOPPEMENT : les clés passées par
// l'environnement sont des clés d'essai (comptes de la mnémonique publique,
// clés de test publiées), jamais des clés réelles. Garde de réseau (revue de sécurité de l'étape 8) :
// l'identifiant EVM du point doit être 2121 à 2124 ou 31337 et
// NOOR_RPC_URL doit viser la boucle locale, sauf --reseau-distant ; sinon
// refus, code 2, rien n'est envoyé. Une clé mal saisie ou une URL qui porte
// des identifiants est refusée sans que la valeur soit recopiée ; le
// résultat ne porte l'URL que sans ses secrets.

import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { Contract, JsonRpcProvider, Wallet, ZeroHash, hexlify, randomBytes, sha256 } from "ethers";
import {
  DOC_TYPE_PERIODE,
  PROJECT_ROOT,
  anchorFingerprint,
  deploymentsDir,
  gasLimitReseauDistant,
  journalIdOf,
  jsonReplacer,
  parseArgs,
  periodMetaDuManifeste,
  readDeployment,
  readOrgs,
  signDigest,
  signDigestBy,
} from "../lib/noortrace.mjs";
import { construireManifeste } from "../lib/journal.mjs";

const args = parseArgs(process.argv.slice(2));
const reseau = String(args.network ?? "noorcore");
const intervalleMs = Number(args.intervalle ?? 50);
const journalNom = String(args.journal ?? "journal-principal");
const DELAI_MAX_MS = 120_000;
/** Identifiants EVM des réseaux de développement et d'essai (CT-4 EX-7.2, EX-7.3) : seuls réseaux où cet outil écrit. */
const RESEAUX_DEVELOPPEMENT = new Set([2121n, 2122n, 2123n, 2124n, 31337n]);
const HOTES_LOCAUX = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const HEX_CLE = /^0x[0-9a-fA-F]{64}$/;

/** Refus avant toute écriture : code 2. */
class Refus extends Error {
  constructor(message) {
    super(message);
    this.code = 2;
  }
}

/** Une clé secp256k1 saisie : 0x suivi de 64 chiffres hexadécimaux ; le message de refus ne nomme que la variable et le rang, jamais la valeur. */
function cleValidee(valeur, nom) {
  if (typeof valeur !== "string" || !HEX_CLE.test(valeur.trim())) throw new Refus(`${nom} : clé secp256k1 attendue, 0x suivi de 64 chiffres hexadécimaux ; la valeur saisie n'est pas recopiée`);
  return valeur.trim();
}

/** URL sans identifiants ni chaîne de requête, seule forme écrite dans le résultat ou un message. */
function urlSansSecret(u) {
  try {
    const x = new URL(u);
    x.username = "";
    x.password = "";
    x.search = "";
    return x.toString().replace(/\/$/, "");
  } catch {
    return "<URL illisible>";
  }
}

/** NOOR_RPC_URL contrôlée : http(s), sans identifiants ni chaîne de requête ; boucle locale sauf --reseau-distant. */
function urlVerifiee(brute, { distant }) {
  let u;
  try {
    u = new URL(brute);
  } catch {
    throw new Refus("NOOR_RPC_URL : URL illisible");
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Refus(`NOOR_RPC_URL : schéma ${u.protocol} refusé`);
  if (u.username || u.password || u.search) throw new Refus(`NOOR_RPC_URL : ${urlSansSecret(u)} porte des identifiants ou une chaîne de requête : aucun secret ne passe par l'URL`);
  if (!distant && !HOTES_LOCAUX.has(u.hostname)) throw new Refus(`NOOR_RPC_URL : ${u.hostname} hors de la boucle locale ; cet outil n'écrit que dans le registre de développement : --reseau-distant pour un autre point, dont l'identifiant EVM doit rester 2121 à 2124 ou 31337`);
  return u.toString().replace(/\/$/, "");
}

/** Message d'erreur sans secret : hexadécimal long et identifiants d'URL effacés. */
function messageSur(e) {
  return String(e?.message ?? e)
    .replace(/0x[0-9a-fA-F]{40,}/g, "0x…")
    .replace(/\/\/[^/@\s]+@/g, "//");
}

/** Point JSON-RPC, contrôlé par urlVerifiee au début de main (refus : code 2, sans pile). */
let url = null;

/** ABI d'un contrat, lue dans les artefacts de compilation. */
function abiDe(nom) {
  const fichier = path.join(PROJECT_ROOT, "hh-artifacts", "contracts", `${nom}.sol`, `${nom}.json`);
  if (!fs.existsSync(fichier)) throw new Error(`Artefact absent : ${fichier} (lancer npx hardhat compile)`);
  return JSON.parse(fs.readFileSync(fichier, "utf8")).abi;
}

/** Appel JSON-RPC direct, sans lot ni scrutation intermédiaire. */
let idRpc = 0;
async function rpc(methode, params = []) {
  const reponse = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++idRpc, method: methode, params }),
  });
  const corps = await reponse.json();
  if (corps.error) throw new Error(`${methode} : ${corps.error.message ?? JSON.stringify(corps.error)}`);
  return corps.result;
}

const dormir = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const arrondi = (x) => Math.round(x * 10) / 10;
const entier = (hex) => Number(BigInt(hex));


async function main() {
  url = urlVerifiee(process.env.NOOR_RPC_URL || "http://127.0.0.1:8645", { distant: args["reseau-distant"] === true });
  if (!process.env.NOOR_PRIVATE_KEY) throw new Refus("NOOR_PRIVATE_KEY manquante (clé privée du compte d'essai qui relaie les transactions)");
  const cle = cleValidee(process.env.NOOR_PRIVATE_KEY, "NOOR_PRIVATE_KEY");
  const clesApprobateurs = (process.env.NOORTRACE_APPROVER_KEYS ?? "")
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k, i) => cleValidee(k, `NOORTRACE_APPROVER_KEYS, clé de rang ${i + 1}`));
  if (clesApprobateurs.length === 0) throw new Refus("NOORTRACE_APPROVER_KEYS manquante (clés privées d'essai des approbateurs, séparées par des virgules)");
  if (!Number.isFinite(intervalleMs) || intervalleMs < 1) throw new Error(`--intervalle invalide : ${args.intervalle}`);

  // Le déploiement et l'organisation, tels qu'écrits par les scripts de déploiement.
  const dir = deploymentsDir();
  const deployment = readDeployment(reseau, dir);
  if (!deployment) throw new Error(`Aucun fichier deployments/${reseau}.json : déployer d'abord avec scripts/deploy/deploy-noortrace.mjs`);
  const orgs = readOrgs(reseau, dir);
  const slugs = Object.keys(orgs.organisations ?? {});
  const slug = String(args.org ?? slugs[0] ?? "");
  const org = orgs.organisations?.[slug];
  if (!org) throw new Error(`Organisation « ${slug || "(aucune)"} » absente de deployments/${reseau}-orgs.json : amorcer d'abord avec scripts/deploy/bootstrap-org.mjs`);

  const chainId = BigInt(await rpc("eth_chainId"));
  // Garde de réseau : jamais d'écriture hors des réseaux de développement et d'essai.
  if (!RESEAUX_DEVELOPPEMENT.has(chainId)) throw new Refus(`eth_chainId ${chainId} : hors des réseaux de développement (2121 à 2124) et d'essai (31337) ; cet outil de mesure n'écrit pas dans un autre registre`);
  if (chainId.toString() !== String(deployment.chainId)) {
    throw new Refus(`chainId du réseau (${chainId}) différent de celui de deployments/${reseau}.json (${deployment.chainId})`);
  }

  const provider = new JsonRpcProvider(url, undefined, { batchMaxCount: 1 });
  const expediteur = new Wallet(cle, provider);

  // Les signataires : les clés fournies dont l'adresse est membre du jeu, jusqu'au seuil.
  const membres = new Set(org.approbateurs.map((a) => a.toLowerCase()));
  const signataires = clesApprobateurs
    .map((k) => new Wallet(k))
    .filter((w) => membres.has(w.address.toLowerCase()))
    .slice(0, org.seuil);
  if (signataires.length < org.seuil) {
    throw new Error(`Il faut ${org.seuil} clé(s) d'approbateur membre(s) du jeu de « ${slug} » ; ${signataires.length} fournie(s)`);
  }

  const contrats = {};
  for (const nom of ["AttestationRegistry", "PeriodRegistry", "RecorderRegistry"]) {
    const adresse = deployment.contrats?.[nom]?.adresse;
    if (!adresse) throw new Error(`Déploiement incomplet : ${nom} absent`);
    if ((await rpc("eth_getCode", [adresse, "latest"])) === "0x") throw new Error(`Aucun code à l'adresse de ${nom} (${adresse})`);
    contrats[nom] = new Contract(adresse, abiDe(nom), provider);
  }

  const gasLimit = gasLimitReseauDistant();
  const gasPrice = BigInt(await rpc("eth_gasPrice"));
  let nonce = entier(await rpc("eth_getTransactionCount", [expediteur.address, "latest"]));
  const orgId = org.orgId;
  const journalId = journalIdOf(journalNom);

  const verifications = {};
  const check = (nom, ok) => {
    verifications[nom] = Boolean(ok);
    if (!ok) console.error(`Vérification en échec : ${nom}`);
  };

  /**
   * Signe, envoie et chronomètre une transaction vers `contrat.methode(...arguments)`,
   * puis vérifie l'événement `evenement` dans le reçu et par eth_getLogs.
   */
  async function mesurer({ nom, contrat, methode, arguments: argsTx, evenement }) {
    const to = await contrat.getAddress();
    const data = contrat.interface.encodeFunctionData(methode, argsTx);
    const nonceTx = nonce++;
    const brute = await expediteur.signTransaction({
      type: 2,
      chainId,
      nonce: nonceTx,
      to,
      data,
      gasLimit,
      maxFeePerGas: gasPrice,
      maxPriorityFeePerGas: gasPrice,
    });

    const hauteurAvantEnvoi = entier(await rpc("eth_blockNumber"));
    const horodatageEnvoi = new Date();
    const t0 = performance.now();
    const hash = await rpc("eth_sendRawTransaction", [brute]);
    const tAccepte = performance.now();

    let recu = null;
    let sondages = 0;
    while (!recu) {
      recu = await rpc("eth_getTransactionReceipt", [hash]);
      sondages += 1;
      if (recu) break;
      if (performance.now() - t0 > DELAI_MAX_MS) throw new Error(`${nom} : aucun reçu après ${DELAI_MAX_MS / 1000} s (${hash})`);
      await dormir(intervalleMs);
    }
    const t1 = performance.now();

    const bloc = await rpc("eth_getBlockByHash", [recu.blockHash, false]);
    const fragment = contrat.interface.getEvent(evenement);
    const topic0 = fragment.topicHash;
    const journauxRecu = recu.logs.filter((l) => l.address.toLowerCase() === to.toLowerCase() && l.topics[0] === topic0);
    const decode = journauxRecu.length === 1 ? contrat.interface.parseLog({ topics: [...journauxRecu[0].topics], data: journauxRecu[0].data }) : null;
    const viaGetLogs = await rpc("eth_getLogs", [{ address: to, topics: [topic0], fromBlock: recu.blockNumber, toBlock: recu.blockNumber }]);
    const retrouves = viaGetLogs.filter((l) => l.transactionHash === hash && l.topics[0] === topic0);

    check(`${nom}: status 1`, recu.status === "0x1");
    check(`${nom}: reçu dans un bloc`, recu.blockNumber != null && bloc != null && bloc.hash === recu.blockHash);
    check(`${nom}: événement ${evenement} dans le reçu`, journauxRecu.length === 1 && decode?.name === evenement);
    check(`${nom}: événement ${evenement} retrouvé par eth_getLogs`, retrouves.length === 1 && retrouves[0].blockHash === recu.blockHash);

    const numeroBloc = entier(recu.blockNumber);
    return {
      nom,
      methode,
      evenement,
      hash,
      nonce: nonceTx,
      hauteurAvantEnvoi,
      bloc: numeroBloc,
      blocHash: recu.blockHash,
      blocsAttendus: numeroBloc - hauteurAvantEnvoi,
      horodatageEnvoi: horodatageEnvoi.toISOString(),
      horodatageBloc: new Date(entier(bloc.timestamp) * 1000).toISOString(),
      delaiAcceptationMs: arrondi(tAccepte - t0),
      delaiRecuMs: arrondi(t1 - t0),
      sondages,
      gasLimit,
      gasUsed: entier(recu.gasUsed),
      status: recu.status,
      topic0,
      logIndex: journauxRecu.length === 1 ? entier(journauxRecu[0].logIndex) : null,
      champs: decode ? Object.fromEntries(decode.fragment.inputs.map((e, i) => [e.name, decode.args[i]])) : null,
      retrouveParGetLogs: retrouves.length === 1,
    };
  }

  // 1. Un nouvel enregistreur (clé de chaîne aléatoire, clé Ed25519 d'essai), au seuil.
  const enregistreur = Wallet.createRandom();
  const ed25519PubKey = hexlify(randomBytes(32));
  const dReg = await contrats.RecorderRegistry.registerDigest(orgId, journalId, enregistreur.address, ed25519PubKey);
  const mesureInscription = await mesurer({
    nom: "registerRecorder",
    contrat: contrats.RecorderRegistry,
    methode: "registerRecorder",
    arguments: [orgId, journalId, enregistreur.address, ed25519PubKey, await signDigestBy(signataires, dReg)],
    evenement: "RecorderRegistered",
  });
  check("isActiveRecorder", (await contrats.RecorderRegistry.isActiveRecorder(orgId, enregistreur.address)) === true);

  // 2. La période suivante du journal (continuité temps/séquence) : racine RFC 6962
  // de trois feuilles aléatoires et manifeste v0 de CT-1 (§10), dont periodHash
  // (SHA-256 du manifeste canonique préfixé, scripts/lib/journal.mjs) sert d'ancre.
  const feuilles = [0, 1, 2].map(() => sha256(randomBytes(32)));
  const precedentId = await contrats.PeriodRegistry.latestPeriodOf(orgId, journalId);
  let periodStart;
  let firstSeq;
  let prevPeriodHash = ZeroHash;
  if (precedentId === 0n) {
    const maintenant = BigInt(Math.floor(Date.now() / 1000));
    periodStart = maintenant - (maintenant % 3600n);
    firstSeq = 1n;
  } else {
    const precedente = await contrats.PeriodRegistry.getPeriod(precedentId);
    periodStart = precedente.periodEnd;
    firstSeq = precedente.lastSeq + 1n;
    prevPeriodHash = precedente.periodHash;
  }
  const periodEnd = periodStart + 3600n;
  const lastSeq = firstSeq + 2n;
  const manifeste = construireManifeste({
    org_id: orgId,
    journal_id: journalId,
    period_start: Number(periodStart),
    first_seq: Number(firstSeq),
    hashes: feuilles,
    prev_period_hash: prevPeriodHash,
    recorder_key_id: "mesure-enregistreur",
    nonce: hexlify(randomBytes(32)),
    generated_at: new Date().toISOString(),
  });
  const meta = periodMetaDuManifeste(manifeste, { uri: `mesure://${slug}/${journalNom}/${firstSeq}-${lastSeq}` });
  const { periodHash, root } = meta;

  // 3. L'ancre de la période, signée par l'enregistreur : empreinte
  // keccak256(orgId || journalId || periodHash), pas la racine nue (une racine
  // se répète, AttestationRegistry n'ancre chaque empreinte qu'une fois).
  const empreinteAncre = anchorFingerprint({ orgId, journalId, periodHash });
  const dAnc = await contrats.AttestationRegistry.anchorDigest(empreinteAncre, DOC_TYPE_PERIODE);
  const mesureAncre = await mesurer({
    nom: "anchor",
    contrat: contrats.AttestationRegistry,
    methode: "anchor",
    arguments: [empreinteAncre, DOC_TYPE_PERIODE, enregistreur.address, await signDigest(enregistreur, dAnc)],
    evenement: "Anchored",
  });
  const lookup = await contrats.AttestationRegistry.lookup(empreinteAncre);
  check("lookup.issuer", lookup.issuer === enregistreur.address);

  // 4. La clôture de période, au seuil.
  const dPer = await contrats.PeriodRegistry.periodDigest(meta);
  const mesurePeriode = await mesurer({
    nom: "submitPeriod",
    contrat: contrats.PeriodRegistry,
    methode: "submitPeriod",
    arguments: [meta, await signDigestBy(signataires, dPer)],
    evenement: "PeriodSubmitted",
  });
  const idPeriode = await contrats.PeriodRegistry.latestPeriodOf(orgId, journalId);
  check("latestPeriodOf", idPeriode > precedentId);
  check("isKnown", (await contrats.PeriodRegistry.isKnown(orgId, periodHash)) === true);
  check("getPeriod.periodHash", (await contrats.PeriodRegistry.getPeriod(idPeriode)).periodHash === periodHash);

  // 5. Les blocs sont-ils toujours canoniques à la fin de la mesure ?
  const mesures = [mesureInscription, mesureAncre, mesurePeriode];
  const hauteurFinale = entier(await rpc("eth_blockNumber"));
  for (const m of mesures) {
    const bloc = await rpc("eth_getBlockByNumber", [`0x${m.bloc.toString(16)}`, false]);
    m.canoniqueApresBlocs = hauteurFinale - m.bloc;
    check(`${m.nom}: bloc toujours canonique`, bloc?.hash === m.blocHash);
  }

  const delais = mesures.map((m) => m.delaiRecuMs);
  const resultat = {
    reseau,
    url: urlSansSecret(url),
    chainId: chainId.toString(),
    organisation: { slug, orgId, curatorSet: org.curatorSet, seuil: org.seuil, signataires: signataires.map((w) => w.address) },
    expediteur: expediteur.address,
    enregistreur: enregistreur.address,
    intervalleScrutationMs: intervalleMs,
    gasLimit,
    gasPrice,
    transactions: mesures,
    finalite: {
      delaiRecuMs: { min: Math.min(...delais), max: Math.max(...delais), moyenne: arrondi(delais.reduce((a, b) => a + b, 0) / delais.length) },
      blocsAttendus: mesures.map((m) => m.blocsAttendus),
      hauteurFinale,
    },
    gaz: Object.fromEntries(mesures.map((m) => [m.nom, m.gasUsed])),
    periode: { id: idPeriode, periodHash, empreinteAncre, firstSeq, lastSeq, periodStart, periodEnd },
    verifications,
    succes: Object.values(verifications).every(Boolean),
  };

  console.log(JSON.stringify(resultat, jsonReplacer, 2));
  if (!resultat.succes) process.exitCode = 1;
  provider.destroy();
}

main().catch((e) => {
  // Le message seul, sans la saisie ni la pile.
  console.error("Échec de la mesure :", messageSur(e));
  process.exitCode = e instanceof Refus ? 2 : 1;
});
