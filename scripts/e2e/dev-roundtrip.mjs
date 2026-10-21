// Aller-retour de bout en bout de NOORTRACE sur un réseau où les contrats sont
// déployés, avec trois approbateurs et un seuil de 2 :
//   1. amorce une organisation d'essai (CuratorSet + assignation), ou signe
//      avec le jeu d'approbateurs EN PLACE si l'organisation existe déjà ;
//   2. inscrit un enregistreur (clé de chaîne = un compte, clé Ed25519 = 32 octets d'essai) ;
//   3. ancre l'empreinte de la période dans AttestationRegistry.anchor
//      (fingerprint = keccak256(orgId || journalId || periodHash), issuer = clé
//      de l'enregistreur, docType = keccak256("noortrace/periode/v0")) ;
//   4. soumet la période dans PeriodRegistry ;
//   5. relit lookup, getPeriod, isKnown, isActiveRecorder, et imprime un JSON de
//      résultat avec les hachages de transaction et les numéros de bloc.
//
//   npx hardhat --config hardhat.config.mjs run --network hardhat scripts/e2e/dev-roundtrip.mjs   (fumée, en mémoire)
//   npx hardhat --config hardhat.config.mjs run --network noorcore scripts/e2e/dev-roundtrip.mjs
//   node scripts/e2e/dev-roundtrip.mjs --network noorcore [--org <slug>] [--remplacer-le-jeu]
//
// Sur le réseau Hardhat en mémoire, les contrats sont déployés à la volée. Sur
// un réseau distant, les adresses viennent de deployments/<réseau>.json et le
// compte NOOR_PRIVATE_KEY doit administrer CuratorSetRegistry.
//
// L'ORGANISATION. Sans --org (ni NOORTRACE_ORG), le script amorce une
// organisation d'essai e2e-<horodatage> avec trois portefeuilles jetables (ou
// NOORTRACE_APPROVER_KEYS : trois clés privées séparées par des virgules) ; sur
// un réseau distant, cette organisation et son CuratorSet RESTENT dans le
// registre, hors de deployments/<réseau>-orgs.json. Avec --org <slug> :
//   - si l'organisation n'existe pas encore, elle est amorcée comme ci-dessus ;
//   - si elle existe, son jeu d'approbateurs N'EST PAS remplacé : le script
//     exige NOORTRACE_APPROVER_KEYS (clés d'approbateurs membres du jeu en
//     place, au moins « seuil ») et signe avec elles ; la nouvelle période
//     s'enchaîne à la dernière du journal (continuité par journal) ;
//   - --remplacer-le-jeu (ou NOORTRACE_REMPLACER_LE_JEU=1) force l'amorçage
//     d'un NOUVEAU jeu pour une organisation existante : ses approbateurs
//     actuels ne pourront plus rien signer, et l'adresse du jeu précédent n'est
//     conservée que dans le JSON de résultat et l'événement CuratorSetAssigned.
// Les approbateurs signent hors chaîne et n'ont pas besoin de gaz.
// Le code de sortie est 1 si une relecture ne correspond pas à ce qui a été écrit.

import { fileURLToPath } from "node:url";
import { Wallet, ZeroHash, hexlify, keccak256, randomBytes, sha256, toUtf8Bytes, concat } from "ethers";
import {
  DOC_TYPE_PERIODE,
  anchorFingerprint,
  bootstrapOrg,
  deploymentsDir,
  ensureCompiled,
  ensureDeployment,
  journalIdOf,
  jsonReplacer,
  orgIdOf,
  parseArgs,
  periodDigest,
  registerDigest,
  signDigest,
  signDigestBy,
  signatairesDuJeuEnPlace,
  txOverrides,
} from "../lib/noortrace.mjs";

process.env.HARDHAT_CONFIG ??= fileURLToPath(new URL("../../hardhat.config.mjs", import.meta.url));
const hre = (await import("hardhat")).default;

/**
 * Racine de Merkle RFC 6962 (SHA-256, préfixes 0x00 feuille / 0x01 nœud).
 * Une période sans événement a la racine NULLE : c'est la convention que
 * PeriodRegistry impose (et non sha256("") de l'arbre vide de la RFC).
 */
function merkleRoot(leaves) {
  if (leaves.length === 0) return ZeroHash;
  if (leaves.length === 1) return sha256(concat(["0x00", leaves[0]]));
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return sha256(concat(["0x01", merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k))]));
}

/** Sérialisation canonique minimale : clés triées, sans espace. */
function canonical(obj) {
  return JSON.stringify(obj, (_k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  await ensureCompiled(hre);
  const conn = await hre.network.create(args.network ? String(args.network) : undefined);
  const { ethers, networkName } = conn;
  const simulated = conn.networkConfig?.type === "edr-simulated";
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const verifications = {};
  const check = (name, ok) => {
    verifications[name] = Boolean(ok);
    if (!ok) console.error(`Vérification en échec : ${name}`);
  };

  // 0. Les contrats : frais en mémoire, lus depuis deployments/ ailleurs.
  const { deployer, attestationRegistry, curatorSetRegistry, periodRegistry, recorderRegistry, deployment } = await ensureDeployment(conn, {
    dir: deploymentsDir(),
    log: console.error,
  });
  // Limite de gaz explicite hors du réseau en mémoire : l'eth_estimateGas de
  // l'instance de développement de noorcore rend 300000 pour tout appel, ce
  // qui ne suffit pas à submitPeriod (voir txOverrides).
  const surcharges = txOverrides(conn);

  // 1. L'organisation : amorcée (jeu neuf, seuil 2) ou existante (jeu en place).
  const approverKeys = process.env.NOORTRACE_APPROVER_KEYS ? process.env.NOORTRACE_APPROVER_KEYS.split(",").map((k) => k.trim()).filter(Boolean) : [];
  const slugExplicite = args.org ?? process.env.NOORTRACE_ORG;
  const slug = String(slugExplicite ?? `e2e-${Date.now()}`);
  const orgId = orgIdOf(slug);
  const remplacerLeJeu = args["remplacer-le-jeu"] === true || process.env.NOORTRACE_REMPLACER_LE_JEU === "1";
  const dejaAmorcee = await curatorSetRegistry.isRegistered(orgId);
  let org;
  let signataires;
  if (dejaAmorcee && !remplacerLeJeu) {
    // Jamais de remplacement silencieux : on signe avec le jeu en place.
    if (approverKeys.length === 0) {
      throw new Error(
        `L'organisation « ${slug} » est déjà amorcée (CuratorSet ${await curatorSetRegistry.curatorSetOf(orgId)}) : fournir NOORTRACE_APPROVER_KEYS ` +
          "(clés privées d'approbateurs membres du jeu en place) pour signer avec lui, ou --remplacer-le-jeu pour installer un nouveau jeu en connaissance de cause.",
      );
    }
    const jeu = await signatairesDuJeuEnPlace(ethers, { curatorSetRegistry, orgId, wallets: approverKeys.map((k) => new Wallet(k)) });
    signataires = jeu.signataires;
    org = { curatorSet: jeu.curatorSetAddress, approbateurs: signataires.map((a) => a.address), seuil: jeu.threshold, amorcee: false, jeuPrecedent: null };
    console.error(`Organisation « ${slug} » déjà amorcée : signature avec le jeu en place ${jeu.curatorSetAddress} (seuil ${jeu.threshold}).`);
  } else {
    const approvers = approverKeys.length >= 3 ? approverKeys.slice(0, 3).map((k) => new Wallet(k)) : [0, 1, 2].map(() => Wallet.createRandom());
    let jeuPrecedent = null;
    if (dejaAmorcee) {
      jeuPrecedent = await curatorSetRegistry.curatorSetOf(orgId);
      console.error(`Attention : « ${slug} » est déjà amorcée (${jeuPrecedent}) ; le jeu sera remplacé (--remplacer-le-jeu). Ses approbateurs actuels ne pourront plus rien signer.`);
    }
    if (!simulated) {
      console.error(`Attention : l'organisation d'essai « ${slug} » et son CuratorSet resteront dans le CuratorSetRegistry de ${networkName}, hors de deployments/${networkName}-orgs.json.`);
    }
    const { record } = await bootstrapOrg(ethers, {
      curatorSetRegistry,
      admin: deployer,
      slug,
      approvers: approvers.map((a) => a.address),
      threshold: 2,
      log: console.error,
      overrides: surcharges,
    });
    signataires = [approvers[0], approvers[2]]; // deux sur trois
    org = { ...record, amorcee: true, jeuPrecedent };
  }

  // 2. L'enregistreur : une clé de chaîne et une clé Ed25519 d'essai, propres à
  // l'exécution (l'enregistreur ne signe que hors chaîne, il n'a pas besoin de
  // gaz ; et chez une organisation, une clé Ed25519 n'est active que sous une
  // seule clé de chaîne à la fois).
  const recorder = Wallet.createRandom();
  const ed25519PubKey = keccak256(toUtf8Bytes(`noortrace-e2e-cle-ed25519-de-test | ${hexlify(randomBytes(16))}`));
  const journalId = journalIdOf("journal-principal");
  const recorderRegistryAddress = await recorderRegistry.getAddress();
  const dReg = await recorderRegistry.registerDigest(orgId, journalId, recorder.address, ed25519PubKey);
  check("registerDigest_contrat_egal_client", dReg === registerDigest({ chainId, registry: recorderRegistryAddress, orgId, journalId, chainKey: recorder.address, ed25519PubKey }));
  const regRcpt = await (await recorderRegistry.connect(deployer).registerRecorder(orgId, journalId, recorder.address, ed25519PubKey, await signDigestBy(signataires, dReg), surcharges)).wait();
  const actif = await recorderRegistry.isActiveRecorder(orgId, recorder.address);
  check("isActiveRecorder", actif === true);
  check("recorderByPubKey", (await recorderRegistry.recorderByPubKey(orgId, ed25519PubKey)).chainKey === recorder.address);

  // 3. Une période d'essai : trois événements, racine RFC 6962, manifeste canonique.
  // Le nonce d'exécution entre dans les feuilles et dans le manifeste : deux
  // exécutions ne produisent jamais la même racine ni la même empreinte.
  const nonceExecution = hexlify(randomBytes(32));
  const evenements = ["intention: lire le dossier 2026-77812", "execution: crm.lookup", "effets: lecture de 2 pièces"].map((e) =>
    sha256(toUtf8Bytes(`${e} | execution ${nonceExecution}`)),
  );
  const root = merkleRoot(evenements);
  // Continuité par journal : si l'organisation a déjà une période (exécution
  // répétée avec --org sur un réseau persistant), la nouvelle commence où la
  // précédente s'arrête ; sinon, l'heure courante et la séquence 1.
  const precedentId = await periodRegistry.latestPeriodOf(orgId, journalId);
  let periodStart;
  let firstSeq;
  if (precedentId === 0n) {
    const now = BigInt(Math.floor(Date.now() / 1000));
    periodStart = now - (now % 3600n);
    firstSeq = 1n;
  } else {
    const precedente = await periodRegistry.getPeriod(precedentId);
    periodStart = precedente.periodEnd;
    firstSeq = precedente.lastSeq + 1n;
  }
  const periodEnd = periodStart + 3600n;
  const lastSeq = firstSeq + 2n;
  const manifest = {
    org: slug,
    journal: "journal-principal",
    root,
    periodStart: periodStart.toString(),
    periodEnd: periodEnd.toString(),
    firstSeq: firstSeq.toString(),
    lastSeq: lastSeq.toString(),
    version: 1,
    nonce: nonceExecution,
  };
  const periodHash = keccak256(toUtf8Bytes(canonical(manifest)));
  const meta = { orgId, journalId, periodHash, root, periodStart, periodEnd, firstSeq, lastSeq, version: 1, uri: `e2e://${slug}/periode/${precedentId + 1n}` };

  // 3 bis. L'ancre de la période, signée par la clé de chaîne de l'enregistreur,
  // relayée par le déployeur. L'empreinte ancrée est celle du manifeste
  // préfixée du journal, pas la racine nue : AttestationRegistry n'ancre
  // chaque empreinte qu'une fois pour toute la chaîne, et une racine se répète
  // (période vide, événements identiques) là où periodHash ne se répète pas.
  const empreinteAncre = anchorFingerprint({ orgId, journalId, periodHash });
  const anchorDigest = await attestationRegistry.anchorDigest(empreinteAncre, DOC_TYPE_PERIODE);
  const anchorRcpt = await (
    await attestationRegistry.connect(deployer).anchor(empreinteAncre, DOC_TYPE_PERIODE, recorder.address, await signDigest(recorder, anchorDigest), surcharges)
  ).wait();
  const lookup = await attestationRegistry.lookup(empreinteAncre);
  check("lookup_issuer", lookup.issuer === recorder.address);
  check("lookup_docType", lookup.docType === DOC_TYPE_PERIODE);
  check("lookup_non_revoque", lookup.revokedAt === 0n);

  // 4. La clôture de période, signée au seuil.
  const periodRegistryAddress = await periodRegistry.getAddress();
  const dPer = await periodRegistry.periodDigest(meta);
  check("periodDigest_contrat_egal_client", dPer === periodDigest({ chainId, registry: periodRegistryAddress, meta }));
  const periodRcpt = await (await periodRegistry.connect(deployer).submitPeriod(meta, await signDigestBy(signataires, dPer), surcharges)).wait();
  const id = await periodRegistry.latestPeriodOf(orgId, journalId);
  const periode = await periodRegistry.getPeriod(id);
  check("getPeriod_periodHash", periode.periodHash === periodHash);
  check("getPeriod_root", periode.root === root);
  check("getPeriod_bornes", periode.periodStart === periodStart && periode.periodEnd === periodEnd && periode.firstSeq === firstSeq && periode.lastSeq === lastSeq);
  check("getPeriod_publisher", periode.publisher === deployer.address);
  check("isKnown", (await periodRegistry.isKnown(orgId, periodHash)) === true);
  check("latestPeriodOf", id > 0n && id > precedentId);

  const resultat = {
    reseau: networkName,
    chainId: chainId.toString(),
    contrats: deployment.contrats,
    organisation: {
      slug,
      orgId,
      curatorSet: org.curatorSet,
      approbateurs: org.approbateurs,
      seuil: org.seuil,
      amorcee: org.amorcee,
      jeuPrecedent: org.jeuPrecedent,
      bloc: org.bloc ?? null,
      txDeploiement: org.txDeploiement ?? null,
      txAssignation: org.txAssignation ?? null,
    },
    enregistreur: { chainKey: recorder.address, ed25519PubKey, journalId, tx: regRcpt.hash, bloc: regRcpt.blockNumber, actif },
    ancre: {
      empreinte: empreinteAncre,
      periodHash,
      root,
      docType: DOC_TYPE_PERIODE,
      tx: anchorRcpt.hash,
      bloc: anchorRcpt.blockNumber,
      lookup: { issuer: lookup.issuer, docType: lookup.docType, issuedAt: lookup.issuedAt, revokedAt: lookup.revokedAt },
    },
    periode: {
      id,
      periodHash,
      tx: periodRcpt.hash,
      bloc: periodRcpt.blockNumber,
      getPeriod: {
        orgId: periode.orgId,
        journalId: periode.journalId,
        periodHash: periode.periodHash,
        root: periode.root,
        periodStart: periode.periodStart,
        periodEnd: periode.periodEnd,
        firstSeq: periode.firstSeq,
        lastSeq: periode.lastSeq,
        publishedAt: periode.publishedAt,
        version: periode.version,
        publisher: periode.publisher,
        uri: periode.uri,
      },
      isKnown: verifications.isKnown,
    },
    verifications,
    succes: Object.values(verifications).every(Boolean),
  };

  console.log(JSON.stringify(resultat, jsonReplacer, 2));
  if (!resultat.succes) process.exitCode = 1;
}

main().catch((e) => {
  console.error("Échec de l'aller-retour :", e);
  process.exitCode = 1;
});
