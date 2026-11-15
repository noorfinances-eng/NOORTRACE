// Amorce une organisation sur un réseau où NOORTRACE est déployé : déploie un
// CuratorSet (admin = déployeur, approbateurs, seuil) et l'assigne à l'organisation
// dans CuratorSetRegistry, puis écrit deployments/<réseau>-orgs.json.
//
//   node scripts/deploy/bootstrap-org.mjs --org <slug> --approvers 0xa,0xb,0xc --threshold 2 --network noorcore
//
// `npx hardhat run` ne transmet pas d'arguments au script ; dans ce cas, les
// mêmes valeurs se passent par NOORTRACE_ORG, NOORTRACE_APPROVERS et
// NOORTRACE_THRESHOLD :
//
//   NOORTRACE_ORG=demo NOORTRACE_APPROVERS=0xa,0xb NOORTRACE_THRESHOLD=1 \
//     npx hardhat --config hardhat.config.mjs run --network noorcore scripts/deploy/bootstrap-org.mjs
//
// Sur le réseau Hardhat en mémoire, les contrats sont déployés à la volée
// (rien n'y survit d'une exécution à l'autre).
//
// Outil de développement, hors de la section 7 de spec/CT-4-registre.md : il
// laisse le déployeur administrateur du jeu (EX-5.6). Le jeu d'une organisation
// déjà inscrite n'est remplacé, après un avertissement, que sur un réseau de
// développement ou d'essai (identifiants EVM 2121 à 2124, 31337) ; ailleurs,
// l'outil refuse (code 2) sans --remplacer, parce qu'un remplacement rend les
// approbateurs du client muets et contourne la voie de CT-4 EX-8.10 (reassigner,
// demande écrite du client) : revue de sécurité interne, EX-7.2. L'inscription
// d'un client suit l'outil de référence scripts/registre/noortrace-registre.mjs
// (inscrire-client), qui ne réutilise jamais un slug (EX-6.3, EX-7.6).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isAddress } from "ethers";
import { bootstrapOrg, deploymentsDir, ensureCompiled, ensureDeployment, jsonReplacer, orgIdOf, parseArgs, readOrgs, txOverrides, writeOrgs } from "../lib/noortrace.mjs";

/** Identifiants EVM des réseaux de développement et d'essai (CT-4 EX-7.2, EX-7.3). */
export const RESEAUX_DEVELOPPEMENT = Object.freeze([2121n, 2122n, 2123n, 2124n, 31337n]);

/**
 * CT-4 EX-7.2 : le jeu d'une organisation déjà inscrite ne se remplace que sur un
 * réseau de développement ou d'essai ; ailleurs, --remplacer est exigé. Rend
 * null (admis) ou le message du refus.
 */
export function refusRemplacement({ chainId, inscrite, remplacer }) {
  if (!inscrite) return null;
  let id;
  try {
    id = BigInt(chainId);
  } catch {
    return `identifiant de chaîne illisible (${String(chainId).slice(0, 40)}) : remplacement refusé`;
  }
  if (RESEAUX_DEVELOPPEMENT.includes(id)) return null;
  if (remplacer === true) return null;
  return `l'organisation est déjà inscrite sur le réseau ${id}, hors des réseaux de développement (2121 à 2124) et d'essai (31337) : son jeu ne se remplace pas par cet outil sans --remplacer ; la voie prévue est reassigner avec la demande écrite du client (CT-4 EX-8.10)`;
}

function usage(message) {
  console.error(message);
  console.error("Usage : node scripts/deploy/bootstrap-org.mjs --org <slug> --approvers 0xa,0xb,0xc --threshold n [--network <réseau>]");
  process.exit(2);
}

async function main() {
  process.env.HARDHAT_CONFIG ??= fileURLToPath(new URL("../../hardhat.config.mjs", import.meta.url));
  const hre = (await import("hardhat")).default;
  const args = parseArgs(process.argv.slice(2));
  const slug = String(args.org ?? process.env.NOORTRACE_ORG ?? "");
  const approversRaw = String(args.approvers ?? process.env.NOORTRACE_APPROVERS ?? "");
  const thresholdRaw = String(args.threshold ?? process.env.NOORTRACE_THRESHOLD ?? "");

  if (!slug) usage("Argument --org manquant.");
  const approvers = approversRaw.split(",").map((a) => a.trim()).filter(Boolean);
  if (approvers.length === 0) usage("Argument --approvers manquant (adresses séparées par des virgules).");
  const bad = approvers.filter((a) => !isAddress(a));
  if (bad.length > 0) usage(`Adresse(s) d'approbateur invalide(s) : ${bad.join(", ")}`);
  const threshold = Number(thresholdRaw);
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > approvers.length) {
    usage(`Argument --threshold invalide : ${thresholdRaw || "(absent)"} pour ${approvers.length} approbateur(s).`);
  }

  await ensureCompiled(hre);
  const conn = await hre.network.create(args.network ? String(args.network) : undefined);
  const { ethers, networkName } = conn;

  const dir = deploymentsDir();
  const { deployer, curatorSetRegistry, deployment } = await ensureDeployment(conn, { dir, log: console.log });

  const registryAdmin = await curatorSetRegistry.admin();
  if (registryAdmin.toLowerCase() !== deployer.address.toLowerCase()) {
    throw new Error(`Le compte ${deployer.address} n'administre pas CuratorSetRegistry (admin : ${registryAdmin})`);
  }

  const orgs = readOrgs(networkName, dir);
  // L'avertissement se fonde sur la chaîne, pas seulement sur le fichier : une
  // organisation amorcée par l'e2e n'y figure pas.
  const orgId = orgIdOf(slug);
  const inscrite = await curatorSetRegistry.isRegistered(orgId);
  const refus = refusRemplacement({ chainId: deployment.chainId, inscrite, remplacer: args.remplacer === true });
  if (refus) {
    console.error(`Refus : « ${slug} » : ${refus}`);
    process.exitCode = 2;
    return;
  }
  if (inscrite) {
    const jeuPrecedent = await curatorSetRegistry.curatorSetOf(orgId);
    console.log(`Attention : « ${slug} » est déjà amorcée (CuratorSet ${jeuPrecedent}) ; le jeu sera remplacé et ses approbateurs actuels ne pourront plus rien signer.`);
  }

  // Limite de gaz explicite hors du réseau en mémoire (voir txOverrides).
  const { record } = await bootstrapOrg(ethers, { curatorSetRegistry, admin: deployer, slug, approvers, threshold, log: console.log, overrides: txOverrides(conn) });

  orgs.reseau = networkName;
  orgs.chainId = deployment.chainId;
  orgs.curatorSetRegistry = await curatorSetRegistry.getAddress();
  orgs.organisations = { ...(orgs.organisations ?? {}), [slug]: record };
  const file = writeOrgs(orgs, dir);

  console.log(`Fichier des organisations : ${file}`);
  console.log(JSON.stringify(record, jsonReplacer, 2));
}

/** Chemin réel d'un fichier (liens symboliques résolus), ou null. */
function cheminReel(p) {
  try {
    return fs.realpathSync(path.resolve(p));
  } catch {
    return null;
  }
}

// Lancé par `node scripts/deploy/bootstrap-org.mjs …` ou par `npx hardhat run … scripts/deploy/bootstrap-org.mjs` (le chemin du
// script est dans argv) ; importé par un essai, le module n'exécute rien.
if (process.argv.slice(1).some((a) => cheminReel(a) === fileURLToPath(import.meta.url))) {
  main().catch((e) => {
    console.error("Échec de l'amorçage :", e);
    process.exitCode = 1;
  });
}
