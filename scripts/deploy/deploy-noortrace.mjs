// Déploie les quatre contrats de NOORTRACE sur le réseau choisi et écrit
// deployments/<réseau>.json (adresses, numéros de bloc, hachages de
// transaction).
//
//   npx hardhat --config hardhat.config.mjs run --network hardhat scripts/deploy/deploy-noortrace.mjs
//   npx hardhat --config hardhat.config.mjs run --network noorcore scripts/deploy/deploy-noortrace.mjs
//   node scripts/deploy/deploy-noortrace.mjs --network noorcore [--force]
//
// Le dossier de sortie se redirige avec NOORTRACE_DEPLOYMENTS_DIR.
//
// Un fichier deployments/<réseau>.json existant n'est pas écrasé : il porte
// les adresses du registre en service, et une relance par erreur produirait
// quatre contrats neufs où aucune organisation n'existe. Pour redéployer
// vraiment, passer --force (ou NOORTRACE_FORCE=1 avec `npx hardhat run`, qui ne
// transmet pas d'arguments) : l'ancien fichier est archivé sous
// <réseau>.<horodatage>.json et chaque adresse qui change est signalée. Sur le
// réseau Hardhat en mémoire, rien ne survit d'une exécution à l'autre : le
// fichier n'est qu'une trace et il est simplement remplacé.

import { fileURLToPath } from "node:url";
import { deployNoortrace, deploymentsDir, ensureCompiled, jsonReplacer, parseArgs, txOverrides, writeDeployment } from "../lib/noortrace.mjs";

process.env.HARDHAT_CONFIG ??= fileURLToPath(new URL("../../hardhat.config.mjs", import.meta.url));
const hre = (await import("hardhat")).default;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  await ensureCompiled(hre);

  const conn = await hre.network.create(args.network ? String(args.network) : undefined);
  const { ethers, networkName } = conn;
  const simulated = conn.networkConfig?.type === "edr-simulated";
  const force = args.force === true || process.env.NOORTRACE_FORCE === "1";

  // Limite de gaz explicite hors du réseau en mémoire : l'eth_estimateGas de
  // l'instance de développement de noorcore est une heuristique fixe.
  const { deployment } = await deployNoortrace(ethers, { networkName, log: console.log, overrides: txOverrides(conn) });
  const file = writeDeployment(deployment, deploymentsDir(), { force: force || simulated, archive: !simulated, log: console.log });

  console.log(`Fichier de déploiement : ${file}`);
  console.log(JSON.stringify(deployment, jsonReplacer, 2));
}

main().catch((e) => {
  console.error("Échec du déploiement :", e);
  process.exitCode = 1;
});
