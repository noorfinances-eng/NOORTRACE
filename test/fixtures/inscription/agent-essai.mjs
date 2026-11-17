// Lanceur d'essai de l'agent d'inscription : même conduite que
// `bin/noortrace-inscription-agent` (ligne de disponibilité, code 2 et message
// sur la sortie d'erreur pour une configuration refusée, arrêt sur SIGTERM),
// par l'API programmatique `demarrerAgent(configuration, { memeCompteAdmis })`.
// Les essais tournent sous un seul compte (souvent le compte 0) : l'option,
// réservée aux essais et jamais lue par le binaire, lève le seul contrôle des
// comptes d'EX-7.23 (revue de l'étape 8, CT-4 EX-7.28) ; tous les autres contrôles
// de démarrage s'appliquent tels quels. Usage : node agent-essai.mjs --config <fichier>.
// Lancé seulement comme programme : Hardhat charge tout fichier JavaScript de test/ (fixtures comprises) ;
// chargé ainsi, le lanceur n'écrit rien et ne termine pas le processus de la suite.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { demarrerAgent, ErreurConfiguration } from "../../../paquets/inscription/src/agent/index.mjs";

async function principal() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || args[0] !== "--config") {
    process.stderr.write("usage : agent-essai.mjs --config <fichier>\n");
    process.exit(2);
  }
  let agent;
  try {
    agent = await demarrerAgent(args[1], { memeCompteAdmis: true });
  } catch (e) {
    process.stderr.write(`noortrace-inscription-agent : ${e instanceof ErreurConfiguration ? e.message : `démarrage impossible : ${e?.message ?? e}`}\n`);
    process.exit(2);
  }
  process.stdout.write(JSON.stringify({ pret: true, pid: agent.pid, prise: agent.prise }) + "\n");
  let arret = false;
  const arreter = async () => {
    if (arret) return;
    arret = true;
    await agent.arreter();
    process.exit(0);
  };
  process.on("SIGTERM", arreter);
  process.on("SIGINT", arreter);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) await principal();
