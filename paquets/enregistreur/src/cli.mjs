// Point d'entrée du démon `noortrace` (CT-2 §15.4, §15.6) :
//
//   noortrace --config <fichier>          démarre le démon
//   noortrace validate-config <fichier>   pas 1 à 3 d'EX-15.4, rapport, code 0 ou 2 (EX-15.7)
//
// Une configuration invalide n'est jamais servie : rapport sur stderr (une
// ligne par erreur : pointeur JSON, règle, valeur sauf pour un secret) et
// code de retour 2 ; le démon ne démarre pas (14.2, « Configuration invalide
// au démarrage »). SIGTERM et SIGINT arrêtent proprement (code 0) ; SIGHUP
// recharge la politique (EX-15.5).

import fs from "node:fs";
import { validerConfiguration, resoudreSecrets, ligneRapport } from "./configuration.mjs";
import { Coeur } from "./coeur.mjs";
import { ClientServiceApprobation } from "./service-approbation-http.mjs";
import { ErreurEnregistreur } from "./erreurs.mjs";
import { Redacteur, controleRedaction, controleSecretsRedaction } from "./redaction.mjs";
import { demarrerFrontalMcp } from "./mcp/demon.mjs";
import { demarrerFrontalModele } from "./modele/demon.mjs";
import { controleModele } from "./modele/formats.mjs";
import { controlePolitiqueApprobation } from "./politique/regles.mjs";

const USAGE = "usage : noortrace --config <fichier> | noortrace validate-config <fichier>";

/**
 * Règles du pas 3 d'EX-15.4 des lots branchés ici (rédaction : EX-10.6,
 * EX-10.23 ; politique d'approbation : CT-3 EX-4.2, EX-8.2, avertissements
 * d'EX-4.14 ; frontal modèle : EX-5.2, EX-5.28, EX-5.32, EX-7.3).
 */
const REGLES_SUPPLEMENTAIRES = [controleRedaction, controlePolitiqueApprobation, controleModele];

function rapporter(flux, titre, liste) {
  for (const e of liste) flux.write(`${titre} ${ligneRapport(e)}\n`);
}

/**
 * Exécute la ligne de commande.
 * @param {string[]} argv arguments après le nom du programme
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, env?: NodeJS.ProcessEnv}} [io]
 * @returns {Promise<number|{coeur: Coeur}>} code de retour, ou le cœur démarré
 */
export async function principal(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  if (argv[0] === "validate-config") {
    if (!argv[1]) {
      stderr.write(`${USAGE}\n`);
      return 2;
    }
    let octets;
    try {
      octets = fs.readFileSync(argv[1]);
    } catch {
      stderr.write(`/ : fichier de configuration illisible\n`);
      return 2;
    }
    const v = validerConfiguration(new Uint8Array(octets), { reglesSupplementaires: REGLES_SUPPLEMENTAIRES });
    rapporter(stdout, "erreur :", v.erreurs);
    rapporter(stdout, "avertissement :", v.avertissements);
    return v.erreurs.length ? 2 : 0;
  }
  const k = argv.indexOf("--config");
  if (k < 0 || !argv[k + 1]) {
    stderr.write(`${USAGE}\n`);
    return 2;
  }
  let octets;
  try {
    octets = new Uint8Array(fs.readFileSync(argv[k + 1]));
  } catch {
    stderr.write(`/ : fichier de configuration illisible\n`);
    return 2;
  }
  const v = validerConfiguration(octets, { reglesSupplementaires: REGLES_SUPPLEMENTAIRES });
  if (v.erreurs.length) {
    rapporter(stderr, "config_invalid :", v.erreurs);
    return 2;
  }
  rapporter(stderr, "avertissement :", v.avertissements);
  const s = resoudreSecrets(v.config, { env: io.env ?? process.env });
  s.erreurs.push(...controleSecretsRedaction(v.config, s.secrets));
  if (s.erreurs.length) {
    rapporter(stderr, "config_invalid :", s.erreurs);
    return 2;
  }
  const svc = v.config.policy.approval?.service;
  let service = null;
  if (svc && (svc.url || svc.socket)) {
    const jeton = s.secrets.get("/policy/approval/service/token");
    service = new ClientServiceApprobation({
      url: svc.url,
      socket: svc.socket,
      jeton: jeton ? Buffer.from(jeton).toString("utf8") : null,
      timeout_ms: v.config.policy.approval.timeout_ms,
    });
  }
  let coeur;
  let redaction;
  try {
    redaction = Redacteur.depuisConfiguration(v.config, s.secrets);
    coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, octetsConfig: octets, service, redaction, reglesSupplementaires: REGLES_SUPPLEMENTAIRES, minuteurs: true, supervision: true });
  } catch (e) {
    const raison = e instanceof ErreurEnregistreur ? e.raison : "demarrage";
    stderr.write(`demarrage_refuse : ${raison} : ${e.message}\n`);
    return 2;
  }
  // Frontal modèle (CT-2 §5) : passerelle, ICAP ou miroir selon model.mode, et registre de corrélation (5.6), offert au frontal MCP.
  let modele;
  try {
    modele = await demarrerFrontalModele(coeur, s.secrets);
  } catch (e) {
    stderr.write(`demarrage_refuse : frontal_modele : ${e.message}\n`);
    await coeur.arreter();
    // Les fils de rédaction (EX-3.6) sont fermés : le processus sort avec le code 2.
    await redaction?.fermer?.();
    return 2;
  }
  // Frontal MCP (CT-2 §4) : après le cœur, avant l'annonce du démarrage.
  let mcp = null;
  if (v.config.mcp.enabled) {
    try {
      mcp = await demarrerFrontalMcp(coeur, s.secrets, { correlateur: modele.correlateur });
    } catch (e) {
      stderr.write(`demarrage_refuse : frontal_mcp : ${e.message}\n`);
      await modele.arreter();
      await coeur.arreter();
      await redaction?.fermer?.();
      return 2;
    }
  }
  const a = coeur.serveur?.address();
  const supervision = a ? `${a.address}:${a.port}` : "-";
  stdout.write(`noortrace: demon demarre (journal ${v.config.recorder.journal_id}, epoque ${coeur.ecrivain?.epoque ?? "-"}, supervision ${supervision})\n`);
  return { coeur, mcp, modele };
}

/** Lance le démon comme processus : signaux d'arrêt et de rechargement. */
export async function lancer() {
  const r = await principal(process.argv.slice(2));
  if (typeof r === "number") {
    process.exitCode = r;
    return;
  }
  const { coeur, mcp, modele } = r;
  let arret = false;
  const arreter = async () => {
    if (arret) return;
    arret = true;
    await mcp?.arreter().catch(() => {});
    await modele?.arreter().catch(() => {});
    await coeur.arreter();
    process.exit(0);
  };
  process.on("SIGTERM", arreter);
  process.on("SIGINT", arreter);
  process.on("SIGHUP", async () => {
    const k = process.argv.indexOf("--config");
    try {
      const res = await coeur.recharger(new Uint8Array(fs.readFileSync(process.argv[k + 1])));
      process.stderr.write(res.accepte ? "noortrace: politique rechargee\n" : `noortrace: rechargement refuse (${res.raison})\n`);
    } catch (e) {
      process.stderr.write(`noortrace: rechargement refuse (${e.message})\n`);
    }
  });
}
