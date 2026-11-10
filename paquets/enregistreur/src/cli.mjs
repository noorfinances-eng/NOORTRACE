// Point d'entrée du démon `noortrace` (CT-2 §15.4, §15.6) :
//
//   noortrace --config <fichier>          démarre le démon
//   noortrace validate-config <fichier>   pas 1 à 3 d'EX-15.4, rapport, code 0 ou 2 (EX-15.7)
//
// Une configuration invalide n'est jamais servie : rapport sur stderr (une
// ligne par erreur : pointeur JSON, règle, valeur sauf pour un secret) et
// code de retour 2 ; le démon ne démarre pas (14.2, « Configuration invalide
// au démarrage »). SIGTERM et SIGINT arrêtent proprement (code 0) ; SIGHUP
// recharge la politique (EX-15.5) et le document `ancrage-v0` (CT-5 EX-4.9) ;
// SIGUSR2 porte la confirmation de l'exploitant après un saut d'horloge
// (EX-7.13) ; SIGURG, avec la demande écrite à côté du journal
// d'exploitation, porte `noortrace-ctl cle rotation-urgence` et
// `noortrace-ctl ancrage <etat|metriques|retirer-qualification>` :
// `noortrace-ctl` les envoie (src/ctl-demon.mjs). Avec `anchoring.ancrage`,
// le composant d'ancrage de CT-5 est branché avant le cœur
// (src/ancrage-demon.mjs, lot F2) : une configuration d'ancrage invalide
// n'empêche pas le démon de démarrer (CT-5 EX-4.8) ; une clé de chaîne d'une
// classe non servie (A à C) le refuse (`demarrage_refuse : ancrage`).

import fs from "node:fs";
import { validerConfiguration, resoudreSecrets, ligneRapport } from "./configuration.mjs";
import { lireSecretsVault } from "./secrets-vault.mjs";
import { fichierDemandeRotation } from "./ctl-demon.mjs";
import { Coeur } from "./coeur.mjs";
import { ClientServiceApprobation } from "./service-approbation-http.mjs";
import { ErreurEnregistreur } from "./erreurs.mjs";
import { Redacteur, controleRedaction, controleSecretsRedaction } from "./redaction.mjs";
import { demarrerFrontalMcp } from "./mcp/demon.mjs";
import { demarrerFrontalModele } from "./modele/demon.mjs";
import { controleModele } from "./modele/formats.mjs";
import { controlePolitiqueApprobation } from "./politique/regles.mjs";
import { RegistreCorrelation } from "./modele/correlation.mjs";
import { origineAnnoncee } from "./modele/demon.mjs";
import { demarrerSdk } from "./sdk/demon.mjs";
import { controleSdk } from "./sdk/configuration.mjs";
import { controleConnecteurTcp } from "./mcp/prise-tcp.mjs";
import { demarrerOtel } from "./otel/demon.mjs";
import { controleOtel } from "./otel/configuration.mjs";
import { controleWorm, supportWormDepuisConfiguration } from "./worm/configuration.mjs";
import { preparerAncrage, ErreurBranchementAncrage } from "./ancrage-demon.mjs";

const USAGE = "usage : noortrace --config <fichier> | noortrace validate-config <fichier>";

/**
 * Règles du pas 3 d'EX-15.4 des lots branchés ici (rédaction : EX-10.6,
 * EX-10.23 ; politique d'approbation : CT-3 EX-4.2, EX-8.2, avertissements
 * d'EX-4.14 ; frontal modèle : EX-5.2, EX-5.28, EX-5.32, EX-7.3 ; prise
 * TCP des connecteurs : EX-4.39, lecture 134).
 */
const REGLES_SUPPLEMENTAIRES = [controleRedaction, controlePolitiqueApprobation, controleModele, controleSdk, controleConnecteurTcp, controleOtel, controleWorm];

function rapporter(flux, titre, liste) {
  for (const e of liste) flux.write(`${titre} ${ligneRapport(e)}\n`);
}

/**
 * Exécute la ligne de commande.
 * @param {string[]} argv arguments après le nom du programme
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, env?: NodeJS.ProcessEnv,
 *   horloge?: {murale: () => number, monotone: () => number, programmer?: Function}}} [io]
 *   `horloge` : horloge injectée (essais du démon réel à l'horloge réglable, CT-2 §7.4 ; `programmer` pour le composant d'ancrage)
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
  // Références { vault } (15.2) : lues avant la résolution des autres (pas 4).
  const lus = await lireSecretsVault(v.config, { env: io.env ?? process.env });
  const s = resoudreSecrets(v.config, { env: io.env ?? process.env, vault: lus.valeurs });
  if (lus.erreurs.length) s.erreurs = [...lus.erreurs, ...s.erreurs.filter((e) => !lus.erreurs.some((x) => x.pointeur === e.pointeur))];
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
      // EX-18.8 : identifiant d'utilisateur attendu du pair sur la prise Unix.
      peer_user: svc.peer_user ?? null,
    });
  }
  // Composant d'ancrage de CT-5 (`anchoring.ancrage`, lot F2) : document `ancrage-v0` lu, ses secrets résolus (pas 4), clé de
  // chaîne et manifeste d'instance ; `null` quand `anchoring.ancrage` est `null` ou absent (comportement inchangé).
  let ancrage = null;
  try {
    ancrage = await preparerAncrage({ config: v.config, secrets: s.secrets, env: io.env ?? process.env, horloge: io.horloge ?? null });
  } catch (e) {
    if (!(e instanceof ErreurBranchementAncrage)) throw e;
    stderr.write(`demarrage_refuse : ancrage : ${e.raison} : ${e.message}\n`);
    return 2;
  }
  let coeur;
  let redaction;
  try {
    redaction = Redacteur.depuisConfiguration(v.config, s.secrets);
    // Copies WORM (§12.6, lot WORM) ; bail détenu par une autre instance : instance
    // passive (13.4), les frontaux s'ouvrent et rendent -31010 bail_non_detenu.
    const worm = supportWormDepuisConfiguration(v.config, s.secrets);
    coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, octetsConfig: octets, service, redaction, worm, ancrage, horloge: io.horloge ?? undefined, env: io.env ?? process.env, attendreBail: true, reglesSupplementaires: REGLES_SUPPLEMENTAIRES, minuteurs: true, supervision: true });
  } catch (e) {
    const raison = e instanceof ErreurEnregistreur ? e.raison : "demarrage";
    stderr.write(`demarrage_refuse : ${raison} : ${e.message}\n`);
    // Les fils de rédaction (EX-3.6) sont fermés : sans eux ouverts, le
    // processus sort avec le code 2 (une adresse d'écoute prise, EADDRINUSE,
    // laissait le démon vivant après le refus).
    await redaction?.fermer?.().catch?.(() => {});
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
  // Registre de corrélation (5.6) : celui du frontal modèle ; sans frontal modèle, un registre
  // propre aux échanges déclarés par le SDK (EX-5.22, EX-6.8), offert aussi au frontal MCP.
  const correlateur =
    modele.correlateur ??
    (v.config.sdk?.enabled
      ? new RegistreCorrelation({
          fenetreMs: v.config.model.correlation_window_ms,
          monotone: () => coeur.horlogeBrute.monotone(),
          ecrirePiece: (p) => coeur.ecrirePiece(p),
          origine: (nom) => origineAnnoncee(coeur.config, nom),
          journal: coeur.journal,
        })
      : null);
  // Frontal MCP (CT-2 §4) : après le cœur, avant l'annonce du démarrage.
  let mcp = null;
  if (v.config.mcp.enabled) {
    try {
      mcp = await demarrerFrontalMcp(coeur, s.secrets, { correlateur });
    } catch (e) {
      stderr.write(`demarrage_refuse : frontal_mcp : ${e.message}\n`);
      await modele.arreter();
      await coeur.arreter();
      await redaction?.fermer?.();
      return 2;
    }
  }
  // Point d'entrée SDK (CT-2 §6.1 à §6.3) et ingestion OpenTelemetry (§6.8).
  let sdk = null;
  let otel = null;
  try {
    sdk = await demarrerSdk(coeur, s.secrets, { correlateur });
    otel = await demarrerOtel(coeur, s.secrets);
  } catch (e) {
    stderr.write(`demarrage_refuse : ${sdk ? "otel" : "sdk"} : ${e.message}\n`);
    await sdk?.arreter();
    await mcp?.arreter();
    await modele.arreter();
    await coeur.arreter();
    await redaction?.fermer?.();
    return 2;
  }
  const a = coeur.serveur?.address();
  const supervision = a ? `${a.address}:${a.port}` : "-";
  stdout.write(`noortrace: demon demarre (journal ${v.config.recorder.journal_id}, epoque ${coeur.ecrivain?.epoque ?? "-"}, supervision ${supervision})\n`);
  // Instance passive (13.4) : la fin du démarrage suit la prise du bail.
  coeur.demarrage?.then(
    () => stdout.write(`noortrace: bail acquis (epoque ${coeur.ecrivain?.epoque ?? "-"})\n`),
    () => {},
  );
  return { coeur, mcp, modele, sdk, otel };
}

/** Lance le démon comme processus : signaux d'arrêt et de rechargement. */
export async function lancer() {
  const r = await principal(process.argv.slice(2));
  if (typeof r === "number") {
    process.exitCode = r;
    return;
  }
  superviserProcessus(r, { argv: process.argv, relancer: lancer });
}

/**
 * Installe les signaux du processus du démon sur un démarrage réussi
 * (SIGTERM, SIGINT, SIGHUP, SIGUSR2, SIGURG, veille du bail) ; partagé entre
 * `lancer` et les essais qui démarrent le démon réel avec une horloge
 * injectée (`principal(argv, { horloge })`, lot F2).
 * @param {{coeur: Coeur, mcp: object|null, modele: object|null, sdk: object|null, otel: object|null}} r
 * @param {{argv?: string[], relancer?: () => void, env?: NodeJS.ProcessEnv}} [o] `argv` : ligne de commande portant `--config`
 */
export function superviserProcessus(r, o = {}) {
  const { coeur, mcp, modele, sdk, otel } = r;
  const argvDemon = o.argv ?? process.argv;
  let arret = false;
  const arreter = async () => {
    if (arret) return;
    arret = true;
    await otel?.arreter().catch(() => {});
    await sdk?.arreter().catch(() => {});
    await mcp?.arreter().catch(() => {});
    await modele?.arreter().catch(() => {});
    await coeur.arreter();
    process.exit(0);
  };
  process.on("SIGTERM", arreter);
  process.on("SIGINT", arreter);
  // Instance passive : un échec de la fin du démarrage (après la prise du
  // bail) refuse le démarrage comme avant elle (code 2).
  coeur.demarrage?.catch(async (e) => {
    process.stderr.write(`demarrage_refuse : ${e instanceof ErreurEnregistreur ? e.raison : "demarrage"} : ${e.message}\n`);
    arret = true;
    await otel?.arreter().catch(() => {});
    await sdk?.arreter().catch(() => {});
    await mcp?.arreter().catch(() => {});
    await modele?.arreter().catch(() => {});
    process.exit(2);
  });
  // Bail perdu (EX-13.6) : l'instance reste en mode dégradé « bail » ; elle ne
  // reprend qu'après une nouvelle acquisition, donc après relecture du journal
  // (EX-12.10) : le démon est relancé dans ce processus et redevient passif
  // tant qu'une autre instance détient le bail (13.4 pas 8).
  const veille = setInterval(async () => {
    if (arret || !coeur.degrade.actif("bail")) return;
    clearInterval(veille);
    arret = true;
    process.stderr.write("noortrace: bail perdu, relance en instance passive\n");
    await otel?.arreter().catch(() => {});
    await sdk?.arreter().catch(() => {});
    await mcp?.arreter().catch(() => {});
    await modele?.arreter().catch(() => {});
    await coeur.arreter().catch(() => {});
    await coeur.o.redaction?.fermer?.().catch?.(() => {});
    for (const s of ["SIGTERM", "SIGINT", "SIGHUP", "SIGUSR2", "SIGURG"]) process.removeAllListeners(s);
    (o.relancer ?? lancer)();
  }, 250);
  veille.unref?.();
  // `noortrace-ctl clock --accept` (EX-7.13) : confirmation de l'exploitant, consignée par le cœur.
  process.on("SIGUSR2", () => {
    const r = coeur.accepterHorloge();
    process.stderr.write(r.accepte ? "noortrace: horloge acceptee\n" : `noortrace: acceptation de l'horloge refusee (${r.raison})\n`);
  });
  // `noortrace-ctl cle rotation-urgence` (CT-8 EX-10.14, CT-2 EX-11.16) : SIGURG
  // n'agit qu'avec la demande écrite par noortrace-ctl à côté du journal d'exploitation.
  // `noortrace-ctl ancrage <etat|metriques|retirer-qualification> [id]` partage le signal et le fichier de demande :
  // la demande dit ce qu'elle porte (`demande: "rotation-urgence"` ou `"ancrage"`).
  process.on("SIGURG", async () => {
    const f = fichierDemandeRotation(coeur.config.supervision.ops_log.path);
    let demande = null;
    try {
      demande = JSON.parse(fs.readFileSync(f, "utf8"));
      fs.rmSync(f);
    } catch {
      coeur.journal.consigner("warning", "signataire", "key_rotation_emergency_ignored", { raison: "sans_demande" });
      return;
    }
    if (demande?.demande === "ancrage") {
      await coeur.commandeAncrage({ commande: demande.commande, id: demande.id ?? null }).catch((e) => coeur.journal.consigner("warning", "ancrage", "anchoring_ctl_refused", { command: String(demande.commande ?? "").slice(0, 64), raison: "erreur", erreur: String(e?.message ?? e).slice(0, 200) }));
      return;
    }
    await coeur.rotationUrgence().catch((e) => coeur.journal.consigner("error", "signataire", "key_rotation_emergency_refused", { raison: "erreur", erreur: String(e?.message ?? e) }));
  });
  process.on("SIGHUP", async () => {
    const k = argvDemon.indexOf("--config");
    try {
      const res = await coeur.recharger(new Uint8Array(fs.readFileSync(argvDemon[k + 1])), { env: o.env });
      process.stderr.write(res.accepte ? "noortrace: politique rechargee\n" : `noortrace: rechargement refuse (${res.raison})\n`);
    } catch (e) {
      process.stderr.write(`noortrace: rechargement refuse (${e.message})\n`);
    }
  });
}
