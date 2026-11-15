// Scénarios des tests adversariaux TA-29 et TA-75 de CT-9 joués sur le démon
// réel et sur `noortrace-ctl` (référence ou mutant du paquet
// @noortrace/enregistreur, CT-9 EX-10.5), contre un S3 à Object Lock
// (LocalStack en conteneur, image épinglée de
// test/fixtures/enregistreur-worm/outils.mjs) :
//
//   TA-29 (MN-29)  support WORM fermé, segment fermé : le fil de supervision
//                  du démon met à jour `noortrace_worm_copy_pending` ; support
//                  rouvert : la jauge revient à 0 ;
//   TA-75 (MN-75)  gel posé, une version passée à `off` hors de l'outil : la
//                  relecture du rôle Lecteur hors du démon (`sonde.mjs releve`,
//                  `noortrace-ctl worm gel etat`) met
//                  `noortrace_releve_externe_ok{check="registre_gels"}` à 0.
//
// Les règles d'alerte de CT-8 §10 sont jugées ici par l'évaluateur réduit des
// essais (`etatsAlerte`). Un collecteur en marche se branche sur les mêmes
// scénarios : `demonSupportFerme` rend le port de `/metrics` du démon laissé
// en marche, `gelSurveille` rend le fichier d'exposition écrit par la relecture.

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import http from "node:http";
import { spawn } from "node:child_process";
import yaml from "js-yaml";
import * as N from "@noortrace/noyau";
import { Coeur, validerConfiguration, resoudreSecrets, supportWormDepuisConfiguration, principalCtl, OperationsS3, identifiantsS3, controleWorm } from "@noortrace/enregistreur";
import { analyser, evaluer } from "../supervision/promql.mjs";
import { RACINE, configurationDev } from "../enregistreur-coeur/outils.mjs";
import { IMAGES, dockerDisponible, demarrerS3, arreterConteneur, certificats, creerBucketVerrouille, identifiantsRole, fichierSecret } from "../enregistreur-worm/outils.mjs";
import { demarrer, arreter, appelerOutil, attendre } from "./demon.mjs";

export const SONDE = path.join(RACINE, "scripts", "deploiement", "sonde.mjs");
export const REGLES = yaml.load(fs.readFileSync(path.join(RACINE, "deploiement", "observabilite", "regles-noortrace.yml"), "utf8")).groups.flatMap((g) => g.rules);
const DELAIS_RAPIDES = [20, 20, 20];

/** Docker et l'image du S3 à Object Lock sont-ils là ? `{ ok, condition }`. */
export function supportDisponible() {
  return dockerDisponible([IMAGES.s3]);
}

/**
 * État d'une règle d'alerte du fichier de référence à des instants donnés,
 * sur des séries échantillonnées chaque minute (évaluateur réduit des essais ;
 * la clause `for` est tenue comme le collecteur la tient).
 * @param {string} nomRegle
 * @param {object[]} regles règles chargées (un attaquant qui coupe les règles du démon en retire)
 * @param {{et: object, ech: {t: number, v: number}[]}[]} series
 * @param {number[]} instants millisecondes
 * @returns {boolean[]}
 */
export function etatsAlerte(nomRegle, regles, series, instants) {
  const r = regles.find((x) => x.alert === nomRegle);
  if (!r) return instants.map(() => false);
  const arbre = analyser(r.expr);
  const m = r.for ? /^([0-9]+)([smh])$/.exec(r.for) : null;
  const pour = m ? Number(m[1]) * { s: 1000, m: 60000, h: 3600000 }[m[2]] : 0;
  const etats = new Map();
  let depuis = null;
  for (let t = 0; t <= Math.max(...instants); t += 60000) {
    if (evaluer(arbre, series, t).length) depuis ??= t;
    else depuis = null;
    if (instants.includes(t)) etats.set(t, depuis !== null && t - depuis >= pour);
  }
  return instants.map((t) => etats.get(t));
}

/** Série d'une jauge tenue à `valeurs[k]` pendant `minutes[k]` minutes ; `null` : aucun échantillon. */
export function serieTenue(etiquettes, valeurs, minutes) {
  const ech = [];
  let t = 0;
  valeurs.forEach((v, k) => {
    for (let j = 0; j < minutes[k]; j++, t += 60000) if (v !== null) ech.push({ t, v });
  });
  return ech.length ? [{ et: etiquettes, ech }] : [];
}

/**
 * Terminaison TLS vers le S3, que l'essai ferme (point de terminaison fermé :
 * connexion refusée) et rouvre sur le même port.
 */
async function supportCommutable(c, cible) {
  const sockets = new Set();
  let serveur = null;
  let port = 0;
  const ouvrir = () => new Promise((res, rej) => {
    const s = tls.createServer({ cert: fs.readFileSync(c.cert), key: fs.readFileSync(c.key) }, (x) => {
      const d = net.connect(cible.port, "127.0.0.1");
      sockets.add(x);
      sockets.add(d);
      x.pipe(d).pipe(x);
      const fin = () => {
        x.destroy();
        d.destroy();
      };
      x.on("error", fin);
      d.on("error", fin);
      x.on("close", () => sockets.delete(x));
      d.on("close", () => sockets.delete(d));
    });
    s.once("error", rej);
    s.listen(port, "127.0.0.1", () => {
      serveur = s;
      port = s.address().port;
      res();
    });
  });
  const fermer = () => new Promise((r) => {
    if (!serveur) return r();
    for (const s of sockets) s.destroy();
    const s = serveur;
    serveur = null;
    s.close(() => r());
  });
  await ouvrir();
  return {
    get port() {
      return port;
    },
    get origine() {
      return `https://127.0.0.1:${port}`;
    },
    get ouvert() {
      return serveur !== null;
    },
    fermer,
    /** Rouvre sur le même port (quelques essais si le port vient d'être repris). */
    async rouvrir() {
      if (serveur) return;
      for (let essai = 1; ; essai++) {
        try {
          await ouvrir();
          return;
        } catch (e) {
          if (e?.code !== "EADDRINUSE" || essai >= 20) throw e;
          await new Promise((r) => setTimeout(r, 250));
        }
      }
    },
  };
}

/**
 * Décor commun : S3 à Object Lock en conteneur, autorité TLS d'essai,
 * terminaison TLS commutable. `fermer()` arrête le conteneur.
 * @param {string} dir répertoire de travail (créé par l'appelant)
 * @param {string} nom nom du conteneur
 */
export async function monterSupport(dir, nom) {
  const s3 = await demarrerS3(nom);
  const c = certificats(path.join(dir, "tls"));
  const ca = path.join(dir, "ca.pem");
  fs.writeFileSync(ca, c.caPem);
  const support = await supportCommutable(c, { port: s3.port });
  let n = 0;
  return {
    dir,
    s3,
    tls: c,
    ca,
    support,
    /** Bucket neuf à Object Lock, mode COMPLIANCE, rétention par défaut de 4018 jours ; rend le membre `storage.seal.worm`. */
    async worm(etiquette) {
      const bucket = `noortrace-adv-${process.pid}-${etiquette}-${++n}`;
      await creerBucketVerrouille(support.origine, bucket, { ca: c.caPem, jours: 4018, mode: "COMPLIANCE" });
      return { type: "s3-object-lock", bucket, prefix: "journal-adv/", mode: "compliance", retain_days: 4018, endpoint: support.origine, region: null, legal_hold_on_write: false, lock_audit_interval_days: 30, copy_pieces: false };
    },
    async fermer() {
      await support.fermer();
      arreterConteneur(nom);
    },
  };
}

/** Texte de `GET /metrics` d'un démon, ou null. */
export function metriques(port) {
  return new Promise((res) => {
    const r = http.get({ host: "127.0.0.1", port, path: "/metrics" }, (x) => {
      const m = [];
      x.on("data", (k) => m.push(k));
      x.on("end", () => res(x.statusCode === 200 ? Buffer.concat(m).toString("utf8") : null));
    });
    r.on("error", () => res(null));
  });
}

/** Valeur d'une série sans étiquette (ou de la série exacte donnée) dans une exposition ; null si elle n'y est pas. */
export function valeurExposee(texte, serie) {
  if (typeof texte !== "string") return null;
  const m = new RegExp(`^${serie.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} ([0-9.eE+-]+)$`, "m").exec(texte);
  return m ? Number(m[1]) : null;
}

// ---------------------------------------------------------------------------
// TA-29 : support fermé, segment fermé, démon réel
// ---------------------------------------------------------------------------

/** `modifier(config, env)` d'une configuration de démon : copies WORM vers `worm`, autorité TLS d'essai admise. */
export function avecWorm(decor, worm, dir) {
  return (config, env) => {
    config.storage.seal.worm = { ...worm, credentials: { file: fichierSecret(path.join(dir, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) } };
    env.NODE_EXTRA_CA_CERTS = decor.ca;
  };
}

/**
 * Démon réel d'un paquet (référence ou mutant), support WORM fermé, un
 * segment fermé sans copie, et le premier tour du fil de supervision passé
 * depuis le dernier démarrage (preuve : la ligne `integrity_check` du contrôle
 * quotidien `configuration_worm`, qui suit le contrôle horaire dans le même
 * tour). Le démon est laissé en marche : `/metrics` est servi sur
 * `c.portSante`.
 * @param {object} paquet `{ bin(nom) }`
 * @param {object} c configuration de `configurationDemon` passée par `avecWorm`, `segment_max_bytes` petit
 * @param {object} decor décor de `monterSupport`
 * @returns {Promise<{demon: object, c: object, segmentsFermes: number, enAttente: () => Promise<number|null>, rouvrir: () => Promise<void>, arreter: () => Promise<void>}>}
 */
export async function demonSupportFerme(paquet, c, decor) {
  const fichier = path.join(c.dir, "configuration.json");
  await decor.support.fermer();
  let p = await demarrer(paquet, c, fichier);
  const segments = () => fs.readdirSync(path.join(c.journal, "segments")).filter((f) => /^seg-[0-9]{16}-[0-9]{20}\.ndjson$/.test(f));
  try {
    for (let k = 0; segments().length < 2; k++) {
      if (k >= 80) throw new Error("aucun segment fermé après 80 appels");
      const r = await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__lire", { id: `S-ta29-${k}` });
      if (r.statut !== 200) throw new Error(`appel d'outil refusé (${r.statut})`);
    }
  } finally {
    await arreter(p);
  }
  const segmentsFermes = segments().length - 1;
  const avant = fs.existsSync(c.config.supervision.ops_log.path) ? fs.readFileSync(c.config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).length : 0;
  p = await demarrer(paquet, c, fichier);
  const depuis = () => p.lignes().slice(avant);
  try {
    await attendre(() => depuis().some((l) => l.event === "integrity_check" && l.data?.check === "configuration_worm"), 120000, 200);
  } catch (e) {
    await arreter(p);
    throw e;
  }
  return {
    demon: p,
    c,
    segmentsFermes,
    lignes: depuis,
    enAttente: async () => valeurExposee(await metriques(c.portSante), "noortrace_worm_copy_pending"),
    rouvrir: () => decor.support.rouvrir(),
    arreter: () => arreter(p),
  };
}

// ---------------------------------------------------------------------------
// TA-75 : gel posé, version passée à off, relecture du Lecteur hors du démon
// ---------------------------------------------------------------------------

/**
 * Journal à une période close copiée sur le support, gel posé sur cette
 * période par l'outil de référence. Rend de quoi relire le gel sous les
 * identifiants du Lecteur avec le `noortrace-ctl` d'un paquet donné, et de
 * quoi passer une version à `off` hors de l'outil, comme l'administrateur
 * du client de MN-75.
 * @param {object} decor décor de `monterSupport`
 * @param {string} dir répertoire neuf
 */
export async function gelSurveille(decor, dir) {
  await decor.support.rouvrir();
  const worm = await decor.worm("gel");
  const { config, env } = configurationDev(dir, { journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-adversarial-gel-${process.pid}-${worm.bucket}`))) });
  config.storage.seal.worm = { ...worm, credentials: { file: fichierSecret(path.join(dir, "secrets", "worm-ecrivain"), identifiantsRole("ecrivain")) } };
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleWorm] });
  if (v.erreurs.length) throw new Error(`configuration de l'essai invalide : ${JSON.stringify(v.erreurs)}`);
  const s = resoudreSecrets(v.config, { env });
  if (s.erreurs.length) throw new Error(`secrets de l'essai : ${JSON.stringify(s.erreurs)}`);
  const fichier = path.join(dir, "configuration.json");
  fs.writeFileSync(fichier, JSON.stringify(config));
  const ref = (role) => JSON.stringify({ file: fichierSecret(path.join(dir, "secrets", role), identifiantsRole(role)) });
  const horloge = (decalage) => ({ murale: () => Date.now() + decalage, monotone: () => performance.now() + 1e7 + decalage });
  const coeur = async (decalage) => {
    const support = supportWormDepuisConfiguration(v.config, s.secrets, { tls: { ca: decor.tls.caPem }, delais: DELAIS_RAPIDES });
    return { c: await Coeur.demarrer({ config: v.config, secrets: s.secrets, worm: support, horloge: horloge(decalage) }), worm: support };
  };
  // Une période close et copiée : un démarrage, puis un second une heure plus tard.
  const a = await coeur(0);
  const P = Math.floor(a.c.horlogeBrute.murale() / 3600000) * 3600;
  await a.c.arreter();
  const b = await coeur(3600000 - (Date.now() % 3600000) + 2000);
  await b.c.tic();
  await b.worm.vider();
  await b.c.arreter();
  const sortie = [];
  const io = { stdout: { write: (t) => sortie.push(t) }, stderr: { write: () => {} }, env, tls: { ca: decor.tls.caPem }, delais: DELAIS_RAPIDES };
  const code = await principalCtl(["worm", "gel", "poser", "--configuration", fichier, "--identifiants", ref("gardien-pose"), "--identite", "j.dupont", "--de", String(P), "--a", String(P), "--motif", "litige"], io);
  if (code !== 0) throw new Error(`pose du gel : code ${code}`);
  const gel = sortie.join("").trim();
  const ops = new OperationsS3({ worm: v.config.storage.seal.worm, identifiants: identifiantsS3(new TextEncoder().encode(identifiantsRole("administrateur"))), tls: { ca: decor.tls.caPem }, delais: DELAIS_RAPIDES });
  const pose = JSON.parse((await ops.lire(`${worm.prefix}gels/${gel}/0001-pose.json`)).corps.toString("utf8"));
  const objet = JSON.parse((await ops.lire(pose.objects.key)).corps.toString("utf8").split("\n")[0]);
  const envEnfant = { ...process.env, ...env, NODE_EXTRA_CA_CERTS: decor.ca };
  const lancer = (programme, args) => new Promise((resolve) => {
    const x = spawn(process.execPath, [programme, ...args], { cwd: RACINE, env: envEnfant });
    const out = [];
    const err = [];
    x.stdout.on("data", (d) => out.push(d));
    x.stderr.on("data", (d) => err.push(d));
    x.on("close", (status) => resolve({ status, stdout: Buffer.concat(out).toString("utf8"), stderr: Buffer.concat(err).toString("utf8") }));
  });
  const argsEtat = ["worm", "gel", "etat", "--configuration", fichier, "--identifiants", ref("lecteur"), "--gel", gel];
  return {
    gel,
    objet,
    fichier,
    /** Passe la version du gel à `off` hors de l'outil, sous les identifiants de l'administrateur. */
    passerOff: async () => (await ops.poserGel(objet.key, objet.version_id, false)).statut,
    /** `noortrace-ctl worm gel etat` du paquet donné, sous les identifiants du Lecteur : `{ status, stdout, stderr }`. */
    etat: (paquet) => lancer(paquet.bin("noortrace-ctl"), argsEtat),
    /**
     * Relecture du Lecteur hors du démon (CT-8 §11.12, EX-10.9) : `sonde.mjs releve --check registre_gels`
     * autour du `noortrace-ctl` du paquet donné ; rend le fichier d'exposition écrit et la jauge lue.
     */
    async relire(paquet, nom) {
      const exposition = path.join(dir, `releve-${nom}.prom`);
      const r = await lancer(SONDE, ["releve", "--check", "registre_gels", "--sortie", exposition, "--", process.execPath, paquet.bin("noortrace-ctl"), ...argsEtat]);
      const texte = fs.existsSync(exposition) ? fs.readFileSync(exposition, "utf8") : null;
      return { ...r, exposition, jauge: valeurExposee(texte, 'noortrace_releve_externe_ok{check="registre_gels"}') };
    },
  };
}
