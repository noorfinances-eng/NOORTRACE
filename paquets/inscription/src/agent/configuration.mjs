// Configuration de l'agent (INTERFACES.md 3.1) : document JSON strict,
// `version` 0, et contrôles de démarrage d'EX-7.28 et d'EX-7.3 : références
// admises pour la nature de l'instance, répertoire de la prise du compte de
// l'agent en 0750 dont le groupe n'a pour membre que le compte de
// l'interface, données du compte de l'agent en 0750, aucune prise d'écoute
// `AF_INET` ni `AF_INET6`.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { FORMES_CONFIGURATION, lireReference, MOTIF_ALIAS, motifRefusReference } from "../commun/references.mjs";
import { pointsRefusesEnProduction } from "./reseau.mjs";
import { refusCheminPrise } from "./client.mjs";

/** Erreur de configuration ou de démarrage (l'agent ne démarre pas). */
export class ErreurConfiguration extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurConfiguration";
  }
}

const MEMBRES = ["version", "prise", "interface_uid", "donnees", "nature", "instance", "rpc", "jeton", "comptes", "cles", "delai_s"];
const ROLES = ["deployeur", "administrateur", "tresorerie", "relayeur", "exploitant"];
/** Alias de clés déclarés au plus (`cles.alias`). */
export const ALIAS_MAX = 64;

/** Lit et contrôle la forme d'une configuration ; rend la configuration normalisée. */
export function lireConfiguration(source) {
  let c;
  try {
    c = typeof source === "string" ? lireJsonStrict(fs.readFileSync(source)) : source;
  } catch (e) {
    throw new ErreurConfiguration(`configuration illisible : ${e.message}`);
  }
  const refus = (m) => new ErreurConfiguration(`configuration : ${m}`);
  if (!c || typeof c !== "object" || Array.isArray(c)) throw refus("objet attendu");
  for (const k of Object.keys(c)) if (!MEMBRES.includes(k)) throw refus(`membre inconnu ${k}`);
  if (c.version !== 0) throw refus("version 0 attendue");
  const absolu = (nom, v) => {
    if (typeof v !== "string" || !path.isAbsolute(v) || v.split("/").includes("..")) throw refus(`${nom} : chemin absolu attendu`);
    return v;
  };
  absolu("prise", c.prise);
  // complément du 2026-11-16 : 103 octets au plus (et non 107, taille de sun_path sous Linux seulement)
  const refusPrise = refusCheminPrise(c.prise);
  if (refusPrise !== null) throw refus(`prise : ${refusPrise}`);
  absolu("donnees", c.donnees);
  if (!Number.isSafeInteger(c.interface_uid) || c.interface_uid < 0) throw refus("interface_uid : entier positif attendu");
  if (c.nature !== "developpement" && c.nature !== "production") throw refus("nature : developpement ou production");
  if (c.instance !== null) absolu("instance", c.instance);
  if (!Array.isArray(c.rpc) || c.rpc.length < 1 || c.rpc.length > 8 || !c.rpc.every((u) => typeof u === "string" && /^https?:\/\/[^\s/@]+(\/[^\s]*)?$/.test(u))) throw refus("rpc : de 1 à 8 adresses http(s), sans identifiant");
  // EX-7.1 (ligne --rpc) : en production, http:// seulement vers la boucle locale ; refusé dès le démarrage, de sorte que
  // le jeton du nœud ne part jamais vers un point refusé (revue de l'étape 8).
  if (c.nature === "production") {
    const refuses = pointsRefusesEnProduction(c.rpc);
    if (refuses.length > 0) throw refus(`rpc : ${refuses[0]} : http:// n'est admis en production que vers 127.0.0.1, ::1 ou localhost (EX-7.1)`);
  }
  if (c.jeton !== null && c.jeton !== undefined) {
    let ref;
    try {
      ref = lireReference("jeton", c.jeton, { formes: ["env", "fichier"] });
    } catch (e) {
      throw refus(e.message);
    }
    void ref;
  }
  const comptes = c.comptes ?? {};
  if (typeof comptes !== "object" || Array.isArray(comptes)) throw refus("comptes : objet attendu");
  for (const k of Object.keys(comptes)) {
    if (!ROLES.includes(k)) throw refus(`comptes : rôle inconnu ${k}`);
    try {
      lireReference(`comptes.${k}`, comptes[k], { formes: FORMES_CONFIGURATION });
    } catch (e) {
      throw refus(e.message);
    }
  }
  const cles = lireCles(c.cles, refus, absolu);
  const delai = c.delai_s ?? 120;
  if (!Number.isSafeInteger(delai) || delai < 1 || delai > 3600) throw refus("delai_s : entier de 1 à 3600");
  return { version: 0, prise: c.prise, interface_uid: c.interface_uid, donnees: c.donnees, nature: c.nature, instance: c.instance, rpc: [...c.rpc], jeton: c.jeton ?? null, comptes: { ...comptes }, cles, delai_s: delai };
}

/**
 * Membre `cles` (CT-4 EX-7.25) : `{ repertoire, alias }`.
 * `repertoire` : répertoire de clés (chemin absolu) dont un travail peut
 * désigner un fichier par `fichier:` ou `graine:`, ou null (aucun fichier
 * désignable par un travail) ; `alias` : noms (`MOTIF_ALIAS`) → références
 * de la configuration (formes d'EX-7.3), qu'un travail désigne par
 * `alias:<nom>`. Absent : `{ repertoire: null, alias: {} }`.
 */
function lireCles(v, refus, absolu) {
  if (v === undefined || v === null) return { repertoire: null, alias: {} };
  if (typeof v !== "object" || Array.isArray(v)) throw refus("cles : objet { repertoire, alias } attendu");
  for (const k of Object.keys(v)) if (k !== "repertoire" && k !== "alias") throw refus(`cles : membre inconnu ${k}`);
  const repertoire = v.repertoire === undefined || v.repertoire === null ? null : absolu("cles.repertoire", v.repertoire);
  const alias = {};
  if (v.alias !== undefined && v.alias !== null) {
    if (typeof v.alias !== "object" || Array.isArray(v.alias)) throw refus("cles.alias : objet nom → référence attendu");
    const noms = Object.keys(v.alias);
    if (noms.length > ALIAS_MAX) throw refus(`cles.alias : au plus ${ALIAS_MAX} alias`);
    for (const nom of noms) {
      if (!MOTIF_ALIAS.test(nom)) throw refus("cles.alias : nom d'alias [a-z0-9][a-z0-9-]* de 1 à 64 caractères attendu");
      try {
        lireReference(`cles.alias.${nom}`, v.alias[nom], { formes: FORMES_CONFIGURATION });
      } catch (e) {
        throw refus(e.message);
      }
      alias[nom] = v.alias[nom];
    }
  }
  return { repertoire, alias };
}

/** EX-7.3 : chaque référence de la configuration (`comptes`, `cles.alias`) est admise pour la nature et l'identifiant EVM de l'instance. */
export function controlerReferences(config, instance) {
  const controler = (champ, role, reference) => {
    const ref = lireReference(champ, reference, { formes: FORMES_CONFIGURATION });
    const motif = motifRefusReference(ref, { role, nature: instance.nature, evmChainId: instance.evmChainId });
    if (motif) throw new ErreurConfiguration(`${champ} : référence ${ref.forme}: refusée pour une instance de nature ${instance.nature} d'identifiant EVM ${instance.evmChainId} (EX-7.3)`);
  };
  for (const [role, reference] of Object.entries(config.comptes)) controler(`comptes.${role}`, role, reference);
  for (const [nom, reference] of Object.entries(config.cles?.alias ?? {})) controler(`cles.alias.${nom}`, "alias", reference);
}

/**
 * EX-7.23 : l'interface et l'agent sont deux processus sous deux comptes du
 * système. L'agent refuse de démarrer si le compte que sa configuration
 * désigne pour l'interface est le sien, si ce compte est le compte 0, ou
 * s'il tourne lui-même sous le compte 0 : sous un seul compte, le serveur de
 * l'interface, exposé au navigateur, lirait tout ce que lit l'agent (jeton du
 * nœud, fichiers de clés) et écrirait ses registres sans passer par la prise
 * (revue de l'étape 8 ; révision d'EX-7.28 demandée). `uid` : compte
 * de l'agent (celui du processus par défaut).
 */
export function controlerComptes(config, { uid = process.getuid() } = {}) {
  if (uid === 0) throw new ErreurConfiguration("l'agent ne tourne pas sous le compte 0 : un compte de service propre est exigé (EX-7.23)");
  if (config.interface_uid === 0) throw new ErreurConfiguration("interface_uid : le compte 0 n'est pas admis pour l'interface (EX-7.23)");
  if (config.interface_uid === uid) throw new ErreurConfiguration(`interface_uid ${config.interface_uid} : le compte de l'interface doit différer de celui de l'agent (EX-7.23)`);
}

/** Membres d'un groupe : liste de `/etc/group` et comptes dont c'est le groupe principal (`/etc/passwd`). */
export function membresDuGroupe(gid, { group = "/etc/group", passwd = "/etc/passwd" } = {}) {
  const membres = new Set();
  for (const l of fs.readFileSync(group, "utf8").split("\n")) {
    const p = l.split(":");
    if (p.length >= 4 && Number(p[2]) === gid) for (const m of p[3].split(",").filter(Boolean)) membres.add(m);
  }
  for (const l of fs.readFileSync(passwd, "utf8").split("\n")) {
    const p = l.split(":");
    if (p.length >= 4 && Number(p[3]) === gid) membres.add(p[0]);
  }
  return membres;
}

/** Nom du compte d'un identifiant (`/etc/passwd`), ou null. */
export function nomDuCompte(uid, { passwd = "/etc/passwd" } = {}) {
  for (const l of fs.readFileSync(passwd, "utf8").split("\n")) {
    const p = l.split(":");
    if (p.length >= 3 && Number(p[2]) === uid) return p[0];
  }
  return null;
}

/**
 * EX-7.28 : le répertoire de la prise appartient au compte de l'agent, est
 * en 0750, et son groupe n'a pour membre que le compte de l'interface ; les
 * données appartiennent au compte de l'agent, en 0750. Rend le `gid` du
 * groupe de l'interface. Commence par `controlerComptes` (EX-7.23), sauf
 * `options.memeCompteAdmis` (essais de l'API programmatique seulement ;
 * jamais lu par `bin/noortrace-inscription-agent`).
 */
export function controlerRepertoires(config, options = {}) {
  const uid = process.getuid();
  if (options.memeCompteAdmis !== true) controlerComptes(config, { uid });
  const dir = path.dirname(config.prise);
  let st;
  try {
    st = fs.statSync(dir);
  } catch {
    throw new ErreurConfiguration(`répertoire de la prise ${dir} absent`);
  }
  if (!st.isDirectory()) throw new ErreurConfiguration(`${dir} n'est pas un répertoire`);
  if (st.uid !== uid) throw new ErreurConfiguration(`le répertoire de la prise n'appartient pas au compte de l'agent (EX-7.28)`);
  if ((st.mode & 0o777) !== 0o750) throw new ErreurConfiguration(`le répertoire de la prise est en ${(st.mode & 0o777).toString(8)}, 0750 attendu (EX-7.28)`);
  const interfaceNom = nomDuCompte(config.interface_uid, options);
  if (interfaceNom === null) throw new ErreurConfiguration(`interface_uid ${config.interface_uid} : aucun compte`);
  const membres = membresDuGroupe(st.gid, options);
  const autres = [...membres].filter((m) => m !== interfaceNom);
  if (autres.length > 0) throw new ErreurConfiguration(`le groupe du répertoire de la prise a d'autres membres que le compte de l'interface : ${autres.join(", ")} (EX-7.28)`);
  let sd;
  try {
    sd = fs.statSync(config.donnees);
  } catch {
    throw new ErreurConfiguration(`répertoire des données ${config.donnees} absent`);
  }
  if (!sd.isDirectory() || sd.uid !== uid || (sd.mode & 0o777) !== 0o750) throw new ErreurConfiguration("le répertoire des données doit appartenir au compte de l'agent, en 0750 (INTERFACES.md 3.6)");
  return st.gid;
}

/**
 * Prises d'écoute `AF_INET` ou `AF_INET6` du processus : inodes des
 * descripteurs `socket:[n]` de `/proc/self/fd` retrouvés, à l'état d'écoute
 * (TCP `0A`) ou liés (UDP), dans `/proc/self/net/{tcp,tcp6,udp,udp6}`.
 */
export function prisesIp() {
  const inodes = new Set();
  for (const fd of fs.readdirSync("/proc/self/fd")) {
    try {
      const m = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/self/fd/${fd}`));
      if (m) inodes.add(m[1]);
    } catch {
      // descripteur fermé entre la lecture et le lien
    }
  }
  const trouvees = [];
  for (const table of ["tcp", "tcp6", "udp", "udp6"]) {
    let texte;
    try {
      texte = fs.readFileSync(`/proc/self/net/${table}`, "utf8");
    } catch {
      continue;
    }
    for (const l of texte.split("\n").slice(1)) {
      const p = l.trim().split(/\s+/);
      if (p.length < 10) continue;
      const etat = p[3];
      const inode = p[9];
      if (inodes.has(inode) && (table.startsWith("udp") || etat === "0A")) trouvees.push({ table, inode });
    }
  }
  return trouvees;
}
