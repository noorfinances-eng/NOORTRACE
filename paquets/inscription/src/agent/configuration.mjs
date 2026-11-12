// Configuration de l'agent (INTERFACES.md 3.1) : document JSON strict,
// `version` 0, et contrôles de démarrage d'EX-7.28 et d'EX-7.3 : références
// admises pour la nature de l'instance, répertoire de la prise du compte de
// l'agent en 0750 dont le groupe n'a pour membre que le compte de
// l'interface, données du compte de l'agent en 0750, aucune prise d'écoute
// `AF_INET` ni `AF_INET6`.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { lireReference, motifRefusReference } from "../commun/references.mjs";

/** Erreur de configuration ou de démarrage (l'agent ne démarre pas). */
export class ErreurConfiguration extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurConfiguration";
  }
}

const MEMBRES = ["version", "prise", "interface_uid", "donnees", "nature", "instance", "rpc", "jeton", "comptes", "delai_s"];
const ROLES = ["deployeur", "administrateur", "tresorerie", "relayeur", "exploitant"];

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
  if (Buffer.byteLength(c.prise) > 107) throw refus("prise : chemin au-delà de 107 octets (sun_path)");
  absolu("donnees", c.donnees);
  if (!Number.isSafeInteger(c.interface_uid) || c.interface_uid < 0) throw refus("interface_uid : entier positif attendu");
  if (c.nature !== "developpement" && c.nature !== "production") throw refus("nature : developpement ou production");
  if (c.instance !== null) absolu("instance", c.instance);
  if (!Array.isArray(c.rpc) || c.rpc.length < 1 || c.rpc.length > 8 || !c.rpc.every((u) => typeof u === "string" && /^https?:\/\/[^\s/@]+(\/[^\s]*)?$/.test(u))) throw refus("rpc : de 1 à 8 adresses http(s), sans identifiant");
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
      lireReference(`comptes.${k}`, comptes[k]);
    } catch (e) {
      throw refus(e.message);
    }
  }
  const delai = c.delai_s ?? 120;
  if (!Number.isSafeInteger(delai) || delai < 1 || delai > 3600) throw refus("delai_s : entier de 1 à 3600");
  return { version: 0, prise: c.prise, interface_uid: c.interface_uid, donnees: c.donnees, nature: c.nature, instance: c.instance, rpc: [...c.rpc], jeton: c.jeton ?? null, comptes: { ...comptes }, delai_s: delai };
}

/** EX-7.3 : chaque référence de la configuration est admise pour la nature et l'identifiant EVM de l'instance. */
export function controlerReferences(config, instance) {
  for (const [role, reference] of Object.entries(config.comptes)) {
    const ref = lireReference(`comptes.${role}`, reference);
    const motif = motifRefusReference(ref, { role, nature: instance.nature, evmChainId: instance.evmChainId });
    if (motif) throw new ErreurConfiguration(`comptes.${role} : référence ${ref.forme}: refusée pour une instance de nature ${instance.nature} d'identifiant EVM ${instance.evmChainId} (EX-7.3)`);
  }
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
 * groupe de l'interface.
 */
export function controlerRepertoires(config, options = {}) {
  const uid = process.getuid();
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
