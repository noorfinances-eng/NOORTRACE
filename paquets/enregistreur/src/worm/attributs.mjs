// Compagnon des attributs `a` et `i` (CT-2 EX-12.18 ; CT-8 EX-3.9, §3.4, CO-4,
// CO-6) : programme `noortrace-attributs`, distinct du démon, seul admis sous
// le compte 0 avec les capacités `LINUX_IMMUTABLE`, `FOWNER` et
// `DAC_READ_SEARCH`, sans réseau. Quand `storage.seal.append_only_attribute`
// est vrai, il pose, toutes les `--intervalle-s` secondes (60 au plus) :
//   - `a` (ajout seul) sur le segment courant et le journal d'intention de
//     chaque journal sous `--racine` (`storage.root`) ;
//   - `i` (immuable) sur chaque segment fermé et chaque manifeste (et sa
//     signature), après avoir retiré `a` d'un segment qui vient d'être fermé.
// L'attribut « will not affect the ability to write to already existing file
// descriptors » (chattr(1)) : le démon continue d'écrire par le descripteur
// qu'il a ouvert. Le démon n'a jamais `CAP_LINUX_IMMUTABLE` (CT-2 EX-18.4) et
// ne peut ni poser ni retirer ces attributs.
//
// Le compagnon ne lit pas la configuration (CT-8 : `--racine` et
// `--intervalle-s` seulement) : il déduit l'état des noms de fichiers de 12.1
// (segment courant : le dernier dans l'ordre des noms, EX-12.1 ; journal
// d'intention : celui de la plus grande époque). Jeton de clôture au
// scellement (CT-2 EX-13.5 (2)) : un segment fermé d'époque inférieure à
// celle du dernier segment scellé (`i`) n'est pas scellé. Les attributs sont
// posés et lus par `chattr` et `lsattr` (e2fsprogs), Node.js n'offrant pas
// l'ioctl `FS_IOC_SETFLAGS` sans module natif. L'état du dernier passage est
// écrit sous `TMPDIR` pour la sonde (`noortrace-attributs sonde`).
//
// Panne bruyante (étape 7) : un répertoire qui ne peut pas être lu
// (sans `DAC_READ_SEARCH`, le compte 0 ne parcourt pas `storage.root`, 0700
// du compte 10001), ou des attributs qui ne peuvent pas être lus, sont des
// erreurs du passage (`attribute_unreadable`) : la sonde dit malade et
// `--une-fois` rend 1. Une racine illisible ou absente arrête le compagnon en
// service (code 1, `attribute_root_unreadable`) : il ne verrait aucun
// journal. Seul un sous-répertoire absent (`ENOENT`, pas encore créé par le
// démon) est vide sans erreur.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Mémoire des fichiers scellés (étape 8, CT-2 EX-12.18) : pour chaque
 * nom scellé (`i` posé ou lu), le périphérique, l'inode et le SHA-256 du
 * fichier au moment du scellement, gardés hors de `storage.root` (en mémoire
 * du compagnon et dans le fichier d'état sous `TMPDIR`). Le compte du démon
 * possède le répertoire du journal : il peut renommer `segments/` et remettre
 * un fichier de même nom ; l'attribut ne l'en empêche pas. Le passage suivant
 * voit qu'un nom scellé n'a plus l'inode enregistré, ou a disparu, et le
 * consigne en erreur (`attribute_sealed_replaced`, `attribute_sealed_missing`),
 * ce qui rend la sonde malade et `--une-fois` à 1. Le fichier de remplacement
 * est scellé lui aussi (il garde la trace de la réécriture).
 * @typedef {Map<string, {dev: number, ino: number, sha256: string}>} Scelles clé : chemin relatif à la racine
 */

const sha256Fichier = (chemin) => {
  try {
    return `0x${createHash("sha256").update(fs.readFileSync(chemin)).digest("hex")}`;
  } catch {
    return null;
  }
};
const SEGMENT = /^seg-([0-9]{16})-([0-9]{20})\.ndjson$/;
const INTENTION = /^intentions-([0-9]{20})\.ndjson$/;
const MANIFESTE = /^periode-[0-9]{10}\.(json|sig)$/;

/** Attributs d'un fichier (drapeaux de `lsattr`), ou null. */
export function lireAttributs(chemin) {
  try {
    const s = execFileSync("lsattr", ["-d", chemin], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return s.trim().split(/\s+/)[0];
  } catch {
    return null;
  }
}

function chattr(modes, chemin) {
  execFileSync("chattr", [...modes, chemin], { stdio: ["ignore", "pipe", "pipe"] });
}


/**
 * Un passage sur tous les journaux d'une racine.
 * @param {string} racine `storage.root`
 * @param {{consigner?: (niveau: string, evenement: string, data: object) => void, scelles?: Scelles}} [o]
 *   `scelles` : mémoire des fichiers scellés, tenue à jour par le passage (CT-2 EX-12.18)
 * @returns {{poses: {fichier: string, attribut: string}[], refus: {fichier: string, raison: string}[], erreurs: {fichier: string, message: string}[], remplaces: {fichier: string, raison: string}[], racineIllisible: boolean}}
 */
export function passageAttributs(racine, o = {}) {
  const consigner = o.consigner ?? (() => {});
  const scelles = o.scelles ?? new Map();
  const r = { poses: [], refus: [], erreurs: [], remplaces: [], racineIllisible: false };
  const illisible = (chemin, message) => {
    r.erreurs.push({ fichier: chemin, message });
    consigner("error", "attribute_unreadable", { fichier: path.relative(racine, chemin) || ".", message });
  };
  // Un nom scellé est-il encore le fichier scellé ? Comparaison du périphérique et de l'inode à la mémoire ;
  // enregistrement du fichier quand il vient d'être scellé ou qu'il porte déjà `i` sans mémoire.
  const verifierScelle = (chemin) => {
    const rel = path.relative(racine, chemin);
    let st;
    try {
      st = fs.statSync(chemin);
    } catch (e) {
      st = null;
      if (scelles.has(rel)) {
        r.erreurs.push({ fichier: chemin, message: "fichier scellé disparu" });
        r.remplaces.push({ fichier: chemin, raison: "disparu" });
        consigner("error", "attribute_sealed_missing", { fichier: rel, sha256_scelle: scelles.get(rel).sha256, message: `${e?.code ?? "erreur"}` });
      }
      return false;
    }
    const m = scelles.get(rel);
    if (!m) {
      scelles.set(rel, { dev: st.dev, ino: st.ino, sha256: sha256Fichier(chemin) });
      return true;
    }
    if (m.dev === st.dev && m.ino === st.ino) return true;
    const present = sha256Fichier(chemin);
    r.erreurs.push({ fichier: chemin, message: "nom scellé porté par un autre fichier (inode changé)" });
    r.remplaces.push({ fichier: chemin, raison: "inode_change" });
    consigner("error", "attribute_sealed_replaced", { fichier: rel, inode_scelle: m.ino, inode_present: st.ino, sha256_scelle: m.sha256, sha256_present: present });
    return false;
  };
  // Entrées d'un répertoire ; absent (ENOENT) : aucune ; illisible : erreur du passage.
  const lister = (d) => {
    try {
      return fs.readdirSync(d).sort();
    } catch (e) {
      if (e?.code === "ENOENT" && d !== racine) return [];
      if (d === racine) r.racineIllisible = true;
      illisible(d, `${e?.code ?? "erreur"} : ${e?.message ?? e}`);
      return [];
    }
  };
  // Attributs d'un fichier ; illisibles : erreur du passage, le fichier est laissé.
  const attributs = (c) => {
    const at = lireAttributs(c);
    if (at === null) illisible(c, "lsattr : attributs illisibles");
    return at;
  };
  const poser = (chemin, modes, attribut) => {
    try {
      chattr(modes, chemin);
      r.poses.push({ fichier: chemin, attribut });
      consigner("info", "attribute_set", { fichier: path.relative(racine, chemin), attribut });
    } catch (e) {
      r.erreurs.push({ fichier: chemin, message: String(e.stderr ?? e.message).trim() });
      consigner("error", "attribute_failed", { fichier: path.relative(racine, chemin), attribut, message: String(e.stderr ?? e.message).trim() });
    }
  };
  for (const org of lister(racine).filter((n) => HEX64.test(n))) {
    for (const jid of lister(path.join(racine, org)).filter((n) => HEX64.test(n))) {
      const rep = path.join(racine, org, jid);
      // Segments : le dernier est courant (`a`), les autres fermés (`i`).
      const segs = lister(path.join(rep, "segments")).filter((n) => SEGMENT.test(n));
      let scellee = 0;
      const lus = new Map();
      for (const n of segs.slice(0, -1)) {
        const at = attributs(path.join(rep, "segments", n));
        lus.set(n, at);
        if ((at ?? "").includes("i")) scellee = Math.max(scellee, Number(SEGMENT.exec(n)[2]));
      }
      for (const n of segs.slice(0, -1)) {
        const c = path.join(rep, "segments", n);
        const at = lus.get(n);
        if (at === null) continue;
        if (at.includes("i")) {
          verifierScelle(c);
          continue;
        }
        const e = Number(SEGMENT.exec(n)[2]);
        if (e < scellee) {
          r.refus.push({ fichier: c, raison: "epoque_inferieure" });
          consigner("error", "attribute_refused", { fichier: path.relative(racine, c), raison: "epoque_inferieure", epoch: e, sealed_epoch: scellee });
          continue;
        }
        // Un nom déjà scellé sous un autre inode est un remplacement : consigné, puis scellé à son tour.
        verifierScelle(c);
        poser(c, at.includes("a") ? ["-a", "+i"] : ["+i"], "i");
        scellee = Math.max(scellee, e);
      }
      // Noms scellés de ce journal qui ne sont plus listés (répertoire renommé, fichier disparu).
      const listes = new Set(segs.map((n) => path.join(path.relative(racine, rep), "segments", n)));
      for (const rel of [...scelles.keys()]) {
        if (rel.startsWith(`${path.join(path.relative(racine, rep), "segments")}${path.sep}`) && !listes.has(rel)) verifierScelle(path.join(racine, rel));
      }
      const courant = segs.at(-1);
      if (courant) {
        const c = path.join(rep, "segments", courant);
        const at = attributs(c);
        if (at !== null && !at.includes("a") && !at.includes("i")) poser(c, ["+a"], "a");
      }
      // Journal d'intention : celui de la plus grande époque.
      const ints = lister(path.join(rep, "intentions")).filter((n) => INTENTION.test(n));
      if (ints.length) {
        const c = path.join(rep, "intentions", ints.at(-1));
        const at = attributs(c);
        if (at !== null && !at.includes("a")) poser(c, ["+a"], "a");
      }
      // Manifestes et signatures.
      for (const n of lister(path.join(rep, "manifestes")).filter((x) => MANIFESTE.test(x))) {
        const c = path.join(rep, "manifestes", n);
        const at = attributs(c);
        if (at === null) continue;
        verifierScelle(c);
        if (!at.includes("i")) poser(c, ["+i"], "i");
      }
    }
  }
  return r;
}

const fichierEtat = () => path.join(process.env.TMPDIR || os.tmpdir(), "noortrace-attributs.etat");
/** Mémoire des fichiers scellés, hors de `storage.root` (CT-2 EX-12.18). */
const fichierScelles = () => path.join(process.env.TMPDIR || os.tmpdir(), "noortrace-attributs.scelles.json");

/** Lit la mémoire des fichiers scellés d'une racine ; vide si absente ou illisible. */
export function lireScelles(racine) {
  try {
    const tout = JSON.parse(fs.readFileSync(fichierScelles(), "utf8"));
    const m = new Map();
    for (const [rel, v] of Object.entries(tout?.[racine] ?? {})) {
      if (Number.isSafeInteger(v?.ino) && Number.isSafeInteger(v?.dev)) m.set(rel, { dev: v.dev, ino: v.ino, sha256: typeof v.sha256 === "string" ? v.sha256 : null });
    }
    return m;
  } catch {
    return new Map();
  }
}

/** Écrit la mémoire des fichiers scellés d'une racine (les autres racines du fichier sont gardées). */
export function ecrireScelles(racine, scelles) {
  let tout = {};
  try {
    tout = JSON.parse(fs.readFileSync(fichierScelles(), "utf8")) ?? {};
  } catch {
    tout = {};
  }
  tout[racine] = Object.fromEntries(scelles);
  fs.writeFileSync(fichierScelles(), JSON.stringify(tout), { mode: 0o600 });
}

/**
 * Ligne de commande : `--racine <r> [--intervalle-s <n>] [--une-fois]`, ou
 * `sonde` (code 0 si le dernier passage a réussi et date de moins de deux
 * intervalles).
 * @param {string[]} argv
 * @param {{stderr?: NodeJS.WritableStream, maintenant?: () => number}} [io]
 * @returns {Promise<number>}
 */
export async function principalAttributs(argv, io = {}) {
  const stderr = io.stderr ?? process.stderr;
  const maintenant = io.maintenant ?? (() => Date.now());
  if (argv[0] === "sonde" && argv.length === 1) {
    try {
      const e = JSON.parse(fs.readFileSync(fichierEtat(), "utf8"));
      return e.ok && maintenant() - e.ts <= 2 * e.intervalle_s * 1000 + 5000 ? 0 : 1;
    } catch {
      return 1;
    }
  }
  const o = {};
  for (let k = 0; k < argv.length; k++) {
    if (argv[k] === "--une-fois") o.uneFois = true;
    else if (argv[k] === "--racine" && argv[k + 1]) o.racine = argv[++k];
    else if (argv[k] === "--intervalle-s" && /^[0-9]{1,4}$/.test(argv[k + 1] ?? "")) o.intervalle = Number(argv[++k]);
    else {
      stderr.write("usage : noortrace-attributs --racine <storage.root> [--intervalle-s <1 à 60>] [--une-fois] | noortrace-attributs sonde\n");
      return 2;
    }
  }
  const intervalle = o.intervalle ?? 60;
  if (!o.racine || intervalle < 1 || intervalle > 60) {
    stderr.write("usage : noortrace-attributs --racine <storage.root> [--intervalle-s <1 à 60>] [--une-fois] | noortrace-attributs sonde\n");
    return 2;
  }
  const consigner = (niveau, evenement, data) => stderr.write(`${JSON.stringify({ ts: new Date(maintenant()).toISOString(), level: niveau, component: "stockage", event: evenement, data })}\n`);
  const racine = path.resolve(o.racine);
  const scelles = lireScelles(racine);
  const tour = () => {
    const r = passageAttributs(racine, { consigner, scelles });
    const etat = { ts: maintenant(), intervalle_s: intervalle, ok: r.erreurs.length === 0, poses: r.poses.length, refus: r.refus.length, erreurs: r.erreurs.length, remplaces: r.remplaces.length };
    try {
      fs.writeFileSync(fichierEtat(), JSON.stringify(etat));
    } catch {
      // sonde sans état : code 1
    }
    try {
      ecrireScelles(racine, scelles);
    } catch (e) {
      consigner("error", "attribute_memory_unwritable", { message: String(e?.message ?? e) });
      r.erreurs.push({ fichier: fichierScelles(), message: "mémoire des fichiers scellés non écrite" });
    }
    return r;
  };
  if (o.uneFois) return tour().erreurs.length ? 1 : 0;
  for (;;) {
    if (tour().racineIllisible) {
      // Rien n'est visible : le compagnon s'arrête plutôt que de tourner à vide.
      consigner("error", "attribute_root_unreadable", { racine: o.racine });
      return 1;
    }
    await new Promise((res) => setTimeout(res, intervalle * 1000));
  }
}
