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

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const HEX64 = /^[0-9a-f]{64}$/;
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

const lister = (d) => {
  try {
    return fs.readdirSync(d).sort();
  } catch {
    return [];
  }
};

/**
 * Un passage sur tous les journaux d'une racine.
 * @param {string} racine `storage.root`
 * @param {{consigner?: (niveau: string, evenement: string, data: object) => void}} [o]
 * @returns {{poses: {fichier: string, attribut: string}[], refus: {fichier: string, raison: string}[], erreurs: {fichier: string, message: string}[]}}
 */
export function passageAttributs(racine, o = {}) {
  const consigner = o.consigner ?? (() => {});
  const r = { poses: [], refus: [], erreurs: [] };
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
      for (const n of segs.slice(0, -1)) {
        if ((lireAttributs(path.join(rep, "segments", n)) ?? "").includes("i")) scellee = Math.max(scellee, Number(SEGMENT.exec(n)[2]));
      }
      for (const n of segs.slice(0, -1)) {
        const c = path.join(rep, "segments", n);
        const at = lireAttributs(c) ?? "";
        if (at.includes("i")) continue;
        const e = Number(SEGMENT.exec(n)[2]);
        if (e < scellee) {
          r.refus.push({ fichier: c, raison: "epoque_inferieure" });
          consigner("error", "attribute_refused", { fichier: path.relative(racine, c), raison: "epoque_inferieure", epoch: e, sealed_epoch: scellee });
          continue;
        }
        poser(c, at.includes("a") ? ["-a", "+i"] : ["+i"], "i");
        scellee = Math.max(scellee, e);
      }
      const courant = segs.at(-1);
      if (courant) {
        const c = path.join(rep, "segments", courant);
        const at = lireAttributs(c) ?? "";
        if (!at.includes("a") && !at.includes("i")) poser(c, ["+a"], "a");
      }
      // Journal d'intention : celui de la plus grande époque.
      const ints = lister(path.join(rep, "intentions")).filter((n) => INTENTION.test(n));
      if (ints.length) {
        const c = path.join(rep, "intentions", ints.at(-1));
        if (!(lireAttributs(c) ?? "").includes("a")) poser(c, ["+a"], "a");
      }
      // Manifestes et signatures.
      for (const n of lister(path.join(rep, "manifestes")).filter((x) => MANIFESTE.test(x))) {
        const c = path.join(rep, "manifestes", n);
        if (!(lireAttributs(c) ?? "").includes("i")) poser(c, ["+i"], "i");
      }
    }
  }
  return r;
}

const fichierEtat = () => path.join(process.env.TMPDIR || os.tmpdir(), "noortrace-attributs.etat");

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
  const tour = () => {
    const r = passageAttributs(o.racine, { consigner });
    const etat = { ts: maintenant(), intervalle_s: intervalle, ok: r.erreurs.length === 0, poses: r.poses.length, refus: r.refus.length, erreurs: r.erreurs.length };
    try {
      fs.writeFileSync(fichierEtat(), JSON.stringify(etat));
    } catch {
      // sonde sans état : code 1
    }
    return r;
  };
  if (o.uneFois) return tour().erreurs.length ? 1 : 0;
  for (;;) {
    tour();
    await new Promise((res) => setTimeout(res, intervalle * 1000));
  }
}
