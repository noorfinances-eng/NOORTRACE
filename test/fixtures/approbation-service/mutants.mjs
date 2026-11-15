// Mutants du paquet livré `paquets/approbation` (étape 8, revue de sécurité
// interne : « un mutant par règle nouvelle », tué par l'oracle de l'essai).
// Même procédé que TA-51 (`approbation-service-configuration.test.js`) : copie
// du paquet sous `NOORTRACE_TMP` (sinon le répertoire temporaire du système),
// `node_modules` du dépôt lié entrée par entrée, règle retirée par un
// remplacement textuel qui doit apparaître exactement une fois, copie
// détruite par `detruire()`. Avec `console`, une copie de `paquets/console`
// mutée prend la place de `@noortrace/console` pour la copie du service
// (réponses que le service exécute par ce module, TA-47).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { RACINE } from "./outils.mjs";

const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();

function appliquer(racinePaquet, remplacements, nom) {
  for (const r of remplacements) {
    const f = path.join(racinePaquet, r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (r.tous ? n < 1 : n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
    fs.writeFileSync(f, r.tous ? texte.split(r.ancien).join(r.nouveau) : texte.replace(r.ancien, () => r.nouveau));
  }
}

/** Lie chaque entrée de `node_modules` du dépôt dans `dest` ; `@noortrace/*` entrée par entrée, `remplacer` prenant le pas. */
function lierNodeModules(dest, remplacer = {}) {
  const src = path.join(RACINE, "node_modules");
  fs.mkdirSync(dest);
  for (const e of fs.readdirSync(src)) {
    if (e === "@noortrace") continue;
    fs.symlinkSync(path.join(src, e), path.join(dest, e));
  }
  fs.mkdirSync(path.join(dest, "@noortrace"));
  for (const e of fs.readdirSync(path.join(src, "@noortrace"))) {
    const cible = remplacer[e] ?? fs.realpathSync(path.join(src, "@noortrace", e));
    fs.symlinkSync(cible, path.join(dest, "@noortrace", e));
  }
}

/**
 * Copie mutée du paquet `approbation`.
 * @param {string} nom
 * @param {{fichier: string, ancien: string, nouveau: string, tous?: boolean}[]} remplacements chemins relatifs au paquet (`src/…`)
 * @param {{console?: {fichier: string, ancien: string, nouveau: string, tous?: boolean}[]}} [o] remplacements d'une copie de `paquets/console`
 * @returns {{racine: string, paquet: string, importer: (rel: string) => Promise<object>, detruire: () => void}}
 */
export function copiePaquet(nom, remplacements, o = {}) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-${nom}-`));
  const paquet = path.join(racine, "approbation");
  try {
    fs.cpSync(path.join(RACINE, "paquets", "approbation"), paquet, { recursive: true });
    const remplacer = {};
    if (o.console) {
      const c = path.join(racine, "console");
      fs.cpSync(path.join(RACINE, "paquets", "console"), c, { recursive: true });
      appliquer(c, o.console, `${nom} (console)`);
      remplacer.console = c;
    }
    lierNodeModules(path.join(racine, "node_modules"), remplacer);
    appliquer(paquet, remplacements, nom);
  } catch (e) {
    // un mutant mal posé (texte introuvable) ne laisse pas de copie derrière lui
    fs.rmSync(racine, { recursive: true, force: true });
    throw e;
  }
  return {
    racine,
    paquet,
    importer: (rel) => import(pathToFileURL(path.join(paquet, rel)).href),
    detruire: () => fs.rmSync(racine, { recursive: true, force: true }),
  };
}
