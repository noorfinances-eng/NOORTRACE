// Répertoires temporaires des essais : création, inscription et libération
// dans tous les cas, échec compris.
//
// Un essai rend la machine dans l'état où il l'a trouvée. Les aides communes
// des essais (`test/fixtures/enregistreur-coeur/outils.mjs`,
// `test/fixtures/approbation-service/outils.mjs`,
// `test/fixtures/inscription/outils.mjs`) créent leurs répertoires par
// `creerRepertoireTemporaire`, qui les inscrit ici ; un répertoire créé
// ailleurs s'inscrit par `inscrireRepertoireTemporaire`.
//
// Libération, sous mocha (la suite de `npm test`, lancée par Hardhat) :
// - à la fin de chaque fichier d'essai, après tous ses crochets `after`
//   (démons, serveurs et processus fils arrêtés), les répertoires inscrits
//   pendant qu'il tournait sont supprimés : un crochet « after all » est
//   ajouté, au début de la passe, en dernier à la dernière suite de premier
//   niveau de chaque fichier. Mocha joue les fichiers l'un après l'autre et
//   leurs suites de premier niveau sont contiguës : un répertoire inscrit
//   entre la fin de la suite de premier niveau précédente et la fin de la
//   dernière suite d'un fichier appartient à ce fichier (ou à un fichier
//   déjà terminé) ;
// - ce qui est inscrit avant la fin de la première suite (chargement des
//   fichiers, crochets de niveau racine) ou après la dernière (crochets
//   `after` de niveau racine) est supprimé à la fin de la passe, par un
//   crochet « after all » de la racine ajouté après tous les autres ;
// - en secours (passe arrêtée par `process.exit`, crochet de la racine non
//   joué), à la sortie du processus, de façon synchrone.
// Un essai en échec n'empêche pas ces crochets : mocha joue les « after all »
// même quand un essai ou un « before all » de la suite échoue.
// Suppression : `fs.rm(…, { recursive, force, maxRetries })`, prises Unix
// comprises (elles sont dans ces répertoires). Une suppression qui échoue est
// reprise à la sortie, et signalée sur la sortie d'erreur si elle échoue
// encore. Aucun essai ne garde un de ces répertoires pour le diagnostic.
//
// Hors de mocha (processus fils qui importe une aide), les répertoires sont
// inscrits mais pas libérés ici : leur propriétaire est l'essai qui a lancé
// le processus.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SUPPRESSION = Object.freeze({ recursive: true, force: true, maxRetries: 10, retryDelay: 100 });

/** Répertoires inscrits depuis la fin de la suite de premier niveau précédente. */
let enCours = new Set();
/** Répertoires d'un fichier dont la dernière suite de premier niveau n'est pas finie. */
const parFichier = new Map();
/** Répertoires libérés en fin de passe (ou à la sortie du processus). */
const finDePasse = new Set();
let installe = false;

/** Inscrit un répertoire créé ailleurs ; rend son chemin. */
export function inscrireRepertoireTemporaire(chemin) {
  enCours.add(chemin);
  return chemin;
}

/**
 * Répertoire temporaire neuf sous `base` (défaut : `os.tmpdir()`), inscrit
 * pour libération.
 */
export function creerRepertoireTemporaire(prefixe, base = os.tmpdir()) {
  return inscrireRepertoireTemporaire(fs.mkdtempSync(path.join(base, prefixe)));
}

/** Supprime des répertoires ; ceux qui résistent passent à la sortie du processus. */
async function liberer(repertoires) {
  for (const d of repertoires) {
    try {
      await fs.promises.rm(d, SUPPRESSION);
    } catch {
      finDePasse.add(d);
    }
  }
}

function libererALaSortie() {
  for (const d of [...finDePasse, ...enCours, ...[...parFichier.values()].flatMap((s) => [...s])]) {
    try {
      fs.rmSync(d, SUPPRESSION);
    } catch (e) {
      process.stderr.write(`test/aides/temporaires.mjs : ${d} non supprimé (${e.code ?? e.message})\n`);
    }
  }
}

/** Ajoute les crochets de libération à la racine de la passe et à ses suites de premier niveau. */
function installer(racine) {
  if (installe) return;
  installe = true;
  const suites = racine.suites;
  suites.forEach((suite, i) => {
    const derniere = i === suites.length - 1 || suites[i + 1].file !== suite.file;
    suite.afterAll("libération des répertoires temporaires du fichier (test/aides/temporaires.mjs)", async function () {
      this.timeout(120000);
      const inscrits = enCours;
      enCours = new Set();
      if (i === 0) {
        for (const d of inscrits) finDePasse.add(d);
        return;
      }
      const cle = suite.file ?? `#${i}`;
      const lot = parFichier.get(cle) ?? new Set();
      for (const d of inscrits) lot.add(d);
      if (!derniere) {
        parFichier.set(cle, lot);
        return;
      }
      parFichier.delete(cle);
      await liberer(lot);
    });
  });
  racine.afterAll("libération des répertoires temporaires restants (test/aides/temporaires.mjs)", async function () {
    this.timeout(120000);
    const restants = [...finDePasse, ...enCours, ...[...parFichier.values()].flatMap((s) => [...s])];
    finDePasse.clear();
    enCours = new Set();
    parFichier.clear();
    await liberer(restants);
  });
}

// Sous mocha, ce module est évalué au chargement du premier fichier d'essai
// qui l'importe, au niveau racine : le crochet « before all » ci-dessous est
// celui de la racine de la passe, joué une fois au début.
if (typeof globalThis.describe === "function" && typeof globalThis.before === "function") {
  globalThis.before("installation de la libération des répertoires temporaires (test/aides/temporaires.mjs)", function () {
    installer(this.test.parent);
  });
  process.once("exit", libererALaSortie);
}
