#!/usr/bin/env node
// Garde des répertoires temporaires du travail `tests` de
// .github/workflows/ci.yml : `npm test` ne laisse aucune entrée nouvelle d'un
// préfixe du dépôt (PREFIXES) dans le répertoire temporaire des essais
// (`os.tmpdir()`, c'est-à-dire `$TMPDIR` ou `/tmp`, et `$NOORTRACE_TMP` s'il
// est posé). Un essai rend la machine dans l'état où il l'a trouvée ; les
// aides communes libèrent leurs répertoires par test/aides/temporaires.mjs.
//
//   node scripts/tests/temporaires.mjs releve <fichier>    avant `npm test`
//   node scripts/tests/temporaires.mjs comparer <fichier>  après `npm test`
//
// `releve` écrit dans <fichier> la liste des entrées présentes d'un préfixe
// du dépôt, une par ligne ; `comparer` relève à nouveau et nomme sur la
// sortie d'erreur chaque entrée absente du relevé de <fichier>.
// Codes : 0 aucune entrée nouvelle ; 1 entrée(s) nouvelle(s) ; 2 usage ou
// fichier illisible.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/**
 * Préfixes des entrées que les essais, leurs aides et les outils qu'ils
 * lancent créent directement dans le répertoire temporaire (`mkdtemp`,
 * `tempfile.mkdtemp`, fichier au nom tiré d'un gabarit). test/temporaires-ci.test.js vérifie que chaque préfixe
 * littéral créé sous le répertoire temporaire par test/, paquets/sdk-python/tests,
 * paquets/<paquet>/src et les outils de scripts/ lancés par les essais en relève.
 */
export const PREFIXES = Object.freeze([
  // convention des essais et des outils
  "noortrace-",
  // prises Unix sous un chemin court (108 octets au plus) : nt-prise-, nt-prises-, nt-agent-, nt-sup-
  "nt-",
  "ntadv-", // test/fixtures/enregistreur-adversarial/demon.mjs
  "ntmes-", // scripts/mesures/montage.mjs
  "ntpt-", // test/enregistreur-sdk-python.test.js (TMPDIR de chaque passage pytest)
  "ntpy-", // paquets/sdk-python/tests/test_sdk.py
  "ntrv-", // paquets/sdk-python/tests/test_revue.py
  "ntta33-", // test/fixtures/enregistreur-signataires/ta.mjs
  // essais nommés d'après leur domaine
  "noyau-", // test/noyau.test.js, test/noyau-revue.test.js
  "ancrage-", // essais et aides de l'ancrage
  "ct4-", // test/registreCt4.test.js
  "ct5-", // test/ancrage-empreinte-squattee.test.js
  "ct7-", // test/securite.test.js, test/securite-reserve-ceremonie.test.js
  "ct8-", // test/confrontation.test.js
  "verif-go-revue-", // test/verificateur-go-revue.test.js
  "banc-client-", // test/banc-client-fictif.test.js
  "banc-g-", // test/banc-client-fictif.test.js
  "pages-console-", // test/exploitation-console-pages.test.js
  "validators-go-", // test/certificatCommit.test.js (fichier validators-go-<pid>.json)
]);

/** L'entrée de ce nom porte-t-elle un préfixe du dépôt ? */
export function estDuDepot(nom) {
  return PREFIXES.some((p) => nom.startsWith(p));
}

const DECRIT = "d'un préfixe du dépôt (scripts/tests/temporaires.mjs, PREFIXES)";

/** Répertoires examinés : `os.tmpdir()` et `$NOORTRACE_TMP`, sans doublon. */
export function bases(env = process.env) {
  const b = [path.resolve(os.tmpdir())];
  if (env.NOORTRACE_TMP) b.push(path.resolve(env.NOORTRACE_TMP));
  return [...new Set(b)];
}

/** Entrées d'un préfixe du dépôt dans les répertoires examinés (chemins absolus, triés). */
export function relever(repertoires = bases()) {
  const out = [];
  for (const b of repertoires) {
    let noms;
    try {
      noms = fs.readdirSync(b);
    } catch {
      continue;
    }
    for (const n of noms) if (estDuDepot(n)) out.push(path.join(b, n));
  }
  return out.sort();
}

/** Entrées de `apres` absentes de `avant`. */
export function nouvelles(avant, apres) {
  const a = new Set(avant);
  return apres.filter((e) => !a.has(e));
}

function principal(argv) {
  const [commande, fichier] = argv;
  if (argv.length !== 2 || !["releve", "comparer"].includes(commande)) {
    process.stderr.write("usage : node scripts/tests/temporaires.mjs releve|comparer <fichier>\n");
    return 2;
  }
  const examines = bases();
  if (commande === "releve") {
    const r = relever(examines);
    try {
      fs.writeFileSync(fichier, r.map((e) => `${e}\n`).join(""));
    } catch (e) {
      process.stderr.write(`temporaires : ${fichier} non écrit (${e.message})\n`);
      return 2;
    }
    process.stdout.write(`temporaires : ${r.length} entrée(s) ${DECRIT} relevée(s) sous ${examines.join(", ")}\n`);
    return 0;
  }
  let avant;
  try {
    avant = fs.readFileSync(fichier, "utf8").split("\n").filter(Boolean);
  } catch (e) {
    process.stderr.write(`temporaires : ${fichier} illisible (${e.message})\n`);
    return 2;
  }
  const n = nouvelles(avant, relever(examines));
  if (n.length === 0) {
    process.stdout.write(`temporaires : aucune entrée nouvelle ${DECRIT} sous ${examines.join(", ")}\n`);
    return 0;
  }
  for (const e of n) process.stderr.write(`temporaires : laissé par les essais : ${e}\n`);
  process.stderr.write(`temporaires : ${n.length} entrée(s) nouvelle(s) ${DECRIT} : un essai ne libère pas ses répertoires temporaires (test/aides/temporaires.mjs)\n`);
  return 1;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = principal(process.argv.slice(2));
