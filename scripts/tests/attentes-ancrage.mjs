#!/usr/bin/env node
// Contrôle du rapport des essais du composant d'ancrage dans l'intégration
// continue (travail `ancrage` de .github/workflows/ci.yml) : aucun échec, et
// chaque essai en attente l'est pour une condition admise sur un exécuteur
// sans réseau de développement ni accès voulu aux services publics.
//
//   node scripts/tests/attentes-ancrage.mjs <sortie de hardhat test>
//
// Conditions admises, nommées dans le titre de l'essai en attente (« — en
// attente : <condition> », forme d'`enAttente` des fixtures) :
// - le réseau de développement noorcore (quatre validateurs construits depuis
//   noorchain-core, absent de ce dépôt) ou le parcours d'inscription qui en
//   dépend ;
// - un prestataire RFC 3161 ou un calendrier OpenTimestamps publics
//   (NOORTRACE_TSA_PUBLIQUE=1, NOORTRACE_RESEAU_PUBLIC=1) ;
// - un essai qui dépend des précédents, eux-mêmes en attente pour l'une de ces
//   raisons ;
// - une capacité de la machine que le travail n'installe pas : le démon Docker
//   (support WORM en conteneur des essais JS-9, JS-10 et du complément TM-16)
//   et l'adresse IPv6 locale ::1 (écoute du serveur interne, AN-27). Quand
//   l'exécuteur les offre, ces essais s'exécutent et doivent réussir.
// Toute autre attente (binaire Go, python-opentimestamps, openssl, `unshare`)
// est un échec : ces outils sont installés par le travail. Codes : 0 conforme ;
// 1 échec ou attente non admise ; 2 usage ou fichier illisible.

import fs from "node:fs";

const ADMISES = [
  /réseau de développement/,
  /dev-net\.sh/,
  /NOORTRACE_PARCOURS_REGISTRE/,
  /npm run e2e:registre/,
  /NOORTRACE_TSA_PUBLIQUE=1/,
  /NOORTRACE_RESEAU_PUBLIC=1/,
  /les essais précédents n'ont pas abouti/,
  /Docker absent ou démon dockerd injoignable/,
  /la machine n'offre pas d'IPv6/,
];

function principal(argv) {
  if (argv.length !== 1) {
    process.stderr.write("usage : node scripts/tests/attentes-ancrage.mjs <sortie de hardhat test>\n");
    return 2;
  }
  let texte;
  try {
    texte = fs.readFileSync(argv[0], "utf8");
  } catch (e) {
    process.stderr.write(`attentes-ancrage : ${argv[0]} illisible (${e.message})\n`);
    return 2;
  }
  // Codes de couleur éventuels retirés avant la lecture.
  const lignes = texte.replace(/\u001b\[[0-9;]*m/g, "").split("\n");
  const reussis = lignes.map((l) => /^\s*(\d+) passing\b/.exec(l)).find(Boolean);
  const echecs = lignes.map((l) => /^\s*(\d+) failing\b/.exec(l)).find(Boolean);
  const enAttente = lignes.map((l) => /^\s*(\d+) pending\b/.exec(l)).find(Boolean);
  if (!reussis) {
    process.stderr.write("attentes-ancrage : aucune ligne « N passing » : rapport incomplet\n");
    return 1;
  }
  const titres = lignes.filter((l) => /^\s+- /.test(l)).map((l) => l.trim().slice(2));
  const nonAdmises = titres.filter((t) => {
    const k = t.lastIndexOf("en attente : ");
    if (k < 0) return true;
    const condition = t.slice(k + "en attente : ".length);
    return !ADMISES.some((r) => r.test(condition));
  });
  const nEchecs = echecs ? Number(echecs[1]) : 0;
  const nAttente = enAttente ? Number(enAttente[1]) : 0;
  process.stdout.write(`attentes-ancrage : ${reussis[1]} réussis, ${nEchecs} échec(s), ${nAttente} en attente (${titres.length} titres lus)\n`);
  for (const t of titres) process.stdout.write(`  en attente : ${t}\n`);
  if (titres.length !== nAttente) {
    process.stderr.write(`attentes-ancrage : ${nAttente} en attente annoncés, ${titres.length} titres lus\n`);
    return 1;
  }
  if (nEchecs > 0) return 1;
  if (nonAdmises.length) {
    for (const t of nonAdmises) process.stderr.write(`attentes-ancrage : attente non admise : ${t}\n`);
    return 1;
  }
  return 0;
}

process.exitCode = principal(process.argv.slice(2));
