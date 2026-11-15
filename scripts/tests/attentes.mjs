#!/usr/bin/env node
// Garde des essais en attente du travail `tests` de .github/workflows/ci.yml
// (`npm test`, revue de sécurité de l'étape 8, CT-9 EX-5.4) :
// aucun échec, et chaque essai en attente nomme sa condition dans son titre
// (« — en attente : <condition> », forme des fixtures) et la condition
// principale de ce texte est l'une des attentes admises ci-dessous. Un essai
// en attente sans condition nommée, ou pour une condition hors de la liste,
// fait échouer le travail : un essai vidé ou sauté ne reste pas vert en silence.
//
//   node scripts/tests/attentes.mjs <sortie de hardhat test>
//
// Condition principale : le texte qui suit le dernier « en attente : » du
// titre, jusqu'au premier « ; », « : » ou « ( » précédé d'une espace (ou
// jusqu'à la fin), sans crochet fermant final. Les détails qui suivent
// (variable, commande, motif, renvoi) ne sont pas lus. Chaque attente admise
// est une expression ancrée au début de la condition principale, qui nomme une
// ressource et son absence : un texte qui cite une ressource au passage
// (« chemin B éprouvé par … (…, Docker) ») n'est pas une condition admise.
// Les essais écrivent donc d'abord la ressource absente, puis le détail.
//
// Attentes admises : ressources que le travail `tests` n'installe pas et que
// d'autres travaux de la CI fournissent, ou que seule la phase 2 fournit :
// - le démon Docker, Docker Compose, les images de la démonstration, de
//   l'installation et des essais (travail `images`, démonstration de
//   référence) ; le procès-verbal du banc client fictif, banc de plus d'une
//   heure lancé sur demande, après Docker, images et réseau de développement ;
// - Chromium, Firefox ou WebKit de Playwright (travaux `console-chromium` et
//   `exploitation-chromium`) ;
// - la chaîne Go 1.27.3 et le binaire du vérificateur Go (travail
//   `verificateur`) ;
// - les environnements Python des SDK, cadres et intégrations (travaux
//   `sdk-python` et d'intégration) ; strace et les deux SDK JavaScript des
//   intégrations, installés à version exacte hors de package.json (travail
//   `integrations`, CT-2 19.5.7) ;
// - les interpréteurs Python aux versions épinglées, les modules Go et les
//   sorties de CT-8 des confrontations (travail `confrontation`) ;
//   python-opentimestamps (travail `ancrage`) ; le relevé des condensés de
//   deux constructions des images (travail `images`) ;
// - le compte 0 (essais joués sous sudo, travail `parcours-superutilisateur`) ;
// - le réseau de développement noorcore à quatre validateurs et son binaire
//   noorcore (construit hors de la CI, chain/scripts/build-noorcore.sh), un
//   prestataire RFC 3161 ou un calendrier OpenTimestamps publics (jamais dans
//   la suite, décision du plan du 13 novembre 2026, point 9) ;
// - une machine vierge du système de référence, préparée sous sudo depuis
//   ses sources de paquets publiques (installation réelle de TE-7, IC-2 :
//   système de référence de la porte 2, décision du plan du 13 novembre 2026,
//   point 1, et réseau public, jamais dans la suite, point 9) ;
// - les modules matériels simulés (SoftHSM2, swtpm, tpm2-tools) ;
// - le binaire prometheus 3.5.0, libfaketime, un serveur S3 qui applique les
//   politiques IAM, l'adresse IPv6 locale ;
// - un essai qui dépend d'essais précédents eux-mêmes en attente.
// Codes : 0 conforme ; 1 échec ou attente non admise ; 2 usage ou fichier
// illisible.

import fs from "node:fs";

export const ADMISES = Object.freeze([
  // Docker, images, banc client fictif
  /^Docker absent\b/,
  /^démon Docker injoignable$/,
  /^(Docker Compose|greffon docker compose) absent$/,
  /^images? absentes? du magasin local$/,
  /^image\(s\) absente\(s\) du magasin local$/,
  /^image \S+ (absente|indisponible|non construite)$/,
  /^serveur S3 appliquant les politiques IAM indisponible$/,
  /^procès-verbal du banc absent$/,
  /^relevé de deux constructions absent$/,
  // Navigateurs de Playwright
  /^(Chromium|Firefox|WebKit)( par Playwright)? indisponible$/,
  /^(Chromium|chromium|firefox|webkit) ne se lance pas$/,
  /^[Pp]laywright absent$/,
  // Go 1.27.3 et vérificateur Go
  /^(go1\.27\.3|chaîne de compilation Go 1\.27\.3) (absent|introuvable)$/,
  /^NOORTRACE_GO_BIN désigne un répertoire avec go1\.27\.3 et verificateur\/scripts\/construire\.sh réussit$/,
  /^(binaire (du vérificateur )?Go de CT-6|vérificateur Go de CT-6)( absent)?$/,
  /^(NOORTRACE_VERIFIER_BIN|binaire noortrace-verifier) absent$/,
  // Environnements Python des SDK, cadres et intégrations
  /^environnement( Python \S+| du cadre( \S+)?| du mandataire| \S+)? absent$/,
  // Intégrations (travail `integrations`) : strace, SDK JavaScript à version exacte hors de package.json
  /^strace absent$/,
  /^SDK \S+ \S+ non installé$/,
  // Confrontations rejouées par le travail `confrontation` (interpréteurs aux versions épinglées, modules Go, sorties CT-8)
  /^interpréteur Python aux versions d'exigences\.txt absent$/,
  /^module \S+ absent du cache de modules Go$/,
  /^NOORTRACE_CT8_SORTIES absent$/,
  // python-opentimestamps (travail `ancrage`)
  /^python-opentimestamps absent$/,
  // Compte 0
  /^compte 0\b/,
  /^setpriv absent$/,
  /^superutilisateur requis$/,
  /^l'essai sous un second compte exige le superutilisateur$/,
  /^le démon doit être lancé par le superutilisateur pour /,
  /^essai hors du compte root$/,
  // Réseau de développement, prestataires et calendriers publics, machine vierge
  /^(le )?réseau de développement( 2124)? (absent|arrêté|n'est pas debout|ne répond pas\b)/,
  /^le validateur \S+ ne répond pas( eth_chainId 0x84c)?$/,
  /^le binaire noorcore ne sert pas noor_getCommitCertificate$/,
  /^binaire noorcore absent$/,
  /^aucun parcours d'inscription$/,
  /^NOORTRACE_(TSA_PUBLIQUE|RESEAU_PUBLIC)=1$/,
  /^réseau public joignable$/,
  /^machine vierge Ubuntu 24\.04 avec ses sources de paquets$/,
  // Modules matériels simulés
  /^(SoftHSM2|swtpm|tpm2-tools) absent$/,
  // Prometheus, libfaketime, IPv6
  /^binaire prometheus 3\.5\.0 absent$/,
  /^bibliothèque libfaketime \S+$/,
  /^(la machine n'offre pas d'IPv6|IPv6 indisponible)$/,
  // Dépendance d'essais précédents en attente
  /^les essais précédents n'ont pas abouti$/,
]);

const MARQUE = "en attente : ";

/** Condition principale d'un texte de condition : jusqu'au premier « ; », « : » ou « ( » précédé d'une espace. */
export function conditionPrincipale(condition) {
  return condition.split(/\s+[;:]\s|\s+[;:]$|\s+\(/)[0].replace(/\]+$/, "").trim();
}

/** Condition nommée d'un titre en attente (texte après le dernier « en attente : »), ou null. */
export function conditionDuTitre(titre) {
  const k = titre.lastIndexOf(MARQUE);
  return k < 0 ? null : titre.slice(k + MARQUE.length);
}

/** Vrai si la condition principale du texte est une attente admise. */
export function admise(condition) {
  const p = conditionPrincipale(condition);
  return ADMISES.some((r) => r.test(p));
}

export function controler(texte) {
  const lignes = texte.replace(/\u001b\[[0-9;]*m/g, "").split("\n");
  // Comptes de mocha (lignes indentées) ; le bilan de hardhat (« N passing (N mocha) », non indenté) compte les
  // essais en attente parmi les réussis et n'est pas lu.
  const total = (motif) => lignes.map((l) => motif.exec(l)).filter(Boolean).reduce((n, m) => n + Number(m[1]), 0);
  const reussis = total(/^\s+(\d+) passing\b/);
  const nEchecs = total(/^\s+(\d+) failing\b/);
  const nAttente = total(/^\s+(\d+) pending\b/);
  // Titres en attente : lignes « - <titre> » du corps du rapport, hors du détail des échecs (lignes de différence
  // « - … » d'une assertion), qui suit « N failing » jusqu'au corps d'un rapport suivant.
  const titres = [];
  let details = false;
  for (const l of lignes) {
    if (/^\s+\d+ failing\b/.test(l)) details = true;
    else if (/^\s+✔ /.test(l)) details = false;
    else if (!details && /^\s+- /.test(l)) titres.push(l.trim().slice(2));
  }
  const nonAdmises = titres.filter((t) => {
    const condition = conditionDuTitre(t);
    return condition === null || !admise(condition);
  });
  return { reussis, nEchecs, nAttente, titres, nonAdmises, complet: lignes.some((l) => /^\s+\d+ passing\b/.test(l)) };
}

function principal(argv) {
  if (argv.length !== 1) {
    process.stderr.write("usage : node scripts/tests/attentes.mjs <sortie de hardhat test>\n");
    return 2;
  }
  let texte;
  try {
    texte = fs.readFileSync(argv[0], "utf8");
  } catch (e) {
    process.stderr.write(`attentes : ${argv[0]} illisible (${e.message})\n`);
    return 2;
  }
  const r = controler(texte);
  if (!r.complet) {
    process.stderr.write("attentes : aucune ligne « N passing » : rapport incomplet\n");
    return 1;
  }
  process.stdout.write(`attentes : ${r.reussis} réussis, ${r.nEchecs} échec(s), ${r.nAttente} en attente (${r.titres.length} titres lus)\n`);
  if (r.titres.length !== r.nAttente) {
    process.stderr.write(`attentes : ${r.nAttente} en attente annoncés, ${r.titres.length} titres lus\n`);
    return 1;
  }
  if (r.nEchecs > 0) return 1;
  for (const t of r.nonAdmises) {
    const c = conditionDuTitre(t);
    process.stderr.write(`attentes : attente non admise : ${t}${c === null ? "" : ` (condition principale : « ${conditionPrincipale(c)} »)`}\n`);
  }
  return r.nonAdmises.length ? 1 : 0;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) process.exitCode = principal(process.argv.slice(2));
