#!/usr/bin/env node
// Rapprochement de l'usage des fournisseurs de modèle (CT-7 EX-3.8), pour la
// démonstration de référence : compare, clé par clé et route par route, le
// nombre de requêtes que le fournisseur déclare pour une clé détenue par la
// passerelle au nombre d'échanges `noortrace.modele.echange` de la route dans
// le journal. Un excédent révèle un usage de la clé hors de la passerelle :
// une omission par qui tient l'enregistreur n'est visible que par une source
// extérieure à lui (CT-7 MN-18, risque accepté RA-16). Sans dépendance.
//
//   node demo/rapprochement.mjs --configuration <configuration.json>
//        --segments <répertoire des segments du journal>
//        --usage <relevé d'usage du fournisseur, JSON> [--json]
//
// - La configuration donne les routes à clé propre (`policy.model.routes`,
//   `credentials: "propre"`) : chemin, libellé du fournisseur, référence du
//   secret. La clé est résolue comme le démon la résout (`env` ou `file`) et
//   nommée par les 16 premiers chiffres hexadécimaux de son SHA-256 ; sa
//   valeur n'est jamais écrite.
// - Les segments (`seg-*.ndjson` : un en-tête, puis une ligne par événement)
//   donnent les échanges journalisés d'une route : événements d'outil
//   `noortrace.modele.echange` dont `code.model` commence par le libellé de la
//   route suivi de « / ».
// - Le relevé est celui que publie le fournisseur ; pour la démonstration,
//   `GET /demo/usage` du simulateur : `{ "version": 0, "usage": [{
//   "key_sha256_16", "route", "requests" }] }`.
//
// Sortie : une ligne par clé et par route (déclarées, journalisées, écart),
// ou le rapport JSON avec --json. Codes : 0 aucun écart ; 3 écart (incident :
// le fournisseur déclare plus de requêtes que le journal n'a d'échanges, ou
// une clé de la passerelle sert une route que la configuration ne lui donne
// pas) ; 1 entrée illisible ; 2 usage.
//
// Ce que le rapprochement ne voit pas (RA-16) : un échange que le
// fournisseur ne déclare pas, un usage sous une clé que la passerelle ne
// détient pas, et une requête que le fournisseur a refusée avant de la
// compter ; un écart négatif (le journal a plus d'échanges que le relevé)
// est rapporté sans être un incident de ce contrôle.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

/** Empreinte publique d'une clé : 16 premiers chiffres hexadécimaux de son SHA-256. */
export const empreinteCle = (valeur) => createHash("sha256").update(valeur).digest("hex").slice(0, 16);

/** Résout une référence de secret `{ env }` ou `{ file }` (espaces de fin retirés) ; null si elle ne se résout pas. */
export function resoudreSecret(reference, env = process.env) {
  if (reference === null || typeof reference !== "object") return null;
  if (typeof reference.env === "string") return typeof env[reference.env] === "string" && env[reference.env] !== "" ? env[reference.env] : null;
  if (typeof reference.file === "string") {
    try {
      return fs.readFileSync(reference.file, "utf8").replace(/\s+$/, "");
    } catch {
      return null;
    }
  }
  return null;
}

/** Routes à clé propre de la configuration : `[{ route, label, key_sha256_16 }]` ; lève si un secret ne se résout pas. */
export function routesPropres(configuration, env = process.env) {
  const routes = [];
  for (const r of configuration?.policy?.model?.routes ?? []) {
    if (r.credentials !== "propre") continue;
    const secret = resoudreSecret(r.secret, env);
    if (secret === null) throw new Error(`secret de la route ${r.path} non résolu`);
    routes.push({ route: r.path, label: r.provider_label, key_sha256_16: empreinteCle(secret) });
  }
  return routes;
}

/** Nombre d'échanges de modèle journalisés par libellé de fournisseur, lus dans les segments. */
export function echangesJournalises(repertoire) {
  const parLibelle = new Map();
  for (const nom of fs.readdirSync(repertoire).filter((n) => /^seg-.*\.ndjson$/.test(n)).sort()) {
    const lignes = fs.readFileSync(path.join(repertoire, nom), "utf8").split("\n").filter(Boolean);
    for (const l of lignes.slice(1)) {
      const e = JSON.parse(l);
      if (e?.execution?.tool !== "noortrace.modele.echange" || typeof e?.code?.model !== "string") continue;
      const libelle = e.code.model.split("/")[0];
      parLibelle.set(libelle, (parLibelle.get(libelle) ?? 0) + 1);
    }
  }
  return parLibelle;
}

/**
 * Rapprochement : pour chaque route à clé propre, les requêtes déclarées
 * par le fournisseur pour la clé de la route, les échanges journalisés et
 * leur écart ; puis les lignes du relevé qui portent une clé de la passerelle
 * sur une route que la configuration ne lui donne pas.
 * @returns {{version: 0, lignes: object[], incident: boolean}}
 */
export function rapprocher({ routes, journalises, releve }) {
  if (releve === null || typeof releve !== "object" || !Array.isArray(releve.usage)) throw new Error("relevé d'usage hors forme : { usage: [...] } attendu");
  const lignes = routes.map((r) => {
    const declarees = releve.usage.filter((u) => u.key_sha256_16 === r.key_sha256_16 && u.route === r.route).reduce((n, u) => n + Number(u.requests), 0);
    const journalisees = journalises.get(r.label) ?? 0;
    return { key_sha256_16: r.key_sha256_16, route: r.route, provider_label: r.label, declared: declarees, journaled: journalisees, gap: declarees - journalisees };
  });
  const cles = new Set(routes.map((r) => r.key_sha256_16));
  for (const u of releve.usage) {
    if (cles.has(u.key_sha256_16) && !routes.some((r) => r.key_sha256_16 === u.key_sha256_16 && r.route === u.route)) {
      lignes.push({ key_sha256_16: u.key_sha256_16, route: u.route, provider_label: null, declared: Number(u.requests), journaled: 0, gap: Number(u.requests) });
    }
  }
  return { version: 0, lignes, incident: lignes.some((l) => l.gap > 0) };
}

const USAGE = "usage : demo/rapprochement.mjs --configuration <fichier> --segments <répertoire> --usage <fichier> [--json]";

export function principal(argv, io = {}) {
  const out = io.stdout ?? process.stdout;
  const err = io.stderr ?? process.stderr;
  let o;
  try {
    o = parseArgs({ args: argv, options: { configuration: { type: "string" }, segments: { type: "string" }, usage: { type: "string" }, json: { type: "boolean", default: false } }, strict: true, allowPositionals: false }).values;
  } catch (e) {
    err.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  if (!o.configuration || !o.segments || !o.usage) {
    err.write(`${USAGE}\n`);
    return 2;
  }
  let rapport;
  try {
    rapport = rapprocher({
      routes: routesPropres(JSON.parse(fs.readFileSync(o.configuration, "utf8")), io.env ?? process.env),
      journalises: echangesJournalises(o.segments),
      releve: JSON.parse(fs.readFileSync(o.usage, "utf8")),
    });
  } catch (e) {
    err.write(`rapprochement impossible : ${e.message}\n`);
    return 1;
  }
  if (o.json) out.write(`${JSON.stringify(rapport)}\n`);
  else {
    for (const l of rapport.lignes) {
      out.write(`clé ${l.key_sha256_16}, route ${l.route} : ${l.declared} requête(s) déclarée(s) par le fournisseur, ${l.journaled} échange(s) journalisé(s), écart ${l.gap > 0 ? "+" : ""}${l.gap}${l.gap > 0 ? " — usage de la clé hors de la passerelle" : ""}\n`);
    }
    out.write(rapport.incident ? "Résultat : ÉCART — au moins une clé de la passerelle a servi hors du journal (CT-7 EX-3.8).\n" : "Résultat : aucun écart entre le relevé du fournisseur et le journal.\n");
  }
  return rapport.incident ? 3 : 0;
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = principal(process.argv.slice(2));
