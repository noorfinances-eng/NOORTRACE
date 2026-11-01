#!/usr/bin/env node
// Contrôle préalable de l'hôte de l'enregistreur (CT-8 §6, EX-6.1 à EX-6.5).
//
//   node scripts/deploiement/controle-prealable.mjs --profil rapide|production \
//     --configuration <configuration de l'enregistreur> [--ancrage <ancrage-v0>] \
//     --compose <fichier Compose> --images deploiement/images/images.json \
//     --secrets <répertoire des secrets> --stockage <chemin du stockage> \
//     [--dimensionnement <sortie de dimensionner.mjs>] [--mandataire] \
//     [--declare cache-protege] [--seulement <IP-n,…>] [--ip-interne <adresse>] [--json] \
//     [--ecrire-observations <fichier>] [--observations <fichier>] [--date <horodatage>]
//
// Les fichiers ne sont exigés que par les vérifications qui les lisent
// (EX-6.1) : --configuration par IP-7, IP-8 et IP-10 ; --secrets par IP-10 ;
// --images par IP-10 et IP-12 ; --compose par IP-12 et, en production, par
// IP-6 (ports publiés) ; --stockage par IP-3 et IP-4. Avec --seulement, une
// vérification non demandée ne lit rien et n'essaie aucune connexion. Sans
// configuration, la borne d'horloge d'IP-5 est 1 000 ms. --ip-interne
// remplace NOORTRACE_IP_INTERNE (que sudo efface de l'environnement) pour les
// ports de production publiés sur l'adresse interne.
//
// Deux phases : la collecte relève les observations sur l'hôte (système,
// ressources, stockage, horloge, ports, noms, sortie réseau déclarée,
// mandataire, droits, moteur, fichier Compose) ; l'évaluation, fonction pure
// des observations et des exigences du profil, produit le rapport
// controle-prealable-v0. --observations saute la collecte et évalue un
// fichier d'observations ($defs/observations), ou un fichier de cas des
// vecteurs ($defs/cas : observations, seuil et liste only repris) : c'est
// ainsi que spec/vecteurs/ct-8/controle-prealable/ se rejoue sans hôte ; la
// configuration y est facultative (borne d'horloge : clock.warn_skew_ms, 1 000
// ms à défaut, valeur de l'exemple de CT-2 §15.3).
//
// Le contrôle ne fait que lire et essayer des connexions (écoute d'essai
// d'un port, connexion TCP de 5 s puis poignée de main TLS) ; il n'écrit que
// le fichier de --ecrire-observations. Le rapport ne contient ni nom d'hôte,
// ni secret, ni contenu de fichier. Codes : 0 prêt (avec ou sans
// avertissement) ; 1 non prêt ; 2 usage invalide (option inconnue, fichier
// illisible, configuration ou observations invalides contre leur schéma).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import * as J from "../lib/journal.mjs";
import * as D from "../lib/deploiement.mjs";

const USAGE = "Usage : node scripts/deploiement/controle-prealable.mjs --profil rapide|production --configuration <fichier> [--ancrage <fichier>] --compose <fichier> --images <images.json> --secrets <répertoire> --stockage <chemin> [--dimensionnement <fichier>] [--mandataire] [--declare cache-protege] [--seulement IP-n,…] [--ip-interne <adresse>] [--json] [--ecrire-observations <fichier>] [--observations <fichier>] [--date <horodatage>]";

/** Fichiers exigés par chaque vérification (EX-6.1) ; IP-6 n'exige --compose qu'en production. */
export const FICHIERS_EXIGES = Object.freeze({
  configuration: ["IP-7", "IP-8", "IP-10"],
  secrets: ["IP-10"],
  images: ["IP-10", "IP-12"],
  compose: ["IP-12"],
  stockage: ["IP-3", "IP-4"],
});

class Usage extends Error {}

/** Borne d'erreur d'horloge sans configuration : clock.warn_skew_ms de l'exemple de CT-2 §15.3. */
export const EXIGENCE_HORLOGE_DEFAUT = 1000;

const lireJSON = (f, quoi) => {
  try {
    return JSON.parse(fs.readFileSync(f, "utf8"));
  } catch (err) {
    throw new Usage(`${quoi} ${f} : illisible (${err.code ?? err.message})`);
  }
};

const resumeErreurs = (erreurs) => erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ");

/** Analyse les options d'EX-6.1 ; lève Usage. */
export function analyserOptions(argv) {
  const { values: o } = parseArgs({
    args: argv,
    strict: true,
    allowPositionals: false,
    options: {
      profil: { type: "string" },
      configuration: { type: "string" },
      ancrage: { type: "string" },
      compose: { type: "string" },
      images: { type: "string" },
      secrets: { type: "string" },
      stockage: { type: "string" },
      dimensionnement: { type: "string" },
      mandataire: { type: "boolean" },
      declare: { type: "string", multiple: true },
      seulement: { type: "string" },
      "ip-interne": { type: "string" },
      json: { type: "boolean" },
      "ecrire-observations": { type: "string" },
      observations: { type: "string" },
      date: { type: "string" },
    },
  });
  if (!["rapide", "production"].includes(o.profil)) throw new Usage("--profil rapide ou production est requis");
  for (const d of o.declare ?? []) if (d !== "cache-protege") throw new Usage(`--declare : seule la déclaration cache-protege est admise (reçu ${JSON.stringify(d)})`);
  if (o.date !== undefined && !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(o.date)) throw new Usage("--date : horodatage AAAA-MM-JJTHH:MM:SS.mmmZ attendu");
  let only = null;
  if (o.seulement !== undefined) {
    only = o.seulement.split(",");
    if (!only.length || only.some((x) => !/^IP-([1-9]|1[0-3])$/.test(x)) || new Set(only).size !== only.length) throw new Usage("--seulement : liste d'identifiants IP-1 à IP-13, séparés par des virgules, sans doublon");
  }
  if (o["ip-interne"] !== undefined && !/^([0-9]{1,3}(\.[0-9]{1,3}){3}|\[?[0-9a-fA-F:]+\]?)$/.test(o["ip-interne"])) throw new Usage("--ip-interne : adresse IPv4 ou IPv6 attendue");
  if (o.observations === undefined) {
    const demandee = (id) => only === null || only.includes(id);
    for (const [k, ids] of Object.entries(FICHIERS_EXIGES)) {
      const exige = ids.some(demandee) || (k === "compose" && o.profil === "production" && demandee("IP-6"));
      if (exige && o[k] === undefined) throw new Usage(`--${k} est requis (sauf avec --observations) pour ${[...ids, ...(k === "compose" && o.profil === "production" ? ["IP-6"] : [])].filter(demandee).join(", ")}`);
    }
  }
  if (o.observations !== undefined && o["ecrire-observations"] !== undefined) throw new Usage("--observations et --ecrire-observations s'excluent");
  return { ...o, only };
}

/** Exécute le contrôle : rend { rapport, observations } ; lève Usage. */
export async function controler(o, { env = process.env } = {}) {
  const schema = D.chargerSchema("controle-prealable");
  let configuration = null;
  if (o.configuration !== undefined) {
    configuration = lireJSON(o.configuration, "configuration");
    const schemas = ["configuration-enregistreur", "politique-redaction", "politique-approbation"].map((n) => D.chargerSchema(n));
    const erreurs = J.validerSchema(configuration, schemas[0], { registre: J.registreSchemas(schemas) });
    if (erreurs.length) throw new Usage(`configuration ${o.configuration} invalide contre configuration-enregistreur-v0 : ${resumeErreurs(erreurs)}`);
  }
  const ancrage = o.ancrage !== undefined ? lireJSON(o.ancrage, "ancrage") : null;
  let storageFreeMinBytes;
  if (o.profil === "production") {
    storageFreeMinBytes = null;
    if (o.dimensionnement !== undefined) {
      const s = lireJSON(o.dimensionnement, "dimensionnement");
      const erreurs = D.validerSchemaDeploiement(s, D.chargerSchema("dimensionnement"), { fragment: "#/$defs/sorties" });
      if (erreurs.length || s.valid !== true) throw new Usage(`dimensionnement ${o.dimensionnement} : sortie valide de dimensionner.mjs attendue${erreurs.length ? ` (${resumeErreurs(erreurs)})` : ""}`);
      storageFreeMinBytes = s.totals.local_bytes;
    }
  }
  const clockMaxErrorMs = configuration?.clock?.warn_skew_ms ?? EXIGENCE_HORLOGE_DEFAUT;
  let observations;
  let only = o.only;
  if (o.observations !== undefined) {
    observations = lireJSON(o.observations, "observations");
    // Un fichier de cas des vecteurs ($defs/cas) est admis : ses observations,
    // son seuil d'espace (sauf --dimensionnement) et sa liste only (sauf
    // --seulement) sont repris ; son profil doit être celui de --profil.
    if (D.validerSchemaDeploiement(observations, schema, { fragment: "#/$defs/cas" }).length === 0) {
      const cas = observations;
      if (cas.profile !== o.profil) throw new Usage(`le cas ${o.observations} est du profil ${cas.profile}, pas ${o.profil}`);
      if (o.profil === "production" && o.dimensionnement === undefined && Object.hasOwn(cas, "storage_free_min_bytes")) storageFreeMinBytes = cas.storage_free_min_bytes;
      if (only === null && cas.only) only = cas.only;
      observations = cas.observations;
    }
    const erreurs = D.validerSchemaDeploiement(observations, schema, { fragment: "#/$defs/observations" });
    if (erreurs.length) throw new Usage(`observations ${o.observations} invalides contre controle-prealable-v0 : ${resumeErreurs(erreurs)}`);
  } else {
    let description = null;
    if (o.images !== undefined) {
      description = lireJSON(o.images, "description des images");
      const erreurs = D.validerSchemaDeploiement(description, D.chargerSchema("conteneurs"));
      if (erreurs.length) throw new Usage(`${o.images} : non conforme à conteneurs-v0 : ${resumeErreurs(erreurs)}`);
    }
    let texteCompose = null;
    if (o.compose !== undefined) {
      try {
        texteCompose = fs.readFileSync(o.compose, "utf8");
      } catch {
        texteCompose = null; // IP-12 non exécutée (fichier_absent)
      }
    }
    try {
      observations = await D.collecterObservations({
        profil: o.profil,
        configuration,
        cheminConfiguration: o.configuration ?? null,
        ancrage,
        texteCompose,
        nomCompose: o.compose !== undefined ? path.basename(o.compose) : "compose.yaml",
        description,
        secrets: o.secrets ?? null,
        stockage: o.stockage ?? null,
        mandataire: o.mandataire === true,
        cacheProtege: (o.declare ?? []).includes("cache-protege"),
        ipInterne: o["ip-interne"] ?? null,
        only,
        date: o.date ?? null,
        env,
      });
    } catch (err) {
      throw new Usage(err.message);
    }
    const ko = D.validerSchemaDeploiement(observations, schema, { fragment: "#/$defs/observations" });
    if (ko.length) throw new Error(`observations collectées non conformes : ${resumeErreurs(ko)}`);
  }
  if (o.date !== undefined) observations = { ...observations, checked_at: o.date };
  const ex = D.exigencesProfil(o.profil, { storageFreeMinBytes, clockMaxErrorMs, only });
  const rapport = D.evaluerControle(observations, ex);
  const ko = D.validerSchemaDeploiement(rapport, schema);
  if (ko.length) throw new Error(`rapport non conforme à controle-prealable-v0 : ${resumeErreurs(ko)}`);
  return { rapport, observations };
}

/** Résumé lisible d'un rapport. */
export function resume(r) {
  const lignes = [`profil ${r.profile} : ${r.verdict} (code ${r.exit_code})`];
  for (const c of r.checks) lignes.push(`  ${c.id.padEnd(5)} ${c.status}${c.reason ? ` (${c.reason})` : ""}${c.blocking ? "" : ", non bloquante"}`);
  return lignes.join("\n") + "\n";
}

async function principal(argv) {
  let o;
  try {
    o = analyserOptions(argv);
  } catch (err) {
    process.stderr.write(`Erreur : ${D.messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  let res;
  try {
    res = await controler(o);
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n`);
    return 2;
  }
  if (o["ecrire-observations"] !== undefined) fs.writeFileSync(o["ecrire-observations"], D.texteJSON(res.observations));
  process.stdout.write(o.json ? D.texteJSON(res.rapport) : resume(res.rapport));
  return res.rapport.exit_code;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = await principal(process.argv.slice(2));
