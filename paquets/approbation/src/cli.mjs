// Ligne de commande du service :
//
//   noortrace-approbation --config <fichier>
//       démarre le service (une ligne JSON sur la sortie standard quand il
//       écoute, arrêt propre sur SIGTERM ou SIGINT) ; un refus au démarrage
//       (EX-10.14, révision 0.6) l'arrête avant toute écoute, code 1, avec une
//       ligne `$defs/rapport_validation` sur la sortie d'erreur : erreurs de la
//       validation, ou `reference_illisible` (secret illisible ou mal formé,
//       nommé par son pointeur, jamais par sa valeur), `jetons_egaux` (deux
//       valeurs égales), `ecoute_impossible` ; une cause qu'aucun code ne
//       nomme (état illisible, amorce de l'annuaire refusée) est écrite en
//       texte, code 1 ;
//   noortrace-approbation valider-configuration <fichier>
//       validation d'EX-10.12 sans secret, sans état, sans écoute : une
//       ligne `$defs/rapport_validation` ; codes 0, 1, 2 (usage) ;
//   noortrace-approbation valider-politique <fichier> [--environment …] [--expire-after-ms N]
//       document `politique-approbation-v0` hors protocole (EX-4.2) ;
//   noortrace-approbation sonde --url <url>
//       sonde du conteneur (EX-12.22, révision 0.6) : `GET <url>` (l'écoute
//       `etat`, `http://127.0.0.1:8601/v0/etat`), sans corps, sans
//       authentification, sans suivre de redirection, 2 500 ms au plus en
//       tout ; le corps reçu sur une ligne de la sortie standard, la raison
//       d'un échec sur la sortie d'erreur ; code 0 sur une réponse 200 dont le
//       corps, en JSON strict, est `$defs/reponse_etat_service` (forme fermée
//       d'EX-12.12), quelle que soit la valeur de `ready` ; 1 dans tout autre
//       cas, usage incorrect compris (`--url` absente ou répétée, argument
//       inconnu) ; aucune autre valeur ;
//   noortrace-approbation --version

import fs from "node:fs";
import http from "node:http";
import { chargerConfiguration, lireEtValiderConfiguration, trierErreurs, ErreurConfiguration } from "./configuration.mjs";
import { demarrerService } from "./demarrage.mjs";
import { validerPolitique, avertissementsPolitique } from "./politique.mjs";
import { lireJsonStrict } from "./json.mjs";
import { IDS, registreSchemas } from "./schema.mjs";

const USAGE = `usage :
  noortrace-approbation --config <fichier>
  noortrace-approbation valider-configuration <fichier>
  noortrace-approbation valider-politique <fichier> [--environment production|developpement] [--expire-after-ms N]
  noortrace-approbation sonde --url <url>
  noortrace-approbation --version`;

/** Délai total de la sonde, en millisecondes. */
export const DELAI_SONDE_MS = 2500;

function option(args, nom) {
  const k = args.indexOf(nom);
  return k >= 0 ? args[k + 1] : undefined;
}

/**
 * Corps de la forme d'EX-12.12 : `$defs/reponse_etat_service` de
 * `console-service-v0` (révision 0.6), objet fermé `{ ready, set_read_at,
 * open_tickets }`.
 */
export function formeEtat(v) {
  return registreSchemas().estValide(`${IDS.consoleService}#/$defs/reponse_etat_service`, v);
}

/**
 * Arguments de la sonde (EX-12.22) : exactement `--url <url>`, une fois ;
 * rend l'URL, ou null pour tout autre usage (code 1).
 * @param {string[]} args arguments qui suivent `sonde`
 */
export function argumentsSonde(args) {
  if (args.length !== 2 || args[0] !== "--url" || typeof args[1] !== "string" || args[1] === "") return null;
  return args[1];
}

/**
 * Sonde : `GET url` en HTTP, au plus `DELAI_SONDE_MS` en tout.
 * @returns {Promise<{code: 0|1, sortie: string|null, erreur: string|null}>}
 */
export function sonder(url) {
  return new Promise((resoudre) => {
    let fini = false;
    const finir = (r) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      resoudre(r);
    };
    const echec = (raison) => finir({ code: 1, sortie: null, erreur: raison });
    const minuteur = setTimeout(() => {
      echec("délai écoulé");
      req?.destroy();
    }, DELAI_SONDE_MS);
    let u;
    try {
      u = new URL(url);
    } catch {
      echec("url invalide");
      return;
    }
    if (u.protocol !== "http:") {
      echec("url http attendue (écoute d'état, sans TLS)");
      return;
    }
    let req;
    try {
      req = http.get(u, { agent: false, headers: { accept: "application/json" } }, (res) => {
        const morceaux = [];
        let taille = 0;
        res.on("data", (x) => {
          taille += x.length;
          if (taille > 65536) {
            res.destroy();
            echec("corps trop grand");
          } else morceaux.push(x);
        });
        res.on("end", () => {
          const texte = Buffer.concat(morceaux).toString("utf8");
          if (res.statusCode !== 200) return echec(`statut ${res.statusCode}`);
          let v;
          try {
            v = lireJsonStrict(texte);
          } catch {
            return echec("corps illisible");
          }
          if (!formeEtat(v)) return echec("corps hors de la forme d'EX-12.12");
          // le corps reçu, sur une ligne
          finir({ code: 0, sortie: texte.replace(/[\r\n]+/g, " ").trim(), erreur: null });
        });
        res.on("error", () => echec("réponse interrompue"));
      });
    } catch {
      echec("requête impossible");
      return;
    }
    req.on("error", (e) => echec(`connexion : ${e.code ?? "erreur"}`));
  });
}

function ecrireRapport(flux, rapport) {
  flux.write(JSON.stringify({ valide: rapport.valide, errors: rapport.errors }) + "\n");
}

/**
 * @param {string[]} args
 * @returns {Promise<number>} code de sortie (0, 1 refus, 2 usage)
 */
export async function principal(args) {
  if (args.includes("--version")) {
    const p = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    process.stdout.write(`${p.name} ${p.version}\n`);
    return 0;
  }
  if (args[0] === "valider-configuration") {
    const fichier = args[1];
    if (!fichier || args.length !== 2) {
      process.stderr.write(USAGE + "\n");
      return 2;
    }
    const { rapport } = lireEtValiderConfiguration(fichier);
    ecrireRapport(process.stdout, rapport);
    return rapport.valide ? 0 : 1;
  }
  if (args[0] === "sonde") {
    // EX-12.22 : tout usage incorrect rend 1, jamais une autre valeur
    const url = argumentsSonde(args.slice(1));
    if (url === null) {
      process.stderr.write("sonde : usage : noortrace-approbation sonde --url <url>\n");
      return 1;
    }
    const r = await sonder(url);
    if (r.sortie !== null) process.stdout.write(r.sortie + "\n");
    if (r.erreur !== null) process.stderr.write(`sonde : ${r.erreur}\n`);
    return r.code;
  }
  if (args[0] === "valider-politique") {
    const fichier = args[1];
    if (!fichier) {
      process.stderr.write(USAGE + "\n");
      return 2;
    }
    const environment = option(args, "--environment") ?? "developpement";
    const expire = Number(option(args, "--expire-after-ms") ?? 3600000);
    let doc;
    try {
      doc = lireJsonStrict(fs.readFileSync(fichier), { substituts: "admis" });
    } catch (e) {
      process.stdout.write(JSON.stringify({ valide: false, errors: [{ code: "schema", pointer: null }], message: e.message }) + "\n");
      return 1;
    }
    const errors = validerPolitique(doc, { environment, expire_after_ms: expire });
    const warnings = errors.length ? [] : avertissementsPolitique(doc, {});
    process.stdout.write(JSON.stringify({ valide: errors.length === 0, errors, warnings }) + "\n");
    return errors.length === 0 ? 0 : 1;
  }
  const chemin = option(args, "--config");
  if (!chemin || args.length !== 2 || args[0] !== "--config") {
    process.stderr.write(USAGE + "\n");
    return 2;
  }
  // Refus au démarrage (EX-10.14) : une ligne rapport_validation, code 1 ;
  // la ligne ne porte jamais la valeur d'un secret, seulement des pointeurs.
  const refuser = (e) => {
    if (e instanceof ErreurConfiguration) ecrireRapport(process.stderr, { valide: false, errors: trierErreurs(e.erreurs) });
    else process.stderr.write(`démarrage refusé : ${e?.message ?? "erreur"}\n`);
    return 1;
  };
  let charge;
  try {
    charge = chargerConfiguration(chemin);
  } catch (e) {
    return refuser(e);
  }
  let instance;
  try {
    instance = await demarrerService({ config: charge.config, secrets: charge.secrets, base: charge.base });
  } catch (e) {
    return refuser(e);
  }
  process.stdout.write(JSON.stringify({ pret: true, pid: process.pid, noyau: instance.noyau, console: instance.console, etat: instance.etat }) + "\n");
  return new Promise((resoudre) => {
    let fin = false;
    const arreter = async () => {
      if (fin) return;
      fin = true;
      await instance.arreter().catch(() => {});
      resoudre(0);
    };
    process.on("SIGTERM", arreter);
    process.on("SIGINT", arreter);
  });
}
