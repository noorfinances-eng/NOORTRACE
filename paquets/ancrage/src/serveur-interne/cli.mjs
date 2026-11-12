// Ligne de commande de `bin/noortrace-tsa-interne` : `init` (autorité de
// développement), `servir` (serveur RFC 3161 interne), `crl` (republication
// de la CRL), `ac` (certificat de l'AC ou CRL sur la sortie standard, pour
// le document d'ancrage et le fichier d'ancres du réviseur), `sonde` (santé
// d'un serveur en marche, sonde de conteneur sans interpréteur). L'horloge, l'aléa et les flux sont fournis par le binaire :
// aucun module de `src/` ne lit l'horloge de la machine (règle 2
// d'INTERFACES.md). Codes de retour : 0 réussite, 1 erreur d'exécution,
// 2 usage. Le journal du serveur est écrit en NDJSON sur la sortie d'erreur
// (clés en anglais, comme CT-2 §17.3) ; il ne porte jamais un jeton (AN-28).

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { initialiserAutorite, publierCrl, chargerAutorite, ALGORITHMES, FICHIERS_AUTORITE } from "./init.mjs";
import { demarrerServeur, CHEMIN_SANTE } from "./serveur.mjs";
import { Compteur } from "./compteur.mjs";
import { Autorite } from "./autorite.mjs";

export const USAGE = `noortrace-tsa-interne — serveur RFC 3161 interne non qualifié (CT-5 §7)

Commandes :
  init   --repertoire <rep> --politique <oid> --crl-url <url>
         [--algorithme rsa-3072|p-256] [--validite-jours <n ≤ 1095>]
         [--validite-ac-jours <n>] [--validite-crl-jours <n>]
         Crée l'AC et l'unité de test (clés PKCS#8 et certificats PEM, CRL vide).
  servir --repertoire <rep> [--politique <oid>] [--inclure-ac]
         | --cle <pkcs8.pem> --certificat <unite.pem> --politique <oid> [--chaine <ac.pem>]
         [--compteur <rep>] [--hote 127.0.0.1] [--port <n>] [--ecart-ms <n>]
         [--tls-cle <pem> --tls-certificat <pem> --tls-ac-clients <pem>] [--taille-max <octets>]
         Sert les requêtes TimeStampReq (POST application/timestamp-query).
  crl    --repertoire <rep> [--validite-crl-jours <n>]
         Republie la CRL vide de l'AC (numéro incrémenté).
  ac     --repertoire <rep> [--crl]
         Écrit sur la sortie standard le certificat de l'AC (ac.pem) ou, avec
         --crl, la CRL en vigueur (crl.pem) ; ne lit aucune clé privée.
  sonde  --url http://127.0.0.1:<port>${CHEMIN_SANTE}
         0 si le serveur répond 200 « ok » en 2 500 ms au plus, 1 sinon ;
         une adresse hors de la boucle locale est refusée sans connexion.
  aide   Affiche cette aide.

Codes de retour : 0 réussite ; 1 erreur ; 2 usage.
`;

/** Analyse `--option valeur` et `--drapeau`. */
export function analyserArguments(argv) {
  const options = {};
  const positionnels = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const nom = a.slice(2);
      const suivant = argv[i + 1];
      if (suivant !== undefined && !suivant.startsWith("--")) {
        options[nom] = suivant;
        i++;
      } else {
        options[nom] = true;
      }
    } else {
      positionnels.push(a);
    }
  }
  return { options, positionnels };
}

function entierOption(options, nom, defaut) {
  const v = options[nom];
  if (v === undefined) return defaut;
  if (!/^[0-9]+$/.test(String(v))) throw new ErreurUsage(`--${nom} : entier attendu`);
  return Number(v);
}

export class ErreurUsage extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurUsage";
  }
}

function exiger(options, nom) {
  const v = options[nom];
  if (v === undefined || v === true) throw new ErreurUsage(`--${nom} requis`);
  return v;
}

/** Journal NDJSON sur un flux : une ligne par événement, clés en anglais. */
export function journalFlux(flux, horloge) {
  return {
    consigner(niveau, evenement, data = {}) {
      const ligne = { ts: new Date(horloge.murale()).toISOString(), level: niveau, component: "tsa_interne", event: evenement, data };
      flux.write(`${JSON.stringify(ligne)}\n`);
    },
  };
}

/**
 * Point d'entrée.
 * @param {{argv: string[], horloge: {murale: () => number, monotone: () => number, ecartMs?: number}, aleatoire: (n: number) => Uint8Array,
 *   sortie: {write: (s: string) => void}, erreur: {write: (s: string) => void}, signaux?: boolean}} contexte
 * @returns {Promise<number>} code de retour ; pour `servir`, la promesse ne se résout qu'à l'arrêt
 */
export async function lancer(contexte) {
  const { argv, horloge, aleatoire, sortie, erreur } = contexte;
  const { options, positionnels } = analyserArguments(argv);
  const commande = positionnels[0];
  try {
    if (commande === undefined || commande === "aide" || options.aide) {
      sortie.write(USAGE);
      return commande === undefined && !options.aide ? 2 : 0;
    }
    if (commande === "init") return commandeInit(options, horloge, aleatoire, sortie);
    if (commande === "crl") return commandeCrl(options, horloge, sortie);
    if (commande === "ac") return commandeAc(options, sortie);
    if (commande === "sonde") return await commandeSonde(options, sortie);
    // `await` : une promesse rejetée doit être rattrapée ici (message en français, code 1), jamais une exception non gérée.
    if (commande === "servir") return await commandeServir(options, horloge, sortie, erreur, contexte.signaux ?? true);
    throw new ErreurUsage(`commande inconnue : ${commande}`);
  } catch (e) {
    if (e instanceof ErreurUsage) {
      erreur.write(`usage : ${e.message}\n${USAGE}`);
      return 2;
    }
    erreur.write(`erreur : ${e.message}\n`);
    return 1;
  }
}

function commandeInit(options, horloge, aleatoire, sortie) {
  const algorithme = options.algorithme ?? "rsa-3072";
  if (!ALGORITHMES.includes(algorithme)) throw new ErreurUsage(`--algorithme : ${ALGORITHMES.join(" ou ")} attendu`);
  const r = initialiserAutorite({
    repertoire: exiger(options, "repertoire"),
    algorithme,
    politique: exiger(options, "politique"),
    crlUrl: exiger(options, "crl-url"),
    validiteJours: entierOption(options, "validite-jours", 1095),
    validiteAcJours: entierOption(options, "validite-ac-jours", 3652),
    validiteCrlJours: entierOption(options, "validite-crl-jours", 30),
    horloge,
    aleatoire,
  });
  sortie.write(`autorité créée dans ${r.repertoire}\n`);
  for (const [k, c] of Object.entries(r.fichiers)) if (k !== "compteur") sortie.write(`  ${k} : ${c}\n`);
  sortie.write(`  politique : ${r.descripteur.policy_oid}\n  CRL : ${r.descripteur.crl_url}\n  unité valable jusqu'au ${r.descripteur.unit_not_after}\n`);
  return 0;
}

function commandeCrl(options, horloge, sortie) {
  const r = publierCrl({ repertoire: exiger(options, "repertoire"), horloge, validiteCrlJours: entierOption(options, "validite-crl-jours", 30) });
  sortie.write(`CRL numéro ${r.numero} publiée dans ${r.chemin} (thisUpdate ${r.thisUpdate}, nextUpdate ${r.nextUpdate})\n`);
  return 0;
}

function commandeAc(options, sortie) {
  const rep = exiger(options, "repertoire");
  const fichier = path.join(String(rep), options.crl === true ? FICHIERS_AUTORITE.crl : FICHIERS_AUTORITE.ac);
  const texte = fs.readFileSync(fichier, "utf8");
  const bloc = options.crl === true ? "X509 CRL" : "CERTIFICATE";
  if (!new RegExp(`^-----BEGIN ${bloc}-----\\n[A-Za-z0-9+/=\\n]+-----END ${bloc}-----\\n$`).test(texte)) throw new Error(`${fichier} : un seul bloc PEM ${bloc} attendu`);
  sortie.write(texte);
  return 0;
}

/** Délai de la sonde : sous le `timeout` de 3 s de la sonde Compose (comme `noortrace-ctl sonde`). */
export const DELAI_SONDE_MS = 2500;

/**
 * Sonde : `GET <url>` sur la boucle locale (127.0.0.1 ou [::1]) en `http://` ;
 * 0 sur 200 « ok », 1 sinon (connexion refusée, délai, autre réponse, adresse
 * hors de la boucle locale, refusée sans connexion).
 */
async function commandeSonde(options, sortie) {
  const brut = exiger(options, "url");
  let u;
  try {
    u = new URL(String(brut));
  } catch {
    throw new ErreurUsage("--url : adresse illisible");
  }
  if (u.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(u.hostname) || u.username || u.password) {
    sortie.write(`sonde refusée : http://127.0.0.1 ou http://[::1] seulement\n`);
    return 1;
  }
  const statut = await new Promise((resoudre) => {
    const req = http.request(u, { method: "GET", timeout: DELAI_SONDE_MS, agent: false }, (rep) => {
      const morceaux = [];
      let taille = 0;
      rep.on("data", (m) => {
        taille += m.length;
        if (taille <= 64) morceaux.push(m);
      });
      rep.on("end", () => resoudre(rep.statusCode === 200 && Buffer.concat(morceaux).toString("utf8") === "ok\n" ? 200 : rep.statusCode));
      rep.on("error", () => resoudre(null));
    });
    req.on("timeout", () => req.destroy(new Error("délai")));
    req.on("error", () => resoudre(null));
    req.end();
  });
  sortie.write(`${statut ?? "injoignable"}\n`);
  return statut === 200 ? 0 : 1;
}

async function commandeServir(options, horloge, sortie, erreur, signaux) {
  const ecart = options["ecart-ms"] === undefined ? 0 : Number(options["ecart-ms"]);
  if (!Number.isFinite(ecart)) throw new ErreurUsage("--ecart-ms : nombre attendu");
  const horlogeServeur = { murale: horloge.murale, monotone: horloge.monotone, ecartMs: ecart };
  const journal = journalFlux(erreur, horloge);

  let autorite;
  if (options.repertoire) {
    const rep = exiger(options, "repertoire");
    const compteur = options.compteur ? Compteur.ouvrir({ repertoire: String(options.compteur) }) : undefined;
    autorite = chargerAutorite({ repertoire: rep, politique: options.politique === true ? undefined : options.politique, compteur, inclureAc: options["inclure-ac"] === true });
  } else {
    const cle = fs.readFileSync(exiger(options, "cle"));
    const certificat = fs.readFileSync(exiger(options, "certificat"));
    const chaine = options.chaine && options.chaine !== true ? [fs.readFileSync(options.chaine)] : [];
    const compteur = Compteur.ouvrir({ repertoire: options.compteur && options.compteur !== true ? String(options.compteur) : path.join(path.dirname(exiger(options, "cle")), "compteur") });
    autorite = new Autorite({ clePrivee: cle, certificat, chaine, politique: exiger(options, "politique"), compteur });
  }

  let ecoute;
  if (options["tls-cle"] || options["tls-certificat"] || options["tls-ac-clients"]) {
    ecoute = {
      tls: {
        cle: fs.readFileSync(exiger(options, "tls-cle")),
        certificat: fs.readFileSync(exiger(options, "tls-certificat")),
        acClients: fs.readFileSync(exiger(options, "tls-ac-clients")),
        hote: options.hote && options.hote !== true ? options.hote : "127.0.0.1",
        port: entierOption(options, "port", 0),
      },
    };
  } else {
    ecoute = { hote: options.hote && options.hote !== true ? options.hote : "127.0.0.1", port: entierOption(options, "port", 0) };
  }
  const tailleMaxCorps = entierOption(options, "taille-max", 4096);

  let serveur;
  try {
    serveur = await demarrerServeur({ autorite, ecoute, journal, horloge: horlogeServeur, tailleMaxCorps });
  } catch (e) {
    autorite.fermer();
    throw e;
  }
  sortie.write(`${serveur.adresse.url}\n`);
  return new Promise((resoudre) => {
    const arreter = async () => {
      await serveur.fermer();
      autorite.fermer();
      journal.consigner("info", "tsa_arret", {});
      resoudre(0);
    };
    if (signaux) {
      process.once("SIGINT", arreter);
      process.once("SIGTERM", arreter);
    }
  });
}
