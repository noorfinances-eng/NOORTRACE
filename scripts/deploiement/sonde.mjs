#!/usr/bin/env node
// Sonde de référence de la supervision (CT-8 EX-10.7) et relevé des
// relectures hors du composant (EX-10.9).
//
//   node scripts/deploiement/sonde.mjs [--approbation <base>] [--console <origine>]
//       [--rpc <cible>=<url>]… [--expediteur <adresse>]… [--instance <manifeste>]
//       [--delai <ms>] [--sortie <fichier .prom>] [--intervalle <secondes>]
//
//   À chaque passage (une passe sans --intervalle ; défaut d'EX-10.7 : 15 s) :
//   GET <base>/v0/etat du service d'approbation (défaut http://127.0.0.1:8601,
//   port d'état d'EX-3.5) → noortrace_approbation_pret (1 seulement pour une
//   réponse 200 de la forme de CT-3 EX-12.12 avec ready vrai),
//   noortrace_approbation_tickets_ouverts et noortrace_approbation_jeu_lu_age_s ;
//   GET <origine>/v0/sante du serveur de console (CT-3 EX-13.44), quand
//   --console est donné → noortrace_console_prete ; pour chaque point RPC
//   déclaré, eth_blockNumber et eth_getBlockTransactionCountByNumber("pending")
//   → noortrace_registre_sonde_ok{target}, noortrace_registre_hauteur{target},
//   noortrace_registre_mempool{target} ; le solde de chaque expéditeur
//   (--expediteur, et comptes deployeur, administrateur_registre et relayeur
//   en vigueur du manifeste d'instance, CT-4 EX-4.19) par le premier point qui
//   répond → noortrace_registre_solde_wei{sender}. Aucune transaction n'est
//   soumise.
//
//   node scripts/deploiement/sonde.mjs releve --check <registre_gels|console|copie_exploitation>
//       --sortie <fichier .prom> -- <commande> [arguments…]
//
//   Lance la relecture (par exemple noortrace-ctl worm gel etat sous les
//   identifiants du Lecteur, TP-4) et écrit noortrace_releve_externe_ok{check}
//   (1 si la commande rend 0, 0 sinon) et noortrace_releve_externe_dernier_s{check}
//   (fin de la relecture, secondes UNIX ; écart E-C5 de
//   scripts/lib/supervision.mjs). Un fichier par relecture, dans le
//   répertoire du collecteur textfile de l'exportateur de nœud.
//
// Codes : 0 exposition écrite (quelles que soient les réponses sondées) ;
// 1 manifeste illisible ou commande de relecture introuvable ; 2 usage.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { messageOptions } from "../lib/deploiement.mjs";
import { msDepuisHorodatage, secondes } from "../lib/supervision.mjs";

const USAGE = [
  "Usage : node scripts/deploiement/sonde.mjs [--approbation <base>] [--console <origine>] [--rpc <cible>=<url>]… [--expediteur <adresse>]…",
  "          [--instance <manifeste>] [--delai <ms>] [--sortie <fichier>] [--intervalle <s>]",
  "        node scripts/deploiement/sonde.mjs releve --check <registre_gels|console|copie_exploitation> --sortie <fichier> -- <commande> [arguments…]",
].join("\n");

export const RELEVES = Object.freeze(["registre_gels", "console", "copie_exploitation"]);
const ADRESSE = /^0x[0-9a-fA-F]{40}$/;
const CIBLE = /^[a-z][a-z0-9_-]{0,63}$/;
const ROLES_PROVISION = new Set(["deployeur", "administrateur_registre", "relayeur"]);

/** Le corps est-il de la forme de CT-3 EX-12.12 (`$defs/reponse_etat_service`, objet fermé) ? */
export function formeEtat(c) {
  if (c === null || typeof c !== "object" || Array.isArray(c)) return false;
  const cles = Object.keys(c).sort().join(",");
  if (cles !== "open_tickets,ready,set_read_at") return false;
  if (typeof c.ready !== "boolean") return false;
  if (!Number.isSafeInteger(c.open_tickets) || c.open_tickets < 0) return false;
  return c.set_read_at === null || msDepuisHorodatage(c.set_read_at) !== null;
}

/** Le corps est-il de la forme de CT-3 EX-13.44 (`$defs/reponse_sante`) ? */
export function formeSante(c) {
  if (c === null || typeof c !== "object" || Array.isArray(c)) return false;
  if (Object.keys(c).sort().join(",") !== "checked_at,identity_ready,ready,service_reachable") return false;
  return typeof c.ready === "boolean" && typeof c.service_reachable === "boolean" && typeof c.identity_ready === "boolean" && msDepuisHorodatage(c.checked_at) !== null;
}

/**
 * Exposition d'une passe, fonction pure des réponses relevées.
 * @param {{approbation: {statut: number, corps: any}|null, console?: {statut: number, corps: any}|null|undefined,
 *   rpc: {target: string, hauteur: bigint|null, mempool: bigint|null}[], soldes: {sender: string, wei: bigint}[]}} r
 * @param {number} maintenant ms UTC
 */
export function expositionSonde(r, maintenant) {
  const L = [];
  const a = r.approbation;
  const etatOk = a !== null && a.statut === 200 && formeEtat(a.corps);
  L.push("# HELP noortrace_approbation_pret Service d'approbation pret (GET /v0/etat, ready) ; 0 sans reponse conforme (CT-8 EX-10.7).");
  L.push("# TYPE noortrace_approbation_pret gauge");
  L.push(`noortrace_approbation_pret ${etatOk && a.corps.ready ? 1 : 0}`);
  if (etatOk) {
    L.push("# HELP noortrace_approbation_tickets_ouverts Tickets non decides (open_tickets).");
    L.push("# TYPE noortrace_approbation_tickets_ouverts gauge");
    L.push(`noortrace_approbation_tickets_ouverts ${a.corps.open_tickets}`);
    if (a.corps.set_read_at !== null) {
      L.push("# HELP noortrace_approbation_jeu_lu_age_s Age de la derniere lecture du jeu (set_read_at), en secondes.");
      L.push("# TYPE noortrace_approbation_jeu_lu_age_s gauge");
      L.push(`noortrace_approbation_jeu_lu_age_s ${secondes(Math.max(0, maintenant - msDepuisHorodatage(a.corps.set_read_at)))}`);
    }
  }
  if (r.console !== undefined) {
    const c = r.console;
    const ok = c !== null && c.statut === 200 && formeSante(c.corps) && c.corps.ready === true;
    L.push("# HELP noortrace_console_prete Serveur de console pret (GET /v0/sante, ready) ; 0 sans reponse conforme (CT-8 EX-10.7).");
    L.push("# TYPE noortrace_console_prete gauge");
    L.push(`noortrace_console_prete ${ok ? 1 : 0}`);
  }
  if (r.rpc.length) {
    L.push("# HELP noortrace_registre_sonde_ok Point RPC qui repond a eth_blockNumber (CT-4 EX-10.5).");
    L.push("# TYPE noortrace_registre_sonde_ok gauge");
    for (const x of r.rpc) L.push(`noortrace_registre_sonde_ok{target="${x.target}"} ${x.hauteur !== null ? 1 : 0}`);
    L.push("# HELP noortrace_registre_hauteur Hauteur rendue par eth_blockNumber.");
    L.push("# TYPE noortrace_registre_hauteur gauge");
    for (const x of r.rpc) if (x.hauteur !== null) L.push(`noortrace_registre_hauteur{target="${x.target}"} ${x.hauteur}`);
    L.push("# HELP noortrace_registre_mempool Transactions du bloc pending (eth_getBlockTransactionCountByNumber).");
    L.push("# TYPE noortrace_registre_mempool gauge");
    for (const x of r.rpc) if (x.mempool !== null) L.push(`noortrace_registre_mempool{target="${x.target}"} ${x.mempool}`);
  }
  if (r.soldes.length) {
    L.push("# HELP noortrace_registre_solde_wei Solde de l'expediteur, en wei (CT-4 EX-8.18).");
    L.push("# TYPE noortrace_registre_solde_wei gauge");
    for (const x of r.soldes) L.push(`noortrace_registre_solde_wei{sender="${x.sender}"} ${x.wei}`);
  }
  return L.join("\n") + "\n";
}

/** Exposition d'un relevé hors du composant (EX-10.9). */
export function expositionReleve(check, ok, fin) {
  return [
    "# HELP noortrace_releve_externe_ok Relecture hors du composant reussie (CT-8 EX-10.9).",
    "# TYPE noortrace_releve_externe_ok gauge",
    `noortrace_releve_externe_ok{check="${check}"} ${ok ? 1 : 0}`,
    "# HELP noortrace_releve_externe_dernier_s Fin de la derniere relecture, en secondes UNIX.",
    "# TYPE noortrace_releve_externe_dernier_s gauge",
    `noortrace_releve_externe_dernier_s{check="${check}"} ${secondes(fin)}`,
    "",
  ].join("\n");
}

/** Requête HTTP(S) : { statut, corps } (corps JSON ou null), ou null sans réponse dans le délai. */
function requete(url, { methode = "GET", corps = null, delai }) {
  return new Promise((resolve) => {
    let u;
    try {
      u = new URL(url);
    } catch {
      resolve(null);
      return;
    }
    const mod = u.protocol === "https:" ? https : u.protocol === "http:" ? http : null;
    if (!mod) {
      resolve(null);
      return;
    }
    const donnees = corps === null ? null : Buffer.from(JSON.stringify(corps));
    const req = mod.request(u, { method: methode, timeout: delai, headers: donnees ? { "content-type": "application/json", "content-length": donnees.length } : {} }, (res) => {
      const morceaux = [];
      let taille = 0;
      res.on("data", (d) => {
        taille += d.length;
        if (taille > 1048576) req.destroy();
        else morceaux.push(d);
      });
      res.on("end", () => {
        let j = null;
        try {
          j = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
        } catch {
          j = null;
        }
        resolve({ statut: res.statusCode, corps: j });
      });
      res.on("error", () => resolve(null));
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(null));
    if (donnees) req.write(donnees);
    req.end();
  });
}

async function appelRPC(url, methode, params, delai) {
  const r = await requete(url, { methode: "POST", corps: { jsonrpc: "2.0", id: 1, method: methode, params }, delai });
  if (!r || r.statut !== 200 || r.corps === null || typeof r.corps !== "object" || r.corps.error !== undefined) return null;
  return typeof r.corps.result === "string" && /^0x[0-9a-fA-F]{1,64}$/.test(r.corps.result) ? BigInt(r.corps.result) : null;
}

/** Une passe de sonde ; rend l'exposition. */
export async function passe(o, maintenant = () => Date.now()) {
  const approbation = await requete(`${o.approbation.replace(/\/+$/, "")}/v0/etat`, { delai: o.delai });
  const r = { approbation, rpc: [], soldes: [] };
  if (o.console !== null) r.console = await requete(`${o.console.replace(/\/+$/, "")}/v0/sante`, { delai: o.delai });
  let premierOk = null;
  for (const { target, url } of o.rpc) {
    const hauteur = await appelRPC(url, "eth_blockNumber", [], o.delai);
    const mempool = hauteur === null ? null : await appelRPC(url, "eth_getBlockTransactionCountByNumber", ["pending"], o.delai);
    r.rpc.push({ target, hauteur, mempool });
    if (hauteur !== null && premierOk === null) premierOk = url;
  }
  if (premierOk !== null) {
    for (const sender of o.expediteurs) {
      const wei = await appelRPC(premierOk, "eth_getBalance", [sender, "latest"], o.delai);
      if (wei !== null) r.soldes.push({ sender, wei });
    }
  }
  return expositionSonde(r, maintenant());
}

function ecrireAtomique(fichier, texte) {
  const tmp = `${fichier}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, texte, { mode: 0o644 });
  fs.renameSync(tmp, fichier);
}

/** Expéditeurs pourvus d'une provision dans un manifeste d'instance (comptes en vigueur). */
export function expediteursManifeste(m) {
  if (!m || !Array.isArray(m.accounts)) throw new Error("manifeste d'instance sans accounts");
  return m.accounts.filter((a) => ROLES_PROVISION.has(a.role) && a.to_height === null && ADRESSE.test(a.address)).map((a) => a.address.toLowerCase());
}

function releve(argv, erreur) {
  const fin = argv.indexOf("--");
  const avant = fin < 0 ? argv : argv.slice(0, fin);
  const commande = fin < 0 ? [] : argv.slice(fin + 1);
  let o;
  try {
    o = parseArgs({ args: avant, strict: true, allowPositionals: false, options: { check: { type: "string" }, sortie: { type: "string" } } }).values;
    if (!RELEVES.includes(o.check)) throw new Error(`--check : l'un de ${RELEVES.join(", ")}`);
    if (o.sortie === undefined) throw new Error("option --sortie requise");
    if (!commande.length) throw new Error("commande de relecture absente après --");
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  const r = spawnSync(commande[0], commande.slice(1), { stdio: ["ignore", "inherit", "inherit"] });
  if (r.error && r.error.code === "ENOENT") {
    erreur.write(`Erreur : commande introuvable : ${commande[0]}\n`);
    ecrireAtomique(o.sortie, expositionReleve(o.check, false, Date.now()));
    return 1;
  }
  ecrireAtomique(o.sortie, expositionReleve(o.check, r.status === 0, Date.now()));
  return 0;
}

export async function principal(argv, sortie = process.stdout, erreur = process.stderr) {
  if (argv[0] === "releve") return releve(argv.slice(1), erreur);
  let o;
  try {
    o = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        approbation: { type: "string" },
        console: { type: "string" },
        rpc: { type: "string", multiple: true },
        expediteur: { type: "string", multiple: true },
        instance: { type: "string" },
        delai: { type: "string" },
        sortie: { type: "string" },
        intervalle: { type: "string" },
      },
    }).values;
    for (const k of ["delai", "intervalle"]) if (o[k] !== undefined && (!/^[0-9]{1,7}$/.test(o[k]) || Number(o[k]) < 1)) throw new Error(`--${k} : entier positif attendu`);
    for (const x of o.expediteur ?? []) if (!ADRESSE.test(x)) throw new Error(`--expediteur : adresse 0x de 40 chiffres hexadécimaux attendue : ${x}`);
    for (const x of o.rpc ?? []) {
      const i = x.indexOf("=");
      if (i < 1 || !CIBLE.test(x.slice(0, i)) || !/^https?:\/\//.test(x.slice(i + 1))) throw new Error(`--rpc : <cible>=<url http(s)> attendu : ${x}`);
    }
  } catch (err) {
    erreur.write(`Erreur : ${messageOptions(err)}\n${USAGE}\n`);
    return 2;
  }
  const expediteurs = (o.expediteur ?? []).map((x) => x.toLowerCase());
  if (o.instance !== undefined) {
    try {
      for (const a of expediteursManifeste(JSON.parse(fs.readFileSync(o.instance, "utf8")))) if (!expediteurs.includes(a)) expediteurs.push(a);
    } catch (err) {
      erreur.write(`Erreur : manifeste d'instance illisible : ${err.message}\n`);
      return 1;
    }
  }
  const options = {
    approbation: o.approbation ?? "http://127.0.0.1:8601",
    console: o.console ?? null,
    rpc: (o.rpc ?? []).map((x) => ({ target: x.slice(0, x.indexOf("=")), url: x.slice(x.indexOf("=") + 1) })),
    expediteurs,
    delai: Number(o.delai ?? 2000),
  };
  const une = async () => {
    const texte = await passe(options);
    if (o.sortie !== undefined) ecrireAtomique(o.sortie, texte);
    else sortie.write(texte);
  };
  await une();
  if (o.intervalle === undefined) return 0;
  const minuterie = setInterval(() => { une().catch((e) => erreur.write(`Erreur : ${e.message}\n`)); }, Number(o.intervalle) * 1000);
  const arreter = () => clearInterval(minuterie);
  process.once("SIGTERM", arreter);
  process.once("SIGINT", arreter);
  return null;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  principal(process.argv.slice(2)).then((code) => { if (code !== null) process.exitCode = code; });
}
