// Sonde du serveur de console (CT-3 EX-13.44, contrat 2.11) : de la
// configuration, elle ne lit que `console_origin`, `listen` et les
// certificats de `tls.cert` ; elle joint `listen.host` (`127.0.0.1` pour
// `0.0.0.0`, `::1` pour `::`) avec l'indication de nom de l'hôte de
// `console_origin`, exige que le certificat présenté soit le premier de
// `tls.cert` (SHA-256 du DER), envoie `GET /v0/sante` avec `Host` égal à
// l'autorité de `console_origin`, attend 2 500 ms au plus en tout. Code 0 pour
// 200, corps conforme à `$defs/reponse_sante` et `ready` vrai ; 1 sinon.

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import crypto from "node:crypto";
import { lireJsonStrict } from "@noortrace/approbation";
import { blocsPem } from "./outils.mjs";
import { conformeService } from "./configuration.mjs";

export const CONFIGURATION_DEFAUT = "/etc/noortrace-console/configuration.json";
export const DELAI_SONDE_MS = 2500;

const ORIGINE = /^https:\/\/([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?)(:[1-9][0-9]{0,4})?$/;

/** Lit ce dont la sonde a besoin ; lève une erreur de texte sans valeur secrète. */
function lireConfiguration(chemin) {
  let doc;
  try {
    doc = lireJsonStrict(fs.readFileSync(chemin));
  } catch {
    throw new Error("configuration illisible");
  }
  const origine = doc?.console_origin;
  const m = typeof origine === "string" ? ORIGINE.exec(origine) : null;
  if (!m) throw new Error("console_origin illisible");
  const l = doc.listen;
  if (!l || typeof l.host !== "string" || l.host === "" || !Number.isInteger(l.port) || l.port < 1 || l.port > 65535) throw new Error("listen illisible");
  const ref = doc.tls?.cert;
  let octets;
  try {
    if (ref && typeof ref.file === "string" && Object.keys(ref).length === 1) octets = fs.readFileSync(path.resolve(path.dirname(path.resolve(chemin)), ref.file));
    else if (ref && typeof ref.env === "string" && Object.keys(ref).length === 1 && process.env[ref.env] !== undefined) octets = Buffer.from(process.env[ref.env], "utf8");
    else throw new Error();
  } catch {
    throw new Error("tls.cert illisible");
  }
  const premier = blocsPem(octets.toString("utf8"), "CERTIFICATE")[0];
  let empreinte;
  try {
    empreinte = crypto.createHash("sha256").update(new crypto.X509Certificate(premier).raw).digest("hex");
  } catch {
    throw new Error("tls.cert illisible");
  }
  const hote = l.host === "0.0.0.0" ? "127.0.0.1" : l.host === "::" ? "::1" : l.host;
  return { hote, port: l.port, nom: m[1], autorite: origine.slice("https://".length), empreinte };
}

/**
 * Sonde d'EX-13.44.
 * @param {{chemin?: string}} [o]
 * @returns {Promise<{code: 0|1, sortie: string, erreur: string}>}
 */
export async function sonder({ chemin = CONFIGURATION_DEFAUT } = {}) {
  const echec = (raison, sortie = "") => ({ code: 1, sortie, erreur: `sonde : ${raison}\n` });
  let c;
  try {
    c = lireConfiguration(chemin);
  } catch (e) {
    return echec(e.message);
  }
  let r;
  try {
    r = await echanger(c);
  } catch (e) {
    return echec(e.message);
  }
  const sortie = r.corps.replace(/[\r\n]+/g, " ") + "\n";
  if (r.statut !== 200) return echec(`statut ${r.statut}`, sortie);
  let v;
  try {
    v = lireJsonStrict(Buffer.from(r.corps, "utf8"));
  } catch {
    return echec("corps non JSON", sortie);
  }
  if (!conformeService("reponse_sante", v)) return echec("corps non conforme", sortie);
  if (v.ready !== true) return echec("ready faux", sortie);
  return { code: 0, sortie, erreur: "" };
}

/** Connexion TLS, contrôle du certificat, requête et réponse HTTP/1.1. */
function echanger(c) {
  return new Promise((resoudre, rejeter) => {
    let fini = false;
    const options = { host: c.hote, port: c.port, rejectUnauthorized: false, ALPNProtocols: ["http/1.1"] };
    if (net.isIP(c.nom) === 0) options.servername = c.nom;
    const s = tls.connect(options);
    const terminer = (erreur, valeur) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      s.destroy();
      if (erreur) rejeter(new Error(erreur));
      else resoudre(valeur);
    };
    const minuteur = setTimeout(() => terminer("delai depasse"), DELAI_SONDE_MS);
    const morceaux = [];
    s.on("secureConnect", () => {
      const cert = s.getPeerX509Certificate();
      const empreinte = cert ? crypto.createHash("sha256").update(cert.raw).digest("hex") : null;
      if (empreinte !== c.empreinte) return terminer("certificat different");
      s.write(`GET /v0/sante HTTP/1.1\r\nHost: ${c.autorite}\r\nAccept: application/json\r\nConnection: close\r\n\r\n`);
    });
    s.on("data", (d) => morceaux.push(d));
    s.on("end", () => {
      const r = lireReponse(Buffer.concat(morceaux));
      if (r === null) terminer("reponse illisible");
      else terminer(null, r);
    });
    s.on("error", () => terminer("connexion refusee"));
  });
}

/** Statut et corps d'une réponse HTTP/1.1 complète, ou `null`. */
function lireReponse(brut) {
  const fin = brut.indexOf("\r\n\r\n");
  if (fin < 0) return null;
  const tete = brut.subarray(0, fin).toString("latin1").split("\r\n");
  const m = /^HTTP\/1\.1 ([0-9]{3}) /.exec(tete[0] + " ");
  if (!m) return null;
  const entetes = new Map(tete.slice(1).map((l) => [l.slice(0, l.indexOf(":")).trim().toLowerCase(), l.slice(l.indexOf(":") + 1).trim()]));
  let corps = brut.subarray(fin + 4);
  try {
    if ((entetes.get("transfer-encoding") ?? "").toLowerCase() === "chunked") corps = deChunk(corps);
    else if (entetes.has("content-length")) corps = corps.subarray(0, Number(entetes.get("content-length")));
  } catch {
    return null;
  }
  return { statut: Number(m[1]), corps: corps.toString("utf8") };
}

function deChunk(o) {
  const parties = [];
  let i = 0;
  while (i < o.length) {
    const fin = o.indexOf("\r\n", i);
    if (fin < 0) throw new Error("reponse illisible");
    const n = parseInt(o.subarray(i, fin).toString("latin1"), 16);
    if (!Number.isInteger(n)) throw new Error("reponse illisible");
    if (n === 0) break;
    parties.push(o.subarray(fin + 2, fin + 2 + n));
    i = fin + 2 + n + 2;
  }
  return Buffer.concat(parties);
}
