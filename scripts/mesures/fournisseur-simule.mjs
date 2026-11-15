#!/usr/bin/env node
// Fournisseur de modèle simulé du harnais de mesure de CT-2 EX-16.2 (pas 2 et
// 5) : la forme documentée de `POST /v1/messages` de l'API Messages, hors flux
// et en flux SSE, sans clé ni modèle, sans dépendance. Ce n'est pas un modèle.
//
//   fournisseur-simule.mjs servir [--ecoute 127.0.0.1:8080] [--reponse-octets 16384]
//        [--intervalle-ms 50] [--evenements 6]
//
// Hors flux : une réponse `message` fixe de la taille demandée. En flux
// (`"stream": true`) : `message_start`, `content_block_start`, des
// `content_block_delta`, `content_block_stop`, `message_delta`,
// `message_stop`, soit `--evenements` événements en tout (6 au moins), un
// toutes les `--intervalle-ms` millisecondes (CT-2 §16.1 : un événement toutes
// les 50 ms), chacun remis au système par une écriture à part.
//
// Le numéro de l'échange est lu dans `metadata.user_id` de la requête
// (`mesure-<n>`). Mesure : pour chaque requête, sur l'horloge monotone du
// système (`process.hrtime.bigint()`), l'instant où elle est reçue en entier,
// l'instant où la réponse (hors flux) est remise au système, et, en flux,
// pour chaque écriture, son décalage dans le corps, sa longueur et son
// instant. `GET /mesures` les rend ; `POST /mesures/vider` les oublie.

import fs from "node:fs";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { remplissage, option } from "./serveur-nul.mjs";

export const MODELE = "modele-simule-1";

/** Réponse hors flux de `octets` octets (corps JSON entier) pour un numéro d'un chiffre. */
export function preparerMessage(octets) {
  const corps = (n, texte) => JSON.stringify({ id: `msg_mesure_${n}`, type: "message", role: "assistant", model: MODELE, content: [{ type: "text", text: texte }], stop_reason: "end_turn", stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } });
  const fixe = Buffer.byteLength(corps(0, ""));
  const texte = remplissage(Math.max(0, octets - fixe));
  return (n) => Buffer.from(corps(n, texte), "utf8");
}

/** Les événements SSE d'un flux de `nombre` événements (6 au moins), chacun en octets. */
export function evenementsFlux(n, nombre) {
  const ev = (type, donnees) => Buffer.from(`event: ${type}\ndata: ${JSON.stringify({ type, ...donnees })}\n\n`, "utf8");
  const deltas = Math.max(1, nombre - 5);
  const liste = [
    ev("message_start", { message: { id: `msg_mesure_${n}`, type: "message", role: "assistant", model: MODELE, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 1 } } }),
    ev("content_block_start", { index: 0, content_block: { type: "text", text: "" } }),
  ];
  for (let k = 0; k < deltas; k++) liste.push(ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: `morceau ${k + 1} sur ${deltas} ` } }));
  liste.push(ev("content_block_stop", { index: 0 }), ev("message_delta", { delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: deltas } }), ev("message_stop", {}));
  return liste;
}

export function creerFournisseur({ reponseOctets = 16384, intervalleMs = 50, evenements = 6 } = {}) {
  const message = preparerMessage(reponseOctets);
  const mesures = { echanges: [] };
  const json = (rep, statut, objet) => {
    const corps = Buffer.from(JSON.stringify(objet), "utf8");
    rep.writeHead(statut, { "Content-Type": "application/json", "Content-Length": corps.length }).end(corps);
  };
  const serveur = http.createServer((req, rep) => {
    const chemin = (req.url ?? "").split("?")[0];
    if (chemin === "/mesures" && req.method === "GET") return json(rep, 200, { echanges: mesures.echanges });
    if (chemin === "/mesures/vider" && req.method === "POST") {
      mesures.echanges.length = 0;
      return json(rep, 200, { ok: true });
    }
    if (chemin !== "/v1/messages") return json(rep, 404, { type: "error", error: { type: "not_found_error", message: "Not found" } });
    if (req.method !== "POST") return rep.writeHead(405, { Allow: "POST" }).end();
    const morceaux = [];
    req.on("data", (x) => morceaux.push(x));
    req.on("end", () => {
      const recu = process.hrtime.bigint();
      let m;
      try {
        m = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        return json(rep, 400, { type: "error", error: { type: "invalid_request_error", message: "Invalid JSON" } });
      }
      const n = Number(/^mesure-([0-9]+)$/.exec(m?.metadata?.user_id ?? "")?.[1] ?? -1);
      const entetes = { "request-id": `req_mesure_${n}` };
      if (m?.stream !== true) {
        const corps = message(n);
        rep.writeHead(200, { "Content-Type": "application/json", "Content-Length": corps.length, ...entetes }).end(corps);
        mesures.echanges.push({ n, flux: false, recu_ns: String(recu), repondu_ns: String(process.hrtime.bigint()) });
        return undefined;
      }
      const liste = evenementsFlux(n, evenements);
      const ecritures = [];
      rep.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", ...entetes });
      rep.flushHeaders();
      let k = 0;
      let decalage = 0;
      const debut = process.hrtime.bigint();
      const suivant = () => {
        const octets = liste[k];
        rep.write(octets);
        ecritures.push({ decalage, octets: octets.length, emis_ns: String(process.hrtime.bigint()) });
        decalage += octets.length;
        k += 1;
        if (k === liste.length) {
          rep.end();
          mesures.echanges.push({ n, flux: true, recu_ns: String(recu), ecritures });
          return;
        }
        // Cadence fixe depuis le début du flux : un retard d'une écriture ne décale pas les suivantes.
        const attente = Number(debut + BigInt(k) * BigInt(Math.round(intervalleMs * 1e6)) - process.hrtime.bigint()) / 1e6;
        setTimeout(suivant, Math.max(0, attente));
      };
      suivant();
      return undefined;
    });
  });
  serveur.keepAliveTimeout = 0;
  return { serveur, mesures };
}

function principal(args) {
  if (args[0] !== "servir") {
    process.stderr.write("usage : fournisseur-simule.mjs servir [--ecoute hôte:port] [--reponse-octets n] [--intervalle-ms n] [--evenements n]\n");
    process.exit(2);
  }
  const [hote, port] = option(args, "--ecoute", "127.0.0.1:8080").split(":");
  const reponseOctets = Number(option(args, "--reponse-octets", "16384"));
  const intervalleMs = Number(option(args, "--intervalle-ms", "50"));
  const evenements = Number(option(args, "--evenements", "6"));
  if (!Number.isInteger(reponseOctets) || reponseOctets < 0 || !(intervalleMs >= 0) || !Number.isInteger(evenements) || evenements < 6) {
    process.stderr.write("--reponse-octets : entier positif ; --intervalle-ms : nombre positif ; --evenements : entier d'au moins 6\n");
    process.exit(2);
  }
  const { serveur } = creerFournisseur({ reponseOctets, intervalleMs, evenements });
  serveur.listen(Number(port), hote, () => process.stdout.write(`${JSON.stringify({ service: "fournisseur-simule", event: "ecoute", hote, port: serveur.address().port, reponse_octets: reponseOctets, intervalle_ms: intervalleMs, evenements })}\n`));
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => {
    serveur.close(() => process.exit(0));
    serveur.closeAllConnections();
  });
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) principal(process.argv.slice(2));
