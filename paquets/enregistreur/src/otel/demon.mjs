// Point d'entrée OpenTelemetry dans le démon (CT-2 §3.4, §6.8) : ingestion
// et serveur OTLP/HTTP sur `otel.listen`, démarrés après le cœur (EX-15.4 pas
// 7) et arrêtés avant lui ; registre de recouvrement nourri par les
// scellements du cœur (EX-6.34 : appels du frontal MCP et du SDK, échanges du
// frontal modèle et du SDK).

import { VERSION_ENREGISTREUR } from "../coeur.mjs";
import { octetsLibres } from "../fichiers.mjs";
import { nomVuParLeModele } from "../modele/correlation.mjs";
import { origineAnnoncee } from "../modele/demon.mjs";
import { IngestionOtel } from "./ingestion.mjs";
import { ServeurOtel } from "./serveur.mjs";
import { RegistreRecouvrement } from "./tables.mjs";

/**
 * Jetons des sources (`otel.static_tokens`, EX-6.37) : identifiant → octets.
 * @param {object} config
 * @param {Map<string, Uint8Array>} secrets
 */
export function jetonsOtel(config, secrets) {
  const m = new Map();
  (config.otel?.static_tokens ?? []).forEach((t, k) => {
    const s = secrets.get(`/otel/static_tokens/${k}/token`);
    if (s) m.set(t.id, s);
  });
  return m;
}

/**
 * Raison de mode dégradé qui fait refuser une requête OTLP par `503`
 * (EX-6.39) : bail non détenu ou perdu, stockage, clé, horloge, attente ;
 * jamais le service d'approbation (sans effet sur l'ingestion).
 * @param {import("../coeur.mjs").Coeur} coeur
 * @returns {string|null}
 */
export function panneIngestion(coeur) {
  if (!coeur.bailDetenu) return "bail_non_detenu";
  if (coeur.intervention || !coeur.ecrivain) return "stockage";
  return coeur.degrade.raisons().find((r) => r !== "approbation") ?? null;
}

/**
 * Branche le registre de recouvrement sur les scellements du cœur (EX-6.34),
 * y compris ceux d'événements scellés depuis l'attente, démon en marche
 * (lecture 125) :
 * nom vu par le modèle d'un appel (gabarit et normalisation de sa connexion
 * d'hôte ; pour le SDK, le `tool` déclaré), partie de `code.model` qui suit
 * le premier `/` d'un échange.
 * @param {import("../coeur.mjs").Coeur} coeur
 * @param {RegistreRecouvrement} registre
 */
export function brancherRecouvrement(coeur, registre) {
  coeur.ecouterScellements(({ genre, host, appel, evenement }) => {
    if (!host || !evenement) return;
    const cfg = coeur.config;
    const t = coeur.horlogeBrute.monotone();
    const sdk = (cfg.sdk?.hosts ?? []).find((h) => h.id === host);
    if (genre === "appel") {
      // Appel scellé depuis l'attente (lecture 125) : le nom annoncé est
      // celui de l'événement (`execution.tool`).
      const annonce = appel?.tool_announced ?? evenement.execution?.tool;
      if (typeof annonce !== "string") return;
      if (sdk) {
        const nom = appel?.tool_original ?? (annonce.startsWith(`${sdk.alias}__`) ? annonce.slice(sdk.alias.length + 2) : annonce);
        return registre.inscrire({ genre: "appel", host_group: sdk.host_group, nom, t, seq: evenement.seq });
      }
      const h = (cfg.mcp?.hosts ?? []).find((x) => x.id === host);
      if (h) registre.inscrire({ genre: "appel", host_group: h.host_group, nom: nomVuParLeModele(annonce, h, origineAnnoncee(cfg, annonce)), t, seq: evenement.seq });
      return;
    }
    const h = sdk ?? (cfg.model?.hosts ?? []).find((x) => x.id === host);
    const m = evenement.code?.model;
    if (!h || typeof m !== "string") return;
    const k = m.indexOf("/");
    registre.inscrire({ genre: "echange", host_group: h.host_group, modele: k >= 0 ? m.slice(k + 1) : m, t, seq: evenement.seq });
  });
}

/**
 * Démarre l'ingestion OpenTelemetry, si `otel.enabled`.
 * @param {import("../coeur.mjs").Coeur} coeur
 * @param {Map<string, Uint8Array>} secrets
 * @param {{redacteur?: object|null}} [o]
 * @returns {Promise<{ingestion: IngestionOtel|null, serveur: ServeurOtel|null, arreter: () => Promise<void>}>}
 */
export async function demarrerOtel(coeur, secrets, o = {}) {
  const otel = coeur.config.otel;
  if (!otel?.enabled) return { ingestion: null, serveur: null, async arreter() {} };
  const r = o.redacteur ?? coeur.o?.redaction ?? null;
  const redacteur = r && typeof r.redigerPiece === "function" ? r : null;
  if (!redacteur) coeur.journal.consigner("warning", "redaction", "redaction_absente", { component: "otel" });
  const recouvrement = new RegistreRecouvrement({ fenetreMs: otel.overlap_window_ms });
  brancherRecouvrement(coeur, recouvrement);
  const ingestion = new IngestionOtel({
    config: () => coeur.config,
    journal: coeur.journal,
    metriques: coeur.metriques,
    redacteur,
    jetons: jetonsOtel(coeur.config, secrets),
    monotone: () => coeur.horlogeBrute.monotone(),
    ecrirePiece: (p) => coeur.ecrirePiece(p),
    sceller: (partiel) => coeur.scellerPartiel(partiel, { priorite: "basse" }),
    panne: () => panneIngestion(coeur),
    octetsLibres: () => octetsLibres(coeur.repertoire),
    version: () => ({ policy_version: coeur.versionPolitique, recorder: VERSION_ENREGISTREUR, nomRedaction: coeur.nomRedaction }),
    recouvrement,
  });
  const serveur = new ServeurOtel({ ingestion, config: () => coeur.config, journal: coeur.journal });
  await serveur.ecouter();
  const a = serveur.adresse();
  coeur.journal.consigner("info", "otel", "otel_listening", { address: a ? `${a.address}:${a.port}` : null, path: otel.path, tls: otel.tls !== null, sources: (otel.hosts ?? []).length });
  return { ingestion, serveur, arreter: () => serveur.fermer() };
}
