#!/usr/bin/env node
// Service `verificateur` de la démonstration de référence (CT-2 §19.1, §19.4) :
// il ne fait que vérifier. Il attend le dossier que l'enregistreur a exporté
// dans le volume des exports, qu'il monte en lecture seule, le vérifie hors
// ligne par le binaire `noortrace-verifier` (CT-6), imprime la sortie de CT-2
// §19.4 et se termine avec le code 0 si le dossier est valide, 1 sinon. Il
// n'a aucun réseau, ne demande rien à l'enregistreur et ne détient aucune clé.
//
//   verificateur-demo.mjs verifier
//
// Variables : `VERIFICATEUR_EXPORTS` (/var/lib/noortrace-exports),
// `VERIFICATEUR_DOSSIER` (par défaut : la destination que nomme le contexte,
// dossiers/seq-7 dans le scénario, sous le répertoire des exports),
// `VERIFICATEUR_CONTEXTE` (demonstration.json, sous le répertoire des
// exports), `VERIFICATEUR_ANCRES` (fichier d'ancres du réviseur),
// `VERIFICATEUR_BIN` (/usr/local/bin/noortrace-verifier),
// `VERIFICATEUR_ATTENTE_MAX_MS` (110000), `DEMO_ORGANISATION`,
// `DEMO_JOURNAL` (noms affichés de l'organisation et du journal).
//
// Durée imprimée (CT-2 EX-19.1) : du démarrage de ce processus à l'impression
// du résultat, sur l'horloge monotone du processus, en secondes à trois
// décimales. Le service démarre avec la composition et attend le dossier : la
// durée couvre donc la démonstration, de son lancement au verdict.

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

/** Contrôles de l'architecture attendus réussis et non exécutés dans la démonstration hors ligne (CT-6 §3). */
export const CONTROLES_REUSSIS = Object.freeze([1, 2, 3, 6, 7, 8]);
export const CONTROLES_HORS_LIGNE = Object.freeze([4, 5]);

/** `0x7099…79c8` : six premiers et quatre derniers caractères d'une adresse. */
export const abreger = (adresse) => `${adresse.slice(0, 6)}…${adresse.slice(-4)}`;

/** Secondes à trois décimales, virgule décimale. */
export const secondes = (ms) => (Math.round(ms) / 1000).toFixed(3).replace(".", ",");

/** `2026-11-10T10:00:00Z → 11:00:00Z`. */
export function periode(debutS, finS) {
  const iso = (s) => new Date(s * 1000).toISOString().replace(".000Z", "Z");
  return `${iso(debutS)} → ${iso(finS).slice(11)}`;
}

const liste = (elements) => (elements.length <= 1 ? elements.join("") : `${elements.slice(0, -1).join(", ")} et ${elements.at(-1)}`);

/**
 * Lignes de la sortie de CT-2 §19.4, d'après le rapport du vérificateur, le
 * dossier et le contexte écrit par l'exploitation de la démonstration.
 * `reference` dit si le dossier est celui que la démonstration attend :
 * verdict valide, contrôles 1, 2, 3, 6, 7 et 8 réussis, contrôles 4 et 5 non
 * exécutés pour partie absente, clé inscrite, période enregistrée et racine
 * ancrée prouvées par le dossier.
 * @returns {{lignes: string[], reference: boolean}}
 */
export function sortie({ rapport, contexte, evenement, organisation, journal, dossier, dureeMs }) {
  const controles = new Map(rapport.controls.map((c) => [c.number, c]));
  const reussis = rapport.controls.filter((c) => c.status === "reussi").map((c) => c.number);
  const nonExecutes = rapport.controls.filter((c) => c.status === "non_execute");
  const echoues = rapport.controls.filter((c) => c.status !== "reussi" && c.status !== "non_execute");
  const horsLigne = nonExecutes.length === CONTROLES_HORS_LIGNE.length && CONTROLES_HORS_LIGNE.every((n) => controles.get(n)?.status === "non_execute" && controles.get(n)?.reason === "partie_absente");
  const registre = rapport.facts?.registry ?? null;
  const roles = new Set((registre?.entries ?? []).map((e) => e.role));
  const signataires = (registre?.certificates ?? []).map((c) => c.signers.length);
  const approbation = rapport.facts?.approval ?? null;
  const reference = rapport.verdict === "valide" && CONTROLES_REUSSIS.every((n) => reussis.includes(n)) && horsLigne && echoues.length === 0 &&
    roles.has("inscription") && roles.has("cloture") && roles.has("ancre") && signataires.length > 0 && approbation?.decision === "approuve";
  const r = contexte.recorder;
  const lignes = [
    "noortrace — démonstration de référence",
    `  enregistreur    : ${evenement.code?.recorder ?? "version inconnue"}, clé ${rapport.facts?.recorder_keys?.event_key_id ?? "inconnue"} (classe ${r.class}, démonstration), bail ${r.lease_store}, époque ${r.epoch}`,
    `  journal         : ${organisation} / ${journal}, ${contexte.closure.count} événements, période ${periode(rapport.period.period_start, rapport.period.period_end)}`,
    `  registre-dev    : ${[
      roles.has("inscription") ? "clé inscrite (RecorderRegistry)" : "inscription de la clé non prouvée par le dossier",
      roles.has("cloture") ? "période enregistrée (PeriodRegistry)" : "période non enregistrée",
      roles.has("ancre") ? "racine ancrée (AttestationRegistry)" : "racine non ancrée",
      signataires.length ? `bloc certifié par ${Math.min(...signataires)} validateurs` : "aucun bloc certifié",
    ].join(", ")}`,
    `  dossier         : ${dossier}/ (${rapport.event.tool}, ${approbation ? `${approbation.decision === "approuve" ? "approuvé" : approbation.decision} par ${liste(approbation.approvers.map(abreger))}, seuil ${approbation.required} sur ${approbation.size}` : "sans approbation"})`,
    `  vérificateur    : ${reussis.length} contrôles [ok], ${nonExecutes.length} non exécutés avec raison admise (${horsLigne ? "T-*, O-* : démonstration hors ligne" : nonExecutes.map((c) => `contrôle ${c.number} : ${c.reason}`).join(" ; ") || "aucun"})${echoues.length ? `, ${echoues.length} en échec (${echoues.map((c) => c.number).join(", ")})` : ""}`,
  ];
  if (reference) {
    lignes.push(
      "  Résultat : VALIDE — cet événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste",
      "             signé par cette clé, approuvé par ces adresses, et son ancre est dans un bloc que les validateurs nommés ont signé.",
      "             Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne).",
    );
  } else {
    lignes.push(
      `  Résultat : ${String(rapport.verdict).toUpperCase()} — ${rapport.verdict === "valide" ? "le dossier est valide, mais il n'est pas celui que la démonstration attend" : "le dossier n'est pas vérifié"} : ${rapport.bound ?? "voir le rapport du vérificateur"}.`,
      `             ${horsLigne ? "Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne)." : "Ce que ce dossier ne prouve pas est dit par le rapport du vérificateur (contrôles non exécutés)."}`,
    );
  }
  lignes.push(
    "  Ce que l'agent n'a pas pu faire : joindre outils-demo ou modele-demo directement (réseaux séparés) ; obtenir",
    `  le résultat de payments.create avant qu'un événement durable existe ; effacer seq ${contexte.retained_seq} (sa demande retenue).`,
    `  Durée totale : ${secondes(dureeMs)} s`,
  );
  return { lignes, reference };
}

const attendre = (ms) => new Promise((r) => setTimeout(r, ms));

async function verifier() {
  const env = (nom, defaut) => process.env[nom] ?? defaut;
  const exports_ = env("VERIFICATEUR_EXPORTS", "/var/lib/noortrace-exports");
  const fichierContexte = path.join(exports_, env("VERIFICATEUR_CONTEXTE", "demonstration.json"));
  const attenteMax = Number(env("VERIFICATEUR_ATTENTE_MAX_MS", "110000"));
  const echec = (texte) => {
    process.stdout.write(`noortrace — démonstration de référence\n  Résultat : AUCUN VERDICT — ${texte}\n  Durée totale : ${secondes(performance.now())} s\n`);
    return 1;
  };
  // Un contexte déjà là au démarrage est celui d'un passage précédent : le journal est terminé (CT-2 EX-19.4), et ce
  // processus n'a pas vu la démonstration se dérouler. Il ne rend pas le verdict d'un autre passage sous sa propre durée.
  if (fs.existsSync(fichierContexte)) return echec("le volume des exports porte déjà le dossier d'un passage précédent : la démonstration se rejoue sur un nouveau journal (docker compose down --volumes, puis up).");
  // Le contexte est écrit par l'exploitation après l'export : sa présence dit que le dossier est en place.
  while (!fs.existsSync(fichierContexte)) {
    if (performance.now() > attenteMax) return echec(`aucun dossier exporté après ${secondes(attenteMax)} s : voir les journaux d'agent-demo, d'approbateur-demo et d'exploitation-demo.`);
    await attendre(200);
  }
  let contexte;
  let evenement;
  let dossierRelatif;
  let dossier;
  try {
    contexte = JSON.parse(fs.readFileSync(fichierContexte, "utf8"));
    // Le dossier à vérifier est celui que l'exploitation dit avoir fait exporter, sous le répertoire des exports.
    dossierRelatif = env("VERIFICATEUR_DOSSIER", contexte.export.destination);
    if (typeof dossierRelatif !== "string" || path.isAbsolute(dossierRelatif) || dossierRelatif.split("/").includes("..")) throw Object.assign(new Error("destination hors des exports"), { code: "destination_hors_exports" });
    dossier = path.join(exports_, dossierRelatif);
    evenement = JSON.parse(fs.readFileSync(path.join(dossier, "evenement.json"), "utf8"));
  } catch (e) {
    return echec(`dossier ou contexte illisible (${e.code ?? e.name}).`);
  }
  const r = spawnSync(env("VERIFICATEUR_BIN", "/usr/local/bin/noortrace-verifier"), [dossier, "--ancres", env("VERIFICATEUR_ANCRES", "/etc/noortrace-demo/ancres-demo.json"), "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  let rapport;
  try {
    rapport = JSON.parse(r.stdout);
  } catch {
    return echec(`le vérificateur n'a rendu aucun rapport (code ${r.status}) : ${(r.stderr ?? "").trim().split("\n")[0] ?? ""}`);
  }
  const s = sortie({ rapport, contexte, evenement, organisation: env("DEMO_ORGANISATION", "assureur-demo"), journal: env("DEMO_JOURNAL", "journal-demo"), dossier: dossierRelatif, dureeMs: performance.now() });
  process.stdout.write(`${s.lignes.join("\n")}\n`);
  return rapport.verdict === "valide" && r.status === 0 ? 0 : 1;
}

if (estProgramme(import.meta.url)) {
  if (process.argv[2] !== "verifier") {
    process.stderr.write("usage : verificateur-demo.mjs verifier\n");
    process.exit(2);
  }
  verifier().then((c) => process.exit(c), (e) => {
    process.stderr.write(`verificateur-demo : ${e.message}\n`);
    process.exit(1);
  });
}
