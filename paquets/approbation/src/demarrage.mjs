// Assemblage du service : configuration contrôlée, journal du service,
// empreinte du logiciel consignée au démarrage (CT-7 EX-3.10), magasin d'état
// relu (EX-7.23), machine, annuaire retenu dans l'ordre d'EX-13.38 et
// administrateurs recopiés (EX-13.37) avant toute écoute, notifications
// (13.19), lecteur du jeu, écoutes des deux canaux et de l'état (EX-10.12).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { ecrireHorodatage } from "@noortrace/noyau";
import { MagasinEtat } from "./persistance.mjs";
import { Machine } from "./tickets.mjs";
import { Supervision } from "./supervision.mjs";
import { EtatAnnuaire, annuaireDeDemarrage } from "./annuaire.mjs";
import { LecteurJeu } from "./lecteur-jeu.mjs";
import { ServiceApprobation } from "./service.mjs";
import { Ecoute, EcouteEtat } from "./transport.mjs";
import { Notificateur } from "./notifications.mjs";
import { jetonsDistincts, ErreurConfiguration } from "./configuration.mjs";
import { lireJsonStrict } from "./json.mjs";

const RACINE_PAQUET = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Empreinte du logiciel : SHA-256 des fichiers `src/`, `schemas/`, `bin/` et
 * `package.json` du paquet, dans l'ordre de leur chemin (CT-7 EX-3.10).
 */
export function empreinteLogiciel() {
  const h = createHash("sha256");
  const fichiers = [];
  for (const d of ["bin", "schemas", "src"]) {
    const dir = path.join(RACINE_PAQUET, d);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir).sort()) fichiers.push(`${d}/${f}`);
  }
  fichiers.push("package.json");
  for (const f of fichiers.sort()) {
    h.update(f + "\0");
    h.update(fs.readFileSync(path.join(RACINE_PAQUET, f)));
    h.update("\0");
  }
  return "0x" + h.digest("hex");
}

/**
 * Démarre le service.
 * @param {{config: object, secrets: {cle: Uint8Array, jetonNoyau: string|null, jetonConsole: string|null,
 *     jetonRpc?: string|null, cleWebhook?: string|null, caWebhook?: string|null,
 *     tls?: {noyau: object|null, console: object|null}},
 *   base?: string, horloge?: () => number, appelRpc?: (m: string, p: unknown[]) => Promise<unknown>,
 *   sortie?: (ligne: object) => void,
 *   essais?: {tirerNonce?: () => string|undefined, tailleBoite?: number, minuterie?: boolean,
 *     envoyer?: Function, compacterApres?: number}}} p
 *   `config` : document complété (`completer`) ; `secrets` : rendu de `resoudreSecrets` ;
 *   `essais` : réglages des essais seulement, qu'aucune configuration ne porte (nonce imposé
 *   à `preparer_inscription`, taille de rotation de la boîte, minuteries réelles coupées sous
 *   une horloge injectée, envoi des notifications remplacé, compactage après n lignes)
 * @returns {Promise<{service: ServiceApprobation, noyau: object, console: object|null, etat: object|null,
 *   arreter: () => Promise<void>}>}
 */
export async function demarrerService(p) {
  const c = p.config;
  const essais = p.essais ?? {};
  // EX-12.4, EX-10.12 (jetons_egaux par valeur), rapport d'EX-10.14
  if (!jetonsDistincts(p.secrets)) throw new ErreurConfiguration([{ code: "jetons_egaux", pointer: "/console/token" }]);
  const base = p.base ?? process.cwd();
  const horloge = p.horloge ?? Date.now;
  fs.mkdirSync(c.state_dir, { recursive: true, mode: 0o700 });
  const supervision = new Supervision({ journal: path.join(c.state_dir, "journal-service.ndjson"), horloge, sortie: p.sortie });
  supervision.consigner("demarrage", {
    environment: c.environment,
    empreinte: empreinteLogiciel(),
    pid: process.pid,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    node: process.version,
  });
  if (c.environment === "production" && typeof process.getuid === "function" && process.getuid() === 0) {
    throw new Error("le service ne s'exécute pas sous l'identité root en production (CT-7 EX-3.10)");
  }
  const magasin = new MagasinEtat({ repertoire: c.state_dir, cle: p.secrets.cle, compacterApres: essais.compacterApres });
  let docs;
  try {
    docs = await magasin.ouvrir();
  } catch (e) {
    await magasin.fermer().catch(() => {});
    throw e;
  }
  const fermer = async (e) => {
    await magasin.fermer().catch(() => {});
    await supervision.vider();
    throw e;
  };
  if (docs.tronque) supervision.consigner("reprise", { kind: "derniere_ligne_tronquee" });
  const vide = docs.meta === null && docs.tickets.length === 0;
  if (vide && c.tickets.epoch !== null) {
    supervision.consigner("avertissement", { kind: "etat_vide_epoque", epoque: c.tickets.epoch, message: "l'époque doit être nouvelle après une perte d'état (EX-7.1)" });
  }
  const machine = Machine.restaurer(
    {
      org_id: c.org_id,
      journal_id: c.journal_id,
      identifiants: c.tickets.epoch !== null ? { mode: "epoque", epoque: c.tickets.epoch } : { mode: "aleatoire" },
      max_open_tickets: c.max_open_tickets,
      escalation: c.escalation,
      administrators: c.administrators,
      // journal du service ; les causes de notification sont reprises par le service (13.19)
      evenement: (type, detail) => {
        if (type !== "notification") supervision.consigner(type, detail);
      },
    },
    docs,
  );
  // Annuaire (EX-13.38) : état persisté, amorce ou annuaire vide, puis recopie
  // d'administrators (EX-13.37), avant toute écoute du canal de la console.
  let retenu;
  try {
    retenu = annuaireDeDemarrage({
      persiste: { annuaire: docs.annuaire, defis: docs.defis },
      config: c,
      lireAmorce: () => lireJsonStrict(fs.readFileSync(path.resolve(base, c.console.annuaire))),
      at: ecrireHorodatage(Math.max(horloge(), machine.dernierAt ?? 0)),
      journal: (type, d) => supervision.consigner(type, d),
    });
  } catch (e) {
    return fermer(e);
  }
  const annuaire = new EtatAnnuaire(retenu);
  if (retenu.aEcrire) {
    try {
      await magasin.ajouter({ meta: machine.meta(), ...annuaire.exporter() });
    } catch (e) {
      return fermer(e);
    }
    if (retenu.changeAdministrateurs) {
      supervision.consigner("operation_annuaire", { methode: "changer_administrateurs", entry: null, revision: annuaire.document.revision });
    }
  }
  const notifications = new Notificateur({
    boite: path.join(c.state_dir, "notifications.ndjson"),
    console_origin: c.console_origin,
    horloge,
    journal: (type, d) => supervision.consigner(type, d),
    webhook: c.notifications
      ? { url: c.notifications.url, cle: p.secrets.cleWebhook, ca: p.secrets.caWebhook ?? null, timeout_ms: c.notifications.timeout_ms }
      : null,
    tailleBoite: essais.tailleBoite,
    envoyer: essais.envoyer,
    minuterie: essais.minuterie,
  });
  const lecteur = c.rpc || p.appelRpc
    ? new LecteurJeu({
      url: c.rpc?.url ?? "http://127.0.0.1:0",
      jeton: p.secrets.jetonRpc ?? null,
      timeout_ms: c.rpc?.timeout_ms ?? 5000,
      org_id: c.org_id,
      depuis_bloc: c.rpc?.logs_from_block ?? 0,
      adressesConnues: () => annuaire.adresses(),
      appel: p.appelRpc,
    })
    : null;
  const service = new ServiceApprobation({
    config: c, machine, magasin, supervision, lecteur, annuaire, notifications, horloge,
    tirerNonce: essais.tirerNonce, minuterie: essais.minuterie,
  });
  await service.demarrer();
  const tls = p.secrets.tls ?? { noyau: null, console: null };
  const noyau = new Ecoute({ canal: "noyau", service, config: c.noyau, tls: tls.noyau, jeton: p.secrets.jetonNoyau, bodyMax: c.body_max_bytes });
  const console_ = c.console
    ? new Ecoute({ canal: "console", service, config: c.console, tls: tls.console, jeton: p.secrets.jetonConsole, bodyMax: c.body_max_bytes })
    : null;
  const etat = c.etat ? new EcouteEtat({ service, tcp: c.etat }) : null;
  // une écoute qui ne s'ouvre pas : ecoute_impossible au pointeur de l'écoute (EX-10.14)
  let pointeur = "/noyau";
  try {
    await noyau.demarrer();
    pointeur = "/console";
    await console_?.demarrer();
    pointeur = "/etat";
    await etat?.demarrer();
  } catch (e) {
    await noyau.arreter().catch(() => {});
    await console_?.arreter().catch(() => {});
    await etat?.arreter().catch(() => {});
    await service.arreter();
    throw Object.assign(new ErreurConfiguration([{ code: "ecoute_impossible", pointer: pointeur }]), { cause: e });
  }
  supervision.consigner("ecoute", { noyau: noyau.adresse, console: console_?.adresse ?? null, etat: etat?.adresse ?? null });
  return {
    service,
    noyau: noyau.adresse,
    console: console_?.adresse ?? null,
    etat: etat?.adresse ?? null,
    async arreter() {
      await noyau.arreter();
      await console_?.arreter();
      await etat?.arreter();
      await service.arreter();
    },
  };
}
