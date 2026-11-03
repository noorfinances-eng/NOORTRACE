// Assemblage du service : configuration contrôlée, journal et notifications,
// empreinte du logiciel consignée au démarrage (CT-7 EX-3.10), magasin d'état
// relu (EX-7.23), machine, annuaire, lecteur du jeu, écoutes des deux canaux.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { MagasinEtat } from "./persistance.mjs";
import { Machine } from "./tickets.mjs";
import { Supervision } from "./supervision.mjs";
import { Annuaire } from "./annuaire.mjs";
import { LecteurJeu } from "./lecteur-jeu.mjs";
import { ServiceApprobation } from "./service.mjs";
import { Ecoute } from "./transport.mjs";
import { jetonsDistincts } from "./configuration.mjs";

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
 * @param {{config: object, secrets: {cle: Uint8Array, jetonNoyau: string|null, jetonConsole: string|null},
 *   base?: string, horloge?: () => number, appelRpc?: (m: string, p: unknown[]) => Promise<unknown>,
 *   sortie?: (ligne: object) => void}} p
 * @returns {Promise<{service: ServiceApprobation, noyau: object, console: object|null, arreter: () => Promise<void>}>}
 */
export async function demarrerService(p) {
  const c = p.config;
  // EX-12.4 : jeton de la console distinct de celui du noyau, comparé par valeur.
  if (!jetonsDistincts(p.secrets)) throw new Error("jeton de la console égal à celui du noyau (EX-12.4)");
  const base = p.base ?? process.cwd();
  const horloge = p.horloge ?? Date.now;
  fs.mkdirSync(c.state_dir, { recursive: true, mode: 0o700 });
  const supervision = new Supervision({
    journal: path.join(c.state_dir, "journal-service.ndjson"),
    notifications: path.join(c.state_dir, "notifications.ndjson"),
    console_origin: c.console_origin,
    horloge,
    sortie: p.sortie,
  });
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
  const magasin = new MagasinEtat({ repertoire: c.state_dir, cle: p.secrets.cle });
  let docs;
  try {
    docs = await magasin.ouvrir();
  } catch (e) {
    await magasin.fermer().catch(() => {});
    throw e;
  }
  if (docs.tronque) supervision.consigner("reprise", { kind: "derniere_ligne_tronquee" });
  const vide = docs.meta === null && docs.tickets.length === 0;
  if (vide && c.tickets.epoch !== null) {
    supervision.consigner("avertissement", { kind: "etat_vide_epoque", epoque: c.tickets.epoch, message: "l'époque doit être nouvelle après une perte d'état (EX-7.1)" });
  }
  const evenement = (type, detail) => {
    if (type === "notification") supervision.notifier(detail);
    else supervision.consigner(type, detail);
  };
  const machine = Machine.restaurer(
    {
      org_id: c.org_id,
      journal_id: c.journal_id,
      identifiants: c.tickets.epoch !== null ? { mode: "epoque", epoque: c.tickets.epoch } : { mode: "aleatoire" },
      max_open_tickets: c.max_open_tickets,
      escalation: c.escalation,
      administrators: c.administrators,
      evenement,
    },
    docs,
  );
  let annuaire;
  if (c.console?.annuaire) {
    annuaire = Annuaire.lire(path.resolve(base, c.console.annuaire));
    if (annuaire.document.org_id !== c.org_id) throw new Error("annuaire d'une autre organisation");
    if (JSON.stringify(annuaire.administrators) !== JSON.stringify(c.administrators)) {
      // le réglage de configuration fait foi (13.4) ; la recopie est une opération de l'étape 6
      supervision.consigner("avertissement", { kind: "administrateurs_differents_de_l_annuaire" });
      annuaire.document.administrators = [...c.administrators];
    }
  } else {
    annuaire = Annuaire.vide(c.org_id, c.administrators);
  }
  const lecteur = c.rpc || p.appelRpc
    ? new LecteurJeu({
      url: c.rpc?.url ?? "http://127.0.0.1:0",
      timeout_ms: c.rpc?.timeout_ms ?? 5000,
      org_id: c.org_id,
      depuis_bloc: c.rpc?.logs_from_block ?? 0,
      adressesConnues: () => annuaire.adresses(),
      appel: p.appelRpc,
    })
    : null;
  const service = new ServiceApprobation({ config: c, machine, magasin, supervision, lecteur, annuaire, horloge });
  await service.demarrer();
  const noyau = new Ecoute({ canal: "noyau", service, config: c.noyau, jeton: p.secrets.jetonNoyau, bodyMax: c.body_max_bytes, base });
  const console_ = c.console
    ? new Ecoute({ canal: "console", service, config: c.console, jeton: p.secrets.jetonConsole, bodyMax: c.body_max_bytes, base })
    : null;
  try {
    await noyau.demarrer();
    await console_?.demarrer();
  } catch (e) {
    await noyau.arreter().catch(() => {});
    await service.arreter();
    throw e;
  }
  supervision.consigner("ecoute", { noyau: noyau.adresse, console: console_?.adresse ?? null });
  return {
    service,
    noyau: noyau.adresse,
    console: console_?.adresse ?? null,
    async arreter() {
      await noyau.arreter();
      await console_?.arreter();
      await service.arreter();
    },
  };
}
