// Famille notifications/ des vecteurs de CT-3 (13.19 ; EX-13.40, EX-13.41) :
// un document de notification par nature (`kind`), son corps envoyé au
// webhook (le JCS du document, en UTF-8, qui est aussi la ligne de la boîte
// d'envoi) et l'en-tête NOORTRACE-Signature de la requête :
//
//   sha256=<64 chiffres hexadécimaux de HMAC-SHA256(K, P ‖ corps)>
//   P = octets UTF-8 de "noortrace/notification/v0\n"
//   K = le secret notifications.key, espaces de tête et de fin retirés, en octets ASCII
//
// puis des corps que le relais du client refuse parce que leur MAC diffère
// (corps altéré, préfixe omis, autre clé, clé non dépouillée de ses espaces).
//
// Tout est déterministe (EX-A.1) : les identifiants `ntf-…`, tirés au hasard
// par le service, sont ici les 32 premiers chiffres du SHA-256 d'une étiquette ;
// les instants sont fixés ; la clé est celle de l'exemple d'EX-13.41, qui n'est
// pas tirée au hasard et n'est valable nulle part. Aucun document ne porte
// d'identité de personne (EX-13.11) : identifiants de ticket et d'entrée, nom
// d'outil, adresses des comptes de test, empreintes, rôles et instants.
//
// L'exemple du texte (EX-13.40, EX-13.41) est relu dans CT-3 et recalculé : son
// corps de 472 octets et sa signature doivent être ceux que le texte imprime ;
// un écart arrête la génération. Il n'est pas recopié dans les vecteurs.
//
// Le MAC est calculé ici avec node:crypto, sans rien importer du service
// d'approbation, que les essais confrontent à ces vecteurs.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "../../lib/journal.mjs";

const REPERTOIRE_SCHEMAS = path.join(fileURLToPath(new URL("../../../", import.meta.url)), "spec", "schemas");
/** Les schémas que `$defs/notification` de configuration-approbation-v0 référence, et lui. */
const FICHIERS_SCHEMAS_NOTIFICATION = ["evenement-v0.schema.json", "ticket-v0.schema.json", "annuaire-approbateurs-v0.schema.json", "configuration-approbation-v0.schema.json"];
const ID_SCHEMA = "https://noortrace.example/schemas/v0/configuration-approbation.schema.json";

/** Préfixe de domaine du MAC d'une notification, P (EX-13.41). */
export const PREFIXE_NOTIFICATION = "noortrace/notification/v0\n";
/** Clé de l'exemple d'EX-13.41 (49 caractères) : ni tirée au hasard, ni valable où que ce soit. */
export const CLE_EXEMPLE_NOTIFICATION = "noortrace/exemple/cle-de-webhook/0123456789abcdef";
/** Seconde clé des refus : même forme, autre valeur. */
export const AUTRE_CLE_NOTIFICATION = "noortrace/exemple/cle-de-webhook/fedcba9876543210";
/** Étiquette dont le SHA-256 donne l'identifiant d'une notification des vecteurs. */
export const ETIQUETTE_NOTIFICATION = (cas) => `noortrace/vecteurs/ct3/notification/${cas}`;
/** Outil et ticket des cas : noms des vecteurs de CT-3, sans lien avec l'exemple du texte. */
const OUTIL = "crm.claims.delete";
const TICKET = "apr-0001";
const ECHEANCE = "2026-11-10T12:00:00.000Z";

const exiger = (condition, message) => {
  if (!condition) throw new Error(`generer-ct3 : ${message}`);
};

/** Le validateur de `$defs/notification`, avec les schémas qu'il référence. */
export function validateurNotification(repertoire = REPERTOIRE_SCHEMAS) {
  const registre = J.registreSchemas(FICHIERS_SCHEMAS_NOTIFICATION.map((f) => JSON.parse(fs.readFileSync(path.join(repertoire, f), "utf8"))));
  return (document) => J.validerSchema(document, registre[ID_SCHEMA], { registre, fragment: "#/$defs/notification" });
}

/** Les octets de la clé K : le secret, espaces de tête et de fin retirés, en ASCII (EX-13.41). */
export function cleNotification(secret) {
  const k = secret.trim();
  exiger(/^[\x20-\x7e]{32,1024}$/.test(k), "clé de notification : 32 à 1 024 caractères ASCII imprimables attendus");
  return Buffer.from(k, "ascii");
}

/** Les 64 chiffres hexadécimaux de HMAC-SHA256(K, P ‖ corps) (EX-13.41) ; `prefixe` vide : MAC sans séparation de domaine, pour les refus. */
export function macNotification(secret, corps, { prefixe = PREFIXE_NOTIFICATION, depouiller = true } = {}) {
  const cle = depouiller ? cleNotification(secret) : Buffer.from(secret, "ascii");
  return crypto.createHmac("sha256", cle).update(Buffer.from(prefixe, "utf8")).update(corps).digest("hex");
}

/** L'exemple annoté d'EX-13.40, relu dans le texte de CT-3. */
function exempleDuTexte(MD) {
  const m = /<!-- exemple: configuration-approbation\/notification -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(m, "CT-3 : exemple annoté configuration-approbation/notification absent");
  const signature = /porte `NOORTRACE-Signature:\s+sha256=([0-9a-f]{64})`/.exec(MD);
  exiger(signature, "CT-3 : signature de l'exemple d'EX-13.41 absente");
  const taille = /Son corps envoyé, le JCS de ce document, fait (\d+) octets/.exec(MD);
  exiger(taille, "CT-3 : taille du corps de l'exemple d'EX-13.40 absente");
  exiger(MD.includes(`\`${CLE_EXEMPLE_NOTIFICATION}\``), "CT-3 : clé de l'exemple d'EX-13.41 absente");
  return { document: JSON.parse(m[1]), signature: signature[1], taille: Number(taille[1]) };
}

/**
 * La famille notifications/. `ctx` : { ADR (adresse du compte de test i),
 * ORIGINE (console_origin de l'annuaire des vecteurs), MD (texte de CT-3) }.
 * Rend { fichier (notifications.json), exemple (contrôle de l'exemple du texte) }.
 */
export function familleNotifications({ ADR, ORIGINE, MD }) {
  const valider = validateurNotification();
  const ecran = `${ORIGINE}/tickets/${TICKET}`;
  const ident = (cas) => `ntf-${J.sha256(Buffer.from(ETIQUETTE_NOTIFICATION(cas), "utf8")).slice(2, 34)}`;
  const dA = J.sha256(Buffer.from("noortrace/vecteurs/ct3/notification/d_a", "utf8")).slice(2);
  const empreinte = `${dA.slice(0, 8)}…${dA.slice(56)}`;
  const doc = (cas, kind, created_at, recipients, { ticket = TICKET, tool = OUTIL, deadline = ECHEANCE, link = ecran, details = null } = {}) => ({ version: 0, id: ident(cas), kind, created_at, recipients, ticket, tool, deadline, link, details });
  const D = (heure) => `2026-11-10T${heure}Z`;
  const sansTicket = { ticket: null, tool: null, deadline: null };

  // [identifiant du cas, ce qu'il exerce, document]
  const conception = [
    ["ouverture", "Premier gel du jeu du ticket (EX-7.12) : les entrées actives dont l'adresse active est un membre éligible ; details nul.", doc("ouverture", "ouverture", D("11:00:00.000"), { entries: ["apb-0001", "apb-0002"], roles: [] })],
    ["escalade-jeu", "Étape d'escalade de cible jeu (EX-7.13) : les entrées dont l'adresse active est un membre éligible sans vote courant.", doc("escalade-jeu", "escalade", D("11:20:00.000"), { entries: ["apb-0002"], roles: [] })],
    ["escalade-administrateur", "Étape d'escalade de cible administrateur : le rôle administrateur_jeu, sans aucune entrée.", doc("escalade-administrateur", "escalade", D("11:40:00.000"), { entries: [], roles: ["administrateur_jeu"] })],
    ["escalade-demandeur", "Étape d'escalade de cible demandeur : l'entrée active dont requester_identities contient le launched_by du ticket ; le document ne porte pas cette identité.", doc("escalade-demandeur", "escalade", D("11:50:00.000"), { entries: ["apb-0003"], roles: [] })],
    ["nouveau-gel", "Nouveau gel qui change le jeu figé (EX-8.6) : membres éligibles après le gel ; details porte l'adresse ajoutée depuis l'ouverture et le seuil effectif.", doc("nouveau-gel", "nouveau_gel", D("11:05:00.000"), { entries: ["apb-0001", "apb-0002", "apb-0003"], roles: [] }, { details: { added_members: [ADR(3)], effective_required: 2 } })],
    ["seuil-inatteignable", "Moins de membres éligibles que le seuil effectif (EX-7.29) : les rôles administrateur_jeu et administrateur.", doc("seuil-inatteignable", "seuil_inatteignable", D("11:06:00.000"), { entries: [], roles: ["administrateur_jeu", "administrateur"] }, { details: { eligible_count: 1, effective_required: 2 } })],
    ["vote-inscrit", "Vote accepté sur le canal de la console (EX-12.16) : l'entrée dont l'adresse active est approver ; digest est l'empreinte de D_A (EX-9.18), dont le caractère U+2026 compte trois octets dans le corps.", doc("vote-inscrit", "vote_inscrit", D("11:10:00.000"), { entries: ["apb-0001"], roles: [] }, { details: { approver: ADR(1), decision: "approuve", digest: empreinte, at: D("11:10:00.000") } })],
    ["vote-inscrit-refus", "Vote de refus : même forme, decision refuse ; le motif du vote n'est jamais dans le document.", doc("vote-inscrit-refus", "vote_inscrit", D("11:12:00.000"), { entries: ["apb-0002"], roles: [] }, { details: { approver: ADR(2), decision: "refuse", digest: empreinte, at: D("11:12:00.000") } })],
    ["operation-annuaire-valider", "Opération valider acceptée, faite par un administrateur : l'entrée visée ; ticket, tool et deadline nuls ; lien vers l'écran d'inscription ; by_self faux.", doc("operation-annuaire-valider", "operation_annuaire", D("09:40:00.000"), { entries: ["apb-0002"], roles: [] }, { ...sansTicket, link: `${ORIGINE}/inscription`, details: { op: "valider", entry: "apb-0002", address: ADR(2), revision: 4, at: D("09:40:00.000"), by_self: false } })],
    ["operation-annuaire-inscrire", "Opération inscrire acceptée, faite par la session de l'entrée elle-même : by_self vrai.", doc("operation-annuaire-inscrire", "operation_annuaire", D("09:35:00.000"), { entries: ["apb-0002"], roles: [] }, { ...sansTicket, link: `${ORIGINE}/inscription`, details: { op: "inscrire", entry: "apb-0002", address: ADR(2), revision: 3, at: D("09:35:00.000"), by_self: true } })],
    ["operation-annuaire-desactiver", "Opération desactiver, sans adresse : address nul.", doc("operation-annuaire-desactiver", "operation_annuaire", D("10:40:00.000"), { entries: ["apb-0002"], roles: [] }, { ...sansTicket, link: `${ORIGINE}/inscription`, details: { op: "desactiver", entry: "apb-0002", address: null, revision: 9, at: D("10:40:00.000"), by_self: false } })],
    ["plafond-atteint", "Premier evaluer refusé par plafond_atteint d'un launched_by dans une période de 15 minutes (EX-14.1) : le rôle administrateur ; ticket, tool, deadline et link nuls ; le document ne porte pas le launched_by.", doc("plafond-atteint", "plafond_atteint", D("11:30:00.000"), { entries: [], roles: ["administrateur"] }, { ...sansTicket, link: null, details: { max_open_tickets: 20 } })],
  ];

  const cases = conception.map(([id, description, document]) => {
    const erreurs = valider(document);
    exiger(erreurs.length === 0, `notifications ${id} : document non conforme à $defs/notification ${JSON.stringify(erreurs.slice(0, 2))}`);
    const corps = J.octetsJCS(document);
    return { id, description, checks: ["EX-13.40", "EX-13.41"], document, expected: { body: corps.toString("utf8"), body_size: corps.length, body_sha256: J.sha256(corps), signature: `sha256=${macNotification(CLE_EXEMPLE_NOTIFICATION, corps)}` } };
  });
  exiger(new Set(cases.map((c) => c.document.id)).size === cases.length, "notifications : identifiants en double");
  for (const kind of ["ouverture", "escalade", "nouveau_gel", "seuil_inatteignable", "vote_inscrit", "operation_annuaire", "plafond_atteint"]) exiger(cases.some((c) => c.document.kind === kind), `notifications : nature ${kind} sans cas`);
  // Aucune identité de personne (EX-13.11) : ni identité de session, ni launched_by, ni alias.
  for (const c of cases) exiger(!/oidc |@|launched_by|session_identity|display_name|external_id|reason/.test(c.expected.body), `notifications ${c.id} : le corps porte une identité de personne ou un motif`);

  // Corps que le relais refuse : le MAC présenté n'est pas celui que le relais recalcule sur les octets reçus.
  const base = cases.find((c) => c.id === "vote-inscrit");
  const corpsBase = Buffer.from(base.expected.body, "utf8");
  const altere = Buffer.from(base.expected.body.replace('"decision":"approuve"', '"decision":"refuse"'), "utf8");
  exiger(!altere.equals(corpsBase), "notifications : corps altéré identique");
  const refus = [
    ["corps-altere", "Le corps de vote-inscrit dont la décision a été changée en chemin, avec la signature du corps d'origine.", altere, base.expected.signature],
    ["prefixe-omis", "Le corps de vote-inscrit signé sans le préfixe « noortrace/notification/v0\\n » : HMAC-SHA256(K, corps).", corpsBase, `sha256=${macNotification(CLE_EXEMPLE_NOTIFICATION, corpsBase, { prefixe: "" })}`],
    ["autre-cle", "Le corps de vote-inscrit signé par une autre clé.", corpsBase, `sha256=${macNotification(AUTRE_CLE_NOTIFICATION, corpsBase)}`],
    ["cle-avec-saut-de-ligne", "Le corps de vote-inscrit signé par la clé suivie d'un saut de ligne, comme un fichier de secret la porte : K est le secret dépouillé de ses espaces de tête et de fin (EX-13.41).", corpsBase, `sha256=${macNotification(`${CLE_EXEMPLE_NOTIFICATION}\n`, corpsBase, { depouiller: false })}`],
  ].map(([id, description, corps, signature]) => {
    const attendue = `sha256=${macNotification(CLE_EXEMPLE_NOTIFICATION, corps)}`;
    exiger(signature !== attendue, `notifications, refus ${id} : la signature présentée est la bonne`);
    return { id, description, checks: ["EX-13.41"], body: corps.toString("utf8"), signature, expected: { accepted: false, signature: attendue } };
  });
  // La clé d'un fichier de secret, avec son saut de ligne final, donne bien la signature des cas une fois dépouillée.
  exiger(macNotification(`  ${CLE_EXEMPLE_NOTIFICATION}\n`, corpsBase) === base.expected.signature.slice(7), "notifications : clé dépouillée");

  // L'exemple du texte : corps de la taille imprimée, signature imprimée.
  const ex = exempleDuTexte(MD);
  exiger(valider(ex.document).length === 0, "notifications : l'exemple d'EX-13.40 n'est pas conforme à $defs/notification");
  const corpsEx = J.octetsJCS(ex.document);
  exiger(corpsEx.length === ex.taille, `notifications : le corps de l'exemple d'EX-13.40 fait ${corpsEx.length} octets, ${ex.taille} dans le texte`);
  exiger(MD.includes(`\`\`\`text\n${corpsEx.toString("utf8")}\n\`\`\``), "notifications : le corps imprimé par EX-13.40 n'est pas le JCS de son document");
  exiger(macNotification(CLE_EXEMPLE_NOTIFICATION, corpsEx) === ex.signature, "notifications : la signature de l'exemple d'EX-13.41 n'est pas celle du texte");

  const fichier = {
    version: 0,
    prefix: PREFIXE_NOTIFICATION,
    prefix_hex: Buffer.from(PREFIXE_NOTIFICATION, "utf8").toString("hex"),
    key: CLE_EXEMPLE_NOTIFICATION,
    header: "NOORTRACE-Signature",
    cases,
    refusals: refus,
  };
  return { fichier, exemple: { taille: corpsEx.length, signature: `sha256=${ex.signature}` } };
}
