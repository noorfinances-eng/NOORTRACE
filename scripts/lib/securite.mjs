// Implémentation de référence de la spécification CT-7 de NOORTRACE
// (spec/CT-7-securite-et-conformite.md), partie « attestation de périmètre »
// (section 7), et de sa vérification dans un dossier (CT-1 révision 0.4,
// §11.2 et §11.4, vérifications AT-1 à AT-7 ; CT-6 révision 0.3, section 5.5).
//
// L'attestation est une DÉCLARATION du client : la vérifier établit qui l'a
// signée, que son texte n'a pas changé, qu'elle nomme l'organisation et le
// journal de l'événement et, avec son inscription, où elle se place dans le
// journal ; jamais que le périmètre déclaré est exact (CT-7 EX-7.1).
//
//   P_P  = UTF-8("noortrace/attestation-perimetre/v0\n")       35 octets
//   D_P  = keccak256(P_P ‖ JCS(P))                             JCS v0 de CT-1 §4
//   M    = keccak256("\x19Ethereum Signed Message:\n32" ‖ D_P) EIP-191 version 0x45
//
// Dépendances : scripts/lib/journal.mjs (JCS v0, analyse JSON stricte, schémas,
// SHA-256, contrôles d'événement) et scripts/lib/console.mjs (Keccak-256,
// EIP-191, recouvrement secp256k1) ; ethers seulement pour signer avec un
// portefeuille. Aucun accès au réseau ; le système de fichiers n'est lu que
// par schemasAttestation(), pour charger les schémas de spec/schemas quand
// l'appelant ne les fournit pas.
//
// journal.mjs importe ce module pour la quatorzième partie du dossier ; les
// deux modules s'importent mutuellement : aucune valeur de journal.mjs n'est
// lue au chargement de ce module, seulement dans ses fonctions.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, Signature, SigningKey } from "ethers";
import * as J from "./journal.mjs";
import * as C from "./console.mjs";

// ---------------------------------------------------------------------------
// Constantes (CT-7 §7.2, CT-1 §11.2, CT-6 EX-4.15)
// ---------------------------------------------------------------------------

/** Préfixe de domaine de l'attestation de périmètre, P_P (CT-7 EX-7.6, EX-7.7). */
export const PREFIXE_ATTESTATION = "noortrace/attestation-perimetre/v0\n";
/** P_P en hexadécimal, sans 0x (constante prefix_hex du schéma des vecteurs). */
export const PREFIXE_ATTESTATION_HEX = Buffer.from(PREFIXE_ATTESTATION, "utf8").toString("hex");

/** $id du schéma de l'attestation (CT-7 §7.1). */
export const ID_SCHEMA_ATTESTATION_PERIMETRE = "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json";

/** Limite de la partie attestation-perimetre.json (CT-6 EX-4.15) : 4 Mio. */
export const LIMITE_PARTIE_ATTESTATION = 4 * 1024 * 1024;
/** Limite du document de politique embarqué, octets décodés (CT-1 §11.2, CT-6 EX-4.15). */
export const LIMITE_DOCUMENT_POLITIQUE = 2097152;
/**
 * Plafond absolu de lecture de la partie pour D-2 (CT-6 EX-4.15) : 64 Mio.
 * Au-delà de 4 Mio la partie n'est pas analysée (AT-1 échoue) ; au-delà de
 * 64 Mio son SHA-256 n'est pas calculé et l'entrée est inutilisable (code 2).
 */
export const PLAFOND_LECTURE_ATTESTATION = 64 * 1024 * 1024;
/** Durée maximale de la validité d'une attestation (CT-7 EX-7.2, AT-1) : 366 jours, en millisecondes. */
export const DUREE_MAX_VALIDITE_MS = 366 * 86400000;

/** Ordre des canaux de capture (CT-6 EX-6.20, facts.perimeter.capture_channels). */
export const ORDRE_CANAUX = Object.freeze(["mandataire_mcp", "passerelle", "icap", "miroir", "sdk", "opentelemetry"]);

/** Les vérifications de la partie, dans l'ordre du rapport, avec le contrôle sous lequel CT-6 les range (EX-5.10). */
export const VERIFICATIONS_AT = Object.freeze([
  { id: "AT-1", controls: [7] },
  { id: "AT-2", controls: [7] },
  { id: "AT-3", controls: [7] },
  { id: "AT-4", controls: [7] },
  { id: "AT-5", controls: [7] },
  { id: "AT-6", controls: [6] },
  { id: "AT-7", controls: [6] },
]);
export const IDS_AT = Object.freeze(VERIFICATIONS_AT.map((v) => v.id));

/** Libellés des vérifications AT- (CT-6 §8.4, révision 0.3). */
export const LIBELLES_AT = Object.freeze({
  "AT-1": { fr: "forme de l'attestation de périmètre", en: "form of the perimeter attestation" },
  "AT-2": { fr: "condensé de l'attestation", en: "attestation digest" },
  "AT-3": { fr: "signatures de l'attestation", en: "attestation signatures" },
  "AT-4": { fr: "signataires membres du jeu déclaré, seuil", en: "signers in the declared set, threshold" },
  "AT-5": { fr: "organisation, journal et validité de l'attestation", en: "organisation, journal and validity of the attestation" },
  "AT-6": { fr: "inscription de l'attestation au journal", en: "attestation recorded in the journal" },
  "AT-7": { fr: "politique en vigueur pour l'événement", en: "policy in force for the event" },
});

const MOITIE_N = C.N_SECP256K1 / 2n;
const RE_SIGNATURE = /^0x[0-9a-f]{130}$/;
const RE_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const T = (fr, en = fr) => ({ fr, en });
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const resumer = (erreurs) => erreurs.slice(0, 4).map((e) => (typeof e === "string" ? e : `${e.chemin || "/"} : ${e.message}`)).join(" ; ") + (erreurs.length > 4 ? ` ; … (${erreurs.length})` : "");

// ---------------------------------------------------------------------------
// Schémas
// ---------------------------------------------------------------------------

const RACINE_SCHEMAS = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "spec", "schemas");
let schemasParDefaut = null;

/**
 * Registre des cinq schémas dont la partie a besoin (evenement, manifeste,
 * dossier, point-de-controle, attestation-perimetre), lus une fois dans
 * spec/schemas (ou dans `repertoire`).
 */
export function schemasAttestation(repertoire = null) {
  if (!repertoire && schemasParDefaut) return schemasParDefaut;
  const rep = repertoire ?? RACINE_SCHEMAS;
  const registre = J.registreSchemas(["evenement", "manifeste", "dossier", "point-de-controle", "attestation-perimetre"].map((n) => JSON.parse(fs.readFileSync(path.join(rep, `${n}-v0.schema.json`), "utf8"))));
  if (!repertoire) schemasParDefaut = registre;
  return registre;
}

// ---------------------------------------------------------------------------
// Condensé, message, signature (CT-7 §7.2, EX-7.6)
// ---------------------------------------------------------------------------

/** D_P = keccak256(P_P ‖ JCS(P)), en hexadécimal 0x. Lève ErreurFormat si JCS(P) n'est pas calculable. */
export function condenseAttestation(P) {
  return C.enHex(C.keccak256(C.concat(C.utf8(PREFIXE_ATTESTATION), J.octetsJCS(P))));
}

/** M = keccak256("\x19Ethereum Signed Message:\n32" ‖ D_P), en hexadécimal 0x (CT-1 §6.3 avec D_P à la place de D_A). */
export function messageAttestation(D_P) {
  return C.enHex(C.condenseEIP191(C.depuisHex(D_P)));
}

/**
 * Signature EIP-191 de D_P par un portefeuille ethers (RFC 6979, s bas,
 * v = 27 + recid) : identique à wallet.signMessage(getBytes(D_P)).
 */
export function signerAttestation(wallet, P) {
  return Signature.from(wallet.signingKey.sign(messageAttestation(condenseAttestation(P)))).serialized;
}

/** Attestation signée (CT-7 EX-7.9) : { version: 0, attestation: P, digest: D_P, signatures }. */
export function assemblerAttestation(P, signatures) {
  return { version: 0, attestation: P, digest: condenseAttestation(P), signatures: signatures.map(({ address, signature }) => ({ address, signature })) };
}

/**
 * Examine une signature sur M (AT-3) : 65 octets en hexadécimal minuscule,
 * s dans la moitié basse de l'ordre, v ∈ {27, 28}, puis recouvrement. Rend
 * { adresse, motif } : adresse recouvrée, ou null avec le motif du refus.
 * La forme canonique est contrôlée AVANT tout recouvrement.
 */
export function examinerSignature(M, signature) {
  if (typeof signature !== "string" || !RE_SIGNATURE.test(signature)) return { adresse: null, motif: T("signature de 65 octets en hexadécimal minuscule attendue", "65-byte lowercase hexadecimal signature expected") };
  const r = BigInt("0x" + signature.slice(2, 66));
  const s = BigInt("0x" + signature.slice(66, 130));
  const v = parseInt(signature.slice(130, 132), 16);
  if (v !== 27 && v !== 28) return { adresse: null, motif: T(`v = ${v}, 27 ou 28 attendu`, `v = ${v}, 27 or 28 expected`) };
  if (s > MOITIE_N) return { adresse: null, motif: T("s dans la moitié haute de l'ordre (forme non canonique)", "s in the upper half of the order (non-canonical form)") };
  try {
    return { adresse: C.recouvrerAdresse(C.depuisHex(M), r, s, v - 27), motif: null };
  } catch {
    return { adresse: null, motif: T("signature non recouvrable", "signature not recoverable") };
  }
}

// ---------------------------------------------------------------------------
// Relations que le schéma n'exprime pas (CT-7 EX-7.2, AT-1)
// ---------------------------------------------------------------------------

/** Erreurs de relation d'une attestation P déjà conforme à son schéma (dates, ordre de validité, unicités, journal des agents, JCS v0). */
export function relationsAttestation(P) {
  const erreurs = [];
  erreurs.push(...J.horodatagesHorsCalendrier([["/validity/from", P.validity?.from], ["/validity/until", P.validity?.until], ["/issued_at", P.issued_at]]).map((e) => `${e.chemin} : ${e.message}`));
  const de = J.msHorodatage(P.validity?.from);
  const a = J.msHorodatage(P.validity?.until);
  if (!Number.isNaN(de) && !Number.isNaN(a) && de > a) erreurs.push(`validity.from ${P.validity.from} postérieur à validity.until ${P.validity.until}`);
  else if (!Number.isNaN(de) && !Number.isNaN(a) && a - de > DUREE_MAX_VALIDITE_MS) erreurs.push(`validité du ${P.validity.from} au ${P.validity.until} : plus de 366 jours (CT-7 EX-7.2)`);
  const journaux = (P.journals ?? []).map((j) => j.journal_id);
  if (new Set(journaux).size !== journaux.length) erreurs.push("journal_id en double dans journals");
  const ids = new Set(journaux);
  (P.agents ?? []).forEach((ag, i) => {
    if (!ids.has(ag.journal_id)) erreurs.push(`agents[${i}] (${ag.agent_id}) : journal_id ${ag.journal_id} absent de journals`);
  });
  const agents = (P.agents ?? []).map((ag) => ag.agent_id);
  if (new Set(agents).size !== agents.length) erreurs.push("agent_id en double dans agents");
  const signataires = (P.signatories ?? []).map((s) => s.address);
  if (new Set(signataires).size !== signataires.length) erreurs.push("adresse en double dans signatories");
  try {
    J.octetsJCS(P);
  } catch (err) {
    erreurs.push(`forme canonique JCS v0 incalculable : ${err.message}`);
  }
  return erreurs;
}

/** Lecture stricte d'un texte JSON (octets ou chaîne) ; rend { valeur } ou { erreur }. */
function lireStrict(entree) {
  try {
    return { valeur: J.analyserJSONStrict(entree) };
  } catch (err) {
    return { erreur: err.message };
  }
}

const statut = (id, status, reason = null, detail = null) => ({ id, status, reason: status === "non_execute" ? reason : null, detail });

/**
 * AT-1 à AT-4 sur une attestation signée et un jeu déclaré, partagés par la
 * vérification hors dossier et par celle de la partie. `erreursForme` : les
 * erreurs de forme déjà trouvées (schéma de la partie). Rend { digest,
 * recovered, verifs (Map id -> { status, reason, detail }) }.
 */
function verifierAT1aAT4(signee, jeu, erreursForme, schemas) {
  const verifs = new Map();
  const erreurs = [...erreursForme];
  const P = estObjet(signee) ? signee.attestation : null;
  if (erreurs.length === 0 && estObjet(P)) erreurs.push(...relationsAttestation(P));
  if (erreurs.length) {
    verifs.set("AT-1", statut("AT-1", "echoue", null, T(resumer(erreurs))));
    for (const id of ["AT-2", "AT-3", "AT-4"]) verifs.set(id, statut(id, "non_execute", "prerequis_en_echec", T("AT-1 en échec", "AT-1 failed")));
    return { digest: null, recovered: null, verifs };
  }
  const nbAgents = P.agents.length;
  verifs.set("AT-1", statut("AT-1", "reussi", null, T(`attestation bien formée : ${P.journals.length} journal(aux), ${nbAgents} agent(s), validité du ${P.validity.from} au ${P.validity.until}`, `attestation well-formed: ${P.journals.length} journal(s), ${nbAgents} agent(s), validity from ${P.validity.from} to ${P.validity.until}`)));

  // AT-2 : condensé.
  const digest = condenseAttestation(P);
  verifs.set("AT-2", digest === signee.digest ? statut("AT-2", "reussi", null, T(`D_P recalculé ${digest}`, `recomputed D_P ${digest}`)) : statut("AT-2", "echoue", null, T(`D_P recalculé ${digest} différent de digest ${signee.digest}`, `recomputed D_P ${digest} differs from digest ${signee.digest}`)));

  // AT-3 : chaque signature, canonique, recouvre l'adresse déclarée (sur M de D_P recalculé).
  const M = messageAttestation(digest);
  const recovered = [];
  const fautes = [];
  signee.signatures.forEach((x, i) => {
    const e = examinerSignature(M, x.signature);
    recovered.push(e.adresse);
    if (e.adresse === null) fautes.push(T(`signatures[${i}] (${x.address}) : ${e.motif.fr}`, `signatures[${i}] (${x.address}): ${e.motif.en}`));
    else if (e.adresse !== x.address) fautes.push(T(`signatures[${i}] : adresse recouvrée ${e.adresse} différente de ${x.address}`, `signatures[${i}]: recovered address ${e.adresse} differs from ${x.address}`));
  });
  if (fautes.length) verifs.set("AT-3", statut("AT-3", "echoue", null, T(fautes.map((f) => f.fr).join(" ; "), fautes.map((f) => f.en).join("; "))));
  else verifs.set("AT-3", statut("AT-3", "reussi", null, T(`adresses recouvrées : ${recovered.join(", ")}`, `recovered addresses: ${recovered.join(", ")}`)));

  // AT-4 : signataires distincts, nommés, membres du jeu, au seuil ; seuil cohérent.
  if (verifs.get("AT-3").status !== "reussi") {
    verifs.set("AT-4", statut("AT-4", "non_execute", "prerequis_en_echec", T("AT-3 en échec", "AT-3 failed")));
  } else {
    const adresses = signee.signatures.map((x) => x.address);
    const nommes = new Set(P.signatories.map((s) => s.address));
    const membres = new Set(jeu.members);
    const f4 = [];
    if (new Set(adresses).size !== adresses.length) f4.push(T("adresse en double dans signatures", "duplicate address in signatures"));
    for (const a of adresses) {
      if (!nommes.has(a)) f4.push(T(`${a} absente de signatories`, `${a} not in signatories`));
      if (!membres.has(a)) f4.push(T(`${a} hors du jeu déclaré`, `${a} outside the declared set`));
    }
    const distincts = new Set(adresses).size;
    if (distincts < jeu.threshold.required) f4.push(T(`${distincts} signataire(s) pour un seuil de ${jeu.threshold.required}`, `${distincts} signer(s) for a threshold of ${jeu.threshold.required}`));
    if (!(jeu.threshold.required <= jeu.threshold.size && jeu.threshold.size === jeu.members.length)) f4.push(T(`seuil ${jeu.threshold.required}/${jeu.threshold.size} incohérent avec ${jeu.members.length} membre(s)`, `threshold ${jeu.threshold.required}/${jeu.threshold.size} inconsistent with ${jeu.members.length} member(s)`));
    if (f4.length) verifs.set("AT-4", statut("AT-4", "echoue", null, T(f4.map((f) => f.fr).join(" ; "), f4.map((f) => f.en).join("; "))));
    else verifs.set("AT-4", statut("AT-4", "reussi", null, T(`${distincts} signataire(s) membre(s) du jeu déclaré, seuil de ${jeu.threshold.required} sur ${jeu.threshold.size}`, `${distincts} signer(s) in the declared set, threshold ${jeu.threshold.required} of ${jeu.threshold.size}`)));
  }
  return { digest, recovered, verifs };
}

/**
 * Vérification hors dossier (CT-7 EX-7.16, annexe A.6) : AT-1 à AT-4 sur une
 * attestation signée `signee` et un jeu déclaré `jeu` ({ threshold, members,
 * source }). `signee` peut être un objet, ou le texte JSON (chaîne ou octets)
 * de l'attestation signée : il est alors lu par l'analyseur strict (clé en
 * double, nombre non entier : AT-1). `brut` (facultatif) : le texte JSON
 * d'origine d'un `signee` déjà analysé, relu de même.
 *
 * Rend { digest, recovered, checks, retained, details } : les quatre premiers
 * membres ont exactement la forme de `$defs/cas_attestation.expected` du
 * schéma attestation-perimetre-v0 ; `details` associe à chaque AT- un texte
 * { fr, en }.
 */
export function verifierAttestation(signee, jeu, { brut = null, schemas = null } = {}) {
  const registre = schemas ?? schemasAttestation();
  const schema = registre[ID_SCHEMA_ATTESTATION_PERIMETRE];
  if (!schema) throw new J.ErreurFormat("le schéma attestation-perimetre-v0 est requis pour vérifier une attestation", "AT-1");
  const erreurs = [];
  let valeur = signee;
  if (typeof signee === "string" || Buffer.isBuffer(signee) || signee instanceof Uint8Array) {
    const lu = lireStrict(signee);
    if (lu.erreur) erreurs.push(`attestation signée illisible : ${lu.erreur}`);
    valeur = lu.valeur ?? null;
  } else if (brut !== null) {
    const lu = lireStrict(brut);
    if (lu.erreur) erreurs.push(`texte JSON de l'attestation signée : ${lu.erreur}`);
  }
  if (erreurs.length === 0) {
    erreurs.push(...J.validerSchema(valeur, schema, { registre, fragment: "#/$defs/attestation_signee" }).map((e) => `attestation signée ${e.chemin || "/"} : ${e.message}`));
    erreurs.push(...J.validerSchema(jeu, schema, { registre, fragment: "#/$defs/jeu_approbateurs" }).map((e) => `jeu déclaré ${e.chemin || "/"} : ${e.message}`));
  }
  const r = verifierAT1aAT4(valeur, jeu, erreurs, registre);
  const checks = ["AT-1", "AT-2", "AT-3", "AT-4"].map((id) => {
    const v = r.verifs.get(id);
    return { id, status: v.status, reason: v.reason };
  });
  return {
    digest: r.digest,
    recovered: r.verifs.get("AT-3").status === "non_execute" ? null : r.recovered,
    checks,
    retained: checks.every((c) => c.status === "reussi"),
    details: Object.fromEntries(["AT-1", "AT-2", "AT-3", "AT-4"].map((id) => [id, r.verifs.get(id).detail])),
  };
}

// ---------------------------------------------------------------------------
// Document de politique (AT-6) : texte UTF-8, objet JSON sans membre en double
// ---------------------------------------------------------------------------

/**
 * Vérifie qu'un texte est du JSON (RFC 8259) dont aucun objet ne répète un nom
 * de membre (noms comparés après décodage), sans autre contrainte sur les
 * nombres : le reste du document de politique n'est ni lu ni validé (CT-1
 * AT-6). Rend la valeur (JSON.parse), ou lève une Error qui dit le défaut.
 */
export function analyserJSONSansDoublon(texte) {
  let i = 0;
  const n = texte.length;
  const espaces = () => {
    while (i < n && (texte[i] === " " || texte[i] === "\t" || texte[i] === "\n" || texte[i] === "\r")) i++;
  };
  const chaine = () => {
    const debut = i;
    i++;
    while (i < n) {
      const c = texte[i];
      if (c === "\\") i += 2;
      else if (c === '"') {
        i++;
        return JSON.parse(texte.slice(debut, i));
      } else if (c < " ") throw new Error(`caractère de contrôle dans une chaîne à la position ${i}`);
      else i++;
    }
    throw new Error("chaîne non terminée");
  };
  const valeur = (profondeur) => {
    if (profondeur > 512) throw new Error("imbrication trop profonde");
    espaces();
    const c = texte[i];
    if (c === "{") {
      i++;
      const vus = new Set();
      espaces();
      if (texte[i] === "}") {
        i++;
        return;
      }
      for (;;) {
        espaces();
        if (texte[i] !== '"') throw new Error(`nom de membre attendu à la position ${i}`);
        const nom = chaine();
        if (vus.has(nom)) throw new Error(`nom de membre en double : ${JSON.stringify(nom)}`);
        vus.add(nom);
        espaces();
        if (texte[i] !== ":") throw new Error(`« : » attendu à la position ${i}`);
        i++;
        valeur(profondeur + 1);
        espaces();
        if (texte[i] === ",") {
          i++;
          continue;
        }
        if (texte[i] === "}") {
          i++;
          return;
        }
        throw new Error(`« , » ou « } » attendu à la position ${i}`);
      }
    }
    if (c === "[") {
      i++;
      espaces();
      if (texte[i] === "]") {
        i++;
        return;
      }
      for (;;) {
        valeur(profondeur + 1);
        espaces();
        if (texte[i] === ",") {
          i++;
          continue;
        }
        if (texte[i] === "]") {
          i++;
          return;
        }
        throw new Error(`« , » ou « ] » attendu à la position ${i}`);
      }
    }
    if (c === '"') return void chaine();
    const m = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(texte.slice(i, i + 400));
    if (!m) throw new Error(`valeur JSON attendue à la position ${i}`);
    i += m[0].length;
  };
  valeur(0);
  espaces();
  if (i !== n) throw new Error(`texte après la valeur JSON, position ${i}`);
  return JSON.parse(texte);
}

/** Décodage strict d'un base64 canonique (remplissage exact, réencodage identique), au plus `limite` octets ; rend un Buffer ou null. */
export function decoderBase64Document(texte, limite = LIMITE_DOCUMENT_POLITIQUE) {
  if (typeof texte !== "string" || texte.length < 4 || !RE_BASE64.test(texte)) return null;
  const octets = Buffer.from(texte, "base64");
  if (octets.toString("base64") !== texte || octets.length > limite) return null;
  return octets;
}

// ---------------------------------------------------------------------------
// La partie attestation-perimetre.json d'un dossier (CT-1 §11.4, CT-6 §5.5)
// ---------------------------------------------------------------------------

/** Vrai si `ev` est exploitable pour AT-5 et AT-6 (E-1 et E-2 : schéma, dates, forme canonique). */
function evenementExploitable(ev, schemas) {
  if (!estObjet(ev)) return false;
  const res = J.controlesEvenement(ev, { schemas, cles: [] });
  return res["E-1"]?.ok === true && res["E-2"]?.ok === true;
}

/** Vrai si cles.json est exploitable (première partie de E-8 : schéma, rattachement au journal, unicités, validités). */
function clesExploitables(clesDoc, ev, schemas) {
  if (!estObjet(clesDoc)) return false;
  return J.validerSchema(clesDoc, schemas[J.ID_SCHEMA_DOSSIER], { registre: schemas, fragment: "#/$defs/cles" }).length === 0 && J.verifierCles(clesDoc, estObjet(ev) ? ev : null).length === 0;
}

/** Jeu d'approbateurs exploitable de approbations.json (pour AV-AT-2), ou null. */
function jeuApprobations(approbations, schemas) {
  if (!estObjet(approbations) || !estObjet(approbations.approver_set)) return null;
  const schema = schemas[ID_SCHEMA_ATTESTATION_PERIMETRE];
  return J.validerSchema(approbations.approver_set, schema, { registre: schemas, fragment: "#/$defs/jeu_approbateurs" }).length === 0 ? approbations.approver_set : null;
}

/**
 * Vérifications AT-1 à AT-7 de la partie attestation-perimetre.json (CT-1
 * §11.4, révision 0.4), dans la forme du rapport de CT-6 (révision 0.3, 5.5).
 *
 * Paramètres :
 *   octets       : octets du fichier (Buffer), ou null si le fichier n'est pas
 *                  lisible (voir `inexploitable`) ;
 *   inexploitable: motif ({ fr, en } ou chaîne) d'un refus de lecture par
 *                  l'appelant (fichier au-delà de 4 Mio non lu, imbrication),
 *                  ou null ;
 *   evenement    : evenement.json analysé (objet), ou null ;
 *   cles         : cles.json analysé (objet), ou null ;
 *   approbations : approbations.json analysé (objet), ou null ;
 *   schemas      : registre des cinq schémas (schemasAttestation()).
 *
 * Rend { checks, retenue, digest, faits, avertissements, nonRetenue,
 * motifNonRetenue } :
 *   checks       : sept { id, controls, status, reason, admitted, detail },
 *                  detail = { fr, en } ;
 *   retenue      : AT-1 à AT-5 réussies, AT-6 réussie ou non exécutée faute
 *                  d'inscription (partie_absente) ou de clé reliée
 *                  (ancre_absente) ;
 *   faits        : facts.perimeter (CT-6 EX-6.20), null si non retenue ;
 *   avertissements: [{ id: AV-AT-n, check, detail { fr, en } }] ;
 *   nonRetenue   : {ids} de FP et d'AV-AT-1 (les AT- en échec, ou, s'il n'y
 *                  en a aucune, les AT-1 à AT-6 non exécutées faute de
 *                  prérequis), null pour une attestation retenue ;
 *   motifNonRetenue : « echec » ou « non_execute » (libellé de FP), ou null.
 * Une vérification AT- ne change jamais le verdict (CT-6 EX-5.11) : l'appelant
 * ne doit pas les compter.
 */
export function verifierPartieAttestation({ octets = null, inexploitable = null, evenement = null, cles = null, approbations = null, schemas = null } = {}) {
  const registre = schemas ?? schemasAttestation();
  if (!registre[ID_SCHEMA_ATTESTATION_PERIMETRE] || !registre[J.ID_SCHEMA_DOSSIER] || !registre[J.ID_SCHEMA_EVENEMENT]) {
    throw new J.DossierInutilisable("les schémas evenement, dossier et attestation-perimetre sont requis pour vérifier la partie attestation-perimetre.json (CT-1 révision 0.4)");
  }
  const fichier = "attestation-perimetre.json";
  const verifs = new Map();
  const poser = (id, status, reason, detail) => verifs.set(id, statut(id, status, reason, detail));

  // AT-1 : lecture bornée, JSON strict, objet, schéma, base64 du document, relations.
  const erreurs = [];
  let partie = null;
  if (inexploitable) erreurs.push(typeof inexploitable === "string" ? inexploitable : inexploitable.fr);
  else if (!octets) erreurs.push(`${fichier} absent du répertoire`);
  else if (octets.length > LIMITE_PARTIE_ATTESTATION) erreurs.push(`${fichier} : ${octets.length} octets, au-delà de la limite de ${LIMITE_PARTIE_ATTESTATION} octets`);
  else {
    const lu = lireStrict(octets);
    if (lu.erreur) erreurs.push(`${fichier} : ${lu.erreur}`);
    else if (!estObjet(lu.valeur)) erreurs.push(`${fichier} : objet JSON attendu, reçu ${lu.valeur === null ? "le littéral null" : Array.isArray(lu.valeur) ? "un tableau" : typeof lu.valeur}`);
    else {
      partie = lu.valeur;
      erreurs.push(...J.validerSchema(partie, registre[J.ID_SCHEMA_DOSSIER], { registre, fragment: "#/$defs/attestation_perimetre" }).map((e) => `${fichier} ${e.chemin || "/"} : ${e.message}`));
      if (erreurs.length === 0 && partie.inscription !== null) {
        const ev = partie.inscription.event;
        erreurs.push(...J.horodatagesHorsCalendrier([["/inscription/event/ts", ev.ts], ["/inscription/event/approval/at", ev.approval?.at]]).map((e) => `${fichier} ${e.chemin} : ${e.message}`));
        if (!decoderBase64Document(partie.inscription.policy_document)) erreurs.push(`${fichier} /inscription/policy_document : base64 non canonique, ou plus de ${LIMITE_DOCUMENT_POLITIQUE} octets décodés`);
      }
    }
  }
  const signee = partie?.signed ?? null;
  const jeu = partie?.approver_set ?? null;
  const at14 = verifierAT1aAT4(signee, jeu, erreurs.length ? erreurs : [], registre);
  for (const id of ["AT-1", "AT-2", "AT-3", "AT-4"]) verifs.set(id, at14.verifs.get(id));
  if (erreurs.length) poser("AT-1", "echoue", null, T(resumer(erreurs)));
  const reussie = (id) => verifs.get(id)?.status === "reussi";
  const P = reussie("AT-1") ? signee.attestation : null;
  const D_P = at14.digest;

  const evOk = evenementExploitable(evenement, registre);
  const ev = evOk ? evenement : null;

  // AT-5 : organisation, journal, validité.
  if (!reussie("AT-1")) poser("AT-5", "non_execute", "prerequis_en_echec", T("AT-1 en échec", "AT-1 failed"));
  else if (!ev) poser("AT-5", "non_execute", "prerequis_en_echec", T("evenement.json inexploitable", "evenement.json unusable"));
  else {
    const f = [];
    if (P.org.org_id !== ev.org_id) f.push(T(`org_id ${P.org.org_id} de l'attestation différent de celui de l'événement ${ev.org_id}`, `org_id ${P.org.org_id} of the attestation differs from the event's ${ev.org_id}`));
    if (!P.journals.some((j) => j.journal_id === ev.journal_id)) f.push(T(`journal ${ev.journal_id} de l'événement absent de journals`, `journal ${ev.journal_id} of the event not in journals`));
    const t = J.msHorodatage(ev.ts);
    if (!(t >= J.msHorodatage(P.validity.from) && t <= J.msHorodatage(P.validity.until))) f.push(T(`ts ${ev.ts} de l'événement hors de la validité [${P.validity.from}, ${P.validity.until}]`, `ts ${ev.ts} of the event outside the validity [${P.validity.from}, ${P.validity.until}]`));
    if (f.length) poser("AT-5", "echoue", null, T(f.map((x) => x.fr).join(" ; "), f.map((x) => x.en).join("; ")));
    else poser("AT-5", "reussi", null, T(`organisation et journal de l'événement couverts ; ts ${ev.ts} dans la validité`, `organisation and journal of the event covered; ts ${ev.ts} within the validity`));
  }

  // AT-6 : inscription.
  const clesOk = evOk && clesExploitables(cles, ev, registre);
  const inscription = partie && reussie("AT-1") ? partie.inscription : undefined;
  let valeurInscription = null;
  if (!reussie("AT-1")) poser("AT-6", "non_execute", "prerequis_en_echec", T("AT-1 en échec", "AT-1 failed"));
  else if (inscription === null) poser("AT-6", "non_execute", "partie_absente", T("aucune inscription jointe : inscription vaut null", "no inscription attached: inscription is null"));
  else if (!reussie("AT-2")) poser("AT-6", "non_execute", "prerequis_en_echec", T("AT-2 en échec", "AT-2 failed"));
  else if (!ev) poser("AT-6", "non_execute", "prerequis_en_echec", T("evenement.json inexploitable", "evenement.json unusable"));
  else if (!clesOk) poser("AT-6", "non_execute", "prerequis_en_echec", T("cles.json inexploitable (première partie de E-8)", "cles.json unusable (first part of E-8)"));
  else {
    const ins = inscription.event;
    const f = [];
    const res = J.controlesEvenement(ins, { schemas: registre, cles });
    for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-11"]) {
      if (res[id]?.ok === false) f.push(T(`événement d'inscription : ${id} en échec (${res[id].detail})`, `inscription event: ${id} failed (${res[id].detail})`));
    }
    if (res["E-8"]?.ok !== true && res["E-8"]?.ok !== false) f.push(T(`événement d'inscription : signature non vérifiée (${res["E-8"]?.detail})`, `inscription event: signature not checked (${res["E-8"]?.detail})`));
    if (ins.execution?.tool !== J.OUTIL_POLITIQUE) f.push(T(`outil ${ins.execution?.tool} au lieu de ${J.OUTIL_POLITIQUE}`, `tool ${ins.execution?.tool} instead of ${J.OUTIL_POLITIQUE}`));
    if (ins.org_id !== ev.org_id || ins.journal_id !== ev.journal_id) f.push(T("org_id ou journal_id de l'inscription différents de ceux de l'événement prouvé", "org_id or journal_id of the inscription differ from the proven event's"));
    const valeur = estObjet(ins.execution?.arguments?.value) ? ins.execution.arguments.value : null;
    const doc = decoderBase64Document(inscription.policy_document);
    if (!valeur || typeof valeur.policy_sha256 !== "string" || typeof valeur.policy_version !== "string") f.push(T("execution.arguments.value sans policy_version ni policy_sha256", "execution.arguments.value without policy_version and policy_sha256"));
    else if (J.sha256(doc) !== valeur.policy_sha256) f.push(T(`SHA-256 du document de politique ${J.sha256(doc)} différent de policy_sha256 ${valeur.policy_sha256}`, `SHA-256 of the policy document ${J.sha256(doc)} differs from policy_sha256 ${valeur.policy_sha256}`));
    else {
      let texte = null;
      try {
        texte = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(doc);
      } catch {
        f.push(T("document de politique : octets UTF-8 invalides", "policy document: invalid UTF-8 bytes"));
      }
      if (texte !== null) {
        let d = null;
        try {
          d = analyserJSONSansDoublon(texte);
        } catch (err) {
          f.push(T(`document de politique : ${err.message}`, `policy document: ${err.message}`));
        }
        if (d !== null && !estObjet(d)) f.push(T("document de politique : objet JSON attendu", "policy document: JSON object expected"));
        else if (d !== null) {
          const perim = d.perimeter;
          if (!estObjet(perim)) f.push(T("document de politique sans membre perimeter objet", "policy document without an object member perimeter"));
          else if (typeof perim.attestation_digest !== "string") f.push(T("perimeter.attestation_digest absent ou non textuel", "perimeter.attestation_digest absent or not a string"));
          else if (perim.attestation_digest !== D_P) f.push(T(`perimeter.attestation_digest ${perim.attestation_digest} différent de D_P ${D_P}`, `perimeter.attestation_digest ${perim.attestation_digest} differs from D_P ${D_P}`));
        }
      }
    }
    if (Number.isSafeInteger(ins.seq) && Number.isSafeInteger(ev.seq)) {
      if (ins.seq > ev.seq) f.push(T(`inscription seq ${ins.seq} postérieure à l'événement prouvé seq ${ev.seq}`, `inscription seq ${ins.seq} later than the proven event seq ${ev.seq}`));
      else if (ins.seq === ev.seq) {
        let h1 = null;
        let h2 = null;
        try {
          h1 = J.hachageEvenement(ins);
          h2 = J.hachageEvenement(ev);
        } catch {
          /* E-2 l'a dit */
        }
        if (h1 === null || h1 !== h2) f.push(T(`inscription de même seq ${ins.seq} que l'événement prouvé mais de hash différent`, `inscription with the same seq ${ins.seq} as the proven event but a different hash`));
      }
    }
    const ti = J.msHorodatage(ins.ts);
    const te = J.msHorodatage(ev.ts);
    if (!(ti <= te)) f.push(T(`ts de l'inscription ${ins.ts} postérieur à celui de l'événement prouvé ${ev.ts}`, `ts of the inscription ${ins.ts} later than the proven event's ${ev.ts}`));
    if (f.length) poser("AT-6", "echoue", null, T(f.map((x) => x.fr).join(" ; "), f.map((x) => x.en).join("; ")));
    else if (ins.recorder_key_id !== ev.recorder_key_id) {
      // La clé de l'inscription n'est reliée au journal que si c'est celle de l'événement prouvé (CT-1 §11.4, CT-6 EX-5.12).
      poser("AT-6", "non_execute", "ancre_absente", T(`inscription signée par la clé ${ins.recorder_key_id}, autre que celle de l'événement prouvé (${ev.recorder_key_id}) : rien ne relie cette clé au journal de l'événement`, `inscription signed by key ${ins.recorder_key_id}, other than the proven event's (${ev.recorder_key_id}): nothing ties this key to the event's journal`));
    } else {
      valeurInscription = { seq: ins.seq, hash: J.hachageEvenement(ins), ts: ins.ts, key_id: ins.recorder_key_id, policy_version: valeur.policy_version, policy_sha256: valeur.policy_sha256 };
      poser("AT-6", "reussi", null, T(`inscrite par l'événement seq ${ins.seq} (${valeurInscription.hash}), politique ${valeur.policy_version} de SHA-256 ${valeur.policy_sha256}`, `recorded by event seq ${ins.seq} (${valeurInscription.hash}), policy ${valeur.policy_version} with SHA-256 ${valeur.policy_sha256}`));
    }
  }

  // AT-7 : politique en vigueur pour l'événement prouvé.
  const avertissements = [];
  const at6 = verifs.get("AT-6");
  if (at6.status === "reussi") {
    const ve = ev.code?.policy_version;
    const vi = valeurInscription.policy_version;
    if (ve === vi) poser("AT-7", "reussi", null, T(`version de politique de l'événement ${ve} = celle de l'inscription`, `policy version of the event ${ve} = that of the inscription`));
    else {
      poser("AT-7", "non_execute", "piece_hors_dossier", T(`version de politique de l'événement (${ve}) différente de celle de l'inscription (${vi}) : ensemble de politique en vigueur hors du dossier`, `policy version of the event (${ve}) differs from that of the inscription (${vi}): policy set in force outside the dossier`));
      avertissements.push({ id: "AV-AT-3", check: "AT-7", detail: T(`version de politique de l'événement (${ve}) différente de celle de l'inscription (${vi})`, `policy version of the event (${ve}) differs from that of the inscription (${vi})`) });
    }
  } else if (at6.status === "non_execute" && at6.reason === "partie_absente") poser("AT-7", "non_execute", "partie_absente", T("AT-6 non exécutée : aucune inscription", "AT-6 not run: no inscription"));
  else if (at6.status === "non_execute" && at6.reason === "ancre_absente") poser("AT-7", "non_execute", "prerequis_en_echec", T("AT-6 non exécutée : inscription non reliée à la clé de l'événement prouvé", "AT-6 not run: inscription not tied to the proven event's key"));
  else poser("AT-7", "non_execute", "prerequis_en_echec", T(at6.status === "echoue" ? "AT-6 en échec" : "AT-6 non exécutée", at6.status === "echoue" ? "AT-6 failed" : "AT-6 not run"));

  // Rétention (CT-6 EX-6.19) : AT-1 à AT-5 réussies ; AT-6 réussie, ou non exécutée faute d'inscription (partie_absente) ou faute de clé reliée (ancre_absente).
  const sansInscriptionReliee = (c) => c.status === "non_execute" && (c.reason === "partie_absente" || c.reason === "ancre_absente");
  const retenue = ["AT-1", "AT-2", "AT-3", "AT-4", "AT-5"].every(reussie) && (reussie("AT-6") || sansInscriptionReliee(at6));

  // AV-AT-2 : jeu différent de celui de approbations.json.
  const jeuA = jeuApprobations(approbations, registre);
  if (reussie("AT-4") && jeuA) {
    const memes = jeuA.members.length === jeu.members.length && new Set([...jeuA.members, ...jeu.members]).size === jeu.members.length && jeuA.threshold.required === jeu.threshold.required && jeuA.threshold.size === jeu.threshold.size;
    if (!memes) avertissements.unshift({ id: "AV-AT-2", check: "AT-4", detail: T(`jeu d'approbateurs de l'attestation différent de celui de approbations.json (attestation : ${jeu.source} ; approbations.json : ${jeuA.source})`, `approver set of the attestation differs from that of approbations.json (attestation: ${jeu.source}; approbations.json: ${jeuA.source})`) });
  }
  // AV-AT-1 : attestation non retenue, levé par la première AT- en échec.
  const checks = VERIFICATIONS_AT.map(({ id, controls }) => {
    const v = verifs.get(id);
    return { id, controls, status: v.status, reason: v.status === "non_execute" ? v.reason : null, admitted: v.status === "non_execute" ? v.reason !== "prerequis_en_echec" : null, detail: v.detail };
  });
  const enEchec = checks.filter((c) => c.status === "echoue").map((c) => c.id);
  // {ids} de FP et d'AV-AT-1 (CT-6 EX-6.19, 5.5) : les AT- en échec ; s'il n'y en a aucune, les AT-1 à AT-6 non exécutées faute de prérequis.
  const nonRetenue = retenue ? null : enEchec.length ? enEchec : checks.filter((c) => c.status === "non_execute" && c.reason === "prerequis_en_echec" && c.id !== "AT-7").map((c) => c.id);
  const motifNonRetenue = retenue ? null : enEchec.length ? "echec" : "non_execute";
  if (!retenue) {
    const ids = nonRetenue.join(", ");
    const quoi = enEchec.length ? T("en échec", "failed") : T("non exécutée(s)", "not run");
    avertissements.unshift({ id: "AV-AT-1", check: nonRetenue[0] ?? "AT-1", detail: T(`attestation de périmètre non retenue : ${ids} ${quoi.fr} ; elle ne change ni les statuts ni le verdict`, `perimeter attestation not retained: ${ids} ${quoi.en}; it changes neither the statuses nor the verdict`) });
  }

  // facts.perimeter (CT-6 EX-6.20) : seulement pour une attestation retenue.
  let faits = null;
  if (retenue) {
    faits = {
      provenance: "declaree",
      digest: D_P,
      org_id: P.org.org_id,
      journal_ids: P.journals.map((j) => j.journal_id),
      valid_from: P.validity.from,
      valid_until: P.validity.until,
      issued_at: P.issued_at,
      signers: [...at14.recovered],
      required: jeu.threshold.required,
      size: jeu.threshold.size,
      set_source: jeu.source,
      agents: P.agents.length,
      capture_channels: ORDRE_CANAUX.filter((c) => P.agents.some((a) => a.capture_channels.includes(c))),
      exceptions: P.not_captured.length,
      egress_default_policy: P.egress.default_policy,
      egress_rules_sha256: P.egress.rules_sha256,
      inscription: reussie("AT-6") ? { ...valeurInscription, same_policy_version: reussie("AT-7") } : null,
    };
  }
  // Ordre d'EX-6.15 : position de la vérification qui lève, puis numéro.
  avertissements.sort((a, b) => IDS_AT.indexOf(a.check) - IDS_AT.indexOf(b.check) || Number(a.id.split("-")[2]) - Number(b.id.split("-")[2]));
  return { checks, retenue, digest: D_P, faits, avertissements, nonRetenue, motifNonRetenue };
}

/**
 * Partie attestation-perimetre.json (objet) : l'attestation signée, le jeu
 * déclaré et l'inscription facultative ({ event, policy_document (octets) }
 * ou null). Le document de politique est encodé en base64 (CT-1 §3).
 */
export function construirePartieAttestation({ signee, approver_set, inscription = null }) {
  return {
    version: 0,
    signed: signee,
    approver_set,
    inscription: inscription ? { event: inscription.event, policy_document: Buffer.from(inscription.policy_document).toString("base64") } : null,
  };
}

// ===========================================================================
// Cérémonie des clés : procès-verbal ceremonie-cles-v0 (CT-7 section 5)
// ===========================================================================
//
//   V    = le procès-verbal privé de son membre signatures
//   P_C  = UTF-8("noortrace/ceremonie-cles/v0\n")                28 octets
//   D_C  = Keccak-256(P_C ‖ JCS(V))                             JCS v0 de CT-1 §4
//   M    = Keccak-256("\x19Ethereum Signed Message:\n32" ‖ D_C) EIP-191 version 0x45
//
// Vérifications CR-1 à CR-12 de CT-7 §5.8, hors ligne et sans réseau.

/** Préfixe de domaine du procès-verbal de cérémonie, P_C (CT-7 EX-5.7). */
export const PREFIXE_CEREMONIE = "noortrace/ceremonie-cles/v0\n";
/** P_C en hexadécimal, sans 0x. */
export const PREFIXE_CEREMONIE_HEX = Buffer.from(PREFIXE_CEREMONIE, "utf8").toString("hex");
/** $id du schéma du procès-verbal (CT-7 §5.6). */
export const ID_SCHEMA_CEREMONIE = "https://noortrace.example/schemas/v0/ceremonie-cles.schema.json";
/** Taille maximale d'un procès-verbal lu (CT-7 EX-5.9) : 1 Mio. */
export const LIMITE_PROCES_VERBAL = 1024 * 1024;
/** Les douze vérifications, dans l'ordre (CT-7 §5.8). */
export const IDS_CR = Object.freeze(Array.from({ length: 12 }, (_, i) => `CR-${i + 1}`));

/**
 * Forme de `purpose_details` par objet (CT-7 5.1, CR-12) : null, ou la clé
 * qui distingue la forme de l'objet dans le schéma.
 */
export const DETAILS_PAR_OBJET = Object.freeze({
  creation: null,
  rotation: null,
  sauvegarde: null,
  inscription_membres: null,
  autre: null,
  rotation_urgence: "decided_at",
  revocation: "tx_hash",
  recompletement: "tx_hash",
  destruction: "destruction_proof_sha256",
  restauration: "backup_ceremony_digest",
  changement_administrateur: "approver_set_hash",
});

/** Algorithme(s) admis par usage (CT-7 §4.3 et CR-5). */
export const ALGORITHME_PAR_USAGE = Object.freeze({
  enregistreur: Object.freeze(["ed25519"]),
  chaine: Object.freeze(["secp256k1"]),
  approbateur: Object.freeze(["secp256k1"]),
  gouvernance: Object.freeze(["secp256k1"]),
  administrateur_registre: Object.freeze(["secp256k1"]),
  deployeur: Object.freeze(["secp256k1"]),
  relayeur: Object.freeze(["secp256k1"]),
  tresorerie: Object.freeze(["secp256k1"]),
  approvisionnement: Object.freeze(["secp256k1"]),
  validateur: Object.freeze(["secp256k1"]),
  tsa_interne: Object.freeze(["rsa", "ecdsa_p256"]),
  enveloppe: Object.freeze(["aes256"]),
});

/** Classes de garde admises en production, par usage (CT-7 §4.3, EX-4.2 ; CR-6). */
export const CLASSES_ADMISES_PRODUCTION = Object.freeze({
  enregistreur: Object.freeze(["A", "B", "C"]),
  chaine: Object.freeze(["A", "B", "C"]),
  approbateur: Object.freeze(["sans_objet"]),
  gouvernance: Object.freeze(["A", "B", "C"]),
  administrateur_registre: Object.freeze(["A"]),
  deployeur: Object.freeze(["A", "B", "C"]),
  relayeur: Object.freeze(["A", "B", "C"]),
  tresorerie: Object.freeze(["A", "B", "C"]),
  approvisionnement: Object.freeze(["A", "B", "C"]),
  validateur: Object.freeze(["D"]),
  tsa_interne: Object.freeze(["A", "B", "C"]),
  enveloppe: Object.freeze(["A", "B", "C"]),
});

/**
 * Sauvegarde par usage (CT-7 §4.4, EX-4.4 ; CR-7) : `aucune` (sauvegarde
 * interdite), `partage` (partage k sur n toujours exigé),
 * `partage_en_production` (exigé en production), `libre` (au choix du client).
 */
export const SAUVEGARDE_PAR_USAGE = Object.freeze({
  enregistreur: "aucune",
  chaine: "aucune",
  approbateur: "aucune",
  validateur: "aucune",
  deployeur: "aucune",
  relayeur: "aucune",
  approvisionnement: "aucune",
  tsa_interne: "aucune",
  enveloppe: "partage",
  administrateur_registre: "partage_en_production",
  tresorerie: "partage_en_production",
  gouvernance: "libre",
});

const P_SECP = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
let schemaCeremonieParDefaut = null;

/** Le schéma ceremonie-cles-v0, lu une fois dans spec/schemas (ou dans `repertoire`). */
export function schemaCeremonie(repertoire = null) {
  if (!repertoire && schemaCeremonieParDefaut) return schemaCeremonieParDefaut;
  const s = JSON.parse(fs.readFileSync(path.join(repertoire ?? RACINE_SCHEMAS, "ceremonie-cles-v0.schema.json"), "utf8"));
  if (!repertoire) schemaCeremonieParDefaut = s;
  return s;
}

/** Le procès-verbal privé de son membre `signatures` (V de CT-7 EX-5.7). */
function sansSignatures(pv) {
  const { signatures, ...corps } = pv;
  return corps;
}

/** D_C = Keccak-256(P_C ‖ JCS(V)), en hexadécimal 0x (CT-7 EX-5.7). */
export function condenseCeremonie(pv) {
  return C.enHex(C.keccak256(C.concat(C.utf8(PREFIXE_CEREMONIE), J.octetsJCS(sansSignatures(pv)))));
}

/** M = Keccak-256("\x19Ethereum Signed Message:\n32" ‖ D_C), en hexadécimal 0x. */
export function messageCeremonie(D_C) {
  return C.enHex(C.condenseEIP191(C.depuisHex(D_C)));
}

/** Octets d'une clé privée secp256k1 : hexadécimal 0x, octets, ou portefeuille ethers. */
function octetsCle(cle) {
  if (typeof cle === "string") return C.depuisHex(cle);
  if (cle instanceof Uint8Array) return Uint8Array.from(cle);
  if (cle && cle.signingKey) return C.depuisHex(cle.signingKey.privateKey);
  if (cle && typeof cle.privateKey === "string") return C.depuisHex(cle.privateKey);
  throw new J.ErreurFormat("clé privée secp256k1 attendue (hexadécimal 0x, octets ou portefeuille)");
}

/**
 * Signe le procès-verbal : rend une copie dont `signatures` porte, dans l'ordre
 * de `participants`, la signature EIP-191 de D_C par la clé de chaque
 * participant (RFC 6979, s bas, v = 27 + recid), identique à
 * `signMessage(getBytes(D_C))` d'ethers (CT-7 EX-5.7). `cles` associe à
 * l'identifiant d'un participant sa clé privée ; un participant sans clé
 * n'a pas de signature.
 */
export function signerCeremonie(pv, cles) {
  const copie = structuredClone(pv);
  const M = C.condenseEIP191(C.depuisHex(condenseCeremonie(copie)));
  const parId = cles instanceof Map ? cles : new Map(Object.entries(cles));
  copie.signatures = copie.participants.filter((p) => parId.has(p.id)).map((p) => ({ participant: p.id, signature: C.signerHachage(octetsCle(parId.get(p.id)), M) }));
  return copie;
}

/** Examine une signature de procès-verbal sur M (CR-11) : forme canonique contrôlée AVANT le recouvrement. */
function examinerSignatureCeremonie(M, signature) {
  const o = C.depuisHex(signature);
  if (o.length !== 65) return { adresse: null, motif: "signature de 65 octets attendue" };
  const r = BigInt(C.enHex(o.slice(0, 32)));
  const s = BigInt(C.enHex(o.slice(32, 64)));
  const v = o[64];
  if (v !== 27 && v !== 28) return { adresse: null, motif: `v = ${v}, 27 ou 28 attendu` };
  if (r < 1n || r >= C.N_SECP256K1) return { adresse: null, motif: "r hors de [1, n − 1]" };
  if (s < 1n || s >= C.N_SECP256K1) return { adresse: null, motif: "s hors de [1, n − 1]" };
  if (s > MOITIE_N) return { adresse: null, motif: "s dans la moitié haute de l'ordre (forme non canonique)" };
  try {
    return { adresse: C.recouvrerAdresse(M, r, s, v - 27), motif: null };
  } catch {
    return { adresse: null, motif: "signature non recouvrable" };
  }
}

/** Analyse d'une clé publique SubjectPublicKeyInfo DER : { type, courbe } ou null. */
function analyserSpki(octets) {
  try {
    const k = crypto.createPublicKey({ key: Buffer.from(octets), format: "der", type: "spki" });
    return { type: k.asymmetricKeyType, courbe: k.asymmetricKeyDetails?.namedCurve ?? null, der: k.export({ type: "spki", format: "der" }) };
  } catch {
    return null;
  }
}

/** Adresse secp256k1 d'une clé publique non compressée (65 octets 04 ‖ X ‖ Y), ou le motif du refus. */
function adresseDeClePublique(pk) {
  if (pk.length !== 65 || pk[0] !== 4) return { erreur: "clé publique secp256k1 de 65 octets commençant par 04 attendue" };
  const x = BigInt(C.enHex(pk.slice(1, 33)));
  const y = BigInt(C.enHex(pk.slice(33)));
  if (x >= P_SECP || y >= P_SECP || (y * y - (x * x * x + 7n)) % P_SECP !== 0n) return { erreur: "point hors de la courbe secp256k1" };
  return { adresse: "0x" + C.enHex(C.keccak256(pk.slice(1))).slice(26) };
}

/**
 * Vérifie un procès-verbal (octets ou chaîne du fichier) : CR-1 à CR-12 de
 * CT-7 §5.8, dans l'ordre. Rend { verdict, digest, statuses, failed,
 * not_executed, signers } : `statuses` donne, pour chaque CR-, son statut
 * (`reussi`, `echoue`, `non_execute`), sa raison (`prerequis_en_echec` pour
 * une vérification non exécutée) et le détail des règles violées ;
 * `signers` liste, dans l'ordre de `participants` et sans doublon, les
 * adresses des participants dont la signature est canonique et recouvre leur
 * adresse (vide si CR-1 échoue).
 */
export function verifierCeremonie(octets, { schema = null } = {}) {
  const fautes = Object.fromEntries(IDS_CR.map((id) => [id, []]));
  const faute = (id, m) => fautes[id].push(m);
  const brut = typeof octets === "string" ? Buffer.from(octets, "utf8") : Buffer.from(octets);
  let pv;
  if (brut.length > LIMITE_PROCES_VERBAL) faute("CR-1", `procès-verbal de ${brut.length} octets, plus de 1 Mio`);
  else {
    try {
      pv = J.analyserJSONStrict(brut);
    } catch (err) {
      faute("CR-1", `JSON strict : ${err.message}`);
    }
  }
  if (fautes["CR-1"].length === 0) {
    const s = schema ?? schemaCeremonie();
    const erreurs = J.validerSchema(pv, s);
    if (erreurs.length) faute("CR-1", `schéma ceremonie-cles-v0 : ${resumer(erreurs)}`);
  }
  if (fautes["CR-1"].length) {
    return {
      verdict: "invalide",
      digest: null,
      statuses: IDS_CR.map((id) => (id === "CR-1" ? { id, status: "echoue", reason: null, detail: fautes[id].join(" ; ") } : { id, status: "non_execute", reason: "prerequis_en_echec", detail: "CR-1 en échec" })),
      failed: ["CR-1"],
      not_executed: IDS_CR.slice(1),
      signers: [],
    };
  }

  const parts = new Map();
  for (const p of pv.participants) if (!parts.has(p.id)) parts.set(p.id, p);
  const role = (id) => parts.get(id)?.role;
  const production = pv.environment === "production";

  // CR-2 : participants.
  if (parts.size !== pv.participants.length) faute("CR-2", "identifiants de participants en double");
  if (new Set(pv.participants.map((p) => p.address)).size !== pv.participants.length) faute("CR-2", "adresses de participants en double");
  if (pv.participants.length < 2) faute("CR-2", "moins de deux participants");
  const nbOfficiants = pv.participants.filter((p) => p.role === "officiant").length;
  if (nbOfficiants !== 1) faute("CR-2", `${nbOfficiants} officiant(s), exactement un attendu`);
  if (!pv.participants.some((p) => p.role === "temoin")) faute("CR-2", "aucun témoin");
  const auditeurs = new Set(pv.participants.filter((p) => p.role === "auditeur").map((p) => p.id));
  for (const st of pv.steps) if (auditeurs.has(st.performed_by)) faute("CR-2", `étape ${st.n} exécutée par l'auditeur ${st.performed_by}`);
  for (const k of pv.keys) for (const h of k.backup.holders) if (auditeurs.has(h)) faute("CR-2", `l'auditeur ${h} détient une part de ${k.key_id}`);

  // CR-3 : chronologie (instants à la milliseconde, dates du calendrier).
  const ms = (t, quoi) => {
    const v = J.msHorodatage(t);
    if (Number.isNaN(v)) faute("CR-3", `${quoi} ${t} : date hors du calendrier`);
    return v;
  };
  const debut = ms(pv.started_at, "started_at");
  const fin = ms(pv.ended_at, "ended_at");
  if (!Number.isNaN(debut) && !Number.isNaN(fin) && debut > fin) faute("CR-3", "started_at postérieur à ended_at");
  let precedent = debut;
  pv.steps.forEach((st, i) => {
    if (st.n !== i + 1) faute("CR-3", `étape d'indice ${i} numérotée ${st.n}, ${i + 1} attendu`);
    const t = ms(st.at, `étape ${st.n} :`);
    if (Number.isNaN(t)) return;
    if (!Number.isNaN(precedent) && t < precedent) faute("CR-3", `étape ${st.n} : instant ${st.at} antérieur au précédent`);
    if (!Number.isNaN(debut) && t < debut) faute("CR-3", `étape ${st.n} : instant avant started_at`);
    if (!Number.isNaN(fin) && t > fin) faute("CR-3", `étape ${st.n} : instant après ended_at`);
    precedent = t;
  });

  // CR-4 : étapes.
  for (const st of pv.steps) {
    if (!parts.has(st.performed_by)) faute("CR-4", `étape ${st.n} : exécutant ${st.performed_by} inconnu`);
    for (const w of st.witnessed_by) {
      if (role(w) !== "temoin" && role(w) !== "auditeur") faute("CR-4", `étape ${st.n} : ${w} n'est ni témoin ni auditeur`);
      if (w === st.performed_by) faute("CR-4", `étape ${st.n} : ${w} témoin de sa propre étape`);
    }
    if (!st.witnessed_by.some((w) => role(w) === "temoin" && w !== st.performed_by)) faute("CR-4", `étape ${st.n} : aucun participant de rôle temoin parmi ses témoins (l'auditeur s'ajoute au témoin sans le remplacer)`);
    if (st.outcome === "exception" && !pv.findings.some((f) => f.step === st.n)) faute("CR-4", `étape ${st.n} en exception sans constat qui la nomme`);
  }

  // CR-5 : clés.
  if (new Set(pv.keys.map((k) => k.key_id)).size !== pv.keys.length) faute("CR-5", "key_id en double");
  for (const k of pv.keys) {
    const q = `clé ${k.key_id}`;
    if (!ALGORITHME_PAR_USAGE[k.usage].includes(k.algorithm)) faute("CR-5", `${q} : algorithme ${k.algorithm} non admis pour l'usage ${k.usage}`);
    if ((k.usage === "approbateur") !== (k.generated_in === "detenteur")) faute("CR-5", `${q} : generated_in ${k.generated_in} pour l'usage ${k.usage}`);
    const pk = k.public_key === null ? null : C.depuisHex(k.public_key);
    const attendue = pk === null ? null : C.enHex(C.sha256(pk));
    if (k.fingerprint !== attendue) faute("CR-5", `${q} : fingerprint ${k.fingerprint} différente de ${attendue}`);
    switch (k.algorithm) {
      case "ed25519":
        if (pk === null || pk.length !== 32) faute("CR-5", `${q} : clé publique Ed25519 de 32 octets attendue`);
        if (k.address !== null) faute("CR-5", `${q} : adresse non nulle pour Ed25519`);
        break;
      case "rsa":
      case "ecdsa_p256": {
        const spki = pk === null ? null : analyserSpki(pk);
        const bon = spki !== null && Buffer.compare(spki.der, Buffer.from(pk)) === 0 && (k.algorithm === "rsa" ? spki.type === "rsa" : spki.type === "ec" && spki.courbe === "prime256v1");
        if (!bon) faute("CR-5", `${q} : SubjectPublicKeyInfo DER ${k.algorithm} attendu`);
        if (k.address !== null) faute("CR-5", `${q} : adresse non nulle pour ${k.algorithm}`);
        break;
      }
      case "aes256":
        if (pk !== null || k.address !== null) faute("CR-5", `${q} : une clé aes256 n'a ni clé publique, ni empreinte, ni adresse`);
        break;
      case "secp256k1":
        if (k.address === null) faute("CR-5", `${q} : adresse secp256k1 absente`);
        if (pk === null) {
          if (k.usage !== "approbateur") faute("CR-5", `${q} : clé publique absente (admis seulement pour une clé d'approbateur)`);
        } else {
          const a = adresseDeClePublique(pk);
          if (a.erreur) faute("CR-5", `${q} : ${a.erreur}`);
          else if (k.address !== null && a.adresse !== k.address) faute("CR-5", `${q} : adresse ${k.address} différente de l'adresse dérivée ${a.adresse}`);
        }
        break;
      default:
        faute("CR-5", `${q} : algorithme ${k.algorithm} inconnu`);
    }
  }

  // CR-6 : classes.
  for (const k of pv.keys) {
    if ((k.usage === "approbateur") !== (k.custody_class === "sans_objet")) faute("CR-6", `clé ${k.key_id} : classe ${k.custody_class} pour l'usage ${k.usage}`);
    if (production && !CLASSES_ADMISES_PRODUCTION[k.usage].includes(k.custody_class)) faute("CR-6", `clé ${k.key_id} : classe ${k.custody_class} non admise en production pour l'usage ${k.usage}`);
  }

  // CR-7 : sauvegarde.
  for (const k of pv.keys) {
    const b = k.backup;
    const q = `clé ${k.key_id}`;
    if (b.scheme === "aucune") {
      if (b.k !== null || b.n !== null || b.holders.length) faute("CR-7", `${q} : sauvegarde aucune avec k, n ou détenteurs`);
    } else {
      if (!(Number.isInteger(b.k) && Number.isInteger(b.n) && b.k >= 2 && b.k <= b.n)) faute("CR-7", `${q} : partage ${b.k} sur ${b.n}, 2 ≤ k ≤ n attendu`);
      if (b.holders.length !== b.n || new Set(b.holders).size !== b.holders.length) faute("CR-7", `${q} : ${b.holders.length} détenteur(s) pour n = ${b.n}, distincts attendus`);
      for (const h of b.holders) if (role(h) !== "detenteur_part") faute("CR-7", `${q} : ${h} n'est pas détenteur de part`);
    }
    const regle = SAUVEGARDE_PAR_USAGE[k.usage];
    if (regle === "aucune" && b.scheme !== "aucune") faute("CR-7", `${q} : aucune sauvegarde admise pour l'usage ${k.usage}`);
    if (regle === "partage" && b.scheme !== "partage_k_sur_n") faute("CR-7", `${q} : partage k sur n exigé pour l'usage ${k.usage}`);
    if (regle === "partage_en_production" && production && b.scheme !== "partage_k_sur_n") faute("CR-7", `${q} : partage k sur n exigé en production pour l'usage ${k.usage}`);
  }

  // CR-8 : membres.
  const membres = pv.participants.filter((p) => p.role === "membre");
  const clesMembres = pv.keys.filter((k) => k.usage === "approbateur");
  for (const k of clesMembres) {
    const n = membres.filter((m) => m.address === k.address).length;
    if (n !== 1) faute("CR-8", `clé ${k.key_id} : ${n} membre(s) de cette adresse, exactement un attendu`);
  }
  for (const m of membres) {
    const n = clesMembres.filter((k) => k.address === m.address).length;
    if (n !== 1) faute("CR-8", `membre ${m.id} : ${n} clé(s) d'approbateur, exactement une attendue`);
  }

  // CR-9 : production.
  if (production) {
    if (pv.script.sha256 === null) faute("CR-9", "script sans empreinte en production");
    if (!pv.records.some((r) => r.kind === "video") && auditeurs.size === 0) faute("CR-9", "ni enregistrement vidéo ni auditeur en production");
    if (pv.keys.some((k) => k.generated_in === "poste") && (pv.workstation.offline !== true || pv.workstation.image_sha256 === null)) faute("CR-9", "clé générée sur un poste en ligne ou sans empreinte d'image");
  }

  // CR-10 : constats.
  const numeros = new Set(pv.steps.map((st) => st.n));
  pv.findings.forEach((f, i) => {
    if (f.n !== i + 1) faute("CR-10", `constat d'indice ${i} numéroté ${f.n}, ${i + 1} attendu`);
    if (f.step !== null && !numeros.has(f.step)) faute("CR-10", `constat ${f.n} : étape ${f.step} inexistante`);
    if (f.kind === "incident" && f.resolution === null) faute("CR-10", `constat ${f.n} : incident sans résolution`);
  });

  // CR-12 : objet (purpose_details et ce que l'objet exige, CT-7 5.1).
  {
    const d = pv.purpose_details;
    const cleForme = DETAILS_PAR_OBJET[pv.purpose];
    const nb = (r) => pv.participants.filter((p) => p.role === r).length;
    if (cleForme === null) {
      if (d !== null) faute("CR-12", `purpose_details non nul pour l'objet ${pv.purpose}`);
    } else if (d === null || !(cleForme in d)) faute("CR-12", `purpose_details de l'objet ${pv.purpose} absent ou d'une autre forme (membre ${cleForme} attendu)`);
    else if (pv.purpose === "rotation_urgence") {
      const a = J.msHorodatage(d.decided_at);
      const b = J.msHorodatage(d.revocation_included_at);
      if (Number.isNaN(a) || Number.isNaN(b)) faute("CR-12", "purpose_details : date hors du calendrier");
      else if (a > b) faute("CR-12", "decided_at postérieur à revocation_included_at");
    } else if (pv.purpose === "restauration") {
      if (!(d.k >= 2 && d.k <= d.n)) faute("CR-12", `restauration d'un partage ${d.k} sur ${d.n}, 2 ≤ k ≤ n attendu`);
      if (nb("detenteur_part") < d.k) faute("CR-12", `restauration avec ${nb("detenteur_part")} détenteur(s) de part, au moins k = ${d.k} attendus`);
    } else if (pv.purpose === "changement_administrateur") {
      if (nb("membre") < d.required) faute("CR-12", `${nb("membre")} membre(s) présent(s), au moins required = ${d.required} attendus`);
      if (!pv.keys.some((k) => k.usage === "gouvernance")) faute("CR-12", "aucune clé d'usage gouvernance (la nouvelle clé)");
    }
    if (["creation", "rotation", "rotation_urgence"].includes(pv.purpose) && pv.keys.length === 0) faute("CR-12", `objet ${pv.purpose} sans clé`);
    if (pv.purpose === "sauvegarde" && !pv.keys.some((k) => k.backup.scheme === "partage_k_sur_n")) faute("CR-12", "sauvegarde sans clé partagée k sur n");
    if (pv.purpose === "inscription_membres" && !pv.keys.some((k) => k.usage === "approbateur")) faute("CR-12", "inscription de membres sans clé d'approbateur");
  }

  // CR-11 : signatures.
  const digest = condenseCeremonie(pv);
  const M = C.condenseEIP191(C.depuisHex(digest));
  const nommes = pv.signatures.map((s) => s.participant);
  if (new Set(nommes).size !== nommes.length) faute("CR-11", "deux signatures pour un même participant");
  for (const p of parts.keys()) if (!nommes.includes(p)) faute("CR-11", `signature de ${p} absente`);
  const valides = new Set();
  for (const s of pv.signatures) {
    const p = parts.get(s.participant);
    if (!p) {
      faute("CR-11", `signature d'un participant inconnu ${s.participant}`);
      continue;
    }
    const e = examinerSignatureCeremonie(M, s.signature);
    if (e.adresse === null) faute("CR-11", `signature de ${s.participant} : ${e.motif}`);
    else if (e.adresse !== p.address) faute("CR-11", `signature de ${s.participant} : adresse recouvrée ${e.adresse} différente de ${p.address}`);
    else valides.add(s.participant);
  }
  const signers = [];
  for (const p of pv.participants) if (valides.has(p.id) && !signers.includes(p.address)) signers.push(p.address);

  const statuses = IDS_CR.map((id) => ({ id, status: fautes[id].length ? "echoue" : "reussi", reason: null, detail: fautes[id].length ? fautes[id].join(" ; ") : null }));
  const failed = statuses.filter((s) => s.status === "echoue").map((s) => s.id);
  return { verdict: failed.length ? "invalide" : "valide", digest, statuses, failed, not_executed: [], signers };
}

/** Le fichier attendu.json d'un résultat de verifierCeremonie (`#/$defs/attendu`). */
export function attenduCeremonie(r) {
  return { verdict: r.verdict, digest: r.digest, failed: r.failed, not_executed: r.not_executed, signers: r.signers };
}

/** Phrase fixe de CT-7 §5.8 pour un procès-verbal valide. */
export function phraseCeremonie(pv, r) {
  return `Procès-verbal ${pv.ceremony_id} : forme, chronologie, clés et ${pv.signatures.length} signatures vérifiées (D_C = ${r.digest}). Les identités, les rôles, les étapes et les constats sont déclarés par le procès-verbal et ses signataires.`;
}

// ===========================================================================
// Modèle de menace : tables de CT-7 (sections 0.2, 3.2 à 3.5) et menaces.json
// ===========================================================================

/** Préfixe fixe de la colonne « Test de CT-9 » (CT-7 §3.4, §3.8). */
export const PREFIXE_TEST_CT9 = "Le test échoue si la réponse est retirée : ";
/** Porteurs d'un risque accepté : texte de la table 3.5 → valeur de `owner`. */
export const PORTEURS = Object.freeze({ client: "client", "exploitant NOORTRACE": "exploitant_noortrace", "réviseur": "reviseur", "opérateur de validateur": "operateur_validateur" });
/** Expression des renvois (CT-7 RV-4). */
export const RE_RENVOI = /CT-([1-9]) (EX-[0-9A-Z]+\.[0-9]+|§[0-9A-Z]+(?:\.[0-9]+)*|[A-Z]{1,2}-[0-9]+)/g;
/** Fichiers des spécifications, par nom court. */
export const FICHIERS_SPEC = Object.freeze({
  "CT-1": "CT-1-evenements-et-formats.md",
  "CT-2": "CT-2-enregistreur.md",
  "CT-3": "CT-3-approbations.md",
  "CT-4": "CT-4-registre.md",
  "CT-5": "CT-5-ancrage.md",
  "CT-6": "CT-6-verificateur.md",
  "CT-7": "CT-7-securite-et-conformite.md",
});

/** Renvois d'un texte, dans l'ordre de leur première occurrence, sans doublon (RV-4). */
export function refsDe(texte) {
  const vus = [];
  for (const m of texte.matchAll(RE_RENVOI)) {
    const r = `CT-${m[1]} ${m[2]}`;
    if (!vus.includes(r)) vus.push(r);
  }
  return vus;
}

/** Cellules d'une ligne de table Markdown : séparateur `|` non précédé de `\`, `\|` rendu par `|`, espaces de bord retirés. */
export function cellules(ligne) {
  let l = ligne.trim();
  if (l.startsWith("|")) l = l.slice(1);
  if (l.endsWith("|") && !l.endsWith("\\|")) l = l.slice(0, -1);
  return l.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, "|"));
}

const echapperRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Texte d'une section d'une spécification : du titre de niveau 2 à 4 dont le
 * numéro est `numero` jusqu'au titre suivant de niveau 2 à 4 (exclu). Rend
 * null si le titre n'existe pas.
 */
export function texteSection(texte, numero) {
  const lignes = texte.split("\n");
  const re = new RegExp(`^#{2,4} ${echapperRe(numero)}[. ]`);
  let enCode = false;
  let debut = -1;
  for (let i = 0; i < lignes.length; i++) {
    if (lignes[i].startsWith("```")) enCode = !enCode;
    if (enCode) continue;
    if (debut < 0) {
      if (re.test(lignes[i])) debut = i;
    } else if (/^#{2,4} /.test(lignes[i])) {
      return lignes.slice(debut + 1, i).join("\n");
    }
  }
  return debut < 0 ? null : lignes.slice(debut + 1).join("\n");
}

/** Tables d'un texte (hors blocs de code) : liste de { entete, lignes } (cellules), séparateur retiré. */
export function tablesDe(texte) {
  const tables = [];
  let cur = null;
  let enCode = false;
  for (const l of texte.split("\n")) {
    if (l.startsWith("```")) enCode = !enCode;
    if (!enCode && l.startsWith("|")) {
      if (!cur) {
        cur = [];
        tables.push(cur);
      }
      cur.push(l);
    } else cur = null;
  }
  return tables.map((t) => ({ entete: cellules(t[0]), lignes: t.slice(2).map(cellules) }));
}

/**
 * Lignes d'une table source (CT-7 §3.3, RV-6) : première cellule de chaque
 * ligne de la table de la section, gras retiré ; pour une section sans table
 * (liste de CT-2 §18.5), « puce n » pour chaque élément de liste.
 */
export function lignesSources(texteSpec, section) {
  const s = texteSection(texteSpec, section);
  if (s === null) return null;
  const tables = tablesDe(s);
  if (tables.length) return tables[0].lignes.map((c) => c[0].replace(/\*\*/g, ""));
  return s.split("\n").filter((l) => l.startsWith("- ")).map((_, i) => `puce ${i + 1}`);
}

/**
 * Tables de CT-7 lues dans son texte (EX-A.4) : composants (3.2), tables
 * sources et rattachement (3.3), menaces (3.4), risques acceptés (3.5),
 * traçabilité (0.2) ; chaque table est une liste de lignes de cellules. Rend
 * aussi `version` et `date` lues dans l'en-tête.
 */
export function lireTablesCt7(texte) {
  const tab = (num, i = 0) => {
    const s = texteSection(texte, num);
    if (s === null) throw new J.ErreurFormat(`CT-7 : section ${num} introuvable`);
    const t = tablesDe(s)[i];
    if (!t) throw new J.ErreurFormat(`CT-7 : table ${i + 1} de la section ${num} introuvable`);
    return t.lignes;
  };
  const m = /^Version (\d+\.\d+), (\d{4}-\d{2}-\d{2})/m.exec(texte);
  if (!m) throw new J.ErreurFormat("CT-7 : ligne « Version x.y, AAAA-MM-JJ » introuvable");
  return { version: m[1], date: m[2], composants: tab("3.2"), sources: tab("3.3", 0), rattachement: tab("3.3", 1), menaces: tab("3.4"), risques: tab("3.5"), tracabilite: tab("0.2") };
}

/**
 * Objet `menaces.json` (CT-7 §3.8, EX-A.4) depuis les tables de CT-7 et le
 * texte des spécifications citées (`specs` : nom court → texte), qui donnent
 * le nombre de lignes de chaque table source. Lève ErreurFormat sur une
 * incohérence de lecture (composant ou risque accepté inconnu).
 */
export function construireMenaces(tables, specs) {
  const components = tables.composants.map((c) => ({ id: c[0].replace(/^`|`$/g, ""), name: c[1], holds: c[2], trust: c[3] }));
  const idParNom = new Map(components.map((c) => [c.name, c.id]));
  const source_tables = tables.sources.map((c) => {
    const lignes = specs?.[c[0]] ? lignesSources(specs[c[0]], c[1]) : null;
    return { spec: c[0], section: c[1], rows: lignes ? lignes.length : Number(c[3]) };
  });
  const sources = new Map();
  for (const c of tables.rattachement) {
    for (const mn of c[3].split(",").map((x) => x.trim())) {
      if (!sources.has(mn)) sources.set(mn, []);
      sources.get(mn).push({ spec: c[0], section: c[1], row: c[2] });
    }
  }
  const risques = new Map();
  for (const c of tables.risques) {
    const owner = PORTEURS[c[3]];
    if (!owner) throw new J.ErreurFormat(`CT-7 §3.5 : porteur inconnu « ${c[3]} » (${c[0]})`);
    for (const mn of c[4].split(",").map((x) => x.trim())) risques.set(mn, { id: c[0], name: c[1], bound: c[2], owner });
  }
  const threats = tables.menaces.map((c) => {
    const component = idParNom.get(c[1]);
    if (!component) throw new J.ErreurFormat(`CT-7 §3.4 : composant inconnu « ${c[1]} » (${c[0]})`);
    let residuel = c[8];
    let accepted_risk = null;
    const m = / ?Risque accepté (RA-\d+)\.$/.exec(residuel);
    if (m) {
      residuel = residuel.slice(0, m.index);
      accepted_risk = risques.get(c[0]) ?? null;
      if (!accepted_risk || accepted_risk.id !== m[1]) throw new J.ErreurFormat(`CT-7 : ${c[0]} cite ${m[1]}, que la table 3.5 ne lui rattache pas`);
    }
    return {
      id: c[0],
      component,
      stride: c[2].split(",").map((x) => x.trim().replace(/^`|`$/g, "")),
      actor: c[3],
      asset: c[4],
      effect: c[5],
      response: { text: c[6], refs: refsDe(c[6]) },
      detection: { text: c[7], refs: refsDe(c[7]) },
      residual: { text: residuel, accepted_risk },
      test: PREFIXE_TEST_CT9 + c[9],
      sources: sources.get(c[0]) ?? [],
    };
  });
  return { version: 0, kind: "modele-menace", spec: "CT-7", spec_version: tables.version, date: tables.date, components, source_tables, threats };
}

/** Texte des spécifications de `spec/` (nom court → texte), lu dans `repertoire`. */
export function lireSpecifications(repertoire) {
  return Object.fromEntries(Object.entries(FICHIERS_SPEC).map(([k, f]) => [k, fs.readFileSync(path.join(repertoire, f), "utf8")]));
}

// ===========================================================================
// Contrôles de l'outil de référence sur une attestation (CT-7 EX-7.3, EX-7.4)
// ===========================================================================

/** Membres dont la valeur ne doit jamais avoir la forme d'une adresse IP (EX-7.3). */
export const MEMBRES_SANS_ADRESSE_IP = Object.freeze(["host", "name", "description", "summary", "channel", "enforcement", "notes"]);
const RE_IPV4 = /(?<![0-9.])(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?![0-9]|\.[0-9])/;
const RE_IPV6 = /(?<![0-9A-Za-z:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|::(?:[0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5})(?![0-9A-Za-z:])/;

/** Vrai si la chaîne contient une adresse IPv4 ou IPv6. */
export function contientAdresseIP(texte) {
  return typeof texte === "string" && (RE_IPV4.test(texte) || RE_IPV6.test(texte));
}

/**
 * Contrôles d'EX-7.3 et EX-7.4 sur une attestation P (l'objet, pas
 * l'attestation signée) : rend { erreurs, avertissements, rappels }, listes
 * de textes. Erreur : une adresse IP dans un membre de MEMBRES_SANS_ADRESSE_IP,
 * une destination `via: "direct"` sans ligne `not_captured` de même `channel`.
 * Avertissement : une chaîne de plus de 20 caractères sans espace dans
 * `secret_ref` qui n'est ni un chemin ni un nom de variable. Rappel : un
 * tableau `not_captured` vide déclare qu'aucune exception n'est connue, non
 * qu'il n'en existe pas.
 */
export function controlerDeclaration(P) {
  const erreurs = [];
  const avertissements = [];
  const rappels = [];
  const parcourir = (v, chemin) => {
    if (Array.isArray(v)) v.forEach((x, i) => parcourir(x, `${chemin}/${i}`));
    else if (estObjet(v)) {
      for (const [k, x] of Object.entries(v)) {
        if (MEMBRES_SANS_ADRESSE_IP.includes(k) && contientAdresseIP(x)) erreurs.push(`${chemin}/${k} : adresse IP refusée (CT-7 EX-7.3)`);
        parcourir(x, `${chemin}/${k}`);
      }
    }
  };
  parcourir(P, "");
  (P?.gateway_credentials ?? []).forEach((g, i) => {
    for (const [k, x] of Object.entries(g?.secret_ref ?? {})) {
      if (typeof x !== "string" || x.length <= 20 || /\s/.test(x)) continue;
      const chemin = x.includes("/");
      const variable = /^[A-Za-z_][A-Za-z0-9_]*$/.test(x);
      if (!chemin && !variable) avertissements.push(`/gateway_credentials/${i}/secret_ref/${k} : chaîne de ${x.length} caractères sans espace qui n'est ni un chemin ni un nom de variable ; une valeur de secret n'a pas sa place dans l'attestation (CT-7 EX-7.3)`);
    }
  });
  const canaux = new Set((P?.not_captured ?? []).map((n) => n.channel));
  (P?.egress?.allowed_destinations ?? []).forEach((d, i) => {
    if (d.via === "direct" && !canaux.has(d.name)) erreurs.push(`/egress/allowed_destinations/${i} (${d.name}) : sortie directe sans ligne not_captured de même channel (CT-7 EX-7.4)`);
  });
  if (Array.isArray(P?.not_captured) && P.not_captured.length === 0) rappels.push("not_captured est vide : cela déclare qu'aucune exception n'est connue de l'organisation, non qu'il n'en existe pas (CT-7 EX-7.4)");
  return { erreurs, avertissements, rappels };
}

/**
 * AT-1 sur une attestation P seule (sans signatures) : schéma racine
 * attestation-perimetre-v0 et relations d'EX-7.2. Rend la liste des erreurs.
 */
export function formeAttestation(P, { schemas = null } = {}) {
  const registre = schemas ?? schemasAttestation();
  const schema = registre[ID_SCHEMA_ATTESTATION_PERIMETRE];
  const erreurs = J.validerSchema(P, schema, { registre }).map((e) => `${e.chemin || "/"} : ${e.message}`);
  if (erreurs.length === 0) erreurs.push(...relationsAttestation(P));
  return erreurs;
}

// ===========================================================================
// Clés de test publiées par les vecteurs (CT-7 EX-4.10, EX-A.7, RV-9)
// ===========================================================================

/** Éléments DER (étiquette, octets de l'élément entier) contenus dans `octets`, au premier niveau. */
function elementsDER(octets) {
  const out = [];
  let i = 0;
  while (i < octets.length) {
    const debut = i;
    const etiquette = octets[i++];
    let n = octets[i++];
    if (n & 0x80) {
      const k = n & 0x7f;
      n = 0;
      for (let j = 0; j < k; j++) n = n * 256 + octets[i++];
    }
    out.push({ etiquette, element: octets.subarray(debut, i + n), contenu: octets.subarray(i, i + n) });
    i += n;
  }
  return out;
}

/**
 * SubjectPublicKeyInfo DER d'un certificat PEM, lu par la seule structure
 * TLV (RFC 5280 §4.1) : un certificat de test volontairement mal formé
 * ailleurs (nom, extension) garde ainsi sa clé publique.
 */
function spkiDuCertificat(pem) {
  const der = Buffer.from(pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  const [certificat] = elementsDER(der);
  const [tbs] = elementsDER(certificat.contenu);
  const champs = elementsDER(tbs.contenu);
  const decalage = champs[0].etiquette === 0xa0 ? 1 : 0;
  return champs[decalage + 5].element;
}

/**
 * Objet `cles-de-test.json` recalculé depuis les fichiers de clés des
 * vecteurs de `repertoire` (spec/vecteurs), lus et jamais réécrits : clés
 * Ed25519 de ct-1 (cles/cles-test.json) ; comptes Hardhat 0 à 9 du mnémonique
 * public de ct-3 (constantes.json) ; clés secp256k1 et Ed25519 dérivées
 * d'étiquettes de ct-4 (constantes.json) ; clés RSA de test de ct-6
 * (rfc3161/cles/*.pem, SHA-256 du SubjectPublicKeyInfo DER). Une entrée par
 * clé publique : { source, label, algorithm, public_key, address,
 * spki_sha256 } ; triées par source puis étiquette.
 */
export function clesDeTest(repertoire) {
  const lireJSON = (f) => JSON.parse(fs.readFileSync(path.join(repertoire, f), "utf8"));
  const cles = [];
  const ajouter = (e) => cles.push({ source: e.source, label: e.label, algorithm: e.algorithm, public_key: e.public_key ?? null, address: e.address ?? null, spki_sha256: e.spki_sha256 ?? null });
  const secp = (source, label, prive) => {
    const pub = SigningKey.computePublicKey(prive, false).toLowerCase();
    ajouter({ source, label, algorithm: "secp256k1", public_key: pub, address: "0x" + C.enHex(C.keccak256(C.depuisHex(pub).slice(1))).slice(26) });
  };
  for (const k of lireJSON("ct-1/cles/cles-test.json").keys) ajouter({ source: "ct-1", label: k.seed_label, algorithm: "ed25519", public_key: k.public_key });
  const ct3 = lireJSON("ct-3/constantes.json");
  for (let i = 0; i <= 9; i++) {
    const chemin = `m/44'/60'/0'/0/${i}`;
    secp("ct-3", chemin, HDNodeWallet.fromPhrase(ct3.mnemonic, undefined, chemin).privateKey);
  }
  const ed = new Set(cles.filter((k) => k.algorithm === "ed25519").map((k) => k.public_key));
  const parcourir = (v) => {
    if (Array.isArray(v)) return v.forEach(parcourir);
    if (!estObjet(v)) return;
    if (typeof v.seed === "string" && typeof v.private_key === "string") secp("ct-4", v.seed, v.private_key);
    if (typeof v.chain_key_seed === "string" && typeof v.chain_key_private === "string") secp("ct-4", v.chain_key_seed, v.chain_key_private);
    const graineEd = v.ed25519_seed ?? (typeof v.seed === "string" && !v.private_key && typeof v.public_key === "string" ? v.seed : null);
    if (typeof graineEd === "string" && typeof v.public_key === "string" && !ed.has(v.public_key)) {
      ed.add(v.public_key);
      ajouter({ source: "ct-4", label: graineEd, algorithm: "ed25519", public_key: v.public_key });
    }
    for (const x of Object.values(v)) parcourir(x);
  };
  // Les comptes Hardhat de ct-4 (membre accounts de la racine) sont ceux de ct-3.
  const { accounts, ...ct4 } = lireJSON("ct-4/constantes.json");
  parcourir(ct4);
  const rep6 = path.join(repertoire, "ct-6", "rfc3161", "cles");
  for (const f of fs.readdirSync(rep6).filter((x) => x.endsWith(".pem")).sort()) {
    const pem = fs.readFileSync(path.join(rep6, f), "utf8");
    const cle = pem.includes("BEGIN CERTIFICATE") ? crypto.createPublicKey({ key: spkiDuCertificat(pem), format: "der", type: "spki" }) : crypto.createPublicKey(pem);
    const der = cle.export({ type: "spki", format: "der" });
    const algorithm = cle.asymmetricKeyType === "rsa" ? "rsa" : cle.asymmetricKeyType === "ec" ? "ecdsa_p256" : cle.asymmetricKeyType;
    ajouter({ source: "ct-6", label: `rfc3161/cles/${f}`, algorithm, spki_sha256: J.sha256(der) });
  }
  cles.sort((a, b) => (a.source < b.source ? -1 : a.source > b.source ? 1 : a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  return { version: 0, keys: cles };
}
