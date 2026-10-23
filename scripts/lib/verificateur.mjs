// Vérificateur de dossier v0 (spec/CT-6-verificateur.md) : réunit les huit
// contrôles de l'architecture et produit le rapport, l'énoncé et la borne.
//
// Ce module est le cœur de l'implémentation de référence JavaScript ;
// scripts/verify/dossier.mjs n'en est que la ligne de commande (lecture bornée
// des fichiers, options, sortie). Il ne touche ni au réseau, ni au système de
// fichiers, ni à l'horloge du système (EX-3.2, EX-3.3) : les octets lui sont
// remis par l'appelant.
//
//   contrôles 1, 2, 3, 6, 7 : vérifications D-1 à A-4 de CT-1 §11.4, reprises
//                             sans changement de scripts/lib/journal.mjs ;
//   contrôle 4              : T-1 à T-11, scripts/lib/horodatage.mjs ;
//   contrôle 5              : O-1 à O-7, scripts/lib/ots.mjs ;
//   contrôle 8              : R-1 à R-10 et N-4, scripts/lib/registre.mjs ;
//   N-3                     : clés de cles.json contre celles du fichier d'ancres ;
//   N-1, N-2                : conformité du fichier d'ancres et du fichier
//                             d'en-têtes (code 2 en cas de défaut).
//
// Puis : statut de chaque contrôle (EX-6.4, EX-6.5 et les règles propres
// EX-9.18, EX-10.12, EX-11.20), verdict (EX-6.7), énoncé (EX-6.8, EX-6.9),
// borne (EX-6.12), faits (EX-6.13), rapport JSON (section 8.6, schéma
// rapport-verification-v0) et rapport lisible en français ou en anglais
// (section 8.5).

import * as J from "./journal.mjs";
import * as H from "./horodatage.mjs";
import * as O from "./ots.mjs";
import * as R from "./registre.mjs";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

export const NOM_VERIFICATEUR = "scripts/verify/dossier.mjs";
export const VERSION_VERIFICATEUR = "0.1.0";
export const FORMAT_RAPPORT = "noortrace/rapport-verification";

export const ID_SCHEMA_ANCRES = "https://noortrace.example/schemas/v0/ancres-confiance.schema.json";
export const ID_SCHEMA_ENTETES = "https://noortrace.example/schemas/v0/entetes-bitcoin.schema.json";
export const ID_SCHEMA_RAPPORT = "https://noortrace.example/schemas/v0/rapport-verification.schema.json";

/** Fichiers de spec/schemas employés par le vérificateur, avec leur $id. */
export const FICHIERS_SCHEMAS = [
  { fichier: "evenement-v0.schema.json", id: J.ID_SCHEMA_EVENEMENT },
  { fichier: "manifeste-v0.schema.json", id: J.ID_SCHEMA_MANIFESTE },
  { fichier: "dossier-v0.schema.json", id: J.ID_SCHEMA_DOSSIER },
  { fichier: "registre-v0.schema.json", id: R.ID_SCHEMA_REGISTRE },
  { fichier: "validateurs-v0.schema.json", id: R.ID_SCHEMA_VALIDATEURS },
  { fichier: "ancres-confiance-v0.schema.json", id: ID_SCHEMA_ANCRES },
  { fichier: "entetes-bitcoin-v0.schema.json", id: ID_SCHEMA_ENTETES },
  { fichier: "rapport-verification-v0.schema.json", id: ID_SCHEMA_RAPPORT },
];

const KIO = 1024;
const MIO = 1024 * 1024;

/** Limites de lecture (EX-4.13). */
export const LIMITES = {
  index: 1 * MIO,
  partieCT1: 16 * MIO,
  jeton: 64 * KIO,
  ots: 256 * KIO,
  registre: 64 * MIO,
  certificat: 64 * MIO,
  validateurs: 1 * MIO,
  entetes: 64 * MIO,
  nombreEntetes: O.BORNES.entetes,
  secondManifeste: 1 * MIO,
  ancres: 16 * MIO,
  piece: 1024 * MIO,
  profondeurJSON: 128,
};

/** Limite de lecture de chaque fichier du dossier (dossier.json et les douze parties). */
export function limiteFichier(fichier) {
  switch (fichier) {
    case "dossier.json":
      return LIMITES.index;
    case "jeton-rfc3161.der":
      return LIMITES.jeton;
    case "preuve.ots":
      return LIMITES.ots;
    case "registre.json":
      return LIMITES.registre;
    case "certificat-commit.json":
      return LIMITES.certificat;
    case "validateurs.json":
      return LIMITES.validateurs;
    default:
      return LIMITES.partieCT1;
  }
}

/** Les fichiers qu'un dossier peut contenir : dossier.json et les douze parties (CT-1 §11.1). Tout autre fichier est ignoré (EX-4.1). */
export const FICHIERS_DOSSIER = ["dossier.json", ...J.PARTIES_DOSSIER.map((p) => p.file)];

const FICHIERS_JSON_CT1 = ["evenement.json", "voisins.json", "chemin.json", "manifeste.json", "manifeste.sig", "cles.json", "approbations.json"];

/** Ordre des raisons d'un contrôle non exécuté (EX-6.5). */
const ORDRE_RAISONS = ["prerequis_en_echec", "hors_perimetre_version", "partie_absente", "ancre_absente"];

/** Contrôles servis par chaque vérification de CT-1 (table 5.1 ; P-3 sert 2 et 3, P-5 sert 3 et 6). */
const CONTROLES_CT1 = {
  "D-1": [], "D-2": [],
  "E-1": [1], "E-2": [1], "E-3": [1], "E-4": [1], "E-5": [7], "E-6": [1], "E-7": [1], "E-8": [6], "E-9": [7], "E-10": [6], "E-11": [6],
  "C-1": [2], "C-2": [2], "C-3": [6],
  "M-1": [3], "M-2": [3], "M-3": [3],
  "P-1": [3], "P-2": [3], "P-3": [2, 3], "P-4": [3], "P-5": [3, 6],
  "A-1": [7], "A-2": [7], "A-3": [7], "A-4": [7],
};

/** Vérifications de CT-1 de chaque contrôle (table 5.1). */
const VERIFICATIONS_CT1 = {
  1: ["E-1", "E-2", "E-3", "E-4", "E-6", "E-7"],
  2: ["C-1", "C-2", "P-3"],
  3: ["M-1", "M-2", "M-3", "P-1", "P-2", "P-3", "P-4", "P-5"],
  6: ["E-8", "E-10", "E-11", "C-3", "P-5"],
  7: ["E-5", "E-9", "A-1", "A-2", "A-3", "A-4"],
};

const T = (fr, en = fr) => ({ fr, en });

/** Libellés des huit contrôles (section 8.4). */
export const LIBELLES_CONTROLES = {
  1: T("hachage canonique de l'événement", "canonical hash of the event"),
  2: T("chaînage avec les voisins", "chaining with the neighbours"),
  3: T("inclusion dans la racine du manifeste", "inclusion in the manifest root"),
  4: T("jeton d'horodatage RFC 3161 sur periodHash", "RFC 3161 time-stamp token on periodHash"),
  5: T("preuve OpenTimestamps et en-têtes Bitcoin", "OpenTimestamps proof and Bitcoin headers"),
  6: T("signatures de l'enregistreur", "recorder signatures"),
  7: T("signatures des approbateurs et seuil", "approver signatures and threshold"),
  8: T("inclusion au registre, bloc certifié par un quorum", "registry inclusion, quorum-certified block"),
};

/** Libellés anglais des vérifications de CT-1 (la table 11.4 de CT-1 n'a pas de version anglaise, section 8.4). */
const LIBELLES_CT1_EN = {
  "D-1": "dossier.json index conforms to the schema, event.seq and event.hash equal to those of evenement.json",
  "D-2": "SHA-256 of each present part equal to the index; absent parts really absent, with a reason",
  "E-1": "each event conforms to evenement-v0.schema.json",
  "E-2": "canonical form computable (integers only, well-formed strings, no duplicate key)",
  "E-3": "reserved tool among the four names; fields consistent with the kind of event",
  "E-4": "every redacted reference comes with a non-null policy.redaction",
  "E-5": "approvers and signatures of the same length; approval.ticket = policy.ticket",
  "E-6": "every inline reference checks sha256 = SHA-256(JCS(value)) and length",
  "E-7": "hash recomputed from the object equal to hash",
  "E-8": "cles.json usable (schema, org_id and journal_id of the event, unique key_id and public_key, valid_to >= valid_from); Ed25519 sig valid under the public key recorder_key_id of cles.json",
  "E-9": "address recovered from each EIP-191 signature equal to approvers[i]; canonical signature",
  "E-10": "rotation event consistent with the envelope, new_key_id different from old_key_id, valid counter-signature, key and validity announced in cles.json equal (new valid_from = old valid_to = ts)",
  "E-11": "ts of each event within the announced validity of the key that signs it (bounds included; key absent: not run, E-8 carries the failure)",
  "C-1": "voisins.json: envelope { version, previous, next }; contiguous seq, non-decreasing ts, identical org_id and journal_id",
  "C-2": "prev_hash = recomputed hash of the previous event; next.prev_hash = recomputed hash of the event; prev_hash null iff seq = 1",
  "C-3": "recorder_key_id constant between neighbours, except after a rotation (new_key_id)",
  "M-1": "chemin.leaf_hash = SHA-256(0x00 || recomputed hash)",
  "M-2": "RFC 9162 inclusion algorithm on (leaf_hash, leaf_index, tree_size, path) gives chemin.root",
  "M-3": "chemin.root = manifeste.root; tree_size = count; leaf_index = seq - first_seq",
  "P-1": "manifest conforms to the schema; period_end = period_start + 3600; count = last_seq - first_seq + 1; org_id and journal_id of the event",
  "P-2": "first_seq <= seq <= last_seq and period_start <= ts < period_end for the proven event",
  "P-3": "neighbours of the period within its time bounds; neighbour outside the period at first_seq - 1 (ts < period_start) or last_seq + 1 (ts >= period_end), otherwise truncated manifest",
  "P-4": "root null iff count = 0; count >= 1 in a dossier",
  "P-5": "recomputed periodHash = manifeste.sig.period_hash; signature valid under the key of cles.json; consistent key; generated_at within its validity (cles.json unusable: not run)",
  "A-1": "approbations.json present iff approval is not null; equal ticket and request_hash",
  "A-2": "each approval event is a decision (E-1 to E-11) whose approval and arguments.value match the proven event; decision before the relayed call (seq, approval.at <= ts); a proven decision is in events",
  "A-3": "distinct approvers, members of the declared set, at least as many as required; threshold consistent with the set",
  "A-4": "request_hash = recomputed hash of the request event (status retenue) when it is in the dossier",
};

/** Libellés des vérifications R- (table 11.4) et N- (table 12.4). */
const LIBELLES_R_N = {
  "R-1": T("parties conformes et appariées", "parts well-formed and matched"),
  "R-2": T("jeu de validateurs de l'ancre", "validator set of the anchor"),
  "R-3": T("cohérence de validateurs.json", "consistency of validateurs.json"),
  "R-4": T("identifiant de chaîne", "chain identifier"),
  "R-5": T("signatures et quorum", "signatures and quorum"),
  "R-6": T("hachage du bloc", "block hash"),
  "R-7": T("racine des reçus", "receipts root"),
  "R-8": T("contrat émetteur", "emitting contract"),
  "R-9": T("événement et valeurs de la période", "event and period values"),
  "R-10": T("inscriptions", "registrations"),
  "N-1": T("fichier d'ancres", "anchors file"),
  "N-2": T("fichier d'en-têtes", "headers file"),
  "N-3": T("clés d'enregistreur", "recorder keys"),
  "N-4": T("clé de chaîne", "chain key"),
};

/** Libellé d'une vérification dans une langue. */
export function libelleVerification(id, langue = "fr") {
  const ct1 = J.CONTROLES_DOSSIER.find((c) => c.id === id);
  if (ct1) return langue === "en" ? LIBELLES_CT1_EN[id] : ct1.libelle;
  const t = H.LIBELLES[id] ?? O.LIBELLES[id] ?? LIBELLES_R_N[id];
  return t ? t[langue] : id;
}

// ---------------------------------------------------------------------------
// Erreurs : entrée inutilisable (code 2)
// ---------------------------------------------------------------------------

/**
 * Entrée inutilisable (code 2, EX-4.10, EX-4.12) : `kind` est l'un des types
 * d'erreur de la section 8.6, `check` la vérification N- en cause ou null.
 * `message` est un texte { fr, en }.
 */
export class EntreeInutilisable extends Error {
  constructor(kind, message, check = null) {
    super(typeof message === "string" ? message : message.fr);
    this.kind = kind;
    this.texte = typeof message === "string" ? T(message) : message;
    this.check = check;
  }
}

// ---------------------------------------------------------------------------
// Outils
// ---------------------------------------------------------------------------

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const choisir = (t, langue) => (t === null || t === undefined ? null : typeof t === "string" ? t : t[langue]);
const nonVide = (s) => (typeof s === "string" && s.length > 0 ? s : null);
const RE_HEX32 = /^0x[0-9a-f]{64}$/;
const RE_HORODATAGE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

/**
 * Instant RFC 3339 UTC d'un nombre de secondes UNIX, sans fraction (EX-6.11).
 * Calcul en BigInt, sans Date : aucune RangeError pour un entier que le schéma
 * du manifeste admet (jusqu'à 2^53 − 1), en lecture comme en JSON.
 */
export function instantUnix(secondes) {
  return R.instantRFC3339(secondes);
}

/** Joint une liste : « a, b et c » (fr) ou « a, b and c » (en). */
function joindreListe(liste, langue) {
  if (liste.length <= 1) return liste.join("");
  return liste.slice(0, -1).join(", ") + (langue === "en" ? " and " : " et ") + liste[liste.length - 1];
}

/** Profondeur d'imbrication d'un texte JSON (octets lus en latin1 : seuls les octets ASCII comptent). */
function profondeurOctets(octets) {
  return R.profondeurJSON(Buffer.from(octets).toString("latin1"));
}

/** Analyse JSON stricte bornée en profondeur ; rend { valeur } ou { erreur }. */
export function lireJSONBorne(octets, langue = "fr") {
  if (profondeurOctets(octets) > LIMITES.profondeurJSON) return { erreur: T(`imbrication JSON de plus de ${LIMITES.profondeurJSON} niveaux`, `JSON nesting deeper than ${LIMITES.profondeurJSON} levels`) };
  try {
    return { valeur: J.analyserJSONStrict(octets) };
  } catch (err) {
    return { erreur: T(`pas du JSON exploitable : ${err.message}`, `not usable JSON: ${err.message}`) };
  }
}

const resumerErreursSchema = (erreurs) => erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ") + (erreurs.length > 4 ? ` ; … (${erreurs.length})` : "");

// ---------------------------------------------------------------------------
// N-1 et N-2 : fichier d'ancres et fichier d'en-têtes (section 12.4)
// ---------------------------------------------------------------------------

/**
 * N-1 (EX-12.2) sur des octets déjà lus dans la limite de 16 Mio : JSON
 * strict, schéma ancres-confiance-v0, cohérence (PEM lisibles, dates
 * existantes, noms d'autorités distincts, jeux de validateurs chargeables et
 * disjoints, triplets d'enregistreurs uniques). Rend l'objet d'ancres ou lève
 * EntreeInutilisable (ancres_inutilisables, N-1).
 */
export function controlerAncres(octets, schemas) {
  const refus = (fr, en) => {
    throw new EntreeInutilisable("ancres_inutilisables", T(`fichier d'ancres inutilisable : ${fr}`, `unusable anchors file: ${en}`), "N-1");
  };
  if (octets.length > LIMITES.ancres) refus(`${octets.length} octets, au-delà de la limite de ${LIMITES.ancres}`, `${octets.length} bytes, beyond the limit of ${LIMITES.ancres}`);
  const lu = lireJSONBorne(octets);
  if (lu.erreur) refus(lu.erreur.fr, lu.erreur.en);
  const ancres = lu.valeur;
  const erreurs = J.validerSchema(ancres, schemas[ID_SCHEMA_ANCRES], { registre: schemas });
  if (erreurs.length) refus(`non conforme à ancres-confiance-v0 : ${resumerErreursSchema(erreurs)}`, `does not conform to ancres-confiance-v0: ${resumerErreursSchema(erreurs)}`);
  const defauts = [];
  if (!horodatageExiste(ancres.prepared_at)) defauts.push(`/prepared_at : date inexistante (${ancres.prepared_at})`);
  defauts.push(...H.controlerAncresTsa(ancres));
  defauts.push(...R.defautsAncreRegistre(ancres.registry));
  const triplets = new Map();
  ancres.recorders.forEach((r, i) => {
    const k = `${r.org_id}|${r.journal_id}|${r.key_id}`;
    if (triplets.has(k)) defauts.push(`/recorders/${i} : (org_id, journal_id, key_id) déjà déclaré en /recorders/${triplets.get(k)}`);
    else triplets.set(k, i);
  });
  if (defauts.length) refus(defauts.join(" ; "), defauts.join("; "));
  return ancres;
}
const horodatageExiste = (v) => {
  const ms = Date.parse(v);
  return typeof v === "string" && !Number.isNaN(ms) && new Date(ms).toISOString() === v;
};

/**
 * N-2 (EX-12.3) sur des octets déjà lus dans la limite de 64 Mio : JSON
 * strict, au plus 200 000 en-têtes, schéma entetes-bitcoin-v0,
 * start_height + n − 1 < 2^32. Rend l'objet ou lève EntreeInutilisable
 * (taille_depassee ou entree_illisible, N-2).
 */
export function controlerEntetes(octets, schemas) {
  const refus = (kind, fr, en) => {
    throw new EntreeInutilisable(kind, T(`fichier d'en-têtes Bitcoin inutilisable : ${fr}`, `unusable Bitcoin headers file: ${en}`), "N-2");
  };
  if (octets.length > LIMITES.entetes) refus("taille_depassee", `${octets.length} octets, au-delà de la limite de ${LIMITES.entetes}`, `${octets.length} bytes, beyond the limit of ${LIMITES.entetes}`);
  const lu = lireJSONBorne(octets);
  if (lu.erreur) refus("entree_illisible", lu.erreur.fr, lu.erreur.en);
  const objet = lu.valeur;
  if (estObjet(objet) && Array.isArray(objet.headers) && objet.headers.length > LIMITES.nombreEntetes) refus("taille_depassee", `${objet.headers.length} en-têtes, au-delà de ${LIMITES.nombreEntetes}`, `${objet.headers.length} headers, beyond ${LIMITES.nombreEntetes}`);
  const erreurs = J.validerSchema(objet, schemas[ID_SCHEMA_ENTETES], { registre: schemas });
  if (erreurs.length) refus("entree_illisible", `non conforme à entetes-bitcoin-v0 : ${resumerErreursSchema(erreurs)}`, `does not conform to entetes-bitcoin-v0: ${resumerErreursSchema(erreurs)}`);
  const defauts = O.controlerEntetes(objet);
  if (defauts.length) refus("entree_illisible", defauts.join(" ; "), defauts.join("; "));
  return objet;
}

/**
 * Second manifeste (EX-4.7, EX-4.12) : au plus 1 Mio, JSON strict, schéma
 * manifeste-v0. Rend l'objet ou lève EntreeInutilisable.
 */
export function controlerSecondManifeste(octets, schemas) {
  const refus = (kind, fr, en) => {
    throw new EntreeInutilisable(kind, T(`second manifeste inutilisable : ${fr}`, `unusable second manifest: ${en}`));
  };
  if (octets.length > LIMITES.secondManifeste) refus("taille_depassee", `${octets.length} octets, au-delà de la limite de ${LIMITES.secondManifeste}`, `${octets.length} bytes, beyond the limit of ${LIMITES.secondManifeste}`);
  const lu = lireJSONBorne(octets);
  if (lu.erreur) refus("entree_illisible", lu.erreur.fr, lu.erreur.en);
  const erreurs = J.validerSchema(lu.valeur, schemas[J.ID_SCHEMA_MANIFESTE], { registre: schemas });
  if (erreurs.length) refus("entree_illisible", `non conforme à manifeste-v0 : ${resumerErreursSchema(erreurs)}`, `does not conform to manifeste-v0: ${resumerErreursSchema(erreurs)}`);
  return lu.valeur;
}

// ---------------------------------------------------------------------------
// Traduction des détails de CT-1 (section 8.4)
// ---------------------------------------------------------------------------

const ROLES_EN = [
  [/^evenement : /, "event: "],
  [/^voisin précédent : /, "previous neighbour: "],
  [/^voisin suivant : /, "next neighbour: "],
  [/^approbation\[(\d+)\] : /, "approval[$1]: "],
];
const SEGMENTS_EN = [
  [/^dossier\.json conforme au schéma$/, "dossier.json conforms to the schema"],
  [/^hash (0x[0-9a-f]{64})$/, "hash $1"],
  [/^hash recalculé (0x[0-9a-f]+) différent de hash (\S+)$/, "recomputed hash $1 differs from hash $2"],
  [/^signature valide sous (\S+)$/, "valid signature under $1"],
  [/^signature invalide sous la clé (\S+) \((\S+)\)$/, "invalid signature under key $1 ($2)"],
  [/^clé (\S+) absente de cles\.json$/, "key $1 not in cles.json"],
  [/^previous (seq \d+|null), next (seq \d+|null)$/, "previous $1, next $2"],
  [/^chaînage avec les voisins fournis$/, "chaining with the given neighbours"],
  [/^clé (\S+) puis (\S+)$/, "key $1 then $2"],
  [/^clé (\S+)$/, "key $1"],
  [/^leaf_hash (0x[0-9a-f]+)$/, "leaf_hash $1"],
  [/^chemin de (\d+) nœud\(s\) mène à la racine \(indice (\d+), taille (\d+)\)$/, "path of $1 node(s) leads to the root (index $2, size $3)"],
  [/^chemin cohérent avec le manifeste$/, "path consistent with the manifest"],
  [/^période \[(\d+), (\d+)\), seq (\d+)\.\.(\d+)$/, "period [$1, $2), seq $3..$4"],
  [/^événement dans la période$/, "event within the period"],
  [/^voisins cohérents avec la période$/, "neighbours consistent with the period"],
  [/^count (\d+), racine (0x[0-9a-f]+)$/, "count $1, root $2"],
  [/^periodHash (0x[0-9a-f]+) signé par (\S+)$/, "periodHash $1 signed by $2"],
  [/^ticket (\S+)$/, "ticket $1"],
  [/^(\d+) événement\(s\) de décision cohérent\(s\)$/, "$1 consistent decision event(s)"],
  [/^(\d+) approbateur\(s\) distinct\(s\) sur un seuil de (\d+)\/(\d+)$/, "$1 distinct approver(s) for a threshold of $2/$3"],
  [/^événement de demande \(request_hash (0x[0-9a-f]+)\) absent du dossier : non vérifiable$/, "request event (request_hash $1) not in the dossier: cannot be checked"],
  [/^événement de demande seq (\d+) retenu, hash égal à request_hash$/, "request event seq $1 held, hash equal to request_hash"],
  [/^aucune approbation liée, partie absente avec sa raison$/, "no linked approval, part absent with its reason"],
  [/^aucune approbation liée$/, "no linked approval"],
  [/^index inexploitable$/, "unusable index"],
  [/^événement ou voisins inexploitables$/, "event or neighbours unusable"],
  [/^chemin\.json inexploitable$/, "chemin.json unusable"],
  [/^manifeste\.json inexploitable$/, "manifeste.json unusable"],
  [/^manifeste\.sig inexploitable$/, "manifeste.sig unusable"],
  [/^manifeste ou événement inexploitable$/, "manifest or event unusable"],
  [/^événement inexploitable$/, "event unusable"],
  [/^événement inexploitable \(objet attendu\)$/, "event unusable (object expected)"],
  [/^hash de l'événement incalculable$/, "hash of the event cannot be computed"],
  [/^forme canonique incalculable$/, "canonical form cannot be computed"],
  [/^aucun événement lisible$/, "no readable event"],
  [/^aucune clé publique fournie$/, "no public key given"],
  [/^aucune période de validité annoncée$/, "no validity period announced"],
  [/^approbations\.json absent ou inexploitable$/, "approbations.json absent or unusable"],
  [/^approval non nul mais approbations\.json absent ou inexploitable$/, "approval not null but approbations.json absent or unusable"],
  [/^cles\.json inexploitable \(E-8\) : signature du manifeste non vérifiable$/, "cles.json unusable (E-8): manifest signature cannot be checked"],
  [/^(\S+) déclaré présent mais absent du répertoire$/, "$1 declared present but missing from the directory"],
  [/^(\S+) déclaré absent mais présent dans le répertoire$/, "$1 declared absent but present in the directory"],
  [/^(\S+) : SHA-256 (0x[0-9a-f]+) différent de l'index (\S+)$/, "$1: SHA-256 $2 differs from the index $3"],
  [/^periodHash recalculé (0x[0-9a-f]+) différent de manifeste\.sig\.period_hash (\S+)$/, "recomputed periodHash $1 differs from manifeste.sig.period_hash $2"],
  [/^signature du manifeste invalide sous (\S+)$/, "invalid manifest signature under $1"],
  [/^chemin\.root (\S+) différent de manifeste\.root (\S+)$/, "chemin.root $1 differs from manifeste.root $2"],
  [/^(\d+) pièce\(s\) fournie\(s\) à part vérifiée\(s\)$/, "$1 piece(s) given separately checked"],
  [/^continuité avec le manifeste (précédent|suivant) \(periodHash (0x[0-9a-f]+)\) vérifiée$/, (_, sens, h) => `continuity with the ${sens === "précédent" ? "previous" : "next"} manifest (periodHash ${h}) checked`],
];

/** Détail d'une vérification de CT-1 en anglais : traduction segment par segment ; un segment non reconnu reste en français. */
export function traduireDetailCT1(detail) {
  if (detail === null) return null;
  return detail
    .split(" ; ")
    .map((segment) => {
      let prefixe = "";
      let reste = segment;
      for (const [re, rempl] of ROLES_EN) {
        if (re.test(reste)) {
          prefixe = reste.match(re)[0].replace(re, rempl);
          reste = reste.replace(re, "");
          break;
        }
      }
      for (const [re, rempl] of SEGMENTS_EN) if (re.test(reste)) return prefixe + reste.replace(re, rempl);
      return prefixe + reste;
    })
    .join("; ");
}

// ---------------------------------------------------------------------------
// Vérification d'un dossier
// ---------------------------------------------------------------------------

/**
 * Vérifie un dossier v0 et rend le corps du rapport (sans `verifier` ni
 * `inputs`, que la ligne de commande ajoute).
 *
 * Paramètres :
 *   fichiers        : nom -> octets des fichiers du dossier lus dans leur limite
 *                     (dossier.json et les parties présentes dans le répertoire) ;
 *   nonLus          : Map nom -> { taille, limite, debut } des fichiers du
 *                     dossier au-delà de leur limite, non lus (debut : les
 *                     limite + 1 premiers octets) ;
 *   schemas         : registre des schémas ($id -> document) ;
 *   ancres          : fichier d'ancres déjà contrôlé par N-1, ou null ;
 *   entetes         : fichier d'en-têtes déjà contrôlé par N-2, ou null ;
 *   pieces          : null, ou { lire(nom) -> octets | null } (pièces fournies
 *                     à part, nommées par leur sha256 sans 0x, EX-4.6) ;
 *   secondManifeste : second manifeste conforme à son schéma, ou null ;
 *   exiger          : numéros des contrôles exigés (--exiger) ;
 *   langue          : "fr" ou "en".
 *
 * Lève J.DossierInutilisable quand dossier.json est absent ou n'est pas du JSON.
 */
export function verifierDossierComplet({ fichiers, nonLus = new Map(), schemas, ancres = null, entetes = null, pieces = null, secondManifeste = null, exiger = [], langue = "fr" }) {
  const L = (fr, en) => (langue === "en" ? en : fr);
  const lang = (t) => choisir(t, langue);

  // Parties refusées avant l'analyse : au-delà de leur limite (non lues), ou
  // imbrication JSON au-delà de 128 niveaux (EX-4.11, EX-4.13).
  const inexploitables = new Map();
  for (const [f, info] of nonLus) inexploitables.set(f, `fichier de ${info.taille} octets, au-delà de la limite de ${info.limite} octets, non lu`);
  for (const f of FICHIERS_JSON_CT1) if (fichiers[f] && profondeurOctets(fichiers[f]) > LIMITES.profondeurJSON) inexploitables.set(f, `imbrication JSON de plus de ${LIMITES.profondeurJSON} niveaux`);
  if (fichiers["dossier.json"] && profondeurOctets(fichiers["dossier.json"]) > LIMITES.profondeurJSON) throw new J.DossierInutilisable(`dossier.json illisible : imbrication JSON de plus de ${LIMITES.profondeurJSON} niveaux`);

  // Contrôles 1, 2, 3, 6, 7 : vérifications de CT-1, sans changement.
  const ct1 = J.verifierDossier(fichiers, { schemas, inexploitables });

  const lireObjet = (f) => {
    if (!fichiers[f] || inexploitables.has(f)) return null;
    try {
      const v = J.analyserJSONStrict(fichiers[f]);
      return estObjet(v) ? v : null;
    } catch {
      return null;
    }
  };
  const indexBrut = (() => {
    try {
      return J.analyserJSONStrict(fichiers["dossier.json"]);
    } catch {
      return null;
    }
  })();
  const index = estObjet(indexBrut) ? indexBrut : {};
  const parts = Array.isArray(index.parts) && index.parts.length === J.PARTIES_DOSSIER.length ? index.parts : null;
  const partie = (name) => (parts ? parts.find((p) => estObjet(p) && p.name === name) ?? null : null);
  const ev = lireObjet("evenement.json");
  const voisins = lireObjet("voisins.json");
  const chemin = lireObjet("chemin.json");
  const manifeste = lireObjet("manifeste.json");
  const manifesteSig = lireObjet("manifeste.sig");
  const clesDoc = lireObjet("cles.json");
  const approbations = lireObjet("approbations.json");

  // Vérifications de CT-1 au format du rapport ; raisons de EX-6.3.
  const pApprobations = partie("approbations");
  const sansApprobation = Boolean(pApprobations && pApprobations.present === false && pApprobations.reason_if_absent === J.RAISON_AUCUNE_APPROBATION);
  const checks = new Map();
  for (const c of ct1.controles) {
    let status;
    let reason = null;
    if (c.ok === false) status = "echoue";
    else if (c.execute) status = "reussi";
    else {
      status = "non_execute";
      if (["A-2", "A-3", "A-4"].includes(c.id) && c.detail === J.RAISON_AUCUNE_APPROBATION && sansApprobation) reason = "partie_absente";
      else if (c.id === "A-4" && /^événement de demande \(request_hash /.test(c.detail ?? "")) reason = "piece_hors_dossier";
      else reason = "prerequis_en_echec";
    }
    checks.set(c.id, { id: c.id, controls: CONTROLES_CT1[c.id], status, reason, detailFr: c.detail });
  }

  // E-6 avec les pièces fournies à part (EX-4.6).
  let piecesLues = 0;
  if (pieces && checks.get("E-6").status !== "non_execute") {
    const roles = [];
    if (ev) roles.push({ role: "evenement", e: ev });
    if (voisins && estObjet(voisins.previous)) roles.push({ role: "voisin précédent", e: voisins.previous });
    if (voisins && estObjet(voisins.next)) roles.push({ role: "voisin suivant", e: voisins.next });
    if (approbations && Array.isArray(approbations.events)) approbations.events.forEach((e, i) => estObjet(e) && roles.push({ role: `approbation[${i}]`, e }));
    const cache = new Map();
    const fautes = [];
    let verifiees = 0;
    for (const { role, e } of roles) {
      for (const { chemin: ou, ref } of J.referencesEvenement(e)) {
        if (!estObjet(ref) || typeof ref.sha256 !== "string" || !RE_HEX32.test(ref.sha256)) continue;
        const nom = ref.sha256.slice(2);
        if (!cache.has(nom)) {
          const octets = pieces.lire(nom);
          if (octets) piecesLues++;
          cache.set(nom, octets);
        }
        const octets = cache.get(nom);
        if (!octets) continue;
        const r = J.verifierReference({ ...ref, value: undefined }, octets);
        verifiees++;
        if (!r.ok) fautes.push(`${role} : ${ou} : pièce ${nom} : ${r.raison}`);
      }
    }
    const e6 = checks.get("E-6");
    if (fautes.length) {
      e6.detailFr = [...(e6.status === "echoue" && e6.detailFr ? [e6.detailFr] : []), ...fautes].join(" ; ");
      e6.status = "echoue";
    } else if (e6.status === "reussi" && verifiees) e6.detailFr = [e6.detailFr, `${[...cache.values()].filter(Boolean).length} pièce(s) fournie(s) à part vérifiée(s)`].filter(Boolean).join(" ; ");
  }

  // P-5 avec le second manifeste (EX-4.7) : continuité de CT-1 §10.3.
  const p1Reussie = checks.get("P-1").status === "reussi";
  if (secondManifeste && p1Reussie && checks.get("P-5").status !== "non_execute") {
    const p5 = checks.get("P-5");
    const fautes = [];
    let succes = null;
    try {
      if (secondManifeste.org_id !== manifeste.org_id || secondManifeste.journal_id !== manifeste.journal_id) fautes.push("second manifeste d'un autre journal (org_id ou journal_id différents)");
      else if (secondManifeste.period_start === manifeste.period_start) fautes.push("second manifeste ni précédent ni suivant (même period_start)");
      else {
        const precede = secondManifeste.period_start < manifeste.period_start;
        const c = precede ? J.verifierContinuiteManifestes(secondManifeste, manifeste) : J.verifierContinuiteManifestes(manifeste, secondManifeste);
        if (!c.valide) fautes.push(...c.erreurs.map((e) => `second manifeste ${precede ? "précédent" : "suivant"} : ${e}`));
        else succes = `continuité avec le manifeste ${precede ? "précédent" : "suivant"} (periodHash ${J.hachageManifeste(secondManifeste)}) vérifiée`;
      }
    } catch (err) {
      fautes.push(`second manifeste sans forme canonique : ${err.message}`);
    }
    if (fautes.length) {
      p5.detailFr = [...(p5.status === "echoue" && p5.detailFr ? [p5.detailFr] : []), ...fautes].join(" ; ");
      p5.status = "echoue";
    } else if (succes && p5.status === "reussi") p5.detailFr = [p5.detailFr, succes].filter(Boolean).join(" ; ");
  }

  // periodHash recalculé (EX-5.4) : P-1 réussie et forme canonique calculable.
  let periodHash = null;
  if (p1Reussie) {
    try {
      periodHash = J.hachageManifeste(manifeste);
    } catch {
      periodHash = null;
    }
  }
  const manifesteP1 = p1Reussie ? manifeste : null;
  const tsEvenement = ev && typeof ev.ts === "string" ? ev.ts : null;

  // Première partie de E-8 : cles.json conforme, org_id et journal_id de l'événement, key_id et
  // public_key uniques, valid_to ≥ valid_from (pour R-10 et N-3).
  let clesListe = null;
  if (clesDoc && !inexploitables.has("cles.json")) {
    const erreurs = J.validerSchema(clesDoc, schemas[J.ID_SCHEMA_DOSSIER], { registre: schemas, fragment: "#/$defs/cles" });
    if (erreurs.length === 0 && J.verifierCles(clesDoc, ev).length === 0) clesListe = clesDoc.keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key }));
  }

  // Parties réservées : état de chacune (index exploitable ou non, présente, absente, trop grande, manquante).
  const etatPartie = (name, file) => {
    if (!parts) return { etat: "index" };
    const p = partie(name);
    if (!p || p.present !== true) return { etat: "absente", raison: p && typeof p.reason_if_absent === "string" ? p.reason_if_absent : null };
    if (nonLus.has(file)) return { etat: "trop_grande", ...nonLus.get(file) };
    if (!fichiers[file]) return { etat: "manquante" };
    return { etat: "presente", octets: fichiers[file] };
  };
  const raisonAbsence = (raison) => (raison === J.RAISON_HORS_PERIMETRE ? "hors_perimetre_version" : "partie_absente");
  const resumeAbsence = (fichiersAbsents, raisons) => {
    const motifs = [...new Set(raisons.map((r) => r ?? L("sans raison déclarée", "no declared reason")))];
    return L(`${fichiersAbsents.join(", ")} ${fichiersAbsents.length > 1 ? "absents" : "absent"} (${motifs.join(" ; ")})`, `${fichiersAbsents.join(", ")} absent (${motifs.join("; ")})`);
  };

  /** Contrôles 4 et 5 : même traitement des états de la partie. */
  const controleBinaire = (name, file, idPremier, limite, verifier) => {
    const e = etatPartie(name, file);
    if (e.etat === "index") return { status: "non_execute", reason: "prerequis_en_echec", summary: L("index dossier.json inexploitable", "dossier.json index unusable"), checks: [], warnings: [], anchors_used: [], facts: null, proposition: null };
    if (e.etat === "absente") return { status: "non_execute", reason: raisonAbsence(e.raison), summary: resumeAbsence([file], [e.raison]), checks: [], warnings: [], anchors_used: [], facts: null, proposition: null };
    const octets = e.etat === "presente" ? e.octets : e.etat === "trop_grande" ? e.debut : Buffer.alloc(0);
    const r = verifier(octets);
    if (e.etat !== "presente") {
      const premier = r.checks.find((c) => c.id === idPremier);
      premier.status = "echoue";
      premier.reason = null;
      premier.admitted = null;
      premier.detail = e.etat === "trop_grande" ? L(`${file} : fichier de ${e.taille} octets, au-delà de la limite de ${limite} octets ; la partie est inexploitable`, `${file}: file of ${e.taille} bytes, beyond the limit of ${limite} bytes; the part is unusable`) : L(`${file} déclaré présent mais absent du répertoire`, `${file} declared present but missing from the directory`);
      r.status = "echoue";
      r.reason = null;
      r.summary = L(`vérification(s) en échec : ${idPremier}`, `failed check(s): ${idPremier}`);
      r.facts = null;
      r.proposition = null;
    }
    return r;
  };

  // Contrôle 4 : jeton RFC 3161 (section 9).
  const c4 = controleBinaire("jeton_rfc3161", "jeton-rfc3161.der", "T-1", LIMITES.jeton, (octets) => H.verifierJeton(octets, { periodHash, ancres, tsEvenement, langue }));
  // Contrôle 5 : preuve OpenTimestamps (section 10).
  const c5 = controleBinaire("preuve_ots", "preuve.ots", "O-1", LIMITES.ots, (octets) => O.verifierPreuve(octets, { periodHash, entetes, ancres, langue }));

  // Contrôle 8 : registre et certificat de commit (section 11).
  let c8;
  if (!parts) {
    c8 = { statut: "non_execute", raison: "prerequis_en_echec", resume: L("index dossier.json inexploitable", "dossier.json index unusable"), ancresEmployees: [], verifications: [], n4: null, avertissements: [], faits: null, enonce: null, inscriptionsProuvees: [] };
  } else {
    const parties8 = {};
    for (const [name, file] of [["registre", "registre.json"], ["certificat_commit", "certificat-commit.json"], ["validateurs", "validateurs.json"]]) {
      const e = etatPartie(name, file);
      if (e.etat === "absente") parties8[name] = { present: false, raison: e.raison };
      else if (e.etat === "trop_grande") parties8[name] = { present: true, octets: e.debut, tropGrand: true };
      else if (e.etat === "manquante") parties8[name] = { present: true, octets: null };
      else parties8[name] = { present: true, octets: e.octets };
    }
    c8 = R.verifierControle8({ parties: parties8, manifeste: manifesteP1, periodHash, cles: clesListe, ancres, schemas, langue });
  }

  // N-3 : clés d'enregistreur du fichier d'ancres (EX-12.4).
  const orgId = ev?.org_id ?? null;
  const journalId = ev?.journal_id ?? null;
  const recordersDossier = (ancres?.recorders ?? []).map((r, i) => ({ ...r, indice: i })).filter((r) => r.org_id === orgId && r.journal_id === journalId);
  let n3 = null;
  const clesConfirmeesN3 = new Set();
  const pointeursN3 = [];
  if (ancres && recordersDossier.length) {
    if (!clesListe) {
      n3 = { status: "non_execute", reason: "prerequis_en_echec", detail: T("cles.json inexploitable (première partie de E-8)", "cles.json unusable (first part of E-8)") };
    } else {
      const signataires = new Set();
      const ajouter = (e) => estObjet(e) && typeof e.recorder_key_id === "string" && signataires.add(e.recorder_key_id);
      ajouter(ev);
      if (voisins) [voisins.previous, voisins.next].forEach(ajouter);
      if (approbations && Array.isArray(approbations.events)) approbations.events.forEach(ajouter);
      if (manifesteSig && typeof manifesteSig.recorder_key_id === "string") signataires.add(manifesteSig.recorder_key_id);
      const comparees = [];
      const differences = [];
      for (const cle of clesListe) {
        if (!signataires.has(cle.key_id)) continue;
        const a = recordersDossier.find((r) => r.key_id === cle.key_id);
        if (!a) continue;
        comparees.push({ cle, a });
        pointeursN3.push(`/recorders/${a.indice}`);
        if (a.public_key !== cle.public_key) differences.push(T(`${cle.key_id} : public_key ${cle.public_key} de cles.json différente de ${a.public_key} de l'ancre (/recorders/${a.indice})`, `${cle.key_id}: public_key ${cle.public_key} of cles.json differs from ${a.public_key} of the anchors file (/recorders/${a.indice})`));
      }
      pointeursN3.sort((x, y) => Number(x.split("/")[2]) - Number(y.split("/")[2]));
      if (differences.length) n3 = { status: "echoue", reason: null, detail: T(differences.map((d) => d.fr).join(" ; "), differences.map((d) => d.en).join("; ")) };
      else if (comparees.length) {
        for (const { cle } of comparees) clesConfirmeesN3.add(cle.key_id);
        const ids = comparees.map((x) => x.cle.key_id);
        const ptrs = comparees.map((x) => `/recorders/${x.a.indice}`).join(", ");
        n3 = {
          status: "reussi",
          reason: null,
          detail: T(`${joindreListe(ids, "fr")} de cles.json ${ids.length > 1 ? "égales aux clés" : "égale à la clé"} de l'ancre (${ptrs})`, `${joindreListe(ids, "en")} of cles.json equal to the anchors file's ${ids.length > 1 ? "keys" : "key"} (${ptrs})`),
        };
      } else n3 = { status: "non_execute", reason: "ancre_absente", detail: T("aucune clé signataire du dossier dans les enregistreurs du fichier d'ancres", "no signing key of the dossier among the recorders of the anchors file") };
    }
  }

  // Liste des vérifications, dans l'ordre de la section 5.2 : D, E, C, M, P, A, T, O, R, N.
  const liste = [];
  for (const c of J.CONTROLES_DOSSIER) {
    const x = checks.get(c.id);
    const detail = x.detailFr === null || x.detailFr === undefined ? null : langue === "en" ? traduireDetailCT1(x.detailFr) : x.detailFr;
    liste.push({ id: x.id, controls: x.controls, status: x.status, reason: x.reason, admitted: x.status === "non_execute" ? x.reason !== "prerequis_en_echec" : null, detail: nonVide(detail) });
  }
  const normaliser = (c) => ({ id: c.id, controls: c.controls, status: c.status, reason: c.status === "non_execute" ? c.reason : null, admitted: c.status === "non_execute" ? c.reason !== "prerequis_en_echec" : null, detail: nonVide(c.detail) });
  for (const c of c4.checks) liste.push(normaliser(c));
  for (const c of c5.checks) liste.push(normaliser(c));
  for (const c of c8.verifications) liste.push(normaliser(c));
  if (n3) liste.push(normaliser({ id: "N-3", controls: [6], status: n3.status, reason: n3.reason, detail: lang(n3.detail) }));
  if (c8.n4) liste.push(normaliser(c8.n4));
  const parId = new Map(liste.map((c) => [c.id, c]));

  // Statut des contrôles 1, 2, 3, 6, 7 (EX-6.4, EX-6.5).
  const statutCT1 = (ids, sansEffet = []) => {
    const vs = ids.map((id) => parId.get(id)).filter(Boolean);
    if (vs.some((v) => v.status === "echoue")) return { status: "echoue", reason: null };
    const non = vs.filter((v) => v.status === "non_execute" && v.reason !== "piece_hors_dossier" && !sansEffet.includes(v.id));
    if (non.length) return { status: "non_execute", reason: ORDRE_RAISONS.find((r) => non.some((v) => v.reason === r)) ?? "prerequis_en_echec" };
    return { status: "reussi", reason: null };
  };
  const idsControle = {
    1: VERIFICATIONS_CT1[1],
    2: VERIFICATIONS_CT1[2],
    3: VERIFICATIONS_CT1[3],
    4: c4.checks.map((c) => c.id),
    5: c5.checks.map((c) => c.id),
    6: [...VERIFICATIONS_CT1[6], ...(n3 ? ["N-3"] : [])],
    7: VERIFICATIONS_CT1[7],
    8: [...c8.verifications.map((c) => c.id), ...(c8.n4 ? ["N-4"] : [])],
  };
  const statuts = {
    1: statutCT1(idsControle[1]),
    2: statutCT1(idsControle[2]),
    3: statutCT1(idsControle[3]),
    4: { status: c4.status, reason: c4.reason },
    5: { status: c5.status, reason: c5.reason },
    6: statutCT1(idsControle[6], ["N-3"]),
    7: statutCT1(idsControle[7]),
    8: { status: c8.statut, reason: c8.raison },
  };
  const reussi = (n) => statuts[n].status === "reussi";

  // Provenance des clés employées (EX-3.6, EX-6.8) : clé par clé, ancres
  // (confirmée par N-3), registre (inscription prouvée par R-10 dans un
  // contrôle 8 réussi) ou dossier ; « mixte » quand les deux clés diffèrent.
  const cleEvenement = ev?.recorder_key_id ?? null;
  const cleManifeste = manifesteSig?.recorder_key_id ?? null;
  const inscrites = new Set(reussi(8) ? (c8.inscriptionsProuvees ?? []).map((x) => x.key_id) : []);
  const provenanceCle = (k) => (clesConfirmeesN3.has(k) ? "ancres" : inscrites.has(k) ? "registre" : "dossier");
  const provenanceEvenement = provenanceCle(cleEvenement);
  const provenanceManifeste = provenanceCle(cleManifeste);
  const provenance = provenanceEvenement === provenanceManifeste ? provenanceEvenement : "mixte";

  // Résumés des contrôles.
  const echecsDe = (n) => idsControle[n].filter((id) => parId.get(id)?.status === "echoue");
  const bloquantsDe = (n) => idsControle[n].filter((id) => parId.get(id)?.status === "non_execute" && parId.get(id).reason === "prerequis_en_echec");
  const resumeGenerique = (n) => {
    const s = statuts[n];
    if (s.status === "echoue") return L(`vérification(s) en échec : ${echecsDe(n).join(", ")}`, `failed check(s): ${echecsDe(n).join(", ")}`);
    if (s.status === "non_execute" && s.reason === "prerequis_en_echec") return L(`vérification(s) non exécutée(s) sans raison admise : ${bloquantsDe(n).join(", ")}`, `check(s) not run without an admitted reason: ${bloquantsDe(n).join(", ")}`);
    return null;
  };
  const voisinsSeq = { p: estObjet(voisins?.previous) ? voisins.previous.seq : null, n: estObjet(voisins?.next) ? voisins.next.seq : null };
  const provTexte = {
    ancres: { pl: T("clés fournies par le fichier d'ancres", "keys given by the anchors file"), sg: T("clé fournie par le fichier d'ancres", "key given by the anchors file"), seule: T("fournie par le fichier d'ancres", "given by the anchors file") },
    registre: { pl: T("clés inscrites au registre", "keys registered in the registry"), sg: T("clé inscrite au registre", "key registered in the registry"), seule: T("inscrite au registre", "registered in the registry") },
    dossier: { pl: T("clés déclarées par le dossier", "keys declared by the dossier"), sg: T("clé déclarée par le dossier", "key declared by the dossier"), seule: T("déclarée par le dossier", "declared by the dossier") },
  };
  const resumes = {};
  resumes[1] = reussi(1) ? L("hachage canonique recalculé égal à hash", "recomputed canonical hash equals hash") : resumeGenerique(1);
  if (reussi(2)) {
    const { p, n } = voisinsSeq;
    resumes[2] =
      p !== null && n !== null ? L(`chaîné aux voisins seq ${p} et ${n}`, `chained to neighbours seq ${p} and ${n}`)
      : p !== null ? L(`chaîné au voisin précédent seq ${p} (le dossier ne fournit pas de suivant)`, `chained to previous neighbour seq ${p} (the dossier gives no next event)`)
      : n !== null ? L(`premier événement du journal, chaîné au voisin suivant seq ${n}`, `first event of the journal, chained to next neighbour seq ${n}`)
      : L("premier événement du journal, sans voisin dans le dossier", "first event of the journal, with no neighbour in the dossier");
  } else resumes[2] = resumeGenerique(2);
  resumes[3] = reussi(3) ? L(`feuille ${chemin.leaf_index} de l'arbre de ${chemin.tree_size} du manifeste ${periodHash}`, `leaf ${chemin.leaf_index} of the ${chemin.tree_size}-leaf tree of manifest ${periodHash}`) : resumeGenerique(3);
  resumes[4] = c4.summary ?? null;
  resumes[5] = c5.summary ?? null;
  if (reussi(6)) {
    const deux = cleEvenement !== cleManifeste;
    if (provenance === "mixte") {
      const pe = provTexte[provenanceEvenement].seule;
      const pm = provTexte[provenanceManifeste].seule;
      resumes[6] = L(`${cleEvenement} (événement, ${pe.fr}), ${cleManifeste} (manifeste, ${pm.fr})`, `${cleEvenement} (event, ${pe.en}), ${cleManifeste} (manifest, ${pm.en})`);
    } else {
      const prov = provTexte[provenance][deux ? "pl" : "sg"];
      resumes[6] = deux ? L(`${cleEvenement} (événement), ${cleManifeste} (manifeste), ${prov.fr}`, `${cleEvenement} (event), ${cleManifeste} (manifest), ${prov.en}`) : L(`${cleEvenement} (événement et manifeste), ${prov.fr}`, `${cleEvenement} (event and manifest), ${prov.en}`);
    }
  } else resumes[6] = resumeGenerique(6);
  if (reussi(7)) {
    const a = ev.approval;
    const n = a.approvers.length;
    const horsDossier = parId.get("A-4")?.reason === "piece_hors_dossier";
    // La décision est nommée quand ce n'est pas une approbation (F3, EX-6.8).
    const quoi = { approuve: T("", ""), refuse: T(" (refus)", " (refusal)"), expire: T(" (demande expirée)", " (expired request)") }[a.decision] ?? T(` (${a.decision})`, ` (${a.decision})`);
    const sig = n === 0 ? T("aucune signature", "no signature") : T(`${n} signature${n > 1 ? "s" : ""}`, `${n} signature${n > 1 ? "s" : ""}`);
    resumes[7] = L(`${a.ticket}${quoi.fr} : ${sig.fr}, seuil ${a.threshold.required} sur ${a.threshold.size}${horsDossier ? " ; A-4 hors dossier" : ""}`, `${a.ticket}${quoi.en}: ${sig.en}, threshold ${a.threshold.required} of ${a.threshold.size}${horsDossier ? "; A-4 outside the dossier" : ""}`);
  } else if (statuts[7].status === "non_execute" && statuts[7].reason === "partie_absente") {
    resumes[7] = resumeAbsence(["approbations.json"], [pApprobations?.reason_if_absent ?? null]);
  } else resumes[7] = resumeGenerique(7);
  resumes[8] = c8.resume ?? null;

  const anchorsUsed = { 1: [], 2: [], 3: [], 4: c4.anchors_used ?? [], 5: c5.anchors_used ?? [], 6: n3 && n3.status !== "non_execute" ? pointeursN3 : [], 7: [], 8: c8.ancresEmployees ?? [] };
  const controls = [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({
    number: n,
    status: statuts[n].status,
    reason: statuts[n].status === "non_execute" ? statuts[n].reason : null,
    checks: idsControle[n],
    anchors_used: anchorsUsed[n],
    summary: nonVide(resumes[n]),
  }));

  // Verdict (EX-6.7).
  const failed_checks = liste.filter((c) => c.status === "echoue").map((c) => c.id);
  const blocking_unexecuted = liste.filter((c) => c.status === "non_execute" && c.reason === "prerequis_en_echec").map((c) => c.id);
  const requis = [...new Set(exiger)].sort((a, b) => a - b);
  const nonReussisExiges = requis.filter((n) => !reussi(n));
  const verdict = failed_checks.length || blocking_unexecuted.length ? "invalide" : nonReussisExiges.length ? "incomplet" : "valide";
  const exit_code = { valide: 0, invalide: 1, incomplet: 3 }[verdict];

  // Désignation de l'événement et de la période (EX-6.13) : valeurs bien formées seulement.
  const event = ev && Number.isSafeInteger(ev.seq) && ev.seq >= 0 && typeof ev.hash === "string" && RE_HEX32.test(ev.hash) && typeof ev.ts === "string" && RE_HORODATAGE.test(ev.ts) ? { seq: ev.seq, hash: ev.hash, ts: ev.ts, tool: typeof ev.execution?.tool === "string" ? ev.execution.tool : null } : null;
  const org_id = ev && typeof ev.org_id === "string" && RE_HEX32.test(ev.org_id) ? ev.org_id : null;
  const journal_id = ev && typeof ev.journal_id === "string" && RE_HEX32.test(ev.journal_id) ? ev.journal_id : null;
  const period = periodHash ? { period_start: manifeste.period_start, period_end: manifeste.period_end, period_hash: periodHash } : null;

  // Faits (EX-6.13) : valeurs des contrôles réussis seulement.
  const facts = {
    recorder_keys: reussi(6) ? { event_key_id: cleEvenement, manifest_key_id: cleManifeste, source: provenance, event_key_source: provenanceEvenement, manifest_key_source: provenanceManifeste } : null,
    approval: reussi(7) ? { decision: ev.approval.decision, ticket: ev.approval.ticket, approvers: [...ev.approval.approvers], required: ev.approval.threshold.required, size: ev.approval.threshold.size, set_source: "dossier" } : null,
    timestamp: reussi(4) ? c4.facts : null,
    bitcoin: reussi(5) ? c5.facts : null,
    registry: reussi(8) ? c8.faits : null,
  };

  // Énoncé (EX-6.8, EX-6.9) et borne (EX-6.12).
  let statement;
  if (verdict === "invalide") {
    const fr = [];
    const en = [];
    if (failed_checks.length) {
      fr.push(`Dossier invalide : vérification(s) en échec : ${failed_checks.join(", ")}`);
      en.push(`Invalid dossier: failed check(s): ${failed_checks.join(", ")}`);
      if (blocking_unexecuted.length) {
        fr.push(` ; vérification(s) non exécutée(s) sans raison admise : ${blocking_unexecuted.join(", ")}`);
        en.push(`; check(s) not run without an admitted reason: ${blocking_unexecuted.join(", ")}`);
      }
    } else {
      fr.push(`Dossier invalide : vérification(s) non exécutée(s) sans raison admise : ${blocking_unexecuted.join(", ")}`);
      en.push(`Invalid dossier: check(s) not run without an admitted reason: ${blocking_unexecuted.join(", ")}`);
    }
    fr.push(" ; le vérificateur n'affirme rien sur cet événement.");
    en.push("; the verifier asserts nothing about this event.");
    statement = { fr: fr.join(""), en: en.join("") };
  } else {
    statement = construireEnonce({
      ev,
      voisinsSeq,
      manifeste,
      periodHash,
      cleEvenement,
      cleManifeste,
      provenance,
      provenanceEvenement,
      provenanceManifeste,
      approbation: reussi(7) ? ev.approval : null,
      propositions: { 4: reussi(4) ? c4.proposition : null, 5: reussi(5) ? c5.proposition : null, 8: reussi(8) ? c8.enonce : null },
      statuts,
    });
  }
  const nonExecutes = controls.filter((c) => c.status === "non_execute");
  const bound = nonExecutes.length ? L(`verdict borné : ${nonExecutes.map((c) => `contrôle ${c.number} non exécuté (${c.reason})`).join(", ")}`, `bounded verdict: ${nonExecutes.map((c) => `control ${c.number} not run (${c.reason})`).join(", ")}`) : null;

  return {
    event,
    org_id,
    journal_id,
    period,
    controls,
    checks: liste,
    failed_checks,
    blocking_unexecuted,
    absent_parts: ct1.partiesAbsentes.map((p) => ({ name: p.name, file: p.file, reason: p.reason })),
    warnings: ordonnerAvertissements([...c4.warnings, ...c5.warnings, ...c8.avertissements], liste).map((w) => ({ id: w.id, check: w.check ?? null, detail: lang(w.detail) })),
    facts,
    verdict,
    exit_code,
    statement,
    bound,
    required_not_passed: verdict === "incomplet" ? nonReussisExiges : [],
    pieces_lues: piecesLues,
  };
}

/**
 * Ordre des avertissements (EX-6.15) : position, dans le rapport, de la
 * vérification qui les lève ; puis identifiant (famille T, O, R, N, puis
 * numéro) ; puis ordre d'émission, qui suit l'ordre de leur objet.
 */
export function ordonnerAvertissements(avertissements, liste) {
  const position = new Map(liste.map((c, i) => [c.id, i]));
  const familles = ["T", "O", "R", "N"];
  const cle = (w) => {
    const m = /^AV-([A-Z])-([0-9]+)$/.exec(w.id) ?? [null, "Z", "0"];
    return [position.get(w.check) ?? liste.length, familles.indexOf(m[1]) === -1 ? familles.length : familles.indexOf(m[1]), Number(m[2])];
  };
  return avertissements
    .map((w, i) => ({ w, i, k: cle(w) }))
    .sort((a, b) => a.k[0] - b.k[0] || a.k[1] - b.k[1] || a.k[2] - b.k[2] || a.i - b.i)
    .map((x) => x.w);
}

/**
 * Énoncé d'un verdict valide ou incomplet (EX-6.8), dans les deux langues :
 * fragments F0 à F8 assemblés sans autre caractère.
 */
export function construireEnonce({ ev, voisinsSeq, manifeste, periodHash, cleEvenement, cleManifeste, provenance, provenanceEvenement = provenance, provenanceManifeste = provenance, approbation, propositions, statuts }) {
  const { p, n } = voisinsSeq;
  const voisinage =
    p !== null && n !== null ? T(`chaîné à ses voisins seq ${p} et ${n}`, `chained to its neighbours seq ${p} and ${n}`)
    : p !== null ? T(`chaîné à son voisin précédent seq ${p} (le dossier ne fournit pas de suivant)`, `chained to its previous neighbour seq ${p} (the dossier gives no next event)`)
    : n !== null ? T(`premier événement du journal, chaîné à son voisin suivant seq ${n}`, `the first event of the journal, chained to its next neighbour seq ${n}`)
    : T("premier événement du journal, sans voisin dans le dossier", "the first event of the journal, with no neighbour in the dossier");
  const debut = instantUnix(manifeste.period_start);
  const fin = instantUnix(manifeste.period_end);
  const fr = [];
  const en = [];
  // F0, F1
  fr.push(`L'événement seq ${ev.seq} (hachage ${ev.hash}) du journal ${ev.journal_id} de l'organisation ${ev.org_id}`);
  en.push(`Event seq ${ev.seq} (hash ${ev.hash}) of journal ${ev.journal_id} of organisation ${ev.org_id}`);
  fr.push(` est bien formé, ${voisinage.fr} et inclus dans la période du ${debut} au ${fin} close par le manifeste ${periodHash}`);
  en.push(` is well-formed, ${voisinage.en} and included in the period from ${debut} to ${fin} closed by manifest ${periodHash}`);
  // F2 : provenance commune (pluriel ou singulier), ou clé par clé (cas mixte).
  const PROV = {
    dossier: { fr: ["clés déclarées par le dossier", "clé déclarée par le dossier", "déclarée par le dossier"], en: ["keys declared by the dossier", "declared by the dossier", "declared by the dossier"] },
    registre: { fr: ["clés inscrites au registre", "clé inscrite au registre", "inscrite au registre"], en: ["keys registered in the registry", "registered in the registry", "registered in the registry"] },
    ancres: { fr: ["clés fournies par le fichier d'ancres", "clé fournie par le fichier d'ancres", "fournie par le fichier d'ancres"], en: ["keys given by the anchors file", "given by the anchors file", "given by the anchors file"] },
  };
  const provenanceTexte =
    provenance === "mixte"
      ? {
          fr: `clé ${cleEvenement} ${PROV[provenanceEvenement].fr[2]}, clé ${cleManifeste} ${PROV[provenanceManifeste].fr[2]}`,
          en: `key ${cleEvenement} ${PROV[provenanceEvenement].en[2]}, key ${cleManifeste} ${PROV[provenanceManifeste].en[2]}`,
        }
      : { fr: PROV[provenance].fr[cleEvenement !== cleManifeste ? 0 : 1], en: PROV[provenance].en[cleEvenement !== cleManifeste ? 0 : 1] };
  if (cleEvenement !== cleManifeste) {
    fr.push(` ; l'événement est signé par la clé d'enregistreur ${cleEvenement} et le manifeste par la clé ${cleManifeste}, ${provenanceTexte.fr}`);
    en.push(`; the event is signed by recorder key ${cleEvenement} and the manifest by key ${cleManifeste}, ${provenanceTexte.en}`);
  } else {
    fr.push(` ; l'événement est signé, comme le manifeste, par la clé d'enregistreur ${cleEvenement}, ${provenanceTexte.fr}`);
    en.push(`; the event is signed, like the manifest, by recorder key ${cleEvenement}, ${provenanceTexte.en}`);
  }
  // F3 : selon approval.decision (approuve, refuse, expire).
  if (approbation) {
    const k = approbation.approvers.length;
    const sig = k === 1 ? "1 signature" : `${k} signatures`;
    const seuilFr = `seuil de ${approbation.threshold.required} sur ${approbation.threshold.size} du jeu déclaré par le dossier`;
    const seuilEn = `threshold ${approbation.threshold.required} of ${approbation.threshold.size} of the set declared by the dossier`;
    if (approbation.decision === "refuse") {
      fr.push(` ; l'événement porte un refus signé par ${joindreListe(approbation.approvers, "fr")} (${sig}, ${seuilFr})`);
      en.push(`; the event carries a refusal signed by ${joindreListe(approbation.approvers, "en")} (${sig}, ${seuilEn})`);
    } else if (approbation.decision === "expire") {
      fr.push(` ; l'événement porte une demande d'approbation expirée sans signature (${seuilFr})`);
      en.push(`; the event carries an approval request that expired without signature (${seuilEn})`);
    } else {
      fr.push(` ; l'événement a été approuvé par ${joindreListe(approbation.approvers, "fr")} (${sig}, ${seuilFr})`);
      en.push(`; the event was approved by ${joindreListe(approbation.approvers, "en")} (${sig}, ${seuilEn})`);
    }
  }
  // F4, F5, F6
  for (const k of [4, 5, 8]) {
    const prop = propositions[k];
    if (prop) {
      fr.push(` ; ${prop.fr}`);
      en.push(`; ${prop.en}`);
    }
  }
  // F7
  const nonReussi = (k) => statuts[k].status !== "reussi";
  const auMoinsUnNonExecute = [1, 2, 3, 4, 5, 6, 7, 8].some((k) => statuts[k].status === "non_execute");
  if (auMoinsUnNonExecute) {
    const elements = [];
    if (nonReussi(4) && nonReussi(5)) elements.push(T("sa date (contrôles 4 et 5)", "its date (controls 4 and 5)"));
    else if (nonReussi(4)) elements.push(T("un horodatage par une autorité (contrôle 4)", "a time-stamp by an authority (control 4)"));
    else if (nonReussi(5)) elements.push(T("un ancrage dans Bitcoin (contrôle 5)", "an anchoring in Bitcoin (control 5)"));
    if (nonReussi(7)) elements.push(T("une approbation (contrôle 7)", "an approval (control 7)"));
    if (nonReussi(8)) elements.push(T("son inscription au registre (contrôle 8)", "its registration in the registry (control 8)"));
    if (elements.length) {
      const joindre = (xs, sep, dernier) => (xs.length === 1 ? xs[0] : xs.slice(0, -1).join(sep) + dernier + xs[xs.length - 1]);
      fr.push(` ; ce dossier ne prouve rien sur ${joindre(elements.map((e) => e.fr), ", sur ", " ni sur ")}`);
      en.push(`; this dossier proves nothing about ${joindre(elements.map((e) => e.en), ", ", " or ")}`);
    }
  }
  // F8
  fr.push(".");
  en.push(".");
  return { fr: fr.join(""), en: en.join("") };
}

// ---------------------------------------------------------------------------
// Rapport JSON (section 8.6)
// ---------------------------------------------------------------------------

/** Bloc `verifier` du rapport : nom, implémentation, version, environnement, schémas employés. */
export function blocVerificateur(schemasEmployes = []) {
  return {
    name: NOM_VERIFICATEUR,
    implementation: "reference_javascript",
    version: VERSION_VERIFICATEUR,
    runtime: `node ${process.version}`,
    schemas: schemasEmployes.map((s) => ({ id: s.id, sha256: s.sha256 })),
  };
}

/** Rapport complet (codes 0, 1, 3), clés dans l'ordre du schéma rapport-verification-v0. */
export function rapportJSON({ verifier, langue, inputs, corps }) {
  return {
    format: FORMAT_RAPPORT,
    version: 0,
    verifier,
    language: langue,
    inputs,
    event: corps.event,
    org_id: corps.org_id,
    journal_id: corps.journal_id,
    period: corps.period,
    controls: corps.controls,
    checks: corps.checks,
    failed_checks: corps.failed_checks,
    blocking_unexecuted: corps.blocking_unexecuted,
    absent_parts: corps.absent_parts,
    warnings: corps.warnings,
    facts: corps.facts,
    verdict: corps.verdict,
    exit_code: corps.exit_code,
    statement: corps.statement,
    bound: corps.bound,
  };
}

/** Rapport d'erreur (code 2). */
export function rapportErreur({ verifier, langue, inputs = null, erreur }) {
  return {
    format: FORMAT_RAPPORT,
    version: 0,
    verifier,
    language: langue,
    inputs,
    verdict: null,
    exit_code: 2,
    error: { kind: erreur.kind, message: choisir(erreur.texte, langue) || erreur.message, check: erreur.check ?? null },
  };
}

// ---------------------------------------------------------------------------
// Rapport lisible (section 8.5)
// ---------------------------------------------------------------------------

const ETIQUETTES = {
  fr: {
    titre: "Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)",
    verificateur: "Vérificateur",
    repertoire: "Répertoire",
    index: "Index",
    ancres: "Ancres",
    entetes: "En-têtes",
    pieces: "Pièces",
    second: "2e manifeste",
    evenement: "Événement",
    journal: "Journal",
    periode: "Période",
    controles: "Contrôles de l'architecture :",
    nonReussies: "Vérifications non réussies :",
    toutes: "Vérifications :",
    avertissements: "Avertissements :",
    absentes: "Parties absentes",
    borne: "Borne",
    resultat: "Résultat",
    enonce: "Énoncé",
    aucunAncre: "aucun fichier d'ancres",
    statut: { reussi: "[réussi]", echoue: "[ÉCHEC]", non_execute: "[non exécuté]" },
    nonExecute: "non exécuté",
    outil: "outil",
    a: "à",
  },
  en: {
    titre: "Offline verification of a NOORTRACE evidence dossier (format v0, CT-1 and CT-6)",
    verificateur: "Verifier",
    repertoire: "Directory",
    index: "Index",
    ancres: "Anchors",
    entetes: "Headers",
    pieces: "Pieces",
    second: "2nd manifest",
    evenement: "Event",
    journal: "Journal",
    periode: "Period",
    controles: "Architecture controls:",
    nonReussies: "Checks not passed:",
    toutes: "Checks:",
    avertissements: "Warnings:",
    absentes: "Absent parts",
    borne: "Bound",
    resultat: "Result",
    enonce: "Statement",
    aucunAncre: "no anchors file",
    statut: { reussi: "[passed]", echoue: "[FAILED]", non_execute: "[not run]" },
    nonExecute: "not run",
    outil: "tool",
    a: "to",
  },
};

/** Rapport lisible d'un rapport JSON (codes 0, 1, 3), dans sa langue. `detail` : toutes les vérifications. */
export function rapportLisible(rapport, { detail = false } = {}) {
  const langue = rapport.language;
  const E = ETIQUETTES[langue];
  const ligne = (etiquette, valeur) => `${etiquette.padEnd(14)}: ${valeur}`;
  const out = [];
  const v = rapport.verifier;
  const inp = rapport.inputs;
  out.push(E.titre);
  out.push(ligne(E.verificateur, `${v.name} ${v.version} (${v.runtime})`));
  out.push(ligne(E.repertoire, inp.dossier.path));
  out.push(ligne(E.index, `dossier.json, SHA-256 ${inp.dossier.index_sha256}`));
  out.push(ligne(E.ancres, inp.anchors ? `${inp.anchors.path}, SHA-256 ${inp.anchors.sha256}` : E.aucunAncre));
  if (inp.bitcoin_headers) out.push(ligne(E.entetes, `${inp.bitcoin_headers.path}, SHA-256 ${inp.bitcoin_headers.sha256}`));
  if (inp.pieces) out.push(ligne(E.pieces, langue === "en" ? `${inp.pieces.path}, ${inp.pieces.files} piece(s) read` : `${inp.pieces.path}, ${inp.pieces.files} pièce(s) lue(s)`));
  if (inp.second_manifest) out.push(ligne(E.second, `${inp.second_manifest.path}, SHA-256 ${inp.second_manifest.sha256}`));
  if (rapport.event) out.push(ligne(E.evenement, `seq ${rapport.event.seq}, hash ${rapport.event.hash}, ts ${rapport.event.ts}${rapport.event.tool ? `, ${E.outil} ${rapport.event.tool}` : ""}`));
  if (rapport.org_id) out.push(ligne(E.journal, `org_id ${rapport.org_id}, journal_id ${rapport.journal_id}`));
  if (rapport.period) out.push(ligne(E.periode, `${instantUnix(rapport.period.period_start)} ${E.a} ${instantUnix(rapport.period.period_end)}, periodHash ${rapport.period.period_hash}`));
  out.push(E.controles);
  for (const c of rapport.controls) {
    const etat = E.statut[c.status].padEnd(14);
    const libelle = LIBELLES_CONTROLES[c.number][langue];
    let suite = "";
    if (c.status === "non_execute") suite = ` — ${E.nonExecute} (${c.reason})${c.summary ? `${langue === "en" ? ":" : " :"} ${c.summary}` : ""}`;
    else if (c.summary) suite = ` — ${c.summary}`;
    out.push(`  ${etat}${c.number}  ${libelle}${suite}`);
  }
  const listees = rapport.checks.filter((c) => detail || c.status !== "reussi");
  if (listees.length) {
    out.push(detail ? E.toutes : E.nonReussies);
    for (const c of listees) {
      out.push(`  ${E.statut[c.status].padEnd(14)}${c.id.padEnd(4)} [${c.controls.length ? c.controls.join(", ") : "—"}] ${libelleVerification(c.id, langue)}`);
      const d = [c.detail, c.status === "non_execute" ? `(${c.reason})` : null].filter(Boolean).join(" ");
      if (d) out.push(`${" ".repeat(22)}${d}`);
    }
  }
  if (rapport.warnings.length) {
    out.push(E.avertissements);
    for (const w of rapport.warnings) out.push(`  ${w.id} (${w.check ?? "—"}) ${w.detail}`);
  }
  if (rapport.absent_parts.length) {
    // « Parties absentes » dépasse quatorze caractères : l'étiquette n'est pas complétée, comme dans CT-1.
    const etiquette = langue === "en" ? `${E.absentes.padEnd(14)}: ` : `${E.absentes} : `;
    out.push(etiquette + rapport.absent_parts.map((p) => `${p.file} (${p.reason})`).join(", "));
  }
  if (rapport.bound) out.push(ligne(E.borne, rapport.bound));
  out.push(ligne(E.resultat, ligneResultat(rapport)));
  out.push(ligne(E.enonce, rapport.statement[langue]));
  return out.join("\n");
}

/** Ligne « Résultat » (EX-8.6, point 11). */
function ligneResultat(r) {
  const en = r.language === "en";
  if (r.verdict === "valide") return en ? "VALID — no failed check, no check left unrun without an admitted reason" : "VALIDE — aucune vérification en échec, aucune vérification non exécutée sans raison admise";
  if (r.verdict === "incomplet") {
    const nums = r.controls.filter((c) => r.inputs.required_controls.includes(c.number) && c.status !== "reussi").map((c) => c.number).join(", ");
    return en ? `INCOMPLETE — required control(s) not passed: ${nums}` : `INCOMPLET — contrôle(s) exigé(s) non réussi(s) : ${nums}`;
  }
  const morceaux = [];
  if (r.failed_checks.length) morceaux.push(en ? `failed check(s): ${r.failed_checks.join(", ")}` : `vérification(s) en échec : ${r.failed_checks.join(", ")}`);
  if (r.blocking_unexecuted.length) morceaux.push(en ? `check(s) not run without an admitted reason: ${r.blocking_unexecuted.join(", ")}` : `vérification(s) non exécutée(s) sans raison admise : ${r.blocking_unexecuted.join(", ")}`);
  return (en ? "INVALID — " : "INVALIDE — ") + morceaux.join(en ? "; " : " ; ");
}
