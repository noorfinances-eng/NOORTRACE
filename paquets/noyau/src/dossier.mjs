// Dossier de preuve v0 (CT-1 §11) : lecture des parties et contrôles
// numérotés de §11.4 (D-, E-, C-, M-, P-, A-, K-, AT-), verdict.
//
// Le module est pur : il reçoit le contenu des fichiers du répertoire
// (nom → octets) ; la lecture d'un répertoire est dans dossier-fichiers.mjs.
//
// Règles de lecture appliquées (CT-1 §11.4 et vecteurs de §11.5) :
// - une partie présente qui n'est pas du JSON, dont le JSON n'est pas un
//   objet, ou qui dépasse sa limite de taille (CT-6 EX-4.13, TAILLES_MAX),
//   met en échec le contrôle qui porte la partie ; un fichier sans forme
//   canonique (clé en double, substitut isolé, nombre non entier ou hors de
//   l'intervalle sûr) met en échec E-2, quelle que soit la partie, la
//   treizième comprise ; dans ces cas, les contrôles qui dépendent de la
//   partie ne sont pas exécutés, sans raison admise. Seule exception, la
//   quatorzième partie : tout défaut d'attestation-perimetre.json, forme
//   canonique comprise, est porté par AT-1 et ne change aucun autre contrôle
//   (CT-1 §11.4, révision 0.4) ;
// - une partie déclarée présente dont le fichier manque (ou n'est pas un
//   fichier ordinaire) met D-2 en échec, et D-2 seul : le contrôle qui la
//   porte et ceux qui en dépendent ne sont pas exécutés (raison
//   partie_manquante pour le porteur, CT-6 EX-4.11) ;
// - une partie qui est un objet JSON mais enfreint son schéma met en échec le
//   contrôle qui la porte, et les autres contrôles s'exécutent sur les champs
//   bien typés qu'ils lisent (cascades publiées par les vecteurs : E-1 et E-3,
//   E-1 et A-3, M-3, P-1 et P-4, E-1, E-7, E-8, C-2 et M-1) ;
// - cles.json qui enfreint la première partie de E-8 (schéma, identifiants,
//   unicité, ordre des validités) est inexploitable : E-8 échoue, et E-11,
//   P-5, K-3 ne sont pas exécutés ;
// - le hash d'un événement n'est jamais lu : il est toujours recalculé.

import { ZERO32, decoderHorodatage, estEntierSur, estHex, octetsVersHex, utf8 } from "./conventions.mjs";
import { ErreurJson, analyserJson, egaliteJson } from "./json-strict.mjs";
import { keccak256, sha256Hex } from "./hachage.mjs";
import { NOMS_RESERVES, objetApprobation, sorteEvenement } from "./evenement.mjs";
import { CONTROLES_EVENEMENT, controlerEvenement, hashRecalcule, nouvelleCle } from "./controles-evenement.mjs";
import { dansValidite, indexerCles } from "./cles.mjs";
import { feuille, verifierCoherence, verifierInclusion } from "./merkle.mjs";
import { ecartsManifeste, empreinteAncre, hacherManifeste, verifierContinuite, verifierSignatureManifeste } from "./manifeste.mjs";
import { hacherPoint, verifierSignaturePoint } from "./point-de-controle.mjs";
import { verifierPartieAttestation } from "./attestation.mjs";
import { ORDRE_CONTROLES, trierControles } from "./chainage.mjs";
import { validerSchema } from "./schemas.mjs";

/** Les douze parties v0, dans l'ordre de l'index (CT-1 §11.1). */
export const PARTIES_V0 = Object.freeze([
  { name: "evenement", file: "evenement.json" },
  { name: "voisins", file: "voisins.json" },
  { name: "chemin", file: "chemin.json" },
  { name: "manifeste", file: "manifeste.json" },
  { name: "manifeste_sig", file: "manifeste.sig" },
  { name: "cles", file: "cles.json" },
  { name: "approbations", file: "approbations.json" },
  { name: "jeton_rfc3161", file: "jeton-rfc3161.der" },
  { name: "preuve_ots", file: "preuve.ots" },
  { name: "registre", file: "registre.json" },
  { name: "certificat_commit", file: "certificat-commit.json" },
  { name: "validateurs", file: "validateurs.json" },
]);

/** Treizième partie facultative (révision 0.3). */
export const PARTIE_POINTS_DE_CONTROLE = Object.freeze({ name: "points_de_controle", file: "points-de-controle.json" });

/** Quatorzième partie facultative (révision 0.4). */
export const PARTIE_ATTESTATION_PERIMETRE = Object.freeze({ name: "attestation_perimetre", file: "attestation-perimetre.json" });

/** Les cinq parties réservées à CT-4 et CT-5, vérifiées par CT-6. */
export const PARTIES_RESERVEES = Object.freeze(["jeton_rfc3161", "preuve_ots", "registre", "certificat_commit", "validateurs"]);

/** Noms de fichier qu'un dossier peut déclarer, index compris. */
export const FICHIERS_DOSSIER = Object.freeze([
  "dossier.json",
  ...PARTIES_V0.map((p) => p.file),
  PARTIE_POINTS_DE_CONTROLE.file,
  PARTIE_ATTESTATION_PERIMETRE.file,
]);

const KIO = 1024;
const MIO = 1024 * 1024;

/**
 * Limite de taille de chaque fichier d'un dossier, en octets (CT-6 EX-4.13) :
 * `dossier.json` 1 Mio ; les parties JSON v0 de CT-1 16 Mio ;
 * `jeton-rfc3161.der` 64 Kio ; `preuve.ots` 256 Kio ; `registre.json` et
 * `certificat-commit.json` 64 Mio ; `validateurs.json` 1 Mio ;
 * `points-de-controle.json` 1 Mio (EX-4.14) ; `attestation-perimetre.json`
 * 4 Mio (EX-4.15). Un fichier plus grand n'est pas analysé : il est
 * inexploitable et met en échec le contrôle qui le porte (EX-4.11).
 */
export const TAILLES_MAX = Object.freeze({
  "dossier.json": 1 * MIO,
  "evenement.json": 16 * MIO,
  "voisins.json": 16 * MIO,
  "chemin.json": 16 * MIO,
  "manifeste.json": 16 * MIO,
  "manifeste.sig": 16 * MIO,
  "cles.json": 16 * MIO,
  "approbations.json": 16 * MIO,
  "jeton-rfc3161.der": 64 * KIO,
  "preuve.ots": 256 * KIO,
  "registre.json": 64 * MIO,
  "certificat-commit.json": 64 * MIO,
  "validateurs.json": 1 * MIO,
  "points-de-controle.json": 1 * MIO,
  "attestation-perimetre.json": 4 * MIO,
});

/**
 * Plafond absolu de lecture de `attestation-perimetre.json` (CT-6 EX-4.15) :
 * au-delà de 4 Mio, la partie n'est lue que pour son SHA-256 (D-2), en flux,
 * jusqu'à 64 Mio ; au-delà, l'entrée est inutilisable (`taille_depassee`).
 */
export const PLAFOND_LECTURE = 64 * MIO;

/** Raisons de non-exécution admises (CT-1 §11.4) : le dossier reste valide. */
export const RAISONS_ADMISES = Object.freeze(["partie_absente", "piece_hors_dossier"]);

/** Énoncé de la borne quand les contrôles 4, 5 et 8 ne sont pas exécutés (CT-1 §11.3). */
export const BORNE =
  "cet événement est bien formé, chaîné à ses voisins, inclus dans la période close par ce manifeste signé par cette clé, " +
  "et approuvé par ces adresses ; ce dossier ne dit rien sur la date ni sur l'ancre (contrôles 4, 5 et 8 non exécutés)";

/** doc_type de l'ancre d'un point au registre : keccak256("noortrace/point-de-controle/v0"). */
export const DOC_TYPE_POINT = octetsVersHex(keccak256(utf8("noortrace/point-de-controle/v0")));

const CONTROLES_K = ["K-1", "K-2", "K-3", "K-4", "K-5", "K-6", "K-7", "K-8", "K-9"];
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * @typedef {object} ResultatControle
 * @property {string} id
 * @property {"reussi"|"echoue"|"non_execute"} statut
 * @property {string|null} raison raison de non-exécution
 * @property {boolean} admise la non-exécution l'est pour une raison admise
 * @property {string[]} details
 */

/**
 * @typedef {object} RapportDossier
 * @property {boolean} utilisable false si dossier.json est absent ou n'est pas du JSON (CT-6 EX-4.12 : code 2, sans verdict)
 * @property {string|null} erreur raison d'inutilisabilité
 * @property {"valide"|"invalide"|null} verdict
 * @property {boolean|null} valide
 * @property {{seq: number, hash: string}|null} evenement seq et hash recalculé, lus dans evenement.json exploitable seulement
 * @property {ResultatControle[]} controles dans l'ordre de CT-1 §11.4 ; K- seulement si la treizième partie est déclarée présente
 * @property {string[]} controles_en_echec liste exacte, dans l'ordre de §11.4
 * @property {string[]} non_executes_bloquants contrôles non exécutés sans raison admise
 * @property {{name: string, reason: string}[]} parties_absentes
 * @property {string|null} borne énoncé de la borne (§11.3), pour un dossier valide sans les contrôles 4, 5 et 8
 * @property {{verifications: object[], retenue: boolean, avertissements: string[], digest: string|null}|null} perimetre
 *   AT-1 à AT-7, seulement si la quatorzième partie est déclarée présente
 */

/**
 * @typedef {object} FichierNonLu
 * Fichier présent dans le répertoire mais non lu, parce qu'il dépasse sa
 * limite (TAILLES_MAX) : sa taille, et son SHA-256 calculé en flux pour la
 * seule partie attestation-perimetre.json jusqu'au plafond (null sinon).
 * @property {number} taille
 * @property {string|null} sha256
 */

/**
 * Vérifie un dossier de preuve v0.
 * @param {Map<string, Uint8Array|FichierNonLu>|Record<string, Uint8Array|FichierNonLu>} fichiers
 *   fichiers du répertoire, par nom : leurs octets, ou un FichierNonLu pour un fichier au-delà de sa limite
 * @param {object} [options]
 * @param {object} [options.manifestePrecedent] manifeste de la période précédente, fourni à part (continuité, P-5)
 * @param {object} [options.manifesteSuivant] manifeste de la période suivante, fourni à part (continuité, P-5)
 * @param {Uint8Array[]} [options.pieces] pièces fournies à part (E-6) : chacune doit être celle d'une référence du dossier
 * @param {{rfc3161?: Function, registry?: Function, ots?: Function}} [options.verificateursAncres]
 *   vérifications des ancres d'un point (K-7, K-8, K-9) déléguées à CT-6 ; chaque fonction reçoit
 *   (ancre, { checkpoint_hash, partie }) et rend { statut, raison?, details? }
 * @param {number} [options.profondeurMax] borne d'imbrication des JSON lus (aucune par défaut, CT-1 §4 n'en
 *   fixe pas ; PROFONDEUR_CT6 = 128 applique celle de CT-6 EX-4.13) ; une partie au-delà est inexploitable
 * @returns {RapportDossier}
 */
export function verifierDossier(fichiers, options = {}) {
  const brut = (nom) => (fichiers instanceof Map ? fichiers.get(nom) : fichiers[nom]);
  const aFichier = (nom) => (fichiers instanceof Map ? fichiers.has(nom) : Object.prototype.hasOwnProperty.call(fichiers, nom));
  const optionsJson = { profondeurMax: options.profondeurMax };
  const limiteDe = (nom) => TAILLES_MAX[nom] ?? Infinity;
  /**
   * Entrée d'un fichier : null s'il est absent du répertoire ; { octets } s'il
   * est lu dans sa limite ; { tropGrand, taille, sha256 } au-delà ;
   * { manquant } pour toute autre valeur (fichier non ordinaire).
   */
  const entree = (nom) => {
    if (!aFichier(nom)) return null;
    const v = brut(nom);
    if (v instanceof Uint8Array) {
      if (v.length <= limiteDe(nom)) return { octets: v };
      const empreinte = nom === PARTIE_ATTESTATION_PERIMETRE.file && v.length <= PLAFOND_LECTURE ? sha256Hex(v) : null;
      return { tropGrand: true, taille: v.length, sha256: empreinte };
    }
    if (v !== null && typeof v === "object" && Number.isSafeInteger(v.taille) && v.taille > limiteDe(nom)) {
      return { tropGrand: true, taille: v.taille, sha256: typeof v.sha256 === "string" ? v.sha256 : null };
    }
    return { manquant: true };
  };
  const tropGrand = (nom, x) => `${nom} : ${x.taille} octets, au-delà de sa limite de ${limiteDe(nom)} octets (CT-6 EX-4.13) : non analysé`;

  /** @type {Map<string, ResultatControle>} */
  const R = new Map();
  const poser = (id, statut, details = [], raison = null) => {
    R.set(id, { id, statut, raison, admise: statut === "non_execute" && RAISONS_ADMISES.includes(raison), details });
  };
  const reussi = (id, details = []) => poser(id, "reussi", details);
  const echoue = (id, details) => poser(id, "echoue", details);
  const nonExecute = (id, raison, details = []) => poser(id, "non_execute", details, raison);
  const selon = (id, ecarts, details = []) => (ecarts.length ? echoue(id, ecarts) : reussi(id, details));
  const statutDe = (id) => R.get(id)?.statut;

  // ------------------------------------------------------------ index
  const xIndex = entree("dossier.json");
  if (xIndex?.tropGrand) {
    echoue("D-1", [tropGrand("dossier.json", xIndex)]);
    return conclure(null, false, false, [], null);
  }
  if (!xIndex?.octets) return inutilisable("dossier.json absent");
  let index;
  try {
    index = analyserJson(xIndex.octets, optionsJson);
  } catch (e) {
    if (!(e instanceof ErreurJson)) throw e;
    if (!e.formeCanonique) return inutilisable(`dossier.json n'est pas du JSON : ${e.message}`);
    echoue("E-2", [`dossier.json sans forme canonique : ${e.message}`]);
    nonExecute("D-1", "prerequis_en_echec");
    return conclure(null, false, false, [], null);
  }

  const schemaIndex = validerSchema("dossier", index);
  const ecartsIndex = schemaIndex.erreurs.map((e) => `schéma : ${e}`);
  if (schemaIndex.valide && decoderHorodatage(index.generated_at) === null) ecartsIndex.push("generated_at : horodatage qui ne se décode pas");
  if (ecartsIndex.length) {
    echoue("D-1", ecartsIndex);
    return conclure(null, false, false, [], null);
  }
  const parties = new Map(index.parts.map((p) => [p.name, p]));
  const avecPoints = parties.get(PARTIE_POINTS_DE_CONTROLE.name)?.present === true;
  const avecAttestation = parties.get(PARTIE_ATTESTATION_PERIMETRE.name)?.present === true;
  const partiesAbsentes = index.parts.filter((p) => !p.present).map((p) => ({ name: p.name, reason: p.reason_if_absent }));

  // Partie attestation au-delà du plafond absolu de lecture : entrée
  // inutilisable (CT-6 EX-4.15, code 2, taille_depassee).
  if (avecAttestation) {
    const x = entree(PARTIE_ATTESTATION_PERIMETRE.file);
    if (x?.tropGrand && x.taille > PLAFOND_LECTURE) {
      return inutilisable(`taille_depassee : ${PARTIE_ATTESTATION_PERIMETRE.file} de ${x.taille} octets, au-delà du plafond de lecture de ${PLAFOND_LECTURE} octets (CT-6 EX-4.15)`);
    }
  }

  // ------------------------------------------------------------ D-2
  const ecartsD2 = [];
  const notesD2 = [];
  for (const p of index.parts) {
    const x = entree(p.file);
    if (p.present) {
      if (!x || x.manquant) ecartsD2.push(`${p.file} déclaré présent, absent du répertoire (ou pas un fichier ordinaire)`);
      else {
        const empreinte = x.octets ? sha256Hex(x.octets) : x.sha256;
        if (empreinte === null) notesD2.push(`${tropGrand(p.file, x)} ; SHA-256 non calculé, la limite interdisant de lire au-delà`);
        else if (empreinte !== p.sha256) ecartsD2.push(`${p.file} : SHA-256 ${empreinte} différent de celui de l'index ${p.sha256}`);
      }
    } else if (x) {
      ecartsD2.push(`${p.file} déclaré absent, présent dans le répertoire`);
    }
  }
  selon("D-2", ecartsD2, notesD2);

  // ------------------------------------------------------------ lecture des parties
  const ecartsE2 = [];
  /**
   * Lit une partie JSON : { etat, valeur, message } ; etat : absente,
   * manquante, trop_grande, syntaxe, canonique, non_objet, objet.
   */
  const lirePartie = (nom) => {
    const p = parties.get(nom);
    if (!p || !p.present) return { etat: "absente" };
    const x = entree(p.file);
    if (!x || x.manquant) return { etat: "manquante", message: `${p.file} manquant` };
    if (x.tropGrand) return { etat: "trop_grande", message: tropGrand(p.file, x) };
    try {
      const valeur = analyserJson(x.octets, optionsJson);
      return estObjet(valeur) ? { etat: "objet", valeur } : { etat: "non_objet", valeur, message: `${p.file} n'est pas un objet JSON` };
    } catch (e) {
      if (!(e instanceof ErreurJson)) throw e;
      if (e.formeCanonique) {
        ecartsE2.push(`${p.file} sans forme canonique : ${e.message}`);
        return { etat: "canonique", message: e.message };
      }
      return { etat: "syntaxe", message: `${p.file} n'est pas du JSON : ${e.message}` };
    }
  };
  // Contrôle qui porte une partie inexploitable : échec pour du non-JSON, un
  // non-objet ou un fichier au-delà de sa limite ; pour une partie sans forme
  // canonique, l'échec est porté par E-2 ; pour une partie manquante, par D-2.
  const porteur = (id, lecture) => {
    if (lecture.etat === "syntaxe" || lecture.etat === "non_objet" || lecture.etat === "trop_grande") return { id, ecart: lecture.message };
    return null;
  };
  // Raison de non-exécution du porteur d'une partie qui n'a pas pu être lue.
  const raisonPorteur = (lecture) => (lecture.etat === "manquante" ? "partie_manquante" : "prerequis_en_echec");

  const lEvt = lirePartie("evenement");
  const lVoisins = lirePartie("voisins");
  const lChemin = lirePartie("chemin");
  const lManifeste = lirePartie("manifeste");
  const lSig = lirePartie("manifeste_sig");
  const lCles = lirePartie("cles");
  const lApprob = lirePartie("approbations");
  // La treizième partie est lue ici, avec les autres, pour que sa forme
  // canonique soit portée par E-2 comme pour toute partie.
  const lPoints = avecPoints ? lirePartie(PARTIE_POINTS_DE_CONTROLE.name) : null;

  const evt = lEvt.etat === "objet" ? lEvt.valeur : null;
  const voisins = lVoisins.etat === "objet" ? lVoisins.valeur : null;
  const chemin = lChemin.etat === "objet" ? lChemin.valeur : null;
  const manifeste = lManifeste.etat === "objet" ? lManifeste.valeur : null;
  const msig = lSig.etat === "objet" ? lSig.valeur : null;
  const approbations = lApprob.etat === "objet" ? lApprob.valeur : null;
  const previous = voisins && estObjet(voisins.previous) ? voisins.previous : null;
  const next = voisins && estObjet(voisins.next) ? voisins.next : null;
  const hashEvt = hashRecalcule(evt);

  // cles.json : première partie de E-8.
  let indexCles = null;
  const ecartsE8 = [];
  if (lCles.etat === "objet") {
    indexCles = indexerCles(lCles.valeur, evt ? { org_id: evt.org_id, journal_id: evt.journal_id } : {});
    ecartsE8.push(...indexCles.erreurs);
  } else if (porteur("E-8", lCles)) {
    ecartsE8.push(lCles.message);
  }
  const clesExploitables = indexCles?.exploitable === true;

  // ------------------------------------------------------------ D-1 (fin) : event de l'index
  if (evt) {
    const ecartsD1 = [];
    if (index.event.seq !== evt.seq) ecartsD1.push(`event.seq ${index.event.seq} de l'index différent de seq ${evt.seq} de evenement.json`);
    if (index.event.hash !== evt.hash) ecartsD1.push(`event.hash ${index.event.hash} de l'index différent de hash ${evt.hash} de evenement.json`);
    selon("D-1", ecartsD1);
  } else {
    nonExecute("D-1", "prerequis_en_echec", ["evenement.json inexploitable : event de l'index non comparé"]);
  }

  // ------------------------------------------------------------ E-1 à E-11
  const evenements = [];
  if (evt) evenements.push({ role: "evenement", e: evt });
  if (voisins) {
    for (const role of ["previous", "next"]) {
      const v = voisins[role];
      if (v !== null && v !== undefined) evenements.push({ role: `voisins.${role}`, e: v });
    }
  }
  if (approbations && Array.isArray(approbations.events)) {
    approbations.events.forEach((e, k) => evenements.push({ role: `approbations.events[${k}]`, e }));
  }
  const parEvenement = evenements.map(({ role, e }) => ({ role, e, ...controlerEvenement(e, { indexCles: indexCles ?? null }) }));
  const resultatProuve = parEvenement.find((x) => x.role === "evenement");
  const ecartsParPartie = { "E-1": [], "E-2": ecartsE2, "E-8": ecartsE8 };
  const pe = porteur("E-1", lEvt);
  if (pe) ecartsParPartie["E-1"].push(pe.ecart);
  for (const id of CONTROLES_EVENEMENT) {
    const ecarts = [...(ecartsParPartie[id] ?? [])];
    let nonExec = null;
    for (const x of parEvenement) {
      const r = x.controles[id];
      if (r.statut === "echoue") {
        if (id === "E-8" && indexCles && !indexCles.exploitable) continue;
        ecarts.push(...r.details.map((d) => `${x.role} (seq ${x.e?.seq}) : ${d}`));
      } else if (r.statut === "non_execute" && !nonExec) {
        nonExec = r.raison;
      }
    }
    if (ecarts.length) echoue(id, ecarts);
    else if (nonExec || (id !== "E-1" && id !== "E-2" && !evt)) nonExecute(id, nonExec ?? "prerequis_en_echec");
    else reussi(id);
  }
  // L'événement prouvé n'a pas été lu (fichier manquant ou sans forme
  // canonique) : E-1 ne peut pas l'avoir validé.
  if (!evt && statutDe("E-1") === "reussi") nonExecute("E-1", raisonPorteur(lEvt));
  if (!indexCles && ecartsE8.length === 0) nonExecute("E-8", raisonPorteur(lCles), [lCles.etat === "manquante" ? "cles.json manquant" : "cles.json inexploitable"]);

  // E-6 : pièces fournies à part.
  if (Array.isArray(options.pieces) && options.pieces.length) {
    const refs = new Map();
    for (const x of parEvenement) {
      for (const { reference } of referencesDe(x.e)) refs.set(reference.sha256, reference);
    }
    const ecartsPieces = [];
    options.pieces.forEach((octets, k) => {
      const empreinte = sha256Hex(octets);
      const ref = refs.get(empreinte);
      if (!ref) ecartsPieces.push(`pièce ${k} (${empreinte}) : aucune référence du dossier ne la désigne`);
      else if (ref.length !== octets.length) ecartsPieces.push(`pièce ${k} : length ${ref.length} différente de ${octets.length} octets`);
    });
    if (ecartsPieces.length) echoue("E-6", [...(R.get("E-6").statut === "echoue" ? R.get("E-6").details : []), ...ecartsPieces]);
  }

  // evenement.json exploitable au sens de AT-5 et AT-6 : E-1 et E-2 réussies sur lui.
  const evtExploitable =
    evt !== null && resultatProuve.controles["E-1"].statut === "reussi" && resultatProuve.controles["E-2"].statut === "reussi";

  // ------------------------------------------------------------ C-1 à C-3
  const voisinsUtilisables = voisins !== null;
  if (!evt || !voisinsUtilisables) {
    const pc = porteur("C-1", lVoisins);
    if (pc) echoue("C-1", [pc.ecart]);
    else nonExecute("C-1", evt ? raisonPorteur(lVoisins) : "prerequis_en_echec");
    nonExecute("C-2", "prerequis_en_echec");
    nonExecute("C-3", "prerequis_en_echec");
  } else {
    const ecarts1 = [];
    const env = validerSchema("enveloppe-voisins", voisins);
    if (!env.valide) ecarts1.push(...env.erreurs.map((e) => `voisins.json : ${e}`));
    if (voisins.previous === null) {
      if (evt.seq !== 1) ecarts1.push(`previous nul alors que seq vaut ${evt.seq}`);
    } else if (previous && previous.seq !== evt.seq - 1) {
      ecarts1.push(`previous.seq ${previous.seq} différent de seq − 1 (${evt.seq - 1})`);
    }
    if (next && next.seq !== evt.seq + 1) ecarts1.push(`next.seq ${next.seq} différent de seq + 1 (${evt.seq + 1})`);
    const t = decoderHorodatage(evt.ts);
    const tp = previous ? decoderHorodatage(previous.ts) : null;
    const tn = next ? decoderHorodatage(next.ts) : null;
    if (t !== null && tp !== null && tp > t) ecarts1.push(`ts de previous (${previous.ts}) postérieur à celui de l'événement (${evt.ts})`);
    if (t !== null && tn !== null && tn < t) ecarts1.push(`ts de next (${next.ts}) antérieur à celui de l'événement (${evt.ts})`);
    for (const v of [previous, next]) {
      if (v && (v.org_id !== evt.org_id || v.journal_id !== evt.journal_id)) ecarts1.push(`voisin seq ${v.seq} : org_id ou journal_id différent`);
    }
    selon("C-1", ecarts1);

    const ecarts2 = [];
    for (const [nom, v] of [["evenement", evt], ["previous", previous], ["next", next]]) {
      if (!v) continue;
      if (v.seq === 1 && v.prev_hash !== ZERO32) ecarts2.push(`${nom} : seq 1 et prev_hash non nul`);
      if (v.seq !== 1 && v.prev_hash === ZERO32) ecarts2.push(`${nom} : prev_hash nul alors que seq vaut ${v.seq}`);
    }
    if (previous) {
      const hp = hashRecalcule(previous);
      if (hp === null || evt.prev_hash !== hp) ecarts2.push(`prev_hash ${evt.prev_hash} différent du hash recalculé de previous (${hp})`);
    }
    if (next && (hashEvt === null || next.prev_hash !== hashEvt)) {
      ecarts2.push(`next.prev_hash ${next.prev_hash} différent du hash recalculé de l'événement (${hashEvt})`);
    }
    selon("C-2", ecarts2);

    const ecarts3 = [];
    if (previous) {
      const attendue = nouvelleCle(previous) ?? previous.recorder_key_id;
      if (evt.recorder_key_id !== attendue) ecarts3.push(`recorder_key_id ${evt.recorder_key_id}, ${attendue} attendue après previous`);
    }
    if (next) {
      const attendue = nouvelleCle(evt) ?? evt.recorder_key_id;
      if (next.recorder_key_id !== attendue) ecarts3.push(`next.recorder_key_id ${next.recorder_key_id}, ${attendue} attendue`);
    }
    selon("C-3", ecarts3);
  }

  // ------------------------------------------------------------ M-1 à M-3
  const pm = porteur("M-2", lChemin);
  if (!chemin) {
    nonExecute("M-1", "prerequis_en_echec");
    if (pm) echoue("M-2", [pm.ecart]);
    else nonExecute("M-2", raisonPorteur(lChemin));
    nonExecute("M-3", "prerequis_en_echec");
  } else {
    if (!evt || hashEvt === null || !estHex(chemin.leaf_hash, 32)) nonExecute("M-1", "prerequis_en_echec");
    else {
      const f = feuille(hashEvt);
      selon("M-1", chemin.leaf_hash === f ? [] : [`leaf_hash ${chemin.leaf_hash} différent de SHA-256(0x00 || hash recalculé) ${f}`]);
    }
    const ecartsM2 = validerSchema("chemin", chemin).erreurs.map((e) => `chemin.json : ${e}`);
    if (!verifierInclusion(chemin)) ecartsM2.push("l'algorithme de CT-1 §9.3 ne mène pas à chemin.root");
    selon("M-2", ecartsM2);
    if (!manifeste || !evt) nonExecute("M-3", "prerequis_en_echec");
    else {
      const ecarts = [];
      if (chemin.root !== manifeste.root) ecarts.push(`chemin.root ${chemin.root} différent de manifeste.root ${manifeste.root}`);
      if (chemin.tree_size !== manifeste.count) ecarts.push(`chemin.tree_size ${chemin.tree_size} différent de manifeste.count ${manifeste.count}`);
      if (chemin.leaf_index !== evt.seq - manifeste.first_seq) ecarts.push(`leaf_index ${chemin.leaf_index} différent de seq − first_seq (${evt.seq - manifeste.first_seq})`);
      selon("M-3", ecarts);
    }
  }

  // ------------------------------------------------------------ P-1 à P-5
  if (!manifeste) {
    const pp = porteur("P-1", lManifeste);
    if (pp) echoue("P-1", [pp.ecart]);
    else nonExecute("P-1", raisonPorteur(lManifeste));
    for (const id of ["P-2", "P-3", "P-4", "P-5"]) nonExecute(id, "prerequis_en_echec");
  } else {
    const ecartsP1 = ecartsManifeste(manifeste);
    if (evt) {
      if (manifeste.org_id !== evt.org_id) ecartsP1.push("org_id du manifeste différent de celui de l'événement");
      if (manifeste.journal_id !== evt.journal_id) ecartsP1.push("journal_id du manifeste différent de celui de l'événement");
    }
    selon("P-1", ecartsP1);

    const debut = estEntierSur(manifeste.period_start) ? manifeste.period_start * 1000 : null;
    const fin = estEntierSur(manifeste.period_end) ? manifeste.period_end * 1000 : null;
    const typesSeq = estEntierSur(manifeste.first_seq) && estEntierSur(manifeste.last_seq);
    if (!evt || debut === null || fin === null || !typesSeq) nonExecute("P-2", "prerequis_en_echec");
    else {
      const ecarts = [];
      const t = decoderHorodatage(evt.ts);
      if (!(manifeste.first_seq <= evt.seq && evt.seq <= manifeste.last_seq)) ecarts.push(`seq ${evt.seq} hors de [${manifeste.first_seq}, ${manifeste.last_seq}]`);
      if (t === null || t < debut || t >= fin) ecarts.push(`ts ${evt.ts} hors de la période [${manifeste.period_start}, ${manifeste.period_end})`);
      selon("P-2", ecarts);
    }

    if (!voisinsUtilisables || debut === null || fin === null || !typesSeq) nonExecute("P-3", "prerequis_en_echec");
    else {
      const ecarts = [];
      for (const v of [previous, next]) {
        if (!v) continue;
        const t = decoderHorodatage(v.ts);
        if (t === null) continue;
        if (manifeste.first_seq <= v.seq && v.seq <= manifeste.last_seq) {
          if (t < debut || t >= fin) ecarts.push(`voisin seq ${v.seq} de la période horodaté hors de la période (${v.ts})`);
        } else if (!((v.seq === manifeste.first_seq - 1 && t < debut) || (v.seq === manifeste.last_seq + 1 && t >= fin))) {
          ecarts.push(`voisin seq ${v.seq} hors de la période par seq mais horodaté ${v.ts} : le manifeste a tronqué sa période`);
        }
      }
      selon("P-3", ecarts);
    }

    const ecartsP4 = [];
    if ((manifeste.root === ZERO32) !== (manifeste.count === 0)) ecartsP4.push(`root ${manifeste.root} et count ${manifeste.count} : racine nulle si et seulement si count = 0`);
    if (!(estEntierSur(manifeste.count) && manifeste.count >= 1)) ecartsP4.push("count ≥ 1 attendu dans un dossier");
    selon("P-4", ecartsP4);

    if (!msig) {
      const ps = porteur("P-5", lSig);
      if (ps) echoue("P-5", [ps.ecart]);
      else nonExecute("P-5", raisonPorteur(lSig));
    } else if (!clesExploitables) {
      nonExecute("P-5", "prerequis_en_echec", ["cles.json inexploitable"]);
    } else {
      const ecarts = validerSchema("manifeste_sig", msig).erreurs.map((e) => `manifeste.sig : ${e}`);
      let ph = null;
      try {
        ph = hacherManifeste(manifeste);
      } catch (e) {
        ecarts.push(`periodHash incalculable : ${e.message}`);
      }
      if (ph !== null && msig.period_hash !== ph) ecarts.push(`period_hash ${msig.period_hash} différent du periodHash recalculé ${ph}`);
      if (manifeste.recorder_key_id !== msig.recorder_key_id) ecarts.push(`recorder_key_id du manifeste (${manifeste.recorder_key_id}) différent de celui de manifeste.sig (${msig.recorder_key_id})`);
      const cle = indexCles.cles.get(msig.recorder_key_id);
      if (!cle) ecarts.push(`clé ${msig.recorder_key_id} absente de cles.json`);
      else {
        if (!cle.admise || !verifierSignatureManifeste(manifeste, msig.sig, cle.octets)) ecarts.push(`signature du manifeste invalide sous ${msig.recorder_key_id}`);
        const g = decoderHorodatage(manifeste.generated_at);
        if (g === null || !dansValidite(cle, g)) ecarts.push(`generated_at ${manifeste.generated_at} hors de la validité de la clé ${msig.recorder_key_id}`);
      }
      if (options.manifestePrecedent) ecarts.push(...verifierContinuite(options.manifestePrecedent, manifeste).erreurs.map((e) => `continuité avec le précédent : ${e}`));
      if (options.manifesteSuivant) ecarts.push(...verifierContinuite(manifeste, options.manifesteSuivant).erreurs.map((e) => `continuité avec le suivant : ${e}`));
      selon("P-5", ecarts);
    }
  }

  // ------------------------------------------------------------ A-1 à A-4
  if (!evt || !(evt.approval === null || estObjet(evt.approval))) {
    for (const id of ["A-1", "A-2", "A-3", "A-4"]) nonExecute(id, "prerequis_en_echec");
  } else if (evt.approval === null) {
    if (lApprob.etat === "absente") {
      reussi("A-1");
      for (const id of ["A-2", "A-3", "A-4"]) nonExecute(id, "partie_absente", ["aucune approbation liée"]);
    } else if (lApprob.etat === "manquante") {
      nonExecute("A-1", "partie_manquante", ["approbations.json déclaré présent mais manquant (D-2)"]);
      for (const id of ["A-2", "A-3", "A-4"]) nonExecute(id, "prerequis_en_echec");
    } else {
      echoue("A-1", ["approbations.json présent alors que approval est nul"]);
      for (const id of ["A-2", "A-3", "A-4"]) nonExecute(id, "prerequis_en_echec");
    }
  } else {
    const approbation = evt.approval;
    // A-1
    if (lApprob.etat === "absente") echoue("A-1", ["approbations.json absent alors que approval n'est pas nul"]);
    else if (!approbations) {
      const pa = porteur("A-1", lApprob);
      if (pa) echoue("A-1", [pa.ecart]);
      else nonExecute("A-1", raisonPorteur(lApprob));
    } else {
      const ecarts = validerSchema("enveloppe-approbations", approbations).erreurs.map((e) => `approbations.json : ${e}`);
      if (approbations.ticket !== approbation.ticket) ecarts.push(`ticket ${approbations.ticket} différent de approval.ticket ${approbation.ticket}`);
      if (approbations.request_hash !== approbation.request_hash) ecarts.push("request_hash différent de celui de approval");
      selon("A-1", ecarts);
    }
    // A-2
    if (!approbations || !Array.isArray(approbations.events)) nonExecute("A-2", "prerequis_en_echec");
    else {
      const ecarts = [];
      let A = null;
      try {
        A = objetApprobation(evt);
      } catch {
        A = null;
      }
      const decision = sorteEvenement(evt) === "decision";
      const tsEvt = decoderHorodatage(evt.ts);
      approbations.events.forEach((d, k) => {
        if (!estObjet(d)) return ecarts.push(`events[${k}] n'est pas un objet`);
        if (d.execution?.tool !== NOMS_RESERVES.DECISION) ecarts.push(`events[${k}] : execution.tool ${d.execution?.tool}, ${NOMS_RESERVES.DECISION} attendu`);
        if (!egaliteJson(d.approval, approbation)) ecarts.push(`events[${k}] : approval différent, clé pour clé, de celui de l'événement prouvé`);
        if (A === null || !egaliteJson(d.execution?.arguments?.value, A)) ecarts.push(`events[${k}] : execution.arguments.value différent de A`);
        if (!decision) {
          if (!(d.seq < evt.seq)) ecarts.push(`events[${k}] : seq ${d.seq} non antérieur à celui de l'événement prouvé (${evt.seq})`);
          const at = decoderHorodatage(d.approval?.at);
          if (at === null || tsEvt === null || at > tsEvt) ecarts.push(`events[${k}] : approval.at postérieur au ts de l'événement prouvé`);
        }
      });
      if (decision && !approbations.events.some((d) => hashEvt !== null && hashRecalcule(d) === hashEvt)) {
        ecarts.push("la décision prouvée ne figure pas dans events");
      }
      selon("A-2", ecarts);
    }
    // A-3
    const jeu = approbations?.approver_set;
    const jeuLisible =
      estObjet(jeu) && Array.isArray(jeu.members) && estObjet(jeu.threshold) && Array.isArray(approbation.approvers) && estObjet(approbation.threshold);
    if (!jeuLisible) nonExecute("A-3", "prerequis_en_echec");
    else {
      const ecarts = [];
      const approbateurs = approbation.approvers;
      const distincts = new Set(approbateurs);
      if (distincts.size !== approbateurs.length) ecarts.push("approbateurs en double");
      for (const a of distincts) if (!jeu.members.includes(a)) ecarts.push(`${a} n'est pas membre du jeu déclaré`);
      if (approbation.decision === "expire") {
        if (approbateurs.length !== 0 || (Array.isArray(approbation.signatures) && approbation.signatures.length !== 0)) {
          ecarts.push("décision expire : aucune signature attendue");
        }
      } else {
        const membres = [...distincts].filter((a) => jeu.members.includes(a)).length;
        if (membres < jeu.threshold.required) ecarts.push(`${membres} approbateur(s) distinct(s) membre(s), seuil ${jeu.threshold.required}`);
      }
      if (!egaliteJson(approbation.threshold, jeu.threshold)) ecarts.push("threshold de l'événement différent de celui du jeu déclaré");
      if (!(jeu.threshold.required <= jeu.threshold.size)) ecarts.push("required supérieur à size");
      if (jeu.threshold.size !== jeu.members.length) ecarts.push(`size ${jeu.threshold.size} différent du nombre de membres ${jeu.members.length}`);
      selon("A-3", ecarts);
    }
    // A-4
    if (!voisinsUtilisables) nonExecute("A-4", "prerequis_en_echec");
    else {
      const demande = [previous, next].find((v) => v && hashRecalcule(v) === approbation.request_hash);
      if (!demande) nonExecute("A-4", "piece_hors_dossier", ["l'événement de demande n'est pas un voisin : request_hash non vérifiable"]);
      else selon("A-4", demande.execution?.status === "retenue" ? [] : [`la demande (seq ${demande.seq}) a le statut ${demande.execution?.status}, retenue attendu`]);
    }
  }

  // ------------------------------------------------------------ K-1 à K-9
  if (avecPoints) verifierPoints();

  // ------------------------------------------------------------ AT-1 à AT-7
  let perimetre = null;
  if (avecAttestation) {
    const p = parties.get(PARTIE_ATTESTATION_PERIMETRE.name);
    const x = entree(p.file);
    if (!x?.octets) {
      const motif = x?.tropGrand ? `${p.file} : ${x.taille} octets, au-delà de 4 Mio (CT-6 EX-4.15) : non analysé` : `${p.file} manquant`;
      perimetre = {
        verifications: [
          { id: "AT-1", status: "echoue", reason: null, details: [motif] },
          ...["AT-2", "AT-3", "AT-4", "AT-5", "AT-6", "AT-7"].map((id) => ({ id, status: "non_execute", reason: "prerequis_en_echec", details: [] })),
        ],
        retenue: false,
        avertissements: ["AV-AT-1"],
        digest: null,
      };
    } else {
      perimetre = verifierPartieAttestation(x.octets, {
        profondeurMax: options.profondeurMax,
        evenement: evtExploitable ? evt : null,
        indexCles: clesExploitables ? indexCles : null,
        approbations: R.get("A-1")?.statut === "reussi" ? approbations : null,
      });
    }
  }

  // Parties réservées présentes : leurs vérifications (T-, O-, R-, N-) relèvent
  // de CT-6 ; la bibliothèque ne les exécute pas.
  const reserveesPresentes = PARTIES_RESERVEES.filter((n) => parties.get(n)?.present === true);
  return conclure(evt && hashEvt !== null ? { seq: evt.seq, hash: hashEvt } : null, avecPoints, true, partiesAbsentes, perimetre, reserveesPresentes);

  function verifierPoints() {
    const prerequis = (depuis) => {
      for (const id of CONTROLES_K.slice(depuis)) nonExecute(id, "prerequis_en_echec");
    };
    if (lPoints.etat !== "objet") {
      // Sans forme canonique : l'échec est porté par E-2 (ecartsE2) ; fichier
      // manquant : par D-2 ; non-JSON, non-objet, trop grand : par K-1.
      if (lPoints.etat === "canonique") nonExecute("K-1", "prerequis_en_echec", ["points-de-controle.json sans forme canonique (E-2)"]);
      else if (lPoints.etat === "manquante") nonExecute("K-1", "partie_manquante", ["points-de-controle.json manquant (D-2)"]);
      else echoue("K-1", [lPoints.message ?? "points-de-controle.json inexploitable"]);
      return prerequis(1);
    }
    const partie = lPoints.valeur;
    const ecarts1 = validerSchema("points_de_controle", partie).erreurs.map((e) => `points-de-controle.json : ${e}`);
    // Sans manifeste exploitable (P-1 non réussie) ni événement, les relations
    // ne peuvent pas se comparer ; le schéma de la partie est contrôlé quand
    // même, et un défaut de schéma met K-1 en échec (CT-6 EX-5.9).
    if (statutDe("P-1") !== "reussi" || !evt || !manifeste) {
      if (ecarts1.length) echoue("K-1", ecarts1);
      else nonExecute("K-1", "prerequis_en_echec", ["P-1 n'a pas réussi : relations au manifeste non comparées"]);
      return prerequis(1);
    }
    if (ecarts1.length === 0) {
      const k = partie.checkpoint;
      if (k.org_id !== evt.org_id || k.journal_id !== evt.journal_id) ecarts1.push("checkpoint : org_id ou journal_id différent de celui de l'événement");
      if (k.period_start !== manifeste.period_start) ecarts1.push(`checkpoint.period_start ${k.period_start} différent de celui du manifeste (${manifeste.period_start})`);
      if (!(1 <= k.tree_size && k.tree_size <= manifeste.count)) ecarts1.push(`tree_size ${k.tree_size} hors de [1, count = ${manifeste.count}]`);
      if (k.last_seq !== manifeste.first_seq + k.tree_size - 1) ecarts1.push(`last_seq ${k.last_seq} différent de first_seq + tree_size − 1`);
      if (k.root === ZERO32) ecarts1.push("racine du point nulle");
      const t = decoderHorodatage(k.checkpoint_ts);
      if (t === null) ecarts1.push("checkpoint_ts : horodatage qui ne se décode pas");
      else if (t < manifeste.period_start * 1000) ecarts1.push(`checkpoint_ts ${k.checkpoint_ts} antérieur à period_start`);
    }
    if (ecarts1.length) {
      echoue("K-1", ecarts1);
      return prerequis(1);
    }
    reussi("K-1");
    const k = partie.checkpoint;
    // K-2
    const ch = hacherPoint(k);
    selon("K-2", ch === partie.checkpoint_hash ? [] : [`checkpoint_hash ${partie.checkpoint_hash} différent du checkpointHash recalculé ${ch}`]);
    // K-3
    if (!clesExploitables) nonExecute("K-3", "prerequis_en_echec", ["cles.json inexploitable"]);
    else {
      const cle = indexCles.cles.get(k.key_id);
      if (!cle) echoue("K-3", [`clé ${k.key_id} absente de cles.json`]);
      else {
        const ecarts = [];
        if (!cle.admise || !verifierSignaturePoint(k, cle.octets)) ecarts.push(`signature du point invalide sous ${k.key_id}`);
        if (!dansValidite(cle, decoderHorodatage(k.checkpoint_ts))) ecarts.push(`checkpoint_ts ${k.checkpoint_ts} hors de la validité de la clé ${k.key_id}`);
        selon("K-3", ecarts);
      }
    }
    // K-4
    if (statutDe("M-3") !== "reussi") nonExecute("K-4", "prerequis_en_echec", ["M-3 n'a pas réussi"]);
    else {
      const ecarts = [];
      if (!(chemin.leaf_index < k.tree_size)) ecarts.push(`leaf_index ${chemin.leaf_index} non inférieur à tree_size ${k.tree_size}`);
      const te = decoderHorodatage(evt.ts);
      if (te === null || te > decoderHorodatage(k.checkpoint_ts)) ecarts.push(`ts ${evt.ts} postérieur à checkpoint_ts ${k.checkpoint_ts}`);
      selon("K-4", ecarts);
    }
    // K-5
    const c = partie.consistency;
    const ecarts5 = [];
    if (c.first_size !== k.tree_size) ecarts5.push("consistency.first_size différent de tree_size");
    if (c.second_size !== manifeste.count) ecarts5.push("consistency.second_size différent de count");
    if (c.first_root !== k.root) ecarts5.push("consistency.first_root différent de la racine du point");
    if (c.second_root !== manifeste.root) ecarts5.push("consistency.second_root différent de la racine du manifeste");
    const vc = verifierCoherence(c);
    if (!vc.valide) ecarts5.push(`preuve de cohérence refusée : ${vc.raison}`);
    selon("K-5", ecarts5);
    // K-6
    const porteurLast = [evt, previous, next].find((v) => v && v.seq === k.last_seq);
    if (!porteurLast) nonExecute("K-6", "piece_hors_dossier", [`l'événement seq ${k.last_seq} n'est pas dans le dossier`]);
    else {
      const h = hashRecalcule(porteurLast);
      selon("K-6", h === k.last_hash ? [] : [`last_hash ${k.last_hash} différent du hash recalculé de seq ${k.last_seq} (${h})`]);
    }
    // K-7 à K-9 : ancres.
    const ancres = partie.anchors;
    const deleguer = (id, cle, verifPrealable) => {
      const ancre = ancres[cle];
      if (ancre === null) return nonExecute(id, "partie_absente", ["ancre non fournie"]);
      const prealable = verifPrealable ? verifPrealable(ancre) : [];
      if (prealable.length) return echoue(id, prealable);
      const f = options.verificateursAncres?.[cle];
      if (typeof f !== "function") return nonExecute(id, "verification_ct6_requise", ["vérification de l'ancre fixée par CT-6, hors de cette bibliothèque"]);
      const r = f(ancre, { checkpoint_hash: ch, partie });
      poser(id, r.statut, r.details ?? [], r.raison ?? null);
    };
    deleguer("K-7", "rfc3161");
    deleguer("K-8", "registry", (a) => {
      const ecarts = [];
      const f = empreinteAncre(evt.org_id, evt.journal_id, ch);
      if (a.fingerprint !== f) ecarts.push(`fingerprint ${a.fingerprint} différent de keccak256(org_id || journal_id || checkpoint_hash) ${f}`);
      if (a.doc_type !== DOC_TYPE_POINT) ecarts.push(`doc_type ${a.doc_type} différent de ${DOC_TYPE_POINT}`);
      return ecarts;
    });
    deleguer("K-9", "ots");
  }

  function inutilisable(erreur) {
    return {
      utilisable: false,
      erreur,
      verdict: null,
      valide: null,
      evenement: null,
      controles: [],
      controles_en_echec: [],
      non_executes_bloquants: [],
      parties_absentes: [],
      borne: null,
      perimetre: null,
    };
  }

  function conclure(evenement, avecK, indexLu, absentes, perim, reservees = []) {
    // Tout contrôle non posé (index illisible) est non exécuté faute de prérequis.
    for (const id of ORDRE_CONTROLES) {
      if (CONTROLES_K.includes(id) && !avecK) continue;
      if (!R.has(id)) nonExecute(id, "prerequis_en_echec");
    }
    const controles = ORDRE_CONTROLES.filter((id) => R.has(id) && (avecK || !CONTROLES_K.includes(id))).map((id) => R.get(id));
    const enEchec = trierControles(controles.filter((c) => c.statut === "echoue").map((c) => c.id));
    const bloquants = controles.filter((c) => c.statut === "non_execute" && !c.admise).map((c) => c.id);
    for (const n of reservees) bloquants.push(`partie ${n} (vérification CT-6)`);
    const valide = enEchec.length === 0 && bloquants.length === 0;
    const sansAncre = absentes.some((p) => ["jeton_rfc3161", "preuve_ots", "registre"].includes(p.name));
    return {
      utilisable: true,
      erreur: null,
      verdict: valide ? "valide" : "invalide",
      valide,
      evenement,
      controles,
      controles_en_echec: enEchec,
      non_executes_bloquants: bloquants,
      parties_absentes: indexLu ? absentes : [],
      borne: valide && sansAncre ? BORNE : null,
      perimetre: perim,
    };
  }
}

function referencesDe(e) {
  const sortie = [];
  if (!estObjet(e)) return sortie;
  const ajouter = (r) => {
    if (estObjet(r) && typeof r.sha256 === "string") sortie.push({ reference: r });
  };
  if (estObjet(e.intent)) ajouter(e.intent);
  ajouter(e.execution?.arguments);
  ajouter(e.execution?.result);
  if (Array.isArray(e.context)) e.context.forEach(ajouter);
  return sortie;
}

/**
 * Construit l'index dossier.json d'un dossier à partir des fichiers de ses
 * parties (CT-1 §11.1) : parties présentes avec le SHA-256 de leurs octets,
 * parties absentes avec leur raison, douze, treize ou quatorze parties.
 * @param {object} p
 * @param {{seq: number, hash: string}} p.event
 * @param {string} p.org_id
 * @param {string} p.journal_id
 * @param {string} p.generated_at instant d'export (paramètre : aucune horloge n'est lue)
 * @param {Map<string, Uint8Array>|Record<string, Uint8Array>} p.fichiers fichiers des parties présentes, par nom de fichier
 * @param {Record<string, string>} [p.raisons] raison d'absence par nom de partie (défaut : « hors périmètre CT-1 »,
 *   « aucune approbation liée », « aucun point de contrôle », « aucune attestation de périmètre »)
 * @param {boolean} [p.points] déclarer la treizième partie
 * @param {boolean} [p.attestation] déclarer la quatorzième partie (implique la treizième)
 * @returns {object} l'index
 */
export function indexerDossier(p) {
  const lire = (nom) => (p.fichiers instanceof Map ? p.fichiers.get(nom) : p.fichiers[nom]);
  const defauts = {
    approbations: "aucune approbation liée",
    points_de_controle: "aucun point de contrôle",
    attestation_perimetre: "aucune attestation de périmètre",
  };
  const liste = [...PARTIES_V0];
  if (p.points || p.attestation) liste.push(PARTIE_POINTS_DE_CONTROLE);
  if (p.attestation) liste.push(PARTIE_ATTESTATION_PERIMETRE);
  return {
    version: 0,
    event: { seq: p.event.seq, hash: p.event.hash },
    org_id: p.org_id,
    journal_id: p.journal_id,
    generated_at: p.generated_at,
    parts: liste.map(({ name, file }) => {
      const o = lire(file);
      if (o instanceof Uint8Array) return { name, file, sha256: sha256Hex(o), present: true, reason_if_absent: null };
      const raison = p.raisons?.[name] ?? defauts[name] ?? "hors périmètre CT-1";
      return { name, file, sha256: null, present: false, reason_if_absent: raison };
    }),
  };
}
