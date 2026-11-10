// Format des fichiers OpenTimestamps (CT-6 §10.2, EX-10.2, EX-10.5) et ordre
// de sérialisation de la bibliothèque de référence (CT-5 EX-6.4) : lecture
// stricte et bornée, écriture, fusion (EX-6.6), construction d'une preuve
// depuis l'empreinte, le nonce et les réponses des calendriers (EX-6.2, EX-6.4).
//
// Le lecteur est structurel : il ne calcule aucun condensé. L'exécution des
// opérations (O-3) et la comparaison aux en-têtes (O-4, O-5) sont dans
// `verification.mjs`. Rien n'est réencodé à la lecture : les octets reçus
// sont conservés tels quels par l'appelant ; l'écriture ne sert qu'aux
// preuves que ce composant construit ou fusionne lui-même.

import { concatener, hexVersOctets, octetsVersHex, sha256, utf8 } from "@noortrace/noyau";

/** En-tête magique, 31 octets (CT-6 §10.2, R2-F01). */
export const EN_TETE_MAGIQUE = Uint8Array.from([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
/** Seule version admise (CT-6 §10.2). */
export const VERSION = 0x01;

/** Codes d'opération (CT-6 §10.2). */
export const OP = Object.freeze({
  APPEND: 0xf0,
  PREPEND: 0xf1,
  SHA256: 0x08,
  SHA1: 0x02,
  RIPEMD160: 0x03,
  KECCAK256: 0x67,
  REVERSE: 0xf2,
  HEXLIFY: 0xf3,
});
/** Opérations du profil de la version 0 (CT-6 EX-10.7). */
export const PROFIL_V0 = Object.freeze(new Set([OP.APPEND, OP.PREPEND, OP.SHA256]));
/** Opérations binaires (un argument en varbytes). */
const BINAIRES = new Set([OP.APPEND, OP.PREPEND]);
/** Opérations unaires reconnues hors profil. */
const UNAIRES_HORS_PROFIL = new Set([OP.SHA1, OP.RIPEMD160, OP.KECCAK256, OP.REVERSE, OP.HEXLIFY]);
/** Toutes les opérations reconnues ; une autre étiquette rend le fichier illisible (R2-F15). */
const OPERATIONS_CONNUES = new Set([...PROFIL_V0, ...UNAIRES_HORS_PROFIL]);

/** Étiquettes d'attestation (8 octets). */
export const ETIQUETTE_BITCOIN = Uint8Array.from([0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01]);
export const ETIQUETTE_EN_ATTENTE = Uint8Array.from([0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e]);

/** Bornes (CT-6 §10.2, EX-10.2, §15.1). */
export const BORNES = Object.freeze({
  TAILLE_FICHIER: 256 * 1024, // EX-4.13, EX-10.2
  ARGUMENT_MIN: 1,
  ARGUMENT_MAX: 4096, // R2-F13
  MESSAGE_MAX: 4096, // R2-F13 (O-3)
  CHARGE_ATTESTATION_MAX: 8192, // R2-F19
  URI_MAX: 1000, // R2-F20
  VARUINT_OCTETS_MAX: 9, // EX-10.2
  OPERATIONS_PAR_CHEMIN_MAX: 255, // R2-F18
  HAUTEUR_MAX: 0xffffffff, // EX-10.2 : hauteur < 2^32
  REPONSE_CALENDRIER_MAX: 10000, // CT-5 EX-6.2, EX-6.6 (R1-F63)
});

const CARACTERES_URI = /^[A-Za-z0-9\-._/:]*$/;

/** Erreur de lecture ou d'écriture d'une preuve ; `code` est stable et sans donnée sensible. */
export class ErreurOts extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {number} [position] décalage dans le fichier
   */
  constructor(code, message, position) {
    super(position === undefined ? message : `${message} (octet ${position})`);
    this.name = "ErreurOts";
    this.code = code;
    this.position = position;
  }
}

/** Comparaison lexicographique de deux suites d'octets (ordre de `bytes` en Python). */
export function comparerOctets(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

function memesOctets(a, b) {
  return comparerOctets(a, b) === 0;
}

// ---------------------------------------------------------------------------
// varuint et varbytes
// ---------------------------------------------------------------------------

/**
 * Encode un entier non négatif en LEB128 non signé (forme minimale).
 * @param {number|bigint} valeur
 * @returns {Uint8Array}
 */
export function encoderVaruint(valeur) {
  let v = BigInt(valeur);
  if (v < 0n) throw new ErreurOts("varuint", "varuint négatif");
  const octets = [];
  do {
    let groupe = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) groupe |= 0x80;
    octets.push(groupe);
  } while (v > 0n);
  if (octets.length > BORNES.VARUINT_OCTETS_MAX) throw new ErreurOts("varuint", "varuint de plus de 9 octets");
  return Uint8Array.from(octets);
}

/**
 * Encode `varbytes(octets)` = varuint(longueur) ‖ octets.
 * @param {Uint8Array} octets
 */
export function encoderVarbytes(octets) {
  return concatener(encoderVaruint(octets.length), octets);
}

/** Lecteur borné sur une suite d'octets. */
class Lecteur {
  constructor(octets) {
    this.octets = octets;
    this.position = 0;
  }

  get reste() {
    return this.octets.length - this.position;
  }

  octet() {
    if (this.position >= this.octets.length) throw new ErreurOts("tronque", "fin de fichier prématurée", this.position);
    const o = this.octets[this.position];
    this.position += 1;
    return o;
  }

  suite(n) {
    if (this.position + n > this.octets.length) throw new ErreurOts("tronque", `fin de fichier prématurée (${n} octets attendus)`, this.position);
    const s = this.octets.subarray(this.position, this.position + n);
    this.position += n;
    return s;
  }

  /**
   * varuint LEB128 sous forme minimale, au plus 9 octets (EX-10.2).
   * @returns {bigint}
   */
  varuint() {
    const debut = this.position;
    let valeur = 0n;
    let decalage = 0n;
    let nb = 0;
    for (;;) {
      const o = this.octet();
      nb += 1;
      if (nb > BORNES.VARUINT_OCTETS_MAX) throw new ErreurOts("varuint_trop_long", "varuint de plus de 9 octets", debut);
      valeur |= BigInt(o & 0x7f) << decalage;
      if ((o & 0x80) === 0) {
        // Forme minimale : un groupe final nul après un groupe de suite est interdit.
        if (nb > 1 && (o & 0x7f) === 0) throw new ErreurOts("varuint_non_minimal", "varuint sous forme non minimale", debut);
        return valeur;
      }
      decalage += 7n;
    }
  }

  /**
   * varbytes(min..max).
   * @param {number} min
   * @param {number} max
   */
  varbytes(min, max) {
    const debut = this.position;
    const n = this.varuint();
    if (n > BigInt(max)) throw new ErreurOts("varbytes_longueur", `varbytes de ${n} octets, plus de ${max}`, debut);
    if (n < BigInt(min)) throw new ErreurOts("varbytes_longueur", `varbytes de ${n} octets, moins de ${min}`, debut);
    return this.suite(Number(n));
  }
}

// ---------------------------------------------------------------------------
// Arbre
// ---------------------------------------------------------------------------

/**
 * Attestation d'une feuille.
 * @typedef {object} Attestation
 * @property {"bitcoin"|"en_attente"|"inconnue"} genre
 * @property {Uint8Array} etiquette 8 octets
 * @property {Uint8Array} charge charge utile telle que lue (sans son préfixe de longueur)
 * @property {number|null} hauteur hauteur du bloc (Bitcoin)
 * @property {string|null} uri URI du calendrier (en attente)
 */

/**
 * Nœud de l'arbre : des attestations et des opérations vers des sous-nœuds.
 * Les attestations et les opérations sont dédoublonnées comme les ensembles
 * et les dictionnaires de la bibliothèque de référence.
 */
export class Noeud {
  constructor() {
    /** @type {Attestation[]} */
    this.attestations = [];
    /** @type {{code: number, argument: Uint8Array|null, noeud: Noeud}[]} */
    this.operations = [];
  }

  /** Ajoute une attestation (sans doublon). */
  ajouterAttestation(attestation) {
    if (!this.attestations.some((a) => memesOctets(a.etiquette, attestation.etiquette) && memesOctets(a.charge, attestation.charge))) {
      this.attestations.push(attestation);
    }
    return this;
  }

  /**
   * Rend le sous-nœud de l'opération (code, argument), créé s'il manque.
   * @param {number} code
   * @param {Uint8Array|null} argument
   */
  operation(code, argument) {
    const existante = this.operations.find(
      (o) => o.code === code && (o.argument === null ? argument === null : argument !== null && memesOctets(o.argument, argument)),
    );
    if (existante) return existante.noeud;
    const noeud = new Noeud();
    this.operations.push({ code, argument: argument === null ? null : Uint8Array.from(argument), noeud });
    return noeud;
  }

  /** Fusionne un autre arbre dans celui-ci (`Timestamp.merge`). */
  fusionner(autre) {
    for (const a of autre.attestations) this.ajouterAttestation(a);
    for (const o of autre.operations) this.operation(o.code, o.argument).fusionner(o.noeud);
    return this;
  }

  /** Retire les attestations qui satisfont le prédicat ; rend le nombre retiré. */
  retirerAttestations(predicat) {
    const avant = this.attestations.length;
    this.attestations = this.attestations.filter((a) => !predicat(a));
    return avant - this.attestations.length;
  }

  /** Copie profonde. */
  copier() {
    const n = new Noeud();
    for (const a of this.attestations) n.attestations.push({ ...a, etiquette: Uint8Array.from(a.etiquette), charge: Uint8Array.from(a.charge) });
    for (const o of this.operations) n.operations.push({ code: o.code, argument: o.argument === null ? null : Uint8Array.from(o.argument), noeud: o.noeud.copier() });
    return n;
  }

  /** Vrai si l'arbre porte au moins une attestation (une feuille). */
  estNonVide() {
    return this.attestations.length > 0 || this.operations.some((o) => o.noeud.estNonVide());
  }
}

/** Construit une attestation Bitcoin. */
export function attestationBitcoin(hauteur) {
  if (!Number.isInteger(hauteur) || hauteur < 0 || hauteur > BORNES.HAUTEUR_MAX) throw new ErreurOts("hauteur", "hauteur Bitcoin hors bornes");
  return { genre: "bitcoin", etiquette: Uint8Array.from(ETIQUETTE_BITCOIN), charge: encoderVaruint(hauteur), hauteur, uri: null };
}

/** Construit une attestation en attente. */
export function attestationEnAttente(uri) {
  if (typeof uri !== "string" || uri.length > BORNES.URI_MAX || !CARACTERES_URI.test(uri)) throw new ErreurOts("uri", "URI de calendrier refusée");
  return { genre: "en_attente", etiquette: Uint8Array.from(ETIQUETTE_EN_ATTENTE), charge: encoderVarbytes(utf8(uri)), hauteur: null, uri };
}

/**
 * Lit une attestation (étiquette puis charge utile), charges connues
 * consommées exactement (CT-6 §10.2).
 * @param {Lecteur} lecteur
 * @returns {Attestation}
 */
function lireAttestation(lecteur) {
  const debut = lecteur.position;
  const etiquette = Uint8Array.from(lecteur.suite(8));
  const charge = Uint8Array.from(lecteur.varbytes(0, BORNES.CHARGE_ATTESTATION_MAX));
  if (memesOctets(etiquette, ETIQUETTE_BITCOIN)) {
    const interne = new Lecteur(charge);
    const hauteur = interne.varuint();
    if (interne.reste !== 0) throw new ErreurOts("attestation", "charge Bitcoin non consommée exactement", debut);
    if (hauteur > BigInt(BORNES.HAUTEUR_MAX)) throw new ErreurOts("hauteur", "hauteur Bitcoin supérieure ou égale à 2^32", debut);
    return { genre: "bitcoin", etiquette, charge, hauteur: Number(hauteur), uri: null };
  }
  if (memesOctets(etiquette, ETIQUETTE_EN_ATTENTE)) {
    const interne = new Lecteur(charge);
    const uriOctets = interne.varbytes(0, BORNES.URI_MAX);
    if (interne.reste !== 0) throw new ErreurOts("attestation", "charge d'attestation en attente non consommée exactement", debut);
    let uri;
    try {
      uri = new TextDecoder("utf-8", { fatal: true }).decode(uriOctets);
    } catch {
      throw new ErreurOts("uri", "URI de calendrier qui n'est pas de l'UTF-8", debut);
    }
    if (!CARACTERES_URI.test(uri)) throw new ErreurOts("uri", "URI de calendrier avec un caractère hors de l'alphabet admis", debut);
    return { genre: "en_attente", etiquette, charge, hauteur: null, uri };
  }
  return { genre: "inconnue", etiquette, charge, hauteur: null, uri: null };
}

/**
 * Lit un arbre (`Timestamp` de la bibliothèque de référence) depuis le
 * lecteur, dans la limite de 255 opérations par chemin.
 * @param {Lecteur} lecteur
 * @param {number} operationsRestantes
 * @returns {Noeud}
 */
function lireArbre(lecteur, operationsRestantes) {
  const noeud = new Noeud();
  const lireBranche = (etiquette) => {
    if (etiquette === 0x00) {
      const position = lecteur.position;
      const attestation = lireAttestation(lecteur);
      // Un doublon n'a pas de forme canonique (ensemble dans la bibliothèque
      // de référence) : il ouvrirait une divergence entre analyseurs.
      if (noeud.attestations.some((a) => memesOctets(a.etiquette, attestation.etiquette) && memesOctets(a.charge, attestation.charge))) {
        throw new ErreurOts("doublon", "attestation en double sous un même nœud", position);
      }
      noeud.attestations.push(attestation);
      return;
    }
    if (etiquette === 0xff) throw new ErreurOts("branche", "octet ff sans branche", lecteur.position - 1);
    if (!OPERATIONS_CONNUES.has(etiquette)) throw new ErreurOts("operation_inconnue", `étiquette d'opération inconnue 0x${etiquette.toString(16).padStart(2, "0")}`, lecteur.position - 1);
    if (operationsRestantes === 0) throw new ErreurOts("profondeur", "plus de 255 opérations sur un chemin", lecteur.position - 1);
    const position = lecteur.position - 1;
    const argument = BINAIRES.has(etiquette) ? Uint8Array.from(lecteur.varbytes(BORNES.ARGUMENT_MIN, BORNES.ARGUMENT_MAX)) : null;
    if (noeud.operations.some((o) => o.code === etiquette && (o.argument === null ? argument === null : argument !== null && memesOctets(o.argument, argument)))) {
      throw new ErreurOts("doublon", "opération en double sous un même nœud (la bibliothèque de référence écraserait la première branche)", position);
    }
    const sous = lireArbre(lecteur, operationsRestantes - 1);
    noeud.operations.push({ code: etiquette, argument, noeud: sous });
  };
  let etiquette = lecteur.octet();
  while (etiquette === 0xff) {
    lireBranche(lecteur.octet());
    etiquette = lecteur.octet();
  }
  lireBranche(etiquette);
  return noeud;
}

/**
 * Lit un `Timestamp` nu (réponse d'un calendrier : arbre sans en-tête de
 * fichier), borné à 10 000 octets (CT-5 EX-6.2, EX-6.6).
 * @param {Uint8Array} octets
 * @param {{tailleMax?: number}} [options]
 * @returns {Noeud}
 */
export function lireTimestamp(octets, options = {}) {
  const tailleMax = options.tailleMax ?? BORNES.REPONSE_CALENDRIER_MAX;
  if (!(octets instanceof Uint8Array)) throw new ErreurOts("type", "octets attendus");
  if (octets.length > tailleMax) throw new ErreurOts("taille", `réponse de ${octets.length} octets, plus de ${tailleMax}`);
  const lecteur = new Lecteur(octets);
  const arbre = lireArbre(lecteur, BORNES.OPERATIONS_PAR_CHEMIN_MAX);
  if (lecteur.reste !== 0) throw new ErreurOts("octets_en_trop", "octets après l'arbre", lecteur.position);
  return arbre;
}

/**
 * Lit un fichier `.ots` (CT-6 §10.2, EX-10.2, EX-10.5) : en-tête magique,
 * version, opération de hachage du fichier `08`, empreinte de 32 octets,
 * arbre, fin de fichier exacte. Lève `ErreurOts` sur tout défaut (O-1).
 * @param {Uint8Array} octets
 * @returns {{empreinte: Uint8Array, empreinteHex: string, arbre: Noeud, taille: number}}
 */
export function lireOts(octets) {
  if (!(octets instanceof Uint8Array)) throw new ErreurOts("type", "octets attendus");
  if (octets.length > BORNES.TAILLE_FICHIER) throw new ErreurOts("taille", `fichier de ${octets.length} octets, plus de 256 Kio`);
  const lecteur = new Lecteur(octets);
  if (!memesOctets(lecteur.suite(EN_TETE_MAGIQUE.length), EN_TETE_MAGIQUE)) throw new ErreurOts("en_tete", "en-tête magique absent", 0);
  const version = lecteur.octet();
  if (version !== VERSION) throw new ErreurOts("version", `version ${version} refusée (01 attendu)`, lecteur.position - 1);
  const op = lecteur.octet();
  if (op !== OP.SHA256) throw new ErreurOts("operation_fichier", "opération de hachage du fichier autre que sha256", lecteur.position - 1);
  const empreinte = Uint8Array.from(lecteur.suite(32));
  const arbre = lireArbre(lecteur, BORNES.OPERATIONS_PAR_CHEMIN_MAX);
  if (lecteur.reste !== 0) throw new ErreurOts("octets_en_trop", "octets après l'arbre", lecteur.position);
  return { empreinte, empreinteHex: octetsVersHex(empreinte), arbre, taille: octets.length };
}

// ---------------------------------------------------------------------------
// Écriture (ordre de la bibliothèque de référence, CT-5 EX-6.4)
// ---------------------------------------------------------------------------

/** Ordre des attestations : étiquette, puis hauteur (Bitcoin), URI (en attente), charge (inconnue). */
export function comparerAttestations(a, b) {
  const e = comparerOctets(a.etiquette, b.etiquette);
  if (e !== 0) return e;
  if (a.genre === "bitcoin") return a.hauteur - b.hauteur;
  if (a.genre === "en_attente") return a.uri < b.uri ? -1 : a.uri > b.uri ? 1 : 0;
  return comparerOctets(a.charge, b.charge);
}

/** Ordre des opérations : code, puis argument. */
export function comparerOperations(a, b) {
  if (a.code !== b.code) return a.code - b.code;
  if (a.argument === null || b.argument === null) return 0;
  return comparerOctets(a.argument, b.argument);
}

function ecrireAttestation(a, sortie) {
  sortie.push(a.etiquette, encoderVarbytes(a.charge));
}

function ecrireOperation(o, sortie) {
  sortie.push(Uint8Array.of(o.code));
  if (o.argument !== null) sortie.push(encoderVarbytes(o.argument));
}

/**
 * Sérialise un arbre (`Timestamp.serialize`) : attestations puis opérations,
 * triées, `ff` avant chaque branche sauf la dernière (EX-6.4).
 * @param {Noeud} noeud
 * @param {Uint8Array[]} sortie
 * @param {number} profondeur opérations déjà traversées
 */
function ecrireArbre(noeud, sortie, profondeur) {
  const attestations = [...noeud.attestations].sort(comparerAttestations);
  const operations = [...noeud.operations].sort(comparerOperations);
  if (attestations.length === 0 && operations.length === 0) throw new ErreurOts("branche_vide", "nœud sans attestation ni opération");
  for (let i = 0; i < attestations.length - 1; i += 1) {
    sortie.push(Uint8Array.of(0xff, 0x00));
    ecrireAttestation(attestations[i], sortie);
  }
  if (operations.length === 0) {
    sortie.push(Uint8Array.of(0x00));
    ecrireAttestation(attestations[attestations.length - 1], sortie);
    return;
  }
  if (attestations.length > 0) {
    sortie.push(Uint8Array.of(0xff, 0x00));
    ecrireAttestation(attestations[attestations.length - 1], sortie);
  }
  if (profondeur + 1 > BORNES.OPERATIONS_PAR_CHEMIN_MAX) throw new ErreurOts("profondeur", "plus de 255 opérations sur un chemin");
  for (let i = 0; i < operations.length; i += 1) {
    if (i < operations.length - 1) sortie.push(Uint8Array.of(0xff));
    ecrireOperation(operations[i], sortie);
    ecrireArbre(operations[i].noeud, sortie, profondeur + 1);
  }
}

/**
 * Sérialise un `Timestamp` nu.
 * @param {Noeud} arbre
 * @returns {Uint8Array}
 */
export function ecrireTimestamp(arbre) {
  const sortie = [];
  ecrireArbre(arbre, sortie, 0);
  return concatener(...sortie);
}

/**
 * Écrit un fichier `.ots` (CT-6 §10.2) depuis une empreinte et un arbre.
 * @param {{empreinte: Uint8Array|string, arbre: Noeud}} p
 * @returns {Uint8Array}
 */
export function ecrireOts({ empreinte, arbre }) {
  const e = typeof empreinte === "string" ? hexVersOctets(empreinte, 32) : empreinte;
  if (!(e instanceof Uint8Array) || e.length !== 32) throw new ErreurOts("empreinte", "empreinte de 32 octets attendue");
  if (!(arbre instanceof Noeud)) throw new ErreurOts("type", "arbre attendu");
  const sortie = [EN_TETE_MAGIQUE, Uint8Array.of(VERSION, OP.SHA256), e];
  ecrireArbre(arbre, sortie, 0);
  const octets = concatener(...sortie);
  if (octets.length > BORNES.TAILLE_FICHIER) throw new ErreurOts("taille", "fichier de plus de 256 Kio");
  return octets;
}

// ---------------------------------------------------------------------------
// Construction (EX-6.2, EX-6.4) et fusion (EX-6.6)
// ---------------------------------------------------------------------------

/**
 * Engagement e = SHA-256(empreinte ‖ nonce) (CT-5 EX-6.2, étape 1).
 * @param {Uint8Array|string} empreinte 32 octets
 * @param {Uint8Array} nonce 16 octets
 * @returns {Uint8Array}
 */
export function engagementOctets(empreinte, nonce) {
  const e = typeof empreinte === "string" ? hexVersOctets(empreinte, 32) : empreinte;
  if (!(e instanceof Uint8Array) || e.length !== 32) throw new ErreurOts("empreinte", "empreinte de 32 octets attendue");
  if (!(nonce instanceof Uint8Array) || nonce.length !== 16) throw new ErreurOts("nonce", "nonce de 16 octets attendu");
  return sha256(concatener(e, nonce));
}

/**
 * Construit la preuve d'EX-6.4 : `f0 nonce`, `08`, puis la fusion des
 * `Timestamp` reçus des calendriers pour l'engagement.
 * @param {{empreinte: Uint8Array|string, nonce: Uint8Array, reponses: (Uint8Array|Noeud)[]}} p
 * @returns {{octets: Uint8Array, engagement: Uint8Array, arbre: Noeud}}
 */
export function construirePreuve({ empreinte, nonce, reponses }) {
  const engagement = engagementOctets(empreinte, nonce);
  const arbre = new Noeud();
  const noeudE = arbre.operation(OP.APPEND, nonce).operation(OP.SHA256, null);
  if (!Array.isArray(reponses) || reponses.length === 0) throw new ErreurOts("reponses", "au moins une réponse de calendrier attendue");
  for (const r of reponses) noeudE.fusionner(r instanceof Noeud ? r : lireTimestamp(r));
  return { octets: ecrireOts({ empreinte, arbre }), engagement, arbre };
}

/**
 * Trouve les nœuds portant une attestation en attente, avec le message
 * (engagement) de chaque nœud calculé par les seules opérations du profil.
 * @param {Noeud} arbre
 * @param {Uint8Array} message message du nœud racine
 * @returns {{noeud: Noeud, message: Uint8Array, attestation: Attestation}[]}
 */
export function attestationsEnAttente(arbre, message) {
  const resultat = [];
  const parcourir = (noeud, m) => {
    for (const a of noeud.attestations) if (a.genre === "en_attente") resultat.push({ noeud, message: m, attestation: a });
    for (const o of noeud.operations) {
      const suivant = appliquerOperation(o.code, o.argument, m);
      if (suivant !== null) parcourir(o.noeud, suivant);
    }
  };
  parcourir(arbre, message);
  return resultat;
}

/**
 * Applique une opération du profil (CT-6 EX-10.7) ; rend `null` pour une
 * opération hors profil ou un message hors bornes.
 * @param {number} code
 * @param {Uint8Array|null} argument
 * @param {Uint8Array} message
 * @returns {Uint8Array|null}
 */
export function appliquerOperation(code, argument, message) {
  if (message.length < 1 || message.length > BORNES.MESSAGE_MAX) return null;
  let resultat;
  if (code === OP.APPEND) resultat = concatener(message, argument);
  else if (code === OP.PREPEND) resultat = concatener(argument, message);
  else if (code === OP.SHA256) resultat = sha256(message);
  else return null;
  if (resultat.length < 1 || resultat.length > BORNES.MESSAGE_MAX) return null;
  return resultat;
}

/**
 * Fusion d'EX-6.6 : le chemin reçu du calendrier pour l'engagement `e`
 * remplace l'attestation en attente de ce calendrier au nœud de `e`.
 * @param {Uint8Array} preuve fichier `.ots` courant
 * @param {{engagement: Uint8Array|string, chemin: Uint8Array|Noeud, uri: string}} p
 * @returns {{octets: Uint8Array, arbre: Noeud, retirees: number}}
 */
export function fusionnerOts(preuve, { engagement, chemin, uri }) {
  const { empreinte, arbre } = lireOts(preuve);
  const e = typeof engagement === "string" ? hexVersOctets(engagement, 32) : engagement;
  if (!(e instanceof Uint8Array) || e.length !== 32) throw new ErreurOts("engagement", "engagement de 32 octets attendu");
  const recu = chemin instanceof Noeud ? chemin : lireTimestamp(chemin);
  const copie = arbre.copier();
  const cibles = attestationsEnAttente(copie, empreinte).filter((c) => memesOctets(c.message, e) && (uri === undefined || c.attestation.uri === uri));
  if (cibles.length === 0) throw new ErreurOts("engagement_inconnu", "aucune attestation en attente pour cet engagement");
  let retirees = 0;
  const noeuds = new Set(cibles.map((c) => c.noeud));
  for (const noeud of noeuds) {
    retirees += noeud.retirerAttestations((a) => a.genre === "en_attente" && (uri === undefined || a.uri === uri));
    noeud.fusionner(recu);
  }
  return { octets: ecrireOts({ empreinte, arbre: copie }), arbre: copie, retirees };
}
