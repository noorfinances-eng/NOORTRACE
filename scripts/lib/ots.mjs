// Contrôle 5 de l'architecture : preuve OpenTimestamps contre les en-têtes
// Bitcoin (spec/CT-6-verificateur.md §10). Implémentation de référence
// JavaScript des vérifications O-1 à O-7 et des avertissements AV-O-1 à AV-O-3.
//
// Ce module ne fait aucun accès réseau : il ne met jamais une preuve à niveau
// auprès d'un calendrier et ne consulte aucun nœud Bitcoin. La chaîne
// d'en-têtes est une entrée déclarative (--entetes-bitcoin), crue seulement au
// travers de O-5, qui la rattache par le hachage au point de contrôle du
// fichier d'ancres et recalcule la preuve de travail au-dessus de lui.
//
// Contenu :
//   - la lecture stricte du format .ots de opentimestamps.core (§10.2,
//     EX-10.2) : en-tête magique, version 01, opération de fichier 08,
//     empreinte, arbre d'opérations et d'attestations, varuint sous forme
//     minimale, bornes de la bibliothèque de référence ;
//   - l'exécution des opérations du profil v0 { f0, f1, 08 } (EX-10.7) ;
//   - les en-têtes Bitcoin : 80 octets, double SHA-256, nBits → cible
//     (SetCompact, GetCompact), preuve de travail, réajustement de difficulté,
//     médiane des onze derniers blocs (EX-10.9) ;
//   - les vérifications O-1 à O-7 (verifierPreuve), le statut du contrôle 5
//     (EX-10.12), les faits rapportés (EX-10.14) et la proposition de
//     l'énoncé (EX-10.15) ;
//   - le contrôle N-2 du fichier d'en-têtes (controlerEntetes).

import crypto from "node:crypto";

// ---------------------------------------------------------------------------
// Constantes (§10.2, §10.3)
// ---------------------------------------------------------------------------

export const EN_TETE_MAGIQUE = Buffer.from("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294", "hex");
export const VERSION_MAJEURE = 0x01;
export const OP = { append: 0xf0, prepend: 0xf1, reverse: 0xf2, hexlify: 0xf3, sha1: 0x02, ripemd160: 0x03, sha256: 0x08, keccak256: 0x67 };
const OPS_BINAIRES = new Set([OP.append, OP.prepend]);
const OPS_UNAIRES = new Set([OP.reverse, OP.hexlify, OP.sha1, OP.ripemd160, OP.sha256, OP.keccak256]);
const OPS_PROFIL = new Set([OP.append, OP.prepend, OP.sha256]);
export const ETIQUETTE_BITCOIN = Buffer.from("0588960d73d71901", "hex");
export const ETIQUETTE_EN_ATTENTE = Buffer.from("83dfe30d2ef90c8e", "hex");
// URI de 0 à 1000 octets : la bibliothèque de référence admet l'URI vide (R2-F20, EX-10.2).
const URI_PERMISE = /^[A-Za-z0-9._/:-]*$/;

/** Bornes de EX-10.2 et de la section 15.1 pour le contrôle 5. */
export const BORNES = {
  taillePreuve: 256 * 1024,
  operationsParChemin: 255,
  argument: 4096,
  message: 4096,
  chargeAttestation: 8192,
  uri: 1000,
  octetsVaruint: 9,
  entetes: 200000,
};

/** powLimit de chaque réseau (R2-F51, R2-F53). */
export const POW_LIMIT = {
  mainnet: BigInt("0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
  regtest: BigInt("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
};
export const NBITS_REGTEST = 0x207fffff;
const INTERVALLE_REAJUSTEMENT = 2016;
const DUREE_CIBLE = 1209600; // 14 jours
const MEDIANE = 11;

const T = (fr, en = fr) => ({ fr, en });
const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
/** Double SHA-256 (R2-F44). */
export const dSHA = (b) => sha256(sha256(b));

// ---------------------------------------------------------------------------
// Lecture du format .ots
// ---------------------------------------------------------------------------

/** Erreur de format : le fichier .ots est illisible (O-1). */
export class ErreurOts extends Error {}

class Lecteur {
  constructor(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  octet() {
    if (this.pos >= this.buf.length) throw new ErreurOts("fichier tronqué");
    return this.buf[this.pos++];
  }
  octets(n) {
    if (this.pos + n > this.buf.length) throw new ErreurOts("fichier tronqué");
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return Buffer.from(b);
  }
  /** varuint LEB128, forme minimale, 9 octets au plus (EX-10.2). */
  varuint() {
    let valeur = 0n;
    let decalage = 0n;
    for (let i = 0; ; i++) {
      if (i >= BORNES.octetsVaruint) throw new ErreurOts(`varuint de plus de ${BORNES.octetsVaruint} octets`);
      const b = this.octet();
      valeur |= BigInt(b & 0x7f) << decalage;
      decalage += 7n;
      if (!(b & 0x80)) {
        if (i > 0 && b === 0) throw new ErreurOts("varuint sous forme non minimale");
        return valeur;
      }
    }
  }
  varbytes(min, max) {
    const n = this.varuint();
    if (n > BigInt(max)) throw new ErreurOts(`varbytes de ${n} octets, au plus ${max}`);
    if (n < BigInt(min)) throw new ErreurOts(`varbytes de ${n} octets, au moins ${min}`);
    return this.octets(Number(n));
  }
  fin() {
    return this.pos === this.buf.length;
  }
}

/**
 * Lit un fichier .ots selon O-1 (EX-10.5). Rend { empreinte (32 octets),
 * arbre } ; un arbre est une liste de branches :
 *   { type: "attestation", attestation: { genre: "bitcoin", hauteur }
 *       | { genre: "en_attente", uri } | { genre: "inconnue", etiquette, charge } }
 *   { type: "operation", op, argument (Buffer ou null), arbre }.
 * Lève ErreurOts au premier défaut.
 */
export function lireOts(octets) {
  const buf = Buffer.from(octets);
  if (buf.length > BORNES.taillePreuve) throw new ErreurOts(`fichier de ${buf.length} octets, au-delà de ${BORNES.taillePreuve}`);
  const l = new Lecteur(buf);
  if (!l.octets(EN_TETE_MAGIQUE.length).equals(EN_TETE_MAGIQUE)) throw new ErreurOts("en-tête magique absent");
  const version = l.octet();
  if (version !== VERSION_MAJEURE) throw new ErreurOts(`version 0x${version.toString(16).padStart(2, "0")}, 01 attendue`);
  const opFichier = l.octet();
  if (opFichier !== OP.sha256) throw new ErreurOts(`opération de hachage du fichier 0x${opFichier.toString(16).padStart(2, "0")}, 08 (SHA-256) attendue`);
  const empreinte = l.octets(32);
  const arbre = lireArbre(l, 0);
  if (!l.fin()) throw new ErreurOts(`${buf.length - l.pos} octet(s) après l'arbre`);
  return { empreinte, arbre };
}

function lireArbre(l, profondeur) {
  const branches = [];
  for (;;) {
    const etiquette = l.octet();
    if (etiquette === 0xff) {
      branches.push(lireBranche(l, l.octet(), profondeur));
      continue;
    }
    branches.push(lireBranche(l, etiquette, profondeur));
    return branches;
  }
}

function lireBranche(l, etiquette, profondeur) {
  if (etiquette === 0x00) return { type: "attestation", attestation: lireAttestation(l) };
  if (!OPS_BINAIRES.has(etiquette) && !OPS_UNAIRES.has(etiquette)) throw new ErreurOts(`étiquette d'opération inconnue 0x${etiquette.toString(16).padStart(2, "0")}`);
  if (profondeur + 1 > BORNES.operationsParChemin) throw new ErreurOts(`chemin de plus de ${BORNES.operationsParChemin} opérations`);
  const argument = OPS_BINAIRES.has(etiquette) ? l.varbytes(1, BORNES.argument) : null;
  return { type: "operation", op: etiquette, argument, arbre: lireArbre(l, profondeur + 1) };
}

function lireAttestation(l) {
  const etiquette = l.octets(8);
  const charge = l.varbytes(0, BORNES.chargeAttestation);
  if (etiquette.equals(ETIQUETTE_BITCOIN)) {
    const c = new Lecteur(charge);
    const hauteur = c.varuint();
    if (!c.fin()) throw new ErreurOts("charge de l'attestation Bitcoin non consommée");
    if (hauteur >= 2n ** 32n) throw new ErreurOts(`hauteur Bitcoin ${hauteur} ≥ 2^32`);
    return { genre: "bitcoin", hauteur: Number(hauteur) };
  }
  if (etiquette.equals(ETIQUETTE_EN_ATTENTE)) {
    const c = new Lecteur(charge);
    const uri = c.varbytes(0, BORNES.uri);
    if (!c.fin()) throw new ErreurOts("charge de l'attestation en attente non consommée");
    const texte = uri.toString("latin1");
    if (!URI_PERMISE.test(texte)) throw new ErreurOts("URI d'attestation en attente hors des caractères permis");
    return { genre: "en_attente", uri: texte };
  }
  return { genre: "inconnue", etiquette, charge };
}

// ---------------------------------------------------------------------------
// Écriture du format .ots (vecteurs et tests)
// ---------------------------------------------------------------------------

/** varuint LEB128 minimal. */
export function encoderVaruint(n) {
  let v = BigInt(n);
  const out = [];
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return Buffer.from(out);
}
const varbytes = (b) => Buffer.concat([encoderVaruint(b.length), b]);

/** Octets d'une attestation (sans le 00 qui l'introduit). */
export function encoderAttestation(a) {
  if (a.genre === "bitcoin") return Buffer.concat([ETIQUETTE_BITCOIN, varbytes(encoderVaruint(a.hauteur))]);
  if (a.genre === "en_attente") return Buffer.concat([ETIQUETTE_EN_ATTENTE, varbytes(varbytes(Buffer.from(a.uri, "latin1")))]);
  return Buffer.concat([a.etiquette, varbytes(a.charge)]);
}

/**
 * Sérialise un arbre dans l'ordre que python-opentimestamps écrit
 * (timestamp.py, Timestamp.serialize) : attestations triées (par hauteur pour
 * Bitcoin), puis opérations triées par étiquette et argument ; chaque branche
 * sauf la dernière précédée de ff.
 */
export function encoderArbre(arbre) {
  const attestations = arbre.filter((b) => b.type === "attestation").sort((a, b) => comparerAttestations(a.attestation, b.attestation));
  const operations = arbre.filter((b) => b.type === "operation").sort((a, b) => a.op - b.op || Buffer.compare(a.argument ?? Buffer.alloc(0), b.argument ?? Buffer.alloc(0)));
  const branches = [...attestations, ...operations];
  if (branches.length === 0) throw new Error("arbre vide");
  const parties = [];
  branches.forEach((b, i) => {
    if (i < branches.length - 1) parties.push(Buffer.from([0xff]));
    if (b.type === "attestation") parties.push(Buffer.from([0x00]), encoderAttestation(b.attestation));
    else parties.push(Buffer.from([b.op]), b.argument ? varbytes(b.argument) : Buffer.alloc(0), encoderArbre(b.arbre));
  });
  return Buffer.concat(parties);
}
function comparerAttestations(a, b) {
  if (a.genre === "bitcoin" && b.genre === "bitcoin") return a.hauteur - b.hauteur;
  return Buffer.compare(encoderAttestation(a), encoderAttestation(b));
}

/** Fichier .ots complet : en-tête, version 01, opération 08, empreinte, arbre. */
export function encoderOts(empreinte, arbre) {
  return Buffer.concat([EN_TETE_MAGIQUE, Buffer.from([VERSION_MAJEURE, OP.sha256]), Buffer.from(empreinte), encoderArbre(arbre)]);
}

/**
 * Construit un arbre linéaire depuis une suite d'opérations
 * [{ op, argument }…] terminée par une liste de branches finales.
 */
export function chemin(operations, finales) {
  let arbre = finales;
  for (let i = operations.length - 1; i >= 0; i--) arbre = [{ type: "operation", op: operations[i].op, argument: operations[i].argument ?? null, arbre }];
  return arbre;
}

/** Applique une opération du profil v0 à un message. */
export function appliquer(op, argument, message) {
  if (op === OP.append) return Buffer.concat([message, argument]);
  if (op === OP.prepend) return Buffer.concat([argument, message]);
  if (op === OP.sha256) return sha256(message);
  throw new Error(`opération 0x${op.toString(16)} hors du profil v0`);
}

// ---------------------------------------------------------------------------
// Exécution des opérations (O-3)
// ---------------------------------------------------------------------------

/**
 * Rejoue les opérations depuis l'empreinte (EX-10.7). Rend { defaut (texte
 * bilingue ou null), attestations: [{ genre, hauteur | uri | etiquette,
 * resultat (Buffer ou null), horsProfil }], operations (ensemble des
 * étiquettes rencontrées) }.
 */
export function executer(preuve) {
  const attestations = [];
  const operations = new Set();
  let defaut = null;
  const parcourir = (arbre, message, horsProfil) => {
    for (const b of arbre) {
      if (b.type === "attestation") {
        attestations.push({ ...b.attestation, resultat: horsProfil || message === null ? null : message, horsProfil });
        continue;
      }
      operations.add(b.op);
      if (horsProfil || !OPS_PROFIL.has(b.op) || message === null) {
        parcourir(b.arbre, null, horsProfil || !OPS_PROFIL.has(b.op));
        continue;
      }
      let resultat = null;
      if (message.length < 1 || message.length > BORNES.message) defaut ??= T(`message de ${message.length} octets en entrée de l'opération 0x${b.op.toString(16)}`, `${message.length}-byte message input to operation 0x${b.op.toString(16)}`);
      else {
        resultat = appliquer(b.op, b.argument, message);
        if (resultat.length < 1 || resultat.length > BORNES.message) {
          defaut ??= T(`résultat de ${resultat.length} octets de l'opération 0x${b.op.toString(16)}, au plus ${BORNES.message}`, `${resultat.length}-byte result of operation 0x${b.op.toString(16)}, at most ${BORNES.message}`);
          resultat = null;
        }
      }
      parcourir(b.arbre, resultat, false);
    }
  };
  parcourir(preuve.arbre, preuve.empreinte, false);
  return { defaut, attestations, operations };
}

// ---------------------------------------------------------------------------
// En-têtes Bitcoin (§10.3)
// ---------------------------------------------------------------------------

/** Champs d'un en-tête brut de 80 octets (R2-F43). */
export function champsEntete(h) {
  return {
    version: h.readInt32LE(0),
    prev: h.subarray(4, 36),
    racine: h.subarray(36, 68),
    nTime: h.readUInt32LE(68),
    nBits: h.readUInt32LE(72),
    nNonce: h.readUInt32LE(76),
  };
}
/** Hachage d'un en-tête dans l'ordre d'affichage de Bitcoin Core (octets inversés), 0x. */
export const hachageAffiche = (h) => hex(Buffer.from(dSHA(h)).reverse());
/** Entier petit-boutiste de 256 bits. */
export const entierLE = (b) => BigInt("0x" + (Buffer.from(b).reverse().toString("hex") || "0"));

/** SetCompact (arith_uint256.cpp, R2-F45) : { cible, negatif, debordement }. */
export function setCompact(x) {
  const taille = x >>> 24;
  let mot = x & 0x007fffff;
  let cible;
  if (taille <= 3) {
    mot >>>= 8 * (3 - taille);
    cible = BigInt(mot);
  } else cible = BigInt(mot) << BigInt(8 * (taille - 3));
  const negatif = mot !== 0 && (x & 0x00800000) !== 0;
  const debordement = mot !== 0 && (taille > 34 || (mot > 0xff && taille > 33) || (mot > 0xffff && taille > 32));
  return { cible, negatif, debordement };
}
/** GetCompact (arith_uint256.cpp, R2-F49). */
export function getCompact(n) {
  let taille = n === 0n ? 0 : Math.ceil(n.toString(16).length / 2);
  let compact;
  if (taille <= 3) compact = Number(n << BigInt(8 * (3 - taille)));
  else compact = Number(n >> BigInt(8 * (taille - 3)));
  if (compact & 0x00800000) {
    compact >>>= 8;
    taille += 1;
  }
  return (compact | (taille << 24)) >>> 0;
}
/** Travail d'un bloc : ⌊2^256 / (cible + 1)⌋ (R2-F47). */
export const travail = (cible) => (1n << 256n) / (cible + 1n);

/**
 * Défauts N-2 d'un fichier d'en-têtes (EX-12.3) déjà analysé en JSON : forme
 * du schéma entetes-bitcoin-v0 et start_height + n − 1 < 2^32. Rend une liste
 * de messages (vide si conforme).
 */
export function controlerEntetes(objet) {
  const d = [];
  if (!objet || typeof objet !== "object" || Array.isArray(objet)) return ["le fichier d'en-têtes n'est pas un objet JSON"];
  const cles = ["version", "network", "start_height", "source", "headers"];
  for (const k of Object.keys(objet)) if (!cles.includes(k)) d.push(`clé inconnue ${k}`);
  for (const k of cles) if (!(k in objet)) d.push(`clé ${k} absente`);
  if (objet.version !== 0) d.push("version différente de 0");
  if (!["mainnet", "regtest"].includes(objet.network)) d.push("network hors de mainnet, regtest");
  if (!Number.isInteger(objet.start_height) || objet.start_height < 0 || objet.start_height > 4294967295) d.push("start_height hors de 0..2^32−1");
  if (typeof objet.source !== "string" || objet.source.length < 1 || objet.source.length > 512) d.push("source de 1 à 512 caractères attendue");
  if (!Array.isArray(objet.headers) || objet.headers.length < 1) d.push("headers : liste non vide attendue");
  else {
    if (objet.headers.length > BORNES.entetes) d.push(`plus de ${BORNES.entetes} en-têtes`);
    const k = objet.headers.findIndex((h) => typeof h !== "string" || !/^0x[0-9a-f]{160}$/.test(h));
    if (k !== -1) d.push(`headers[${k}] : 80 octets en hexadécimal minuscule 0x attendus`);
    if (Number.isInteger(objet.start_height) && objet.start_height + objet.headers.length - 1 >= 2 ** 32) d.push("start_height + n − 1 ≥ 2^32");
  }
  return d;
}

/** Chaîne d'en-têtes : { reseau, s, t, entetes: [Buffer], h(i) }. */
export function preparerEntetes(objet) {
  const entetes = objet.headers.map((x) => Buffer.from(x.slice(2), "hex"));
  const s = objet.start_height;
  return { reseau: objet.network, s, t: s + entetes.length - 1, entetes, h: (i) => entetes[i - s] };
}

/**
 * Règles 1 à 6 de O-5 (EX-10.9). Rend { status, detail, cibles (Map hauteur →
 * cible), regleNBits } ; status : reussi, echoue ou non_execute
 * (ancre_absente : point de contrôle hors des en-têtes fournis, ou
 * réajustement non vérifiable).
 */
export function rattacherChaine(chaine, ancre) {
  const { s, t, h } = chaine;
  const c = ancre.checkpoint.height;
  const echec = (fr, en) => ({ status: "echoue", reason: null, detail: T(fr, en) });
  if (chaine.reseau !== ancre.network) return echec(`réseau ${chaine.reseau} du fichier d'en-têtes différent du réseau ${ancre.network} de l'ancre`, `network ${chaine.reseau} of the headers file differs from network ${ancre.network} of the anchor`);
  for (let i = s + 1; i <= t; i++) if (!champsEntete(h(i)).prev.equals(dSHA(h(i - 1)))) return echec(`en-tête ${i} : prev différent du double SHA-256 de l'en-tête ${i - 1}`, `header ${i}: prev differs from the double SHA-256 of header ${i - 1}`);
  // Point de contrôle hors du fichier : rien ne contredit l'ancre, l'exportateur ne la
  // connaît pas ; O-5 n'est pas exécutée (ancre_absente), EX-10.9, règle 3.
  if (c < s || c > t) return { status: "non_execute", reason: "ancre_absente", detail: T(`point de contrôle ${c} hors des en-têtes ${s} à ${t} fournis : la chaîne ne contient pas la hauteur du point de contrôle`, `checkpoint ${c} outside the given headers ${s} to ${t}: the chain does not contain the checkpoint height`) };
  if (hachageAffiche(h(c)) !== ancre.checkpoint.hash) return echec(`en-tête ${c} de hachage ${hachageAffiche(h(c))} différent du point de contrôle ${ancre.checkpoint.hash}`, `header ${c} with hash ${hachageAffiche(h(c))} differs from checkpoint ${ancre.checkpoint.hash}`);
  const powLimit = POW_LIMIT[ancre.network];
  const cibles = new Map();
  let nonVerifiable = null;
  for (let i = c + 1; i <= t; i++) {
    const e = champsEntete(h(i));
    const { cible, negatif, debordement } = setCompact(e.nBits);
    if (negatif || debordement || cible === 0n || cible > powLimit) return echec(`en-tête ${i} : nBits 0x${e.nBits.toString(16)} négatif, nul, en débordement ou au-dessus de powLimit`, `header ${i}: nBits 0x${e.nBits.toString(16)} negative, zero, overflowing or above powLimit`);
    if (entierLE(dSHA(h(i))) > cible) return echec(`en-tête ${i} : double SHA-256 au-dessus de la cible de nBits 0x${e.nBits.toString(16)} (preuve de travail invalide)`, `header ${i}: double SHA-256 above the nBits 0x${e.nBits.toString(16)} target (invalid proof of work)`);
    cibles.set(i, cible);
    if (ancre.network === "regtest") {
      if (e.nBits !== NBITS_REGTEST) return echec(`en-tête ${i} : nBits 0x${e.nBits.toString(16)} au lieu de 0x207fffff (regtest)`, `header ${i}: nBits 0x${e.nBits.toString(16)} instead of 0x207fffff (regtest)`);
    } else if (i % INTERVALLE_REAJUSTEMENT !== 0) {
      if (e.nBits !== champsEntete(h(i - 1)).nBits) return echec(`en-tête ${i} : nBits différent de celui de l'en-tête ${i - 1} hors réajustement`, `header ${i}: nBits differs from header ${i - 1} outside a retarget`);
    } else if (i - INTERVALLE_REAJUSTEMENT < s) {
      nonVerifiable ??= T(`réajustement de l'en-tête ${i} non vérifiable : l'en-tête ${i - INTERVALLE_REAJUSTEMENT} manque`, `retarget of header ${i} cannot be checked: header ${i - INTERVALLE_REAJUSTEMENT} is missing`);
    } else {
      const precedent = champsEntete(h(i - 1));
      const attendu = nBitsReajuste(precedent.nBits, precedent.nTime - champsEntete(h(i - INTERVALLE_REAJUSTEMENT)).nTime, powLimit);
      if (e.nBits !== attendu) return echec(`en-tête ${i} : nBits 0x${e.nBits.toString(16)} différent du réajustement attendu 0x${attendu.toString(16)}`, `header ${i}: nBits 0x${e.nBits.toString(16)} differs from the expected retarget 0x${attendu.toString(16)}`);
    }
    if (i - MEDIANE >= s) {
      const med = medianeTemps(chaine, i - MEDIANE, i - 1);
      if (e.nTime <= med) return echec(`en-tête ${i} : nTime ${e.nTime} non supérieur à la médiane ${med} des onze précédents`, `header ${i}: nTime ${e.nTime} not above the median ${med} of the eleven previous ones`);
    }
  }
  if (nonVerifiable) return { status: "non_execute", reason: "ancre_absente", detail: nonVerifiable };
  return { status: "reussi", reason: null, cibles };
}
/**
 * nBits attendu au premier bloc d'une période de difficulté sur mainnet
 * (EX-10.9, règle 5 ; pow.cpp, R2-F49) : Δ ramené dans [302 400, 4 838 400],
 * division entière après la multiplication, cible bornée par powLimit.
 */
export function nBitsReajuste(nBitsPrecedent, delta, powLimit = POW_LIMIT.mainnet) {
  const d = Math.min(Math.max(delta, DUREE_CIBLE / 4), DUREE_CIBLE * 4);
  let nouvelle = (setCompact(nBitsPrecedent).cible * BigInt(d)) / BigInt(DUREE_CIBLE);
  if (nouvelle > powLimit) nouvelle = powLimit;
  return getCompact(nouvelle);
}

/** Médiane (sixième des onze valeurs triées) de nTime de a à b inclus. */
function medianeTemps(chaine, a, b) {
  const v = [];
  for (let i = a; i <= b; i++) v.push(champsEntete(chaine.h(i)).nTime);
  v.sort((x, y) => x - y);
  return v[Math.floor(v.length / 2)];
}

// ---------------------------------------------------------------------------
// Vérifications O-1 à O-7 (§10.4)
// ---------------------------------------------------------------------------

export const LIBELLES = {
  "O-1": T("format", "format"),
  "O-2": T("empreinte = periodHash", "file digest = periodHash"),
  "O-3": T("opérations", "operations"),
  "O-4": T("attestation Bitcoin contre l'en-tête", "Bitcoin attestation against the header"),
  "O-5": T("chaîne d'en-têtes rattachée au point de contrôle", "header chain connected to the checkpoint"),
  "O-6": T("profondeur", "depth"),
  "O-7": T("présence d'une attestation Bitcoin", "presence of a Bitcoin attestation"),
};
export const IDS = Object.keys(LIBELLES);

/**
 * Avertissements dans l'ordre de EX-6.15 : vérification qui les lève, dans
 * l'ordre de ses numéros, puis identifiant, puis ordre d'émission (celui de
 * leur objet).
 */
function ordonnerAvertissements(liste) {
  const numero = (id) => Number(/-([0-9]+)$/.exec(id ?? "")?.[1] ?? Infinity);
  return liste
    .map((w, i) => ({ w, i }))
    .sort((a, b) => numero(a.w.check) - numero(b.w.check) || numero(a.w.id) - numero(b.w.id) || a.i - b.i)
    .map((x) => x.w);
}

const RAISONS_ORDRE = ["prerequis_en_echec", "hors_perimetre_version", "partie_absente", "ancre_absente"];
const reussi = (detail) => ({ status: "reussi", reason: null, detail });
const echoue = (detail) => ({ status: "echoue", reason: null, detail });
const nonExecute = (reason, detail) => ({ status: "non_execute", reason, detail });
function heriter(prerequis) {
  const manquants = prerequis.filter(([, p]) => p.status !== "reussi").map(([id, p]) => ({ id, raison: p.status === "echoue" ? "prerequis_en_echec" : p.reason, echec: p.status === "echoue" }));
  const r = RAISONS_ORDRE.find((x) => manquants.some((m) => m.raison === x)) ?? "prerequis_en_echec";
  const cause = manquants.find((m) => m.raison === r) ?? manquants[0];
  if (cause.echec) return nonExecute(r, T(`prérequis ${cause.id} en échec`, `prerequisite ${cause.id} failed`));
  return nonExecute(r, T(`prérequis ${cause.id} non exécuté (${cause.raison})`, `prerequisite ${cause.id} not run (${cause.raison})`));
}
const instantUnix = (s) => new Date(s * 1000).toISOString().slice(0, 19) + "Z";
/** « aucune attestation en attente », « une attestation en attente », « 2 attestations en attente »… */
const compte = (n, genre) => {
  const [frS, frP, enS, enP] = { attente: ["attestation en attente", "attestations en attente", "pending attestation", "pending attestations"], inconnue: ["attestation inconnue", "attestations inconnues", "unknown attestation", "unknown attestations"], bitcoin: ["attestation Bitcoin", "attestations Bitcoin", "Bitcoin attestation", "Bitcoin attestations"] }[genre];
  if (n === 0) return T(`aucune ${frS}`, `no ${enS}`);
  if (n === 1) return T(`une ${frS}`, `one ${enS}`);
  return T(`${n} ${frP}`, `${n} ${enP}`);
};

/**
 * Vérifie la preuve de la partie `preuve_ots` (O-1 à O-7) et rend le statut du
 * contrôle 5.
 *
 * Paramètres :
 *   octets     : octets de preuve.ots (partie présente) ;
 *   periodHash : periodHash recalculé (0x…), ou null s'il n'est pas calculable ;
 *   entetes    : fichier d'en-têtes (objet JSON conforme à N-2), ou null ;
 *   ancres     : fichier d'ancres (objet conforme à N-1), ou null ;
 *   langue     : "fr" (défaut) ou "en".
 *
 * Rend { checks, warnings, status, reason, summary, anchors_used, facts,
 * proposition } comme horodatage.mjs.
 */
export function verifierPreuve(octets, { periodHash = null, entetes = null, ancres = null, langue = "fr" } = {}) {
  const r = evaluerPreuve(octets, { periodHash, entetes, ancres });
  const choisir = (t) => (t === null || t === undefined ? null : typeof t === "string" ? t : t[langue]);
  return {
    checks: r.checks.map((c) => ({ id: c.id, controls: [5], status: c.status, reason: c.reason, admitted: c.status === "non_execute" ? c.reason !== "prerequis_en_echec" : null, detail: choisir(c.detail) })),
    warnings: r.warnings.map((w) => ({ id: w.id, check: w.check, detail: choisir(w.detail) })),
    status: r.status,
    reason: r.reason,
    summary: choisir(r.summary),
    anchors_used: r.anchors_used,
    facts: r.facts,
    proposition: r.proposition,
  };
}

/** Évaluation bilingue (textes { fr, en }). */
export function evaluerPreuve(octets, { periodHash = null, entetes = null, ancres = null } = {}) {
  const res = {};
  const avertissements = [];
  const ancre = ancres ? ancres.bitcoin ?? null : null;

  // O-1 : format.
  let preuve = null;
  try {
    preuve = lireOts(octets);
    res["O-1"] = reussi(T("en-tête magique, version 01, opération de fichier 08, arbre conforme, fin de fichier exacte", "magic header, version 01, file operation 08, well-formed tree, exact end of file"));
  } catch (err) {
    if (!(err instanceof ErreurOts)) throw err;
    res["O-1"] = echoue(T(`preuve illisible : ${err.message}`, `unreadable proof: ${err.message}`));
  }

  // O-2 : empreinte = periodHash.
  if (res["O-1"].status !== "reussi") res["O-2"] = heriter([["O-1", res["O-1"]]]);
  else if (periodHash === null) res["O-2"] = nonExecute("prerequis_en_echec", T("periodHash non calculable (manifeste.json inexploitable)", "periodHash cannot be computed (manifeste.json unusable)"));
  else if (hex(preuve.empreinte) !== periodHash) res["O-2"] = echoue(T(`empreinte du fichier ${hex(preuve.empreinte)} différente du periodHash recalculé ${periodHash}`, `file digest ${hex(preuve.empreinte)} differs from the recomputed periodHash ${periodHash}`));
  else res["O-2"] = reussi(T(`empreinte du fichier égale au periodHash recalculé ${periodHash}`, `file digest equal to the recomputed periodHash ${periodHash}`));

  // O-3 : opérations.
  let execution = null;
  if (res["O-1"].status !== "reussi") res["O-3"] = heriter([["O-1", res["O-1"]]]);
  else {
    execution = executer(preuve);
    const horsProfil = [...execution.operations].filter((o) => !OPS_PROFIL.has(o)).map((o) => o.toString(16).padStart(2, "0"));
    if (execution.defaut) res["O-3"] = echoue(execution.defaut);
    else {
      const tailles = [...new Set(execution.attestations.filter((a) => a.resultat).map((a) => a.resultat.length))].sort((a, b) => a - b);
      const resultat = tailles.length ? T(` ; résultat${tailles.length > 1 ? "s" : ""} de ${tailles.join(", ")} octets`, `; result${tailles.length > 1 ? "s" : ""} of ${tailles.join(", ")} bytes`) : T("", "");
      res["O-3"] = horsProfil.length
        ? reussi(T(`opérations du profil rejouées ; opérations hors profil non exécutées : ${horsProfil.join(", ")}${resultat.fr}`, `profile operations replayed; out-of-profile operations not run: ${horsProfil.join(", ")}${resultat.en}`))
        : reussi(T(`opérations rejouées, toutes du profil f0, f1, 08${resultat.fr}`, `operations replayed, all in the f0, f1, 08 profile${resultat.en}`));
    }
  }

  // O-7 : attestation Bitcoin présente (avant O-5, qui en dépend).
  const attestations = execution?.attestations ?? (preuve ? executer(preuve).attestations : []);
  const bitcoin = attestations.filter((a) => a.genre === "bitcoin");
  const enAttente = attestations.filter((a) => a.genre === "en_attente");
  const inconnues = attestations.filter((a) => a.genre === "inconnue");
  if (res["O-1"].status !== "reussi") res["O-7"] = heriter([["O-1", res["O-1"]]]);
  else if (bitcoin.length === 0) {
    const a = compte(enAttente.length, "attente");
    const i = compte(inconnues.length, "inconnue");
    res["O-7"] = nonExecute("partie_absente", T(`aucune attestation Bitcoin : ${a.fr}, ${i.fr} ; la preuve n'est pas complétée (ots upgrade)`, `no Bitcoin attestation: ${a.en}, ${i.en}; the proof is not upgraded (ots upgrade)`));
  } else {
    const b = compte(bitcoin.length, "bitcoin");
    const a = compte(enAttente.length, "attente");
    res["O-7"] = reussi(T(`${b.fr}, ${a.fr}`, `${b.en}, ${a.en}`));
  }
  if (preuve) {
    for (const a of enAttente) avertissements.push({ id: "AV-O-2", check: "O-7", detail: T(`attestation en attente du calendrier ${a.uri}, non exploitée`, `pending attestation from calendar ${a.uri}, not used`) });
    for (const a of inconnues) avertissements.push({ id: "AV-O-2", check: "O-7", detail: T(`attestation inconnue d'étiquette ${hex(a.etiquette)}, non exploitée`, `unknown attestation with tag ${hex(a.etiquette)}, not used`) });
    for (const a of bitcoin.filter((x) => x.horsProfil)) avertissements.push({ id: "AV-O-2", check: "O-4", detail: T(`attestation Bitcoin de hauteur ${a.hauteur} sous une opération hors profil, non exploitée`, `Bitcoin attestation at height ${a.hauteur} under an out-of-profile operation, not used`) });
  }

  // O-5 : chaîne d'en-têtes rattachée au point de contrôle.
  let chaine = null;
  let rattachement = null;
  if (res["O-7"].status !== "reussi") res["O-5"] = heriter([["O-7", res["O-7"]]]);
  else if (!entetes) res["O-5"] = nonExecute("partie_absente", T("aucun fichier d'en-têtes Bitcoin fourni (--entetes-bitcoin)", "no Bitcoin headers file given (--entetes-bitcoin)"));
  else if (!ancre) res["O-5"] = nonExecute("ancre_absente", T(ancres ? "le fichier d'ancres ne donne aucune ancre bitcoin" : "aucun fichier d'ancres", ancres ? "the anchors file gives no bitcoin anchor" : "no anchors file"));
  else {
    chaine = preparerEntetes(entetes);
    rattachement = rattacherChaine(chaine, ancre);
    if (rattachement.status === "reussi") {
      const nbits = new Set();
      for (let i = ancre.checkpoint.height + 1; i <= chaine.t; i++) nbits.add(champsEntete(chaine.h(i)).nBits);
      const cibles = [...nbits].map((n) => "0x" + n.toString(16).padStart(8, "0")).join(", ");
      const travail = nbits.size > 0
        ? T(`preuve de travail sous la cible de nBits ${cibles} vérifiée`, `proof of work under the nBits ${cibles} target checked`)
        : T("aucun en-tête au-dessus du point de contrôle, aucune preuve de travail recalculée", "no header above the checkpoint, no proof of work recomputed");
      res["O-5"] = reussi(T(`en-têtes ${chaine.s} à ${chaine.t} du réseau ${ancre.network} rattachés au point de contrôle ${ancre.checkpoint.height} de l'ancre (/bitcoin) ; ${travail.fr}`, `headers ${chaine.s} to ${chaine.t} of network ${ancre.network} connected to checkpoint ${ancre.checkpoint.height} of the anchor (/bitcoin); ${travail.en}`));
    } else res["O-5"] = rattachement.status === "echoue" ? echoue(rattachement.detail) : nonExecute(rattachement.reason, rattachement.detail);
    // AV-O-3 : O-5 exécutée (réussie ou en échec) sur le réseau regtest (table 10.7).
    if (ancre.network === "regtest" && res["O-5"].status !== "non_execute") avertissements.push({ id: "AV-O-3", check: "O-5", detail: T("réseau regtest : réseau d'essai, sans valeur probante hors des tests", "regtest network: a test network, no evidential value outside tests") });
  }

  // O-4 : attestation Bitcoin contre l'en-tête.
  const statutsAttestation = new Map();
  let retenue = null;
  if (res["O-3"].status !== "reussi" || res["O-5"].status !== "reussi") res["O-4"] = heriter([["O-3", res["O-3"]], ["O-5", res["O-5"]]]);
  else {
    const concordantes = [];
    const discordantes = [];
    const raisons = [];
    for (const a of bitcoin) {
      if (a.horsProfil) {
        statutsAttestation.set(a, "non_execute");
        raisons.push("hors_perimetre_version");
      } else if (a.hauteur < chaine.s || a.hauteur > chaine.t) {
        statutsAttestation.set(a, "non_execute");
        raisons.push("ancre_absente");
      } else if (a.resultat && a.resultat.length === 32 && a.resultat.equals(champsEntete(chaine.h(a.hauteur)).racine)) {
        statutsAttestation.set(a, "reussi");
        concordantes.push(a);
      } else {
        statutsAttestation.set(a, "echoue");
        discordantes.push(a);
      }
    }
    if (concordantes.length) {
      retenue = concordantes.reduce((m, a) => (a.hauteur < m.hauteur ? a : m));
      res["O-4"] = reussi(T(`attestation Bitcoin de hauteur ${retenue.hauteur} : résultat égal aux octets 36 à 67 de l'en-tête ${retenue.hauteur}`, `Bitcoin attestation at height ${retenue.hauteur}: result equal to bytes 36 to 67 of header ${retenue.hauteur}`));
      for (const a of discordantes) avertissements.push({ id: "AV-O-1", check: "O-4", detail: T(`attestation Bitcoin de hauteur ${a.hauteur} qui ne concorde pas avec l'en-tête ${a.hauteur}, à côté d'une attestation concordante`, `Bitcoin attestation at height ${a.hauteur} that does not match header ${a.hauteur}, next to a matching attestation`) });
    } else if (discordantes.length) {
      const a = discordantes[0];
      res["O-4"] = echoue(T(`attestation Bitcoin de hauteur ${a.hauteur} : résultat ${a.resultat ? hex(a.resultat) : "absent"} différent des octets 36 à 67 de l'en-tête ${a.hauteur} (${hex(champsEntete(chaine.h(a.hauteur)).racine)})`, `Bitcoin attestation at height ${a.hauteur}: result ${a.resultat ? hex(a.resultat) : "missing"} differs from bytes 36 to 67 of header ${a.hauteur} (${hex(champsEntete(chaine.h(a.hauteur)).racine)})`));
    } else {
      const r = RAISONS_ORDRE.find((x) => raisons.includes(x));
      res["O-4"] = nonExecute(r, r === "hors_perimetre_version" ? T("attestations Bitcoin toutes sous une opération hors profil", "Bitcoin attestations all under an out-of-profile operation") : T(`aucune attestation Bitcoin dans les en-têtes ${chaine.s} à ${chaine.t} fournis`, `no Bitcoin attestation within the given headers ${chaine.s} to ${chaine.t}`));
    }
  }

  // O-6 : profondeur.
  if (res["O-4"].status !== "reussi") res["O-6"] = heriter([["O-4", res["O-4"]]]);
  else {
    const k = chaine.t - retenue.hauteur + 1;
    if (k >= ancre.min_confirmations) res["O-6"] = reussi(T(`profondeur k = ${k}, au moins min_confirmations = ${ancre.min_confirmations}`, `depth k = ${k}, at least min_confirmations = ${ancre.min_confirmations}`));
    else res["O-6"] = nonExecute("ancre_absente", T(`profondeur k = ${k}, inférieure à min_confirmations = ${ancre.min_confirmations} : la chaîne fournie ne porte pas assez de blocs`, `depth k = ${k}, below min_confirmations = ${ancre.min_confirmations}: the given chain does not carry enough blocks`));
  }

  // Statut du contrôle 5 (EX-10.12). O-2 est exigée réussie en plus de O-4,
  // O-6 et O-7 : sans elle (periodHash non calculable), rien ne relie la preuve
  // au manifeste, et aucun contrôle n'est réussi sans ses vérifications (V-6).
  let status;
  let reason = null;
  if (["O-1", "O-2", "O-3", "O-4", "O-5"].some((id) => res[id].status === "echoue")) status = "echoue";
  else if (["O-2", "O-4", "O-6", "O-7"].every((id) => res[id].status === "reussi")) status = "reussi";
  else {
    status = "non_execute";
    reason = RAISONS_ORDRE.find((x) => IDS.some((id) => res[id].status === "non_execute" && res[id].reason === x));
  }

  let facts = null;
  let proposition = null;
  let summary;
  const anchors_used = res["O-5"].status === "reussi" || res["O-5"].status === "echoue" ? ["/bitcoin"] : [];
  if (status === "reussi") {
    const h = retenue.hauteur;
    const c = ancre.checkpoint.height;
    const k = chaine.t - h + 1;
    let cumul = 0n;
    for (let i = Math.max(h, c + 1); i <= chaine.t; i++) cumul += travail(rattachement.cibles.get(i));
    const median = chaine.t >= h + MEDIANE ? instantUnix(medianeTemps(chaine, h + 1, h + MEDIANE)) : null;
    facts = {
      file_digest: hex(preuve.empreinte),
      network: ancre.network,
      checkpoint: { height: c, hash: ancre.checkpoint.hash },
      attestations: attestations.map((a) => ({
        kind: a.genre,
        height: a.genre === "bitcoin" ? a.hauteur : null,
        uri: a.genre === "en_attente" ? a.uri : null,
        tag: a.genre === "inconnue" ? hex(a.etiquette) : null,
        status: statutsAttestation.get(a) ?? "non_execute",
      })),
      retained_height: h,
      block_hash: hachageAffiche(chaine.h(h)),
      block_time: instantUnix(champsEntete(chaine.h(h)).nTime),
      median_bound: median,
      confirmations: k,
      cumulative_work: cumul.toString(),
    };
    proposition = propositionEnonce(facts, periodHash);
    const essai = ancre.network === "regtest" ? T(" (réseau d'essai)", " (test network)") : T("", "");
    summary = T(`bloc Bitcoin ${h} du réseau ${ancre.network}, ${k} confirmations${essai.fr}`, `Bitcoin block ${h} on network ${ancre.network}, ${k} confirmations${essai.en}`);
  } else if (status === "echoue") {
    const ids = IDS.filter((id) => res[id].status === "echoue");
    summary = T(`vérification(s) en échec : ${ids.join(", ")}`, `failed check(s): ${ids.join(", ")}`);
  } else {
    // Le résumé reprend la cause première : une non-exécution qui n'est pas héritée d'un prérequis.
    const premier = IDS.find((id) => res[id].status === "non_execute" && res[id].reason === reason && !/^prérequis /.test(res[id].detail.fr)) ?? IDS.find((id) => res[id].status === "non_execute" && res[id].reason === reason);
    summary = res[premier].detail;
  }

  return { checks: IDS.map((id) => ({ id, ...res[id] })), warnings: ordonnerAvertissements(avertissements), status, reason, summary, anchors_used, facts, proposition };
}

/** Proposition française et anglaise que le contrôle 5 réussi fournit à l'énoncé (EX-10.15). */
export function propositionEnonce(f, periodHash) {
  let fr = `le manifeste d'empreinte ${periodHash} existait avant la création du bloc Bitcoin ${f.retained_height} (${f.block_hash}, réseau ${f.network}), sous ${f.confirmations} blocs dont le travail se rattache au point de contrôle ${f.checkpoint.height} du réviseur ; heure inscrite par le mineur : ${f.block_time} UTC, précision non garantie par le protocole`;
  let en = `the manifest with digest ${periodHash} existed before Bitcoin block ${f.retained_height} (${f.block_hash}, ${f.network} network) was created, under ${f.confirmations} blocks whose work connects to the reviewer's checkpoint ${f.checkpoint.height}; time written by the miner: ${f.block_time} UTC, accuracy not guaranteed by the protocol`;
  if (f.median_bound) {
    fr += ` ; borne sous hypothèse : ${f.median_bound} UTC`;
    en += `; bound under assumption: ${f.median_bound} UTC`;
  }
  if (f.network === "regtest") {
    fr += " (réseau d'essai, sans valeur probante)";
    en += " (test network, no evidential value)";
  }
  return { fr, en };
}
