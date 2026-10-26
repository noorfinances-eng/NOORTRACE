// Contrôle 8 du vérificateur (spec/CT-6-verificateur.md, section 11) :
// inclusion des transactions du registre dans des blocs certifiés par un
// quorum du jeu de validateurs que le RÉVISEUR déclare dans son fichier
// d'ancres. Implémentation de référence JavaScript des vérifications R-1 à
// R-10 et N-4 ; scripts/verify/dossier.mjs l'appelle, le binaire Go de la
// phase 2 doit rendre les mêmes statuts.
//
// Rien n'est cru du dossier ni du nœud qui l'a servi ; tout se recalcule :
//
//   BFTBlockHash = keccak256("noor/v1/bftblockhash" ‖ parentHash ‖ u64be(number)
//                  ‖ u64be(timestamp) ‖ stateRoot ‖ transactionsRoot ‖ receiptsRoot
//                  ‖ u64be(gasUsed) ‖ u64be(gasLimit) ‖ baseFeePerGas sur 32 octets)
//                  (EX-11.4 : ce n'est PAS keccak256(RLP(en-tête)) d'Ethereum) ;
//   receiptsRoot = racine du trie Merkle-Patricia {RLP(i) -> encodage de
//                  consensus du reçu i}, bloom recalculé (EX-11.5) ;
//   certificat   = proposition et precommits relus octet par octet et vérifiés
//                  contre le jeu de l'ANCRE (scripts/lib/certificat-commit.mjs) ;
//   journaux     = PeriodSubmitted, Anchored, RecorderRegistered décodés mot par
//                  mot et comparés au manifeste recalculé (EX-11.9, EX-11.18,
//                  EX-11.19).
//
// Le trie est une implémentation minimale et bornée (au plus 256 reçus par
// bloc, clés de 1 à 3 octets) : construction récursive sur les couples
// triés, profondeur bornée par la longueur des clés. Les vecteurs de
// spec/vecteurs/ct-6/registre la confrontent à go-ethereum (types.DeriveSha).
//
// Ce module ne touche ni au réseau ni au système de fichiers. Il ne dépend que
// de node:crypto (par certificat-commit.mjs), d'ethers (keccak256) et des
// fonctions de validation de schéma de scripts/lib/journal.mjs.

import { keccak256 } from "ethers";
import { chargerJeuValidateurs, hachageJeuValidateurs, verifierCertificat } from "./certificat-commit.mjs";
import { analyserJSONStrict, validerSchema } from "./journal.mjs";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

export const ID_SCHEMA_REGISTRE = "https://noortrace.example/schemas/v0/registre.schema.json";
export const ID_SCHEMA_VALIDATEURS = "https://noortrace.example/schemas/v0/validateurs.schema.json";

/** Préfixe de la préimage de BFTBlockHash (core/node/blockexec.go de noorcore). */
export const DOMAINE_BLOC_BFT = "noor/v1/bftblockhash";

/** Signatures des événements prouvés (contracts/*.sol) ; l'ancre d'un point de contrôle du journal (révision 0.2, EX-11.23) est le même événement Anchored. */
export const SIGNATURES_EVENEMENTS = {
  cloture: "PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)",
  ancre: "Anchored(bytes32,address,bytes32)",
  inscription: "RecorderRegistered(bytes32,address,bytes32,bytes32,address)",
  ancre_point_de_controle: "Anchored(bytes32,address,bytes32)",
};

/** topics[0] de chaque rôle : keccak256 de la signature de l'événement (EX-11.9). */
export const SUJETS_EVENEMENTS = {
  cloture: "0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba",
  ancre: "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e",
  inscription: "0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec",
  ancre_point_de_controle: "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e",
};

/** Nom de l'événement de chaque rôle. */
export const NOMS_EVENEMENTS = { cloture: "PeriodSubmitted", ancre: "Anchored", inscription: "RecorderRegistered", ancre_point_de_controle: "Anchored" };

/** Clé du contrat de chaque rôle dans l'ancre `registry.contracts`. */
export const CONTRAT_DU_ROLE = { cloture: "period_registry", ancre: "attestation_registry", inscription: "recorder_registry", ancre_point_de_controle: "attestation_registry" };

/** Nom du contrat de chaque rôle, pour les détails et l'énoncé. */
export const NOM_CONTRAT_DU_ROLE = { cloture: "PeriodRegistry", ancre: "AttestationRegistry", inscription: "RecorderRegistry", ancre_point_de_controle: "AttestationRegistry" };

/** keccak256(UTF-8("noortrace/periode/v0")) : docType des ancres de période (DOC_TYPE_PERIODE). */
export const DOC_TYPE_PERIODE = "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee";

/** keccak256(UTF-8("noortrace/point-de-controle/v0")) : docType des ancres d'un point de contrôle du journal (CT-1 §10.6, CT-6 §11.9). */
export const DOC_TYPE_POINT_DE_CONTROLE = "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178";

/** Rôle de l'entrée de registre.json qui porte l'ancre d'un point de contrôle du journal (révision 0.2). */
export const ROLE_ANCRE_POINT = "ancre_point_de_controle";

/** Limites de lecture (EX-4.13) et de structure (EX-15.1). */
export const LIMITES = {
  registre: 64 * 1024 * 1024,
  certificat_commit: 64 * 1024 * 1024,
  validateurs: 1024 * 1024,
  profondeurJSON: 128,
};

/** Fichier de chaque partie du contrôle 8 (CT-1 §11.1). */
export const FICHIERS_PARTIES = { registre: "registre.json", certificat_commit: "certificat-commit.json", validateurs: "validateurs.json" };

/** Raison exacte d'une partie absente d'un dossier produit pour CT-1. */
export const RAISON_HORS_PERIMETRE_CT1 = "hors périmètre CT-1";

/** Ordre des raisons d'un statut non exécuté (EX-6.5). */
const ORDRE_RAISONS = ["prerequis_en_echec", "hors_perimetre_version", "partie_absente", "ancre_absente", "piece_hors_dossier"];
const RAISONS_ADMISES = new Set(["partie_absente", "ancre_absente", "hors_perimetre_version", "piece_hors_dossier"]);

// ---------------------------------------------------------------------------
// Octets, entiers, RLP
// ---------------------------------------------------------------------------

/** Octets d'une chaîne hexadécimale 0x… (longueur paire). */
export function octetsHex(h) {
  if (typeof h !== "string" || !/^0x([0-9a-fA-F]{2})*$/.test(h)) throw new Error(`hexadécimal 0x… attendu : ${String(h).slice(0, 80)}`);
  return Buffer.from(h.slice(2), "hex");
}

function hexDe(octets) {
  return "0x" + Buffer.from(octets).toString("hex");
}

/** keccak256 (Keccak d'origine, celui de l'EVM) d'octets, en Buffer de 32 octets. */
export function keccak(octets) {
  return Buffer.from(keccak256(octets).slice(2), "hex");
}

/** Entier d'une quantité JSON-RPC 0x… en BigInt. */
export function quantite(q) {
  if (typeof q !== "string" || !/^0x[0-9a-fA-F]+$/.test(q)) throw new Error(`quantité 0x… attendue : ${String(q).slice(0, 80)}`);
  return BigInt(q);
}

/** Octets grand-boutistes minimaux d'un entier positif ou nul (zéro : aucun octet). */
export function octetsEntier(n) {
  const v = BigInt(n);
  if (v < 0n) throw new Error("entier négatif");
  if (v === 0n) return Buffer.alloc(0);
  let h = v.toString(16);
  if (h.length % 2) h = "0" + h;
  return Buffer.from(h, "hex");
}

/** Entier grand-boutiste sur `largeur` octets, complété à gauche par des zéros. */
export function entierLargeurFixe(n, largeur) {
  const b = octetsEntier(n);
  if (b.length > largeur) throw new Error(`entier de plus de ${largeur} octets`);
  return Buffer.concat([Buffer.alloc(largeur - b.length), b]);
}

function enteteRLP(longueur, base) {
  if (longueur <= 55) return Buffer.from([base + longueur]);
  const L = octetsEntier(longueur);
  return Buffer.concat([Buffer.from([base + 55 + L.length]), L]);
}

/**
 * Encodage RLP (EX-11.5, règle 1) : un Buffer (ou Uint8Array) est une chaîne
 * d'octets, un tableau une liste, un objet {brut} un élément déjà encodé
 * (nœud de trie de moins de 32 octets inséré tel quel dans son parent).
 */
export function rlp(element) {
  if (element instanceof Uint8Array) {
    const b = Buffer.from(element);
    if (b.length === 1 && b[0] < 0x80) return b;
    return Buffer.concat([enteteRLP(b.length, 0x80), b]);
  }
  if (Array.isArray(element)) {
    const charge = Buffer.concat(element.map(rlp));
    return Buffer.concat([enteteRLP(charge.length, 0xc0), charge]);
  }
  if (element && element.brut instanceof Uint8Array) return Buffer.from(element.brut);
  throw new Error("rlp : octets, liste ou {brut} attendus");
}

// ---------------------------------------------------------------------------
// Hachage du bloc (EX-11.4)
// ---------------------------------------------------------------------------

function hex32(valeur, nom) {
  const b = octetsHex(valeur);
  if (b.length !== 32) throw new Error(`${nom} : 32 octets attendus`);
  return b;
}

/** Préimage de 212 octets de BFTBlockHash, depuis les champs de l'en-tête de registre.json. */
export function preimageBloc(bloc) {
  return Buffer.concat([
    Buffer.from(DOMAINE_BLOC_BFT, "ascii"),
    hex32(bloc.parentHash, "parentHash"),
    entierLargeurFixe(quantite(bloc.number), 8),
    entierLargeurFixe(quantite(bloc.timestamp), 8),
    hex32(bloc.stateRoot, "stateRoot"),
    hex32(bloc.transactionsRoot, "transactionsRoot"),
    hex32(bloc.receiptsRoot, "receiptsRoot"),
    entierLargeurFixe(quantite(bloc.gasUsed), 8),
    entierLargeurFixe(quantite(bloc.gasLimit), 8),
    entierLargeurFixe(quantite(bloc.baseFeePerGas), 32),
  ]);
}

/** BFTBlockHash d'un en-tête (0x…). */
export function hachageBlocBFT(bloc) {
  return hexDe(keccak(preimageBloc(bloc)));
}

// ---------------------------------------------------------------------------
// Reçus et racine des reçus (EX-11.5)
// ---------------------------------------------------------------------------

/** Bloom de 256 octets d'un reçu, recalculé depuis ses journaux (règle 2). */
export function bloomRecu(journaux) {
  const bloom = Buffer.alloc(256);
  const ajouter = (donnee) => {
    const h = keccak(donnee);
    for (const k of [0, 2, 4]) {
      const n = ((h[k] << 8) | h[k + 1]) & 0x7ff;
      bloom[255 - (n >> 3)] |= 1 << (n & 7);
    }
  };
  for (const j of journaux) {
    ajouter(octetsHex(j.address));
    for (const t of j.topics) ajouter(octetsHex(t));
  }
  return bloom;
}

/** Encodage de consensus d'un reçu {type, status, cumulativeGasUsed, logs} (règle 3). */
export function encodageRecu(recu) {
  const type = Number(quantite(recu.type));
  if (!Number.isInteger(type) || type < 0 || type > 4) throw new Error(`type de reçu ${recu.type} hors de 0 à 4`);
  const statut = quantite(recu.status);
  if (statut > 1n) throw new Error(`status ${recu.status} hors de {0x0, 0x1}`);
  const journaux = recu.logs.map((j) => {
    const adresse = octetsHex(j.address);
    if (adresse.length !== 20) throw new Error("adresse de journal de 20 octets attendue");
    return [adresse, j.topics.map((t) => hex32(t, "sujet")), octetsHex(j.data)];
  });
  const corps = rlp([statut === 1n ? Buffer.from([1]) : Buffer.alloc(0), octetsEntier(quantite(recu.cumulativeGasUsed)), bloomRecu(recu.logs), journaux]);
  return type === 0 ? corps : Buffer.concat([Buffer.from([type]), corps]);
}

function quartets(octets) {
  const out = new Array(octets.length * 2);
  for (let i = 0; i < octets.length; i++) {
    out[2 * i] = octets[i] >> 4;
    out[2 * i + 1] = octets[i] & 15;
  }
  return out;
}

/** Codage hex-prefix d'une suite de quartets (règle 4). */
export function hexPrefix(q, feuille) {
  const f = feuille ? 2 : 0;
  const octets = [];
  let reste;
  if (q.length % 2 === 1) {
    octets.push(((f + 1) << 4) | q[0]);
    reste = q.slice(1);
  } else {
    octets.push(f << 4);
    reste = q;
  }
  for (let i = 0; i < reste.length; i += 2) octets.push((reste[i] << 4) | reste[i + 1]);
  return Buffer.from(octets);
}

/** Référence d'un nœud dans son parent : le nœud encodé s'il fait moins de 32 octets, sinon son keccak256. */
function reference(noeud) {
  const enc = rlp(noeud);
  return enc.length < 32 ? { brut: enc } : keccak(enc);
}

/** Nœud du trie pour des couples {q (quartets), v (Buffer)} de clés distinctes, non vide. */
function noeudTrie(couples) {
  if (couples.length === 1) return [hexPrefix(couples[0].q, true), couples[0].v];
  let p = 0;
  for (;;) {
    const c = couples[0].q[p];
    if (c === undefined || couples.some((x) => x.q[p] !== c)) break;
    p++;
  }
  if (p > 0) {
    return [hexPrefix(couples[0].q.slice(0, p), false), reference(noeudTrie(couples.map((x) => ({ q: x.q.slice(p), v: x.v }))))];
  }
  const branche = new Array(17).fill(Buffer.alloc(0));
  for (let d = 0; d < 16; d++) {
    const sous = couples.filter((x) => x.q.length > 0 && x.q[0] === d).map((x) => ({ q: x.q.slice(1), v: x.v }));
    if (sous.length) branche[d] = reference(noeudTrie(sous));
  }
  const vide = couples.find((x) => x.q.length === 0);
  if (vide) branche[16] = vide.v;
  return branche;
}

/** Racine (32 octets) d'un trie Merkle-Patricia de couples {cle, valeur} (Buffers), clés distinctes. */
export function racineTrie(couples) {
  if (couples.length === 0) return keccak(Buffer.from([0x80]));
  const vues = new Set();
  for (const c of couples) {
    const k = Buffer.from(c.cle).toString("hex");
    if (vues.has(k)) throw new Error("clé de trie en double");
    vues.add(k);
  }
  return keccak(rlp(noeudTrie(couples.map((c) => ({ q: quartets(Buffer.from(c.cle)), v: Buffer.from(c.valeur) })))));
}

/** receiptsRoot recalculé (0x…) d'une liste de reçus, dans l'ordre des transactions. */
export function racineRecus(recus) {
  return hexDe(racineTrie(recus.map((r, i) => ({ cle: rlp(octetsEntier(i)), valeur: encodageRecu(r) }))));
}

// ---------------------------------------------------------------------------
// Journaux d'événements (EX-11.9)
// ---------------------------------------------------------------------------

const ZERO12 = Buffer.alloc(12);

/** Mot de 32 octets lu comme adresse : 12 octets de tête nuls exigés. */
function motAdresse(mot) {
  return mot.subarray(0, 12).equals(ZERO12) ? hexDe(mot.subarray(12)) : null;
}

/** Mot de 32 octets lu comme entier non signé de `bits` bits : octets de tête nuls exigés. */
function motEntier(mot, bits) {
  const tete = 32 - bits / 8;
  if (!mot.subarray(0, tete).equals(Buffer.alloc(tete))) return null;
  return BigInt(hexDe(mot));
}

function nombreSortie(n) {
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString();
}

/**
 * Décode le journal prouvé d'une entrée selon son rôle et contrôle sa forme
 * (nombre de sujets, topics[0], disposition des données, octets de tête nuls).
 * Rend {erreurs: [..], valeurs} ; `valeurs` est l'objet `event` des faits
 * (EX-11.21), `null` quand la forme est fautive.
 */
export function decoderJournal(role, journal, langue = "fr") {
  const L = traducteur(langue);
  const erreurs = [];
  const sujets = journal.topics.map((t) => octetsHex(t));
  const donnees = octetsHex(journal.data);
  const nbSujets = { cloture: 4, ancre: 3, inscription: 4, ancre_point_de_controle: 3 }[role];
  if (sujets.length !== nbSujets) erreurs.push(L(`${sujets.length} sujet(s) au lieu de ${nbSujets}`, `${sujets.length} topic(s) instead of ${nbSujets}`));
  else if (hexDe(sujets[0]) !== SUJETS_EVENEMENTS[role]) erreurs.push(L(`topics[0] ${hexDe(sujets[0])} n'est pas celui de ${NOMS_EVENEMENTS[role]}`, `topics[0] ${hexDe(sujets[0])} is not that of ${NOMS_EVENEMENTS[role]}`));
  if (erreurs.length) return { erreurs, valeurs: null };

  if (role === "ancre" || role === ROLE_ANCRE_POINT) {
    const issuer = motAdresse(sujets[2]);
    if (issuer === null) erreurs.push(L("topics[2] (émetteur) : octets de tête non nuls", "topics[2] (issuer): non-zero leading bytes"));
    if (donnees.length !== 32) erreurs.push(L(`data de ${donnees.length} octets au lieu de 32`, `data of ${donnees.length} bytes instead of 32`));
    if (erreurs.length) return { erreurs, valeurs: null };
    return { erreurs, valeurs: { name: "Anchored", fingerprint: hexDe(sujets[1]), issuer, docType: hexDe(donnees) } };
  }
  if (role === "inscription") {
    const chainKey = motAdresse(sujets[2]);
    if (chainKey === null) erreurs.push(L("topics[2] (clé de chaîne) : octets de tête non nuls", "topics[2] (chain key): non-zero leading bytes"));
    if (donnees.length !== 64) erreurs.push(L(`data de ${donnees.length} octets au lieu de 64`, `data of ${donnees.length} bytes instead of 64`));
    const publisher = donnees.length === 64 ? motAdresse(donnees.subarray(32, 64)) : null;
    if (donnees.length === 64 && publisher === null) erreurs.push(L("relayeur : octets de tête non nuls", "relayer: non-zero leading bytes"));
    if (erreurs.length) return { erreurs, valeurs: null };
    return {
      erreurs,
      valeurs: { name: "RecorderRegistered", orgId: hexDe(sujets[1]), chainKey, journalId: hexDe(sujets[3]), ed25519PubKey: hexDe(donnees.subarray(0, 32)), publisher },
    };
  }
  // cloture : PeriodSubmitted
  const publisher = motAdresse(sujets[3]);
  if (publisher === null) erreurs.push(L("topics[3] (relayeur) : octets de tête non nuls", "topics[3] (relayer): non-zero leading bytes"));
  if (donnees.length < 352 || donnees.length % 32 !== 0) {
    erreurs.push(L(`data de ${donnees.length} octets : au moins 352 et un multiple de 32 attendus`, `data of ${donnees.length} bytes: at least 352 and a multiple of 32 expected`));
    return { erreurs, valeurs: null };
  }
  const mot = (i) => donnees.subarray(32 * i, 32 * i + 32);
  const champs64 = { periodStart: 3, periodEnd: 4, firstSeq: 5, lastSeq: 6, publishedAt: 9 };
  const entiers = {};
  for (const [nom, i] of Object.entries(champs64)) {
    entiers[nom] = motEntier(mot(i), 64);
    if (entiers[nom] === null) erreurs.push(L(`w${i} (${nom}) : uint64 attendu`, `w${i} (${nom}): uint64 expected`));
  }
  const version = motEntier(mot(7), 32);
  if (version === null) erreurs.push(L("w7 (version) : uint32 attendu", "w7 (version): uint32 expected"));
  if (BigInt(hexDe(mot(8))) !== 0x140n) erreurs.push(L(`w8 (position de uri) ${hexDe(mot(8))} au lieu de 0x140`, `w8 (offset of uri) ${hexDe(mot(8))} instead of 0x140`));
  const longueurUri = BigInt(hexDe(mot(10)));
  const attendu = 352n + ((longueurUri + 31n) / 32n) * 32n;
  if (BigInt(donnees.length) !== attendu) erreurs.push(L(`data de ${donnees.length} octets pour un uri de ${longueurUri} octets (${attendu} attendus)`, `data of ${donnees.length} bytes for a uri of ${longueurUri} bytes (${attendu} expected)`));
  if (erreurs.length) return { erreurs, valeurs: null };
  const lg = Number(longueurUri);
  const uriOctets = donnees.subarray(352, 352 + lg);
  if (!donnees.subarray(352 + lg).equals(Buffer.alloc(donnees.length - 352 - lg))) {
    erreurs.push(L("octets de remplissage de uri non nuls", "non-zero padding bytes after uri"));
    return { erreurs, valeurs: null };
  }
  let uri;
  try {
    uri = new TextDecoder("utf-8", { fatal: true }).decode(uriOctets);
  } catch {
    uri = hexDe(uriOctets);
  }
  return {
    erreurs,
    valeurs: {
      name: "PeriodSubmitted",
      id: nombreSortie(BigInt(hexDe(sujets[1]))),
      periodHash: hexDe(sujets[2]),
      orgId: hexDe(mot(0)),
      journalId: hexDe(mot(1)),
      root: hexDe(mot(2)),
      periodStart: nombreSortie(entiers.periodStart),
      periodEnd: nombreSortie(entiers.periodEnd),
      firstSeq: nombreSortie(entiers.firstSeq),
      lastSeq: nombreSortie(entiers.lastSeq),
      version: Number(version),
      publisher,
      uri,
      publishedAt: nombreSortie(entiers.publishedAt),
    },
  };
}

/** Empreinte de l'ancre : keccak256(org_id ‖ journal_id ‖ periodHash), préimage de 96 octets (CT-1 §10.4). */
export function empreinteAncre(orgId, journalId, periodHash) {
  return hexDe(keccak(Buffer.concat([hex32(orgId, "org_id"), hex32(journalId, "journal_id"), hex32(periodHash, "periodHash")])));
}

// ---------------------------------------------------------------------------
// Instants
// ---------------------------------------------------------------------------

/** Instant RFC 3339 UTC « AAAA-MM-JJThh:mm:ssZ » de secondes UNIX (BigInt ou nombre), sans fraction (EX-6.11). */
export function instantRFC3339(secondes) {
  const s = BigInt(secondes);
  const jours = s / 86400n;
  const reste = s % 86400n;
  // Algorithme « civil_from_days » (H. Hinnant), en BigInt : vaut pour tout u64.
  const z = jours + 719468n;
  const ere = z / 146097n;
  const jde = z - ere * 146097n;
  const ade = (jde - jde / 1460n + jde / 36524n - jde / 146096n) / 365n;
  let annee = ade + ere * 400n;
  const jda = jde - (365n * ade + ade / 4n - ade / 100n);
  const mp = (5n * jda + 2n) / 153n;
  const jour = jda - (153n * mp + 2n) / 5n + 1n;
  const mois = mp < 10n ? mp + 3n : mp - 9n;
  if (mois <= 2n) annee += 1n;
  const d2 = (n) => n.toString().padStart(2, "0");
  return `${annee.toString().padStart(4, "0")}-${d2(mois)}-${d2(jour)}T${d2(reste / 3600n)}:${d2((reste % 3600n) / 60n)}:${d2(reste % 60n)}Z`;
}

// ---------------------------------------------------------------------------
// Lecture des parties
// ---------------------------------------------------------------------------

function traducteur(langue) {
  return (fr, en) => (langue === "en" ? en : fr);
}

/** Profondeur d'imbrication maximale d'un texte JSON (tableaux et objets), chaînes ignorées. */
export function profondeurJSON(texte) {
  let p = 0;
  let max = 0;
  let dansChaine = false;
  for (let i = 0; i < texte.length; i++) {
    const c = texte.charCodeAt(i);
    if (dansChaine) {
      if (c === 0x5c) i++;
      else if (c === 0x22) dansChaine = false;
      continue;
    }
    if (c === 0x22) dansChaine = true;
    else if (c === 0x7b || c === 0x5b) {
      p++;
      if (p > max) max = p;
    } else if (c === 0x7d || c === 0x5d) p--;
  }
  return max;
}

/**
 * Lit une partie JSON du contrôle 8 : octets présents, taille dans la limite,
 * profondeur d'imbrication au plus 128, JSON strict (aucune clé en double,
 * entiers sûrs), conformité au schéma. Rend {valeur} ou {erreur} (texte).
 */
export function lirePartie(partie, nom, { schemas, idSchema, fragment = "", limite, langue = "fr" }) {
  const L = traducteur(langue);
  const fichier = FICHIERS_PARTIES[nom];
  if (!partie.octets) return { erreur: L(`${fichier} déclaré présent mais absent du répertoire`, `${fichier} declared present but missing from the directory`) };
  if (partie.tropGrand || partie.octets.length > limite) return { erreur: L(`${fichier} dépasse la limite de ${limite} octets`, `${fichier} exceeds the limit of ${limite} bytes`) };
  let texte;
  try {
    texte = new TextDecoder("utf-8", { fatal: true }).decode(partie.octets);
  } catch {
    return { erreur: L(`${fichier} : octets UTF-8 invalides`, `${fichier}: invalid UTF-8 bytes`) };
  }
  if (profondeurJSON(texte) > LIMITES.profondeurJSON) return { erreur: L(`${fichier} : imbrication JSON de plus de ${LIMITES.profondeurJSON} niveaux`, `${fichier}: JSON nesting deeper than ${LIMITES.profondeurJSON} levels`) };
  let valeur;
  try {
    valeur = analyserJSONStrict(partie.octets);
  } catch (err) {
    return { erreur: L(`${fichier} n'est pas du JSON exploitable : ${err.message}`, `${fichier} is not usable JSON: ${err.message}`) };
  }
  const schema = schemas?.[idSchema];
  if (!schema) return { erreur: L(`schéma ${idSchema} non fourni`, `schema ${idSchema} not provided`) };
  const erreurs = validerSchema(valeur, schema, { registre: schemas, fragment });
  if (erreurs.length) {
    const vues = erreurs.slice(0, 4).map((e) => `${e.chemin} : ${e.message}`).join(" ; ");
    return { erreur: L(`${fichier} non conforme au schéma : ${vues}${erreurs.length > 4 ? ` ; … (${erreurs.length} erreurs)` : ""}`, `${fichier} does not conform to its schema: ${vues}${erreurs.length > 4 ? ` ; … (${erreurs.length} errors)` : ""}`) };
  }
  return { valeur };
}

/**
 * Contraintes de registre-v0.schema.json que le validateur de
 * scripts/lib/journal.mjs n'interprète pas (contains, minContains,
 * maxContains) : exactement une entrée `cloture`, exactement une `ancre`,
 * au plus 8 `inscription`. Rend la liste des écarts.
 */
export function ecartsRoles(registre, langue = "fr") {
  const L = traducteur(langue);
  const compte = { cloture: 0, ancre: 0, inscription: 0, ancre_point_de_controle: 0 };
  for (const e of registre.entries) compte[e.role]++;
  const ecarts = [];
  if (compte.cloture !== 1) ecarts.push(L(`${compte.cloture} entrée(s) cloture au lieu d'une`, `${compte.cloture} cloture entr(y/ies) instead of one`));
  if (compte.ancre !== 1) ecarts.push(L(`${compte.ancre} entrée(s) ancre au lieu d'une`, `${compte.ancre} ancre entr(y/ies) instead of one`));
  if (compte.inscription > 8) ecarts.push(L(`${compte.inscription} entrées inscription, au plus 8`, `${compte.inscription} inscription entries, at most 8`));
  if (compte.ancre_point_de_controle > 1) ecarts.push(L(`${compte.ancre_point_de_controle} entrées ancre_point_de_controle, au plus une`, `${compte.ancre_point_de_controle} ancre_point_de_controle entries, at most one`));
  return ecarts;
}

// ---------------------------------------------------------------------------
// Ancre `registry` : cohérence (partie de N-1) et jeu valable à une hauteur
// ---------------------------------------------------------------------------

/**
 * Cohérence de l'ancre `registry` au-delà de son schéma (EX-12.2) : chaque jeu
 * se charge comme le nœud le charge, from_height ≤ to_height, intervalles
 * disjoints. Rend la liste des défauts (vide si cohérente). Sert à N-1.
 */
export function defautsAncreRegistre(registry) {
  if (!registry) return [];
  const defauts = [];
  const intervalles = [];
  registry.validator_sets.forEach((jeu, i) => {
    try {
      chargerJeuValidateurs({ validators: jeu.validators });
    } catch (err) {
      defauts.push(`/registry/validator_sets/${i} : ${err.message}`);
    }
    const de = BigInt(jeu.from_height);
    const a = jeu.to_height === null ? null : BigInt(jeu.to_height);
    if (a !== null && de > a) defauts.push(`/registry/validator_sets/${i} : from_height ${de} > to_height ${a}`);
    intervalles.push({ i, de, a });
  });
  for (let x = 0; x < intervalles.length; x++) {
    for (let y = x + 1; y < intervalles.length; y++) {
      const p = intervalles[x];
      const q = intervalles[y];
      const finP = p.a ?? (1n << 64n);
      const finQ = q.a ?? (1n << 64n);
      if (p.de <= finQ && q.de <= finP) defauts.push(`/registry/validator_sets/${p.i} et /registry/validator_sets/${q.i} : intervalles de hauteurs qui se recouvrent`);
    }
  }
  return defauts;
}

/** Jeu de l'ancre valable à la hauteur h (BigInt) : {indice, jeu} ou null. */
export function jeuAncrePourHauteur(registry, h) {
  if (!registry) return null;
  for (const [indice, jeu] of registry.validator_sets.entries()) {
    const de = BigInt(jeu.from_height);
    const a = jeu.to_height === null ? null : BigInt(jeu.to_height);
    if (h >= de && (a === null || h <= a)) return { indice, jeu };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Statuts
// ---------------------------------------------------------------------------

function premiereRaison(raisons) {
  for (const r of ORDRE_RAISONS) if (raisons.includes(r)) return r;
  return raisons[0] ?? null;
}

/** Statut agrégé d'une vérification à plusieurs portées (section 11.4). */
function agreger(items) {
  if (items.some((x) => x.statut === "echoue")) return { statut: "echoue", raison: null };
  const non = items.filter((x) => x.statut === "non_execute");
  if (non.length) return { statut: "non_execute", raison: premiereRaison(non.map((x) => x.raison)) };
  return { statut: "reussi", raison: null };
}

function verification(id, statut, raison, detail) {
  return {
    id,
    controls: [8],
    status: statut,
    reason: statut === "non_execute" ? raison : null,
    admitted: statut === "non_execute" ? RAISONS_ADMISES.has(raison) : null,
    detail: detail ?? null,
  };
}

/** Joint une liste en français (« a, b et c ») ou en anglais (« a, b and c »). */
function joindre(liste, langue) {
  if (liste.length <= 1) return liste.join("");
  const et = langue === "en" ? " and " : " et ";
  return liste.slice(0, -1).join(", ") + et + liste[liste.length - 1];
}

/**
 * Les trois parties du contrôle 8 lues dans un dossier : `index` est l'objet
 * de dossier.json, `fichiers` la table nom de fichier -> octets du répertoire
 * (comme verifierDossier de scripts/lib/journal.mjs la reçoit). Rend l'objet
 * `parties` de verifierControle8.
 */
export function partiesDuDossier(index, fichiers) {
  const out = {};
  for (const nom of ["registre", "certificat_commit", "validateurs"]) {
    const p = Array.isArray(index?.parts) ? index.parts.find((x) => x?.name === nom) : undefined;
    if (!p) out[nom] = { present: false, raison: null };
    else if (p.present === true) out[nom] = { present: true, octets: fichiers?.[p.file] ?? null };
    else out[nom] = { present: false, raison: p.reason_if_absent ?? null };
  }
  return out;
}

/** Raison d'un contrôle dont une partie requise est absente (EX-4.3). */
export function raisonPartieAbsente(raisonDeclaree) {
  return raisonDeclaree === RAISON_HORS_PERIMETRE_CT1 ? "hors_perimetre_version" : "partie_absente";
}

// ---------------------------------------------------------------------------
// Contrôle 8
// ---------------------------------------------------------------------------

/**
 * Exécute le contrôle 8 : vérifications R-1 à R-10, R-11 quand elle figure
 * (révision 0.2), et N-4 quand elle figure.
 *
 * `parties` : {registre, certificat_commit, validateurs}, chacune
 *   {present: true, octets: Buffer|null, tropGrand?: bool} (octets nul : fichier
 *   déclaré présent mais absent du répertoire) ou {present: false, raison}
 *   (raison déclarée dans l'index). Les octets sont ceux du fichier ; le
 *   SHA-256 est l'affaire de D-2.
 * `manifeste` : l'objet de manifeste.json quand P-1 a réussi, sinon null.
 * `periodHash` : le periodHash recalculé (CT-1 §10.2), ou null s'il n'est pas
 *   calculable (EX-5.4 : R-9 et R-10 sont alors non exécutées, raison
 *   prerequis_en_echec ; R-1 à R-8 s'exécutent ; N-4 ne figure pas).
 * `cles` : les clés de cles.json [{key_id, public_key}] quand cles.json est
 *   conforme à son schéma avec des key_id et des public_key uniques (première
 *   partie de E-8), sinon null (R-10 non exécutée, prerequis_en_echec).
 * `ancres` : le fichier d'ancres déjà validé (N-1 : schéma, et
 *   defautsAncreRegistre vide), ou null ; un fichier d'ancres non validé peut
 *   lever une exception (code 2, EX-4.10), jamais rendre un statut.
 * `schemas` : registre de schémas ($id -> document) contenant
 *   registre-v0.schema.json et validateurs-v0.schema.json.
 * `langue` : "fr" ou "en", pour les détails et le résumé ; l'énoncé est
 *   rendu dans les deux langues.
 * `pointDeControle` (révision 0.2, EX-11.24) : null quand le dossier ne déclare
 *   pas la partie points-de-controle.json présente ; sinon
 *   { orgId, journalId, keyId, checkpointHash (recalculé par K-2, ou null si
 *   K-2 n'a pas réussi), reference (anchors.registry de la partie, ou null) }.
 *   R-11 figure dans les vérifications si ce paramètre n'est pas nul ou si
 *   registre.json porte une entrée ancre_point_de_controle ; sinon elle est
 *   omise et le rapport est celui de la version 0.1 (EX-6.18).
 *
 * Rend {
 *   statut, raison, resume, ancresEmployees (pointeurs RFC 6901),
 *   verifications (R-1 à R-10, puis R-11 quand elle figure, dans l'ordre, au
 *     format du rapport ; vide si une partie requise est absente, EX-5.6),
 *   n4 (vérification N-4 au format du rapport, ou null si elle ne figure pas),
 *   avertissements [{id, check, detail}],
 *   faits (EX-11.21, ou null si le contrôle n'a pas réussi),
 *   enonce ({fr, en} : la proposition de EX-11.22, ou null),
 *   inscriptionsProuvees ([{key_id, public_key, chain_key, block_number}] :
 *     inscriptions que R-10 prouve dans un contrôle 8 réussi, pour la
 *     provenance « registre » de l'énoncé, EX-6.8),
 *   entreePoint (révision 0.2 : { indice, block_number, block_time, issuer,
 *     rattachee } de l'entrée ancre_point_de_controle quand R-11 a réussi,
 *     sinon null ; rattachee vaut true si la règle 2 a rattaché la référence
 *     de la partie)
 * }.
 */
export function verifierControle8({ parties, manifeste = null, periodHash = null, cles = null, ancres = null, schemas, langue = "fr", pointDeControle = null }) {
  const L = traducteur(langue);
  const sortie = { statut: null, raison: null, resume: null, ancresEmployees: [], verifications: [], n4: null, avertissements: [], faits: null, enonce: null, inscriptionsProuvees: [], entreePoint: null };
  // EX-5.4 : sans periodHash recalculé (P-1 en échec), seules R-9 et R-10 ne
  // s'exécutent pas ; R-1 à R-8 ne dépendent pas du manifeste. N-4 ne figure
  // pas : la clé du manifeste n'est pas établie (EX-12.5).
  if (!periodHash) manifeste = null;

  // Parties requises (EX-4.3, EX-11.20) : registre et certificat_commit.
  const absentes = ["registre", "certificat_commit"].filter((n) => !parties[n]?.present);
  if (absentes.length) {
    const raisons = absentes.map((n) => raisonPartieAbsente(parties[n]?.raison));
    sortie.statut = "non_execute";
    sortie.raison = premiereRaison(raisons);
    const fichiers = ["registre", "certificat_commit", "validateurs"].filter((n) => !parties[n]?.present).map((n) => FICHIERS_PARTIES[n]);
    const motifs = [...new Set(absentes.map((n) => parties[n]?.raison ?? L("non déclarée", "not declared")))];
    sortie.resume = L(`${fichiers.join(", ")} ${fichiers.length > 1 ? "absents" : "absent"} (${motifs.join(" ; ")})`, `${fichiers.join(", ")} absent (${motifs.join("; ")})`);
    return sortie;
  }

  const registry = ancres?.registry ?? null;
  const ids = ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"];
  const res = {};
  const poser = (id, statut, raison, detail) => (res[id] = verification(id, statut, raison, detail));
  // R-11 (révision 0.2) figure avec la partie points-de-controle.json ou avec une
  // entrée ancre_point_de_controle ; sans l'une ni l'autre, le rapport reste celui
  // de la version 0.1 (EX-6.18). L'entrée se cherche dans le texte avant R-1 :
  // registre.json illisible → R-11 non exécutée comme les autres (prerequis_en_echec).
  let avecR11 = pointDeControle !== null;
  if (!avecR11 && parties.registre?.octets) {
    try {
      const brut = JSON.parse(Buffer.from(parties.registre.octets).toString("utf8"));
      avecR11 = Array.isArray(brut?.entries) && brut.entries.some((e) => e?.role === ROLE_ANCRE_POINT);
    } catch {
      avecR11 = false;
    }
  }
  if (avecR11) ids.push("R-11");

  // Clé du manifeste dans le fichier d'ancres : N-4 ne figure que si elle a une chain_key (EX-12.5).
  let ancreCleChaine = null;
  if (manifeste && Array.isArray(ancres?.recorders)) {
    const i = ancres.recorders.findIndex((r) => r.org_id === manifeste.org_id && r.journal_id === manifeste.journal_id && r.key_id === manifeste.recorder_key_id && r.chain_key);
    if (i !== -1) ancreCleChaine = { indice: i, chain_key: ancres.recorders[i].chain_key, key_id: ancres.recorders[i].key_id };
  }
  const poserN4 = (statut, raison, detail) => {
    if (ancreCleChaine) sortie.n4 = { ...verification("N-4", statut, raison, detail) };
  };

  const conclure = () => {
    sortie.verifications = ids.map((id) => res[id]);
    const echec = sortie.verifications.some((v) => v.status === "echoue") || sortie.n4?.status === "echoue";
    const statutsBloquants = ["R-1", "R-2", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9"].map((id) => res[id]);
    if (echec) {
      sortie.statut = "echoue";
      const ids8 = [...sortie.verifications, ...(sortie.n4 ? [sortie.n4] : [])].filter((v) => v.status === "echoue").map((v) => v.id);
      sortie.resume = L(`vérification(s) en échec : ${ids8.join(", ")}`, `failed check(s): ${ids8.join(", ")}`);
    } else if (statutsBloquants.every((v) => v.status === "reussi")) {
      sortie.statut = "reussi";
    } else {
      sortie.statut = "non_execute";
      sortie.raison = premiereRaison(statutsBloquants.filter((v) => v.status === "non_execute").map((v) => v.reason));
      const premiere = statutsBloquants.find((v) => v.status === "non_execute" && v.reason === sortie.raison);
      sortie.resume = premiere?.detail ?? null;
    }
    if (ancreCleChaine && sortie.n4) sortie.ancresEmployees.push(`/recorders/${ancreCleChaine.indice}`);
    return sortie;
  };

  const sansRegistre = ancres ? L("le fichier d'ancres ne donne pas d'ancre registry", "the anchors file gives no registry anchor") : L("aucun fichier d'ancres", "no anchors file");

  // ----- R-1 : parties conformes et appariées -------------------------------
  const lu = lirePartie(parties.registre, "registre", { schemas, idSchema: ID_SCHEMA_REGISTRE, limite: LIMITES.registre, langue });
  const luCert = lirePartie(parties.certificat_commit, "certificat_commit", { schemas, idSchema: ID_SCHEMA_REGISTRE, fragment: "#/$defs/certificat_commit", limite: LIMITES.certificat_commit, langue });
  const ecartsR1 = [];
  if (lu.erreur) ecartsR1.push(lu.erreur);
  else ecartsR1.push(...ecartsRoles(lu.valeur, langue));
  if (luCert.erreur) ecartsR1.push(luCert.erreur);
  let entrees = null;
  let certificats = null;
  const certParHauteur = new Map();
  if (!ecartsR1.length) {
    entrees = lu.valeur.entries;
    certificats = luCert.valeur.certificates;
    for (const [i, c] of certificats.entries()) {
      const h = quantite(c.height);
      if (certParHauteur.has(h)) ecartsR1.push(L(`deux certificats de hauteur ${h}`, `two certificates of height ${h}`));
      else certParHauteur.set(h, { indice: i, certificat: c });
    }
    const servis = new Set();
    for (const [i, e] of entrees.entries()) {
      const h = quantite(e.block.number);
      if (!certParHauteur.has(h)) ecartsR1.push(L(`entrée ${i} (${e.role}, bloc ${h}) : aucun certificat de cette hauteur`, `entry ${i} (${e.role}, block ${h}): no certificate of this height`));
      else servis.add(h);
      if (e.transaction_index >= e.receipts.length) ecartsR1.push(L(`entrée ${i} : transaction_index ${e.transaction_index} hors des ${e.receipts.length} reçus`, `entry ${i}: transaction_index ${e.transaction_index} outside the ${e.receipts.length} receipts`));
      else if (e.log_index >= e.receipts[e.transaction_index].logs.length) ecartsR1.push(L(`entrée ${i} : log_index ${e.log_index} hors des journaux du reçu`, `entry ${i}: log_index ${e.log_index} outside the receipt's logs`));
    }
    for (const h of certParHauteur.keys()) if (!servis.has(h)) ecartsR1.push(L(`certificat de hauteur ${h} qui ne sert aucune entrée`, `certificate of height ${h} serving no entry`));
  }
  if (ecartsR1.length) {
    poser("R-1", "echoue", null, ecartsR1.join(" ; "));
    const d = L("R-1 en échec", "R-1 failed");
    for (const id of ids.slice(1)) poser(id, "non_execute", "prerequis_en_echec", d);
    poserN4("non_execute", "prerequis_en_echec", d);
    return conclure();
  }
  const validateursPresents = parties.validateurs?.present === true;
  poser("R-1", "reussi", null, L(
    `registre.json (${entrees.length} entrées) et certificat-commit.json (${certificats.length} certificats) conformes et appariés`,
    `registre.json (${entrees.length} entries) and certificat-commit.json (${certificats.length} certificates) conformant and matched`,
  ));
  if (registry) sortie.ancresEmployees.push("/registry");

  // ----- R-2 : jeu de l'ancre --------------------------------------------------
  const parCert = certificats.map((c) => ({ c, h: quantite(c.height) }));
  const r2 = parCert.map(({ c, h }) => {
    if (!registry) return { statut: "non_execute", raison: "ancre_absente", detail: sansRegistre };
    const trouve = jeuAncrePourHauteur(registry, h);
    if (!trouve) return { statut: "non_execute", raison: "ancre_absente", detail: L(`hauteur ${h} : aucun jeu de l'ancre ne couvre cette hauteur`, `height ${h}: no set of the anchor covers this height`) };
    const hachage = hachageJeuValidateurs(trouve.jeu.validators);
    if (hachage !== c.valsetHash) return { statut: "echoue", detail: L(`hauteur ${h} : valsetHash ${c.valsetHash} différent du hachage ${hachage} du jeu /registry/validator_sets/${trouve.indice}`, `height ${h}: valsetHash ${c.valsetHash} differs from hash ${hachage} of set /registry/validator_sets/${trouve.indice}`), trouve };
    return { statut: "reussi", trouve, hachage };
  });
  {
    const a = agreger(r2);
    const jeux = [...new Set(r2.filter((x) => x.trouve).map((x) => x.trouve.indice))].sort((p, q) => p - q);
    for (const j of jeux) sortie.ancresEmployees.push(`/registry/validator_sets/${j}`);
    let d;
    if (a.statut === "reussi") {
      const descr = jeux.map((j) => {
        const jeu = registry.validator_sets[j];
        const intervalle = jeu.to_height === null ? L(`hauteurs ${jeu.from_height} et suivantes`, `heights ${jeu.from_height} onwards`) : L(`hauteurs ${jeu.from_height} à ${jeu.to_height}`, `heights ${jeu.from_height} to ${jeu.to_height}`);
        return `/registry/validator_sets/${j} (${intervalle}) : ${L("hachage", "hash")} ${hachageJeuValidateurs(jeu.validators)}`;
      });
      d = L(`jeu de l'ancre ${descr.join(" ; ")} égal au valsetHash des ${certificats.length} certificats`, `anchor set ${descr.join("; ")} equal to the valsetHash of the ${certificats.length} certificates`);
    } else d = [...new Set(r2.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; ");
    poser("R-2", a.statut, a.raison, d);
  }

  // ----- R-3 : cohérence de validateurs.json ----------------------------------
  if (!validateursPresents) {
    poser("R-3", "non_execute", "partie_absente", L(`validateurs.json absent (${parties.validateurs?.raison ?? "non déclaré"})`, `validateurs.json absent (${parties.validateurs?.raison ?? "not declared"})`));
  } else {
    const luVal = lirePartie(parties.validateurs, "validateurs", { schemas, idSchema: ID_SCHEMA_VALIDATEURS, limite: LIMITES.validateurs, langue });
    if (luVal.erreur) poser("R-3", "echoue", null, luVal.erreur);
    else {
      const items = parCert.map(({ c, h }) => {
        const couvrants = luVal.valeur.sets.filter((s) => h >= BigInt(s.from_height) && (s.to_height === null || h <= BigInt(s.to_height)));
        if (!couvrants.length) return { statut: "echoue", detail: L(`hauteur ${h} : validateurs.json ne déclare aucun jeu pour cette hauteur`, `height ${h}: validateurs.json declares no set for this height`) };
        if (!couvrants.some((s) => hachageJeuValidateurs(s.validators) === c.valsetHash)) return { statut: "echoue", detail: L(`hauteur ${h} : le jeu déclaré par validateurs.json a le hachage ${hachageJeuValidateurs(couvrants[0].validators)}, pas le valsetHash ${c.valsetHash}`, `height ${h}: the set declared by validateurs.json has hash ${hachageJeuValidateurs(couvrants[0].validators)}, not valsetHash ${c.valsetHash}`) };
        return { statut: "reussi" };
      });
      const a = agreger(items);
      poser("R-3", a.statut, a.raison, a.statut === "reussi" ? L(`validateurs.json déclare le jeu de valsetHash de chacun des ${certificats.length} certificats`, `validateurs.json declares the valsetHash set of each of the ${certificats.length} certificates`) : items.filter((x) => x.statut === "echoue").map((x) => x.detail).join(" ; "));
    }
  }

  // ----- R-4 : identifiant de chaîne -------------------------------------------
  {
    const items = parCert.map(({ c, h }) => {
      if (!registry) return { statut: "non_execute", raison: "ancre_absente", detail: sansRegistre };
      if (c.chainId !== registry.chain_id) return { statut: "echoue", detail: L(`hauteur ${h} : chainId « ${c.chainId} » au lieu de « ${registry.chain_id} » (ancre)`, `height ${h}: chainId "${c.chainId}" instead of "${registry.chain_id}" (anchor)`) };
      return { statut: "reussi" };
    });
    const a = agreger(items);
    const d = a.statut === "reussi" ? L(`chainId ${registry.chain_id} égal à celui de l'ancre, pour les ${certificats.length} certificats`, `chainId ${registry.chain_id} equal to the anchor's, for the ${certificats.length} certificates`) : [...new Set(items.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; ");
    poser("R-4", a.statut, a.raison, d);
  }

  // ----- R-5 : signatures et quorum, contre le jeu de l'ancre ---------------
  const signatairesParHauteur = new Map();
  const r5ParHauteur = new Map();
  {
    const items = parCert.map(({ c, h }, i) => {
      const p = r2[i];
      if (p.statut !== "reussi") {
        const raison = p.statut === "non_execute" && RAISONS_ADMISES.has(p.raison) ? p.raison : "prerequis_en_echec";
        return { statut: "non_execute", raison, detail: p.statut === "echoue" ? L(`hauteur ${h} : R-2 en échec`, `height ${h}: R-2 failed`) : L(`R-2 non exécutée (${p.raison}) : ${p.detail}`, `R-2 not run (${p.raison}): ${p.detail}`) };
      }
      const jeu = chargerJeuValidateurs({ validators: p.trouve.jeu.validators });
      // Seuls les champs nommés par EX-11.3 sont lus : rien d'autre du certificat n'entre.
      const propre = { chainId: c.chainId, valsetHash: c.valsetHash, h: c.height, r: c.round, hash: c.blockHash, prop: c.proposal.line, cmts: c.precommits.map((x) => x.line) };
      const v = verifierCertificat(propre, jeu);
      for (const ctl of v.controles) {
        for (const rq of ctl.remarques ?? []) sortie.avertissements.push({ id: "AV-R-2", check: "R-5", detail: L(`hauteur ${h}, ${ctl.nom}${ctl.indice ? ` ${ctl.indice}` : ""} (${ctl.validatorId ?? "?"}) : ${rq}`, `height ${h}, ${ctl.nom}${ctl.indice ? ` ${ctl.indice}` : ""} (${ctl.validatorId ?? "?"}): ${rq}`) });
      }
      if (!v.valide) {
        const fautes = v.controles.filter((x) => !x.ok).map((x) => `${x.nom}${x.indice ? ` ${x.indice}` : ""} : ${x.detail}`);
        return { statut: "echoue", detail: L(`hauteur ${h} : ${fautes.join(" ; ")}`, `height ${h}: ${fautes.join("; ")}`) };
      }
      signatairesParHauteur.set(h, { signataires: v.signataires, quorum: v.quorum, taille: v.tailleJeu, indiceJeu: p.trouve.indice });
      return { statut: "reussi", n: v.signataires.length, quorum: v.quorum, taille: v.tailleJeu };
    });
    parCert.forEach(({ h }, i) => r5ParHauteur.set(h, items[i]));
    const a = agreger(items);
    let d;
    if (a.statut === "reussi") {
      const minN = Math.min(...items.map((x) => x.n));
      const q = [...new Set(items.map((x) => `${x.quorum} ${L("sur", "of")} ${x.taille}`))].join(", ");
      d = L(`${certificats.length} certificats : proposition et precommits valides, au moins ${minN} signataires distincts, quorum ${q}`, `${certificats.length} certificates: proposal and precommits valid, at least ${minN} distinct signers, quorum ${q}`);
    } else d = [...new Set(items.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; ");
    poser("R-5", a.statut, a.raison, d);
  }

  // ----- R-6 et R-7 : hachage du bloc et racine des reçus, par entrée --------
  const r6 = entrees.map((e, i) => {
    const h = quantite(e.block.number);
    const { certificat: c } = certParHauteur.get(h);
    const calcule = hachageBlocBFT(e.block);
    const fautes = [];
    if (calcule !== c.blockHash) fautes.push(L(`BFTBlockHash recalculé ${calcule} différent du blockHash certifié ${c.blockHash}`, `recomputed BFTBlockHash ${calcule} differs from certified blockHash ${c.blockHash}`));
    if (calcule !== e.block.hash) fautes.push(L(`BFTBlockHash recalculé ${calcule} différent de block.hash ${e.block.hash}`, `recomputed BFTBlockHash ${calcule} differs from block.hash ${e.block.hash}`));
    if (quantite(c.height) !== h) fautes.push(L("hauteur du certificat différente", "certificate height differs"));
    return fautes.length ? { statut: "echoue", detail: L(`entrée ${i} (${e.role}, bloc ${h}) : ${fautes.join(" ; ")}`, `entry ${i} (${e.role}, block ${h}): ${fautes.join("; ")}`) } : { statut: "reussi", hachage: calcule };
  });
  {
    const a = agreger(r6);
    const blocs = new Set(entrees.map((e) => e.block.number)).size;
    poser("R-6", a.statut, a.raison, a.statut === "reussi" ? L(`BFTBlockHash recalculé égal au blockHash certifié et à block.hash, pour les ${blocs} blocs`, `recomputed BFTBlockHash equal to the certified blockHash and to block.hash, for the ${blocs} blocks`) : r6.filter((x) => x.statut === "echoue").map((x) => x.detail).join(" ; "));
  }
  const r7 = entrees.map((e, i) => {
    let calcule;
    try {
      calcule = racineRecus(e.receipts);
    } catch (err) {
      return { statut: "echoue", detail: L(`entrée ${i} (${e.role}) : reçus inexploitables (${err.message})`, `entry ${i} (${e.role}): unusable receipts (${err.message})`) };
    }
    if (calcule !== e.block.receiptsRoot) return { statut: "echoue", detail: L(`entrée ${i} (${e.role}, bloc ${quantite(e.block.number)}) : racine recalculée ${calcule} sur ${e.receipts.length} reçu(s) différente de receiptsRoot ${e.block.receiptsRoot}`, `entry ${i} (${e.role}, block ${quantite(e.block.number)}): recomputed root ${calcule} over ${e.receipts.length} receipt(s) differs from receiptsRoot ${e.block.receiptsRoot}`) };
    return { statut: "reussi", racine: calcule };
  });
  {
    const a = agreger(r7);
    const blocs = new Set(entrees.map((e) => e.block.number)).size;
    poser("R-7", a.statut, a.raison, a.statut === "reussi" ? L(`receiptsRoot recalculé égal à celui de l'en-tête, pour les ${blocs} blocs`, `recomputed receiptsRoot equal to the header's, for the ${blocs} blocks`) : r7.filter((x) => x.statut === "echoue").map((x) => x.detail).join(" ; "));
  }
  const lie = entrees.map((_, i) => r6[i].statut === "reussi" && r7[i].statut === "reussi");
  const journalProuve = (e) => e.receipts[e.transaction_index].logs[e.log_index];

  // ----- R-8 : contrat émetteur -------------------------------------------------
  {
    const items = entrees.map((e, i) => {
      if (!lie[i]) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L(`entrée ${i} : R-6 ou R-7 en échec`, `entry ${i}: R-6 or R-7 failed`) };
      if (!registry) return { statut: "non_execute", raison: "ancre_absente", detail: sansRegistre };
      const attendue = registry.contracts[CONTRAT_DU_ROLE[e.role]];
      const adresse = journalProuve(e).address;
      if (adresse !== attendue) return { statut: "echoue", detail: L(`entrée ${i} (${e.role}) : journal émis par ${adresse}, pas par ${NOM_CONTRAT_DU_ROLE[e.role]} ${attendue} de l'ancre`, `entry ${i} (${e.role}): log emitted by ${adresse}, not by ${NOM_CONTRAT_DU_ROLE[e.role]} ${attendue} of the anchor`) };
      return { statut: "reussi" };
    });
    const a = agreger(items);
    const roles = [...new Set(["inscription", "ancre", ROLE_ANCRE_POINT, "cloture"].filter((r) => entrees.some((e) => e.role === r)).map((r) => NOM_CONTRAT_DU_ROLE[r]))];
    poser("R-8", a.statut, a.raison, a.statut === "reussi" ? L(`journaux émis par ${joindre(roles, "fr")} aux adresses de l'ancre`, `logs emitted by ${joindre(roles, "en")} at the anchor's addresses`) : [...new Set(items.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; "));
  }

  // ----- R-9 : événement et valeurs de la période ------------------------------
  const decodes = entrees.map((e, i) => (lie[i] ? decoderJournal(e.role, journalProuve(e), langue) : null));
  const indiceAncre = entrees.findIndex((e) => e.role === "ancre");
  {
    const items = entrees.map((e, i) => {
      if (e.role === "inscription" || e.role === ROLE_ANCRE_POINT) return null;
      if (!lie[i]) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L(`entrée ${i} (${e.role}) : R-6 ou R-7 en échec`, `entry ${i} (${e.role}): R-6 or R-7 failed`) };
      if (!manifeste) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L("P-1 n'a pas réussi : periodHash non recalculé", "P-1 did not pass: periodHash not recomputed") };
      const { erreurs, valeurs } = decodes[i];
      const fautes = [...erreurs];
      if (valeurs && e.role === "cloture") {
        const egal = (nom, lu, attendu) => {
          if (String(lu) !== String(attendu)) fautes.push(L(`${nom} ${lu} au lieu de ${attendu} (manifeste)`, `${nom} ${lu} instead of ${attendu} (manifest)`));
        };
        egal("periodHash", valeurs.periodHash, periodHash);
        egal("orgId", valeurs.orgId, manifeste.org_id);
        egal("journalId", valeurs.journalId, manifeste.journal_id);
        egal("root", valeurs.root, manifeste.root);
        egal("periodStart", valeurs.periodStart, manifeste.period_start);
        egal("periodEnd", valeurs.periodEnd, manifeste.period_end);
        egal("firstSeq", valeurs.firstSeq, manifeste.first_seq);
        egal("lastSeq", valeurs.lastSeq, manifeste.last_seq);
        egal("version", valeurs.version, manifeste.version);
        const ts = quantite(e.block.timestamp);
        if (String(valeurs.publishedAt) !== ts.toString()) fautes.push(L(`publishedAt ${valeurs.publishedAt} différent de block.timestamp ${ts}`, `publishedAt ${valeurs.publishedAt} differs from block.timestamp ${ts}`));
      }
      if (valeurs && e.role === "ancre") {
        const attendue = empreinteAncre(manifeste.org_id, manifeste.journal_id, periodHash);
        if (valeurs.fingerprint !== attendue) fautes.push(L(`empreinte ${valeurs.fingerprint} au lieu de keccak256(org_id ‖ journal_id ‖ periodHash) = ${attendue}`, `fingerprint ${valeurs.fingerprint} instead of keccak256(org_id ‖ journal_id ‖ periodHash) = ${attendue}`));
        if (valeurs.docType !== DOC_TYPE_PERIODE) fautes.push(L(`docType ${valeurs.docType} au lieu de ${DOC_TYPE_PERIODE}`, `docType ${valeurs.docType} instead of ${DOC_TYPE_PERIODE}`));
      }
      if (fautes.length) return { statut: "echoue", detail: L(`${NOMS_EVENEMENTS[e.role]} (entrée ${i}) : ${fautes.join(" ; ")}`, `${NOMS_EVENEMENTS[e.role]} (entry ${i}): ${fautes.join("; ")}`) };
      return { statut: "reussi", valeurs };
    }).filter(Boolean);
    const a = agreger(items);
    let d;
    if (a.statut === "reussi") {
      const fp = decodes[indiceAncre].valeurs.fingerprint;
      d = L(`PeriodSubmitted : periodHash, org_id, journal_id, root, bornes et version égaux au manifeste, publishedAt égal à l'horodatage du bloc ; Anchored : empreinte ${fp} = keccak256(org_id ‖ journal_id ‖ periodHash), docType de période`, `PeriodSubmitted: periodHash, org_id, journal_id, root, bounds and version equal to the manifest, publishedAt equal to the block timestamp; Anchored: fingerprint ${fp} = keccak256(org_id ‖ journal_id ‖ periodHash), period docType`);
    } else d = [...new Set(items.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; ");
    poser("R-9", a.statut, a.raison, d);
  }

  // ----- R-10 : inscriptions ----------------------------------------------------
  const inscriptionsVues = [];
  {
    const indices = entrees.map((e, i) => (e.role === "inscription" ? i : -1)).filter((i) => i !== -1);
    const ancreLiee = indiceAncre !== -1 && lie[indiceAncre];
    const issuerAncre = ancreLiee ? decodes[indiceAncre]?.valeurs?.issuer ?? null : null;
    const cleManifeste = cles?.find((k) => k.key_id === manifeste?.recorder_key_id) ?? null;
    if (!indices.length) {
      poser("R-10", "non_execute", "partie_absente", L("aucune entrée inscription dans registre.json", "no inscription entry in registre.json"));
    } else {
      // Inscriptions de la clé du manifeste : au moins l'une sous l'émetteur de
      // l'ancre ; les autres (réinscription sous une nouvelle clé de chaîne)
      // lèvent AV-R-3 sans faire échouer R-10 (EX-11.19).
      const inscriptionsManifeste = [];
      const items = indices.map((i) => {
        const e = entrees[i];
        const h = quantite(e.block.number);
        if (!lie[i]) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L(`entrée ${i} : R-6 ou R-7 en échec`, `entry ${i}: R-6 or R-7 failed`) };
        if (!manifeste) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L("P-1 n'a pas réussi : periodHash non recalculé", "P-1 did not pass: periodHash not recomputed") };
        if (!cles) return { statut: "non_execute", raison: "prerequis_en_echec", detail: L("cles.json inexploitable (première partie de E-8)", "cles.json unusable (first part of E-8)") };
        const { erreurs, valeurs } = decodes[i];
        const fautes = [...erreurs];
        let cle = null;
        if (valeurs) {
          if (valeurs.orgId !== manifeste.org_id) fautes.push(L(`orgId ${valeurs.orgId} au lieu de ${manifeste.org_id}`, `orgId ${valeurs.orgId} instead of ${manifeste.org_id}`));
          if (valeurs.journalId !== manifeste.journal_id) fautes.push(L(`journalId ${valeurs.journalId} au lieu de ${manifeste.journal_id}`, `journalId ${valeurs.journalId} instead of ${manifeste.journal_id}`));
          cle = cles.find((k) => k.public_key === valeurs.ed25519PubKey) ?? null;
          if (!cle) fautes.push(L(`clé Ed25519 ${valeurs.ed25519PubKey} absente de cles.json`, `Ed25519 key ${valeurs.ed25519PubKey} not in cles.json`));
        }
        if (fautes.length) return { statut: "echoue", detail: L(`RecorderRegistered (entrée ${i}, bloc ${h}) : ${fautes.join(" ; ")}`, `RecorderRegistered (entry ${i}, block ${h}): ${fautes.join("; ")}`) };
        const vue = { key_id: cle.key_id, public_key: cle.public_key, chain_key: valeurs.chainKey, block_number: nombreSortie(h) };
        if (cle.key_id === manifeste.recorder_key_id) inscriptionsManifeste.push(vue);
        inscriptionsVues.push(vue);
        return { statut: "reussi" };
      });
      if (ancreLiee && inscriptionsManifeste.length && items.every((x) => x.statut === "reussi")) {
        if (issuerAncre === null) items.push({ statut: "echoue", detail: L("émetteur de l'ancre illisible", "anchor issuer unreadable") });
        else if (!inscriptionsManifeste.some((x) => x.chain_key === issuerAncre)) {
          const sous = joindre(inscriptionsManifeste.map((x) => `${x.chain_key} (bloc ${x.block_number})`), langue);
          items.push({ statut: "echoue", detail: L(`${manifeste.recorder_key_id}, clé du manifeste, inscrite sous ${sous}, jamais sous l'émetteur de l'ancre ${issuerAncre}`, `${manifeste.recorder_key_id}, the manifest key, registered under ${sous}, never under the anchor issuer ${issuerAncre}`) });
        } else {
          for (const x of inscriptionsManifeste.filter((y) => y.chain_key !== issuerAncre)) sortie.avertissements.push({ id: "AV-R-3", check: "R-10", detail: L(`inscription de ${x.key_id}, clé du manifeste, au bloc ${x.block_number} sous la clé de chaîne ${x.chain_key}, autre que l'émetteur de l'ancre ${issuerAncre} : non retenue`, `registration of ${x.key_id}, the manifest key, in block ${x.block_number} under chain key ${x.chain_key}, other than the anchor issuer ${issuerAncre}: not retained`) });
        }
      }
      const a = agreger(items);
      let d;
      if (a.statut === "reussi") {
        const blocs = [...new Set(inscriptionsVues.map((x) => x.block_number))];
        const cleM = inscriptionsVues.find((x) => x.key_id === manifeste.recorder_key_id && x.chain_key === issuerAncre);
        d = L(
          `RecorderRegistered ${blocs.length > 1 ? "aux blocs" : "au bloc"} ${joindre(blocs.map(String), "fr")} : ${joindre(inscriptionsVues.map((x) => x.key_id), "fr")} de cles.json${cleM ? ` ; ${cleM.key_id}, clé du manifeste, inscrite sous ${cleM.chain_key}, émetteur de l'ancre` : ""}`,
          `RecorderRegistered in block${blocs.length > 1 ? "s" : ""} ${joindre(blocs.map(String), "en")}: ${joindre(inscriptionsVues.map((x) => x.key_id), "en")} of cles.json${cleM ? `; ${cleM.key_id}, the manifest key, registered under ${cleM.chain_key}, the anchor issuer` : ""}`,
        );
      } else d = [...new Set(items.filter((x) => x.statut === a.statut).map((x) => x.detail))].join(" ; ");
      poser("R-10", a.statut, a.raison, d);
    }
    // AV-R-1 : aucune inscription de la clé du manifeste (EX-11.19).
    if (manifeste && (cleManifeste || !indices.length)) {
      const inscrite = cleManifeste && indices.some((i) => {
        const dj = decodes[i] ?? decoderJournal("inscription", journalProuve(entrees[i]), langue);
        return dj.valeurs?.ed25519PubKey === cleManifeste.public_key;
      });
      if (!inscrite) sortie.avertissements.push({ id: "AV-R-1", check: "R-10", detail: L(`aucune inscription de ${manifeste.recorder_key_id}, clé du manifeste : l'émetteur de l'ancre n'est relié à aucune clé d'enregistreur`, `no registration of ${manifeste.recorder_key_id}, the manifest key: the anchor issuer is tied to no recorder key`) });
    }
  }

  // ----- R-11 : ancre d'un point de contrôle du journal (EX-11.24, révision 0.2) -----
  const indicePoint = entrees.findIndex((e) => e.role === ROLE_ANCRE_POINT);
  let entreePointRattachee = null;
  if (avecR11) {
    if (indicePoint === -1) poser("R-11", "non_execute", "partie_absente", L("aucune entrée ancre_point_de_controle dans registre.json", "no ancre_point_de_controle entry in registre.json"));
    else if (!lie[indicePoint]) poser("R-11", "non_execute", "prerequis_en_echec", L(`entrée ${indicePoint} : R-6 ou R-7 en échec`, `entry ${indicePoint}: R-6 or R-7 failed`));
    else {
      const e = entrees[indicePoint];
      const h = quantite(e.block.number);
      const { erreurs, valeurs } = decodes[indicePoint];
      // Règle 1 : forme du journal (3 sujets, sujet d'Anchored, docType du point).
      const fautes = [...erreurs];
      if (valeurs && valeurs.docType !== DOC_TYPE_POINT_DE_CONTROLE) fautes.push(L(`docType ${valeurs.docType} au lieu de ${DOC_TYPE_POINT_DE_CONTROLE} (point de contrôle)`, `docType ${valeurs.docType} instead of ${DOC_TYPE_POINT_DE_CONTROLE} (checkpoint)`));
      let statut = null;
      let raison = null;
      let detail = null;
      let rattachee = false;
      if (fautes.length) {
        statut = "echoue";
        detail = L(`Anchored (entrée ${indicePoint}, bloc ${h}) : ${fautes.join(" ; ")}`, `Anchored (entry ${indicePoint}, block ${h}): ${fautes.join("; ")}`);
      } else if (!pointDeControle || !pointDeControle.reference) {
        statut = "non_execute";
        raison = "partie_absente";
        detail = L(`entrée sans partie points-de-controle.json à rattacher (bloc ${h}, émetteur ${valeurs.issuer}, docType du point)`, `entry with no points-de-controle.json part to tie to (block ${h}, issuer ${valeurs.issuer}, checkpoint docType)`);
      } else if (!pointDeControle.checkpointHash) {
        statut = "non_execute";
        raison = "prerequis_en_echec";
        detail = L(`K-2 n'a pas réussi : checkpointHash non recalculé (bloc ${h}, émetteur ${valeurs.issuer})`, `K-2 did not pass: checkpointHash not recomputed (block ${h}, issuer ${valeurs.issuer})`);
      } else {
        // Règle 2 : rattachement à la référence de la partie.
        const ref = pointDeControle.reference;
        const attendue = empreinteAncre(pointDeControle.orgId, pointDeControle.journalId, pointDeControle.checkpointHash);
        const ecarts = [];
        if (valeurs.fingerprint !== attendue) ecarts.push(L(`empreinte ${valeurs.fingerprint} au lieu de keccak256(org_id ‖ journal_id ‖ checkpoint_hash) = ${attendue}`, `fingerprint ${valeurs.fingerprint} instead of keccak256(org_id ‖ journal_id ‖ checkpoint_hash) = ${attendue}`));
        if (String(nombreSortie(h)) !== String(ref.block_number)) ecarts.push(L(`bloc ${h} au lieu de block_number ${ref.block_number} de la partie`, `block ${h} instead of block_number ${ref.block_number} of the part`));
        if (e.block.hash !== ref.block_hash) ecarts.push(L(`block.hash ${e.block.hash} au lieu de block_hash ${ref.block_hash} de la partie`, `block.hash ${e.block.hash} instead of block_hash ${ref.block_hash} of the part`));
        if (e.transaction_hash !== ref.transaction_hash) ecarts.push(L(`transaction_hash ${e.transaction_hash} au lieu de ${ref.transaction_hash} de la partie`, `transaction_hash ${e.transaction_hash} instead of ${ref.transaction_hash} of the part`));
        if (e.log_index !== ref.log_index) ecarts.push(L(`log_index ${e.log_index} au lieu de ${ref.log_index} de la partie`, `log_index ${e.log_index} instead of ${ref.log_index} of the part`));
        // Règle 3 : émetteur relié à une inscription de la clé du point (R-10 réussie).
        const inscriptionsPoint = res["R-10"].status === "reussi" ? inscriptionsVues.filter((x) => x.key_id === pointDeControle.keyId) : [];
        if (inscriptionsPoint.length) {
          if (!inscriptionsPoint.some((x) => x.chain_key === valeurs.issuer)) {
            const sous = joindre(inscriptionsPoint.map((x) => `${x.chain_key} (bloc ${x.block_number})`), langue);
            ecarts.push(L(`émetteur ${valeurs.issuer} : ${pointDeControle.keyId}, clé du point, inscrite sous ${sous}, jamais sous cet émetteur`, `issuer ${valeurs.issuer}: ${pointDeControle.keyId}, the checkpoint key, registered under ${sous}, never under this issuer`));
          }
        } else {
          sortie.avertissements.push({ id: "AV-K-3", check: "R-11", detail: L(`aucune inscription de ${pointDeControle.keyId}, clé du point de contrôle, prouvée dans le dossier : l'émetteur de l'ancre du point ${valeurs.issuer} n'est relié à aucune clé d'enregistreur`, `no registration of ${pointDeControle.keyId}, the checkpoint key, proven in the dossier: the issuer of the checkpoint anchor ${valeurs.issuer} is tied to no recorder key`) });
        }
        if (ecarts.length) {
          statut = "echoue";
          detail = L(`Anchored (entrée ${indicePoint}, bloc ${h}) : ${ecarts.join(" ; ")}`, `Anchored (entry ${indicePoint}, block ${h}): ${ecarts.join("; ")}`);
        } else {
          statut = "reussi";
          rattachee = true;
          detail = L(`Anchored au bloc ${h}, émetteur ${valeurs.issuer}, docType ${valeurs.docType} (point de contrôle), empreinte ${valeurs.fingerprint} = keccak256(org_id ‖ journal_id ‖ checkpoint_hash), bloc, transaction et log_index égaux à la référence de la partie`, `Anchored in block ${h}, issuer ${valeurs.issuer}, docType ${valeurs.docType} (checkpoint), fingerprint ${valeurs.fingerprint} = keccak256(org_id ‖ journal_id ‖ checkpoint_hash), block, transaction and log_index equal to the part's reference`);
        }
      }
      poser("R-11", statut, raison, detail);
      if (statut === "reussi") entreePointRattachee = { indice: indicePoint, block_number: nombreSortie(h), block_time: instantRFC3339(quantite(e.block.timestamp)), issuer: valeurs.issuer, rattachee };
    }
  }

  // ----- N-4 : clé de chaîne de l'ancre (EX-12.5) -----------------------------------
  if (ancreCleChaine) {
    const r5Ancre = indiceAncre === -1 ? null : r5ParHauteur.get(quantite(entrees[indiceAncre].block.number));
    if (indiceAncre === -1 || !lie[indiceAncre]) poserN4("non_execute", "prerequis_en_echec", L("l'entrée ancre n'a pas passé R-6 et R-7", "the ancre entry did not pass R-6 and R-7"));
    else if (r5Ancre && r5Ancre.statut !== "reussi") {
      const raison = r5Ancre.statut === "echoue" ? "prerequis_en_echec" : r5Ancre.raison;
      poserN4("non_execute", raison, L(`R-5 n'a pas réussi pour le certificat du bloc de l'ancre (${r5Ancre.statut === "echoue" ? "en échec" : `non exécutée, ${r5Ancre.raison}`}) : l'émetteur lu n'est pas authentifié`, `R-5 did not pass for the certificate of the anchor's block (${r5Ancre.statut === "echoue" ? "failed" : `not run, ${r5Ancre.raison}`}): the issuer read is not authenticated`));
    } else {
      const issuer = decodes[indiceAncre]?.valeurs?.issuer ?? null;
      if (issuer === ancreCleChaine.chain_key) poserN4("reussi", null, L(`émetteur de l'ancre ${issuer} égal à la chain_key de ${ancreCleChaine.key_id} dans l'ancre (/recorders/${ancreCleChaine.indice})`, `anchor issuer ${issuer} equal to the chain_key of ${ancreCleChaine.key_id} in the anchors file (/recorders/${ancreCleChaine.indice})`));
      else poserN4("echoue", null, L(`émetteur de l'ancre ${issuer ?? "illisible"} différent de la chain_key ${ancreCleChaine.chain_key} de ${ancreCleChaine.key_id} dans l'ancre (/recorders/${ancreCleChaine.indice})`, `anchor issuer ${issuer ?? "unreadable"} differs from the chain_key ${ancreCleChaine.chain_key} of ${ancreCleChaine.key_id} in the anchors file (/recorders/${ancreCleChaine.indice})`));
    }
  }

  conclure();
  if (sortie.statut !== "reussi") return sortie;
  sortie.entreePoint = entreePointRattachee;

  // ----- Contrôle réussi : faits (EX-11.21), résumé, énoncé (EX-11.22) --------
  const iCloture = entrees.findIndex((e) => e.role === "cloture");
  const ancre = decodes[indiceAncre].valeurs;
  sortie.faits = {
    chain_id: registry.chain_id,
    entries: entrees.map((e, i) => ({
      role: e.role,
      block_number: nombreSortie(quantite(e.block.number)),
      block_hash: r6[i].hachage,
      block_time: instantRFC3339(quantite(e.block.timestamp)),
      transaction_index: e.transaction_index,
      transaction_hash_declared: e.transaction_hash,
      emitter: journalProuve(e).address,
      event: decodes[i].valeurs,
    })),
    certificates: parCert.map(({ h }) => {
      const s = signatairesParHauteur.get(h);
      const jeu = registry.validator_sets[s.indiceJeu];
      return { height: nombreSortie(h), valset_hash: hachageJeuValidateurs(jeu.validators), set_source: jeu.source, set_size: s.taille, quorum: s.quorum, signers: s.signataires };
    }),
  };
  const minSignataires = Math.min(...[...signatairesParHauteur.values()].map((x) => x.signataires.length));
  const tailles = [...new Set([...signatairesParHauteur.values()].map((x) => x.taille))];
  const hInscriptions = entrees.map((e, i) => (e.role === "inscription" ? sortie.faits.entries[i].block_number : null)).filter((x) => x !== null);
  const hAncre = sortie.faits.entries[indiceAncre].block_number;
  const hCloture = sortie.faits.entries[iCloture].block_number;
  const hPoint = indicePoint === -1 ? null : sortie.faits.entries[indicePoint].block_number;
  sortie.resume = L(
    `${registry.chain_id} : ${hInscriptions.length ? `${hInscriptions.length > 1 ? "inscriptions blocs" : "inscription bloc"} ${joindre(hInscriptions.map(String), "fr")}, ` : ""}ancre bloc ${hAncre}, clôture bloc ${hCloture}, ${hPoint !== null ? `ancre du point bloc ${hPoint}, ` : ""}${minSignataires} validateurs sur ${joindre(tailles.map(String), "fr")} à chaque bloc`,
    `${registry.chain_id}: ${hInscriptions.length ? `${hInscriptions.length > 1 ? "registrations blocks" : "registration block"} ${joindre(hInscriptions.map(String), "en")}, ` : ""}anchor block ${hAncre}, closing block ${hCloture}, ${hPoint !== null ? `checkpoint anchor block ${hPoint}, ` : ""}${minSignataires} of ${joindre(tailles.map(String), "en")} validators in each block`,
  );

  if (res["R-10"].status === "reussi") sortie.inscriptionsProuvees = inscriptionsVues;
  const inscriptionManifeste = res["R-10"].status === "reussi" ? inscriptionsVues.find((x) => x.key_id === manifeste.recorder_key_id && x.chain_key === ancre.issuer) : null;
  const n4Reussie = sortie.n4?.status === "reussi";
  const tClo = sortie.faits.entries[iCloture].block_time;
  const tAnc = sortie.faits.entries[indiceAncre].block_time;
  const adrClo = sortie.faits.entries[iCloture].emitter;
  const adrAnc = sortie.faits.entries[indiceAncre].emitter;
  // Proposition de signature (EX-11.22) : un groupe par jeu de l'ancre retenu par
  // R-2, dans l'ordre de la plus petite hauteur ; n = plus petit nombre de
  // signataires des certificats du groupe.
  const groupes = [];
  for (const { h } of [...parCert].sort((p, q) => (p.h < q.h ? -1 : p.h > q.h ? 1 : 0))) {
    const sg = signatairesParHauteur.get(h);
    let g = groupes.find((x) => x.indiceJeu === sg.indiceJeu);
    if (!g) {
      const jeu = registry.validator_sets[sg.indiceJeu];
      g = { indiceJeu: sg.indiceJeu, hauteurs: [], n: Infinity, taille: jeu.validators.length, hachage: hachageJeuValidateurs(jeu.validators), source: jeu.source };
      groupes.push(g);
    }
    g.hauteurs.push(nombreSortie(h));
    g.n = Math.min(g.n, sg.signataires.length);
  }
  let signatureFr;
  let signatureEn;
  if (groupes.length === 1) {
    const g = groupes[0];
    signatureFr = `chacun de ces blocs est signé par ${g.n} des ${g.taille} validateurs du jeu ${g.hachage} que le réviseur déclare (${g.source})`;
    signatureEn = `each of these blocks is signed by ${g.n} of the ${g.taille} validators of set ${g.hachage} declared by the reviewer (${g.source})`;
  } else {
    const morceaux = groupes.map((g, k) => {
      const un = g.hauteurs.length === 1;
      const hs = { fr: joindre(g.hauteurs.map(String), "fr"), en: joindre(g.hauteurs.map(String), "en") };
      const sujetFr = un ? `le bloc ${hs.fr}` : `les blocs ${hs.fr}`;
      const sujetEn = un ? `block ${hs.en}` : `blocks ${hs.en}`;
      const verbeFr = k === 0 ? (un ? " est signé par " : " sont signés par ") : " par ";
      const verbeEn = k === 0 ? (un ? " is signed by " : " are signed by ") : " by ";
      return {
        fr: `${sujetFr}${verbeFr}${g.n} des ${g.taille} validateurs du jeu ${g.hachage} que le réviseur déclare (${g.source})`,
        en: `${sujetEn}${verbeEn}${g.n} of the ${g.taille} validators of set ${g.hachage} declared by the reviewer (${g.source})`,
      };
    });
    signatureFr = joindre(morceaux.map((m) => m.fr), "fr");
    signatureEn = joindre(morceaux.map((m) => m.en), "en");
  }
  sortie.enonce = {
    fr:
      `sur le registre ${registry.chain_id}, la clôture de cette période (organisation ${manifeste.org_id}, journal ${manifeste.journal_id}) figure au bloc ${hCloture} (heure déclarée par le bloc : ${tClo} UTC), émise par le contrat PeriodRegistry ${adrClo}, et son ancre ${ancre.fingerprint} au bloc ${hAncre} (heure déclarée ${tAnc} UTC), émise par AttestationRegistry ${adrAnc} pour l'émetteur ${ancre.issuer}` +
      (inscriptionManifeste ? `, clé de chaîne inscrite au bloc ${inscriptionManifeste.block_number} pour la clé d'enregistreur ${manifeste.recorder_key_id}` : "") +
      (n4Reussie ? `, que le réviseur tient pour la clé de chaîne de ${manifeste.recorder_key_id}` : "") +
      ` ; ${signatureFr}`,
    en:
      `on registry ${registry.chain_id}, the closing of this period (organisation ${manifeste.org_id}, journal ${manifeste.journal_id}) is in block ${hCloture} (time declared by the block: ${tClo} UTC), emitted by contract PeriodRegistry ${adrClo}, and its anchor ${ancre.fingerprint} in block ${hAncre} (declared time ${tAnc} UTC), emitted by AttestationRegistry ${adrAnc} for issuer ${ancre.issuer}` +
      (inscriptionManifeste ? `, chain key registered in block ${inscriptionManifeste.block_number} for recorder key ${manifeste.recorder_key_id}` : "") +
      (n4Reussie ? `, which the reviewer holds as the chain key of ${manifeste.recorder_key_id}` : "") +
      `; ${signatureEn}`,
  };
  return sortie;
}

// ---------------------------------------------------------------------------
// Construction des parties depuis des réponses JSON-RPC (exportateur, CT-4)
// ---------------------------------------------------------------------------

/** Champs de l'en-tête engagés par BFTBlockHash, tels que eth_getBlockByNumber(h, false) les rend (11.2.1). */
export const CHAMPS_ENTETE = ["number", "hash", "parentHash", "timestamp", "stateRoot", "transactionsRoot", "receiptsRoot", "gasUsed", "gasLimit", "baseFeePerGas"];

function minusculesHex(v) {
  return typeof v === "string" ? v.toLowerCase() : v;
}

/**
 * Entrée de registre.json depuis les résultats JSON-RPC : `bloc` (résultat de
 * eth_getBlockByNumber(h, false)), `recus` (résultats de
 * eth_getTransactionReceipt, un par transaction du bloc, dans l'ordre de
 * bloc.transactions), `transactionHash` et `logIndex` du journal prouvé.
 * Hexadécimal ramené en minuscules (les adresses EIP-55 aussi), seuls les
 * champs engagés retenus.
 */
export function entreeRegistre({ role, bloc, recus, transactionHash, logIndex = 0 }) {
  const ordre = bloc.transactions.map((t) => (typeof t === "string" ? t : t.hash).toLowerCase());
  const parHash = new Map(recus.map((r) => [r.transactionHash.toLowerCase(), r]));
  if (ordre.length !== recus.length || ordre.some((t) => !parHash.has(t))) throw new Error("reçus : il faut exactement un reçu par transaction du bloc");
  const transaction_index = ordre.indexOf(transactionHash.toLowerCase());
  if (transaction_index === -1) throw new Error(`transaction ${transactionHash} absente du bloc`);
  const block = {};
  for (const c of CHAMPS_ENTETE) block[c] = minusculesHex(bloc[c]);
  return {
    role,
    block,
    receipts: ordre.map((t) => {
      const r = parHash.get(t);
      return {
        type: minusculesHex(r.type ?? "0x0"),
        status: minusculesHex(r.status),
        cumulativeGasUsed: minusculesHex(r.cumulativeGasUsed),
        logs: r.logs.map((j) => ({ address: j.address.toLowerCase(), topics: j.topics.map((x) => x.toLowerCase()), data: j.data.toLowerCase() })),
      };
    }),
    transaction_index,
    log_index: logIndex,
    transaction_hash: transactionHash.toLowerCase(),
  };
}
