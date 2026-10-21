// Vérification HORS LIGNE d'un certificat de commit de noorcore (mode BFT).
//
// Un certificat de décision (DecidedCert, core/consensus/cert_store.go) est la
// preuve minimale qu'une hauteur a été décidée par le jeu de validateurs : la
// ligne brute de l'enveloppe signée de la proposition du tour décidé, et les
// lignes brutes des enveloppes signées d'au moins « quorum » precommits de ce
// même tour pour ce même bloc. Ce module recalcule tout depuis ces lignes
// brutes, exactement comme le fait le nœud (VerifyEnvelope, signing.go) :
//
//   digest = sha256("noor/v1/bft-sign|" || LP(domain) || LP(chainId) || LP(type)
//                   || LP(validatorId) || valsetHash(32) || u64be(height)
//                   || u64be(round) || blockHash(32) || bodyHash(32))
//   LP(x)  = longueur de x sur 4 octets grand-boutiens, puis x
//   bodyHash = sha256(octets bruts du corps, tels qu'ils figurent dans la ligne)
//   signature secp256k1 de 65 octets [R || S || V], S bas exigé, V dans {0, 1}
//
//   hachage du jeu = sha256("noor/v1/valsethash|" || pour chaque id trié :
//                           id || 0x00 || clé publique brute || 0x00)
//   quorum(N) = floor((N + f) / 2) + 1 avec f = floor((N - 1) / 3)
//
// Rien de ce que le RPC a décodé n'est cru : validatorId, bodyHash et sig sont
// relus dans la ligne brute, le corps est haché sur ses octets d'origine, la
// clé publique est recouvrée de la signature puis comparée à celle du
// validateur nommé dans le jeu FOURNI par l'appelant. Le vérificateur prouve
// qu'un quorum de ce jeu a signé ce bloc ; il ne prouve pas que ce jeu est le
// bon : c'est au dossier de porter le jeu et son origine.
//
// Le vérificateur accepte ce que le DÉCODEUR du nœud accepte, pas seulement ce
// que son encodeur produit : si une ligne légale mais non canonique émise par
// un seul validateur était refusée ici, un bloc réellement décidé serait
// déclaré invalide. Comme encoding/json et VerifyEnvelope (signing.go) :
//   - les noms de membres JSON sont comparés sans tenir compte de la casse
//     (« Domain », « BODY » ; aussi ſ/S et le signe Kelvin/K, comme Go) et,
//     en cas de doublon, la dernière occurrence gagne ;
//   - le base64 des champs d'octets est l'alphabet standard avec bourrage,
//     mais les bits de bourrage non nuls et les « \n »/« \r » sont tolérés ;
//   - un hachage de corps accepte « 0x » ou « 0X » et les chiffres majuscules ;
//   - Voter et proposer peuvent être vides (le signataire est alors le
//     validatorId) mais, présents, doivent lui être égaux ; Vote.Type n'est pas
//     comparé au type de l'enveloppe (le dispatcher du nœud impose celui-ci) ;
//   - les entiers sont des littéraux JSON entiers lus dans le texte brut
//     (« 8328.0 », « "8328" » sont refusés, 2^64 − 1 est accepté) ;
//   - ce que le décodeur Go refuse (types erronés, base64 URL ou sans bourrage,
//     hachage sans 0x…) est refusé ici aussi.
// Une ligne acceptée sous une forme non canonique est signalée comme telle dans
// le détail du contrôle (remarques), sans invalider le certificat. Les vecteurs
// de référence de ce contrat viennent de core/consensus/signing_vectors_test.go.
//
// Ce module ne dépend que de node:crypto et d'ethers (SigningKey) ; il ne
// touche ni au réseau ni au système de fichiers.

import { createHash } from "node:crypto";
import { SigningKey } from "ethers";

// ---------------------------------------------------------------------------
// Constantes du protocole (core/consensus/signing.go, wire.go, types.go)
// ---------------------------------------------------------------------------

/** Domaine mêlé à chaque digest signé (SignDomain). */
export const DOMAINE_SIGNATURE = "noor/v1/bft";
/** Préfixe du digest signé (SignDigestPrefix). */
export const PREFIXE_DIGEST = "noor/v1/bft-sign|";
/** Préfixe du hachage du jeu de validateurs (ValidatorSetHash). */
export const PREFIXE_HACHAGE_JEU = "noor/v1/valsethash|";
/** Types de message des enveloppes (WireProposal, WirePrevote, WirePrecommit). */
export const TYPE_PROPOSITION = "CONS_PROPOSAL";
export const TYPE_PREVOTE = "CONS_PREVOTE";
export const TYPE_PRECOMMIT = "CONS_PRECOMMIT";
/** Valeurs de Vote.Type (VotePrevote = 1, VotePrecommit = 2). */
export const VOTE_PREVOTE = 1;
export const VOTE_PRECOMMIT = 2;
/** Ordre du groupe secp256k1 et sa moitié (secp256k1HalfN). */
export const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const MOITIE_N_SECP256K1 = N_SECP256K1 >> 1n;
/** Hachage nul (32 octets à zéro), forme d'un blockHash absent. */
export const HACHAGE_NUL = "0x" + "00".repeat(32);

const U64_MAX = (1n << 64n) - 1n;

// ---------------------------------------------------------------------------
// Octets, hexadécimal, base64
// ---------------------------------------------------------------------------

/** Octets d'une valeur : Buffer/Uint8Array tels quels, chaîne hexadécimale 0x… décodée. */
export function octets(valeur, nom = "valeur") {
  if (valeur instanceof Uint8Array) return Buffer.from(valeur);
  if (typeof valeur === "string") {
    const h = valeur.startsWith("0x") || valeur.startsWith("0X") ? valeur.slice(2) : valeur;
    if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error(`${nom} : hexadécimal invalide`);
    return Buffer.from(h, "hex");
  }
  throw new Error(`${nom} : octets ou chaîne hexadécimale attendus`);
}

/** Chaîne hexadécimale 0x… (minuscules) d'octets. */
export function hex(buf) {
  return "0x" + Buffer.from(buf).toString("hex");
}

/** Octets de longueur exacte, sinon erreur nommée. */
function octetsFixes(valeur, longueur, nom) {
  const b = octets(valeur, nom);
  if (b.length !== longueur) throw new Error(`${nom} : ${longueur} octets attendus, ${b.length} reçus`);
  return b;
}

/** Hachage de 32 octets, ou le hachage nul si la valeur est absente. */
function hachage32(valeur, nom) {
  if (valeur === undefined || valeur === null) return Buffer.alloc(32);
  return octetsFixes(valeur, 32, nom);
}

/** Entier non signé de 64 bits (nombre entier sûr, bigint ou chaîne décimale). */
export function u64(valeur, nom = "entier") {
  let n;
  if (typeof valeur === "bigint") n = valeur;
  else if (typeof valeur === "number") {
    if (!Number.isSafeInteger(valeur)) throw new Error(`${nom} : entier sûr attendu`);
    n = BigInt(valeur);
  } else if (typeof valeur === "string" && /^(0|[1-9][0-9]*)$/.test(valeur)) n = BigInt(valeur);
  else throw new Error(`${nom} : entier non signé attendu`);
  if (n < 0n || n > U64_MAX) throw new Error(`${nom} : hors de [0, 2^64)`);
  return n;
}

function u64be(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(n);
  return b;
}

function lp(b) {
  const l = Buffer.alloc(4);
  l.writeUInt32BE(b.length);
  return Buffer.concat([l, b]);
}

function utf8(s) {
  return Buffer.from(String(s), "utf8");
}

/** sha256 d'une suite d'octets, en Buffer. */
export function sha256(...parties) {
  const h = createHash("sha256");
  for (const p of parties) h.update(p);
  return h.digest();
}

/** Décodage base64 strict (alphabet standard, bourrage obligatoire, bits de bourrage nuls) : la forme que l'encodeur Go produit. */
export function base64Strict(s, nom = "base64") {
  if (typeof s !== "string" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error(`${nom} : base64 invalide`);
  const b = Buffer.from(s, "base64");
  if (b.toString("base64") !== s) throw new Error(`${nom} : base64 non canonique`);
  return b;
}

/**
 * Décodage base64 comme base64.StdEncoding en Go (ce que encoding/json applique
 * aux champs []byte) : alphabet standard, bourrage « = » obligatoire et bien
 * placé, « \r » et « \n » ignorés, bits de bourrage non nuls tolérés (les mêmes
 * octets sont rendus). Rend {octets, canonique} ; canonique est faux quand la
 * chaîne n'est pas celle que l'encodeur Go aurait écrite pour ces octets.
 */
export function base64Go(s, nom = "base64") {
  if (typeof s !== "string") throw new Error(`${nom} : chaîne base64 attendue`);
  const propre = s.replace(/[\r\n]/g, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(propre)) throw new Error(`${nom} : base64 invalide`);
  const octets = Buffer.from(propre, "base64");
  return { octets, canonique: octets.toString("base64") === s };
}

/** Comparaison d'octets en temps constant (equalConstTime). */
function egauxOctets(a, b) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a[i] ^ b[i];
  return v === 0;
}

// ---------------------------------------------------------------------------
// Digest, hachage du jeu, quorum, signatures
// ---------------------------------------------------------------------------

/**
 * Digest signé d'une enveloppe (SigningDigest). Les chaînes sont prises en
 * UTF-8 ; valsetHash et bodyHash font 32 octets ; blockHash absent vaut 32
 * octets nuls. Rend 0x… (32 octets).
 */
export function digestEnveloppe({ domain, chainId, type, validatorId, valsetHash, height, round, blockHash, bodyHash }) {
  return hex(
    sha256(
      utf8(PREFIXE_DIGEST),
      lp(utf8(domain ?? "")),
      lp(utf8(chainId ?? "")),
      lp(utf8(type ?? "")),
      lp(utf8(validatorId ?? "")),
      octetsFixes(valsetHash, 32, "valsetHash"),
      u64be(u64(height, "height")),
      u64be(u64(round, "round")),
      hachage32(blockHash, "blockHash"),
      octetsFixes(bodyHash, 32, "bodyHash"),
    ),
  );
}

/** Ordre des chaînes de Go (comparaison octet par octet en UTF-8), pour sort.Strings. */
function comparerIdsGo(a, b) {
  return Buffer.compare(utf8(a), utf8(b));
}

/**
 * Membre d'un objet JavaScript lu comme encoding/json affecte un champ Go : nom
 * plié (insensible à la casse), dernière propriété gagnante dans l'ordre des
 * propriétés. Rend la valeur, ou undefined.
 */
function proprieteGo(objet, nom) {
  const voulu = plierNomGo(nom);
  let valeur;
  for (const [k, v] of Object.entries(objet)) if (plierNomGo(k) === voulu) valeur = v;
  return valeur;
}

/** Valeur d'un champ Go de type string donnée en JavaScript : chaîne, ou absent/null (""), tout autre type refusé comme json.Unmarshal. */
function chaineGo(valeur, nom) {
  if (valeur === undefined || valeur === null) return "";
  if (typeof valeur !== "string") throw new Error(`${nom} : chaîne attendue`);
  return valeur;
}

/**
 * Entrées d'un jeu sous une forme commune [{id, pubKey (Buffer brut)}], sans
 * validation, lues comme LoadValidatorSetFile lit validators.json : membres
 * « validators », « id », « pubKeyHex » reconnus sans tenir compte de la casse,
 * identifiant et clé nettoyés par strings.TrimSpace, préfixe « 0x » (minuscule
 * seulement) retiré, hexadécimal strict. Le synonyme « validateurs » et une
 * clé déjà en octets (pubKey) sont des commodités de ce module.
 */
function entreesJeu(source) {
  let liste = source;
  if (typeof liste === "string") liste = JSON.parse(liste);
  if (liste && typeof liste === "object" && !Array.isArray(liste)) {
    const validators = proprieteGo(liste, "validators");
    if (Array.isArray(validators)) liste = validators;
    else if (Array.isArray(liste.validateurs)) liste = liste.validateurs;
  }
  if (!Array.isArray(liste)) throw new Error("jeu de validateurs : tableau ou {validators:[…]} attendu");
  return liste.map((v, i) => {
    if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error(`validator[${i}] : objet attendu`);
    const id = trimSpaceGo(chaineGo(proprieteGo(v, "id"), `validator[${i}] id`));
    let pubKey;
    if (v.pubKey instanceof Uint8Array) pubKey = Buffer.from(v.pubKey);
    else {
      let pkh = trimSpaceGo(chaineGo(proprieteGo(v, "pubKeyHex") ?? v.pubKey, `validator[${i}] pubKeyHex`));
      if (pkh.startsWith("0x")) pkh = pkh.slice(2);
      if (pkh.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(pkh)) throw new Error(`validator[${i}] pubKeyHex : hexadécimal invalide`);
      pubKey = Buffer.from(pkh, "hex");
    }
    return { id, pubKey };
  });
}

/**
 * Hachage du jeu de validateurs (ValidatorSetHash) : identifiants triés à la
 * Go, chacun suivi d'un octet nul, puis la clé publique BRUTE telle que
 * déclarée (sans normalisation) suivie d'un octet nul. Accepte un tableau
 * [{id, pubKeyHex}], un objet {validators:[…]} (le fichier validators.json)
 * ou le résultat de chargerJeuValidateurs. Rend 0x… (32 octets).
 */
export function hachageJeuValidateurs(source) {
  const entrees = entreesJeu(source?.validateurs ?? source);
  const ids = entrees.map((e) => e.id).sort(comparerIdsGo);
  const parId = new Map();
  for (const e of entrees) parId.set(e.id, e.pubKey); // comme la map Go : la dernière clé d'un id gagne
  const parties = [utf8(PREFIXE_HACHAGE_JEU)];
  for (const id of ids) parties.push(utf8(id), Buffer.from([0]), parId.get(id), Buffer.from([0]));
  return hex(sha256(...parties));
}

/** Seuil de votes d'un jeu de taille n (Quorum2f1) : floor((n + f) / 2) + 1, f = floor((n - 1) / 3). */
export function quorum(n) {
  if (!Number.isInteger(n)) throw new Error("quorum : entier attendu");
  if (n <= 0) return 0;
  const f = Math.floor((n - 1) / 3);
  return Math.floor((n + f) / 2) + 1;
}

/**
 * Forme canonique d'une signature [R || S || V] de 65 octets (isCanonicalLowS) :
 * R dans [1, N), S dans [1, N/2], V dans {0, 1}. Rend un booléen.
 */
export function signatureCanonique(sig) {
  let b;
  try {
    b = octets(sig, "signature");
  } catch {
    return false;
  }
  if (b.length !== 65 || b[64] > 1) return false;
  const r = BigInt(hex(b.subarray(0, 32)));
  const s = BigInt(hex(b.subarray(32, 64)));
  if (r === 0n || r >= N_SECP256K1) return false;
  if (s === 0n || s > MOITIE_N_SECP256K1) return false;
  return true;
}

/**
 * Clé publique (non compressée, 0x04…, 65 octets) qui a produit la signature
 * sig65 sur digest (RecoverPubKey, précédé du contrôle de forme canonique de
 * VerifySignature). Le V de noorcore vaut 0 ou 1 ; ethers attend 27 ou 28.
 */
export function recupererClePublique(digest, sig65) {
  const d = octetsFixes(digest, 32, "digest");
  const b = octets(sig65, "signature");
  if (b.length !== 65) throw new Error(`signature : 65 octets attendus, ${b.length} reçus`);
  if (!signatureCanonique(b)) throw new Error("signature non canonique (S bas et V dans {0, 1} exigés)");
  const cle = SigningKey.recoverPublicKey(hex(d), { r: hex(b.subarray(0, 32)), s: hex(b.subarray(32, 64)), v: 27 + b[64] });
  return cle.toLowerCase();
}

/**
 * Forme non compressée 0x04 || X || Y (65 octets) d'une clé publique donnée
 * en 65 octets (préfixe 0x04 exigé), 64 octets (X || Y) ou 33 octets
 * compressés (normalizeUncompressedPubKey). Rend 0x… en minuscules.
 */
export function normaliserClePublique(pub) {
  const b = octets(pub, "clé publique");
  switch (b.length) {
    case 65:
      if (b[0] !== 0x04) throw new Error("clé publique : préfixe 0x04 attendu sur une clé de 65 octets");
      return hex(b);
    case 64:
      return hex(Buffer.concat([Buffer.from([0x04]), b]));
    case 33:
      return SigningKey.computePublicKey(hex(b), false).toLowerCase();
    default:
      throw new Error(`clé publique : longueur ${b.length} non prise en charge`);
  }
}

/**
 * Charge un jeu de validateurs comme LoadValidatorSetFile : identifiants et
 * clés nettoyés, hexadécimal strict, jeu non vide, identifiants non vides et
 * uniques, clé non vide et exploitable pour chacun, aucune clé partagée (après
 * normalisation), tri par identifiant. Accepte le contenu de validators.json
 * (objet, tableau ou texte JSON). Rend {validateurs:[{id, pubKey, cle}],
 * taille, quorum, hachage} où cle est la forme 0x04… et pubKey les octets bruts.
 */
export function chargerJeuValidateurs(source) {
  const entrees = entreesJeu(source);
  if (entrees.length === 0) throw new Error("jeu de validateurs vide");
  const ids = new Set();
  const cles = new Map();
  const validateurs = [];
  for (const e of entrees) {
    if (e.id === "") throw new Error("identifiant de validateur vide");
    if (ids.has(e.id)) throw new Error(`identifiant de validateur en double : ${e.id}`);
    ids.add(e.id);
    if (e.pubKey.length === 0) throw new Error(`validateur ${e.id} : clé publique vide`);
    let cle;
    try {
      cle = normaliserClePublique(e.pubKey);
    } catch (err) {
      throw new Error(`validateur ${e.id} : clé publique inexploitable (${err.message})`);
    }
    if (cles.has(cle)) throw new Error(`validateurs ${cles.get(cle)} et ${e.id} : même clé publique`);
    cles.set(cle, e.id);
    validateurs.push({ id: e.id, pubKey: e.pubKey, cle });
  }
  validateurs.sort((a, b) => comparerIdsGo(a.id, b.id));
  return { validateurs, taille: validateurs.length, quorum: quorum(validateurs.length), hachage: hachageJeuValidateurs(validateurs) };
}

// ---------------------------------------------------------------------------
// Lecture d'une ligne brute : découpage exact des membres de l'objet JSON
// ---------------------------------------------------------------------------

/**
 * Pliage d'un nom de membre JSON comme encoding/json (foldName) : les lettres
 * ASCII sont ramenées en majuscules, et les deux caractères non ASCII dont
 * l'orbite de pliage simple contient une lettre ASCII, « ſ » (U+017F) et le
 * signe Kelvin « K » (U+212A), sont ramenés à « S » et « K ». Deux noms qui se
 * plient pareil désignent le même champ Go.
 */
export function plierNomGo(nom) {
  let out = "";
  for (const c of String(nom)) {
    if (c === "\u017f") out += "S";
    else if (c === "\u212a") out += "K";
    else if (c >= "a" && c <= "z") out += c.toUpperCase();
    else out += c;
  }
  return out;
}

/**
 * Membres de premier niveau d'un objet JSON, dans l'ordre du texte, avec pour
 * chacun le texte BRUT de sa valeur : tableau de {cle, brut}. Erreur si le
 * texte n'est pas exactement un objet JSON.
 */
export function decouperMembres(texte) {
  if (typeof texte !== "string") throw new Error("ligne : chaîne attendue");
  let i = 0;
  const n = texte.length;
  const blancs = () => {
    while (i < n && (texte[i] === " " || texte[i] === "\t" || texte[i] === "\n" || texte[i] === "\r")) i++;
  };
  const chaine = () => {
    // i est sur le guillemet ouvrant ; rend la chaîne décodée, i après le guillemet fermant.
    const debut = i;
    i++;
    while (i < n) {
      const c = texte[i];
      if (c === "\\") i += 2;
      else if (c === '"') {
        i++;
        return JSON.parse(texte.slice(debut, i));
      } else i++;
    }
    throw new Error("ligne : chaîne JSON non terminée");
  };
  const valeur = () => {
    // i est sur le premier caractère d'une valeur ; avance i juste après elle.
    const c = texte[i];
    if (c === '"') {
      chaine();
      return;
    }
    if (c === "{" || c === "[") {
      let profondeur = 0;
      while (i < n) {
        const d = texte[i];
        if (d === '"') chaine();
        else {
          if (d === "{" || d === "[") profondeur++;
          else if (d === "}" || d === "]") profondeur--;
          i++;
          if (profondeur === 0) return;
        }
      }
      throw new Error("ligne : objet ou tableau JSON non terminé");
    }
    const m = /^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(texte.slice(i, i + 64));
    if (!m) throw new Error(`ligne : valeur JSON inattendue à la position ${i}`);
    i += m[0].length;
  };

  blancs();
  if (texte[i] !== "{") throw new Error("ligne : objet JSON attendu");
  i++;
  const membres = [];
  blancs();
  if (texte[i] === "}") i++;
  else {
    for (;;) {
      blancs();
      if (texte[i] !== '"') throw new Error(`ligne : clé attendue à la position ${i}`);
      const cle = chaine();
      blancs();
      if (texte[i] !== ":") throw new Error(`ligne : « : » attendu à la position ${i}`);
      i++;
      blancs();
      const debut = i;
      valeur();
      membres.push({ cle, brut: texte.slice(debut, i) });
      blancs();
      if (texte[i] === ",") {
        i++;
        continue;
      }
      if (texte[i] === "}") {
        i++;
        break;
      }
      throw new Error(`ligne : « , » ou « } » attendu à la position ${i}`);
    }
  }
  blancs();
  if (i !== n) throw new Error("ligne : texte après la fin de l'objet JSON");
  // Le découpage doit coïncider avec une analyse complète ; sinon la ligne est refusée.
  JSON.parse(texte);
  return membres;
}

/**
 * Membres de premier niveau d'un objet JSON (Map clé exacte -> texte brut de la
 * valeur). C'est ce que fait json.RawMessage en Go : le corps est haché sur ses
 * octets d'origine, jamais sur une re-sérialisation. En cas de clé répétée, la
 * dernière occurrence gagne (comme JSON.parse et Go).
 */
export function membresBruts(texte) {
  const membres = new Map();
  for (const { cle, brut } of decouperMembres(texte)) membres.set(cle, brut);
  return membres;
}

/**
 * Membres d'un objet JSON vus comme encoding/json les affecte à une structure
 * Go : Map nom plié (plierNomGo) -> {brut, cle}, la dernière occurrence d'un
 * même nom plié gagnant dans l'ordre du texte. `cle` garde la graphie exacte
 * rencontrée, pour signaler une forme non canonique.
 */
export function membresBrutsGo(texte) {
  const membres = new Map();
  for (const { cle, brut } of decouperMembres(texte)) membres.set(plierNomGo(cle), { brut, cle });
  return membres;
}

/** Membre d'une Map de membresBrutsGo par son nom Go ; rend {brut, cle} ou undefined. */
function membreGo(m, nom) {
  return m.get(plierNomGo(nom));
}

/** Entier u64 lu dans le texte brut d'une valeur JSON (littéral entier canonique seulement). */
function u64Brut(brut, nom) {
  if (brut === undefined) throw new Error(`${nom} : absent`);
  if (!/^(0|[1-9][0-9]*)$/.test(brut)) throw new Error(`${nom} : entier non signé attendu`);
  return u64(brut, nom);
}

/** Entier u64 d'un champ de corps Go : absent ou null vaut 0 (valeur zéro du champ), sinon littéral entier canonique. */
function u64BrutOuZero(brut, nom) {
  if (brut === undefined || brut === "null") return 0n;
  return u64Brut(brut, nom);
}

/** Chaîne d'un champ Go de type string : absent ou null vaut "", sinon une chaîne JSON. */
function chaineBruteOuVide(brut, nom) {
  if (brut === undefined || brut === "null") return "";
  return chaineBrute(brut, nom);
}

function chaineBrute(brut, nom) {
  if (brut === undefined) throw new Error(`${nom} : absent`);
  const v = JSON.parse(brut);
  if (typeof v !== "string") throw new Error(`${nom} : chaîne attendue`);
  return v;
}

/** Champ []byte Go lu dans le texte brut : absent ou null vaut null (nil), sinon base64 à la Go ; note une forme non canonique. */
function base64Brut(brut, nom, remarques, obligatoire = true) {
  if (brut === undefined || brut === "null") {
    if (obligatoire) throw new Error(`${nom} : absent`);
    return null;
  }
  const { octets, canonique } = base64Go(chaineBrute(brut, nom), nom);
  if (!canonique) remarques.push(`base64 non canonique pour « ${nom} »`);
  return octets;
}

/** Note dans `remarques` les membres dont la graphie n'est pas celle de l'encodeur Go. */
function noterGraphies(m, noms, remarques) {
  for (const nom of noms) {
    const membre = membreGo(m, nom);
    if (membre && membre.cle !== nom) remarques.push(`membre « ${membre.cle} » pour « ${nom} »`);
  }
}

const MEMBRES_ENVELOPPE = ["domain", "chainId", "type", "validatorId", "valsetHash", "height", "round", "blockHash", "bodyHash", "body", "sig"];

/**
 * Analyse une ligne brute d'enveloppe signée (SignedEnvelope en JSON) sans
 * rien lui faire confiance, et comme le décodeur du nœud la lirait : noms de
 * membres pliés (dernière occurrence gagnante), champs []byte en base64 à la
 * Go, entiers lus dans le texte brut, corps conservé en octets d'origine.
 * Rend {domain, chainId, type, validatorId, valsetHash, height, round,
 * blockHash (null si absent), bodyHash, corpsBrut, sig, remarques} ; erreur
 * descriptive sinon. `remarques` liste les formes non canoniques acceptées.
 */
export function analyserEnveloppe(ligne) {
  const m = membresBrutsGo(ligne);
  const remarques = [];
  const brut = (nom) => membreGo(m, nom)?.brut;
  const env = {
    domain: chaineBruteOuVide(brut("domain"), "domain"),
    chainId: chaineBruteOuVide(brut("chainId"), "chainId"),
    type: chaineBruteOuVide(brut("type"), "type"),
    validatorId: chaineBruteOuVide(brut("validatorId"), "validatorId"),
    valsetHash: base64Brut(brut("valsetHash"), "valsetHash", remarques),
    height: u64BrutOuZero(brut("height"), "height"),
    round: u64BrutOuZero(brut("round"), "round"),
    blockHash: base64Brut(brut("blockHash"), "blockHash", remarques, false),
    bodyHash: base64Brut(brut("bodyHash"), "bodyHash", remarques),
    corpsBrut: brut("body"),
    sig: base64Brut(brut("sig"), "sig", remarques),
    remarques,
  };
  if (env.corpsBrut === undefined) throw new Error("body : absent");
  noterGraphies(m, MEMBRES_ENVELOPPE, remarques);
  return env;
}

/**
 * Hachage de 32 octets lu dans le texte brut d'un champ common.Hash d'un corps :
 * chaîne JSON « 0x » ou « 0X » suivie de 64 chiffres hexadécimaux
 * (hexutil.UnmarshalFixedJSON) ; absent ou null vaut le hachage nul (valeur
 * zéro) — null est en fait refusé par Go (non-string), ce que l'on reproduit.
 */
function hachageCorpsBrut(brut, nom, remarques) {
  if (brut === undefined) return Buffer.alloc(32);
  if (brut === "null") throw new Error(`${nom} : null n'est pas un hachage`);
  const valeur = chaineBrute(brut, nom);
  if (!/^0[xX][0-9a-fA-F]{64}$/.test(valeur)) throw new Error(`${nom} : hachage 0x… de 32 octets attendu`);
  if (valeur[1] === "X" || /[A-F]/.test(valeur)) remarques.push(`hachage non canonique pour « ${nom} »`);
  return Buffer.from(valeur.slice(2), "hex");
}

/** Vérifie qu'un champ brut a le type que le décodeur Go exige ; lève sinon. `type` : "u64", "hash", "string", "bytes", "strings", "bytesList". */
function typerChampGo(brut, nom, type, remarques) {
  if (brut === undefined || brut === "null") return;
  switch (type) {
    case "u64":
      u64Brut(brut, nom);
      return;
    case "hash":
      hachageCorpsBrut(brut, nom, remarques);
      return;
    case "string":
      chaineBrute(brut, nom);
      return;
    case "bytes":
      base64Go(chaineBrute(brut, nom), nom);
      return;
    case "strings":
    case "bytesList": {
      const v = JSON.parse(brut);
      if (!Array.isArray(v)) throw new Error(`${nom} : tableau attendu`);
      for (const e of v) {
        if (typeof e !== "string") throw new Error(`${nom} : tableau de chaînes attendu`);
        if (type === "bytesList") base64Go(e, nom);
      }
      return;
    }
    default:
      throw new Error(`${nom} : type inconnu`);
  }
}

/** Les champs d'une Proposal Go (types.go) et leur type JSON, pour refuser ce que json.Unmarshal refuserait. */
const CHAMPS_PROPOSITION = {
  height: "u64", round: "u64", proposer: "string", blockHash: "hash", parentHash: "hash", timestamp: "u64",
  stateRoot: "hash", receiptsRoot: "hash", txRoot: "hash", gasUsed: "u64", gasLimit: "u64", baseFeeHex: "string",
  txsRaw: "bytesList", polkaRound: "u64", polkaLines: "strings", sig: "bytes",
};
/** Les champs d'un Vote Go (types.go). */
const CHAMPS_VOTE = { Height: "u64", Round: "u64", Voter: "string", Type: "u64", BlockHash: "hash", Sig: "bytes" };

/** Vide au sens de strings.TrimSpace (unicode.White_Space : U+0085 inclus, U+FEFF exclu). */
const BLANCS_GO = "[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";
const RE_TRIM_GO = new RegExp(`^${BLANCS_GO}+|${BLANCS_GO}+$`, "g");

/** strings.TrimSpace de Go : même jeu de caractères blancs (différent de String.prototype.trim sur U+0085 et U+FEFF). */
export function trimSpaceGo(s) {
  return String(s).replace(RE_TRIM_GO, "");
}

// ---------------------------------------------------------------------------
// Vérification d'une enveloppe contre les attentes d'un certificat
// ---------------------------------------------------------------------------

/**
 * Vérifie une ligne brute d'enveloppe contre les attentes `att` :
 * {type, chainId, valsetHash (Buffer), hauteur (bigint), ronde (bigint),
 * blockHash (Buffer), jeu (chargerJeuValidateurs)}. Reprend les contrôles de
 * VerifyEnvelope dans leur ordre, puis lie le corps au certificat : pour un
 * precommit, Vote de type 2 avec mêmes hauteur, tour et bloc, Voter égal au
 * validatorId ; pour une proposition, Proposal avec mêmes hauteur, tour et
 * bloc, proposer égal au validatorId. Les formes non canoniques que le
 * décodeur du nœud accepte sont acceptées et listées dans `remarques`.
 * Rend {ok, detail, validatorId, cle, remarques}.
 */
export function verifierLigne(ligne, att) {
  const echec = (detail, validatorId = null) => ({ ok: false, detail, validatorId, cle: null, remarques: [] });
  let env;
  try {
    env = analyserEnveloppe(ligne);
  } catch (err) {
    return echec(`enveloppe illisible : ${err.message}`);
  }
  const qui = env.validatorId;
  if (env.domain !== DOMAINE_SIGNATURE) return echec(`domaine « ${env.domain} » au lieu de « ${DOMAINE_SIGNATURE} »`, qui);
  if (env.chainId !== att.chainId) return echec(`chainId « ${env.chainId} » au lieu de « ${att.chainId} »`, qui);
  if (env.type !== att.type) return echec(`type « ${env.type} » au lieu de « ${att.type} »`, qui);
  if (env.valsetHash.length !== 32) return echec(`valsetHash de ${env.valsetHash.length} octets`, qui);
  if (!egauxOctets(env.valsetHash, att.valsetHash)) return echec(`valsetHash ${hex(env.valsetHash)} différent de celui du certificat`, qui);
  const validateur = att.jeu.validateurs.find((v) => v.id === qui);
  if (!validateur) return echec(`validateur « ${qui} » absent du jeu fourni`, qui);
  if (env.bodyHash.length !== 32) return echec(`bodyHash de ${env.bodyHash.length} octets`, qui);
  const bodyHash = sha256(utf8(env.corpsBrut));
  if (!egauxOctets(env.bodyHash, bodyHash)) return echec(`bodyHash déclaré ${hex(env.bodyHash)} ≠ sha256(corps) ${hex(bodyHash)}`, qui);
  if (env.height !== att.hauteur) return echec(`hauteur ${env.height} au lieu de ${att.hauteur}`, qui);
  if (env.round !== att.ronde) return echec(`tour ${env.round} au lieu de ${att.ronde}`, qui);

  // Le corps est relu dans son texte brut, comme json.Unmarshal le lit dans
  // Vote ou Proposal : noms pliés, entiers littéraux (bigint), valeur zéro
  // pour un champ absent ou null, types vérifiés pour tous les champs connus.
  let corps;
  try {
    corps = membresBrutsGo(env.corpsBrut);
  } catch (err) {
    return echec(`corps illisible : ${err.message.replace(/^ligne : /, "")}`, qui);
  }
  const remarques = [...env.remarques];
  const champ = (nom) => membreGo(corps, nom)?.brut;
  let hachageCorpsBloc;
  try {
    if (att.type === TYPE_PRECOMMIT || att.type === TYPE_PREVOTE) {
      for (const [nom, type] of Object.entries(CHAMPS_VOTE)) typerChampGo(champ(nom), `Vote.${nom}`, type, []);
      noterGraphies(corps, Object.keys(CHAMPS_VOTE), remarques);
      const hauteur = u64BrutOuZero(champ("Height"), "Vote.Height");
      if (hauteur !== att.hauteur) return echec(`Vote.Height ${hauteur} au lieu de ${att.hauteur}`, qui);
      const ronde = u64BrutOuZero(champ("Round"), "Vote.Round");
      if (ronde !== att.ronde) return echec(`Vote.Round ${ronde} au lieu de ${att.ronde}`, qui);
      // Vote.Type : un uint8 pour le décodeur, non comparé au type de l'enveloppe
      // (le dispatcher du nœud remplace la valeur par celle de l'enveloppe).
      const typeAttendu = att.type === TYPE_PRECOMMIT ? VOTE_PRECOMMIT : VOTE_PREVOTE;
      const typeCorps = u64BrutOuZero(champ("Type"), "Vote.Type");
      if (typeCorps > 255n) throw new Error("Vote.Type : uint8 attendu");
      if (champ("Type") === undefined || champ("Type") === "null") remarques.push("Vote.Type absent");
      else if (typeCorps !== BigInt(typeAttendu)) remarques.push(`Vote.Type ${typeCorps} sous une enveloppe ${att.type}`);
      // Voter : vide, c'est le signataire (dispatcher) ; présent, il doit lui être égal.
      const voter = chaineBruteOuVide(champ("Voter"), "Vote.Voter");
      if (voter === "") remarques.push("Vote.Voter vide");
      else if (voter !== qui) return echec(`Vote.Voter « ${voter} » différent du signataire « ${qui} »`, qui);
      hachageCorpsBloc = hachageCorpsBrut(champ("BlockHash"), "Vote.BlockHash", remarques);
    } else if (att.type === TYPE_PROPOSITION) {
      for (const [nom, type] of Object.entries(CHAMPS_PROPOSITION)) typerChampGo(champ(nom), `Proposal.${nom}`, type, []);
      noterGraphies(corps, Object.keys(CHAMPS_PROPOSITION), remarques);
      const hauteur = u64BrutOuZero(champ("height"), "Proposal.height");
      if (hauteur !== att.hauteur) return echec(`Proposal.height ${hauteur} au lieu de ${att.hauteur}`, qui);
      const ronde = u64BrutOuZero(champ("round"), "Proposal.round");
      if (ronde !== att.ronde) return echec(`Proposal.round ${ronde} au lieu de ${att.ronde}`, qui);
      // proposer : vide après TrimSpace, c'est le signataire (signing.go) ; sinon égal à lui.
      const proposer = chaineBruteOuVide(champ("proposer"), "Proposal.proposer");
      if (trimSpaceGo(proposer) === "") remarques.push("Proposal.proposer vide");
      else if (proposer !== qui) return echec(`Proposal.proposer « ${proposer} » différent du signataire « ${qui} »`, qui);
      hachageCorpsBloc = hachageCorpsBrut(champ("blockHash"), "Proposal.blockHash", remarques);
    } else {
      return echec(`type attendu inconnu « ${att.type} »`, qui);
    }
  } catch (err) {
    return echec(`corps : ${err.message}`, qui);
  }
  if (!egauxOctets(hachageCorpsBloc, att.blockHash)) return echec(`bloc du corps ${hex(hachageCorpsBloc)} différent du certificat ${hex(att.blockHash)}`, qui);
  if (env.blockHash === null) return echec("blockHash absent de l'enveloppe (vote nul ?) alors que le certificat désigne un bloc", qui);
  if (env.blockHash.length !== 32) return echec(`blockHash d'enveloppe de ${env.blockHash.length} octets`, qui);
  if (!egauxOctets(env.blockHash, att.blockHash)) return echec(`blockHash d'enveloppe ${hex(env.blockHash)} différent du certificat`, qui);

  const digest = digestEnveloppe({
    domain: env.domain,
    chainId: env.chainId,
    type: env.type,
    validatorId: env.validatorId,
    valsetHash: env.valsetHash,
    height: env.height,
    round: env.round,
    blockHash: env.blockHash,
    bodyHash,
  });
  if (env.sig.length !== 65) return echec(`signature de ${env.sig.length} octets`, qui);
  if (!signatureCanonique(env.sig)) return echec("signature non canonique (S haut ou V hors {0, 1})", qui);
  let cle;
  try {
    cle = recupererClePublique(digest, env.sig);
  } catch (err) {
    return echec(`recouvrement de la clé impossible : ${err.message}`, qui);
  }
  if (cle !== validateur.cle) return echec(`la signature recouvre ${cle}, pas la clé de « ${qui} » (${validateur.cle})`, qui);
  const detail = `signé par « ${qui} » (${cle.slice(0, 14)}…), digest ${digest}${remarques.length ? ` ; forme non canonique acceptée comme par le nœud : ${remarques.join(", ")}` : ""}`;
  return { ok: true, detail, validatorId: qui, cle, remarques };
}

// ---------------------------------------------------------------------------
// Certificat : normalisation de l'entrée et vérification complète
// ---------------------------------------------------------------------------

/**
 * Ramène une entrée à la forme du certificat. Entrées acceptées :
 *   - le résultat de noor_getCommitCertificate (core/rpc/commit_certificate.go) :
 *     {height: "0x207c", round: "0x0", chainId, valsetHash, blockHash,
 *      proposal: {line, …}, precommits: [{line, …}], …} ; seules les LIGNES
 *     brutes sont retenues, les champs décodés à côté (validatorId, bodyHash,
 *     sig), le jeu annoncé (validatorSet) et le verdict du nœud (canonical)
 *     sont ignorés : rien n'est cru du nœud ;
 *   - la réponse JSON-RPC complète qui l'enveloppe ({jsonrpc, id, result}) ;
 *   - l'objet DecidedCert tel que le nœud le stocke ({chainId, valsetHash, h,
 *     r, hash, prop, cmts}) et ses synonymes longs.
 * Rend {chainId, valsetHash, h, r, hash, prop, cmts} sans rien vérifier d'autre
 * que la présence des champs ; erreur si l'entrée n'est pas un certificat.
 */
export function normaliserCertificat(entree) {
  let c = entree;
  if (typeof c === "string") c = JSON.parse(c);
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error("certificat : objet JSON attendu");
  if ("jsonrpc" in c || ("result" in c && !("prop" in c))) {
    if (c.error) throw new Error(`réponse JSON-RPC en erreur : ${c.error.message ?? JSON.stringify(c.error)}`);
    c = c.result;
  }
  if (c && typeof c === "object") {
    for (const k of ["certificate", "certificat", "cert"]) if (c[k] && typeof c[k] === "object" && !("prop" in c)) c = c[k];
  }
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error("certificat : absent (le nœud n'a pas de certificat pour ce bloc ?)");
  const prendre = (...noms) => {
    for (const n of noms) if (c[n] !== undefined) return c[n];
    return undefined;
  };
  const ligneDe = (v) => (v && typeof v === "object" && !Array.isArray(v) && "line" in v ? v.line : v);
  const cmts = prendre("cmts", "commitLines", "precommits");
  const sortie = {
    chainId: prendre("chainId"),
    valsetHash: prendre("valsetHash"),
    h: prendre("h", "height", "hauteur"),
    r: prendre("r", "round", "ronde"),
    hash: prendre("hash", "blockHash"),
    prop: ligneDe(prendre("prop", "propLine", "proposal", "proposition")),
    cmts: Array.isArray(cmts) ? cmts.map(ligneDe) : cmts,
  };
  if (sortie.prop === undefined && sortie.cmts === undefined && sortie.h === undefined) {
    throw new Error("certificat : aucun des champs attendus (prop, cmts, h) n'est présent");
  }
  return sortie;
}

/** Entier d'un champ du certificat : nombre, chaîne décimale ou quantité hexadécimale 0x… (forme des réponses RPC). */
export function entierCertificat(valeur, nom = "entier") {
  if (typeof valeur === "string" && /^0[xX][0-9a-fA-F]+$/.test(valeur)) {
    const n = BigInt(valeur);
    if (n > U64_MAX) throw new Error(`${nom} : hors de [0, 2^64)`);
    return n;
  }
  return u64(valeur, nom);
}

/** Entier en sortie : nombre si sûr, sinon chaîne décimale (pour JSON.stringify). */
function entierSortie(n) {
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString();
}

/**
 * Vérifie un certificat de commit contre un jeu de validateurs FOURNI.
 *
 * `certificat` : sortie de noor_getCommitCertificate ou DecidedCert (voir
 * normaliserCertificat). `validators` : contenu de validators.json ou résultat
 * de chargerJeuValidateurs. `options` : {blockHashCanonique} ajoute le
 * contrôle « bloc_canonique » (hachage lu par eth_getBlockByNumber) ;
 * {chainIdAttendu}, {hauteurAttendue} et {blockHashAttendu} ajoutent
 * « chaine », « hauteur » et « bloc_demande » (ce que l'appelant a demandé).
 *
 * Rend {valide, controles:[{nom, ok, detail, …}], signataires, quorum,
 * tailleJeu, chainId, hauteur, ronde, blockHash, valsetHash, proposant}.
 * `valide` n'est vrai que si TOUS les contrôles passent : chaque ligne doit
 * être une enveloppe valide (un certificat écrit par le nœud n'en contient
 * pas d'autre), les signataires des precommits doivent être distincts et au
 * moins aussi nombreux que le quorum du jeu.
 */
export function verifierCertificat(certificat, validators, options = {}) {
  const controles = [];
  const resultat = { valide: false, controles, signataires: [], quorum: null, tailleJeu: null, chainId: null, hauteur: null, ronde: null, blockHash: null, valsetHash: null, proposant: null };
  const noter = (nom, ok, detail, extra = {}) => {
    controles.push({ nom, ok, detail, ...extra });
    return ok;
  };
  const conclure = () => {
    resultat.valide = controles.length > 0 && controles.every((c) => c.ok);
    return resultat;
  };

  // 1. Structure du certificat.
  let c;
  try {
    c = normaliserCertificat(certificat);
    if (typeof c.chainId !== "string" || c.chainId.trim() === "") throw new Error("chainId absent ou vide");
    c.hauteur = entierCertificat(c.h, "hauteur (h)");
    if (c.hauteur === 0n) throw new Error("hauteur 0 : la genèse n'est jamais décidée par le BFT");
    c.ronde = entierCertificat(c.r, "tour (r)");
    if (typeof c.valsetHash !== "string") throw new Error("valsetHash absent");
    c.valsetHashOctets = octetsFixes(c.valsetHash, 32, "valsetHash");
    if (typeof c.hash !== "string") throw new Error("hash (bloc) absent");
    c.blockHashOctets = octetsFixes(c.hash, 32, "hash (bloc)");
    if (c.blockHashOctets.every((o) => o === 0)) throw new Error("hash (bloc) nul");
    if (typeof c.prop !== "string" || c.prop === "") throw new Error("prop (ligne de la proposition) absente ou vide");
    if (!Array.isArray(c.cmts) || c.cmts.length === 0) throw new Error("cmts (lignes de precommit) absentes ou vides");
    c.cmts.forEach((l, i) => {
      if (typeof l !== "string" || l === "") throw new Error(`cmts[${i}] : ligne vide ou non textuelle`);
    });
  } catch (err) {
    noter("structure", false, err.message);
    return conclure();
  }
  resultat.chainId = c.chainId;
  resultat.hauteur = entierSortie(c.hauteur);
  resultat.ronde = entierSortie(c.ronde);
  resultat.blockHash = hex(c.blockHashOctets);
  resultat.valsetHash = hex(c.valsetHashOctets);
  noter("structure", true, `chaîne « ${c.chainId} », hauteur ${c.hauteur}, tour ${c.ronde}, bloc ${resultat.blockHash}, ${c.cmts.length} ligne(s) de precommit`);

  // 2. Jeu de validateurs fourni.
  let jeu;
  try {
    jeu = validators && Array.isArray(validators.validateurs) && validators.hachage ? validators : chargerJeuValidateurs(validators);
  } catch (err) {
    noter("jeu_validateurs", false, `jeu fourni inexploitable : ${err.message}`);
    return conclure();
  }
  resultat.tailleJeu = jeu.taille;
  resultat.quorum = jeu.quorum;
  noter("jeu_validateurs", true, `${jeu.taille} validateur(s) : ${jeu.validateurs.map((v) => v.id).join(", ")} ; quorum ${jeu.quorum}`);

  // 3. Le certificat désigne bien ce jeu.
  if (!noter("hachage_jeu", jeu.hachage === resultat.valsetHash, jeu.hachage === resultat.valsetHash ? `valsetHash ${jeu.hachage} = hachage du jeu fourni` : `valsetHash du certificat ${resultat.valsetHash} ≠ hachage du jeu fourni ${jeu.hachage}`)) {
    return conclure();
  }

  // 4. Attentes optionnelles de l'appelant.
  if (options.chainIdAttendu !== undefined) {
    const ok = c.chainId === String(options.chainIdAttendu);
    noter("chaine", ok, ok ? `chaîne « ${c.chainId} » attendue` : `chaîne « ${c.chainId} » au lieu de « ${options.chainIdAttendu} »`);
  }
  if (options.hauteurAttendue !== undefined) {
    let ok = false;
    let attendue = String(options.hauteurAttendue);
    try {
      attendue = u64(options.hauteurAttendue, "hauteur attendue");
      ok = attendue === c.hauteur;
    } catch {
      ok = false;
    }
    noter("hauteur", ok, ok ? `hauteur ${c.hauteur} attendue` : `hauteur ${c.hauteur} au lieu de ${attendue}`);
  }
  if (options.blockHashAttendu !== undefined) {
    let ok = false;
    let attendu = String(options.blockHashAttendu);
    try {
      attendu = hex(octetsFixes(options.blockHashAttendu, 32, "bloc demandé"));
      ok = attendu === resultat.blockHash;
    } catch {
      ok = false;
    }
    noter("bloc_demande", ok, ok ? `bloc ${resultat.blockHash} demandé` : `bloc du certificat ${resultat.blockHash} ≠ bloc demandé ${attendu}`);
  }
  if (options.blockHashCanonique !== undefined) {
    let ok = false;
    let canon = String(options.blockHashCanonique);
    try {
      canon = hex(octetsFixes(options.blockHashCanonique, 32, "bloc canonique"));
      ok = canon === resultat.blockHash;
    } catch {
      ok = false;
    }
    noter("bloc_canonique", ok, ok ? `bloc ${resultat.blockHash} = bloc canonique de la hauteur ${c.hauteur}` : `bloc du certificat ${resultat.blockHash} ≠ bloc canonique ${canon}`);
  }

  // 5. La proposition du tour décidé.
  const commun = { chainId: c.chainId, valsetHash: c.valsetHashOctets, hauteur: c.hauteur, ronde: c.ronde, blockHash: c.blockHashOctets, jeu };
  const prop = verifierLigne(c.prop, { ...commun, type: TYPE_PROPOSITION });
  noter("proposition", prop.ok, prop.detail, { validatorId: prop.validatorId, ...(prop.remarques.length ? { remarques: prop.remarques } : {}) });
  if (prop.ok) resultat.proposant = prop.validatorId;

  // 6. Chaque precommit, puis distinction des signataires et quorum.
  const signataires = [];
  const vus = new Map();
  const doublons = [];
  c.cmts.forEach((ligne, i) => {
    const r = verifierLigne(ligne, { ...commun, type: TYPE_PRECOMMIT });
    noter("precommit", r.ok, r.detail, { indice: i + 1, validatorId: r.validatorId, ...(r.remarques.length ? { remarques: r.remarques } : {}) });
    if (!r.ok) return;
    if (vus.has(r.validatorId)) doublons.push(`« ${r.validatorId} » (lignes ${vus.get(r.validatorId)} et ${i + 1})`);
    else {
      vus.set(r.validatorId, i + 1);
      signataires.push(r.validatorId);
    }
  });
  signataires.sort(comparerIdsGo);
  resultat.signataires = signataires;
  noter("signataires_distincts", doublons.length === 0, doublons.length === 0 ? `${signataires.length} signataire(s) distinct(s) : ${signataires.join(", ") || "aucun"}` : `signataire(s) en double : ${doublons.join(" ; ")}`);
  const okQuorum = signataires.length >= jeu.quorum;
  noter("quorum", okQuorum, `${signataires.length} signataire(s) distinct(s) valide(s) pour un quorum de ${jeu.quorum} sur ${jeu.taille}${okQuorum ? "" : " : insuffisant"}`);
  return conclure();
}

// ---------------------------------------------------------------------------
// Construction d'enveloppes au format exact du nœud (tests et vecteurs)
// ---------------------------------------------------------------------------

/** Chaîne JSON à la manière de l'encodeur Go : <, >, & et U+2028/2029 échappés. */
export function chaineJSONGo(s) {
  return JSON.stringify(String(s))
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(new RegExp(String.fromCharCode(0x2028), "g"), "\\u2028")
    .replace(new RegExp(String.fromCharCode(0x2029), "g"), "\\u2029");
}

const hachageJSON = (h) => chaineJSONGo(hex(hachage32(h, "hachage")));

/**
 * Corps JSON d'un Vote tel que json.Marshal(consensus.Vote) le produit :
 * {"Height":…,"Round":…,"Voter":"…","Type":…,"BlockHash":"0x…","Sig":null}.
 */
export function encoderVote({ height, round, voter, type, blockHash }) {
  return `{"Height":${u64(height, "height")},"Round":${u64(round, "round")},"Voter":${chaineJSONGo(voter ?? "")},"Type":${type ?? 0},"BlockHash":${hachageJSON(blockHash)},"Sig":null}`;
}

/**
 * Corps JSON d'une Proposal tel que json.Marshal(consensus.Proposal) le
 * produit : les hachages (tableaux fixes) figurent toujours, les entiers nuls,
 * chaînes vides et tableaux vides marqués omitempty sont omis.
 */
export function encoderProposition(p) {
  const parties = [
    `"height":${u64(p.height, "height")}`,
    `"round":${u64(p.round, "round")}`,
    `"proposer":${chaineJSONGo(p.proposer ?? "")}`,
    `"blockHash":${hachageJSON(p.blockHash)}`,
    `"parentHash":${hachageJSON(p.parentHash)}`,
  ];
  if (p.timestamp) parties.push(`"timestamp":${u64(p.timestamp, "timestamp")}`);
  parties.push(`"stateRoot":${hachageJSON(p.stateRoot)}`, `"receiptsRoot":${hachageJSON(p.receiptsRoot)}`, `"txRoot":${hachageJSON(p.txRoot)}`);
  if (p.gasUsed) parties.push(`"gasUsed":${u64(p.gasUsed, "gasUsed")}`);
  if (p.gasLimit) parties.push(`"gasLimit":${u64(p.gasLimit, "gasLimit")}`);
  if (p.baseFeeHex) parties.push(`"baseFeeHex":${chaineJSONGo(p.baseFeeHex)}`);
  if (p.txsRaw && p.txsRaw.length) parties.push(`"txsRaw":[${p.txsRaw.map((t) => chaineJSONGo(octets(t, "txsRaw").toString("base64"))).join(",")}]`);
  if (p.polkaRound) parties.push(`"polkaRound":${u64(p.polkaRound, "polkaRound")}`);
  if (p.polkaLines && p.polkaLines.length) parties.push(`"polkaLines":[${p.polkaLines.map(chaineJSONGo).join(",")}]`);
  if (p.sig) parties.push(`"sig":${chaineJSONGo(octets(p.sig, "sig").toString("base64"))}`);
  return `{${parties.join(",")}}`;
}

/** Signature [R || S || V] (65 octets, V dans {0, 1}, S bas) d'un digest par une clé privée secp256k1. */
export function signerDigest(digest, clePrivee) {
  const cle = clePrivee instanceof SigningKey ? clePrivee : new SigningKey(typeof clePrivee === "string" && !clePrivee.startsWith("0x") ? "0x" + clePrivee : clePrivee);
  const s = cle.sign(hex(octetsFixes(digest, 32, "digest")));
  return Buffer.concat([octets(s.r), octets(s.s), Buffer.from([s.yParity])]);
}

/**
 * Ligne brute d'une enveloppe signée, octet pour octet comme
 * EncodeSignedEnvelope(signEnvelope(…)) : ordre des champs du Go, []byte en
 * base64, blockHash omis s'il est nul, corps inséré tel quel.
 * `env` : {type, chainId, valsetHash, validatorId, height, round, blockHash, body}.
 */
export function signerEnveloppe(env, clePrivee) {
  const valsetHash = octetsFixes(env.valsetHash, 32, "valsetHash");
  const blockHash = hachage32(env.blockHash, "blockHash");
  const blocNul = blockHash.every((o) => o === 0);
  const corps = typeof env.body === "string" ? env.body : JSON.stringify(env.body);
  const bodyHash = sha256(utf8(corps));
  const digest = digestEnveloppe({ domain: DOMAINE_SIGNATURE, chainId: env.chainId, type: env.type, validatorId: env.validatorId, valsetHash, height: env.height, round: env.round, blockHash, bodyHash });
  const sig = signerDigest(digest, clePrivee);
  const parties = [
    `"domain":${chaineJSONGo(DOMAINE_SIGNATURE)}`,
    `"chainId":${chaineJSONGo(env.chainId)}`,
    `"type":${chaineJSONGo(env.type)}`,
    `"validatorId":${chaineJSONGo(env.validatorId)}`,
    `"valsetHash":${chaineJSONGo(valsetHash.toString("base64"))}`,
    `"height":${u64(env.height, "height")}`,
    `"round":${u64(env.round, "round")}`,
  ];
  if (!blocNul) parties.push(`"blockHash":${chaineJSONGo(blockHash.toString("base64"))}`);
  parties.push(`"bodyHash":${chaineJSONGo(bodyHash.toString("base64"))}`, `"body":${corps}`, `"sig":${chaineJSONGo(sig.toString("base64"))}`);
  return `{${parties.join(",")}}`;
}

/** Ligne d'un vote signé (SignVoteEnvelope) : le type d'enveloppe découle de vote.type. */
export function signerVote(vote, { chainId, valsetHash, validatorId }, clePrivee) {
  const type = vote.type === VOTE_PRECOMMIT ? TYPE_PRECOMMIT : vote.type === VOTE_PREVOTE ? TYPE_PREVOTE : null;
  if (!type) throw new Error(`type de vote inconnu : ${vote.type}`);
  return signerEnveloppe({ type, chainId, valsetHash, validatorId, height: vote.height, round: vote.round, blockHash: vote.blockHash, body: encoderVote(vote) }, clePrivee);
}

/** Ligne d'une proposition signée (SignProposalEnvelope). */
export function signerProposition(proposition, { chainId, valsetHash, validatorId }, clePrivee) {
  return signerEnveloppe(
    { type: TYPE_PROPOSITION, chainId, valsetHash, validatorId, height: proposition.height, round: proposition.round, blockHash: proposition.blockHash, body: encoderProposition(proposition) },
    clePrivee,
  );
}

/** Clé publique 0x04… d'une clé privée (PubKeyHexFromPriv). */
export function clePubliqueDe(clePrivee) {
  const cle = clePrivee instanceof SigningKey ? clePrivee : new SigningKey(typeof clePrivee === "string" && !clePrivee.startsWith("0x") ? "0x" + clePrivee : clePrivee);
  return cle.publicKey.toLowerCase();
}
