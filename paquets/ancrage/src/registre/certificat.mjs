// Certificat de commit (CT-4 §9.1 à §9.3 ; CT-6 §11.3.3) : lecture des
// lignes d'enveloppe comme le décodeur du nœud (EX-11.6), condensé signé par
// chaque validateur (EX-11.7), hachage d'un jeu de validateurs et quorum
// (EX-11.8), vérification d'un certificat contre un jeu (EX-11.14), et
// lecture d'un manifeste d'instance ou d'un fichier de validateurs pour en
// tirer le jeu en vigueur à une hauteur (CT-4 §4.8, CP-4).
//
// Rien n'est cru du nœud : `validatorSet`, `quorum`, `canonical` et
// `validatorSetMatchesCertificate` ne sont jamais lus (CT-4 EX-9.1, CT-6
// EX-11.3) ; la ligne de proposition est exigée.

import { sha256 } from "@noortrace/noyau";
import { clePubliqueNonCompressee, recouvrerClePublique65 } from "./cle-chaine.mjs";
import {
  concatener, decoderBase64Noeud, estHexOctets, estOctets, hexVersOctets, octetsEgaux, octetsVersHex, quantiteVersEntier,
  u64, utf8Octets, versEntier, MAX_U64,
} from "./octets.mjs";

export const DOMAINE_BFT = "noor/v1/bft";
const PREFIXE_SIGNATURE = utf8Octets("noor/v1/bft-sign|");
const PREFIXE_JEU = utf8Octets("noor/v1/valsethash|");

/** Bornes de CT-6 §15.1 pour un certificat. */
export const BORNES_CERTIFICAT = Object.freeze({ precommits: 128, ligne: 4194304, validateurs: 128, jeux: 16 });

// ------------------------------------------------- Jeu de validateurs

/**
 * Lit un jeu `{ validators: [{ id, pubKeyHex }] }` : identifiants non vides et
 * distincts, clés hexadécimales de 33, 64 ou 65 octets qui sont des points de
 * secp256k1. Rend `{ validateurs: [{ id, declaree, publique }], hash }` ou null.
 */
export function lireJeu(jeu) {
  const liste = Array.isArray(jeu) ? jeu : jeu?.validators;
  if (!Array.isArray(liste) || liste.length < 1 || liste.length > BORNES_CERTIFICAT.validateurs) return null;
  const ids = new Set();
  const validateurs = [];
  for (const v of liste) {
    if (!v || typeof v !== "object" || typeof v.id !== "string") return null;
    const id = v.id.trim();
    if (id.length === 0 || ids.has(id)) return null;
    if (typeof v.pubKeyHex !== "string" || !/^0x([0-9a-f]{66}|[0-9a-f]{128}|[0-9a-f]{130})$/.test(v.pubKeyHex)) return null;
    const declaree = hexVersOctets(v.pubKeyHex);
    const publique = clePubliqueNonCompressee(declaree);
    if (!publique) return null;
    ids.add(id);
    validateurs.push({ id, declaree, publique });
  }
  return { validateurs, hash: hachageJeu(validateurs) };
}

/**
 * EX-11.8 : `sha256("noor/v1/valsethash|" ‖ pour chaque identifiant, par
 * ordre croissant de ses octets : id ‖ 00 ‖ clé déclarée ‖ 00)`.
 */
export function hachageJeu(validateurs) {
  const tries = [...validateurs].map((v) => ({ id: utf8Octets(v.id), cle: v.declaree ?? hexVersOctets(v.pubKeyHex) }))
    .sort((a, b) => Buffer.compare(Buffer.from(a.id), Buffer.from(b.id)));
  const parties = [PREFIXE_JEU];
  for (const v of tries) parties.push(v.id, Uint8Array.of(0), v.cle, Uint8Array.of(0));
  return sha256(concatener(...parties));
}

/** Quorum d'un jeu de `N` validateurs : `⌊(N + f) / 2⌋ + 1`, `f = ⌊(N − 1) / 3⌋`. */
export function quorum(N) {
  const f = Math.floor((N - 1) / 3);
  return Math.floor((N + f) / 2) + 1;
}

/**
 * Jeux par hauteur, depuis un manifeste d'instance (`validator_sets`), un
 * fichier `validateurs-v0` (`sets`) ou un seul `validators.json` (valable à
 * toute hauteur). Rend `[{ from_height, to_height, jeu, source }]` ou null.
 */
export function lireJeux(source) {
  if (!source || typeof source !== "object") return null;
  const liste = Array.isArray(source.validator_sets) ? source.validator_sets : Array.isArray(source.sets) ? source.sets : null;
  if (liste === null) {
    const jeu = lireJeu(source);
    return jeu ? [{ from_height: 0, to_height: null, jeu, source: typeof source.source === "string" ? source.source : null, validators: Array.isArray(source) ? source : source.validators }] : null;
  }
  if (liste.length < 1 || liste.length > BORNES_CERTIFICAT.jeux) return null;
  const sortie = [];
  for (const s of liste) {
    if (!s || typeof s !== "object") return null;
    const de = versEntier(s.from_height);
    const a = s.to_height === null || s.to_height === undefined ? null : versEntier(s.to_height);
    if (de === null || (s.to_height !== null && s.to_height !== undefined && a === null)) return null;
    if (a !== null && a < de) return null;
    const jeu = lireJeu(s.validators);
    if (!jeu) return null;
    sortie.push({ from_height: Number(de), to_height: a === null ? null : Number(a), jeu, source: typeof s.source === "string" ? s.source : null, validators: s.validators });
  }
  return sortie;
}

/** Le jeu dont l'intervalle contient la hauteur `h`, ou null. */
export function jeuPourHauteur(jeux, h) {
  const n = typeof h === "bigint" ? Number(h) : h;
  for (const j of jeux) if (j.from_height <= n && (j.to_height === null || n <= j.to_height)) return j;
  return null;
}

// --------------------------------------------------- Lecture des lignes

/**
 * Découpe un objet JSON en membres de premier niveau `{ cle, brut, debut }`
 * (clé décodée, valeur brute telle qu'écrite), sans tolérer de texte hors de
 * l'objet. Rend null si le texte n'est pas un objet JSON bien formé.
 */
export function membresObjetJson(texte) {
  let i = 0;
  const n = texte.length;
  const blancs = () => { while (i < n && (texte[i] === " " || texte[i] === "\t" || texte[i] === "\n" || texte[i] === "\r")) i++; };
  const chaine = () => {
    // position sur le guillemet ouvrant ; rend la fin (après le guillemet fermant)
    let j = i + 1;
    while (j < n) {
      const c = texte[j];
      if (c === "\\") { j += 2; continue; }
      if (c === "\"") return j + 1;
      if (texte.charCodeAt(j) < 0x20) return -1;
      j++;
    }
    return -1;
  };
  const valeur = () => {
    // rend la fin d'une valeur commençant à i
    const c = texte[i];
    if (c === "\"") return chaine();
    if (c === "{" || c === "[") {
      let profondeur = 0;
      let j = i;
      while (j < n) {
        const d = texte[j];
        if (d === "\"") { const save = i; i = j; const fin = chaine(); i = save; if (fin < 0) return -1; j = fin; continue; }
        if (d === "{" || d === "[") profondeur++;
        else if (d === "}" || d === "]") { profondeur--; if (profondeur === 0) return j + 1; if (profondeur < 0) return -1; }
        j++;
      }
      return -1;
    }
    let j = i;
    while (j < n && /[-+0-9A-Za-z.]/.test(texte[j])) j++;
    return j === i ? -1 : j;
  };
  blancs();
  if (texte[i] !== "{") return null;
  i++;
  const membres = [];
  blancs();
  if (texte[i] === "}") { i++; blancs(); return i === n ? membres : null; }
  for (;;) {
    blancs();
    if (texte[i] !== "\"") return null;
    const finCle = chaine();
    if (finCle < 0) return null;
    let cle;
    try { cle = JSON.parse(texte.slice(i, finCle)); } catch { return null; }
    i = finCle;
    blancs();
    if (texte[i] !== ":") return null;
    i++;
    blancs();
    const debut = i;
    const fin = valeur();
    if (fin < 0) return null;
    const brut = texte.slice(debut, fin);
    try { JSON.parse(brut); } catch { return null; }
    membres.push({ cle, brut, debut });
    i = fin;
    blancs();
    if (texte[i] === ",") { i++; continue; }
    if (texte[i] === "}") { i++; blancs(); return i === n ? membres : null; }
    return null;
  }
}

/** Repli de Go : égalité exacte, sinon sans la casse (Unicode simple folding approché par `toLowerCase`). */
function memeNom(a, b) {
  return a === b || a.toLowerCase() === b.toLowerCase() || a.normalize("NFKC").toLowerCase() === b.normalize("NFKC").toLowerCase();
}

/** Dernier membre d'un nom donné (comparaison de Go), ou undefined ; `canonique` faux si la casse diffère ou si le nom est en double. */
function membre(membres, nom, etat) {
  let trouve;
  let compte = 0;
  for (const m of membres) {
    if (memeNom(m.cle, nom)) {
      trouve = m;
      compte++;
      if (m.cle !== nom) etat.canonique = false;
    }
  }
  if (compte > 1) etat.canonique = false;
  return trouve;
}

function lireEntierJson(m, etat) {
  if (m === undefined) return 0n;
  if (m.brut === "null") { etat.canonique = false; return 0n; }
  if (!/^(0|[1-9][0-9]*)$/.test(m.brut)) return null;
  const x = BigInt(m.brut);
  return x > MAX_U64 ? null : x;
}

function lireChaineJson(m) {
  if (m === undefined || m.brut === "null") return null;
  const v = JSON.parse(m.brut);
  return typeof v === "string" ? v : undefined;
}

function lireBase64(m, etat) {
  const s = lireChaineJson(m);
  if (s === null || s === undefined) return null;
  const d = decoderBase64Noeud(s);
  if (!d) return null;
  if (!d.canonique) etat.canonique = false;
  return d.octets;
}

function lireHachageHex(m, etat) {
  const s = lireChaineJson(m);
  if (s === null || s === undefined) return null;
  if (!/^0[xX][0-9a-fA-F]{64}$/.test(s)) return null;
  if (!/^0x[0-9a-f]{64}$/.test(s)) etat.canonique = false;
  return hexVersOctets("0x" + s.slice(2).toLowerCase());
}

const TYPES_CORPS_PROPOSITION = Object.freeze({
  height: "entier", round: "entier", timestamp: "entier", gasUsed: "entier", gasLimit: "entier", polkaRound: "entier",
  proposer: "chaine", baseFeeHex: "chaine",
  blockHash: "hachage", parentHash: "hachage", stateRoot: "hachage", receiptsRoot: "hachage", txRoot: "hachage",
  txsRaw: "tableau_base64", polkaLines: "tableau_chaines", sig: "chaine",
});
const TYPES_CORPS_VOTE = Object.freeze({
  Height: "entier", Round: "entier", Voter: "chaine", Type: "octet", BlockHash: "hachage", Sig: "chaine",
});

/** Contrôle du type d'un membre connu d'un corps (CT-6 EX-11.6, révision 0.4). */
function membreTypeAdmis(type, brut) {
  let v;
  try { v = JSON.parse(brut); } catch { return false; }
  switch (type) {
    case "entier": return v === null || (/^(0|[1-9][0-9]*)$/.test(brut) && BigInt(brut) <= MAX_U64);
    case "octet": return v === null || (/^(0|[1-9][0-9]*)$/.test(brut) && BigInt(brut) <= 255n);
    case "chaine": return v === null || typeof v === "string";
    case "hachage": return typeof v === "string" && /^0[xX][0-9a-fA-F]{64}$/.test(v);
    case "tableau_base64": return v === null || (Array.isArray(v) && v.every((x) => typeof x === "string" && decoderBase64Noeud(x) !== null));
    case "tableau_chaines": return v === null || (Array.isArray(v) && v.every((x) => typeof x === "string"));
    default: return true;
  }
}

/**
 * Lit une ligne d'enveloppe (CT-6 EX-11.6) : rend `{ domain, chainId, type,
 * validatorId, valsetHash, height, round, blockHash, bodyHash, corps,
 * corpsOctets, sig, canonique }` ou `{ refus }`. Les entiers absents ou nuls
 * valent 0 comme chez le décodeur ; un membre connu d'un corps mal typé
 * rend la ligne illisible.
 */
export function lireLigne(ligne) {
  if (typeof ligne !== "string" || ligne.length === 0 || ligne.length > BORNES_CERTIFICAT.ligne) return { refus: "ligne absente ou hors borne" };
  const membres = membresObjetJson(ligne);
  if (!membres) return { refus: "ligne : objet JSON attendu" };
  const etat = { canonique: true };
  const domain = lireChaineJson(membre(membres, "domain", etat));
  const chainId = lireChaineJson(membre(membres, "chainId", etat));
  const type = lireChaineJson(membre(membres, "type", etat));
  const validatorId = lireChaineJson(membre(membres, "validatorId", etat));
  for (const [nom, v] of [["domain", domain], ["chainId", chainId], ["type", type], ["validatorId", validatorId]]) {
    if (typeof v !== "string") return { refus: `${nom} : chaîne attendue` };
  }
  const valsetHash = lireBase64(membre(membres, "valsetHash", etat), etat);
  const blockHashM = membre(membres, "blockHash", etat);
  const blockHash = blockHashM === undefined || blockHashM.brut === "null" ? new Uint8Array(32) : lireBase64(blockHashM, etat);
  const bodyHash = lireBase64(membre(membres, "bodyHash", etat), etat);
  const sig = lireBase64(membre(membres, "sig", etat), etat);
  if (!valsetHash || valsetHash.length !== 32) return { refus: "valsetHash : 32 octets base64 attendus" };
  if (!blockHash || blockHash.length !== 32) return { refus: "blockHash : 32 octets base64 attendus" };
  if (!bodyHash || bodyHash.length !== 32) return { refus: "bodyHash : 32 octets base64 attendus" };
  if (!sig || sig.length !== 65) return { refus: "sig : 65 octets base64 attendus" };
  const height = lireEntierJson(membre(membres, "height", etat), etat);
  const round = lireEntierJson(membre(membres, "round", etat), etat);
  if (height === null || round === null) return { refus: "height ou round : entier attendu" };
  const corpsM = membre(membres, "body", etat);
  if (corpsM === undefined || corpsM.brut === "null") return { refus: "body absent" };
  const corpsMembres = membresObjetJson(corpsM.brut);
  if (!corpsMembres) return { refus: "body : objet JSON attendu" };
  const corpsOctets = utf8Octets(corpsM.brut);
  // Types des membres connus du corps selon le type d'enveloppe.
  const types = type === "CONS_PROPOSAL" ? TYPES_CORPS_PROPOSITION : type === "CONS_PRECOMMIT" ? TYPES_CORPS_VOTE : {};
  const corps = {};
  for (const [nom, t] of Object.entries(types)) {
    const m = membre(corpsMembres, nom, etat);
    if (m === undefined) continue;
    if (!membreTypeAdmis(t, m.brut)) return { refus: `body.${nom} : type refusé` };
    corps[nom] = { brut: m.brut, valeur: JSON.parse(m.brut) };
  }
  return { domain, chainId, type, validatorId, valsetHash, height, round, blockHash, bodyHash, corps, corpsOctets, sig, canonique: etat.canonique };
}

function LP(octets) {
  const L = new Uint8Array(4);
  new DataView(L.buffer).setUint32(0, octets.length);
  return concatener(L, octets);
}

/** Condensé signé d'une enveloppe (CT-6 EX-11.7). */
export function condenseEnveloppe({ chainId, type, validatorId, valsetHash, height, round, blockHash, bodyHash }) {
  return sha256(concatener(
    PREFIXE_SIGNATURE, LP(utf8Octets(DOMAINE_BFT)), LP(utf8Octets(chainId)), LP(utf8Octets(type)), LP(utf8Octets(validatorId)),
    valsetHash, u64(height), u64(round), blockHash, bodyHash,
  ));
}

function hachageCorps(corps, nom) {
  const m = corps[nom];
  if (!m || typeof m.valeur !== "string") return null;
  return hexVersOctets("0x" + m.valeur.slice(2).toLowerCase());
}

/**
 * Vérifie une enveloppe (EX-11.14) : type attendu, domaine, `chainId`,
 * `valsetHash`, hauteur, tour et `blockHash` du certificat, `bodyHash` égal au
 * sha256 des octets du corps, corps cohérent, signature sous la clé du
 * validateur nommé dans le jeu. Rend `{ ok, validatorId, raison, avertissements }`.
 */
export function verifierEnveloppe(ligne, attendu) {
  const l = lireLigne(ligne);
  const echec = (raison) => ({ ok: false, validatorId: l.validatorId ?? null, raison, avertissements: [] });
  if (l.refus) return echec(l.refus);
  const avertissements = l.canonique ? [] : ["AV-R-2"];
  if (l.type !== attendu.type) return echec(`type ${l.type}, attendu ${attendu.type}`);
  if (l.domain !== DOMAINE_BFT) return echec("domaine différent");
  if (l.chainId !== attendu.chainId) return echec("chainId différent");
  if (!octetsEgaux(l.valsetHash, attendu.valsetHash)) return echec("valsetHash différent");
  if (l.height !== attendu.height || l.round !== attendu.round) return echec("hauteur ou tour différents");
  if (!octetsEgaux(l.blockHash, attendu.blockHash)) return echec("blockHash de l'enveloppe différent");
  if (!octetsEgaux(l.bodyHash, sha256(l.corpsOctets))) return echec("bodyHash différent du corps");
  const c = l.corps;
  const entier = (nom) => (c[nom] === undefined || c[nom].valeur === null ? 0n : BigInt(c[nom].brut));
  if (l.type === "CONS_PROPOSAL") {
    if (entier("height") !== attendu.height || entier("round") !== attendu.round) return echec("corps : hauteur ou tour différents");
    const bh = hachageCorps(c, "blockHash");
    if (!bh || !octetsEgaux(bh, attendu.blockHash)) return echec("corps : blockHash différent");
    const proposer = c.proposer?.valeur ?? null;
    if (proposer !== null && proposer.trim() !== "" && proposer !== l.validatorId) return echec("corps : proposer différent du signataire");
    if (proposer !== null && proposer !== l.validatorId) avertissements.push("AV-R-2");
  } else {
    if (entier("Height") !== attendu.height || entier("Round") !== attendu.round) return echec("corps : hauteur ou tour différents");
    const bh = hachageCorps(c, "BlockHash");
    if (!bh || !octetsEgaux(bh, attendu.blockHash)) return echec("corps : BlockHash différent");
    const voter = c.Voter?.valeur ?? null;
    if (voter !== null && voter !== "" && voter !== l.validatorId) return echec("corps : Voter différent du signataire");
    const typeVote = c.Type === undefined || c.Type.valeur === null ? null : BigInt(c.Type.brut);
    if (typeVote !== 2n) avertissements.push("AV-R-2");
  }
  const validateur = attendu.jeu.validateurs.find((v) => v.id === l.validatorId);
  if (!validateur) return echec(`validateur ${l.validatorId} hors du jeu`);
  const publique = recouvrerClePublique65(condenseEnveloppe(l), l.sig);
  if (!publique || !octetsEgaux(publique, validateur.publique)) return echec("signature invalide");
  return { ok: true, validatorId: l.validatorId, raison: null, avertissements, lue: l };
}

/**
 * Lit le `result` d'un certificat (ou la réponse JSON-RPC complète) et ne
 * garde que ce que CT-6 EX-11.3 lit. Rend `{ height, round, chainId,
 * valsetHash, blockHash, proposition, precommits }` ou null.
 */
export function lireCertificat(reponse) {
  const c = reponse && typeof reponse === "object" && "result" in reponse && !("height" in reponse) ? reponse.result : reponse;
  if (!c || typeof c !== "object") return null;
  const height = quantiteVersEntier(c.height, MAX_U64);
  const round = quantiteVersEntier(c.round, MAX_U64);
  if (height === null || round === null) return null;
  if (typeof c.chainId !== "string" || c.chainId.length === 0 || c.chainId.length > 64) return null;
  if (!estHexOctets(c.valsetHash, 32) || !estHexOctets(c.blockHash, 32)) return null;
  if (!c.proposal || typeof c.proposal.line !== "string") return null;
  if (!Array.isArray(c.precommits) || c.precommits.length < 1 || c.precommits.length > BORNES_CERTIFICAT.precommits) return null;
  if (!c.precommits.every((p) => p && typeof p.line === "string")) return null;
  return {
    height, round, chainId: c.chainId, valsetHash: hexVersOctets(c.valsetHash), blockHash: hexVersOctets(c.blockHash),
    proposition: c.proposal.line, precommits: c.precommits.map((p) => p.line), brut: c,
  };
}

/**
 * Vérifie un certificat contre un jeu (CT-6 EX-11.11, EX-11.13, EX-11.14 ;
 * CT-4 CP-4). `attendu` : `{ bftChainId, hauteur, blockHash (hex), jeu }`
 * (`jeu` : résultat de `lireJeu`). Rend `{ ok, motif, raison, signataires,
 * proposition, avertissements, txsRaw }`.
 */
export function verifierCertificat(reponse, attendu) {
  const c = lireCertificat(reponse);
  const echec = (motif, raison) => ({ ok: false, motif, raison, signataires: [], proposition: null, avertissements: [], txsRaw: null });
  if (!c) return echec("certificat_invalide", "certificat illisible");
  if (c.chainId !== attendu.bftChainId) return echec("certificat_invalide", `chainId ${c.chainId}, attendu ${attendu.bftChainId}`);
  const hauteur = typeof attendu.hauteur === "bigint" ? attendu.hauteur : BigInt(attendu.hauteur);
  if (c.height !== hauteur) return echec("certificat_invalide", `hauteur ${c.height}, attendue ${hauteur}`);
  if (attendu.blockHash && !octetsEgaux(c.blockHash, hexVersOctets(attendu.blockHash))) return echec("certificat_invalide", "blockHash différent de l'en-tête");
  if (!octetsEgaux(c.valsetHash, attendu.jeu.hash)) return echec("certificat_invalide", "valsetHash différent du jeu");
  const base = { chainId: c.chainId, valsetHash: c.valsetHash, height: c.height, round: c.round, blockHash: c.blockHash, jeu: attendu.jeu };
  const avertissements = [];
  const prop = verifierEnveloppe(c.proposition, { ...base, type: "CONS_PROPOSAL" });
  if (!prop.ok) return echec("certificat_invalide", `proposition : ${prop.raison}`);
  avertissements.push(...prop.avertissements);
  const signataires = [];
  for (const ligne of c.precommits) {
    const r = verifierEnveloppe(ligne, { ...base, type: "CONS_PRECOMMIT" });
    if (!r.ok) return echec("certificat_invalide", `precommit : ${r.raison}`);
    if (signataires.includes(r.validatorId)) return echec("certificat_invalide", `precommit en double de ${r.validatorId}`);
    signataires.push(r.validatorId);
    avertissements.push(...r.avertissements);
  }
  const N = attendu.jeu.validateurs.length;
  if (signataires.length < quorum(N)) return echec("certificat_invalide", `${signataires.length} precommits, quorum ${quorum(N)} sur ${N}`);
  let txsRaw = null;
  const m = prop.lue.corps.txsRaw;
  if (m && Array.isArray(m.valeur)) txsRaw = m.valeur.map((x) => decoderBase64Noeud(x).octets);
  return { ok: true, motif: null, raison: null, signataires, proposition: prop.lue, avertissements: [...new Set(avertissements)], txsRaw, certificat: c };
}

/** Erreur JSON-RPC du certificat → conduite de CT-4 §9.3 : `{ code, reessayer, suivant }`. */
export function classerErreurCertificat(erreur) {
  const message = typeof erreur?.message === "string" ? erreur.message : "";
  const code = typeof erreur?.code === "number" ? erreur.code : null;
  if (code === -32601) return { code: "inutilisable", reessayer: false, suivant: false };
  if (code === -32602) return { code: "inutilisable", reessayer: false, suivant: false };
  if (code === -32603) return { code: "noeud_suiveur", reessayer: false, suivant: true };
  if (/not yet persisted/i.test(message)) return { code: "certificat_indisponible", reessayer: true, suivant: false };
  if (/leader unreachable/i.test(message)) return { code: "noeud_suiveur", reessayer: false, suivant: true };
  if (/unknown block/i.test(message)) return { code: "certificat_indisponible", reessayer: false, suivant: false };
  if (/pruned|prune|retention|élagu|elagu/i.test(message) && !/inside the retention window/i.test(message)) return { code: "certificat_elague", reessayer: false, suivant: false };
  if (/no commit certificate stored/i.test(message)) return { code: "certificat_indisponible", reessayer: false, suivant: true };
  return { code: "certificat_indisponible", reessayer: false, suivant: true };
}

/** Hexadécimal d'un hachage de jeu. */
export function hachageJeuHex(jeu) {
  return octetsVersHex(jeu.hash);
}

export { estOctets };
