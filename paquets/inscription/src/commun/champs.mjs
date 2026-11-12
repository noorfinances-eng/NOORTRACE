// Types des champs de l'application d'exploitant (CT-4 EX-7.25, révision
// 0.7 ; INTERFACES.md 2.1) : adresse, hachage, clé publique Ed25519, slug,
// nom de journal, seuil, montant, référence de clé, texte, entier, origine
// HTTPS, identité de session, document JSON contrôlé contre son schéma,
// chemin relatif sous le répertoire du client, et la liste de valeurs d'un de
// ces types ; aucun autre (`TYPES_DECLARES`). Chaque valeur reçue par
// une page ou une route est contrôlée ici, côté serveur (la page répète ces
// contrôles pour l'affichage seulement), puis de nouveau par l'agent, qui ne
// croit pas l'interface (EX-7.23).
//
// Une valeur refusée n'est jamais recopiée dans le message d'erreur, ni
// gardée, ni consignée : le message nomme le champ et la règle, pas la
// valeur (EX-7.25 : une clé nue tapée par erreur dans un champ ne doit
// laisser aucune trace).

/** Erreur de champ : `code` (`requete_invalide` ou `reference_refusee`), `champ`, message sans la valeur. */
export class ErreurChamp extends Error {
  constructor(code, champ, message) {
    super(`${champ} : ${message}`);
    this.name = "ErreurChamp";
    this.code = code;
    this.champ = champ;
  }
}

const MOTIF_ADRESSE = /^0x[0-9a-fA-F]{40}$/;
const MOTIF_HACHAGE = /^0x[0-9a-fA-F]{64}$/;
/** Grammaire de RG-1 et RG-2 (CT-4 EX-6.2, EX-6.4). */
export const MOTIF_SLUG = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
/** Slug d'une organisation de production : `o-` et 32 chiffres hexadécimaux minuscules (EX-6.2). */
export const MOTIF_SLUG_PRODUCTION = /^o-[0-9a-f]{32}$/;
const MOTIF_MONTANT = /^(0|[1-9][0-9]{0,77})$/;
const MOTIF_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Une valeur nue qui ressemble à un secret : 64 chiffres hexadécimaux avec
 * ou sans `0x` (clé secp256k1, graine Ed25519, jeton), une suite de 12 à 24
 * mots en minuscules (mnémonique), une valeur base64 ou base64url de 32
 * octets (43 caractères d'un même alphabet, 44 avec le remplissage, mêlant
 * majuscules, minuscules et chiffres). Sert à refuser la valeur dans un
 * champ de référence (EX-7.25) et dans un champ de texte libre, où une clé
 * collée par erreur ne doit pas entrer. `base64` faux : la forme base64 n'est
 * pas cherchée (un chemin de fichier en a l'alphabet).
 */
export function ressembleASecret(v, { base64 = true } = {}) {
  if (typeof v !== "string") return false;
  const t = v.trim();
  if (/(?:^|[^0-9a-fA-F])(?:0x)?[0-9a-fA-F]{64}(?:$|[^0-9a-fA-F])/.test(t)) return true;
  const mots = t.split(/\s+/);
  if (mots.length >= 12 && mots.length <= 24 && mots.every((m) => /^[a-z]{3,8}$/.test(m))) return true;
  if (base64) {
    const melange = (x) => /[A-Z]/.test(x) && /[a-z]/.test(x) && /[0-9]/.test(x);
    for (const motif of [/(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{43}=?)(?=$|[^A-Za-z0-9+/=])/g, /(?:^|[^A-Za-z0-9_=-])([A-Za-z0-9_-]{43}=?)(?=$|[^A-Za-z0-9_=-])/g]) {
      for (const m of t.matchAll(motif)) if (melange(m[1])) return true;
    }
  }
  return false;
}

/** Texte libre : 1 à `max` caractères, sans caractère de contrôle, et jamais une valeur qui ressemble à un secret. */
export function texte(champ, v, { max = 256, min = 1 } = {}) {
  if (typeof v !== "string") throw new ErreurChamp("requete_invalide", champ, "texte attendu");
  const n = [...v].length;
  if (n < min || n > max) throw new ErreurChamp("requete_invalide", champ, `texte de ${min} à ${max} caractères attendu`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw new ErreurChamp("requete_invalide", champ, "caractère de contrôle refusé");
  if (ressembleASecret(v)) throw new ErreurChamp("requete_invalide", champ, "valeur refusée : elle a la forme d'une clé, d'une graine ou d'une mnémonique (aucune clé n'entre par un formulaire)");
  return v;
}

/** Adresse de 20 octets, rendue en minuscules (CT-4 §0). */
export function adresse(champ, v, { nonNulle = true } = {}) {
  if (typeof v !== "string" || !MOTIF_ADRESSE.test(v)) throw new ErreurChamp("requete_invalide", champ, "adresse 0x et 40 chiffres hexadécimaux attendue");
  const a = v.toLowerCase();
  if (nonNulle && /^0x0{40}$/.test(a)) throw new ErreurChamp("requete_invalide", champ, "adresse nulle refusée");
  return a;
}

/** Hachage de 32 octets (SHA-256, keccak256), rendu en minuscules. */
export function hachage(champ, v) {
  if (typeof v !== "string" || !MOTIF_HACHAGE.test(v)) throw new ErreurChamp("requete_invalide", champ, "hachage 0x et 64 chiffres hexadécimaux attendu");
  return v.toLowerCase();
}

/** Clé publique Ed25519 de 32 octets, non nulle (CT-1 §6, RG-7). */
export function clePubliqueEd25519(champ, v) {
  const h = hachage(champ, v);
  if (/^0x0{64}$/.test(h)) throw new ErreurChamp("requete_invalide", champ, "clé publique nulle refusée");
  return h;
}

/** Slug d'organisation (RG-1) ; en production, la forme `o-<32 hex>` (EX-6.2). */
export function slug(champ, v, { production = false } = {}) {
  if (typeof v !== "string" || !MOTIF_SLUG.test(v) || (production && !MOTIF_SLUG_PRODUCTION.test(v))) {
    throw new ErreurChamp("requete_invalide", champ, production ? "slug de production o- et 32 chiffres hexadécimaux attendu" : "slug de 1 à 64 caractères [a-z0-9-] attendu (RG-1)");
  }
  return v;
}

/** Nom de journal (RG-2). */
export function nomJournal(champ, v) {
  if (typeof v !== "string" || !MOTIF_SLUG.test(v)) throw new ErreurChamp("requete_invalide", champ, "nom de journal de 1 à 64 caractères [a-z0-9-] attendu (RG-2)");
  return v;
}

/** Identifiant de clé d'enregistreur (`recorder_key_id`, CT-1 §3). */
export function keyId(champ, v) {
  if (typeof v !== "string" || !MOTIF_KEY_ID.test(v)) throw new ErreurChamp("requete_invalide", champ, "identifiant de clé [A-Za-z0-9._-] de 1 à 64 caractères attendu");
  return v;
}

/** Seuil d'un jeu d'approbateurs : entier de 1 à 64. */
export function seuil(champ, v) {
  if (!Number.isSafeInteger(v) || v < 1 || v > 64) throw new ErreurChamp("requete_invalide", champ, "entier de 1 à 64 attendu");
  return v;
}

/** Montant ou budget : entier positif, nombre JSON sûr ou chaîne décimale. Rend un `bigint`. */
export function montant(champ, v, { min = 0n } = {}) {
  let x = null;
  if (Number.isSafeInteger(v) && v >= 0) x = BigInt(v);
  else if (typeof v === "string" && MOTIF_MONTANT.test(v)) x = BigInt(v);
  if (x === null || x < min) throw new ErreurChamp("requete_invalide", champ, `entier décimal d'au moins ${min} attendu`);
  return x;
}

/** Entier (EX-7.25, révision 0.7) : nombre JSON entier sûr, de `min` à `max`. */
export function entier(champ, v, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(v) || v < min || v > max) throw new ErreurChamp("requete_invalide", champ, `entier de ${min} à ${max} attendu`);
  return v;
}

/** Booléen strict. */
export function booleen(champ, v) {
  if (typeof v !== "boolean") throw new ErreurChamp("requete_invalide", champ, "booléen attendu");
  return v;
}

/** Objet JSON (document à contrôler ensuite contre son schéma). */
export function objet(champ, v) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) throw new ErreurChamp("requete_invalide", champ, "objet JSON attendu");
  return v;
}

/** Liste d'éléments d'un type, de `min` à `max` éléments. */
export function liste(champ, v, element, { min = 1, max = 64 } = {}) {
  if (!Array.isArray(v) || v.length < min || v.length > max) throw new ErreurChamp("requete_invalide", champ, `liste de ${min} à ${max} éléments attendue`);
  return v.map((x, k) => element(`${champ}[${k}]`, x));
}

/**
 * Chemin relatif sous le répertoire d'un client dans les données de
 * l'agent : segments `[A-Za-z0-9._-]`, ni absolu, ni `..`, ni segment vide.
 */
export function cheminRelatif(champ, v) {
  if (typeof v !== "string" || v.length < 1 || v.length > 512) throw new ErreurChamp("requete_invalide", champ, "chemin relatif attendu");
  const segments = v.split("/");
  if (segments.some((s) => !/^[A-Za-z0-9._-]{1,128}$/.test(s) || s === "." || s === "..")) {
    throw new ErreurChamp("requete_invalide", champ, "chemin relatif sous le répertoire du client attendu (segments [A-Za-z0-9._-], sans ..)");
  }
  return v;
}

/** Les types déclarés, nommés comme dans INTERFACES.md 2.1, dont le contrôle est pur (les autres se contrôlent contre un schéma). */
export const TYPES = Object.freeze({
  adresse, hachage, cle_publique_ed25519: clePubliqueEd25519, slug, nom_journal: nomJournal, seuil, montant, texte, entier, chemin: cheminRelatif,
});

/** Liste close des types de champ d'EX-7.25 (révision 0.7) : valeur de l'attribut `data-type` de chaque champ de page. */
export const TYPES_DECLARES = Object.freeze([
  "adresse", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "seuil", "montant", "reference_cle", "texte",
  "entier", "origine", "identite", "document", "chemin",
  // Listes de valeurs d'un de ces types.
  "liste_adresses", "liste_noms_journal", "liste_identites", "liste_documents",
]);
