// Bornes communes de mémoire et de temps sur les entrées (étape 8, revue de
// sécurité interne, cause structurante S-1 : CT-2 EX-4.47, EX-6.28, EX-17.2,
// EX-17.3). Les textes bornent la taille des requêtes et la profondeur JSON ;
// ils ne bornent ni la longueur des chaînes venues d'une entrée recopiées au
// journal d'exploitation, ni le nombre total de nœuds d'un texte JSON, ni la
// longueur d'un `id` JSON-RPC. Ce module fixe ces bornes en un seul point,
// appliquées pendant l'analyse ou avant toute matérialisation, et rend des
// valeurs recopiées : dans V8, une tranche d'au moins treize caractères d'un
// texte garde une référence au texte entier (chaîne « tranchée »), de sorte
// qu'une ligne d'exploitation qui portait l'`id` ou le nom d'une méthode
// retenait la requête entière en mémoire (constats CT-2 EX-17.2, CT-2 EX-4.47).

/** Longueur maximale, en caractères UTF-16, d'un `id` JSON-RPC d'hôte (frontal MCP, point d'entrée SDK) ; au-delà, -32600. */
export const ID_JSONRPC_MAX = 256;

/** Longueur maximale d'une chaîne venue d'une entrée recopiée dans une ligne du journal d'exploitation (`request_id`, `method`, noms d'outils). */
export const CHAINE_JOURNAL_MAX = 256;

/** Octets des lignes du journal d'exploitation gardées en mémoire (diagnostic), toutes lignes confondues. */
export const JOURNAL_MEMOIRE_MAX_OCTETS = 16 * 1048576;

/** Nombre total de nœuds (valeurs) d'un texte JSON analysé par `analyserTexte`, toutes imbrications confondues. */
export const NOEUDS_JSON_MAX = 1000000;

/** Longueur maximale du texte décimal d'un entier avant conversion en `BigInt` (2^64 tient en 20 chiffres). */
export const CHIFFRES_ENTIER_MAX = 20;

/** Octets maximaux d'un message du protocole PostgreSQL lu par le client du magasin de bail. */
export const MESSAGE_PG_MAX_OCTETS = 1048576;

/** Itérations SCRAM-SHA-256 admises du serveur (PostgreSQL emploie 4 096 ; RFC 7677 §4 recommande au moins 4 096). */
export const SCRAM_ITERATIONS_MAX = 600000;

/** Octets maximaux d'une réponse de la passerelle JSON d'etcd. */
export const REPONSE_ETCD_MAX_OCTETS = 1048576;

/** Délai d'identification d'une connexion aux prises (preuve, jeton, poignée de main), en millisecondes. */
export const DELAI_IDENTIFICATION_MS = 5000;

/** Connexions non identifiées admises à la fois sur une prise. */
export const CONNEXIONS_NON_IDENTIFIEES_MAX = 64;

/** Sessions ouvertes à la fois par une connexion du point d'entrée SDK. */
export const SESSIONS_SDK_PAR_CONNEXION_MAX = 1024;

/** Spans par requête OTLP quand `otel.spans_per_request` est absent (EX-6.28 « Absent : pas de borne propre » : borne de la version 0, lecture au LISEZMOI). */
export const SPANS_PAR_REQUETE_DEFAUT = 10000;

/** Éléments répétés (resource_spans, scope_spans, spans, événements, liens, attributs, valeurs) comptés pendant le décodage, par span admis. */
export const ELEMENTS_OTLP_PAR_SPAN = 128;

/** Index distincts (choix, appels d'outils, candidats) d'un réassemblage de flux de modèle (EX-5.27). */
export const INDEX_REASSEMBLAGE_MAX = 100000;

/** Octets d'un bloc d'en-têtes HTTP encapsulés d'un message ICAP (`Encapsulated`, RFC 3507 §4.4.1). */
export const ICAP_ENTETES_MAX_OCTETS = 262144;

/** Octets d'un morceau `chunked` d'un corps ICAP ; au-delà, 400. */
export const ICAP_CHUNK_MAX_OCTETS = 16777216;

/** Délai d'inactivité d'une connexion ICAP, en millisecondes. */
export const ICAP_INACTIVITE_MS = 120000;

/** Connexions ICAP à la fois (la valeur annoncée par `Max-Connections`). */
export const ICAP_CONNEXIONS_MAX = 1000;

/** Octets d'une trame de la copie remise à l'adaptateur du miroir, et connexions copiées suivies à la fois (CT-2 EX-5.6). */
export const MIROIR_TRAME_MAX_OCTETS = 16777216;
export const MIROIR_CONNEXIONS_MAX = 10000;

/**
 * Longueur maximale, en octets UTF-8, du chemin d'une prise Unix que le démon
 * ou ses processus ouvrent ou joignent (`mcp.socket`, `sdk.socket`,
 * `model.mirror.socket`, `policy.approval.service.socket`, `--socket` de
 * `noortrace-miroir` et de `noortrace-connecteur` ; CT-2 EX-18.1, complément
 * du 2026-11-16). Même borne que le SDK (`CHEMIN_PRISE_MAX` de
 * paquets/sdk-js, `CHEMIN_PRISE_MAX` de paquets/sdk-python ; CT-2 EX-6.10) :
 * Node.js tronque le chemin à `sizeof(sockaddr_un.sun_path) - 1`, 107 octets
 * sous Linux et 103 sous macOS (R12-F50) ; un chemin plus long ferait écouter
 * ou joindre une autre prise, souvent dans le répertoire parent.
 */
export const CHEMIN_PRISE_MAX_OCTETS = 103;

/**
 * Règle de longueur d'un chemin de prise Unix (EX-18.1, EX-6.10).
 * @param {unknown} chemin
 * @returns {string|null} la règle violée (`chemin_prise_trop_long : …`), ou null
 */
export function regleCheminPrise(chemin) {
  if (typeof chemin !== "string") return null;
  const n = Buffer.byteLength(chemin, "utf8");
  return n > CHEMIN_PRISE_MAX_OCTETS ? `chemin_prise_trop_long : ${n} octets, au plus ${CHEMIN_PRISE_MAX_OCTETS} (EX-18.1, EX-6.10)` : null;
}

/** Attente de la réponse rédigée d'un échange par la corrélation d'un appel d'outil, en millisecondes (CT-2 EX-5.11). */
export const CORRELATION_ATTENTE_MAX_MS = 5000;

/** Membres d'un `approver_set` d'une remise admis à l'inscription (EX-7.19 pas 2). */
export const MEMBRES_JEU_REMISE_MAX = 1024;

/** Octets d'une remise de décision admise à l'inscription. */
export const REMISE_MAX_OCTETS = 1048576;

/**
 * Copie plate d'une chaîne : une chaîne courte est déjà une copie (V8 ne
 * tranche pas sous treize caractères) ; une autre est recopiée par un
 * aller-retour UTF-8, qui ne garde aucune référence au texte d'origine.
 * @param {string} s
 * @returns {string}
 */
export function copierChaine(s) {
  if (typeof s !== "string" || s.length < 13) return s;
  return Buffer.from(s, "utf8").toString("utf8");
}

/**
 * Chaîne recopiée et bornée pour le journal d'exploitation : au-delà de
 * `max` caractères, le début, puis `…[n]` où `n` est la longueur d'origine
 * (EX-17.3 admet les tailles).
 * @param {unknown} s
 * @param {number} [max]
 * @returns {unknown} la valeur telle quelle si ce n'est pas une chaîne
 */
export function chaineBornee(s, max = CHAINE_JOURNAL_MAX) {
  if (typeof s !== "string") return s;
  if (s.length <= max) return copierChaine(s);
  return `${copierChaine(s.slice(0, max))}…[${s.length}]`;
}

/**
 * Valeur de `data` d'une ligne d'exploitation, chaînes recopiées et bornées à
 * tout niveau (profondeur au plus `profondeur`, au-delà la valeur est
 * remplacée par sa sorte) ; objets et tableaux recopiés.
 * @param {unknown} v
 * @param {number} [profondeur]
 * @returns {unknown}
 */
export function bornerValeurJournal(v, profondeur = 8) {
  if (typeof v === "string") return chaineBornee(v);
  if (v === null || typeof v !== "object") return v;
  if (profondeur <= 0) return Array.isArray(v) ? `[tableau:${v.length}]` : "[objet]";
  if (Array.isArray(v)) return v.map((x) => bornerValeurJournal(x, profondeur - 1));
  if (v instanceof Uint8Array) return `[octets:${v.length}]`;
  const o = {};
  for (const k of Object.keys(v)) o[chaineBornee(k)] = bornerValeurJournal(v[k], profondeur - 1);
  return o;
}

/**
 * Texte décimal d'un entier admissible avant `BigInt` : signe facultatif,
 * au plus `CHIFFRES_ENTIER_MAX` chiffres.
 * @param {string} s
 * @returns {boolean}
 */
export function entierCourt(s) {
  return typeof s === "string" && s.length <= CHIFFRES_ENTIER_MAX + 1 && /^-?[0-9]{1,20}$/.test(s);
}

/**
 * Compteur d'un budget : `prendre(n)` rend faux dès que le budget est épuisé.
 */
export class Budget {
  /** @param {number} max */
  constructor(max) {
    this.max = max;
    this.n = 0;
  }

  prendre(n = 1) {
    this.n += n;
    return this.n <= this.max;
  }
}
