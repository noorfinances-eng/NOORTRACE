// Implémentation de référence de la spécification CT-3 de NOORTRACE
// (spec/CT-3-approbations.md) : les approbations.
//
//   - validation de la politique d'approbation (document
//     politique-approbation-v0) : schéma et règles que le schéma n'exprime pas,
//     avec la liste complète des erreurs (section 4, EX-4.2, EX-8.2) ;
//   - évaluation exacte d'une demande (section 6) : sélection de l'outil,
//     pointeurs RFC 6901, comparaisons décimales en entiers exacts, logique à
//     trois valeurs, issues, rangs, règle par défaut, fenêtres ;
//   - outils susceptibles d'approbation (CANDIDATS, EX-4.11) ;
//   - machine à états du service d'approbation (sections 7, 8, 10 et 12) :
//     tickets, minuteurs, votes, décompte, fenêtre de contestation,
//     séparation des tâches, gel du jeu, remises, acquittements, fenêtres ;
//   - lecture du jeu d'approbateurs dans le CuratorSetRegistry, par une source
//     JSON-RPC fournie par l'appelant (EX-8.1, EX-8.5) ;
//   - objet signé A, normalisation d'un vote (EX-9.3) et vérification d'une
//     remise par le noyau avant scellement (SG-1 à SG-7, EX-9.11 ; CT-2
//     EX-7.5), avec les fonctions EIP-191 de scripts/lib/journal.mjs ;
//   - comportement observable du mandataire (section 11 ; CT-2 EX-4.49,
//     EX-4.50, EX-6.7) ;
//   - partie calculable des échanges du noyau de l'enregistreur avec le
//     service (CT-2 §7.5 : messages charger, ouvrir, acquitter, consommer,
//     expiration ; vérifications de relais RL-1 à RL-4 et MAC de relais ;
//     expiration par le noyau ; motif rédigé ; fichiers des approbations ;
//     contrôles de démarrage de la configuration qui touchent l'approbation).
//
// Fonctions pures, sauf la lecture du jeu (asynchrone, par la source donnée) :
// aucune horloge (les instants sont des paramètres), aucun accès au système de
// fichiers ni au réseau. Les scripts (scripts/vecteurs/generer-ct3.mjs)
// lisent et écrivent les fichiers.
//
// Conventions (CT-1 §3) : octets en hexadécimal minuscule préfixé 0x,
// horodatages RFC 3339 UTC à la milliseconde, clés JSON en anglais, valeurs
// énumérées en français sans accent.

import { createHmac } from "node:crypto";
import { Interface, ZeroAddress, getAddress, toQuantity } from "ethers";
import * as J from "./journal.mjs";
import * as C from "./capture.mjs";

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

/** Identifiants des schémas de CT-3. */
export const ID_SCHEMA_POLITIQUE_APPROBATION = "https://noortrace.example/schemas/v0/politique-approbation.schema.json";
export const ID_SCHEMA_TICKET = "https://noortrace.example/schemas/v0/ticket.schema.json";
/** Les fichiers de spec/schemas à charger ensemble (références croisées du schéma de ticket). */
export const FICHIERS_SCHEMAS = ["evenement-v0.schema.json", "politique-approbation-v0.schema.json", "ticket-v0.schema.json"];

/** Les trois valeurs de vérité d'une condition (section 4). */
export const VRAI = "VRAI";
export const FAUX = "FAUX";
export const INDETERMINE = "INDETERMINE";

/** Niveaux d'une règle (section 5). */
export const NIVEAUX = ["automatique", "fenetre", "revue"];
/** Opérateurs de comparaison numérique (table 4.9). */
export const OPERATEURS_NUMERIQUES = ["egal_numerique", "strictement_superieur", "superieur_ou_egal", "strictement_inferieur", "inferieur_ou_egal"];

/** Grammaire décimale D (EX-4.6). */
export const RE_DECIMAL = /^-?(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?$/;
/** Motif d'un nom annoncé (CT-1 execution.tool, CT-2 EX-4.10). */
export const RE_NOM_ANNONCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
/** Identifiant de ticket (EX-7.1). */
export const RE_IDENTIFIANT_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;
/** `source` d'un jeu lu au registre (EX-8.8). */
export const RE_SOURCE_REGISTRE = /^CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?$/;
/** `source` d'un jeu statique (EX-8.8). */
export const RE_SOURCE_STATIQUE = /^jeu statique de la politique .{1,128}$/u;

/** Bornes que le schéma n'exprime pas (EX-4.2). */
export const MAX_JETONS_POINTEUR = 32;
export const MAX_PROFONDEUR_CONDITION = 8;
export const MAX_PREDICATS_REGLE = 64;
/** Longueur maximale d'un motif de vote (EX-9.10). */
export const MAX_MOTIF = 1024;
/** Attente maximale d'une requête `decisions` (EX-12.8). */
export const ATTENTE_DECISIONS_MAX_MS = 25000;
/** Tranche maximale d'une requête eth_getLogs sur noorcore (EX-8.1, pas 5). */
export const TRANCHE_JOURNAUX = 16384;
/** Plafond de tickets non décidés par demandeur, quand la configuration ne le donne pas (défaut de 10.3). */
export const PLAFOND_TICKETS_DEFAUT = 20;
/** Intervalle de lecture du jeu par défaut (8.2). */
export const INTERVALLE_LECTURE_DEFAUT_MS = 10000;

/** Mode d'attente de la configuration de référence, de la démonstration et des outils du projet (EX-11.1) ; le membre mode est requis par le schéma de configuration de CT-2. */
export const MODE_ATTENTE_DEFAUT = "erreur";

/** États du ticket (7.3). */
export const ETATS = ["reserve", "ouvert", "seuil_atteint", "verification", "a_remettre", "approuve", "refuse", "expire", "consomme", "clos", "abandonne"];
/** États non décidés (EX-14.1). */
export const ETATS_NON_DECIDES = ["reserve", "ouvert", "seuil_atteint", "verification", "a_remettre"];
/** États où un vote, une récusation, un retrait ou une lecture du jeu s'applique (T5, T6, T10). */
export const ETATS_COLLECTE = ["ouvert", "seuil_atteint", "verification"];
/** États décidés tant que court le délai de reconnaissance (EX-7.5). */
export const ETATS_DECIDES = ["approuve", "refuse", "expire"];

/** Chaînes fixes de `approval.reason` d'une décision expire (EX-7.11), dans l'ordre de priorité. */
export const RAISONS_EXPIRATION = Object.freeze({
  reservation: "reservation abandonnee avant l'ouverture",
  retrait: "echeance avancee par retrait",
  caduque: "decision non scellee avant l'echeance",
  jeu_illisible: "echeance atteinte, jeu d'approbateurs illisible",
  jeu_reassigne: "echeance atteinte, jeu reassigne",
  seuil_inatteignable: "echeance atteinte, seuil inatteignable",
  objection: "echeance atteinte, objection non levee",
  contestation: "echeance atteinte pendant la fenetre de contestation",
  autre: "echeance atteinte sans decision",
});
/** `reason` d'une expiration scellée par le noyau seul (EX-12.11). */
export const RAISON_EXPIRATION_NOYAU = "expire par l'enregistreur, service d'approbation sans reponse";

/** Texte fixe du résultat d'un appel refusé par la politique sans ticket (EX-11.8). */
export const TEXTE_REFUS_POLITIQUE = "noortrace: appel refuse par la politique";
/** Clé de _meta qui porte l'identité de l'enregistreur dans un résultat rendu (CT-2 EX-4.4, 4.4 pas 14). */
export const CLE_SERVER_INFO = "io.modelcontextprotocol/serverInfo";
/** Clé de _meta qui porte le ticket et son état dans le signal d'approbation (CT-2 EX-4.49). */
export const CLE_META_APPROBATION = "noortrace/approval";
/** États que porte le signal d'approbation (CT-2 EX-4.49, table d'EX-11.7). */
export const ETATS_SIGNAL = ["en_attente", "refuse", "expire"];

/** Codes d'erreur de validation d'une politique (ticket-v0, $defs/code_erreur_politique). */
export const CODES_ERREUR_POLITIQUE = ["schema", "nom_double", "pointeur_trop_long", "condition_trop_profonde", "trop_de_predicats", "substitut_isole", "launched_by_double", "contest_ms_trop_long", "seuil_statique_incoherent", "jeu_statique_en_production"];

/** Ordre des vérifications du noyau sur une remise (EX-9.11 ; SG-7 adoptée par CT-2 0.3, EX-7.5). */
export const VERIFICATIONS_REMISE = ["SG-1", "SG-2", "SG-3", "SG-4", "SG-5", "SG-6", "SG-7"];
/** Ordre des vérifications du noyau avant de relayer un appel approuvé (CT-2 EX-7.21). */
export const VERIFICATIONS_RELAIS = ["RL-1", "RL-2", "RL-3", "RL-4"];
/** Domaine du MAC de relais (CT-2 EX-7.22). */
export const DOMAINE_MAC_RELAIS = "noortrace/relais/v0";
/** Longueur minimale, en octets décodés, de la clé du MAC de relais et de la clé de pseudonymisation (CT-2 EX-7.22, EX-10.12). */
export const LONGUEUR_CLE_MIN = 32;
/** Longueur maximale de approval.reason (CT-1 §5.3, CT-2 EX-10.24). */
export const MAX_MOTIF_DECISION = 1024;

const N_SECP256K1 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const MOITIE_N = N_SECP256K1 / 2n;

const copie = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const longueur = (s) => [...s].length;
const exiger = (condition, message) => {
  if (!condition) throw new Error(`approbation : ${message}`);
};
/** Échappement d'un nom de membre dans un pointeur JSON (RFC 6901 §3). */
const echapper = (k) => String(k).replace(/~/g, "~0").replace(/\//g, "~1");
const ms = (ts) => {
  const v = J.msHorodatage(ts);
  exiger(!Number.isNaN(v), `horodatage invalide : ${JSON.stringify(ts)}`);
  return v;
};

// ---------------------------------------------------------------------------
// Schémas
// ---------------------------------------------------------------------------

/** Registre des trois schémas de CT-3 à partir de leurs documents (voir FICHIERS_SCHEMAS). */
export function registreSchemas(documents) {
  return J.registreSchemas(documents);
}

/** Erreurs de schéma d'une valeur contre un $defs de ticket-v0 (`#/$defs/<nom>`), ou contre la politique (`nom` = null). */
export function erreursSchema(valeur, schemas, nom = null) {
  if (nom === null) return J.validerSchema(valeur, schemas[ID_SCHEMA_POLITIQUE_APPROBATION], { registre: schemas });
  return J.validerSchema(valeur, schemas[ID_SCHEMA_TICKET], { registre: schemas, fragment: `#/$defs/${nom}` });
}

// ---------------------------------------------------------------------------
// Validation d'une politique d'approbation (EX-4.2, EX-8.2, EX-4.14)
// ---------------------------------------------------------------------------

/** Jetons d'un pointeur (RFC 6901 §4 : ~1 décodé avant ~0), sans la contrôler. */
export function jetonsPointeur(pointeur) {
  return pointeur.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/** Profondeur d'une condition : un prédicat est au niveau 1, chaque all, any ou none ajoute un niveau (EX-4.2, point 3). */
export function profondeurCondition(c) {
  for (const k of ["all", "any", "none"]) if (Object.hasOwn(c, k)) return 1 + Math.max(...c[k].map(profondeurCondition));
  return 1;
}

/** Les prédicats d'une condition avec leur pointeur JSON relatif (`""` pour la condition elle-même), dans l'ordre du document. */
export function predicatsCondition(c, chemin = "") {
  for (const k of ["all", "any", "none"]) if (Object.hasOwn(c, k)) return c[k].flatMap((e, i) => predicatsCondition(e, `${chemin}/${k}/${i}`));
  return [{ predicat: c, chemin }];
}

/** Chaînes du document (valeurs et noms de membres) qui contiennent un substitut isolé, par pointeur. */
function substitutsIsoles(v, chemin, out) {
  if (typeof v === "string") {
    if (!J.chaineBienFormee(v)) out.push(chemin);
  } else if (Array.isArray(v)) {
    v.forEach((e, i) => substitutsIsoles(e, `${chemin}/${i}`, out));
  } else if (estObjet(v)) {
    for (const k of Object.keys(v)) {
      if (!J.chaineBienFormee(k)) out.push(`${chemin}/${echapper(k)}`);
      substitutsIsoles(v[k], `${chemin}/${echapper(k)}`, out);
    }
  }
  return out;
}

/**
 * Erreurs de validation d'un document politique-approbation-v0 au chargement
 * (EX-4.2, EX-8.2) : liste COMPLÈTE de { code, pointer }, triée par pointer
 * puis par code (annexe A.4). Une non-conformité au schéma donne une seule
 * entrée { code: "schema", pointer: null }, quel que soit le nombre d'erreurs
 * de schéma ; les règles que le schéma n'exprime pas ne sont alors pas
 * vérifiées (elles supposent la forme du schéma). `environment` est celui que
 * transmet le message charger (12.2) ; `expire_after_ms` est la valeur de
 * /policy/approval/expire_after_ms sous laquelle le document est chargé.
 */
export function erreursPolitique(doc, { schemas, environment, expire_after_ms }) {
  exiger(schemas?.[ID_SCHEMA_POLITIQUE_APPROBATION], "schéma politique-approbation-v0 absent du registre");
  if (erreursSchema(doc, schemas).length) return [{ code: "schema", pointer: null }];
  return erreursSemantiques(doc, { environment, expire_after_ms });
}

/**
 * Les règles d'EX-4.2 (points 1 à 7) et d'EX-8.2 que le schéma n'exprime pas,
 * sur un document conforme au schéma : liste de { code, pointer } triée par
 * pointer puis par code.
 */
export function erreursSemantiques(doc, { environment, expire_after_ms }) {
  exiger(environment === "production" || environment === "developpement", `environment invalide : ${JSON.stringify(environment)}`);
  exiger(Number.isSafeInteger(expire_after_ms) && expire_after_ms >= 1, "expire_after_ms entier positif attendu");
  const erreurs = [];
  const ajouter = (code, pointer) => erreurs.push({ code, pointer });

  // 1. Noms uniques, règle par défaut comprise : la règle par défaut est lue
  // la première, puis les règles dans l'ordre ; chaque reprise d'un nom déjà vu
  // est une erreur à son propre pointeur.
  const noms = new Set([doc.default.name]);
  doc.rules.forEach((r, i) => {
    if (noms.has(r.name)) ajouter("nom_double", `/rules/${i}/name`);
    noms.add(r.name);
  });

  doc.rules.forEach((r, i) => {
    // 2. Pointeurs d'au plus 32 jetons : prédicats et same_arguments.
    if (r.when !== null) {
      const preds = predicatsCondition(r.when);
      for (const { predicat, chemin } of preds) if (jetonsPointeur(predicat.path).length > MAX_JETONS_POINTEUR) ajouter("pointeur_trop_long", `/rules/${i}/when${chemin}/path`);
      // 3. Profondeur et nombre de prédicats : une erreur par règle, au pointeur de la condition.
      if (profondeurCondition(r.when) > MAX_PROFONDEUR_CONDITION) ajouter("condition_trop_profonde", `/rules/${i}/when`);
      if (preds.length > MAX_PREDICATS_REGLE) ajouter("trop_de_predicats", `/rules/${i}/when`);
    }
    if (r.window !== null) r.window.same_arguments.forEach((p, k) => {
      if (jetonsPointeur(p).length > MAX_JETONS_POINTEUR) ajouter("pointeur_trop_long", `/rules/${i}/window/same_arguments/${k}`);
    });
    // 6. contest_ms < expire_after_ms.
    if (r.contest_ms !== null && r.contest_ms >= expire_after_ms) ajouter("contest_ms_trop_long", `/rules/${i}/contest_ms`);
  });
  if (doc.default.contest_ms !== null && doc.default.contest_ms >= expire_after_ms) ajouter("contest_ms_trop_long", "/default/contest_ms");

  // 4. Chaînes bien formées.
  for (const p of substitutsIsoles(doc, "", [])) ajouter("substitut_isole", p);

  // 5. Un launched_by une seule fois.
  const identites = new Set();
  doc.separation.identities.forEach((e, j) => {
    if (identites.has(e.launched_by)) ajouter("launched_by_double", `/separation/identities/${j}/launched_by`);
    identites.add(e.launched_by);
  });

  // 7. Règles propres à approver_set (EX-8.2).
  const js = doc.approver_set;
  if (js.source === "statique") {
    if (js.threshold.size !== js.members.length || js.threshold.required > js.threshold.size) ajouter("seuil_statique_incoherent", "/approver_set/threshold");
    if (environment === "production") ajouter("jeu_statique_en_production", "/approver_set/source");
  }

  return erreurs.sort((a, b) => (a.pointer < b.pointer ? -1 : a.pointer > b.pointer ? 1 : a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
}

/**
 * Avertissements de chargement (EX-4.14), sans refus : sélecteurs qui ne
 * désignent aucun nom de `outils` ; pointeurs qui désignent un chemin rédigé
 * ou supprimé par la politique de rédaction (`cheminsRediges` : pointeurs
 * /arguments/… des règles champ de portée arguments) ; règle fenetre à
 * plusieurs sélecteurs ou à joker, sans same_arguments ou sans condition
 * (sa fenêtre couvre plus que l'appel approuvé, EX-5.2) ; liste d'exclusion
 * (egal ou dans placé sous un nombre pair de none, zéro compris, dans la
 * condition d'une règle automatique refuse ; sous un nombre impair de none, le
 * prédicat forme une liste blanche, none sur egal ou dans, qui n'est pas
 * signalée, CT-3 EX-4.14) ; demandeur configuré
 * (`demandeurs` : launched_by des connexions d'hôte, transmis par charger)
 * sans entrée dans separation.identities alors que self_approval vaut
 * interdite (séparation non vérifiable, EX-10.5). Rend des chaînes.
 */
export function avertissementsPolitique(doc, { outils = null, cheminsRediges = [], demandeurs = [] } = {}) {
  const out = [];
  doc.rules.forEach((r, i) => {
    if (outils) r.tools.forEach((s, k) => {
      if (!outils.some((nom) => selectionne([s], nom))) out.push(`/rules/${i}/tools/${k} : le sélecteur ${s} ne désigne aucun outil de la liste reçue`);
    });
    const pointeurs = [...(r.when ? predicatsCondition(r.when).map((p) => p.predicat.path) : []), ...(r.window?.same_arguments ?? [])];
    for (const p of pointeurs) if (cheminsRediges.some((c) => p === c || p.startsWith(c + "/"))) out.push(`/rules/${i} : le pointeur ${p} désigne un chemin rédigé ; la réévaluation de 6.8 ne pourra pas conclure`);
    if (r.level === "fenetre") {
      if (r.tools.length > 1 || r.tools.some((s) => s.endsWith("*"))) out.push(`/rules/${i}/tools : règle fenetre à plusieurs outils ou à joker ; chaque outil a sa propre portée (EX-5.2), mais l'approbateur doit voir lesquels sa décision couvre`);
      if (r.window.same_arguments.length === 0) out.push(`/rules/${i}/window/same_arguments : vide ; la fenêtre couvre toute valeur des arguments que la condition admet`);
      if (r.when === null) out.push(`/rules/${i}/when : nulle ; la fenêtre couvre tout appel de l'outil, sans borne sur ses arguments`);
    }
    if (r.level === "automatique" && r.decision === "refuse" && r.when !== null) for (const { predicat, chemin } of predicatsCondition(r.when)) {
      // Sous un nombre impair de none, egal ou dans forme une liste blanche (none sur egal ou dans), qui ne laisse rien passer : pas d'avertissement (EX-4.14).
      const negations = chemin.split("/").filter((x) => x === "none").length;
      if ((predicat.op === "egal" || predicat.op === "dans") && negations % 2 === 0) out.push(`/rules/${i}/when${chemin} : liste d'exclusion (${predicat.op}) ; une autre écriture de la valeur y échappe (4.8) : préférer une liste blanche`);
    }
  });
  if (doc.separation.self_approval === "interdite") for (const lb of demandeurs) {
    if (!doc.separation.identities.some((e) => e.launched_by === lb)) out.push(`/separation/identities : aucune entrée pour le demandeur ${lb} ; la séparation des tâches n'est pas vérifiable pour lui (EX-10.5)`);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Évaluation (sections 4 et 6)
// ---------------------------------------------------------------------------

const RE_INDICE = /^(0|[1-9][0-9]{0,8})$/;

/**
 * RESOUDRE (EX-4.4) : le pointeur `p` appliqué à la racine R = { arguments }.
 * Rend { resolu, valeur }. Membre d'objet d'abord ; indice de tableau `0` ou
 * `[1-9][0-9]{0,8}` inférieur à la longueur ; tout le reste est non résolu.
 */
export function resoudre(R, p) {
  let x = R;
  for (const j of jetonsPointeur(p)) {
    if (estObjet(x) && Object.hasOwn(x, j)) x = x[j];
    else if (Array.isArray(x) && RE_INDICE.test(j) && Number(j) < x.length) x = x[Number(j)];
    else return { resolu: false, valeur: undefined };
  }
  return { resolu: true, valeur: x };
}

/**
 * NUMERIQUE (EX-4.5, EX-4.6) : le couple (m, e) d'entiers exacts d'une valeur
 * numérique, ou null. Nombre JSON entier de [-(2^53-1), 2^53-1] : (valeur, 0) ;
 * chaîne D : (chiffres sans le point, avec le signe ; nombre de décimales).
 */
export function valeurNumerique(v) {
  if (typeof v === "number") {
    if (!Number.isInteger(v) || Math.abs(v) > Number.MAX_SAFE_INTEGER) return null;
    return { m: BigInt(v), e: 0 };
  }
  if (typeof v !== "string" || !RE_DECIMAL.test(v)) return null;
  const negatif = v.startsWith("-");
  const [entier, fraction = ""] = (negatif ? v.slice(1) : v).split(".");
  const m = BigInt(entier + fraction);
  return { m: negatif ? -m : m, e: fraction.length };
}

/** COMPARER (EX-4.6) : -1, 0 ou 1, en entiers de précision arbitraire mis à la même échelle. */
export function comparerNumeriques(a, b) {
  const E = Math.max(a.e, b.e);
  const x = a.m * 10n ** BigInt(E - a.e);
  const y = b.m * 10n ** BigInt(E - b.e);
  return x < y ? -1 : x > y ? 1 : 0;
}

/** PREDICAT (table 4.9) : VRAI, FAUX ou INDETERMINE. */
export function valeurPredicat(p, R) {
  const { resolu, valeur } = resoudre(R, p.path);
  if (p.op === "existe") return resolu ? VRAI : FAUX;
  if (!resolu) return INDETERMINE;
  switch (p.op) {
    case "egal":
      if (typeof valeur !== typeof p.value || valeur === null) return INDETERMINE;
      return valeur === p.value ? VRAI : FAUX;
    case "dans":
      if (typeof valeur !== "string") return INDETERMINE;
      return p.value.includes(valeur) ? VRAI : FAUX;
    case "commence_par":
      if (typeof valeur !== "string") return INDETERMINE;
      return valeur.startsWith(p.value) ? VRAI : FAUX;
    case "finit_par":
      if (typeof valeur !== "string") return INDETERMINE;
      return valeur.endsWith(p.value) ? VRAI : FAUX;
    default: {
      exiger(OPERATEURS_NUMERIQUES.includes(p.op), `opérateur inconnu : ${p.op}`);
      const a = valeurNumerique(valeur);
      if (a === null) return INDETERMINE;
      const c = comparerNumeriques(a, valeurNumerique(p.value));
      const ok = { egal_numerique: c === 0, strictement_superieur: c > 0, superieur_ou_egal: c >= 0, strictement_inferieur: c < 0, inferieur_ou_egal: c <= 0 }[p.op];
      return ok ? VRAI : FAUX;
    }
  }
}

/** Combinaison de Kleene (EX-4.8) de valeurs déjà calculées. */
export function combiner(op, valeurs) {
  switch (op) {
    case "all":
      return valeurs.includes(FAUX) ? FAUX : valeurs.includes(INDETERMINE) ? INDETERMINE : VRAI;
    case "any":
      return valeurs.includes(VRAI) ? VRAI : valeurs.every((v) => v === FAUX) ? FAUX : INDETERMINE;
    case "none":
      return valeurs.includes(VRAI) ? FAUX : valeurs.every((v) => v === FAUX) ? VRAI : INDETERMINE;
    default:
      throw new Error(`approbation : combinaison inconnue ${op}`);
  }
}

/** VALEUR d'une condition (EX-4.8), récursive. */
export function valeurCondition(c, R) {
  for (const op of ["all", "any", "none"]) if (Object.hasOwn(c, op)) return combiner(op, c[op].map((e) => valeurCondition(e, R)));
  return valeurPredicat(c, R);
}

/** SELECTIONNE (EX-4.3) : nom exact, préfixe `p*`, ou `*`. */
export function selectionne(selecteurs, nom) {
  return selecteurs.some((s) => (s.endsWith("*") ? nom.startsWith(s.slice(0, -1)) : s === nom));
}

/** Racine R = { "arguments": A } d'une demande (4.5) ; `{}` quand la requête ne porte pas d'arguments. */
export const racineDemande = (d) => ({ arguments: d.arguments === undefined ? {} : d.arguments });

/**
 * Portée K d'une demande pour une règle fenetre (EX-5.2) : { policy_version,
 * rule, tool, launched_by, values }, ou null si l'un des pointeurs de
 * same_arguments n'est pas résolu ou ne désigne pas une chaîne. Le nom
 * annoncé de l'outil fait partie de la portée : une approbation ne couvre
 * jamais un autre outil que celui de la demande ouvrante.
 */
export function porteeFenetre(regle, d, policy_version) {
  const R = racineDemande(d);
  const values = [];
  for (const p of regle.window.same_arguments) {
    const r = resoudre(R, p);
    if (!r.resolu || typeof r.valeur !== "string") return null;
    values.push(r.valeur);
  }
  return { policy_version, rule: regle.name, tool: d.tool_announced, launched_by: d.delegation.launched_by, values };
}

/** Indice de la fenêtre de `fenetres` qui couvre la portée K à l'instant t (EX-5.5), ou -1 ; la première dans l'ordre de F. */
export function fenetreCouvrante(fenetres, K, tMs) {
  return fenetres.findIndex((w) => J.egalJSON(w.scope, K) && ms(w.start) <= tMs && tMs < ms(w.end) && w.remaining >= 1);
}

/**
 * ISSUE (EX-6.2) d'une règle qui sélectionne la demande, de condition `v`
 * (VRAI ou INDETERMINE) : { k, x, m, fenetre } (rang, décision, marque,
 * indice de la fenêtre qui couvre la demande pour le rang 2).
 */
export function issueRegle(r, v, K, fenetres, tMs) {
  const marque = v === INDETERMINE ? " [indetermine]" : "";
  switch (r.level) {
    case "automatique":
      if (r.decision === "autorise") return v === VRAI ? { k: 1, x: "autorise", m: "", fenetre: null } : { k: 0 };
      return { k: 5, x: "refuse", m: marque, fenetre: null };
    case "fenetre": {
      if (v === VRAI) {
        const i = fenetreCouvrante(fenetres, K, tMs);
        if (i !== -1) return { k: 2, x: "autorise", m: ` [fenetre ${fenetres[i].ticket} ${fenetres[i].end}]`, fenetre: i };
      }
      return { k: 3, x: "a_approuver", m: marque, fenetre: null };
    }
    case "revue":
      return { k: 4, x: "a_approuver", m: marque, fenetre: null };
    default:
      throw new Error(`approbation : niveau inconnu ${r.level}`);
  }
}

/**
 * EVALUER (6.2) : la politique `P` (valide), la demande `d` (requête evaluer
 * de 12.3 : tool_announced, arguments, delegation.launched_by), les fenêtres
 * ouvertes `fenetres` (objets fenetre_ouverte de ticket-v0) et l'instant `t`
 * (horodatage). `policy_version` est la version en vigueur, qui entre dans la
 * portée d'une fenêtre ; par défaut code.policy_version de la demande.
 *
 * Rend { rule, decision, contest_ms, opening, fenetres, fenetreConsommee } :
 * `rule` et `decision` sont la réponse de CT-2 EX-7.4 ; `contest_ms` et
 * `opening` vont au ticket créé pour a_approuver (null sinon) ; `fenetres` est
 * l'état F après l'évaluation (une unité consommée au rang 2, EX-5.5 ; aucune
 * fenêtre n'est retirée, EX-6.5) ; `fenetreConsommee` l'indice consommé ou null.
 * La fonction n'a pas d'effet : la création du ticket revient au service.
 */
export function evaluer(P, d, { fenetres = [], t, policy_version = d.code?.policy_version } = {}) {
  const tMs = typeof t === "number" ? t : ms(t);
  const R = racineDemande(d);
  const issues = [];
  P.rules.forEach((r, i) => {
    if (!selectionne(r.tools, d.tool_announced)) return;
    let v = r.when === null ? VRAI : valeurCondition(r.when, R);
    let K = null;
    if (r.level === "fenetre") {
      K = porteeFenetre(r, d, policy_version);
      v = combiner("all", [v, K === null ? INDETERMINE : VRAI]);
    }
    if (v === FAUX) return;
    const issue = issueRegle(r, v, K, fenetres, tMs);
    if (issue.k > 0) issues.push({ ...issue, i, K });
  });
  let rule;
  let decision;
  let contest_ms = null;
  let opening = null;
  let fenetreConsommee = null;
  if (issues.length === 0) {
    rule = P.default.name;
    decision = P.default.level === "automatique" ? P.default.decision : "a_approuver";
    if (decision === "a_approuver") contest_ms = P.default.contest_ms;
  } else {
    const kMax = Math.max(...issues.map((c) => c.k));
    const e = issues.find((c) => c.k === kMax);
    const r = P.rules[e.i];
    rule = r.name + e.m;
    decision = e.x;
    if (decision === "a_approuver") contest_ms = r.contest_ms;
    if (kMax === 3 && e.m === "") opening = { scope: e.K, duration_ms: r.window.duration_ms, max_calls: r.window.max_calls };
    if (kMax === 2) fenetreConsommee = e.fenetre;
  }
  const apres = fenetres.map(copie);
  if (fenetreConsommee !== null) apres[fenetreConsommee].remaining -= 1;
  return { rule, decision, contest_ms, opening, fenetres: apres, fenetreConsommee };
}

/**
 * CANDIDATS(P, L) (EX-4.11) : les noms de L, dans l'ordre de L, sans doublon,
 * qu'une règle peut soumettre à approbation ou refuser, ou que la règle par
 * défaut peut décider quand elle n'est pas (automatique, autorise).
 */
export function candidats(P, L) {
  const defautRestrictif = !(P.default.level === "automatique" && P.default.decision === "autorise");
  const vus = new Set();
  const out = [];
  for (const nom of L) {
    if (vus.has(nom)) continue;
    vus.add(nom);
    const regles = P.rules.filter((r) => selectionne(r.tools, nom));
    const c1 = regles.some((r) => r.level !== "automatique" || r.decision === "refuse");
    const c2 = defautRestrictif && !regles.some((r) => r.when === null);
    if (c1 || c2) out.push(nom);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Objet signé, normalisation d'un vote, vérification d'une remise (section 9)
// ---------------------------------------------------------------------------

/** A = { decision, journal_id, org_id, request_hash, ticket } (CT-1 §6.3), dans l'ordre des clés de CT-1. */
export function objetA({ decision, journal_id, org_id, request_hash, ticket }) {
  return J.objetApprobation({ decision, journal_id, org_id, request_hash, ticket });
}

/** Ce que la console calcule et affiche (EX-9.6) : A, D_A (64 chiffres hexadécimaux) et le condensé EIP-191 signé. */
export function condensesVote(champs) {
  const A = objetA(champs);
  return { A, D_A: J.condenseApprobation(A), M: J.condenseEIP191Approbation(A) };
}

/** Signature d'un vote par un Wallet ethers (tests, vecteurs) : EIP-191 sur les octets de D_A (EX-9.7). */
export function signerVote(wallet, champs) {
  return J.signerApprobation(wallet, objetA(champs));
}

/**
 * Normalisation d'une signature reçue (EX-9.3), sans la clé : 65 octets
 * exigés ; r et s dans [1, n − 1], sinon refus ; v ∈ {0, 1} devient v + 27 ;
 * v hors de {27, 28} est refusé ; s dans la moitié haute devient n − s et v
 * est inversé.
 * Rend { signature, reason } (signature null et reason signature_invalide en
 * cas de refus).
 */
export function normaliserSignature(signature) {
  const refus = { signature: null, reason: "signature_invalide" };
  if (typeof signature !== "string" || !/^0x([0-9a-f]{2})*$/.test(signature) || signature.length !== 132) return refus;
  const r = signature.slice(2, 66);
  const rn = BigInt("0x" + r);
  let s = BigInt("0x" + signature.slice(66, 130));
  let v = parseInt(signature.slice(130, 132), 16);
  if (rn === 0n || rn >= N_SECP256K1 || s === 0n || s >= N_SECP256K1) return refus;
  if (v === 0 || v === 1) v += 27;
  if (v !== 27 && v !== 28) return refus;
  if (s > MOITIE_N) {
    s = N_SECP256K1 - s;
    v = v === 27 ? 28 : 27;
  }
  return { signature: "0x" + r + s.toString(16).padStart(64, "0") + v.toString(16), reason: null };
}

/**
 * Vérification d'une remise par le noyau avant scellement (EX-9.11, CT-2
 * EX-7.5) : SG-1 à SG-7 dans l'ordre, la première en échec donne la raison.
 * `contexte` : { org_id, journal_id, retained: [{ seq, ticket, hash, ts,
 * launched_by }], decided: [{ ticket, decision, seq, hash, at }],
 * expire_after_ms, separation, write_at } (annexe A.7) : expire_after_ms et
 * separation sont ceux de la politique de la version de l'événement retenue.
 * Rend { result: "scelle" | "refuse", reason, check }.
 */
export function verifierRemise(remise, contexte, { schemas }) {
  const refus = (check, reason) => ({ result: "refuse", reason, check });
  // SG-1 : forme de $defs/remise (approval sans at, source d'EX-8.8), approval.ticket = ticket, remise_id = <ticket>/<n>.
  if (erreursSchema(remise, schemas, "remise").length || remise.approval.ticket !== remise.ticket || !remise.remise_id.startsWith(`${remise.ticket}/`)) return refus("SG-1", "remise_mal_formee");
  const a = remise.approval;
  // SG-2 : un événement retenue porte ce ticket, et l'un d'eux a pour hash request_hash.
  const retenues = contexte.retained.filter((e) => e.ticket === remise.ticket);
  if (retenues.length === 0) return refus("SG-2", "ticket_inconnu");
  const demande = retenues.find((e) => e.hash === a.request_hash);
  if (!demande) return refus("SG-2", "request_hash_different");
  // SG-3 : aucune décision scellée pour ce ticket.
  if (contexte.decided.some((x) => x.ticket === remise.ticket)) return refus("SG-3", "ticket_deja_decide");
  // SG-4 : approuve et refuse écrits strictement avant l'échéance request_ts + E.
  if (a.decision !== "expire" && !(ms(contexte.write_at) < ms(demande.ts) + contexte.expire_after_ms)) return refus("SG-4", "echeance_depassee");
  // SG-5 : E-5 et E-9 (forme canonique exigée, aucune normalisation).
  if (a.approvers.length !== a.signatures.length) return refus("SG-5", "signature_invalide");
  const A = objetA({ decision: a.decision, journal_id: contexte.journal_id, org_id: contexte.org_id, request_hash: a.request_hash, ticket: a.ticket });
  for (let i = 0; i < a.signatures.length; i++) if (!J.verifierSignatureApprobation(A, a.signatures[i], a.approvers[i]).ok) return refus("SG-5", "signature_invalide");
  // SG-6 : A-3 de CT-1, raisons dans l'ordre de la table d'EX-9.11.
  const js = remise.approver_set;
  if (new Set(a.approvers).size !== a.approvers.length) return refus("SG-6", "approbateur_double");
  if (a.approvers.some((x) => !js.members.includes(x))) return refus("SG-6", "approbateur_hors_jeu");
  if (!J.egalJSON(a.threshold, js.threshold) || js.threshold.size !== js.members.length || js.threshold.required > js.threshold.size) return refus("SG-6", "seuil_different_du_jeu");
  if (a.decision === "expire" && a.approvers.length > 0) return refus("SG-6", "expire_avec_signatures");
  if (a.decision !== "expire" && a.approvers.length < a.threshold.required) return refus("SG-6", "seuil_non_atteint");
  // SG-7 : séparation des tâches, sous self_approval interdite de la politique de la version de la retenue (CT-2 EX-7.5).
  exiger(estObjet(contexte.separation) && typeof demande.launched_by === "string", "SG-7 exige contexte.separation et retained[].launched_by");
  if (contexte.separation.self_approval === "interdite") {
    const demandeur = adressesDemandeur(contexte.separation, demande.launched_by);
    if (a.approvers.some((x) => demandeur.includes(String(x).toLowerCase()))) return refus("SG-7", "auto_approbation");
  }
  return { result: "scelle", reason: null, check: null };
}

/** L'objet approval scellé (CT-1 §5.3, ordre de ses clés) : l'approval d'une remise augmenté de `at`. */
export function approvalScelle(approvalSansAt, at) {
  const a = approvalSansAt;
  return { decision: a.decision, ticket: a.ticket, request_hash: a.request_hash, threshold: copie(a.threshold), approvers: [...a.approvers], signatures: [...a.signatures], at, reason: a.reason };
}

// ---------------------------------------------------------------------------
// Jeu d'approbateurs (section 8)
// ---------------------------------------------------------------------------

/** Adresses minuscules triées par ordre croissant de leur écriture hexadécimale (EX-8.1, pas 6). */
export const trierAdresses = (adresses) => [...new Set(adresses.map((a) => a.toLowerCase()))].sort();

/** Le jeu d'une politique à approver_set statique (EX-8.2) : objet jeu de ticket-v0, champs de chaîne nuls. */
export function jeuStatique(approver_set) {
  return { chain_id: null, registry: null, set: null, height: null, block_hash: null, threshold: copie(approver_set.threshold), members: trierAdresses(approver_set.members) };
}

/** Deux jeux sont égaux pour EX-8.6 s'ils ont la même adresse de jeu, le même seuil et les mêmes membres (l'adresse est celle du jeu épinglé, EX-8.1). */
export function memeJeu(a, b) {
  return a.set === b.set && a.threshold.required === b.threshold.required && a.threshold.size === b.threshold.size && J.egalJSON(a.members, b.members);
}

/**
 * `source` d'un jeu déclaré (EX-8.8). Jeu lu au registre : hauteurs de gel et
 * de confirmation, hachage du bloc de confirmation, ` repli` pour le jeu de
 * repli. Jeu statique : « jeu statique de la politique <policy_version> ».
 */
export function sourceJeu(jeu, { hauteurConfirmation = jeu.height, blocConfirmation = jeu.block_hash, repli = false, policy_version = null } = {}) {
  if (jeu.set === null) {
    exiger(typeof policy_version === "string", "policy_version requise pour la source d'un jeu statique");
    return `jeu statique de la politique ${policy_version}`;
  }
  return `CuratorSet c=${jeu.chain_id} r=${jeu.registry} s=${jeu.set} h=${jeu.height}..${hauteurConfirmation} b=${blocConfirmation}${repli ? " repli" : ""}`;
}

const ABI_JEU = new Interface([
  "function curatorSetOf(bytes32 orgId) view returns (address)",
  "function getThreshold() view returns (uint256)",
  "function getCuratorCount() view returns (uint256)",
  "function isCurator(address who) view returns (bool)",
  "event CuratorAdded(address indexed curator)",
  "event CuratorRemoved(address indexed curator)",
  "event ThresholdUpdated(uint256 threshold)",
  "event CuratorSetAssigned(bytes32 indexed orgId, address indexed curatorSet, address indexed previous)",
]);
/** Sujets des journaux surveillés (EX-8.5). */
export const SUJETS_JEU = Object.freeze({
  CuratorAdded: ABI_JEU.getEvent("CuratorAdded").topicHash,
  CuratorRemoved: ABI_JEU.getEvent("CuratorRemoved").topicHash,
  ThresholdUpdated: ABI_JEU.getEvent("ThresholdUpdated").topicHash,
  CuratorSetAssigned: ABI_JEU.getEvent("CuratorSetAssigned").topicHash,
});

class Illisible extends Error {
  constructor(cause) {
    super(cause);
    this.cause = cause;
  }
}

/**
 * Lecture du jeu d'approbateurs d'une organisation (EX-8.1), à une hauteur H
 * unique. `source.requete(methode, params)` rend le résultat d'une requête
 * JSON-RPC (eth_chainId, eth_blockNumber, eth_getBlockByNumber, eth_call,
 * eth_getCode, eth_getLogs) ou lève une erreur. `adresses` : les adresses
 * connues du service (contacts, separation.identities, lectures précédentes) ;
 * `depuis` : premier bloc des journaux à relire si la reconstitution est
 * nécessaire. Rend { status: "lu", jeu, cause: null } ou
 * { status: "illisible", jeu: null, cause } (cause de ticket-v0).
 */
export async function lireJeu(source, { approver_set, org_id, adresses = [], depuis = 0, tranche = TRANCHE_JOURNAUX }) {
  exiger(approver_set?.source === "registre", "lireJeu ne vaut que pour approver_set.source = registre");
  const appel = async (methode, params) => {
    try {
      return await source.requete(methode, params);
    } catch {
      throw new Illisible("etat_indisponible");
    }
  };
  try {
    // 1. Chaîne, hauteur, bloc.
    if (BigInt(await appel("eth_chainId", [])) !== BigInt(approver_set.chain_id)) throw new Illisible("chaine_differente");
    const H = BigInt(await appel("eth_blockNumber", []));
    const h = toQuantity(H);
    const bloc = await appel("eth_getBlockByNumber", [h, false]);
    if (!bloc || typeof bloc.hash !== "string") throw new Illisible("etat_indisponible");
    const lireVue = async (to, fonction, args = []) => {
      const brut = await appel("eth_call", [{ to, data: ABI_JEU.encodeFunctionData(fonction, args) }, h]);
      try {
        return ABI_JEU.decodeFunctionResult(fonction, brut)[0];
      } catch {
        throw new Illisible("etat_indisponible");
      }
    };
    // 2. Adresse du jeu de l'organisation, égale au jeu épinglé par la politique.
    const S = String(await lireVue(approver_set.registry, "curatorSetOf", [org_id])).toLowerCase();
    if (S === ZeroAddress) throw new Illisible("organisation_sans_jeu");
    if (S !== approver_set.set.toLowerCase()) throw new Illisible("jeu_non_attendu");
    // 3. Code déployé à H.
    const code = await appel("eth_getCode", [S, h]);
    if (typeof code !== "string" || code === "0x" || code === "") throw new Illisible("jeu_sans_code");
    // 4. Seuil et taille.
    const t = BigInt(await lireVue(S, "getThreshold"));
    const n = BigInt(await lireVue(S, "getCuratorCount"));
    if (!(t >= 1n && t <= n) || n > 65535n) throw new Illisible("seuil_incoherent");
    // 5. Membres : adresses connues membres à H, sinon reconstitution par les journaux.
    const estMembre = async (a) => Boolean(await lireVue(S, "isCurator", [getAddress(a)]));
    let membres = [];
    for (const a of trierAdresses(adresses)) if (await estMembre(a)) membres.push(a);
    if (BigInt(membres.length) !== n) {
      const courant = new Set();
      for (let debut = BigInt(depuis); debut <= H; debut += BigInt(tranche)) {
        const fin = debut + BigInt(tranche) - 1n < H ? debut + BigInt(tranche) - 1n : H;
        const journaux = await appel("eth_getLogs", [{ address: S, fromBlock: toQuantity(debut), toBlock: toQuantity(fin), topics: [[SUJETS_JEU.CuratorAdded, SUJETS_JEU.CuratorRemoved]] }]);
        const tries = [...journaux].sort((x, y) => Number(BigInt(x.blockNumber) - BigInt(y.blockNumber)) || Number(BigInt(x.logIndex) - BigInt(y.logIndex)));
        for (const j of tries) {
          const a = ("0x" + j.topics[1].slice(26)).toLowerCase();
          if (j.topics[0] === SUJETS_JEU.CuratorAdded) courant.add(a);
          else courant.delete(a);
        }
      }
      membres = [];
      for (const a of trierAdresses([...courant])) if (await estMembre(a)) membres.push(a);
      if (BigInt(membres.length) !== n || courant.size !== membres.length) throw new Illisible("membres_non_reconstitues");
    }
    // 6. Minuscules, tri.
    const jeu = {
      chain_id: Number(approver_set.chain_id),
      registry: approver_set.registry.toLowerCase(),
      set: S,
      height: Number(H),
      block_hash: bloc.hash.toLowerCase(),
      threshold: { required: Number(t), size: Number(n) },
      members: trierAdresses(membres),
    };
    return { status: "lu", jeu, cause: null };
  } catch (err) {
    if (err instanceof Illisible) return { status: "illisible", jeu: null, cause: err.cause };
    throw err;
  }
}

/**
 * Surveillance du jeu figé (EX-8.5) : les journaux CuratorSetAssigned de
 * l'organisation sur le registre et CuratorAdded, CuratorRemoved,
 * ThresholdUpdated du jeu figé, des blocs ]jeu.height, jusqua]. Rend la liste
 * des changements { event, block } ; une liste non vide demande une nouvelle
 * lecture (lireJeu).
 */
export async function changementsJeu(source, { jeu, org_id, jusqua, tranche = TRANCHE_JOURNAUX }) {
  const out = [];
  const fin = BigInt(jusqua);
  for (let debut = BigInt(jeu.height) + 1n; debut <= fin; debut += BigInt(tranche)) {
    const bout = debut + BigInt(tranche) - 1n < fin ? debut + BigInt(tranche) - 1n : fin;
    const plage = { fromBlock: toQuantity(debut), toBlock: toQuantity(bout) };
    const registre = await source.requete("eth_getLogs", [{ ...plage, address: jeu.registry, topics: [SUJETS_JEU.CuratorSetAssigned, org_id] }]);
    const membres = await source.requete("eth_getLogs", [{ ...plage, address: jeu.set, topics: [[SUJETS_JEU.CuratorAdded, SUJETS_JEU.CuratorRemoved, SUJETS_JEU.ThresholdUpdated]] }]);
    for (const j of [...registre, ...membres]) {
      const nom = Object.entries(SUJETS_JEU).find(([, s]) => s === j.topics[0])[0];
      out.push({ event: nom, block: Number(BigInt(j.blockNumber)), logIndex: Number(BigInt(j.logIndex)) });
    }
  }
  return out.sort((a, b) => a.block - b.block || a.logIndex - b.logIndex).map(({ event, block }) => ({ event, block }));
}

// ---------------------------------------------------------------------------
// Séparation des tâches (section 10)
// ---------------------------------------------------------------------------

/** Adresses du demandeur (EX-10.1) : celles de l'entrée de separation.identities dont launched_by est égal, octet pour octet. */
export function adressesDemandeur(separation, launched_by) {
  const e = separation.identities.find((x) => x.launched_by === launched_by);
  return e ? trierAdresses(e.addresses) : [];
}

/** Membres éligibles d'un jeu figé (EX-10.2) : ni adresse du demandeur sous self_approval interdite, ni récusé. */
export function eligibles(jeu, { self_approval, requester_addresses, recuses = [] }) {
  return jeu.members.filter((a) => !(self_approval === "interdite" && requester_addresses.includes(a)) && !recuses.includes(a));
}

// ---------------------------------------------------------------------------
// Service d'approbation : machine à états (sections 7, 8, 10, 12)
// ---------------------------------------------------------------------------

/** Ordre des minuteurs à instant égal (EX-7.7), puis identifiant de ticket croissant. */
const ORDRE_MINUTEURS = { echeance: 0, fin_contestation: 1, fin_reservation: 2, fin_reconnaissance: 3, escalade: 4, fin_fenetre: 5 };
/** Raisons de refus d'une remise par le noyau qui relèvent de T14, T15, T16 (12.5). */
const RE_MARQUE_FENETRE = / \[fenetre (apr-[0-9a-z]+(?:-[0-9a-z]+)*) ([0-9T:.Z-]+)\]$/;
const RE_HEX32 = /^0x[0-9a-f]{64}$/;
/** Adresse d'un membre de jeu déclaré : 20 octets en hexadécimal minuscule (ticket-v0, $defs/adresse). */
const RE_ADRESSE_JEU = /^0x[0-9a-f]{40}$/;
const RE_ADRESSE = /^0x[0-9a-f]{40}$/;

/** Clé de rapprochement d'une demande (EX-7.3), sous forme d'une chaîne comparée octet pour octet. */
export function cleRapprochement({ org_id, journal_id }, d) {
  return JSON.stringify([org_id, journal_id, d.code.policy_version, d.tool_announced, J.canonicaliserJCSIntegral(d.arguments === undefined ? {} : d.arguments), d.delegation.launched_by, d.delegation.on_behalf_of, d.delegation.scope]);
}

/** Clé de rapprochement d'un document ticket-v0, ou null quand ses arguments sont effacés (EX-7.24). */
function cleDuDocument(service, doc) {
  if (doc.request.arguments === null) return null;
  return cleRapprochement(service, { code: { policy_version: doc.request.policy_version }, tool_announced: doc.request.tool_announced, arguments: doc.request.arguments, delegation: doc.request.delegation });
}

const estChaineOuNul = (v) => v === null || typeof v === "string";
const estHorodatage = (v) => typeof v === "string" && !Number.isNaN(J.msHorodatage(v));
const estSeq = (v) => Number.isSafeInteger(v) && v >= 1;

/**
 * Forme des données d'une entrée (7.4, $defs/entree), contrôlée avant tout
 * effet : une entrée mal formée est refusée (requete_invalide) sans changer
 * ni l'état ni les votes (EX-7.8).
 */
function donneesValides(kind, d) {
  if (!estObjet(d)) return false;
  const ticket = typeof d.ticket === "string";
  switch (kind) {
    case "charger":
      return typeof d.policy_version === "string" && d.policy_version.length > 0 && (d.requesters === undefined || (Array.isArray(d.requesters) && d.requesters.every((x) => typeof x === "string")));
    case "evaluer":
      return estObjet(d.request) && typeof d.request.tool_announced === "string" && estObjet(d.request.delegation) && typeof d.request.delegation.launched_by === "string" && estObjet(d.request.code) && typeof d.request.code.policy_version === "string" && (d.evaluation === undefined || estObjet(d.evaluation));
    case "ouvrir":
      return ticket && typeof d.request_hash === "string" && estSeq(d.request_seq) && estHorodatage(d.request_ts);
    case "jeu_lu":
      return (d.status === "lu" && estObjet(d.jeu)) || (d.status === "illisible" && typeof d.cause === "string");
    case "voter":
      return ticket && typeof d.approver === "string" && (d.decision === "approuve" || d.decision === "refuse") && typeof d.signature === "string" && estChaineOuNul(d.reason) && estChaineOuNul(d.session_identity ?? null);
    case "recuser":
      return ticket && typeof d.approver === "string";
    case "retirer":
      return ticket && typeof d.by === "string" && estChaineOuNul(d.reason ?? null);
    case "horloge":
      return true;
    case "acquitter": {
      if (!ticket || typeof d.remise_id !== "string" || !["scelle", "temporaire", "refuse"].includes(d.result)) return false;
      if (d.result === "scelle" || d.reason === "ticket_deja_decide") return estSeq(d.seq) && typeof d.hash === "string" && RE_HEX32.test(d.hash) && estHorodatage(d.at) && ["approuve", "refuse", "expire"].includes(d.decision) && estObjet(d.approval);
      return true;
    }
    case "consommer":
      return ticket && estSeq(d.seq) && typeof d.hash === "string";
    case "expiration":
      return ticket && estSeq(d.seq) && typeof d.hash === "string" && estHorodatage(d.at) && estObjet(d.approval);
    default:
      return false;
  }
}

/** Données d'une entrée inscrites dans la transition d'un ticket (EX-7.22) : jamais les arguments en clair (EX-7.24). */
function donneesTransition(kind, d) {
  if (kind === "evaluer" || !estObjet(d)) return null;
  if (kind === "voter") return { approver: d.approver, decision: d.decision, reason: d.reason ?? null, session_identity: d.session_identity ?? null };
  const { ticket, ...reste } = copie(d);
  return reste;
}

/**
 * Service d'approbation de référence : une machine à états qui ne change que
 * sur les entrées de 7.4 ({ kind, at, data }, $defs/entree de ticket-v0),
 * traitées une à une dans l'ordre de leur `at` (EX-7.7). Tout l'état d'un
 * ticket est dans son document ticket-v0 (EX-7.22) : la reprise ne relit que
 * ces documents, les fenêtres, la version en vigueur, les versions chargées,
 * le jeu de repli et le compteur (EX-7.23).
 *
 * Paramètres : `org_id`, `journal_id`, `environment`, `policy_version` (version
 * en vigueur au départ), `parametres` = { expire_after_ms, approver_set,
 * separation } (valeurs de la politique de toute version chargée sans document,
 * comme dans les traces de l'annexe A.6), `politique` (document
 * politique-approbation-v0 de la version de départ, facultatif : sans lui,
 * evaluer exige data.evaluation), `service` = { max_open_tickets, escalation,
 * set_poll_interval_ms, administrators } (configuration de 10.3 ;
 * administrators : identités qui peuvent retirer, EX-7.15), `schemas` (pour
 * charger un document), `epoque` (préfixe des identifiants, conservé hors du
 * service pour qu'un identifiant reste unique après une perte d'état, EX-7.1 ;
 * null dans les traces, qui partent d'un service vide).
 */
export class ServiceApprobation {
  constructor({ org_id, journal_id, environment = "developpement", policy_version, parametres, politique = null, service = {}, schemas = null, epoque = null }) {
    exiger(J.estHex32(org_id) && J.estHex32(journal_id), "org_id et journal_id hexadécimaux de 32 octets attendus");
    exiger(typeof policy_version === "string" && policy_version.length > 0, "policy_version attendue");
    exiger(epoque === null || /^[0-9a-z]+$/.test(epoque), "epoque : chiffres et minuscules");
    this.org_id = org_id;
    this.journal_id = journal_id;
    this.environment = environment;
    this.parametres = copie(parametres);
    this.schemas = schemas;
    this.service = { max_open_tickets: PLAFOND_TICKETS_DEFAUT, escalation: [], set_poll_interval_ms: INTERVALLE_LECTURE_DEFAUT_MS, administrators: [], ...copie(service) };
    this.versions = new Map([[policy_version, { politique: copie(politique), ...copie(parametres) }]]);
    this.vigueur = policy_version;
    this.tickets = new Map();
    this.cles = new Map();
    this.compteur = 0;
    this.epoque = epoque;
    this.fenetres = [];
    const js = this.parametres.approver_set;
    this.repli = js.source === "statique" ? jeuStatique(js) : null;
    this.dernier = -Infinity;
    this.journal = [];
  }

  // -- état ------------------------------------------------------------------

  /** États de tous les tickets connus, par identifiant croissant. */
  etats() {
    return Object.fromEntries([...this.tickets.keys()].sort().map((id) => [id, this.tickets.get(id).state]));
  }

  /** Fenêtres ouvertes, triées par ticket (EX-A.6). */
  fenetresOuvertes() {
    return copie(this.fenetres).sort((a, b) => (a.ticket < b.ticket ? -1 : a.ticket > b.ticket ? 1 : 0));
  }

  /** Document ticket-v0 d'un ticket (copie). */
  documentTicket(id) {
    return copie(this.tickets.get(id));
  }

  /**
   * État persisté du service (EX-7.22, EX-7.23) : les documents ticket-v0,
   * les fenêtres ($defs/fenetre_ouverte), la version en vigueur, les versions
   * chargées, le jeu de repli, le compteur et son époque, l'instant de la
   * dernière entrée. Rien d'autre : la reprise se fait depuis ces seuls objets.
   */
  instantane() {
    return copie({
      org_id: this.org_id, journal_id: this.journal_id, environment: this.environment, parametres: this.parametres, service: this.service,
      versions: [...this.versions.entries()], vigueur: this.vigueur, compteur: this.compteur, epoque: this.epoque, fenetres: this.fenetres, repli: this.repli, dernier: this.dernier === -Infinity ? null : this.dernier,
      tickets: [...this.tickets.values()],
    });
  }

  /** Service rétabli depuis son état persisté (EX-7.23) ; les minuteurs reprennent depuis leurs instants absolus, au fil des entrées. */
  static restaurer(etat, { schemas = null } = {}) {
    const e = copie(etat);
    const s = new ServiceApprobation({ org_id: e.org_id, journal_id: e.journal_id, environment: e.environment, policy_version: e.vigueur, parametres: e.parametres, service: e.service, schemas, epoque: e.epoque });
    s.versions = new Map(e.versions);
    s.compteur = e.compteur;
    s.fenetres = e.fenetres;
    s.repli = e.repli;
    s.dernier = e.dernier === null ? -Infinity : e.dernier;
    for (const doc of e.tickets) {
      s.tickets.set(doc.ticket, doc);
      s.cles.set(doc.ticket, cleDuDocument(s, doc));
    }
    return s;
  }

  version(v) {
    return this.versions.get(v);
  }

  /** approver_set de la politique sous laquelle un ticket a été créé (EX-7.21). */
  jeuDeLaVersion(tk) {
    return this.version(tk.request.policy_version).approver_set;
  }

  // -- entrées -----------------------------------------------------------------

  /**
   * Traite une entrée { kind, at, data } (7.4) : déclenche d'abord les
   * minuteurs échus (EX-7.7), puis l'entrée. Rend l'attendu d'un pas de trace
   * (EX-A.6) : { tickets, accepted, reason, response, remises, windows }, plus
   * `errors` pour politique_invalide et `data` pour le refus d'une entrée qui
   * en porte (12.4, 12.8).
   */
  traiter(entree) {
    const { kind, at, data } = entree;
    const atMs = ms(at);
    exiger(atMs >= this.dernier, `entrée ${kind} à ${at}, antérieure à l'entrée précédente`);
    this.dernier = atMs;
    const sortie = { accepted: true, reason: null, response: null, remises: [], errors: null, data: null };
    this.declencherMinuteurs(atMs, sortie);
    const gestion = {
      charger: () => this.charger(data, atMs, sortie),
      evaluer: () => this.evaluerEntree(data, atMs, sortie),
      ouvrir: () => this.ouvrir(data, atMs, sortie),
      jeu_lu: () => this.jeuLu(data, atMs, sortie),
      voter: () => this.voter(data, atMs, sortie),
      recuser: () => this.recuser(data, atMs, sortie),
      retirer: () => this.retirer(data, atMs, sortie),
      horloge: () => {},
      acquitter: () => this.acquitter(data, atMs, sortie),
      consommer: () => this.consommer(data, atMs, sortie),
      expiration: () => this.expiration(data, atMs, sortie),
    }[kind];
    exiger(gestion, `entrée inconnue : ${kind}`);
    if (!donneesValides(kind, data)) {
      const tk = estObjet(data) && typeof data.ticket === "string" ? this.tickets.get(data.ticket) ?? null : null;
      this.refuser(sortie, "requete_invalide", tk, kind, atMs, data);
    } else gestion();
    const r = { tickets: this.etats(), accepted: sortie.accepted, reason: sortie.reason, response: sortie.response, remises: sortie.remises, windows: this.fenetresOuvertes() };
    if (sortie.errors) r.errors = sortie.errors;
    if (sortie.data) r.data = sortie.data;
    return r;
  }

  refuser(sortie, reason, tk = null, kind = null, atMs = null, data = null) {
    sortie.accepted = false;
    sortie.reason = reason;
    sortie.response = null;
    if (tk) this.transition(tk, kind, atMs, tk.state, tk.state, false, reason, donneesTransition(kind, data));
  }

  transition(tk, input, atMs, from, to, accepted = true, reason = null, data = null) {
    tk.transitions.push({ at: J.horodatage(atMs), input, from, to, accepted, reason, data });
  }

  changerEtat(tk, input, atMs, to, data = null) {
    const from = tk.state;
    tk.state = to;
    this.transition(tk, input, atMs, from, to, true, null, data);
    if (["consomme", "clos", "abandonne"].includes(to)) {
      // EX-7.24 : arguments en clair, événement et pièce effacés ; les valeurs de la portée d'une fenêtre sont des données des arguments.
      tk.request.arguments = null;
      tk.request.retained_event = null;
      tk.request.arguments_piece = null;
      if (tk.opening) tk.opening.scope.values = null;
      this.cles.set(tk.ticket, null);
    }
  }

  alerte(atMs, ticket, note) {
    this.journal.push({ at: J.horodatage(atMs), ticket, note });
  }

  // -- minuteurs (EX-7.7) ------------------------------------------------------

  minuteurs(tk) {
    const out = [];
    const s = tk.state;
    const courante = this.remiseCourante(tk);
    if (ETATS_COLLECTE.includes(s) || (s === "a_remettre" && courante && ["approuve", "refuse"].includes(courante.approval.decision))) out.push({ instant: ms(tk.deadline), type: "echeance" });
    if (s === "seuil_atteint") out.push({ instant: ms(tk.contest_end), type: "fin_contestation" });
    if (s === "reserve") out.push({ instant: ms(tk.reserved_at) + tk.expire_after_ms, type: "fin_reservation" });
    if (ETATS_DECIDES.includes(s)) out.push({ instant: ms(tk.recognize_until), type: "fin_reconnaissance" });
    const etapes = this.service.escalation;
    if (ETATS_COLLECTE.includes(s) && tk.escalations < etapes.length) out.push({ instant: ms(tk.request.request_ts) + etapes[tk.escalations].after_ms, type: "escalade" });
    return out;
  }

  declencherMinuteurs(tMs, sortie) {
    for (;;) {
      let choisi = null;
      const candidat = (c) => {
        if (c.instant > tMs) return;
        if (!choisi || c.instant < choisi.instant || (c.instant === choisi.instant && (ORDRE_MINUTEURS[c.type] < ORDRE_MINUTEURS[choisi.type] || (ORDRE_MINUTEURS[c.type] === ORDRE_MINUTEURS[choisi.type] && c.id < choisi.id)))) choisi = c;
      };
      for (const id of [...this.tickets.keys()].sort()) for (const m of this.minuteurs(this.tickets.get(id))) candidat({ ...m, id });
      for (const w of this.fenetres) candidat({ instant: ms(w.end), type: "fin_fenetre", id: w.ticket });
      if (!choisi) return;
      this.declencher(choisi, sortie);
    }
  }

  declencher({ instant, type, id }, sortie) {
    if (type === "fin_fenetre") {
      // EX-5.6 : à t = fin, W(K) est retirée de F et effacée, avec les valeurs de sa portée.
      this.fenetres = this.fenetres.filter((w) => !(w.ticket === id && ms(w.end) === instant));
      return;
    }
    const tk = this.tickets.get(id);
    switch (type) {
      case "echeance":
        // T13 (a_remettre : décision approuve ou refuse non scellée à l'échéance, remplacée par expire) ou T9.
        this.remiseExpiration(tk, tk.state === "a_remettre" ? RAISONS_EXPIRATION.caduque : this.raisonEcheance(tk), instant, "echeance", sortie);
        break;
      case "fin_contestation":
        // T7 : décision approuve calculée à s + C.
        tk.contest_end = null;
        tk.computed_decision = { decision: "approuve", at: J.horodatage(instant) };
        this.changerEtat(tk, "fin_contestation", instant, "verification");
        this.confirmerStatique(tk, "fin_contestation", instant, sortie);
        break;
      case "fin_reservation":
        // T3 : aucun événement de chaîne ; la clé est libérée.
        tk.key_released = true;
        this.changerEtat(tk, "fin_reservation", instant, "abandonne");
        break;
      case "fin_reconnaissance":
        // T19 : un approuve non consommé est consigné.
        if (tk.state === "approuve") this.alerte(instant, id, "approbation_non_consommee");
        this.changerEtat(tk, "fin_reconnaissance", instant, "clos");
        break;
      case "escalade": {
        // EX-7.13 : notification seulement ; ni jeu, ni seuil, ni échéance ne changent.
        const etape = this.service.escalation[tk.escalations];
        tk.escalations += 1;
        this.alerte(instant, id, `escalade ${etape.notify}`);
        this.transition(tk, "escalade", instant, tk.state, tk.state, true, null, { notify: etape.notify });
        break;
      }
      default:
        throw new Error(`approbation : minuteur inconnu ${type}`);
    }
  }

  /** Raison d'une expiration à l'échéance (T9), par la priorité d'EX-7.11. */
  raisonEcheance(tk) {
    if (tk.approver_set === null) return RAISONS_EXPIRATION.jeu_illisible;
    if (tk.set_reassigned) return RAISONS_EXPIRATION.jeu_reassigne;
    if (tk.eligible.length < tk.effective_required) return RAISONS_EXPIRATION.seuil_inatteignable;
    if (this.objections(tk).length > 0) return RAISONS_EXPIRATION.objection;
    if (tk.state === "seuil_atteint") return RAISONS_EXPIRATION.contestation;
    return RAISONS_EXPIRATION.autre;
  }

  // -- remises (12.5) ----------------------------------------------------------

  /** La remise courante d'un ticket (7.5) : la dernière présentée, tant qu'il est en a_remettre et qu'elle n'a pas été refusée ; sinon null. */
  remiseCourante(tk) {
    if (tk.current_remise === null) return null;
    return tk.remises.find((r) => r.remise.remise_id === tk.current_remise).remise;
  }

  ajouterRemise(tk, approval, approver_set, computedMs, input, atMs, sortie) {
    const remise = { remise_id: `${tk.ticket}/${tk.remises.length + 1}`, ticket: tk.ticket, approval, approver_set };
    tk.remises.push({ remise: copie(remise), computed_at: J.horodatage(computedMs) });
    tk.current_remise = remise.remise_id;
    tk.contest_end = null;
    tk.computed_decision = null;
    if (tk.state !== "a_remettre") this.changerEtat(tk, input, atMs, "a_remettre");
    else this.transition(tk, input, atMs, "a_remettre", "a_remettre");
    sortie.remises.push(copie(remise));
  }

  /** Jeu de repli tel qu'une remise ou une réponse nouveau le déclare (EX-8.8) : source terminée par « repli », ou jeu statique de la version. */
  jeuDeRepli(policy_version) {
    exiger(this.repli !== null, "aucun jeu de repli");
    const r = this.repli;
    return { threshold: copie(r.threshold), members: [...r.members], source: sourceJeu(r, { repli: r.set !== null, policy_version }) };
  }

  /** Jeu que porte la réponse nouveau d'evaluer (EX-12.6) : jeu statique de la politique, ou jeu de repli courant (EX-8.3 garantit qu'il existe). */
  jeuReponseNouveau(policy_version) {
    const js = this.version(policy_version).approver_set;
    if (js.source === "statique") {
      const j = jeuStatique(js);
      return { threshold: j.threshold, members: j.members, source: sourceJeu(j, { policy_version }) };
    }
    return this.jeuDeRepli(policy_version);
  }

  /** Jeu déclaré d'une remise (EX-8.8, EX-8.9) : jeu figé et dernière confirmation, ou jeu de repli. */
  jeuDeclare(tk) {
    const v = tk.request.policy_version;
    if (tk.approver_set !== null) {
      const j = tk.approver_set;
      return { threshold: copie(j.threshold), members: [...j.members], source: sourceJeu(j, { hauteurConfirmation: tk.confirmation?.height, blocConfirmation: tk.confirmation?.block_hash, policy_version: v }) };
    }
    const js = this.jeuDeLaVersion(tk);
    if (js.source === "statique") {
      const j = jeuStatique(js);
      return { threshold: j.threshold, members: j.members, source: sourceJeu(j, { policy_version: v }) };
    }
    return this.jeuDeRepli(v);
  }

  remiseExpiration(tk, reason, atMs, input, sortie) {
    const js = this.jeuDeclare(tk);
    const approval = { decision: "expire", ticket: tk.ticket, request_hash: tk.request.request_hash, threshold: copie(js.threshold), approvers: [], signatures: [], reason };
    this.ajouterRemise(tk, approval, js, atMs, input, atMs, sortie);
  }

  /** Votes qui comptent pour une décision (EX-7.27) : votes courants des éligibles ; pour refuse, aussi ceux des membres récusés (EX-10.4). */
  votesComptes(tk, decision) {
    const elig = new Set(tk.eligible);
    const recuses = new Set(tk.recused.filter((a) => tk.approver_set.members.includes(a)));
    return tk.votes.filter((v) => v.status === "courant" && v.decision === decision && (elig.has(v.approver) || (decision === "refuse" && recuses.has(v.approver))));
  }

  /** T8 : remise d'une décision approuve ou refuse (EX-7.28) après confirmation du jeu : exactement effective_required signatures. */
  remiseDecision(tk, input, atMs, sortie) {
    const dec = tk.computed_decision.decision;
    const t = tk.effective_required;
    const choisis = this.votesComptes(tk, dec).slice(0, t);
    exiger(choisis.length === t, `ticket ${tk.ticket} : ${choisis.length} vote(s) ${dec} pour un seuil effectif de ${t}`);
    const approval = { decision: dec, ticket: tk.ticket, request_hash: tk.request.request_hash, threshold: copie(tk.approver_set.threshold), approvers: choisis.map((v) => v.approver), signatures: choisis.map((v) => v.signature), reason: choisis[t - 1].reason ?? null };
    this.ajouterRemise(tk, approval, this.jeuDeclare(tk), ms(tk.computed_decision.at), input, atMs, sortie);
  }

  /** Jeu statique : la confirmation est acquise, T8 suit l'entrée en verification (EX-8.7). */
  confirmerStatique(tk, input, atMs, sortie) {
    if (tk.state === "verification" && tk.approver_set?.set === null) this.remiseDecision(tk, input, atMs, sortie);
  }

  // -- votes et décompte (7.11, 10.2) -----------------------------------------

  objections(tk) {
    return tk.votes.filter((v) => v.objection && v.objection.lifted_at === null);
  }

  /**
   * Recalcule les éligibles (EX-10.3) et écarte les votes courants de qui ne
   * l'est plus ; le vote refuse d'un membre récusé reste compté (EX-10.4).
   */
  recalculerEligibles(tk, atMs) {
    tk.eligible = eligibles(tk.approver_set, { self_approval: tk.self_approval, requester_addresses: tk.requester_addresses, recuses: tk.recused });
    for (const v of tk.votes) {
      if (v.status !== "courant" || tk.eligible.includes(v.approver)) continue;
      const membre = tk.approver_set.members.includes(v.approver);
      const recuse = tk.recused.includes(v.approver);
      if (membre && recuse && v.decision === "refuse") continue;
      v.status = "ecarte";
      v.cause = !membre ? "hors_jeu" : recuse ? "recuse" : "auto_approbation";
    }
    if (tk.eligible.length < tk.effective_required) this.alerte(atMs, tk.ticket, "seuil inatteignable : moins de membres éligibles que le seuil (EX-7.29)");
  }

  /** Décompte (EX-7.27) à l'instant atMs, après une entrée qui change les votes, le jeu, les éligibles ou les objections. */
  decompte(tk, input, atMs, sortie) {
    const t = tk.effective_required;
    const a = this.votesComptes(tk, "approuve").length;
    const r = this.votesComptes(tk, "refuse").length;
    const C = tk.contest_ms;
    const O = this.objections(tk);
    const verifier = (decision) => {
      if (tk.state === "verification" && tk.computed_decision?.decision === decision) return;
      tk.contest_end = null;
      tk.computed_decision = { decision, at: J.horodatage(atMs) };
      this.changerEtat(tk, input, atMs, "verification");
      this.confirmerStatique(tk, input, atMs, sortie);
    };
    if (r >= t) return verifier("refuse");
    if (a >= t && C === 0) return verifier("approuve");
    if (a >= t && C > 0 && O.length === 0) {
      if (tk.state === "seuil_atteint" || (tk.state === "verification" && tk.computed_decision?.decision === "approuve")) return;
      tk.computed_decision = null;
      tk.contest_end = J.horodatage(atMs + C);
      this.changerEtat(tk, input, atMs, "seuil_atteint");
      return;
    }
    tk.computed_decision = null;
    tk.contest_end = null;
    if (tk.state !== "ouvert") this.changerEtat(tk, input, atMs, "ouvert");
  }

  // -- charger (12.2) ------------------------------------------------------------

  charger(data, atMs, sortie) {
    const v = data.policy_version;
    if (data.approval !== undefined) {
      // Message complet de 12.2 : validation d'EX-4.2 et EX-8.2, CANDIDATS.
      exiger(this.schemas, "charger d'un document exige les schémas");
      const doc = data.approval.rules;
      const errors = erreursPolitique(doc, { schemas: this.schemas, environment: data.environment ?? this.environment, expire_after_ms: data.approval.expire_after_ms });
      if (errors.length) {
        sortie.errors = errors;
        return this.refuser(sortie, "politique_invalide");
      }
      this.versions.set(v, { politique: copie(doc), expire_after_ms: data.approval.expire_after_ms, approver_set: copie(doc.approver_set), separation: copie(doc.separation) });
      const noms = (data.tools ?? []).map((t) => t.tool_announced);
      sortie.response = { policy_version: v, policy_sha256: data.policy_sha256 ?? null, approval_candidates: candidats(doc, noms) };
      // EX-4.14 : avertissements au journal du service, jamais dans la réponse ; requesters (CT-2 EX-7.15) pour le cinquième.
      for (const av of avertissementsPolitique(doc, { outils: data.tools ? noms : null, demandeurs: data.requesters ?? [] })) this.alerte(atMs, null, `avertissement ${v} : ${av}`);
    } else {
      // Trace de l'annexe A.6 : la version porte les paramètres de la trace ; la réponse ne porte que policy_version.
      if (!this.versions.has(v)) this.versions.set(v, { politique: null, ...copie(this.parametres) });
      sortie.response = { policy_version: v };
    }
    if (v !== this.vigueur) {
      this.vigueur = v;
      this.fenetres = []; // EX-4.12 : toute nouvelle version ferme toutes les fenêtres.
    }
  }

  // -- evaluer (12.3, 7.2, 7.9) --------------------------------------------------

  ticketActif(cle) {
    for (const id of [...this.tickets.keys()].sort()) {
      const tk = this.tickets.get(id);
      if (tk.key_released || this.cles.get(id) !== cle) continue;
      if (ETATS_NON_DECIDES.includes(tk.state) || ETATS_DECIDES.includes(tk.state)) return tk;
    }
    return null;
  }

  /** Consomme l'unité de la fenêtre qu'une sortie autorise de rang 2 nomme (EX-5.5) ; une fenêtre épuisée est retirée (EX-5.6). */
  consommerFenetre(rule) {
    const m = RE_MARQUE_FENETRE.exec(rule ?? "");
    if (!m) return;
    const w = this.fenetres.find((f) => f.ticket === m[1] && f.end === m[2] && f.remaining >= 1);
    if (!w) return;
    w.remaining -= 1;
    this.fenetres = this.fenetres.filter((f) => f.remaining >= 1);
  }

  evaluerEntree(data, atMs, sortie) {
    const d = data.request;
    const vigueurJs = this.version(this.vigueur).approver_set;
    if (vigueurJs.source === "registre" && this.repli === null) return this.refuser(sortie, "non_pret"); // EX-8.3
    const pv = this.version(d.code.policy_version);
    if (!pv) return this.refuser(sortie, "politique_inconnue");
    const cle = cleRapprochement(this, d);
    const tk = this.ticketActif(cle);
    if (tk) return this.reemission(tk, atMs, sortie);
    let ev = data.evaluation;
    if (ev === undefined) {
      exiger(pv.politique, `version ${d.code.policy_version} chargée sans document : data.evaluation requise`);
      const r = evaluer(pv.politique, d, { fenetres: this.fenetres, t: atMs, policy_version: this.vigueur });
      ev = { rule: r.rule, decision: r.decision, contest_ms: r.contest_ms, opening: r.opening };
    }
    if (ev.decision !== "a_approuver") {
      // EX-6.5 : une sortie autorise de rang 2 consomme une unité de sa fenêtre, persistée avant la réponse (EX-7.22).
      if (ev.decision === "autorise") this.consommerFenetre(ev.rule);
      sortie.response = { rule: ev.rule, decision: ev.decision, ticket: null, ticket_state: null, approval: null, approver_set: null };
      return;
    }
    // EX-14.1 : plafond de tickets non décidés par demandeur.
    const ouverts = [...this.tickets.values()].filter((t) => ETATS_NON_DECIDES.includes(t.state) && t.request.delegation.launched_by === d.delegation.launched_by).length;
    if (ouverts >= this.service.max_open_tickets) return this.refuser(sortie, "plafond_atteint");
    // T1.
    this.compteur += 1;
    const id = `apr-${this.epoque === null ? "" : this.epoque + "-"}${String(this.compteur).padStart(4, "0")}`;
    const doc = {
      version: 0,
      ticket: id,
      org_id: this.org_id,
      journal_id: this.journal_id,
      state: "reserve",
      request: {
        tool_announced: d.tool_announced,
        tool_original: d.tool_original,
        server_alias: d.server_alias,
        class: d.class,
        delegation: copie(d.delegation),
        arguments: copie(d.arguments === undefined ? {} : d.arguments),
        rule: ev.rule,
        policy_version: d.code.policy_version,
        request_hash: null,
        request_seq: null,
        request_ts: null,
        retained_event: null,
        arguments_piece: null,
      },
      key_released: false,
      reserved_at: J.horodatage(atMs),
      deadline: null,
      expire_after_ms: pv.expire_after_ms,
      contest_ms: ev.contest_ms ?? 0,
      opening: copie(ev.opening ?? null),
      self_approval: pv.separation.self_approval,
      requester_addresses: adressesDemandeur(pv.separation, d.delegation.launched_by),
      approver_set: null,
      effective_required: null,
      confirmation: null,
      set_reassigned: false,
      eligible: [],
      recused: [],
      votes: [],
      contest_end: null,
      computed_decision: null,
      remises: [],
      current_remise: null,
      sealed: null,
      served_at: null,
      consumed: null,
      recognize_until: null,
      escalations: 0,
      transitions: [],
    };
    this.tickets.set(id, doc);
    this.cles.set(id, cle);
    this.transition(doc, "evaluer", atMs, null, "reserve");
    sortie.response = { rule: ev.rule, decision: "a_approuver", ticket: id, ticket_state: "nouveau", approval: null, approver_set: this.jeuReponseNouveau(d.code.policy_version) };
  }

  /** Réponse à une ré-émission reconnue (EX-7.16 à EX-7.19 ; T21). */
  reemission(tk, atMs, sortie) {
    const s = tk.state;
    const rep = (decision, ticket_state, approval = null, approver_set = null) => ({ rule: tk.request.rule, decision, ticket: tk.ticket, ticket_state, approval, approver_set });
    const servir = s === "approuve" && tk.served_at === null;
    if (servir) tk.served_at = J.horodatage(atMs); // T21 : servie, persistée avant la réponse (EX-7.17, EX-7.22)
    this.transition(tk, "evaluer", atMs, s, s);
    if (s === "reserve") sortie.response = rep("a_approuver", "nouveau", null, this.jeuReponseNouveau(tk.request.policy_version));
    else if (servir) sortie.response = rep("autorise", "approuve", copie(tk.sealed.approval));
    else if (s === "refuse" || s === "expire") sortie.response = rep("refuse", s, copie(tk.sealed.approval));
    else sortie.response = rep("a_approuver", "en_attente");
  }

  // -- ouvrir (12.4) ---------------------------------------------------------------

  ouvrir(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    if (!tk) return this.refuser(sortie, "ticket_inconnu");
    const reponse = () => ({ ticket: tk.ticket, state: tk.state, deadline: tk.deadline });
    if (tk.request.request_hash !== null) {
      if (tk.request.request_hash === data.request_hash) {
        // EX-7.20 : sans effet ; rend l'état courant.
        this.transition(tk, "ouvrir", atMs, tk.state, tk.state, true, null, donneesTransition("ouvrir", data));
        sortie.response = reponse();
        return;
      }
      this.refuser(sortie, "ticket_deja_ouvert", tk, "ouvrir", atMs, data);
      sortie.data = { request_hash: tk.request.request_hash };
      return;
    }
    if (!RE_HEX32.test(data.request_hash) || !(ms(data.request_ts) <= atMs) || !["reserve", "abandonne"].includes(tk.state)) return this.refuser(sortie, "requete_invalide", tk, "ouvrir", atMs, data);
    tk.request.request_hash = data.request_hash;
    tk.request.request_seq = data.request_seq;
    tk.request.request_ts = data.request_ts;
    tk.deadline = J.horodatage(ms(data.request_ts) + tk.expire_after_ms);
    if (tk.state === "reserve") {
      // T2 : échéance request_ts + E, lecture du jeu demandée, notification ; événement et pièce gardés pour la console (EX-9.6).
      tk.request.retained_event = estObjet(data.request_event) ? copie(data.request_event) : null;
      tk.request.arguments_piece = typeof data.arguments_piece === "string" ? data.arguments_piece : null;
      this.changerEtat(tk, "ouvrir", atMs, "ouvert", donneesTransition("ouvrir", data));
      this.alerte(atMs, tk.ticket, "notification des membres éligibles et lecture du jeu demandée");
      const js = this.jeuDeLaVersion(tk);
      if (js.source === "statique") this.geler(tk, jeuStatique(js), "ouvrir", atMs, sortie);
    } else {
      // T4 : ouvrir tardif d'un ticket abandonné : expire sur le jeu de repli ; la clé n'est pas reprise.
      this.remiseExpiration(tk, RAISONS_EXPIRATION.reservation, atMs, "ouvrir", sortie);
    }
    sortie.response = reponse();
  }

  // -- jeu_lu (8.2, 8.3, T5, T8) -----------------------------------------------

  geler(tk, jeu, input, atMs, sortie) {
    const avant = tk.approver_set;
    tk.approver_set = copie(jeu);
    // EX-8.6 : le nombre de signatures exigé ne baisse jamais pendant la vie du ticket.
    tk.effective_required = Math.max(tk.effective_required ?? 0, jeu.threshold.required);
    tk.confirmation = jeu.set === null ? null : { height: jeu.height, block_hash: jeu.block_hash };
    if (avant !== null) {
      const ajoutes = jeu.members.filter((a) => !avant.members.includes(a));
      if (ajoutes.length) this.alerte(atMs, tk.ticket, `membres ajoutés au jeu après l'ouverture : ${ajoutes.join(", ")}`);
    }
    this.recalculerEligibles(tk, atMs);
    this.transition(tk, input, atMs, tk.state, tk.state, true, null, input === "jeu_lu" ? { status: "lu", jeu: copie(jeu), cause: null } : null);
    this.decompte(tk, input, atMs, sortie);
  }

  jeuLu(data, atMs, sortie) {
    const vjs = this.version(this.vigueur).approver_set;
    // EX-8.3 : le jeu de repli est la dernière lecture réussie du jeu épinglé de la version en vigueur.
    if (data.status === "lu" && vjs.source === "registre" && data.jeu.set === vjs.set) this.repli = copie(data.jeu);
    for (const id of [...this.tickets.keys()].sort()) {
      const tk = this.tickets.get(id);
      if (!ETATS_COLLECTE.includes(tk.state)) continue;
      const tjs = this.jeuDeLaVersion(tk);
      if (tjs.source === "statique") continue; // un jeu statique ne se relit pas
      const lu = data.status === "lu" && data.jeu.set === tjs.set;
      if (!lu) {
        // T5 : lecture illisible inscrite ; un autre jeu que le jeu épinglé est illisible (jeu_non_attendu, EX-8.1).
        const cause = data.status === "lu" ? "jeu_non_attendu" : data.cause;
        if (cause === "jeu_non_attendu") tk.set_reassigned = true;
        this.transition(tk, "jeu_lu", atMs, tk.state, tk.state, true, null, { status: "illisible", jeu: null, cause });
        continue;
      }
      tk.set_reassigned = false;
      if (tk.approver_set === null) {
        this.geler(tk, data.jeu, "jeu_lu", atMs, sortie);
      } else if (!memeJeu(tk.approver_set, data.jeu)) {
        // EX-8.6 : nouveau gel ; depuis seuil_atteint, retour en ouvert (fenêtre annulée), puis décompte.
        if (tk.state === "seuil_atteint") {
          tk.contest_end = null;
          this.changerEtat(tk, "jeu_lu", atMs, "ouvert");
        }
        this.geler(tk, data.jeu, "jeu_lu", atMs, sortie);
      } else {
        tk.confirmation = { height: data.jeu.height, block_hash: data.jeu.block_hash };
        if (tk.state === "verification" && atMs >= ms(tk.computed_decision.at)) this.remiseDecision(tk, "jeu_lu", atMs, sortie);
        else this.transition(tk, "jeu_lu", atMs, tk.state, tk.state, true, null, { status: "lu", jeu: copie(data.jeu), cause: null });
      }
    }
  }

  // -- voter, recuser, retirer (EX-9.10, EX-10.4, EX-7.15) ----------------------

  /** Première raison de refus commune à voter et recuser (EX-9.10), ou null. */
  refusCollecte(tk) {
    if (!tk) return "ticket_inconnu";
    if (tk.state === "reserve") return "ticket_non_ouvert";
    if (!ETATS_COLLECTE.includes(tk.state)) return "ticket_clos_aux_votes";
    if (tk.approver_set === null) return "jeu_non_fige";
    return null;
  }

  refusEligibilite(tk, approver) {
    if (!tk.approver_set.members.includes(approver)) return "hors_jeu";
    if (tk.self_approval === "interdite" && tk.requester_addresses.includes(approver)) return "auto_approbation";
    if (tk.recused.includes(approver)) return "recuse";
    return null;
  }

  voter(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    let raison = this.refusCollecte(tk);
    let signature = null;
    if (!raison) {
      const n = normaliserSignature(data.signature);
      const champs = { decision: data.decision, journal_id: this.journal_id, org_id: this.org_id, request_hash: tk.request.request_hash, ticket: tk.ticket };
      if (n.signature === null || !RE_ADRESSE.test(data.approver) || !J.verifierSignatureApprobation(objetA(champs), n.signature, data.approver).ok) raison = "signature_invalide";
      else signature = n.signature;
    }
    if (!raison) raison = this.refusEligibilite(tk, data.approver);
    if (!raison && data.reason !== null && longueur(data.reason) > MAX_MOTIF) raison = "motif_trop_long";
    const courant = tk ? tk.votes.find((v) => v.approver === data.approver && v.status === "courant") : null;
    // EX-9.10 : un vote est identique au vote courant s'il porte la même décision, quel que soit son motif.
    if (!raison && courant && courant.decision === data.decision) raison = "vote_identique";
    if (raison) return this.refuser(sortie, raison, tk, "voter", atMs, data);
    // T6 : vote enregistré, vote précédent remplacé ; objection levée (EX-10.8) ou inscrite (EX-10.7).
    if (data.decision === "approuve") for (const v of tk.votes) if (v.approver === data.approver && v.objection && v.objection.lifted_at === null) v.objection.lifted_at = J.horodatage(atMs);
    if (courant) courant.status = "remplace";
    const objection = data.decision === "refuse" && tk.contest_ms > 0 ? { lifted_at: null } : null;
    tk.votes.push({ at: J.horodatage(atMs), approver: data.approver, decision: data.decision, signature, reason: data.reason, session_identity: data.session_identity ?? null, status: "courant", cause: null, objection });
    this.transition(tk, "voter", atMs, tk.state, tk.state, true, null, donneesTransition("voter", data));
    this.decompte(tk, "voter", atMs, sortie);
  }

  recuser(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    const raison = this.refusCollecte(tk) ?? this.refusEligibilite(tk, data.approver);
    if (raison) return this.refuser(sortie, raison, tk, "recuser", atMs, data);
    // EX-10.4 : inéligible pour ce ticket ; son vote approuve courant est retiré, son vote refuse reste compté ; objection maintenue.
    tk.recused.push(data.approver);
    this.recalculerEligibles(tk, atMs);
    this.transition(tk, "recuser", atMs, tk.state, tk.state, true, null, donneesTransition("recuser", data));
    this.decompte(tk, "recuser", atMs, sortie);
  }

  retirer(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    const raison = !tk ? "ticket_inconnu" : tk.state === "reserve" ? "ticket_non_ouvert" : !ETATS_COLLECTE.includes(tk.state) ? "ticket_clos_aux_votes" : null;
    if (raison) return this.refuser(sortie, raison, tk, "retirer", atMs, data);
    if (data.by !== tk.request.delegation.launched_by && !this.service.administrators.includes(data.by)) return this.refuser(sortie, "retrait_non_autorise", tk, "retirer", atMs, data);
    // T10 : échéance avancée à at, décision expire ; le motif reste dans la trace (EX-7.11).
    tk.deadline = J.horodatage(atMs);
    this.transition(tk, "retirer", atMs, tk.state, tk.state, true, null, donneesTransition("retirer", data));
    this.remiseExpiration(tk, RAISONS_EXPIRATION.retrait, atMs, "retirer", sortie);
  }

  // -- acquitter, consommer, expiration (12.5, 12.6) -----------------------------

  sceller(tk, input, data, atMs, decision) {
    tk.sealed = { decision, seq: data.seq, hash: data.hash, at: data.at, approval: copie(data.approval) };
    tk.recognize_until = J.horodatage(ms(data.at) + tk.expire_after_ms);
    tk.current_remise = null;
    tk.computed_decision = null;
    tk.contest_end = null;
    if (tk.request.request_hash === null) tk.request.request_hash = data.approval.request_hash; // T17 depuis reserve ou abandonne
    this.changerEtat(tk, input, atMs, decision, donneesTransition(input, data));
  }

  /** L'objet approval d'un acquittement ou d'une expiration est-il celui du ticket (garde de T11, T14, T17) ? */
  approvalCoherent(tk, data, decision) {
    const a = data.approval;
    return a.ticket === tk.ticket && a.decision === decision && a.at === data.at && typeof a.request_hash === "string";
  }

  acquitter(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    if (!tk) return this.refuser(sortie, "ticket_inconnu");
    const entree = tk.remises.find((r) => r.remise.remise_id === data.remise_id);
    const remise = entree ? entree.remise : null;
    const reponse = () => {
      sortie.response = { ticket: tk.ticket, state: tk.state };
    };
    const sansEffet = () => {
      this.transition(tk, "acquitter", atMs, tk.state, tk.state, true, null, donneesTransition("acquitter", data));
      reponse();
    };
    const scellement = data.result === "scelle" || data.reason === "ticket_deja_decide";
    // EX-7.20 : un acquitter identique à un acquitter déjà accepté pour ce ticket est sans effet et rend la même réponse.
    const recu = donneesTransition("acquitter", data);
    if (tk.transitions.some((t) => t.input === "acquitter" && t.accepted && J.egalJSON(t.data, recu))) return sansEffet();
    if (tk.state !== "a_remettre") {
      // EX-7.20 : un acquittement répété à l'identique est sans effet ; une remise qui n'est plus courante aussi.
      if (scellement && tk.sealed && tk.sealed.seq === data.seq && tk.sealed.hash === data.hash && J.egalJSON(tk.sealed.approval, data.approval)) return sansEffet();
      if (!scellement && remise) return sansEffet();
      if (scellement && tk.sealed) this.alerte(atMs, tk.ticket, "alerte : scellement contraire à la décision déjà scellée");
      return this.refuser(sortie, "requete_invalide", tk, "acquitter", atMs, data);
    }
    if (!remise) return this.refuser(sortie, "requete_invalide", tk, "acquitter", atMs, data);
    if (data.result === "scelle") {
      // T11 : une remise présentée pour ce ticket, scellée telle que le noyau la rend (motif éventuellement rédigé, EX-9.14).
      const dec = remise.approval.decision;
      if (data.decision !== dec || !this.approvalCoherent(tk, data, dec) || data.approval.request_hash !== remise.approval.request_hash) return this.refuser(sortie, "requete_invalide", tk, "acquitter", atMs, data);
      this.sceller(tk, "acquitter", data, atMs, dec);
      // EX-11.5, EX-7.17 : requête retenue que le noyau relaie : l'approbation est servie.
      if (dec === "approuve" && data.held === true) tk.served_at = J.horodatage(atMs);
      // EX-5.4 : ouverture de la fenêtre d'un ticket ouvrant approuvé, si la version est encore en vigueur et la fenêtre pas déjà finie.
      if (dec === "approuve" && tk.opening && tk.opening.scope.policy_version === this.vigueur) {
        const debut = ms(data.at);
        const fin = debut + tk.opening.duration_ms;
        if (fin > atMs) {
          const w = { scope: copie(tk.opening.scope), start: data.at, end: J.horodatage(fin), remaining: tk.opening.max_calls, ticket: tk.ticket };
          this.fenetres = this.fenetres.filter((f) => !J.egalJSON(f.scope, w.scope));
          this.fenetres.push(w);
        }
      }
      return reponse();
    }
    if (remise.remise_id !== tk.current_remise) return sansEffet(); // remise qui n'est plus la courante
    if (data.result === "temporaire") return sansEffet(); // T12 : re-présentée au plus tôt timeout_ms plus tard
    if (data.reason === "ticket_deja_decide") {
      if (!this.approvalCoherent(tk, data, data.decision)) return this.refuser(sortie, "requete_invalide", tk, "acquitter", atMs, data);
      if (data.approval.request_hash === tk.request.request_hash) {
        // T14 : alignement sur le noyau, seul scelleur ; l'objet approval est celui qu'il a scellé.
        this.sceller(tk, "acquitter", data, atMs, data.decision);
        return reponse();
      }
      // T20 : décision scellée d'une autre demande sous cet identifiant : aucun alignement, ticket clos, alerte.
      this.alerte(atMs, tk.ticket, "alerte : identifiant_en_collision (décision scellée d'une autre demande)");
      tk.current_remise = null;
      tk.computed_decision = null;
      this.changerEtat(tk, "acquitter", atMs, "clos", donneesTransition("acquitter", data));
      return reponse();
    }
    if (data.reason === "echeance_depassee") return sansEffet(); // T15 : la remise expire de T13 sera présentée
    // T16 : défaut du service ; alerte d'exploitation ; la remise refusée cesse d'être courante.
    this.alerte(atMs, tk.ticket, `alerte : remise refusée par le noyau (${data.reason})`);
    tk.current_remise = null;
    tk.computed_decision = null;
    if (data.reason === "ticket_inconnu") {
      tk.key_released = true;
      this.changerEtat(tk, "acquitter", atMs, "abandonne", donneesTransition("acquitter", data));
    } else if (remise.approval.decision === "expire") {
      // Une remise expire refusée n'est pas remplacée : le noyau scelle lui-même expire (EX-12.11).
      this.transition(tk, "acquitter", atMs, tk.state, tk.state, true, null, donneesTransition("acquitter", data));
    } else {
      for (const v of tk.votes) if (v.status === "courant" && remise.approval.approvers.includes(v.approver)) {
        v.status = "ecarte";
        v.cause = "remise_refusee";
      }
      this.changerEtat(tk, "acquitter", atMs, "ouvert", donneesTransition("acquitter", data));
      this.decompte(tk, "acquitter", atMs, sortie);
    }
    reponse();
  }

  consommer(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    if (!tk) return this.refuser(sortie, "ticket_inconnu");
    if (["consomme", "clos"].includes(tk.state) && tk.consumed && tk.consumed.seq === data.seq && tk.consumed.hash === data.hash) {
      this.transition(tk, "consommer", atMs, tk.state, tk.state, true, null, donneesTransition("consommer", data));
      sortie.response = { ticket: tk.ticket, state: tk.state };
      return;
    }
    if (tk.state === "clos" && tk.served_at !== null && tk.consumed === null) {
      // T22 : consommation tardive (relais d'une approbation servie, scellé après la fin du délai de reconnaissance, CT-2 EX-7.20).
      tk.consumed = { seq: data.seq, hash: data.hash };
      this.transition(tk, "consommer", atMs, "clos", "clos", true, null, donneesTransition("consommer", data));
      this.alerte(atMs, tk.ticket, "consommation_tardive");
      sortie.response = { ticket: tk.ticket, state: tk.state };
      return;
    }
    if (tk.state !== "approuve") return this.refuser(sortie, "requete_invalide", tk, "consommer", atMs, data);
    // T18.
    tk.consumed = { seq: data.seq, hash: data.hash };
    this.changerEtat(tk, "consommer", atMs, "consomme", donneesTransition("consommer", data));
    sortie.response = { ticket: tk.ticket, state: tk.state };
  }

  expiration(data, atMs, sortie) {
    const tk = this.tickets.get(data.ticket);
    if (!tk) return this.refuser(sortie, "ticket_inconnu");
    if (tk.sealed && tk.sealed.seq === data.seq && tk.sealed.hash === data.hash && J.egalJSON(tk.sealed.approval, data.approval)) {
      this.transition(tk, "expiration", atMs, tk.state, tk.state, true, null, donneesTransition("expiration", data));
      sortie.response = { ticket: tk.ticket, state: tk.state };
      return;
    }
    const sources = [...ETATS_NON_DECIDES, "abandonne"];
    const memeDemande = tk.request.request_hash === null || data.approval.request_hash === tk.request.request_hash;
    if (!sources.includes(tk.state) || !this.approvalCoherent(tk, data, "expire") || !memeDemande) return this.refuser(sortie, "requete_invalide", tk, "expiration", atMs, data);
    // T17 : alignement sur le noyau (CT-2 EX-9.4, EX-12.11) ; l'objet approval est celui qu'il a scellé seul.
    this.sceller(tk, "expiration", data, atMs, "expire");
    sortie.response = { ticket: tk.ticket, state: tk.state };
  }
}

/**
 * Rejoue une trace de l'annexe A.6 ($defs/trace de ticket-v0) sur un service
 * vide (EX-A.6) : rend, pour chaque pas, l'attendu calculé ({ tickets,
 * accepted, reason, response, remises, windows }) et le service final.
 * `apresPas(service, i)` peut rendre un autre service pour la suite (reprise).
 */
export function rejouerTrace(trace, { schemas = null, apresPas = null } = {}) {
  const service = new ServiceApprobation({
    org_id: trace.org_id,
    journal_id: trace.journal_id,
    environment: trace.environment,
    policy_version: trace.policy_version,
    parametres: { expire_after_ms: trace.expire_after_ms, approver_set: trace.approver_set, separation: trace.separation },
    service: trace.service,
    schemas,
  });
  let courant = service;
  const pas = trace.steps.map((s, i) => {
    const r = courant.traiter(s.input);
    delete r.errors;
    delete r.data;
    if (apresPas) courant = apresPas(courant, i) ?? courant;
    return r;
  });
  return { pas, service: courant };
}

/**
 * Cohérence des transitions d'un document ticket-v0 : les transitions
 * acceptées s'enchaînent (chaque `from` est le `to` précédent) et la dernière
 * donne `state`. Ce n'est pas un rejeu (TK-12 reprend depuis les documents,
 * EX-7.23) : seulement un contrôle de forme. Rend la liste des écarts.
 */
export function ecartsTransitions(doc) {
  const ecarts = [];
  let etat = null;
  doc.transitions.forEach((t, i) => {
    if (t.from !== etat) ecarts.push(`/transitions/${i} : from ${t.from}, état courant ${etat}`);
    if (t.accepted) etat = t.to;
    else if (t.to !== t.from) ecarts.push(`/transitions/${i} : entrée refusée qui change l'état`);
  });
  if (etat !== doc.state) ecarts.push(`état rejoué ${etat}, state ${doc.state}`);
  return ecarts;
}

// ---------------------------------------------------------------------------
// Comportement du mandataire (section 11)
// ---------------------------------------------------------------------------

/**
 * Jeu déclaré exploitable (CT-2 EX-7.16, EX-9.4 ; CT-3 EX-12.6, EX-12.11) :
 * la forme de `$defs/approver_set` vérifiée par SG-1 (seuil, adresses
 * minuscules distinctes, `source` de la forme d'EX-8.8) et la cohérence que
 * vérifie SG-6 (`size` égal au nombre de membres, `required` ≤ `size`). Un
 * jeu qui ne l'est pas ne peut pas donner une décision `expire` conforme à
 * A-3 de CT-1 ; la règle se recalcule sur la seule ligne d'un fichier des
 * approbations (EX-12.23).
 */
export function jeuExploitable(jeu) {
  if (!estObjet(jeu) || !J.egalJSON(Object.keys(jeu).sort(), ["members", "source", "threshold"])) return false;
  const t = jeu.threshold;
  const entier = (n) => Number.isSafeInteger(n) && n >= 1 && n <= 65535;
  if (!estObjet(t) || !J.egalJSON(Object.keys(t).sort(), ["required", "size"]) || !entier(t.required) || !entier(t.size)) return false;
  if (!Array.isArray(jeu.members) || jeu.members.length < 1 || jeu.members.some((a) => typeof a !== "string" || !RE_ADRESSE_JEU.test(a)) || new Set(jeu.members).size !== jeu.members.length) return false;
  if (typeof jeu.source !== "string" || jeu.source.length > 256 || !(RE_SOURCE_REGISTRE.test(jeu.source) || RE_SOURCE_STATIQUE.test(jeu.source))) return false;
  return t.size === jeu.members.length && t.required <= t.size;
}

/**
 * Les sept combinaisons de la table d'EX-7.16 (EX-12.6) : toute autre réponse
 * à evaluer est invalide, et le noyau la traite comme une indisponibilité du
 * service. Exactement les six membres, dans un ordre quelconque (l'ordre des
 * membres d'un objet JSON n'a pas de sens) ; `rule` chaîne ou null, non nul
 * pour a_approuver (CT-1 §5.3) ; approval non nul seulement pour une décision
 * scellée du même ticket ; approver_set non nul seulement pour ticket_state
 * nouveau, et alors exploitable (jeuExploitable, EX-9.4).
 */
export function combinaisonAdmise(r) {
  if (!estObjet(r)) return false;
  const cles = ["approval", "approver_set", "decision", "rule", "ticket", "ticket_state"];
  if (!J.egalJSON(Object.keys(r).sort(), cles)) return false;
  if (r.rule !== null && typeof r.rule !== "string") return false;
  if (r.ticket === null) return r.ticket_state === null && r.approval === null && r.approver_set === null && (r.decision === "autorise" || r.decision === "refuse");
  if (typeof r.ticket !== "string" || !RE_IDENTIFIANT_TICKET.test(r.ticket)) return false;
  const scelle = (decision) => estObjet(r.approval) && r.approval.ticket === r.ticket && r.approval.decision === decision && r.approver_set === null;
  switch (r.ticket_state) {
    case "nouveau":
      return r.decision === "a_approuver" && r.rule !== null && r.approval === null && jeuExploitable(r.approver_set);
    case "en_attente":
      return r.decision === "a_approuver" && r.rule !== null && r.approval === null && r.approver_set === null;
    case "approuve":
      return r.decision === "autorise" && scelle("approuve");
    case "refuse":
    case "expire":
      return r.decision === "refuse" && scelle(r.ticket_state);
    default:
      return false;
  }
}

/**
 * Texte du signal d'approbation (CT-2 EX-4.49) :
 * « noortrace: appel soumis a approbation ; ticket=<ticket> ; state=<state> ».
 */
export function texteSignalApprobation(ticket, state) {
  exiger(typeof ticket === "string" && RE_IDENTIFIANT_TICKET.test(ticket), `ticket invalide : ${JSON.stringify(ticket)}`);
  exiger(ETATS_SIGNAL.includes(state), `état du signal invalide : ${JSON.stringify(state)}`);
  return `noortrace: appel soumis a approbation ; ticket=${ticket} ; state=${state}`;
}

/** Un résultat rendu par l'enregistreur lui-même (CT-2 EX-4.49) : resultType (hôte moderne), content, isError, _meta, dans cet ordre. */
function resultatEnregistreur(texte, { hoteModerne = true, recorder = C.VERSION_ENREGISTREUR, approbation = null } = {}) {
  const _meta = { [CLE_SERVER_INFO]: { name: C.IDENTITE_ENREGISTREUR.name, version: recorder } };
  if (approbation) _meta[CLE_META_APPROBATION] = approbation;
  const result = { content: [{ type: "text", text: texte }], isError: true, _meta };
  return hoteModerne ? { resultType: "complete", ...result } : result;
}

/** Résultat d'un appel refusé par la politique sans ticket (EX-11.8, CT-2 EX-4.49) ; sans resultType pour un hôte de l'ère héritée. */
export function resultatRefusPolitique({ hoteModerne = true, recorder = C.VERSION_ENREGISTREUR } = {}) {
  return resultatEnregistreur(TEXTE_REFUS_POLITIQUE, { hoteModerne, recorder });
}

/**
 * Signal d'approbation (CT-2 EX-4.49) : résultat isError de texte fixe, sans
 * structuredContent, dont _meta porte serverInfo et « noortrace/approval » =
 * { ticket, state } ; state ∈ { en_attente, refuse, expire } (EX-11.7) ; sans
 * resultType pour un hôte de l'ère héritée. Jamais journalisé.
 */
export function resultatSignalApprobation(ticket, state, { hoteModerne = true, recorder = C.VERSION_ENREGISTREUR } = {}) {
  return resultatEnregistreur(texteSignalApprobation(ticket, state), { hoteModerne, recorder, approbation: { ticket, state } });
}

/**
 * Ce que le mandataire fait d'une réponse à evaluer (EX-7.16, EX-11.3 à
 * EX-11.8 ; CT-2 EX-4.49, EX-4.50, EX-7.16), en mode `erreur` (celui de la
 * configuration de référence, EX-11.1) ou `retenir`. `decisionScellee` :
 * l'approval de la décision que le noyau a lui-même scellée pour le ticket de
 * la réponse, ou null ; la réponse doit être applicable
 * (reponseEvaluerApplicable : l'une des sept combinaisons et, pour une
 * décision scellée, un approval égal à celui du noyau).
 *   { action: "relayer", approval: null } — autorise sans ticket ;
 *   { action: "verifier_relais", ticket, approval } — autorise d'un ticket
 *     approuve : relais seulement après RL-1 à RL-4 (CT-2 EX-7.21,
 *     verifierRelais), sous l'approval de la décision scellée par le noyau,
 *     jamais celui de la réponse (EX-7.12) ;
 *   { action: "resultat", result } — résultat isError rendu par
 *     l'enregistreur (CT-2 EX-4.49) : refus par la politique sans ticket, ou
 *     signal d'approbation (ticket en attente, refusé ou expiré ; ré-émission
 *     d'un ticket dont une requête est déjà retenue) ;
 *   { action: "erreur", error } — -31010 (raison approbation) pour une
 *     réponse non applicable (indisponibilité du service, CT-2 §14.2) : la
 *     seule erreur JSON-RPC ;
 *   { action: "retenir", ticket } — mode retenir, aucune requête de ce ticket
 *     déjà retenue (CT-2 EX-4.50).
 * `recorder` est code.recorder, la version de l'enregistreur.
 */
export function actionMandataire(reponse, { decisionScellee = null, mode = MODE_ATTENTE_DEFAUT, hoteModerne = true, requeteDejaRetenue = false, recorder = C.VERSION_ENREGISTREUR } = {}) {
  if (!reponseEvaluerApplicable(reponse, { decisionScellee })) return { action: "erreur", error: C.erreurEnregistreur("MODE_DEGRADE", { reason: "approbation" }) };
  if (reponse.decision === "autorise" && reponse.ticket === null) return { action: "relayer", approval: null };
  if (reponse.decision === "autorise") return { action: "verifier_relais", ticket: reponse.ticket, approval: copie(decisionScellee) };
  if (reponse.ticket === null) return { action: "resultat", result: resultatRefusPolitique({ hoteModerne, recorder }) };
  const state = ["refuse", "expire"].includes(reponse.ticket_state) ? reponse.ticket_state : "en_attente";
  if (mode === "retenir" && state === "en_attente" && !requeteDejaRetenue) return { action: "retenir", ticket: reponse.ticket };
  return { action: "resultat", result: resultatSignalApprobation(reponse.ticket, state, { hoteModerne, recorder }) };
}

/**
 * Fin de la rétention d'une requête (CT-2 EX-4.50) : à `hold_timeout_ms`
 * (`issue` = "delai"), signal en_attente, le ticket continue ; à la décision
 * scellée `refuse` ou `expire`, signal de même state (et l'événement refusee
 * qui reprend la policy de la retenue) ; à `approuve`, relais de la requête
 * retenue après RL-1 à RL-4. Rend { action: "resultat", result } ou
 * { action: "relayer" }.
 */
export function finRetention(ticket, issue, { hoteModerne = true, recorder = C.VERSION_ENREGISTREUR } = {}) {
  if (issue === "approuve") return { action: "relayer" };
  exiger(["delai", "refuse", "expire"].includes(issue), `issue de rétention inconnue : ${JSON.stringify(issue)}`);
  return { action: "resultat", result: resultatSignalApprobation(ticket, issue === "delai" ? "en_attente" : issue, { hoteModerne, recorder }) };
}

/**
 * Résultat de `debutAppel` du SDK (CT-2 EX-6.7) selon la réponse d'evaluer :
 * { call, decision, ticket, ticket_state }, `call` nul sauf pour autorise ;
 * une réponse non applicable (reponseEvaluerApplicable avec
 * `decisionScellee`, l'approval de la décision que le noyau a scellée pour ce
 * ticket, ou null) rend l'erreur -31010 (raison approbation). Pour autorise
 * d'un ticket approuve, l'appelant ne rend `call` qu'après RL-1 à RL-4
 * (verifierRelais, CT-2 EX-7.21). Le SDK ne retient jamais : en_attente rend
 * aussitôt a_approuver.
 */
export function resultatDebutAppel(reponse, { call = null, decisionScellee = null } = {}) {
  if (!reponseEvaluerApplicable(reponse, { decisionScellee })) return { error: C.erreurEnregistreur("MODE_DEGRADE", { reason: "approbation" }) };
  const autorise = reponse.decision === "autorise";
  exiger(!autorise || typeof call === "string", "un appel autorisé exige l'identifiant call");
  return { call: autorise ? call : null, decision: reponse.decision, ticket: reponse.ticket, ticket_state: reponse.ticket_state };
}

/**
 * Avertissements de la commande de validation de l'enregistreur sur le mode
 * d'attente (EX-11.1, EX-11.2) : `retenir` est signalé ; hold_timeout_ms doit
 * rester sous le plus petit délai par appel des hôtes raccordés, d'au moins
 * une seconde (`delaisHotesMs`, facultatif).
 */
export function avertissementsModeAttente(approval, { delaisHotesMs = [] } = {}) {
  const out = [];
  if (approval.mode === "retenir") {
    out.push("mode retenir : le mode par défaut est erreur (CT-3 EX-11.1)");
    if (delaisHotesMs.length) {
      const min = Math.min(...delaisHotesMs);
      if (!(approval.hold_timeout_ms <= min - 1000)) out.push(`hold_timeout_ms ${approval.hold_timeout_ms} n'est pas inférieur d'au moins une seconde au plus petit délai des hôtes (${min} ms, CT-3 EX-11.2)`);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Noyau de l'enregistreur : échanges avec le service (CT-2 §7.5)
// ---------------------------------------------------------------------------

/** Gabarits de launched_by d'une connexion d'hôte, jamais transmis au service (CT-2 EX-7.15). */
export const GABARITS_LAUNCHED_BY = ["${peer_user}", "${oauth_subject}"];

/** Comparaison par unités de code UTF-16 (CT-1 §4), celle de l'opérateur < sur les chaînes. */
const comparerUtf16 = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

/** Les launched_by fixes de connexions d'hôte (entrées de mcp.hosts et sdk.hosts) : triés par unités UTF-16, sans doublon, sans gabarit (CT-2 EX-7.15). */
export function demandeursFixes(hotes) {
  const fixes = (hotes ?? []).map((h) => h?.launched_by).filter((lb) => typeof lb === "string" && !GABARITS_LAUNCHED_BY.includes(lb));
  return [...new Set(fixes)].sort(comparerUtf16);
}

/**
 * Message `charger` du noyau (CT-2 EX-7.15, CT-3 12.2) : { org_id,
 * journal_id, environment, policy_version, policy_sha256, approval, tools,
 * requesters }. `approval` est /policy/approval sans `service` ; `tools` la
 * liste agrégée { tool_announced, tool_original, server_alias, class, effects }
 * triée par tool_announced ; `hotes` les entrées de mcp.hosts et de sdk.hosts.
 */
export function messageCharger({ org_id, journal_id, environment, policy_version, policy_sha256, approval, tools, hotes = [] }) {
  exiger(estObjet(approval), "approval : /policy/approval attendu");
  const sansService = {};
  for (const [k, v] of Object.entries(approval)) if (k !== "service") sansService[k] = copie(v);
  const outils = (tools ?? []).map((t) => ({ tool_announced: t.tool_announced, tool_original: t.tool_original, server_alias: t.server_alias, class: t.class, effects: t.effects === undefined ? null : copie(t.effects) }));
  outils.sort((a, b) => comparerUtf16(a.tool_announced, b.tool_announced));
  return { org_id, journal_id, environment, policy_version, policy_sha256, approval: sansService, tools: outils, requesters: demandeursFixes(hotes) };
}

/**
 * Réponse d'evaluer applicable par le noyau (CT-2 EX-7.16) : l'une des sept
 * combinaisons (combinaisonAdmise) et, pour une décision scellée (approuve,
 * refuse, expire), un `approval` égal clé pour clé à celui de la décision que
 * le noyau a lui-même scellée pour ce ticket (`decisionScellee`, null s'il
 * n'en a pas scellé : réponse invalide, RL-1). Une réponse non applicable est
 * une indisponibilité du service : -31010, raison approbation, consignée
 * approval_response_invalid.
 */
export function reponseEvaluerApplicable(r, { decisionScellee = null } = {}) {
  if (!combinaisonAdmise(r)) return false;
  if (!["approuve", "refuse", "expire"].includes(r.ticket_state)) return true;
  return estObjet(decisionScellee) && decisionScellee.decision === r.ticket_state && J.egalJSON(r.approval, decisionScellee);
}

/**
 * Refus de sceller la retenue d'une réponse nouveau (CT-2 EX-7.17) :
 * `decisions` = les décisions scellées du journal [{ ticket, seq }] (l'index
 * de SG-3). Rend null (sceller la retenue ; deux retenue sans décision d'un
 * même ticket restent admises), ou { error: -31010 raison approbation,
 * note: "identifiant_en_collision", ticket, seq }.
 */
export function refuserRetenue(ticket, decisions) {
  const d = (decisions ?? []).find((x) => x.ticket === ticket);
  if (!d) return null;
  return { error: C.erreurEnregistreur("MODE_DEGRADE", { reason: "approbation" }), note: "identifiant_en_collision", ticket, seq: d.seq };
}

/**
 * Ce que le noyau fait d'une réponse `nouveau` (CT-2 4.4 pas 6, EX-7.17) :
 * `decisions` = les décisions scellées du journal [{ ticket, seq }] ;
 * `retenues` = les événements retenue durables du journal [{ ticket, seq,
 * hash }]. Une décision scellée pour ce ticket : refus (refuserRetenue). Une
 * retenue sans décision déjà durable pour ce ticket (service qui garde le
 * ticket en reserve faute d'avoir reçu ouvrir) : rien n'est scellé ; le noyau
 * renvoie `ouvrir` pour cette retenue, rend le signal en_attente (ou retient
 * la requête, EX-4.50) et consigne approval_pending : { action: "signal",
 * retenue }. Sinon : { action: "sceller" }. Deux retenue d'un même ticket ne
 * naissent que d'une course, avant que la première soit durable (CT-3
 * EX-7.19).
 */
export function actionNouveau(ticket, { decisions = [], retenues = [] } = {}) {
  const refus = refuserRetenue(ticket, decisions);
  if (refus) return { action: "erreur", ...refus };
  const r = retenues.find((x) => x.ticket === ticket);
  if (r) return { action: "signal", retenue: { seq: r.seq, hash: r.hash } };
  return { action: "sceller" };
}

/**
 * Message `ouvrir` (CT-2 EX-7.18, CT-3 12.4) : { ticket, request_hash,
 * request_seq, request_ts, request_event, arguments_piece } depuis
 * l'événement retenue tel que scellé et les octets de sa pièce « arguments »
 * (base64 RFC 4648 §4, avec remplissage), ou null quand la référence est en
 * ligne.
 */
export function messageOuvrir(evenementRetenue, octetsArguments = null) {
  const ev = evenementRetenue;
  exiger(ev?.execution?.status === "retenue" && typeof ev.policy?.ticket === "string", "ouvrir : événement retenue avec ticket attendu");
  const enLigne = Object.hasOwn(ev.execution.arguments ?? {}, "value");
  exiger(enLigne || octetsArguments !== null, "ouvrir : octets de la pièce arguments attendus");
  return { ticket: ev.policy.ticket, request_hash: ev.hash, request_seq: ev.seq, request_ts: ev.ts, request_event: copie(ev), arguments_piece: enLigne ? null : Buffer.from(octetsArguments).toString("base64") };
}

/**
 * Requête `acquitter` (CT-2 EX-7.19, CT-3 EX-12.9) : { remise_id, ticket,
 * result, reason, seq, hash, at, decision, held, approval }, membres non
 * applicables à null. `scelle` : seq, hash, at, decision, held, approval (avec
 * at et request_hash) ; `refuse` : reason (raison de 12.8) et, pour
 * ticket_deja_decide, la décision scellée ; `temporaire` : reason
 * mode_degrade.
 */
export function messageAcquitter({ remise_id, ticket, result, reason = null, seq = null, hash = null, at = null, decision = null, held = null, approval = null }) {
  exiger(["scelle", "temporaire", "refuse"].includes(result), `acquitter : result inconnu ${JSON.stringify(result)}`);
  exiger(typeof remise_id === "string" && remise_id.startsWith(`${ticket}/`), "acquitter : remise_id de la forme <ticket>/<n>");
  const decisionDonnee = result === "scelle" || reason === "ticket_deja_decide";
  if (decisionDonnee) exiger(estSeq(seq) && RE_HEX32.test(hash ?? "") && estHorodatage(at) && ETATS_DECIDES.includes(decision) && estObjet(approval), "acquitter : seq, hash, at, decision et approval de la décision scellée attendus");
  if (result === "scelle") exiger(typeof held === "boolean" && reason === null, "acquitter scelle : held booléen, reason null");
  if (result === "temporaire") exiger(reason === "mode_degrade", "acquitter temporaire : reason mode_degrade");
  if (result === "refuse") exiger(typeof reason === "string", "acquitter refuse : raison attendue");
  return {
    remise_id,
    ticket,
    result,
    reason: result === "scelle" ? null : reason,
    seq: decisionDonnee ? seq : null,
    hash: decisionDonnee ? hash : null,
    at: decisionDonnee ? at : null,
    decision: decisionDonnee ? decision : null,
    held: result === "scelle" ? held : null,
    approval: decisionDonnee ? copie(approval) : null,
  };
}

/**
 * Message `consommer` (CT-2 EX-7.20, CT-3 EX-12.10) : { ticket, seq, hash }
 * d'un événement executee qui porte une approbation : celui du premier relais
 * du ticket (les continuations MRTR qui héritent de l'approbation, EX-4.21,
 * n'en envoient pas).
 */
export function messageConsommer(evenementExecutee) {
  const ev = evenementExecutee;
  exiger(ev?.execution?.status === "executee" && estObjet(ev.approval), "consommer : événement executee portant une approbation attendu");
  return { ticket: ev.approval.ticket, seq: ev.seq, hash: ev.hash };
}

/**
 * Issue d'un envoi de `consommer` (CT-2 EX-7.20) : `reponse` est la réponse
 * du service ({ ticket, state }) ou null, `erreur` sa raison d'erreur (12.8)
 * ou null ; sans réponse ni erreur (délai), le message est réessayé. Une
 * réponse `consomme` ou `clos` (consommation tardive, T22 de CT-3), ou une
 * erreur `requete_invalide` ou `ticket_inconnu`, est finale : consignée
 * (approval_consume_final), elle met fin aux essais. Rend "final" ou
 * "reessayer".
 */
export function issueConsommer({ reponse = null, erreur = null } = {}) {
  if (reponse && ["consomme", "clos"].includes(reponse.state)) return "final";
  if (erreur === "requete_invalide" || erreur === "ticket_inconnu") return "final";
  return "reessayer";
}

/** Délai E d'un événement : `expireAfterMs` est un nombre, ou une fonction de la version de politique (code.policy_version) de la retenue. */
const delaiE = (expireAfterMs, policy_version) => (typeof expireAfterMs === "function" ? expireAfterMs(policy_version) : expireAfterMs);

/**
 * Les `consommer` à renvoyer au redémarrage (CT-2 EX-7.20) : pour le premier
 * événement executee (plus petit seq) de chaque ticket dont l'approbation est
 * portée par un executee du journal, si le délai de reconnaissance
 * (approval.at + E) court encore à `maintenantMs` ; les continuations MRTR
 * qui héritent de l'approbation (EX-4.21) n'en donnent pas. `E` : nombre, ou
 * fonction de la version de politique de la retenue (donnée par
 * `versionRetenue(ticket)`, à défaut celle de l'événement).
 */
export function aReconsommer(evenements, maintenantMs, expireAfterMs, { versionRetenue = null } = {}) {
  const premiers = new Map();
  for (const ev of evenements ?? []) {
    if (ev?.execution?.status !== "executee" || !estObjet(ev.approval)) continue;
    const t = ev.approval.ticket;
    if (!premiers.has(t) || ev.seq < premiers.get(t).seq) premiers.set(t, ev);
  }
  return [...premiers.values()]
    .sort((a, b) => a.seq - b.seq)
    .filter((ev) => maintenantMs < ms(ev.approval.at) + delaiE(expireAfterMs, versionRetenue ? versionRetenue(ev.approval.ticket) : ev.code?.policy_version))
    .map(messageConsommer);
}

/**
 * MAC de relais (CT-2 EX-7.22) : HMAC-SHA-256(K_relais, UTF-8("noortrace/relais/v0")
 * ‖ 0x00 ‖ JCS intégral des arguments en clair), en hexadécimal 0x ; la clé
 * a au moins 32 octets.
 */
export function macRelais(cle, args) {
  const k = Buffer.from(cle);
  exiger(k.length >= LONGUEUR_CLE_MIN, `clé du MAC de relais : au moins ${LONGUEUR_CLE_MIN} octets`);
  const m = createHmac("sha256", k).update(Buffer.concat([Buffer.from(DOMAINE_MAC_RELAIS, "utf8"), Buffer.from([0]), Buffer.from(J.canonicaliserJCSIntegral(args === undefined ? {} : args), "utf8")])).digest();
  return "0x" + m.toString("hex");
}

/**
 * MAC de contrôle de la clé du MAC de relais (CT-2 EX-7.22, §13.4) : le MAC
 * de relais de la chaîne JSON "controle" (des arguments sont toujours un
 * objet : aucune collision). Première ligne de chaque fichier mac-<epoch>,
 * `{ "kind": "controle", "mac" }` : une instance qui reprend les fichiers
 * d'une autre (bascule, reprise) compare la sienne ; une différence dit que
 * les deux instances ne résolvent pas storage.relay_mac_key vers les mêmes
 * octets.
 */
export function macControle(cle) {
  return macRelais(cle, "controle");
}

/** Ligne de contrôle d'un fichier approbations/mac-<epoch>.ndjson (CT-2 EX-12.23) : { kind: "controle", mac } en JCS intégral suivi de \n. */
export function ligneMacControle(cle) {
  return J.canonicaliserJCSIntegral({ kind: "controle", mac: macControle(cle) }) + "\n";
}

/**
 * Contrôle de la clé du MAC de relais à la reprise ou après une bascule
 * (CT-2 EX-7.22, §13.4) : `lignes` = les lignes relues d'un fichier
 * mac-<epoch> ; vrai si sa ligne de contrôle est celle de `cle`. Faux : erreur
 * de configuration (relay_mac_key_mismatch), l'instance ne prend pas le bail.
 */
export function controleMacConforme(lignes, cle) {
  const c = (lignes ?? []).find((l) => l?.kind === "controle");
  return Boolean(c) && c.mac === macControle(cle);
}

/**
 * Vérifications de relais RL-1 à RL-4 (CT-2 EX-7.21), dans l'ordre, avant
 * l'intention d'un appel dont la réponse est autorise/approuve, ou avant de
 * relayer une requête retenue dont la décision approuve vient d'être scellée.
 *   `reponse` : la réponse d'evaluer (son approval), ou null pour une requête
 *     retenue (l'approval relayé est alors celui de la décision scellée) ;
 *   `decisionScellee` : l'approval de la décision que le noyau a scellée pour
 *     ce ticket, ou null ;
 *   `retenue` : l'événement retenue dont le hash est approval.request_hash,
 *     ou null ;
 *   `appel` : { execution: { tool, arguments }, delegation } de l'appel à
 *     relayer (événement partiel) ;
 *   `macRetenue`, `macAppel` : MAC inscrit pour la retenue (null si la ligne
 *     manque) et MAC des arguments en clair de l'appel ;
 *   `executees` : événements executee du journal (reprise et en attente
 *     compris) ; `intentionsOuvertes` : tickets des intentions ouvertes ;
 *     `relaisEnCours` : tickets des relais en cours qui ont passé RL-3 ;
 *   `maintenantMs` : instant de la vérification (horloge murale, 7.4) ;
 *   `timeoutMs` : timeout_ms de l'outil (EX-4.22), marge de RL-4 ;
 *   `expireAfterMs` : E de la version de politique de la retenue (nombre ou
 *     fonction de la version) ;
 *   `continuation` : null pour un premier relais ; pour une continuation MRTR
 *     qui hérite de l'approbation (EX-4.21) : { requestState (sha256 du
 *     requestState de la ré-émission), inscrites : [{ ticket,
 *     request_state_sha256 }] (lignes continuation des fichiers des
 *     approbations), consommees : [sha256] (lignes continuation_consommee),
 *     enCours : [sha256] (continuations en cours qui ont passé RL-3) } ; RL-3
 *     devient alors : ce requestState a été inscrit pour ce ticket et n'a pas
 *     servi.
 * Rend null si l'appel peut être relayé, sinon { check, error } (-31010,
 * raison approbation ; aucune intention, aucun événement ; consigné
 * approval_relay_refused).
 */
export function verifierRelais({ reponse = null, decisionScellee, retenue, appel, macRetenue, macAppel, executees = [], intentionsOuvertes = [], relaisEnCours = [], maintenantMs, timeoutMs = 0, expireAfterMs, continuation = null }) {
  const refus = (check) => ({ check, error: C.erreurEnregistreur("MODE_DEGRADE", { reason: "approbation" }) });
  // RL-1 : une décision scellée par le noyau, approuve, et la réponse égale à elle.
  if (!estObjet(decisionScellee) || decisionScellee.decision !== "approuve") return refus("RL-1");
  if (reponse !== null && !J.egalJSON(reponse.approval, decisionScellee)) return refus("RL-1");
  const ticket = decisionScellee.ticket;
  // RL-2 : l'appel est la demande approuvée (jamais run_id, déclaratif).
  if (!estObjet(retenue) || retenue.hash !== decisionScellee.request_hash || retenue.policy?.ticket !== ticket) return refus("RL-2");
  const da = appel?.delegation ?? {};
  const dr = retenue.delegation ?? {};
  if (appel?.execution?.tool !== retenue.execution.tool || da.launched_by !== dr.launched_by || da.on_behalf_of !== dr.on_behalf_of || da.scope !== dr.scope) return refus("RL-2");
  const ra = appel.execution.arguments ?? {};
  const rr = retenue.execution.arguments ?? {};
  if (ra.sha256 !== rr.sha256 || ra.length !== rr.length || ra.redacted !== rr.redacted) return refus("RL-2");
  if (typeof macRetenue !== "string" || typeof macAppel !== "string" || macRetenue !== macAppel) return refus("RL-2");
  // RL-3 : l'approbation n'a pas servi ; pour une continuation MRTR, son requestState a été inscrit pour ce ticket et n'a pas servi.
  if (continuation === null) {
    if (executees.some((ev) => ev?.execution?.status === "executee" && ev.approval?.ticket === ticket)) return refus("RL-3");
    if (intentionsOuvertes.includes(ticket) || relaisEnCours.includes(ticket)) return refus("RL-3");
  } else {
    const rs = continuation.requestState;
    if (typeof rs !== "string" || !(continuation.inscrites ?? []).some((l) => l.ticket === ticket && l.request_state_sha256 === rs)) return refus("RL-3");
    if ((continuation.consommees ?? []).includes(rs) || (continuation.enCours ?? []).includes(rs)) return refus("RL-3");
  }
  // RL-4 : dans le délai, avec la marge du délai de l'outil : maintenant + timeout_ms strictement avant approval.at + E (E de la version de la retenue).
  if (!(maintenantMs + timeoutMs < ms(decisionScellee.at) + delaiE(expireAfterMs, retenue.code?.policy_version))) return refus("RL-4");
  return null;
}

/**
 * Héritage d'une continuation MRTR (CT-2 EX-4.21) : une ré-émission qui porte
 * `requestState` n'hérite de la policy, de l'approval, de l'intent et du code
 * de l'appel d'origine que si le noyau a gardé, au relais du résultat
 * input_required de cet appel, un enregistrement pour ce requestState
 * (`enregistrement` : { host, tool, mac, consomme }, null s'il est inconnu :
 * redémarrage pour un appel sans ticket, autre connexion) et que la
 * ré-émission (`appel` : { host, tool, mac }, `mac` étant le MAC de relais de
 * ses arguments en clair, EX-7.22) vient de la même connexion d'hôte, porte
 * le même nom annoncé et les mêmes arguments en clair (MAC égal ; l'égalité
 * des pièces rédigées ne suffit pas : un champ rédigé peut changer sans
 * changer la pièce) et que le requestState n'a pas encore servi (usage
 * unique). Pour un appel qui porte un ticket approuvé, RL-1, RL-2, RL-3 en
 * mode continuation et RL-4 s'appliquent en plus (verifierRelais). Rend
 * { herite: true } ou { herite: false, raison } : sans héritage, la
 * ré-émission repasse par le pas 3 de 4.4.
 */
export function heritageContinuation(enregistrement, appel) {
  if (!estObjet(enregistrement)) return { herite: false, raison: "request_state_inconnu" };
  if (enregistrement.consomme) return { herite: false, raison: "request_state_deja_servi" };
  if (enregistrement.host !== appel?.host || enregistrement.tool !== appel?.tool) return { herite: false, raison: "autre_appel" };
  if (typeof enregistrement.mac !== "string" || enregistrement.mac !== appel?.mac) return { herite: false, raison: "arguments_differents" };
  return { herite: true };
}

/**
 * L'approver_set d'une expiration scellée par le noyau seul (CT-2 EX-9.4,
 * CT-3 EX-12.11) : celui de la dernière remise reçue pour ce ticket dont le
 * jeu est exploitable (jeuExploitable : forme de SG-1, cohérence de SG-6),
 * quelle que soit sa décision, sinon celui de la réponse nouveau (lignes
 * retenue d'EX-12.23), sinon null. `remises` : les remises reçues pour ce
 * ticket, dans l'ordre (objets ou lignes remise, qui portent approver_set).
 */
export function jeuExpiration({ remises = [], approverSetNouveau = null } = {}) {
  for (let i = remises.length - 1; i >= 0; i--) if (jeuExploitable(remises[i]?.approver_set)) return copie(remises[i].approver_set);
  return jeuExploitable(approverSetNouveau) ? copie(approverSetNouveau) : null;
}

/**
 * Expiration d'un ticket par le noyau seul (CT-2 EX-9.4, CT-3 EX-12.11) :
 * l'instant à partir duquel le noyau la scelle (request_ts + E +
 * timeout_ms, E de la version de la retenue) et l'approval sans at, de raison
 * fixe RAISON_EXPIRATION_NOYAU (non rédigée), sans approbateur ni signature,
 * dont l'approver_set est celui de jeuExpiration (dernière remise reçue au
 * jeu exploitable, sinon réponse nouveau) et le threshold celui de cet
 * approver_set, de sorte que la décision vérifie A-3 de CT-1. L'écrivain pose
 * at (approvalScelle).
 */
export function expirationParLeNoyau({ retenue, remises = [], approverSetNouveau = null, expireAfterMs, timeoutMs }) {
  exiger(retenue?.execution?.status === "retenue", "expiration : événement retenue attendu");
  const jeu = jeuExpiration({ remises, approverSetNouveau });
  exiger(jeu !== null, "expiration : aucun approver_set exploitable (remises du ticket, réponse nouveau)");
  const threshold = copie(jeu.threshold);
  const E = delaiE(expireAfterMs, retenue.code?.policy_version);
  return {
    instantMs: ms(retenue.ts) + E + timeoutMs,
    approval: { decision: "expire", ticket: retenue.policy.ticket, request_hash: retenue.hash, threshold, approvers: [], signatures: [], reason: RAISON_EXPIRATION_NOYAU },
    approver_set: copie(jeu),
  };
}

/** Message `expiration` (CT-2 EX-9.4, CT-3 EX-12.11) : { ticket, seq, hash, at, approval } de l'événement de décision expire scellé par le noyau. */
export function messageExpiration(evenementDecision) {
  const ev = evenementDecision;
  exiger(ev?.execution?.tool === "noortrace.approbation.decision" && ev.approval?.decision === "expire", "expiration : événement de décision expire attendu");
  return { ticket: ev.approval.ticket, seq: ev.seq, hash: ev.hash, at: ev.approval.at, approval: copie(ev.approval) };
}

/**
 * Motif d'une décision rédigé avant scellement (CT-2 EX-10.24) : les
 * détecteurs de texte de toutes les règles de la politique de rédaction
 * chargée (C.chargerPolitique), quelles que soient leur portée et leurs
 * outils, avec leur action, par passages ; tronqué à 1 024 points de code ;
 * null reste null ; au-delà du budget (EX-10.23), null. Les chaînes fixes
 * d'une décision expire ne passent pas par cette fonction.
 */
export function redigerMotifDecision(politique, reason, { budgetMs = C.BUDGET_REDACTION_MS, onDepassement = null } = {}) {
  if (reason === null || reason === undefined) return null;
  const r = C.redigerTexteEnLigne(politique, reason, { budgetMs, onDepassement, scope: "motif" });
  if (r.depasse) return null;
  return C.tronquer(r.texte, MAX_MOTIF_DECISION);
}

/**
 * Ligne d'un fichier approbations/approbations-<epoch>.ndjson (CT-2
 * EX-12.23) : JCS intégral suivi de \n, de l'objet { kind: "retenue",
 * ticket, request_seq, request_hash, approver_set }, { kind: "remise",
 * ticket, remise_id, decision, approver_set }, { kind: "decision", ticket,
 * seq, hash, approver_set }, { kind: "continuation", ticket, seq, hash,
 * request_state_sha256 } (résultat input_required relayé sous un ticket
 * approuvé, EX-4.21 : seq et hash de son événement executee) ou { kind:
 * "continuation_consommee", ticket, request_state_sha256 } (continuation qui a
 * passé RL-3).
 */
export function ligneApprobations(kind, objet) {
  const membres = { retenue: ["ticket", "request_seq", "request_hash", "approver_set"], remise: ["ticket", "remise_id", "decision", "approver_set"], decision: ["ticket", "seq", "hash", "approver_set"], continuation: ["ticket", "seq", "hash", "request_state_sha256"], continuation_consommee: ["ticket", "request_state_sha256"] }[kind];
  exiger(membres, `ligne d'approbations : kind inconnu ${JSON.stringify(kind)}`);
  const o = { kind };
  for (const k of membres) {
    exiger(objet[k] !== undefined, `ligne ${kind} : ${k} manquant`);
    o[k] = copie(objet[k]);
  }
  return J.canonicaliserJCSIntegral(o) + "\n";
}

/** Ligne d'un fichier approbations/mac-<epoch>.ndjson (CT-2 EX-12.23) : { ticket, request_hash, mac } en JCS intégral suivi de \n. */
export function ligneMac({ ticket, request_hash, mac }) {
  exiger(/^0x[0-9a-f]{64}$/.test(mac ?? ""), "mac : 32 octets en hexadécimal 0x");
  return J.canonicaliserJCSIntegral({ ticket, request_hash, mac }) + "\n";
}

/**
 * Relecture d'un fichier des approbations (CT-2 EX-12.23) : une dernière
 * ligne incomplète est une écriture tronquée (coupée), une ligne illisible
 * suivie d'autres lignes est une corruption (C.ErreurModeDegrade, raison
 * stockage). Rend { lignes, tronque }.
 */
export function lireFichierApprobations(texte) {
  const brut = String(texte).split("\n");
  const derniere = brut.pop();
  const lignes = [];
  for (const [i, l] of brut.entries()) {
    try {
      lignes.push(C.analyserJSONIntegral(l));
    } catch {
      throw new C.ErreurModeDegrade("stockage", `fichier des approbations : ligne ${i + 1} illisible`);
    }
  }
  return { lignes, tronque: derniere !== "" };
}

/**
 * L'approver_set d'une décision scellée, pour l'exportateur (CT-2 EX-12.23,
 * CT-3 EX-8.9) : celui de sa ligne decision, écrite avant que l'événement de
 * décision soit ajouté au segment. Sans elle (fichier incomplet, par exemple
 * une copie restaurée sans ses dernières lignes, 12.8) : pour `approuve` ou
 * `refuse`, la dernière ligne remise du ticket qui porte cette décision et dont
 * le jeu est exploitable ; pour `expire`, la règle d'EX-9.4 (jeuExpiration :
 * dernière ligne remise au jeu exploitable, de toute décision, sinon la ligne
 * retenue). null si rien n'est inscrit.
 */
export function approverSetDecision(lignes, { ticket, decision, seq = null }) {
  const du = lignes.filter((l) => l.ticket === ticket);
  const d = du.find((l) => l.kind === "decision" && (seq === null || l.seq === seq));
  if (d) return copie(d.approver_set);
  const retenue = du.filter((l) => l.kind === "retenue").at(-1)?.approver_set ?? null;
  if (decision === "expire") return jeuExpiration({ remises: du.filter((l) => l.kind === "remise"), approverSetNouveau: retenue });
  const remises = du.filter((l) => l.kind === "remise" && l.decision === decision && jeuExploitable(l.approver_set));
  if (remises.length) return copie(remises[remises.length - 1].approver_set);
  return retenue === null ? null : copie(retenue);
}

/**
 * Un fichier mac-<epoch> est-il échu (CT-2 EX-12.23) ? Vrai quand toutes ses
 * lignes le sont : une ligne ne sert plus à partir de request_ts + 2E
 * (`requestTs(request_hash)` : ts de la retenue, en millisecondes ou RFC
 * 3339 ; `expireAfterMs` : E de sa version, nombre ou fonction du
 * request_hash).
 */
export function fichierMacEchu(lignes, { requestTs, maintenantMs, expireAfterMs }) {
  return lignes.every((l) => {
    const t = requestTs(l.request_hash);
    const E = typeof expireAfterMs === "function" ? expireAfterMs(l.request_hash) : expireAfterMs;
    return maintenantMs >= (typeof t === "number" ? t : ms(t)) + 2 * E;
  });
}

/**
 * Contrôles de démarrage d'une configuration d'enregistreur qui relèvent de
 * l'approbation et des motifs (CT-2 EX-15.4 pas 2, 3 et 4, EX-15.7) :
 *   - pas 2 : schéma configuration-enregistreur-v0 (registre `schemas` avec
 *     politique-redaction et politique-approbation, $ref de
 *     policy.approval.rules) ;
 *   - pas 3 : politique de rédaction (EX-10.6, règles a) à c) comprises),
 *     `extract` des gabarits d'effets (même sous-ensemble et mêmes règles),
 *     politique d'approbation (CT-3 EX-4.2, EX-8.2, avec recorder.environment
 *     et /policy/approval/expire_after_ms) ; avertissements de CT-3 EX-4.14
 *     (avec les outils `outils` s'ils sont donnés et les launched_by fixes),
 *     du mode retenir (EX-11.1, EX-11.2 avec `delaisHotesMs`) ;
 *   - pas 4 (si `secrets` est donné : { relay_mac_key, pseudonym_key, autres :
 *     [clés] }, octets décodés) : relay_mac_key et pseudonym_key d'au moins 32
 *     octets, relay_mac_key distincte de toute autre clé.
 * Rend { erreurs, avertissements } (chaînes : pointeur JSON, règle).
 */
export function controlesConfiguration(config, { schemas, outils = null, delaisHotesMs = [], secrets = null } = {}) {
  const erreurs = [];
  const avertissements = [];
  if (schemas?.[C.ID_SCHEMA_CONFIGURATION]) {
    for (const e of J.validerSchema(config, schemas[C.ID_SCHEMA_CONFIGURATION], { registre: schemas })) erreurs.push(`${e.chemin} : schéma : ${e.message}`);
    if (erreurs.length) return { erreurs, avertissements };
  }
  const policy = config?.policy ?? {};
  const budgetMs = config?.limits?.redaction_budget_ms ?? C.BUDGET_REDACTION_MS;
  for (const e of C.erreursPolitiqueRedaction(policy.redaction, { schemas, budgetMs })) erreurs.push(`/policy/redaction : ${e} (EX-10.6)`);
  for (const [alias, serveur] of Object.entries(policy.servers ?? {})) {
    for (const [nom, outil] of Object.entries(serveur?.tools ?? {})) {
      for (const e of C.erreursGabaritsEffets(outil?.effects, { ou: `/policy/servers/${echapper(alias)}/tools/${echapper(nom)}/effects` })) erreurs.push(`${e} (EX-7.6, EX-10.6)`);
    }
  }
  const approval = policy.approval ?? {};
  if (approval.rules !== undefined) {
    for (const e of erreursPolitique(approval.rules, { schemas, environment: config.recorder?.environment, expire_after_ms: approval.expire_after_ms })) erreurs.push(`/policy/approval/rules${e.pointer ?? ""} : ${e.code} (CT-3 EX-4.2, EX-8.2)`);
    if (!erreurs.some((e) => e.startsWith("/policy/approval/rules"))) {
      const hotes = [...(config.mcp?.hosts ?? []), ...(config.sdk?.hosts ?? [])];
      for (const a of avertissementsPolitique(approval.rules, { outils, demandeurs: demandeursFixes(hotes) })) avertissements.push(`/policy/approval/rules : ${a} (CT-3 EX-4.14)`);
    }
  }
  for (const a of avertissementsModeAttente({ mode: approval.mode, hold_timeout_ms: approval.hold_timeout_ms }, { delaisHotesMs })) avertissements.push(`/policy/approval/mode : ${a}`);
  if (secrets) {
    const mac = secrets.relay_mac_key ? Buffer.from(secrets.relay_mac_key) : null;
    if (!mac || mac.length < LONGUEUR_CLE_MIN) erreurs.push(`/storage/relay_mac_key : au moins ${LONGUEUR_CLE_MIN} octets après décodage (CT-2 EX-7.22)`);
    if (secrets.pseudonym_key && Buffer.from(secrets.pseudonym_key).length < LONGUEUR_CLE_MIN) erreurs.push(`/policy/redaction/pseudonym_key : au moins ${LONGUEUR_CLE_MIN} octets après décodage (CT-2 EX-10.12)`);
    const autres = [secrets.pseudonym_key, ...(secrets.autres ?? [])].filter(Boolean).map((k) => Buffer.from(k));
    if (mac && autres.some((k) => k.equals(mac))) erreurs.push("/storage/relay_mac_key : distincte de toute autre clé de l'enregistreur (CT-2 EX-7.22)");
  }
  return { erreurs, avertissements };
}
