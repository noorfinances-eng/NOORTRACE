// Formes lisibles et résumé d'une demande (fonctions pures, sans DOM ni
// texte : elles rendent des valeurs que les écrans mettent en mots avec la
// table des libellés).
//
// Le résumé d'une demande (`resumeVerifie`) ne se compose que de valeurs que
// le modèle d'affichage (CT-3 EX-9.4, EX-9.15, EX-9.16 ; `modeleAffichage` de
// la bibliothèque) a vérifiées :
// - un argument n'y entre que si sa feuille porte l'état `verifie` ; une
//   feuille `non_verifiable` ou `different` n'y entre jamais, et figure dans
//   `reserves`, que l'écran dit en clair ;
// - l'outil annoncé, le demandeur (`launched_by`) et la règle (`policy.rule`)
//   n'y entrent que si l'événement `retenue` est vérifié (contrôle 2) et si
//   les champs liés lui sont égaux (contrôle 4), c'est-à-dire si `blocking` ne
//   porte ni `evenement_invalide` ni `champ_different` ;
// - les effets déclarés, l'intention et tout ce que le service dit seul n'y
//   entrent jamais.
// Aucune valeur n'est recalculée : le montant lisible ne change que les
// séparateurs d'un nombre décimal écrit en chiffres, et la valeur signée
// reste rendue telle quelle à côté.
//
// Complément du 2026-11-18, décision du porteur (langage des écrans) : la
// carte de résumé liste chaque feuille des arguments, avec sa valeur et sa
// marque (`groupesValeurs`) : les feuilles vérifiées d'un côté, celles que
// la console n'a pas pu vérifier dans un groupe à part, « à contrôler par
// vous-même », les feuilles différentes dans un groupe d'alerte. Chaque
// feuille reçoit un libellé courant (`libelleValeur`), tiré du dernier
// segment de son chemin par une table fixe publiée (CT-3 EX-9.4) : ce
// libellé n'est qu'une aide de lecture, le chemin exact reste affiché.

/** Couples (pointeur du montant, pointeur de la devise) reconnus, dans l'ordre d'essai. */
export const COUPLES_MONTANT = Object.freeze([
  Object.freeze(["/amount", "/currency"]),
  Object.freeze(["/montant", "/devise"]),
]);

const ESPACE_INSECABLE = " ";
// Un nombre décimal écrit en chiffres, sans signe ni exposant, sans zéro de
// tête superflu : 1 à 15 chiffres, puis au plus 8 décimales.
const NOMBRE_SIMPLE = /^(0|[1-9][0-9]{0,14})(\.[0-9]{1,8})?$/;
const DEVISE = /^[A-Z]{3}$/;

/**
 * Forme française d'un montant : milliers séparés par une espace insécable,
 * virgule décimale (« 9 500,00 »). Rend `null` si la valeur ne se lit pas
 * sans ambiguïté : ni chaîne ni nombre, signe, exposant, séparateur de
 * milliers, zéro de tête, plus de 15 chiffres ou de 8 décimales.
 * @param {unknown} valeur chaîne (`"9500.00"`) ou nombre JSON (`9500`)
 * @returns {string|null}
 */
export function montantLisible(valeur) {
  let s;
  if (typeof valeur === "string") s = valeur;
  else if (typeof valeur === "number" && Number.isFinite(valeur)) s = String(valeur);
  else return null;
  const m = NOMBRE_SIMPLE.exec(s);
  if (m === null) return null;
  const entier = m[1].replace(/\B(?=([0-9]{3})+$)/g, ESPACE_INSECABLE);
  return m[2] === undefined ? entier : `${entier},${m[2].slice(1)}`;
}

/**
 * Résumé d'une demande, tiré du modèle d'affichage et de lui seul.
 * @param {object} modele `$defs/modele_affichage` (rendu par `modeleAffichage`)
 * @returns {{
 *   lies: boolean,
 *   outil: string|null,
 *   demandeur: string|null,
 *   regle: string|null,
 *   montant: {texte: string, devise: string, pointeurs: string[], valeurs: unknown[]}|null,
 *   reserves: {pointer: string, status: string}[],
 *   feuilles: number,
 *   verifiees: number,
 * }}
 *   `lies` : l'événement est vérifié et les champs liés lui sont égaux ;
 *   `reserves` : les feuilles qui n'ont pas l'état `verifie`, dans l'ordre du modèle.
 */
export function resumeVerifie(modele) {
  const blocking = Array.isArray(modele.blocking) ? modele.blocking : [];
  const lies = !blocking.includes("evenement_invalide") && !blocking.includes("champ_different");
  const feuilles = Array.isArray(modele.arguments) ? modele.arguments : [];
  const verifiee = (pointeur) => feuilles.find((f) => f.pointer === pointeur && f.status === "verifie") ?? null;
  let montant = null;
  for (const [pm, pd] of COUPLES_MONTANT) {
    const m = verifiee(pm);
    const d = verifiee(pd);
    if (m === null || d === null) continue;
    const texte = montantLisible(m.value);
    if (texte === null || typeof d.value !== "string" || !DEVISE.test(d.value)) continue;
    montant = { texte, devise: d.value, pointeurs: [pm, pd], valeurs: [m.value, d.value] };
    break;
  }
  const reserves = feuilles.filter((f) => f.status !== "verifie").map((f) => ({ pointer: f.pointer, status: f.status }));
  const chaine = (v) => (typeof v === "string" && v !== "" ? v : null);
  return {
    lies,
    outil: lies ? chaine(modele.tool && modele.tool.announced) : null,
    demandeur: lies ? chaine(modele.delegation && modele.delegation.launched_by) : null,
    regle: lies ? chaine(modele.rule && modele.rule.policy_rule) : null,
    montant,
    reserves,
    feuilles: feuilles.length,
    verifiees: feuilles.length - reserves.length,
  };
}

/**
 * Le montant qu'un résumé permet d'afficher : celui de `resumeVerifie`, et
 * seulement quand l'événement est vérifié et lié à la demande (`outil` non
 * nul). C'est la seule porte par laquelle un montant s'affiche en grand, sur
 * l'écran d'une demande comme dans la liste.
 * @param {ReturnType<typeof resumeVerifie>} r
 * @returns {{texte: string, devise: string}|null}
 */
export function montantDuResume(r) {
  return r.outil === null || r.montant === null ? null : r.montant;
}

/** Le montant vérifié d'un modèle d'affichage (`montantDuResume(resumeVerifie(modele))`), ou `null`. */
export function montantVerifie(modele) {
  return montantDuResume(resumeVerifie(modele));
}

/**
 * Les feuilles des arguments, réparties selon leur état, chacune dans
 * l'ordre du modèle d'affichage : `verifiees` (état `verifie`),
 * `differentes` (état `different`), `aControler` (tout autre état, dont
 * `non_verifiable` : une feuille dont l'état n'est pas connu se range avec
 * celles que la console n'a pas pu vérifier, jamais avec les vérifiées).
 * @param {object} modele `$defs/modele_affichage`
 * @returns {{verifiees: object[], differentes: object[], aControler: object[]}}
 */
export function groupesValeurs(modele) {
  const feuilles = Array.isArray(modele.arguments) ? modele.arguments : [];
  return {
    verifiees: feuilles.filter((f) => f.status === "verifie"),
    differentes: feuilles.filter((f) => f.status === "different"),
    aControler: feuilles.filter((f) => f.status !== "verifie" && f.status !== "different"),
  };
}

/**
 * Table fixe des libellés courants (CT-3 EX-9.4, complément du 2026-11-18) :
 * dernier segment du chemin d'une feuille → nom du libellé (clé
 * `valeur.<nom>` de la table des textes). Aucune autre déduction : ni mise
 * en forme, ni conversion, ni rapprochement de noms voisins.
 */
export const LIBELLES_VALEURS = Object.freeze({
  amount: "montant",
  montant: "montant",
  currency: "devise",
  devise: "devise",
  beneficiary: "beneficiaire",
  beneficiaire: "beneficiaire",
  beneficiary_iban: "compte_beneficiaire",
  iban: "compte_beneficiaire",
  beneficiary_name: "nom_beneficiaire",
  reference: "reference",
  ref: "reference",
  claim_id: "reference_dossier",
  reason: "motif",
  motif: "motif",
  date: "date",
  recipient: "destinataire",
  destinataire: "destinataire",
  subject: "objet",
  objet: "objet",
  email: "adresse_electronique",
});

/**
 * Le nom du libellé courant d'une feuille, ou `null` hors de la table : le
 * dernier segment du pointeur (RFC 6901 : `~1` rendu en `/`, puis `~0` en
 * `~`), cherché tel quel, casse comprise. Le pointeur vide (une valeur
 * seule), une chaîne qui n'est pas un pointeur et un indice de tableau n'ont
 * pas de libellé.
 * @param {string} pointeur pointeur de la feuille (`/amount`, `/paiement/iban`)
 * @returns {string|null}
 */
export function libelleValeur(pointeur) {
  if (typeof pointeur !== "string" || !pointeur.startsWith("/")) return null;
  const segment = pointeur.slice(pointeur.lastIndexOf("/") + 1).replace(/~1/g, "/").replace(/~0/g, "~");
  return Object.hasOwn(LIBELLES_VALEURS, segment) ? LIBELLES_VALEURS[segment] : null;
}

/**
 * Les trois jetons d'une identité de session canonique (CT-3 EX-13.7), ou
 * `null` si elle n'a pas cette forme : `genre` (`oidc` ou `utilisateur`),
 * `systeme` (pour `oidc`, l'émetteur sans son préfixe `https` et ses deux
 * barres, qu'il porte toujours ; pour `utilisateur`, le domaine tel quel),
 * `personne` (le sujet, ou le nom).
 * @param {unknown} identite
 * @returns {{genre: string, systeme: string, personne: string}|null}
 */
export function partiesIdentite(identite) {
  if (typeof identite !== "string") return null;
  const jetons = identite.split(" ");
  if (jetons.length !== 3 || jetons.some((j) => j === "")) return null;
  const [genre, systeme, personne] = jetons;
  const PREFIXE = "https:" + "//";
  if (genre === "oidc") return systeme.startsWith(PREFIXE) && systeme.length > PREFIXE.length ? { genre, systeme: systeme.slice(PREFIXE.length), personne } : null;
  return genre === "utilisateur" ? { genre, systeme, personne } : null;
}

/**
 * Une identité de session en mots : la personne, puis entre parenthèses le
 * système qui a fourni son compte ; la chaîne telle quelle si elle ne se
 * découpe pas.
 * @param {unknown} identite
 * @returns {string}
 */
export function texteIdentite(identite) {
  const p = partiesIdentite(identite);
  return p === null ? String(identite) : `${p.personne} (${p.systeme})`;
}

/**
 * Les deux plus grandes unités d'une durée : `[[n, unité], …]`, unités
 * `jours`, `heures`, `minutes`, `secondes` ; `[[0, "secondes"]]` sous une
 * seconde. La valeur absolue est prise : le signe est l'affaire de l'écran.
 * @param {number} ms
 * @returns {[number, string][]}
 */
export function partiesDuree(ms) {
  let reste = Math.floor(Math.abs(ms) / 1000);
  const parties = [];
  for (const [unite, taille] of [["jours", 86400], ["heures", 3600], ["minutes", 60], ["secondes", 1]]) {
    const n = Math.floor(reste / taille);
    reste -= n * taille;
    if (n > 0 || parties.length > 0) parties.push([n, unite]);
    if (parties.length === 2) break;
  }
  while (parties.length > 1 && parties[parties.length - 1][0] === 0) parties.pop();
  return parties.length === 0 ? [[0, "secondes"]] : parties;
}

/**
 * Les parties d'un instant dans le fuseau du navigateur, ou `null` si
 * l'instant ne se lit pas : jour, mois (1 à 12), année, heure, minute,
 * seconde, et le décalage du fuseau à cet instant, en minutes à l'est d'UTC.
 * @param {string} iso instant au format de CT-1 §3
 */
export function partiesInstant(iso) {
  if (typeof iso !== "string") return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return { jour: d.getDate(), mois: d.getMonth() + 1, annee: d.getFullYear(), heure: d.getHours(), minute: d.getMinutes(), seconde: d.getSeconds(), decalage: 0 - d.getTimezoneOffset() };
}

/** Décalage d'un fuseau en texte : « UTC », « UTC+1 », « UTC−3:30 ». */
export function texteDecalage(minutes) {
  if (minutes === 0) return "UTC";
  const a = Math.abs(minutes);
  const h = Math.floor(a / 60);
  const m = a % 60;
  return `UTC${minutes > 0 ? "+" : "−"}${h}${m === 0 ? "" : `:${String(m).padStart(2, "0")}`}`;
}
