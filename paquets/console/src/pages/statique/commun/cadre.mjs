// Cadre commun des écrans (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.7,
// EX-13.29, EX-13.33 point 3) : lecture de la session au chargement (sur 401
// `session_absente`, navigation vers `/connexion?retour=<chemin>` ; une
// identité que `analyserIdentite` refuse donne le seul affichage de
// `identite_invalide`, sans autre lecture), barre haute (logo, navigation,
// personne connectée, déconnexion, bascule de thème) et, sous elle,
// l'identité de session en entier ; affichage d'une erreur par son texte et
// son code entre parenthèses ; formes lisibles (instants, durées, états).

import { el, ajouter, bouton, code, icone, marque, message, pastille, remplacer } from "./dom.mjs";
import { t, texteCode } from "./libelles.mjs";
import { ErreurAppel, deconnexion, erreurDeSession, lireSession } from "./client.mjs";
import { partiesDuree, partiesInstant, texteDecalage } from "./lisible.mjs";
import { basculerTheme, estClair, surTheme } from "./theme.mjs";

/** Préfixes des clés d'une erreur du serveur ou du service. */
export const PREFIXES_ERREUR = ["raison.", "serveur.", "page.", "console."];

/** Motif d'un identifiant de ticket (CT-3 EX-7.1), partagé par les écrans. */
export const MOTIF_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;

/** Vrai si `id` est un identifiant de ticket d'EX-7.1 : motif, 5 à 128 caractères. */
export function estIdentifiantTicket(id) {
  return typeof id === "string" && id.length >= 5 && id.length <= 128 && MOTIF_TICKET.test(id);
}

/**
 * Lien vers l'écran d'un ticket dont l'identifiant vient du service (revue de sécurité de l'étape 8) :
 * un identifiant hors d'EX-7.1 n'est jamais placé dans un lien ;
 * il est affiché comme une valeur, avec `reponse_service_invalide`.
 * @param {unknown} id
 * @param {string} [classe] classe du lien
 */
export function lienTicket(id, classe = "nt-fixe") {
  if (estIdentifiantTicket(id)) return el("a", { classe, texte: id, attributs: { href: `/tickets/${id}` } });
  return el("span", { attributs: { "data-code": "reponse_service_invalide" } }, code(texteValeur(id), "nt-fixe valeur"), " ", marque("different", texteCode("reponse_service_invalide", ["console."]), "alerte"));
}

/** Le conteneur principal de l'écran. */
export function principal() {
  return document.getElementById("principal");
}

/**
 * Les nœuds d'un texte suivi de son code entre parenthèses (EX-13.29) : la
 * phrase, puis le code, en petit, à sa suite. Le texte lu est celui de
 * `texteCode` : « phrase (code) ».
 * @param {string} c code
 * @param {string[]} prefixes
 * @returns {HTMLElement[]}
 */
export function phraseCode(c, prefixes) {
  const complet = texteCode(c, prefixes);
  const suffixe = ` (${c})`;
  return [el("span", { texte: complet.slice(0, complet.length - suffixe.length) }), el("span", { classe: "code-brut", texte: suffixe })];
}

/** Un paragraphe « phrase (code) », qui porte `data-code`. */
export function paragrapheCode(c, prefixes, attributs = {}) {
  return el("p", { attributs: { "data-code": c, ...attributs } }, ...phraseCode(c, prefixes));
}

/** Texte d'une erreur d'appel : son texte et son code (EX-13.29). */
export function texteErreur(e) {
  const c = e instanceof ErreurAppel ? e.code : "erreur_page";
  return texteCode(c, PREFIXES_ERREUR);
}

/**
 * Affiche une erreur d'appel dans une zone, sauf si elle fait naviguer vers la
 * connexion (session absente, réauthentification requise).
 * @param {HTMLElement} zone
 * @param {unknown} e
 * @param {...Node} suite éléments affichés après le texte
 * @returns {boolean} vrai si la page navigue
 */
export function afficherErreur(zone, e, ...suite) {
  if (erreurDeSession(e)) return true;
  const c = e instanceof ErreurAppel ? e.code : "erreur_page";
  remplacer(zone, message("erreur", paragrapheCode(c, PREFIXES_ERREUR), ...suite));
  return false;
}

/** Le logo : le signe et le mot, en texte ; `chemin` : adresse du lien, ou `null` pour un simple bloc. */
export function logo(chemin) {
  const mot = el("span", { classe: "nt-logo-mot" }, document.createTextNode(t("cadre.logo.debut")), el("span", { classe: "nt-logo-accent", texte: t("cadre.logo.fin") }));
  const contenu = [icone("logo"), el("span", { classe: "nt-logo-texte" }, mot, el("span", { classe: "nt-outil", texte: t("cadre.console") }))];
  return chemin === null ? el("div", { classe: "nt-logo" }, ...contenu) : el("a", { classe: "nt-logo", attributs: { href: chemin } }, ...contenu);
}

/** La bascule de thème : elle vaut pour la page affichée, rien n'est mémorisé (contrat 3.2). */
export function bascule() {
  const b = el("button", { classe: "nt-bascule", attributs: { type: "button", "data-bascule-theme": "" } }, icone("soleil", "nt-icone-soleil"), icone("lune", "nt-icone-lune"));
  const libeller = (clair) => {
    const libelle = t(clair ? "theme.vers_sombre" : "theme.vers_clair");
    b.setAttribute("aria-label", libelle);
    b.setAttribute("title", libelle);
  };
  libeller(estClair());
  surTheme(libeller);
  b.addEventListener("click", () => basculerTheme());
  return b;
}

/** Le dernier jeton de l'identité de session : le sujet, ou le nom, de la personne (EX-13.7). */
function personneDe(identite) {
  const jetons = String(identite).split(" ");
  return jetons[jetons.length - 1];
}

/**
 * Démarre un écran : lit la session et pose le cadre. Rend la session, ou
 * `null` quand l'écran ne doit rien faire de plus.
 * @param {string} ecran nom de l'écran (`tickets`, `ticket`, `inscription`, `annuaire`)
 */
export async function demarrerEcran(ecran) {
  const racine = principal();
  remplacer(racine, el("main", { classe: "nt-page" }, el("p", { classe: "nt-attenue", texte: t("cadre.chargement") })));
  const r = await lireSession();
  if (r.etat === "navigation") return null;
  if (r.etat === "identite_invalide") {
    // EX-13.7 : le seul affichage de la raison identite_invalide de 12.8 ; ni barre, ni action.
    remplacer(racine, el("main", { classe: "nt-page nt-page-etroite" }, message("erreur", paragrapheCode("identite_invalide", ["raison."]))));
    return null;
  }
  if (r.etat === "erreur") {
    const zone = el("main", { classe: "nt-page nt-page-etroite" });
    remplacer(racine, zone);
    afficherErreur(zone, r.erreur);
    return null;
  }
  const s = r.session;
  const liens = el("ul", { classe: "nt-nav" });
  for (const [nom, chemin] of [
    ["tickets", "/tickets"],
    ["inscription", "/inscription"],
    ["annuaire", "/annuaire"],
  ]) {
    ajouter(liens, el("li", {}, el("a", { texte: t(`cadre.lien.${nom}`), attributs: { href: chemin, "aria-current": nom === ecran || (ecran === "ticket" && nom === "tickets") ? "page" : null } })));
  }
  const nav = el("nav", { attributs: { "aria-label": t("cadre.navigation") } }, liens);
  const sortie = bouton(t("cadre.deconnexion"), null, { petit: true, classe: "nt-sans-impression" });
  const zoneSortie = el("div", { classe: "zone-sortie" });
  sortie.addEventListener("click", async () => {
    sortie.disabled = true;
    try {
      await deconnexion();
      window.location.assign("/connexion");
    } catch (e) {
      sortie.disabled = false;
      afficherErreur(zoneSortie, e);
    }
  });
  const personne = el("p", { classe: "nt-session" }, el("span", { classe: "nt-session-libelle", texte: t("cadre.personne") }), el("span", { texte: personneDe(s.session_identity), attributs: { "data-personne": "" } }));
  const barre = el(
    "header",
    { classe: "nt-barre" },
    el("div", { classe: "nt-barre-dedans" }, logo("/tickets"), nav, el("div", { classe: "nt-barre-fin" }, personne, sortie), el("div", { classe: "nt-barre-outils" }, bascule())),
  );
  // EX-13.7 : l'identité de session est une chaîne canonique ; elle s'affiche en entier, dans son ordre, sous la barre.
  const identite = el(
    "div",
    { classe: "bande-session" },
    el("p", { classe: "bande-session-dedans" }, el("span", { classe: "bande-session-libelle", texte: t("cadre.session") }), " ", el("code", { classe: "nt-fixe", texte: s.session_identity, attributs: { "data-session": "" } })),
    zoneSortie,
  );
  remplacer(racine, barre, identite);
  return s;
}

// Caractères qu'un écran ne montre pas ou qui changent le sens de lecture
// (revue de sécurité de l'étape 8, CT-3 EX-9.16) : catégories Cc (contrôle, dont C0, DEL, C1),
// Cf (format : largeur nulle, marques de direction, U+FEFF…), Zl et Zp.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
// Séquences d'échappement que `JSON.stringify` produit, ou un caractère invisible littéral.
const ECHAPPEMENT_OU_INVISIBLE = /\\(?:u[0-9a-fA-F]{4}|.)|[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;
const COURTS = Object.freeze({ "\\n": "\\u000a", "\\r": "\\u000d", "\\t": "\\u0009", "\\b": "\\u0008", "\\f": "\\u000c" });
const unitesUtf16 = (c) => Array.from({ length: c.length }, (_, k) => `\\u${c.charCodeAt(k).toString(16).padStart(4, "0")}`).join("");

/**
 * Valeur JSON affichée sous sa forme JSON (une chaîne entre guillemets, un
 * nombre et une chaîne de chiffres donc distincts), où tout caractère des
 * catégories Cc, Cf, Zl ou Zp est écrit `\uXXXX` (une unité UTF-16 par
 * séquence), les autres restant littéraux ; `JSON.stringify` n'échappe que
 * `"`, `\` et les C0, dont les formes courtes sont ramenées à `\uXXXX`.
 * @param {unknown} v
 */
export function texteValeur(v) {
  return JSON.stringify(v).replace(ECHAPPEMENT_OU_INVISIBLE, (m) => (m[0] === "\\" ? (COURTS[m] ?? m) : unitesUtf16(m)));
}

/** Vrai si une chaîne porte un caractère des catégories Cc, Cf, Zl ou Zp. */
export function contientInvisibles(v) {
  return typeof v === "string" && INVISIBLE.test(v);
}

/** Marque « contient des caractères invisibles ou de sens d'écriture » (EX-9.16). */
export function marqueInvisibles() {
  return marque("different", t("marque.caracteres_invisibles"), "alerte", { "data-invisibles": "" });
}

/** Durée en millisecondes, exacte (« 1 h 30 min », « 45 s », « 250 ms »). */
export function texteDuree(ms) {
  if (!Number.isFinite(ms)) return String(ms);
  const signe = ms < 0 ? "-" : "";
  let reste = Math.abs(Math.trunc(ms));
  const parties = [];
  const j = Math.floor(reste / 86400000);
  reste -= j * 86400000;
  const h = Math.floor(reste / 3600000);
  reste -= h * 3600000;
  const m = Math.floor(reste / 60000);
  reste -= m * 60000;
  const s = Math.floor(reste / 1000);
  reste -= s * 1000;
  if (j) parties.push(t("duree.jours", { n: j }));
  if (h) parties.push(t("duree.heures", { n: h }));
  if (m) parties.push(t("duree.minutes", { n: m }));
  if (s) parties.push(t("duree.secondes", { n: s }));
  if (reste || parties.length === 0) parties.push(t("duree.millisecondes", { n: reste }));
  return signe + parties.join(" ");
}

/** Durée arrondie à ses deux plus grandes unités (« 4 h 53 min », « 12 min 30 s »). */
export function texteDureeCourte(ms) {
  if (!Number.isFinite(ms)) return String(ms);
  return partiesDuree(ms)
    .map(([n, unite]) => t(`duree.${unite}`, { n }))
    .join(" ");
}

/** Temps restant avant une échéance, en mots : « dans 4 h 53 min », ou « échéance atteinte ». */
export function texteRestant(ms) {
  if (ms === null || !Number.isFinite(ms)) return t("modele.vide");
  return ms <= 0 ? t("modele.echeance.depassee") : t("duree.dans", { duree: texteDureeCourte(ms) });
}

/**
 * Un instant en mots, dans le fuseau du navigateur, avec son décalage :
 * « 17 novembre 2026 à 23:00 (UTC+1) » ; `secondes` : « à 23:00:06 ». Un
 * instant qui ne se lit pas est rendu tel quel.
 */
export function texteInstant(iso, { secondes = false } = {}) {
  const p = partiesInstant(iso);
  if (p === null) return String(iso);
  const deux = (n) => String(n).padStart(2, "0");
  const heure = `${deux(p.heure)}:${deux(p.minute)}${secondes ? `:${deux(p.seconde)}` : ""}`;
  return t("date.instant", { jour: p.jour, mois: t(`mois.${p.mois}`), annee: p.annee, heure, fuseau: texteDecalage(p.decalage) });
}

/**
 * Un instant affiché en mots ; l'instant exact (UTC, format de CT-1 §3) reste
 * dans `datetime` et dans l'info-bulle, et l'écran le reprend dans son
 * détail technique.
 */
export function instant(iso, options = {}) {
  return el("time", { texte: texteInstant(iso, options), attributs: { datetime: String(iso), title: String(iso) } });
}

// Pastille de chaque état d'un ticket (CT-3 7.3) : genre et icône.
const ETATS = Object.freeze({
  reserve: ["neutre", "horloge"],
  ouvert: ["attente", "horloge"],
  seuil_atteint: ["info", "horloge"],
  verification: ["info", "horloge"],
  a_remettre: ["info", "horloge"],
  approuve: ["succes", "coche"],
  refuse: ["refus", "croix"],
  expire: ["neutre", "sablier"],
  consomme: ["succes", "coche"],
  clos: ["neutre", "tiret"],
  abandonne: ["neutre", "tiret"],
});

/**
 * Pastille de l'état d'un ticket : un mot et une icône ; le code de l'état
 * reste dans `data-etat`. Un état inconnu est rendu tel quel, en pastille
 * neutre. `court` : libellé de la liste (« En attente »).
 */
export function pastilleEtat(etat, { grande = false, court = false } = {}) {
  const connu = Object.hasOwn(ETATS, etat);
  const [genre, nomIcone] = connu ? ETATS[etat] : ["neutre", "question"];
  const cle = court && (etat === "ouvert" || etat === "reserve") ? "etat_pastille.court" : `etat_pastille.${etat}`;
  return pastille(genre, connu ? t(cle) : String(etat), nomIcone, { grande, attributs: { "data-etat": String(etat) } });
}

/** Une section titrée : une carte. */
export function section(titre, ...enfants) {
  return el("section", { classe: "nt-carte" }, el("h2", { texte: titre }), ...enfants);
}

/** Une carte dont le titre porte une note à sa droite. */
export function carte(titre, noteTitre, ...enfants) {
  return el("section", { classe: "nt-carte" }, el("div", { classe: "nt-carte-titre" }, el("h2", { texte: titre }), noteTitre ? el("span", { classe: "nt-carte-note", texte: noteTitre }) : null), ...enfants);
}

/** L'en-tête d'un écran : sur-titre, titre, phrase, et l'état à droite. */
export function entete({ surTitre = null, titre, sousTitre = null, etat = [] }) {
  return el(
    "header",
    { classe: "nt-entete" },
    el("div", { classe: "nt-entete-texte" }, ...[surTitre].flat(), el("h1", { texte: titre }), sousTitre ? el("p", { classe: "nt-sous-titre", texte: sousTitre }) : null),
    etat.length > 0 ? el("div", { classe: "nt-entete-etat" }, ...etat) : null,
  );
}

/** Texte accordé en nombre : la clé du singulier jusqu'à 1 (« 0 approbation »), celle du pluriel à partir de 2. */
export function pluriel(n, cleSingulier, clePluriel) {
  return t(n >= 2 ? clePluriel : cleSingulier, { n });
}
