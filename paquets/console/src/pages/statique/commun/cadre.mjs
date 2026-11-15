// Cadre commun des écrans (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.7,
// EX-13.29, EX-13.33 point 3) : lecture de la session au chargement (sur 401
// `session_absente`, navigation vers `/connexion?retour=<chemin>` ; une
// identité que `analyserIdentite` refuse donne le seul affichage de
// `identite_invalide`, sans autre lecture), bandeau de navigation, affichage
// d'une erreur par son texte et son code entre parenthèses, mises en forme.

import { el, ajouter, code, message, remplacer } from "./dom.mjs";
import { t, texteCode } from "./libelles.mjs";
import { ErreurAppel, deconnexion, erreurDeSession, lireSession } from "./client.mjs";

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
 */
export function lienTicket(id) {
  if (estIdentifiantTicket(id)) return el("a", { texte: id, attributs: { href: `/tickets/${id}` } });
  return el("span", { attributs: { "data-code": "reponse_service_invalide" } }, code(texteValeur(id), "fixe valeur"), " ", el("span", { classe: "marque", texte: texteCode("reponse_service_invalide", ["console."]) }));
}

/** Le conteneur principal de l'écran. */
export function principal() {
  return document.getElementById("principal");
}

/** Texte d'une erreur d'appel : son texte et son code (EX-13.29). */
export function texteErreur(e) {
  const code = e instanceof ErreurAppel ? e.code : "erreur_page";
  return texteCode(code, PREFIXES_ERREUR);
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
  const code = e instanceof ErreurAppel ? e.code : "erreur_page";
  remplacer(zone, message("erreur", el("p", { texte: texteErreur(e), attributs: { "data-code": code } }), ...suite));
  return false;
}

/**
 * Démarre un écran : lit la session et pose le cadre. Rend la session, ou
 * `null` quand l'écran ne doit rien faire de plus.
 * @param {string} ecran nom de l'écran (`tickets`, `ticket`, `inscription`, `annuaire`)
 */
export async function demarrerEcran(ecran) {
  const racine = principal();
  remplacer(racine, el("p", { classe: "discret", texte: t("cadre.chargement") }));
  const r = await lireSession();
  if (r.etat === "navigation") return null;
  if (r.etat === "identite_invalide") {
    // EX-13.7 : le seul affichage de la raison identite_invalide de 12.8.
    remplacer(racine, message("erreur", el("p", { texte: texteCode("identite_invalide", ["raison."]), attributs: { "data-code": "identite_invalide" } })));
    return null;
  }
  if (r.etat === "erreur") {
    remplacer(racine);
    afficherErreur(racine, r.erreur);
    return null;
  }
  const s = r.session;
  const nav = el("nav", { classe: "navigation", attributs: { "aria-label": t("cadre.navigation") } });
  for (const [nom, chemin] of [
    ["tickets", "/tickets"],
    ["inscription", "/inscription"],
    ["annuaire", "/annuaire"],
  ]) {
    ajouter(nav, el("a", { texte: t(`cadre.lien.${nom}`), attributs: { href: chemin, "aria-current": nom === ecran || (ecran === "ticket" && nom === "tickets") ? "page" : null } }));
  }
  const sortie = el("button", { classe: "bouton lien", texte: t("cadre.deconnexion"), attributs: { type: "button" } });
  const zoneSortie = el("span");
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
  const entete = el(
    "header",
    { classe: "entete" },
    el("p", { classe: "titre-console", texte: t("cadre.console") }),
    nav,
    el("p", { classe: "session" }, t("cadre.session"), " ", el("code", { classe: "fixe", texte: s.session_identity, attributs: { "data-session": "" } }), " ", sortie, zoneSortie),
  );
  remplacer(racine, entete);
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
  return el("span", { classe: "marque", texte: t("marque.caracteres_invisibles"), attributs: { "data-invisibles": "" } });
}

/** Durée en millisecondes, lisible (« 1 h 30 min », « 45 s », « 250 ms »). */
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

/** Une section titrée. */
export function section(titre, ...enfants) {
  return el("section", { classe: "bloc" }, el("h2", { texte: titre }), ...enfants);
}
