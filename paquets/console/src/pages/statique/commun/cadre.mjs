// Cadre commun des écrans (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.7,
// EX-13.29, EX-13.33 point 3) : lecture de la session au chargement (sur 401
// `session_absente`, navigation vers `/connexion?retour=<chemin>` ; une
// identité que `analyserIdentite` refuse donne le seul affichage de
// `identite_invalide`, sans autre lecture), barre haute (logo, navigation,
// la personne connectée, dite en mots (complément du 2026-11-18, langage des
// écrans : « Vous êtes connecté : … », puis le système qui a fourni le
// compte), déconnexion, bascule de thème) ; au pied de l'écran, dans un bloc
// replié, l'identité de session canonique en entier, dans son ordre
// (EX-13.7). Affichage d'une erreur : ce qui s'est passé et quoi faire, puis
// le code entre parenthèses, à la fin ; formes lisibles (instants, durées,
// états).

import { el, ajouter, bouton, code, detail, fixe, icone, marque, message, pastille, remplacer } from "./dom.mjs";
import { aCle, cleCode, t, texteCode } from "./libelles.mjs";
import { ErreurAppel, deconnexion, erreurDeSession, lireSession } from "./client.mjs";
import { partiesDuree, partiesIdentite, partiesInstant, texteDecalage } from "./lisible.mjs";
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
  if (estIdentifiantTicket(id)) return el("a", { classe, texte: id, attributs: { href: `/tickets/${id}`, "data-valeur": "" } });
  return el("span", { attributs: { "data-code": "reponse_service_invalide" } }, code(texteValeur(id), "nt-fixe valeur"), " ", marque("different", texteCode("reponse_service_invalide", ["console."]), "alerte"));
}

// Le contenu d'un écran se pose entre la barre et le pied de l'écran.
let zoneContenu = null;

/** Le conteneur du contenu de l'écran : sa zone propre une fois le cadre posé, le conteneur du document avant. */
export function principal() {
  return zoneContenu ?? document.getElementById("principal");
}

/**
 * La phrase en langage courant d'un code dont CT-3 fixe le texte mot pour
 * mot (`sens.<clé>`), ou `null` : elle dit la même chose, et se place
 * au-dessus de la phrase fixée.
 */
function cleSens(c, prefixes) {
  const cle = cleCode(c, prefixes);
  return cle !== null && aCle(`sens.${cle}`) ? `sens.${cle}` : null;
}

/**
 * Les nœuds d'un texte suivi de son code entre parenthèses (EX-13.29) : la
 * phrase, puis le code, en petit, à la fin. Le texte lu est celui de
 * `texteCode` : « phrase (code) ». Une phrase fixée par CT-3 porte `data-fixe`.
 * @param {string} c code
 * @param {string[]} prefixes
 * @returns {HTMLElement[]}
 */
export function phraseCode(c, prefixes) {
  const complet = texteCode(c, prefixes);
  const suffixe = ` (${c})`;
  const phrase = complet.slice(0, complet.length - suffixe.length);
  const noeud = cleSens(c, prefixes) === null ? el("span", { texte: phrase }) : fixe(phrase);
  return estEtatAttendu(c, prefixes) ? [noeud] : [noeud, el("span", { classe: "code-brut", texte: suffixe })];
}

/**
 * Les états attendus du parcours, qui ne sont pas des pannes (CT-3 EX-13.29,
 * complément du 2026-11-18) : aucune décision choisie, aucun portefeuille
 * choisi, demande qui n'accepte plus de décision. Leur phrase s'affiche sans
 * son code, que le détail technique de l'écran porte ; de même pour un
 * avertissement du modèle, qui n'est pas une panne non plus.
 */
export const ETATS_ATTENDUS = Object.freeze(["decision_absente", "fournisseur_non_choisi", "ticket_clos_aux_votes"]);
export function estEtatAttendu(c, prefixes) {
  return ETATS_ATTENDUS.includes(c) || prefixes.includes("avertissement.");
}

/**
 * Pour un code dont le texte est fixé : le paragraphe en langage courant
 * qui le précède (ce qui s'est passé, quoi faire), ou `null`.
 */
export function sensCode(c, prefixes) {
  const cle = cleSens(c, prefixes);
  return cle === null ? null : el("p", { classe: "nt-bandeau-titre sens-clair", texte: t(cle), attributs: { "data-sens": c } });
}

/**
 * Le paragraphe « phrase (code) », qui porte `data-code` ; pour un code dont
 * le texte est fixé, précédé de sa phrase en langage courant.
 * @returns {(HTMLElement|null)[]}
 */
export function paragrapheCode(c, prefixes, attributs = {}) {
  const sens = sensCode(c, prefixes);
  return [sens, el("p", { classe: sens === null ? null : "phrase-fixee", attributs: { "data-code": c, ...attributs } }, ...phraseCode(c, prefixes))];
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

/**
 * La personne connectée, en mots (complément du 2026-11-18) : « Vous êtes
 * connecté : », le sujet ou le nom de la personne, puis le système qui a
 * fourni son compte. Chaque jeton de l'identité de session y figure tel
 * quel, sauf le préfixe invariable de l'adresse d'un émetteur ; la chaîne
 * canonique, elle, est au pied de l'écran. Une identité qui ne se découpe
 * pas s'affiche en entier.
 */
function personneConnectee(identite) {
  const p = partiesIdentite(identite);
  if (p === null) return el("p", { classe: "nt-session barre-console-session" }, el("span", { classe: "nt-session-libelle", texte: t("cadre.personne") }), el("code", { classe: "nt-fixe", texte: String(identite), attributs: { "data-valeur": "", "data-personne": "" } }));
  return el(
    "p",
    { classe: "nt-session barre-console-session" },
    el("span", {}, el("span", { classe: "nt-session-libelle", texte: t("cadre.personne") }), " ", el("strong", { classe: "personne-connectee", texte: p.personne, attributs: { "data-valeur": "", "data-personne": "" } })),
    el("span", { classe: "nt-attenue" }, el("span", { texte: t(`cadre.compte.${p.genre}`) }), " ", el("code", { classe: "nt-fixe", texte: p.systeme, attributs: { "data-valeur": "", "data-systeme": p.genre } })),
  );
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
  const sortie = bouton(t("cadre.deconnexion"), null, { petit: true, classe: "nt-sans-impression barre-console-sortie" });
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
  // Les classes `barre-console…` portent les règles propres de la console : la barre tient sur une ligne à 1280 de large.
  const barre = el(
    "header",
    { classe: "nt-barre barre-console" },
    el("div", { classe: "nt-barre-dedans barre-console-ligne" }, logo("/tickets"), nav, el("div", { classe: "nt-barre-fin barre-console-fin" }, personneConnectee(s.session_identity), sortie), el("div", { classe: "nt-barre-outils barre-console-outils" }, bascule())),
  );
  const identite = el("div", { classe: "bande-session" }, zoneSortie);
  // EX-13.7 : l'identité de session est une chaîne canonique ; elle reste lisible en entier, dans son ordre, au pied de l'écran.
  const exacte = detail(t("cadre.detail_connexion"), null, el("p", {}, el("span", { texte: t("cadre.identite_exacte") }), " ", el("code", { classe: "nt-fixe", texte: s.session_identity, attributs: { "data-valeur": "", "data-session": "" } })));
  exacte.setAttribute("id", "detail-connexion");
  zoneContenu = el("div", { classe: "contenu-ecran" });
  remplacer(racine, barre, identite, zoneContenu, el("footer", { classe: "pied-session" }, exacte));
  // La hauteur de la barre dépend de la police et de la largeur : elle est relue à chaque changement.
  noterHauteurBarre();
  new ResizeObserver(() => noterHauteurBarre()).observe(barre);
  window.addEventListener("resize", () => noterHauteurBarre());
  return s;
}

/**
 * Ce que la marque « vérifié » veut dire, et ce qu'elle ne veut pas dire
 * (complément du 2026-11-18) : bien visible, sur chaque écran qui montre
 * une valeur vérifiée ; sur une demande encore à décider, avec l'invitation
 * à comparer les valeurs aux pièces avant d'approuver.
 * @param {boolean} clos la demande n'accepte plus de décision
 */
export function legendeVerifie(clos = false) {
  return el("p", { classe: "legende-verifie", attributs: { id: "legende-verifie" } }, icone("info"), el("span", { texte: t(clos ? "valeurs.verifie_legende_clos" : "valeurs.verifie_legende") }));
}

/**
 * « Contester » expliqué une fois par écran, là où le mot paraît pour la
 * première fois (complément du 2026-11-18) : l'explication suit le premier
 * texte visible qui le porte, hors des blocs repliés fermés ; elle est
 * replacée à chaque nouvel affichage. Dans un bouton, elle suit le groupe de
 * boutons ; dans une valeur de liste, elle s'y ajoute ; ailleurs, elle suit
 * le paragraphe ou le titre. `avecDelai` : la règle de la demande prévoit un
 * délai de contestation.
 * @param {HTMLElement} racine
 * @param {boolean} avecDelai
 */
export function expliquerContestation(racine, avecDelai) {
  for (const n of racine.querySelectorAll("[data-sens-contestation]")) n.remove();
  const marcheur = document.createTreeWalker(racine, NodeFilter.SHOW_TEXT);
  for (let n = marcheur.nextNode(); n !== null; n = marcheur.nextNode()) {
    const parent = n.parentElement;
    if (!/contest/i.test(n.data) || parent === null || parent.closest("details:not([open]) > :not(summary)") !== null) continue;
    if (typeof parent.checkVisibility === "function" && !parent.checkVisibility()) continue;
    const texte = t(avecDelai ? "contestation.sens" : "contestation.sens_aucun");
    const bouton_ = parent.closest("button");
    // Un bouton : après la rangée qui le porte (le titre et les boutons de la décision, ou le groupe de boutons).
    const hote = bouton_ !== null ? (bouton_.closest(".decision-tete") ?? bouton_.closest(".nt-actions") ?? bouton_) : parent.closest("dd, dt, p, h1, h2, h3, h4, li");
    if (hote === null) return;
    if (hote.tagName === "DD" || hote.tagName === "LI") {
      hote.appendChild(el("span", { classe: "sens-contestation", texte, attributs: { "data-sens-contestation": "" } }));
    } else if (hote.tagName === "DT" && hote.nextElementSibling !== null && hote.nextElementSibling.tagName === "DD") {
      hote.nextElementSibling.appendChild(el("span", { classe: "sens-contestation", texte, attributs: { "data-sens-contestation": "" } }));
    } else {
      hote.after(el("p", { classe: "sens-contestation", texte, attributs: { "data-sens-contestation": "" } }));
    }
    return;
  }
}

/** Hauteur notée au plus, en rem (au-delà, la barre couvre de toute façon une bonne part de la fenêtre). */
const BARRE_MAX_REM = 12;

/**
 * Note sur la racine du document (`data-barre`) la hauteur réelle de la
 * barre haute quand elle reste en haut de la fenêtre (position collante, sur
 * un poste), arrondie au rem supérieur ; 0 quand elle défile avec la page
 * (téléphone). La feuille de style en tire `scroll-padding-top` : tout bloc
 * amené dans la fenêtre (défilement de la page, lien vers un bloc, focus au
 * clavier) vient sous la barre, quelle que soit sa hauteur, sans constante.
 */
export function noterHauteurBarre() {
  const racine = document.documentElement;
  const barre = document.querySelector("header.nt-barre");
  let n = 0;
  if (barre !== null && getComputedStyle(barre).position === "sticky") {
    const rem = parseFloat(getComputedStyle(racine).fontSize) || 16;
    n = Math.min(BARRE_MAX_REM, Math.ceil(barre.getBoundingClientRect().height / rem));
  }
  if (racine.getAttribute("data-barre") !== String(n)) racine.setAttribute("data-barre", String(n));
}

/**
 * Amène un bloc dans la fenêtre, sous la barre haute : la hauteur de la
 * barre est relue juste avant (`noterHauteurBarre`). `bloc` : `start` (en
 * haut de la place laissée sous la barre) ou `center`.
 */
export function amenerSousLaBarre(noeud, bloc = "start") {
  noterHauteurBarre();
  noeud.scrollIntoView({ block: bloc });
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
  return marque("different", t("marque.caracteres_invisibles"), "alerte", { "data-invisibles": "", "data-fixe": "" });
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

/**
 * Un instant en mots, le décalage après une virgule (« 17 novembre 2026 à 18:05, UTC+1 ») : pour un instant écrit
 * lui-même entre parenthèses, sans parenthèses imbriquées. Un instant qui ne se lit pas est rendu tel quel.
 */
export function instantCourt(iso) {
  const p = partiesInstant(iso);
  if (p === null) return instant(iso);
  const deux = (n) => String(n).padStart(2, "0");
  const texte = t("date.instant_court", { jour: p.jour, mois: t(`mois.${p.mois}`), annee: p.annee, heure: `${deux(p.heure)}:${deux(p.minute)}`, fuseau: texteDecalage(p.decalage) });
  return el("time", { texte, attributs: { datetime: String(iso), title: String(iso) } });
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
  const cle = court && etat === "ouvert" ? "etat_pastille.court" : `etat_pastille.${etat}`;
  return pastille(genre, connu ? t(cle) : String(etat), nomIcone, { grande, attributs: connu ? { "data-etat": String(etat) } : { "data-etat": String(etat), "data-valeur": "" } });
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
export function entete({ surTitre = null, titre, sousTitre = null, etat = [], large = false }) {
  return el(
    "header",
    { classe: "nt-entete" },
    el("div", { classe: "nt-entete-texte" }, ...[surTitre].flat(), el("h1", { texte: titre }), sousTitre ? el("p", { classe: large ? "nt-sous-titre sous-titre-large" : "nt-sous-titre", texte: sousTitre }) : null),
    etat.length > 0 ? el("div", { classe: "nt-entete-etat" }, ...etat) : null,
  );
}

/** Texte accordé en nombre : la clé du singulier jusqu'à 1 (« 0 approbation »), celle du pluriel à partir de 2. */
export function pluriel(n, cleSingulier, clePluriel) {
  return t(n >= 2 ? clePluriel : cleSingulier, { n });
}
