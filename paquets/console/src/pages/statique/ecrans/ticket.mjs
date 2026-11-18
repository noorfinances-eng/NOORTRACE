// Écran « Ticket et signature » (contrat de l'étape 6, 3.1, 3.4 et 3.5 ;
// CT-3 9.2 à 9.7, 13.9 à 13.11, 13.14, EX-13.18, EX-13.21 à EX-13.25,
// EX-13.30, EX-13.33, EX-13.34) : parcours a et b de signature d'un vote.
//
// Pas 1 : `consulter`, `annuaire` et `tickets` avec `related_to`, pour
// l'affichage seul (modèle d'EX-9.4, marques, consignes d'EX-9.20 ; aucune
// empreinte avant le choix de la décision). Pas 3 : décision (un clic puis
// une confirmation, sans présélection), fournisseur choisi dans la liste EIP-6963, `eth_requestAccounts`,
// adresse active retenue ; puis nouvelles lectures `consulter` et `annuaire`,
// `modeleAffichage` et `controleVote` : l'écran de signature n'est offert que
// si `blocking` est vide. Pas 4 à 6 : sur l'action explicite de l'écran qui
// affiche l'empreinte, après la règle de réauthentification de 3.5, une seule
// requête `personal_sign` à la fois, attente bornée par `echeanceAttente`.
// Pas 7 : `verifierReponse`, nouvelles lectures, `controleVote` de nouveau si
// `state` ou `revision` ont changé. Pas 8 : `voter` avec `requeteVoter`.
// Un changement de décision, de fournisseur ou d'adresse, `accountsChanged`
// qui retire l'adresse, ou la sortie de la page abandonne l'écran de
// signature et fait ignorer toute réponse tardive.

import { lancerDecouverte, rendreFournisseurs, demanderComptes, appelFournisseur, ecouter, noeudsPanne } from "../commun/fournisseurs.mjs";

// EX-13.22, point 1 : la découverte est posée avant toute autre opération.
const decouverte = lancerDecouverte();

import {
  modeleAffichage,
  sessionDuModele,
  controleVote,
  ticketDeControleVote,
  actionRetrait,
  entreeDeSession,
  adresseActive,
  analyserComptes,
  empreinte,
  groupes,
  requetePersonalSign,
  verifierReponse,
  requeteVoter,
  echeanceAttente,
  depuisHex,
  decoderInstant,
  egaliteJson,
} from "noortrace-console/index.mjs";
import { el, actions, ajouter, bouton, code, definitions, detail, donnee, fixe, icone, marque, message, note, pastille, remplacer, vider } from "../commun/dom.mjs";
import { aCle, t } from "../commun/libelles.mjs";
import { ErreurAppel, appeler, allerConnexion, envoiDepuis, erreurDeSession, lireSession, maintenant } from "../commun/client.mjs";
import {
  PREFIXES_ERREUR,
  afficherErreur,
  amenerSousLaBarre,
  expliquerContestation,
  contientInvisibles,
  demarrerEcran,
  entete,
  estIdentifiantTicket,
  instant,
  legendeVerifie,
  lienTicket,
  marqueInvisibles,
  paragrapheCode,
  pastilleEtat,
  phraseCode,
  pluriel,
  principal,
  sensCode,
  texteDuree,
  texteRestant,
  texteValeur,
} from "../commun/cadre.mjs";
import { groupesValeurs, libelleValeur, montantDuResume, resumeVerifie } from "../commun/lisible.mjs";

const PREFIXES_VOTE = ["console."];

// États d'un ticket dont la décision est scellée, ou qui est terminé (CT-3 7.3) : plus rien à décider.
const ETATS_DECIDES = Object.freeze(["approuve", "refuse", "expire", "consomme", "clos", "abandonne"]);
const estDecide = (vue) => vue !== null && ETATS_DECIDES.includes(vue.state);

// Membres de la vue qu'EX-9.4 affiche et lie à la signature (CT-3 EX-9.15) :
// la vue fraîche du pas 3 n'est signée que si elle porte, pour chacun, la
// même valeur que la vue affichée ; sinon la demande a changé.
const MEMBRES_LIES = Object.freeze(["ticket", "org_id", "journal_id", "request_hash", "request", "retained_event", "arguments_piece", "rule", "opening", "effects"]);

/** Vrai si les deux vues portent la même demande sur chaque membre de `MEMBRES_LIES`. */
function memeDemande(affichee, fraiche) {
  return MEMBRES_LIES.every((m) => egaliteJson(Object.hasOwn(affichee, m) ? affichee[m] : null, Object.hasOwn(fraiche, m) ? fraiche[m] : null));
}

const etat = {
  session: null,
  ticket: null,
  // Pas 1.
  vue: null,
  annuaire: null,
  // Choix.
  aConfirmer: null,
  decision: null,
  fournisseur: null,
  comptes: null,
  adresse: null,
  detacher: [],
  // Pas 3 : lecture fraîche sur laquelle portent les contrôles.
  lecture: null,
  // Requête de signature en cours.
  enCours: false,
  minuteur: null,
  generation: 0,
  // Action en cours (récusation, retrait) : confirmation affichée.
  confirmation: null,
  pas1: null,
  // Le détail technique reste ouvert, s'il l'a été, d'un affichage au suivant ; les consignes complètes et le bloc
  // « Changer ma décision » aussi.
  detailOuvert: false,
  completesOuvert: false,
  changerOuvert: false,
  // La dernière lecture de la demande a échoué.
  lectureEchouee: false,
};

const zones = {
  lecture: el("div", { classe: "zone", attributs: { id: "zone-lecture" } }),
  modele: el("div", { classe: "nt-pile nt-pile-large pile-demande", attributs: { id: "zone-modele" } }),
  lies: el("div", { classe: "zone", attributs: { id: "zone-lies" } }),
  decision: el("div", { classe: "nt-pile", attributs: { id: "zone-decision" } }),
  motif: el("div", { classe: "nt-champ", attributs: { id: "zone-motif" } }),
  vote: el("section", { classe: "nt-carte zone-carte", attributs: { id: "vote", tabindex: "-1" } }),
  fournisseurs: el("div", { classe: "nt-pile", attributs: { id: "zone-fournisseurs" } }),
  comptes: el("div", { classe: "nt-pile", attributs: { id: "zone-comptes" } }),
  signature: el("div", { classe: "zone", attributs: { id: "zone-signature" } }),
  resultat: el("div", { classe: "zone zone-resultat", attributs: { id: "zone-resultat", "aria-live": "polite", tabindex: "-1" } }),
  consignes: el("div", { classe: "zone", attributs: { id: "zone-consignes" } }),
  // La récusation, au pied de la carte « Qui décide » ; le retrait, au pied de la carte « Qui demande » (rendreModele).
  recusation: el("section", { classe: "action-carte", attributs: { id: "zone-recusation" } }),
  retrait: el("section", { classe: "action-carte", attributs: { id: "zone-retrait" } }),
};

const champMotif = el("textarea", { classe: "nt-saisie", attributs: { id: "motif", rows: "3", maxlength: "4096", "aria-describedby": "motif-avertissement" } });

// ---------------------------------------------------------------------------
// Abandon (EX-13.21, EX-13.23, EX-9.21 point 8)

function abandonner() {
  etat.generation += 1;
  etat.lecture = null;
  etat.enCours = false;
  if (etat.minuteur !== null) clearTimeout(etat.minuteur);
  etat.minuteur = null;
  rendreSignature();
}

window.addEventListener("pagehide", () => abandonner());
window.addEventListener("pageshow", (e) => {
  if (e.persisted) window.location.reload();
});

// ---------------------------------------------------------------------------
// Lectures

function identite() {
  return etat.session.session_identity;
}

/** L'adresse active que l'annuaire attribue à la session, ou `null`. */
function adresseAttribuee(annuaire) {
  const e = entreeDeSession(annuaire, identite());
  return e !== null && e.active === true ? adresseActive(e) : null;
}

async function lireVueEtAnnuaire() {
  const [c, a] = await Promise.all([
    appeler("consulter", { ticket: etat.ticket, session_identity: identite() }),
    appeler("annuaire", { session_identity: identite() }),
  ]);
  // Une vue d'un autre ticket que celui de l'écran n'est ni affichée ni signée.
  if (c.valeur === null || typeof c.valeur !== "object" || c.valeur.ticket !== etat.ticket) throw new ErreurAppel("reponse_service_invalide");
  if (a.valeur === null || typeof a.valeur !== "object" || !Array.isArray(a.valeur.entries)) throw new ErreurAppel("reponse_service_invalide");
  return { vue: c.valeur, annuaire: a.valeur };
}

// Modèle de la lecture du pas 1 (affichage) : décision nulle, adresse active
// de l'annuaire (la seule que la page retient pour un vote, EX-13.23).
function modelePas1(vue, annuaire) {
  const session = sessionDuModele(annuaire, identite(), vue);
  const approver = adresseAttribuee(annuaire);
  const modele = modeleAffichage(vue, { session, decision: null, approver, reason: null, now: maintenant() });
  const controle = controleVote(annuaire, identite(), "voter", approver ?? "", ticketDeControleVote(vue));
  const raisons = modele.blocking.filter((c) => c !== "decision_absente");
  if (controle.reason !== null && !raisons.includes(controle.reason)) raisons.push(controle.reason);
  return { modele, controle, raisons, approver };
}

async function lecturePas1() {
  vider(zones.lecture);
  let lu;
  try {
    lu = await lireVueEtAnnuaire();
  } catch (e) {
    // La demande n'a pas pu être lue : le retour à la liste, puis ce qui s'est passé et quoi faire ; rien d'autre.
    const zone = el("div");
    remplacer(zones.lecture, filTickets(), zone);
    etat.lectureEchouee = true;
    if (afficherErreur(zone, e)) vider(zones.lecture);
    for (const z of ["modele", "decision", "vote", "signature", "consignes", "recusation", "retrait", "lies"]) vider(zones[z]);
    return;
  }
  etat.lectureEchouee = false;
  let calcul;
  try {
    calcul = modelePas1(lu.vue, lu.annuaire);
  } catch {
    afficherErreur(zones.lecture, new ErreurAppel("reponse_service_invalide"));
    return;
  }
  etat.vue = lu.vue;
  etat.annuaire = lu.annuaire;
  etat.pas1 = calcul;
  rendreModele();
  rendreDecision();
  rendreConsignes();
  rendreRecusation();
  rendreRetrait();
  retenirAdresse();
  rendreFournisseursEtComptes();
}

async function lectureLies() {
  try {
    const r = await appeler("tickets", { session_identity: identite(), related_to: etat.ticket });
    rendreLies(r.valeur);
  } catch (e) {
    const z = el("div");
    remplacer(zones.lies, el("section", { classe: "nt-carte carte-serree" }, el("h2", { classe: "titre-lies", texte: t("ticket.lies.titre") }), z));
    afficherErreur(z, e);
  }
}

// ---------------------------------------------------------------------------
// Affichage du modèle (EX-9.4). Tout ce qu'EX-9.4 demande de montrer avant
// une signature reste visible sans interaction : seuls les codes bruts, les
// noms de champs et les instants exacts vont dans le détail replié. Chaque
// valeur signée s'affiche à un seul endroit (complément du 2026-11-18,
// langage des écrans) : les valeurs de la demande dans la carte « essentiel »,
// le demandeur et la règle dans la carte quand la console les a vérifiés.

const MARQUES_ARGUMENT = Object.freeze({ verifie: ["verifie", "coche"], non_verifiable: ["non-verifiable", "question"], different: ["different", "different"] });
// Marques dont CT-3 fixe le texte (EX-9.4, EX-9.16).
const MARQUES_FIXEES = Object.freeze(["verifie", "non_verifiable"]);

function marqueArgument(statut) {
  const [genre, nomIcone] = MARQUES_ARGUMENT[statut] ?? [null, "info"];
  return marque(genre, t(`marque.${statut}`), nomIcone, MARQUES_FIXEES.includes(statut) ? { "data-marque": statut, "data-fixe": "" } : { "data-marque": statut });
}

// Marque déclarative (EX-9.4) : dit d'où vient la valeur, sans la vérifier ; son texte est fixé.
const marqueDeclarative = (cle) => marque(null, t(cle), "info", { "data-fixe": "" });

// Libellé d'un code à sens connu (classe d'outil, niveau de règle), suivi de
// son explication ; un code inconnu est rendu tel quel.
function libelleCode(famille, valeur) {
  if (typeof valeur !== "string" || !aCle(`${famille}.${valeur}`)) return el("span", {}, code(String(valeur)));
  return el("span", {}, t(`${famille}.${valeur}`), aCle(`${famille}_sens.${valeur}`) ? el("span", { classe: "nt-attenue nt-petit", texte: ` ${t(`${famille}_sens.${valeur}`)}` }) : null);
}

/** Décompte des votes du modèle : approbations, refus, seuil effectif. */
function decompte(modele) {
  const liste = Array.isArray(modele.votes) ? modele.votes : [];
  return { approuve: liste.filter((v) => v.decision === "approuve").length, refuse: liste.filter((v) => v.decision === "refuse").length, requis: modele.effective_required };
}

function texteVotes(d) {
  const approbations = pluriel(d.approuve, "votes.approbation", "votes.approbations");
  return d.requis === null || d.requis === undefined ? t("tickets.votes.sans_seuil", { approbations }) : t("tickets.votes", { approbations, requis: pluriel(d.requis, "votes.requise", "votes.requises") });
}

// Sous le mot « Approbations » : « 0 sur 2 requises ».
function texteVotesCourt(d) {
  return d.requis === null || d.requis === undefined ? t("votes.sans_seuil", { n: d.approuve }) : t("votes.sur", { n: d.approuve, requis: pluriel(d.requis, "votes.requise", "votes.requises") });
}

const fait = (terme, ...valeur) => el("div", { classe: "nt-fait" }, el("dt", { texte: terme }), el("dd", {}, ...valeur));

/**
 * Une liste dense de couples [terme, valeur], une ligne par couple ; un
 * couple nul est sauté ; un troisième élément vrai donne à la valeur toute
 * la largeur, sous son terme (une liste d'adresses, une valeur longue).
 */
function lignes(couples, attributs = {}, classe = null) {
  const dl = el("dl", { classe: classe === null ? "lignes" : `lignes ${classe}`, attributs });
  for (const c of couples) {
    if (c) ajouter(dl, el("div", { classe: c[2] ? "ligne ligne-pleine" : "ligne" }, el("dt", { texte: c[0] }), el("dd", {}, ...[c[1]].flat())));
  }
  return dl;
}

const valeurEtMarque = (valeur, m) => el("span", { classe: "valeur-et-marque" }, valeur, " ", m);

/**
 * Le nom que l'annuaire lu donne au titulaire d'une adresse, ou `null` :
 * seulement pour une adresse qu'un administrateur a validée dans sa fiche.
 * L'annuaire d'une session ordinaire ne porte que sa propre fiche.
 */
function nomDe(adresse) {
  const a = etat.annuaire;
  if (a === null || !Array.isArray(a.entries)) return null;
  for (const e of a.entries) {
    if (typeof e.display_name !== "string" || e.display_name === "" || !Array.isArray(e.addresses)) continue;
    if (e.addresses.some((x) => x.address === adresse && x.validated_at !== null && x.validated_at !== undefined)) return e.display_name;
  }
  return null;
}

/**
 * Une personne : son nom quand l'annuaire lu le donne, « vous » pour sa
 * propre adresse ; puis son adresse de signature, entière, en petit.
 */
function personne(adresse) {
  const nom = nomDe(adresse);
  const mien = etat.pas1 !== null && adresse === etat.pas1.approver;
  return el(
    "span",
    { classe: "personne" },
    nom === null ? null : donnee(nom, "personne-nom"),
    mien ? el("span", { classe: nom === null ? "personne-nom capitale" : "nt-attenue", texte: nom === null ? t("modele.jeu.vous") : `(${t("modele.jeu.vous")})`, attributs: { "data-vous": "" } }) : null,
    // Sans nom connu, l'adresse est présentée : « adresse de signature ».
    nom === null && !mien ? el("span", { classe: "personne-presentation", texte: t("personne.adresse") }) : null,
    code(adresse, "nt-fixe personne-adresse"),
  );
}

/** Une valeur de la demande : son libellé courant, son chemin exact, sa valeur telle qu'elle est signée ou fournie, sa marque. */
function ligneValeur(a) {
  const nom = libelleValeur(a.pointer);
  const racine = a.pointer === "";
  const libelle = racine ? t("valeurs.racine") : nom === null ? null : t(`valeur.${nom}`);
  return el(
    "li",
    { classe: "ligne-valeur", attributs: { "data-pointeur": a.pointer, "data-libelle": nom ?? "" } },
    el(
      "span",
      { classe: "valeur-nom" },
      // Hors de la table des libellés, le chemin lui-même sert de libellé ; sinon il reste affiché à côté, en petit.
      libelle === null ? code(a.pointer, "nt-fixe valeur-libelle") : el("span", { classe: "valeur-libelle", texte: libelle }),
      libelle === null ? null : racine ? el("span", { classe: "valeur-chemin", texte: t("modele.arguments.racine") }) : code(a.pointer, "nt-fixe valeur-chemin"),
    ),
    // Valeur sous sa forme JSON, caractères invisibles écrits `\uXXXX` et marqués (EX-9.16, revue de sécurité de l'étape 8).
    el("span", { classe: "valeur-contenu" }, code(texteValeur(a.value), "nt-fixe valeur"), contientInvisibles(a.value) ? marqueInvisibles() : null),
    marqueArgument(a.status),
  );
}

/**
 * « Ce que contient la demande » : toutes les feuilles du modèle, chacune à
 * un seul endroit, avec sa valeur et sa marque. Une feuille que la console
 * n'a pas pu vérifier n'est rendue que dans le groupe « À contrôler par
 * vous-même » ; une feuille différente, dans un groupe d'alerte. Au-delà de
 * huit valeurs, la présentation se resserre : rien n'est replié (EX-9.4).
 */
function rendreValeurs(modele, clos) {
  const g = groupesValeurs(modele);
  const total = modele.arguments.length;
  const classeListe = total > 8 ? "liste-nue liste-valeurs valeurs-denses" : "liste-nue liste-valeurs";
  const liste = (feuilles, id) => el("ul", { classe: classeListe, attributs: { id } }, ...feuilles.map(ligneValeur));
  const parties = [
    el("h3", { classe: "nt-sur-titre valeurs-titre", texte: t(clos ? "valeurs.titre_clos" : "valeurs.titre"), attributs: { id: "arguments-titre" } }),
  ];
  if (total === 0) parties.push(el("p", { classe: "nt-attenue", texte: t("valeurs.aucune") }));
  if (g.differentes.length > 0) {
    parties.push(
      el(
        "div",
        { classe: "groupe-valeurs groupe-different", attributs: { id: "valeurs-differentes", role: "alert" } },
        el("h4", { classe: "groupe-valeurs-titre" }, icone("alerte"), el("span", { texte: t(g.differentes.length >= 2 ? "different.titres" : "different.titre") })),
        el("p", { texte: t("different.sens") }),
        liste(g.differentes, "liste-differentes"),
      ),
    );
  }
  // Sous les valeurs vérifiées, ce que « vérifié » veut dire, et ce qu'il ne veut pas dire : la console ne dit pas
  // qu'une valeur est juste. Sur une demande à décider, l'invitation à comparer les valeurs aux pièces, avant d'approuver.
  if (g.verifiees.length > 0) parties.push(liste(g.verifiees, "valeurs-verifiees"), legendeVerifie(clos));
  // Une valeur qui cache des caractères invisibles (EX-9.16) : ce que cela veut dire, et quoi faire.
  if (modele.arguments.some((a) => contientInvisibles(a.value))) parties.push(note("alerte", el("p", { texte: t("marque_sens.caracteres_invisibles"), attributs: { id: "invisibles-sens" } })));
  if (g.aControler.length > 0) {
    parties.push(
      el(
        "div",
        { classe: clos ? "groupe-valeurs" : "groupe-valeurs groupe-controle", attributs: { id: "a-controler", role: "note" } },
        el("h4", { classe: "groupe-valeurs-titre" }, icone(clos ? "question" : "alerte"), el("span", { texte: t(clos ? "controle.titre_clos" : "controle.titre") })),
        el("p", { texte: t(clos ? "controle.sens_clos" : "controle.sens"), attributs: { id: "controle-sens" } }),
        liste(g.aControler, "valeurs-a-controler"),
      ),
    );
  }
  return el("div", { classe: "valeurs", attributs: { id: "arguments", "aria-labelledby": "arguments-titre" } }, ...parties);
}

/** La phrase d'en-tête : composée des seules valeurs que le modèle a vérifiées (`resumeVerifie`). */
function rendrePhrase(r, attributs) {
  const phrase = el("p", { classe: "nt-essentiel-phrase phrase-large", attributs });
  if (r.outil === null) ajouter(phrase, t("essentiel.non_liee"));
  else ajouter(phrase, t("essentiel.outil"), " ", el("code", { classe: "nt-fixe", texte: r.outil, attributs: { "data-resume": "outil", "data-valeur": "" } }), r.montant === null ? t("essentiel.point") : t("essentiel.montant"));
  return phrase;
}

/** Le montant en grand, quand ses deux feuilles sont vérifiées ; `null` sinon. */
function rendreMontant(r, attributs) {
  const m = montantDuResume(r);
  if (m === null) return null;
  return el("p", { classe: "nt-chiffre", attributs: { "data-valeur": "", ...attributs } }, document.createTextNode(m.texte), el("span", { classe: "nt-chiffre-unite", texte: m.devise }));
}

// Le bandeau « séparation non vérifiable pour ce demandeur » (EX-9.4, 10.5), repris à côté du demandeur.
function mentionSeparation(modele) {
  return modele.separation_banner ? el("span", { classe: "fait-second", attributs: { "data-code": "separation_non_verifiable" } }, ...phraseCode("separation_non_verifiable", ["avertissement."])) : null;
}

/**
 * La carte « essentiel » : la phrase d'en-tête, le montant s'il est vérifié,
 * toutes les valeurs de la demande avec leur marque, qui demande, pourquoi,
 * où en sont les approbations et pour quand, puis la décision.
 */
function rendreEssentiel(modele, clos) {
  const r = resumeVerifie(modele);
  const d = decompte(modele);
  // La phrase et, à sa suite quand la place le permet, le montant en grand.
  const parties = [el("p", { classe: "nt-sur-titre", texte: t(clos ? "essentiel.titre_clos" : "essentiel.titre"), attributs: { id: "essentiel-titre" } }), el("div", { classe: "phrase-et-montant" }, rendrePhrase(r, { id: "phrase-entete" }), rendreMontant(r, { id: "montant-entete" })), rendreValeurs(modele, clos)];
  const faits = el("dl", { classe: "nt-faits faits-ligne" });
  if (r.demandeur !== null) {
    ajouter(
      faits,
      fait(
        t("essentiel.demandeur"),
        el("code", { classe: "nt-fixe", texte: r.demandeur, attributs: { "data-resume": "demandeur", "data-valeur": "" } }),
        // D'où vient cette identité, en mots, puis la marque fixée (EX-9.4).
        el("span", { classe: "fait-second demandeur-sens" }, el("span", { texte: t("essentiel.demandeur_sens") }), " ", marqueDeclarative("marque.configuration_hote")),
        mentionSeparation(modele),
      ),
    );
  }
  if (r.regle !== null) ajouter(faits, fait(t("essentiel.regle"), el("span", { texte: r.regle, attributs: { "data-resume": "regle", "data-valeur": "" } }), el("span", { classe: "fait-second", texte: t("essentiel.regle_sens") })));
  ajouter(faits, fait(t("essentiel.votes"), el("span", { texte: texteVotesCourt(d), attributs: { id: "resume-votes" } }), d.refuse > 0 ? el("span", { classe: "fait-second", texte: t("votes.refus", { n: d.refuse }) }) : null));
  // Une demande décidée ou close n'a plus d'échéance à tenir.
  // Pour qui a déjà décidé, la date n'est plus « à décider avant » : c'est celle où la demande expire.
  if (!clos) ajouter(faits, fait(t(modele.state === "ouvert" && maDecisionEnregistree() !== null ? "essentiel.echeance_deja" : "essentiel.echeance"), modele.deadline === null ? el("span", { texte: t("modele.vide") }) : instant(modele.deadline), el("span", { classe: "fait-second", texte: texteRestant(modele.remaining_ms), attributs: { id: "resume-echeance" } })));
  parties.push(faits, zones.decision);
  return el("section", { classe: "nt-essentiel essentiel-serre", attributs: { id: "essentiel", "aria-labelledby": "essentiel-titre" } }, ...parties);
}

/** Le lien de retour vers la liste des demandes. */
function filTickets() {
  return el("a", { classe: "nt-fil", attributs: { href: "/tickets" } }, icone("retour"), t("ticket.fil"));
}

/** Une carte du reste de la demande : son titre, une note à sa droite, son contenu. */
function carteReste(titre, noteTitre, attributs, ...enfants) {
  return el("section", { classe: "nt-carte carte-serree", attributs }, el("div", { classe: "nt-carte-titre" }, el("h3", { texte: titre }), noteTitre ? el("span", { classe: "nt-carte-note", texte: noteTitre }) : null), ...enfants);
}

function rendreModele() {
  const { modele, controle, raisons } = etat.pas1;
  const vue = etat.vue;
  const clos = raisons.includes("ticket_clos_aux_votes");
  const etatConnu = aCle(`etat_pastille.${modele.state}`);
  const r = resumeVerifie(modele);
  const parties = [];

  // En-tête : la demande, son état en un mot, ce que cet état veut dire. Le retour à la liste, l'identifiant et
  // l'état tiennent sur une ligne, pour que la décision reste dans le premier écran d'un poste.
  const depassee = modele.remaining_ms !== null && modele.remaining_ms <= 0;
  const deja = modele.state === "ouvert" && maDecisionEnregistree() !== null;
  parties.push(
    entete({
      surTitre: el(
        "div",
        { classe: "ligne-ticket" },
        el("div", { classe: "ligne-ticket-debut" }, filTickets(), el("p", { classe: "nt-sur-titre" }, t("ticket.titre"), " ", code(modele.ticket))),
        el(
          "div",
          { classe: "ligne-ticket-etat", attributs: { id: "etat-ticket" } },
          // La personne a déjà décidé et la demande reste ouverte : la pastille ne dit plus « À décider ».
          deja ? pastille("info", t("etat_pastille.deja"), "horloge", { grande: true, attributs: { "data-etat": String(modele.state), "data-deja": "" } }) : pastilleEtat(modele.state, { grande: true }),
          !clos && modele.remaining_ms !== null && modele.deadline !== null
            ? el("time", { classe: "nt-attenue nt-petit", texte: depassee ? t("modele.echeance.depassee") : t(deja ? "ticket.echeance_deja" : "ticket.echeance_courte", { restant: texteRestant(modele.remaining_ms) }), attributs: { datetime: String(modele.deadline) } })
            : null,
        ),
      ),
      titre: t(deja ? "ticket.titre_etat.deja" : etatConnu ? `ticket.titre_etat.${modele.state}` : "ticket.titre_etat.inconnu"),
      // « Elle attend votre accord » ne se dit pas à qui a déjà donné sa décision.
      sousTitre: etatConnu ? (deja ? t("etat_sens.ouvert_deja") : t(`etat_sens.${modele.state}`)) : null,
      large: true,
    }),
  );

  // Raisons qui bloquent dès la lecture du pas 1, et avertissements : au-dessus de tout le reste.
  parties.push(rendreRaisons(raisons, modele, vue));
  parties.push(...rendreAvertissements(modele.warnings, controle.warnings));

  // La personne connectée a déjà décidé et la demande reste ouverte : le dire avant la carte, sous les avertissements.
  parties.push(rendreDejaDecide(modele));

  // L'essentiel : ce qui est demandé, chaque valeur de la demande, et la décision.
  parties.push(rendreEssentiel(modele, clos));

  // Le reste de la demande : outil et règle, qui demande, effets, qui décide, ce que la signature engage.
  parties.push(el("div", { classe: "titre-groupe" }, el("h2", { texte: t("groupe.reste") }), clos ? null : el("p", { classe: "nt-attenue", texte: t("groupe.reste_sens") })));
  const d = modele.delegation;
  const cartes = [];

  cartes.push(
    carteReste(
      t("modele.outil"),
      null,
      { id: "carte-outil" },
      lignes([
        // Le nom annoncé est dans la phrase d'en-tête quand la console l'a vérifié.
        r.outil === null ? [t("modele.outil.annonce"), code(modele.tool.announced)] : null,
        [t("modele.outil.origine"), code(modele.tool.original)],
        [t("modele.outil.alias"), code(modele.tool.server_alias)],
        [t("modele.outil.classe"), libelleCode("classe", modele.tool.class)],
        // La règle est dans la carte « essentiel » quand la console l'a vérifiée.
        r.regle === null ? [t("modele.regle.policy_rule"), code(modele.rule.policy_rule)] : null,
        modele.rule.name === modele.rule.policy_rule ? null : [t("modele.regle.nom"), donnee(String(modele.rule.name))],
        [t("modele.regle.description"), modele.rule.description === null ? t("modele.vide") : donnee(modele.rule.description)],
        [t("modele.regle.niveau"), libelleCode("niveau", modele.rule.level)],
        [t("modele.regle.contestation"), modele.rule.contest_ms === 0 ? t("modele.regle.sans_contestation") : texteDuree(modele.rule.contest_ms)],
      ]),
    ),
    carteReste(
      t("modele.delegation"),
      null,
      { id: "carte-demandeur" },
      lignes([
        r.demandeur === null ? [t("modele.delegation.launched_by"), [code(d.launched_by), el("span", { classe: "fait-second demandeur-sens" }, el("span", { texte: t("essentiel.demandeur_sens") }), " ", marqueDeclarative("marque.configuration_hote")), mentionSeparation(modele)]] : null,
        [t("modele.delegation.scope"), valeurEtMarque(code(d.scope), marqueDeclarative("marque.configuration_hote"))],
        [t("modele.delegation.on_behalf_of"), valeurEtMarque(d.on_behalf_of === null ? el("span", { texte: t("modele.vide") }) : code(d.on_behalf_of), marqueDeclarative("marque.declare_hote"))],
        [t("modele.delegation.run_id"), valeurEtMarque(d.run_id === null ? el("span", { texte: t("modele.vide") }) : code(d.run_id), marqueDeclarative("marque.declare_hote"))],
        [
          t("modele.intention"),
          valeurEtMarque(
            modele.intent === null ? el("span", { texte: t("modele.vide") }) : donnee(modele.intent),
            modele.intent_status === "en_clair" ? marque(null, t("marque.intention_declaree"), "info", { "data-intention": modele.intent_status, "data-fixe": "" }) : marque("non-verifiable", t("marque.non_verifiable"), "question", { "data-intention": modele.intent_status, "data-fixe": "" }),
          ),
        ],
      ]),
      clos ? null : el("p", { classe: "nt-attenue note-carte", texte: t("modele.delegation.sens") }),
      // Le retrait de la demande, offert à qui l'a lancée : avec le reste de la demande, au pied de « Qui demande ».
      zones.retrait,
    ),
  );

  // Effets déclarés prévus (EX-9.4) : affichés tels que le service les donne, déclaratifs.
  const effets = el("ul", { classe: "liste-nue effets", attributs: { id: "effets" } });
  if (modele.effects.length === 0) ajouter(effets, el("li", { classe: "nt-attenue", texte: t("modele.effets.aucun") }));
  for (const e of modele.effects) {
    const nonResolus = new Map(e.unresolved.map((u) => [u.member, u.pointer]));
    const membre = (nom) => {
      if (nonResolus.has(nom)) {
        return el("span", { classe: "valeur-et-marque", attributs: { "data-connu-apres-execution": nom } }, marque(null, t("marque.connu_apres_execution"), "horloge", { "data-fixe": "" }), el("span", { classe: "nt-attenue note-carte" }, el("span", { texte: t("modele.effets.inconnu_sens") }), " ", code(nonResolus.get(nom))));
      }
      return e[nom] === null ? t("modele.vide") : code(e[nom]);
    };
    ajouter(
      effets,
      el(
        "li",
        {},
        lignes([
          [t("modele.effets.systeme"), code(e.system)],
          [t("modele.effets.action"), libelleCode("classe", e.action)],
          [t("modele.effets.objet"), membre("object"), nonResolus.has("object")],
          [t("modele.effets.montant"), membre("amount")],
          [t("modele.effets.devise"), membre("currency")],
        ]),
      ),
    );
  }
  cartes.push(carteReste(t("modele.effets"), t("modele.effets.declaratif"), { id: "carte-effets" }, effets));

  // Ticket ouvrant (EX-5.4).
  if (modele.opening !== null) {
    const o = modele.opening;
    const memes = el("ul", { classe: "liste-nue" });
    for (const s of o.same_arguments) ajouter(memes, el("li", {}, code(s.pointer), " ", code(texteValeur(s.value), "nt-fixe valeur"), contientInvisibles(s.value) ? " " : null, contientInvisibles(s.value) ? marqueInvisibles() : null));
    cartes.push(
      carteReste(
        t("modele.ouvrant"),
        null,
        { id: "carte-ouvrant" },
        lignes([
          [t("modele.ouvrant.outil"), code(o.tool)],
          [t("modele.ouvrant.condition"), o.when === null ? t("modele.vide") : el("pre", { classe: "nt-pre", texte: JSON.stringify(o.when, null, 2), attributs: { "data-valeur": "" } })],
          [t("modele.ouvrant.memes_arguments"), o.same_arguments.length === 0 ? t("modele.vide") : memes],
          [t("modele.ouvrant.portee"), t("modele.ouvrant.portee_texte", { max_calls: o.max_calls, duree: texteDuree(o.duration_ms) })],
        ]),
      ),
    );
  }

  // Champs signés. Une demande décidée n'a plus de décision à choisir : la carte ne garde que ses identifiants.
  const evenementVerifie = !modele.blocking.includes("evenement_invalide");
  const signes = [
    carteReste(
      t(clos ? "modele.signes_clos" : "modele.signes"),
      null,
      { id: "champs-signes" },
      el("p", { classe: "nt-attenue note-carte", texte: t(clos ? "modele.signes.note_clos" : "modele.signes.note") }),
      lignes([
        clos ? null : [t("modele.signes.decision"), etat.decision === null ? el("span", { classe: "nt-attenue", texte: maDecisionEnregistree() === null ? t("modele.signes.decision_absente") : t(`modele.signes.decision_deja.${maDecisionEnregistree().decision}`) }) : el("span", { attributs: { "data-decision": etat.decision } }, el("span", { classe: "capitale", texte: t(`decision_verbe.${etat.decision}`) }), el("span", { classe: "nt-attenue", texte: t("modele.signes.decision_forme") }), " ", code(etat.decision))],
        [t("modele.signes.ticket"), code(modele.ticket)],
        [t("modele.signes.org_id"), code(modele.org_id)],
        [t("modele.signes.journal_id"), code(modele.journal_id)],
        [t("modele.signes.request_hash"), code(modele.request.request_hash)],
        [
          t("modele.signes.evenement"),
          el(
            "span",
            { classe: "valeur-et-marque" },
            // Le numéro (`seq`) et l'instant (`ts`) de l'événement restent affichés tels quels (EX-9.4).
            el("span", { attributs: { id: "evenement-retenu" } }, el("span", { texte: t("modele.signes.evenement_numero") }), " ", code(String(modele.request.seq)), el("span", { texte: t("modele.signes.evenement_instant") }), " ", code(String(modele.request.ts))),
            evenementVerifie ? marque("verifie", t("marque.verifie"), "coche", { "data-evenement": "verifie", "data-fixe": "" }) : marque("different", t("marque.evenement_invalide"), "different", { "data-evenement": "invalide" }),
          ),
        ],
      ]),
    ),
  ];

  // Aucune empreinte de D_A avant le choix de la décision (EX-9.20, point 2 ;
  // contrat 3.4, révision de l'étape 6) : seule celle de la décision choisie
  // paraît, sur l'écran de signature ; `empreinte_divergente` montre les deux
  // (table de 13.14).

  // Qui décide : le jeu figé (seuil, membres, source), la contestation s'il y en a une, les votes.
  const c = modele.contest;
  const sansContestation = modele.rule.contest_ms === 0 && c.window_end === null && c.objections.length === 0 && c.last_threshold_at === null;
  const jeu = modele.approver_set;
  const votes = el("div", { classe: "votes", attributs: { id: "votes" } }, el("h4", { classe: "nt-sur-titre", texte: t("modele.votes") }));
  if (modele.votes.length === 0) {
    ajouter(votes, el("p", { classe: "nt-attenue", texte: t("modele.votes.aucun") }));
  } else {
    const liste = el("ul", { classe: "liste-nue liste-votes" });
    for (const v of modele.votes) {
      ajouter(
        liste,
        el(
          "li",
          { classe: "vote", attributs: { "data-vote": v.approver, "data-decision": v.decision } },
          personne(v.approver),
          // La décision d'un vote est la valeur signée, `approuve` ou `refuse` : elle reste dans `data-decision` ; l'écran la dit en mots.
          pastille(v.decision === "approuve" ? "succes" : "refus", t(`vote_fait.${v.decision}`), v.decision === "approuve" ? "coche" : "croix", { telQuel: true }),
          instant(v.at),
          v.reason === null ? el("span", { classe: "nt-attenue vote-motif", texte: t("modele.votes.sans_motif") }) : el("span", { classe: "vote-motif" }, donnee(t("modele.votes.motif", { motif: v.reason }))),
        ),
      );
    }
    votes.appendChild(liste);
  }
  cartes.push(
    carteReste(
      t("modele.jeu"),
      texteVotes(decompte(modele)),
      { id: "carte-decision" },
      jeu === null
        ? el("p", { texte: t("modele.jeu.non_fige") })
        : lignes([
            [t("modele.jeu.seuil"), el("span", { texte: t("modele.jeu.seuil_texte", { t: jeu.threshold.required, n: jeu.threshold.size }) })],
            // Le nombre requis en ce moment n'est redit que s'il diffère de celui de la liste.
            modele.effective_required === null || modele.effective_required === jeu.threshold.required ? null : [t("modele.jeu.seuil_effectif"), String(modele.effective_required)],
            [t("modele.jeu.membres"), el("ul", { classe: "liste-nue membres" }, ...jeu.members.map((m) => el("li", {}, personne(m)))), true],
            [t("modele.jeu.source"), donnee(jeu.source, "nt-fixe"), true],
          ]),
      sansContestation
        ? null
        : lignes(
            [
              [t("modele.contest.fin_fenetre"), c.window_end === null ? t("modele.contest.aucune_fenetre") : instant(c.window_end)],
              [t("modele.contest.objections"), c.objections.length === 0 ? t("modele.contest.aucune_objection") : el("ul", { classe: "liste-nue" }, ...c.objections.map((o) => el("li", {}, personne(o.approver), " ", instant(o.at))))],
              [t("modele.contest.dernier_instant"), c.last_threshold_at === null ? t("modele.vide") : instant(c.last_threshold_at)],
            ],
            { id: "contestation" },
          ),
      votes,
      // Se retirer de la demande (récusation) : avec le reste de la demande, au pied de « Qui décide ».
      zones.recusation,
    ),
  );
  // Les cartes courtes en colonnes équilibrées ; la carte des identifiants signés sur toute la largeur, une ligne par
  // identifiant. La récusation et le retrait, deux gestes définitifs, sont dans ces cartes, avec le reste de la
  // demande : jamais entre le choix du portefeuille et la signature.
  parties.push(el("div", { classe: "colonnes-cartes" }, ...cartes), ...signes);

  // Détail technique, replié : codes bruts, noms de champs, instants exacts.
  // Rien de ce qu'EX-9.4 demande d'afficher n'y est : chaque valeur ci-dessous
  // est déjà à l'écran sous sa forme lisible.
  const exact = (v) => (v === null || v === undefined ? el("span", { texte: t("modele.vide") }) : code(String(v)));
  const technique = [
    [t("detail.etat"), exact(modele.state)],
    [t("detail.classe"), exact(modele.tool.class)],
    [t("detail.niveau"), exact(modele.rule.level)],
    [t("detail.echeance"), exact(modele.deadline)],
    [t("detail.restant"), modele.remaining_ms === null ? el("span", { texte: t("modele.vide") }) : el("span", { texte: modele.remaining_ms <= 0 ? t("modele.echeance.depassee") : texteDuree(modele.remaining_ms) })],
    [t("detail.contestation"), exact(modele.rule.contest_ms)],
    [t("detail.fin_fenetre"), exact(c.window_end)],
    [t("detail.dernier_instant"), exact(c.last_threshold_at)],
  ];
  if (c.objections.length > 0) technique.push([t("detail.objections"), el("ul", { classe: "liste-nue" }, ...c.objections.map((o) => el("li", {}, code(o.approver), " ", code(o.at))))]);
  if (modele.votes.length > 0) technique.push([t("detail.votes"), el("ul", { classe: "liste-nue" }, ...modele.votes.map((v) => el("li", {}, code(v.approver), " ", code(v.decision), " ", code(v.at))))]);
  if (modele.warnings.length > 0) technique.push([t("detail.avertissements"), el("span", {}, ...modele.warnings.flatMap((w, k) => [k > 0 ? " " : null, code(w)]))]);
  if (raisons.length > 0) technique.push([t("detail.raisons"), el("span", {}, ...raisons.flatMap((x, k) => [k > 0 ? " " : null, code(x)]))]);
  // Les états attendus du parcours ne sont pas des pannes : leur code est ici, pas à côté de leur phrase (EX-13.29).
  technique.push([t("detail.parcours"), el("span", { attributs: { id: "detail-parcours" } })]);
  // Le sens de la marque « non vérifiable par la console », tel qu'il a été fixé : l'encadré le dit en langage courant.
  if (!clos && groupesValeurs(modele).aControler.length > 0) technique.push([t("detail.non_verifiable"), fixe(t("modele.arguments.non_verifiable_sens"), "nt-petit", "span")]);
  technique.push([t("detail.champs"), el("span", { classe: "nt-fixe nt-petit", texte: t("detail.champs_texte") })]);
  const bloc = detail(t("detail.titre"), t("detail.note"), definitions(technique));
  bloc.setAttribute("id", "detail-technique");
  bloc.open = etat.detailOuvert;
  bloc.addEventListener("toggle", () => {
    etat.detailOuvert = bloc.open;
  });
  parties.push(bloc);

  remplacer(zones.modele, ...parties);
  majParcours();
  sensContestation();
}

/**
 * « Contester » expliqué une fois, là où le mot paraît pour la première fois sur l'écran de la demande (le résumé,
 * la décision et le reste de la demande sont dans `zones.modele`) ; replacé à chaque affichage, et quand un bloc
 * replié s'ouvre ou se ferme.
 */
function sensContestation() {
  if (etat.vue === null || typeof etat.vue !== "object" || etat.vue.rule === null || typeof etat.vue.rule !== "object") return;
  expliquerContestation(zones.modele, etat.vue.rule.contest_ms > 0);
}
zones.modele.addEventListener("toggle", () => sensContestation(), true);

/** Les codes des états attendus du parcours (décision ou portefeuille pas encore choisis), au détail technique. */
function majParcours() {
  const zone = zones.modele.querySelector("#detail-parcours");
  if (zone === null) return;
  const codes = [];
  if (etat.pas1 !== null && !etat.pas1.raisons.includes("ticket_clos_aux_votes")) {
    if (etat.decision === null) codes.push("decision_absente");
    if (etat.fournisseur === null) codes.push("fournisseur_non_choisi");
  }
  remplacer(zone, ...(codes.length === 0 ? [el("span", { texte: t("modele.vide") })] : codes.map((c) => code(c, "code-parcours"))));
}

/**
 * La décision que la vue porte déjà pour la personne connectée, sur une
 * demande qui accepte encore des décisions, ou `null` : le vote courant de
 * l'adresse que l'annuaire lui attribue. Rien n'est déduit hors de la vue.
 */
function maDecisionEnregistree() {
  const p = etat.pas1;
  if (p === null || p.approver === null || p.raisons.includes("ticket_clos_aux_votes")) return null;
  const votes = Array.isArray(p.modele.votes) ? p.modele.votes : [];
  const v = votes.find((x) => x !== null && typeof x === "object" && x.approver === p.approver);
  return v !== undefined && (v.decision === "approuve" || v.decision === "refuse") ? v : null;
}

/**
 * Le rappel d'une décision déjà enregistrée (CT-3 EX-9.4, complément du
 * 2026-11-18, point 8) : ce que la personne a décidé et quand, puis ce que
 * la demande attend, d'après la vue seule (état, décompte, contestations).
 */
function rendreDejaDecide(modele) {
  const v = maDecisionEnregistree();
  if (v === null) return null;
  const d = decompte(modele);
  const c = modele.contest;
  let suite;
  if (modele.state !== "ouvert") suite = aCle(`vote.suite.${modele.state}`) ? t(`vote.suite.${modele.state}`) : null;
  else if (c !== null && typeof c === "object" && Array.isArray(c.objections) && c.objections.length > 0) suite = t("deja.contestee");
  else if (Number.isInteger(d.requis) && d.requis > d.approuve) suite = pluriel(d.requis - d.approuve, "deja.attend", "deja.attendent");
  else suite = t("deja.ouvert");
  return message("info", el("p", { classe: "nt-bandeau-titre", attributs: { id: "deja-decide", "data-decision": v.decision } }, el("span", { texte: t(`deja.${v.decision}`) }), " ", instant(v.at), ".", suite === null ? null : el("span", { texte: ` ${suite}` })));
}

/**
 * Les raisons qui bloquent ; pour `empreinte_divergente`, les deux empreintes
 * de chaque décision. Une demande qui n'accepte plus de décision, sans autre
 * raison, n'est pas une panne : le bandeau dit ce qui s'est passé et ce que
 * cela implique, sans alarme, et sans affirmer ce que la console ne sait pas.
 */
function rendreRaisons(raisons, modele, vue) {
  if (raisons.length === 0) return null;
  const ul = el("ul", { classe: "liste-nue raisons" });
  for (const r of raisons) {
    const sens = sensCode(r, PREFIXES_VOTE);
    const li = el("li", { attributs: { "data-code": r } }, sens, el("span", { classe: sens === null ? null : "phrase-fixee" }, ...phraseCode(r, PREFIXES_VOTE)));
    if (r === "empreinte_divergente" && modele.digests !== null) {
      const service = (d) => (vue.digests && typeof vue.digests[d] === "string" && /^0x[0-9a-f]{64}$/.test(vue.digests[d]) ? empreinte(vue.digests[d]) : t("modele.vide"));
      const table = el("table", { classe: "nt-tableau", attributs: { id: "empreintes-divergentes" } });
      ajouter(table, el("thead", {}, el("tr", {}, ...["decision", "console", "service"].map((x) => el("th", { texte: t(`divergence.${x}`), attributs: { scope: "col" } })))));
      for (const d of ["approuve", "refuse"]) {
        ajouter(
          table,
          el(
            "tr",
            { attributs: { "data-decision": d } },
            el("td", { classe: "nt-cellule-titre", texte: t(`decision.${d}`), attributs: { "data-libelle": t("divergence.decision"), "data-valeur": "" } }),
            el("td", { attributs: { "data-libelle": t("divergence.console") } }, code(modele.digests[d].fingerprint)),
            el("td", { attributs: { "data-libelle": t("divergence.service") } }, code(service(d))),
          ),
        );
      }
      ajouter(li, table, el("p", { texte: t("divergence.prevenir") }));
    }
    ul.appendChild(li);
  }
  if (raisons.length === 1 && raisons[0] === "ticket_clos_aux_votes") {
    const approuve = modele.state === "approuve" || modele.state === "consomme";
    const cle = aCle(`issue.${modele.state}`) ? `issue.${modele.state}` : "issue.inconnu";
    return message(approuve ? "succes" : "info", el("p", { classe: "nt-bandeau-titre", texte: t(cle, { votes: texteVotes(decompte(modele)) }), attributs: { id: "issue" } }), ul);
  }
  return message("erreur", el("p", { classe: "nt-bandeau-titre", texte: t("raisons.titre") }), ul);
}

/**
 * Un bandeau par avertissement : un titre en langage courant, ce qu'il veut
 * dire et quoi faire, puis la phrase de l'avertissement et son code, à la
 * fin. Une phrase que CT-3 fixe mot pour mot reste telle quelle.
 */
const AVERTISSEMENTS_FIXES = Object.freeze(["separation_non_verifiable", "condense_utf8"]);

function rendreAvertissements(warnings, avertissementsControle) {
  const bandeaux = [];
  for (const w of warnings) {
    let txt = t(`avertissement.${w}`);
    if (w === "separation_incomplete") {
      const a = avertissementsControle.find((x) => x.code === "separation_incomplete");
      txt = t("avertissement.separation_incomplete", { adresses: a ? a.addresses.join(", ") : t("modele.vide") });
    }
    const fixee = AVERTISSEMENTS_FIXES.includes(w);
    bandeaux.push(
      message(
        "alerte",
        aCle(`avertissement_titre.${w}`) ? el("p", { classe: "nt-bandeau-titre", texte: t(`avertissement_titre.${w}`) }) : null,
        aCle(`avertissement_sens.${w}`) ? el("p", { texte: t(`avertissement_sens.${w}`) }) : null,
        el("p", { classe: fixee ? "phrase-fixee" : null, attributs: { "data-avertissement": w } }, fixee ? fixe(txt) : w === "separation_incomplete" ? donnee(txt) : el("span", { texte: txt })),
      ),
    );
  }
  return bandeaux;
}

function rendreLies(reponse) {
  // Sans demande lue, les demandes voisines n'ont pas de sens : rien n'est affiché.
  if (etat.lectureEchouee) return;
  const titre = el("h2", { classe: "titre-lies", texte: t("ticket.lies.titre") });
  const related = reponse !== null && typeof reponse === "object" ? reponse.related : undefined;
  // Sans demande voisine, une ligne suffit : ni carte, ni titre.
  if (!Array.isArray(related)) {
    remplacer(zones.lies, el("p", { classe: "nt-attenue nt-petit", texte: t("ticket.lies.non_communique"), attributs: { id: "lies-non-communiquees" } }));
    return;
  }
  if (related.length === 0) {
    remplacer(zones.lies, el("p", { classe: "nt-attenue nt-petit", texte: t("ticket.lies.aucun"), attributs: { id: "lies-aucune" } }));
    return;
  }
  const ul = el("ul", { classe: "liste-nue lies", attributs: { id: "lies" } });
  for (const r of related) {
    ajouter(
      ul,
      el(
        "li",
        { attributs: { "data-ticket": String(r.ticket) } },
        lienTicket(r.ticket),
        " ",
        t(`decision_scellee.${r.decision === "refuse" ? "refuse" : "expire"}`),
        " ",
        instant(String(r.decided_at)),
        " ",
        r.reason === null ? t("modele.votes.sans_motif") : donnee(t("modele.votes.motif", { motif: String(r.reason) })),
      ),
    );
  }
  remplacer(zones.lies, el("section", { classe: "nt-carte carte-serree" }, titre, ul));
}

// ---------------------------------------------------------------------------
// Décision (EX-9.5) : un clic puis une confirmation, pour chacune. Les deux
// boutons ont le même poids : aucun n'est le bouton principal. Le motif,
// facultatif, se saisit à la confirmation, sous son avertissement (EX-13.6).

function libelleDecision(d) {
  const vue = etat.vue;
  if (vue && vue.rule && vue.rule.contest_ms > 0) {
    if (d === "refuse") return t("decision.bouton.objection");
    const mien = etat.pas1 ? etat.pas1.approver : null;
    if (mien !== null && Array.isArray(vue.contest.objections) && vue.contest.objections.some((o) => o.approver === mien)) return t("decision.bouton.levee");
  }
  return t(`decision.bouton.${d}`);
}

/**
 * Après la confirmation de la décision, la page amène la personne au choix
 * du portefeuille (complément du 2026-11-18) : le bloc vient en haut de la
 * fenêtre et reçoit le focus. Aucun portefeuille n'est choisi pour elle
 * (EX-13.22) : la liste reste telle qu'elle était.
 */
/**
 * Le résultat d'une signature ou d'un envoi (panne, refus, décision
 * enregistrée) s'affiche en tête du bloc de signature, et la page y amène la
 * personne : elle ne le cherche pas au bas de la page.
 */
function montrerResultat(...noeuds) {
  remplacer(zones.resultat, ...noeuds);
  amenerAuResultat();
}

function amenerAuResultat() {
  if (zones.resultat.firstChild === null) return;
  amenerSousLaBarre(zones.resultat, "center");
  zones.resultat.focus({ preventScroll: true });
}

function amenerAuPortefeuille() {
  if (zones.vote.firstChild === null) return;
  amenerSousLaBarre(zones.vote);
  zones.vote.focus({ preventScroll: true });
}

function rendreDecision() {
  const raisons = etat.pas1 ? etat.pas1.raisons : [];
  if (raisons.includes("ticket_clos_aux_votes")) {
    // Demande décidée ou close : plus aucune décision à prendre, plus de bouton.
    vider(zones.decision);
    return;
  }
  // Un nouveau vote remplace le précédent tant que la demande accepte des décisions (EX-7.26) : les deux
  // boutons restent offerts, de même poids, sous un intitulé et une phrase qui disent ce que cela fait.
  const deja = maDecisionEnregistree() !== null;
  const titreDecision = t(deja ? "decision.titre_changer" : "decision.titre");
  const ouvert = etat.pas1 && raisons.length === 0;
  if (etat.decision !== null) {
    const m = motif();
    remplacer(
      zones.decision,
      el("h2", { classe: "titre-decision", texte: titreDecision }),
      el("p", { classe: "decision-choisie", texte: t(`decision.choisie.${etat.decision}`), attributs: { id: "decision-choisie", "data-decision": etat.decision } }),
      el("p", { classe: "nt-attenue", attributs: { id: "motif-choisi" } }, m === null ? t("motif.aucun") : donnee(t("modele.votes.motif", { motif: m }))),
      el("p", { texte: t("decision.suite") }),
      actions(
        // Le portefeuille déjà choisi, le lien mène à l'écran de signature ; sinon au choix du portefeuille.
        el("a", { classe: "nt-bouton nt-bouton-principal", texte: t("decision.aller_signature"), attributs: { href: etat.fournisseur !== null && etat.adresse !== null ? "#zone-signature" : "#vote" } }),
        bouton(
          t("decision.changer"),
          () => {
            etat.decision = null;
            etat.aConfirmer = null;
            champMotif.disabled = false;
            abandonner();
            rendreModele();
            rendreDecision();
          },
          { genre: "discret" },
        ),
      ),
    );
  } else if (etat.aConfirmer !== null) {
    const d = etat.aConfirmer;
    remplacer(
      zones.decision,
      el("h2", { classe: "titre-decision", texte: titreDecision }),
      el("p", { classe: "decision-question", texte: t(`decision.confirmer_question.${d}`) }),
      zones.motif,
      actions(
        bouton(
          t(`decision.confirmer.${d}`),
          () => {
            etat.decision = d;
            etat.aConfirmer = null;
            champMotif.disabled = true;
            abandonner();
            rendreModele();
            rendreDecision();
            amenerAuPortefeuille();
            void lecturePas3();
          },
          { genre: "principal" },
        ),
        bouton(t("action.annuler"), () => {
          etat.aConfirmer = null;
          rendreDecision();
        }),
      ),
    );
  } else if (deja) {
    // La personne a déjà décidé et la demande reste ouverte (CT-3 EX-9.4, complément du 2026-11-18, point 8) : elle
    // n'est pas en train de décider. Les deux décisions restent offertes, de même poids, dans un bloc fermé à
    // l'ouverture de l'écran, « Changer ma décision », avec ce que cela fait.
    const bloc = detail(titreDecision, null, el("p", { classe: "nt-attenue", texte: t("decision.changer_sens"), attributs: { id: "decision-changer" } }), boutonsDecision(ouvert, titreDecision), ouvert ? null : el("p", { classe: "nt-attenue nt-petit", texte: t("decision.inactifs") }));
    bloc.setAttribute("id", "changer-decision");
    bloc.open = etat.changerOuvert;
    bloc.addEventListener("toggle", () => {
      etat.changerOuvert = bloc.open;
    });
    remplacer(zones.decision, bloc);
  } else {
    // « Votre décision », puis les deux boutons, sur une ligne quand la place le permet.
    remplacer(
      zones.decision,
      el("div", { classe: "decision-tete" }, el("h2", { classe: "titre-decision", texte: titreDecision }), boutonsDecision(ouvert, titreDecision)),
      // Ce n'est pas une panne : sans code.
      ouvert ? el("p", { classe: "nt-attenue nt-petit", attributs: { id: "decision-suite", "data-code": "decision_absente" } }, el("span", { texte: t("console.decision_absente") }), " ", el("span", { texte: t("decision.etapes") })) : el("p", { classe: "nt-attenue nt-petit", texte: t("decision.inactifs") }),
    );
  }
  majParcours();
  sensContestation();
}

/** Les deux boutons de décision (EX-9.5) : même poids, aucun présélectionné ; chacun demande une confirmation. */
function boutonsDecision(ouvert, libelleGroupe) {
  const groupe = el("div", { classe: "nt-actions boutons-decision", attributs: { role: "group", "aria-label": libelleGroupe } });
  for (const d of ["approuve", "refuse"]) {
    const b = bouton(
      libelleDecision(d),
      () => {
        etat.aConfirmer = d;
        rendreDecision();
      },
      { actif: ouvert, genre: "choix", icone: d === "approuve" ? "coche" : "croix" },
    );
    b.setAttribute("data-decision", d);
    groupe.appendChild(b);
  }
  return groupe;
}

function rendreMotif() {
  remplacer(
    zones.motif,
    el("label", { classe: "nt-libelle", texte: t("motif.libelle"), attributs: { for: "motif" } }),
    champMotif,
    note("alerte", el("p", { texte: t("motif.avertissement"), attributs: { id: "motif-avertissement" } })),
  );
}

function motif() {
  const v = champMotif.value;
  return v === "" ? null : v;
}

// ---------------------------------------------------------------------------
// Fournisseur et adresse (EX-13.22, EX-13.23)

function rendreFournisseursEtComptes() {
  // Sans demande lue, ou sur un ticket qui n'accepte plus de votes, il n'y a rien à signer : la section n'est pas offerte.
  if (etat.pas1 === null || etat.pas1.raisons.includes("ticket_clos_aux_votes")) {
    vider(zones.vote);
    return;
  }
  if (zones.fournisseurs.parentNode !== zones.vote) {
    remplacer(zones.vote, el("h2", { texte: t("vote.titre"), attributs: { id: "vote-titre" } }), el("p", { classe: "nt-attenue", texte: t("vote.sens") }), zones.fournisseurs, zones.comptes);
    zones.vote.setAttribute("aria-labelledby", "vote-titre");
  }
  rendreFournisseurs(zones.fournisseurs, decouverte, etat.fournisseur, choisirFournisseur, etat.vue !== null, false);
  rendreComptes();
  majParcours();
}

decouverte.surChangement(() => {
  // Un fournisseur choisi puis écarté (uuid revendiqué par un autre objet) est abandonné.
  if (etat.fournisseur !== null && !decouverte.fournisseurs.some((f) => f.provider === etat.fournisseur.provider)) {
    oublierFournisseur();
  }
  if (etat.session !== null) rendreFournisseursEtComptes();
});

function oublierFournisseur() {
  for (const f of etat.detacher) f();
  etat.detacher = [];
  etat.fournisseur = null;
  etat.comptes = null;
  etat.adresse = null;
  abandonner();
}

let messageComptes = null;

async function choisirFournisseur(f) {
  oublierFournisseur();
  etat.fournisseur = f;
  messageComptes = null;
  const provider = f.provider;
  etat.detacher.push(
    ecouter(provider, "accountsChanged", (comptes) => {
      if (etat.fournisseur === null || etat.fournisseur.provider !== provider) return;
      surComptes(analyserComptes(comptes) ?? []);
    }),
    ecouter(provider, "disconnect", () => {
      if (etat.fournisseur === null || etat.fournisseur.provider !== provider) return;
      oublierFournisseur();
      messageComptes = { code: "deconnecte", erreur: null };
      rendreFournisseursEtComptes();
    }),
  );
  rendreFournisseursEtComptes();
  await obtenirComptes();
}

async function obtenirComptes() {
  const f = etat.fournisseur;
  if (f === null) return;
  messageComptes = null;
  rendreComptes(true);
  const r = await demanderComptes(f.provider);
  if (etat.fournisseur !== f) return;
  if (r.comptes === undefined) {
    messageComptes = r;
    rendreComptes();
    return;
  }
  surComptes(r.comptes);
}

function surComptes(comptes) {
  etat.comptes = comptes;
  if (etat.adresse !== null && !comptes.includes(etat.adresse)) {
    // EX-13.23 : l'adresse choisie n'est plus exposée ; tout est abandonné.
    etat.adresse = null;
    abandonner();
    messageComptes = { code: "adresse_retiree", erreur: null };
  }
  retenirAdresse();
  rendreComptes();
}

/** Retient l'adresse active dès qu'elle est exposée (EX-13.23). */
function retenirAdresse() {
  if (etat.adresse !== null || etat.comptes === null || etat.annuaire === null) return;
  const active = adresseAttribuee(etat.annuaire);
  if (active !== null && etat.comptes.includes(active)) {
    etat.adresse = active;
    messageComptes = null;
    void lecturePas3();
  }
}

function rendreComptes(attente = false) {
  const parties = [];
  if (etat.fournisseur !== null) {
    parties.push(el("p", {}, donnee(t("portefeuille.courant", { nom: etat.fournisseur.name }))));
    if (attente) parties.push(el("p", { classe: "nt-attenue", texte: t("portefeuille.comptes_demandes") }));
  }
  if (etat.adresse !== null) {
    parties.push(el("p", { attributs: { id: "adresse-retenue" } }, t("adresse.retenue"), " ", code(etat.adresse)));
  } else if (etat.comptes !== null && etat.annuaire !== null) {
    const active = adresseAttribuee(etat.annuaire);
    if (active !== null) {
      parties.push(message("alerte", paragrapheCode("adresse_non_exposee", PREFIXES_VOTE), el("p", {}, t("adresse.active"), " ", code(active))));
    }
  }
  if (messageComptes !== null) {
    if (messageComptes.code === "adresse_retiree") {
      parties.push(message("alerte", el("p", { texte: t("adresse.retiree"), attributs: { "data-code": "adresse_retiree" } })));
    } else {
      const prefixes = ["comptes.", ...PREFIXES_VOTE];
      parties.push(
        message("erreur", el("p", { attributs: { "data-code": messageComptes.code } }, ...noeudsPanne(messageComptes.code, messageComptes.erreur, prefixes))),
        etat.fournisseur !== null ? actions(bouton(t("portefeuille.redemander"), () => void obtenirComptes())) : null,
      );
    }
  }
  remplacer(zones.comptes, ...parties);
}

// ---------------------------------------------------------------------------
// Pas 3 : lecture fraîche, contrôles d'EX-9.15 et d'EX-13.18

async function lecturePas3() {
  if (etat.decision === null || etat.fournisseur === null || etat.adresse === null) return;
  etat.generation += 1;
  const g = etat.generation;
  etat.lecture = null;
  remplacer(zones.signature, el("p", { classe: "nt-attenue", texte: t("signature.verification") }));
  let lu;
  try {
    lu = await lireVueEtAnnuaire();
  } catch (e) {
    if (g !== etat.generation) return;
    afficherErreur(zones.signature, e);
    return;
  }
  if (g !== etat.generation) return;
  let modele;
  let controle;
  let calcul;
  try {
    const session = sessionDuModele(lu.annuaire, identite(), lu.vue);
    modele = modeleAffichage(lu.vue, { session, decision: etat.decision, approver: etat.adresse, reason: motif(), now: maintenant() });
    controle = controleVote(lu.annuaire, identite(), "voter", etat.adresse, ticketDeControleVote(lu.vue));
    calcul = modelePas1(lu.vue, lu.annuaire);
  } catch {
    afficherErreur(zones.signature, new ErreurAppel("reponse_service_invalide"));
    return;
  }
  // Revue CT-3 EX-9.15 : la page signe exactement ce qu'elle affiche. Le modèle
  // affiché devient celui de la vue fraîche (jeu, votes, échéance,
  // avertissements, dont `membres_ajoutes`), et si la demande elle-même a
  // changé depuis l'affichage (un membre de MEMBRES_LIES), aucun écran de
  // signature : la décision est annulée, `demande_modifiee` est affichée avec
  // la consigne de prévenir l'administrateur, et le choix est à refaire sur la
  // vue fraîche, suivie d'une nouvelle lecture.
  const modifiee = !memeDemande(etat.vue, lu.vue);
  etat.vue = lu.vue;
  etat.annuaire = lu.annuaire;
  etat.pas1 = calcul;
  rendreModele();
  rendreRecusation();
  rendreRetrait();
  if (modifiee) {
    etat.decision = null;
    etat.aConfirmer = null;
    champMotif.disabled = false;
    etat.lecture = null;
    rendreDecision();
    remplacer(
      zones.signature,
      message("erreur", paragrapheCode("demande_modifiee", ["page."]), el("p", { texte: t("signature.demande_modifiee_prevenir") })),
    );
    rendreConsignes();
    return;
  }
  etat.lecture = { vue: lu.vue, annuaire: lu.annuaire, modele, controle };
  rendreSignature();
}

// ---------------------------------------------------------------------------
// Écran de signature (EX-9.18 à EX-9.20, EX-13.21)

function groupesFixes(x) {
  const p = el("p", { classe: "groupes", attributs: { "data-valeur": "" } });
  const g = groupes(x).split(" ");
  g.forEach((morceau, k) => {
    if (k > 0) p.appendChild(el("span", { texte: " " }));
    p.appendChild(el("span", { classe: "groupe", texte: morceau }));
  });
  return p;
}

/**
 * Le rappel de la demande, en tête de l'écran de signature : la phrase
 * vérifiée, le montant s'il est vérifié, et chaque valeur que la console n'a
 * pas pu vérifier, avec sa marque.
 */
function rendreRappel(modele) {
  const r = resumeVerifie(modele);
  const g = groupesValeurs(modele);
  const phrase = el("p", { classe: "rappel-phrase", attributs: { id: "rappel-phrase" } });
  if (r.outil === null) {
    ajouter(phrase, t("essentiel.non_liee"));
  } else {
    ajouter(phrase, t("essentiel.outil"), " ", code(r.outil), r.montant === null ? t("essentiel.point") : t("essentiel.montant"));
    if (r.montant !== null) ajouter(phrase, " ", el("strong", { classe: "rappel-montant", texte: `${r.montant.texte}\u00a0${r.montant.devise}`, attributs: { id: "rappel-montant", "data-valeur": "" } }), t("essentiel.point"));
  }
  return el(
    "div",
    { classe: "rappel", attributs: { id: "signature-rappel" } },
    el("p", { classe: "nt-sur-titre", texte: t("signature.rappel") }),
    phrase,
    g.aControler.length === 0
      ? null
      : el(
          "div",
          { classe: "groupe-valeurs groupe-controle", attributs: { id: "rappel-a-controler", role: "note" } },
          el("h4", { classe: "groupe-valeurs-titre" }, icone("alerte"), el("span", { texte: t("controle.titre") })),
          el("ul", { classe: "liste-nue liste-valeurs valeurs-denses" }, ...g.aControler.map(ligneValeur)),
        ),
  );
}

function rendreSignature() {
  const l = etat.lecture;
  if (l === null) {
    vider(zones.signature);
    rendreConsignes();
    return;
  }
  const raisons = [...l.modele.blocking];
  if (l.controle.reason !== null && !raisons.includes(l.controle.reason)) raisons.push(l.controle.reason);
  if (raisons.length > 0) {
    // 13.14 : aucune requête de signature ; chaque raison affichée.
    remplacer(zones.signature, rendreRaisons(raisons, l.modele, l.vue));
    rendreConsignes();
    return;
  }
  const d = l.modele.digests[etat.decision];
  // En tête : ce que la personne s'apprête à faire ; puis le rappel de la demande et, à côté, les consignes courantes
  // (CT-3 EX-9.20, complément du 2026-11-18) ; puis les deux codes, en grand, début et fin : le code de contrôle de la
  // décision, `empreinte(D_A)`, avec `D_A` en entier juste dessous (EX-9.4), et l'autre forme de ce code,
  // `empreinte(H)`, que certaines applications affichent en plus (EX-9.18, complément du 2026-11-18) ; puis le bouton.
  // Ensuite, dans un bloc ouvert sur demande : les noms exacts des deux codes, sous les intitulés que fixe EX-9.18,
  // leurs groupes, et les consignes d'EX-9.20, entières.
  const completes = detail(
    t("consigne.completes"),
    t("consigne.completes_note"),
    el("div", { classe: "nt-encart nt-pile" }, fixe(t("signature.empreinte_d_a"), "intitule", "h3"), el("p", { classe: "nt-petit", texte: t("signature.d_a_sens") }), groupesFixes(d.d_a)),
    el("div", { classe: "nt-encart nt-pile" }, fixe(t("signature.eip191"), "intitule", "h3"), el("p", { classe: "nt-petit", texte: t("signature.eip191_sens") }), groupesFixes(d.h)),
    rendreConsignesElement(),
  );
  completes.setAttribute("id", "consignes-completes");
  completes.open = etat.completesOuvert;
  completes.addEventListener("toggle", () => {
    etat.completesOuvert = completes.open;
  });
  const panneau = el(
    "section",
    { classe: "nt-carte signature", attributs: { id: "ecran-signature", "data-decision": etat.decision, tabindex: "-1", "aria-labelledby": "signature-titre" } },
    // Le titre, et sur la même ligne quand la place le permet, ce que la personne s'apprête à faire.
    el(
      "div",
      { classe: "nt-carte-titre signature-titre" },
      el("h2", { texte: t("signature.titre"), attributs: { id: "signature-titre" } }),
      el("p", { classe: "signature-vous", texte: t(`signature.vous.${etat.decision}`), attributs: { id: "signature-vous", "data-decision": etat.decision } }),
      etat.enCours ? pastille("info", t("signature.pastille_demandee"), "horloge") : null,
    ),
    el(
      "div",
      { classe: "signature-haut" },
      el("div", { classe: "nt-pile signature-gauche" }, rendreRappel(l.modele)),
      // Les consignes courantes, à côté du rappel et au-dessus des codes et du bouton : on les lit avant de signer.
      el("div", { classe: "nt-pile avant-de-signer" }, el("h3", { classe: "intitule-clair", texte: t("signature.avant_titre"), attributs: { id: "avant-de-signer" } }), rendreConsignesCourantes()),
    ),
    // La décision telle qu'elle est signée (`approuve` ou `refuse`, EX-9.4), l'adresse retenue et le portefeuille
    // choisi : sur une rangée, sur un poste.
    lignes(
      [
        [t("signature.decision_signee"), code(etat.decision)],
        [t("signature.adresse"), code(etat.adresse)],
        [t("signature.portefeuille"), donnee(etat.fournisseur.name)],
      ],
      { id: "signature-faits" },
      "faits-signature",
    ),
    // Les deux codes, en grand, début et fin (EX-9.18, complément du 2026-11-18).
    el(
      "div",
      { classe: "codes-signature", attributs: { id: "codes-signature" } },
      el(
        "div",
        { classe: "nt-encart encart-empreinte", attributs: { id: "code-controle" } },
        el("h3", { classe: "intitule-clair", texte: t("signature.code_controle") }),
        el("p", { classe: "nt-empreinte", texte: d.fingerprint, attributs: { id: "empreinte-d-a", "data-valeur": "" } }),
        el("p", { classe: "nt-petit code-entier" }, el("span", { texte: t("signature.code_entier") }), " ", code(d.d_a, "nt-fixe d-a")),
      ),
      el(
        "div",
        { classe: "nt-encart encart-empreinte", attributs: { id: "code-autre" } },
        el("h3", { classe: "intitule-clair", texte: t("signature.code_autre") }),
        el("p", { classe: "nt-empreinte", texte: d.h_fingerprint, attributs: { id: "empreinte-h", "data-valeur": "" } }),
        el("p", { classe: "nt-petit code-autre-sens", texte: t("signature.code_autre_sens") }),
      ),
    ),
    l.modele.warnings.includes("condense_utf8") ? rendreAvertissements(["condense_utf8"], []) : null,
    actions(bouton(t("signature.demander"), () => void demanderSignature(), { actif: !etat.enCours, genre: "principal", icone: "cadenas" }), el("a", { classe: "nt-bouton nt-bouton-discret", texte: t("signature.revenir"), attributs: { href: "#essentiel" } })),
    etat.enCours ? message("info", el("p", { texte: t("signature.en_cours") })) : null,
    completes,
  );
  // Quand l'écran de signature paraît (le portefeuille vient d'être choisi), la page y amène la personne : elle
  // lit les consignes et l'empreinte avant le bouton, sans avoir à chercher plus bas. Un réaffichage ne déplace rien.
  const paraissait = zones.signature.querySelector("#ecran-signature") !== null;
  remplacer(zones.signature, panneau);
  vider(zones.consignes);
  if (!paraissait) {
    amenerSousLaBarre(panneau);
    panneau.focus({ preventScroll: true });
  }
}

/**
 * Les consignes courantes (CT-3 EX-9.20, complément du 2026-11-18) : quatre
 * lignes, fixées mot pour mot par ce complément, affichées avant le bouton
 * de signature, sans sigle ni mot anglais. Les noms exacts des codes sont
 * dans le bloc « Consignes complètes ».
 */
function rendreConsignesCourantes() {
  const ol = el("ol", { classe: "consignes consignes-courantes", attributs: { id: "consignes-courantes", "aria-labelledby": "avant-de-signer" } });
  for (let k = 1; k <= 4; k += 1) ol.appendChild(el("li", { texte: t(`consigne_courante.${k}`), attributs: { "data-consigne": String(k) } }));
  return ol;
}

// Règle de 3.5 : vrai s'il faut réauthentifier avant `personal_sign`.
function reauthentificationAvant(session, m, w) {
  const a = decoderInstant(session.auth_time);
  const fin = decoderInstant(m) + w + 30000;
  if (session.reauth_max_age_s > 0) return fin >= a + session.reauth_max_age_s * 1000;
  return envoiDepuis(session.auth_time) || fin >= a + 600000;
}

async function demanderSignature() {
  const l = etat.lecture;
  if (l === null || etat.enCours || !l.modele.signable || l.controle.reason !== null) return;
  const g = etat.generation;
  const decision = etat.decision;
  const adresse = etat.adresse;
  const provider = etat.fournisseur.provider;
  const vueSignee = l.vue;
  const d = l.modele.digests[decision];
  const motifSigne = motif();
  etat.enCours = true;
  vider(zones.resultat);
  rendreSignature();

  // 3.5 : la session est relue avant la demande de signature.
  const s = await lireSession();
  if (g !== etat.generation) return;
  if (s.etat !== "session") {
    etat.enCours = false;
    rendreSignature();
    if (s.etat === "erreur") afficherErreur(zones.resultat, s.erreur);
    else if (s.etat === "identite_invalide") remplacer(zones.resultat, message("erreur", paragrapheCode("identite_invalide", ["raison."])));
    amenerAuResultat();
    return;
  }
  if (s.session.session_identity !== identite()) {
    window.location.reload();
    return;
  }
  etat.session = s.session;
  const m = maintenant();
  const attente = echeanceAttente(s.session.delai_signature_ms, vueSignee.deadline, m);
  if (attente <= 0) {
    etat.enCours = false;
    abandonnerApres();
    afficherPanne("delai_depasse", null);
    return;
  }
  if (reauthentificationAvant(s.session, m, attente)) {
    etat.enCours = false;
    abandonner();
    allerConnexion();
    return;
  }

  // Pas 4 à 6 : une seule requête, attente bornée.
  const requete = requetePersonalSign(d.d_a, adresse);
  const reponse = await new Promise((resolve) => {
    etat.minuteur = setTimeout(() => resolve({ delai: true }), attente);
    appelFournisseur(provider, requete).then(resolve);
  });
  if (g !== etat.generation) return;
  clearTimeout(etat.minuteur);
  etat.minuteur = null;
  if (reponse.delai) {
    // EX-13.30 : la console cesse d'attendre et ignore toute réponse tardive
    // (l'abandon change la génération).
    etat.enCours = false;
    abandonnerApres();
    afficherPanne("delai_depasse", null);
    return;
  }
  const verdict = verifierReponse(reponse, depuisHex(d.d_a), adresse);
  if (verdict.outcome !== "accepte") {
    // Aucun vote ; la décision est à choisir de nouveau (les deux boutons sont offerts).
    etat.enCours = false;
    abandonnerApres();
    afficherPanne(verdict.reason, reponse.error ?? null, verdict.recovered);
    if (verdict.reason === "non_autorise") {
      // 13.14 : 4100 sur personal_sign, eth_requestAccounts redemandé une fois.
      const f = etat.fournisseur;
      const g2 = etat.generation;
      const r = await demanderComptes(provider);
      if (g2 === etat.generation && etat.fournisseur === f && r.comptes !== undefined) surComptes(r.comptes);
    }
    return;
  }

  // Pas 7 : nouvelles lectures ; contrôles d'EX-13.18 si state ou revision ont changé.
  let lu;
  try {
    lu = await lireVueEtAnnuaire();
  } catch (e) {
    if (g !== etat.generation) return;
    etat.enCours = false;
    abandonnerApres();
    afficherErreur(zones.resultat, e);
    amenerAuResultat();
    return;
  }
  if (g !== etat.generation) return;
  if (lu.vue.state !== l.vue.state || lu.annuaire.revision !== l.annuaire.revision) {
    let c;
    try {
      c = controleVote(lu.annuaire, identite(), "voter", adresse, ticketDeControleVote(lu.vue));
    } catch {
      c = { reason: "reponse_service_invalide" };
    }
    if (c.reason !== null) {
      etat.enCours = false;
      abandonnerApres();
      montrerResultat(message("erreur", paragrapheCode(c.reason, PREFIXES_VOTE), el("p", { texte: t("vote.non_envoye") })));
      return;
    }
  }

  // Pas 8 : le vote, construit une seule fois sur la vue du ticket signé.
  const corps = requeteVoter(vueSignee, decision, verdict.signature, adresse, motifSigne, identite());
  await envoyerVote(corps, g, d.fingerprint);
}

// Après une signature : l'écran de signature est retiré, la décision aussi.
function abandonnerApres() {
  etat.decision = null;
  etat.aConfirmer = null;
  champMotif.disabled = false;
  abandonner();
  if (etat.pas1) {
    rendreModele();
    rendreDecision();
  }
}

async function envoyerVote(corps, g, empreinteSignee) {
  let essais = 0;
  for (;;) {
    try {
      const r = await appeler("voter", corps);
      if (g !== etat.generation) return;
      etat.enCours = false;
      abandonnerApres();
      const v = r.valeur;
      // Ce qui suit la décision dépend de l'état que le service rend : d'autres approbations attendues, délai de contestation, décision prise.
      const etatRendu = v && typeof v.state === "string" ? v.state : null;
      // Puis ce qu'EX-9.20, point 7, demande de vérifier après la décision : la notification indépendante, si l'organisation en envoie une.
      const notification = el("p", { classe: "nt-petit", attributs: { id: "apres-decision" } }, el("span", { texte: t("vote.notification") }), " ", code(empreinteSignee), el("span", { texte: t("vote.notification_sinon") }));
      montrerResultat(message("succes", el("p", { classe: "nt-bandeau-titre", attributs: { "data-resultat": "vote_inscrit", "data-etat": etatRendu ?? "" } }, el("span", { texte: t("vote.inscrit") }), etatRendu !== null && aCle(`vote.suite.${etatRendu}`) ? el("span", { texte: ` ${t(`vote.suite.${etatRendu}`)}` }) : null), notification));
      await lecturePas1();
      amenerAuResultat();
      return;
    } catch (e) {
      if (g !== etat.generation) return;
      if (e instanceof ErreurAppel && e.sansReponse && essais === 0) {
        // EX-9.21 point 8, 13.14 : sans réponse, le même vote est renvoyé.
        essais += 1;
        continue;
      }
      etat.enCours = false;
      abandonnerApres();
      if (e instanceof ErreurAppel && e.code === "vote_identique") {
        montrerResultat(
          message("info", el("p", { classe: "nt-bandeau-titre", texte: t("vote.deja_sens") }), el("p", { classe: "phrase-fixee", attributs: { "data-resultat": "vote_identique" } }, fixe(t(essais > 0 ? "vote.deja_inscrit" : "vote.deja_inscrit_motif")), el("span", { classe: "code-brut", texte: " (vote_identique)" }))),
        );
        await lecturePas1();
        amenerAuResultat();
        return;
      }
      if (e instanceof ErreurAppel && e.sansReponse) {
        // Toujours sans réponse : le même vote peut être renvoyé, sur action.
        const z = el("div");
        remplacer(zones.resultat, z);
        afficherErreur(
          z,
          e,
          actions(
            bouton(t("vote.renvoyer"), () => {
              const g2 = etat.generation;
              void envoyerVote(corps, g2, empreinteSignee);
            }),
          ),
        );
        amenerAuResultat();
        return;
      }
      if (erreurDeSession(e)) return;
      montrerResultat(message("erreur", paragrapheCode(e instanceof ErreurAppel ? e.code : "erreur_page", PREFIXES_ERREUR), el("p", { texte: t("vote.non_inscrit") })));
      return;
    }
  }
}

function afficherPanne(codePanne, erreur, recouvree = null) {
  const sens = sensCode(codePanne, PREFIXES_VOTE);
  const parties = [sens, el("p", { classe: sens === null ? null : "phrase-fixee", attributs: { "data-code": codePanne } }, ...noeudsPanne(codePanne, erreur, PREFIXES_VOTE))];
  if (codePanne === "adresse_differente" && typeof recouvree === "string") parties.push(el("p", {}, t("signature.adresse_recouvree"), " ", code(recouvree)));
  if (codePanne === "refus_approbateur") parties.push(el("p", { texte: t("signature.refus_sens") }));
  // La décision se choisit de nouveau en haut de la page : le lien y ramène.
  parties.push(actions(el("a", { classe: "nt-bouton nt-bouton-discret", texte: t("signature.revenir"), attributs: { href: "#essentiel" } })));
  montrerResultat(message("erreur", ...parties));
}

// ---------------------------------------------------------------------------
// Consignes d'EX-9.20

function origineSaine() {
  const a = etat.annuaire;
  return a !== null && typeof a.console_origin === "string" ? a.console_origin : t("modele.vide");
}

function rendreConsignesElement() {
  const ol = el("ol", { classe: "consignes", attributs: { id: "consignes" } });
  // Chaque consigne : un titre court, puis son texte, que CT-3 EX-9.20 fixe, en entier.
  for (let k = 1; k <= 7; k += 1) ajouter(ol, el("li", {}, el("strong", { classe: "consigne-titre", texte: t(`consigne_titre.${k}`) }), " ", fixe(t(`consigne.${k}`, { origine: origineSaine() }), "consigne-texte")));
  return el("div", { classe: "bloc-consignes nt-pile" }, el("h3", { texte: t("consigne.titre_reference") }), ol);
}

// Avant le choix de la décision, les consignes d'EX-9.20 sont offertes dans un
// bloc replié ; l'écran de signature affiche les consignes courantes avant son
// bouton et garde le texte d'EX-9.20, entier, dans son bloc « Consignes
// complètes » (complément du 2026-11-18 d'EX-9.20).
function rendreConsignes() {
  if (etat.vue === null || etat.pas1 === null || etat.pas1.raisons.includes("ticket_clos_aux_votes")) return vider(zones.consignes);
  if (zones.signature.querySelector("#consignes") !== null) return vider(zones.consignes);
  const bloc = detail(t("consigne.titre"), null, rendreConsignesElement().lastChild);
  bloc.setAttribute("id", "consignes-repliees");
  return remplacer(zones.consignes, bloc);
}

// ---------------------------------------------------------------------------
// Récusation (EX-10.4, EX-13.5, EX-13.18)

function rendreRecusation() {
  if (etat.pas1 === null) return vider(zones.recusation);
  const approver = etat.pas1.approver;
  let c;
  try {
    c = controleVote(etat.annuaire, identite(), "recuser", approver ?? "", ticketDeControleVote(etat.vue));
  } catch {
    c = { reason: "reponse_service_invalide" };
  }
  // Un ticket décidé n'offre plus aucune action.
  if (c.reason === "ticket_clos_aux_votes" || estDecide(etat.vue)) return vider(zones.recusation);
  const parties = [el("h4", { classe: "action-carte-titre", texte: t("recusation.titre") }), el("p", { classe: "nt-attenue", texte: t("recusation.sens") })];
  if (etat.confirmation === "recuser") {
    parties.push(
      message("alerte", el("p", { texte: t("recusation.confirmer_texte") })),
      actions(
        bouton(t("recusation.confirmer"), () => void recuser(), { genre: "danger" }),
        bouton(t("action.annuler"), () => {
          etat.confirmation = null;
          rendreRecusation();
        }),
      ),
    );
  } else {
    parties.push(
      actions(
        bouton(
          t("recusation.bouton"),
          () => {
            etat.confirmation = "recuser";
            rendreRecusation();
          },
          { actif: c.reason === null, petit: true },
        ),
      ),
    );
    if (c.reason !== null) parties.push(el("p", { classe: "nt-attenue nt-petit", attributs: { "data-code": c.reason } }, ...phraseCode(c.reason, PREFIXES_VOTE)));
  }
  const zoneR = el("div", { attributs: { id: "resultat-recusation" } });
  parties.push(zoneR);
  remplacer(zones.recusation, ...parties);
}

async function recuser() {
  etat.confirmation = null;
  const zone = el("div");
  let lu;
  try {
    lu = await lireVueEtAnnuaire();
  } catch (e) {
    rendreRecusation();
    zones.recusation.appendChild(zone);
    afficherErreur(zone, e);
    return;
  }
  const adresse = adresseAttribuee(lu.annuaire);
  const c = controleVote(lu.annuaire, identite(), "recuser", adresse ?? "", ticketDeControleVote(lu.vue));
  rendreRecusation();
  zones.recusation.appendChild(zone);
  if (c.reason !== null) {
    remplacer(zone, message("erreur", paragrapheCode(c.reason, PREFIXES_VOTE)));
    return;
  }
  try {
    const r = await appeler("recuser", { ticket: etat.ticket, approver: adresse, session_identity: identite() });
    remplacer(zone, message("succes", el("p", { texte: t("recusation.inscrite", { etat: t(`etat.${r.valeur.state}`) }), attributs: { "data-resultat": "recusation_inscrite" } })));
    await lecturePas1();
    zones.recusation.appendChild(zone);
  } catch (e) {
    afficherErreur(zone, e);
  }
}

// ---------------------------------------------------------------------------
// Retrait (EX-7.15, EX-12.19, EX-13.18) : offert seulement si `actionRetrait` rend un `by`.

const champMotifRetrait = el("textarea", { classe: "nt-saisie", attributs: { id: "motif-retrait", rows: "2", maxlength: "4096" } });

function rendreRetrait() {
  // EX-7.15 : un retrait clôt un ticket non décidé ; un ticket décidé ne l'offre plus.
  if (etat.annuaire === null || etat.vue === null || estDecide(etat.vue)) return vider(zones.retrait);
  const by = actionRetrait(etat.annuaire, identite(), { launched_by: etat.vue.request.delegation.launched_by });
  if (by === null) return vider(zones.retrait);
  const parties = [el("h4", { classe: "action-carte-titre", texte: t("retrait.titre") }), el("p", { classe: "nt-attenue", texte: t("retrait.sens") }), el("p", {}, t("retrait.par"), " ", code(by))];
  parties.push(el("div", { classe: "nt-champ" }, el("label", { classe: "nt-libelle", texte: t("retrait.motif"), attributs: { for: "motif-retrait" } }), champMotifRetrait, el("p", { classe: "nt-aide", texte: t("motif.avertissement") })));
  if (etat.confirmation === "retirer") {
    parties.push(
      message("alerte", el("p", { texte: t("retrait.confirmer_texte") })),
      actions(
        bouton(t("retrait.confirmer"), () => void retirer(by), { genre: "danger" }),
        bouton(t("action.annuler"), () => {
          etat.confirmation = null;
          rendreRetrait();
        }),
      ),
    );
  } else {
    parties.push(
      actions(
        bouton(t("retrait.bouton"), () => {
          if (champMotifRetrait.value === "") {
            remplacer(zoneRetrait, message("erreur", el("p", { texte: t("retrait.motif_requis") })));
            return;
          }
          etat.confirmation = "retirer";
          rendreRetrait();
        }),
      ),
    );
  }
  parties.push(zoneRetrait);
  return remplacer(zones.retrait, ...parties);
}

const zoneRetrait = el("div", { attributs: { id: "resultat-retrait" } });

async function retirer(by) {
  etat.confirmation = null;
  const reason = champMotifRetrait.value === "" ? null : champMotifRetrait.value;
  rendreRetrait();
  try {
    const r = await appeler("retirer", { ticket: etat.ticket, by, reason, session_identity: identite() });
    remplacer(zoneRetrait, message("succes", el("p", { texte: t("retrait.inscrit", { etat: t(`etat.${r.valeur.state}`) }), attributs: { "data-resultat": "retrait_inscrit" } })));
    await lecturePas1();
    // Le ticket relu peut être décidé, et n'offre alors plus le retrait : son résultat reste affiché.
    if (!zones.retrait.contains(zoneRetrait)) zones.retrait.appendChild(zoneRetrait);
  } catch (e) {
    afficherErreur(zoneRetrait, e);
  }
}

// ---------------------------------------------------------------------------
// Démarrage

async function demarrer() {
  const segment = window.location.pathname.slice("/tickets/".length);
  const s = await demarrerEcran("ticket");
  if (s === null) return;
  etat.session = s;
  const racine = principal();
  if (!window.location.pathname.startsWith("/tickets/") || !estIdentifiantTicket(segment)) {
    ajouter(racine, el("main", { classe: "nt-page" }, filTickets(), message("erreur", paragrapheCode("ticket_inconnu", ["raison."]))));
    return;
  }
  etat.ticket = segment;
  rendreMotif();
  // Sous la demande : le résultat de la dernière signature, en tête du bloc où elle se fait ; le choix du portefeuille
  // et, à côté, les consignes repliées ; puis l'écran de signature. La récusation et le retrait sont avec le reste de
  // la demande (`rendreModele`) : aucun de ces deux gestes définitifs ne se trouve entre le choix du portefeuille et
  // la signature.
  ajouter(racine, el("main", { classe: "nt-page page-ticket" }, zones.lecture, zones.modele, zones.lies, zones.resultat, el("div", { classe: "bas-demande" }, zones.vote, el("div", { classe: "autres-actions" }, zones.consignes)), zones.signature));
  rendreFournisseursEtComptes();
  await Promise.all([lecturePas1(), lectureLies()]);
}

void demarrer();
