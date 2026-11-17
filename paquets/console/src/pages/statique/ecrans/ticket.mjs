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
import { el, actions, ajouter, bouton, code, definitions, detail, icone, marque, message, note, pastille, remplacer, vider } from "../commun/dom.mjs";
import { aCle, t } from "../commun/libelles.mjs";
import { ErreurAppel, appeler, allerConnexion, envoiDepuis, erreurDeSession, lireSession, maintenant } from "../commun/client.mjs";
import {
  PREFIXES_ERREUR,
  afficherErreur,
  contientInvisibles,
  demarrerEcran,
  entete,
  estIdentifiantTicket,
  instant,
  lienTicket,
  marqueInvisibles,
  paragrapheCode,
  pastilleEtat,
  phraseCode,
  pluriel,
  principal,
  texteDuree,
  texteRestant,
  texteValeur,
} from "../commun/cadre.mjs";
import { resumeVerifie } from "../commun/lisible.mjs";

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
  // Le détail technique reste ouvert, s'il l'a été, d'un affichage au suivant.
  detailOuvert: false,
};

const zones = {
  lecture: el("div", { classe: "zone", attributs: { id: "zone-lecture" } }),
  modele: el("div", { classe: "nt-pile nt-pile-large", attributs: { id: "zone-modele" } }),
  lies: el("section", { classe: "nt-carte zone-carte", attributs: { id: "zone-lies" } }),
  decision: el("div", { classe: "nt-pile", attributs: { id: "zone-decision" } }),
  motif: el("div", { classe: "nt-champ", attributs: { id: "zone-motif" } }),
  vote: el("section", { classe: "nt-carte zone-carte", attributs: { id: "vote" } }),
  fournisseurs: el("div", { classe: "nt-pile", attributs: { id: "zone-fournisseurs" } }),
  comptes: el("div", { classe: "nt-pile", attributs: { id: "zone-comptes" } }),
  signature: el("div", { classe: "zone", attributs: { id: "zone-signature" } }),
  resultat: el("div", { classe: "zone", attributs: { id: "zone-resultat", "aria-live": "polite" } }),
  consignes: el("div", { classe: "zone", attributs: { id: "zone-consignes" } }),
  recusation: el("section", { classe: "nt-carte zone-carte", attributs: { id: "zone-recusation" } }),
  retrait: el("section", { classe: "nt-carte zone-carte", attributs: { id: "zone-retrait" } }),
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
    afficherErreur(zones.lecture, e);
    for (const z of ["modele", "decision", "vote", "signature", "consignes", "recusation", "retrait"]) vider(zones[z]);
    return;
  }
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
    remplacer(zones.lies, el("h2", { texte: t("ticket.lies.titre") }), z);
    afficherErreur(z, e);
  }
}

// ---------------------------------------------------------------------------
// Affichage du modèle (EX-9.4). Tout ce qu'EX-9.4 demande de montrer avant
// une signature reste visible sans interaction : seuls les codes bruts, les
// noms de champs et les instants exacts vont dans le détail replié.

const MARQUES_ARGUMENT = Object.freeze({ verifie: ["verifie", "coche"], non_verifiable: ["non-verifiable", "question"], different: ["different", "different"] });

function marqueArgument(statut) {
  const [genre, nomIcone] = MARQUES_ARGUMENT[statut] ?? [null, "info"];
  return marque(genre, t(`marque.${statut}`), nomIcone, { "data-marque": statut });
}

// Marque déclarative (EX-9.4) : dit d'où vient la valeur, sans la vérifier.
const marqueDeclarative = (cle) => marque(null, t(cle), "info");

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

const fait = (terme, ...valeur) => el("div", { classe: "nt-fait" }, el("dt", { texte: terme }), el("dd", {}, ...valeur));
const faitLarge = (terme, ...valeur) => el("div", { classe: "nt-fait fait-large" }, el("dt", { texte: terme }), el("dd", {}, ...valeur));

/**
 * La carte « essentiel » : la phrase d'en-tête, composée des seules valeurs
 * que le modèle a vérifiées (`resumeVerifie`), le montant s'il est vérifié,
 * les réserves dites en clair, les faits clés, puis la décision.
 */
function rendreEssentiel(modele, clos) {
  const r = resumeVerifie(modele);
  const d = decompte(modele);
  const parties = [el("p", { classe: "nt-sur-titre", texte: t(clos ? "essentiel.titre_clos" : "essentiel.titre"), attributs: { id: "essentiel-titre" } })];
  const phrase = el("p", { classe: "nt-essentiel-phrase phrase-large", attributs: { id: "phrase-entete" } });
  if (r.outil === null) {
    ajouter(phrase, t("essentiel.non_liee"));
  } else {
    ajouter(phrase, t("essentiel.outil"), " ", el("code", { classe: "nt-fixe", texte: r.outil, attributs: { "data-resume": "outil" } }), r.montant === null ? t("essentiel.point") : t("essentiel.montant"));
  }
  parties.push(phrase);
  if (r.outil !== null && r.montant !== null) {
    parties.push(
      el("p", { classe: "nt-chiffre", attributs: { id: "montant-entete" } }, document.createTextNode(r.montant.texte), el("span", { classe: "nt-chiffre-unite", texte: r.montant.devise })),
      el(
        "p",
        { classe: "nt-attenue nt-petit", attributs: { id: "montant-signe" } },
        t("essentiel.valeurs_signees"),
        " ",
        code(r.montant.pointeurs[0]),
        " ",
        el("code", { classe: "nt-code valeur", texte: texteValeur(r.montant.valeurs[0]) }),
        t("essentiel.et"),
        code(r.montant.pointeurs[1]),
        " ",
        el("code", { classe: "nt-code valeur", texte: texteValeur(r.montant.valeurs[1]) }),
        t("essentiel.toutes_verifiees"),
      ),
    );
  }
  // Réserves : chaque valeur que la console n'a pas vérifiée est nommée, avec sa marque ; aucune n'entre dans la phrase.
  if (r.reserves.length > 0) {
    const MAX = 6;
    const liste = el("ul", { classe: "liste-nue reserves", attributs: { id: "reserves" } });
    for (const x of r.reserves.slice(0, MAX)) ajouter(liste, el("li", { attributs: { "data-reserve": x.pointer } }, code(x.pointer === "" ? t("modele.arguments.racine") : x.pointer), " ", marqueArgument(x.status)));
    if (r.reserves.length > MAX) ajouter(liste, el("li", { texte: pluriel(r.reserves.length - MAX, "essentiel.reserves_autre", "essentiel.reserves_autres"), attributs: { id: "reserves-autres" } }));
    parties.push(
      note(
        "alerte",
        el("p", { classe: "nt-bandeau-titre", texte: pluriel(r.reserves.length, "essentiel.reserve", "essentiel.reserves") }),
        liste,
        r.outil !== null && r.montant === null && modele.arguments.some((a) => a.status !== "verifie" && (a.pointer === "/amount" || a.pointer === "/currency" || a.pointer === "/montant" || a.pointer === "/devise")) ? el("p", { texte: t("essentiel.montant_non_repris"), attributs: { id: "montant-non-repris" } }) : null,
        clos ? null : el("p", { texte: t(r.reserves.length >= 2 ? "essentiel.reserves_lire" : "essentiel.reserve_lire") }),
      ),
    );
  }
  const faits = el("dl", { classe: "nt-faits faits-ligne" });
  if (r.demandeur !== null) ajouter(faits, faitLarge(t("essentiel.demandeur"), el("code", { classe: "nt-fixe", texte: r.demandeur, attributs: { "data-resume": "demandeur" } }), el("span", { classe: "fait-second", texte: t("marque.configuration_hote") })));
  if (r.regle !== null) ajouter(faits, fait(t("modele.regle"), el("span", { texte: r.regle, attributs: { "data-resume": "regle" } })));
  ajouter(faits, fait(t("essentiel.votes"), el("span", { texte: texteVotes(d), attributs: { id: "resume-votes" } }), d.refuse > 0 ? el("span", { classe: "fait-second", texte: t("votes.refus", { n: d.refuse }) }) : null));
  // Un ticket décidé ou clos n'a plus d'échéance à tenir.
  if (!clos) ajouter(faits, fait(t("modele.echeance.deadline"), el("span", { texte: texteRestant(modele.remaining_ms), attributs: { id: "resume-echeance" } }), modele.deadline === null ? null : el("span", { classe: "fait-second" }, instant(modele.deadline))));
  parties.push(faits, zones.decision);
  return el("section", { classe: "nt-essentiel essentiel-serre", attributs: { id: "essentiel", "aria-labelledby": "essentiel-titre" } }, ...parties);
}

/** Le lien de retour vers la liste des tickets. */
function filTickets() {
  return el("a", { classe: "nt-fil", attributs: { href: "/tickets" } }, icone("retour"), t("ticket.fil"));
}

function rendreModele() {
  const { modele, controle, raisons } = etat.pas1;
  const vue = etat.vue;
  const clos = raisons.includes("ticket_clos_aux_votes");
  const etatConnu = aCle(`etat_pastille.${modele.state}`);
  const parties = [];

  // En-tête : le ticket, son état en un mot, ce que cet état veut dire. Le retour à la liste, l'identifiant et
  // l'état tiennent sur une ligne, pour que la décision reste dans le premier écran d'un poste.
  parties.push(
    entete({
      surTitre: el(
        "div",
        { classe: "ligne-ticket" },
        el("div", { classe: "ligne-ticket-debut" }, filTickets(), el("p", { classe: "nt-sur-titre" }, t("ticket.titre"), " ", code(modele.ticket))),
        el(
          "div",
          { classe: "ligne-ticket-etat", attributs: { id: "etat-ticket" } },
          pastilleEtat(modele.state, { grande: true }),
          !clos && modele.remaining_ms !== null ? el("span", { classe: "nt-attenue nt-petit", texte: t("ticket.echeance_courte", { restant: texteRestant(modele.remaining_ms) }) }) : null,
        ),
      ),
      titre: t(etatConnu ? `ticket.titre_etat.${modele.state}` : "ticket.titre_etat.inconnu"),
      sousTitre: etatConnu ? t(`etat_sens.${modele.state}`) : null,
    }),
  );

  // Raisons qui bloquent dès la lecture du pas 1, et avertissements : au-dessus de tout le reste.
  parties.push(rendreRaisons(raisons, modele, vue));
  parties.push(...rendreAvertissements(modele.warnings, controle.warnings));

  // L'essentiel : ce qui est demandé, en une phrase de valeurs vérifiées, et la décision.
  parties.push(rendreEssentiel(modele, clos));

  // Ce que la signature engage : les arguments, puis les champs signés.
  parties.push(el("div", { classe: "titre-groupe" }, el("h2", { texte: t("groupe.signe") }), el("p", { classe: "nt-attenue", texte: t("groupe.signe_sens") })));

  // Arguments, chacun avec sa marque.
  const table = el("table", { classe: "nt-tableau", attributs: { id: "arguments" } });
  ajouter(table, el("thead", {}, el("tr", {}, ...["pointeur", "valeur", "marque"].map((c) => el("th", { texte: t(`modele.arguments.${c}`), attributs: { scope: "col" } })))));
  const corps = el("tbody");
  for (const a of modele.arguments) {
    // Valeur sous sa forme JSON, caractères invisibles écrits `\uXXXX` et marqués (EX-9.16, revue de sécurité de l'étape 8).
    const valeur = el("td", { attributs: { "data-libelle": t("modele.arguments.valeur") } }, el("span", {}, code(texteValeur(a.value), "nt-fixe valeur"), contientInvisibles(a.value) ? " " : null, contientInvisibles(a.value) ? marqueInvisibles() : null));
    ajouter(
      corps,
      el(
        "tr",
        { attributs: { "data-pointeur": a.pointer } },
        el("td", { classe: "nt-cellule-titre", attributs: { "data-libelle": t("modele.arguments.pointeur") } }, code(a.pointer === "" ? t("modele.arguments.racine") : a.pointer)),
        valeur,
        el("td", { attributs: { "data-libelle": t("modele.arguments.marque") } }, marqueArgument(a.status)),
      ),
    );
  }
  table.appendChild(corps);
  const verifies = modele.arguments.filter((a) => a.status === "verifie").length;
  parties.push(
    el(
      "section",
      { classe: "nt-carte nt-carte-pleine", attributs: { "aria-labelledby": "arguments-titre" } },
      el("div", { classe: "nt-carte-titre" }, el("h3", { texte: t("modele.arguments"), attributs: { id: "arguments-titre" } }), el("span", { classe: "nt-carte-note", texte: t("modele.arguments.compte", { champs: pluriel(modele.arguments.length, "modele.arguments.champ", "modele.arguments.champs"), verifies: pluriel(verifies, "modele.arguments.verifie", "modele.arguments.verifies") }) })),
      table,
      el("p", { classe: "nt-attenue nt-petit pied-carte", texte: t("modele.arguments.non_verifiable_sens") }),
    ),
  );

  // Champs signés.
  const evenementVerifie = !modele.blocking.includes("evenement_invalide");
  parties.push(
    el(
      "section",
      { classe: "nt-carte", attributs: { id: "champs-signes" } },
      el("div", { classe: "nt-carte-titre" }, el("h3", { texte: t("modele.signes") }), el("span", { classe: "nt-carte-note", texte: t("modele.signes.note") })),
      definitions([
        [t("modele.signes.decision"), etat.decision === null ? el("span", { classe: "nt-attenue", texte: t("modele.signes.decision_absente") }) : code(etat.decision)],
        [t("modele.signes.ticket"), code(modele.ticket)],
        [t("modele.signes.org_id"), code(modele.org_id)],
        [t("modele.signes.journal_id"), code(modele.journal_id)],
        [t("modele.signes.request_hash"), code(modele.request.request_hash)],
        [
          t("modele.signes.evenement"),
          el(
            "span",
            { classe: "valeur-et-marque" },
            el("span", { classe: "nt-fixe", texte: t("modele.signes.evenement_texte", { seq: modele.request.seq, ts: modele.request.ts }) }),
            " ",
            evenementVerifie ? marque("verifie", t("marque.verifie"), "coche", { "data-evenement": "verifie" }) : marque("different", t("marque.evenement_invalide"), "different", { "data-evenement": "invalide" }),
          ),
        ],
      ]),
    ),
  );

  // Aucune empreinte de D_A avant le choix de la décision (EX-9.20, point 2 ;
  // contrat 3.4, révision de l'étape 6) : seule celle de la décision choisie
  // paraît, sur l'écran de signature ; `empreinte_divergente` montre les deux
  // (table de 13.14).

  // La demande : outil, règle, délégation et intention, effets, ticket ouvrant.
  parties.push(el("div", { classe: "titre-groupe" }, el("h2", { texte: t("groupe.demande") })));
  const d = modele.delegation;
  const valeurEtMarque = (valeur, m) => el("span", { classe: "valeur-et-marque" }, valeur, " ", m);
  parties.push(
    el(
      "div",
      { classe: "nt-grille" },
      el(
        "section",
        { classe: "nt-carte" },
        el("h3", { texte: t("modele.outil") }),
        definitions([
          [t("modele.outil.annonce"), code(modele.tool.announced)],
          [t("modele.outil.origine"), code(modele.tool.original)],
          [t("modele.outil.alias"), code(modele.tool.server_alias)],
          [t("modele.outil.classe"), libelleCode("classe", modele.tool.class)],
        ]),
      ),
      el(
        "section",
        { classe: "nt-carte" },
        el("h3", { texte: t("modele.regle") }),
        definitions([
          [t("modele.regle.policy_rule"), code(modele.rule.policy_rule)],
          [t("modele.regle.nom"), modele.rule.name],
          [t("modele.regle.description"), modele.rule.description === null ? t("modele.vide") : modele.rule.description],
          [t("modele.regle.niveau"), libelleCode("niveau", modele.rule.level)],
          [t("modele.regle.contestation"), modele.rule.contest_ms === 0 ? t("modele.regle.sans_contestation") : texteDuree(modele.rule.contest_ms)],
        ]),
      ),
    ),
  );
  parties.push(
    el(
      "section",
      { classe: "nt-carte" },
      el("h3", { texte: t("modele.delegation") }),
      modele.separation_banner ? message("alerte", paragrapheCode("separation_non_verifiable", ["avertissement."])) : null,
      definitions([
        [t("modele.delegation.launched_by"), valeurEtMarque(code(d.launched_by), marqueDeclarative("marque.configuration_hote"))],
        [t("modele.delegation.scope"), valeurEtMarque(code(d.scope), marqueDeclarative("marque.configuration_hote"))],
        [t("modele.delegation.on_behalf_of"), valeurEtMarque(d.on_behalf_of === null ? el("span", { texte: t("modele.vide") }) : code(d.on_behalf_of), marqueDeclarative("marque.declare_hote"))],
        [t("modele.delegation.run_id"), valeurEtMarque(d.run_id === null ? el("span", { texte: t("modele.vide") }) : code(d.run_id), marqueDeclarative("marque.declare_hote"))],
        [
          t("modele.intention"),
          valeurEtMarque(
            el("span", { texte: modele.intent === null ? t("modele.vide") : modele.intent }),
            modele.intent_status === "en_clair" ? marque(null, t("marque.intention_declaree"), "info", { "data-intention": modele.intent_status }) : marque("non-verifiable", t("marque.non_verifiable"), "question", { "data-intention": modele.intent_status }),
          ),
        ],
      ]),
    ),
  );

  // Effets déclarés prévus.
  const effets = el("ul", { classe: "liste-nue effets", attributs: { id: "effets" } });
  if (modele.effects.length === 0) ajouter(effets, el("li", { classe: "nt-attenue", texte: t("modele.effets.aucun") }));
  for (const e of modele.effects) {
    const nonResolus = new Map(e.unresolved.map((u) => [u.member, u.pointer]));
    const membre = (nom) => {
      if (nonResolus.has(nom)) {
        return el("span", { attributs: { "data-connu-apres-execution": nom } }, marque(null, t("marque.connu_apres_execution"), "horloge"), " ", code(nonResolus.get(nom)));
      }
      return e[nom] === null ? t("modele.vide") : code(e[nom]);
    };
    ajouter(
      effets,
      el(
        "li",
        {},
        definitions([
          [t("modele.effets.systeme"), code(e.system)],
          [t("modele.effets.action"), libelleCode("classe", e.action)],
          [t("modele.effets.objet"), membre("object")],
          [t("modele.effets.montant"), membre("amount")],
          [t("modele.effets.devise"), membre("currency")],
        ]),
      ),
    );
  }
  parties.push(el("section", { classe: "nt-carte" }, el("div", { classe: "nt-carte-titre" }, el("h3", { texte: t("modele.effets") }), el("span", { classe: "nt-carte-note", texte: t("modele.effets.declaratif") })), effets));

  // Ticket ouvrant (EX-5.4).
  if (modele.opening !== null) {
    const o = modele.opening;
    const memes = el("ul", { classe: "liste-nue" });
    for (const s of o.same_arguments) ajouter(memes, el("li", {}, code(s.pointer), " ", code(texteValeur(s.value), "nt-fixe valeur"), contientInvisibles(s.value) ? " " : null, contientInvisibles(s.value) ? marqueInvisibles() : null));
    parties.push(
      el(
        "section",
        { classe: "nt-carte" },
        el("h3", { texte: t("modele.ouvrant") }),
        definitions([
          [t("modele.ouvrant.outil"), code(o.tool)],
          [t("modele.ouvrant.condition"), o.when === null ? t("modele.vide") : el("pre", { classe: "nt-pre", texte: JSON.stringify(o.when, null, 2) })],
          [t("modele.ouvrant.memes_arguments"), o.same_arguments.length === 0 ? t("modele.vide") : memes],
          [t("modele.ouvrant.portee"), t("modele.ouvrant.portee_texte", { max_calls: o.max_calls, duree: texteDuree(o.duration_ms) })],
        ]),
      ),
    );
  }

  // La décision collective : échéance et contestation, jeu figé, votes.
  parties.push(el("div", { classe: "titre-groupe" }, el("h2", { texte: t("groupe.collectif") })));
  const c = modele.contest;
  const sansContestation = modele.rule.contest_ms === 0 && c.window_end === null && c.objections.length === 0 && c.last_threshold_at === null;
  const echeance = [
    [t("modele.echeance.deadline"), modele.deadline === null ? t("modele.vide") : instant(modele.deadline)],
    [t("modele.echeance.restant"), el("span", { texte: texteRestant(modele.remaining_ms) })],
    [t("modele.regle.contestation"), modele.rule.contest_ms === 0 ? t("modele.regle.sans_contestation") : texteDuree(modele.rule.contest_ms)],
  ];
  if (!sansContestation) {
    echeance.push(
      [t("modele.contest.fin_fenetre"), c.window_end === null ? t("modele.contest.aucune_fenetre") : instant(c.window_end)],
      [t("modele.contest.objections"), c.objections.length === 0 ? t("modele.contest.aucune_objection") : el("ul", { classe: "liste-nue" }, ...c.objections.map((o) => el("li", {}, code(o.approver), " ", instant(o.at))))],
      [t("modele.contest.dernier_instant"), c.last_threshold_at === null ? t("modele.vide") : instant(c.last_threshold_at)],
    );
  }

  // Jeu figé, votes.
  const jeu = modele.approver_set;
  const mien = etat.pas1.approver;
  const votes = el("div", { attributs: { id: "votes" } });
  if (modele.votes.length === 0) {
    ajouter(votes, el("p", { classe: "nt-attenue corps-carte", texte: t("modele.votes.aucun") }));
  } else {
    const tv = el("table", { classe: "nt-tableau" });
    ajouter(tv, el("thead", {}, el("tr", {}, ...["approbateur", "decision", "instant", "motif"].map((x) => el("th", { texte: t(`modele.votes.colonne.${x}`), attributs: { scope: "col" } })))));
    const lignes = el("tbody");
    for (const v of modele.votes) {
      ajouter(
        lignes,
        el(
          "tr",
          { attributs: { "data-vote": v.approver, "data-decision": v.decision } },
          el("td", { classe: "nt-cellule-titre", attributs: { "data-libelle": t("modele.votes.colonne.approbateur") } }, el("span", {}, code(v.approver), v.approver === mien ? el("span", { classe: "nt-attenue nt-petit", texte: ` ${t("modele.jeu.vous")}` }) : null)),
          // La décision d'un vote est la valeur signée : `approuve` ou `refuse`, telle quelle, sans capitale.
          el("td", { attributs: { "data-libelle": t("modele.votes.colonne.decision") } }, pastille(v.decision === "approuve" ? "succes" : "refus", t(`decision.${v.decision}`), v.decision === "approuve" ? "coche" : "croix", { telQuel: true })),
          el("td", { attributs: { "data-libelle": t("modele.votes.colonne.instant") } }, instant(v.at)),
          el("td", { attributs: { "data-libelle": t("modele.votes.colonne.motif") } }, v.reason === null ? el("span", { classe: "nt-attenue", texte: t("modele.votes.sans_motif") }) : el("span", { texte: v.reason })),
        ),
      );
    }
    tv.appendChild(lignes);
    votes.appendChild(tv);
  }
  parties.push(
    el("section", { classe: "nt-carte" }, el("h3", { texte: t("modele.echeance") }), definitions(echeance)),
    el(
      "section",
      { classe: "nt-carte" },
      el("h3", { texte: t("modele.jeu") }),
      jeu === null
        ? el("p", { texte: t("modele.jeu.non_fige") })
        : definitions([
            [t("modele.jeu.seuil"), el("span", {}, t("modele.jeu.seuil_texte", { t: jeu.threshold.required, n: jeu.threshold.size }), el("span", { classe: "nt-attenue nt-petit", texte: ` ${t("modele.jeu.seuil_sens", { t: jeu.threshold.required, n: jeu.threshold.size })}` }))],
            [t("modele.jeu.seuil_effectif"), modele.effective_required === null ? t("modele.vide") : String(modele.effective_required)],
            [t("modele.jeu.membres"), el("ul", { classe: "liste-nue" }, ...jeu.members.map((m) => el("li", {}, code(m), m === mien ? el("span", { classe: "nt-attenue nt-petit", texte: ` ${t("modele.jeu.vous")}` }) : null)))],
            [t("modele.jeu.source"), el("span", { classe: "nt-fixe nt-petit", texte: jeu.source })],
          ]),
    ),
    el("section", { classe: "nt-carte nt-carte-pleine" }, el("div", { classe: "nt-carte-titre" }, el("h3", { texte: t("modele.votes") }), el("span", { classe: "nt-carte-note", texte: texteVotes(decompte(modele)) })), votes),
  );

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
  technique.push([t("detail.champs"), el("span", { classe: "nt-fixe nt-petit", texte: t("detail.champs_texte") })]);
  const bloc = detail(t("detail.titre"), t("detail.note"), definitions(technique));
  bloc.setAttribute("id", "detail-technique");
  bloc.open = etat.detailOuvert;
  bloc.addEventListener("toggle", () => {
    etat.detailOuvert = bloc.open;
  });
  parties.push(bloc);

  remplacer(zones.modele, ...parties);
}

/**
 * Les raisons qui bloquent ; pour `empreinte_divergente`, les deux empreintes
 * de chaque décision. Un ticket qui n'accepte plus de votes, sans autre
 * raison, n'est pas une panne : le bandeau le dit sans alarme.
 */
function rendreRaisons(raisons, modele, vue) {
  if (raisons.length === 0) return null;
  const ul = el("ul", { classe: "liste-nue raisons" });
  for (const r of raisons) {
    const li = el("li", { attributs: { "data-code": r } }, ...phraseCode(r, PREFIXES_VOTE));
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
            el("td", { classe: "nt-cellule-titre", texte: t(`decision.${d}`), attributs: { "data-libelle": t("divergence.decision") } }),
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
    return message(approuve ? "succes" : "info", approuve ? el("p", { classe: "nt-bandeau-titre", texte: t("raisons.approuve", { votes: texteVotes(decompte(modele)) }), attributs: { id: "issue" } }) : null, ul, el("p", { texte: t("raisons.clos_sens") }));
  }
  return message("erreur", el("p", { classe: "nt-bandeau-titre", texte: t("raisons.titre") }), ul);
}

/** Un bandeau par avertissement : son titre, sa phrase et son code, puis ce qu'il veut dire et quoi faire. */
function rendreAvertissements(warnings, avertissementsControle) {
  const bandeaux = [];
  for (const w of warnings) {
    let txt = t(`avertissement.${w}`);
    if (w === "separation_incomplete") {
      const a = avertissementsControle.find((x) => x.code === "separation_incomplete");
      if (a) txt = t("avertissement.separation_incomplete", { adresses: a.addresses.join(", ") });
      else txt = t("avertissement.separation_incomplete", { adresses: "" });
    }
    bandeaux.push(
      message(
        "alerte",
        aCle(`avertissement_titre.${w}`) ? el("p", { classe: "nt-bandeau-titre", texte: t(`avertissement_titre.${w}`) }) : null,
        // Sans titre court, la phrase de l'avertissement est elle-même le titre du bandeau.
        el("p", { classe: aCle(`avertissement_titre.${w}`) ? null : "nt-bandeau-titre", attributs: { "data-avertissement": w } }, el("span", { texte: txt }), el("span", { classe: "code-brut", texte: ` (${w})` })),
        aCle(`avertissement_sens.${w}`) ? el("p", { texte: t(`avertissement_sens.${w}`) }) : null,
      ),
    );
  }
  return bandeaux;
}

function rendreLies(reponse) {
  const parties = [el("h2", { texte: t("ticket.lies.titre") })];
  const related = reponse !== null && typeof reponse === "object" ? reponse.related : undefined;
  if (!Array.isArray(related)) {
    parties.push(el("p", { classe: "nt-attenue", texte: t("ticket.lies.non_communique") }));
  } else if (related.length === 0) {
    parties.push(el("p", { classe: "nt-attenue", texte: t("ticket.lies.aucun") }));
  } else {
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
          r.reason === null ? t("modele.votes.sans_motif") : t("modele.votes.motif", { motif: String(r.reason) }),
        ),
      );
    }
    parties.push(ul);
  }
  remplacer(zones.lies, ...parties);
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

function rendreDecision() {
  const raisons = etat.pas1 ? etat.pas1.raisons : [];
  if (raisons.includes("ticket_clos_aux_votes")) {
    // Ticket décidé ou clos : plus aucune décision à prendre, plus de bouton.
    vider(zones.decision);
    return;
  }
  const parties = [el("h2", { classe: "titre-decision", texte: t("decision.titre") })];
  const ouvert = etat.pas1 && raisons.length === 0;
  if (etat.decision !== null) {
    const m = motif();
    parties.push(
      el("p", { classe: "decision-choisie", attributs: { id: "decision-choisie", "data-decision": etat.decision } }, t("decision.choisie", { decision: t(`decision.${etat.decision}`) })),
      el("p", { classe: "nt-attenue", attributs: { id: "motif-choisi" } }, m === null ? t("motif.aucun") : t("modele.votes.motif", { motif: m })),
      el("p", { texte: t("decision.suite") }),
      actions(
        el("a", { classe: "nt-bouton nt-bouton-principal", texte: t("decision.aller_signature"), attributs: { href: "#vote" } }),
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
    parties.push(
      el("p", { classe: "decision-question", texte: t("decision.confirmer_question", { decision: t(`decision.${d}`) }) }),
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
  } else {
    const groupe = el("div", { classe: "nt-actions", attributs: { role: "group", "aria-label": t("decision.titre") } });
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
    parties.push(groupe);
    if (!ouvert) parties.push(el("p", { classe: "nt-attenue nt-petit", texte: t("decision.inactifs") }));
    else parties.push(el("p", { classe: "nt-attenue nt-petit" }, ...phraseCode("decision_absente", PREFIXES_VOTE), el("span", { texte: ` ${t("decision.sens")}` })));
  }
  remplacer(zones.decision, ...parties);
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
    remplacer(zones.vote, el("h2", { texte: t("vote.titre") }), el("p", { classe: "nt-attenue", texte: t("vote.sens") }), zones.fournisseurs, zones.comptes);
  }
  rendreFournisseurs(zones.fournisseurs, decouverte, etat.fournisseur, choisirFournisseur, etat.vue !== null);
  rendreComptes();
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
    parties.push(el("p", {}, t("portefeuille.courant", { nom: etat.fournisseur.name })));
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
  const p = el("p", { classe: "groupes" });
  const g = groupes(x).split(" ");
  g.forEach((morceau, k) => {
    if (k > 0) p.appendChild(el("span", { texte: " " }));
    p.appendChild(el("span", { classe: "groupe", texte: morceau }));
  });
  return p;
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
  const consignes = rendreConsignesElement();
  // EX-9.18 : D_A en entier, ses groupes, son empreinte en grands caractères
  // sous son intitulé ; puis, à part, le condensé EIP-191 sous le sien.
  const panneau = el(
    "section",
    { classe: "nt-carte signature", attributs: { id: "ecran-signature", "data-decision": etat.decision } },
    el("div", { classe: "nt-carte-titre" }, el("h2", { texte: t("signature.titre", { decision: t(`decision.${etat.decision}`) }) }), etat.enCours ? pastille("info", t("signature.pastille_demandee"), "horloge") : null),
    definitions([
      [t("signature.adresse"), code(etat.adresse)],
      [t("signature.portefeuille"), etat.fournisseur.name],
    ]),
    el(
      "div",
      { classe: "nt-encart nt-pile" },
      el("h3", { classe: "intitule", texte: t("signature.d_a") }),
      el("p", {}, code(d.d_a, "nt-fixe d-a")),
      groupesFixes(d.d_a),
      el("h3", { classe: "intitule", texte: t("signature.empreinte_d_a") }),
      el("p", { classe: "nt-empreinte", texte: d.fingerprint, attributs: { id: "empreinte-d-a" } }),
    ),
    el("div", { classe: "nt-encart nt-pile" }, el("h3", { classe: "intitule", texte: t("signature.eip191") }), el("p", { classe: "empreinte-secondaire", texte: d.h_fingerprint, attributs: { id: "empreinte-h" } }), groupesFixes(d.h)),
    l.modele.warnings.includes("condense_utf8") ? message("alerte", el("p", { attributs: { "data-avertissement": "condense_utf8" } }, el("span", { texte: t("avertissement.condense_utf8") }), el("span", { classe: "code-brut", texte: " (condense_utf8)" }))) : null,
    consignes,
    actions(bouton(t("signature.demander"), () => void demanderSignature(), { actif: !etat.enCours, genre: "principal", icone: "cadenas" }), el("a", { classe: "nt-bouton nt-bouton-discret", texte: t("signature.revenir"), attributs: { href: "#essentiel" } })),
    etat.enCours ? message("info", el("p", { texte: t("signature.en_cours") })) : null,
  );
  remplacer(zones.signature, panneau);
  vider(zones.consignes);
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
      remplacer(zones.resultat, message("erreur", paragrapheCode(c.reason, PREFIXES_VOTE), el("p", { texte: t("vote.non_envoye") })));
      return;
    }
  }

  // Pas 8 : le vote, construit une seule fois sur la vue du ticket signé.
  const corps = requeteVoter(vueSignee, decision, verdict.signature, adresse, motifSigne, identite());
  await envoyerVote(corps, g);
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

async function envoyerVote(corps, g) {
  let essais = 0;
  for (;;) {
    try {
      const r = await appeler("voter", corps);
      if (g !== etat.generation) return;
      etat.enCours = false;
      abandonnerApres();
      const v = r.valeur;
      remplacer(zones.resultat, message("succes", el("p", { texte: t("vote.inscrit", { etat: v && typeof v.state === "string" ? t(`etat.${v.state}`) : t("modele.vide") }), attributs: { "data-resultat": "vote_inscrit" } })));
      await lecturePas1();
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
        remplacer(zones.resultat, message("info", el("p", { attributs: { "data-resultat": "vote_identique" } }, el("span", { texte: t(essais > 0 ? "vote.deja_inscrit" : "vote.deja_inscrit_motif") }), el("span", { classe: "code-brut", texte: " (vote_identique)" }))));
        await lecturePas1();
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
              void envoyerVote(corps, g2);
            }),
          ),
        );
        return;
      }
      if (erreurDeSession(e)) return;
      remplacer(zones.resultat, message("erreur", paragrapheCode(e instanceof ErreurAppel ? e.code : "erreur_page", PREFIXES_ERREUR), el("p", { texte: t("vote.non_inscrit") })));
      return;
    }
  }
}

function afficherPanne(codePanne, erreur, recouvree = null) {
  const parties = [el("p", { attributs: { "data-code": codePanne } }, ...noeudsPanne(codePanne, erreur, PREFIXES_VOTE))];
  if (codePanne === "adresse_differente" && typeof recouvree === "string") parties.push(el("p", {}, t("signature.adresse_recouvree"), " ", code(recouvree)));
  if (codePanne === "refus_approbateur") parties.push(el("p", { texte: t("signature.refus_sens") }));
  remplacer(zones.resultat, message("erreur", ...parties));
}

// ---------------------------------------------------------------------------
// Consignes d'EX-9.20

function origineSaine() {
  const a = etat.annuaire;
  return a !== null && typeof a.console_origin === "string" ? a.console_origin : t("modele.vide");
}

function rendreConsignesElement() {
  const ol = el("ol", { classe: "consignes", attributs: { id: "consignes" } });
  for (let k = 1; k <= 7; k += 1) ajouter(ol, el("li", { texte: t(`consigne.${k}`, { origine: origineSaine() }) }));
  return el("div", { classe: "bloc-consignes nt-pile" }, el("h3", { texte: t("consigne.titre") }), ol);
}

// Avant le choix de la décision, les consignes d'EX-9.20 sont offertes dans un
// bloc replié ; l'écran de signature, lui, les affiche toujours en entier
// (EX-9.20 : « sur l'écran de signature »).
function rendreConsignes() {
  if (etat.vue === null || etat.pas1 === null || etat.pas1.raisons.includes("ticket_clos_aux_votes")) return vider(zones.consignes);
  if (zones.signature.querySelector("#consignes") !== null) return vider(zones.consignes);
  const bloc = detail(t("consigne.titre"), t("consigne.note"), rendreConsignesElement().lastChild);
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
  const parties = [el("h2", { texte: t("recusation.titre") }), el("p", { classe: "nt-attenue", texte: t("recusation.sens") })];
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
          { actif: c.reason === null },
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
  const parties = [el("h2", { texte: t("retrait.titre") }), el("p", { classe: "nt-attenue", texte: t("retrait.sens") }), el("p", {}, t("retrait.par"), " ", code(by))];
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
  ajouter(racine, el("main", { classe: "nt-page page-ticket" }, zones.lecture, zones.modele, zones.lies, zones.vote, zones.consignes, zones.signature, zones.resultat, el("div", { classe: "nt-grille autres-actions" }, zones.recusation, zones.retrait)));
  rendreFournisseursEtComptes();
  await Promise.all([lecturePas1(), lectureLies()]);
}

void demarrer();
