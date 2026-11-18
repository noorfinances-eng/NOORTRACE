// Écran « Demandes » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.3,
// EX-12.21, EX-14.2) : `tickets` sans `related_to` ; pour chaque ticket non
// décidé, une carte : l'outil annoncé, l'identifiant (lien vers son écran,
// que toute la carte prolonge), l'état en pastille, le demandeur, l'échéance,
// les votes `approuve` et `refuse` sur `effective_required`, l'état de la
// fenêtre de contestation (`contest_ms`, `contest`) ; puis le nombre de
// tickets ouverts par demandeur. Les instants s'affichent en mots ; l'instant
// exact reste dans l'attribut `datetime` de chacun.
//
// Complément du 2026-11-18, décision du porteur (langage des écrans) : l'écran
// dit à quoi il sert et porte un bloc replié « Comment ça marche » ; les
// demandes « à décider » (état `ouvert`) viennent d'abord, les autres
// demandes en cours (approbations réunies, décision en cours
// d'enregistrement, en préparation) dans un groupe à part ; le titre d'une
// carte est « Demande d'utiliser l'outil … » ; la réponse `tickets` ne porte
// pas les arguments. La contestation (CT-3 10.2) se dit en mots, et seulement
// quand la règle en prévoit une : une demande sans délai de contestation n'en
// dit rien.
//
// Complément du 2026-11-18 (CT-3 EX-13.3) : pour les dix premières demandes à
// décider au plus, la liste lit ensuite la vue de chaque demande (`consulter`,
// et `annuaire` une fois : des lectures, les mêmes que l'écran d'une demande)
// et affiche à côté du titre le montant que `montantVerifie` rend : celui de
// la phrase vérifiée, et rien quand il n'est pas vérifié. La liste s'affiche
// d'abord ; un montant arrive ensuite ; une lecture qui échoue laisse sa
// ligne sans montant, sans erreur. Chaque date porte ce qu'elle est : pour une
// demande à décider dont la règle prévoit un délai de contestation, « À
// décider avant » donne le dernier moment où l'approuver à temps (EX-10.9),
// et l'expiration est dite à part ; pour une autre demande en cours, « Expire
// le ».

import { modeleAffichage, sessionDuModele, entreeDeSession, adresseActive } from "noortrace-console/index.mjs";
import { el, ajouter, code, detail, icone, marque, message, pastille, remplacer } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { appeler, maintenant } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, entete, estIdentifiantTicket, instant, lienTicket, paragrapheCode, pastilleEtat, pluriel, principal, texteDuree, texteDureeCourte, texteRestant } from "../commun/cadre.mjs";
import { montantVerifie } from "../commun/lisible.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// La contestation d'une demande (CT-3 10.2), en mots. Sans délai de contestation (`contest_ms` nul), il n'y a ni
// fenêtre ni objection : rien n'est affiché (`null`). Avec un délai : si une fenêtre court, jusqu'à quand la demande
// peut encore être contestée ; sinon, pendant combien de temps elle pourra l'être une fois ses approbations réunies ;
// les contestations non levées, qui suspendent la demande ; et le dernier instant où les approbations doivent être
// réunies pour que la fenêtre finisse avant l'échéance (EX-10.9).
function contestation(tk) {
  if (tk.contest_ms === undefined || !estObjet(tk.contest)) return [el("span", { classe: "fait-texte", texte: t("tickets.contestation.non_communiquee") })];
  if (tk.contest_ms === 0) return null;
  const c = tk.contest;
  const lignes = [];
  const n = Array.isArray(c.objections) ? c.objections.length : 0;
  const contestee = (classe) => el("span", { classe, texte: pluriel(n, "tickets.contestation.objection", "tickets.contestation.objections"), attributs: { "data-objections": String(n) } });
  if (c.window_end !== null) {
    const reste = Date.parse(String(c.window_end)) - Date.now();
    lignes.push(el("span", { classe: "fait-texte" }, reste > 0 ? t("tickets.contestation.en_cours", { duree: texteDureeCourte(reste) }) : t("tickets.contestation.jusqu_au"), " ", instant(String(c.window_end)), "."));
    if (n > 0) lignes.push(contestee("fait-second"));
  } else if (n > 0) {
    // Une contestation en cours annule le délai, ou l'empêche de commencer (EX-5.9, point 4) : c'est elle qui se
    // lit d'abord ; un délai entier recommence quand elle est retirée et que les approbations sont réunies.
    lignes.push(contestee("fait-texte"), el("span", { classe: "fait-second", texte: t("tickets.contestation.apres_retrait", { duree: texteDuree(tk.contest_ms) }) }));
  } else {
    lignes.push(el("span", { classe: "fait-texte", texte: t("tickets.contestation.a_venir", { duree: texteDuree(tk.contest_ms) }) }));
  }
  return lignes;
}

// Un fait de la carte : libellé court au-dessus, valeur dessous.
function fait(nom, classe, ...valeur) {
  return faitLibelle(nom, t(`tickets.colonne.${nom}`), classe, ...valeur);
}

function faitLibelle(nom, libelle, classe, ...valeur) {
  return el("div", { classe, attributs: { "data-champ": nom } }, el("dt", { texte: libelle }), el("dd", {}, ...valeur));
}

// Le dernier instant où le seuil doit être atteint (EX-10.9), quand le service le donne pour une demande à décider.
function dernierInstant(tk) {
  if (tk.state !== "ouvert" || !estObjet(tk.contest) || typeof tk.contest_ms !== "number" || tk.contest_ms <= 0) return null;
  const d = tk.contest.last_threshold_at;
  return typeof d === "string" ? d : null;
}

/**
 * L'échéance d'une carte, chaque date avec ce qu'elle est. Demande à décider
 * avec un délai de contestation : le dernier moment pour l'approuver à temps,
 * puis l'expiration, dite à part. Demande à décider sans ce délai : son
 * échéance. Autre demande en cours : « Expire le », si elle n'est pas
 * approuvée d'ici là.
 */
function faitEcheance(tk) {
  const reste = (iso) => el("span", { classe: "fait-second", texte: texteRestant(Date.parse(iso) - Date.now()) });
  if (tk.deadline === null) return fait("echeance", "nt-fait", el("span", { texte: t("modele.vide") }));
  const echeance = String(tk.deadline);
  if (tk.state !== "ouvert") {
    // Une contestation en cours suspend la demande : le dernier moment où la retirer à temps est dit, avec ce qu'il est.
    const c = estObjet(tk.contest) ? tk.contest : null;
    const suspendue = c !== null && Array.isArray(c.objections) && c.objections.length > 0 && typeof c.last_threshold_at === "string";
    return faitLibelle(
      "echeance",
      t("tickets.colonne.expiration"),
      "nt-fait",
      instant(echeance),
      reste(echeance),
      el("span", { classe: "fait-second", texte: t("tickets.echeance.sinon") }),
      suspendue ? el("span", { classe: "fait-second", attributs: { "data-dernier-instant": "" } }, t("tickets.echeance.retrait"), " ", instant(c.last_threshold_at), ".") : null,
    );
  }
  const dernier = dernierInstant(tk);
  if (dernier === null) return fait("echeance", "nt-fait", instant(echeance), reste(echeance));
  return fait("echeance", "nt-fait", el("span", { attributs: { "data-dernier-instant": "" } }, instant(dernier)), reste(dernier), el("span", { classe: "fait-second", attributs: { "data-expiration": "" } }, t("tickets.echeance.approuver"), " ", instant(echeance), "."));
}

// Les emplacements des montants, par identifiant de demande : remplis après l'affichage de la liste.
const zonesMontant = new Map();
const MONTANTS_MAX = 10;

/**
 * Le montant vérifié des dix premières demandes à décider (complément du
 * 2026-11-18) : des lectures seulement, l'une après l'autre, après
 * l'affichage de la liste. Une lecture qui échoue, une vue d'une autre
 * demande, un montant que la console n'a pas vérifié : la ligne reste sans
 * montant, et rien d'autre n'est affiché.
 */
async function lireMontants(identite, aDecider) {
  const cibles = aDecider.filter((tk) => estIdentifiantTicket(tk.ticket) && zonesMontant.has(String(tk.ticket))).slice(0, MONTANTS_MAX);
  if (cibles.length === 0) return;
  let annuaire;
  try {
    annuaire = (await appeler("annuaire", { session_identity: identite })).valeur;
    if (!estObjet(annuaire) || !Array.isArray(annuaire.entries)) return;
  } catch {
    return;
  }
  for (const tk of cibles) {
    try {
      const vue = (await appeler("consulter", { ticket: tk.ticket, session_identity: identite })).valeur;
      if (!estObjet(vue) || vue.ticket !== tk.ticket) continue;
      const entree = entreeDeSession(annuaire, identite);
      const approver = entree !== null && entree.active === true ? adresseActive(entree) : null;
      // La vue porte déjà la décision de la personne connectée : la demande n'attend plus sa décision.
      const mien = approver !== null && vue.state === "ouvert" && Array.isArray(vue.votes) ? vue.votes.find((v) => estObjet(v) && v.approver === approver && (v.decision === "approuve" || v.decision === "refuse")) : undefined;
      if (mien !== undefined) rangerDejaDecidee(String(tk.ticket), mien.decision);
      const m = montantVerifie(modeleAffichage(vue, { session: sessionDuModele(annuaire, identite, vue), decision: null, approver, reason: null, now: maintenant() }));
      if (m === null) continue;
      remplacer(
        zonesMontant.get(String(tk.ticket)),
        el("span", { classe: "nt-masque", texte: t("tickets.montant") }),
        el("strong", { classe: "carte-ticket-somme", texte: `${m.texte}\u00a0${m.devise}`, attributs: { "data-valeur": "" } }),
        marque("verifie", t("marque.verifie"), "coche", { "data-fixe": "", "data-marque": "verifie" }),
      );
    } catch {
      // La ligne reste sans montant.
    }
  }
}

function votes(tk) {
  const approbations = pluriel(tk.votes_approuve, "votes.approbation", "votes.approbations");
  const refus = t("votes.refus", { n: tk.votes_refuse });
  const principal_ = tk.effective_required === null ? t("tickets.votes.sans_seuil", { approbations }) : t("tickets.votes", { approbations, requis: pluriel(tk.effective_required, "votes.requise", "votes.requises") });
  return el("span", { attributs: { "data-votes": "", "data-approuve": String(tk.votes_approuve), "data-refuse": String(tk.votes_refuse), "data-requis": tk.effective_required === null ? "" : String(tk.effective_required) } }, el("span", { texte: principal_ }), el("span", { classe: "fait-second", texte: refus }));
}

function carteTicket(tk) {
  const id = String(tk.ticket);
  const conteste = contestation(tk);
  // Le montant ne vient pas de la réponse `tickets` : son emplacement reste vide tant que la vue n'est pas lue.
  const zoneMontant = el("p", { classe: "carte-ticket-montant", attributs: { "data-montant": "" } });
  if (tk.state === "ouvert") zonesMontant.set(id, zoneMontant);
  return el(
    "li",
    { classe: "nt-carte carte-ticket", attributs: { "data-ticket": id } },
    el(
      "div",
      { classe: "carte-ticket-tete" },
      el(
        "div",
        { classe: "carte-ticket-titre" },
        // La réponse `tickets` ne porte pas les arguments : le titre nomme l'outil ; le montant vérifié vient ensuite.
        el("h3", { classe: "carte-ticket-nom", attributs: { "data-champ": "outil" } }, el("span", { texte: t("tickets.carte.titre") }), " ", code(String(tk.tool_announced))),
        tk.state === "ouvert" ? zoneMontant : null,
        // Revue de sécurité de l'étape 8 (CT-3 EX-7.1) : lien seulement pour un identifiant d'EX-7.1.
        el("p", { classe: "nt-sur-titre" }, t("tickets.colonne.ticket"), " ", lienTicket(tk.ticket, "nt-fixe lien-carte")),
      ),
      el("div", { classe: "carte-ticket-etat" }, pastilleEtat(tk.state, { court: true }), el("span", { classe: "carte-ticket-ouvrir", attributs: { "aria-hidden": "true" } }, t("tickets.ouvrir"), icone("retour", "icone-suite"))),
    ),
    // Le fait « Contestation » n'existe que si la règle prévoit un délai de contestation.
    el("dl", { classe: "nt-faits faits-ticket" }, fait("demandeur", "nt-fait", code(String(tk.launched_by))), faitEcheance(tk), fait("votes", "nt-fait", votes(tk)), conteste === null ? null : fait("contestation", "nt-fait fait-large", ...conteste)),
  );
}

/** Le compteur de l'en-tête : le nombre de demandes à décider. */
function elementCompte(n) {
  return el("p", { classe: "nt-chiffre", attributs: { "aria-label": pluriel(n, "tickets.compte", "tickets.comptes"), id: "compte-a-decider" } }, el("span", { classe: "nt-chiffre-degrade", texte: String(n) }), el("span", { classe: "nt-chiffre-unite", texte: t(n >= 2 ? "tickets.unites" : "tickets.unite") }));
}

/**
 * Une demande à l'état « ouvert » dont la vue porte déjà la décision de la
 * personne connectée (complément du 2026-11-18, EX-13.3) : elle n'attend
 * plus sa décision. Sa carte passe dans le second groupe, dit ce que la
 * personne a décidé et porte « En attente d'autres approbations » ; les
 * nombres des groupes et le compteur suivent. Aucune demande ne quitte la
 * liste, et la carte garde son lien : la personne peut encore changer sa
 * décision sur l'écran de la demande (EX-7.26).
 */
function rangerDejaDecidee(id, decision) {
  const cartes = document.getElementById("liste-tickets");
  const carte = cartes === null ? null : [...cartes.children].find((li) => li.getAttribute("data-ticket") === id);
  if (!carte || carte.hasAttribute("data-deja")) return;
  carte.setAttribute("data-deja", "");
  const etat = carte.querySelector(".carte-ticket-etat [data-etat]");
  if (etat !== null) etat.replaceWith(pastille("info", t("etat_pastille.deja"), "horloge", { attributs: { "data-etat": "ouvert", "data-deja": "" } }));
  const titre = carte.querySelector(".carte-ticket-titre");
  if (titre !== null) titre.appendChild(el("p", { classe: "carte-ticket-deja", texte: t(`tickets.deja.${decision}`), attributs: { "data-deja-decide": decision } }));
  // La date n'est plus « à décider avant » pour elle : c'est celle avant laquelle les autres approbations doivent arriver.
  const libelleEcheance = carte.querySelector('[data-champ="echeance"] > dt');
  if (libelleEcheance !== null) libelleEcheance.textContent = t("tickets.echeance.deja");
  let groupe = cartes.querySelector('li[data-groupe="autres"]');
  if (groupe === null) {
    groupe = intertitre("autres", 0, t("tickets.groupe.autres_sens"));
    cartes.appendChild(groupe);
  }
  // À la suite des demandes déjà rangées ainsi, dans l'ordre de la liste, avant les autres demandes en cours.
  let apres = groupe;
  while (apres.nextElementSibling !== null && apres.nextElementSibling.hasAttribute("data-deja")) apres = apres.nextElementSibling;
  apres.after(carte);
  // Les nombres : ce que chaque groupe porte maintenant.
  const rang = [...cartes.children].indexOf(groupe);
  const aDecider = [...cartes.children].slice(0, rang).filter((li) => li.hasAttribute("data-ticket")).length;
  const autres = [...cartes.children].slice(rang).filter((li) => li.hasAttribute("data-ticket")).length;
  const nombre = (li, n) => {
    const z = li === null ? null : li.querySelector(".groupe-liste-nombre");
    if (z !== null) z.textContent = `(${n})`;
  };
  nombre(cartes.querySelector('li[data-groupe="a_decider"]'), aDecider);
  nombre(groupe, autres);
  const compte = document.getElementById("compte-a-decider");
  if (compte !== null) compte.replaceWith(elementCompte(aDecider));
  if (aDecider === 0 && document.getElementById("aucune-a-decider") === null) {
    const vide = el("li", { classe: "nt-attenue", texte: t("tickets.aucun"), attributs: { id: "aucune-a-decider" } });
    cartes.querySelector('li[data-groupe="a_decider"]').after(vide);
  }
}

// Un intertitre de la liste : un groupe de demandes, et ce que ce groupe veut dire.
function intertitre(cle, n, sens) {
  return el("li", { classe: "groupe-liste", attributs: { "data-groupe": cle } }, el("h2", {}, el("span", { texte: t(`tickets.groupe.${cle}`) }), " ", el("span", { classe: "nt-attenue groupe-liste-nombre", texte: `(${n})` })), sens ? el("p", { classe: "nt-attenue", texte: sens }) : null);
}

function rendre(conteneur, reponse) {
  const liste = estObjet(reponse) && Array.isArray(reponse.tickets) ? reponse.tickets : null;
  zonesMontant.clear();
  if (liste === null) {
    remplacer(conteneur, message("erreur", paragrapheCode("reponse_service_invalide", ["console."])));
    return [];
  }
  // « À décider » : les demandes ouvertes aux décisions. Les autres demandes en cours n'attendent pas de décision.
  const aDecider = liste.filter((tk) => tk.state === "ouvert");
  const autres = liste.filter((tk) => tk.state !== "ouvert");
  const compte = elementCompte(aDecider.length);
  const comment = detail(t("tickets.comment.titre"), null, el("ol", { classe: "consignes" }, ...[1, 2, 3, 4, 5].map((k) => el("li", { texte: t(`tickets.comment.${k}`) }))));
  comment.setAttribute("id", "comment-ca-marche");
  const parties = [entete({ titre: t("tickets.titre"), sousTitre: t("tickets.sens"), etat: liste.length === 0 ? [] : [compte] }), comment];
  if (liste.length === 0) {
    parties.push(el("div", { classe: "nt-vide", attributs: { id: "aucun-ticket" } }, icone("boite"), el("p", { classe: "nt-vide-titre", texte: t("tickets.aucun") }), el("p", { classe: "nt-vide-texte", texte: t("tickets.aucun_sens") })));
    remplacer(conteneur, ...parties);
    return [];
  }
  const cartes = el("ul", { classe: "liste-nue liste-cartes", attributs: { id: "liste-tickets" } });
  const parDemandeur = new Map();
  for (const tk of liste) {
    const lb = String(tk.launched_by);
    parDemandeur.set(lb, (parDemandeur.get(lb) ?? 0) + 1);
  }
  cartes.appendChild(intertitre("a_decider", aDecider.length, null));
  if (aDecider.length === 0) cartes.appendChild(el("li", { classe: "nt-attenue", texte: t("tickets.aucun"), attributs: { id: "aucune-a-decider" } }));
  for (const tk of aDecider) cartes.appendChild(carteTicket(tk));
  if (autres.length > 0) {
    cartes.appendChild(intertitre("autres", autres.length, t("tickets.groupe.autres_sens")));
    for (const tk of autres) cartes.appendChild(carteTicket(tk));
  }
  parties.push(cartes);

  // EX-14.2 : nombre de tickets ouverts par demandeur.
  const resume = el("table", { classe: "nt-tableau", attributs: { id: "par-demandeur" } });
  ajouter(resume, el("thead", {}, el("tr", {}, el("th", { texte: t("tickets.colonne.demandeur"), attributs: { scope: "col" } }), el("th", { texte: t("tickets.colonne.ouverts"), attributs: { scope: "col" } }))));
  const corpsResume = el("tbody");
  for (const [lb, n] of [...parDemandeur.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    ajouter(corpsResume, el("tr", { attributs: { "data-demandeur": lb } }, el("td", { classe: "nt-cellule-titre", attributs: { "data-libelle": t("tickets.colonne.demandeur") } }, code(lb)), el("td", { texte: String(n), attributs: { "data-libelle": t("tickets.colonne.ouverts") } })));
  }
  resume.appendChild(corpsResume);
  parties.push(el("section", { classe: "nt-carte nt-carte-pleine" }, el("div", { classe: "nt-carte-titre" }, el("h2", { texte: t("tickets.par_demandeur") })), resume));
  remplacer(conteneur, ...parties);
  return aDecider;
}

async function demarrer() {
  const s = await demarrerEcran("tickets");
  if (s === null) return;
  const contenu = el("main", { classe: "nt-page" }, el("p", { classe: "nt-attenue", texte: t("cadre.chargement") }));
  principal().appendChild(contenu);
  try {
    const r = await appeler("tickets", { session_identity: s.session_identity });
    const aDecider = rendre(contenu, r.valeur);
    // La liste est affichée ; les montants vérifiés arrivent ensuite, sans la retarder.
    void lireMontants(s.session_identity, aDecider);
  } catch (e) {
    remplacer(contenu);
    afficherErreur(contenu, e);
  }
}

void demarrer();
