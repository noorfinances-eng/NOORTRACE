// Écran « Tickets » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.3,
// EX-12.21, EX-14.2) : `tickets` sans `related_to` ; pour chaque ticket non
// décidé, une carte : l'outil annoncé, l'identifiant (lien vers son écran,
// que toute la carte prolonge), l'état en pastille, le demandeur, l'échéance,
// les votes `approuve` et `refuse` sur `effective_required`, l'état de la
// fenêtre de contestation (`contest_ms`, `contest`) ; puis le nombre de
// tickets ouverts par demandeur. Les instants s'affichent en mots ; l'instant
// exact reste dans l'attribut `datetime` de chacun.

import { el, ajouter, code, icone, message, remplacer } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { appeler } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, entete, instant, lienTicket, paragrapheCode, pastilleEtat, pluriel, principal, texteDuree, texteRestant } from "../commun/cadre.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// État de la fenêtre de contestation : une ligne par élément (délai, fenêtre en cours, objections, dernier instant du seuil).
function contestation(tk) {
  if (tk.contest_ms === undefined || !estObjet(tk.contest)) return [el("span", { classe: "fait-texte", texte: t("tickets.contestation.non_communiquee") })];
  if (tk.contest_ms === 0) return [el("span", { classe: "fait-texte", texte: t("tickets.contestation.aucune") })];
  const c = tk.contest;
  const lignes = [el("span", { classe: "fait-texte", texte: t("tickets.contestation.delai", { duree: texteDuree(tk.contest_ms) }) })];
  lignes.push(c.window_end === null ? el("span", { classe: "fait-second", texte: t("modele.contest.aucune_fenetre") }) : el("span", { classe: "fait-second" }, t("tickets.contestation.fin"), " ", instant(String(c.window_end))));
  const n = Array.isArray(c.objections) ? c.objections.length : 0;
  lignes.push(el("span", { classe: "fait-second", texte: n === 0 ? t("modele.contest.aucune_objection") : pluriel(n, "tickets.contestation.objection", "tickets.contestation.objections"), attributs: { "data-objections": String(n) } }));
  if (c.last_threshold_at !== null && c.last_threshold_at !== undefined) lignes.push(el("span", { classe: "fait-second" }, t("tickets.contestation.dernier_instant"), " ", instant(String(c.last_threshold_at))));
  return lignes;
}

// Un fait de la carte : libellé court au-dessus, valeur dessous.
function fait(nom, ...valeur) {
  return el("div", { classe: "nt-fait", attributs: { "data-champ": nom } }, el("dt", { texte: t(`tickets.colonne.${nom}`) }), el("dd", {}, ...valeur));
}

function votes(tk) {
  const approbations = pluriel(tk.votes_approuve, "votes.approbation", "votes.approbations");
  const refus = t("votes.refus", { n: tk.votes_refuse });
  const principal_ = tk.effective_required === null ? t("tickets.votes.sans_seuil", { approbations }) : t("tickets.votes", { approbations, requis: pluriel(tk.effective_required, "votes.requise", "votes.requises") });
  return el("span", { attributs: { "data-votes": "", "data-approuve": String(tk.votes_approuve), "data-refuse": String(tk.votes_refuse), "data-requis": tk.effective_required === null ? "" : String(tk.effective_required) } }, el("span", { texte: principal_ }), el("span", { classe: "fait-second", texte: refus }));
}

function carteTicket(tk) {
  const id = String(tk.ticket);
  const echeance =
    tk.deadline === null
      ? [el("span", { texte: t("modele.vide") })]
      : [el("span", { texte: texteRestant(Date.parse(String(tk.deadline)) - Date.now()) }), el("span", { classe: "fait-second" }, instant(String(tk.deadline)))];
  return el(
    "li",
    { classe: "nt-carte carte-ticket", attributs: { "data-ticket": id } },
    el(
      "div",
      { classe: "carte-ticket-tete" },
      el(
        "div",
        { classe: "carte-ticket-titre" },
        // Revue de sécurité de l'étape 8 (CT-3 EX-7.1) : lien seulement pour un identifiant d'EX-7.1.
        el("p", { classe: "nt-sur-titre" }, t("tickets.colonne.ticket"), " ", lienTicket(tk.ticket, "nt-fixe lien-carte")),
        el("h2", { attributs: { "data-champ": "outil" } }, code(String(tk.tool_announced))),
      ),
      el("div", { classe: "carte-ticket-etat" }, pastilleEtat(tk.state, { court: true }), el("span", { classe: "carte-ticket-ouvrir", attributs: { "aria-hidden": "true" } }, t("tickets.ouvrir"), icone("retour", "icone-suite"))),
    ),
    el("dl", { classe: "nt-faits faits-ticket" }, fait("demandeur", code(String(tk.launched_by))), fait("echeance", ...echeance), fait("votes", votes(tk)), fait("contestation", ...contestation(tk))),
  );
}

function rendre(conteneur, reponse) {
  const liste = estObjet(reponse) && Array.isArray(reponse.tickets) ? reponse.tickets : null;
  if (liste === null) {
    remplacer(conteneur, message("erreur", paragrapheCode("reponse_service_invalide", ["console."])));
    return;
  }
  const compte = el("p", { classe: "nt-chiffre", attributs: { "aria-label": pluriel(liste.length, "tickets.compte", "tickets.comptes") } }, el("span", { classe: "nt-chiffre-degrade", texte: String(liste.length) }), el("span", { classe: "nt-chiffre-unite", texte: t(liste.length >= 2 ? "tickets.unites" : "tickets.unite") }));
  const parties = [entete({ titre: t("tickets.titre"), sousTitre: t("tickets.sens"), etat: liste.length === 0 ? [] : [compte] })];
  if (liste.length === 0) {
    parties.push(el("div", { classe: "nt-vide", attributs: { id: "aucun-ticket" } }, icone("boite"), el("p", { classe: "nt-vide-titre", texte: t("tickets.aucun") }), el("p", { classe: "nt-vide-texte", texte: t("tickets.aucun_sens") })));
    remplacer(conteneur, ...parties);
    return;
  }
  const cartes = el("ul", { classe: "liste-nue liste-cartes", attributs: { id: "liste-tickets" } });
  const parDemandeur = new Map();
  for (const tk of liste) {
    const lb = String(tk.launched_by);
    parDemandeur.set(lb, (parDemandeur.get(lb) ?? 0) + 1);
    cartes.appendChild(carteTicket(tk));
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
}

async function demarrer() {
  const s = await demarrerEcran("tickets");
  if (s === null) return;
  const contenu = el("main", { classe: "nt-page" }, el("p", { classe: "nt-attenue", texte: t("cadre.chargement") }));
  principal().appendChild(contenu);
  try {
    const r = await appeler("tickets", { session_identity: s.session_identity });
    rendre(contenu, r.valeur);
  } catch (e) {
    remplacer(contenu);
    afficherErreur(contenu, e);
  }
}

void demarrer();
