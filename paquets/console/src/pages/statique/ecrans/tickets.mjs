// Écran « Tickets » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.3,
// EX-12.21, EX-14.2) : `tickets` sans `related_to` ; pour chaque ticket non
// décidé, l'identifiant (lien vers son écran), l'outil annoncé, le demandeur,
// l'échéance, les votes `approuve` et `refuse` sur `effective_required`,
// l'état de la fenêtre de contestation (`contest_ms`, `contest`) ; puis le
// nombre de tickets ouverts par demandeur.

import { el, ajouter, code, message, remplacer } from "../commun/dom.mjs";
import { t, texteCode } from "../commun/libelles.mjs";
import { appeler } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, principal, texteDuree } from "../commun/cadre.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function contestation(tk) {
  if (tk.contest_ms === undefined || !estObjet(tk.contest)) return el("span", { texte: t("tickets.contestation.non_communiquee") });
  if (tk.contest_ms === 0) return el("span", { texte: t("modele.regle.sans_contestation") });
  const c = tk.contest;
  const parties = [el("span", { texte: t("tickets.contestation.delai", { duree: texteDuree(tk.contest_ms) }) })];
  parties.push(" ", c.window_end === null ? el("span", { texte: t("modele.contest.aucune_fenetre") }) : el("span", {}, t("tickets.contestation.fin"), " ", code(String(c.window_end))));
  const n = Array.isArray(c.objections) ? c.objections.length : 0;
  parties.push(" ", el("span", { texte: n === 0 ? t("modele.contest.aucune_objection") : t("tickets.contestation.objections", { n }), attributs: { "data-objections": String(n) } }));
  if (c.last_threshold_at !== null && c.last_threshold_at !== undefined) parties.push(" ", el("span", {}, t("tickets.contestation.dernier_instant"), " ", code(String(c.last_threshold_at))));
  return el("span", {}, ...parties);
}

function rendre(conteneur, reponse) {
  const liste = estObjet(reponse) && Array.isArray(reponse.tickets) ? reponse.tickets : null;
  if (liste === null) {
    remplacer(conteneur, message("erreur", el("p", { texte: texteCode("reponse_service_invalide", ["console."]), attributs: { "data-code": "reponse_service_invalide" } })));
    return;
  }
  const parties = [el("h1", { texte: t("tickets.titre") })];
  if (liste.length === 0) {
    parties.push(el("p", { texte: t("tickets.aucun"), attributs: { id: "aucun-ticket" } }));
    remplacer(conteneur, ...parties);
    return;
  }
  const table = el("table", { classe: "table", attributs: { id: "liste-tickets" } });
  ajouter(
    table,
    el(
      "thead",
      {},
      el(
        "tr",
        {},
        ...["ticket", "outil", "demandeur", "echeance", "votes", "contestation"].map((c) => el("th", { texte: t(`tickets.colonne.${c}`), attributs: { scope: "col" } })),
      ),
    ),
  );
  const corps = el("tbody");
  const parDemandeur = new Map();
  for (const tk of liste) {
    const id = String(tk.ticket);
    const lb = String(tk.launched_by);
    parDemandeur.set(lb, (parDemandeur.get(lb) ?? 0) + 1);
    const votes = t("tickets.votes", {
      approuve: tk.votes_approuve,
      refuse: tk.votes_refuse,
      requis: tk.effective_required === null ? t("modele.vide") : tk.effective_required,
    });
    ajouter(
      corps,
      el(
        "tr",
        { attributs: { "data-ticket": id } },
        el("td", {}, el("a", { texte: id, attributs: { href: `/tickets/${id}` } }), " ", el("span", { classe: "discret", texte: t(`etat.${tk.state}`) })),
        el("td", {}, code(String(tk.tool_announced))),
        el("td", {}, code(lb)),
        el("td", {}, tk.deadline === null ? t("modele.vide") : code(String(tk.deadline))),
        el("td", { texte: votes, attributs: { "data-votes": "" } }),
        el("td", {}, contestation(tk)),
      ),
    );
  }
  table.appendChild(corps);
  parties.push(table);

  // EX-14.2 : nombre de tickets ouverts par demandeur.
  const resume = el("table", { classe: "table", attributs: { id: "par-demandeur" } });
  ajouter(resume, el("thead", {}, el("tr", {}, el("th", { texte: t("tickets.colonne.demandeur"), attributs: { scope: "col" } }), el("th", { texte: t("tickets.colonne.ouverts"), attributs: { scope: "col" } }))));
  const corpsResume = el("tbody");
  for (const [lb, n] of [...parDemandeur.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))) {
    ajouter(corpsResume, el("tr", { attributs: { "data-demandeur": lb } }, el("td", {}, code(lb)), el("td", { texte: String(n) })));
  }
  resume.appendChild(corpsResume);
  parties.push(el("h2", { texte: t("tickets.par_demandeur") }), resume);
  remplacer(conteneur, ...parties);
}

async function demarrer() {
  const s = await demarrerEcran("tickets");
  if (s === null) return;
  const contenu = el("main", { classe: "contenu" }, el("p", { classe: "discret", texte: t("cadre.chargement") }));
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
