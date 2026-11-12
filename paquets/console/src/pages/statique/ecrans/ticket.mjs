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

import { lancerDecouverte, rendreFournisseurs, demanderComptes, appelFournisseur, ecouter, textePanne } from "../commun/fournisseurs.mjs";

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
} from "noortrace-console/index.mjs";
import { el, ajouter, bouton, code, definitions, message, remplacer, vider } from "../commun/dom.mjs";
import { t, texteCode } from "../commun/libelles.mjs";
import { ErreurAppel, appeler, allerConnexion, envoiDepuis, erreurDeSession, lireSession, maintenant } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, principal, section, texteDuree, texteErreur, texteValeur } from "../commun/cadre.mjs";

const MOTIF_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;
const PREFIXES_VOTE = ["console."];

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
};

const zones = {
  lecture: el("div", { attributs: { id: "zone-lecture" } }),
  modele: el("div", { attributs: { id: "zone-modele" } }),
  lies: el("div", { attributs: { id: "zone-lies" } }),
  decision: el("div", { attributs: { id: "zone-decision" } }),
  motif: el("div", { attributs: { id: "zone-motif" } }),
  fournisseurs: el("div", { attributs: { id: "zone-fournisseurs" } }),
  comptes: el("div", { attributs: { id: "zone-comptes" } }),
  signature: el("div", { attributs: { id: "zone-signature" } }),
  resultat: el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } }),
  consignes: el("div", { attributs: { id: "zone-consignes" } }),
  recusation: el("div", { attributs: { id: "zone-recusation" } }),
  retrait: el("div", { attributs: { id: "zone-retrait" } }),
};

const champMotif = el("textarea", { attributs: { id: "motif", rows: "3", maxlength: "4096", "aria-describedby": "motif-avertissement" } });

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
    for (const z of ["modele", "decision", "signature", "consignes", "recusation", "retrait"]) vider(zones[z]);
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
    remplacer(zones.lies, el("h2", { texte: t("ticket.lies.titre") }));
    const z = el("div");
    zones.lies.appendChild(z);
    afficherErreur(z, e);
  }
}

// ---------------------------------------------------------------------------
// Affichage du modèle (EX-9.4)

function marqueArgument(statut) {
  return el("span", { classe: `marque marque-${statut}`, texte: t(`marque.${statut}`), attributs: { "data-marque": statut } });
}

function rendreModele() {
  const { modele, controle, raisons } = etat.pas1;
  const vue = etat.vue;
  const parties = [];
  parties.push(el("h1", {}, t("ticket.titre"), " ", code(modele.ticket)));

  // Raisons qui bloquent dès la lecture du pas 1, et avertissements.
  parties.push(rendreRaisons(raisons, modele, vue));
  parties.push(rendreAvertissements(modele.warnings, controle.warnings));

  // Outil.
  parties.push(
    section(
      t("modele.outil"),
      definitions([
        [t("modele.outil.annonce"), code(modele.tool.announced)],
        [t("modele.outil.origine"), code(modele.tool.original)],
        [t("modele.outil.alias"), code(modele.tool.server_alias)],
        [t("modele.outil.classe"), modele.tool.class],
      ]),
    ),
  );

  // Arguments, chacun avec sa marque.
  const table = el("table", { classe: "table", attributs: { id: "arguments" } });
  ajouter(table, el("thead", {}, el("tr", {}, el("th", { texte: t("modele.arguments.pointeur") }), el("th", { texte: t("modele.arguments.valeur") }), el("th", { texte: t("modele.arguments.marque") }))));
  const corps = el("tbody");
  for (const a of modele.arguments) {
    ajouter(corps, el("tr", { attributs: { "data-pointeur": a.pointer } }, el("td", {}, code(a.pointer === "" ? t("modele.arguments.racine") : a.pointer)), el("td", {}, code(texteValeur(a.value))), el("td", {}, marqueArgument(a.status))));
  }
  table.appendChild(corps);
  parties.push(section(t("modele.arguments"), table, el("p", { classe: "discret", texte: t("modele.arguments.non_verifiable_sens") })));

  // Effets déclarés prévus.
  const effets = el("ul", { classe: "effets", attributs: { id: "effets" } });
  if (modele.effects.length === 0) ajouter(effets, el("li", { texte: t("modele.effets.aucun") }));
  for (const e of modele.effects) {
    const nonResolus = new Map(e.unresolved.map((u) => [u.member, u.pointer]));
    const membre = (nom) => {
      if (nonResolus.has(nom)) {
        return el("span", { attributs: { "data-connu-apres-execution": nom } }, el("span", { classe: "marque", texte: t("marque.connu_apres_execution") }), " ", code(nonResolus.get(nom)));
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
          [t("modele.effets.action"), e.action],
          [t("modele.effets.objet"), membre("object")],
          [t("modele.effets.montant"), membre("amount")],
          [t("modele.effets.devise"), membre("currency")],
        ]),
      ),
    );
  }
  parties.push(section(t("modele.effets"), el("p", { classe: "discret", texte: t("modele.effets.declaratif") }), effets));

  // Règle déclenchée et délai de contestation.
  parties.push(
    section(
      t("modele.regle"),
      definitions([
        [t("modele.regle.policy_rule"), code(modele.rule.policy_rule)],
        [t("modele.regle.nom"), modele.rule.name],
        [t("modele.regle.description"), modele.rule.description === null ? t("modele.vide") : modele.rule.description],
        [t("modele.regle.niveau"), t(`niveau.${modele.rule.level}`)],
        [t("modele.regle.contestation"), modele.rule.contest_ms === 0 ? t("modele.regle.sans_contestation") : texteDuree(modele.rule.contest_ms)],
      ]),
    ),
  );

  // Ticket ouvrant (EX-5.4).
  if (modele.opening !== null) {
    const o = modele.opening;
    const memes = el("ul");
    for (const s of o.same_arguments) ajouter(memes, el("li", {}, code(s.pointer), " ", code(s.value)));
    parties.push(
      section(
        t("modele.ouvrant"),
        definitions([
          [t("modele.ouvrant.outil"), code(o.tool)],
          [t("modele.ouvrant.condition"), o.when === null ? t("modele.vide") : el("pre", { classe: "fixe", texte: JSON.stringify(o.when, null, 2) })],
          [t("modele.ouvrant.memes_arguments"), o.same_arguments.length === 0 ? t("modele.vide") : memes],
          [t("modele.ouvrant.portee"), t("modele.ouvrant.portee_texte", { max_calls: o.max_calls, duree: texteDuree(o.duration_ms) })],
        ]),
      ),
    );
  }

  // Intention.
  parties.push(
    section(
      t("modele.intention"),
      el("p", {}, modele.intent === null ? t("modele.vide") : modele.intent),
      el("p", {}, el("span", { classe: "marque", texte: t(modele.intent_status === "en_clair" ? "marque.intention_declaree" : "marque.non_verifiable"), attributs: { "data-intention": modele.intent_status } })),
    ),
  );

  // Délégation.
  const d = modele.delegation;
  const delegation = [
    section(
      t("modele.delegation"),
      definitions([
        [t("modele.delegation.launched_by"), el("span", {}, code(d.launched_by), " ", el("span", { classe: "marque", texte: t("marque.configuration_hote") }))],
        [t("modele.delegation.scope"), el("span", {}, code(d.scope), " ", el("span", { classe: "marque", texte: t("marque.configuration_hote") }))],
        [t("modele.delegation.on_behalf_of"), el("span", {}, d.on_behalf_of === null ? t("modele.vide") : code(d.on_behalf_of), " ", el("span", { classe: "marque", texte: t("marque.declare_hote") }))],
        [t("modele.delegation.run_id"), el("span", {}, d.run_id === null ? t("modele.vide") : code(d.run_id), " ", el("span", { classe: "marque", texte: t("marque.declare_hote") }))],
      ]),
      modele.separation_banner ? message("alerte", el("p", { texte: t("modele.separation_banniere"), attributs: { "data-code": "separation_non_verifiable" } })) : null,
    ),
  ];
  parties.push(...delegation);

  // Champs signés.
  parties.push(
    section(
      t("modele.signes"),
      definitions([
        [t("modele.signes.ticket"), code(modele.ticket)],
        [t("modele.signes.org_id"), code(modele.org_id)],
        [t("modele.signes.journal_id"), code(modele.journal_id)],
        [t("modele.signes.request_hash"), code(modele.request.request_hash)],
        [t("modele.signes.evenement"), t("modele.signes.evenement_texte", { seq: modele.request.seq, ts: modele.request.ts })],
      ]),
    ),
  );

  // Aucune empreinte de D_A avant le choix de la décision (EX-9.20, point 2 ;
  // contrat 3.4, révision de l'étape 6) : seule celle de la décision choisie
  // paraît, sur l'écran de signature ; `empreinte_divergente` montre les deux
  // (table de 13.14).

  // Échéance, contestation.
  const c = modele.contest;
  parties.push(
    section(
      t("modele.echeance"),
      definitions([
        [t("modele.echeance.deadline"), modele.deadline === null ? t("modele.vide") : code(modele.deadline)],
        [t("modele.echeance.restant"), modele.remaining_ms === null ? t("modele.vide") : modele.remaining_ms <= 0 ? t("modele.echeance.depassee") : texteDuree(modele.remaining_ms)],
        [t("modele.regle.contestation"), modele.rule.contest_ms === 0 ? t("modele.regle.sans_contestation") : texteDuree(modele.rule.contest_ms)],
        [t("modele.contest.fin_fenetre"), c.window_end === null ? t("modele.contest.aucune_fenetre") : code(c.window_end)],
        [t("modele.contest.objections"), c.objections.length === 0 ? t("modele.contest.aucune_objection") : el("ul", {}, ...c.objections.map((o) => el("li", {}, code(o.approver), " ", code(o.at))))],
        [t("modele.contest.dernier_instant"), c.last_threshold_at === null ? t("modele.vide") : code(c.last_threshold_at)],
      ]),
    ),
  );

  // Jeu figé, votes.
  const jeu = modele.approver_set;
  const votes = el("ul", { attributs: { id: "votes" } });
  if (modele.votes.length === 0) ajouter(votes, el("li", { texte: t("modele.votes.aucun") }));
  for (const v of modele.votes) {
    ajouter(votes, el("li", {}, code(v.approver), " ", t(`decision.${v.decision}`), " ", code(v.at), " ", v.reason === null ? t("modele.votes.sans_motif") : t("modele.votes.motif", { motif: v.reason })));
  }
  parties.push(
    section(
      t("modele.jeu"),
      jeu === null
        ? el("p", { texte: t("modele.jeu.non_fige") })
        : definitions([
            [t("modele.jeu.seuil"), t("modele.jeu.seuil_texte", { t: jeu.threshold.required, n: jeu.threshold.size })],
            [t("modele.jeu.seuil_effectif"), modele.effective_required === null ? t("modele.vide") : String(modele.effective_required)],
            [t("modele.jeu.membres"), el("ul", {}, ...jeu.members.map((m) => el("li", {}, code(m))))],
            [t("modele.jeu.source"), code(jeu.source)],
          ]),
      el("h3", { texte: t("modele.votes") }),
      votes,
    ),
  );

  remplacer(zones.modele, ...parties);
}

/** Liste des raisons qui bloquent ; pour `empreinte_divergente`, les deux empreintes de chaque décision. */
function rendreRaisons(raisons, modele, vue) {
  if (raisons.length === 0) return null;
  const ul = el("ul", { classe: "raisons" });
  for (const r of raisons) {
    const li = el("li", { attributs: { "data-code": r } }, texteCode(r, PREFIXES_VOTE));
    if (r === "empreinte_divergente" && modele.digests !== null) {
      const service = (d) => (vue.digests && typeof vue.digests[d] === "string" && /^0x[0-9a-f]{64}$/.test(vue.digests[d]) ? empreinte(vue.digests[d]) : t("modele.vide"));
      const table = el("table", { classe: "table", attributs: { id: "empreintes-divergentes" } });
      ajouter(table, el("thead", {}, el("tr", {}, el("th", { texte: t("divergence.decision") }), el("th", { texte: t("divergence.console") }), el("th", { texte: t("divergence.service") }))));
      for (const d of ["approuve", "refuse"]) {
        ajouter(table, el("tr", { attributs: { "data-decision": d } }, el("td", { texte: t(`decision.${d}`) }), el("td", {}, code(modele.digests[d].fingerprint)), el("td", {}, code(service(d)))));
      }
      ajouter(li, table, el("p", { texte: t("divergence.prevenir") }));
    }
    ul.appendChild(li);
  }
  return message("erreur", el("p", { texte: t("raisons.titre") }), ul);
}

function rendreAvertissements(warnings, avertissementsControle) {
  if (warnings.length === 0) return null;
  const ul = el("ul", { classe: "avertissements" });
  for (const w of warnings) {
    let txt = t(`avertissement.${w}`);
    if (w === "separation_incomplete") {
      const a = avertissementsControle.find((x) => x.code === "separation_incomplete");
      if (a) txt = t("avertissement.separation_incomplete", { adresses: a.addresses.join(", ") });
      else txt = t("avertissement.separation_incomplete", { adresses: "" });
    }
    ajouter(ul, el("li", { attributs: { "data-avertissement": w } }, `${txt} (${w})`));
  }
  return message("alerte", ul);
}

function rendreLies(reponse) {
  const parties = [el("h2", { texte: t("ticket.lies.titre") })];
  const related = reponse !== null && typeof reponse === "object" ? reponse.related : undefined;
  if (!Array.isArray(related)) {
    parties.push(el("p", { texte: t("ticket.lies.non_communique") }));
  } else if (related.length === 0) {
    parties.push(el("p", { texte: t("ticket.lies.aucun") }));
  } else {
    const ul = el("ul", { attributs: { id: "lies" } });
    for (const r of related) {
      ajouter(
        ul,
        el(
          "li",
          { attributs: { "data-ticket": String(r.ticket) } },
          el("a", { texte: String(r.ticket), attributs: { href: `/tickets/${String(r.ticket)}` } }),
          " ",
          t(`decision_scellee.${r.decision === "refuse" ? "refuse" : "expire"}`),
          " ",
          code(String(r.decided_at)),
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
// Décision (EX-9.5) : un clic puis une confirmation, pour chacune.

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
  const parties = [el("h2", { texte: t("decision.titre") })];
  const ouvert = etat.pas1 && etat.pas1.raisons.length === 0;
  if (etat.decision !== null) {
    parties.push(
      el("p", { attributs: { id: "decision-choisie", "data-decision": etat.decision } }, t("decision.choisie", { decision: t(`decision.${etat.decision}`) })),
      bouton(t("decision.changer"), () => {
        etat.decision = null;
        etat.aConfirmer = null;
        champMotif.disabled = false;
        abandonner();
        rendreModele();
        rendreDecision();
      }),
    );
  } else if (etat.aConfirmer !== null) {
    const d = etat.aConfirmer;
    parties.push(
      el("p", { texte: t("decision.confirmer_question", { decision: t(`decision.${d}`) }) }),
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
        { classe: "bouton principal" },
      ),
      bouton(t("action.annuler"), () => {
        etat.aConfirmer = null;
        rendreDecision();
      }),
    );
  } else {
    const groupe = el("div", { classe: "groupe-boutons" });
    for (const d of ["approuve", "refuse"]) {
      const b = bouton(
        libelleDecision(d),
        () => {
          etat.aConfirmer = d;
          rendreDecision();
        },
        { actif: ouvert },
      );
      b.setAttribute("data-decision", d);
      groupe.appendChild(b);
    }
    parties.push(groupe);
    if (!ouvert) parties.push(el("p", { classe: "discret", texte: t("decision.inactifs") }));
    else parties.push(el("p", { classe: "discret", texte: texteCode("decision_absente", PREFIXES_VOTE) }));
  }
  remplacer(zones.decision, ...parties);
}

function rendreMotif() {
  remplacer(
    zones.motif,
    el("label", { texte: t("motif.libelle"), attributs: { for: "motif" } }),
    champMotif,
    message("alerte", el("p", { texte: t("motif.avertissement"), attributs: { id: "motif-avertissement" } })),
  );
}

function motif() {
  const v = champMotif.value;
  return v === "" ? null : v;
}

// ---------------------------------------------------------------------------
// Fournisseur et adresse (EX-13.22, EX-13.23)

function rendreFournisseursEtComptes() {
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
    if (attente) parties.push(el("p", { classe: "discret", texte: t("portefeuille.comptes_demandes") }));
  }
  if (etat.adresse !== null) {
    parties.push(el("p", { attributs: { id: "adresse-retenue" } }, t("adresse.retenue"), " ", code(etat.adresse)));
  } else if (etat.comptes !== null && etat.annuaire !== null) {
    const active = adresseAttribuee(etat.annuaire);
    if (active !== null) {
      parties.push(message("alerte", el("p", { texte: texteCode("adresse_non_exposee", PREFIXES_VOTE), attributs: { "data-code": "adresse_non_exposee" } }), el("p", {}, t("adresse.active"), " ", code(active))));
    }
  }
  if (messageComptes !== null) {
    if (messageComptes.code === "adresse_retiree") {
      parties.push(message("alerte", el("p", { texte: t("adresse.retiree"), attributs: { "data-code": "adresse_retiree" } })));
    } else {
      const prefixes = ["comptes.", ...PREFIXES_VOTE];
      parties.push(
        message("erreur", el("p", { texte: textePanne(messageComptes.code, messageComptes.erreur, prefixes), attributs: { "data-code": messageComptes.code } })),
        etat.fournisseur !== null ? bouton(t("portefeuille.redemander"), () => void obtenirComptes()) : null,
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
  remplacer(zones.signature, el("p", { classe: "discret", texte: t("signature.verification") }));
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
  try {
    const session = sessionDuModele(lu.annuaire, identite(), lu.vue);
    modele = modeleAffichage(lu.vue, { session, decision: etat.decision, approver: etat.adresse, reason: motif(), now: maintenant() });
    controle = controleVote(lu.annuaire, identite(), "voter", etat.adresse, ticketDeControleVote(lu.vue));
  } catch {
    afficherErreur(zones.signature, new ErreurAppel("reponse_service_invalide"));
    return;
  }
  etat.annuaire = lu.annuaire;
  etat.lecture = { vue: lu.vue, annuaire: lu.annuaire, modele, controle };
  rendreSignature();
}

// ---------------------------------------------------------------------------
// Écran de signature (EX-9.18 à EX-9.20, EX-13.21)

function groupesFixes(x) {
  const p = el("p", { classe: "groupes fixe" });
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
  const panneau = el(
    "section",
    { classe: "bloc signature", attributs: { id: "ecran-signature", "data-decision": etat.decision } },
    el("h2", { texte: t("signature.titre", { decision: t(`decision.${etat.decision}`) }) }),
    definitions([
      [t("signature.adresse"), code(etat.adresse)],
      [t("signature.portefeuille"), etat.fournisseur.name],
    ]),
    el("h3", { texte: t("signature.d_a") }),
    el("p", {}, code(d.d_a, "fixe d-a")),
    groupesFixes(d.d_a),
    el("h3", { texte: t("signature.empreinte_d_a") }),
    el("p", { classe: "empreinte fixe", texte: d.fingerprint, attributs: { id: "empreinte-d-a" } }),
    el("h3", { texte: t("signature.eip191") }),
    el("p", { classe: "empreinte-secondaire fixe", texte: d.h_fingerprint, attributs: { id: "empreinte-h" } }),
    groupesFixes(d.h),
    l.modele.warnings.includes("condense_utf8") ? message("alerte", el("p", { texte: `${t("avertissement.condense_utf8")} (condense_utf8)`, attributs: { "data-avertissement": "condense_utf8" } })) : null,
    consignes,
    bouton(t("signature.demander"), () => void demanderSignature(), { actif: !etat.enCours, classe: "bouton principal" }),
    etat.enCours ? el("p", { classe: "discret", texte: t("signature.en_cours") }) : null,
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
    else if (s.etat === "identite_invalide") remplacer(zones.resultat, message("erreur", el("p", { texte: texteCode("identite_invalide", ["raison."]) })));
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
      remplacer(zones.resultat, message("erreur", el("p", { texte: texteCode(c.reason, PREFIXES_VOTE), attributs: { "data-code": c.reason } }), el("p", { texte: t("vote.non_envoye") })));
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
      remplacer(zones.resultat, message("info", el("p", { texte: t("vote.inscrit", { etat: v && typeof v.state === "string" ? t(`etat.${v.state}`) : t("modele.vide") }), attributs: { "data-resultat": "vote_inscrit" } })));
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
        remplacer(zones.resultat, message("info", el("p", { texte: `${t(essais > 0 ? "vote.deja_inscrit" : "vote.deja_inscrit_motif")} (vote_identique)`, attributs: { "data-resultat": "vote_identique" } })));
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
          bouton(t("vote.renvoyer"), () => {
            const g2 = etat.generation;
            void envoyerVote(corps, g2);
          }),
        );
        return;
      }
      if (erreurDeSession(e)) return;
      remplacer(zones.resultat, message("erreur", el("p", { texte: texteErreur(e), attributs: { "data-code": e instanceof ErreurAppel ? e.code : "erreur_page" } }), el("p", { texte: t("vote.non_inscrit") })));
      return;
    }
  }
}

function afficherPanne(codePanne, erreur, recouvree = null) {
  const parties = [el("p", { texte: textePanne(codePanne, erreur, PREFIXES_VOTE), attributs: { "data-code": codePanne } })];
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
  return el("div", { classe: "bloc-consignes" }, el("h3", { texte: t("consigne.titre") }), ol);
}

function rendreConsignes() {
  if (etat.vue === null) return vider(zones.consignes);
  if (zones.signature.querySelector("#consignes") !== null) return vider(zones.consignes);
  return remplacer(zones.consignes, rendreConsignesElement());
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
  const parties = [el("h2", { texte: t("recusation.titre") }), el("p", { texte: t("recusation.sens") })];
  if (etat.confirmation === "recuser") {
    parties.push(
      message("alerte", el("p", { texte: t("recusation.confirmer_texte") })),
      bouton(t("recusation.confirmer"), () => void recuser(), { classe: "bouton principal" }),
      bouton(t("action.annuler"), () => {
        etat.confirmation = null;
        rendreRecusation();
      }),
    );
  } else {
    parties.push(
      bouton(
        t("recusation.bouton"),
        () => {
          etat.confirmation = "recuser";
          rendreRecusation();
        },
        { actif: c.reason === null },
      ),
    );
    if (c.reason !== null) parties.push(el("p", { classe: "discret", texte: texteCode(c.reason, PREFIXES_VOTE), attributs: { "data-code": c.reason } }));
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
    remplacer(zone, message("erreur", el("p", { texte: texteCode(c.reason, PREFIXES_VOTE), attributs: { "data-code": c.reason } })));
    return;
  }
  try {
    const r = await appeler("recuser", { ticket: etat.ticket, approver: adresse, session_identity: identite() });
    remplacer(zone, message("info", el("p", { texte: t("recusation.inscrite", { etat: t(`etat.${r.valeur.state}`) }), attributs: { "data-resultat": "recusation_inscrite" } })));
    await lecturePas1();
    zones.recusation.appendChild(zone);
  } catch (e) {
    afficherErreur(zone, e);
  }
}

// ---------------------------------------------------------------------------
// Retrait (EX-7.15, EX-12.19, EX-13.18) : offert seulement si `actionRetrait` rend un `by`.

const champMotifRetrait = el("textarea", { attributs: { id: "motif-retrait", rows: "2", maxlength: "4096" } });

function rendreRetrait() {
  if (etat.annuaire === null || etat.vue === null) return vider(zones.retrait);
  const by = actionRetrait(etat.annuaire, identite(), { launched_by: etat.vue.request.delegation.launched_by });
  if (by === null) return vider(zones.retrait);
  const parties = [el("h2", { texte: t("retrait.titre") }), el("p", { texte: t("retrait.sens") }), el("p", {}, t("retrait.par"), " ", code(by))];
  parties.push(el("label", { texte: t("retrait.motif"), attributs: { for: "motif-retrait" } }), champMotifRetrait, el("p", { classe: "discret", texte: t("motif.avertissement") }));
  if (etat.confirmation === "retirer") {
    parties.push(
      message("alerte", el("p", { texte: t("retrait.confirmer_texte") })),
      bouton(t("retrait.confirmer"), () => void retirer(by), { classe: "bouton principal" }),
      bouton(t("action.annuler"), () => {
        etat.confirmation = null;
        rendreRetrait();
      }),
    );
  } else {
    parties.push(
      bouton(t("retrait.bouton"), () => {
        if (champMotifRetrait.value === "") {
          remplacer(zoneRetrait, message("erreur", el("p", { texte: t("retrait.motif_requis") })));
          return;
        }
        etat.confirmation = "retirer";
        rendreRetrait();
      }),
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
    remplacer(zoneRetrait, message("info", el("p", { texte: t("retrait.inscrit", { etat: t(`etat.${r.valeur.state}`) }), attributs: { "data-resultat": "retrait_inscrit" } })));
    await lecturePas1();
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
  if (!window.location.pathname.startsWith("/tickets/") || !MOTIF_TICKET.test(segment) || segment.length < 5 || segment.length > 128) {
    ajouter(racine, message("erreur", el("p", { texte: texteCode("ticket_inconnu", ["raison."]) })));
    return;
  }
  etat.ticket = segment;
  rendreMotif();
  ajouter(
    racine,
    el(
      "main",
      { classe: "contenu" },
      zones.lecture,
      zones.modele,
      zones.lies,
      el("section", { classe: "bloc vote", attributs: { id: "vote" } }, zones.decision, zones.motif, zones.fournisseurs, zones.comptes),
      zones.consignes,
      zones.signature,
      zones.resultat,
      el("section", { classe: "bloc" }, zones.recusation),
      el("section", { classe: "bloc" }, zones.retrait),
    ),
  );
  rendreFournisseursEtComptes();
  await Promise.all([lecturePas1(), lectureLies()]);
}

void demarrer();
