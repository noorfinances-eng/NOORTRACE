// Page de la console d'approbation de référence (spec/CT-3-approbations.md,
// révision 0.3, 13.15, EX-13.33 à EX-13.35).
//
// Elle offre le parcours a (portefeuille de navigateur découvert par
// EIP-6963 et appelé par EIP-1193), et par lui le parcours b ; ni le parcours
// c, ni le parcours d, ni window.ethereum. Elle ne détient, ne reçoit ni ne
// dérive aucune clé, ne garde rien dans le navigateur, construit le DOM par
// createElement et textContent seulement, et ne parle qu'à sa propre origine
// (méthodes POST /v0/<méthode> du serveur de console, 12.9). Tout ce qui est
// lié à la signature est recalculé par la bibliothèque scripts/lib/console.mjs
// (carte d'importation, intégrité sha384). Elle emploie les défauts de
// service_timeout_ms et de delai_signature_ms (10.3).

import * as K from "noortrace-console";

// ---------------------------------------------------------------------------
// Découverte EIP-6963 : l'écouteur est posé avant toute autre opération
// (EX-13.22, pas 1) et n'est jamais retiré. Le DOM n'est touché qu'une fois
// la page prête (une annonce synchrone arrive pendant ecouter).
// ---------------------------------------------------------------------------
const etat = {
  session: null,
  annuaire: null,
  fournisseur: null,
  comptes: [],
  adresse: null,
  ticket: null,
  vue: null,
  generation: 0,
  decision: null,
  enAttente: null,
  requeteEnCours: null,
  compteInscription: null,
  fournisseurs: [],
  rejets: [],
  annoncesTardives: false,
  motif: "",
  ecranSignature: null,
  resultat: null,
  inscription: null,
};
let pret = false;
const decouverte = new K.Decouverte({ auChangement: (liste, rejets) => {
  etat.fournisseurs = liste;
  etat.rejets = rejets;
  if (pret) afficherFournisseurs();
} });
decouverte.ecouter(window, Event);
// EX-13.22, pas 6 : « aucun portefeuille » 1 000 ms après le pas 1, et pas avant.
setTimeout(() => {
  etat.annoncesTardives = true;
  if (pret) afficherFournisseurs();
}, K.DELAI_ANNONCE_MS);

const DELAI_SERVICE_MS = 10000;
const LIBELLES = {
  evenement_invalide: "l'événement retenue servi ne se vérifie pas",
  piece_invalide: "la pièce « arguments » servie ne se vérifie pas",
  champ_different: "un champ affiché diffère de l'événement retenue",
  argument_different: "un argument affiché diffère de la pièce",
  argument_absent_de_l_affichage: "un argument de la pièce manque à l'affichage",
  empreinte_divergente: "le service a calculé un autre condensé que la console : aucune signature n'est demandée",
  ticket_clos_aux_votes: "le ticket ne reçoit plus de votes",
  jeu_non_fige: "le jeu d'approbateurs n'est pas figé",
  identite_inconnue: "votre identité n'a pas d'entrée dans l'annuaire des approbateurs",
  identite_desactivee: "votre entrée de l'annuaire est désactivée",
  adresse_non_attribuee: "cette adresse n'est pas l'adresse active que l'annuaire vous attribue",
  hors_jeu: "votre adresse n'est pas membre du jeu figé",
  auto_approbation: "votre adresse est celle du demandeur",
  recuse: "vous vous êtes récusé pour ce ticket",
  session_du_demandeur: "vous êtes le demandeur de ce ticket",
  motif_trop_long: "le motif dépasse 1 024 caractères",
  decision_absente: "aucune décision n'est choisie",
  aucun_fournisseur: "aucun portefeuille ne s'est annoncé",
  fournisseur_non_choisi: "choisissez un portefeuille",
  annonce_en_double: "deux portefeuilles revendiquent le même identifiant : une extension en imite une autre ; prévenez l'administrateur, et si votre portefeuille est exclu, désactivez l'extension en cause et rechargez la page",
  annonce_invalide: "annonce de portefeuille invalide, ignorée",
  adresse_non_exposee: "le portefeuille n'expose pas l'adresse active que l'annuaire vous attribue",
  refus_approbateur: "signature refusée dans le portefeuille ; aucun vote n'a été envoyé",
  non_autorise: "le portefeuille n'a pas autorisé cette page",
  methode_non_prise_en_charge: "ce portefeuille ne peut pas voter",
  deconnecte: "portefeuille indisponible (déconnecté)",
  chaine_deconnectee: "portefeuille indisponible (chaîne déconnectée) ; aucun changement de réseau n'est demandé",
  erreur_portefeuille: "erreur du portefeuille",
  reponse_invalide: "réponse du portefeuille invalide ; aucun vote",
  delai_depasse: "délai dépassé : la console n'attend plus la signature et ne l'enverra pas",
  signature_invalide: "signature mal formée ; aucun vote",
  adresse_differente: "la signature ne vient pas de l'adresse choisie ; aucun vote",
  service_indisponible: "service indisponible",
  session_non_autorisee: "le service refuse cette session pour ce ticket",
};
/** Libellés propres à l'inscription (13.14, pannes de l'inscription) : jamais « vote ». */
const LIBELLES_INSCRIPTION = {
  message_invalide: "le texte d'inscription du service n'est pas celui que la console reconstruit ; aucune signature n'est demandée : prévenez l'administrateur",
  origine_differente: "le texte d'inscription nomme une autre origine que cette page ; aucune signature n'est demandée : prévenez l'administrateur",
  identite_differente: "le texte d'inscription nomme une autre identité que votre session ; aucune signature n'est demandée : prévenez l'administrateur",
  adresse_differente: "le texte ou la signature ne correspond pas au compte choisi ; aucune inscription n'a été envoyée",
  refus_approbateur: "signature refusée dans le portefeuille ; aucune inscription n'a été envoyée",
  signature_invalide: "signature mal formée ; aucune inscription n'a été envoyée",
  reponse_invalide: "réponse du portefeuille invalide ; aucune inscription n'a été envoyée",
  delai_depasse: "délai dépassé : la console n'attend plus la signature et n'enverra pas l'inscription",
  inscription_expiree: "le message d'inscription a expiré : demandez un nouveau message",
  nonce_inconnu: "ce message a été remplacé par une demande plus récente : demandez un nouveau message",
  nonce_deja_utilise: "ce message a déjà été présenté : demandez un nouveau message",
  adresse_deja_attribuee: "cette adresse est déjà dans l'annuaire : si vous la détenez, prévenez l'administrateur",
  identite_desactivee: "votre entrée de l'annuaire est désactivée : prévenez l'administrateur",
  organisation_differente: "le message nomme une autre organisation : prévenez l'administrateur",
};
const STATUTS = { verifie: "vérifié", non_verifiable: "non vérifiable par la console", different: "différent de la pièce" };
/** Marque de l'intention (EX-9.4, contrôle 4 d'EX-9.15), selon intent_status du modèle. */
const MARQUES_INTENTION = { en_clair: "déclarée par l'agent, non vérifiée", reference_non_verifiable: "non vérifiable par la console : l'événement retenu la porte par une référence" };

/** Texte d'un effet déclaré prévu (EX-9.4) : un membre listé dans unresolved est « connu après exécution » (EX-12.14). */
function texteEffet(e) {
  const nonResolu = (membre) => e.unresolved.find((u) => u.member === membre);
  const valeur = (membre) => {
    const u = nonResolu(membre);
    return u ? `connu après exécution (${u.pointer})` : e[membre] ?? "—";
  };
  const montant = e.amount === null && e.currency === null && !nonResolu("amount") && !nonResolu("currency") ? "aucun" : `${valeur("amount")} ${valeur("currency")}`;
  return `${e.system}, ${e.action} ; objet ${valeur("object")} ; montant ${montant}`;
}

// ---------------------------------------------------------------------------
// DOM : createElement et textContent seulement (EX-13.33, 8 ; EX-13.34, 4).
// ---------------------------------------------------------------------------
function el(tag, { testid = null, texte = null, classe = null, attrs = {} } = {}, enfants = []) {
  const n = document.createElement(tag);
  if (testid) n.setAttribute("data-testid", testid);
  if (classe) n.className = classe;
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (texte !== null) n.textContent = texte;
  for (const e of enfants) if (e) n.appendChild(e);
  return n;
}
const vider = (n) => {
  while (n.firstChild) n.removeChild(n.firstChild);
};
const bouton = (texte, testid, action, actif = true) => {
  const b = el("button", { testid, texte, attrs: { type: "button" } });
  b.disabled = !actif;
  b.addEventListener("click", action);
  return b;
};
const raison = (code, testid = "raison") => el("li", { testid, attrs: { "data-code": code }, texte: `${LIBELLES[code] ?? code} (${code})` });
const raisonInscription = (code) => el("li", { testid: "raison", attrs: { "data-code": code }, texte: `${LIBELLES_INSCRIPTION[code] ?? LIBELLES[code] ?? code} (${code})` });

const racine = document.getElementById("console");
const zones = {
  session: el("section", { testid: "zone-session" }),
  portefeuille: el("section", { testid: "zone-portefeuille" }),
  tickets: el("section", { testid: "zone-tickets" }),
  ticket: el("section", { testid: "zone-ticket" }),
  inscription: el("section", { testid: "zone-inscription" }),
  etat: el("p", { testid: "etat", attrs: { role: "status" } }),
};
racine.appendChild(el("h1", { texte: "Console d'approbation NOORTRACE (référence)" }));
for (const z of Object.values(zones)) racine.appendChild(z);
const message = (texte) => {
  zones.etat.textContent = texte;
};
pret = true;
afficherFournisseurs();

// ---------------------------------------------------------------------------
// Canal vers le serveur de console (12.9, EX-12.1) : JSON strict, même origine.
// ---------------------------------------------------------------------------
async function appel(methode, corps) {
  const ctrl = new AbortController();
  const minuteur = setTimeout(() => ctrl.abort(), DELAI_SERVICE_MS);
  let rep;
  try {
    rep = await fetch(`/v0/${methode}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps), signal: ctrl.signal, credentials: "same-origin" });
  } catch {
    return { ok: false, code: "service_indisponible", corps: null };
  } finally {
    clearTimeout(minuteur);
  }
  let valeur = null;
  try {
    valeur = K.analyserJSONStrict(new Uint8Array(await rep.arrayBuffer()));
  } catch {
    return { ok: false, code: "service_indisponible", corps: null };
  }
  if (!rep.ok) return { ok: false, code: typeof valeur?.error?.code === "string" ? valeur.error.code : "service_indisponible", corps: valeur };
  return { ok: true, code: null, corps: valeur };
}

/** Requête au fournisseur : une promesse, même si request lève ou ne rend pas de promesse ; l'issue au format de verifierReponse. */
function appelFournisseur(fournisseur, requete) {
  return Promise.resolve()
    .then(() => fournisseur.provider.request(requete))
    .then((result) => ({ result }), (e) => ({ error: { code: Number.isInteger(e?.code) ? e.code : null, message: typeof e?.message === "string" ? e.message : "" } }));
}

// ---------------------------------------------------------------------------
// Session, annuaire, tickets
// ---------------------------------------------------------------------------
async function demarrer() {
  const s = await appel("session", {});
  if (!s.ok || !K.estIdentite(s.corps?.session_identity)) {
    zones.session.appendChild(el("p", { testid: "session-refusee", texte: "Session refusée : identité absente ou non canonique (identite_invalide)." }));
    return;
  }
  etat.session = s.corps.session_identity;
  zones.session.appendChild(el("p", { testid: "session", texte: `Identité de session : ${etat.session}` }));
  afficherFournisseurs();
  await lireAnnuaire();
  const t = await appel("tickets", { session_identity: etat.session });
  afficherTickets(t.ok ? t.corps.tickets : null, t.code);
  afficherInscription();
}

/** Lit l'annuaire de la session, puis retient l'adresse active si le portefeuille l'expose (EX-13.23). */
async function lireAnnuaire() {
  const a = await appel("annuaire", { session_identity: etat.session });
  etat.annuaire = a.ok ? a.corps : null;
  retenirAdresse();
  return a;
}

function adresseActive() {
  const e = etat.annuaire?.entries?.find((x) => x.session_identity === etat.session);
  if (!e || !e.active) return null;
  return e.addresses.find((x) => x.state === "active")?.address ?? null;
}

/**
 * Adresse retenue pour un vote : l'adresse active de l'entrée, si le
 * portefeuille l'expose (EX-13.23). Quand elle change, la requête en cours
 * et l'écran de signature sont abandonnés (13.14).
 */
function retenirAdresse() {
  const active = adresseActive();
  const avant = etat.adresse;
  etat.adresse = etat.fournisseur && active && etat.comptes.includes(active) ? active : null;
  if (avant !== etat.adresse) {
    abandonnerRequete();
    etat.ecranSignature = null;
  }
}

function afficherTickets(liste, code) {
  vider(zones.tickets);
  zones.tickets.appendChild(el("h2", { texte: "Tickets en attente" }));
  if (liste === null) {
    zones.tickets.appendChild(el("ul", {}, [raison(code)]));
    return;
  }
  const ul = el("ul", { testid: "tickets" });
  for (const t of liste) {
    ul.appendChild(el("li", { attrs: { "data-ticket": t.ticket } }, [
      el("span", { texte: `${t.ticket} : ${t.tool_announced}, demandé par ${t.launched_by}, échéance ${t.deadline ?? "—"}, ${t.votes_approuve} approbation(s), ${t.votes_refuse} refus, seuil ${t.effective_required ?? "—"} ` }),
      bouton("Ouvrir", "ouvrir-ticket", () => ouvrirTicket(t.ticket)),
    ]));
  }
  zones.tickets.appendChild(ul);
}

// ---------------------------------------------------------------------------
// Portefeuilles (EX-13.22, EX-13.23)
// ---------------------------------------------------------------------------
function afficherFournisseurs() {
  vider(zones.portefeuille);
  zones.portefeuille.appendChild(el("h2", { texte: "Portefeuille" }));
  const ul = el("ul", { testid: "fournisseurs" });
  for (const f of etat.fournisseurs) {
    const img = el("img", { attrs: { alt: "", width: "24", height: "24" } });
    img.src = f.icon; // icône EIP-6963 rendue par <img> seulement, jamais comme HTML ni SVG en ligne
    const choisi = etat.fournisseur?.uuid === f.uuid;
    ul.appendChild(el("li", { testid: "fournisseur", attrs: { "data-uuid": f.uuid } }, [
      img,
      el("span", { testid: "nom-fournisseur", texte: ` ${f.name} ` }),
      el("span", { classe: "secondaire", texte: `${f.rdns} (déclaré par le portefeuille, non vérifié) ` }),
      choisi ? el("strong", { testid: "fournisseur-choisi", texte: "choisi" }) : bouton("Choisir ce portefeuille", "choisir-fournisseur", () => choisirFournisseur(f.uuid)),
    ]));
  }
  zones.portefeuille.appendChild(ul);
  if (etat.fournisseurs.length === 0 && etat.annoncesTardives) zones.portefeuille.appendChild(el("p", { testid: "aucun-fournisseur", attrs: { "data-code": "aucun_fournisseur" }, texte: `Aucun portefeuille ne s'est annoncé (aucun_fournisseur) ; la console continue d'écouter.` }));
  if (etat.rejets.length) zones.portefeuille.appendChild(el("ul", { testid: "annonces-ecartees" }, etat.rejets.map((r) => raison(r.reason, "annonce-ecartee"))));
  if (etat.fournisseur) zones.portefeuille.appendChild(el("p", { testid: "comptes", texte: `Adresses exposées : ${etat.comptes.join(", ") || "aucune"}${etat.adresse ? ` ; adresse retenue : ${etat.adresse}` : ""}` }));
  // EX-13.29 : l'adresse active attribuée est affichée quand le portefeuille ne l'expose pas.
  const active = adresseActive();
  if (etat.fournisseur && !etat.adresse && active) zones.portefeuille.appendChild(el("p", { testid: "adresse-attribuee", attrs: { "data-adresse": active }, texte: `Adresse active que l'annuaire vous attribue : ${active} ; sélectionnez ce compte dans votre portefeuille.` }));
  // Après un refus (4001) ou une liste vide : nouvel essai sur action explicite seulement (13.14).
  if (etat.fournisseur && etat.comptes.length === 0) zones.portefeuille.appendChild(bouton("Redemander l'accès aux comptes", "redemander-comptes", () => demanderComptes(true)));
}

async function choisirFournisseur(uuid) {
  const f = etat.fournisseurs.find((x) => x.uuid === uuid);
  if (!f) return;
  abandonnerRequete();
  etat.fournisseur = f;
  etat.comptes = [];
  retenirAdresse();
  if (typeof f.provider.on === "function") {
    f.provider.on("accountsChanged", (liste) => {
      if (etat.fournisseur !== f) return;
      etat.comptes = Array.isArray(liste) ? liste.filter((a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a)).map((a) => a.toLowerCase()) : [];
      retenirAdresse();
      if (etat.compteInscription && !etat.comptes.includes(etat.compteInscription)) {
        abandonnerRequete();
        etat.compteInscription = null;
        etat.inscription = null;
      }
      afficherFournisseurs();
      afficherTicket();
      afficherInscription();
    });
    f.provider.on("disconnect", () => {
      if (etat.fournisseur !== f) return;
      abandonnerRequete();
      message(`${LIBELLES.deconnecte} (deconnecte)`);
    });
  }
  await demanderComptes(true);
}

async function demanderComptes(reessayer) {
  const f = etat.fournisseur;
  const r = await appelFournisseur(f, { method: "eth_requestAccounts" });
  if (etat.fournisseur !== f) return;
  if (r.error) {
    const code = Number.isInteger(r.error.code) && K.CODES_EIP1193[r.error.code] ? K.CODES_EIP1193[r.error.code] : "erreur_portefeuille";
    if (code === "non_autorise" && reessayer) return demanderComptes(false);
    message(`${LIBELLES[code]} (${code})`);
    afficherFournisseurs();
    return;
  }
  const comptes = r.result;
  if (!Array.isArray(comptes) || !comptes.every((a) => typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a))) {
    message(`${LIBELLES.reponse_invalide} (reponse_invalide)`);
    return;
  }
  etat.comptes = comptes.map((a) => a.toLowerCase());
  retenirAdresse();
  afficherFournisseurs();
  afficherTicket();
  afficherInscription();
}

// ---------------------------------------------------------------------------
// Ticket : vue, modèle d'affichage, décision (EX-9.4, EX-9.5, EX-9.15, EX-13.18)
// ---------------------------------------------------------------------------
function ticketDeControle(vue) {
  return {
    launched_by: vue.request.delegation.launched_by,
    self_approval: vue.separation.self_approval,
    policy_requester_addresses: vue.separation.requester_addresses,
    directory_requester_addresses: vue.separation.requester_directory_addresses,
    members: vue.approver_set === null ? null : vue.approver_set.members,
  };
}

function modele(vue, decision, motif) {
  const session = K.sessionDepuisAnnuaire(etat.annuaire ?? { entries: [] }, etat.session, vue.request.delegation.launched_by);
  return K.modeleAffichage(vue, { session, decision, approver: etat.adresse, reason: motif, now: new Date().toISOString() });
}

/** Raisons qui empêchent d'offrir Approuver et Refuser, avant le choix de la décision. */
function raisonsAvantDecision(m) {
  if (!etat.fournisseur) return ["fournisseur_non_choisi"];
  const out = [];
  let adresse = etat.adresse;
  if (!adresse) {
    out.push("adresse_non_exposee");
    adresse = etat.comptes[0] ?? null;
  }
  if (adresse && etat.annuaire) {
    const c = K.controleVote(etat.annuaire, etat.session, "voter", adresse, ticketDeControle(etat.vue));
    if (!c.allowed) out.push(c.reason);
  }
  for (const r of m.blocking) if (r !== "decision_absente" && !(r === "adresse_non_attribuee" && !etat.adresse) && !out.includes(r)) out.push(r);
  return out;
}

/** EX-9.17 : sur un écart, les deux empreintes abrégées de chaque décision, celle de la console et celle du service. */
function empreintesDivergentes(m, vue) {
  const ul = el("ul", { testid: "empreintes-divergentes" });
  for (const d of ["approuve", "refuse"]) {
    const service = vue.digests?.[d];
    const empreinteService = typeof service === "string" && /^0x[0-9a-f]{64}$/.test(service) ? K.empreinte(service) : "valeur mal formée";
    const differe = service !== m.digests[d].d_a;
    ul.appendChild(el("li", { testid: "empreintes-decision", attrs: { "data-decision": d, "data-differe": String(differe) }, texte: `${d} : console ${m.digests[d].fingerprint} ; service ${empreinteService}${differe ? " (différente)" : " (égale)"}` }));
  }
  ul.appendChild(el("li", { texte: "Prévenez l'administrateur de l'organisation par un autre canal que la console." }));
  return ul;
}

async function ouvrirTicket(ticket) {
  abandonnerRequete();
  const gen = ++etat.generation;
  etat.ticket = ticket;
  etat.vue = null;
  etat.decision = null;
  etat.enAttente = null;
  etat.ecranSignature = null;
  etat.resultat = null;
  etat.motif = "";
  vider(zones.ticket);
  const v = await appel("consulter", { ticket, session_identity: etat.session });
  await lireAnnuaire();
  if (etat.generation !== gen) return; // un autre ticket a été ouvert pendant l'attente
  if (!v.ok || v.corps?.ticket !== ticket) {
    vider(zones.ticket);
    zones.ticket.appendChild(el("ul", { testid: "raisons" }, [raison(v.ok ? "service_indisponible" : v.code)]));
    return;
  }
  etat.vue = v.corps;
  afficherTicket();
}

function ligne(testid, libelle, valeur) {
  return el("div", { testid, classe: "ligne" }, [el("span", { classe: "libelle", texte: `${libelle} : ` }), el("span", { classe: "valeur", texte: valeur })]);
}

function afficherTicket() {
  vider(zones.ticket);
  if (!etat.vue) return;
  const vue = etat.vue;
  let m;
  try {
    m = modele(vue, null, null);
  } catch {
    zones.ticket.appendChild(el("ul", { testid: "raisons" }, [raison("service_indisponible")]));
    return;
  }
  const z = zones.ticket;
  z.appendChild(el("h2", { texte: `Ticket ${vue.ticket} (${vue.state})` }));
  const sec = el("div", { testid: "modele" });
  sec.appendChild(ligne("outil", "Outil", `${m.tool.announced} (nom d'origine ${m.tool.original}, serveur ${m.tool.server_alias}, classe ${m.tool.class})`));
  const table = el("table", { testid: "arguments" }, [el("tr", {}, [el("th", { texte: "Argument" }), el("th", { texte: "Valeur en clair" }), el("th", { texte: "Contrôle" })])]);
  for (const a of m.arguments) table.appendChild(el("tr", { testid: "argument", attrs: { "data-pointer": a.pointer, "data-statut": a.status } }, [el("td", { texte: a.pointer || "/" }), el("td", { texte: JSON.stringify(a.value) }), el("td", { testid: "marque", texte: STATUTS[a.status] })]));
  sec.appendChild(table);
  sec.appendChild(el("p", { classe: "secondaire", texte: "« Non vérifiable par la console » : la valeur affichée vient du service seul (forme rédigée, chemin supprimé ou intention par référence) ; ni la console ni la signature ne la lient. Si elle compte pour votre décision, confrontez-la aux sources de l'organisation." }));
  sec.appendChild(ligne("effets", "Effets déclarés prévus (non liés à la signature)", m.effects.length ? m.effects.map(texteEffet).join(" | ") : "aucun"));
  sec.appendChild(ligne("regle", "Règle", `${m.rule.policy_rule} — ${m.rule.description ?? "sans description"} — niveau ${m.rule.level}, délai de contestation ${m.rule.contest_ms} ms`));
  if (m.opening) sec.appendChild(ligne("ouverture", "Ouvre une fenêtre", `outil ${m.opening.tool} seulement ; au plus ${m.opening.max_calls} appels pendant ${m.opening.duration_ms} ms ; condition ${JSON.stringify(m.opening.when)} ; mêmes valeurs ${JSON.stringify(m.opening.same_arguments)}`));
  const intention = ligne("intention", `Intention (${MARQUES_INTENTION[m.intent_status]})`, m.intent ?? "—");
  intention.setAttribute("data-statut", m.intent_status);
  sec.appendChild(intention);
  sec.appendChild(ligne("delegation", "Délégation", `lancé par ${m.delegation.launched_by} et portée ${m.delegation.scope} (configuration de la connexion d'hôte) ; pour le compte de ${m.delegation.on_behalf_of ?? "—"} et exécution ${m.delegation.run_id ?? "—"} (déclaré par l'hôte, non vérifié)`));
  if (m.separation_banner) sec.appendChild(el("p", { testid: "bandeau-separation", classe: "bandeau", texte: "Séparation non vérifiable pour ce demandeur." }));
  sec.appendChild(ligne("demande", "Demande retenue", `request_hash ${m.request.request_hash}, seq ${m.request.seq}, ts ${m.request.ts}`));
  sec.appendChild(ligne("ticket", "Ticket, organisation, journal", `${m.ticket}, ${m.org_id}, ${m.journal_id}`));
  sec.appendChild(ligne("echeance", "Échéance", `${m.deadline ?? "—"} (reste ${m.remaining_ms === null ? "—" : Math.max(0, Math.floor(m.remaining_ms / 1000)) + " s"}) ; fin de fenêtre ${m.contest.window_end ?? "—"} ; objections ${m.contest.objections.length} ; seuil à atteindre avant ${m.contest.last_threshold_at ?? "—"}`));
  sec.appendChild(ligne("jeu", "Jeu figé", m.approver_set === null ? "non figé" : `seuil ${m.effective_required} sur ${m.approver_set.threshold.size} ; membres ${m.approver_set.members.join(", ")} ; source ${m.approver_set.source}`));
  sec.appendChild(ligne("votes", "Votes exprimés", m.votes.map((x) => `${x.approver} ${x.decision}${x.reason ? ` (« ${x.reason} »)` : ""} à ${x.at}`).join(" ; ") || "aucun"));
  z.appendChild(sec);
  const avert = [...m.warnings];
  z.appendChild(el("ul", { testid: "avertissements" }, avert.map((w) => el("li", { testid: "avertissement", attrs: { "data-code": w }, texte: w }))));
  const raisons = raisonsAvantDecision(m);
  z.appendChild(el("ul", { testid: "raisons" }, raisons.map((r) => raison(r))));
  if (m.blocking.includes("empreinte_divergente") && m.digests) z.appendChild(empreintesDivergentes(m, vue));
  // Décision : aucun choix présélectionné, même nombre d'actions pour approuver et refuser (EX-9.5).
  const motif = el("textarea", { testid: "motif", attrs: { maxlength: "4096", rows: "2", "aria-label": "Motif" } });
  motif.value = etat.motif ?? "";
  motif.addEventListener("input", () => (etat.motif = motif.value));
  z.appendChild(el("p", { classe: "secondaire", texte: "Le motif ne doit contenir aucune donnée personnelle (ni nom, ni courriel, ni IBAN) : celui du vote qui complète le seuil est écrit dans le journal sans pouvoir être effacé. Exemple : « Constat et facture concordants »." }));
  z.appendChild(motif);
  const actif = raisons.length === 0;
  const boutons = el("div", { testid: "decision" });
  if (etat.enAttente === null) {
    boutons.appendChild(bouton("Approuver", "approuver", () => preparerDecision("approuve"), actif));
    boutons.appendChild(bouton("Refuser", "refuser", () => preparerDecision("refuse"), actif));
  } else {
    boutons.appendChild(el("span", { texte: `Décision : ${etat.enAttente === "approuve" ? "approuver" : "refuser"}. ` }));
    boutons.appendChild(bouton(etat.enAttente === "approuve" ? "Confirmer : approuver" : "Confirmer : refuser", "confirmer", () => confirmerDecision(), actif));
    boutons.appendChild(bouton("Annuler", "annuler-decision", () => {
      etat.enAttente = null;
      afficherTicket();
    }));
  }
  z.appendChild(boutons);
  if (etat.ecranSignature) z.appendChild(etat.ecranSignature);
  if (etat.resultat) z.appendChild(etat.resultat);
}

function preparerDecision(decision) {
  abandonnerRequete();
  etat.enAttente = decision;
  etat.decision = null;
  etat.ecranSignature = null;
  etat.resultat = null;
  afficherTicket();
}

function resultatRaisons(codes) {
  return el("ul", { testid: "resultat", attrs: { "data-code": codes[0] } }, codes.map((r) => raison(r)));
}

/** Après le choix : nouvelle vue, nouvel annuaire, contrôles d'EX-9.15 et d'EX-13.18, puis écran de signature. */
async function confirmerDecision() {
  const gen = etat.generation;
  const ticket = etat.ticket;
  const decision = etat.enAttente;
  etat.enAttente = null;
  etat.decision = decision;
  etat.resultat = null;
  etat.ecranSignature = null;
  const v = await appel("consulter", { ticket, session_identity: etat.session });
  const a = await lireAnnuaire();
  if (etat.generation !== gen) return; // un autre ticket a été ouvert pendant l'attente
  if (!v.ok || !a.ok || v.corps?.ticket !== ticket) {
    etat.resultat = resultatRaisons([!v.ok ? v.code : !a.ok ? a.code : "service_indisponible"]);
    afficherTicket();
    return;
  }
  etat.vue = v.corps;
  const motif = etat.motif ? etat.motif : null;
  let m;
  let c;
  try {
    m = modele(etat.vue, decision, motif);
    c = etat.adresse ? K.controleVote(etat.annuaire, etat.session, "voter", etat.adresse, ticketDeControle(etat.vue)) : { allowed: false, reason: "adresse_non_exposee" };
  } catch {
    etat.resultat = resultatRaisons(["service_indisponible"]);
    afficherTicket();
    return;
  }
  const bloquants = [...m.blocking];
  if (!c.allowed && !bloquants.includes(c.reason)) bloquants.push(c.reason);
  if (bloquants.length) {
    const ul = resultatRaisons(bloquants);
    if (bloquants.includes("empreinte_divergente") && m.digests) ul.appendChild(el("li", {}, [empreintesDivergentes(m, etat.vue)]));
    etat.resultat = ul;
    afficherTicket();
    return;
  }
  etat.ecranSignature = ecranSignature(m, decision, motif, etat.vue);
  afficherTicket();
}

/**
 * Consignes d'EX-9.20, points 1 à 7, telles que la règle les écrit (condition
 * d'origine comprise), affichées sur l'écran de signature. `origine` est la
 * console_origin de l'annuaire.
 */
function consignesSignature(origine) {
  return [
    "Lire la demande : outil, chaque argument et sa marque (« vérifié », « non vérifiable par la console »), effets prévus (« connu après exécution » pour une valeur tirée du résultat), règle, délégation, intention marquée « déclarée par l'agent, non vérifiée », ou « non vérifiable par la console » quand l'événement la porte par une référence, jeu et votes.",
    "Choisir sa décision et son adresse ; la console affiche alors l'empreinte du condensé de cette décision, et elle seule.",
    "Sur l'écran du portefeuille, retrouver les 64 chiffres hexadécimaux du message (avec ou sans 0x, ou entre « hex( » et « ) ») et comparer les 8 premiers et les 8 derniers à l'empreinte affichée sous l'intitulé « empreinte du condensé à signer » ; pour une objection ou un montant élevé (CT-3 n'en fixe pas le seuil : l'organisation le dit), comparer les huit groupes. Sur un appareil qui montre aussi « Message hash », comparer cette valeur à l'empreinte affichée à part, sous l'intitulé « condensé EIP-191, montré par certains appareils sous « Message hash » » (H), et jamais à l'empreinte du condensé à signer (D_A).",
    "Si tout concorde, confirmer dans le portefeuille.",
    `Si l'empreinte diffère, ou si le portefeuille montre autre chose qu'un message (une transaction, des données typées) : refuser dans le portefeuille, ne pas réessayer depuis cette page, et prévenir l'administrateur de l'organisation par un autre canal que la console. Si le portefeuille ne montre pas les 64 chiffres en hexadécimal, en entier : refuser dans le portefeuille et ne pas voter avec ce portefeuille ; voter avec un portefeuille qui détient la même clé et montre les 64 chiffres (un autre portefeuille de navigateur, ou l'appareil matériel qui porte la clé, par un portefeuille de navigateur), depuis une page de console rechargée ; si aucun ne détient la clé, inscrire une autre adresse. Refuser dans le portefeuille n'est pas voter « refuse » : aucun vote n'est envoyé. Pour s'opposer à la demande, signer la décision « refuse » depuis une console saine : la console de l'organisation ouverte à son origine (${origine}), sur un autre poste ou dans un autre profil de navigateur sans extension que celui où l'écart est apparu, ou après que l'administrateur prévenu a écarté la cause. La concordance des empreintes ne prouve pas qu'une console est saine. Tant que la décision « refuse » n'est pas signée, l'opposition ne compte pas : les autres membres peuvent encore atteindre le seuil « approuve » ; sans décision scellée avant l'échéance, le ticket expire, et un délai écoulé ne vaut jamais approbation.`,
    "Si la console affiche elle-même « empreinte_divergente » : il n'y a rien à signer ; prévenir l'administrateur.",
    "Après le vote, si l'organisation a mis en place la notification indépendante, vérifier qu'elle annonce le vote inscrit en son nom avec le ticket, la décision choisie et l'empreinte affichée. Si elle nomme un autre ticket, une autre décision ou une autre empreinte, ou si elle n'arrive pas dans le délai que l'organisation a fixé, prévenir l'administrateur par un autre canal ; tant que le ticket accepte des votes (ouvert, seuil atteint, vérification), signer la décision voulue sur le ticket concerné depuis une console saine, ce qui remplace le vote ; une décision déjà scellée ne s'annule pas.",
  ];
}

/** Écran de signature (EX-9.18, EX-9.20) : D_A entier, groupes, empreinte, H, consignes. */
function ecranSignature(m, decision, motif, vue) {
  const d = m.digests[decision];
  const z = el("div", { testid: "ecran-signature", attrs: { "data-decision": decision, "data-ticket": m.ticket } });
  z.appendChild(el("h3", { texte: `Signer la décision « ${decision} » du ticket ${m.ticket} avec l'adresse ${etat.adresse}` }));
  z.appendChild(ligne("d-a", "Condensé à signer (D_A)", d.d_a));
  z.appendChild(ligne("groupes", "Groupes", d.groups));
  z.appendChild(el("p", { classe: "libelle", texte: "empreinte du condensé à signer" }));
  z.appendChild(el("p", { testid: "empreinte", classe: "empreinte", texte: d.fingerprint }));
  z.appendChild(el("p", { classe: "libelle", texte: "condensé EIP-191, montré par certains appareils sous « Message hash »" }));
  z.appendChild(el("p", { testid: "empreinte-h", classe: "empreinte-h", texte: d.h_fingerprint }));
  z.appendChild(ligne("groupes-h", "Groupes de H", d.h.slice(2).match(/.{8}/g).join(" ")));
  if (m.warnings.includes("condense_utf8")) z.appendChild(el("p", { testid: "avertissement-utf8", classe: "bandeau", texte: "Certains portefeuilles afficheront ce condensé comme du texte ; comparez-le sur un appareil qui l'affiche en hexadécimal." }));
  z.appendChild(el("ol", { testid: "consignes" }, consignesSignature(etat.annuaire?.console_origin ?? "console_origin de l'annuaire").map((t) => el("li", { texte: t }))));
  z.appendChild(bouton("Demander la signature au portefeuille", "signer", () => signer(m, decision, motif, vue)));
  return z;
}

function abandonnerRequete() {
  etat.requeteEnCours = null;
}

/** Délai d'attente du portefeuille : delai_signature_ms, jamais au-delà de l'échéance (EX-13.30). */
function delaiAvant(echeance) {
  const restant = echeance === null ? Infinity : K.msHorodatage(echeance) - Date.now();
  return Math.max(0, Math.min(K.DELAI_SIGNATURE_MS.defaut, restant));
}

/** Une seule requête personal_sign à la fois, sur action explicite (EX-13.21, EX-13.24), puis EX-9.21 et voter. */
async function signer(m, decision, motif, vue) {
  if (etat.requeteEnCours) return;
  const gen = etat.generation;
  const adresse = etat.adresse;
  // Le vote ne porte que le ticket du A signé, avec la vue de ce ticket (EX-9.21, point 8).
  if (!adresse || etat.ticket !== m.ticket || vue.ticket !== m.ticket || !etat.fournisseur) return;
  const d = m.digests[decision];
  let requete;
  try {
    requete = K.requetePersonalSign(d.d_a, adresse);
  } catch {
    return;
  }
  const jeton = {};
  etat.requeteEnCours = jeton;
  message("Requête de signature envoyée au portefeuille : comparez l'empreinte.");
  const delai = new Promise((r) => setTimeout(() => r({ delai: true }), delaiAvant(vue.deadline)));
  const reponse = await Promise.race([appelFournisseur(etat.fournisseur, requete), delai]);
  if (etat.requeteEnCours !== jeton || etat.generation !== gen) return; // décision, adresse ou ticket changés : la réponse est ignorée
  etat.requeteEnCours = null;
  if (reponse.delai) return terminer("delai_depasse");
  const r = K.verifierReponse(reponse, d.d_a, adresse);
  if (r.outcome !== "accepte") {
    // 4100 : la page redemande l'accès aux comptes une fois, puis attend une nouvelle action (13.14).
    if (r.reason === "non_autorise") await demanderComptes(false);
    const extra = r.reason === "adresse_differente" ? ` Adresse recouvrée : ${r.recovered}.` : r.reason === "erreur_portefeuille" ? ` Code ${reponse.error?.code ?? "absent"} : ${reponse.error?.message ?? ""}` : "";
    return terminer(r.reason, extra);
  }
  // Les contrôles sont refaits si la vue ou l'annuaire ont changé (EX-13.18).
  const revision = etat.annuaire?.revision;
  const v = await appel("consulter", { ticket: m.ticket, session_identity: etat.session });
  const a = await lireAnnuaire();
  if (etat.generation !== gen || etat.ticket !== m.ticket) return; // un autre ticket a été ouvert : rien n'est envoyé
  if (!v.ok || !a.ok || v.corps?.ticket !== m.ticket) return terminer(!v.ok ? v.code : !a.ok ? a.code : "service_indisponible", " Le vote n'a pas été envoyé.");
  if (v.corps.state !== vue.state || etat.annuaire?.revision !== revision) {
    try {
      const m2 = K.modeleAffichage(v.corps, { session: K.sessionDepuisAnnuaire(etat.annuaire, etat.session, v.corps.request.delegation.launched_by), decision, approver: adresse, reason: motif, now: new Date().toISOString() });
      const c2 = K.controleVote(etat.annuaire, etat.session, "voter", adresse, ticketDeControle(v.corps));
      if (m2.blocking.length || !c2.allowed) return terminer(m2.blocking[0] ?? c2.reason);
    } catch {
      return terminer("service_indisponible", " Le vote n'a pas été envoyé.");
    }
  }
  const vote = K.requeteVoter(vue, decision, r.signature, adresse, motif, etat.session);
  if (vote.ticket !== m.ticket) return;
  let rep = await appel("voter", vote);
  if (!rep.ok && rep.code === "service_indisponible") rep = await appel("voter", vote);
  if (etat.generation !== gen) {
    message(`Ticket ${m.ticket} : ${rep.ok ? `vote inscrit (état ${rep.corps.state})` : `${LIBELLES[rep.code] ?? rep.code} (${rep.code})`}.`);
    return;
  }
  if (rep.ok) return terminer(null, `Vote inscrit ; état du ticket : ${rep.corps.state}.`, rep.corps.state);
  if (rep.code === "vote_identique") return terminer(null, "Vote déjà inscrit ; le motif n'a pas changé.", "vote_identique");
  return terminer(rep.code);
}

function terminer(code, texte = "", etatTicket = null) {
  etat.ecranSignature = null;
  etat.resultat = el("div", { testid: "resultat", attrs: { "data-code": code ?? "vote_inscrit", ...(etatTicket ? { "data-etat": etatTicket } : {}) } }, [el("p", { texte: code ? `${LIBELLES[code] ?? code} (${code}).${texte}` : texte })]);
  afficherTicket();
}

// ---------------------------------------------------------------------------
// Inscription par preuve de possession (EX-13.12, EX-13.13, EX-13.15)
// ---------------------------------------------------------------------------
function afficherInscription() {
  vider(zones.inscription);
  if (!etat.session) return;
  zones.inscription.appendChild(el("h2", { texte: "Inscrire une adresse" }));
  if (!etat.fournisseur) {
    zones.inscription.appendChild(el("p", { texte: "Choisissez d'abord un portefeuille." }));
    return;
  }
  const ul = el("ul", { testid: "comptes-inscription" });
  for (const a of etat.comptes) ul.appendChild(el("li", {}, [el("span", { texte: `${a} ` }), etat.compteInscription === a ? el("strong", { texte: "choisi" }) : bouton("Inscrire ce compte", "choisir-compte", () => preparerInscription(a))]));
  zones.inscription.appendChild(ul);
  if (etat.inscription) zones.inscription.appendChild(etat.inscription);
}

function resultatInscription(code) {
  return el("ul", { testid: "resultat-inscription", attrs: { "data-code": code } }, [raisonInscription(code)]);
}

async function preparerInscription(adresse) {
  abandonnerRequete(); // un autre compte choisi : la requête d'inscription en cours est abandonnée (EX-13.21)
  etat.compteInscription = adresse;
  etat.inscription = null;
  const p = await appel("preparer_inscription", { session_identity: etat.session, address: adresse });
  if (etat.compteInscription !== adresse) return;
  const z = el("div", { testid: "message-inscription" });
  etat.inscription = z;
  if (!p.ok) {
    z.appendChild(resultatInscription(p.code));
    return afficherInscription();
  }
  const { fields, message: texte } = p.corps ?? {};
  let code = null;
  try {
    if (K.messageInscription(fields) !== texte) code = "message_invalide";
  } catch {
    code = "message_invalide";
  }
  if (!code && fields.origin !== window.location.origin) code = "origine_differente";
  if (!code && fields.identity !== etat.session) code = "identite_differente";
  if (!code && fields.address !== adresse) code = "adresse_differente";
  if (code) {
    z.appendChild(resultatInscription(code));
    return afficherInscription();
  }
  z.appendChild(el("p", { texte: "Lisez chaque ligne : l'origine doit être celle de cette page, l'identité celle de votre session (l'identifiant de votre compte, pas votre nom), l'adresse celle du compte choisi ; ce message n'est pas un vote. Si une ligne diffère, refusez dans le portefeuille et prévenez l'administrateur." }));
  z.appendChild(el("ol", { testid: "lignes-message" }, texte.split("\n").map((l) => el("li", { testid: "ligne-message", texte: l }))));
  z.appendChild(bouton("Signer le message d'inscription dans le portefeuille", "signer-inscription", () => signerInscription(texte, adresse, fields.expires_at)));
  afficherInscription();
}

async function signerInscription(texte, adresse, expireLe) {
  if (etat.requeteEnCours || !etat.fournisseur) return;
  const jeton = {};
  etat.requeteEnCours = jeton;
  const donnees = K.donneesPersonalSign(texte);
  const delai = new Promise((r) => setTimeout(() => r({ delai: true }), delaiAvant(expireLe)));
  const reponse = await Promise.race([appelFournisseur(etat.fournisseur, K.requetePersonalSign(donnees, adresse)), delai]);
  if (etat.requeteEnCours !== jeton || etat.compteInscription !== adresse) return; // compte changé : la réponse est ignorée
  etat.requeteEnCours = null;
  const z = etat.inscription;
  if (reponse.delai) {
    z.appendChild(resultatInscription("delai_depasse"));
    return afficherInscription();
  }
  const r = K.verifierReponse(reponse, donnees, adresse);
  if (r.outcome !== "accepte") {
    z.appendChild(resultatInscription(r.reason));
    return afficherInscription();
  }
  const rep = await appel("inscrire", { session_identity: etat.session, address: adresse, message: texte, signature: r.signature });
  if (etat.compteInscription !== adresse) return;
  if (rep.ok) z.appendChild(el("p", { testid: "resultat-inscription", attrs: { "data-code": rep.corps.state }, texte: `Adresse ${rep.corps.address} inscrite dans l'entrée ${rep.corps.entry}, état ${rep.corps.state} : un administrateur, autre que vous, doit la valider.` }));
  else z.appendChild(resultatInscription(rep.code));
  afficherInscription();
}

demarrer();
