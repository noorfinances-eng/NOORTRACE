// Écran « Mon adresse » (contrat de l'étape 6, 3.1, 3.4 et 3.5 ; CT-3 13.5,
// EX-13.12, EX-13.13, EX-13.16, EX-13.22, EX-13.23, EX-13.29, EX-13.30) :
// `annuaire` (document réduit) pour l'état de son entrée et de ses adresses ;
// inscription par preuve de possession : découverte, choix du fournisseur,
// `eth_requestAccounts`, choix explicite du compte (sans présélection),
// `preparer_inscription`, `controleDefi` (aucune signature sur un écart),
// texte affiché ligne par ligne, action explicite, règle de 3.5,
// `personal_sign` sur `donneesPersonalSign(texte)`, `verifierReponse`,
// `inscrire` ; pannes de la seconde table de 13.14. Révision 0.6 de CT-3 :
// réauthentification avant `preparer_inscription` quand l'authentification
// ne couvrirait pas l'`inscrire` qui suit (EX-13.48, point 5) ; attente de la
// signature jamais au-delà de `Expire le` du défi (EX-13.30) ; révocation de
// sa propre adresse, confirmée comme définitive (EX-13.17, contrat 3.4).

import { lancerDecouverte, rendreFournisseurs, demanderComptes, appelFournisseur, ecouter, textePanne } from "../commun/fournisseurs.mjs";

// EX-13.22, point 1 : la découverte est posée avant toute autre opération.
const decouverte = lancerDecouverte();

import { analyserComptes, controleDefi, donneesPersonalSign, requetePersonalSign, verifierReponse, echeanceAttente, decoderInstant, utf8, entreeDeSession } from "noortrace-console/index.mjs";
import { el, ajouter, bouton, code, definitions, message, remplacer, vider } from "../commun/dom.mjs";
import { t, texteCode } from "../commun/libelles.mjs";
import { ErreurAppel, appeler, allerConnexion, envoiDepuis, methodesDepuis, lireSession, maintenant } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, principal, section } from "../commun/cadre.mjs";

const PREFIXES = ["inscription.", "console."];

const etat = {
  session: null,
  annuaire: null,
  fournisseur: null,
  comptes: null,
  compte: null,
  defi: null,
  enCours: false,
  minuteur: null,
  generation: 0,
  detacher: [],
  panne: null,
  // Adresse dont la révocation attend la confirmation.
  revocation: null,
};

const zones = {
  entree: el("div", { attributs: { id: "zone-entree" } }),
  fournisseurs: el("div", { attributs: { id: "zone-fournisseurs" } }),
  comptes: el("div", { attributs: { id: "zone-comptes" } }),
  texte: el("div", { attributs: { id: "zone-texte" } }),
  resultat: el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } }),
};

function identite() {
  return etat.session.session_identity;
}

function abandonner() {
  etat.generation += 1;
  etat.defi = null;
  etat.enCours = false;
  if (etat.minuteur !== null) clearTimeout(etat.minuteur);
  etat.minuteur = null;
  rendreTexte();
}

window.addEventListener("pagehide", () => abandonner());
window.addEventListener("pageshow", (e) => {
  if (e.persisted) window.location.reload();
});

// ---------------------------------------------------------------------------
// État de l'entrée

async function lireAnnuaire() {
  try {
    const r = await appeler("annuaire", { session_identity: identite() });
    etat.annuaire = r.valeur;
    rendreEntree();
  } catch (e) {
    afficherErreur(zones.entree, e);
  }
}

function entree() {
  if (etat.annuaire === null || !Array.isArray(etat.annuaire.entries)) return null;
  return entreeDeSession(etat.annuaire, identite());
}

function inscriptionOfferte() {
  const e = entree();
  return etat.annuaire !== null && (e === null || e.active === true);
}

function rendreEntree() {
  const e = entree();
  const parties = [el("h1", { texte: t("inscription.titre") })];
  if (e === null) {
    parties.push(el("p", { texte: t("inscription.entree.absente"), attributs: { "data-entree": "absente" } }));
  } else {
    parties.push(
      definitions([
        [t("inscription.entree.id"), code(e.id)],
        [t("inscription.entree.etat"), el("span", { texte: t(e.active ? "inscription.entree.active" : "inscription.entree.desactivee"), attributs: { "data-entree": e.active ? "active" : "desactivee" } })],
        [t("inscription.entree.creee"), code(e.created_at)],
        [t("inscription.entree.alias"), e.requester_identities.length === 0 ? t("modele.vide") : el("ul", {}, ...e.requester_identities.map((r) => el("li", {}, code(r))))],
      ]),
    );
    const table = el("table", { classe: "table", attributs: { id: "adresses" } });
    ajouter(table, el("thead", {}, el("tr", {}, ...["adresse", "etat", "validation", "revocation", "action"].map((c) => el("th", { texte: t(`inscription.colonne.${c}`), attributs: { scope: "col" } })))));
    const corps = el("tbody");
    for (const a of e.addresses) {
      const validation = a.validated_at === null ? t("modele.vide") : el("span", {}, code(a.validated_at), " ", code(String(a.validated_by)));
      const revocation =
        a.revoked_at === null
          ? t("modele.vide")
          : el("span", {}, code(a.revoked_at), " ", t(`revocation.${a.revocation_cause}`), a.replaced_by ? el("span", {}, " ", t("inscription.remplacee_par"), " ", code(a.replaced_by)) : null, a.revocation_reason ? el("span", {}, " ", t("modele.votes.motif", { motif: a.revocation_reason })) : null);
      ajouter(corps, el("tr", { attributs: { "data-adresse": a.address, "data-etat": a.state } }, el("td", {}, code(a.address)), el("td", { texte: t(`adresse_etat.${a.state}`) }), el("td", {}, validation), el("td", {}, revocation), el("td", {}, actionRevocation(e, a))));
    }
    table.appendChild(corps);
    parties.push(e.addresses.length === 0 ? el("p", { texte: t("inscription.aucune_adresse") }) : table);
    if (!e.active) parties.push(message("alerte", el("p", { texte: texteCode("identite_desactivee", ["raison."]), attributs: { "data-code": "identite_desactivee" } }), el("p", { texte: t("inscription.prevenir") })));
  }
  parties.push(el("p", { classe: "discret", texte: t("inscription.validation_sens") }));
  remplacer(zones.entree, ...parties);
  rendreFournisseursEtComptes();
}

// Révocation par la personne (EX-13.17 ; 13.17 « Clé perdue ») : offerte pour
// une adresse en attente ou active de sa propre entrée, confirmée par un
// second clic avec la consigne qu'elle est définitive ; le serveur exige la
// réauthentification d'EX-13.8 (la page navigue alors vers la connexion).
function actionRevocation(e, a) {
  if (a.state !== "en_attente" && a.state !== "active") return t("modele.vide");
  if (etat.revocation !== a.address) {
    return el(
      "div",
      { classe: "action", attributs: { "data-action": "revoquer" } },
      bouton(t("inscription.revoquer"), () => {
        etat.revocation = a.address;
        rendreEntree();
      }),
    );
  }
  const id = `motif-revoquer-${a.address}`;
  const champ = el("input", { attributs: { type: "text", id, maxlength: "4096", "aria-label": t("annuaire.motif") } });
  return el(
    "div",
    { classe: "action confirmation", attributs: { "data-action": "revoquer", "data-confirmation": "" } },
    message("alerte", el("p", { texte: t("inscription.revoquer_definitif") })),
    el("label", { texte: t("annuaire.motif"), attributs: { for: id } }),
    champ,
    bouton(t("inscription.revoquer_confirmer"), () => void revoquer(e.id, a.address, champ.value === "" ? null : champ.value), { classe: "bouton principal" }),
    bouton(t("action.annuler"), () => {
      etat.revocation = null;
      rendreEntree();
    }),
  );
}

async function revoquer(entree_, adresse, motif) {
  etat.revocation = null;
  try {
    const r = await appeler("revoquer", { session_identity: identite(), entry: entree_, address: adresse, reason: motif });
    remplacer(zones.resultat, message("info", el("p", { texte: t("inscription.revoquee", { adresse: String(r.valeur.address) }), attributs: { "data-resultat": "revoquer" } })));
  } catch (e) {
    if (afficherErreur(zones.resultat, e)) return;
  }
  await lireAnnuaire();
}

// ---------------------------------------------------------------------------
// Fournisseur et compte

function rendreFournisseursEtComptes() {
  if (!inscriptionOfferte()) {
    vider(zones.fournisseurs);
    vider(zones.comptes);
    return;
  }
  rendreFournisseurs(zones.fournisseurs, decouverte, etat.fournisseur, choisirFournisseur, true);
  rendreComptes();
}

decouverte.surChangement(() => {
  if (etat.fournisseur !== null && !decouverte.fournisseurs.some((f) => f.provider === etat.fournisseur.provider)) oublierFournisseur();
  if (etat.session !== null) rendreFournisseursEtComptes();
});

function oublierFournisseur() {
  for (const f of etat.detacher) f();
  etat.detacher = [];
  etat.fournisseur = null;
  etat.comptes = null;
  etat.compte = null;
  abandonner();
}

async function choisirFournisseur(f) {
  oublierFournisseur();
  etat.fournisseur = f;
  etat.panne = null;
  const provider = f.provider;
  etat.detacher.push(
    ecouter(provider, "accountsChanged", (comptes) => {
      if (etat.fournisseur === null || etat.fournisseur.provider !== provider) return;
      surComptes(analyserComptes(comptes) ?? []);
    }),
    ecouter(provider, "disconnect", () => {
      if (etat.fournisseur === null || etat.fournisseur.provider !== provider) return;
      oublierFournisseur();
      etat.panne = { code: "deconnecte", erreur: null };
      rendreFournisseursEtComptes();
    }),
  );
  rendreFournisseursEtComptes();
  await obtenirComptes();
}

async function obtenirComptes() {
  const f = etat.fournisseur;
  if (f === null) return;
  etat.panne = null;
  rendreComptes();
  const r = await demanderComptes(f.provider);
  if (etat.fournisseur !== f) return;
  if (r.comptes === undefined) {
    etat.panne = r;
    rendreComptes();
    return;
  }
  surComptes(r.comptes);
}

function surComptes(comptes) {
  etat.comptes = comptes;
  if (etat.compte !== null && !comptes.includes(etat.compte)) {
    // EX-13.23 : le compte choisi n'est plus exposé ; l'approbateur choisit de nouveau.
    etat.compte = null;
    abandonner();
    etat.panne = { code: "adresse_retiree", erreur: null };
  }
  rendreComptes();
}

function rendreComptes() {
  const parties = [];
  if (etat.fournisseur !== null) parties.push(el("p", {}, t("portefeuille.courant", { nom: etat.fournisseur.name })));
  if (etat.comptes !== null) {
    parties.push(el("h3", { texte: t("inscription.comptes") }));
    if (etat.comptes.length === 0) parties.push(el("p", { texte: t("inscription.aucun_compte") }));
    const ul = el("ul", { classe: "comptes", attributs: { id: "comptes" } });
    for (const a of [...new Set(etat.comptes)]) {
      const choisi = a === etat.compte;
      ajouter(
        ul,
        el(
          "li",
          { attributs: { "data-compte": a } },
          code(a),
          " ",
          choisi ? el("span", { classe: "etiquette", texte: t("inscription.compte_choisi") }) : bouton(t("inscription.choisir_compte"), () => void choisirCompte(a), { actif: !etat.enCours }),
        ),
      );
    }
    parties.push(ul);
  }
  if (etat.panne !== null) {
    if (etat.panne.code === "adresse_retiree") parties.push(message("alerte", el("p", { texte: t("adresse.retiree"), attributs: { "data-code": "adresse_retiree" } })));
    else {
      parties.push(
        message("erreur", el("p", { texte: textePanne(etat.panne.code, etat.panne.erreur, ["comptes.", ...PREFIXES]), attributs: { "data-code": etat.panne.code } })),
        etat.fournisseur !== null ? bouton(t("portefeuille.redemander"), () => void obtenirComptes()) : null,
      );
    }
  }
  remplacer(zones.comptes, ...parties);
}

// ---------------------------------------------------------------------------
// Défi (EX-13.13) et texte affiché ligne par ligne

async function choisirCompte(adresse) {
  etat.compte = adresse;
  abandonner();
  vider(zones.resultat);
  rendreComptes();
  await preparer();
}

async function preparer() {
  if (etat.compte === null) return;
  etat.generation += 1;
  const g = etat.generation;
  const adresse = etat.compte;
  remplacer(zones.texte, el("p", { classe: "discret", texte: t("inscription.preparation") }));
  // EX-13.48, point 5 (révision 0.6) : l'authentification qui couvre
  // `preparer_inscription` doit couvrir aussi l'`inscrire` qui suit, au terme
  // de l'attente admise ; sinon la page fait réauthentifier d'abord, avant de
  // tenir un défi qu'une navigation ferait perdre.
  const s = await lireSession();
  if (g !== etat.generation) return;
  if (s.etat !== "session") {
    vider(zones.texte);
    if (s.etat === "erreur") afficherErreur(zones.resultat, s.erreur);
    else if (s.etat === "identite_invalide") remplacer(zones.resultat, message("erreur", el("p", { texte: texteCode("identite_invalide", ["raison."]) })));
    return;
  }
  etat.session = s.session;
  const ttl = etat.annuaire !== null && Number.isSafeInteger(etat.annuaire.registration_ttl_ms) ? etat.annuaire.registration_ttl_ms : s.session.delai_signature_ms;
  const m0 = maintenant();
  if (reauthentificationAvant(s.session, m0, Math.min(s.session.delai_signature_ms, ttl), [])) {
    abandonner();
    allerConnexion();
    return;
  }
  let r;
  try {
    r = await appeler("preparer_inscription", { session_identity: identite(), address: adresse });
  } catch (e) {
    if (g !== etat.generation) return;
    vider(zones.texte);
    afficherErreur(zones.resultat, e, el("p", { texte: t("inscription.prevenir_si") }));
    return;
  }
  if (g !== etat.generation) return;
  const ecart = controleDefi(r.valeur, { origine: window.location.origin, identite: identite(), adresse });
  if (ecart !== null) {
    // Aucune requête de signature ; la raison et la consigne (13.14).
    vider(zones.texte);
    remplacer(zones.resultat, message("erreur", el("p", { texte: texteCode(ecart, ["defi.", "console."]), attributs: { "data-code": ecart } }), el("p", { texte: t("inscription.defi_refuse") })));
    return;
  }
  etat.defi = { message: r.valeur.message, fields: r.valeur.fields, adresse };
  rendreTexte();
}

function rendreTexte() {
  const d = etat.defi;
  if (d === null) {
    vider(zones.texte);
    return;
  }
  const ol = el("ol", { classe: "texte-inscription fixe", attributs: { id: "texte-inscription" } });
  for (const ligne of d.message.split("\n")) ajouter(ol, el("li", { texte: ligne }));
  remplacer(
    zones.texte,
    section(
      t("inscription.texte"),
      el("p", { texte: t("inscription.texte_verifier") }),
      ol,
      bouton(t("inscription.signer"), () => void signer(), { actif: !etat.enCours, classe: "bouton principal" }),
      etat.enCours ? el("p", { classe: "discret", texte: t("signature.en_cours") }) : null,
    ),
  );
}

// Règle de 3.5 (même règle que pour un vote), avec l'exception de
// l'inscription pour `reauth_max_age_s` = 0 (EX-13.48, point 5, révision
// 0.6) : `admises` sont les méthodes que l'authentification peut avoir déjà
// couvertes sans cesser de couvrir celle qui suit (`preparer_inscription`
// seule, avant `inscrire`).
function reauthentificationAvant(session, m, w, admises) {
  const a = decoderInstant(session.auth_time);
  const fin = decoderInstant(m) + w + 30000;
  if (session.reauth_max_age_s > 0) return fin >= a + session.reauth_max_age_s * 1000;
  const envoyees = methodesDepuis(session.auth_time);
  const couvertes = envoyees.length <= admises.length && envoyees.every((x, k) => x === admises[k]);
  return (envoiDepuis(session.auth_time) && !couvertes) || fin >= a + 600000;
}

async function signer() {
  const d = etat.defi;
  if (d === null || etat.enCours || etat.fournisseur === null) return;
  const g = etat.generation;
  const provider = etat.fournisseur.provider;
  etat.enCours = true;
  vider(zones.resultat);
  rendreTexte();
  rendreComptes();
  const s = await lireSession();
  if (g !== etat.generation) return;
  if (s.etat !== "session") {
    etat.enCours = false;
    rendreTexte();
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
  // EX-13.30 : le délai de signature vaut aussi pour une inscription, jamais
  // au-delà de `Expire le` du défi (révision 0.6 : une signature reçue après
  // ne donnerait que `inscription_expiree`).
  const attente = echeanceAttente(s.session.delai_signature_ms, d.fields.expires_at, m);
  if (attente <= 0) {
    abandonner();
    rendreComptes();
    remplacer(zones.resultat, message("erreur", el("p", { texte: texteCode("inscription_expiree", ["raison."]), attributs: { "data-code": "inscription_expiree" } }), el("p", { texte: t("inscription.recommencer"), attributs: { "data-consigne": "recommencer" } })));
    return;
  }
  if (reauthentificationAvant(s.session, m, attente, ["preparer_inscription"])) {
    abandonner();
    allerConnexion();
    return;
  }
  const donnees = donneesPersonalSign(d.message);
  const reponse = await new Promise((resolve) => {
    etat.minuteur = setTimeout(() => resolve({ delai: true }), attente);
    appelFournisseur(provider, requetePersonalSign(donnees, d.adresse)).then(resolve);
  });
  if (g !== etat.generation) return;
  clearTimeout(etat.minuteur);
  etat.minuteur = null;
  if (reponse.delai) {
    abandonner();
    rendreComptes();
    remplacer(zones.resultat, message("erreur", el("p", { texte: textePanne("delai_depasse", null, PREFIXES), attributs: { "data-code": "delai_depasse" } })));
    return;
  }
  const verdict = verifierReponse(reponse, utf8(d.message), d.adresse);
  if (verdict.outcome !== "accepte") {
    abandonner();
    rendreComptes();
    const parties = [el("p", { texte: textePanne(verdict.reason, reponse.error ?? null, PREFIXES), attributs: { "data-code": verdict.reason } })];
    if (verdict.reason === "adresse_differente" && verdict.recovered) parties.push(el("p", {}, t("signature.adresse_recouvree"), " ", code(verdict.recovered)));
    remplacer(zones.resultat, message("erreur", ...parties));
    if (verdict.reason === "non_autorise") void obtenirComptes();
    return;
  }
  try {
    const r = await appeler("inscrire", { session_identity: identite(), address: d.adresse, message: d.message, signature: verdict.signature });
    if (g !== etat.generation) return;
    abandonner();
    etat.compte = null;
    rendreComptes();
    const v = r.valeur;
    remplacer(zones.resultat, message("info", el("p", { texte: t("inscription.inscrite", { adresse: String(v.address), etat: t(`adresse_etat.${v.state}`) }), attributs: { "data-resultat": "inscription_envoyee" } }), el("p", { texte: t("inscription.validation_sens") })));
    await lireAnnuaire();
  } catch (e) {
    if (g !== etat.generation) return;
    abandonner();
    etat.compte = null;
    rendreComptes();
    const code_ = e instanceof ErreurAppel ? e.code : "";
    const recommencer = ["inscription_expiree", "nonce_inconnu", "nonce_deja_utilise"].includes(code_);
    afficherErreur(zones.resultat, e, el("p", { texte: t(recommencer ? "inscription.recommencer" : "inscription.prevenir"), attributs: { "data-consigne": recommencer ? "recommencer" : "prevenir" } }));
  }
}

// ---------------------------------------------------------------------------
// Démarrage

async function demarrer() {
  const s = await demarrerEcran("inscription");
  if (s === null) return;
  etat.session = s;
  principal().appendChild(el("main", { classe: "contenu" }, zones.entree, el("section", { classe: "bloc", attributs: { id: "inscription" } }, el("h2", { texte: t("inscription.nouvelle") }), el("p", { texte: t("inscription.sens") }), zones.fournisseurs, zones.comptes), zones.texte, zones.resultat));
  await lireAnnuaire();
}

void demarrer();
