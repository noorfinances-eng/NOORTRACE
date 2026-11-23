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

import { lancerDecouverte, rendreFournisseurs, demanderComptes, appelFournisseur, ecouter, noeudsPanne } from "../commun/fournisseurs.mjs";

// EX-13.22, point 1 : la découverte est posée avant toute autre opération.
const decouverte = lancerDecouverte();

import { analyserComptes, controleDefi, donneesPersonalSign, requetePersonalSign, verifierReponse, echeanceAttente, decoderInstant, utf8, entreeDeSession } from "noortrace-console/index.mjs";
import { el, actions, ajouter, bouton, code, definitions, detail, donnee, icone, message, pastille, remplacer, vider } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { ErreurAppel, appeler, allerConnexion, envoiDepuis, methodesDepuis, lireSession, maintenant } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, entete, instant, paragrapheCode, principal, sensCode } from "../commun/cadre.mjs";
import { texteIdentite } from "../commun/lisible.mjs";

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
  entree: el("div", { classe: "nt-pile nt-pile-large", attributs: { id: "zone-entree" } }),
  inscription: el("section", { classe: "nt-carte zone-carte", attributs: { id: "inscription" } }),
  fournisseurs: el("div", { classe: "nt-pile", attributs: { id: "zone-fournisseurs" } }),
  comptes: el("div", { classe: "nt-pile", attributs: { id: "zone-comptes" } }),
  texte: el("div", { classe: "nt-pile", attributs: { id: "zone-texte" } }),
  resultat: el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } }),
};

// Le titre de l'inscription, et la phrase qui dit, quand une adresse attend déjà sa validation, qu'il n'y a rien de
// plus à inscrire : posés une fois, leur texte suit l'annuaire lu.
const titreInscription = el("h2", { attributs: { id: "inscription-titre" } });
const attenteInscription = el("p", { classe: "inscription-attente", attributs: { id: "inscription-attente", hidden: "" } });
const sensInscription = el("p", { classe: "nt-attenue" });
const listeEtapes = el("ol", { classe: "nt-etapes" });
// Avec une adresse en attente de validation, il n'y a rien de plus à inscrire : les trois étapes passent dans un bloc
// fermé, « Inscrire quand même une autre adresse » (une seconde inscription n'est pas refusée, CT-3 EX-13.15) ; il
// reste ouvert, d'une lecture de l'annuaire à la suivante, si la personne l'a ouvert.
const blocAutre = detail("", null, el("p", { classe: "nt-attenue", attributs: { id: "inscription-autre-sens" } }));
blocAutre.setAttribute("id", "inscription-autre");

// Les trois étapes de l'inscription : portefeuille, compte, texte à signer.
// Chaque étape garde son élément ; `rendreEtapes` en met l'état à jour.
const etapes = [1, 2, 3].map((n) => {
  const rond = el("span", { classe: "nt-etape-rond", attributs: { "aria-hidden": "true" } });
  const pastilleEtape = el("span", {});
  const titre = el("p", { classe: "nt-etape-titre" }, el("span", { texte: t(`inscription.etape.${n}`) }), pastilleEtape);
  const zone = [zones.fournisseurs, zones.comptes, zones.texte][n - 1];
  const corps = el("div", { classe: "nt-etape-corps" }, titre, el("p", { classe: "nt-etape-texte", texte: t(`inscription.etape_sens.${n}`) }), zone);
  return { n, rond, pastilleEtape, element: el("li", { classe: "nt-etape nt-etape-a-faire" }, rond, corps) };
});

/** Met à jour l'état des étapes : faite, en cours ou à faire. */
function rendreEtapes() {
  const faites = [etat.fournisseur !== null, etat.compte !== null, false];
  // Une adresse attend déjà sa validation : rien n'est « en cours » tant que la personne n'a pas commencé.
  const attente = etat.fournisseur === null && (entree()?.addresses ?? []).some((a) => a.state === "en_attente");
  const enCours = attente ? -1 : faites.indexOf(false);
  etapes.forEach((e, k) => {
    const genre = faites[k] ? "faite" : k === enCours ? "en-cours" : "a-faire";
    e.element.setAttribute("class", `nt-etape nt-etape-${genre}`);
    e.element.setAttribute("data-etape", genre);
    remplacer(e.rond, genre === "faite" ? icone("coche") : null);
    if (genre !== "faite") e.rond.appendChild(document.createTextNode(String(e.n)));
    remplacer(e.pastilleEtape, genre === "faite" ? pastille("succes", t("etape.faite"), "coche") : genre === "en-cours" ? pastille("info", t("etape.en_cours"), "horloge") : pastille("neutre", t("etape.a_faire"), "tiret"));
  });
}

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

// Pastille de l'état d'une adresse de l'annuaire ; le code reste dans `data-etat` de sa ligne.
const ETATS_ADRESSE = Object.freeze({ en_attente: ["attente", "horloge"], active: ["succes", "coche"], revoquee: ["refus", "croix"] });
function pastilleAdresse(etatAdresse) {
  const [genre, nomIcone] = ETATS_ADRESSE[etatAdresse] ?? ["neutre", "question"];
  return pastille(genre, t(`adresse_etat.${etatAdresse}`), nomIcone);
}

function rendreEntree() {
  const e = entree();
  const pastilleEntree =
    e === null
      ? pastille("neutre", t("inscription.entree.aucune"), "tiret", { grande: true, attributs: { "data-entree": "absente" } })
      : e.active
        ? pastille("succes", t("inscription.entree.pastille_active"), "coche", { grande: true, attributs: { "data-entree": "active" } })
        : pastille("neutre", t("inscription.entree.pastille_desactivee"), "tiret", { grande: true, attributs: { "data-entree": "desactivee" } });
  const parties = [entete({ titre: t("inscription.titre"), sousTitre: t("inscription.sous_titre"), etat: [pastilleEntree] })];
  if (e === null) {
    parties.push(message("info", el("p", { texte: t("inscription.entree.absente") })));
  } else {
    if (!e.active) parties.push(message("alerte", paragrapheCode("identite_desactivee", ["raison."]), el("p", { texte: t("inscription.prevenir") })));
    const table = el("table", { classe: "nt-tableau", attributs: { id: "adresses" } });
    // Validation et révocation partagent une colonne : l'adresse garde la place de s'écrire en entier, sur une ligne.
    const colonnes = ["adresse", "etat", "historique", "action"];
    ajouter(table, el("thead", {}, el("tr", {}, ...colonnes.map((c) => el("th", { texte: t(`inscription.colonne.${c}`), attributs: { scope: "col" } })))));
    const corps = el("tbody");
    const libelle = (c) => ({ "data-libelle": t(`inscription.colonne.${c}`) });
    for (const a of e.addresses) {
      const lignes = [];
      if (a.validated_at !== null) lignes.push(el("span", { classe: "fait-texte" }, t("inscription.validee_le"), " ", instant(a.validated_at)), el("span", { classe: "fait-second" }, t("inscription.par"), " ", donnee(texteIdentite(a.validated_by))));
      if (a.revoked_at !== null) {
        lignes.push(el("span", { classe: "fait-texte" }, el("span", { texte: t(`revocation.${a.revocation_cause}`) }), t("inscription.le"), instant(a.revoked_at)));
        if (a.replaced_by) lignes.push(el("span", { classe: "fait-second" }, t("inscription.remplacee_par"), " ", code(a.replaced_by)));
        if (a.revocation_reason) lignes.push(donnee(t("modele.votes.motif", { motif: a.revocation_reason }), "fait-second"));
      }
      const historique = lignes.length === 0 ? el("span", { classe: "nt-attenue", texte: t("inscription.pas_validee") }) : el("span", {}, ...lignes);
      ajouter(
        corps,
        el(
          "tr",
          { attributs: { "data-adresse": a.address, "data-etat": a.state } },
          el("td", { classe: "nt-cellule-titre", attributs: libelle("adresse") }, code(a.address, "nt-fixe adresse-entiere")),
          el("td", { attributs: libelle("etat") }, pastilleAdresse(a.state)),
          el("td", { attributs: libelle("historique") }, historique),
          el("td", { attributs: libelle("action") }, actionRevocation(e, a)),
        ),
      );
    }
    table.appendChild(corps);
    parties.push(
      el(
        "section",
        { classe: "nt-carte nt-carte-pleine" },
        el("div", { classe: "nt-carte-titre" }, el("h2", { texte: t("inscription.adresses") })),
        // Une adresse active et une adresse en attente : pourquoi deux, et avec laquelle la personne signe.
        e.addresses.some((a) => a.state === "active") && e.addresses.some((a) => a.state === "en_attente") ? el("p", { classe: "pied-carte", texte: t("inscription.deux_adresses"), attributs: { id: "deux-adresses" } }) : null,
        e.addresses.length === 0 ? el("p", { classe: "nt-attenue pied-carte", texte: t("inscription.aucune_adresse") }) : table,
        el("p", { classe: "nt-attenue nt-petit pied-carte", texte: t("inscription.validation_sens") }),
      ),
      el(
        "section",
        { classe: "nt-carte" },
        el("h2", { texte: t("inscription.entree.titre") }),
        definitions([
          [t("inscription.entree.id"), code(e.id)],
          [t("inscription.entree.creee"), instant(e.created_at)],
          [t("inscription.entree.alias"), e.requester_identities.length === 0 ? t("inscription.entree.alias_aucun") : el("ul", { classe: "liste-nue" }, ...e.requester_identities.map((r) => el("li", {}, code(r))))],
        ]),
        // Ce que veut dire la liste, qu'elle soit vide ou non (EX-13.17, `lier_demandeur` ; EX-9.15, contrôle 12).
        el("p", { classe: "nt-attenue nt-petit", texte: t(e.requester_identities.length === 0 ? "inscription.entree.alias_aucun_sens" : "inscription.entree.alias_sens"), attributs: { id: "agents-sens" } }),
      ),
    );
  }
  remplacer(zones.entree, ...parties);
  rendreFournisseursEtComptes();
}

// Révocation par la personne (EX-13.17 ; 13.17 « Clé perdue ») : offerte pour
// une adresse en attente ou active de sa propre entrée, confirmée par un
// second clic avec la consigne qu'elle est définitive ; le serveur exige la
// réauthentification d'EX-13.8 (la page navigue alors vers la connexion).
function actionRevocation(e, a) {
  if (a.state !== "en_attente" && a.state !== "active") return el("span", { classe: "nt-attenue", texte: t("modele.vide") });
  if (etat.revocation !== a.address) {
    return el(
      "div",
      { classe: "action", attributs: { "data-action": "revoquer" } },
      // Chaque bouton dit quelle adresse il révoque : l'adresse active, ou l'adresse en attente de validation.
      bouton(
        t(a.state === "en_attente" ? "inscription.revoquer_attente" : "inscription.revoquer_active"),
        () => {
          etat.revocation = a.address;
          rendreEntree();
        },
        // La révocation ne se défait pas : le bouton en a l'apparence dès le premier clic.
        { petit: true, classe: "bouton-definitif" },
      ),
      // La conséquence se lit avant le premier clic : la révocation est définitive. Pour une adresse en attente, ce
      // n'est pas une clé perdue : c'est une inscription que la personne ne veut pas, ou n'a pas demandée.
      el("p", { classe: "nt-attenue nt-petit", texte: t(a.state === "en_attente" ? "inscription.revoquer_sens_attente" : "inscription.revoquer_sens") }),
    );
  }
  const id = `motif-revoquer-${a.address}`;
  const champ = el("input", { classe: "nt-saisie", attributs: { type: "text", id, maxlength: "4096", "aria-label": t("annuaire.motif") } });
  return el(
    "div",
    { classe: "action confirmation nt-pile", attributs: { "data-action": "revoquer", "data-confirmation": "" } },
    message("alerte", el("p", { texte: t(a.state === "en_attente" ? "inscription.revoquer_definitif_attente" : "inscription.revoquer_definitif") })),
    el("div", { classe: "nt-champ" }, el("label", { classe: "nt-libelle", texte: t("annuaire.motif"), attributs: { for: id } }), champ),
    actions(
      bouton(t("inscription.revoquer_confirmer"), () => void revoquer(e.id, a.address, champ.value === "" ? null : champ.value), { genre: "danger" }),
      bouton(t("action.annuler"), () => {
        etat.revocation = null;
        rendreEntree();
      }),
    ),
  );
}

async function revoquer(entree_, adresse, motif) {
  etat.revocation = null;
  try {
    const r = await appeler("revoquer", { session_identity: identite(), entry: entree_, address: adresse, reason: motif });
    remplacer(zones.resultat, message("succes", el("p", { texte: t("inscription.revoquee", { adresse: String(r.valeur.address) }), attributs: { "data-resultat": "revoquer" } })));
  } catch (e) {
    if (afficherErreur(zones.resultat, e)) return;
  }
  await lireAnnuaire();
}

// ---------------------------------------------------------------------------
// Fournisseur et compte

function rendreFournisseursEtComptes() {
  if (!inscriptionOfferte()) {
    vider(zones.inscription);
    return;
  }
  // Une personne qui a déjà une adresse lit « une nouvelle adresse » ; avec une adresse en attente de validation, la
  // page dit qu'elle n'a rien de plus à inscrire, et les étapes ne sont offertes que dans le bloc fermé (relu à chaque
  // lecture de l'annuaire).
  const adresses = entree()?.addresses ?? [];
  const attente = adresses.some((a) => a.state === "en_attente");
  if (listeEtapes.firstChild === null) ajouter(listeEtapes, ...etapes.map((e) => e.element));
  sensInscription.textContent = t("inscription.sens");
  if (attente) {
    if (blocAutre.parentNode !== zones.inscription) {
      remplacer(blocAutre.querySelector("summary > span"), document.createTextNode(t("inscription.autre")));
      blocAutre.querySelector("#inscription-autre-sens").textContent = t("inscription.autre_sens");
      ajouter(blocAutre.querySelector(".nt-detail-corps"), sensInscription, listeEtapes);
      remplacer(zones.inscription, titreInscription, attenteInscription, blocAutre);
    }
  } else if (zones.inscription.firstChild === null || blocAutre.parentNode === zones.inscription) {
    remplacer(zones.inscription, titreInscription, attenteInscription, sensInscription, listeEtapes);
  }
  titreInscription.textContent = t(adresses.some((a) => a.state === "active" || a.state === "en_attente") ? "inscription.nouvelle_autre" : "inscription.nouvelle");
  attenteInscription.textContent = attente ? t("inscription.attente_deja") : "";
  attenteInscription.hidden = !attente;
  rendreFournisseurs(zones.fournisseurs, decouverte, etat.fournisseur, choisirFournisseur, true, false);
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
  if (etat.fournisseur !== null) parties.push(el("p", {}, donnee(t("portefeuille.courant", { nom: etat.fournisseur.name }))));
  if (etat.comptes !== null) {
    parties.push(el("h3", { texte: t("inscription.comptes") }));
    if (etat.comptes.length === 0) parties.push(el("p", { classe: "nt-attenue", texte: t("inscription.aucun_compte") }));
    const ul = el("ul", { classe: "liste-nue comptes", attributs: { id: "comptes" } });
    for (const a of [...new Set(etat.comptes)]) {
      const choisi = a === etat.compte;
      ajouter(ul, el("li", { classe: "compte", attributs: { "data-compte": a } }, code(a), " ", choisi ? pastille("succes", t("inscription.compte_choisi"), "coche") : bouton(t("inscription.choisir_compte"), () => void choisirCompte(a), { actif: !etat.enCours, petit: true })));
    }
    parties.push(ul);
  }
  if (etat.panne !== null) {
    if (etat.panne.code === "adresse_retiree") parties.push(message("alerte", el("p", { texte: t("adresse.retiree"), attributs: { "data-code": "adresse_retiree" } })));
    else {
      parties.push(
        message("erreur", el("p", { attributs: { "data-code": etat.panne.code } }, ...noeudsPanne(etat.panne.code, etat.panne.erreur, ["comptes.", ...PREFIXES]))),
        etat.fournisseur !== null ? actions(bouton(t("portefeuille.redemander"), () => void obtenirComptes())) : null,
      );
    }
  }
  remplacer(zones.comptes, ...parties);
  rendreEtapes();
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
  remplacer(zones.texte, el("p", { classe: "nt-attenue", texte: t("inscription.preparation") }));
  // EX-13.48, point 5 (révision 0.6) : l'authentification qui couvre
  // `preparer_inscription` doit couvrir aussi l'`inscrire` qui suit, au terme
  // de l'attente admise ; sinon la page fait réauthentifier d'abord, avant de
  // tenir un défi qu'une navigation ferait perdre.
  const s = await lireSession();
  if (g !== etat.generation) return;
  if (s.etat !== "session") {
    vider(zones.texte);
    if (s.etat === "erreur") afficherErreur(zones.resultat, s.erreur);
    else if (s.etat === "identite_invalide") remplacer(zones.resultat, message("erreur", paragrapheCode("identite_invalide", ["raison."])));
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
    remplacer(zones.resultat, message("erreur", paragrapheCode(ecart, ["defi.", "console."]), el("p", { texte: t("inscription.defi_refuse") })));
    return;
  }
  etat.defi = { message: r.valeur.message, fields: r.valeur.fields, adresse };
  rendreTexte();
}

function rendreTexte() {
  const d = etat.defi;
  if (d === null) {
    vider(zones.texte);
    rendreEtapes();
    return;
  }
  const ol = el("ol", { classe: "texte-inscription", attributs: { id: "texte-inscription" } });
  // Le texte à signer est celui du service, que la console a reconstruit et comparé (EX-13.13) : il s'affiche tel quel.
  for (const ligne of d.message.split("\n")) ajouter(ol, el("li", { texte: ligne, attributs: { "data-valeur": "" } }));
  remplacer(
    zones.texte,
    el("h3", { texte: t("inscription.texte") }),
    el("p", { texte: t("inscription.texte_verifier") }),
    ol,
    actions(bouton(t("inscription.signer"), () => void signer(), { actif: !etat.enCours, genre: "principal", icone: "cadenas" })),
    etat.enCours ? message("info", el("p", { texte: t("signature.en_cours") })) : null,
  );
  rendreEtapes();
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
    else if (s.etat === "identite_invalide") remplacer(zones.resultat, message("erreur", paragrapheCode("identite_invalide", ["raison."])));
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
    remplacer(zones.resultat, message("erreur", paragrapheCode("inscription_expiree", ["raison."]), el("p", { texte: t("inscription.recommencer"), attributs: { "data-consigne": "recommencer" } })));
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
    remplacer(zones.resultat, message("erreur", el("p", { attributs: { "data-code": "delai_depasse" } }, ...noeudsPanne("delai_depasse", null, PREFIXES))));
    return;
  }
  const verdict = verifierReponse(reponse, utf8(d.message), d.adresse);
  if (verdict.outcome !== "accepte") {
    abandonner();
    rendreComptes();
    const sens = sensCode(verdict.reason, PREFIXES);
    const parties = [sens, el("p", { classe: sens === null ? null : "phrase-fixee", attributs: { "data-code": verdict.reason } }, ...noeudsPanne(verdict.reason, reponse.error ?? null, PREFIXES))];
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
    remplacer(zones.resultat, message("succes", el("p", { texte: t("inscription.inscrite", { adresse: String(v.address), etat: t(`adresse_etat.${v.state}`) }), attributs: { "data-resultat": "inscription_envoyee" } }), el("p", { texte: t("inscription.validation_sens") })));
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
  principal().appendChild(el("main", { classe: "nt-page" }, zones.entree, zones.inscription, zones.resultat));
  await lireAnnuaire();
}

void demarrer();
