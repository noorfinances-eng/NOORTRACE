// Écran « Annuaire » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 13.6, EX-13.17,
// EX-13.19, EX-13.43) : pour une session dont `administrator` est vrai,
// `annuaire` complet ; par entrée et par adresse, les actions d'EX-13.17 et
// leurs motifs (valider, révoquer, désactiver, réactiver, lier et délier un
// alias de demandeur), la consigne « Avant de valider » avant chaque
// validation ; « Exporter » télécharge le document rendu par `annuaire`, aux
// octets reçus (`Blob` et lien `download`). Une autre session : l'écran le
// dit et n'offre rien. Le service refait chaque contrôle.

import { el, ajouter, bouton, code, definitions, message, remplacer } from "../commun/dom.mjs";
import { t, texteCode } from "../commun/libelles.mjs";
import { appeler } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, principal, section } from "../commun/cadre.mjs";

const etat = { session: null, document: null, octets: null, confirmation: null };

const zones = {
  document: el("div", { attributs: { id: "zone-annuaire" } }),
  resultat: el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } }),
};

function identite() {
  return etat.session.session_identity;
}

async function lire() {
  try {
    const r = await appeler("annuaire", { session_identity: identite() });
    etat.document = r.valeur;
    etat.octets = r.octets;
    rendre();
  } catch (e) {
    afficherErreur(zones.document, e);
  }
}

// Une action d'EX-13.17 : appel, résultat, relecture.
async function agir(methode, corps) {
  etat.confirmation = null;
  try {
    await appeler(methode, { session_identity: identite(), ...corps });
    remplacer(zones.resultat, message("info", el("p", { texte: t("annuaire.action_faite", { action: t(`annuaire.action.${methode}`) }), attributs: { "data-resultat": methode } })));
  } catch (e) {
    afficherErreur(zones.resultat, e);
  }
  await lire();
}

function champMotif(id) {
  return el("input", { attributs: { type: "text", id, maxlength: "4096", "aria-label": t("annuaire.motif") } });
}

const motif = (champ) => (champ.value === "" ? null : champ.value);

// Une action avec motif facultatif, confirmée par un second clic.
function actionAvecMotif(cle, methode, corps, avant = null) {
  const id = `motif-${methode}-${corps.entry}-${corps.address ?? ""}`;
  const confirmer = etat.confirmation === id;
  const champ = champMotif(id);
  if (!confirmer) {
    return el(
      "div",
      { classe: "action", attributs: { "data-action": methode } },
      bouton(t(`annuaire.bouton.${cle}`), () => {
        etat.confirmation = id;
        rendre();
      }),
    );
  }
  return el(
    "div",
    { classe: "action confirmation", attributs: { "data-action": methode, "data-confirmation": "" } },
    avant,
    methode === "valider" ? null : el("label", { texte: t("annuaire.motif"), attributs: { for: id } }),
    methode === "valider" ? null : champ,
    bouton(t(`annuaire.confirmer.${cle}`), () => void agir(methode, methode === "valider" ? corps : { ...corps, reason: motif(champ) }), { classe: "bouton principal" }),
    bouton(t("action.annuler"), () => {
      etat.confirmation = null;
      rendre();
    }),
  );
}

function exporter() {
  // Les octets reçus, tels quels (contrat 3.4).
  const blob = new Blob([etat.octets], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const org = typeof etat.document.org === "string" ? etat.document.org.replace(/[^a-z0-9-]/g, "-") : "organisation";
  const lien = el("a", { attributs: { href: url, download: `annuaire-${org}-revision-${Number(etat.document.revision)}.json` } });
  document.body.appendChild(lien);
  lien.click();
  lien.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

function rendre() {
  const doc = etat.document;
  if (doc === null || typeof doc !== "object" || !Array.isArray(doc.entries)) {
    remplacer(zones.document, message("erreur", el("p", { texte: texteCode("reponse_service_invalide", ["console."]), attributs: { "data-code": "reponse_service_invalide" } })));
    return;
  }
  const parties = [
    definitions([
      [t("annuaire.org"), code(String(doc.org))],
      [t("annuaire.org_id"), code(String(doc.org_id))],
      [t("annuaire.origine"), code(String(doc.console_origin))],
      [t("annuaire.revision"), String(doc.revision)],
      [t("annuaire.mise_a_jour"), doc.updated_at === null ? t("modele.vide") : code(String(doc.updated_at))],
      [t("annuaire.administrateurs"), el("ul", {}, ...doc.administrators.map((a) => el("li", {}, code(a))))],
    ]),
    bouton(t("annuaire.exporter"), exporter, { classe: "bouton" }),
    el("p", { classe: "discret", texte: t("annuaire.exporter_sens") }),
  ];
  parties[1].setAttribute("id", "exporter");
  for (const e of doc.entries) {
    const soi = e.session_identity === identite();
    const adresses = el("ul", { classe: "adresses" });
    for (const a of e.addresses) {
      const actions = [];
      if (a.state === "en_attente" && e.active && !soi) {
        actions.push(actionAvecMotif("valider", "valider", { entry: e.id, address: a.address }, message("alerte", el("p", { texte: t("annuaire.avant_valider_titre") }), el("p", { texte: t("annuaire.avant_valider") }))));
      }
      if (a.state === "en_attente" || a.state === "active") actions.push(actionAvecMotif("revoquer", "revoquer", { entry: e.id, address: a.address }));
      ajouter(
        adresses,
        el(
          "li",
          { attributs: { "data-adresse": a.address, "data-etat": a.state } },
          code(a.address),
          " ",
          t(`adresse_etat.${a.state}`),
          a.validated_at !== null ? el("span", {}, " ", t("annuaire.validee", { par: String(a.validated_by), le: a.validated_at })) : null,
          a.revoked_at !== null ? el("span", {}, " ", t("annuaire.revoquee", { par: String(a.revoked_by), le: a.revoked_at, cause: t(`revocation.${a.revocation_cause}`) })) : null,
          a.revocation_reason ? el("span", {}, " ", t("modele.votes.motif", { motif: a.revocation_reason })) : null,
          el("details", {}, el("summary", { texte: t("annuaire.preuve") }), el("pre", { classe: "fixe", texte: a.proof.message }), definitions([[t("annuaire.recue"), code(a.proof.received_at)]])),
          ...actions,
        ),
      );
    }
    const alias = el("ul", { classe: "alias" });
    for (const lb of e.requester_identities) {
      ajouter(alias, el("li", { attributs: { "data-alias": lb } }, code(lb), " ", bouton(t("annuaire.bouton.delier"), () => void agir("delier_demandeur", { entry: e.id, launched_by: lb }))));
    }
    const champLier = el("input", { attributs: { type: "text", maxlength: "256", "aria-label": t("annuaire.alias_nouveau"), id: `lier-${e.id}` } });
    const lier = el(
      "div",
      { classe: "action", attributs: { "data-action": "lier_demandeur" } },
      el("label", { texte: t("annuaire.alias_nouveau"), attributs: { for: `lier-${e.id}` } }),
      champLier,
      bouton(t("annuaire.bouton.lier"), () => {
        if (champLier.value !== "") void agir("lier_demandeur", { entry: e.id, launched_by: champLier.value });
      }),
    );
    const entreeActions = e.active ? actionAvecMotif("desactiver", "desactiver", { entry: e.id }) : actionAvecMotif("reactiver", "reactiver", { entry: e.id });
    parties.push(
      el(
        "section",
        { classe: "bloc entree", attributs: { "data-entree": e.id } },
        el("h2", {}, code(e.id), " ", e.display_name === null ? "" : String(e.display_name)),
        definitions([
          [t("annuaire.identite"), code(e.session_identity)],
          [t("annuaire.external_id"), e.external_id === null ? t("modele.vide") : code(String(e.external_id))],
          [t("annuaire.etat"), t(e.active ? "inscription.entree.active" : "inscription.entree.desactivee")],
          [t("annuaire.creee"), code(e.created_at)],
        ]),
        el("h3", { texte: t("annuaire.adresses") }),
        e.addresses.length === 0 ? el("p", { texte: t("inscription.aucune_adresse") }) : adresses,
        el("h3", { texte: t("annuaire.alias") }),
        e.requester_identities.length === 0 ? el("p", { texte: t("modele.vide") }) : alias,
        lier,
        entreeActions,
      ),
    );
  }
  if (doc.entries.length === 0) parties.push(el("p", { texte: t("annuaire.aucune_entree") }));
  remplacer(zones.document, ...parties);
}

async function demarrer() {
  const s = await demarrerEcran("annuaire");
  if (s === null) return;
  etat.session = s;
  const contenu = el("main", { classe: "contenu" }, el("h1", { texte: t("annuaire.titre") }));
  principal().appendChild(contenu);
  if (!s.administrator) {
    // Contrat 3.4 : l'écran le dit et n'offre rien.
    ajouter(contenu, message("alerte", el("p", { texte: t("annuaire.non_administrateur"), attributs: { "data-code": "non_administrateur" } })));
    return;
  }
  ajouter(contenu, section(t("annuaire.document"), zones.resultat, zones.document));
  await lire();
}

void demarrer();
