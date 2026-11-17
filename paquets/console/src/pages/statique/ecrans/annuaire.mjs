// Écran « Annuaire » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 13.6, EX-13.17,
// EX-13.19, EX-13.43) : pour une session dont `administrator` est vrai,
// `annuaire` complet ; par entrée et par adresse, les actions d'EX-13.17 et
// leurs motifs (valider, révoquer, désactiver, réactiver, lier et délier un
// alias de demandeur), la consigne « Avant de valider » avant chaque
// validation ; « Exporter » télécharge le document rendu par `annuaire`, aux
// octets reçus (`Blob` et lien `download`). Une autre session : l'écran le
// dit et n'offre rien. Le service refait chaque contrôle.

import { el, actions, ajouter, bouton, code, definitions, detail, message, pastille, remplacer } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { appeler } from "../commun/client.mjs";
import { afficherErreur, demarrerEcran, entete, instant, paragrapheCode, principal, texteInstant } from "../commun/cadre.mjs";

const etat = { session: null, document: null, octets: null, confirmation: null };

const zones = {
  document: el("div", { classe: "nt-pile nt-pile-large", attributs: { id: "zone-annuaire" } }),
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
    remplacer(zones.resultat, message("succes", el("p", { texte: t("annuaire.action_faite", { action: t(`annuaire.action.${methode}`) }), attributs: { "data-resultat": methode } })));
  } catch (e) {
    afficherErreur(zones.resultat, e);
  }
  await lire();
}

function champMotif(id) {
  return el("input", { classe: "nt-saisie", attributs: { type: "text", id, maxlength: "4096", "aria-label": t("annuaire.motif") } });
}

const motif = (champ) => (champ.value === "" ? null : champ.value);

// Une action avec motif facultatif, confirmée par un second clic. Révoquer et
// désactiver sont des gestes qui retirent un droit : leurs boutons le disent
// par leur genre.
const GENRE_ACTION = Object.freeze({ valider: "principal", revoquer: "danger", desactiver: "danger", reactiver: "principal" });

function actionAvecMotif(cle, methode, corps, avant = null) {
  const id = `motif-${methode}-${corps.entry}-${corps.address ?? ""}`;
  const confirmer = etat.confirmation === id;
  const champ = champMotif(id);
  if (!confirmer) {
    return el(
      "div",
      { classe: "action", attributs: { "data-action": methode } },
      bouton(
        t(`annuaire.bouton.${cle}`),
        () => {
          etat.confirmation = id;
          rendre();
        },
        { petit: true },
      ),
    );
  }
  return el(
    "div",
    { classe: "action confirmation nt-pile", attributs: { "data-action": methode, "data-confirmation": "" } },
    avant,
    methode === "valider" ? null : el("div", { classe: "nt-champ" }, el("label", { classe: "nt-libelle", texte: t("annuaire.motif"), attributs: { for: id } }), champ),
    actions(
      bouton(t(`annuaire.confirmer.${cle}`), () => void agir(methode, methode === "valider" ? corps : { ...corps, reason: motif(champ) }), { genre: GENRE_ACTION[cle] }),
      bouton(t("action.annuler"), () => {
        etat.confirmation = null;
        rendre();
      }),
    ),
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

const ETATS_ADRESSE = Object.freeze({ en_attente: ["attente", "horloge"], active: ["succes", "coche"], revoquee: ["refus", "croix"] });

function rendre() {
  const doc = etat.document;
  if (doc === null || typeof doc !== "object" || !Array.isArray(doc.entries)) {
    remplacer(zones.document, message("erreur", paragrapheCode("reponse_service_invalide", ["console."])));
    return;
  }
  const export_ = bouton(t("annuaire.exporter"), exporter, { icone: "dossier" });
  export_.setAttribute("id", "exporter");
  const parties = [
    el(
      "section",
      { classe: "nt-carte" },
      el("div", { classe: "nt-carte-titre" }, el("h2", { texte: t("annuaire.document") }), el("span", { classe: "nt-carte-note", texte: t("annuaire.compte", { entrees: doc.entries.length, revision: String(doc.revision) }) })),
      definitions([
        [t("annuaire.org"), code(String(doc.org))],
        [t("annuaire.org_id"), code(String(doc.org_id))],
        [t("annuaire.origine"), code(String(doc.console_origin))],
        [t("annuaire.revision"), String(doc.revision)],
        [t("annuaire.mise_a_jour"), doc.updated_at === null ? t("modele.vide") : instant(String(doc.updated_at))],
        [t("annuaire.administrateurs"), el("ul", { classe: "liste-nue" }, ...doc.administrators.map((a) => el("li", {}, code(a))))],
      ]),
      actions(export_),
      el("p", { classe: "nt-aide", texte: t("annuaire.exporter_sens") }),
    ),
  ];
  for (const e of doc.entries) {
    const soi = e.session_identity === identite();
    const adresses = el("ul", { classe: "liste-nue adresses" });
    for (const a of e.addresses) {
      const actionsAdresse = [];
      if (a.state === "en_attente" && e.active && !soi) {
        actionsAdresse.push(actionAvecMotif("valider", "valider", { entry: e.id, address: a.address }, message("alerte", el("p", { classe: "nt-bandeau-titre", texte: t("annuaire.avant_valider_titre") }), el("p", { texte: t("annuaire.avant_valider") }))));
      }
      if (a.state === "en_attente" || a.state === "active") actionsAdresse.push(actionAvecMotif("revoquer", "revoquer", { entry: e.id, address: a.address }));
      const [genre, nomIcone] = ETATS_ADRESSE[a.state] ?? ["neutre", "question"];
      ajouter(
        adresses,
        el(
          "li",
          { classe: "nt-encart nt-pile adresse", attributs: { "data-adresse": a.address, "data-etat": a.state } },
          el("div", { classe: "adresse-tete" }, code(a.address), pastille(genre, t(`adresse_etat.${a.state}`), nomIcone)),
          a.validated_at !== null ? el("p", { classe: "nt-attenue nt-petit", texte: t("annuaire.validee", { par: String(a.validated_by), le: texteInstant(a.validated_at) }) }) : null,
          a.revoked_at !== null ? el("p", { classe: "nt-attenue nt-petit", texte: t("annuaire.revoquee", { par: String(a.revoked_by), le: texteInstant(a.revoked_at), cause: t(`revocation.${a.revocation_cause}`) }) }) : null,
          a.revocation_reason ? el("p", { classe: "nt-attenue nt-petit", texte: t("modele.votes.motif", { motif: a.revocation_reason }) }) : null,
          detail(t("annuaire.preuve"), null, el("pre", { classe: "nt-pre", texte: a.proof.message }), definitions([[t("annuaire.recue"), code(a.proof.received_at)]])),
          actionsAdresse.length > 0 ? el("div", { classe: "actions-ligne" }, ...actionsAdresse) : null,
        ),
      );
    }
    const alias = el("ul", { classe: "liste-nue alias" });
    for (const lb of e.requester_identities) {
      ajouter(alias, el("li", { classe: "compte", attributs: { "data-alias": lb } }, code(lb), " ", bouton(t("annuaire.bouton.delier"), () => void agir("delier_demandeur", { entry: e.id, launched_by: lb }), { petit: true })));
    }
    const champLier = el("input", { classe: "nt-saisie", attributs: { type: "text", maxlength: "256", id: `lier-${e.id}` } });
    const lier = el(
      "div",
      { classe: "action nt-champ", attributs: { "data-action": "lier_demandeur" } },
      el("label", { classe: "nt-libelle", texte: t("annuaire.alias_nouveau"), attributs: { for: `lier-${e.id}` } }),
      el(
        "div",
        { classe: "champ-et-bouton" },
        champLier,
        bouton(t("annuaire.bouton.lier"), () => {
          if (champLier.value !== "") void agir("lier_demandeur", { entry: e.id, launched_by: champLier.value });
        }),
      ),
    );
    const entreeActions = e.active ? actionAvecMotif("desactiver", "desactiver", { entry: e.id }) : actionAvecMotif("reactiver", "reactiver", { entry: e.id });
    parties.push(
      el(
        "section",
        { classe: "nt-carte entree", attributs: { "data-entree": e.id } },
        el(
          "div",
          { classe: "nt-carte-titre" },
          el("h2", {}, e.display_name === null ? code(e.id) : el("span", { texte: String(e.display_name) }), soi ? el("span", { classe: "nt-attenue nt-petit", texte: ` ${t("annuaire.soi")}` }) : null),
          e.active ? pastille("succes", t("inscription.entree.active"), "coche") : pastille("neutre", t("inscription.entree.desactivee"), "tiret"),
        ),
        definitions([
          [t("inscription.entree.id"), code(e.id)],
          [t("annuaire.identite"), code(e.session_identity)],
          [t("annuaire.external_id"), e.external_id === null ? t("modele.vide") : code(String(e.external_id))],
          [t("annuaire.creee"), instant(e.created_at)],
        ]),
        el("h3", { texte: t("annuaire.adresses") }),
        e.addresses.length === 0 ? el("p", { classe: "nt-attenue", texte: t("inscription.aucune_adresse") }) : adresses,
        el("h3", { texte: t("annuaire.alias") }),
        e.requester_identities.length === 0 ? el("p", { classe: "nt-attenue", texte: t("annuaire.aucun_alias") }) : alias,
        lier,
        entreeActions,
      ),
    );
  }
  if (doc.entries.length === 0) parties.push(el("div", { classe: "nt-vide" }, el("p", { classe: "nt-vide-titre", texte: t("annuaire.aucune_entree") })));
  remplacer(zones.document, ...parties);
}

async function demarrer() {
  const s = await demarrerEcran("annuaire");
  if (s === null) return;
  etat.session = s;
  const contenu = el("main", { classe: "nt-page" }, entete({ titre: t("annuaire.titre"), sousTitre: t("annuaire.sous_titre") }));
  principal().appendChild(contenu);
  if (!s.administrator) {
    // Contrat 3.4 : l'écran le dit et n'offre rien.
    ajouter(contenu, message("alerte", el("p", { texte: t("annuaire.non_administrateur"), attributs: { "data-code": "non_administrateur" } })));
    return;
  }
  ajouter(contenu, zones.resultat, zones.document);
  await lire();
}

void demarrer();
