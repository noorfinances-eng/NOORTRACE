// Écran « Connexion locale » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.43,
// EX-13.47) : formulaire nom et mot de passe, envoyé par `fetch`
// (`POST /connexion/locale`, JSON) ; `form-action 'none'` interdit l'envoi du
// formulaire lui-même. 204 : navigation vers le paramètre `retour` de
// l'adresse de l'écran, retenu comme en EX-13.43 (un chemin d'écran de la
// table, `/tickets` sinon). Refus : le texte et le code, et pour
// `essai_trop_tot`, le délai. Cet écran ne lit pas la session.

import { el, actions, message, remplacer } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { ErreurAppel, connexionLocale } from "../commun/client.mjs";
import { afficherErreur, bascule, estIdentifiantTicket, logo, principal } from "../commun/cadre.mjs";

/** Le chemin de retour retenu (EX-13.43) : aucune redirection ouverte. */
export function retourRetenu(recherche) {
  const r = new URLSearchParams(recherche).get("retour");
  if (r === "/tickets" || r === "/inscription" || r === "/annuaire") return r;
  if (r !== null && r.startsWith("/tickets/") && estIdentifiantTicket(r.slice("/tickets/".length))) return r;
  return "/tickets";
}

function demarrer() {
  const zone = el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } });
  const nom = el("input", { classe: "nt-saisie", attributs: { id: "nom", name: "nom", type: "text", autocomplete: "username", required: true, maxlength: "255" } });
  const mdp = el("input", { classe: "nt-saisie", attributs: { id: "mot-de-passe", name: "mot-de-passe", type: "password", autocomplete: "current-password", required: true, maxlength: "1024" } });
  const envoi = el("button", { classe: "nt-bouton nt-bouton-principal", texte: t("connexion.envoyer"), attributs: { type: "submit" } });
  const formulaire = el(
    "form",
    { classe: "nt-formulaire", attributs: { id: "formulaire-connexion", novalidate: true } },
    el("div", { classe: "nt-champ" }, el("label", { classe: "nt-libelle", texte: t("connexion.nom"), attributs: { for: "nom" } }), nom),
    el("div", { classe: "nt-champ" }, el("label", { classe: "nt-libelle", texte: t("connexion.mot_de_passe"), attributs: { for: "mot-de-passe" } }), mdp),
    actions(envoi),
  );
  formulaire.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (nom.value === "" || mdp.value === "") {
      remplacer(zone, message("erreur", el("p", { texte: t("connexion.champs_requis") })));
      return;
    }
    envoi.disabled = true;
    remplacer(zone, el("p", { classe: "nt-attenue", texte: t("connexion.en_cours") }));
    try {
      await connexionLocale(nom.value, mdp.value);
      window.location.assign(retourRetenu(window.location.search));
    } catch (err) {
      envoi.disabled = false;
      mdp.value = "";
      if (err instanceof ErreurAppel && err.code === "essai_trop_tot" && Number.isSafeInteger(err.data.retry_after_s)) {
        afficherErreur(zone, err, el("p", { texte: t("connexion.reessayer_dans", { s: err.data.retry_after_s }), attributs: { "data-retry-after": String(err.data.retry_after_s) } }));
      } else {
        afficherErreur(zone, err);
      }
    }
  });
  const barre = el("header", { classe: "nt-barre" }, el("div", { classe: "nt-barre-dedans" }, logo(null), el("div", { classe: "nt-barre-outils" }, bascule())));
  const carte = el("section", { classe: "nt-carte carte-connexion" }, el("div", { classe: "nt-pile" }, el("h1", { texte: t("connexion.titre") }), el("p", { classe: "nt-sous-titre", texte: t("connexion.sens") }), el("p", { classe: "nt-attenue nt-petit", texte: t("connexion.locale") })), formulaire, zone);
  remplacer(principal(), barre, el("main", { classe: "nt-page nt-page-etroite" }, carte));
}

demarrer();
