// Écran « Connexion locale » (contrat de l'étape 6, 3.1 et 3.4 ; CT-3 EX-13.43,
// EX-13.47) : formulaire nom et mot de passe, envoyé par `fetch`
// (`POST /connexion/locale`, JSON) ; `form-action 'none'` interdit l'envoi du
// formulaire lui-même. 204 : navigation vers le paramètre `retour` de
// l'adresse de l'écran, retenu comme en EX-13.43 (un chemin d'écran de la
// table, `/tickets` sinon). Refus : le texte et le code, et pour
// `essai_trop_tot`, le délai. Cet écran ne lit pas la session.

import { el, message, remplacer } from "../commun/dom.mjs";
import { t } from "../commun/libelles.mjs";
import { ErreurAppel, connexionLocale } from "../commun/client.mjs";
import { afficherErreur, principal } from "../commun/cadre.mjs";

const MOTIF_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;

/** Le chemin de retour retenu (EX-13.43) : aucune redirection ouverte. */
export function retourRetenu(recherche) {
  const r = new URLSearchParams(recherche).get("retour");
  if (r === "/tickets" || r === "/inscription" || r === "/annuaire") return r;
  if (r !== null && r.startsWith("/tickets/")) {
    const id = r.slice("/tickets/".length);
    if (MOTIF_TICKET.test(id) && id.length >= 5 && id.length <= 128) return r;
  }
  return "/tickets";
}

function demarrer() {
  const zone = el("div", { attributs: { id: "zone-resultat", "aria-live": "polite" } });
  const nom = el("input", { attributs: { id: "nom", name: "nom", type: "text", autocomplete: "username", required: true, maxlength: "255" } });
  const mdp = el("input", { attributs: { id: "mot-de-passe", name: "mot-de-passe", type: "password", autocomplete: "current-password", required: true, maxlength: "1024" } });
  const envoi = el("button", { classe: "bouton principal", texte: t("connexion.envoyer"), attributs: { type: "submit" } });
  const formulaire = el(
    "form",
    { attributs: { id: "formulaire-connexion", novalidate: true } },
    el("p", {}, el("label", { texte: t("connexion.nom"), attributs: { for: "nom" } }), nom),
    el("p", {}, el("label", { texte: t("connexion.mot_de_passe"), attributs: { for: "mot-de-passe" } }), mdp),
    envoi,
  );
  formulaire.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (nom.value === "" || mdp.value === "") {
      remplacer(zone, message("erreur", el("p", { texte: t("connexion.champs_requis") })));
      return;
    }
    envoi.disabled = true;
    remplacer(zone, el("p", { classe: "discret", texte: t("connexion.en_cours") }));
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
  remplacer(principal(), el("main", { classe: "contenu" }, el("h1", { texte: t("connexion.titre") }), el("p", { texte: t("connexion.sens") }), formulaire, zone));
}

demarrer();
