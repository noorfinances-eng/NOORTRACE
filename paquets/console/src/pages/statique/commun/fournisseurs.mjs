// Portefeuilles de navigateur vus des écrans Ticket et Mon adresse (CT-3
// EX-13.22, EX-13.23, EX-13.29 ; parcours a et b de 13.9 à 13.11) :
// découverte EIP-6963 posée avant toute autre opération (`Decouverte` de la
// bibliothèque sur `window`), message « aucun portefeuille ne s'est annoncé »
// 1 000 ms après le lancement si la liste est vide (et pas avant), liste dans
// l'ordre des premières annonces avec le nom, l'icône rendue par `<img>`
// seulement, et `rdns` « déclaré par le portefeuille, non vérifié » ; aucun
// fournisseur présélectionné ; appels EIP-1193 `request` dont la promesse
// rompue est lue sans confiance (le fournisseur est tenu pour adverse) ;
// `window.ethereum` n'est jamais lu.

import { Decouverte, analyserComptes, codeErreurPortefeuille } from "noortrace-console/index.mjs";
import { el, ajouter, bouton, donnee, icone, message, pastille, remplacer } from "./dom.mjs";
import { t, texteCode } from "./libelles.mjs";
import { paragrapheCode, phraseCode } from "./cadre.mjs";

/** Délai du point 6 d'EX-13.22, en millisecondes. */
export const DELAI_AUCUN_FOURNISSEUR_MS = 1000;

/**
 * Pose l'écouteur de `eip6963:announceProvider` et émet
 * `eip6963:requestProvider` (EX-13.22, point 1), puis arme le délai du
 * point 6. À appeler avant toute autre opération de l'écran.
 */
export function lancerDecouverte() {
  const decouverte = new Decouverte(window);
  decouverte.lancer();
  const rappels = [];
  let echu = false;
  const prevenir = () => {
    for (const f of [...rappels]) f();
  };
  setTimeout(() => {
    echu = true;
    prevenir();
  }, DELAI_AUCUN_FOURNISSEUR_MS);
  decouverte.surChangement(prevenir);
  return {
    get fournisseurs() {
      return decouverte.fournisseurs;
    },
    get ecartees() {
      return decouverte.ecartees;
    },
    /** Vrai 1 000 ms après le lancement. */
    get echu() {
      return echu;
    },
    surChangement(f) {
      rappels.push(f);
    },
  };
}

// Vrai si l'image chargée est d'une seule couleur (ou entièrement transparente) : elle ne montre rien.
function imageUnie(img) {
  try {
    const toile = document.createElement("canvas");
    toile.width = 8;
    toile.height = 8;
    const trace = toile.getContext("2d");
    trace.drawImage(img, 0, 0, 8, 8);
    const points = trace.getImageData(0, 0, 8, 8).data;
    for (let i = 4; i < points.length; i += 1) if (points[i] !== points[i % 4]) return false;
    return true;
  } catch {
    // Image illisible par la page : elle est laissée telle que le portefeuille la fournit.
    return false;
  }
}

/**
 * L'icône d'un portefeuille annoncé : celle qu'il fournit, telle quelle. Si
 * elle manque, ne se charge pas ou est d'une seule couleur (un carré uni
 * ressemble à une image manquante), un pictogramme neutre de portefeuille la
 * remplace : un tracé du gabarit de la page, rien n'est chargé.
 */
function iconeFournisseur(f) {
  const cadre = el("span", { classe: "fournisseur-icone", attributs: { "data-icone": "annoncee" } });
  const neutre = () => {
    cadre.setAttribute("data-icone", "neutre");
    remplacer(cadre, icone("portefeuille"));
  };
  if (typeof f.icon !== "string" || f.icon === "") {
    neutre();
    return cadre;
  }
  const img = el("img", { attributs: { src: f.icon, alt: "", width: "32", height: "32" } });
  img.addEventListener("error", neutre);
  img.addEventListener("load", () => {
    if (imageUnie(img)) neutre();
  });
  cadre.appendChild(img);
  return cadre;
}

/**
 * Affiche la liste des fournisseurs annoncés (EX-13.22, points 4 à 6) et, s'il
 * y a lieu, les annonces écartées.
 * @param {HTMLElement} conteneur
 * @param {ReturnType<typeof lancerDecouverte>} decouverte
 * @param {object|null} choisi fournisseur choisi (comparé par `provider`)
 * @param {(f: object) => void} surChoix
 * @param {boolean} actif faux : les boutons de choix sont inactifs
 * @param {boolean} titre faux : sans l'intitulé « Portefeuille » (l'écran le porte déjà)
 */
export function rendreFournisseurs(conteneur, decouverte, choisi, surChoix, actif = true, titre = true) {
  const liste = decouverte.fournisseurs;
  const parties = titre ? [el("h3", { texte: t("portefeuille.titre") })] : [];
  if (liste.length === 0) {
    parties.push(decouverte.echu ? message("alerte", paragrapheCode("aucun_fournisseur", ["console."])) : el("p", { classe: "discret nt-attenue", texte: t("portefeuille.recherche") }));
  } else {
    const ul = el("ul", { classe: "liste-nue fournisseurs" });
    for (const f of liste) {
      const estChoisi = choisi !== null && choisi.provider === f.provider;
      ajouter(
        ul,
        el(
          "li",
          { classe: estChoisi ? "fournisseur choisi" : "fournisseur", attributs: { "data-uuid": f.uuid } },
          iconeFournisseur(f),
          // Le nom et l'identifiant viennent du portefeuille : ils s'affichent tels quels.
          el("div", { classe: "fournisseur-texte" }, donnee(f.name, "fournisseur-nom"), donnee(t("portefeuille.rdns", { rdns: f.rdns }), "fournisseur-rdns")),
          estChoisi ? pastille("succes", t("portefeuille.choisi"), "coche") : bouton(t("portefeuille.choisir"), () => surChoix(f), { actif }),
        ),
      );
    }
    parties.push(ul);
    // Un portefeuille pas encore choisi n'est pas une panne : la phrase, sans code (EX-13.29, complément du 2026-11-18).
    if (choisi === null) parties.push(el("p", { classe: "discret nt-attenue nt-petit", attributs: { "data-code": "fournisseur_non_choisi" } }, ...phraseCode("fournisseur_non_choisi", ["console."])));
  }
  const ecartees = decouverte.ecartees;
  if (ecartees.some((e) => e.reason === "annonce_en_double")) {
    parties.push(message("alerte", paragrapheCode("annonce_en_double", ["console."])));
  }
  if (ecartees.some((e) => e.reason === "annonce_invalide")) {
    parties.push(message("alerte", paragrapheCode("annonce_invalide", ["console."])));
  }
  remplacer(conteneur, ...parties);
}

// Lecture sans confiance d'une erreur EIP-1193 (`{ code, message }`).
function lireErreur(e) {
  try {
    const code = e !== null && typeof e === "object" && typeof e.code === "number" ? e.code : null;
    const texte = e !== null && typeof e === "object" && typeof e.message === "string" ? e.message : "";
    return { code, message: texte };
  } catch {
    return { code: null, message: "" };
  }
}

/**
 * Appelle `provider.request(requete)` et rend `{ result }` ou `{ error }`
 * (`$defs/reponse_portefeuille`), sans jamais lever.
 */
export function appelFournisseur(provider, requete) {
  return new Promise((resolve) => {
    let p;
    try {
      p = provider.request(requete);
    } catch (e) {
      resolve({ error: lireErreur(e) });
      return;
    }
    Promise.resolve(p).then(
      (r) => resolve({ result: r }),
      (e) => resolve({ error: lireErreur(e) }),
    );
  });
}

/**
 * `eth_requestAccounts` (EX-13.23) : `{ comptes }` (adresses en minuscules),
 * ou `{ code, erreur }`. Rompu par 4100 : redemandé une fois (13.14).
 */
export async function demanderComptes(provider) {
  const une = async () => {
    const r = await appelFournisseur(provider, { method: "eth_requestAccounts" });
    if (Object.prototype.hasOwnProperty.call(r, "error")) return { code: codeErreurPortefeuille(r.error), erreur: r.error };
    const comptes = analyserComptes(r.result);
    if (comptes === null) return { code: "reponse_invalide", erreur: null };
    return { comptes };
  };
  const r = await une();
  if (r.code === "non_autorise") return une();
  return r;
}

/** Pose un écouteur EIP-1193 et rend la fonction qui le retire ; aucune erreur ne sort. */
export function ecouter(provider, evenement, fonction) {
  try {
    if (typeof provider.on === "function") provider.on(evenement, fonction);
  } catch {
    return () => {};
  }
  return () => {
    try {
      if (typeof provider.removeListener === "function") provider.removeListener(evenement, fonction);
    } catch {
      // le fournisseur est tenu pour adverse : rien à faire
    }
  };
}

/**
 * Texte d'une panne du portefeuille (13.14) : le texte du code, et pour
 * `erreur_portefeuille`, le code et le message reçus, comme du texte.
 * @param {string} code
 * @param {{code: number|null, message: string}|null} erreur
 * @param {string[]} prefixes
 */
export function textePanne(code, erreur, prefixes) {
  const base = texteCode(code, prefixes);
  if (code === "erreur_portefeuille" && erreur) {
    return `${base} ${t("portefeuille.erreur_recue", { code: erreur.code === null ? t("portefeuille.sans_code") : erreur.code, message: erreur.message })}`;
  }
  return base;
}

/**
 * Les nœuds d'une panne du portefeuille : la phrase ; pour
 * `erreur_portefeuille`, le code et le message reçus, comme du texte ; puis
 * le code de la panne entre parenthèses, à la fin (EX-13.29).
 * @param {string} code
 * @param {{code: number|null, message: string}|null} erreur
 * @param {string[]} prefixes
 * @returns {HTMLElement[]}
 */
export function noeudsPanne(code, erreur, prefixes) {
  const noeuds = phraseCode(code, prefixes);
  if (code === "erreur_portefeuille" && erreur) {
    noeuds.splice(1, 0, donnee(` ${t("portefeuille.erreur_recue", { code: erreur.code === null ? t("portefeuille.sans_code") : erreur.code, message: erreur.message })}`));
  }
  return noeuds;
}
