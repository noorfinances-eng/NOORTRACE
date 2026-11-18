// Langage des écrans de l'outil d'inscription (complément du 2026-11-18, décision du porteur sur le langage des
// écrans ; paquets/inscription/INTERFACES.md 2.5) : la liste publiée des mots de technicien qui ne doivent pas se
// lire au premier niveau d'un écran, et la lecture de ce premier niveau dans une page.
//
// Premier niveau : le texte rendu de l'écran, hors des blocs repliés fermés (leur titre, lui, en fait partie), hors
// des valeurs venues des données (éléments marqués `data-valeur` : nom d'un client, d'un enregistreur, adresse,
// empreinte, identité, exemple de saisie), et hors de la mention que CT-4 fixe mot pour mot (élément marqué
// `data-phrase-fixee` : « confirmation hors bande absente », EX-7.26), affichée sous sa phrase courante.

/** Lettre d'un mot français : les motifs de JavaScript (`\b`) ne comptent pas les lettres accentuées. */
const LETTRE = "A-Za-zÀ-ÖØ-öø-ÿŒœ";
/** Motif d'un mot entier (`corps` : expression sans drapeau), insensible à la casse sauf `casse`. */
const entier = (corps, { casse = false } = {}) => new RegExp(`(?<![${LETTRE}0-9_])(?:${corps})(?![${LETTRE}0-9_])`, casse ? "" : "i");

/** Mots de technicien : `{ mot, motif }`. */
export const MOTS_TECHNIQUES = Object.freeze([
  // Liste commune aux trois écrans NOORTRACE.
  { mot: "oidc", motif: entier("oidc") },
  { mot: "adresse d'un site en clair dans une phrase", motif: /https?:\/\/[a-z0-9]/i },
  { mot: "chemin JSON employé comme libellé", motif: /(?:^|\s)\/[a-z][a-z0-9_]*(?:\s|$)/ },
  { mot: "condensé", motif: entier("condens[ée]e?s?") },
  { mot: "hachage", motif: entier("hach(?:ages?|ée?s?)") },
  { mot: "hors bande", motif: /hors[ -]bande/i },
  { mot: "clé de chaîne", motif: /cl[ée]s? de cha[îi]ne/i },
  { mot: "manifeste", motif: entier("manifestes?") },
  { mot: "ancre", motif: entier("ancr(?:es?|ée?s?|er|ages?)") },
  { mot: "RPC", motif: entier("RPC", { casse: true }) },
  { mot: "nonce", motif: entier("nonces?") },
  { mot: "regtest", motif: entier("regtest") },
  { mot: "drapeau de ligne de commande", motif: /(?:^|\s)--[a-z]/ },
  { mot: "identifiant de règle ou de contrôle", motif: entier("(?:EX|RG|OP|CP|AV|MN|TE|CLE)-[A-Z]?-?[0-9][0-9.]*", { casse: true }) },
  { mot: "renvoi à la spécification", motif: entier("CT-[0-9]+", { casse: true }) },
  { mot: "suite hexadécimale dans une phrase", motif: /0x[0-9a-f]{8,}/i },
  { mot: "nom de code (mots liés par « _ »)", motif: /(?<![A-Za-z0-9_])[a-z][a-z0-9]*(?:_[a-z0-9]+)+(?![A-Za-z0-9_])/ },
  // Mots propres à l'outil d'inscription.
  { mot: "slug", motif: entier("slugs?") },
  { mot: "jeu d'approbateurs", motif: entier("jeux?") },
  { mot: "seuil", motif: entier("seuils?") },
  { mot: "exploitant", motif: entier("exploitante?s?") },
  { mot: "agent (le service d'inscription)", motif: new RegExp(`(?<![${LETTRE}])agents?(?![${LETTRE}])(?! logiciel)`, "i") },
  { mot: "relayer", motif: new RegExp(`(?<![${LETTRE}])rela(?:i|y)`, "i") },
  { mot: "consigner", motif: new RegExp(`(?<![${LETTRE}])consign(?!es?(?![${LETTRE}]))`, "i") },
  { mot: "approvisionner", motif: /approvisionn/i },
  { mot: "trésorerie", motif: /tr[ée]sorerie/i },
  { mot: "clé de gouvernance", motif: /cl[ée]s? de gouvernance/i },
  { mot: "clé d'enregistreur", motif: /cl[ée]s? d'enregistreur/i },
  { mot: "transaction", motif: entier("transactions?") },
  { mot: "bloc", motif: entier("blocs?") },
  { mot: "capture", motif: new RegExp(`(?<![${LETTRE}])captur`, "i") },
  { mot: "nœud", motif: entier("n(?:œ|oe)uds?") },
  { mot: "validateur", motif: entier("validateurs?") },
  { mot: "gaz", motif: entier("gaz") },
  { mot: "wei", motif: entier("wei") },
  { mot: "JSON", motif: entier("JSON") },
  { mot: "SHA-256", motif: entier("SHA-?256") },
  { mot: "hexadécimal", motif: /hexad[ée]cima/i },
  { mot: "session", motif: entier("sessions?") },
  { mot: "Ed25519, EVM, BFT, API", motif: entier("Ed25519|EVM|BFT|API") },
  { mot: "octet", motif: entier("octets?") },
  { mot: "sortie de la commande", motif: /sortie (?:de la commande|standard|d'erreur)/i },
  { mot: "réseau de développement", motif: /r[ée]seau de d[ée]veloppement/i },
  // « Demande » est le mot de la console d'approbation, pour ce qu'un approbateur doit décider ; ici, ce que le
  // client signe se dit « document à faire signer par le client », ou « document signé ». Le verbe reste admis.
  { mot: "demande (nom : ici, « document à faire signer »)", motif: new RegExp(`(?<![${LETTRE}])(?:(?:la|une|cette|sa|les|des|ces|aucune|nouvelle|votre|chaque|de|sur|à la) demandes?|Demandes?)(?![${LETTRE}])`) },
]);

/** Mots de technicien trouvés dans un texte : `[{ mot, extrait }]`. */
export function motsTechniquesDans(texte) {
  const t = String(texte ?? "");
  const l = [];
  for (const { mot, motif } of MOTS_TECHNIQUES) {
    const m = motif.exec(t);
    if (m) l.push({ mot, extrait: t.slice(Math.max(0, m.index - 40), m.index + m[0].length + 40).replace(/\s+/g, " ").trim() });
  }
  return l;
}

/**
 * Fonction à passer à `page.evaluate` : le texte du premier niveau de l'écran affiché, un morceau par ligne.
 * Elle parcourt les textes rendus et laisse de côté ce qui est dans un bloc replié fermé (hors de son titre), dans
 * un élément `data-valeur` ou `data-phrase-fixee`, dans un champ de saisie, ou non rendu.
 */
export function textePremierNiveau() {
  const morceaux = [];
  const marcheur = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  for (let n = marcheur.nextNode(); n; n = marcheur.nextNode()) {
    const texte = n.nodeValue.replace(/\s+/g, " ").trim();
    if (texte === "") continue;
    const parent = n.parentElement;
    if (!parent || parent.closest("script, style, textarea, [data-valeur], [data-phrase-fixee]")) continue;
    let ferme = false;
    for (let d = parent.closest("details"); d; d = d.parentElement?.closest("details") ?? null) {
      if (d.open) continue;
      const titre = d.querySelector(":scope > summary");
      if (!titre || !titre.contains(parent)) ferme = true;
    }
    if (ferme) continue;
    if (parent.getClientRects().length === 0) continue;
    morceaux.push(texte);
  }
  // Les textes que seul un lecteur d'écran ou une info-bulle rend sont du premier niveau eux aussi.
  for (const e of document.querySelectorAll("[aria-label], [title]")) {
    if (e.closest("[data-valeur], [data-phrase-fixee]") || e.hasAttribute("data-identite")) continue;
    if (e.getClientRects().length === 0) continue;
    for (const a of ["aria-label", "title"]) if (e.getAttribute(a)) morceaux.push(e.getAttribute(a));
  }
  return morceaux.join("\n");
}
