// Lecture minimale des réponses XML de S3 (ListObjectVersions,
// GetObjectLegalHold, GetObjectLockConfiguration, erreurs) : éléments et
// texte, entités prédéfinies et numériques, sans attribut ni espace de noms ;
// aucune entité externe n'est jamais résolue.

/**
 * @typedef {{nom: string, enfants: Noeud[], texte: string}} Noeud
 */

const ENTITES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };

function decoderTexte(t) {
  return t.replace(/&(#x[0-9A-Fa-f]+|#[0-9]+|[a-z]+);/g, (m, e) => {
    if (e[0] === "#") {
      const n = e[1] === "x" ? Number.parseInt(e.slice(2), 16) : Number.parseInt(e.slice(1), 10);
      return Number.isFinite(n) && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return ENTITES[e] ?? m;
  });
}

/**
 * Analyse un document XML en arbre.
 * @param {string} texte
 * @returns {Noeud} racine
 */
export function analyserXml(texte) {
  const racine = { nom: "#document", enfants: [], texte: "" };
  const pile = [racine];
  let i = 0;
  while (i < texte.length) {
    const lt = texte.indexOf("<", i);
    if (lt < 0) {
      pile.at(-1).texte += decoderTexte(texte.slice(i));
      break;
    }
    if (lt > i) pile.at(-1).texte += decoderTexte(texte.slice(i, lt));
    if (texte.startsWith("<?", lt)) {
      i = texte.indexOf("?>", lt) + 2;
    } else if (texte.startsWith("<!--", lt)) {
      i = texte.indexOf("-->", lt) + 3;
    } else if (texte.startsWith("<![CDATA[", lt)) {
      const f = texte.indexOf("]]>", lt);
      pile.at(-1).texte += texte.slice(lt + 9, f);
      i = f + 3;
    } else if (texte.startsWith("<!", lt)) {
      throw new Error("XML : déclaration de type refusée");
    } else if (texte[lt + 1] === "/") {
      const f = texte.indexOf(">", lt);
      const nom = texte.slice(lt + 2, f).trim().replace(/^.*:/, "");
      const n = pile.pop();
      if (!n || n.nom !== nom) throw new Error("XML mal formé");
      i = f + 1;
    } else {
      const f = texte.indexOf(">", lt);
      if (f < 0) throw new Error("XML mal formé");
      let corps = texte.slice(lt + 1, f);
      const vide = corps.endsWith("/");
      if (vide) corps = corps.slice(0, -1);
      const nom = corps.trim().split(/\s+/)[0].replace(/^.*:/, "");
      const n = { nom, enfants: [], texte: "" };
      pile.at(-1).enfants.push(n);
      if (!vide) pile.push(n);
      i = f + 1;
    }
    if (i <= 0) throw new Error("XML mal formé");
  }
  if (pile.length !== 1) throw new Error("XML incomplet");
  return racine;
}

/** Premier enfant de ce nom. */
export function enfant(n, nom) {
  return n?.enfants.find((e) => e.nom === nom) ?? null;
}

/** Enfants de ce nom. */
export function enfants(n, nom) {
  return n?.enfants.filter((e) => e.nom === nom) ?? [];
}

/** Texte d'un enfant, ou null. */
export function texteDe(n, nom) {
  const e = enfant(n, nom);
  return e ? e.texte : null;
}
