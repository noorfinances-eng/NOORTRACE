// Figeage de la conception v1.0 (porte 1 du plan ; spec/figeage/LISEZMOI.md).
//
// La conception est figée par un manifeste : le SHA-256 de chaque fichier
// versionné sous spec/, hors spec/figeage/, au format de `sha256sum`. Toute
// modification ultérieure d'un de ces fichiers, tout ajout et toute
// suppression sont consignés dans le registre spec/figeage/modifications.json :
// chaque entrée MC-n nomme ses fichiers avec leur condensé avant et après.
// La vérification rejoue le registre depuis le manifeste et exige que l'état
// obtenu soit exactement celui des fichiers présents.
//
// Fonctions pures : aucune lecture de fichier ici. L'outil
// scripts/conception/figeage.mjs liste et hache les fichiers, puis appelle
// verifierFigeage ou consignerModification.

export const REPERTOIRE_FIGE = "spec/";
export const REPERTOIRE_FIGEAGE = "spec/figeage/";
export const FICHIER_MANIFESTE = "spec/figeage/conception-v1.0.sha256";
export const FICHIER_REGISTRE = "spec/figeage/modifications.json";
export const VERSION_CONCEPTION = "1.0";

const RE_SHA256 = /^[0-9a-f]{64}$/;
const RE_DATE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const RE_ID = /^MC-([1-9]\d*)$/;
const CLES_REGISTRE = ["conception", "date_figeage", "manifeste", "manifeste_sha256", "modifications"];
const CLES_MODIFICATION = ["id", "date", "etape", "motif", "fichiers"];
const CLES_FICHIER = ["chemin", "avant", "apres"];

// Ordre des chemins : octets UTF-8, comme `LC_ALL=C sort`.
export function comparerChemins(a, b) {
  const x = Buffer.from(a, "utf8");
  const y = Buffer.from(b, "utf8");
  return Buffer.compare(x, y);
}

// Un chemin figé : relatif à la racine du dépôt, sous spec/, hors
// spec/figeage/, sans composant vide, « . » ou « .. », sans caractère de
// contrôle ni barre inverse.
export function cheminFigeable(chemin) {
  if (typeof chemin !== "string" || !chemin.startsWith(REPERTOIRE_FIGE)) return false;
  if (chemin.startsWith(REPERTOIRE_FIGEAGE)) return false;
  if (/[\u0000-\u001f\u007f\\]/.test(chemin)) return false;
  return chemin.split("/").every((c) => c !== "" && c !== "." && c !== "..");
}

// Texte du manifeste depuis une table chemin → condensé.
export function ecrireManifeste(table) {
  const chemins = [...table.keys()].sort(comparerChemins);
  return chemins.map((c) => `${table.get(c)}  ${c}\n`).join("");
}

// Lecture stricte du manifeste. Rend { table, erreurs }.
export function lireManifeste(texte) {
  const erreurs = [];
  const table = new Map();
  if (typeof texte !== "string" || texte === "") return { table, erreurs: ["manifeste vide"] };
  if (!texte.endsWith("\n")) erreurs.push("manifeste : la dernière ligne ne finit pas par un saut de ligne");
  const lignes = texte.split("\n");
  lignes.pop();
  let precedent = null;
  lignes.forEach((ligne, i) => {
    const n = i + 1;
    const m = /^([0-9a-f]{64}) {2}(.+)$/.exec(ligne);
    if (!m) {
      erreurs.push(`manifeste, ligne ${n} : forme attendue « <sha256>  <chemin> »`);
      return;
    }
    const [, condense, chemin] = m;
    if (!cheminFigeable(chemin)) erreurs.push(`manifeste, ligne ${n} : chemin hors du périmètre figé : ${chemin}`);
    if (table.has(chemin)) erreurs.push(`manifeste, ligne ${n} : chemin en double : ${chemin}`);
    if (precedent !== null && comparerChemins(precedent, chemin) >= 0) erreurs.push(`manifeste, ligne ${n} : chemins non triés (${precedent} puis ${chemin})`);
    precedent = chemin;
    table.set(chemin, condense);
  });
  if (table.size === 0 && erreurs.length === 0) erreurs.push("manifeste sans aucune ligne");
  return { table, erreurs };
}

function clesExactes(objet, attendues, lieu, erreurs) {
  if (objet === null || typeof objet !== "object" || Array.isArray(objet)) {
    erreurs.push(`${lieu} : objet attendu`);
    return false;
  }
  const cles = Object.keys(objet);
  for (const c of attendues) if (!(c in objet)) erreurs.push(`${lieu} : membre « ${c} » absent`);
  for (const c of cles) if (!attendues.includes(c)) erreurs.push(`${lieu} : membre « ${c} » inconnu`);
  return true;
}

const condenseOuNul = (v) => v === null || (typeof v === "string" && RE_SHA256.test(v));

// Contrôle de forme du registre, indépendant des fichiers. Rend la liste des
// erreurs (vide si le registre est bien formé).
export function controlerRegistre(registre) {
  const erreurs = [];
  if (!clesExactes(registre, CLES_REGISTRE, "registre", erreurs)) return erreurs;
  if (registre.conception !== VERSION_CONCEPTION) erreurs.push(`registre : conception « ${registre.conception} » au lieu de « ${VERSION_CONCEPTION} »`);
  if (typeof registre.date_figeage !== "string" || !RE_DATE.test(registre.date_figeage)) erreurs.push("registre : date_figeage attendue au format AAAA-MM-JJ");
  if (registre.manifeste !== FICHIER_MANIFESTE) erreurs.push(`registre : manifeste « ${registre.manifeste} » au lieu de « ${FICHIER_MANIFESTE} »`);
  if (typeof registre.manifeste_sha256 !== "string" || !RE_SHA256.test(registre.manifeste_sha256)) erreurs.push("registre : manifeste_sha256 attendu en hexadécimal minuscule de 64 caractères");
  if (!Array.isArray(registre.modifications)) {
    erreurs.push("registre : modifications attendu comme liste");
    return erreurs;
  }
  let dateAvant = registre.date_figeage;
  registre.modifications.forEach((mod, i) => {
    const lieu = `modification ${i + 1}`;
    if (!clesExactes(mod, CLES_MODIFICATION, lieu, erreurs)) return;
    const m = RE_ID.exec(mod.id ?? "");
    if (!m || Number(m[1]) !== i + 1) erreurs.push(`${lieu} : identifiant « ${mod.id} » au lieu de « MC-${i + 1} »`);
    if (typeof mod.date !== "string" || !RE_DATE.test(mod.date)) erreurs.push(`${lieu} : date attendue au format AAAA-MM-JJ`);
    else if (typeof dateAvant === "string" && mod.date < dateAvant) erreurs.push(`${lieu} : date ${mod.date} antérieure à ${dateAvant}`);
    else dateAvant = mod.date;
    if (!(mod.etape === null || (Number.isInteger(mod.etape) && mod.etape >= 1 && mod.etape <= 8))) erreurs.push(`${lieu} : etape attendue entre 1 et 8, ou null`);
    if (typeof mod.motif !== "string" || mod.motif.trim() === "") erreurs.push(`${lieu} : motif vide`);
    if (!Array.isArray(mod.fichiers) || mod.fichiers.length === 0) {
      erreurs.push(`${lieu} : fichiers attendu comme liste non vide`);
      return;
    }
    let precedent = null;
    mod.fichiers.forEach((f, j) => {
      const lieuF = `${lieu}, fichier ${j + 1}`;
      if (!clesExactes(f, CLES_FICHIER, lieuF, erreurs)) return;
      if (!cheminFigeable(f.chemin)) erreurs.push(`${lieuF} : chemin hors du périmètre figé : ${f.chemin}`);
      else if (precedent !== null && comparerChemins(precedent, f.chemin) >= 0) erreurs.push(`${lieuF} : chemins non triés ou en double (${precedent} puis ${f.chemin})`);
      if (typeof f.chemin === "string") precedent = f.chemin;
      if (!condenseOuNul(f.avant)) erreurs.push(`${lieuF} : avant attendu comme condensé SHA-256 ou null`);
      if (!condenseOuNul(f.apres)) erreurs.push(`${lieuF} : apres attendu comme condensé SHA-256 ou null`);
      if (f.avant === f.apres) erreurs.push(`${lieuF} : avant et apres égaux, rien n'est modifié`);
    });
  });
  return erreurs;
}

// Vérification complète.
//   manifeste : texte du manifeste ; condenseManifeste : son SHA-256 ;
//   registre : objet du registre ; fichiers : Map chemin → condensé des
//   fichiers présents sous spec/ (hors spec/figeage/).
// Rend { erreurs, ecarts, etat } : erreurs de forme (manifeste, registre,
// rejeu), écarts entre l'état rejoué et les fichiers présents.
export function verifierFigeage({ manifeste, condenseManifeste, registre, fichiers }) {
  const { table, erreurs } = lireManifeste(manifeste);
  erreurs.push(...controlerRegistre(registre));
  if (registre && typeof registre === "object" && registre.manifeste_sha256 !== condenseManifeste) {
    erreurs.push(`manifeste modifié : SHA-256 ${condenseManifeste} au lieu de ${registre.manifeste_sha256} consigné au registre`);
  }
  const etat = new Map(table);
  const modifications = Array.isArray(registre?.modifications) ? registre.modifications : [];
  for (const mod of modifications) {
    for (const f of Array.isArray(mod?.fichiers) ? mod.fichiers : []) {
      if (!f || typeof f.chemin !== "string") continue;
      const courant = etat.has(f.chemin) ? etat.get(f.chemin) : null;
      if (courant !== f.avant) {
        erreurs.push(`${mod.id}, ${f.chemin} : avant ${f.avant} ne correspond pas à l'état rejoué ${courant}`);
      }
      if (f.apres === null) etat.delete(f.chemin);
      else etat.set(f.chemin, f.apres);
    }
  }
  const ecarts = [];
  for (const [chemin, condense] of fichiers) {
    if (!cheminFigeable(chemin)) continue;
    if (!etat.has(chemin)) ecarts.push({ chemin, nature: "ajouté sans consignation", attendu: null, obtenu: condense });
    else if (etat.get(chemin) !== condense) ecarts.push({ chemin, nature: "modifié sans consignation", attendu: etat.get(chemin), obtenu: condense });
  }
  for (const [chemin, condense] of etat) {
    if (!fichiers.has(chemin)) ecarts.push({ chemin, nature: "supprimé sans consignation", attendu: condense, obtenu: null });
  }
  ecarts.sort((a, b) => comparerChemins(a.chemin, b.chemin));
  return { erreurs, ecarts, etat };
}

// Nouvelle entrée du registre pour les écarts constatés. Rend le registre
// complété (copie) ; lève une erreur si le registre est mal formé ou s'il n'y
// a rien à consigner.
export function consignerModification({ manifeste, condenseManifeste, registre, fichiers, date, etape = null, motif }) {
  const { erreurs, ecarts } = verifierFigeage({ manifeste, condenseManifeste, registre, fichiers });
  if (erreurs.length > 0) throw new Error(`registre ou manifeste invalide, rien n'est consigné :\n${erreurs.join("\n")}`);
  if (ecarts.length === 0) throw new Error("aucun écart avec l'état figé : rien à consigner");
  const mod = {
    id: `MC-${registre.modifications.length + 1}`,
    date,
    etape,
    motif,
    fichiers: ecarts.map((e) => ({ chemin: e.chemin, avant: e.attendu, apres: e.obtenu })),
  };
  const suivant = { ...registre, modifications: [...registre.modifications, mod] };
  const controle = controlerRegistre(suivant);
  if (controle.length > 0) throw new Error(`entrée invalide, rien n'est consigné :\n${controle.join("\n")}`);
  return suivant;
}

export function texteRegistre(registre) {
  return JSON.stringify(registre, null, 2) + "\n";
}
