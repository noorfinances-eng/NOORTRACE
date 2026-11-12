// Lecture des archives d'un dossier (CT-6 EX-18.7) : .zip, .tar (ustar, pax,
// GNU), .tar.gz et .tgz. Écrit dans le paquet, sans dépendance : la
// décompression deflate et gzip emploie DecompressionStream du navigateur.
//
// lireArchive(nom, octets) rend { fichiers: [{ chemin, octets }],
// repertoires: [chemin] }, chemins relatifs au dossier, ou lève
// RefusArchive(raison, parametres) : la page affiche alors la raison et
// « aucun rapport », et le vérificateur ne s'exécute pas.
//
// bornesRepertoire(liste) applique les mêmes bornes à un répertoire choisi
// (révision 0.7 de CT-6, EX-18.7), avant toute lecture : `liste` porte le
// chemin relatif et la taille de chaque fichier.

const LIMITE_ENTREES = 4096;
const LIMITE_OCTETS = 256 * 1024 * 1024;

class RefusArchive extends Error {
  constructor(raison, parametres = {}) {
    super(raison);
    this.name = "RefusArchive";
    this.raison = raison;
    this.parametres = parametres;
  }
}

const decodeurUtf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Archive mal formée ; `detail` est la clé du libellé du défaut (i_…). */
function illisible(detail, parametres = {}) {
  return new RefusArchive("r_illisible", { ...parametres, detail });
}

/** Forme d'archive d'après le nom du fichier, ou null (hors de la table). */
function formeArchive(nom) {
  const n = nom.toLowerCase();
  if (n.endsWith(".tar.gz") || n.endsWith(".tgz")) return "tar.gz";
  if (n.endsWith(".tar")) return "tar";
  if (n.endsWith(".zip")) return "zip";
  return null;
}

/** Décompression bornée par DecompressionStream ; null si la borne est dépassée. */
async function decompresser(format, octets, borne) {
  const flux = new Blob([octets]).stream().pipeThrough(new DecompressionStream(format));
  const lecteur = flux.getReader();
  const morceaux = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await lecteur.read();
      if (done) break;
      total += value.length;
      if (total > borne) {
        await lecteur.cancel();
        return null;
      }
      morceaux.push(value);
    }
  } catch (e) {
    throw illisible("i_flux", { format });
  }
  const sortie = new Uint8Array(total);
  let i = 0;
  for (const m of morceaux) {
    sortie.set(m, i);
    i += m.length;
  }
  return sortie;
}

/** Nom d'entrée en UTF-8 strict, ou refus. */
function decoderNom(octets) {
  try {
    return decodeurUtf8Strict.decode(octets);
  } catch {
    throw new RefusArchive("r_nom_codage");
  }
}

// --- ZIP (APPNOTE.TXT) ---------------------------------------------------

const TABLE_CRC32 = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(octets) {
  let c = 0xffffffff;
  for (let i = 0; i < octets.length; i++) c = TABLE_CRC32[(c ^ octets[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function typeUnix(mode) {
  switch (mode & 0o170000) {
    case 0o120000: return "type_lien_symbolique";
    case 0o020000:
    case 0o060000: return "type_peripherique";
    case 0o010000: return "type_tube";
    case 0o140000: return "type_socket";
    default: return "type_autre";
  }
}

/** Entrées brutes d'une archive ZIP : [{ nom, repertoire, lire() }]. */
function entreesZip(octets) {
  const vue = new DataView(octets.buffer, octets.byteOffset, octets.byteLength);
  const n = octets.length;
  const u16 = (o) => vue.getUint16(o, true);
  const u32 = (o) => vue.getUint32(o, true);
  // Fin du répertoire central : signature suivie de 18 octets et du commentaire,
  // qui va jusqu'à la fin du fichier.
  let fin = -1;
  for (let o = n - 22; o >= 0 && o >= n - 22 - 0xffff; o--) {
    if (u32(o) === 0x06054b50 && o + 22 + u16(o + 20) === n) {
      fin = o;
      break;
    }
  }
  if (fin < 0) throw illisible("i_fin_central");
  if (fin >= 20 && u32(fin - 20) === 0x07064b50) throw new RefusArchive("r_zip64");
  const disque = u16(fin + 4);
  const disqueRepertoire = u16(fin + 6);
  const entreesDisque = u16(fin + 8);
  const entreesTotal = u16(fin + 10);
  const tailleRepertoire = u32(fin + 12);
  const debutRepertoire = u32(fin + 16);
  if (entreesTotal === 0xffff || entreesDisque === 0xffff || tailleRepertoire === 0xffffffff || debutRepertoire === 0xffffffff) {
    throw new RefusArchive("r_zip64");
  }
  if (disque !== 0 || disqueRepertoire !== 0 || entreesDisque !== entreesTotal) throw new RefusArchive("r_volumes");
  if (entreesTotal > LIMITE_ENTREES) throw new RefusArchive("r_trop_entrees");
  if (debutRepertoire + tailleRepertoire !== fin) throw illisible("i_central");
  const entrees = [];
  let o = debutRepertoire;
  let somme = 0;
  for (let i = 0; i < entreesTotal; i++) {
    if (o + 46 > fin || u32(o) !== 0x02014b50) throw illisible("i_central");
    const hote = u16(o + 4) >>> 8;
    const drapeaux = u16(o + 8);
    const methode = u16(o + 10);
    const crc = u32(o + 16);
    const tailleComprimee = u32(o + 20);
    const taille = u32(o + 24);
    const longueurNom = u16(o + 28);
    const longueurExtra = u16(o + 30);
    const longueurCommentaire = u16(o + 32);
    const disqueDebut = u16(o + 34);
    const attributsExternes = u32(o + 38);
    const decalageLocal = u32(o + 42);
    const suivant = o + 46 + longueurNom + longueurExtra + longueurCommentaire;
    if (suivant > fin) throw illisible("i_central");
    const octetsNom = octets.subarray(o + 46, o + 46 + longueurNom);
    // Champs supplémentaires : un champ ZIP64 (0x0001) fait refuser l'archive.
    let e = o + 46 + longueurNom;
    const finExtra = e + longueurExtra;
    while (e + 4 <= finExtra) {
      const id = u16(e);
      const longueur = u16(e + 2);
      if (id === 0x0001) throw new RefusArchive("r_zip64");
      e += 4 + longueur;
    }
    if (tailleComprimee === 0xffffffff || taille === 0xffffffff || decalageLocal === 0xffffffff || disqueDebut === 0xffff) {
      throw new RefusArchive("r_zip64");
    }
    let nom;
    if ((drapeaux & 0x0800) !== 0) {
      nom = decoderNom(octetsNom);
    } else {
      if (octetsNom.some((b) => b >= 0x80)) throw new RefusArchive("r_nom_ascii");
      nom = decoderNom(octetsNom);
    }
    if ((drapeaux & 0x0001) !== 0 || (drapeaux & 0x0040) !== 0 || (drapeaux & 0x2000) !== 0) {
      throw new RefusArchive("r_chiffree", { chemin: nom });
    }
    if (methode !== 0 && methode !== 8) throw new RefusArchive("r_methode", { methode: String(methode), chemin: nom });
    const repertoire = nom.endsWith("/");
    if (hote === 3) {
      const mode = attributsExternes >>> 16;
      const type = mode & 0o170000;
      if (type !== 0 && type !== 0o100000 && type !== 0o040000) {
        throw new RefusArchive("r_type", { chemin: nom, type: typeUnix(mode) });
      }
      if ((type === 0o040000 && !repertoire) || (type === 0o100000 && repertoire)) {
        throw illisible("i_type_nom", { chemin: nom });
      }
    }
    if (repertoire && taille !== 0) throw illisible("i_repertoire_taille", { chemin: nom });
    somme += taille;
    entrees.push({ nom, octetsNom, repertoire, methode, crc, tailleComprimee, taille, decalageLocal });
    o = suivant;
  }
  if (o !== fin) throw illisible("i_central");
  if (somme > LIMITE_OCTETS) throw new RefusArchive("r_trop_gros");
  return entrees.map((x) => ({
    nom: x.nom,
    repertoire: x.repertoire,
    async lire() {
      const l = x.decalageLocal;
      if (l + 30 > debutRepertoire || u32(l) !== 0x04034b50) throw illisible("i_local", { chemin: x.nom });
      const ln = u16(l + 26);
      const le = u16(l + 28);
      const debut = l + 30 + ln + le;
      if (debut + x.tailleComprimee > debutRepertoire) throw illisible("i_local", { chemin: x.nom });
      const nomLocal = octets.subarray(l + 30, l + 30 + ln);
      if (nomLocal.length !== x.octetsNom.length || nomLocal.some((b, i) => b !== x.octetsNom[i])) {
        throw illisible("i_local", { chemin: x.nom });
      }
      const brut = octets.subarray(debut, debut + x.tailleComprimee);
      let donnees;
      if (x.methode === 0) {
        if (x.tailleComprimee !== x.taille) throw illisible("i_taille", { chemin: x.nom });
        donnees = brut.slice();
      } else {
        donnees = await decompresser("deflate-raw", brut, x.taille);
        if (donnees === null || donnees.length !== x.taille) throw illisible("i_taille", { chemin: x.nom });
      }
      if (crc32(donnees) !== x.crc) throw illisible("i_crc", { chemin: x.nom });
      return donnees;
    },
  }));
}

// --- tar (POSIX ustar et pax, GNU) ----------------------------------------

function champTexte(octets, debut, longueur) {
  let fin = debut;
  while (fin < debut + longueur && octets[fin] !== 0) fin++;
  return octets.subarray(debut, fin);
}

function nombreOctal(octets, debut, longueur, quoi) {
  if ((octets[debut] & 0x80) !== 0) {
    // Codage base 256 de GNU ; une valeur négative est refusée.
    if (octets[debut] === 0xff) throw illisible("i_champ_tar", { champ: quoi });
    let v = octets[debut] & 0x7f;
    for (let i = debut + 1; i < debut + longueur; i++) {
      v = v * 256 + octets[i];
      if (v > Number.MAX_SAFE_INTEGER) throw illisible("i_champ_tar", { champ: quoi });
    }
    return v;
  }
  let i = debut;
  const fin = debut + longueur;
  while (i < fin && octets[i] === 0x20) i++;
  let v = 0;
  let chiffres = 0;
  while (i < fin && octets[i] >= 0x30 && octets[i] <= 0x37) {
    v = v * 8 + (octets[i] - 0x30);
    chiffres++;
    i++;
  }
  while (i < fin && (octets[i] === 0x20 || octets[i] === 0)) i++;
  if (i !== fin || chiffres === 0) throw illisible("i_champ_tar", { champ: quoi });
  return v;
}

/** Enregistrements d'un en-tête pax : « longueur clé=valeur\n ». */
function lirePax(donnees) {
  const r = new Map();
  let i = 0;
  while (i < donnees.length) {
    let j = i;
    while (j < donnees.length && donnees[j] >= 0x30 && donnees[j] <= 0x39) j++;
    if (j === i || j >= donnees.length || donnees[j] !== 0x20) throw illisible("i_pax");
    const longueur = Number(new TextDecoder().decode(donnees.subarray(i, j)));
    const fin = i + longueur;
    if (!Number.isSafeInteger(longueur) || fin > donnees.length || fin <= j + 1 || donnees[fin - 1] !== 0x0a) {
      throw illisible("i_pax");
    }
    const enregistrement = donnees.subarray(j + 1, fin - 1);
    const egal = enregistrement.indexOf(0x3d);
    if (egal <= 0) throw illisible("i_pax");
    const cle = decoderNom(enregistrement.subarray(0, egal));
    r.set(cle, enregistrement.subarray(egal + 1));
    i = fin;
  }
  return r;
}

function blocNul(octets, debut) {
  for (let i = debut; i < debut + 512; i++) if (octets[i] !== 0) return false;
  return true;
}

/** Entrées brutes d'une archive tar : [{ nom, repertoire, lire() }]. */
function entreesTar(octets) {
  if (octets.length > LIMITE_OCTETS) throw new RefusArchive("r_trop_gros");
  const entrees = [];
  let o = 0;
  let pax = null;
  let nomLong = null;
  let nombre = 0;
  for (;;) {
    if (o === octets.length) break;
    if (o + 512 > octets.length) throw illisible("i_tar_tronque");
    if (blocNul(octets, o)) {
      // Fin de l'archive : tout ce qui suit est nul.
      for (let i = o; i < octets.length; i++) if (octets[i] !== 0) throw illisible("i_apres_fin");
      if (pax !== null || nomLong !== null) throw illisible("i_pax");
      break;
    }
    let somme = 0;
    let sommeSignee = 0;
    for (let i = o; i < o + 512; i++) {
      const b = i >= o + 148 && i < o + 156 ? 0x20 : octets[i];
      somme += b;
      sommeSignee += b >= 0x80 ? b - 256 : b;
    }
    const sommeEcrite = nombreOctal(octets, o + 148, 8, "chksum");
    if (sommeEcrite !== somme && sommeEcrite !== sommeSignee) throw illisible("i_somme");
    const magie = new TextDecoder("latin1").decode(octets.subarray(o + 257, o + 265));
    let gnu;
    if (magie === "ustar\u000000") gnu = false;
    else if (magie === "ustar  \u0000") gnu = true;
    else throw new RefusArchive("r_tar_format");
    const type = String.fromCharCode(octets[o + 156]);
    let taille = nombreOctal(octets, o + 124, 12, "size");
    const debutDonnees = o + 512;
    const lireDonnees = (t) => {
      if (debutDonnees + t > octets.length) throw illisible("i_tar_tronque");
      return octets.subarray(debutDonnees, debutDonnees + t);
    };
    if (type === "x" || type === "g") {
      const enregistrements = lirePax(lireDonnees(taille));
      if (type === "x") {
        pax = pax ?? new Map();
        for (const [k, v] of enregistrements) pax.set(k, v);
      }
      o = debutDonnees + Math.ceil(taille / 512) * 512;
      continue;
    }
    if (type === "L") {
      nomLong = decoderNom(champTexte(lireDonnees(taille), 0, taille));
      o = debutDonnees + Math.ceil(taille / 512) * 512;
      continue;
    }
    let nom;
    if (pax !== null && pax.has("path")) nom = decoderNom(pax.get("path"));
    else if (nomLong !== null) nom = nomLong;
    else {
      const court = decoderNom(champTexte(octets, o, 100));
      const prefixe = gnu ? "" : decoderNom(champTexte(octets, o + 345, 155));
      nom = prefixe !== "" ? `${prefixe}/${court}` : court;
    }
    if (pax !== null) {
      for (const cle of pax.keys()) {
        if (cle.startsWith("GNU.sparse.")) throw new RefusArchive("r_pax_epars", { chemin: nom });
      }
      if (pax.has("size")) {
        const s = new TextDecoder().decode(pax.get("size"));
        if (!/^[0-9]+$/.test(s) || !Number.isSafeInteger(Number(s))) throw illisible("i_pax");
        taille = Number(s);
      }
    }
    pax = null;
    nomLong = null;
    nombre++;
    if (nombre > LIMITE_ENTREES) throw new RefusArchive("r_trop_entrees");
    let repertoire;
    if (type === "0" || type === "\u0000") repertoire = false;
    else if (type === "5") repertoire = true;
    else {
      const types = { 1: "type_lien_physique", 2: "type_lien_symbolique", 3: "type_peripherique", 4: "type_peripherique", 6: "type_tube" };
      throw new RefusArchive("r_type", { chemin: nom, type: types[type] ?? "type_autre", code: type });
    }
    const donnees = lireDonnees(taille);
    entrees.push({ nom, repertoire, async lire() { return donnees.slice(); } });
    o = debutDonnees + Math.ceil(taille / 512) * 512;
  }
  return entrees;
}

// --- Chemins et racine du dossier ----------------------------------------

/**
 * Normalisation d'EX-18.7 : barre oblique finale d'une entrée de répertoire
 * retirée, préfixe « ./ » répété retiré ; null pour une entrée réduite à
 * « . » (ou « ./ »), à ignorer.
 */
function normaliserChemin(nom, repertoire) {
  let c = nom;
  if (c === "." || c === "./") return null;
  if (repertoire && c.endsWith("/")) c = c.slice(0, -1);
  while (c.startsWith("./")) c = c.slice(2);
  if (c === ".") return null;
  if (c === "") throw new RefusArchive("r_chemin_vide");
  if (c.startsWith("/")) throw new RefusArchive("r_absolu", { chemin: nom });
  if (c.includes("\\")) throw new RefusArchive("r_barre_inverse", { chemin: nom });
  for (const p of c.split("/")) {
    if (p === "" || p === "." || p === "..") throw new RefusArchive("r_composant", { chemin: nom });
  }
  return c;
}

/**
 * Applique EX-18.7 aux entrées brutes d'une archive et rend le dossier :
 * { fichiers: [{ chemin, octets }], repertoires: [chemin] }, chemins relatifs
 * au dossier.
 */
async function dossierDeLArchive(entrees) {
  const types = new Map();
  const retenues = [];
  for (const e of entrees) {
    const c = normaliserChemin(e.nom, e.repertoire);
    if (c === null) continue;
    if (types.has(c)) throw new RefusArchive("r_double", { chemin: c });
    types.set(c, e.repertoire ? "repertoire" : "fichier");
    retenues.push({ chemin: c, entree: e });
  }
  // Un chemin dont un parent est un fichier : à la fois fichier et répertoire.
  for (const c of types.keys()) {
    const parties = c.split("/");
    for (let i = 1; i < parties.length; i++) {
      const parent = parties.slice(0, i).join("/");
      if (types.get(parent) === "fichier") throw new RefusArchive("r_conflit", { chemin: parent });
    }
  }
  let prefixe;
  if (types.has("dossier.json")) {
    prefixe = "";
  } else {
    const premiers = new Set([...types.keys()].map((c) => c.split("/")[0]));
    if (premiers.size !== 1) throw new RefusArchive("r_racine");
    const [seul] = premiers;
    if (types.get(seul) === "fichier") throw new RefusArchive("r_racine");
    prefixe = `${seul}/`;
  }
  const fichiers = [];
  const repertoires = [];
  for (const { chemin, entree } of retenues) {
    if (prefixe !== "" && chemin === prefixe.slice(0, -1)) continue;
    const relatif = chemin.slice(prefixe.length);
    if (entree.repertoire) repertoires.push(relatif);
    else fichiers.push({ chemin: relatif, octets: await entree.lire() });
  }
  return { fichiers, repertoires };
}

/**
 * Bornes d'EX-18.7 pour un répertoire choisi (révision 0.7) : au plus 4 096
 * entrées, fichiers et sous-répertoires comptés (les sous-répertoires d'après
 * les chemins), et 256 Mio pour la somme des tailles des fichiers ; comptées
 * sur les métadonnées, avant toute lecture. Lève RefusArchive.
 * @param {{chemin: string, taille: number}[]} liste
 */
function bornesRepertoire(liste) {
  const repertoires = new Set();
  let somme = 0;
  for (const { chemin, taille } of liste) {
    const parties = chemin.split("/");
    for (let i = 1; i < parties.length; i++) repertoires.add(parties.slice(0, i).join("/"));
    somme += taille;
  }
  if (liste.length + repertoires.size > LIMITE_ENTREES) throw new RefusArchive("r_trop_entrees");
  if (somme > LIMITE_OCTETS) throw new RefusArchive("r_trop_gros");
}

/** Lit l'archive `nom` (Uint8Array `octets`) selon sa forme. */
async function lireArchive(nom, octets) {
  const forme = formeArchive(nom);
  if (forme === null) throw new RefusArchive("r_forme", { nom });
  if (forme === "zip") return dossierDeLArchive(entreesZip(octets));
  if (forme === "tar") return dossierDeLArchive(entreesTar(octets));
  if (octets.length < 2 || octets[0] !== 0x1f || octets[1] !== 0x8b) throw illisible("i_gzip");
  const tar = await decompresser("gzip", octets, LIMITE_OCTETS);
  if (tar === null) throw new RefusArchive("r_trop_gros");
  return dossierDeLArchive(entreesTar(tar));
}
