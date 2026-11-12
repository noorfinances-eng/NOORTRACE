// Archives d'essai de la page de vérification (CT-6 EX-18.7) : écriture
// d'archives tar et ZIP octet par octet, pour fabriquer les formes que les
// outils courants n'écrivent pas (chemins absolus, liens, noms invalides,
// ZIP64, entrée chiffrée…), et table des refus attendus. Les formes
// admises sont fabriquées par les recettes d'EX-18.13 (zip, tar, gzip).

import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import zlib from "node:zlib";
import { RACINE } from "./outils.mjs";

const octets = (x) => (typeof x === "string" ? Buffer.from(x, "utf8") : Buffer.from(x));

// --- tar --------------------------------------------------------------------

function octal(valeur, longueur) {
  return Buffer.from(`${valeur.toString(8).padStart(longueur - 1, "0")}\0`, "latin1");
}

/**
 * Un en-tête tar de 512 octets. `nom` : chaîne ou octets (au plus 100) ;
 * `magie` : "ustar" (POSIX), "gnu" ou "aucune" (tar v7).
 */
export function enTeteTar({ nom, type = "0", taille = 0, magie = "ustar", prefixe = "", lien = "", sommeFausse = false }) {
  const h = Buffer.alloc(512);
  octets(nom).copy(h, 0, 0, 100);
  octal(0o644, 8).copy(h, 100);
  octal(0, 8).copy(h, 108);
  octal(0, 8).copy(h, 116);
  octal(taille, 12).copy(h, 124);
  octal(0, 12).copy(h, 136);
  h.write(type, 156, "latin1");
  octets(lien).copy(h, 157, 0, 100);
  if (magie === "ustar") {
    h.write("ustar\u000000", 257, "latin1");
    octets(prefixe).copy(h, 345, 0, 155);
  } else if (magie === "gnu") {
    h.write("ustar  \u0000", 257, "latin1");
  }
  h.fill(0x20, 148, 156);
  let somme = 0;
  for (const b of h) somme += b;
  if (sommeFausse) somme += 1;
  Buffer.from(`${somme.toString(8).padStart(6, "0")}\0 `, "latin1").copy(h, 148);
  return h;
}

function bourrer(donnees) {
  const n = Math.ceil(donnees.length / 512) * 512;
  const b = Buffer.alloc(n);
  donnees.copy(b);
  return b;
}

/**
 * Archive tar : entrées [{ nom, type, donnees, magie, prefixe, pax, long }] ;
 * `pax` : objet clé → valeur d'un en-tête « x » qui précède l'entrée ;
 * `long` : nom long GNU (« L ») qui précède l'entrée.
 */
export function tar(entrees, { fin = true } = {}) {
  const parties = [];
  for (const e of entrees) {
    const donnees = octets(e.donnees ?? "");
    if (e.pax) {
      let corps = "";
      for (const [k, v] of Object.entries(e.pax)) {
        const sansLongueur = ` ${k}=${v}\n`;
        let l = Buffer.byteLength(sansLongueur) + 1;
        while (String(l).length + Buffer.byteLength(sansLongueur) !== l) l++;
        corps += `${l}${sansLongueur}`;
      }
      const c = Buffer.from(corps, "utf8");
      parties.push(enTeteTar({ nom: "PaxHeaders/x", type: "x", taille: c.length }), bourrer(c));
    }
    if (e.long !== undefined) {
      const c = Buffer.concat([octets(e.long), Buffer.from([0])]);
      parties.push(enTeteTar({ nom: "././@LongLink", type: "L", taille: c.length, magie: "gnu" }), bourrer(c));
    }
    parties.push(enTeteTar({ nom: e.nom, type: e.type ?? "0", taille: e.taille ?? donnees.length, magie: e.magie ?? "ustar", prefixe: e.prefixe ?? "", lien: e.lien ?? "", sommeFausse: e.sommeFausse }));
    if (donnees.length > 0) parties.push(bourrer(donnees));
  }
  if (fin) parties.push(Buffer.alloc(1024));
  return Buffer.concat(parties);
}

// --- ZIP --------------------------------------------------------------------

const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(b) {
  let c = 0xffffffff;
  for (const x of b) c = TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Archive ZIP : entrées [{ nom, donnees, methode (0 ou 8), drapeaux, mode
 * (Unix), extra, taille, crc }] ; `zip64` ajoute un localisateur ZIP64.
 */
export function zip(entrees, { eocd = {}, zip64 = false } = {}) {
  const locales = [];
  const centrales = [];
  let decalage = 0;
  for (const e of entrees) {
    const nom = octets(e.nom);
    const donnees = octets(e.donnees ?? "");
    const methode = e.methode ?? 0;
    const comprimees = methode === 8 ? zlib.deflateRawSync(donnees) : methode === 0 ? donnees : octets(e.comprimees ?? donnees);
    const drapeaux = e.drapeaux ?? 0;
    const crc = e.crc ?? crc32(donnees);
    const taille = e.taille ?? donnees.length;
    const extra = octets(e.extra ?? []);
    const l = Buffer.alloc(30);
    l.writeUInt32LE(0x04034b50, 0);
    l.writeUInt16LE(20, 4);
    l.writeUInt16LE(drapeaux, 6);
    l.writeUInt16LE(methode, 8);
    l.writeUInt32LE(crc, 14);
    l.writeUInt32LE(comprimees.length, 18);
    l.writeUInt32LE(taille, 22);
    l.writeUInt16LE(nom.length, 26);
    l.writeUInt16LE(extra.length, 28);
    locales.push(l, nom, extra, comprimees);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0);
    c.writeUInt16LE((3 << 8) | 30, 4);
    c.writeUInt16LE(20, 6);
    c.writeUInt16LE(drapeaux, 8);
    c.writeUInt16LE(methode, 10);
    c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(comprimees.length, 20);
    c.writeUInt32LE(taille, 24);
    c.writeUInt16LE(nom.length, 28);
    c.writeUInt16LE(extra.length, 30);
    const mode = e.mode ?? (String(e.nom).endsWith("/") ? 0o040755 : 0o100644);
    c.writeUInt32LE(((mode << 16) | (String(e.nom).endsWith("/") ? 0x10 : 0)) >>> 0, 38);
    c.writeUInt32LE(decalage, 42);
    centrales.push(c, nom, extra);
    decalage += 30 + nom.length + extra.length + comprimees.length;
  }
  const repertoire = Buffer.concat(centrales);
  const parties = [...locales, repertoire];
  if (zip64) {
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    parties.push(loc);
  }
  const f = Buffer.alloc(22);
  f.writeUInt32LE(0x06054b50, 0);
  f.writeUInt16LE(eocd.disque ?? 0, 4);
  f.writeUInt16LE(0, 6);
  f.writeUInt16LE(eocd.entrees ?? entrees.length, 8);
  f.writeUInt16LE(eocd.entrees ?? entrees.length, 10);
  f.writeUInt32LE(repertoire.length, 12);
  f.writeUInt32LE(eocd.debut ?? decalage, 16);
  parties.push(f);
  return Buffer.concat(parties);
}

// --- Cas ----------------------------------------------------------------------

const DOSSIER = "{}";

/**
 * Refus d'EX-18.7 : { nom de l'essai, nom du fichier, octets, raison }.
 * `raison` est la clé du libellé (r_…) que la page affiche.
 */
export function casDeRefus() {
  const c = [];
  const ajouter = (titre, fichier, contenu, raison) => c.push({ titre, fichier, octets: contenu, raison });
  // Formes hors de la table.
  ajouter("extension hors de la table (.rar)", "d.rar", tar([{ nom: "d/dossier.json", donnees: DOSSIER }]), "r_forme");
  ajouter("extension hors de la table (.tar.bz2)", "d.tar.bz2", Buffer.from("BZh9"), "r_forme");
  ajouter("tar v7 sans en-tête ustar", "d.tar", tar([{ nom: "d/dossier.json", donnees: DOSSIER, magie: "aucune" }]), "r_tar_format");
  // Chemins (après normalisation).
  ajouter("chemin absolu", "d.tar", tar([{ nom: "/d/dossier.json", donnees: DOSSIER }]), "r_absolu");
  ajouter("composant « . »", "d.tar", tar([{ nom: "d/./dossier.json", donnees: DOSSIER }]), "r_composant");
  ajouter("composant « .. »", "d.tar", tar([{ nom: "d/../dossier.json", donnees: DOSSIER }]), "r_composant");
  ajouter("composant vide", "d.tar", tar([{ nom: "d//dossier.json", donnees: DOSSIER }]), "r_composant");
  ajouter("chemin vide après normalisation", "d.tar", tar([{ nom: "/", type: "5" }, { nom: "d/dossier.json", donnees: DOSSIER }]), "r_chemin_vide");
  ajouter("barre oblique inverse", "d.zip", zip([{ nom: "d\\dossier.json", donnees: DOSSIER }]), "r_barre_inverse");
  ajouter("nom en double", "d.tar", tar([{ nom: "d/dossier.json", donnees: DOSSIER }, { nom: "./d/dossier.json", donnees: DOSSIER }]), "r_double");
  ajouter("chemin à la fois fichier et répertoire", "d.tar", tar([{ nom: "d/x", donnees: "1" }, { nom: "d/x/y", donnees: "2" }]), "r_conflit");
  ajouter("nom tar qui n'est pas de l'UTF-8", "d.tar", tar([{ nom: Buffer.from([0x64, 0x2f, 0xff, 0x2e, 0x6a]), donnees: DOSSIER }]), "r_nom_codage");
  ajouter("nom ZIP marqué UTF-8 qui n'en est pas", "d.zip", zip([{ nom: Buffer.from([0x64, 0x2f, 0xc3, 0x28]), donnees: DOSSIER, drapeaux: 0x0800 }]), "r_nom_codage");
  ajouter("nom ZIP non ASCII sans le bit 11", "d.zip", zip([{ nom: Buffer.from([0x64, 0x2f, 0xe9]), donnees: DOSSIER }]), "r_nom_ascii");
  // Types d'entrée.
  ajouter("lien symbolique (tar)", "d.tar", tar([{ nom: "d/dossier.json", type: "2", lien: "/etc/passwd" }]), "r_type");
  ajouter("lien physique (tar)", "d.tar", tar([{ nom: "d/a.json", donnees: DOSSIER }, { nom: "d/dossier.json", type: "1", lien: "d/a.json" }]), "r_type");
  ajouter("périphérique caractère (tar)", "d.tar", tar([{ nom: "d/zero", type: "3" }]), "r_type");
  ajouter("périphérique bloc (tar)", "d.tar", tar([{ nom: "d/disque", type: "4" }]), "r_type");
  ajouter("tube (tar)", "d.tar", tar([{ nom: "d/tube", type: "6" }]), "r_type");
  ajouter("lien symbolique (ZIP, mode Unix)", "d.zip", zip([{ nom: "d/dossier.json", donnees: "/etc/passwd", mode: 0o120777 }]), "r_type");
  // ZIP.
  ajouter("entrée ZIP chiffrée", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER, drapeaux: 0x0001 }]), "r_chiffree");
  ajouter("champ ZIP64", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER, extra: [0x01, 0x00, 0x00, 0x00] }]), "r_zip64");
  ajouter("localisateur ZIP64", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER }], { zip64: true }), "r_zip64");
  ajouter("ZIP en plusieurs volumes", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER }], { eocd: { disque: 1 } }), "r_volumes");
  ajouter("méthode de compression 12", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER, methode: 12 }]), "r_methode");
  // Racine.
  ajouter("deux répertoires de premier niveau", "d.tar", tar([{ nom: "a/dossier.json", donnees: DOSSIER }, { nom: "b/x", donnees: "1" }]), "r_racine");
  ajouter("un répertoire et un fichier au premier niveau", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER }, { nom: "LISEZMOI", donnees: "x" }]), "r_racine");
  ajouter("un seul fichier au premier niveau", "d.tar", tar([{ nom: "manifeste.json", donnees: DOSSIER }]), "r_racine");
  ajouter("archive vide", "d.tar", Buffer.alloc(1024), "r_racine");
  // Bornes.
  const beaucoup = [];
  for (let i = 0; i < 4097; i++) beaucoup.push({ nom: `d/f${i}`, donnees: "" });
  ajouter("4 097 entrées (tar)", "d.tar", tar(beaucoup), "r_trop_entrees");
  ajouter("4 097 entrées (ZIP)", "d.zip", zip(beaucoup), "r_trop_entrees");
  const grand = Buffer.alloc(256 * 1024 * 1024 + 1);
  ajouter("plus de 256 Mio décompressés (ZIP, deflate)", "d.zip", zip([{ nom: "d/dossier.json", donnees: grand, methode: 8 }]), "r_trop_gros");
  ajouter("plus de 256 Mio décompressés (.tar.gz)", "d.tar.gz", zlib.gzipSync(tar([{ nom: "d/dossier.json", donnees: grand }])), "r_trop_gros");
  // Fichier épars et archives mal formées.
  ajouter("fichier épars pax (GNU.sparse)", "d.tar", tar([{ nom: "d/dossier.json", donnees: DOSSIER, pax: { "GNU.sparse.major": "1", "GNU.sparse.minor": "0" } }]), "r_pax_epars");
  ajouter("somme de contrôle tar fausse", "d.tar", tar([{ nom: "d/dossier.json", donnees: DOSSIER, sommeFausse: true }]), "r_illisible");
  ajouter("tar tronqué", "d.tar", tar([{ nom: "d/dossier.json", donnees: "x".repeat(1000) }], { fin: false }).subarray(0, 1024), "r_illisible");
  ajouter("CRC-32 ZIP faux", "d.zip", zip([{ nom: "d/dossier.json", donnees: DOSSIER, crc: 1 }]), "r_illisible");
  ajouter("gzip invalide", "d.tgz", Buffer.from([0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7]), "r_illisible");
  return c;
}

/**
 * Formes admises fabriquées octet par octet : { titre, fichier, octets,
 * attendus: { fichiers: Map(chemin → contenu), repertoires: [...] } }.
 */
export function casAdmis() {
  const c = [];
  const long = `d/${"r".repeat(120)}/dossier-long.json`;
  c.push({
    titre: "tar ustar avec préfixe, nom pax long, nom long GNU, en-têtes g ignorés, « ./ » répétés et entrée « . »",
    fichier: "d.tar",
    octets: Buffer.concat([
      tar([{ nom: "./", type: "5" }], { fin: false }),
      enTeteTar({ nom: "PaxHeaders/g", type: "g", taille: 13 }),
      Buffer.from("13 comment=x\n".padEnd(512, "\0"), "latin1"),
      tar([
        { nom: "./././d/", type: "5" },
        { nom: "dossier.json", prefixe: "d", donnees: DOSSIER },
        { nom: "court", pax: { path: long, mtime: "1.5" }, donnees: "pax" },
        { nom: "court2", long: "d/gnu/nom-long-gnu.json", magie: "gnu", donnees: "gnu" },
        { nom: "d/vide/", type: "5" },
      ]),
    ]),
    attendus: {
      fichiers: new Map([["dossier.json", DOSSIER], [long.slice(2), "pax"], ["gnu/nom-long-gnu.json", "gnu"]]),
      repertoires: ["vide"],
    },
  });
  c.push({
    titre: "ZIP à la racine (dossier.json), stockée et deflate, nom UTF-8 marqué",
    fichier: "d.zip",
    octets: zip([
      { nom: "dossier.json", donnees: DOSSIER, methode: 8 },
      { nom: "sous/", donnees: "" },
      { nom: "sous/é.json", donnees: "é", drapeaux: 0x0800 },
    ]),
    attendus: { fichiers: new Map([["dossier.json", DOSSIER], ["sous/é.json", "é"]]), repertoires: ["sous"] },
  });
  return c;
}

/** Le module archives.js de la page, chargé sans en changer le texte. */
export function chargerArchives() {
  const source = fs.readFileSync(path.join(RACINE, "paquets", "verification-web", "src", "page", "archives.js"), "utf8");
  const f = new vm.Script(`(function () {\n${source}\nreturn { lireArchive, RefusArchive, normaliserChemin, bornesRepertoire };\n})()`, { filename: "archives.js" });
  return f.runInThisContext();
}
