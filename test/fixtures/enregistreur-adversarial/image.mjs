// Arbres d'installation d'essai du démon `noortrace` (CT-7 EX-3.14, PA-4 ;
// CT-9 TA-25) : un répertoire qui a la disposition de `/opt/noortrace` dans
// l'image de référence (`conteneurs/enregistreur/Dockerfile`), sans conteneur :
//
//   <arbre>/package.json
//   <arbre>/paquets/enregistreur/{src,bin,schemas,package.json}
//   <arbre>/paquets/ancrage/{src,bin,package.json,node_modules}
//   <arbre>/paquets/noyau/{src,package.json,node_modules}
//   <arbre>/node_modules/@noortrace/<nom> -> ../../paquets/<nom>
//   <arbre>/node_modules/@noble/hashes
//
// Le démon lancé par `<arbre>/paquets/enregistreur/bin/noortrace` a cet arbre
// pour répertoire d'installation (`racineInstallation`), et son empreinte de
// code ne dépend que de l'arbre et du binaire Node.js. « Image publiée » :
// l'arbre copié du dépôt ; « image modifiée » : le même arbre où un octet
// d'un fichier a changé ; mutant : l'arbre dont le paquet de l'enregistreur
// est une copie mutée (CT-9 EX-10.5). Rien n'est écrit dans le dépôt.

import fs from "node:fs";
import path from "node:path";
import { RACINE } from "../enregistreur-coeur/outils.mjs";

const PAQUETS = path.join(RACINE, "paquets");

/**
 * Construit un arbre d'installation dans `dir` (créé, vide).
 * @param {string} dir
 * @param {{enregistreur?: string}} [o] `enregistreur` : paquet de l'enregistreur à copier (défaut : celui du dépôt)
 * @returns {{racine: string, paquet: string, bin: (nom?: string) => string}}
 */
export function arbreInstallation(dir, o = {}) {
  fs.mkdirSync(dir, { recursive: true });
  if (fs.readdirSync(dir).length) throw new Error(`arbre d'installation : ${dir} n'est pas vide`);
  const copier = (source, nom, parties) => {
    const cible = path.join(dir, "paquets", nom);
    fs.mkdirSync(cible, { recursive: true });
    for (const p of parties) {
      const s = path.join(source, p);
      if (!fs.existsSync(s)) throw new Error(`arbre d'installation : ${s} absent`);
      fs.cpSync(s, path.join(cible, p), { recursive: true, dereference: true });
    }
  };
  copier(o.enregistreur ?? path.join(PAQUETS, "enregistreur"), "enregistreur", ["src", "bin", "schemas", "package.json"]);
  copier(path.join(PAQUETS, "ancrage"), "ancrage", ["src", "bin", "package.json", "node_modules"]);
  copier(path.join(PAQUETS, "noyau"), "noyau", ["src", "package.json", "node_modules"]);
  fs.mkdirSync(path.join(dir, "node_modules", "@noortrace"), { recursive: true });
  for (const nom of ["enregistreur", "ancrage", "noyau"]) fs.symlinkSync(`../../paquets/${nom}`, path.join(dir, "node_modules", "@noortrace", nom));
  fs.mkdirSync(path.join(dir, "node_modules", "@noble"), { recursive: true });
  fs.cpSync(path.join(RACINE, "node_modules", "@noble", "hashes"), path.join(dir, "node_modules", "@noble", "hashes"), { recursive: true, dereference: true });
  fs.writeFileSync(path.join(dir, "package.json"), `${JSON.stringify({ name: "noortrace-arbre-essai", private: true, workspaces: ["paquets/*"] }, null, 2)}\n`);
  const paquet = path.join(dir, "paquets", "enregistreur");
  return { racine: dir, paquet, bin: (nom = "noortrace") => path.join(paquet, "bin", nom) };
}

/**
 * Change un octet d'un fichier de l'arbre (le dernier, un saut de ligne final
 * devenu une espace : le programme reste le même).
 * @param {{racine: string}} arbre
 * @param {string} relatif chemin relatif à la racine de l'arbre
 */
export function modifierUnOctet(arbre, relatif) {
  const f = path.join(arbre.racine, relatif);
  const octets = fs.readFileSync(f);
  if (octets.length === 0 || octets[octets.length - 1] !== 0x0a) throw new Error(`modifierUnOctet : ${relatif} ne finit pas par un saut de ligne`);
  octets[octets.length - 1] = 0x20;
  fs.writeFileSync(f, octets);
}

/** Écrit le fichier de l'image attendue (`--image-attendue`) et rend son chemin. */
export function ecrireImageAttendue(chemin, { image, code_sha256 }) {
  fs.mkdirSync(path.dirname(chemin), { recursive: true });
  fs.writeFileSync(chemin, `${JSON.stringify({ version: 0, image, code_sha256 }, null, 2)}\n`, { mode: 0o444 });
  return chemin;
}
