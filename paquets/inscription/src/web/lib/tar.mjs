// Archive `tar` POSIX `ustar` d'un répertoire (INTERFACES.md 2.3, 4.2) : le
// paquet client y est enveloppé pour le transport ; l'archive n'est pas une
// partie du paquet (EX-7.18). En-têtes de 512 octets, contenus complétés à un
// multiple de 512, deux blocs nuls en fin ; propriétaire 0, modes 0644 et
// 0755, dates nulles, de sorte que deux archives d'un même paquet sont égales
// octet pour octet. Seuls des fichiers ordinaires et des répertoires sont
// admis ; un nom au-delà de 100 octets passe par le préfixe de 155 octets.

import fs from "node:fs";
import path from "node:path";

function octal(n, largeur) {
  return n.toString(8).padStart(largeur - 1, "0") + "\0";
}

function entete(nom, { taille, type }) {
  const b = Buffer.alloc(512, 0);
  let prefixe = "";
  let court = nom;
  if (Buffer.byteLength(nom) > 100) {
    const k = nom.lastIndexOf("/", 155);
    if (k <= 0 || Buffer.byteLength(nom.slice(k + 1)) > 100) throw new Error(`nom trop long pour ustar : ${nom}`);
    prefixe = nom.slice(0, k);
    court = nom.slice(k + 1);
  }
  b.write(court, 0, 100, "utf8");
  b.write(octal(type === "5" ? 0o755 : 0o644, 8), 100, "ascii");
  b.write(octal(0, 8), 108, "ascii");
  b.write(octal(0, 8), 116, "ascii");
  b.write(octal(taille, 12), 124, "ascii");
  b.write(octal(0, 12), 136, "ascii");
  b.fill(0x20, 148, 156);
  b.write(type, 156, "ascii");
  b.write("ustar\0", 257, "ascii");
  b.write("00", 263, "ascii");
  b.write(prefixe, 345, 155, "utf8");
  let somme = 0;
  for (const x of b) somme += x;
  b.write(octal(somme, 7) + " ", 148, "ascii");
  return b;
}

/** Archive d'un répertoire, ses entrées sous `racine/` ; rend un `Buffer`. */
export function archiver(repertoire, racine = path.basename(repertoire)) {
  const blocs = [];
  const parcourir = (absolu, relatif) => {
    blocs.push(entete(`${relatif}/`, { taille: 0, type: "5" }));
    for (const n of fs.readdirSync(absolu).sort()) {
      const a = path.join(absolu, n);
      const r = `${relatif}/${n}`;
      const st = fs.lstatSync(a);
      if (st.isDirectory()) parcourir(a, r);
      else if (st.isFile()) {
        const o = fs.readFileSync(a);
        blocs.push(entete(r, { taille: o.length, type: "0" }), o);
        const reste = o.length % 512;
        if (reste) blocs.push(Buffer.alloc(512 - reste, 0));
      } else throw new Error(`entrée non ordinaire : ${r}`);
    }
  };
  parcourir(repertoire, racine);
  blocs.push(Buffer.alloc(1024, 0));
  return Buffer.concat(blocs);
}
