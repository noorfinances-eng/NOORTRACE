// Recettes d'archives d'EX-18.13 (CT-6 §18.7), appliquées depuis le
// répertoire parent <parent> du dossier <d> :
//   zip -X -r d.zip <d>                 zip -X -0 -r d.zip <d>
//   tar --format=ustar -cf d.tar <d>    tar --format=pax -cf d.tar <d>
//   tar --format=gnu -cf d.tar <d>      tar --format=ustar -C <parent>/<d> -cf d.tar .
//   tar --format=pax -cf - <d> | gzip -n > d.tar.gz

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

/** null si zip, tar (GNU) et gzip sont là, sinon ce qui manque. */
export function outilsArchivesDisponibles() {
  for (const [outil, args] of [["zip", ["-v"]], ["tar", ["--version"]], ["gzip", ["--version"]], ["sh", ["-c", "true"]]]) {
    const r = spawnSync(outil, args, { stdio: "pipe" });
    if (r.status !== 0) return `${outil} absent`;
    if (outil === "tar" && !r.stdout.toString().includes("GNU tar")) return "tar GNU absent";
  }
  return null;
}

export const RECETTES = ["zip -X -r", "zip -X -0 -r", "tar ustar", "tar pax", "tar gnu", "tar ustar -C .", "tar pax | gzip -n"];

/** Les sept archives du dossier `dossier` dans `sortie` : [{ recette, fichier, chemin }]. */
export function recettesArchives(dossier, sortie) {
  const parent = path.dirname(dossier);
  const d = path.basename(dossier);
  const r = [];
  const faire = (recette, fichier, commande, args, cwd = parent) => {
    const chemin = path.join(sortie, `${r.length}-${fichier}`);
    fs.rmSync(chemin, { force: true });
    execFileSync(commande, args(chemin), { cwd, stdio: "pipe" });
    r.push({ recette, fichier, chemin });
  };
  faire("zip -X -r", "d.zip", "zip", (c) => ["-X", "-r", c, d]);
  faire("zip -X -0 -r", "d.zip", "zip", (c) => ["-X", "-0", "-r", c, d]);
  faire("tar ustar", "d.tar", "tar", (c) => ["--format=ustar", "-cf", c, d]);
  faire("tar pax", "d.tar", "tar", (c) => ["--format=pax", "-cf", c, d]);
  faire("tar gnu", "d.tar", "tar", (c) => ["--format=gnu", "-cf", c, d]);
  faire("tar ustar -C .", "d.tar", "tar", (c) => ["--format=ustar", "-C", path.join(parent, d), "-cf", c, "."]);
  faire("tar pax | gzip -n", "d.tar.gz", "sh", (c) => ["-c", 'tar --format=pax -cf - "$1" | gzip -n > "$2"', "sh", d, c]);
  return r;
}
