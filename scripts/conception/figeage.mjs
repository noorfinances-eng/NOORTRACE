#!/usr/bin/env node
// Figeage de la conception v1.0 (porte 1 du plan ; spec/figeage/LISEZMOI.md).
//
//   node scripts/conception/figeage.mjs [--racine <dépôt>] [--json]
//   node scripts/conception/figeage.mjs --consigner --motif <texte>
//        [--etape <1 à 8>] [--date <AAAA-MM-JJ>] [--racine <dépôt>]
//   node scripts/conception/figeage.mjs --initialiser --date <AAAA-MM-JJ>
//        [--racine <dépôt>]
//   npm run conception:figeage
//
// Sans option : rejoue le registre spec/figeage/modifications.json depuis le
// manifeste spec/figeage/conception-v1.0.sha256 et compare l'état obtenu aux
// fichiers présents sous spec/ (fichiers suivis par git et fichiers nouveaux
// non ignorés, hors spec/figeage/). --consigner ajoute au registre une entrée
// MC-n pour les écarts constatés. --initialiser écrit le manifeste et un
// registre vide ; il refuse s'ils existent déjà.
//
// Codes : 0 conforme (ou écriture faite) ; 1 au moins un écart ou une erreur
// du registre ; 2 usage, git absent ou fichier illisible.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  FICHIER_MANIFESTE, FICHIER_REGISTRE, REPERTOIRE_FIGE, VERSION_CONCEPTION,
  cheminFigeable, consignerModification, ecrireManifeste, texteRegistre, verifierFigeage,
} from "../lib/figeage.mjs";

const USAGE = [
  "usage : node scripts/conception/figeage.mjs [--racine <dépôt>] [--json]",
  "        node scripts/conception/figeage.mjs --consigner --motif <texte> [--etape <1 à 8>] [--date <AAAA-MM-JJ>] [--racine <dépôt>]",
  "        node scripts/conception/figeage.mjs --initialiser --date <AAAA-MM-JJ> [--racine <dépôt>]",
].join("\n");

const RACINE_PAR_DEFAUT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

class ErreurUsage extends Error {}

const sha256 = (octets) => createHash("sha256").update(octets).digest("hex");

// Fichiers présents sous spec/ : suivis par git, plus les nouveaux non
// ignorés ; un fichier suivi supprimé de l'arbre de travail est absent.
export function fichiersPresents(racine) {
  const r = spawnSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", REPERTOIRE_FIGE], { cwd: racine, encoding: "buffer" });
  if (r.error || r.status !== 0) throw new ErreurUsage(`git ls-files a échoué dans ${racine} : ${r.error?.message ?? r.stderr.toString("utf8").trim()}`);
  const chemins = [...new Set(r.stdout.toString("utf8").split("\0").filter((c) => c !== ""))];
  const table = new Map();
  for (const chemin of chemins) {
    if (!cheminFigeable(chemin)) continue;
    const absolu = path.join(racine, chemin);
    let st;
    try {
      st = fs.lstatSync(absolu);
    } catch (e) {
      if (e.code === "ENOENT") continue;
      throw new ErreurUsage(`${chemin} illisible : ${e.message}`);
    }
    if (!st.isFile()) throw new ErreurUsage(`${chemin} n'est pas un fichier ordinaire`);
    table.set(chemin, sha256(fs.readFileSync(absolu)));
  }
  return table;
}

function lireEntrees(racine) {
  let manifesteOctets;
  let registreTexte;
  try {
    manifesteOctets = fs.readFileSync(path.join(racine, FICHIER_MANIFESTE));
    registreTexte = fs.readFileSync(path.join(racine, FICHIER_REGISTRE), "utf8");
  } catch (e) {
    throw new ErreurUsage(`lecture impossible : ${e.message}`);
  }
  let registre;
  try {
    registre = JSON.parse(registreTexte);
  } catch (e) {
    throw new ErreurUsage(`${FICHIER_REGISTRE} n'est pas du JSON : ${e.message}`);
  }
  return {
    manifeste: manifesteOctets.toString("utf8"),
    condenseManifeste: sha256(manifesteOctets),
    registre,
    registreTexte,
  };
}

const dateDuJour = () => new Date().toISOString().slice(0, 10);

export function executer(argv, { sortie = process.stdout, erreur = process.stderr } = {}) {
  let o;
  try {
    o = parseArgs({
      args: argv,
      options: {
        racine: { type: "string" },
        json: { type: "boolean" },
        consigner: { type: "boolean" },
        initialiser: { type: "boolean" },
        motif: { type: "string" },
        etape: { type: "string" },
        date: { type: "string" },
      },
      strict: true,
      allowPositionals: false,
    }).values;
  } catch (e) {
    erreur.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  const racine = path.resolve(o.racine ?? RACINE_PAR_DEFAUT);
  try {
    if (o.consigner && o.initialiser) throw new ErreurUsage("--consigner et --initialiser s'excluent");
    if (!o.consigner && !o.initialiser && (o.motif !== undefined || o.etape !== undefined || o.date !== undefined)) {
      throw new ErreurUsage("--motif, --etape et --date ne servent qu'avec --consigner ou --initialiser");
    }
    if (o.initialiser) {
      if (o.date === undefined || !/^\d{4}-\d{2}-\d{2}$/.test(o.date)) throw new ErreurUsage("--initialiser demande --date <AAAA-MM-JJ>");
      if (o.motif !== undefined || o.etape !== undefined) throw new ErreurUsage("--motif et --etape ne servent qu'avec --consigner");
      for (const f of [FICHIER_MANIFESTE, FICHIER_REGISTRE]) {
        if (fs.existsSync(path.join(racine, f))) throw new ErreurUsage(`${f} existe déjà : la conception est déjà figée`);
      }
      const table = fichiersPresents(racine);
      const manifeste = ecrireManifeste(table);
      const registre = {
        conception: VERSION_CONCEPTION,
        date_figeage: o.date,
        manifeste: FICHIER_MANIFESTE,
        manifeste_sha256: sha256(Buffer.from(manifeste, "utf8")),
        modifications: [],
      };
      fs.mkdirSync(path.join(racine, path.dirname(FICHIER_MANIFESTE)), { recursive: true });
      fs.writeFileSync(path.join(racine, FICHIER_MANIFESTE), manifeste);
      fs.writeFileSync(path.join(racine, FICHIER_REGISTRE), texteRegistre(registre));
      sortie.write(`conception ${VERSION_CONCEPTION} figée le ${o.date} : ${table.size} fichiers dans ${FICHIER_MANIFESTE}\n`);
      return 0;
    }
    const entrees = lireEntrees(racine);
    const fichiers = fichiersPresents(racine);
    if (o.consigner) {
      if (o.motif === undefined || o.motif.trim() === "") throw new ErreurUsage("--consigner demande --motif <texte>");
      let etape = null;
      if (o.etape !== undefined) {
        if (!/^[1-8]$/.test(o.etape)) throw new ErreurUsage("--etape attend un entier de 1 à 8");
        etape = Number(o.etape);
      }
      const date = o.date ?? dateDuJour();
      let suivant;
      try {
        suivant = consignerModification({ ...entrees, fichiers, date, etape, motif: o.motif });
      } catch (e) {
        erreur.write(`${e.message}\n`);
        return 1;
      }
      fs.writeFileSync(path.join(racine, FICHIER_REGISTRE), texteRegistre(suivant));
      const mod = suivant.modifications.at(-1);
      sortie.write(`${mod.id} consignée le ${mod.date} : ${mod.fichiers.length} fichier(s)\n`);
      for (const f of mod.fichiers) sortie.write(`  ${f.avant === null ? "ajouté " : f.apres === null ? "supprimé" : "modifié "} ${f.chemin}\n`);
      return 0;
    }
    const { erreurs, ecarts, etat } = verifierFigeage({ ...entrees, fichiers });
    const conforme = erreurs.length === 0 && ecarts.length === 0;
    if (o.json) {
      sortie.write(JSON.stringify({
        conception: VERSION_CONCEPTION,
        conforme,
        fichiers: fichiers.size,
        modifications: Array.isArray(entrees.registre.modifications) ? entrees.registre.modifications.length : null,
        erreurs,
        ecarts,
      }, null, 2) + "\n");
    } else {
      const nMod = Array.isArray(entrees.registre.modifications) ? entrees.registre.modifications.length : 0;
      sortie.write(`conception ${VERSION_CONCEPTION} : ${fichiers.size} fichiers présents, ${etat.size} attendus, ${nMod} modification(s) consignée(s)\n`);
      for (const e of erreurs) sortie.write(`[ERREUR] ${e}\n`);
      for (const e of ecarts) sortie.write(`[ÉCART] ${e.nature} : ${e.chemin}\n`);
      sortie.write(conforme ? "conforme : chaque écart à la conception figée est consigné\n" : `non conforme : ${erreurs.length} erreur(s), ${ecarts.length} écart(s)\n`);
    }
    return conforme ? 0 : 1;
  } catch (e) {
    if (e instanceof ErreurUsage) {
      erreur.write(`${e.message}\n`);
      return 2;
    }
    throw e;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = executer(process.argv.slice(2));
}
