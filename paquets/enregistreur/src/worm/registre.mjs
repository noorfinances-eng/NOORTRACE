// Registre des copies WORM (CT-2 EX-12.29) : `worm/copies-<epoch>.ndjson`,
// ouvert en ajout seul, une ligne JCS intégral `$defs/ligne_copie` du schéma
// `worm-v0` par copie réussie et contrôlée, sans fdatasync propre ; tourné
// avec le segment (une époque, un fichier) et conservé avec le journal. Il ne
// fait foi de rien (le support fait foi) ; il sert au relevé et à l'outil de
// gel, et se reconstruit depuis la liste des versions (EX-17.6 pas 3).
// Et références de pièces d'un segment (EX-12.16 `copy_pieces`, EX-12.35 pas 4).

import fs from "node:fs/promises";
import path from "node:path";
import { referencesEvenement } from "@noortrace/noyau";
import { FichierAjout, creerRepertoire, decouperLignes } from "../fichiers.mjs";
import { jcsIntegralOctets, analyserJsonIntegral } from "../jcs-integral.mjs";

/** Sous-préfixes que l'écrivain copie (EX-12.32) ; jamais `<prefix>gels/`. */
export const SOUS_PREFIXES_ECRIVAIN = Object.freeze(["segments/", "manifestes/", "points/", "ancres/", "pieces/"]);

/** Nom du registre d'une époque (12.1). */
export function nomRegistreCopies(epoque) {
  return `copies-${String(epoque).padStart(20, "0")}.ndjson`;
}

/** Ligne JCS intégral suivie de `\n`. */
export function ligneRegistre(o) {
  const b = jcsIntegralOctets(o);
  const l = new Uint8Array(b.length + 1);
  l.set(b);
  l[b.length] = 10;
  return l;
}

/**
 * Lit toutes les lignes des registres d'un répertoire `worm/` (époques
 * croissantes) ; une ligne incomplète ou illisible est ignorée (le registre
 * ne fait foi de rien).
 * @param {string} dirWorm
 * @returns {Promise<{epoque: number, ligne: object}[]>}
 */
export async function lireRegistres(dirWorm) {
  let noms = [];
  try {
    noms = (await fs.readdir(dirWorm)).filter((n) => /^copies-[0-9]{20}\.ndjson$/.test(n)).sort();
  } catch {
    return [];
  }
  const r = [];
  for (const n of noms) {
    const epoque = Number(n.slice(7, 27));
    let octets;
    try {
      octets = new Uint8Array(await fs.readFile(path.join(dirWorm, n)));
    } catch {
      continue;
    }
    for (const l of decouperLignes(octets)) {
      if (!l.complete) continue;
      try {
        const o = analyserJsonIntegral(l.octets);
        if (typeof o?.key === "string") r.push({ epoque, ligne: o });
      } catch {
        // ligne illisible : ignorée
      }
    }
  }
  return r;
}

/** Ajoute une ligne au registre d'une époque (O_APPEND, sans fdatasync). */
export async function inscrireCopie(dirWorm, epoque, ligne) {
  await creerRepertoire(dirWorm);
  const f = await FichierAjout.ouvrir(path.join(dirWorm, nomRegistreCopies(epoque)), { creer: true, existantAdmis: true });
  try {
    await f.ajouter(ligneRegistre(ligne));
  } finally {
    await f.fermer();
  }
}

/**
 * Empreintes des pièces stockées que référencent les événements d'un segment
 * (EX-12.35 pas 4) : toute référence sans `value` (une référence en ligne n'a
 * pas de pièce stockée), `code.prompt_version`, et `policy_sha256` d'un
 * événement de politique ; dans l'ordre de première apparition.
 * @param {object[]} evenements
 * @returns {string[]}
 */
export function piecesReferencees(evenements) {
  const vues = new Set();
  const r = [];
  const ajouter = (s) => {
    if (typeof s === "string" && /^0x[0-9a-f]{64}$/.test(s) && !vues.has(s)) {
      vues.add(s);
      r.push(s);
    }
  };
  for (const e of evenements) {
    for (const { reference } of referencesEvenement(e)) if (!("value" in reference)) ajouter(reference.sha256);
    ajouter(e?.code?.prompt_version);
    if (e?.execution?.tool === "noortrace.journal.politique") ajouter(e.execution.arguments?.value?.policy_sha256);
  }
  return r;
}
