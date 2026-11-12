// Lecture JSON stricte (noms de membres uniques, aucun substitut isolé,
// profondeur bornée, nombres finis), sur `analyserJson` de `@noortrace/noyau`,
// avec les options de `lireJsonStrict` de `@noortrace/approbation` (CT-3
// EX-12.1). Ce module évite au mandataire et aux routes de l'interface de
// charger le service d'approbation entier.

import { analyserJson } from "@noortrace/noyau";

/** Lit un texte JSON strict ; lève sur un double, un substitut isolé, une profondeur au-delà de 256 ou un nombre infini. */
export function lireJsonStrict(source) {
  const v = analyserJson(source, { nombres: "libres", substituts: "refuses", profondeurMax: 256 });
  const pile = [v];
  while (pile.length) {
    const x = pile.pop();
    if (typeof x === "number" && !Number.isFinite(x)) throw new Error("nombre hors de la double précision");
    if (Array.isArray(x)) pile.push(...x);
    else if (x !== null && typeof x === "object") pile.push(...Object.values(x));
  }
  return v;
}
