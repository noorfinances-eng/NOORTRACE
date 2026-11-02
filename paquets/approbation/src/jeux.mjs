// Jeux d'approbateurs (CT-3 §8) : jeu statique de la politique (EX-8.2),
// comparaison d'une lecture au jeu figé (EX-8.6), jeu déclaré d'une remise
// ou d'une réponse `nouveau` avec sa `source` de la forme exacte d'EX-8.8, et
// forme « exploitable » d'EX-12.6.

import { cloner } from "./json.mjs";

/** Motif de contrôle d'une `source` (EX-8.8). */
export const MOTIF_SOURCE = /^(CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?|jeu statique de la politique .{1,128})$/u;

const trier = (l) => [...l].map((a) => a.toLowerCase()).sort();

/**
 * Jeu (`$defs/jeu` de ticket-v0) d'une politique `statique` : membres en
 * minuscules, triés ; champs de chaîne nuls (EX-8.2).
 * @param {object} pol `approver_set` de la politique
 */
export function jeuStatique(pol) {
  return {
    chain_id: null,
    registry: null,
    set: null,
    height: null,
    block_hash: null,
    threshold: { required: pol.threshold.required, size: pol.threshold.size },
    members: trier(pol.members),
  };
}

/** Deux jeux ont-ils même seuil et mêmes membres (EX-8.6 : `t`, `n` ou membres) ? */
export function jeuxEgaux(a, b) {
  if (a.threshold.required !== b.threshold.required || a.threshold.size !== b.threshold.size) return false;
  const x = trier(a.members);
  const y = trier(b.members);
  return x.length === y.length && x.every((m, k) => m === y[k]);
}

/**
 * `source` d'EX-8.8.
 * @param {object} jeu jeu figé ou lu
 * @param {string} pv version de politique du ticket (jeu statique)
 * @param {{height: number, block_hash: string}|null} confirmation hauteur et bloc de confirmation
 * @param {boolean} repli jeu de repli d'EX-8.4
 */
export function sourceJeu(jeu, pv, confirmation, repli) {
  if (jeu.height === null) return `jeu statique de la politique ${pv}`;
  const c = confirmation ?? { height: jeu.height, block_hash: jeu.block_hash };
  return `CuratorSet c=${jeu.chain_id} r=${jeu.registry} s=${jeu.set} h=${jeu.height}..${c.height} b=${c.block_hash}${repli ? " repli" : ""}`;
}

/**
 * Jeu déclaré (`$defs/approver_set`) : seuil et membres de la lecture, `source`
 * d'EX-8.8 (EX-8.9 : le seuil est celui de la confirmation, non le seuil effectif).
 * @param {object} jeu
 * @param {object} _pol `approver_set` de la politique (inutilisé : la source reprend la lecture)
 * @param {string} pv
 * @param {{height: number, block_hash: string}|null} confirmation
 * @param {boolean} repli
 */
export function jeuDeclare(jeu, _pol, pv, confirmation, repli) {
  return { threshold: cloner(jeu.threshold), members: trier(jeu.members), source: sourceJeu(jeu, pv, confirmation, repli) };
}

/**
 * Jeu « exploitable » d'EX-12.6 : membres distincts, `size` égal au nombre de
 * membres, `required` au plus `size`, `source` de la forme d'EX-8.8.
 * @param {{threshold: {required: number, size: number}, members: string[], source: string}} j
 */
export function jeuExploitable(j) {
  return (
    MOTIF_SOURCE.test(j.source) && new Set(j.members).size === j.members.length &&
    j.threshold.size === j.members.length && j.threshold.required <= j.threshold.size
  );
}
