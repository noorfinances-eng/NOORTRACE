// Envoi d'une transaction du registre par l'agent, pas à pas (CT-4 EX-7.5,
// §8.6, §9.4) : nonce d'EX-8.14, signature, RG-15 sur les octets signés,
// envoi écrit (`envoi-<hachage>.json`) avant la soumission, étape `envoyee`
// juste avant `eth_sendRawTransaction`, soumission des mêmes octets à chaque
// point (EX-8.15), attente du reçu sondée toutes les 100 ms (EX-7.1), issue
// (`issue-<hachage>.json`), OP-11, étape `incluse`, capture (CP-1 à CP-6,
// `capturer` de `@noortrace/ancrage/registre`), étape `capturee`, OP-12, et
// marge de rétention (EX-9.6). Une étape `envoyee` ou `incluse` se reprend
// sur la transaction connue, jamais par un nouvel envoi (EX-7.16).
//
// La clé n'est vue que par `signerTransaction` ; aucun secret n'est écrit.

import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { nonce as lireNonce, reessayer, tete } from "./reseau.mjs";

const MAX_U64 = (1n << 64n) - 1n;

const serialiser = (o) => Buffer.from(JSON.stringify(o, null, 2) + "\n", "utf8");

/** Instance au format attendu par `capturer` et `Envoyeur` d'ancrage. */
export function instanceCapture(instance) {
  return { evmChainId: instance.evmChainId, bftChainId: instance.bftChainId, jeux: instance.jeux, contrats: instance.contrats, fees: instance.fees };
}

/** Écrit l'issue d'un envoi (`#/$defs/issue`) en création exclusive. */
export function ecrireIssue(captures, issue) {
  const v = R.verifierIssue(issue);
  if (!v.valide) throw new Error(`issue hors schéma : ${v.erreurs.join(" ; ")}`);
  fs.mkdirSync(captures, { recursive: true });
  R.ecrireExclusif(path.join(captures, R.nomIssue(issue.transaction_hash)), serialiser(issue));
  R.synchroniserRepertoire(captures);
}

/** Sonde le reçu d'un hachage sur chaque point jusqu'au délai ; rend la réponse (`{ point, octets, resultat }`) ou null. */
export async function attendreRecu(ctx, hash, delaiMs = ctx.delaiMs) {
  const debut = ctx.horloge.monotone();
  for (;;) {
    for (const point of ctx.rpc.points()) {
      try {
        const r = await ctx.rpc.appeler("eth_getTransactionReceipt", [hash], { point });
        if (!r.erreur && r.resultat && typeof r.resultat === "object") return r;
      } catch (e) {
        if (!(e instanceof R.ErreurRpc)) throw e;
      }
    }
    if (ctx.horloge.monotone() - debut >= delaiMs) return null;
    await ctx.attendre(100);
  }
}

/** Attend, au plus 30 s, que le premier point qui répond ait décidé la hauteur `h`. */
export async function attendreHauteur(ctx, h) {
  const debut = ctx.horloge.monotone();
  for (;;) {
    try {
      if ((await tete(ctx.rpc)) >= BigInt(h)) return true;
    } catch (e) {
      if (!(e instanceof R.ErreurRpc) && !(e instanceof R.ErreurLecture)) throw e;
    }
    if (ctx.horloge.monotone() - debut >= 30000) return false;
    await ctx.attendre(100);
  }
}

/** Marge de rétention d'EX-9.6, depuis le certificat capturé : `{ retention_heights, margin_heights, alert }`. */
export async function retention(ctx, captures, index) {
  const lecteur = R.lecteurRepertoire(captures);
  const cert = R.lireFichierRpc(lecteur.lire(index.files.certificate.name));
  const hauteurs = Number.isSafeInteger(cert?.resultat?.retention?.heights) ? cert.resultat.retention.heights : 300000;
  const h = BigInt(await tete(ctx.rpc));
  const marge = Number(BigInt(index.block_number) + BigInt(hauteurs) - h);
  return { retention_heights: hauteurs, margin_heights: marge, alert: marge < hauteurs / 10 };
}

/**
 * Envoie une transaction et la conduit jusqu'à sa capture. Paramètres :
 * `sortie` ; `tenue` et `etape` (le dossier et l'étape suivie, ou null) ;
 * `cle` (signataire) ; `objet` (`appel`, `deploiement`,
 * `approvisionnement`, RG-15) ; `to`, `donnees` (hexadécimal), `value`,
 * `provision` ; `role` et `contrat` de la capture ; `contratCree` (adresse
 * créée par un déploiement, écrite dans `contract` de l'étape) ; `op11(recu)`
 * → `{ ok, detail }` ; `op12(hauteurHex)` → `{ ok, detail }`.
 * Rend `{ envoi, transactionHash, blockNumber, blockHash, gasUsed, coutWei,
 * capture, retention }` ou lève `FinCommande`.
 */
export async function envoyer(ctx, sortie, p) {
  const { instance, rpc } = ctx;
  const from = p.cle.adresse();
  const n = await lireNonce(rpc, from);
  const value = p.value ?? 0n;
  const tx = R.construireTransaction({
    chain_id: instance.evmChainId, nonce: n, max_priority_fee_per_gas: R.FRAIS_NOMINAUX, max_fee_per_gas: R.FRAIS_NOMINAUX,
    gas_limit: instance.fees.gas_limit, to: p.to ?? null, value, data: p.donnees ?? "0x",
  });
  const signee = await R.signerTransaction(tx, p.cle);
  const rg15 = R.verifierRG15(signee.octets, {
    evm_chain_id: instance.evmChainId, fees: instance.fees, objet: p.objet, to: p.to ?? undefined,
    data: p.objet === "approvisionnement" ? undefined : (p.donnees ?? "0x"), provision: p.provision,
  });
  if (rg15.statut !== "reussi") throw new Error(`RG-15 échoue sur la transaction signée : ${rg15.motif}`);
  const envoi = {
    from, to: p.to ?? null, nonce: Number(n), type: 2,
    max_fee_per_gas: "1", max_priority_fee_per_gas: "1", gas_limit: String(instance.fees.gas_limit), value: value.toString(),
    raw_transaction: signee.raw_transaction, transaction_hash: signee.transaction_hash,
    submitted_to: rpc.points().slice(0, 8), submitted_at: ecrireHorodatage(ctx.horloge.murale()),
  };
  const ve = R.verifierEnvoi(envoi);
  if (!ve.valide) throw new Error(`envoi hors schéma : ${ve.erreurs.join(" ; ")}`);
  fs.mkdirSync(ctx.captures, { recursive: true });
  if (!R.ecrireExclusif(path.join(ctx.captures, R.nomEnvoi(envoi.transaction_hash)), serialiser(envoi))) throw new Error(`envoi ${envoi.transaction_hash} déjà écrit`);
  R.synchroniserRepertoire(ctx.captures);
  ctx.consigner("envoi_ecrit", { transaction_hash: envoi.transaction_hash, nonce: envoi.nonce, from });
  if (p.tenue && p.etape) {
    await p.tenue.passer(p.etape, { state: "envoyee", transaction_hash: envoi.transaction_hash, block_number: null, block_hash: null, capture: null, error: null, ...(p.contratCree ? { contract: p.contratCree } : {}) });
  }
  const reponses = await rpc.appelerTous("eth_sendRawTransaction", [envoi.raw_transaction]);
  const acceptes = reponses.filter((r) => !r.panne && !r.erreur);
  if (acceptes.length === 0) {
    ecrireIssue(ctx.captures, { version: 0, transaction_hash: envoi.transaction_hash, state: "ecartee", recorded_at: ecrireHorodatage(ctx.horloge.murale()) });
    const refus = reponses.filter((r) => r.erreur);
    if (p.tenue && p.etape) await p.tenue.passer(p.etape, { state: "a_faire", transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null });
    if (refus.length > 0) sortie.arreter("refuse", "transaction_refusee", null, `${refus[0].point} : ${refus[0].erreur.code} ${refus[0].erreur.message}`.slice(0, 1024), { transaction_hash: envoi.transaction_hash });
    sortie.arreter("inutilisable", "noeud_injoignable", null, "aucun point n'a reçu la transaction", { transaction_hash: envoi.transaction_hash });
  }
  const recu = await attendreRecu(ctx, envoi.transaction_hash);
  if (!recu) {
    sortie.arreter("incertain", "recu_absent", null, `aucun reçu pour ${envoi.transaction_hash} en ${Math.round(ctx.delaiMs / 1000)} s ; reprendre par le travail capturer (envoi ${envoi.transaction_hash}, CT-4 §8.6)`, { envoi: R.nomEnvoi(envoi.transaction_hash), transaction_hash: envoi.transaction_hash });
  }
  return conclure(ctx, sortie, { ...p, envoi, recu });
}

/**
 * Conduit une transaction dont le reçu est obtenu : issue, OP-11, étape
 * `incluse`, capture, étape `capturee`, OP-12, rétention. `envoi` : l'envoi
 * de l'agent (ou null pour une transaction d'autrui). Rend comme `envoyer`.
 */
export async function conclure(ctx, sortie, p) {
  const { recu } = p;
  const hash = p.envoi ? p.envoi.transaction_hash : p.transactionHash;
  const r = recu.resultat;
  const h = R.quantiteVersEntier(r.blockNumber, MAX_U64);
  const blockHash = typeof r.blockHash === "string" ? r.blockHash.toLowerCase() : null;
  if (p.envoi) {
    const present = fs.existsSync(path.join(ctx.captures, R.nomIssue(hash)));
    if (!present && h !== null) ecrireIssue(ctx.captures, { version: 0, transaction_hash: hash, block_number: Number(h), status: r.status === "0x0" ? "0x0" : "0x1", recorded_at: ecrireHorodatage(ctx.horloge.murale()) });
  }
  const echecTransaction = async (detail) => {
    if (p.tenue && p.etape) {
      await p.tenue.passer(p.etape, { state: "echec", transaction_hash: hash, block_number: h === null ? null : Number(h), block_hash: blockHash, capture: null, error: { code: "transaction_annulee", message: detail.slice(0, 1024) } });
    }
    const outputs = { transaction_hash: hash, block_number: h === null ? null : Number(h) };
    const gas = R.quantiteVersEntier(r.gasUsed, MAX_U64);
    if (p.envoi && gas !== null) Object.assign(outputs, { gas_used: Number(gas), cost_wei: (gas * BigInt(p.envoi.max_fee_per_gas)).toString() });
    sortie.echec("OP-11", "echoue", "transaction_annulee", detail, outputs);
  };
  if (r.status !== "0x1") await echecTransaction(`reçu de ${hash} à status ${r.status}`);
  const v11 = p.op11 ? await p.op11(r) : { ok: true };
  if (!v11.ok) await echecTransaction(v11.detail);
  sortie.reussie("OP-11");
  if (p.tenue && p.etape) {
    await p.tenue.passer(p.etape, { state: "incluse", transaction_hash: hash, block_number: Number(h), block_hash: blockHash, capture: null, error: null, ...(p.contratCree ? { contract: p.contratCree } : {}) });
  }
  return capturerEtRelire(ctx, sortie, { ...p, hash, hauteur: Number(h), blockHash });
}

/**
 * Capture (CP-1 à CP-6), étape `capturee`, OP-12 et rétention, pour une
 * transaction incluse (reprise d'une étape `incluse`, EX-7.16).
 */
export async function capturerEtRelire(ctx, sortie, p) {
  const c = await R.capturer({
    rpc: ctx.rpc, transactionHash: p.hash, role: p.role, contrat: p.contrat ?? null, horloge: ctx.horloge, repertoire: ctx.captures,
    instance: instanceCapture(ctx.instance), attendre: ctx.attendre, sending: p.envoi ?? null, attendu: p.attendu ?? null,
    point: p.recu?.point ?? ctx.rpc.points()[0], recu: p.recu ?? null,
  });
  // Capture en échec : les vérifications exécutées jusqu'à l'échec sont consignées, celle qui échoue est nommée par
  // `error.check` (même forme que l'outil de référence) ; l'étape reste `incluse` (EX-7.16).
  for (const ch of c.checks ?? []) sortie.noter(ch.id, ch.status, ch.detail);
  if (c.erreur) {
    const resultat = c.erreur.code === "inutilisable" ? "inutilisable" : "incertain";
    const recuLu = p.recu?.resultat ?? null;
    const gas = recuLu ? R.quantiteVersEntier(recuLu.gasUsed, MAX_U64) : null;
    const outputs = { transaction_hash: p.hash, block_number: p.hauteur };
    if (p.envoi && gas !== null) Object.assign(outputs, { gas_used: Number(gas), cost_wei: (gas * BigInt(p.envoi.max_fee_per_gas)).toString(), envoi: R.nomEnvoi(p.envoi.transaction_hash) });
    sortie.arreter(resultat, c.erreur.code === "inutilisable" ? "certificat_indisponible" : c.erreur.code, c.erreur.check ?? null, c.erreur.message || c.erreur.code, outputs);
  }
  if (p.tenue && p.etape) await p.tenue.passer(p.etape, { state: "capturee", transaction_hash: p.hash, block_number: c.index.block_number, block_hash: c.index.block_hash, capture: c.nom, error: null, ...(p.contratCree ? { contract: p.contratCree } : {}) });
  // OP-12 suit l'envoi (EX-7.5) ; la reprise d'une étape `incluse` ne refait que la capture (`op12` absent), comme
  // l'outil de référence sur le même état.
  if (p.op12) {
    // Les lectures d'état passent par le premier point qui répond : il doit avoir décidé le bloc relu (un validateur
    // peut rendre le reçu avant les autres, et un nœud en retard sert l'état de sa tête, observé sur le réseau de
    // développement).
    await attendreHauteur(ctx, c.index.block_number);
    const v12 = await reessayer(() => p.op12("0x" + BigInt(c.index.block_number).toString(16)), ctx.attendre);
    if (!v12.ok) {
      if (p.tenue && p.etape) await p.tenue.passer(p.etape, { state: "echec", error: { code: "transaction_annulee", message: v12.detail.slice(0, 1024) } });
      sortie.echec("OP-12", "echoue", "transaction_annulee", v12.detail, { transaction_hash: p.hash, block_number: c.index.block_number });
    }
    sortie.reussie("OP-12");
  }
  const recuLu = R.lireFichierRpc(R.lecteurRepertoire(ctx.captures).lire(c.index.files.receipts[c.index.transaction_index].name));
  const gasUsed = R.quantiteVersEntier(recuLu?.resultat?.gasUsed, MAX_U64) ?? 0n;
  const fee = p.envoi ? BigInt(p.envoi.max_fee_per_gas) : null;
  return {
    envoi: p.envoi ?? null,
    transactionHash: p.hash,
    blockNumber: c.index.block_number,
    blockHash: c.index.block_hash,
    gasUsed: Number(gasUsed),
    coutWei: fee === null ? null : (gasUsed * fee).toString(),
    capture: c.nom,
    index: c.index,
    retention: await retention(ctx, ctx.captures, c.index),
  };
}
