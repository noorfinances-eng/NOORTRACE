// Approvisionnement d'une clé de chaîne (CT-4 §8.7, EX-8.18, EX-8.20) :
// destinataire admis (une clé de chaîne du dossier du client), solde lu ;
// sous le seuil de recomplément `refill_below_days × b_k + gas_limit`,
// versement de `P_k` moins le solde, sinon `deja_fait` ; consommation depuis
// le dernier approvisionnement capturé, rapportée à la durée écoulée, et
// examen exigé au-delà de deux fois le budget (EX-8.18). La confirmation hors
// bande d'EX-7.26 est exigée par l'agent avant l'exécution du travail.

import * as R from "@noortrace/ancrage/registre";
import { Sortie } from "../sortie.mjs";
import { TenueDossier, etape } from "../dossier.mjs";
import { envoyer } from "../envoi.mjs";
import { solde } from "../reseau.mjs";
import { cleRole, consommerConfirmation, dossierClient, ecartCompte, prealables } from "./base.mjs";
import { completerResult } from "./inscrire-client.mjs";
import { provision } from "./preparer.mjs";

/** Dernier approvisionnement capturé de `vers` dans les captures : `{ index, instantMs }` ou null. */
function dernierApprovisionnement(ctx, vers) {
  let dernier = null;
  for (const c of R.listerCaptures(ctx.captures)) {
    if (c.index.role !== "approvisionnement" || c.index.sending?.to !== vers) continue;
    if (!dernier || c.index.block_number > dernier.index.block_number) dernier = c;
  }
  return dernier ? { index: dernier.index, instantMs: Date.parse(dernier.index.captured_at) } : null;
}

export async function approvisionner(ctx, travail) {
  const sortie = new Sortie("approvisionner", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const tenue = new TenueDossier(ctx.client.dossier, d, { horloge: ctx.horloge, completer: completerResult(ctx) });
  await prealables(ctx, sortie);
  const tresorerie = cleRole(ctx, sortie, "tresorerie");
  const vers = p.cle_chaine;
  // OP-5 : trésorerie du rôle ; destinataire admis par EX-8.20 (clé de chaîne du dossier).
  const ecart = ecartCompte(ctx, "tresorerie", tresorerie.adresse());
  if (ecart) sortie.echec("OP-5", "refuse", "compte_inattendu", ecart);
  if (!d.recorders.some((r) => r.chain_key === vers)) {
    sortie.echec("OP-5", "refuse", "compte_inattendu", `destinataire ${vers} hors d'EX-8.20 : aucune clé de chaîne du dossier du client ${ctx.slug}`);
  }
  sortie.reussie("OP-5");
  const budget = BigInt(p.budget_jour ?? d.funding.daily_budget_gas);
  if (ctx.instance.fees.max_daily_budget_gas !== undefined && budget > BigInt(ctx.instance.fees.max_daily_budget_gas)) {
    sortie.echec("OP-3", "refuse", "provision_excessive", `budget journalier ${budget} au-delà de fees.max_daily_budget_gas (EX-8.20)`);
  }
  const pK = provision(ctx.instance.fees, budget);
  const seuilRecomplement = BigInt(ctx.instance.fees.refill_below_days) * budget + BigInt(ctx.instance.fees.gas_limit);
  const avant = await solde(ctx.rpc, vers);
  const dernier = dernierApprovisionnement(ctx, vers);
  const ecoule = dernier ? Math.max(0, Math.floor((ctx.horloge.murale() - dernier.instantMs) / 1000)) : null;
  const consommation = dernier ? (pK > avant ? pK - avant : 0n) : null;
  const outputs = {
    to: vers,
    admitted_as: "dossier",
    balance_before_wei: avant.toString(),
    provision_wei: pK.toString(),
    refill_below_wei: seuilRecomplement.toString(),
    daily_budget_gas: Number(budget),
    consumption_since_last_funding_wei: consommation === null ? null : consommation.toString(),
    elapsed_seconds: ecoule,
    review: null,
  };
  const deuxFois = consommation === null ? null : (2n * budget * BigInt(ecoule)) / 86400n;
  if (deuxFois !== null) outputs.twice_budget_wei = deuxFois.toString();
  if (avant >= seuilRecomplement) {
    // Au-dessus du seuil : rien n'est versé, sans examen (EX-8.18 ne s'applique qu'à un versement).
    const enAttente = R.envoisSansIssue(ctx.captures, tresorerie.adresse());
    if (enAttente.length > 0) sortie.echec("OP-3", "refuse", "transaction_en_attente", `envoi ${enAttente[0].transaction_hash} de la trésorerie sans issue connue`);
    sortie.reussie("OP-3");
    return sortie.rendre("deja_fait", { outputs: { ...outputs, balance_after_wei: avant.toString() } });
  }
  if (deuxFois !== null && consommation > deuxFois) {
    sortie.arreter("refuse", "examen_requis", null, `consommation ${consommation} wei depuis le dernier approvisionnement, au-delà de deux fois le budget de la même durée (${deuxFois} wei) : examen par l'exploitant (EX-8.18)`, outputs);
  }
  const value = pK - avant;
  // OP-3 : solde de la trésorerie, provision non dépassée, aucun envoi sans issue.
  const enAttente = R.envoisSansIssue(ctx.captures, tresorerie.adresse());
  if (enAttente.length > 0) sortie.echec("OP-3", "refuse", "transaction_en_attente", `envoi ${enAttente[0].transaction_hash} de la trésorerie sans issue connue`);
  const st = await solde(ctx.rpc, tresorerie.adresse());
  if (st < BigInt(ctx.instance.fees.gas_limit) + value) sortie.echec("OP-3", "refuse", "solde_insuffisant", `solde de la trésorerie ${st} wei < ${BigInt(ctx.instance.fees.gas_limit) + value} wei`);
  if (avant + value > pK) sortie.echec("OP-3", "refuse", "provision_excessive", `provision ${pK} dépassée`);
  sortie.reussie("OP-3");
  const e = etape(d, "approvisionnement", vers);
  consommerConfirmation(ctx, { operations: ["approvisionner"], orgId: d.organisation.org_id, cleChaine: vers });
  const res = await envoyer(ctx, sortie, {
    tenue, etape: e && e.state !== "capturee" && e.state !== "faite" ? e : null, cle: tresorerie, objet: "approvisionnement", to: vers, value, provision: pK,
    role: "approvisionnement", contrat: null,
    op11: (recu) => ((recu.logs ?? []).length === 0 ? { ok: true } : { ok: false, detail: "journal inattendu dans le reçu d'un approvisionnement" }),
    op12: async (h) => {
      const r = await ctx.rpc.appelerPremier("eth_getBalance", [vers, h]);
      const b = r.erreur ? null : R.quantiteVersEntier(r.resultat, (1n << 256n) - 1n);
      return b !== null && b >= pK ? { ok: true } : { ok: false, detail: `solde de ${vers} à ${h} sous la provision` };
    },
  });
  const apres = await solde(ctx.rpc, vers);
  return sortie.rendre("reussi", {
    outputs: { ...outputs, balance_after_wei: apres.toString(), amount_wei: value.toString(), transaction_hash: res.transactionHash, block_number: res.blockNumber, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture },
  });
}
