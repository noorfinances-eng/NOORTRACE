// Pas 1 : préparation du dossier d'inscription (CT-4 §7.5, `inscrire-client
// --preparer`) : OP-2, OP-1, OP-4, OP-5, provision `P_k` (EX-4.19), dossier
// écrit avec toutes ses étapes à `a_faire` et `result` nul. Rien n'est envoyé.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { ecrireHorodatage } from "@noortrace/noyau";
import { IDS, valider } from "../../commun/schemas.mjs";
import { MOTIF_SLUG, MOTIF_SLUG_PRODUCTION } from "../../commun/champs.mjs";
import { Sortie } from "../sortie.mjs";
import { ecrireDossier } from "../dossier.mjs";
import { creerRepertoire } from "../donnees.mjs";
import { cleRole, ecartCompte, etat, keccakTexte, prealables } from "./base.mjs";
import { SOURCE } from "../version.mjs";

/** Budget journalier par défaut : un journal horaire, 24 × (100 000 + 350 000) gaz (CT-4 §7.5). */
export const BUDGET_DEFAUT = 10800000n;

/** Provision `P_k = provision_days × b_k + gas_limit` (EX-4.19). */
export function provision(fees, budget) {
  return BigInt(fees.provision_days) * BigInt(budget) + BigInt(fees.gas_limit);
}

/** Lit `cles-essai.json` et les documents de clé qu'il désigne (réseau de développement, EX-7.3). */
function lireClesEssai(chemin) {
  const doc = lireJsonStrict(fs.readFileSync(chemin));
  const dir = path.dirname(chemin);
  const recorders = (doc.recorders ?? []).map((r) => {
    if (typeof r.file !== "string" || r.file.includes("/") || r.file.includes("..")) throw new Error("cles-essai.json : nom de fichier de clé hors forme");
    return lireJsonStrict(fs.readFileSync(path.join(dir, r.file)));
  });
  return { approbateurs: doc.approvers, admin_jeu: doc.set_admin, cles_enregistreur: recorders };
}

export async function preparer(ctx, travail) {
  const sortie = new Sortie("inscrire-client", ctx);
  const p = travail.parametres;
  await prealables(ctx, sortie);
  if (fs.existsSync(ctx.client.dossier)) sortie.arreter("inutilisable", "usage", null, `${ctx.client.dossier} existe déjà`);
  const cle = cleRole(ctx, sortie, "tresorerie", p.tresorerie ?? null, { option: "tresorerie" });
  let entrees = p;
  if (p.cles_essai) {
    try {
      // Chemin relatif sous le répertoire du client (EX-7.25, révision 0.7), où l'exploitant a déposé cles-essai.json.
      entrees = { ...p, ...lireClesEssai(path.join(ctx.client.dir, p.cles_essai)) };
    } catch (e) {
      sortie.arreter("inutilisable", "entree_illisible", null, `clés d'essai illisibles : ${String(e.message).slice(0, 200)}`);
    }
  }
  const production = ctx.instance.nature === "production";

  // OP-4 : organisation, journaux, jeu, clés.
  const refus = (message, code = "jeu_invalide") => sortie.echec("OP-4", "refuse", code, message);
  if (!MOTIF_SLUG.test(p.org)) refus(`slug "${p.org}" hors de la grammaire ${MOTIF_SLUG.source}`);
  if (production && !MOTIF_SLUG_PRODUCTION.test(p.org)) refus(`slug de production : o- et 32 chiffres hexadécimaux (EX-6.2)`);
  const orgId = keccakTexte(p.org);
  const journals = p.journaux.map((name) => ({ name, journal_id: keccakTexte(name) }));
  if (new Set(p.journaux).size !== p.journaux.length) refus("journaux : noms en double");
  const membresBruts = Array.isArray(entrees.approbateurs) ? entrees.approbateurs : [];
  if (!membresBruts.every((a) => typeof a === "string" && /^0x[0-9a-f]{40}$/.test(a) && !/^0x0{40}$/.test(a))) refus("membres : adresses non nulles, en minuscules");
  const membres = [...membresBruts].sort();
  const budget = BigInt(p.budget_jour ?? BUDGET_DEFAUT);
  if (budget > BigInt(Number.MAX_SAFE_INTEGER)) sortie.arreter("inutilisable", "usage", null, "budget journalier au-delà de 2^53 − 1");
  const montant = provision(ctx.instance.fees, budget);
  const recorders = entrees.cles_enregistreur ?? [];
  const steps = [];
  const etapeVide = (step, subject) => ({ step, subject, state: "a_faire", transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null, updated_at: null });
  for (const s of ["jeu_approbateurs", "assignation", "lecture_jeu"]) steps.push(etapeVide(s, p.org));
  for (const r of recorders) steps.push(etapeVide("approvisionnement", r.chain_key));
  for (const r of recorders) steps.push(etapeVide("inscription", r.key_id));
  for (const j of journals) {
    steps.push(etapeVide("premiere_ancre", j.name));
    steps.push(etapeVide("premiere_cloture", j.name));
  }
  const dossier = {
    version: 0,
    instance: {
      evm_chain_id: ctx.instance.evmChainId,
      bft_chain_id: ctx.instance.bftChainId,
      genesis_sha256: ctx.instance.genesisSha256,
      contracts: {
        curator_set_registry: ctx.instance.contrats.curator_set_registry,
        recorder_registry: ctx.instance.contrats.recorder_registry,
        period_registry: ctx.instance.contrats.period_registry,
        attestation_registry: ctx.instance.contrats.attestation_registry,
      },
      manifest_sha256: ctx.instance.manifestSha256,
      validator_set_hash: ctx.instance.validatorSetHash,
    },
    organisation: { slug: p.org, org_id: orgId },
    approvers: { members: membres, threshold: p.seuil, set_admin: entrees.admin_jeu },
    journals,
    recorders,
    funding: { funder: cle.adresse(), daily_budget_gas: Number(budget), amount_wei: montant.toString() },
    steps,
    result: null,
    prepared_by: ctx.exploitant,
    prepared_at: ecrireHorodatage(ctx.horloge.murale()),
    source: `dossier préparé par ${SOURCE} (CT-4 §7.5)`,
  };
  const v = valider(IDS.inscription, dossier);
  if (!v.valide) refus(`dossier non conforme à inscription-client-v0 : ${v.erreurs[0]}`);
  if (p.seuil < 1 || p.seuil > membres.length) refus(`seuil ${p.seuil} hors de [1, ${membres.length}]`);
  if (/^0x0{40}$/.test(entrees.admin_jeu)) refus("administrateur du jeu nul");
  if (production && Object.values(ctx.instance.comptes).includes(entrees.admin_jeu)) refus("administrateur du jeu : compte de l'exploitant refusé en production (EX-5.6)");
  for (const r of recorders) {
    if (!journals.some((j) => j.journal_id === r.journal_id)) refus(`clé ${r.key_id} rattachée à un journal absent du dossier`);
    if (production && (r.custody_class === "D" || r.chain_key_class === "D")) refus(`clé ${r.key_id} : classe de garde D refusée en production (CT-2 §11.2)`, "cle_invalide");
  }
  if (await etat.isRegistered(ctx, orgId)) {
    refus(`l'organisation ${p.org} (${orgId}) a déjà un jeu : un slug n'est attribué qu'une fois (EX-6.3)`, "organisation_existante");
  }
  sortie.reussie("OP-4");

  // OP-5 : trésorerie du rôle.
  const ecart = ecartCompte(ctx, "tresorerie", cle.adresse());
  if (ecart) sortie.echec("OP-5", "refuse", "compte_inattendu", ecart);
  sortie.reussie("OP-5");

  creerRepertoire(ctx.client.dir);
  ecrireDossier(ctx.client.dossier, dossier);
  return sortie.rendre("reussi", { outputs: { org_id: orgId, journal_ids: journals.map((j) => j.journal_id), amount_wei: montant.toString(), dossier: ctx.client.dossier } });
}
