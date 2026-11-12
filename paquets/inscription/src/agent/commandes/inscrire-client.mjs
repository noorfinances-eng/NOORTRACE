// Pas 2 à 5 (CT-4 §7.6, `inscrire-client --dossier`) : pour chaque étape
// encore à faire, dans l'ordre, `jeu_approbateurs` (déploiement de
// `CuratorSet(set_admin, members, threshold)`), `assignation`
// (`setCuratorSet`), `lecture_jeu` (CT-3 EX-8.1, `LecteurJeu`),
// `approvisionnement` de chaque clé de chaîne ; arrêt au premier refus ;
// reprise selon la table d'EX-7.16 (jamais un nouvel envoi pour une étape
// `envoyee` ou `incluse`).

import fs from "node:fs";
import * as R from "@noortrace/ancrage/registre";
import { LecteurJeu } from "@noortrace/approbation";
import { Sortie } from "../sortie.mjs";
import { TenueDossier, etape, referenceTransaction } from "../dossier.mjs";
import { attendreHauteur, attendreRecu, capturerEtRelire, conclure, envoyer } from "../envoi.mjs";
import * as J from "../jeu.mjs";
import { lecture, nonce as lireNonce, solde } from "../reseau.mjs";
import { ecrireAtomique, serialiser } from "../donnees.mjs";
import { cleRole, consommerConfirmation, dossierClient, ecartCompte, ecartRolesDistincts, etat, prealables, ZERO20 } from "./base.mjs";
import { provision } from "./preparer.mjs";

const ROLE_ETAPE = { jeu_approbateurs: "jeu_approbateurs", assignation: "assignation", approvisionnement: "approvisionnement", inscription: "inscription", premiere_ancre: "ancre", premiere_cloture: "cloture" };

/** Rôle de capture d'une étape du dossier. */
export const roleDeEtape = (step) => ROLE_ETAPE[step] ?? null;

/** Fonction de complétion de `result` (7.10) pour une `TenueDossier`. */
export function completerResult(ctx) {
  return async (dossier, instant) => {
    const jeu = etape(dossier, "jeu_approbateurs");
    const assignation = etape(dossier, "assignation");
    const lectureJeu = etape(dossier, "lecture_jeu");
    const set = jeu?.contract ?? null;
    if (!set || !referenceTransaction(jeu) || !referenceTransaction(assignation) || !lectureJeu || lectureJeu.block_number === null) return null;
    const setRead = await lectureJeuA(ctx, dossier, set, lectureJeu);
    if (!setRead) return null;
    const recorders = [];
    for (const r of dossier.recorders) {
      // Approvisionnement fait sans transaction (solde déjà au moins P_k, EX-7.16) : funding nul (EX-7.29, révision 0.7).
      const eF = etape(dossier, "approvisionnement", r.chain_key);
      const f = eF?.state === "faite" ? null : referenceTransaction(eF);
      const i = referenceTransaction(etape(dossier, "inscription", r.key_id));
      if ((!f && eF?.state !== "faite") || !i) return null;
      recorders.push({ key_id: r.key_id, chain_key: r.chain_key, funding: f, registration: i });
    }
    return {
      curator_set: set,
      set_deployment: referenceTransaction(jeu),
      assignment: referenceTransaction(assignation),
      approver_set: { source: "registre", chain_id: dossier.instance.evm_chain_id, registry: dossier.instance.contracts.curator_set_registry, set, members: null, threshold: null },
      set_read: setRead,
      recorders,
      completed_at: instant,
    };
  };
}

/** `set_read` de l'étape `lecture_jeu` : la lecture gardée par l'agent à cette hauteur, ou une relecture à cette hauteur. */
async function lectureJeuA(ctx, dossier, set, e) {
  try {
    const garde = JSON.parse(fs.readFileSync(ctx.client.lectureJeu, "utf8"));
    if (garde.height === e.block_number && garde.block_hash === e.block_hash) return garde;
  } catch {
    // relecture ci-dessous
  }
  const h = "0x" + BigInt(e.block_number).toString(16);
  const t = await etat.seuil(ctx, set, h);
  const n = await etat.taille(ctx, set, h);
  const membres = [];
  for (const a of dossier.approvers.members) if (await etat.estMembre(ctx, set, a, h)) membres.push(a);
  if (t === null || n === null || BigInt(membres.length) !== n) return null;
  return { height: e.block_number, block_hash: e.block_hash, threshold: Number(t), size: Number(n), members: membres.sort() };
}

/** OP-3 (EX-4.18, 8.6) : solde de l'expéditeur, aucun envoi sans issue ; pour un approvisionnement, provision non dépassée. */
async function op3(ctx, sortie, { expediteur, value = 0n, destinataire = null, provisionK = null }) {
  const enAttente = R.envoisSansIssue(ctx.captures, expediteur);
  if (enAttente.length > 0) sortie.echec("OP-3", "refuse", "transaction_en_attente", `envoi ${enAttente[0].transaction_hash} de ${expediteur} sans issue connue ; reprendre par le travail capturer (8.6)`);
  const s = await solde(ctx.rpc, expediteur);
  const besoin = BigInt(ctx.instance.fees.gas_limit) * 1n + value;
  if (s < besoin) sortie.echec("OP-3", "refuse", "solde_insuffisant", `solde de ${expediteur} : ${s} wei < ${besoin} wei (EX-4.18)`);
  if (destinataire && provisionK !== null) {
    const sd = await solde(ctx.rpc, destinataire);
    if (sd + value > provisionK) sortie.echec("OP-3", "refuse", "provision_excessive", `${destinataire} : solde ${sd} + ${value} > provision ${provisionK} (EX-4.20)`);
  }
  sortie.reussie("OP-3");
}

/** Hauteur hexadécimale d'un nombre. */
const hx = (n) => "0x" + BigInt(n).toString(16);

export async function inscrireClient(ctx) {
  const sortie = new Sortie("inscrire-client", ctx);
  const dossierLu = dossierClient(ctx, sortie);
  const tenue = new TenueDossier(ctx.client.dossier, dossierLu, { horloge: ctx.horloge, completer: completerResult(ctx) });
  const d = tenue.dossier;
  await prealables(ctx, sortie);

  // Clés de l'exploitant et OP-5 : comptes du manifeste, administrateur du registre (EX-3.1).
  const deployeur = cleRole(ctx, sortie, "deployeur");
  const administrateur = cleRole(ctx, sortie, "administrateur");
  const tresorerie = cleRole(ctx, sortie, "tresorerie");
  for (const [role, cle] of [["deployeur", deployeur], ["administrateur", administrateur], ["tresorerie", tresorerie]]) {
    const ecart = ecartCompte(ctx, role, cle.adresse());
    if (ecart) sortie.echec("OP-5", "refuse", "compte_inattendu", ecart);
  }
  const distincts = ecartRolesDistincts(ctx, { deployeur: deployeur.adresse(), administrateur: administrateur.adresse(), tresorerie: tresorerie.adresse() });
  if (distincts) sortie.echec("OP-5", "refuse", "compte_inattendu", distincts);
  const admin = await etat.adminRegistre(ctx);
  if (admin !== administrateur.adresse()) sortie.echec("OP-5", "refuse", "pas_administrateur", `admin() du CuratorSetRegistry ${admin} ≠ administrateur du registre ${administrateur.adresse()}`);
  sortie.reussie("OP-5");

  const orgId = d.organisation.org_id;
  const membres = d.approvers.members;
  const seuil = d.approvers.threshold;
  const setAdmin = d.approvers.set_admin;
  let fait = false;
  const sorties = { curator_set: null, set_deployment: null, assignment: null, set_read: null, funded: [] };

  // Reprise d'une étape envoyée (EX-7.16) : reçu présent, l'étape passe par incluse ; absent, transaction_en_attente.
  const reprendreEnvoyee = async (e, role, contrat, op11, op12, extra = {}) => {
    const recu = await attendreRecu(ctx, e.transaction_hash, 0);
    if (!recu) {
      sortie.arreter("refuse", "transaction_en_attente", "OP-3", `étape ${e.step} (${e.subject}) envoyee : ${e.transaction_hash} sans reçu ; reprendre par le travail capturer (envoi ${e.transaction_hash}, 8.6)`);
    }
    const envoi = R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === e.transaction_hash)?.envoi ?? null;
    return conclure(ctx, sortie, { tenue, etape: e, envoi, transactionHash: e.transaction_hash, recu, role, contrat, op11, op12, ...extra });
  };

  // ------------------------------------------------------------ jeu_approbateurs
  const eJeu = etape(d, "jeu_approbateurs");
  const op11Jeu = (contrat) => (recu) => {
    if ((recu.contractAddress ?? "").toLowerCase() !== contrat) return { ok: false, detail: `contractAddress ${recu.contractAddress} ≠ ${contrat}` };
    const logs = (recu.logs ?? []).filter((l) => l.address.toLowerCase() === contrat);
    const admins = logs.filter((l) => l.topics[0] === J.EVENEMENTS.AdminAccepted).map((l) => J.adresseDeSujet(l.topics[2]));
    const ajoutes = logs.filter((l) => l.topics[0] === J.EVENEMENTS.CuratorAdded).map((l) => J.adresseDeSujet(l.topics[1])).sort();
    const seuils = logs.filter((l) => l.topics[0] === J.EVENEMENTS.ThresholdUpdated).map((l) => J.decoderMot(l.data));
    if (admins.length !== 1 || admins[0] !== setAdmin) return { ok: false, detail: "AdminAccepted absent ou d'un autre administrateur" };
    if (JSON.stringify(ajoutes) !== JSON.stringify(membres)) return { ok: false, detail: "CuratorAdded différents des membres du dossier" };
    if (seuils.length !== 1 || seuils[0] !== BigInt(seuil)) return { ok: false, detail: "ThresholdUpdated absent ou d'un autre seuil" };
    return { ok: true };
  };
  const op12Jeu = (contrat) => async (h) => {
    if ((await etat.seuil(ctx, contrat, h)) !== BigInt(seuil)) return { ok: false, detail: `getThreshold() à ${h} ≠ ${seuil}` };
    if ((await etat.taille(ctx, contrat, h)) !== BigInt(membres.length)) return { ok: false, detail: `getCuratorCount() à ${h} ≠ ${membres.length}` };
    for (const m of membres) if (!(await etat.estMembre(ctx, contrat, m, h))) return { ok: false, detail: `isCurator(${m}) faux à ${h}` };
    if ((await etat.adminJeu(ctx, contrat, h)) !== setAdmin) return { ok: false, detail: `admin() du jeu à ${h} ≠ ${setAdmin}` };
    return { ok: true };
  };
  let set = eJeu.contract ?? null;
  if (eJeu.state === "envoyee") {
    await reprendreEnvoyee(eJeu, "jeu_approbateurs", set, op11Jeu(set), op12Jeu(set), { contratCree: set });
    fait = true;
  } else if (eJeu.state === "incluse") {
    await capturerEtRelire(ctx, sortie, { tenue, etape: eJeu, hash: eJeu.transaction_hash, hauteur: eJeu.block_number, role: "jeu_approbateurs", contrat: set, contratCree: set, envoi: R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === eJeu.transaction_hash)?.envoi ?? null });
    fait = true;
  } else if (eJeu.state === "a_faire" || eJeu.state === "echec") {
    // OP-4 : organisation libre, ou jeu déjà déployé pour ce dossier par cet acteur (reprise, EX-7.16).
    if (await etat.isRegistered(ctx, orgId)) {
      const assigne = await etat.curatorSetOf(ctx, orgId);
      const envoiConnu = R.lireEnvois(ctx.captures).find((x) => x.envoi.from === deployeur.adresse() && x.envoi.to === null && R.adresseCreation(deployeur.adresse(), x.envoi.nonce) === assigne);
      const conforme = envoiConnu && (await etat.adminJeu(ctx, assigne)) === setAdmin && (await etat.seuil(ctx, assigne)) === BigInt(seuil) && (await etat.taille(ctx, assigne)) === BigInt(membres.length);
      if (!conforme) sortie.echec("OP-4", "refuse", "organisation_existante", `l'organisation ${d.organisation.slug} (${orgId}) a déjà un jeu : un slug n'est attribué qu'une fois (EX-6.3)`);
      sortie.reussie("OP-4");
      const recu = await attendreRecu(ctx, envoiConnu.envoi.transaction_hash, 0);
      set = assigne;
      await conclure(ctx, sortie, { tenue, etape: eJeu, envoi: envoiConnu.envoi, recu, role: "jeu_approbateurs", contrat: set, op11: op11Jeu(set), op12: op12Jeu(set), contratCree: set });
    } else {
      sortie.reussie("OP-4");
      await op3(ctx, sortie, { expediteur: deployeur.adresse() });
      let code;
      try {
        code = J.codeCreationCuratorSet(ctx.racine);
      } catch (e) {
        sortie.arreter("inutilisable", "usage", null, `code de création de CuratorSet illisible (${J.ARTEFACT_CURATOR_SET}, npm run compile) : ${String(e.message).slice(0, 200)}`);
      }
      const n = await lireNonce(ctx.rpc, deployeur.adresse());
      set = R.adresseCreation(deployeur.adresse(), n);
      await envoyer(ctx, sortie, {
        tenue, etape: eJeu, cle: deployeur, objet: "deploiement", to: null, donnees: J.donneesDeploiement(code, setAdmin, membres, seuil),
        role: "jeu_approbateurs", contrat: set, contratCree: set, op11: op11Jeu(set), op12: op12Jeu(set),
      });
    }
    fait = true;
  }
  sorties.curator_set = set;
  sorties.set_deployment = referenceTransaction(eJeu);

  // ------------------------------------------------------------ assignation
  const eAss = etape(d, "assignation");
  const op11Ass = (recu) => {
    const j = (recu.logs ?? []).find((l) => l.address.toLowerCase() === ctx.instance.contrats.curator_set_registry && l.topics[0] === J.EVENEMENTS.CuratorSetAssigned);
    if (!j) return { ok: false, detail: "CuratorSetAssigned absent du reçu" };
    if (j.topics[1] !== orgId || J.adresseDeSujet(j.topics[2]) !== set || J.adresseDeSujet(j.topics[3]) !== ZERO20) return { ok: false, detail: "CuratorSetAssigned d'autres valeurs que celles envoyées" };
    return { ok: true };
  };
  const op12Ass = async (h) => ((await etat.curatorSetOf(ctx, orgId, h)) === set ? { ok: true } : { ok: false, detail: `curatorSetOf(${orgId}) à ${h} ≠ ${set}` });
  if (eAss.state === "envoyee") {
    await reprendreEnvoyee(eAss, "assignation", ctx.instance.contrats.curator_set_registry, op11Ass, op12Ass);
    fait = true;
  } else if (eAss.state === "incluse") {
    await capturerEtRelire(ctx, sortie, { tenue, etape: eAss, hash: eAss.transaction_hash, hauteur: eAss.block_number, role: "assignation", contrat: ctx.instance.contrats.curator_set_registry, envoi: R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === eAss.transaction_hash)?.envoi ?? null });
    fait = true;
  } else if (eAss.state === "a_faire" || eAss.state === "echec") {
    const assigne = await etat.curatorSetOf(ctx, orgId);
    if (assigne === set) {
      // Déjà faite par cet acteur : l'envoi est retrouvé dans les captures, puis capturé.
      const envoiConnu = R.lireEnvois(ctx.captures).find((x) => x.envoi.from === administrateur.adresse() && x.envoi.to === ctx.instance.contrats.curator_set_registry && x.envoi.raw_transaction.includes(J.encoderSetCuratorSet(orgId, set).slice(2)));
      const recu = envoiConnu ? await attendreRecu(ctx, envoiConnu.envoi.transaction_hash, 0) : null;
      if (!recu) sortie.echec("OP-4", "refuse", "organisation_existante", `l'organisation ${orgId} est déjà assignée à ${set} sans envoi connu dans les captures`);
      await conclure(ctx, sortie, { tenue, etape: eAss, envoi: envoiConnu.envoi, recu, role: "assignation", contrat: ctx.instance.contrats.curator_set_registry, op11: op11Ass, op12: op12Ass });
    } else if (assigne !== ZERO20) {
      sortie.echec("OP-4", "refuse", "organisation_existante", `l'organisation ${orgId} est assignée à un autre jeu ${assigne}`);
    } else {
      await op3(ctx, sortie, { expediteur: administrateur.adresse() });
      await envoyer(ctx, sortie, {
        tenue, etape: eAss, cle: administrateur, objet: "appel", to: ctx.instance.contrats.curator_set_registry, donnees: J.encoderSetCuratorSet(orgId, set),
        role: "assignation", contrat: ctx.instance.contrats.curator_set_registry, op11: op11Ass, op12: op12Ass,
      });
    }
    fait = true;
  }
  sorties.assignment = referenceTransaction(eAss);

  // ------------------------------------------------------------ lecture_jeu
  const eLec = etape(d, "lecture_jeu");
  if (eLec.state !== "faite") {
    // La lecture se fait à une hauteur au moins égale au bloc d'assignation (7.6) : le point lu l'a décidé.
    if (eAss.block_number !== null) await attendreHauteur(ctx, eAss.block_number);
    const lecteur = new LecteurJeu({
      url: ctx.rpc.points()[0], timeout_ms: 10000, org_id: orgId, depuis_bloc: eJeu.block_number ?? 0,
      adressesConnues: () => membres,
      appel: async (methode, params) => {
        const r = await ctx.rpc.appelerPremier(methode, params);
        if (r.erreur) throw new Error(`${r.erreur.code} ${r.erreur.message}`);
        return r.resultat;
      },
    });
    const l = await lecteur.lire({ chain_id: ctx.instance.evmChainId, registry: ctx.instance.contrats.curator_set_registry, set });
    if (l.status !== "lu") sortie.arreter("refuse", "jeu_invalide", null, `lecture du jeu (CT-3 EX-8.1) : ${l.cause}`);
    if (l.jeu.height < (eAss.block_number ?? 0)) sortie.arreter("refuse", "jeu_invalide", null, `lecture du jeu à ${l.jeu.height}, avant l'assignation ${eAss.block_number}`);
    const setRead = { height: l.jeu.height, block_hash: l.jeu.block_hash, threshold: l.jeu.threshold.required, size: l.jeu.threshold.size, members: l.jeu.members };
    ecrireAtomique(ctx.client.lectureJeu, serialiser(setRead));
    await tenue.passer(eLec, { state: "faite", transaction_hash: null, block_number: setRead.height, block_hash: setRead.block_hash, capture: null, error: null });
    sorties.set_read = setRead;
    fait = true;
  } else {
    sorties.set_read = await lectureJeuA(ctx, d, set, eLec);
  }

  // ------------------------------------------------------------ approvisionnement
  const budget = BigInt(d.funding.daily_budget_gas);
  const pK = provision(ctx.instance.fees, budget);
  for (const r of d.recorders) {
    const e = etape(d, "approvisionnement", r.chain_key);
    const op11Ap = (recu) => ((recu.logs ?? []).length === 0 ? { ok: true } : { ok: false, detail: "journal inattendu dans le reçu d'un approvisionnement" });
    const op12Ap = async (h) => {
      const res = await ctx.rpc.appelerPremier("eth_getBalance", [r.chain_key, h]);
      const b = res.erreur ? null : R.quantiteVersEntier(res.resultat, (1n << 256n) - 1n);
      return b !== null && b >= pK ? { ok: true } : { ok: false, detail: `solde de ${r.chain_key} à ${h} sous la provision` };
    };
    if (e.state === "capturee" || e.state === "faite") {
      sorties.funded.push({ chain_key: r.chain_key, transaction_hash: e.transaction_hash, deja_fait: true });
      continue;
    }
    if (e.state === "envoyee") {
      const res = await reprendreEnvoyee(e, "approvisionnement", null, op11Ap, op12Ap);
      sorties.funded.push({ chain_key: r.chain_key, transaction_hash: res.transactionHash, amount_wei: BigInt(res.envoi?.value ?? "0").toString() });
      fait = true;
      continue;
    }
    if (e.state === "incluse") {
      const envoi = R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === e.transaction_hash)?.envoi ?? null;
      await capturerEtRelire(ctx, sortie, { tenue, etape: e, hash: e.transaction_hash, hauteur: e.block_number, role: "approvisionnement", contrat: null, envoi });
      sorties.funded.push({ chain_key: r.chain_key, transaction_hash: e.transaction_hash, amount_wei: BigInt(envoi?.value ?? "0").toString() });
      fait = true;
      continue;
    }
    const s = await solde(ctx.rpc, r.chain_key);
    if (s >= pK) {
      await tenue.passer(e, { state: "faite", transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null });
      sorties.funded.push({ chain_key: r.chain_key, transaction_hash: null, deja_fait: true });
      fait = true;
      continue;
    }
    const value = pK - s;
    await op3(ctx, sortie, { expediteur: tresorerie.adresse(), value, destinataire: r.chain_key, provisionK: pK });
    consommerConfirmation(ctx, { operations: ["approvisionnement"], orgId, cleChaine: r.chain_key });
    const res = await envoyer(ctx, sortie, {
      tenue, etape: e, cle: tresorerie, objet: "approvisionnement", to: r.chain_key, value, provision: pK,
      role: "approvisionnement", contrat: null, op11: op11Ap, op12: op12Ap,
    });
    sorties.funded.push({ chain_key: r.chain_key, transaction_hash: res.transactionHash, amount_wei: value.toString() });
    fait = true;
  }
  return sortie.rendre(fait ? "reussi" : "deja_fait", { outputs: sorties });
}

export { hx, lecture };
