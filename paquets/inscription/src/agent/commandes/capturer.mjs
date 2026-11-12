// Reprise par la capture (CT-4 §8.6, EX-7.13, EX-7.16) : `envoi` (un envoi
// de l'agent dont l'issue n'est pas connue : attente du reçu, sans nouvelle
// soumission, puis issue, OP-11, capture, OP-12) ou `transaction` (une
// transaction incluse : OP-11 et capture). Le rôle et le contrat se lisent
// dans l'étape du dossier qui porte ce hachage, sinon se déduisent de la
// transaction signée comme le fait `capturer --envoi` (EX-8.16). Avec le
// dossier du client, l'étape passe à `capturee`.
//
// Reprise d'EX-7.29 (révision 0.7) : une `transaction` qu'aucune étape ne
// porte, et dont le reçu montre l'effet d'une étape `echec` du dossier avec
// ses valeurs (événement émis par le contrat de cette étape, OP-11), est la
// transaction qui a accompli l'étape : après la capture (CP-1 à CP-6) et
// OP-12 sur ces valeurs, l'étape passe à `capturee` avec ce
// `transaction_hash`, son bloc et sa capture. C'est le seul passage
// d'`echec` à `capturee`. Une transaction qui n'accomplit aucune étape `echec`
// se capture sans changer le dossier.

import fs from "node:fs";
import path from "node:path";
import * as R from "@noortrace/ancrage/registre";
import { lireJsonStrict } from "@noortrace/approbation";
import { octetsVersHex } from "@noortrace/noyau";
import { Sortie } from "../sortie.mjs";
import { TenueDossier } from "../dossier.mjs";
import { attendreRecu, capturerEtRelire, conclure } from "../envoi.mjs";
import * as J from "../jeu.mjs";
import { dossierClient, prealables } from "./base.mjs";
import { completerResult, roleDeEtape } from "./inscrire-client.mjs";

/** Rôle et contrat d'une transaction signée et de son reçu (EX-8.16). */
function deduire(ctx, tx, recu) {
  const sel = octetsVersHex(tx.data.subarray(0, 4));
  if (tx.to === null) {
    let code = null;
    try {
      code = J.codeCreationCuratorSet(ctx.racine);
    } catch {
      code = null;
    }
    const role = code && octetsVersHex(tx.data).startsWith(code) ? "jeu_approbateurs" : "deploiement";
    return { role, contrat: (recu?.contractAddress ?? "").toLowerCase() || null };
  }
  if (tx.data.length === 0) return { role: "approvisionnement", contrat: null };
  const c = ctx.instance.contrats;
  const parSelecteur = {
    [R.SELECTEURS.registerRecorder]: "inscription", [R.SELECTEURS.revokeRecorder]: "revocation", [R.SELECTEURS.anchor]: "ancre", [R.SELECTEURS.submitPeriod]: "cloture",
    "0xd3dc8837": "administration_jeu", "0xa7484439": "administration_jeu", "0xf4db2a99": "administration_jeu", "0x34e182a6": "administration_jeu", "0x7af25fd9": "administration_jeu",
  };
  if (sel === J.SELECTEURS.setCuratorSet && tx.to === c.curator_set_registry) {
    const j = (recu?.logs ?? []).find((l) => l.topics?.[0] === J.EVENEMENTS.CuratorSetAssigned);
    return { role: j && !/^0x0{64}$/.test(j.topics[3]) ? "reassignation" : "assignation", contrat: tx.to };
  }
  if (parSelecteur[sel]) return { role: parSelecteur[sel], contrat: tx.to };
  return null;
}

/** OP-11 générique : `status` 0x1 et, pour un rôle à événement, l'événement émis par le contrat. */
function op11Generique(role, contrat) {
  return (recu) => {
    const evenement = R.EVENEMENT_PAR_ROLE[role];
    if (!evenement) {
      if (role === "approvisionnement" && (recu.logs ?? []).length > 0) return { ok: false, detail: "journal inattendu dans le reçu d'un approvisionnement" };
      if (role === "jeu_approbateurs" && !(recu.logs ?? []).some((l) => l.topics?.[0] === J.EVENEMENTS.AdminAccepted && l.address.toLowerCase() === contrat)) return { ok: false, detail: "AdminAccepted absent du reçu du déploiement" };
      return { ok: true };
    }
    const sujet = R.SUJETS[evenement];
    return (recu.logs ?? []).some((l) => l.address.toLowerCase() === contrat && l.topics?.[0] === sujet) ? { ok: true } : { ok: false, detail: `${evenement} absent du reçu` };
  };
}

/**
 * Étape `echec` du dossier qu'accomplit une transaction de rôle `role`, d'après
 * l'événement que son reçu porte et les valeurs de l'étape (EX-7.29) ; rend
 * `{ etape, contrat }` ou null. L'approvisionnement n'a pas d'événement : sa
 * reprise est celle d'`inscrire-client` (solde au moins `P_k`, étape `faite`).
 */
export function etapeEchecAccomplie(ctx, d, role, recu) {
  const c = ctx.instance.contrats;
  const orgId = d.organisation.org_id;
  const logs = (recu?.logs ?? []).map((l) => ({ address: String(l.address).toLowerCase(), topics: l.topics ?? [], data: l.data ?? "0x" }));
  const de = (adresse) => logs.filter((l) => l.address === adresse);
  for (const e of d.steps) {
    if (e.state !== "echec" || roleDeEtape(e.step) !== role) continue;
    if (role === "inscription") {
      const r = d.recorders.find((x) => x.key_id === e.subject);
      if (!r) continue;
      const ok = de(c.recorder_registry).some((l) => {
        const j = R.decoderJournal("inscription", l);
        return j && j.orgId === orgId && j.chainKey === r.chain_key && j.journalId === r.journal_id && j.ed25519PubKey === r.public_key;
      });
      if (ok) return { etape: e, contrat: c.recorder_registry };
    } else if (role === "jeu_approbateurs") {
      const contrat = String(recu?.contractAddress ?? "").toLowerCase();
      if (!/^0x[0-9a-f]{40}$/.test(contrat)) continue;
      const l = de(contrat);
      const admins = l.filter((x) => x.topics[0] === J.EVENEMENTS.AdminAccepted).map((x) => J.adresseDeSujet(x.topics[2]));
      const ajoutes = l.filter((x) => x.topics[0] === J.EVENEMENTS.CuratorAdded).map((x) => J.adresseDeSujet(x.topics[1])).sort();
      const seuils = l.filter((x) => x.topics[0] === J.EVENEMENTS.ThresholdUpdated).map((x) => J.decoderMot(x.data));
      if (admins.length === 1 && admins[0] === d.approvers.set_admin && JSON.stringify(ajoutes) === JSON.stringify([...d.approvers.members].sort()) && seuils.length === 1 && seuils[0] === BigInt(d.approvers.threshold)) {
        return { etape: e, contrat };
      }
    } else if (role === "assignation") {
      const set = d.steps.find((x) => x.step === "jeu_approbateurs")?.contract ?? null;
      const ok = set && de(c.curator_set_registry).some((x) => x.topics[0] === J.EVENEMENTS.CuratorSetAssigned && x.topics[1] === orgId && J.adresseDeSujet(x.topics[2]) === set && /^0x0{64}$/.test(x.topics[3] ?? ""));
      if (ok) return { etape: e, contrat: c.curator_set_registry };
    } else if (role === "ancre") {
      const empreintes = d.journals.map((j) => R.empreinteAncre(orgId, j.journal_id, e.subject).fingerprint).filter(Boolean);
      const cles = d.recorders.map((r) => r.chain_key);
      const ok = de(c.attestation_registry).some((l) => {
        const j = R.decoderJournal("ancre", l);
        return j && empreintes.includes(j.fingerprint) && cles.includes(j.issuer);
      });
      if (ok) return { etape: e, contrat: c.attestation_registry };
    } else if (role === "cloture") {
      const ok = de(c.period_registry).some((l) => {
        const j = R.decoderJournal("cloture", l);
        return j && j.orgId === orgId && j.periodHash === e.subject;
      });
      if (ok) return { etape: e, contrat: c.period_registry };
    }
  }
  return null;
}

/** OP-12 déclarative selon le rôle (relecture à la hauteur du bloc, CT-4 §7.3). */
function op12Generique(ctx, role, contrat, recu, to) {
  const etat = (h) => async (lecture) => lecture(h);
  return async (h) => {
    const logs = (recu.logs ?? []).filter((l) => contrat && l.address.toLowerCase() === contrat);
    const c = ctx.instance.contrats;
    if (role === "inscription") {
      const l = logs.find((x) => x.topics[0] === R.SUJETS.RecorderRegistered);
      const j = l ? R.decoderJournal("inscription", { address: l.address.toLowerCase(), topics: l.topics, data: l.data }) : null;
      const actif = j ? await R.isActiveRecorder({ rpc: ctx.rpc, contrat: c.recorder_registry, orgId: j.orgId, chainKey: j.chainKey, hauteur: h }) : false;
      return actif ? { ok: true } : { ok: false, detail: `isActiveRecorder faux à ${h}` };
    }
    if (role === "assignation" || role === "reassignation") {
      const l = logs.find((x) => x.topics[0] === J.EVENEMENTS.CuratorSetAssigned);
      if (!l) return { ok: false, detail: "CuratorSetAssigned absent" };
      const lu = J.decoderAdresse(await R.appelLecture(ctx.rpc, c.curator_set_registry, Uint8Array.from(Buffer.from(J.encoderCuratorSetOf(l.topics[1]).slice(2), "hex")), { hauteur: h }));
      return lu === J.adresseDeSujet(l.topics[2]) ? { ok: true } : { ok: false, detail: `curatorSetOf à ${h} ≠ ${J.adresseDeSujet(l.topics[2])}` };
    }
    if (role === "jeu_approbateurs") {
      const n = J.decoderMot(await R.appelLecture(ctx.rpc, contrat, Uint8Array.from(Buffer.from(J.encoderGetCuratorCount().slice(2), "hex")), { hauteur: h }));
      return n !== null && n > 0n ? { ok: true } : { ok: false, detail: `getCuratorCount() nul à ${h}` };
    }
    if (role === "approvisionnement") {
      const r = await ctx.rpc.appelerPremier("eth_getBalance", [to, h]);
      const b = r.erreur ? null : R.quantiteVersEntier(r.resultat, (1n << 256n) - 1n);
      return b !== null && b > 0n ? { ok: true } : { ok: false, detail: `solde nul de ${to} à ${h}` };
    }
    if (role === "ancre") {
      const l = logs.find((x) => x.topics[0] === R.SUJETS.Anchored);
      const lu = l ? await R.lookup({ rpc: ctx.rpc, contrat: c.attestation_registry, fingerprint: l.topics[1], hauteur: h }) : null;
      return lu && lu.issuer === J.adresseDeSujet(l.topics[2]) ? { ok: true } : { ok: false, detail: `lookup différent à ${h}` };
    }
    if (role === "cloture") {
      const l = logs.find((x) => x.topics[0] === R.SUJETS.PeriodSubmitted);
      const j = l ? R.decoderJournal("cloture", { address: l.address.toLowerCase(), topics: l.topics, data: l.data }) : null;
      const connu = j ? await R.isKnown({ rpc: ctx.rpc, contrat: c.period_registry, orgId: j.orgId, periodHash: j.periodHash, hauteur: h }) : false;
      return connu ? { ok: true } : { ok: false, detail: `isKnown faux à ${h}` };
    }
    void etat;
    return { ok: true };
  };
}

export async function capturer(ctx, travail) {
  const sortie = new Sortie("capturer", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const tenue = new TenueDossier(ctx.client.dossier, d, { horloge: ctx.horloge, completer: completerResult(ctx) });
  const hash = p.envoi ?? p.transaction;
  let envoi = null;
  if (p.envoi) {
    const chemin = path.join(ctx.captures, R.nomEnvoi(hash));
    try {
      envoi = lireJsonStrict(fs.readFileSync(chemin));
    } catch {
      sortie.arreter("inutilisable", "entree_illisible", null, `envoi ${R.nomEnvoi(hash)} illisible ou absent des captures du client`);
    }
    if (!R.verifierEnvoi(envoi).valide || envoi.transaction_hash !== hash) sortie.arreter("inutilisable", "entree_illisible", null, "envoi non conforme à #/$defs/envoi");
  }
  await prealables(ctx, sortie);
  let etapeDossier = d.steps.find((e) => e.transaction_hash === hash) ?? null;
  const recu = await attendreRecu(ctx, hash, p.envoi ? ctx.delaiMs : 0);
  if (!recu) {
    sortie.arreter("incertain", "recu_absent", null, `aucun reçu pour ${hash}${p.envoi ? ` en ${Math.round(ctx.delaiMs / 1000)} s` : ""} (8.6)`, p.envoi ? { envoi: R.nomEnvoi(hash), transaction_hash: hash } : { transaction_hash: hash });
  }
  let role = etapeDossier ? roleDeEtape(etapeDossier.step) : null;
  let contrat = null;
  const lue = envoi ? R.lireTransaction(envoi.raw_transaction) : null;
  const t = lue ?? (await ctx.rpc.appelerPremier("eth_getTransactionByHash", [hash]).then((r) => (r.erreur || !r.resultat ? null : { to: r.resultat.to ? r.resultat.to.toLowerCase() : null, data: Uint8Array.from(Buffer.from(String(r.resultat.input).slice(2), "hex")) })));
  const deduit = t ? deduire(ctx, t, recu.resultat) : null;
  if (!role && deduit) role = deduit.role;
  if (deduit) contrat = deduit.contrat;
  if (role === "jeu_approbateurs") contrat = etapeDossier?.contract ?? contrat;
  if (!role) sortie.arreter("inutilisable", "usage", null, "rôle de la transaction indéterminé (sélecteur non reconnu, aucune étape du dossier)");
  // EX-7.29 : transaction qu'aucune étape ne porte, qui accomplit une étape `echec` avec ses valeurs.
  let reprise = null;
  if (!etapeDossier && p.transaction && recu.resultat.status === "0x1") {
    reprise = etapeEchecAccomplie(ctx, d, role, recu.resultat);
    if (reprise) {
      etapeDossier = reprise.etape;
      contrat = reprise.contrat;
    }
  }
  const op11 = op11Generique(role, contrat);
  const vue = (e) => (e ? { step: e.step, subject: e.subject, state: e.state } : null);
  if (p.envoi) {
    const res = await conclure(ctx, sortie, { tenue, etape: etapeDossier, envoi, recu, role, contrat, op11, op12: op12Generique(ctx, role, contrat, recu.resultat, envoi.to), contratCree: role === "jeu_approbateurs" ? contrat : null });
    return sortie.rendre("reussi", { outputs: { transaction_hash: res.transactionHash, block_number: res.blockNumber, block_hash: res.blockHash, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture, retention: res.retention, dossier: vue(etapeDossier) } });
  }
  // `transaction` : OP-11 sur le reçu, puis capture (CP-1 à CP-6).
  const v = recu.resultat.status === "0x1" ? op11(recu.resultat) : { ok: false, detail: `reçu à status ${recu.resultat.status}` };
  if (!v.ok) sortie.echec("OP-11", "echoue", "transaction_annulee", v.detail);
  sortie.reussie("OP-11");
  const c = await R.capturer({
    rpc: ctx.rpc, transactionHash: hash, role, contrat, horloge: ctx.horloge, repertoire: ctx.captures,
    instance: { evmChainId: ctx.instance.evmChainId, bftChainId: ctx.instance.bftChainId, jeux: ctx.instance.jeux }, attendre: ctx.attendre,
    sending: R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === hash)?.envoi ?? null, point: recu.point, recu,
  });
  for (const ch of c.checks ?? []) sortie.noter(ch.id, ch.status, ch.detail);
  if (c.erreur) sortie.arreter(c.erreur.code === "inutilisable" ? "inutilisable" : "incertain", c.erreur.code === "inutilisable" ? "certificat_indisponible" : c.erreur.code, c.erreur.check ?? null, c.erreur.message || c.erreur.code, { transaction_hash: hash });
  if (reprise) {
    // OP-12 sur les valeurs de l'étape, à la hauteur du bloc capturé, avant le passage à capturee (EX-7.29).
    const to = t?.to ?? null;
    const v12 = await op12Generique(ctx, role, contrat, recu.resultat, to)("0x" + BigInt(c.index.block_number).toString(16));
    if (!v12.ok) sortie.echec("OP-12", "echoue", "transaction_annulee", v12.detail, { transaction_hash: hash, block_number: c.index.block_number });
    sortie.reussie("OP-12");
  }
  if (etapeDossier && etapeDossier.state !== "capturee") {
    await tenue.passer(etapeDossier, { state: "capturee", transaction_hash: hash, block_number: c.index.block_number, block_hash: c.index.block_hash, capture: c.nom, error: null, ...(role === "jeu_approbateurs" && contrat ? { contract: contrat } : {}) });
  }
  const { retention } = await import("../envoi.mjs");
  return sortie.rendre("reussi", { outputs: { capture: c.nom, transaction_hash: hash, block_number: c.index.block_number, block_hash: c.index.block_hash, sha256: c.sha256, retention: await retention(ctx, ctx.captures, c.index), dossier: vue(etapeDossier) } });
}

export { capturerEtRelire };
