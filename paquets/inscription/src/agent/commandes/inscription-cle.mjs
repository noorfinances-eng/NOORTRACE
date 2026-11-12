// Pas 6 (CT-4 §7.7) : `condense inscription` prépare la demande de
// signature `demande_signature` de l'inscription d'une clé du dossier, que
// l'exploitant remet aux approbateurs hors de l'application (EX-7.27) ;
// `inscrire-cle` relaie la demande signée qu'on lui rend, après OP-6 et
// OP-7, par `RecorderRegistry.registerRecorder` (EX-7.24). Aucune page ne
// fait signer un condensé : l'application ne signe jamais `registerDigest`.

import fs from "node:fs";
import path from "node:path";
import { lireJsonStrict } from "@noortrace/approbation";
import { ecrireHorodatage, octetsVersHex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { Sortie } from "../sortie.mjs";
import { TenueDossier, etape } from "../dossier.mjs";
import { attendreRecu, capturerEtRelire, conclure, envoyer } from "../envoi.mjs";
import { lecture, solde, tete } from "../reseau.mjs";
import { ecrireNouveau, serialiser } from "../donnees.mjs";
import { cleRole, dossierClient, ecartCompte, etat, prealables, ZERO20 } from "./base.mjs";
import { completerResult } from "./inscrire-client.mjs";

const mot = (hex) => hex.replace(/^0x/, "").padStart(64, "0");
const ZERO32 = "0x" + "00".repeat(32);

/** `registerDigest` rendu par le contrat (EX-6.1, OP-6). */
async function registerDigestContrat(ctx, f) {
  const donnees = "0xeeaa91a2" + mot(f.org_id) + mot(f.journal_id) + mot(f.chain_key) + mot(f.ed25519_public_key);
  return R.decoderBytes32(await lecture(ctx.rpc, ctx.instance.contrats.recorder_registry, donnees));
}

/** Bloc de tête `{ height, block_hash }`. */
async function blocTete(ctx) {
  const h = await tete(ctx.rpc);
  const b = await ctx.rpc.appelerPremier("eth_getBlockByNumber", ["0x" + h.toString(16), false]);
  if (b.erreur || typeof b.resultat?.hash !== "string") throw new R.ErreurLecture("retour_illisible", "eth_getBlockByNumber illisible");
  return { height: Number(h), block_hash: b.resultat.hash.toLowerCase() };
}

export async function condenseInscription(ctx, travail) {
  const sortie = new Sortie("condense", ctx);
  const d = dossierClient(ctx, sortie);
  const r = d.recorders.find((x) => x.key_id === travail.parametres.key_id);
  if (!r) sortie.arreter("inutilisable", "usage", null, `clé ${travail.parametres.key_id} absente du dossier`);
  await prealables(ctx, sortie);
  const orgId = d.organisation.org_id;
  const fields = { org_id: orgId, journal_id: r.journal_id, chain_key: r.chain_key, ed25519_public_key: r.public_key };
  const contrat = ctx.instance.contrats.recorder_registry;
  const digest = R.registerDigest(ctx.instance.evmChainId, contrat, fields.org_id, fields.journal_id, fields.chain_key, fields.ed25519_public_key);
  const duContrat = await registerDigestContrat(ctx, fields);
  if (duContrat !== digest) sortie.echec("OP-6", "refuse", "condense_different", `registerDigest du contrat ${duContrat} ≠ condensé recalculé ${digest}`);
  sortie.reussie("OP-6");
  // OP-8, partie « organisation enregistrée » : précède la lecture du jeu et du seuil (signer_set) ; elle n'est pas
  // consignée parmi les vérifications de `condense`, comme le fait l'outil de référence (LISEZMOI.md, « Écarts »).
  const set = await etat.curatorSetOf(ctx, orgId);
  if (set === ZERO20) sortie.arreter("refuse", "organisation_inconnue", "OP-8", `l'organisation ${orgId} n'a pas de jeu (curatorSetOf nul)`);
  const bloc = await blocTete(ctx);
  const t = await etat.seuil(ctx, set, "0x" + bloc.height.toString(16));
  const demande = {
    version: 0,
    operation: "inscription",
    evm_chain_id: ctx.instance.evmChainId,
    contract: contrat,
    fields,
    digest,
    eip191_digest: octetsVersHex(R.hachageSigne(digest)),
    signer_set: { curator_set: set, threshold: Number(t), height: bloc.height, block_hash: bloc.block_hash },
    signatures: [],
    prepared_at: ecrireHorodatage(ctx.horloge.murale()),
  };
  const v = R.verifierDemandeSchema(demande);
  if (!v.valide) throw new Error(`demande hors schéma : ${v.erreurs.join(" ; ")}`);
  const chemin = path.join(ctx.client.demandes, `demande-inscription-${r.key_id}-${ctx.travailId}.json`);
  ecrireNouveau(chemin, serialiser(demande));
  return sortie.rendre("reussi", { outputs: { operation: "inscription", digest, eip191_digest: demande.eip191_digest, signer_set: demande.signer_set, expires_at: null, demande: chemin } });
}

/** OP-12 de l'inscription : `isActiveRecorder` et `recorderByPubKey` relus à la hauteur du bloc. */
function relectureInscription(ctx, f) {
  const contrat = ctx.instance.contrats.recorder_registry;
  return async (h) => {
    const actif = await R.isActiveRecorder({ rpc: ctx.rpc, contrat, orgId: f.org_id, chainKey: f.chain_key, hauteur: h });
    const pk = await R.recorderByPubKey({ rpc: ctx.rpc, contrat, orgId: f.org_id, clePublique: f.ed25519_public_key, hauteur: h });
    return actif && pk.chainKey === f.chain_key ? { ok: true } : { ok: false, detail: `relecture à ${h} : isActiveRecorder ${actif}, recorderByPubKey ${pk.chainKey}` };
  };
}

/** RecorderRegistered de l'inscription (OP-11) : `{ ok, detail }`. */
function op11Inscription(ctx, f) {
  return (recu) => {
    for (const l of recu.logs ?? []) {
      if (l.address.toLowerCase() !== ctx.instance.contrats.recorder_registry || l.topics[0] !== R.SUJETS.RecorderRegistered) continue;
      const j = R.decoderJournal("inscription", { address: l.address.toLowerCase(), topics: l.topics, data: l.data });
      if (j && j.orgId === f.org_id && j.chainKey === f.chain_key && j.journalId === f.journal_id && j.ed25519PubKey === f.ed25519_public_key) return { ok: true };
    }
    return { ok: false, detail: "RecorderRegistered absent du reçu ou d'autres valeurs que celles envoyées" };
  };
}

export async function inscrireCle(ctx, travail) {
  const sortie = new Sortie("inscrire-cle", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const tenue = new TenueDossier(ctx.client.dossier, d, { horloge: ctx.horloge, completer: completerResult(ctx) });
  const demande = p.demande;
  const sch = R.verifierDemandeSchema(demande);
  if (!sch.valide || demande.operation !== "inscription") sortie.echec("OP-6", "inutilisable", "entree_illisible", `demande hors du schéma demande_signature d'une inscription : ${sch.erreurs?.[0] ?? "opération"}`);
  const f = demande.fields;
  const r = d.recorders.find((x) => x.chain_key === f.chain_key && x.public_key === f.ed25519_public_key && x.journal_id === f.journal_id);
  if (!r || f.org_id !== d.organisation.org_id) sortie.arreter("inutilisable", "usage", null, "la demande ne porte sur aucune clé de ce dossier");
  const e = etape(d, "inscription", r.key_id);
  await prealables(ctx, sortie);
  const expediteur = p.relayeur ? cleRole(ctx, sortie, "relayeur") : cleRole(ctx, sortie, "cle_chaine", p.cle_chaine, { option: "cle_chaine" });
  if (p.relayeur) {
    const ecart = ecartCompte(ctx, "relayeur", expediteur.adresse());
    if (ecart) sortie.echec("OP-5", "refuse", "compte_inattendu", ecart);
    sortie.reussie("OP-5");
  } else if (expediteur.adresse() !== f.chain_key) {
    sortie.arreter("refuse", "compte_inattendu", null, `la clé de chaîne désignée ${expediteur.adresse()} n'est pas celle de la demande ${f.chain_key}`);
  }
  // OP-6 : condensé recalculé, égal à celui de la demande et du contrat ; hachage signé.
  const contrat = ctx.instance.contrats.recorder_registry;
  if (demande.contract !== contrat || demande.evm_chain_id !== ctx.instance.evmChainId) sortie.echec("OP-6", "refuse", "condense_different", "demande pour un autre contrat ou une autre chaîne");
  const pre = R.verifierDemande(demande, { complete: false });
  if (pre.resultat !== "valide" && pre.check === "OP-6") sortie.echec("OP-6", "refuse", pre.code === "entree_illisible" ? "condense_different" : pre.code, "condensé de la demande différent du condensé recalculé (OP-6)");
  const duContrat = await registerDigestContrat(ctx, f);
  if (duContrat !== demande.digest) sortie.echec("OP-6", "refuse", "condense_different", `registerDigest du contrat ${duContrat} ≠ condensé de la demande`);
  sortie.reussie("OP-6");
  // Reprise d'EX-7.16 : une étape `envoyee` se reprend par son reçu (absent : transaction_en_attente, jamais un nouvel
  // envoi), une étape `incluse` par la capture de la transaction connue.
  if (e && e.state === "envoyee") {
    const recu = await attendreRecu(ctx, e.transaction_hash, 0);
    if (!recu) sortie.arreter("refuse", "transaction_en_attente", "OP-3", `étape inscription (${e.subject}) envoyee : ${e.transaction_hash} sans reçu ; reprendre par le travail capturer (envoi ${e.transaction_hash}, 8.6)`);
    const envoi = R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === e.transaction_hash)?.envoi ?? null;
    const res = await conclure(ctx, sortie, { tenue, etape: e, envoi, transactionHash: e.transaction_hash, recu, role: "inscription", contrat, op11: op11Inscription(ctx, f), op12: relectureInscription(ctx, f) });
    return sortie.rendre("reussi", { outputs: { transaction_hash: res.transactionHash, block_number: res.blockNumber, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture, is_active_recorder: true, retention: res.retention } });
  }
  if (e && e.state === "incluse") {
    const envoi = R.lireEnvois(ctx.captures).find((x) => x.envoi.transaction_hash === e.transaction_hash)?.envoi ?? null;
    const res = await capturerEtRelire(ctx, sortie, { tenue, etape: e, hash: e.transaction_hash, hauteur: e.block_number, role: "inscription", contrat, envoi });
    return sortie.rendre("reussi", { outputs: { transaction_hash: res.transactionHash, block_number: res.blockNumber, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture, is_active_recorder: true, retention: res.retention } });
  }
  // OP-8, organisation enregistrée.
  const set = await etat.curatorSetOf(ctx, f.org_id);
  if (set === ZERO20) sortie.echec("OP-8", "refuse", "organisation_inconnue", `l'organisation ${f.org_id} n'a pas de jeu`);
  // Reprise (EX-7.13) : clé active sous le même journal et la même clé Ed25519, dossier ou non.
  const rec = await R.recorderOf({ rpc: ctx.rpc, contrat, orgId: f.org_id, chainKey: f.chain_key });
  if (rec.registeredAt !== 0n && rec.revokedAt === 0n && rec.journalId === f.journal_id && rec.ed25519PubKey === f.ed25519_public_key) {
    // Les valeurs rendues sont celles de l'étape du dossier, qui n'est pas modifiée (même conduite que l'outil de
    // référence ; une étape `echec` dont l'inscription a été incluse par un autre reste `echec` : LISEZMOI.md, « Questions »).
    return sortie.rendre("deja_fait", { outputs: { transaction_hash: e?.transaction_hash ?? null, block_number: e?.block_number ?? null, capture: e?.capture ?? null, is_active_recorder: true, registered_at: rec.registeredAt.toString() } });
  }
  sortie.reussie("OP-8");
  // OP-7 : signatures canoniques, membres du jeu à latest, au seuil, rangées ; la transaction en joint exactement t.
  const t = await etat.seuil(ctx, set);
  const membres = [];
  for (const s of demande.signatures) if (await etat.estMembre(ctx, set, s.signer)) membres.push(s.signer);
  const v = R.verifierDemande(demande, { membres, complete: false });
  if (v.resultat !== "valide") sortie.echec("OP-7", "refuse", v.code, `signatures de la demande : ${v.code}`);
  if (BigInt(v.signers.length) < t) sortie.echec("OP-7", "refuse", "signatures_insuffisantes", `${v.signers.length} signature(s) pour un seuil de ${t}`);
  sortie.reussie("OP-7");
  const signatures = demande.signatures.slice(0, Number(t)).map((s) => ({ v: s.v, r: s.r, s: s.s }));
  // OP-8, clés : clé de chaîne jamais inscrite, clé Ed25519 active sous aucune autre clé de chaîne.
  if (rec.registeredAt !== 0n) {
    if (rec.revokedAt !== 0n) sortie.echec("OP-8", "refuse", "cle_revoquee", `clé de chaîne ${f.chain_key} révoquée : jamais réinscrite (EX-8.8)`);
    sortie.echec("OP-8", "refuse", "cle_deja_active", `clé de chaîne ${f.chain_key} déjà inscrite sous un autre journal ou une autre clé Ed25519`);
  }
  const parCle = await R.recorderByPubKey({ rpc: ctx.rpc, contrat, orgId: f.org_id, clePublique: f.ed25519_public_key });
  if (parCle.chainKey !== ZERO20 && parCle.revokedAt === 0n) sortie.echec("OP-8", "refuse", "cle_ed25519_active", `clé Ed25519 active sous la clé de chaîne ${parCle.chainKey}`);
  sortie.reussie("OP-8");
  // OP-3 et envoi.
  const enAttente = R.envoisSansIssue(ctx.captures, expediteur.adresse());
  if (enAttente.length > 0) sortie.echec("OP-3", "refuse", "transaction_en_attente", `envoi ${enAttente[0].transaction_hash} de ${expediteur.adresse()} sans issue connue`);
  const s = await solde(ctx.rpc, expediteur.adresse());
  if (s < BigInt(ctx.instance.fees.gas_limit)) sortie.echec("OP-3", "refuse", "solde_insuffisant", `solde de ${expediteur.adresse()} : ${s} wei < ${ctx.instance.fees.gas_limit} wei (EX-4.18)`);
  sortie.reussie("OP-3");
  ecrireNouveau(path.join(ctx.client.demandes, `demande-inscription-relayee-${r.key_id}-${ctx.travailId}.json`), serialiser(demande));
  const donnees = octetsVersHex(R.encoderRegisterRecorder({ ...f, signatures }));
  const res = await envoyer(ctx, sortie, {
    tenue, etape: e, cle: expediteur, objet: "appel", to: contrat, donnees, role: "inscription", contrat,
    op11: op11Inscription(ctx, f),
    op12: relectureInscription(ctx, f),
  });
  return sortie.rendre("reussi", { outputs: { transaction_hash: res.transactionHash, block_number: res.blockNumber, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture, is_active_recorder: true, retention: res.retention } });
}

export { ZERO32, lireJsonStrict, fs };
