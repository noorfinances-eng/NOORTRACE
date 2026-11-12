// Administration du jeu d'approbateurs d'un client (CT-4 §8.5, EX-7.26,
// EX-7.27, EX-8.21 ; décision de l'étape 6 : travail offert). Deux travaux,
// comme pour l'inscription d'une clé :
//
// - `condense-administration` prépare la demande `administration_jeu` (sortie
//   de `condense administration_jeu`) : `opNonce()` lu à la tête, condensé de
//   RG-11 recalculé et comparé à `adminOpDigest` du contrat (OP-6), demande
//   écrite sans signature. L'exploitant la remet à l'administrateur du jeu
//   hors de l'application ; aucune page ne la fait signer (EX-7.27).
// - `administrer-jeu` relaie la demande signée qu'on lui rend (sortie de
//   `administrer-jeu`) : OP-5 (relayeur du rôle ; signataire `admin()`, ou
//   `pendingAdmin()` pour `acceptAdmin`, et nonce égal à `opNonce()`), OP-6,
//   OP-7, OP-3, puis, juste avant l'envoi, la confirmation hors bande du client
//   (EX-7.26, EX-8.21) : sans confirmation non consommée pour cette demande,
//   rien n'est envoyé et le travail est refusé sans sortie ; puis l'envoi,
//   OP-11 (`AdminOpRelayed` émis par le jeu), la capture (rôle
//   `administration_jeu`) et OP-12 (l'effet de l'opération relu à la hauteur
//   du bloc).

import path from "node:path";
import * as R from "@noortrace/ancrage/registre";
import { ecrireHorodatage, octetsVersHex } from "@noortrace/noyau";
import { Sortie } from "../sortie.mjs";
import { etape } from "../dossier.mjs";
import { envoyer } from "../envoi.mjs";
import * as J from "../jeu.mjs";
import { lecture, solde } from "../reseau.mjs";
import { ecrireNouveau, serialiser } from "../donnees.mjs";
import { cleRole, consommerConfirmation, dossierClient, ecartCompte, prealables } from "./base.mjs";

const mot = (hex) => "0x" + hex.replace(/^0x/, "").padStart(64, "0");

/** Jeu du client : `result.curator_set`, sinon le contrat de l'étape `jeu_approbateurs` ; null s'il n'est pas déployé. */
export function jeuDuClient(d) {
  return d.result?.curator_set ?? etape(d, "jeu_approbateurs")?.contract ?? null;
}

/** `arg` de 32 octets d'une opération (RG-11) : adresse, entier, ou 32 octets nuls pour `acceptAdmin`. */
export function argOperation(nom, valeur) {
  const o = J.OPERATIONS[nom];
  if (o.argument === "adresse") return mot(String(valeur).toLowerCase());
  if (o.argument === "entier") return mot(BigInt(valeur).toString(16));
  return "0x" + "00".repeat(32);
}

/** `adminOpDigest(op, arg, nonce)` rendu par le contrat (OP-6). */
async function condenseDuContrat(ctx, set, nom, arg, nonce) {
  return R.decoderBytes32(await lecture(ctx.rpc, set, J.encoderAdminOpDigest(J.opDe(nom), arg, nonce)));
}

/** `opNonce()` du jeu, à `latest`. */
async function nonceDuJeu(ctx, set) {
  const n = J.decoderMot(await lecture(ctx.rpc, set, J.encoderOpNonce()));
  if (n === null) throw new R.ErreurLecture("retour_illisible", "opNonce() illisible");
  return n;
}

export async function condenseAdministration(ctx, travail) {
  const sortie = new Sortie("condense", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const set = jeuDuClient(d);
  if (!set) sortie.arreter("inutilisable", "usage", null, `le jeu du client ${ctx.slug} n'est pas déployé`);
  await prealables(ctx, sortie);
  const arg = argOperation(p.op, p.arg);
  const nonce = await nonceDuJeu(ctx, set);
  const digest = R.adminOpDigest(ctx.instance.evmChainId, set, p.op, arg, nonce.toString());
  const duContrat = await condenseDuContrat(ctx, set, p.op, arg, nonce);
  if (duContrat !== digest) sortie.echec("OP-6", "refuse", "condense_different", `adminOpDigest du contrat ${duContrat} ≠ condensé recalculé ${digest}`);
  sortie.reussie("OP-6");
  const demande = {
    version: 0,
    operation: "administration_jeu",
    evm_chain_id: ctx.instance.evmChainId,
    contract: set,
    fields: { op: p.op, arg, nonce: nonce.toString() },
    digest,
    eip191_digest: octetsVersHex(R.hachageSigne(digest)),
    signer_set: null,
    signatures: [],
    prepared_at: ecrireHorodatage(ctx.horloge.murale()),
  };
  const v = R.verifierDemandeSchema(demande);
  if (!v.valide) throw new Error(`demande hors schéma : ${v.erreurs.join(" ; ")}`);
  const chemin = path.join(ctx.client.demandes, `demande-administration-${ctx.travailId}.json`);
  ecrireNouveau(chemin, serialiser(demande));
  return sortie.rendre("reussi", { outputs: { operation: "administration_jeu", digest, eip191_digest: demande.eip191_digest, signer_set: null, expires_at: null, demande: chemin } });
}

/** OP-12 : l'effet de l'opération relu à la hauteur du bloc. */
function relecture(ctx, set, nom, arg, signataire) {
  return async (h) => {
    const adresse = "0x" + arg.slice(26);
    const v = (hex) => J.decoderMot(hex);
    switch (nom) {
      case "CuratorSet.addCurator":
      case "CuratorSet.removeCurator": {
        const membre = v(await lecture(ctx.rpc, set, J.encoderIsCurator(adresse), h)) === 1n;
        const attendu = nom === "CuratorSet.addCurator";
        return membre === attendu ? { ok: true } : { ok: false, detail: `isCurator(${adresse}) ${membre} à ${h}` };
      }
      case "CuratorSet.setThreshold": {
        const t = v(await lecture(ctx.rpc, set, J.encoderGetThreshold(), h));
        return t === BigInt(arg) ? { ok: true } : { ok: false, detail: `getThreshold() ${t} à ${h}` };
      }
      case "CuratorSet.proposeAdmin": {
        const pa = J.decoderAdresse(await lecture(ctx.rpc, set, J.encoderPendingAdmin(), h));
        return pa === adresse ? { ok: true } : { ok: false, detail: `pendingAdmin() ${pa} à ${h}` };
      }
      default: {
        const a = J.decoderAdresse(await lecture(ctx.rpc, set, J.encoderAdmin(), h));
        return a === signataire ? { ok: true } : { ok: false, detail: `admin() ${a} à ${h}` };
      }
    }
  };
}

export async function administrerJeu(ctx, travail) {
  const sortie = new Sortie("administrer-jeu", ctx);
  const p = travail.parametres;
  const d = dossierClient(ctx, sortie);
  const demande = p.demande;
  const sch = R.verifierDemandeSchema(demande);
  if (!sch.valide || demande.operation !== "administration_jeu") sortie.echec("OP-6", "inutilisable", "entree_illisible", `demande hors du schéma demande_signature d'une administration du jeu : ${sch.erreurs?.[0] ?? "opération"}`);
  const set = jeuDuClient(d);
  if (!set || demande.contract !== set) sortie.arreter("inutilisable", "usage", null, "la demande ne porte pas sur le jeu de ce client");
  const nom = demande.fields.op;
  if (!J.OPERATIONS[nom]) sortie.echec("OP-6", "inutilisable", "entree_illisible", "opération du jeu inconnue");
  await prealables(ctx, sortie);
  // Expéditeur : le relayeur du rôle (OP-5), ou une clé désignée par référence.
  let cle;
  if (p.relayeur) {
    cle = cleRole(ctx, sortie, "relayeur");
    const ecart = ecartCompte(ctx, "relayeur", cle.adresse());
    if (ecart) sortie.echec("OP-5", "refuse", "compte_inattendu", ecart);
    sortie.reussie("OP-5");
  } else {
    cle = cleRole(ctx, sortie, "expediteur", p.expediteur, { option: "expediteur" });
  }
  // OP-6 : condensé recalculé, égal à celui de la demande et à celui du contrat.
  if (demande.evm_chain_id !== ctx.instance.evmChainId) sortie.echec("OP-6", "refuse", "condense_different", "demande pour une autre chaîne");
  const pre = R.verifierDemande(demande, { complete: false });
  if (pre.resultat !== "valide" && pre.check === "OP-6") sortie.echec("OP-6", "refuse", "condense_different", "condensé de la demande différent du condensé recalculé (OP-6)");
  const nonce = BigInt(demande.fields.nonce);
  const duContrat = await condenseDuContrat(ctx, set, nom, demande.fields.arg, nonce);
  if (duContrat !== demande.digest) sortie.echec("OP-6", "refuse", "condense_different", `adminOpDigest du contrat ${duContrat} ≠ condensé de la demande`);
  sortie.reussie("OP-6");
  // OP-5 : signataire administrateur du jeu (administrateur proposé pour acceptAdmin), nonce égal à opNonce().
  const attendu = nom === "CuratorSet.acceptAdmin"
    ? J.decoderAdresse(await lecture(ctx.rpc, set, J.encoderPendingAdmin()))
    : J.decoderAdresse(await lecture(ctx.rpc, set, J.encoderAdmin()));
  const signataire = demande.signatures[0]?.signer ?? null;
  if (signataire !== attendu) sortie.echec("OP-5", "refuse", "pas_administrateur", `signataire ${signataire} ≠ ${nom === "CuratorSet.acceptAdmin" ? "pendingAdmin()" : "admin()"} ${attendu}`);
  const courant = await nonceDuJeu(ctx, set);
  if (courant !== nonce) sortie.echec("OP-5", "refuse", "pas_administrateur", `nonce de la demande ${nonce} ≠ opNonce() ${courant} : refaire la demande`);
  sortie.reussie("OP-5");
  // OP-7 : une signature canonique, qui recouvre son signataire, celui qu'attend le contrat.
  const v = R.verifierDemande(demande, { administrateur: attendu, complete: false });
  if (v.resultat !== "valide") sortie.echec("OP-7", "refuse", v.code, `signature de la demande : ${v.code}`);
  if (demande.signatures.length !== 1) sortie.echec("OP-7", "refuse", "signatures_insuffisantes", "une signature de l'administrateur attendue");
  sortie.reussie("OP-7");
  // OP-3.
  const enAttente = R.envoisSansIssue(ctx.captures, cle.adresse());
  if (enAttente.length > 0) sortie.echec("OP-3", "refuse", "transaction_en_attente", `envoi ${enAttente[0].transaction_hash} de ${cle.adresse()} sans issue connue`);
  const s = await solde(ctx.rpc, cle.adresse());
  if (s < BigInt(ctx.instance.fees.gas_limit)) sortie.echec("OP-3", "refuse", "solde_insuffisant", `solde de ${cle.adresse()} : ${s} wei < ${ctx.instance.fees.gas_limit} wei (EX-4.18)`);
  sortie.reussie("OP-3");
  // EX-7.26, EX-8.21 : la confirmation hors bande de cette demande, consommée juste avant l'envoi.
  consommerConfirmation(ctx, { operations: ["administrer-jeu"], orgId: d.organisation.org_id, digest: demande.digest });
  ecrireNouveau(path.join(ctx.client.demandes, `demande-administration-relayee-${ctx.travailId}.json`), serialiser(demande));
  const sig = demande.signatures[0];
  const res = await envoyer(ctx, sortie, {
    tenue: null, etape: null, cle, objet: "appel", to: set, donnees: J.encoderOperationSignee(nom, demande.fields.arg, nonce, sig),
    role: "administration_jeu", contrat: set,
    op11: (recu) => ((recu.logs ?? []).some((l) => l.address.toLowerCase() === set && l.topics?.[0] === J.EVENEMENTS.AdminOpRelayed && l.topics[1] === J.opDe(nom))
      ? { ok: true } : { ok: false, detail: "AdminOpRelayed absent du reçu ou d'une autre opération" }),
    op12: relecture(ctx, set, nom, demande.fields.arg, signataire),
  });
  return sortie.rendre("reussi", { outputs: { operation: nom, transaction_hash: res.transactionHash, block_number: res.blockNumber, gas_used: res.gasUsed, cost_wei: res.coutWei, capture: res.capture } });
}
