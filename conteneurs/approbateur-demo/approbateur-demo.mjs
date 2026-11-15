#!/usr/bin/env node
// Service `approbateur-demo` de la démonstration de référence (CT-2 §19.2,
// pas 1, 6 et 9) : il joue les approbateurs de l'organisation de
// démonstration, et il est le SEUL service à détenir leurs clés. Ni
// l'enregistreur, ni le service d'approbation, ni l'agent ne les ont.
//
//   approbateur-demo.mjs servir
//   approbateur-demo.mjs sonde
//
// Ce qu'il détient : les clés des comptes Hardhat 1 à 3 de la mnémonique
// publique de test (CT-3 annexe A.2, `spec/vecteurs/ct-3/constantes.json`).
// Ce sont des clés de démonstration publiques : elles ne protègent rien, et
// l'enregistreur refuse en production une politique qui les nomme (CT-2
// EX-15.8).
//
// Ce qu'il fait, dans l'ordre :
//   1. inscription de la clé de l'enregistreur au registre (CT-4 §7.7,
//      §8.7) : demande d'inscription signée au seuil par les comptes 1 et 2,
//      transaction `registerRecorder` envoyée par le compte 1 ;
//   2. approbateurs de la console : par le canal de la console du service
//      d'approbation (CT-3 §12.9), il inscrit les adresses des comptes 1 et 2
//      à l'annuaire (défi signé par chaque clé, validation par
//      l'administrateur), lit chaque ticket ouvert (`consulter`), recalcule le
//      condensé D_A de la décision (CT-1 §6.3) et vote `approuve` avec les
//      comptes 1 et 2 ;
//   3. clôture de la période (CT-4 §8.2) : pour chaque manifeste déposé dans
//      le répertoire d'échange, il vérifie la signature du manifeste par la clé
//      inscrite, signe la demande de clôture au seuil et l'y dépose ;
//      l'exploitant la remet à l'enregistreur, qui relaie `submitPeriod`.

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { attendre, attendreChaine, clientRpc, rpc, envoyer, jeuPour, seuilDe } from "../demo-commun/chaine.mjs";

/** Vrai quand ce fichier est le programme lancé (lien symbolique du point d'entrée compris), faux quand il est importé. */
function estProgramme(url) {
  try {
    return Boolean(process.argv[1]) && fs.realpathSync(process.argv[1]) === fileURLToPath(url);
  } catch {
    return false;
  }
}

/** Comptes Hardhat 1 à 3 (`m/44'/60'/0'/0/1` à `/3`), clés publiques de test de CT-3 A.2 ; seul fichier de la démonstration qui les écrit (le programme des cas, monté dans la même image, les importe d'ici). */
export const CLES_APPROBATEURS = Object.freeze([
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]);
/** Identités de session que la console de démonstration affirme pour ses deux approbateurs et son administrateur. */
export const SESSIONS = Object.freeze({
  1: "oidc https://idp.assureur-demo.example approbateur-1",
  2: "oidc https://idp.assureur-demo.example approbateur-2",
  admin: "oidc https://idp.assureur-demo.example admin-1",
});

const env = (nom, defaut) => process.env[nom] ?? defaut;

function journal(evenement, donnees = {}) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), service: "approbateur-demo", event: evenement, ...donnees })}\n`);
}

/**
 * Signature `personal_sign` (EIP-191, version 0x45) d'un texte par un signataire de chaîne : r ‖ s ‖ v, v ∈ {27, 28}, s bas.
 * @param {{signerCondense: (h: Uint8Array) => {r: string, s: string, v: number}}} signataire
 */
export function signerTexte(signataire, texte) {
  const octets = N.utf8(texte);
  const sig = signataire.signerCondense(N.keccak256(N.concatener(N.utf8(`\x19Ethereum Signed Message:\n${octets.length}`), octets)));
  return `${sig.r}${sig.s.slice(2)}${sig.v.toString(16)}`;
}

/** Signatures au seuil d'un condensé interne du registre, rangées par adresse croissante (RG-13). */
function signerAuSeuil(signataires, seuil, condense) {
  const hache = R.hachageSigne(condense);
  const signatures = signataires.slice(0, seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hache) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
  return { hache, signatures };
}

/** Jeu de l'organisation lu au registre (`curatorSetFor` du contrat qui vérifiera les signatures) : adresse, seuil, tête de chaîne à la lecture. */
async function lireJeu(client, contrat, orgId) {
  const tete = await rpc(client, "eth_getBlockByNumber", ["latest", false]);
  const curatorSet = await jeuPour(client, contrat, orgId);
  return { curator_set: curatorSet, threshold: await seuilDe(client, curatorSet), height: Number(BigInt(tete.number)), block_hash: tete.hash };
}

/** Pas 1 : inscription de la clé de l'enregistreur (demande signée au seuil, transaction du compte 1). */
async function inscrireCle(o) {
  const { client, instance, signataires, orgId, journalId, cleChaine, cleEd25519 } = o;
  fs.mkdirSync(path.join(o.demandes, "inscription"), { recursive: true });
  const deja = await R.recorderOf({ rpc: client, contrat: instance.recorderRegistry, orgId, chainKey: cleChaine });
  if (deja.registeredAt !== 0n) {
    if (deja.revokedAt !== 0n || deja.ed25519PubKey !== cleEd25519 || deja.journalId !== journalId) throw new Error("la clé de chaîne est déjà inscrite pour une autre clé, un autre journal, ou révoquée");
    journal("cle_deja_inscrite", { chain_key: cleChaine });
    return;
  }
  const jeu = await lireJeu(client, instance.recorderRegistry, orgId);
  const fields = { org_id: orgId, journal_id: journalId, chain_key: cleChaine, ed25519_public_key: cleEd25519 };
  const digest = R.registerDigest(instance.evmChainId, instance.recorderRegistry, orgId, journalId, cleChaine, cleEd25519);
  const { hache, signatures } = signerAuSeuil(signataires, jeu.threshold, digest);
  const demande = { version: 0, operation: "inscription", evm_chain_id: instance.evmChainId, contract: instance.recorderRegistry, fields, digest, eip191_digest: N.octetsVersHex(hache), signer_set: jeu, signatures, prepared_at: N.ecrireHorodatage(Date.now()) };
  const v = R.verifierDemande(demande, { complete: true });
  if (v.resultat !== "valide") throw new Error(`demande d'inscription refusée par son propre contrôle (${v.check} ${v.code})`);
  const envoi = await envoyer({ client, evmChainId: instance.evmChainId, signataire: signataires[0], to: instance.recorderRegistry, data: R.encoderRegisterRecorder({ ...fields, signatures }), gasLimit: 500000n });
  const lue = await R.recorderOf({ rpc: client, contrat: instance.recorderRegistry, orgId, chainKey: cleChaine });
  if (lue.registeredAt === 0n || lue.ed25519PubKey !== cleEd25519) throw new Error("inscription envoyée mais non lue au registre");
  // Capture de l'inscription (CT-4 §9.4) : en-tête, reçus et certificat de commit du bloc, déposés dans le répertoire
  // d'échange pour que l'exploitant les remette à l'enregistreur et que le dossier porte l'inscription (CT-6, R-10).
  const capture = await R.capturer({
    rpc: client, transactionHash: envoi.hash, role: "inscription", contrat: instance.recorderRegistry, horloge: { murale: () => Date.now() },
    repertoire: path.join(o.demandes, "inscription"), instance: { evmChainId: instance.evmChainId, bftChainId: instance.bftChainId, jeux: instance.manifeste }, attendre,
  });
  if (capture.erreur) throw new Error(`capture de l'inscription en échec (${capture.erreur.code} ${capture.erreur.check ?? ""}) : ${capture.erreur.message}`);
  journal("cle_inscrite", { registre: "RecorderRegistry", chain_key: cleChaine, ed25519_public_key: cleEd25519, signataires: signatures.map((s) => s.signer), seuil: jeu.threshold, transaction: envoi.hash, bloc: Number(BigInt(envoi.recu.blockNumber)), capture: capture.nom });
}

/** Appel d'une méthode du canal de la console, sur la prise du service (jeton porteur). */
function appelConsole(prise, jeton, methode, corps) {
  return new Promise((resoudre, rejeter) => {
    const octets = Buffer.from(JSON.stringify(corps), "utf8");
    const req = http.request({ socketPath: prise, method: "POST", path: `/v0/${methode}`, headers: { "content-type": "application/json", "content-length": octets.length, authorization: `Bearer ${jeton}` } }, (rep) => {
      const m = [];
      rep.on("data", (x) => m.push(x));
      rep.on("end", () => {
        try {
          resoudre({ statut: rep.statusCode, corps: JSON.parse(Buffer.concat(m).toString("utf8")) });
        } catch (e) {
          rejeter(e);
        }
      });
    });
    req.setTimeout(10000, () => req.destroy(new Error("délai du canal de la console")));
    req.on("error", rejeter);
    req.end(octets);
  });
}

/** Pas 2 a : inscription des adresses des comptes 1 et 2 à l'annuaire des approbateurs (CT-3 §13.5). */
async function inscrireAnnuaire(o) {
  const appel = async (methode, corps, admis = []) => {
    const r = await appelConsole(o.prise, o.jeton, methode, corps);
    if (r.statut !== 200 && !admis.includes(r.corps?.error?.code)) throw new Error(`${methode} refusé (${r.statut} ${r.corps?.error?.code ?? ""})`);
    return r;
  };
  for (const i of [1, 2]) {
    const adresse = o.signataires[i - 1].adresse();
    const vue = (await appel("annuaire", { session_identity: SESSIONS.admin })).corps;
    const entree = (vue.entries ?? []).find((e) => e.session_identity === SESSIONS[i]);
    const etat = entree?.addresses?.find((a) => a.address === adresse)?.state ?? null;
    if (etat === "active") continue;
    if (etat === null) {
      const p = (await appel("preparer_inscription", { session_identity: SESSIONS[i], address: adresse })).corps;
      await appel("inscrire", { session_identity: SESSIONS[i], address: adresse, message: p.message, signature: signerTexte(o.signataires[i - 1], p.message) });
    }
    const apres = (await appel("annuaire", { session_identity: SESSIONS.admin })).corps;
    const e = apres.entries.find((x) => x.session_identity === SESSIONS[i]);
    await appel("valider", { session_identity: SESSIONS.admin, entry: e.id, address: adresse });
    journal("approbateur_inscrit", { identite: SESSIONS[i], adresse });
  }
}

/** Pas 2 b : lecture d'un ticket ouvert et vote des comptes 1 et 2. */
async function voter(o, ticket) {
  for (const i of [1, 2]) {
    const adresse = o.signataires[i - 1].adresse();
    const vue = await appelConsole(o.prise, o.jeton, "consulter", { ticket, session_identity: SESSIONS[i] });
    if (vue.statut !== 200) return void journal("ticket_non_lu", { ticket, code: vue.corps?.error?.code ?? null });
    const t = vue.corps;
    if (t.votes.some((v) => v.approver === adresse && v.status === "courant")) continue;
    if (!t.eligible.includes(adresse)) continue;
    // L'approbateur recalcule ce qu'il signe (CT-3 EX-9.6) : l'empreinte de la demande est celle de l'événement retenu qu'il lit,
    // et D_A de la décision « approuve » ; les condensés du service ne sont qu'un contrôle croisé.
    if (t.retained_event.hash !== t.request_hash) throw new Error(`ticket ${ticket} : l'événement retenu n'est pas la demande`);
    const A = { decision: "approuve", journal_id: t.journal_id, org_id: t.org_id, request_hash: t.request_hash, ticket };
    if (N.octetsVersHex(N.condenseApprobation(A)) !== t.digests.approuve) throw new Error(`ticket ${ticket} : condensé D_A différent de celui du service`);
    if (t.org_id !== o.orgId || t.journal_id !== o.journalId) throw new Error(`ticket ${ticket} : autre journal`);
    const r = await appelConsole(o.prise, o.jeton, "voter", { ticket, approver: adresse, decision: "approuve", signature: N.signerApprobation(N.hexVersOctets(CLES_APPROBATEURS[i - 1], 32), A), reason: null, session_identity: SESSIONS[i] });
    if (r.statut !== 200) return void journal("vote_refuse", { ticket, approbateur: adresse, code: r.corps?.error?.code ?? null });
    journal("vote_inscrit", { ticket, outil: t.request.tool_announced, approbateur: adresse, decision: "approuve", etat: r.corps.state });
  }
}

/** Pas 3 : demande de clôture signée au seuil pour un manifeste déposé par l'exploitant. */
async function signerCloture(o, fichier) {
  const depot = JSON.parse(fs.readFileSync(fichier, "utf8"));
  const m = depot.manifeste;
  if (m.org_id !== o.orgId || m.journal_id !== o.journalId) throw new Error("manifeste d'un autre journal");
  // `depot.signature` est le document `manifeste.sig` (CT-1 §10.2) : `{ version, period_hash, recorder_key_id, sig }`.
  const periodHash = N.hacherManifeste(m);
  if (depot.signature?.period_hash !== periodHash) throw new Error("la signature déposée n'est pas celle de ce manifeste");
  if (!N.verifierSignatureManifeste(m, depot.signature.sig, N.hexVersOctets(o.cleEd25519, 32))) throw new Error("signature du manifeste invalide pour la clé inscrite");
  const periodMeta = {
    org_id: m.org_id, journal_id: m.journal_id, period_hash: periodHash, root: m.root,
    period_start: String(m.period_start), period_end: String(m.period_end), first_seq: String(m.first_seq), last_seq: String(m.last_seq), version: m.version, uri: "",
  };
  const jeu = await lireJeu(o.client, o.instance.periodRegistry, o.orgId);
  const digest = R.periodDigest(o.instance.evmChainId, o.instance.periodRegistry, periodMeta);
  const { hache, signatures } = signerAuSeuil(o.signataires, jeu.threshold, digest);
  const demande = { version: 0, operation: "cloture", evm_chain_id: o.instance.evmChainId, contract: o.instance.periodRegistry, fields: { period_meta: periodMeta }, digest, eip191_digest: N.octetsVersHex(hache), signer_set: jeu, signatures, prepared_at: N.ecrireHorodatage(Date.now()) };
  const v = R.verifierDemande(demande, { complete: true });
  if (v.resultat !== "valide") throw new Error(`demande de clôture refusée par son propre contrôle (${v.check} ${v.code})`);
  const sortie = path.join(path.dirname(fichier), `demande-cloture-${periodHash}.json`);
  fs.writeFileSync(`${sortie}.partiel`, `${JSON.stringify(demande, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(`${sortie}.partiel`, sortie);
  journal("cloture_signee", { period_hash: periodHash, period_start: m.period_start, period_end: m.period_end, signataires: signatures.map((s) => s.signer), seuil: jeu.threshold });
}

function lireInstance(chemin) {
  const d = JSON.parse(fs.readFileSync(chemin, "utf8"));
  const adresse = (nom) => d.contracts.find((c) => c.name === nom)?.address;
  return { manifeste: d, bftChainId: d.bft_chain_id, evmChainId: d.evm_chain_id, attestationRegistry: adresse("AttestationRegistry"), periodRegistry: adresse("PeriodRegistry"), recorderRegistry: adresse("RecorderRegistry") };
}

async function servir() {
  const etat = env("APPROBATEUR_ETAT", "/run/temporaire");
  const pret = path.join(etat, "pret");
  fs.rmSync(pret, { force: true });
  const instance = lireInstance(env("APPROBATEUR_INSTANCE", "/etc/noortrace-demo/instance-registre.json"));
  const o = {
    client: clientRpc(env("APPROBATEUR_RPC_URL", "http://registre-dev:8545")),
    instance,
    signataires: CLES_APPROBATEURS.map((k) => R.SignataireChaineFichier.depuisOctets(k)),
    orgId: env("APPROBATEUR_ORG_ID", ""), journalId: env("APPROBATEUR_JOURNAL_ID", ""),
    cleChaine: env("APPROBATEUR_CLE_CHAINE", "").toLowerCase(), cleEd25519: env("APPROBATEUR_CLE_ED25519", "").toLowerCase(),
    prise: env("APPROBATEUR_CONSOLE_PRISE", "/run/noortrace-console/console.sock"),
    jeton: env("APPROBATEUR_CONSOLE_JETON", ""),
    demandes: env("APPROBATEUR_DEMANDES", "/var/lib/noortrace-demandes"),
  };
  for (const [nom, v, motif] of [["APPROBATEUR_ORG_ID", o.orgId, /^0x[0-9a-f]{64}$/], ["APPROBATEUR_JOURNAL_ID", o.journalId, /^0x[0-9a-f]{64}$/], ["APPROBATEUR_CLE_CHAINE", o.cleChaine, /^0x[0-9a-f]{40}$/], ["APPROBATEUR_CLE_ED25519", o.cleEd25519, /^0x[0-9a-f]{64}$/]]) {
    if (!motif.test(v)) throw new Error(`${nom} absent ou hors forme`);
  }
  let arret = false;
  for (const s of ["SIGTERM", "SIGINT"]) process.on(s, () => (arret = true));
  await attendreChaine(o.client, instance.evmChainId);
  await inscrireCle(o);
  // Le service d'approbation crée sa prise à son démarrage : on l'attend.
  for (let k = 0; !fs.existsSync(o.prise); k++) {
    if (k > 240) throw new Error(`prise du canal de la console absente : ${o.prise}`);
    await attendre(250);
  }
  await inscrireAnnuaire(o);
  fs.mkdirSync(etat, { recursive: true });
  fs.writeFileSync(pret, "pret\n");
  journal("pret", { approbateurs: o.signataires.slice(0, 2).map((s) => s.adresse()) });
  const signees = new Set();
  while (!arret) {
    try {
      const r = await appelConsole(o.prise, o.jeton, "tickets", { session_identity: SESSIONS[1] });
      if (r.statut === 200) for (const t of r.corps.tickets) if (["ouvert", "seuil_atteint"].includes(t.state)) await voter(o, t.ticket);
      for (const nom of fs.existsSync(o.demandes) ? fs.readdirSync(o.demandes) : []) {
        if (!/^manifeste-[0-9]+\.json$/.test(nom) || signees.has(nom)) continue;
        signees.add(nom);
        await signerCloture(o, path.join(o.demandes, nom));
      }
    } catch (e) {
      journal("erreur", { message: e.message });
    }
    await attendre(300);
  }
  process.exit(0);
}

if (estProgramme(import.meta.url)) {
  if (process.argv[2] === "servir") {
    servir().catch((e) => {
      journal("echec", { message: e.message });
      process.exit(1);
    });
  } else if (process.argv[2] === "sonde") {
    process.exit(fs.existsSync(path.join(env("APPROBATEUR_ETAT", "/run/temporaire"), "pret")) ? 0 : 1);
  } else {
    process.stderr.write("usage : approbateur-demo.mjs servir | sonde\n");
    process.exit(2);
  }
}
