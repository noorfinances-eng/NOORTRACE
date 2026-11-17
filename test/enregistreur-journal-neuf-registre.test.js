// CT-8 §11.4, chemin C, pas 5 (TE-9) sur le réseau de développement 2124
// (CT-4 §7.4 : quatre validateurs noorcore locaux, `bash
// chain/scripts/dev-net.sh start`, JSON-RPC sur 127.0.0.1:8645 à 8648,
// identifiant EVM 2124, sans manifeste : EX-7.2). En attente, condition
// nommée dans le titre, quand le réseau n'est pas debout ; jamais sauté sans
// raison écrite.
//
// Les quatre contrats sont déployés pour l'essai (compte Hardhat 0, fichier de
// déploiement sous un répertoire temporaire, NOORTRACE_DEPLOYMENTS_DIR) : la
// lecture OP-8 de l'outil (`eth_getLogs` en tranches depuis le bloc de
// déploiement) reste courte, et l'essai ne dépend pas de l'âge du déploiement
// partagé du réseau de développement. Un client fictif est inscrit par l'outil
// de référence du registre (jeu de trois approbateurs, comptes Hardhat 1 à 3,
// seuil 2), avec l'ancien journal et sa clé de chaîne. L'ancien journal est produit par le cœur réel sous
// cette organisation, puis sa clé est perdue. Pas 1 à 4 comme
// test/enregistreur-journal-neuf.test.js, mais la demande d'inscription du
// nouveau journal est condensée sur le registre en service (jeu
// d'approbateurs lu en chaîne). Pas 5 : l'inscription est relayée
// (`inscrire-cle`, compte relayeur) et capturée, l'ancienne clé de chaîne est
// révoquée (`condense revocation`, `signer` × 2, `revoquer-cle`), puis le
// nouveau démon démarre : premier événement à `seq` 1 et `prev_hash` nul.
// Clés de test publiées, sans valeur hors du réseau 2124 : comptes Hardhat du
// mnémonique public, graines Ed25519 des outils du cœur, clés de chaîne
// SHA-256(UTF-8(« noortrace/essais/te-9/chemin-c/<organisation>/<nom> »)).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import { lireEvenements } from "@noortrace/enregistreur";
import * as C from "../scripts/lib/conventions-registre.mjs";
import { RACINE, configurationDev, graine } from "./fixtures/enregistreur-coeur/outils.mjs";
import { ctl, repertoireTemporaire } from "./fixtures/enregistreur-export/outils.mjs";
import { valider, demarrerCoeur } from "./fixtures/enregistreur-modele/outils.mjs";
import { compteHardhat, documentCle, outilReference as outilReferenceBrut } from "./fixtures/inscription/outils.mjs";

const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const RPC = ["--rpc", POINTS.join(",")];
/** Environnement des commandes de l'outil : fichier de déploiement de l'essai. */
const ENV = {};
const outilReference = (args) => outilReferenceBrut(args, { env: ENV });
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const pub = (keyId) => N.octetsVersHex(N.clePubliqueEd25519(graine(keyId)));

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS, delaiMs: 3000 });
  try {
    for (const p of POINTS) {
      const c = await rpc.appeler("eth_chainId", [], { point: p });
      if (c.erreur || c.resultat !== "0x84c") return `le validateur ${p} ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)`;
    }
    const m = await rpc.appeler("noor_getCommitCertificate", ["latest"]);
    if (m.erreur && m.erreur.code === -32601) return "le binaire noorcore ne sert pas noor_getCommitCertificate (CT-4 §9.1)";
    return null;
  } catch (e) {
    return `le réseau de développement n'est pas debout (${e.message}) : bash chain/scripts/dev-net.sh start`;
  }
}

/**
 * L'outil de référence sur le réseau : un refus passager `noeud_suiveur`
 * (OP-2, rien n'est envoyé) est relancé, au plus vingt fois à 500 ms.
 */
async function reference(args) {
  let r;
  for (let i = 0; i < 20; i += 1) {
    r = await outilReference([...args, ...RPC]);
    if (r.sortie?.error?.code !== "noeud_suiveur") return r;
    await new Promise((ok) => setTimeout(ok, 500));
  }
  return r;
}

const reussi = (r, quoi, attendu = "reussi") => expect(r.sortie?.result, `${quoi} : ${JSON.stringify(r.sortie?.error ?? null)} ${r.err.slice(-1500)}`).to.equal(attendu);

function verifierJournalReference(rep, cles) {
  const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "verifier-journal.mjs"), rep, "--cles", cles, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: JSON.parse(r.stdout) };
}

function clesJournal(chemin, org, journal, keyId) {
  fs.writeFileSync(chemin, JSON.stringify({ version: 0, org_id: org, journal_id: journal, keys: [{ key_id: keyId, algorithm: "ed25519", public_key: pub(keyId), valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: `clé d'essai ${keyId} des outils du cœur, sans valeur hors des tests` }] }, null, 2) + "\n");
  return chemin;
}

/** Démarre puis arrête le cœur réel sur une configuration de développement de l'organisation inscrite ; rend la configuration écrite. */
async function journalDuCoeur(dir, { org_id, journal_id, keyId }) {
  fs.mkdirSync(dir, { recursive: true });
  const { config: brut, env } = configurationDev(dir, { org_id, journal_id });
  brut.signer.key_id = keyId;
  brut.signer.backend.path = path.join(dir, "cles", `${keyId}.pem`);
  brut.signer.rotation.next_key_id = null;
  const v = valider(brut, env);
  const { coeur } = await demarrerCoeur(v.config, v.secrets);
  const repertoire = coeur.repertoire;
  await coeur.arreter();
  const cheminConfig = path.join(dir, "configuration.json");
  fs.writeFileSync(cheminConfig, JSON.stringify(brut, null, 2));
  return { config: v.config, cheminConfig, repertoire, journal: v.config.supervision.ops_log.path };
}

describe("CT-8 §11.4 chemin C, pas 5 (TE-9) sur le réseau de développement 2124 : inscription du nouveau journal relayée et capturée, ancienne clé de chaîne révoquée, nouveau démon démarré à seq 1 (CT-2 EX-11.16, CT-4 §8.4)", function () {
  this.timeout(1_200_000);
  let absent = null;
  let dir;
  let slug;
  let orgId;
  let caps;
  const k = {};
  const JOURNAL_ANCIEN = "journal-ancien";
  const JOURNAL_NOUVEAU = "journal-nouveau";
  const JID_ANCIEN = C.journalIdDuNom(JOURNAL_ANCIEN);
  const JID_NOUVEAU = C.journalIdDuNom(JOURNAL_NOUVEAU);
  let ancien;
  let demande;
  let fin;

  before(async function () {
    absent = await reseauDebout();
    if (absent) return;
    dir = repertoireTemporaire("noortrace-chemin-c-2124-");
    // Contrats de l'essai (CT-4 §7.4), déployés par le script du dépôt sous un répertoire de déploiement propre.
    ENV.NOORTRACE_DEPLOYMENTS_DIR = path.join(dir, "deployments");
    const dep = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploy", "deploy-noortrace.mjs"), "--network", "noorcore"], { cwd: RACINE, encoding: "utf8", env: { ...process.env, ...ENV, NOOR_PRIVATE_KEY: N.octetsVersHex(compteHardhat(0).cle) }, timeout: 600000 });
    if (dep.status !== 0) throw new Error(`déploiement des contrats de l'essai en échec (code ${dep.status}) : ${(dep.stdout + dep.stderr).slice(-2000)}`);
    slug = `te9-chemin-c-${Date.now()}`;
    caps = path.join(dir, "captures");
    for (const nom of ["cle-chaine-ancienne", "cle-chaine-nouvelle"]) {
      const s = crypto.createHash("sha256").update(`noortrace/essais/te-9/chemin-c/${slug}/${nom}`).digest();
      const f = path.join(dir, `${nom}.cle`);
      fs.writeFileSync(f, s.toString("hex"), { mode: 0o600 });
      k[nom] = { reference: `fichier:${f}`, adresse: new R.SignataireChaineFichier(new Uint8Array(s)).adresse() };
    }
  });

  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("client inscrit au registre en service avec l'ancien journal (rec-test-01, ancienne clé de chaîne active) ; ancien journal produit par le cœur sous cette organisation, puis clé perdue ; pas 1 à 4 : fin établie, demande du nouveau journal condensée sur le registre et signée au seuil, lien écrit et contrôlé", async function () {
    if (absent) return enAttente(this, absent);
    // Client fictif : jeu de trois approbateurs (Hardhat 1 à 3), seuil 2, administrateur du jeu Hardhat 4.
    const cles = path.join(dir, "cles-essai");
    fs.mkdirSync(cles);
    fs.writeFileSync(path.join(cles, "rec-test-01.json"), JSON.stringify(documentCle({ keyId: "rec-test-01", journalId: JID_ANCIEN, chainKey: k["cle-chaine-ancienne"].adresse, publique: pub("rec-test-01") })));
    fs.writeFileSync(path.join(cles, "cles-essai.json"), JSON.stringify({
      version: 0,
      description: "Clés de test publiées de l'essai du chemin C (TE-9) : comptes Hardhat du mnémonique public, graines des outils du cœur.",
      journal: { name: JOURNAL_ANCIEN, journal_id: JID_ANCIEN },
      set_admin: compteHardhat(4).adresse,
      approvers: [1, 2, 3].map((i) => compteHardhat(i).adresse),
      recorders: [{ key_id: "rec-test-01", file: "rec-test-01.json", public_key: pub("rec-test-01"), chain_key: k["cle-chaine-ancienne"].adresse }],
    }));
    const dossier = path.join(dir, "dossier.json");
    const prep = await reference(["inscrire-client", "--preparer", "--org", slug, "--journal", JOURNAL_ANCIEN, "--seuil", "2", "--cles-essai", path.join(cles, "cles-essai.json"), "--exploitant", "hardhat:0", "--prepare-par", "essai du chemin C (TE-9)", "--sortie", dossier]);
    reussi(prep, "inscrire-client --preparer");
    orgId = prep.sortie.outputs.org_id;
    expect(orgId).to.equal(C.orgIdDuSlug(slug));
    reussi(await reference(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps]), "inscrire-client --dossier");
    const demAncien = path.join(dir, "demande-inscription-ancien.json");
    reussi(await reference(["condense", "inscription", "--dossier", dossier, "--key-id", "rec-test-01", "--sortie", demAncien]), "condense inscription (ancien)");
    for (const i of [1, 2]) reussi(await outilReference(["signer", "--demande", demAncien, "--cle", `hardhat:${i}`]), `signer hardhat:${i}`);
    const ia = await reference(["inscrire-cle", "--demande", demAncien, "--cle-chaine", k["cle-chaine-ancienne"].reference, "--dossier", dossier, "--captures", caps]);
    reussi(ia, "inscrire-cle (ancien)");
    expect(ia.sortie.outputs.is_active_recorder).to.equal(true);

    // Ancien journal : le cœur réel sous l'organisation inscrite ; puis la clé de l'enregistreur est perdue.
    ancien = await journalDuCoeur(path.join(dir, "ancien"), { org_id: orgId, journal_id: JID_ANCIEN, keyId: "rec-test-01" });
    fs.rmSync(ancien.config.signer.backend.path);
    fin = (await lireEvenements(ancien.repertoire)).at(-1);
    // Pas 1 : fin de l'ancien journal établie par l'outil de référence de CT-8 EX-11.7.
    const ref = verifierJournalReference(ancien.repertoire, clesJournal(path.join(dir, "cles-ancien.json"), orgId, JID_ANCIEN, "rec-test-01"));
    expect(ref.code, JSON.stringify(ref.rapport).slice(0, 2000)).to.equal(0);
    expect([ref.rapport.last_seq, ref.rapport.last_hash]).to.deep.equal([fin.seq, fin.hash]);

    // Pas 2 : demande d'inscription de la nouvelle paire sous le nouveau journal, condensée sur le registre en service.
    demande = path.join(dir, "registre", "demande-inscription-nouveau.json");
    fs.mkdirSync(path.dirname(demande));
    reussi(await reference(["condense", "inscription", "--org-id", orgId, "--journal-id", JID_NOUVEAU, "--cle-chaine-adresse", k["cle-chaine-nouvelle"].adresse, "--cle-ed25519", pub("rec-test-02"), "--sortie", demande]), "condense inscription (nouveau)");
    for (const i of [1, 2]) reussi(await outilReference(["signer", "--demande", demande, "--cle", `hardhat:${i}`]), `signer hardhat:${i}`);
    const d = lireJSON(demande);
    expect(d.fields).to.deep.equal({ org_id: orgId, journal_id: JID_NOUVEAU, chain_key: k["cle-chaine-nouvelle"].adresse, ed25519_public_key: pub("rec-test-02") });
    expect(d.evm_chain_id).to.equal(2124);
    expect(d.signatures).to.have.lengthOf(2);

    // Pas 3 et 4 : lien écrit, puis contrôlé contre la fin réelle.
    const lien = { old_journal_id: JID_ANCIEN, last_seq: fin.seq, last_hash: fin.hash, new_journal_id: JID_NOUVEAU };
    const r = await ctl(["journal", "successeur", "--configuration", ancien.cheminConfig, "--demande", demande]);
    expect(r.code, r.stdout + r.stderr).to.equal(0);
    expect(r.ligne.link).to.deep.equal(lien);
    const x = await ctl(["journal", "verifier-successeur", "--configuration", ancien.cheminConfig, "--demande", demande]);
    expect(x.code, x.stdout + x.stderr).to.equal(0);
    expect(x.ligne).to.deep.include({ result: "lien_valide", link: lien });
  });

  it("pas 5 : avant le relais, la nouvelle clé de chaîne n'est pas inscrite et l'ancienne l'est ; inscription relayée (inscrire-cle, compte relayeur) et capturée ; ancienne clé révoquée (condense revocation, signer × 2, revoquer-cle), réinscription refusée ; le lien reste valide ; le nouveau démon démarre, premier événement à seq 1 et prev_hash nul, vérifié par l'outil de référence", async function () {
    if (absent) return enAttente(this, absent);
    expect(demande, "pas 1 à 4 joués par l'essai précédent").to.be.a("string");
    const actif = async (cle) => {
      const e = await reference(["condense", "revocation", "--org-id", orgId, "--cle-chaine-adresse", cle, "--sortie", path.join(dir, `sonde-${crypto.randomUUID()}.json`)]);
      return e.sortie?.result === "reussi" ? "active" : e.sortie?.error?.code;
    };
    // Avant le relais (rouge) : la nouvelle clé inconnue du registre, l'ancienne active.
    expect(await actif(k["cle-chaine-nouvelle"].adresse)).to.equal("cle_inconnue");
    expect(await actif(k["cle-chaine-ancienne"].adresse)).to.equal("active");

    // Relais de l'inscription, capturée.
    const ins = await reference(["inscrire-cle", "--demande", demande, "--relayeur", "hardhat:0", "--captures", caps]);
    reussi(ins, "inscrire-cle (nouveau)");
    expect(ins.sortie.outputs.is_active_recorder).to.equal(true);
    expect(ins.sortie.outputs.capture, "inscription capturée").to.be.a("string");
    const capture = path.isAbsolute(ins.sortie.outputs.capture) ? ins.sortie.outputs.capture : path.join(caps, ins.sortie.outputs.capture);
    expect(fs.existsSync(capture), `capture ${ins.sortie.outputs.capture}`).to.equal(true);
    // Rejoué, rien n'est envoyé.
    reussi(await reference(["inscrire-cle", "--demande", demande, "--relayeur", "hardhat:0", "--captures", caps]), "inscrire-cle rejoué", "deja_fait");

    // Révocation de l'ancienne clé de chaîne (CT-4 §8.4), au seuil.
    const rev = path.join(dir, "demande-revocation-ancienne.json");
    reussi(await reference(["condense", "revocation", "--org-id", orgId, "--cle-chaine-adresse", k["cle-chaine-ancienne"].adresse, "--sortie", rev]), "condense revocation");
    reussi(await outilReference(["signer", "--demande", rev, "--cle", "hardhat:2"]), "signer hardhat:2");
    // Une seule signature : sous le seuil, rien n'est envoyé.
    const insuff = await reference(["revoquer-cle", "--demande", rev, "--relayeur", "hardhat:0", "--captures", caps]);
    expect(insuff.sortie?.result, JSON.stringify(insuff.sortie?.error)).to.not.equal("reussi");
    reussi(await outilReference(["signer", "--demande", rev, "--cle", "hardhat:3"]), "signer hardhat:3");
    const rv = await reference(["revoquer-cle", "--demande", rev, "--relayeur", "hardhat:0", "--captures", caps]);
    reussi(rv, "revoquer-cle");
    expect(rv.sortie.outputs.is_active_recorder).to.equal(false);
    // Après le relais (vert) : la nouvelle clé active, l'ancienne révoquée ; elle n'est jamais réinscrite.
    expect(await actif(k["cle-chaine-nouvelle"].adresse)).to.equal("active");
    expect(await actif(k["cle-chaine-ancienne"].adresse)).to.equal("cle_revoquee");
    const demAncien = path.join(dir, "demande-inscription-ancien.json");
    const reinscription = await reference(["inscrire-cle", "--demande", demAncien, "--relayeur", "hardhat:0", "--captures", caps]);
    expect(reinscription.sortie?.error?.code, JSON.stringify(reinscription.sortie)).to.equal("cle_revoquee");

    // La note d'exploitant reste avec la demande et le lien reste valide.
    expect(fs.existsSync(demande.replace(/\.json$/, ".note-exploitant.json"))).to.equal(true);
    const x = await ctl(["journal", "verifier-successeur", "--configuration", ancien.cheminConfig, "--demande", demande]);
    expect(x.code, x.stdout + x.stderr).to.equal(0);
    expect(x.ligne.result).to.equal("lien_valide");

    // Nouveau démon : journal_id du nouveau journal, clé rec-test-02 ; premier événement à seq 1, prev_hash nul.
    const nouveau = await journalDuCoeur(path.join(dir, "nouveau"), { org_id: orgId, journal_id: JID_NOUVEAU, keyId: "rec-test-02" });
    const premiers = await lireEvenements(nouveau.repertoire);
    expect(premiers[0]).to.deep.include({ seq: 1, org_id: orgId, journal_id: JID_NOUVEAU, recorder_key_id: "rec-test-02", prev_hash: N.ZERO32 });
    const ref = verifierJournalReference(nouveau.repertoire, clesJournal(path.join(dir, "cles-nouveau.json"), orgId, JID_NOUVEAU, "rec-test-02"));
    expect(ref.code, JSON.stringify(ref.rapport).slice(0, 2000)).to.equal(0);
  });
});
