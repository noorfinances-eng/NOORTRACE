// Composant d'ancrage, lot D : épreuve sur le réseau de développement
// (CT-4 §7.4 : quatre validateurs noorcore locaux, `bash
// chain/scripts/dev-net.sh start`, JSON-RPC sur 127.0.0.1:8645 à 8648,
// identifiant EVM 2124, BFT noortrace-2124-dev, méthode
// noor_getCommitCertificate), avec un client inscrit par le parcours de
// référence `npm run e2e:registre -- --garder-reseau --sortie <répertoire>`
// (exécuté comme une boîte noire : ses sorties seules sont lues).
//
// En attente, condition nommée dans le titre, quand le réseau n'est pas
// debout, quand le binaire ne sert pas la méthode, ou quand aucun parcours
// n'est disponible (NOORTRACE_PARCOURS_REGISTRE désigne le répertoire
// `--sortie` d'un parcours ; à défaut, le parcours est exécuté ici si le
// vérificateur Go de CT-6 est disponible, NOORTRACE_VERIFIER_BIN ou
// construction par verificateur/scripts/construire.sh).
//
// Épreuve (brief du lot D) : ancrer un point de contrôle (empreinte d'EX-9.1,
// docType du point), attendre le reçu, capturer (CP-1 à CP-6), lookup, puis
// ancrer une seconde fois la même empreinte sous une autre clé et obtenir
// empreinte_squattee (EX-9.7) ; ancrer une période et la clore (submitPeriod,
// CT-4 §8.2) ; vérifier l'index de capture contre son schéma.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { sha256, sha256Hex, utf8, hexVersOctets, signerEip191, adresseDepuisClePrivee } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

const RACINE = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const IDENTIFIANTS = Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`]));
const EVM = 2124;
const BFT = "noortrace-2124-dev";

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

/** Attente réelle, injectée dans l'Envoyeur (règle 2 d'INTERFACES.md : jamais de minuterie dans src/). */
const attendre = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const horloge = { murale: () => Date.now(), monotone: () => Number(process.hrtime.bigint() / 1000000n) };

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS, delaiMs: 3000, identifiants: IDENTIFIANTS });
  try {
    const c = await rpc.appeler("eth_chainId", []);
    if (c.erreur || c.resultat !== "0x84c") return { ok: false, condition: `le réseau de développement ne répond pas eth_chainId 0x84c sur ${POINTS[0]} (bash chain/scripts/dev-net.sh start)` };
    const m = await rpc.appeler("noor_getCommitCertificate", ["latest"]);
    if (m.erreur && m.erreur.code === -32601) return { ok: false, condition: "le binaire noorcore ne sert pas noor_getCommitCertificate (CT-4 §9.1)" };
    for (const p of POINTS.slice(1)) {
      const r = await rpc.appeler("eth_chainId", [], { point: p });
      if (r.erreur || r.resultat !== "0x84c") return { ok: false, condition: `le validateur ${p} ne répond pas (quatre validateurs attendus)` };
    }
    return { ok: true, condition: null, rpc };
  } catch (e) {
    return { ok: false, condition: `le réseau de développement n'est pas debout (${e.message}) : bash chain/scripts/dev-net.sh start` };
  }
}

function binaireGo(travail) {
  const prebuilt = process.env.NOORTRACE_VERIFIER_BIN ?? null;
  if (prebuilt && fs.existsSync(prebuilt)) return prebuilt;
  const dirGo = process.env.NOORTRACE_GO_BIN ?? null;
  const env = { ...process.env, GOTOOLCHAIN: "local", GOFLAGS: "-mod=vendor" };
  if (dirGo) env.PATH = `${dirGo}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  if (v.status !== 0 || !/go1\.27\.3 /.test(v.stdout)) return null;
  const sortie = path.join(travail, "noortrace-verifier");
  const r = spawnSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-o", sortie], { env, cwd: path.join(RACINE, "verificateur"), encoding: "utf8" });
  return r.status === 0 ? sortie : null;
}

/** Le répertoire d'un parcours (NOORTRACE_PARCOURS_REGISTRE), ou un parcours exécuté ici comme une boîte noire. */
function parcours(travail) {
  const donne = process.env.NOORTRACE_PARCOURS_REGISTRE ?? null;
  if (donne && fs.existsSync(path.join(donne, "cles", "cle-chaine-rec-demo-01.cle"))) return { ok: true, repertoire: donne };
  const go = binaireGo(travail);
  if (!go) return { ok: false, condition: "aucun parcours d'inscription (NOORTRACE_PARCOURS_REGISTRE) et vérificateur Go de CT-6 indisponible pour exécuter npm run e2e:registre" };
  const sortie = path.join(travail, "parcours");
  const r = spawnSync("npm", ["run", "e2e:registre", "--", "--garder-reseau", "--sortie", sortie, "--verificateur-go", go], { cwd: RACINE, encoding: "utf8", timeout: 600000 });
  if (r.status !== 0) return { ok: false, condition: `le parcours npm run e2e:registre a échoué (code ${r.status})` };
  return { ok: true, repertoire: sortie };
}

/** Attend que chaque validateur ait atteint la hauteur `h` (au plus 20 s). */
async function tousAuBloc(rpc, h) {
  for (const point of POINTS) {
    for (let k = 0; k < 200; k++) {
      const r = await rpc.appeler("eth_blockNumber", [], { point });
      if (!r.erreur && Number(BigInt(r.resultat)) >= h) break;
      await attendre(100);
    }
  }
}

describe("ancrage, lot D : réseau de développement (CT-5 §9 ; CT-4 §8.2, §8.6, §9.4)", function () {
  this.timeout(900000);
  let travail;
  let ctx = null;

  before(async function () {
    travail = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-registre-reseau-"));
    const reseau = await reseauDebout();
    if (!reseau.ok) { ctx = { condition: reseau.condition }; return; }
    const p = parcours(travail);
    if (!p.ok) { ctx = { condition: p.condition }; return; }
    const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
    const cles = lireJson(path.join(p.repertoire, "cles", "cles-essai.json"));
    const inscription = lireJson(path.join(p.repertoire, "demande-inscription.json"));
    const cle = R.SignataireChaineFichier.depuisOctets(new Uint8Array(fs.readFileSync(path.join(p.repertoire, "cles", "cle-chaine-rec-demo-01.cle"))));
    const approbateurs = [1, 2, 3].map((k) => R.SignataireChaineFichier.depuisOctets(new Uint8Array(fs.readFileSync(path.join(p.repertoire, "cles", `approbateur-${k}.cle`)))));
    expect(cle.adresse()).to.equal(cles.recorders[0].chain_key);
    // Jeu de validateurs : celui que le réseau charge (chain/runtime/validators.json), sinon sa copie publique.
    const fichierJeu = [path.join(RACINE, "chain", "runtime", "validators.json"), path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json")].find((f) => fs.existsSync(f));
    const jeux = { ...lireJson(fichierJeu), source: "validators.json du réseau de développement, clés publiques seulement" };
    const deploiement = lireJson(path.join(RACINE, "deployments", "noorcore.json"));
    const contrats = {
      attestation_registry: deploiement.contrats.AttestationRegistry.adresse.toLowerCase(),
      period_registry: deploiement.contrats.PeriodRegistry.adresse.toLowerCase(),
      recorder_registry: deploiement.contrats.RecorderRegistry.adresse.toLowerCase(),
    };
    const repertoire = path.join(travail, "captures");
    const journal = [];
    const envoyeur = new R.Envoyeur({
      rpc: reseau.rpc, repertoireEnvois: repertoire, horloge, attendre,
      instance: { evmChainId: EVM, bftChainId: BFT, contrats, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux },
      delais: { recuMs: 60000, sondageMs: 250 }, journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }),
    });
    // Le tiers : le compte Hardhat 0 (déployeur du réseau de développement, approvisionné, clé publique de test).
    const constantes = lireJson(path.join(RACINE, "spec", "vecteurs", "ct-4", "constantes.json"));
    const tiers = new R.SignataireChaineFichier(hexVersOctets(constantes.accounts[0].private_key));
    ctx = {
      rpc: reseau.rpc, envoyeur, repertoire, jeux, contrats, cle, tiers, approbateurs, journal,
      orgId: inscription.fields.org_id, journalId: inscription.fields.journal_id, clePublique: inscription.fields.ed25519_public_key,
      seuil: inscription.signer_set.threshold, membres: cles.approvers.map((a) => a.toLowerCase()),
      etiquette: `${Date.now()}`,
    };
  });

  after(function () {
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      enAttente(this, ctx?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("ancre un point de contrôle (EX-9.1, EX-9.3) : reçu, capture CP-1 à CP-6, index conforme au schéma, lookup rend l'émetteur et le docType du point (AN-44 à AN-48)", async function () {
    if (!pret.call(this)) return;
    const objet = sha256Hex(utf8(`noortrace/ancrage/essai-reseau/point/${ctx.etiquette}`));
    const r = await ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.cle, clePublique: ctx.clePublique });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    expect(r.data.request_id).to.equal(`ancre_registre_point:${objet}`);
    // Les relectures qui suivent se font sur le premier point : on attend que chaque validateur ait le bloc (retard d'environ une seconde
    // observé sur le réseau de développement).
    await tousAuBloc(ctx.rpc, r.data.block_number);
    const empreinte = R.empreinteAncre(ctx.orgId, ctx.journalId, objet).fingerprint;
    const index = JSON.parse(fs.readFileSync(path.join(ctx.repertoire, r.outputs.capture), "utf8"));
    expect(R.verifierIndexCapture(index).valide, JSON.stringify(R.verifierIndexCapture(index).erreurs)).to.equal(true);
    expect(index.checks.map((c) => c.status)).to.deep.equal(Array(6).fill("reussi"));
    // La capture est faite auprès du validateur qui a servi le reçu le premier (les quatre sont des validateurs, CP-1).
    expect(POINTS).to.include(index.node.rpc);
    expect(index.node.validator_id).to.equal(IDENTIFIANTS[index.node.rpc]);
    expect(index.bft_chain_id).to.equal(BFT);
    expect(sha256Hex(new Uint8Array(fs.readFileSync(path.join(ctx.repertoire, r.outputs.capture))))).to.equal(r.data.capture_sha256);
    const v = R.verifierCapture({ fichiers: ctx.repertoire, index, jeux: ctx.jeux, bftChainId: BFT });
    expect(v.premierEchec, JSON.stringify(v.checks)).to.equal(null);
    expect(R.decoderJournal("ancre", v.journal)).to.deep.equal({ name: "Anchored", fingerprint: empreinte, issuer: ctx.cle.adresse(), docType: R.DOC_TYPE_POINT_DE_CONTROLE });
    expect(BigInt(r.outputs.gas_used)).to.be.at.most(96977n, "AN-47 : gasUsed ≤ 96 977");
    expect(r.outputs.cost_wei).to.equal(r.outputs.gas_used, "EX-8.17 : 1 wei par gaz");
    // lookup et recorderOf par eth_call (OP-9, AN-46).
    const l = await R.lookup({ rpc: ctx.rpc, contrat: ctx.contrats.attestation_registry, fingerprint: empreinte });
    expect(l.anchored).to.equal(true);
    expect(l.issuer).to.equal(ctx.cle.adresse());
    expect(l.docType).to.equal(R.DOC_TYPE_POINT_DE_CONTROLE);
    expect(l.revokedAt).to.equal(0n);
    const inscrit = await R.recorderOf({ rpc: ctx.rpc, contrat: ctx.contrats.recorder_registry, orgId: ctx.orgId, chainKey: ctx.cle.adresse() });
    expect(inscrit.ed25519PubKey).to.equal(ctx.clePublique);
    expect(inscrit.revokedAt).to.equal(0n);
    expect(await R.isActiveRecorder({ rpc: ctx.rpc, contrat: ctx.contrats.recorder_registry, orgId: ctx.orgId, chainKey: ctx.cle.adresse() })).to.equal(true);
    // Seconde ancre de la même empreinte par la même clé : idempotente (EX-9.3).
    const r2 = await ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.cle });
    expect(r2.type).to.equal("inclusion_registre");
    expect(r2.data).to.deep.equal(r.data);
    ctx.point = { objet, empreinte, inclusion: r };
  });

  it("empreinte prise par un tiers : la clé de chaîne inscrite obtient empreinte_squattee sans nouvel essai, lookup consigné (EX-9.7, CT-4 §8.3, EX-8.6) ; course perdue à l'inclusion : empreinte_squattee aussi", async function () {
    if (!pret.call(this)) return;
    const objet = sha256Hex(utf8(`noortrace/ancrage/essai-reseau/squat/${ctx.etiquette}`));
    const empreinte = R.empreinteAncre(ctx.orgId, ctx.journalId, objet).fingerprint;
    // Le tiers voit l'empreinte et l'ancre le premier (compte approvisionné, hors du registre des enregistreurs).
    const squat = await ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.tiers, sansInscription: true });
    expect(squat.type, JSON.stringify(squat)).to.equal("inclusion_registre");
    // Les validateurs ne commettent pas tous un bloc au même instant : on attend que chacun ait atteint la hauteur du squat,
    // pour que la lecture d'OP-9 (faite sur le premier point) voie l'empreinte prise.
    await tousAuBloc(ctx.rpc, squat.data.block_number);
    const envoisAvant = fs.readdirSync(ctx.repertoire).filter((n) => n.startsWith("envoi-")).length;
    const r = await ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.cle, clePublique: ctx.clePublique });
    expect(r.type).to.equal("echec_registre");
    expect(r.data).to.deep.equal({ request_id: `ancre_registre_point:${objet}`, code: "empreinte_squattee" });
    expect(r.outputs.lookup.issuer).to.equal(ctx.tiers.adresse());
    expect(fs.readdirSync(ctx.repertoire).filter((n) => n.startsWith("envoi-")).length).to.equal(envoisAvant, "aucun envoi");
    const l = await R.lookup({ rpc: ctx.rpc, contrat: ctx.contrats.attestation_registry, fingerprint: empreinte });
    expect(l.issuer).to.equal(ctx.tiers.adresse());
    // Course à l'inclusion : le tiers et la clé inscrite envoient tous deux une ancre de la même empreinte neuve ; la lecture
    // d'OP-9 de la seconde précède l'inclusion de la première. La perdante est refusée par le contrat (status 0x0) et requalifiée
    // empreinte_squattee par la relecture de lookup (CT-4 §8.3), jamais par le texte du refus (EX-5.12).
    const objet2 = sha256Hex(utf8(`noortrace/ancrage/essai-reseau/course/${ctx.etiquette}`));
    const [a, b] = await Promise.all([
      ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet: objet2, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.tiers, sansInscription: true }),
      ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet: objet2, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: ctx.cle }),
    ]);
    const types = [a.type, b.type].sort();
    expect(types[0] === "echec_registre" || types.join() === "inclusion_registre,inclusion_registre").to.equal(true, JSON.stringify([a, b]));
    const perdante = [a, b].find((x) => x.type === "echec_registre");
    if (perdante) {
      expect(["empreinte_squattee", "transaction_annulee"]).to.include(perdante.data.code);
      if (perdante.data.code === "empreinte_squattee" && perdante.outputs.transaction_hash) expect(perdante.outputs.block_number).to.be.a("number");
    }
    // Même attente que pour le squat : la lecture d'OP-9 se fait sur le premier point, qui peut n'avoir pas encore le bloc (observé : une
    // seconde de retard sur le réseau de développement).
    const hauteurs = [a, b].map((x) => x.data?.block_number ?? x.outputs?.block_number).filter((h) => Number.isSafeInteger(h));
    if (hauteurs.length) await tousAuBloc(ctx.rpc, Math.max(...hauteurs));
    const l2 = await R.lookup({ rpc: ctx.rpc, contrat: ctx.contrats.attestation_registry, fingerprint: R.empreinteAncre(ctx.orgId, ctx.journalId, objet2).fingerprint });
    expect(l2.anchored).to.equal(true);
  });

  it("ancre d'une période puis clôture (CT-4 §8.2, EX-8.4) : submitPeriod signé au seuil par les approbateurs du parcours, capture de rôle cloture, continuité avec la période précédente", async function () {
    if (!pret.call(this)) return;
    // Période suivante de celle que le parcours a close : continuité de temps et de séquence (OP-10).
    const dernier = await R.latestPeriodOf({ rpc: ctx.rpc, contrat: ctx.contrats.period_registry, orgId: ctx.orgId, journalId: ctx.journalId });
    expect(dernier > 0n).to.equal(true, "le parcours a clos une première période");
    const precedente = await R.getPeriod({ rpc: ctx.rpc, contrat: ctx.contrats.period_registry, id: dernier });
    const periodHash = sha256Hex(utf8(`noortrace/ancrage/essai-reseau/periode/${ctx.etiquette}`));
    const periodMeta = {
      org_id: ctx.orgId, journal_id: ctx.journalId, period_hash: periodHash, root: sha256Hex(utf8(`racine/${ctx.etiquette}`)),
      period_start: precedente.periodEnd.toString(), period_end: (precedente.periodEnd + 3600n).toString(),
      first_seq: (precedente.lastSeq + 1n).toString(), last_seq: (precedente.lastSeq + 3n).toString(), version: 0, uri: "",
    };
    expect(R.verifierPeriodMeta(periodMeta).statut).to.equal("reussi");
    // Sans ancre incluse et capturée : refus (EX-8.4).
    const sansAncre = await ctx.envoyeur.clore({ periodMeta, signatures: [], cle: ctx.cle });
    expect(sansAncre.data.code).to.equal("ancre_manquante");
    const ancre = await ctx.envoyeur.ancrer({ orgId: ctx.orgId, journalId: ctx.journalId, objet: periodHash, docType: R.DOC_TYPE_PERIODE, cle: ctx.cle, clePublique: ctx.clePublique });
    expect(ancre.type, JSON.stringify(ancre)).to.equal("inclusion_registre");
    expect(ancre.data.request_id).to.equal(`ancre_registre_periode:${periodHash}`);
    await tousAuBloc(ctx.rpc, ancre.data.block_number);
    // Condensé de clôture recalculé (RG-6), signé par deux approbateurs (seuil), rangé par adresse (RG-13).
    const condense = R.periodDigest(EVM, ctx.contrats.period_registry, periodMeta);
    const hachage = R.hachageSigne(condense);
    const signatures = ctx.approbateurs.slice(0, ctx.seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hachage) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
    const r = await ctx.envoyeur.clore({ periodMeta, signatures, cle: ctx.cle, membres: ctx.membres, seuil: ctx.seuil });
    expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
    const index = JSON.parse(fs.readFileSync(path.join(ctx.repertoire, r.outputs.capture), "utf8"));
    expect(index.role).to.equal("cloture");
    expect(R.verifierIndexCapture(index).valide).to.equal(true);
    const v = R.verifierCapture({ fichiers: ctx.repertoire, index, jeux: ctx.jeux, bftChainId: BFT });
    expect(v.premierEchec, JSON.stringify(v.checks)).to.equal(null);
    const journal = R.decoderJournal("cloture", v.journal);
    expect(journal.periodHash).to.equal(periodHash);
    expect(journal.firstSeq).to.equal(precedente.lastSeq + 1n);
    expect(journal.publisher).to.equal(ctx.cle.adresse());
    // Relecture d'état (OP-12, déclarative) : la période est connue et dernière du journal, une fois le bloc chez chaque validateur
    // (la lecture se fait sur le premier point).
    await tousAuBloc(ctx.rpc, r.data.block_number);
    expect(await R.isKnown({ rpc: ctx.rpc, contrat: ctx.contrats.period_registry, orgId: ctx.orgId, periodHash })).to.equal(true);
    const encore = await ctx.envoyeur.clore({ periodMeta, signatures, cle: ctx.cle });
    expect(encore.type).to.equal("inclusion_registre");
    expect(encore.data).to.deep.equal(r.data);
    ctx.periode = { periodHash, ancre, cloture: r };
  });

  it("export des parties depuis les captures de l'essai : registre.json (ancre, clôture, ancre_point_de_controle), certificat-commit.json, validateurs.json conformes à leurs schémas", async function () {
    if (!pret.call(this)) return;
    if (!ctx.point || !ctx.periode) { enAttente(this, "les essais précédents n'ont pas abouti"); return; }
    const captures = R.listerCaptures(ctx.repertoire);
    const choix = R.choisirCaptures({
      repertoire: ctx.repertoire, indexes: captures.map((c) => c.index), periodHash: ctx.periode.periodHash,
      fingerprint: R.empreinteAncre(ctx.orgId, ctx.journalId, ctx.periode.periodHash).fingerprint, empreintePoint: ctx.point.empreinte,
    });
    const parties = R.exporterPartiesRegistre({ repertoire: ctx.repertoire, captures: choix, jeux: { sets: [{ from_height: 1, to_height: null, validators: ctx.jeux.validators, source: ctx.jeux.source }] }, source: `réseau de développement ${BFT}, nœud v1, essai du lot D` });
    expect(parties.registre.entries.map((e) => e.role).sort()).to.deep.equal(["ancre", "ancre_point_de_controle", "cloture"]);
    expect(R.verifierRegistreV0(parties.registre).valide).to.equal(true);
    expect(R.verifierCertificatCommitV0(parties.certificatCommit).valide).to.equal(true);
    expect(R.verifierValidateursV0(parties.validateurs).valide).to.equal(true);
    expect(parties.certificatCommit.certificates).to.have.length(3);
    // Aucun secret dans le répertoire des captures.
    for (const n of fs.readdirSync(ctx.repertoire)) expect(fs.readFileSync(path.join(ctx.repertoire, n), "utf8").toLowerCase()).to.not.include("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
    expect(ctx.journal.filter((l) => l.evenement === "registry_included").length).to.be.at.least(4);
  });
});
