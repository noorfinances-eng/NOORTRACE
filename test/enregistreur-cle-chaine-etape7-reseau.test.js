// Étape 7, sur le réseau de développement 2124 (quatre validateurs
// noorcore, `bash chain/scripts/dev-net.sh start`) : parcours de production
// d'un démon `noortrace` réel (processus enfant) dont la clé de chaîne est
// celle du modèle de production corrigé (écart E-11 :
// `deploiement/config/modele-production/configuration.json`, classe C,
// `anchoring.ancrage` désigné), et complément de TE-14 pour JS-5 (rotation de
// la seule clé de chaîne relayée au registre).
//
// - Parcours de production : `recorder.environment` `production`,
//   signataire Ed25519 de classe C (graine enveloppée par AWS KMS),
//   `anchoring.registry.chain_key` du modèle (classe C, `service_url` AWS KMS)
//   dont seuls l'adresse, le chemin du secret et le point RPC sont remplacés
//   par ceux du banc : le scalaire secp256k1 d'essai (mnémonique publique) est
//   enveloppé par le KMS simulé de LocalStack (conteneur épinglé par
//   condensé, point d'accès remplacé par `AWS_ENDPOINT_URL_KMS`) ; journal neuf
//   inscrit par l'outil de référence du registre (boîte noire) sous
//   l'organisation du parcours `npm run e2e:registre`. Le démon démarre,
//   ancre les points et la période sur noorcore sous la clé de classe C,
//   relaie la clôture ; le dossier exporté est vérifié par les deux
//   vérificateurs (contrôles 4 et 8 réussis, émetteur des ancres = clé de
//   classe C).
// - JS-5 (CT-7 §6.1 ; CT-2 EX-11.19 point 4 ; CT-4 §8.4) : demande
//   `rotation-urgence` (celle de `noortrace-ctl cle rotation-urgence`) au même démon, `next_chain_key` de classe B (clé
//   `ECC_SECG_P256K1` du KMS simulé, approvisionnée par l'outil de
//   référence) : révocation de l'ancienne clé de chaîne et inscription de la
//   même clé Ed25519 sous la nouvelle, relayées sur noorcore depuis les
//   demandes signées au seuil par les approbateurs du parcours ; lues au
//   registre ; aucun événement de la chaîne ; ancres suivantes émises par la
//   clé de classe B (signée par le KMS).
//
// Sans réseau 2124, sans Docker ou sans parcours : chaque essai est en
// attente, la condition nommée dans son titre.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import yaml from "js-yaml";
import { ClientKms, contexteChiffrement } from "@noortrace/enregistreur";
import { regionServiceKms } from "../paquets/enregistreur/src/cle-chaine.mjs";
import {
  Demon, repertoireTemporaire, enAttente, RACINE, lireParcours, inscrireJournal, monterDemonReseauReel, demandeClotureParcours, binaireGo,
  fichierAncres, pointDeControleBitcoin, verifierJs, verifierGo, statuts, fichierTemporaire, POINTS_RESEAU_DEV, EVM_RESEAU_DEV,
} from "./fixtures/enregistreur-ancrage/outils.mjs";
import { demarrerKmsLocalStack, dockerEtImage, IMAGES_SIGNATAIRES, arreterConteneurs } from "./fixtures/enregistreur-signataires/outils.mjs";
import {
  cleEssai, indiceExecution, envelopperCleChaine, creerCleKmsSecp256k1, ecrireSecret, demandeInscription, demandeRevocation, deposerDemande, outilsDesEvenements,
} from "./fixtures/enregistreur-cle-chaine/outils.mjs";

const MODELE = path.join(RACINE, "deploiement", "config", "modele-production", "configuration.json");
const PRODUCTION_YAML = path.join(RACINE, "deploiement", "compose", "production.yaml");
const OUTIL_REGISTRE = path.join(RACINE, "scripts", "registre", "noortrace-registre.mjs");

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS_RESEAU_DEV, delaiMs: 3000, identifiants: Object.fromEntries(POINTS_RESEAU_DEV.map((p, k) => [p, `v${k + 1}`])) });
  try {
    for (const p of POINTS_RESEAU_DEV) {
      const c = await rpc.appeler("eth_chainId", [], { point: p });
      if (c.erreur || c.resultat !== "0x84c") return { ok: false, condition: `réseau de développement 2124 absent : le validateur ${p} ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)` };
    }
    return { ok: true, rpc };
  } catch (e) {
    return { ok: false, condition: `réseau de développement 2124 absent (${e.message}) : bash chain/scripts/dev-net.sh start` };
  }
}

function parcours(travail) {
  const donne = process.env.NOORTRACE_PARCOURS_REGISTRE ?? null;
  if (donne && fs.existsSync(path.join(donne, "cles", "cle-chaine-rec-demo-01.cle"))) return { ok: true, repertoire: donne };
  const go = binaireGo();
  if (!go) return { ok: false, condition: "aucun parcours d'inscription (NOORTRACE_PARCOURS_REGISTRE) et vérificateur Go de CT-6 absent pour exécuter npm run e2e:registre" };
  const sortie = path.join(travail, "parcours");
  const r = spawnSync("npm", ["run", "e2e:registre", "--", "--garder-reseau", "--sortie", sortie, "--verificateur-go", go], { cwd: RACINE, encoding: "utf8", timeout: 600000 });
  if (r.status !== 0) return { ok: false, condition: `le parcours npm run e2e:registre a échoué (code ${r.status})` };
  return { ok: true, repertoire: sortie };
}

/** Outil de référence du registre (boîte noire) ; rend la sortie JSON. */
function outilRegistre(args) {
  const r = spawnSync(process.execPath, [OUTIL_REGISTRE, ...args], { cwd: RACINE, encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024 });
  let j = null;
  try {
    j = JSON.parse(r.stdout);
  } catch {
    j = null;
  }
  return { code: r.status, sortie: j, stderr: r.stderr };
}

/**
 * Demande `rotation-urgence` déposée comme `noortrace-ctl cle rotation-urgence`
 * (`<ops_log.path>.rotation-urgence`, SIGURG au démon, CT-2 EX-15.10), mais
 * datée à l'horloge du démon : l'essai a avancé l'horloge hybride du démon
 * au-delà de la clôture de la période, et une demande datée du temps réel y
 * serait périmée (refus `demande_perimee`, 600 s).
 */
function demanderRotation(demon, m) {
  const fichier = `${m.config.supervision.ops_log.path}.rotation-urgence`;
  const demande = { demande: "rotation-urgence", request_id: N.octetsVersHex(N.sha256(N.utf8(`e7-${Date.now()}`))).slice(2, 34), pid: process.pid, at: N.ecrireHorodatage(m.horloge.murale()) };
  fs.writeFileSync(fichier, `${JSON.stringify(demande)}\n`, { mode: 0o600, flag: "wx" });
  process.kill(demon.pid, "SIGURG");
  return demande;
}

describe("étape 7, réseau de développement 2124 : démon en production, clé de chaîne de classe C du modèle de production (table d'IC-14), ancres et clôture sur noorcore, dossier vérifié (contrôles 4 et 8) ; TE-14 complément JS-5 : rotation de la seule clé de chaîne relayée au registre vers une clé de classe B", function () {
  this.timeout(1800000);
  let travail;
  let ctx = null;
  let demon;
  const etat = {};

  before(async function () {
    travail = repertoireTemporaire("noortrace-e7-reseau-");
    const reseau = await reseauDebout();
    if (!reseau.ok) {
      ctx = { condition: reseau.condition };
      return;
    }
    const d = dockerEtImage(IMAGES_SIGNATAIRES.kms);
    if (!d.ok) {
      ctx = { condition: `KMS simulé indisponible : ${d.condition}` };
      return;
    }
    const p = parcours(travail);
    if (!p.ok) {
      ctx = { condition: p.condition };
      return;
    }
    const modele = JSON.parse(fs.readFileSync(MODELE, "utf8"));
    const ckModele = modele.anchoring.registry.chain_key;
    const region = regionServiceKms(ckModele.service_url);
    const kms = await demarrerKmsLocalStack(`noortrace-e7-reseau-kms-${process.pid}`);
    const client = new ClientKms({ region, env: kms.env, delaiMs: 20000 });
    const kmsRegion = { ...kms, client };
    // Clé de chaîne de classe C : scalaire d'essai dérivé de la mnémonique publique, propre à l'exécution (une clé de chaîne
    // ne s'inscrit qu'une fois sur le réseau, qui garde les exécutions précédentes).
    const base = lireParcours(p.repertoire);
    const k = cleEssai(indiceExecution(0));
    const etiquette = `e7-lot-e-${Date.now()}`;
    const journal = inscrireJournal({ parcours: base, travail, etiquette, aleatoire: () => Uint8Array.from(k.octets) });
    if (journal.condition) {
      ctx = { condition: journal.condition, kms };
      return;
    }
    expect(journal.cleChaine.adresse()).to.equal(k.adresse);
    const arnSym = (await client.appeler("CreateKey", { KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT" })).KeyMetadata.Arn;
    const chiffre = await envelopperCleChaine(kmsRegion, arnSym, k.octets, { org_id: journal.orgId, journal_id: journal.journalId, adresse: k.adresse });
    const fichierCle = ecrireSecret(path.join(travail, "secrets-prod"), "cle-chaine", chiffre);
    // Signataire Ed25519 de classe C : la graine du journal neuf, enveloppée sous le contexte (org_id, journal_id, key_id).
    const graineScellee = Buffer.from((await client.appeler("Encrypt", {
      KeyId: arnSym, Plaintext: Buffer.from(journal.graine).toString("base64"),
      EncryptionContext: contexteChiffrement({ org_id: journal.orgId, journal_id: journal.journalId, key_id: journal.recorder.key_id }).carte,
    })).CiphertextBlob, "base64");
    const fichierGraine = ecrireSecret(path.join(travail, "secrets-prod"), "graine-scellee.bin", graineScellee);
    // Clé de chaîne suivante de classe B (JS-5) : clé ECC_SECG_P256K1 du KMS simulé, approvisionnée par l'outil de référence.
    const kmsB = await creerCleKmsSecp256k1(kmsRegion);
    const fichierArn = ecrireSecret(path.join(travail, "secrets-prod"), "cle-chaine-suivante-arn", `${kmsB.arn}\n`);
    const periodStart = Math.floor(Date.now() / 3600000) * 3600;
    const m = await monterDemonReseauReel({
      travail, parcours: journal, baseMs: periodStart * 1000 + 2000, cK: 10, surchargesAncrage: { registry: { checkpoints: "tous", inclusion_alert_s: 120 } },
      surchargesConfig: (c) => {
        c.recorder.environment = "production";
        c.signer = { ...c.signer, class: "C", backend: { type: "envelope", sealed_seed_file: fichierGraine, wrap: { type: "aws-kms", key_arn: arnSym, region } }, rotation: { planned_every_days: null, next_key_id: null } };
        // Membre `anchoring` du modèle de production : seuls l'adresse, le chemin du secret, le point RPC et le chemin du document
        // d'ancrage sont ceux du banc.
        c.anchoring = {
          ...structuredClone(modele.anchoring),
          ancrage: c.anchoring.ancrage,
          registry: {
            ...structuredClone(modele.anchoring.registry), rpc_url: POINTS_RESEAU_DEV[0],
            chain_key: { ...ckModele, address: k.adresse, secret: { file: fichierCle } },
            next_chain_key: { class: "B", address: kmsB.adresse, secret: { file: fichierArn }, service_url: ckModele.service_url },
          },
        };
      },
    });
    if (m.condition) {
      ctx = { condition: m.condition, kms };
      return;
    }
    demon = new Demon(m, { env: kms.env });
    await demon.demarrer();
    ctx = { montage: m, rpc: reseau.rpc, journal, periodStart, kms, k, kmsB, modele };
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await ctx?.montage?.fermer?.();
    ctx?.kms?.arreter?.();
    arreterConteneurs();
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      enAttente(this, ctx?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("modèle de production corrigé (table d'IC-14) : anchoring.ancrage = /etc/noortrace/ancrage.json, monté par production.yaml avec instance-registre.json à côté (lecture 199) ; clé de chaîne de classe C déchiffrée par AWS KMS (service_url en .example, région eu-central-2) ; secret cle-chaine monté ; identité IAM par le secret identite-aws désigné par AWS_CONFIG_FILE ; uri_prefixes du serveur fichiers = répertoire servi par le pont (/srv/pieces)", function () {
    const modele = JSON.parse(fs.readFileSync(MODELE, "utf8"));
    expect(modele.recorder.environment).to.equal("production");
    expect(modele.anchoring.ancrage).to.equal("/etc/noortrace/ancrage.json");
    expect(modele.anchoring.registry.enabled).to.equal(true);
    expect(modele.anchoring.registry.chain_key).to.deep.include({ class: "C", service_url: "https://kms.eu-central-2.amazonaws.example" });
    expect(regionServiceKms(modele.anchoring.registry.chain_key.service_url)).to.equal("eu-central-2");
    expect(modele.anchoring.registry.chain_key.secret).to.deep.equal({ file: "/run/secrets/cle-chaine" });
    const compose = yaml.load(fs.readFileSync(PRODUCTION_YAML, "utf8"));
    const enr = compose.services.enregistreur;
    const cibles = enr.volumes.filter((v) => v.type === "bind").map((v) => [v.source, v.target, v.read_only]);
    expect(cibles).to.deep.include(["./config/production/ancrage.json", "/etc/noortrace/ancrage.json", true]);
    expect(cibles).to.deep.include(["./config/production/instance-registre.json", "/etc/noortrace/instance-registre.json", true]);
    expect(path.dirname("/etc/noortrace/instance-registre.json")).to.equal(path.dirname(modele.anchoring.ancrage));
    expect(enr.secrets).to.include.members(["cle-chaine", "identite-aws"]);
    expect(enr.environment.AWS_CONFIG_FILE).to.equal("/run/secrets/identite-aws");
    expect(compose.secrets["identite-aws"]).to.deep.equal({ file: "./secrets/identite-aws" });
    // Le pont sert /srv/pieces : les URI du serveur fichiers en relèvent.
    expect(compose.services["pont-fichiers"].command).to.include("/srv/pieces");
    expect(compose.services["pont-fichiers"].volumes.map((v) => v.target)).to.include("/srv/pieces");
    expect(modele.policy.servers.fichiers.uri_prefixes).to.deep.equal(["file:///srv/pieces/"]);
  });

  it("démon en production sur noorcore : clé de chaîne de classe C chargée (chain_key_loaded, AWS KMS), clé suivante de classe B ; ancres des points et de la période émises par la clé de classe C et incluses ; clôture submitPeriod relayée ; dossier exporté vérifié par les deux vérificateurs : verdict valide, contrôles 4 et 8 réussis", async function () {
    if (!pret.call(this)) return;
    const { montage: m, periodStart, journal, k, kmsB } = ctx;
    await demon.attendre((l) => l.some((x) => x.event === "anchoring_attached"), 60000, "anchoring_attached");
    expect(demon.de("anchoring_attached")[0].data).to.include({ profile: "production", registry: true });
    const chargees = demon.de("chain_key_loaded").map((l) => l.data);
    expect(chargees).to.have.lengthOf(2);
    expect(chargees[0]).to.include({ member: "chain_key", class: "C", address: k.adresse, service: "aws-kms" });
    expect(chargees[1]).to.include({ member: "next_chain_key", class: "B", address: kmsB.adresse, service: "aws-kms", key_arn: kmsB.arn });
    expect(fs.readFileSync(m.config.supervision.ops_log.path, "utf8")).to.not.include(N.octetsVersHex(k.octets).slice(2));
    const e1 = await demon.evenement(1);
    etat.seqs = [e1.seq];
    await demon.attendre((l) => l.some((x) => x.event === "registry_included"), 180000, "première ancre incluse");
    await demon.avancer(periodStart * 1000 + 1791300 - m.horloge.murale());
    const e2 = await demon.evenement(2);
    etat.seqs.push(e2.seq);
    await demon.attendre((l) => l.some((x) => x.event === "checkpoint_countersigned" && x.data.tree_size === 3), 180000, "point de taille 3 contresigné");
    await demon.avancer((periodStart + 3601) * 1000 - m.horloge.murale());
    await demon.attendre((l) => l.some((x) => x.event === "period_closed" && x.data.period_start === periodStart), 120000, "period_closed");
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped") && l.some((x) => x.event === "period_close_delegated" && x.data.period_start === periodStart), 300000, "ancres de la période");
    const manifeste = JSON.parse(fs.readFileSync(path.join(m.repertoire, "manifestes", `periode-${periodStart}.json`), "utf8"));
    const periodHash = N.hacherManifeste(manifeste);
    const l = await R.lookup({ rpc: ctx.rpc, contrat: journal.contrats.attestation_registry, fingerprint: N.empreinteAncre(journal.orgId, journal.journalId, periodHash) });
    expect(l).to.include({ anchored: true, issuer: k.adresse, docType: R.DOC_TYPE_PERIODE });
    const demande = demandeClotureParcours({ manifeste, parcours: journal, preparedAt: N.ecrireHorodatage(m.horloge.murale()) });
    fs.writeFileSync(path.join(m.repertoire, "registre", `demande-cloture-${periodHash}.json`), JSON.stringify(demande, null, 2));
    await demon.avancer(61000);
    await demon.attendre((lg) => lg.some((x) => x.event === "period_submitted" && x.data.period_start === periodStart), 240000, "period_submitted");
    // Envois relayés par la clé de classe C : expéditeur de chaque envoi.
    const envois = fs.readdirSync(path.join(m.repertoire, "registre")).filter((n) => n.startsWith("envoi-")).map((n) => JSON.parse(fs.readFileSync(path.join(m.repertoire, "registre", n), "utf8")));
    expect(envois.length).to.be.at.least(3);
    expect(envois.every((e) => e.from === k.adresse)).to.equal(true);
    // Dossier de l'événement 2 : exporté et vérifié hors ligne.
    m.calendriers.completer(1010);
    await demon.avancer(61000);
    await demon.attendre((lg) => lg.filter((x) => x.event === "ots_complete").length >= 2 && lg.some((x) => x.event === "bitcoin_headers_written"), 240000, "ots_complete et entetes-bitcoin.json");
    const destination = path.join(travail, "dossier-prod");
    await demon.exporter(e2.seq, destination);
    const ancres = fichierTemporaire("ancres-e7-prod.json");
    fichierAncres({
      chemin: ancres, montage: m, bitcoin: pointDeControleBitcoin(m, 1000),
      recorders: [{ org_id: journal.orgId, journal_id: journal.journalId, key_id: journal.recorder.key_id, public_key: N.octetsVersHex(journal.clePublique), chain_key: k.adresse, source: "journal neuf de l'essai de l'étape 7, clé de chaîne de classe C" }],
    });
    const entetes = path.join(destination, "entetes-bitcoin.json");
    const js = verifierJs(destination, { ancres, entetes });
    expect(js.code, js.stderr).to.equal(0);
    expect(js.rapport.verdict).to.equal("valide");
    const controles = Object.fromEntries(js.rapport.controls.map((c) => [c.number, c.status]));
    expect(controles[4]).to.equal("reussi");
    expect(controles[8]).to.equal("reussi");
    const go = verifierGo(destination, { ancres, entetes });
    if (!go) return enAttente(this, "vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérification JavaScript faite, vérification Go non faite");
    expect(go.code, go.stderr).to.equal(0);
    expect(go.rapport.verdict).to.equal("valide");
    expect(statuts(go.rapport)).to.deep.equal(statuts(js.rapport));
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    etat.periodeClose = true;
  });

  it("TE-14 complément JS-5 : demande rotation-urgence de noortrace-ctl (next_chain_key de classe B, sans signer.rotation.next_key_id) : révocation de l'ancienne clé de chaîne puis inscription de la même clé Ed25519 sous la clé de classe B, relayées sur noorcore depuis les demandes signées au seuil (RecorderRevoked, RecorderRegistered capturés) ; recorderOf : ancienne révoquée, nouvelle active ; aucun événement de la chaîne ne porte la rotation ; les ancres suivantes sont émises par la clé de classe B (signées par le KMS)", async function () {
    if (!pret.call(this)) return;
    if (!etat.periodeClose) return enAttente(this, "parcours de production de l'essai précédent non abouti");
    const { montage: m, journal, k, kmsB } = ctx;
    // Provision de la nouvelle clé de chaîne par l'outil de référence (CT-4 §8.7 : destinataire `fields.chain_key` d'une demande
    // d'inscription, EX-8.20), trésorerie de développement.
    const instance = { evmChainId: EVM_RESEAU_DEV, recorderRegistry: journal.contrats.recorder_registry, orgId: journal.orgId, approbateurs: journal.approbateurs, seuil: journal.seuil, signerSet: journal.inscription.signer_set, preparedAt: N.ecrireHorodatage(Date.now()) };
    const ins = demandeInscription({ ...instance, journalId: journal.journalId, chainKey: kmsB.adresse, ed25519: N.octetsVersHex(journal.clePublique) });
    const fichierIns = path.join(travail, "demande-inscription-b.json");
    fs.writeFileSync(fichierIns, JSON.stringify(ins, null, 2));
    const a = outilRegistre(["approvisionner", "--vers", kmsB.adresse, "--demande", fichierIns, "--tresorerie", "hardhat:0", "--captures", path.join(travail, "captures-approvisionnement")]);
    if (a.code !== 0) return enAttente(this, `approvisionnement de la clé de classe B par l'outil de référence refusé (${a.sortie?.result ?? a.code} : ${a.sortie?.error?.message ?? a.stderr.slice(-200)})`);
    const avant = await R.recorderOf({ rpc: ctx.rpc, contrat: journal.contrats.recorder_registry, orgId: journal.orgId, chainKey: k.adresse });
    expect(avant.revokedAt).to.equal(0n);
    deposerDemande(m.repertoire, demandeRevocation({ ...instance, chainKey: k.adresse, registeredAt: avant.registeredAt }));
    deposerDemande(m.repertoire, ins);
    const outilsAvant = outilsDesEvenements(m.repertoire);
    // `noortrace-ctl cle rotation-urgence` sans péremption : voir `demanderRotation`. La commande elle-même est éprouvée
    // en temps réel par test/enregistreur-journal-soi.test.js (JS-5) et par l'essai sans registre réel de ce lot.
    demanderRotation(demon, m);
    await demon.attendre((l) => l.some((x) => ["key_rotation_emergency", "key_rotation_emergency_refused", "ctl_request_refused"].includes(x.event)), 600000, "réponse de la rotation");
    const refus = [...demon.de("key_rotation_emergency_refused"), ...demon.de("ctl_request_refused")];
    expect(refus, JSON.stringify(refus.at(-1)?.data)).to.have.lengthOf(0);
    expect(demon.de("key_rotation_emergency").at(-1).data).to.deep.include({ chain_key_only: true, old_chain_key: k.adresse, new_chain_key: kmsB.adresse, registry: { revocation: "incluse", inscription: "incluse" } });
    expect(demon.de("chain_key_switched").at(-1).data).to.include({ old_chain_key: k.adresse, new_chain_key: kmsB.adresse });
    const ancienne = await R.recorderOf({ rpc: ctx.rpc, contrat: journal.contrats.recorder_registry, orgId: journal.orgId, chainKey: k.adresse });
    const nouvelle = await R.recorderOf({ rpc: ctx.rpc, contrat: journal.contrats.recorder_registry, orgId: journal.orgId, chainKey: kmsB.adresse });
    expect(ancienne.revokedAt > 0n).to.equal(true);
    expect(nouvelle).to.deep.include({ revokedAt: 0n, ed25519PubKey: N.octetsVersHex(journal.clePublique), journalId: journal.journalId });
    expect(nouvelle.registeredAt > 0n).to.equal(true);
    const captures = fs.readdirSync(path.join(m.repertoire, "registre")).filter((n) => n.startsWith("capture-"));
    for (const role of ["revocation", "inscription"]) {
      const nom = captures.find((n) => n.endsWith(`-${role}.json`));
      expect(nom, role).to.be.a("string");
      const index = JSON.parse(fs.readFileSync(path.join(m.repertoire, "registre", nom), "utf8"));
      expect(R.verifierCapture({ fichiers: path.join(m.repertoire, "registre"), index, jeux: m.registre.manifeste.validator_sets[0], bftChainId: m.registre.bftChainId }).premierEchec, nom).to.equal(null);
    }
    // JS-5 : aucun événement de la chaîne.
    expect(outilsDesEvenements(m.repertoire)).to.deep.equal(outilsAvant);
    // Ancre suivante : émise par la clé de classe B.
    const e = await demon.evenement(1);
    await demon.avancer(11000);
    await demon.attendre((l) => {
      const k0 = l.findIndex((x) => x.event === "chain_key_switched");
      return k0 >= 0 && l.slice(k0 + 1).some((x) => x.event === "registry_included");
    }, 240000, "ancre sous la clé de classe B");
    const envoisB = fs.readdirSync(path.join(m.repertoire, "registre")).filter((n) => n.startsWith("envoi-")).map((n) => JSON.parse(fs.readFileSync(path.join(m.repertoire, "registre", n), "utf8"))).filter((x) => x.from === kmsB.adresse);
    expect(envoisB.length).to.be.at.least(3, "révocation, inscription et au moins une ancre envoyées par la clé de classe B");
    const tx = envoisB.map((x) => R.lireTransaction(x.raw_transaction)).find((t) => t.to === journal.contrats.attestation_registry);
    expect(tx, "transaction anchor de la clé de classe B").to.not.equal(undefined);
    const issuer = "0x" + Buffer.from(tx.data.subarray(80, 100)).toString("hex");
    expect(issuer).to.equal(kmsB.adresse);
    expect(e.seq).to.be.a("number");
  });
});
