import { expect } from "chai";
import { network } from "hardhat";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  CONTRACT_NAMES,
  DOC_TYPE_PERIODE,
  PROJECT_ROOT,
  anchorFingerprint,
  bootstrapOrg,
  deployNoortrace,
  ensureDeployment,
  journalIdOf,
  orgIdOf,
  readDeployment,
  readOrgs,
  signDigest,
  signatairesDuJeuEnPlace,
  writeDeployment,
} from "../scripts/lib/noortrace.mjs";

// LE DÉPLOIEMENT PRODUIT DES CONTRATS LIÉS ENTRE EUX : PeriodRegistry et
// RecorderRegistry pointent sur le CuratorSetRegistry déployé, dont l'admin est
// le déployeur ; les scripts écrivent deployments/<réseau>.json et
// deployments/<réseau>-orgs.json avec adresses et numéros de bloc, sans jamais
// écraser en silence le fichier d'un registre en service ; les outils de l'e2e
// (jeu en place, empreinte d'ancre) sont vérifiés ici aussi.

async function expectRejet(promise, motif) {
  let erreur = null;
  try {
    await promise;
  } catch (e) {
    erreur = e;
  }
  expect(erreur, "une erreur était attendue").to.not.equal(null);
  expect(String(erreur.message)).to.match(motif);
}

function runScript(args, env) {
  const r = spawnSync(process.execPath, args, { cwd: PROJECT_ROOT, env: { ...process.env, ...env }, encoding: "utf8", timeout: 180_000 });
  if (r.status !== 0) throw new Error(`Script en échec (${r.status}) :\n${r.stdout}\n${r.stderr}`);
  return r;
}

describe("Déploiement de NOORTRACE", function () {
  it("deployNoortrace lie PeriodRegistry et RecorderRegistry au CuratorSetRegistry administré par le déployeur", async function () {
    const { ethers } = await network.create();
    const [deployeur] = await ethers.getSigners();
    const { attestationRegistry, curatorSetRegistry, periodRegistry, recorderRegistry, deployment } = await deployNoortrace(ethers, { networkName: "test" });

    const csr = await curatorSetRegistry.getAddress();
    expect(await periodRegistry.curatorSetRegistry()).to.equal(csr);
    expect(await recorderRegistry.curatorSetRegistry()).to.equal(csr);
    expect(await curatorSetRegistry.admin()).to.equal(deployeur.address);
    expect(await attestationRegistry.isAnchored(ethers.ZeroHash)).to.equal(false);

    expect(deployment.reseau).to.equal("test");
    expect(deployment.deployeur).to.equal(deployeur.address);
    for (const name of CONTRACT_NAMES) {
      const c = deployment.contrats[name];
      expect(ethers.isAddress(c.adresse), name).to.equal(true);
      expect(c.bloc, name).to.be.a("number").greaterThan(0);
      expect(c.tx, name).to.match(/^0x[0-9a-f]{64}$/);
      expect(await ethers.provider.getCode(c.adresse)).to.not.equal("0x");
    }
    expect(deployment.bloc).to.equal(deployment.contrats.RecorderRegistry.bloc);
  });

  it("bootstrapOrg déploie un CuratorSet (admin, approbateurs, seuil) et l'assigne à l'organisation", async function () {
    const { ethers } = await network.create();
    const [deployeur] = await ethers.getSigners();
    const { curatorSetRegistry, periodRegistry } = await deployNoortrace(ethers);
    const approbateurs = [ethers.Wallet.createRandom().address, ethers.Wallet.createRandom().address, ethers.Wallet.createRandom().address];

    const { orgId, curatorSet, record } = await bootstrapOrg(ethers, { curatorSetRegistry, admin: deployeur, slug: "assureur-du-lac", approvers: approbateurs, threshold: 2 });
    expect(orgId).to.equal(orgIdOf("assureur-du-lac"));
    expect(await curatorSetRegistry.curatorSetOf(orgId)).to.equal(await curatorSet.getAddress());
    expect(await periodRegistry.curatorSetFor(orgId)).to.equal(await curatorSet.getAddress());
    expect(await curatorSet.admin()).to.equal(deployeur.address);
    expect(await curatorSet.getThreshold()).to.equal(2n);
    expect(await curatorSet.getCuratorCount()).to.equal(3n);
    for (const a of approbateurs) expect(await curatorSet.isCurator(a)).to.equal(true);
    expect(record.seuil).to.equal(2);
    expect(record.bloc).to.be.a("number").greaterThan(0);

    await expectRejet(bootstrapOrg(ethers, { curatorSetRegistry, admin: deployeur, slug: "x", approvers: approbateurs, threshold: 4 }), /seuil invalide/);
    await expectRejet(bootstrapOrg(ethers, { curatorSetRegistry, admin: deployeur, slug: "x", approvers: [], threshold: 1 }), /au moins un approbateur/);
  });

  it("le script deploy-noortrace.mjs écrit deployments/<réseau>.json avec adresses et numéros de bloc", async function () {
    this.timeout(180_000);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-deploy-"));
    const r = runScript([path.join(PROJECT_ROOT, "scripts", "deploy", "deploy-noortrace.mjs"), "--network", "hardhat"], { NOORTRACE_DEPLOYMENTS_DIR: dir });
    const deployment = readDeployment("hardhat", dir);
    expect(deployment, r.stdout).to.not.equal(null);
    expect(deployment.reseau).to.equal("hardhat");
    expect(deployment.chainId).to.equal("31337");
    for (const name of CONTRACT_NAMES) {
      expect(deployment.contrats[name].adresse).to.match(/^0x[0-9a-fA-F]{40}$/);
      expect(deployment.contrats[name].bloc).to.be.a("number").greaterThan(0);
    }
    expect(r.stdout).to.include("Fichier de déploiement");
  });

  it("writeDeployment refuse d'écraser un fichier existant sans --force, et l'archive avec", async function () {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-write-"));
    const contrats = (suffixe) => Object.fromEntries(CONTRACT_NAMES.map((n, i) => [n, { adresse: `0x${String(i + 1).padStart(39, "0")}${suffixe}`, bloc: 1, tx: "0x" + "0".repeat(64) }]));
    const v1 = { reseau: "recette", chainId: "2124", deployeur: "0x" + "1".repeat(40), horodatage: "2026-10-21T10:43:54.486Z", bloc: 1, contrats: contrats("a") };
    const v2 = { ...v1, horodatage: "2026-10-21T11:00:00.000Z", contrats: contrats("b") };
    writeDeployment(v1, dir);
    expect(() => writeDeployment(v2, dir)).to.throw(/existe déjà.*--force/);
    expect(readDeployment("recette", dir).horodatage).to.equal(v1.horodatage, "le fichier d'origine est intact");

    const journal = [];
    writeDeployment(v2, dir, { force: true, log: (l) => journal.push(l) });
    expect(readDeployment("recette", dir).horodatage).to.equal(v2.horodatage);
    const archive = fs.readdirSync(dir).find((f) => /^recette\.2026-10-21T10-43-54-486Z\.json$/.test(f));
    expect(archive, fs.readdirSync(dir).join(", ")).to.not.equal(undefined);
    expect(JSON.parse(fs.readFileSync(path.join(dir, archive), "utf8")).horodatage).to.equal(v1.horodatage);
    expect(journal.some((l) => l.includes("archivé"))).to.equal(true);
    for (const name of CONTRACT_NAMES) expect(journal.some((l) => l.startsWith(`${name} : `) && l.includes("adresse changée")), name).to.equal(true);

    // Sans archive (réseau en mémoire) : remplacé, aucun fichier de plus.
    const avant = fs.readdirSync(dir).length;
    writeDeployment(v1, dir, { force: true, archive: false });
    expect(fs.readdirSync(dir).length).to.equal(avant);
    expect(readDeployment("recette", dir).horodatage).to.equal(v1.horodatage);
  });

  it("ensureDeployment refuse un fichier d'une autre chaîne et l'absence de compte sur un réseau distant", async function () {
    const { ethers } = await network.create();
    const { deployment } = await deployNoortrace(ethers, { networkName: "recette" });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ensure-"));
    // Un fichier copié d'une autre chaîne (chainId 2124) alors que la connexion est sur 31337.
    writeDeployment({ ...deployment, chainId: "2124" }, dir);
    const connDistante = { ethers, networkName: "recette", networkConfig: { type: "http" } };
    await expectRejet(ensureDeployment(connDistante, { dir }), /chainId du réseau recette \(31337\) différent.*\(2124\)/);
    // Le bon chainId, mais aucun compte (NOOR_PRIVATE_KEY absent) : consigne explicite plutôt qu'un TypeError plus loin.
    writeDeployment(deployment, dir, { force: true, archive: false });
    const sansCompte = { ...connDistante, ethers: Object.create(ethers, { getSigners: { value: async () => [] } }) };
    await expectRejet(ensureDeployment(sansCompte, { dir }), /aucun compte de déploiement.*NOOR_PRIVATE_KEY/);
    // Avec un compte, le fichier est rattaché.
    const { periodRegistry, fresh } = await ensureDeployment(connDistante, { dir });
    expect(fresh).to.equal(false);
    expect(await periodRegistry.getAddress()).to.equal(deployment.contrats.PeriodRegistry.adresse);
  });

  it("signatairesDuJeuEnPlace retient les clés membres du jeu assigné, jusqu'au seuil, et refuse en dessous", async function () {
    const { ethers } = await network.create();
    const [deployeur] = await ethers.getSigners();
    const { curatorSetRegistry } = await deployNoortrace(ethers);
    const approbateurs = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
    const { orgId, curatorSet } = await bootstrapOrg(ethers, { curatorSetRegistry, admin: deployeur, slug: "assureur-du-lac", approvers: approbateurs.map((a) => a.address), threshold: 2 });

    const etranger = ethers.Wallet.createRandom();
    const jeu = await signatairesDuJeuEnPlace(ethers, { curatorSetRegistry, orgId, wallets: [etranger, approbateurs[2], approbateurs[0], approbateurs[1]] });
    expect(jeu.curatorSetAddress).to.equal(await curatorSet.getAddress());
    expect(jeu.threshold).to.equal(2);
    expect(jeu.signataires.map((w) => w.address)).to.deep.equal([approbateurs[2].address, approbateurs[0].address]);

    await expectRejet(signatairesDuJeuEnPlace(ethers, { curatorSetRegistry, orgId, wallets: [etranger, approbateurs[0]] }), /Il faut 2 clé\(s\).*1 fournie\(s\)/);
    await expectRejet(signatairesDuJeuEnPlace(ethers, { curatorSetRegistry, orgId: orgIdOf("inconnue"), wallets: approbateurs }), /aucun jeu assigné/);
  });

  it("anchorFingerprint : deux périodes de même racine s'ancrent toutes les deux, la racine nue ne s'ancrerait qu'une fois", async function () {
    const { ethers } = await network.create();
    const { attestationRegistry } = await deployNoortrace(ethers);
    const enregistreur = ethers.Wallet.createRandom();
    const orgId = orgIdOf("assureur-du-lac");
    const journalId = journalIdOf("journal-principal");
    const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));
    const ancrer = async (fingerprint) => {
      const d = await attestationRegistry.anchorDigest(fingerprint, DOC_TYPE_PERIODE);
      return attestationRegistry.anchor(fingerprint, DOC_TYPE_PERIODE, enregistreur.address, await signDigest(enregistreur, d));
    };
    // Deux heures vides (racine nulle) ou aux événements identiques : même racine, empreintes distinctes.
    const e1 = anchorFingerprint({ orgId, journalId, periodHash: h("manifeste-heure-1") });
    const e2 = anchorFingerprint({ orgId, journalId, periodHash: h("manifeste-heure-2") });
    expect(e1).to.not.equal(e2);
    expect(e1).to.equal(ethers.keccak256(ethers.concat([orgId, journalId, h("manifeste-heure-1")])));
    await (await ancrer(e1)).wait();
    await (await ancrer(e2)).wait();
    expect((await attestationRegistry.lookup(e2)).issuer).to.equal(enregistreur.address);
    // La racine nue, elle, ne s'ancre qu'une fois pour toute la chaîne, et jamais nulle.
    const racine = h("racine-repetee");
    await (await ancrer(racine)).wait();
    await expect(ancrer(racine)).to.be.revertedWithCustomError(attestationRegistry, "AlreadyAnchored");
    await expect(ancrer(ethers.ZeroHash)).to.be.revertedWithCustomError(attestationRegistry, "BadFingerprint");
  });

  it("le script e2e dev-roundtrip.mjs réussit en mémoire et ancre l'empreinte de la période", async function () {
    this.timeout(180_000);
    const r = runScript([path.join(PROJECT_ROOT, "scripts", "e2e", "dev-roundtrip.mjs"), "--network", "hardhat"], {});
    const resultat = JSON.parse(r.stdout);
    expect(resultat.succes, r.stderr).to.equal(true);
    expect(resultat.organisation.amorcee).to.equal(true);
    expect(resultat.organisation.slug).to.match(/^e2e-\d+$/);
    const { orgId } = resultat.organisation;
    const { journalId } = resultat.enregistreur;
    expect(resultat.ancre.empreinte).to.equal(anchorFingerprint({ orgId, journalId, periodHash: resultat.periode.periodHash }));
    expect(resultat.ancre.empreinte).to.not.equal(resultat.ancre.root);
    expect(resultat.periode.getPeriod.firstSeq).to.equal("1");
  });

  it("le script bootstrap-org.mjs écrit deployments/<réseau>-orgs.json", async function () {
    this.timeout(180_000);
    const { ethers } = await network.create();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-orgs-"));
    const approbateurs = [ethers.Wallet.createRandom().address, ethers.Wallet.createRandom().address, ethers.Wallet.createRandom().address];
    runScript(
      [path.join(PROJECT_ROOT, "scripts", "deploy", "bootstrap-org.mjs"), "--org", "assureur-du-lac", "--approvers", approbateurs.join(","), "--threshold", "2", "--network", "hardhat"],
      { NOORTRACE_DEPLOYMENTS_DIR: dir },
    );
    const orgs = readOrgs("hardhat", dir);
    expect(orgs.reseau).to.equal("hardhat");
    const org = orgs.organisations["assureur-du-lac"];
    expect(org.orgId).to.equal(orgIdOf("assureur-du-lac"));
    expect(org.curatorSet).to.match(/^0x[0-9a-fA-F]{40}$/);
    expect(org.approbateurs).to.deep.equal(approbateurs);
    expect(org.seuil).to.equal(2);
    expect(org.bloc).to.be.a("number").greaterThan(0);
  });
});
