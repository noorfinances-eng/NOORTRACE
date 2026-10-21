import { expect } from "chai";
import { network } from "hardhat";
import { journalIdOf, orgIdOf, registerDigest, revokeDigest, signDigestBy, signRawDigest } from "../scripts/lib/noortrace.mjs";

// LE REGISTRE DES CLÉS D'ENREGISTREUR.
//
// L'enregistreur déployé chez le client signe les événements en Ed25519 et les
// ancres avec une clé de chaîne. Le registre publie, par organisation, quelles
// clés valent et depuis quand. L'inscription et la révocation sont autorisées
// par signatures au seuil du jeu d'approbateurs de l'organisation, et chaque
// condensé porte sa propre étiquette : une inscription ne révoque jamais. Le
// condensé de révocation est lié à l'inscription qu'il vise (registeredAt), et
// une clé Ed25519 n'est active que sous une clé de chaîne à la fois.

describe("RecorderRegistry", function () {
  async function deploy() {
    const { ethers } = await network.create();
    const [admin, relais, enregistreur] = await ethers.getSigners();
    const approbateurs = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
    const orgA = orgIdOf("assureur-du-lac");
    const orgB = orgIdOf("banque-des-cimes");
    const journal = journalIdOf("journal-principal");
    const pubKey = ethers.keccak256(ethers.toUtf8Bytes("cle-ed25519-de-test"));

    const CuratorSet = await ethers.getContractFactory("CuratorSet");
    const setA = await CuratorSet.deploy(admin.address, approbateurs.map((a) => a.address), 2);
    const setB = await CuratorSet.deploy(admin.address, approbateurs.map((a) => a.address), 2);
    await setA.waitForDeployment();
    await setB.waitForDeployment();

    const CuratorSetRegistry = await ethers.getContractFactory("CuratorSetRegistry");
    const setRegistry = await CuratorSetRegistry.deploy(admin.address);
    await setRegistry.waitForDeployment();
    await (await setRegistry.setCuratorSet(orgA, await setA.getAddress())).wait();
    await (await setRegistry.setCuratorSet(orgB, await setB.getAddress())).wait();

    const RecorderRegistry = await ethers.getContractFactory("RecorderRegistry");
    const registry = await RecorderRegistry.deploy(await setRegistry.getAddress());
    const registre2 = await RecorderRegistry.deploy(await setRegistry.getAddress());
    await registry.waitForDeployment();
    await registre2.waitForDeployment();

    const chainId = (await ethers.provider.getNetwork()).chainId;
    const sigsInscription = async (wallets, { orgId = orgA, journalId = journal, chainKey = enregistreur.address, ed25519PubKey = pubKey, reg = registry } = {}) =>
      signDigestBy(wallets, await reg.registerDigest(orgId, journalId, chainKey, ed25519PubKey));
    const sigsRevocation = async (wallets, { orgId = orgA, chainKey = enregistreur.address, reg = registry } = {}) =>
      signDigestBy(wallets, await reg.revokeDigest(orgId, chainKey));
    const inscrire = async (wallets = approbateurs, over = {}) =>
      registry
        .connect(relais)
        .registerRecorder(over.orgId ?? orgA, over.journalId ?? journal, over.chainKey ?? enregistreur.address, over.ed25519PubKey ?? pubKey, await sigsInscription(wallets, over));

    return { ethers, admin, relais, enregistreur, approbateurs, orgA, orgB, journal, pubKey, setA, setRegistry, registry, registre2, chainId, sigsInscription, sigsRevocation, inscrire };
  }

  it("les condensés donnés par le contrat sont ceux que le client recalcule", async function () {
    const { registry, chainId, orgA, journal, enregistreur, pubKey, inscrire } = await deploy();
    const address = await registry.getAddress();
    expect(await registry.registerDigest(orgA, journal, enregistreur.address, pubKey)).to.equal(
      registerDigest({ chainId, registry: address, orgId: orgA, journalId: journal, chainKey: enregistreur.address, ed25519PubKey: pubKey }),
    );
    // Avant l'inscription, le condensé de révocation porte registeredAt = 0.
    expect(await registry.revokeDigest(orgA, enregistreur.address)).to.equal(revokeDigest({ chainId, registry: address, orgId: orgA, chainKey: enregistreur.address, registeredAt: 0n }));
    // Les deux étiquettes diffèrent : une inscription et une révocation ne se confondent pas.
    expect(await registry.registerDigest(orgA, journal, enregistreur.address, pubKey)).to.not.equal(await registry.revokeDigest(orgA, enregistreur.address));
    // Après l'inscription, il porte l'instant d'inscription.
    await (await inscrire()).wait();
    const { registeredAt } = await registry.recorderOf(orgA, enregistreur.address);
    expect(registeredAt).to.be.greaterThan(0n);
    expect(await registry.revokeDigest(orgA, enregistreur.address)).to.equal(revokeDigest({ chainId, registry: address, orgId: orgA, chainKey: enregistreur.address, registeredAt }));
  });

  it("inscription : deux approbateurs sur trois, relayés par un tiers ; tout se relit", async function () {
    const { ethers, relais, enregistreur, approbateurs, orgA, journal, pubKey, registry, inscrire } = await deploy();
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(false);
    const tx = await inscrire([approbateurs[1], approbateurs[2]]);
    await expect(tx).to.emit(registry, "RecorderRegistered").withArgs(orgA, enregistreur.address, journal, pubKey, relais.address);
    const rcpt = await tx.wait();
    const bloc = await ethers.provider.getBlock(rcpt.blockNumber);

    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(true);
    expect(await registry.activeRecorderCount(orgA)).to.equal(1n);
    const r = await registry.recorderOf(orgA, enregistreur.address);
    expect(r.chainKey).to.equal(enregistreur.address);
    expect(r.ed25519PubKey).to.equal(pubKey);
    expect(r.journalId).to.equal(journal);
    expect(r.registeredAt).to.equal(BigInt(bloc.timestamp));
    expect(r.revokedAt).to.equal(0n);
  });

  it("une clé inconnue se lit vide et inactive", async function () {
    const { ethers, registry, orgA, enregistreur } = await deploy();
    const r = await registry.recorderOf(orgA, enregistreur.address);
    expect(r.chainKey).to.equal(ethers.ZeroAddress);
    expect(r.ed25519PubKey).to.equal(ethers.ZeroHash);
    expect(r.registeredAt).to.equal(0n);
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(false);
    expect(await registry.activeRecorderCount(orgA)).to.equal(0n);
  });

  it("révocation : au seuil, datée, et la clé n'est plus active", async function () {
    const { ethers, relais, enregistreur, approbateurs, orgA, registry, inscrire, sigsRevocation } = await deploy();
    await (await inscrire()).wait();
    const tx = await registry.connect(relais).revokeRecorder(orgA, enregistreur.address, await sigsRevocation([approbateurs[0], approbateurs[1]]));
    await expect(tx).to.emit(registry, "RecorderRevoked").withArgs(orgA, enregistreur.address, relais.address);
    const rcpt = await tx.wait();
    const bloc = await ethers.provider.getBlock(rcpt.blockNumber);

    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(false);
    expect(await registry.activeRecorderCount(orgA)).to.equal(0n);
    const r = await registry.recorderOf(orgA, enregistreur.address);
    expect(r.revokedAt).to.equal(BigInt(bloc.timestamp));
    expect(r.registeredAt).to.be.greaterThan(0n, "l'historique de la clé reste lisible");
  });

  it("réinscription refusée : une clé révoquée ne revient pas, une clé active ne se réinscrit pas", async function () {
    const { enregistreur, approbateurs, orgA, registry, inscrire, sigsRevocation } = await deploy();
    await (await inscrire()).wait();
    await expect(inscrire()).to.be.revertedWith("RecorderRegistry: cle deja active");
    await (await registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).wait();
    await expect(inscrire()).to.be.revertedWith("RecorderRegistry: cle revoquee");
    // Même avec une autre clé Ed25519 ou un autre journal : la clé de chaîne est brûlée chez cette organisation.
    await expect(inscrire(approbateurs, { ed25519PubKey: journalIdOf("autre-cle"), journalId: journalIdOf("autre-journal") })).to.be.revertedWith("RecorderRegistry: cle revoquee");
  });

  it("révocation pré-signée : une autorisation signée avant l'inscription ne vaut plus après (condensé lié à registeredAt)", async function () {
    const { enregistreur, approbateurs, orgA, registry, inscrire, sigsRevocation } = await deploy();
    const sigsAvant = await sigsRevocation(approbateurs);
    await expect(registry.revokeRecorder(orgA, enregistreur.address, sigsAvant)).to.be.revertedWith("RecorderRegistry: cle inconnue");
    await (await inscrire()).wait();
    // Relayée après l'inscription, l'autorisation périmée est refusée…
    await expect(registry.revokeRecorder(orgA, enregistreur.address, sigsAvant)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(true);
    // … et une révocation signée pour l'inscription en place passe.
    await (await registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).wait();
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(false);
  });

  it("révocation d'une clé inconnue ou déjà révoquée : refusée", async function () {
    const { enregistreur, approbateurs, orgA, registry, inscrire, sigsRevocation } = await deploy();
    await expect(registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).to.be.revertedWith("RecorderRegistry: cle inconnue");
    await (await inscrire()).wait();
    await (await registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).wait();
    await expect(registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).to.be.revertedWith("RecorderRegistry: cle deja revoquee");
  });

  it("seuil : une signature ne suffit pas, un inconnu ne compte pas, un doublon ne compte qu'une fois", async function () {
    const { ethers, enregistreur, approbateurs, orgA, registry, inscrire, sigsInscription, sigsRevocation } = await deploy();
    const inconnu = ethers.Wallet.createRandom();
    await expect(inscrire([approbateurs[0]])).to.be.revertedWith("RecorderRegistry: signatures insuffisantes");
    await expect(inscrire([approbateurs[0], inconnu])).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    const [s] = await sigsInscription([approbateurs[0]]);
    await expect(registry.registerRecorder(orgA, journalIdOf("journal-principal"), enregistreur.address, ethers.keccak256(ethers.toUtf8Bytes("cle-ed25519-de-test")), [s, s])).to.be.revertedWith(
      "RecorderRegistry: seuil non atteint",
    );

    await (await inscrire()).wait();
    await expect(registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation([approbateurs[2]]))).to.be.revertedWith("RecorderRegistry: signatures insuffisantes");
    await expect(registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation([approbateurs[2], inconnu]))).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(true);
  });

  it("une signature sur le condensé nu (sans préfixe EIP-191) est refusée", async function () {
    const { approbateurs, orgA, journal, enregistreur, pubKey, registry } = await deploy();
    const d = await registry.registerDigest(orgA, journal, enregistreur.address, pubKey);
    await expect(registry.registerRecorder(orgA, journal, enregistreur.address, pubKey, [signRawDigest(approbateurs[0], d), signRawDigest(approbateurs[1], d)])).to.be.revertedWith(
      "RecorderRegistry: seuil non atteint",
    );
  });

  it("clé nulle : chainKey, ed25519PubKey, orgId et journalId nuls sont refusés", async function () {
    const { ethers, approbateurs, inscrire } = await deploy();
    await expect(inscrire(approbateurs, { chainKey: ethers.ZeroAddress })).to.be.revertedWith("RecorderRegistry: chainKey=0");
    await expect(inscrire(approbateurs, { ed25519PubKey: ethers.ZeroHash })).to.be.revertedWith("RecorderRegistry: ed25519PubKey=0");
    await expect(inscrire(approbateurs, { orgId: ethers.ZeroHash })).to.be.revertedWith("RecorderRegistry: orgId=0");
    await expect(inscrire(approbateurs, { journalId: ethers.ZeroHash })).to.be.revertedWith("RecorderRegistry: journalId=0");
  });

  it("organisation inconnue : le refus la nomme", async function () {
    const { approbateurs, setRegistry, inscrire } = await deploy();
    const inconnue = orgIdOf("organisation-jamais-enregistree");
    await expect(inscrire(approbateurs, { orgId: inconnue })).to.be.revertedWithCustomError(setRegistry, "UnknownOrganization").withArgs(inconnue);
  });

  it("digest : une signature d'inscription ne révoque pas, et réciproquement", async function () {
    const { enregistreur, approbateurs, orgA, journal, pubKey, registry, inscrire, sigsInscription, sigsRevocation } = await deploy();
    await (await inscrire()).wait();
    await expect(registry.revokeRecorder(orgA, enregistreur.address, await sigsInscription(approbateurs))).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(true);

    // Une signature de révocation ne vaut pas inscription pour une autre clé de chaîne.
    const autre = journalIdOf("autre-journal");
    await expect(registry.registerRecorder(orgA, autre, approbateurs[0].address, journalIdOf("autre-cle-ed25519"), await sigsRevocation(approbateurs))).to.be.revertedWith(
      "RecorderRegistry: seuil non atteint",
    );
    void journal;
    void pubKey;
  });

  it("digest : rejeu sur un autre registre ou une autre organisation refusé", async function () {
    const { enregistreur, approbateurs, orgA, orgB, journal, pubKey, registry, registre2, sigsInscription } = await deploy();
    const sigsPourRegistre1 = await sigsInscription(approbateurs);
    await expect(registre2.registerRecorder(orgA, journal, enregistreur.address, pubKey, sigsPourRegistre1)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    // Les mêmes approbateurs siègent chez B : une signature pour A ne vaut rien pour B.
    await expect(registry.registerRecorder(orgB, journal, enregistreur.address, pubKey, sigsPourRegistre1)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    // Signée pour B, elle passe, et les inscriptions de A et B sont indépendantes.
    await (await registry.registerRecorder(orgB, journal, enregistreur.address, pubKey, await sigsInscription(approbateurs, { orgId: orgB }))).wait();
    expect(await registry.isActiveRecorder(orgB, enregistreur.address)).to.equal(true);
    expect(await registry.isActiveRecorder(orgA, enregistreur.address)).to.equal(false);
    expect(await registry.activeRecorderCount(orgB)).to.equal(1n);
    expect(await registry.activeRecorderCount(orgA)).to.equal(0n);
  });

  it("digest : le relayeur ne peut altérer ni la clé Ed25519, ni le journal, ni la clé de chaîne", async function () {
    const { ethers, enregistreur, approbateurs, orgA, journal, pubKey, registry, sigsInscription } = await deploy();
    const sigs = await sigsInscription(approbateurs);
    const autrePubKey = ethers.keccak256(ethers.toUtf8Bytes("cle-substituee"));
    await expect(registry.registerRecorder(orgA, journal, enregistreur.address, autrePubKey, sigs)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    await expect(registry.registerRecorder(orgA, journalIdOf("autre-journal"), enregistreur.address, pubKey, sigs)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    await expect(registry.registerRecorder(orgA, journal, approbateurs[0].address, pubKey, sigs)).to.be.revertedWith("RecorderRegistry: seuil non atteint");
    await (await registry.registerRecorder(orgA, journal, enregistreur.address, pubKey, sigs)).wait();
    expect((await registry.recorderOf(orgA, enregistreur.address)).ed25519PubKey).to.equal(pubKey);
  });

  it("plusieurs enregistreurs par organisation : le compte des clés actives suit", async function () {
    const { ethers, approbateurs, orgA, registry, inscrire, sigsRevocation } = await deploy();
    const k2 = ethers.Wallet.createRandom().address;
    await (await inscrire()).wait();
    await (await inscrire(approbateurs, { chainKey: k2, ed25519PubKey: journalIdOf("cle-2") })).wait();
    expect(await registry.activeRecorderCount(orgA)).to.equal(2n);
    await (await registry.revokeRecorder(orgA, k2, await sigsRevocation(approbateurs, { chainKey: k2 }))).wait();
    expect(await registry.activeRecorderCount(orgA)).to.equal(1n);
    expect(await registry.isActiveRecorder(orgA, k2)).to.equal(false);
  });

  it("clé Ed25519 : active sous une seule clé de chaîne à la fois, retrouvée par recorderByPubKey, rotation de la clé de chaîne possible", async function () {
    const { ethers, approbateurs, enregistreur, orgA, orgB, journal, pubKey, registry, inscrire, sigsRevocation } = await deploy();
    const k2 = ethers.Wallet.createRandom().address;
    const inconnu = await registry.recorderByPubKey(orgA, pubKey);
    expect(inconnu.chainKey).to.equal(ethers.ZeroAddress);
    expect(inconnu.registeredAt).to.equal(0n);

    await (await inscrire()).wait();
    // La même clé Ed25519 sous une seconde clé de chaîne : refusée tant que la première est active.
    await expect(inscrire(approbateurs, { chainKey: k2 })).to.be.revertedWith("RecorderRegistry: cle Ed25519 deja active");
    expect(await registry.activeRecorderCount(orgA)).to.equal(1n);
    expect((await registry.recorderByPubKey(orgA, pubKey)).chainKey).to.equal(enregistreur.address);
    // L'index est par organisation : chez B, la même clé Ed25519 est libre.
    await (await inscrire(approbateurs, { orgId: orgB })).wait();
    expect((await registry.recorderByPubKey(orgB, pubKey)).chainKey).to.equal(enregistreur.address);

    // Rotation de la clé de chaîne seule : une fois la première révoquée, la clé Ed25519 se réinscrit sous k2.
    await (await registry.revokeRecorder(orgA, enregistreur.address, await sigsRevocation(approbateurs))).wait();
    expect((await registry.recorderByPubKey(orgA, pubKey)).revokedAt).to.be.greaterThan(0n, "l'index désigne la clé de chaîne révoquée");
    await (await inscrire(approbateurs, { chainKey: k2 })).wait();
    const r = await registry.recorderByPubKey(orgA, pubKey);
    expect(r.chainKey).to.equal(k2);
    expect(r.journalId).to.equal(journal);
    expect(r.revokedAt).to.equal(0n);
    expect(await registry.activeRecorderCount(orgA)).to.equal(1n);
  });

  it("le constructeur refuse un registre nul", async function () {
    const { ethers } = await deploy();
    const RecorderRegistry = await ethers.getContractFactory("RecorderRegistry");
    await expect(RecorderRegistry.deploy(ethers.ZeroAddress)).to.be.revertedWith("RecorderRegistry: curatorSetRegistry=0");
  });
});
