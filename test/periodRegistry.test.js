import { expect } from "chai";
import { network } from "hardhat";
import { journalIdOf, orgIdOf, periodDigest, signDigestBy, signRawDigest } from "../scripts/lib/noortrace.mjs";

// LE REGISTRE DES PÉRIODES DE JOURNAL.
//
// Chaque heure, l'enregistreur du client produit un manifeste de période (racine
// de Merkle, bornes de temps et de séquence) ; les approbateurs de l'organisation
// signent sa clôture (EIP-191, au seuil de leur CuratorSet) et n'importe qui
// relaie. Ces tests vérifient que :
//   - le seuil est appliqué contre le jeu de l'organisation, avec des signataires
//     uniques et membres ;
//   - le condensé lie TOUS les champs du manifeste, de sorte qu'un relayeur ne
//     peut enregistrer que ce qui a été signé ;
//   - une signature ne vaut que pour un registre et une organisation ;
//   - les périodes d'un journal se suivent sans trou ni chevauchement, en temps
//     comme en séquence, et une période vide se déclare lastSeq + 1 == firstSeq
//     avec une racine nulle ;
//   - l'unicité d'un periodHash est cloisonnée par organisation, et aucune borne
//     ne peut figer un journal (lastSeq et periodEnd restent sous 2^64 - 1).

describe("PeriodRegistry", function () {
  async function deploy() {
    const { ethers } = await network.create();
    const [admin, relais] = await ethers.getSigners();
    const approbateurs = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
    const orgA = orgIdOf("assureur-du-lac");
    const orgB = orgIdOf("banque-des-cimes");
    const journal = journalIdOf("journal-principal");

    const CuratorSet = await ethers.getContractFactory("CuratorSet");
    const setA = await CuratorSet.deploy(admin.address, approbateurs.map((a) => a.address), 2);
    // Même jeu de personnes chez B : une signature pour A ne doit quand même rien valoir pour B.
    const setB = await CuratorSet.deploy(admin.address, approbateurs.map((a) => a.address), 2);
    await setA.waitForDeployment();
    await setB.waitForDeployment();

    const CuratorSetRegistry = await ethers.getContractFactory("CuratorSetRegistry");
    const setRegistry = await CuratorSetRegistry.deploy(admin.address);
    await setRegistry.waitForDeployment();
    await (await setRegistry.setCuratorSet(orgA, await setA.getAddress())).wait();
    await (await setRegistry.setCuratorSet(orgB, await setB.getAddress())).wait();

    const PeriodRegistry = await ethers.getContractFactory("PeriodRegistry");
    const registry = await PeriodRegistry.deploy(await setRegistry.getAddress());
    const registre2 = await PeriodRegistry.deploy(await setRegistry.getAddress());
    await registry.waitForDeployment();
    await registre2.waitForDeployment();

    const chainId = (await ethers.provider.getNetwork()).chainId;
    const now = BigInt(Math.floor(Date.now() / 1000));
    const h = (s) => ethers.keccak256(ethers.toUtf8Bytes(s));

    const meta = (over = {}) => ({
      orgId: orgA,
      journalId: journal,
      periodHash: h("manifeste-1"),
      root: h("racine-1"),
      periodStart: now,
      periodEnd: now + 3600n,
      firstSeq: 1n,
      lastSeq: 10n,
      version: 1,
      uri: "ipfs://manifeste-1",
      ...over,
    });
    // Signatures de `wallets` sur le condensé du contrat `reg` pour `m`.
    const signer = async (wallets, m, reg = registry) => signDigestBy(wallets, await reg.periodDigest(m));

    return { ethers, admin, relais, approbateurs, orgA, orgB, journal, setA, setB, setRegistry, registry, registre2, chainId, now, h, meta, signer };
  }

  it("le condensé donné par le contrat est celui que le client recalcule (abi.encode du manifeste entier)", async function () {
    const { registry, chainId, meta } = await deploy();
    const m = meta();
    expect(await registry.periodDigest(m)).to.equal(periodDigest({ chainId, registry: await registry.getAddress(), meta: m }));
    // Changer n'importe quel champ change le condensé, y compris l'URI et la version.
    for (const over of [{ uri: "" }, { version: 2 }, { lastSeq: 11n }, { root: meta().periodHash }]) {
      expect(await registry.periodDigest(meta(over))).to.not.equal(await registry.periodDigest(m));
    }
  });

  it("seuil atteint : deux approbateurs sur trois enregistrent la période, et tout se relit", async function () {
    const { ethers, relais, approbateurs, orgA, journal, registry, meta, signer } = await deploy();
    const m = meta();
    const sigs = await signer([approbateurs[0], approbateurs[2]], m);
    const tx = await registry.connect(relais).submitPeriod(m, sigs);
    const rcpt = await tx.wait();
    const bloc = await ethers.provider.getBlock(rcpt.blockNumber);
    // L'événement porte tout ce que getPeriod rend, URI et instant d'enregistrement compris.
    await expect(tx)
      .to.emit(registry, "PeriodSubmitted")
      .withArgs(1n, m.periodHash, orgA, journal, m.root, m.periodStart, m.periodEnd, m.firstSeq, m.lastSeq, m.version, relais.address, m.uri, BigInt(bloc.timestamp));

    expect(await registry.periodCount()).to.equal(1n);
    expect(await registry.latestPeriodId()).to.equal(1n);
    expect(await registry.latestPeriodOf(orgA, journal)).to.equal(1n);
    expect(await registry.isKnown(orgA, m.periodHash)).to.equal(true);
    const p = await registry.getPeriod(1);
    expect(p.orgId).to.equal(orgA);
    expect(p.journalId).to.equal(journal);
    expect(p.periodHash).to.equal(m.periodHash);
    expect(p.root).to.equal(m.root);
    expect(p.periodStart).to.equal(m.periodStart);
    expect(p.periodEnd).to.equal(m.periodEnd);
    expect(p.firstSeq).to.equal(m.firstSeq);
    expect(p.lastSeq).to.equal(m.lastSeq);
    expect(p.publishedAt).to.equal(BigInt(bloc.timestamp));
    expect(p.version).to.equal(m.version);
    expect(p.publisher).to.equal(relais.address);
    expect(p.uri).to.equal(m.uri);
  });

  it("trois signatures valides passent aussi (la boucle s'arrête au seuil)", async function () {
    const { approbateurs, registry, meta, signer } = await deploy();
    const m = meta();
    await (await registry.submitPeriod(m, await signer(approbateurs, m))).wait();
    expect(await registry.periodCount()).to.equal(1n);
  });

  it("seuil non atteint : une seule signature est refusée avant même d'être vérifiée", async function () {
    const { approbateurs, registry, meta, signer } = await deploy();
    const m = meta();
    await expect(registry.submitPeriod(m, await signer([approbateurs[0]], m))).to.be.revertedWith("PeriodRegistry: signatures insuffisantes");
    await expect(registry.submitPeriod(m, [])).to.be.revertedWith("PeriodRegistry: signatures insuffisantes");
  });

  it("signataire hors jeu : un inconnu ne compte pas, même avec le bon préfixe", async function () {
    const { ethers, approbateurs, registry, meta, signer } = await deploy();
    const m = meta();
    const inconnu = ethers.Wallet.createRandom();
    await expect(registry.submitPeriod(m, await signer([approbateurs[0], inconnu], m))).to.be.revertedWith("PeriodRegistry: seuil non atteint");
    await expect(registry.submitPeriod(m, await signer([inconnu, ethers.Wallet.createRandom()], m))).to.be.revertedWith("PeriodRegistry: seuil non atteint");
  });

  it("doublon de signature : la même clé ne vaut qu'une voix", async function () {
    const { approbateurs, registry, meta, signer } = await deploy();
    const m = meta();
    const [s] = await signer([approbateurs[1]], m);
    await expect(registry.submitPeriod(m, [s, s])).to.be.revertedWith("PeriodRegistry: seuil non atteint");
  });

  it("une signature sur le condensé nu (sans préfixe EIP-191) est refusée", async function () {
    const { approbateurs, registry, meta } = await deploy();
    const m = meta();
    const d = await registry.periodDigest(m);
    await expect(registry.submitPeriod(m, [signRawDigest(approbateurs[0], d), signRawDigest(approbateurs[1], d)])).to.be.revertedWith(
      "PeriodRegistry: seuil non atteint",
    );
  });

  it("organisation inconnue : le refus la nomme ; organisation nulle : refus explicite", async function () {
    const { ethers, approbateurs, setRegistry, registry, meta, signer } = await deploy();
    const inconnue = orgIdOf("organisation-jamais-enregistree");
    const m = meta({ orgId: inconnue });
    await expect(registry.submitPeriod(m, await signer(approbateurs, m))).to.be.revertedWithCustomError(setRegistry, "UnknownOrganization").withArgs(inconnue);
    const m0 = meta({ orgId: ethers.ZeroHash });
    await expect(registry.submitPeriod(m0, await signer(approbateurs, m0))).to.be.revertedWith("PeriodRegistry: orgId=0");
  });

  it("journal nul refusé : un journal « 0 » n'existe pas, même implicitement", async function () {
    const { ethers, approbateurs, orgA, registry, meta, signer } = await deploy();
    const m = meta({ journalId: ethers.ZeroHash });
    await expect(registry.submitPeriod(m, await signer(approbateurs, m))).to.be.revertedWith("PeriodRegistry: journalId=0");
    expect(await registry.latestPeriodOf(orgA, ethers.ZeroHash)).to.equal(0n);
  });

  it("periodHash dupliqué : un manifeste déjà connu de l'organisation est refusé, même signé à nouveau et sur un autre journal", async function () {
    const { approbateurs, registry, meta, signer, now } = await deploy();
    const m = meta();
    await (await registry.submitPeriod(m, await signer(approbateurs, m))).wait();
    // Rejeu pur des mêmes signatures.
    await expect(registry.submitPeriod(m, await signer(approbateurs, m))).to.be.revertedWith("PeriodRegistry: doublon");
    // Même empreinte sous un autre journal de la même organisation, avec des bornes libres.
    const m2 = meta({ journalId: journalIdOf("autre-journal"), periodStart: now + 7200n, periodEnd: now + 10800n });
    await expect(registry.submitPeriod(m2, await signer(approbateurs, m2))).to.be.revertedWith("PeriodRegistry: doublon");
  });

  it("l'unicité du periodHash est cloisonnée par organisation : B ne peut pas préempter l'empreinte de A", async function () {
    const { approbateurs, orgA, orgB, journal, registry, meta, signer, now } = await deploy();
    // A prépare sa clôture (empreinte X) et obtient ses signatures.
    const mA = meta();
    const sigsA = await signer(approbateurs, mA);
    // B, avec ses propres approbateurs, enregistre d'abord une période portant la même empreinte X sous son orgId.
    const mB = meta({ orgId: orgB, journalId: journalIdOf("journal-de-b"), periodStart: now + 99n, periodEnd: now + 199n, firstSeq: 7n, lastSeq: 9n });
    await (await registry.submitPeriod(mB, await signer(approbateurs, mB))).wait();
    expect(await registry.isKnown(orgB, mA.periodHash)).to.equal(true);
    expect(await registry.isKnown(orgA, mA.periodHash)).to.equal(false, "l'empreinte de B n'est pas connue chez A");
    // La clôture légitime de A passe : B n'a rien bloqué.
    await (await registry.submitPeriod(mA, sigsA)).wait();
    expect(await registry.isKnown(orgA, mA.periodHash)).to.equal(true);
    expect((await registry.getPeriod(2)).orgId).to.equal(orgA);
    expect(await registry.latestPeriodOf(orgA, journal)).to.equal(2n);
    // Et chez A, l'empreinte est maintenant prise.
    await expect(registry.submitPeriod(mA, sigsA)).to.be.revertedWith("PeriodRegistry: doublon");
  });

  it("periodHash nul, période inversée, séquence inversée : refusés", async function () {
    const { ethers, approbateurs, registry, meta, signer, now } = await deploy();
    const m0 = meta({ periodHash: ethers.ZeroHash });
    await expect(registry.submitPeriod(m0, await signer(approbateurs, m0))).to.be.revertedWith("PeriodRegistry: periodHash=0");
    const mInv = meta({ periodStart: now + 3600n, periodEnd: now });
    await expect(registry.submitPeriod(mInv, await signer(approbateurs, mInv))).to.be.revertedWith("PeriodRegistry: periode invalide");
    const mEgal = meta({ periodStart: now, periodEnd: now });
    await expect(registry.submitPeriod(mEgal, await signer(approbateurs, mEgal))).to.be.revertedWith("PeriodRegistry: periode invalide");
    const mSeq = meta({ firstSeq: 10n, lastSeq: 5n });
    await expect(registry.submitPeriod(mSeq, await signer(approbateurs, mSeq))).to.be.revertedWith("PeriodRegistry: sequence invalide");
  });

  it("bornes hors plage : lastSeq ou periodEnd = 2^64 - 1 refusés par un require nommé, jamais par une panique", async function () {
    const { approbateurs, registry, meta, signer, now, h } = await deploy();
    const max = 2n ** 64n - 1n;
    // S1 : enregistreur à numérotation zéro-based, première heure vide, « lastSeq = firstSeq - 1 » débordé en uint64.
    const s1 = meta({ firstSeq: 0n, lastSeq: max, root: h("arbre-vide") });
    await expect(registry.submitPeriod(s1, await signer(approbateurs, s1))).to.be.revertedWith("PeriodRegistry: lastSeq hors plage");
    const s1b = meta({ firstSeq: 1n, lastSeq: max });
    await expect(registry.submitPeriod(s1b, await signer(approbateurs, s1b))).to.be.revertedWith("PeriodRegistry: lastSeq hors plage");
    // S2 : fin de période au maximum, qu'aucune période ne pourrait suivre.
    const s2 = meta({ periodEnd: max });
    await expect(registry.submitPeriod(s2, await signer(approbateurs, s2))).to.be.revertedWith("PeriodRegistry: periodEnd hors plage");
    // Juste sous la borne, tout passe, et l'écart de séquence qui suit est un refus nommé.
    const ok = meta({ firstSeq: 1n, lastSeq: max - 1n });
    await (await registry.submitPeriod(ok, await signer(approbateurs, ok))).wait();
    const suite = meta({ periodHash: h("manifeste-2"), root: h("racine-2"), periodStart: now + 3600n, periodEnd: now + 7200n, firstSeq: 0n, lastSeq: 0n });
    await expect(registry.submitPeriod(suite, await signer(approbateurs, suite))).to.be.revertedWith("PeriodRegistry: discontinuite de sequence");
  });

  it("continuité de temps : la période suivante commence exactement où la précédente s'arrête", async function () {
    const { approbateurs, registry, meta, signer, now, h } = await deploy();
    const m1 = meta();
    await (await registry.submitPeriod(m1, await signer(approbateurs, m1))).wait();

    const trou = meta({ periodHash: h("manifeste-2"), root: h("racine-2"), periodStart: now + 3601n, periodEnd: now + 7200n, firstSeq: 11n, lastSeq: 20n });
    await expect(registry.submitPeriod(trou, await signer(approbateurs, trou))).to.be.revertedWith("PeriodRegistry: discontinuite temporelle");
    const chevauche = meta({ periodHash: h("manifeste-2"), root: h("racine-2"), periodStart: now + 3599n, periodEnd: now + 7200n, firstSeq: 11n, lastSeq: 20n });
    await expect(registry.submitPeriod(chevauche, await signer(approbateurs, chevauche))).to.be.revertedWith("PeriodRegistry: discontinuite temporelle");

    const m2 = meta({ periodHash: h("manifeste-2"), root: h("racine-2"), periodStart: now + 3600n, periodEnd: now + 7200n, firstSeq: 11n, lastSeq: 20n });
    await (await registry.submitPeriod(m2, await signer(approbateurs, m2))).wait();
    expect(await registry.latestPeriodOf(m2.orgId, m2.journalId)).to.equal(2n);
  });

  it("continuité de séquence : firstSeq == lastSeq précédent + 1, ni trou ni recouvrement", async function () {
    const { approbateurs, registry, meta, signer, now, h } = await deploy();
    const m1 = meta();
    await (await registry.submitPeriod(m1, await signer(approbateurs, m1))).wait();
    const suite = (firstSeq, lastSeq) => meta({ periodHash: h(`manifeste-${firstSeq}-${lastSeq}`), root: h("racine-2"), periodStart: now + 3600n, periodEnd: now + 7200n, firstSeq, lastSeq });

    const trou = suite(12n, 20n);
    await expect(registry.submitPeriod(trou, await signer(approbateurs, trou))).to.be.revertedWith("PeriodRegistry: discontinuite de sequence");
    const recouvre = suite(10n, 20n);
    await expect(registry.submitPeriod(recouvre, await signer(approbateurs, recouvre))).to.be.revertedWith("PeriodRegistry: discontinuite de sequence");
    const ok = suite(11n, 20n);
    await (await registry.submitPeriod(ok, await signer(approbateurs, ok))).wait();
    expect((await registry.getPeriod(2)).firstSeq).to.equal(11n);
  });

  it("la continuité est par journal : un autre journal de la même organisation est libre", async function () {
    const { approbateurs, registry, meta, signer, now, h } = await deploy();
    const m1 = meta();
    await (await registry.submitPeriod(m1, await signer(approbateurs, m1))).wait();
    const autre = meta({ journalId: journalIdOf("journal-secondaire"), periodHash: h("manifeste-s1"), root: h("racine-s1"), periodStart: now + 99n, periodEnd: now + 199n, firstSeq: 500n, lastSeq: 600n });
    await (await registry.submitPeriod(autre, await signer(approbateurs, autre))).wait();
    expect(await registry.latestPeriodOf(m1.orgId, m1.journalId)).to.equal(1n);
    expect(await registry.latestPeriodOf(autre.orgId, autre.journalId)).to.equal(2n);
  });

  it("période vide : lastSeq + 1 == firstSeq et racine nulle ; la suivante reprend au même numéro", async function () {
    const { ethers, approbateurs, registry, meta, signer, now, h } = await deploy();
    const m1 = meta();
    await (await registry.submitPeriod(m1, await signer(approbateurs, m1))).wait();

    const vide = meta({ periodHash: h("manifeste-vide"), root: ethers.ZeroHash, periodStart: now + 3600n, periodEnd: now + 7200n, firstSeq: 11n, lastSeq: 10n });
    await (await registry.submitPeriod(vide, await signer(approbateurs, vide))).wait();
    const p = await registry.getPeriod(2);
    expect(p.root).to.equal(ethers.ZeroHash);
    expect(p.firstSeq).to.equal(11n);
    expect(p.lastSeq).to.equal(10n);

    // Après une période vide, la suivante commence à firstSeq de la vide.
    const m3 = meta({ periodHash: h("manifeste-3"), root: h("racine-3"), periodStart: now + 7200n, periodEnd: now + 10800n, firstSeq: 11n, lastSeq: 15n });
    await (await registry.submitPeriod(m3, await signer(approbateurs, m3))).wait();
    expect(await registry.latestPeriodOf(m3.orgId, m3.journalId)).to.equal(3n);
  });

  it("période vide : une racine non nulle est refusée (convention fixée par le contrat)", async function () {
    const { ethers, approbateurs, registry, meta, signer, h } = await deploy();
    const fantaisiste = meta({ firstSeq: 1n, lastSeq: 0n, root: h("racine-fantaisiste") });
    await expect(registry.submitPeriod(fantaisiste, await signer(approbateurs, fantaisiste))).to.be.revertedWith("PeriodRegistry: root d'une periode vide != 0");
    // sha256("") (arbre vide de la RFC 6962) n'est pas la convention non plus.
    const rfc = meta({ firstSeq: 1n, lastSeq: 0n, root: ethers.sha256("0x") });
    await expect(registry.submitPeriod(rfc, await signer(approbateurs, rfc))).to.be.revertedWith("PeriodRegistry: root d'une periode vide != 0");
    const vide = meta({ firstSeq: 1n, lastSeq: 0n, root: ethers.ZeroHash });
    await (await registry.submitPeriod(vide, await signer(approbateurs, vide))).wait();
    expect((await registry.getPeriod(1)).root).to.equal(ethers.ZeroHash);
  });

  it("une période non vide exige une racine non nulle", async function () {
    const { ethers, approbateurs, registry, meta, signer } = await deploy();
    const m = meta({ root: ethers.ZeroHash });
    await expect(registry.submitPeriod(m, await signer(approbateurs, m))).to.be.revertedWith("PeriodRegistry: root=0");
  });

  it("rejeu sur un autre registre refusé : le condensé lie l'adresse du contrat", async function () {
    const { approbateurs, registry, registre2, meta, signer } = await deploy();
    const m = meta();
    const sigsPourRegistre1 = await signer(approbateurs, m, registry);
    await expect(registre2.submitPeriod(m, sigsPourRegistre1)).to.be.revertedWith("PeriodRegistry: seuil non atteint");
    // Les mêmes personnes, en signant pour registre2, passent.
    await (await registre2.submitPeriod(m, await signer(approbateurs, m, registre2))).wait();
    expect(await registre2.isKnown(m.orgId, m.periodHash)).to.equal(true);
  });

  it("rejeu sur une autre organisation refusé : une signature dit POUR QUI elle vaut", async function () {
    const { approbateurs, orgB, registry, meta, signer } = await deploy();
    // Les mêmes approbateurs siègent chez A et chez B.
    const mA = meta();
    const sigsPourA = await signer(approbateurs, mA);
    const mB = meta({ orgId: orgB });
    await expect(registry.submitPeriod(mB, sigsPourA)).to.be.revertedWith("PeriodRegistry: seuil non atteint");
    await (await registry.submitPeriod(mB, await signer(approbateurs, mB))).wait();
    expect((await registry.getPeriod(1)).orgId).to.equal(orgB);
  });

  it("champs modifiés par le relayeur refusés : chaque champ du manifeste est lié par la signature", async function () {
    const { approbateurs, registry, meta, signer, h } = await deploy();
    const m = meta();
    const sigs = await signer(approbateurs, m);
    const alterations = [
      { root: h("autre-racine") },
      { periodHash: h("autre-manifeste") },
      { periodEnd: m.periodEnd + 1n },
      { periodStart: m.periodStart - 1n },
      { lastSeq: 11n },
      { firstSeq: 2n },
      { version: 2 },
      { uri: "ipfs://autre" },
      { journalId: journalIdOf("autre-journal") },
    ];
    for (const over of alterations) {
      await expect(registry.submitPeriod(meta(over), sigs), JSON.stringify(over, (_k, v) => (typeof v === "bigint" ? v.toString() : v))).to.be.revertedWith(
        "PeriodRegistry: seuil non atteint",
      );
    }
    // Non altéré, le même jeu de signatures passe.
    await (await registry.submitPeriod(m, sigs)).wait();
    expect(await registry.periodCount()).to.equal(1n);
  });

  it("le seuil appliqué est celui de l'organisation au moment de la soumission", async function () {
    const { admin, approbateurs, setA, registry, meta, signer } = await deploy();
    await (await setA.connect(admin).setThreshold(3)).wait();
    const m = meta();
    await expect(registry.submitPeriod(m, await signer([approbateurs[0], approbateurs[1]], m))).to.be.revertedWith("PeriodRegistry: signatures insuffisantes");
    await (await registry.submitPeriod(m, await signer(approbateurs, m))).wait();
    expect(await registry.periodCount()).to.equal(1n);
  });

  it("getPeriod refuse un identifiant hors plage ; le constructeur refuse un registre nul", async function () {
    const { ethers, registry } = await deploy();
    await expect(registry.getPeriod(0)).to.be.revertedWith("PeriodRegistry: id invalide");
    await expect(registry.getPeriod(1)).to.be.revertedWith("PeriodRegistry: id invalide");
    expect(await registry.latestPeriodId()).to.equal(0n);
    const PeriodRegistry = await ethers.getContractFactory("PeriodRegistry");
    await expect(PeriodRegistry.deploy(ethers.ZeroAddress)).to.be.revertedWith("PeriodRegistry: curatorSetRegistry=0");
  });
});
