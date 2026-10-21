import { expect } from "chai";
import { network } from "hardhat";
import { hashMessage, getBytes } from "ethers";
import { signDigestBy, signRawDigest } from "../scripts/lib/noortrace.mjs";

const ethers_hashMessage = (digest) => hashMessage(getBytes(digest));

// LA BIBLIOTHÈQUE DE SIGNATURES AU SEUIL, isolée des registres : préfixe
// EIP-191, appartenance au jeu, unicité, arrêt au seuil, forme canonique des
// signatures, seuil nul jamais atteint. Vérifiée au travers d'un contrat
// harnais (contracts/test/ThresholdSignaturesHarness.sol).

describe("ThresholdSignatures", function () {
  async function deploy() {
    const { ethers } = await network.create();
    const [admin] = await ethers.getSigners();
    const membres = [ethers.Wallet.createRandom(), ethers.Wallet.createRandom(), ethers.Wallet.createRandom()];
    const inconnu = ethers.Wallet.createRandom();

    const CuratorSet = await ethers.getContractFactory("CuratorSet");
    const set = await CuratorSet.deploy(admin.address, membres.map((m) => m.address), 2);
    await set.waitForDeployment();

    const Harness = await ethers.getContractFactory("ThresholdSignaturesHarness");
    const harness = await Harness.deploy();
    await harness.waitForDeployment();

    const digest = ethers.keccak256(ethers.toUtf8Bytes("un-condense-quelconque"));
    const prefixed = ethers.hashMessage(ethers.getBytes(digest));
    return { ethers, set, harness, membres, inconnu, digest, prefixed };
  }

  it("prefixed applique exactement le préfixe EIP-191 de personal_sign", async function () {
    const { harness, digest, prefixed } = await deploy();
    expect(await harness.prefixed(digest)).to.equal(prefixed);
  });

  it("compte les membres, ignore les inconnus et les signatures invalides", async function () {
    const { harness, set, membres, inconnu, digest, prefixed } = await deploy();
    const setAddr = await set.getAddress();
    expect(await harness.countSigners(setAddr, prefixed, await signDigestBy([membres[0]], digest), 3)).to.equal(1n);
    expect(await harness.countSigners(setAddr, prefixed, await signDigestBy([membres[0], inconnu], digest), 3)).to.equal(1n);
    expect(await harness.countSigners(setAddr, prefixed, await signDigestBy([inconnu], digest), 3)).to.equal(0n);
    // Une signature malformée (v = 0) rend address(0) et est simplement ignorée.
    const [bonne] = await signDigestBy([membres[1]], digest);
    const cassee = { v: 0, r: bonne.r, s: bonne.s };
    expect(await harness.countSigners(setAddr, prefixed, [cassee, bonne], 3)).to.equal(1n);
    expect(await harness.countSigners(setAddr, prefixed, [], 3)).to.equal(0n);
  });

  it("une même clé ne compte qu'une fois", async function () {
    const { harness, set, membres, digest, prefixed } = await deploy();
    const [s] = await signDigestBy([membres[2]], digest);
    expect(await harness.countSigners(await set.getAddress(), prefixed, [s, s, s], 3)).to.equal(1n);
  });

  it("s'arrête au seuil : trois signatures valides, seuil 2, compte 2", async function () {
    const { harness, set, membres, digest, prefixed } = await deploy();
    const sigs = await signDigestBy(membres, digest);
    expect(await harness.countSigners(await set.getAddress(), prefixed, sigs, 2)).to.equal(2n);
    expect(await harness.countSigners(await set.getAddress(), prefixed, sigs, 3)).to.equal(3n);
  });

  it("meetsThreshold : vrai au seuil, faux en dessous, faux sans préfixe", async function () {
    const { harness, set, membres, inconnu, digest } = await deploy();
    const setAddr = await set.getAddress();
    expect(await harness.meetsThreshold(setAddr, digest, await signDigestBy([membres[0], membres[1]], digest), 2)).to.equal(true);
    expect(await harness.meetsThreshold(setAddr, digest, await signDigestBy([membres[0], inconnu], digest), 2)).to.equal(false);
    expect(await harness.meetsThreshold(setAddr, digest, [signRawDigest(membres[0], digest), signRawDigest(membres[1], digest)], 2)).to.equal(false);
  });

  it("meetsThreshold : un seuil nul n'est jamais atteint, même sans aucune signature", async function () {
    const { harness, set, membres, digest } = await deploy();
    const setAddr = await set.getAddress();
    expect(await harness.meetsThreshold(setAddr, digest, [], 0)).to.equal(false);
    expect(await harness.meetsThreshold(setAddr, digest, await signDigestBy([membres[0]], digest), 0)).to.equal(false);
    // countSigners, lui, compte simplement (et s'arrête au seuil, donc à 0 dès la première valide).
    expect(await harness.countSigners(setAddr, ethers_hashMessage(digest), [], 0)).to.equal(0n);
  });

  it("forme canonique seulement : la forme malléable (v ^ 1, r, n - s) d'une signature est ignorée, v hors {27, 28} aussi", async function () {
    const { harness, set, membres, digest, prefixed } = await deploy();
    const setAddr = await set.getAddress();
    const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const [sig] = await signDigestBy([membres[0]], digest);
    const malleable = { v: sig.v === 27 ? 28 : 27, r: sig.r, s: "0x" + (N - BigInt(sig.s)).toString(16).padStart(64, "0") };
    // Seule, la forme malléable ne compte pas ; avec l'originale, elle ne compte toujours qu'une voix.
    expect(await harness.countSigners(setAddr, prefixed, [malleable], 3)).to.equal(0n);
    expect(await harness.countSigners(setAddr, prefixed, [sig], 3)).to.equal(1n);
    expect(await harness.countSigners(setAddr, prefixed, [sig, malleable], 3)).to.equal(1n);
    expect(await harness.countSigners(setAddr, prefixed, [{ v: 29, r: sig.r, s: sig.s }, { v: 1, r: sig.r, s: sig.s }], 3)).to.equal(0n);
    const [sig1] = await signDigestBy([membres[1]], digest);
    expect(await harness.meetsThreshold(setAddr, digest, [malleable, sig1], 2)).to.equal(false);
    expect(await harness.meetsThreshold(setAddr, digest, [sig, sig1], 2)).to.equal(true);
  });

  it("un membre retiré du jeu ne compte plus", async function () {
    const { ethers, harness, set, membres, digest } = await deploy();
    const [admin] = await ethers.getSigners();
    const sigs = await signDigestBy([membres[0], membres[1]], digest);
    expect(await harness.meetsThreshold(await set.getAddress(), digest, sigs, 2)).to.equal(true);
    await (await set.connect(admin).removeCurator(membres[1].address)).wait();
    expect(await harness.meetsThreshold(await set.getAddress(), digest, sigs, 2)).to.equal(false);
  });
});
