import { expect } from "chai";
import crypto from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { computeAddress, hashMessage } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as K from "../scripts/lib/console.mjs";

// TEST DIFFÉRENTIEL PERMANENT DES PRIMITIVES DE LA CONSOLE DE RÉFÉRENCE
// (spec/CT-3-approbations.md, révision 0.3, EX-13.32, EX-A.9).
//
// scripts/lib/console.mjs écrit lui-même, sans importation, SHA-256,
// HMAC-SHA-256, PBKDF2-HMAC-SHA-256, scrypt, AES-128-CTR, Keccak-256 et
// secp256k1 (adresse, signature RFC 6979 à s bas, recouvrement), et le
// condensé EIP-191. Ce fichier confronte chacune de ces primitives, sur des
// entrées tirées d'un générateur déterministe (SHA-256 d'un compteur, graine
// fixe : deux exécutions font les mêmes comparaisons), à node:crypto, à
// @noble/hashes (keccak_256), à @noble/curves (secp256k1) et à ethers
// (hashMessage, computeAddress), tous présents dans node_modules. Aucune
// dépendance n'est ajoutée au dépôt.

const { keccak_256: keccak256Noble } = await import(pathToFileURL(path.join(PROJECT_ROOT, "node_modules", "@noble", "hashes", "sha3.js")).href);
const { secp256k1 } = await import(pathToFileURL(path.join(PROJECT_ROOT, "node_modules", "@noble", "curves", "secp256k1.js")).href);

const GRAINE = "noortrace/test/console-primitives/v0";
const N = K.N_SECP256K1;

/** Générateur déterministe : octets de SHA-256(GRAINE ‖ "/" ‖ compteur), compteur croissant. */
function generateur() {
  let compteur = 0;
  const octets = (n) => {
    const out = Buffer.alloc(n);
    for (let o = 0; o < n; o += 32) crypto.createHash("sha256").update(`${GRAINE}/${compteur++}`).digest().copy(out, o, 0, Math.min(32, n - o));
    return new Uint8Array(out);
  };
  const entier = (min, max) => min + (octets(4).reduce((a, b) => a * 256 + b, 0) % (max - min + 1));
  /** Clé privée dans [1, n − 1]. */
  const cle = () => {
    for (;;) {
      const k = octets(32);
      const v = BigInt("0x" + Buffer.from(k).toString("hex"));
      if (v >= 1n && v < N) return k;
    }
  };
  return { octets, entier, cle };
}

const hex = (o) => Buffer.from(o).toString("hex");
const sans0x = (t) => String(t).toLowerCase().replace(/^0x/, "");

describe("CT-3 0.3 : primitives de scripts/lib/console.mjs confrontées à node:crypto, @noble/hashes, @noble/curves et ethers (EX-13.32)", function () {
  this.timeout(120_000);
  const comptes = {};
  const compter = (nom) => (comptes[nom] = (comptes[nom] ?? 0) + 1);

  after(function () {
    const total = Object.values(comptes).reduce((a, b) => a + b, 0);
    console.log(`      comparaisons : ${total} (${Object.entries(comptes).map(([k, v]) => `${k} ${v}`).join(", ")}), écarts : 0`);
  });

  it("SHA-256, HMAC-SHA-256 et Keccak-256 : longueurs 0 à 139 puis tirées jusqu'à 5 000 octets ; clés HMAC de 0 à 200 octets (au-delà du bloc de 64)", function () {
    const g = generateur();
    for (let i = 0; i < 400; i++) {
      const m = g.octets(i < 140 ? i : g.entier(140, 5000));
      const k = g.octets(g.entier(0, 200));
      expect(hex(K.sha256(m)), `sha256 ${i}`).to.equal(crypto.createHash("sha256").update(m).digest("hex"));
      expect(hex(K.hmacSha256(k, m)), `hmac ${i}`).to.equal(crypto.createHmac("sha256", k).update(m).digest("hex"));
      expect(hex(K.keccak256(m)), `keccak ${i}`).to.equal(hex(keccak256Noble(m)));
      compter("sha256");
      compter("hmacSha256");
      compter("keccak256");
    }
    // Frontières des blocs de Keccak-256 (136 octets) et de SHA-256 (64 octets, remplissage à 56).
    for (const n of [55, 56, 63, 64, 65, 135, 136, 137, 271, 272, 273]) {
      const m = g.octets(n);
      expect(hex(K.keccak256(m)), `keccak ${n}`).to.equal(hex(keccak256Noble(m)));
      expect(hex(K.sha256(m)), `sha256 ${n}`).to.equal(crypto.createHash("sha256").update(m).digest("hex"));
      compter("keccak256");
      compter("sha256");
    }
  });

  it("PBKDF2-HMAC-SHA-256 : mots de passe de 0 à 40 octets, 1 à 300 itérations, longueurs de 1 à 70 octets (plus d'un bloc)", function () {
    const g = generateur();
    g.octets(1 << 12); // autre portion du flux que le cas précédent
    for (let i = 0; i < 40; i++) {
      const p = g.octets(g.entier(0, 40));
      const s = g.octets(16);
      const it = g.entier(1, 300);
      const L = g.entier(1, 70);
      expect(hex(K.pbkdf2Sha256(p, s, it, L)), `pbkdf2 ${i}`).to.equal(crypto.pbkdf2Sync(p, s, it, L, "sha256").toString("hex"));
      compter("pbkdf2Sha256");
    }
  });

  it("scrypt (RFC 7914) : N petits (2 à 4 096), r de 1 à 8, p de 1 à 3", function () {
    const g = generateur();
    for (const [n, r, p] of [[2, 1, 1], [16, 1, 1], [16, 8, 1], [256, 2, 3], [1024, 1, 1], [1024, 8, 1], [4096, 8, 1]]) {
      const pw = g.octets(12);
      const sel = g.octets(32);
      expect(hex(K.scrypt(pw, sel, n, r, p, 32)), `scrypt N=${n} r=${r} p=${p}`).to.equal(crypto.scryptSync(pw, sel, 32, { N: n, r, p, maxmem: 64 * 1024 * 1024 }).toString("hex"));
      compter("scrypt");
    }
  });

  it("AES-128-CTR : longueurs de 0 à 5 000 octets ; compteur de 128 bits qui déborde 2^128 et retenue au-delà des 64 bits de poids faible", function () {
    const g = generateur();
    const reference = (cle, iv, m) => {
      const c = crypto.createCipheriv("aes-128-ctr", cle, iv);
      return Buffer.concat([c.update(m), c.final()]).toString("hex");
    };
    for (let i = 0; i < 300; i++) {
      const cle = g.octets(16);
      const iv = g.octets(16);
      const m = g.octets(i < 40 ? i : g.entier(40, 5000));
      expect(hex(K.aes128Ctr(cle, iv, m)), `aes ${i}`).to.equal(reference(cle, iv, m));
      compter("aes128Ctr");
    }
    // Débordement de 2^128 : le compteur repart de zéro après ff…ff, au deuxième bloc.
    const ivMax = new Uint8Array(16).fill(0xff);
    const ivRetenue = Uint8Array.from([...g.octets(8), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]);
    for (const iv of [ivMax, ivRetenue]) {
      const cle = g.octets(16);
      const m = g.octets(100);
      expect(hex(K.aes128Ctr(cle, iv, m)), `aes iv ${hex(iv)}`).to.equal(reference(cle, iv, m));
      compter("aes128Ctr");
    }
  });

  it("secp256k1 : adresse (ethers computeAddress), signature RFC 6979 à s bas (@noble/curves), recouvrement, y compris d'une signature à s haut avec l'identifiant de recouvrement inversé", function () {
    const g = generateur();
    g.octets(1 << 13);
    for (let i = 0; i < 200; i++) {
      const sk = g.cle();
      const h = g.octets(32);
      const adresse = sans0x(computeAddress("0x" + hex(sk)));
      expect(sans0x(K.adresseDeCle(sk)), `adresse ${i}`).to.equal(adresse);
      compter("adresseDeCle");
      const ref = secp256k1.sign(h, sk, { lowS: true });
      const attendue = ref.r.toString(16).padStart(64, "0") + ref.s.toString(16).padStart(64, "0") + (27 + ref.recovery).toString(16);
      const sig = K.signerHachage(Uint8Array.from(sk), h);
      expect(sans0x(sig), `signature ${i}`).to.equal(attendue);
      compter("signerHachage");
      expect(ref.s <= N / 2n, `s bas ${i}`).to.equal(true);
      expect(sans0x(K.recouvrerAdresse(h, ref.r, ref.s, ref.recovery)), `recouvrement ${i}`).to.equal(adresse);
      compter("recouvrerAdresse");
      // La même signature à s haut, identifiant de recouvrement inversé, recouvre la même adresse (EX-9.3).
      expect(sans0x(K.recouvrerAdresse(h, ref.r, N - ref.s, ref.recovery ^ 1)), `recouvrement s haut ${i}`).to.equal(adresse);
      compter("recouvrerAdresse");
      // Et l'identifiant de recouvrement faux ne la recouvre pas.
      expect(sans0x(K.recouvrerAdresse(h, ref.r, ref.s, ref.recovery ^ 1)), `recid faux ${i}`).not.to.equal(adresse);
      compter("recouvrerAdresse");
    }
    // Clés limites : 1 et n − 1.
    for (const k of [1n, N - 1n]) {
      const sk = Uint8Array.from(Buffer.from(k.toString(16).padStart(64, "0"), "hex"));
      expect(sans0x(K.adresseDeCle(sk))).to.equal(sans0x(computeAddress("0x" + hex(sk))));
      compter("adresseDeCle");
    }
  });

  it("condensé EIP-191 (version 0x45) : messages de 0 à 200 octets, dont 32 octets comme un D_A, comparés à ethers hashMessage", function () {
    const g = generateur();
    g.octets(1 << 14);
    for (let i = 0; i < 100; i++) {
      const m = g.octets(i === 0 ? 0 : i < 10 ? 32 : g.entier(1, 200));
      expect(hex(K.condenseEIP191(m)), `eip191 ${i}`).to.equal(sans0x(hashMessage(m)));
      compter("condenseEIP191");
    }
  });

  it("déterminisme : le générateur rend les mêmes octets à chaque exécution", function () {
    const a = generateur();
    const b = generateur();
    expect(hex(a.octets(100))).to.equal(hex(b.octets(100)));
    expect(hex(generateur().octets(32))).to.equal(crypto.createHash("sha256").update(`${GRAINE}/0`).digest("hex"));
  });
});
