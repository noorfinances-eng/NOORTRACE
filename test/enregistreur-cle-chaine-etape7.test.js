// Étape 7 : clé de chaîne des classes B et C (CT-2 EX-11.19, §11.2 ;
// D-10) et rotation de la clé de chaîne relayée au registre (CT-2 EX-11.16,
// EX-11.19 point 4 ; CT-4 §8.4 ; CT-7 JS-5), sans réseau de développement :
//
// - signature DER d'un service ramenée à `s` bas et `v` recouvré
//   (`signatureDepuisDer`) ; refus des formes non minimales ;
// - refus nommés sans service : classe A (« classe absente »), classe C ou B
//   sans `service_url` d'AWS KMS, secret non résolu, ARN illisible ;
// - classes C (enveloppe AWS KMS `Encrypt`/`Decrypt`) et B (clé
//   `ECC_SECG_P256K1` d'AWS KMS, `Sign` `DIGEST`) contre le KMS simulé de
//   LocalStack en conteneur (image épinglée par condensé) : adresse dérivée,
//   condensé d'essai recouvert, mauvaise adresse et mauvais contexte refusés,
//   clé effacée à l'arrêt ; démon en production : la validation admet la
//   classe C, `principal` refuse de démarrer (code 2) avec une classe A ou une
//   mauvaise adresse ;
// - rotation relayée sur le nœud noorcore factice des essais du registre :
//   rotation de la seule clé de chaîne (JS-5 : révocation puis inscription de
//   la même clé Ed25519 sous `next_chain_key`, relayées depuis les demandes
//   signées au seuil, bascule, aucun événement dans la chaîne, ancres
//   suivantes émises par la nouvelle clé) ; rotation d'urgence d'EX-11.16
//   (inscription de la nouvelle paire, événement de rotation, révocation de
//   l'ancienne clé de chaîne) ; refus nommés (demande absente, demande d'une
//   autre clé, registre non branché).
//
// Les clés secp256k1 sont dérivées pendant l'essai de la mnémonique publique
// `test test … junk` (fixtures/enregistreur-cle-chaine/outils.mjs), sauf la
// clé de classe B, engendrée par le KMS simulé.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";
import {
  Coeur, principal, cleChaineDepuisConfiguration, ErreurBranchementAncrage, validerConfiguration, CLASSES_CLE_CHAINE_SERVIES,
} from "@noortrace/enregistreur";
import { monterEnProcessus, echangeFactice, repertoireTemporaire, enAttente } from "./fixtures/enregistreur-ancrage/outils.mjs";
import { attenteCalme } from "./fixtures/ancrage-composant/outils.mjs";
import { configurationDev, graine } from "./fixtures/enregistreur-coeur/outils.mjs";
import { demarrerKmsLocalStack, dockerEtImage, IMAGES_SIGNATAIRES, arreterConteneurs } from "./fixtures/enregistreur-signataires/outils.mjs";
import {
  cleEssai, envelopperCleChaine, creerCleKmsSecp256k1, ecrireSecret, demandeInscription, demandeRevocation, deposerDemande, outilsDesEvenements, SERVICE_KMS_ESSAI,
} from "./fixtures/enregistreur-cle-chaine/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;
/** Ordre de la courbe secp256k1 (SEC 2, § 2.4.1). */
const ORDRE = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** `s` d'une signature DER (séquence de deux entiers). */
function sDer(der) {
  const b = Buffer.from(der);
  const lr = b[3];
  const ls = b[4 + lr + 1];
  return BigInt(`0x${b.subarray(4 + lr + 2, 4 + lr + 2 + ls).toString("hex")}`);
}

/** Rejet attendu d'une promesse par ErreurBranchementAncrage, de raison et de message donnés. */
async function rejet(promesse, motif, raison) {
  let e = null;
  try {
    await promesse;
  } catch (x) {
    e = x;
  }
  expect(e, "rejet attendu").to.be.instanceOf(ErreurBranchementAncrage);
  expect(e.message).to.match(motif);
  expect(e.raison).to.equal(raison);
  return e;
}

/** DER minimal d'un entier positif (X.690). */
function derEntier(x) {
  let h = x.toString(16);
  if (h.length % 2) h = `0${h}`;
  let b = Buffer.from(h, "hex");
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
}
const derSignature = (r, s) => {
  const corps = Buffer.concat([derEntier(r), derEntier(s)]);
  return new Uint8Array(Buffer.concat([Buffer.from([0x30, corps.length]), corps]));
};

/** Configuration minimale d'essai avec un registre activé et une clé de chaîne donnée. */
function configAvecCle(dir, chainKey, o = {}) {
  const { config } = configurationDev(dir, {});
  config.anchoring.registry = { enabled: true, rpc_url: "http://127.0.0.1:8645", chain_key: chainKey, next_chain_key: o.suivante ?? null };
  return config;
}

describe("étape 7 : clé de chaîne des classes B et C sans service (CT-2 EX-11.19 ; signature DER, refus nommés)", function () {
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-e7-cle-chaine-");
  });
  after(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("classes servies B, C et D ; signature DER d'un service (s haut ou bas) ramenée à s bas et v recouvert sur l'adresse ; DER non minimal, octets en trop, s nul ou autre adresse refusés", function () {
    expect(CLASSES_CLE_CHAINE_SERVIES).to.deep.equal(["B", "C", "D"]);
    const k = cleEssai(7);
    for (let i = 0; i < 8; i++) {
      const h = N.sha256(N.utf8(`étape 7 condensé ${i}`));
      const ref = k.signataire.signerCondense(h);
      const r = BigInt(ref.r);
      const s = BigInt(ref.s);
      for (const sDer of [s, ORDRE - s]) {
        const sig = R.signatureDepuisDer(h, derSignature(r, sDer), k.adresse);
        expect(sig).to.deep.equal(ref);
        expect(R.recouvrerSignataire(h, sig)).to.equal(k.adresse);
      }
    }
    const h = N.sha256(N.utf8("refus"));
    const ref = k.signataire.signerCondense(h);
    const bon = derSignature(BigInt(ref.r), BigInt(ref.s));
    expect(() => R.signatureDepuisDer(h, Uint8Array.from([...bon, 0]), k.adresse)).to.throw(/séquence|octets en trop/);
    // Entier r sur 33 octets avec un zéro de tête inutile (bit de poids fort nul) : forme non minimale (X.690).
    const corps = Buffer.concat([Buffer.from([0x02, 33, 0]), Buffer.from(ref.r.slice(2), "hex")]);
    if (!(corps[3] & 0x80)) {
      const der = Buffer.concat([Buffer.from([0x30, corps.length + derEntier(BigInt(ref.s)).length]), corps, derEntier(BigInt(ref.s))]);
      expect(() => R.signatureDepuisDer(h, new Uint8Array(der), k.adresse)).to.throw(/non minimal/);
    }
    expect(() => R.signatureDepuisDer(h, derSignature(BigInt(ref.r), 0n), k.adresse)).to.throw(/hors de/);
    expect(() => R.signatureDepuisDer(h, bon, cleEssai(8).adresse)).to.throw(/ne recouvre pas/);
  });

  it("refus attendus sans service : classe A (« classe absente » : non servie, nommée, classe_cle_chaine) ; classe C sans service_url ou hors d'AWS KMS, classe B avec un secret qui n'est pas un ARN ou d'une autre région, secret non résolu : cle_chaine ; next_chain_key de même adresse que chain_key : cle_chaine", async function () {
    const k = cleEssai(9);
    const secret = new Map([["/anchoring/registry/chain_key/secret", k.octets]]);
    const base = (classe, service_url = SERVICE_KMS_ESSAI) => configAvecCle(path.join(dir, `c-${classe}`), { class: classe, address: k.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url });
    await rejet(cleChaineDepuisConfiguration(base("A"), secret), /classe A .*non servie.*(module PKCS#11|PKCS#11)/, "classe_cle_chaine");
    await rejet(cleChaineDepuisConfiguration(base("C", null), secret), /service_url doit désigner AWS KMS.*null/, "cle_chaine");
    await rejet(cleChaineDepuisConfiguration(base("C", "https://coffre.exploitant.example/v1/transit/decrypt/cle"), secret), /service_url doit désigner AWS KMS/, "cle_chaine");
    await rejet(cleChaineDepuisConfiguration(base("B"), new Map([["/anchoring/registry/chain_key/secret", N.utf8("pas un arn")]])), /ARN/, "cle_chaine");
    await rejet(cleChaineDepuisConfiguration(base("B"), new Map([["/anchoring/registry/chain_key/secret", N.utf8("arn:aws:kms:eu-west-3:111122223333:key/k1")]])), /région/, "cle_chaine");
    await rejet(cleChaineDepuisConfiguration(base("C"), new Map()), /non résolu/, "cle_chaine");
    // Classe D : servie hors production, adresse confrontée ; la suivante ne peut pas reprendre la même adresse.
    const d = configAvecCle(path.join(dir, "d"), { class: "D", address: k.adresse, secret: { file: "/x" }, service_url: null });
    const cle = await cleChaineDepuisConfiguration(d, secret);
    expect(cle.classe).to.equal("D");
    expect(cle.adresse()).to.equal(k.adresse);
    cle.effacer();
    expect(() => cle.signerCondense(N.sha256(N.utf8("après effacement")))).to.throw(/effacée/);
    const autre = structuredClone(d);
    autre.anchoring.registry.chain_key.address = cleEssai(10).adresse;
    await rejet(cleChaineDepuisConfiguration(autre, secret), /adresse de la clé de chaîne différente/, "cle_chaine");
  });

  // Étape 7 : le modèle de production ne porte plus
  // l'adresse réelle d'AWS KMS (CT-8 : noms d'hôtes d'exemple en `.example`),
  // et `service_url` désigne le point d'accès lui-même.
  it("service_url (étape 7) : point d'accès d'AWS KMS https://kms.<région>.<domaine> (région lue dans le nom), employé tel quel sauf AWS_ENDPOINT_URL_KMS ou AWS_ENDPOINT_URL ; le modèle de production le donne en .example et valide en production", async function () {
    const { regionServiceKms, origineServiceKms } = await import("../paquets/enregistreur/src/cle-chaine.mjs");
    expect(regionServiceKms("https://kms.eu-central-2.amazonaws.com")).to.equal("eu-central-2");
    expect(regionServiceKms("https://kms.cn-north-1.amazonaws.com.cn/")).to.equal("cn-north-1");
    expect(regionServiceKms("https://kms-fips.us-east-1.amazonaws.example")).to.equal("us-east-1");
    expect(regionServiceKms("https://kms.eu-central-2.amazonaws.example")).to.equal("eu-central-2");
    for (const refus of [null, "https://coffre.exploitant.example/v1/transit/decrypt/cle", "http://kms.eu-central-2.amazonaws.com", "https://kms.eu-central-2.amazonaws.com/chemin", "https://kms.inconnue.amazonaws.com", "https://u:p@kms.eu-central-2.amazonaws.com"]) {
      expect(regionServiceKms(refus), String(refus)).to.equal(null);
    }
    expect(origineServiceKms("https://kms.eu-central-2.amazonaws.example/", {})).to.equal("https://kms.eu-central-2.amazonaws.example");
    expect(origineServiceKms("https://kms.eu-central-2.amazonaws.example", { AWS_ENDPOINT_URL_KMS: "http://127.0.0.1:4566" })).to.equal("http://127.0.0.1:4566");
    expect(origineServiceKms("https://kms.eu-central-2.amazonaws.example", { AWS_ENDPOINT_URL: "http://127.0.0.1:4567/" })).to.equal("http://127.0.0.1:4567");
    const modele = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "deploiement", "config", "modele-production", "configuration.json"), "utf8"));
    const url = modele.anchoring.registry.chain_key.service_url;
    expect(new URL(url).hostname).to.match(/\.(example|invalid)$/);
    expect(regionServiceKms(url)).to.equal("eu-central-2");
    const v = validerConfiguration(N.utf8(JSON.stringify(modele)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  });

  it("validation (EX-15.4 pas 3, EX-11.19) : en production, une clé de chaîne de classe D est refusée, une clé de classe B ou C admise", function () {
    const k = cleEssai(11);
    for (const [classe, attendu] of [["D", true], ["C", false], ["B", false]]) {
      const c = configAvecCle(path.join(dir, `v-${classe}`), { class: classe, address: k.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url: classe === "D" ? null : SERVICE_KMS_ESSAI });
      c.recorder.environment = "production";
      c.signer = { ...c.signer, class: "C", backend: { type: "envelope", sealed_seed_file: "/var/lib/noortrace/graine.bin", wrap: { type: "aws-kms", key_arn: "arn:aws:kms:us-east-1:000000000000:key/k1", region: "us-east-1" } } };
      const v = validerConfiguration(N.utf8(JSON.stringify(c)));
      expect(v.erreurs.some((e) => e.pointeur === "/anchoring/registry/chain_key/class"), `${classe} : ${JSON.stringify(v.erreurs)}`).to.equal(attendu);
    }
  });
});

describe("étape 7 : clé de chaîne des classes B et C par le KMS simulé (LocalStack en conteneur), démon en production (CT-2 EX-11.19, EX-11.9 ; CT-7 §5.4 pas 6)", function () {
  this.timeout(600000);
  let dir;
  let kms = null;
  let condition = null;
  const org = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
  const journal = "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164";

  before(async function () {
    dir = repertoireTemporaire("noortrace-e7-kms-");
    const d = dockerEtImage(IMAGES_SIGNATAIRES.kms);
    if (!d.ok) {
      condition = d.condition;
      return;
    }
    kms = await demarrerKmsLocalStack(`noortrace-e7-kms-${process.pid}`);
  });
  after(function () {
    kms?.arreter();
    arreterConteneurs();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (condition || !kms) {
      enAttente(this, condition ?? "KMS simulé non démarré");
      return false;
    }
    return true;
  }

  /** Configuration d'essai portant la clé de chaîne `ck` et le secret résolu. */
  function avec(ck, secret, suivante = null) {
    const c = configAvecCle(path.join(dir, `cfg-${Math.random().toString(16).slice(2)}`), ck, { suivante: suivante?.ck ?? null });
    c.recorder.org_id = org;
    c.recorder.journal_id = journal;
    const secrets = new Map([["/anchoring/registry/chain_key/secret", secret]]);
    if (suivante) secrets.set("/anchoring/registry/next_chain_key/secret", suivante.secret);
    return { c, secrets };
  }

  it("classe C : scalaire d'essai enveloppé par AWS KMS Encrypt (contexte org_id, journal_id, key_id = adresse) ; déchiffré au démarrage, adresse dérivée égale, condensé d'essai et vingt condensés signés et recouverts ; mauvaise adresse, enveloppe d'un autre contexte, enveloppe altérée : refus nommés ; effacée à l'arrêt", async function () {
    if (!pret.call(this)) return;
    const arn = await kms.creerCleSymetrique();
    const k = cleEssai(21);
    const chiffre = await envelopperCleChaine(kms, arn, k.octets, { org_id: org, journal_id: journal, adresse: k.adresse });
    expect(Buffer.from(chiffre).includes(Buffer.from(k.octets))).to.equal(false);
    const { c, secrets } = avec({ class: "C", address: k.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url: SERVICE_KMS_ESSAI }, chiffre);
    const cle = await cleChaineDepuisConfiguration(c, secrets, { env: kms.env });
    expect(cle.classe).to.equal("C");
    expect(cle.adresse()).to.equal(k.adresse);
    expect(cle.localisation()).to.include({ service: "aws-kms", key_arn: arn, region: "us-east-1" });
    expect(JSON.stringify(cle)).to.not.include(N.octetsVersHex(k.octets).slice(2));
    for (let i = 0; i < 20; i++) {
      const h = N.sha256(N.utf8(`classe C ${i}`));
      const sig = await cle.signerCondense(h);
      expect(R.lireSignature(sig), "s bas, v 27 ou 28").to.not.equal(null);
      expect(R.recouvrerSignataire(h, sig)).to.equal(k.adresse);
    }
    cle.effacer();
    expect(() => cle.signerCondense(N.sha256(N.utf8("x")))).to.throw(/effacée/);
    // Mauvaise adresse déclarée : le KMS déchiffre sous le contexte de l'adresse déclarée, qui n'est pas celui de l'enveloppe.
    const autre = cleEssai(22);
    const x = avec({ class: "C", address: autre.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url: SERVICE_KMS_ESSAI }, chiffre);
    await rejet(cleChaineDepuisConfiguration(x.c, x.secrets, { env: kms.env }), /illisible.*Decrypt|Decrypt/, "cle_chaine");
    // Enveloppe faite pour l'autre adresse mais déclarée sous elle : déchiffrée, l'adresse dérivée diffère.
    const chiffreAutre = await envelopperCleChaine(kms, arn, k.octets, { org_id: org, journal_id: journal, adresse: autre.adresse });
    const y = avec({ class: "C", address: autre.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url: SERVICE_KMS_ESSAI }, chiffreAutre);
    await rejet(cleChaineDepuisConfiguration(y.c, y.secrets, { env: kms.env }), /adresse de la clé de chaîne différente/, "cle_chaine");
    const altere = Uint8Array.from(chiffre);
    altere[altere.length - 1] ^= 1;
    const z = avec({ class: "C", address: k.adresse, secret: { file: "/run/secrets/cle-chaine" }, service_url: SERVICE_KMS_ESSAI }, altere);
    await rejet(cleChaineDepuisConfiguration(z.c, z.secrets, { env: kms.env }), /illisible/, "cle_chaine");
    // KMS injoignable : refus nommé, sans secret dans le message.
    const e = await rejet(cleChaineDepuisConfiguration(c, secrets, { env: { ...kms.env, AWS_ENDPOINT_URL_KMS: "http://127.0.0.1:9" } }), /illisible/, "cle_chaine");
    expect(e.message).to.not.include(Buffer.from(chiffre).toString("base64").slice(0, 16));
  });

  it("classe B : clé ECC_SECG_P256K1 du KMS (la clé ne quitte jamais le service) ; adresse lue par GetPublicKey, quarante condensés signés par Sign DIGEST ECDSA_SHA_256, chaque signature DER ramenée à s bas et recouvrant l'adresse ; clé P-256 refusée ; mauvaise adresse refusée", async function () {
    if (!pret.call(this)) return;
    const { arn, adresse } = await creerCleKmsSecp256k1(kms);
    const { c, secrets } = avec({ class: "B", address: adresse, secret: { file: "/run/secrets/cle-chaine-arn" }, service_url: SERVICE_KMS_ESSAI }, N.utf8(`${arn}\n`));
    const cle = await cleChaineDepuisConfiguration(c, secrets, { env: kms.env });
    expect(cle.classe).to.equal("B");
    expect(cle.adresse()).to.equal(adresse);
    expect(cle.localisation()).to.deep.equal({ service: "aws-kms", key_arn: arn, region: "us-east-1" });
    let hauts = 0;
    for (let i = 0; i < 40; i++) {
      const h = N.sha256(N.utf8(`classe B ${i}`));
      const r = await kms.client.appeler("Sign", { KeyId: arn, Message: Buffer.from(h).toString("base64"), MessageType: "DIGEST", SigningAlgorithm: "ECDSA_SHA_256" });
      if (sDer(Buffer.from(r.Signature, "base64")) > ORDRE / 2n) hauts += 1;
      const sig = await cle.signerCondense(h);
      expect(R.lireSignature(sig)).to.not.equal(null);
      expect(R.recouvrerSignataire(h, sig)).to.equal(adresse);
    }
    console.log(`      signatures DER du KMS à s haut, ramenées à s bas : ${hauts} sur 40`);
    const p256 = await creerCleKmsSecp256k1(kms, "ECC_NIST_P256");
    const w = avec({ class: "B", address: adresse, secret: { file: "/x" }, service_url: SERVICE_KMS_ESSAI }, N.utf8(p256.arn));
    await rejet(cleChaineDepuisConfiguration(w.c, w.secrets, { env: kms.env }), /ECC_SECG_P256K1 attendue/, "cle_chaine");
    const v = avec({ class: "B", address: cleEssai(23).adresse, secret: { file: "/x" }, service_url: SERVICE_KMS_ESSAI }, N.utf8(arn));
    await rejet(cleChaineDepuisConfiguration(v.c, v.secrets, { env: kms.env }), /adresse de la clé de chaîne différente/, "cle_chaine");
  });

  it("démon en production (signataire de classe C par enveloppe AWS KMS, anchoring.ancrage désigné, registre activé) : classe A → demarrage_refuse : ancrage : classe_cle_chaine (code 2) ; mauvaise adresse de classe C → demarrage_refuse : ancrage : cle_chaine (code 2) ; aucun secret sur la sortie d'erreur", async function () {
    if (!pret.call(this)) return;
    const d = path.join(dir, "demon-prod");
    const x = await monterEnProcessus({ dir: d, periodStart: PERIODE });
    if (x.condition) return enAttente(this, x.condition);
    try {
      const arnSym = await kms.creerCleSymetrique();
      const graineCle = graine(x.config.signer.key_id);
      const scelle = await kms.chiffrerGraine(arnSym, graineCle, { org_id: x.config.recorder.org_id, journal_id: x.config.recorder.journal_id, key_id: x.config.signer.key_id });
      const fichierGraine = ecrireSecret(path.join(d, "secrets"), "graine-scellee.bin", scelle);
      const k = cleEssai(24);
      const chiffre = await envelopperCleChaine(kms, arnSym, k.octets, { org_id: x.config.recorder.org_id, journal_id: x.config.recorder.journal_id, adresse: k.adresse });
      const fichierCle = ecrireSecret(path.join(d, "secrets"), "cle-chaine", chiffre);
      const env = { ...x.env, ...kms.env };
      for (const [nom, ck, motif] of [
        ["classe-a", { class: "A", address: k.adresse, secret: { file: fichierCle }, service_url: SERVICE_KMS_ESSAI }, /^demarrage_refuse : ancrage : classe_cle_chaine : clé de chaîne de classe A .*non servie/m],
        ["mauvaise-adresse", { class: "C", address: cleEssai(25).adresse, secret: { file: fichierCle }, service_url: SERVICE_KMS_ESSAI }, /^demarrage_refuse : ancrage : cle_chaine : /m],
      ]) {
        const config = JSON.parse(fs.readFileSync(x.cheminConfig, "utf8"));
        config.recorder.environment = "production";
        config.signer = { ...config.signer, class: "C", backend: { type: "envelope", sealed_seed_file: fichierGraine, wrap: { type: "aws-kms", key_arn: arnSym, region: "us-east-1" } }, rotation: { planned_every_days: null, next_key_id: null } };
        config.anchoring.registry.chain_key = ck;
        const v = validerConfiguration(N.utf8(JSON.stringify(config)));
        expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
        const chemin = path.join(d, `configuration-${nom}.json`);
        fs.writeFileSync(chemin, JSON.stringify(config));
        let err = "";
        const code = await principal(["--config", chemin], { env, stdout: { write() {} }, stderr: { write: (s) => (err += s) } });
        expect(code, err).to.equal(2);
        expect(err).to.match(motif);
        expect(err).to.not.include(N.octetsVersHex(k.octets).slice(2));
      }
    } finally {
      await x.fermer();
    }
  });
});

describe("étape 7 : rotation de la clé de chaîne relayée au registre, nœud noorcore factice (CT-2 EX-11.16, EX-11.19 point 4 ; CT-4 §8.4 ; CT-7 JS-5)", function () {
  this.timeout(600000);

  /** Monte un cœur en processus dont `anchoring.registry` porte la clé du registre factice et `next_chain_key` (classe D d'essai). */
  async function monter(dir, { nextKeyId }) {
    const suivante = cleEssai(31 + (nextKeyId ? 1 : 0));
    let x;
    x = await monterEnProcessus({
      dir, periodStart: PERIODE, surchargesAncrage: { registry: { checkpoints: "tous" } },
      config: (c) => {
        const f = ecrireSecret(path.join(dir, "secrets"), "cle-chaine-suivante.hex", N.octetsVersHex(suivante.octets));
        c.anchoring.registry.next_chain_key = { class: "D", address: suivante.adresse, secret: { file: f }, service_url: null };
        c.signer.rotation.next_key_id = nextKeyId;
      },
    });
    if (x.condition) return x;
    const noeud = x.m.registre.noeud;
    noeud.approvisionner(suivante.adresse, 4719000000n);
    const ancrage = await x.preparer();
    x.horloge.m = T0 + 5000;
    const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage, horloge: x.horloge });
    const calme = attenteCalme(ancrage.composant, { tolerance: () => x.m.transport.etat?.pendantesEnVol ?? 0 });
    const ancienne = x.config.anchoring.registry.chain_key.address;
    const r = x.m.registre;
    const signerSet = { curator_set: "0x" + "a1".repeat(20), threshold: r.seuil, height: 1000, block_hash: "0x" + "9d".repeat(32) };
    const commun = { evmChainId: r.instance.evmChainId, recorderRegistry: r.contrats.recorder_registry, orgId: x.config.recorder.org_id, approbateurs: r.approbateurs, seuil: r.seuil, signerSet, preparedAt: "2026-11-05T07:00:10.000Z" };
    return { x, noeud, ancrage, coeur, calme, suivante, ancienne, commun };
  }

  /** Une minute de plus : un échange puis un tic (point de contrôle remis et ancré). */
  async function minute(t, j) {
    await t.x.horloge.aller(T0 + j * 60000, t.calme);
    const e = await echangeFactice(t.coeur, j);
    await t.coeur.tic();
    await t.calme();
    return e;
  }

  it("JS-5, rotation de la seule clé de chaîne (next_chain_key posée, sans signer.rotation.next_key_id) : refusée sans demande ou avec une demande d'une autre clé ; puis révocation de l'ancienne clé et inscription de la même clé Ed25519 sous la nouvelle, relayées par la nouvelle clé de chaîne depuis les demandes signées au seuil (captures revocation et inscription) ; bascule (chain_key_switched) ; aucun événement de la chaîne ne la porte ; les ancres suivantes sont émises par la nouvelle clé de chaîne", async function () {
    const dir = repertoireTemporaire("noortrace-e7-js5-factice-");
    let t;
    try {
      t = await monter(dir, { nextKeyId: null });
      if (t.condition) return enAttente(this, t.condition);
      await minute(t, 1);
      const outilsAvant = outilsDesEvenements(t.x.repertoire);
      expect(t.noeud.ancres.size).to.be.at.least(1);
      expect([...t.noeud.ancres.values()].every((a) => a.issuer === t.ancienne)).to.equal(true);
      // Sans demande déposée : refus nommé, rien n'est envoyé.
      expect(await t.coeur.rotationUrgence()).to.deep.equal({ accepte: false, raison: "revocation_demande_absente" });
      const repertoireJournal = t.x.repertoire;
      const pub = N.octetsVersHex(N.clePubliqueEd25519(graine(t.x.config.signer.key_id)));
      const enr = t.noeud.enregistreurs.get(t.commun.orgId + t.ancienne);
      deposerDemande(repertoireJournal, demandeRevocation({ ...t.commun, chainKey: t.ancienne, registeredAt: enr.registeredAt }));
      // Demande d'inscription d'une autre clé Ed25519 : refus nommé avant tout envoi.
      deposerDemande(repertoireJournal, demandeInscription({ ...t.commun, journalId: t.x.config.recorder.journal_id, chainKey: t.suivante.adresse, ed25519: N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-02"))) }));
      expect(await t.coeur.rotationUrgence()).to.deep.equal({ accepte: false, raison: "inscription_demande_invalide" });
      expect(t.noeud.enregistreurs.get(t.commun.orgId + t.ancienne).revokedAt).to.equal(0n);
      deposerDemande(repertoireJournal, demandeInscription({ ...t.commun, journalId: t.x.config.recorder.journal_id, chainKey: t.suivante.adresse, ed25519: pub }));
      const r = await t.coeur.rotationUrgence();
      expect(r.accepte, JSON.stringify(r)).to.equal(true);
      expect(r.cleChaine).to.deep.include({ ancienne: t.ancienne, nouvelle: t.suivante.adresse, registry: { revocation: "incluse", inscription: "incluse" } });
      const ligne = t.coeur.journal.trouver("key_rotation_emergency").at(-1);
      expect(ligne.data).to.deep.include({ chain_key_only: true, old_chain_key: t.ancienne, new_chain_key: t.suivante.adresse });
      expect(ligne.seq ?? null).to.equal(null);
      expect(t.coeur.journal.trouver("chain_key_switched").at(-1).data).to.deep.include({ old_chain_key: t.ancienne, new_chain_key: t.suivante.adresse, reason: "rotation_cle_chaine" });
      const relais = t.coeur.journal.trouver("chain_key_revocation_relayed").concat(t.coeur.journal.trouver("chain_key_registration_relayed"));
      expect(relais.map((l) => [l.data.operation, l.data.issue, l.data.sender])).to.deep.equal([["revocation", "incluse", t.suivante.adresse], ["inscription", "incluse", t.suivante.adresse]]);
      // Au registre (factice) : ancienne révoquée, même clé Ed25519 active sous la nouvelle.
      expect(t.noeud.enregistreurs.get(t.commun.orgId + t.ancienne).revokedAt > 0n).to.equal(true);
      expect(t.noeud.enregistreurs.get(t.commun.orgId + t.suivante.adresse)).to.deep.include({ ed25519PubKey: pub, revokedAt: 0n });
      const captures = fs.readdirSync(path.join(repertoireJournal, "registre")).filter((n) => n.startsWith("capture-"));
      expect(captures.some((n) => n.endsWith("-revocation.json"))).to.equal(true);
      expect(captures.some((n) => n.endsWith("-inscription.json"))).to.equal(true);
      // JS-5 : aucun événement de la chaîne ne porte la rotation de la clé de chaîne.
      const outilsApres = outilsDesEvenements(repertoireJournal);
      expect(outilsApres).to.deep.equal(outilsAvant);
      expect(t.ancrage.etat()).to.include({ chain_key: t.suivante.adresse, next_chain_key: null });
      // Ancres suivantes : émises par la nouvelle clé de chaîne.
      const avant = new Set(t.noeud.ancres.keys());
      await minute(t, 2);
      await minute(t, 3);
      const nouvelles = [...t.noeud.ancres].filter(([fp]) => !avant.has(fp)).map(([, a]) => a.issuer);
      expect(nouvelles.length).to.be.at.least(1);
      expect(nouvelles.every((a) => a === t.suivante.adresse), JSON.stringify(nouvelles)).to.equal(true);
      // Une seconde demande : la clé de chaîne suivante est consommée (jusqu'à une nouvelle configuration).
      expect((await t.coeur.rotationUrgence()).raison).to.equal("cle_chaine_suivante_absente");
    } finally {
      await t?.coeur?.arreter().catch(() => {});
      await t?.x?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("EX-11.16 relayée, dans l'ordre : (1) inscription de la nouvelle paire (next_chain_key, clé rec-test-02) relayée depuis la demande déposée — sans elle, refus inscription_demande_absente et rien n'est écrit ; (2) événement noortrace.journal.rotation-cle scellé ; (3) révocation de l'ancienne clé de chaîne relayée ; les documents de la nouvelle clé Ed25519 sont ancrés par la nouvelle clé de chaîne", async function () {
    const dir = repertoireTemporaire("noortrace-e7-ex1116-factice-");
    let t;
    try {
      t = await monter(dir, { nextKeyId: "rec-test-02" });
      if (t.condition) return enAttente(this, t.condition);
      await minute(t, 1);
      const avantRefus = outilsDesEvenements(t.x.repertoire).length;
      expect(await t.coeur.rotationUrgence()).to.deep.equal({ accepte: false, raison: "inscription_demande_absente" });
      expect(outilsDesEvenements(t.x.repertoire).length).to.equal(avantRefus);
      const pub2 = N.octetsVersHex(N.clePubliqueEd25519(graine("rec-test-02")));
      deposerDemande(t.x.repertoire, demandeInscription({ ...t.commun, journalId: t.x.config.recorder.journal_id, chainKey: t.suivante.adresse, ed25519: pub2 }));
      const enr = t.noeud.enregistreurs.get(t.commun.orgId + t.ancienne);
      deposerDemande(t.x.repertoire, demandeRevocation({ ...t.commun, chainKey: t.ancienne, registeredAt: enr.registeredAt }));
      const r = await t.coeur.rotationUrgence();
      expect(r.accepte, JSON.stringify(r)).to.equal(true);
      expect(r.evenement.execution.tool).to.equal("noortrace.journal.rotation-cle");
      const ligne = t.coeur.journal.trouver("key_rotation_emergency").at(-1);
      expect(ligne.data).to.deep.include({ old_key_id: "rec-test-01", new_key_id: "rec-test-02", registry: { inscription: "incluse", revocation: "incluse" } });
      // Ordre d'EX-11.16 au journal d'exploitation : inscription relayée, rotation, révocation relayée.
      const ordre = t.coeur.journal.lignes
        .filter((l) => ["chain_key_registration_relayed", "key_rotated", "chain_key_revocation_relayed"].includes(l.event)).map((l) => l.event);
      expect(ordre).to.deep.equal(["chain_key_registration_relayed", "key_rotated", "chain_key_revocation_relayed"]);
      expect(t.noeud.enregistreurs.get(t.commun.orgId + t.suivante.adresse)).to.deep.include({ ed25519PubKey: pub2, revokedAt: 0n });
      expect(t.noeud.enregistreurs.get(t.commun.orgId + t.ancienne).revokedAt > 0n).to.equal(true);
      // EX-11.19 point 3 : documents de rec-test-02 ancrés par la nouvelle clé de chaîne.
      expect(t.ancrage.cleChainePour("rec-test-02").adresse()).to.equal(t.suivante.adresse);
      expect(t.ancrage.cleChainePour("rec-test-01").adresse()).to.equal(t.ancienne);
      const avant = new Set(t.noeud.ancres.keys());
      await minute(t, 2);
      await minute(t, 3);
      const nouvelles = [...t.noeud.ancres].filter(([fp]) => !avant.has(fp)).map(([, a]) => a.issuer);
      expect(nouvelles.length).to.be.at.least(1);
      expect(nouvelles.every((a) => a === t.suivante.adresse), JSON.stringify(nouvelles)).to.equal(true);
    } finally {
      await t?.coeur?.arreter().catch(() => {});
      await t?.x?.fermer?.();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
