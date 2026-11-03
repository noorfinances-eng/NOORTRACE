// Signataires de production des classes A, B et C (CT-2 §11 ; EX-11.1 à
// EX-11.10, EX-11.14 à EX-11.18 ; EX-14.11 ; EX-15.4 pas 3 et 5) : chaque
// exigence en réussite et en échec, backend par backend, contre :
//
// - classe A : SoftHSM2 réel (paquet du système), par l'auxiliaire PKCS#11 ;
//   un auxiliaire hostile (signature tronquée, d'un autre message, d'une
//   autre clé, jamais rendue) éprouve EX-11.6 et le délai d'EX-11.18 ;
// - classe B : Vault et OpenBao réels (conteneurs épinglés par condensé) ;
//   AWS KMS et Google Cloud KMS par les simulateurs de
//   fixtures/enregistreur-signataires/simulateurs.mjs (LocalStack 4.0.3
//   n'implémente pas ECC_NIST_EDWARDS25519 : `CreateKey` rend InternalError ;
//   Google n'a pas d'émulateur de KMS) ;
// - classe C : AWS KMS par LocalStack réel (Encrypt/Decrypt avec contexte),
//   TPM 2.0 logiciel réel (swtpm + tpm2-tools), Google Cloud KMS et Azure Key
//   Vault par simulateurs.
//
// Pour chaque backend, dans un cœur réel (Coeur.demarrer) : clé publique et
// signature de test au démarrage, ligne `signer_ready` (classe, backend,
// identifiant de clé, jamais le secret), appel d'écriture signé et vérifié,
// rotation (§11.4) vers la clé suivante, journal vérifié (signatures sous les
// clés de la chaîne) ; pour les classes A et B, panne du backend → mode
// dégradé « clé » (-31017 après relais, rien de scellé), puis sortie par
// `health()` et une signature de test (EX-14.11). Un test qui exige Docker ou
// un logiciel système absent est mis en attente, son titre nomme la condition.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, ErreurEnregistreur, SignataireVerifie, SignatairePkcs11, SignataireTransit, SignataireAwsKms, SignataireCloudKms, SignataireEnveloppe,
  ClientKms, ClientCloudKms, ErreurSignataire, MECANISMES_PKCS11, crc32c, clePubliqueSpki, contexteChiffrement, entetesSigv4Kms,
  signataireDepuisConfiguration, environnementAuxiliaire, validerConfiguration, resoudreSecrets, pieceJson, lireEvenements,
  verifierRepertoireJournal, principal, desceller, AUXILIAIRE_PKCS11, lireSecretsVault, compterAuditTransit, rapprocher,
} from "@noortrace/enregistreur";
import { REFERENCE, configurationDemon, demarrer, arreter } from "./fixtures/enregistreur-adversarial/demon.mjs";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { ctl } from "./fixtures/enregistreur-signataires/ta.mjs";
import { configurationDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { certificats } from "./fixtures/enregistreur-worm/outils.mjs";
import { simulateurAwsKms, simulateurCloudKms, simulateurAzure, simulateurImds, simulateurMetadonneesGoogle } from "./fixtures/enregistreur-signataires/simulateurs.mjs";
import {
  IMAGES_SIGNATAIRES, dockerEtImage, softHsmDisponible, jetonSoftHsm, demarrerTransit, demarrerKmsLocalStack, tpmDisponible, demarrerSwtpm,
  arreterConteneurs, suspendreConteneur,
} from "./fixtures/enregistreur-signataires/outils.mjs";

const HOSTILE = path.join(path.dirname(new URL(import.meta.url).pathname), "fixtures", "enregistreur-signataires", "pkcs11-hostile.py");
const enAttente = (ctx, condition) => {
  ctx.test.title += ` — en attente : ${condition}`;
  ctx.skip();
};

let dir;
let tls;
before(function () {
  dir = repertoireTemporaire("noortrace-signataires-");
  tls = certificats(path.join(dir, "tls"));
});
after(function () {
  arreterConteneurs();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------------ outils

let nDir = 0;
/** Configuration de développement (ou de production) dont le signataire est `signer` ; rend { config, secrets, env }. */
function configuration(signer, o = {}) {
  const d = path.join(dir, `j${++nDir}`);
  fs.mkdirSync(d, { recursive: true });
  const { config, env } = configurationDev(d, { environment: o.environment ?? "developpement" });
  config.signer = { verify_after_sign: true, max_message_bytes: null, timeout_ms: 5000, health_interval_ms: 100, rotation: { planned_every_days: null, next_key_id: null }, ...signer };
  Object.assign(env, o.env ?? {});
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  if (v.erreurs.length) throw new Error(JSON.stringify(v.erreurs));
  const s = resoudreSecrets(v.config, { env });
  if (s.erreurs.length) throw new Error(JSON.stringify(s.erreurs));
  return { config: v.config, secrets: s.secrets, env, dir: d };
}

let nAppel = 0;
/** Un appel d'écriture relayé puis scellé (4.4 pas 7 à 13) ; rend l'événement. */
async function appelEcriture(coeur) {
  const n = String(++nAppel);
  const args = pieceJson({ claim_id: n });
  await coeur.ecrirePiece(args);
  const appel = {
    host: { id: "agent-sinistres-stdio" },
    delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "s", run_id: null },
    tool_announced: "sap__payments.create", tool_original: "payments.create", server_alias: "sap", class: "ecriture",
    arguments: args.reference, context: [], intent: null, code: {},
  };
  const relais = await coeur.preparerRelais(appel, {
    reponse: { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
    argumentsEnClair: { claim_id: n }, upstream_id: `e-${n.padStart(12, "0")}`,
  });
  return coeur.terminerRelais(relais, { resultat: pieceJson({ content: [], isError: false }), resultatRedige: { content: [], isError: false }, argumentsRediges: { claim_id: n }, duration_ms: 1, is_error: false });
}

async function attendreQue(f, ms = 15000) {
  const fin = Date.now() + ms;
  while (Date.now() < fin) {
    if (await f()) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}

/**
 * Parcours commun d'un backend dans un cœur réel : démarrage (signer_ready),
 * appel signé, rotation, appel sous la nouvelle clé, journal vérifié ;
 * `casser`/`reparer` (classes A et B) : mode dégradé « clé » et sa sortie.
 * Rend les observations.
 */
async function parcoursCoeur(x, o = {}) {
  const backend = o.backend ?? (await signataireDepuisConfiguration(x.config, x.secrets, { env: x.env, ca: tls.caPem }));
  const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, signataire: backend });
  const obs = { backend };
  try {
    obs.pret = coeur.journal.trouver("signer_ready");
    obs.ops = fs.readFileSync(x.config.supervision.ops_log.path, "utf8");
    const cle0 = x.config.signer.key_id;
    obs.publique0 = await coeur.signataire.clePublique(cle0);
    const e1 = await appelEcriture(coeur);
    obs.e1 = e1;
    obs.sig1 = N.verifierEd25519(obs.publique0, N.messageSignatureEvenement(e1), N.hexVersOctets(e1.sig, 64));
    if (o.casser) {
      const avant = (await lireEvenements(coeur.repertoire)).length;
      await o.casser();
      try {
        await appelEcriture(coeur);
      } catch (e) {
        obs.erreurApresRelais = e;
      }
      obs.degradeCle = coeur.degrade.actif("cle");
      obs.santeDegradee = coeur.sante().corps;
      try {
        await appelEcriture(coeur);
      } catch (e) {
        obs.erreurAvantRelais = e;
      }
      obs.attentePendantPanne = coeur.attente.length;
      obs.evenementsPendantPanne = (await lireEvenements(coeur.repertoire)).length - avant;
      obs.indisponible = coeur.journal.trouver("signer_unavailable");
      await o.reparer();
      obs.sortie = await attendreQue(async () => {
        await coeur.tic();
        return !coeur.degrade.actif("cle");
      });
      obs.sortieLigne = coeur.journal.trouver("degraded_exit").some((l) => l.data?.reason === "cle");
      obs.attenteScellee = coeur.attente.length === 0;
    }
    if (x.config.signer.rotation.next_key_id) {
      obs.rotation = await coeur.tournerCle(x.config.signer.rotation.next_key_id);
      obs.e2 = await appelEcriture(coeur);
      obs.publique1 = await coeur.signataire.clePublique(x.config.signer.rotation.next_key_id);
    }
    obs.evts = await lireEvenements(coeur.repertoire);
    obs.verification = await verifierRepertoireJournal(coeur.repertoire, {
      org_id: x.config.recorder.org_id, journal_id: x.config.recorder.journal_id, clePublique: async (id) => (id === cle0 ? obs.publique0 : null), dernierOuvert: true,
    });
  } finally {
    await coeur.arreter();
  }
  obs.opsFin = fs.readFileSync(x.config.supervision.ops_log.path, "utf8");
  return obs;
}

/** Assertions communes d'un parcours (classe, backend, secrets jamais consignés, rotation, journal vérifié). */
function verifierParcours(obs, classe, type, secretsInterdits = []) {
  expect(obs.pret, "signer_ready").to.have.length(1);
  expect(obs.pret[0].data).to.include({ class: classe, backend: type });
  expect(obs.pret[0].data.key_id).to.be.a("string");
  expect(obs.opsFin).to.include(`"class":"${classe}"`);
  expect(obs.opsFin, "signature de test consignée (rapprochement, CT-7 EX-3.7)").to.include('"event":"signer_test_signature"');
  for (const s of secretsInterdits) expect(obs.opsFin, "secret consigné").to.not.include(s);
  expect(obs.sig1, "signature vérifiée sous la clé publique (EX-11.6)").to.equal(true);
  if (obs.rotation) {
    expect(obs.rotation.execution.tool).to.equal("noortrace.journal.rotation-cle");
    expect(obs.e2.recorder_key_id).to.not.equal(obs.e1.recorder_key_id);
    expect(N.verifierEd25519(obs.publique1, N.messageSignatureEvenement(obs.e2), N.hexVersOctets(obs.e2.sig, 64))).to.equal(true);
  }
  expect(obs.verification.incidents, JSON.stringify(obs.verification.incidents)).to.deep.equal([]);
}

function verifierPanne(obs) {
  expect(obs.erreurApresRelais, "panne après relais").to.be.instanceOf(ErreurEnregistreur);
  expect(obs.erreurApresRelais.code).to.equal(-31017);
  expect(obs.erreurApresRelais.raison).to.equal("cle");
  expect(obs.degradeCle).to.equal(true);
  expect(obs.santeDegradee.status).to.equal("down");
  // Le refus avant relais (-31010 `cle`, bloquant pour tout) est rendu par le
  // frontal (_etatPanne) : il est éprouvé sur le démon réel (parcours, TA-33) ;
  // dans le cœur seul, le second appel n'est pas scellé non plus.
  expect(obs.erreurAvantRelais, "second appel non scellé").to.be.instanceOf(ErreurEnregistreur);
  expect(obs.erreurAvantRelais.raison).to.equal("cle");
  expect(obs.evenementsPendantPanne, "aucun événement scellé sans clé").to.equal(0);
  expect(obs.indisponible.length).to.be.at.least(1);
  expect(obs.sortie, "sortie du mode « clé » : health() et signature de test (EX-14.11)").to.equal(true);
  expect(obs.sortieLigne).to.equal(true);
  expect(obs.attentePendantPanne, "événements complets gardés en attente (EX-4.46)").to.equal(2);
  expect(obs.attenteScellee, "événements gardés en attente scellés à la sortie (EX-14.10)").to.equal(true);
}

// ------------------------------------------------------------------ configuration et fabrique

describe("signataires : configuration et fabrique (EX-11.8, EX-15.4 pas 3)", function () {
  const base = () => configurationDev(path.join(dir, `cfg${++nDir}`)).config;
  const pkcs11 = { type: "pkcs11", module: "/opt/fabricant/lib/libpkcs11.so", token_label: "noortrace", key_label: "rec-a-01", pin: { env: "PIN" }, mechanism: "CKM_EDDSA" };
  const vault = { type: "vault-transit", url: "https://127.0.0.1:8200", mount: "transit", key_name: "rec-b-01", token: { env: "JETON" }, namespace: null };
  const enveloppe = { type: "envelope", sealed_seed_file: "/var/lib/noortrace/graine.bin", wrap: { type: "aws-kms", key_arn: "arn:aws:kms:eu-west-3:111122223333:key/k1", region: "eu-west-3" } };
  const valider = (c) => validerConfiguration(new TextEncoder().encode(JSON.stringify(c)));

  for (const [classe, backend, ok] of [["A", pkcs11, true], ["B", vault, true], ["C", enveloppe, true], ["B", pkcs11, false], ["A", vault, false], ["D", enveloppe, false], ["C", { type: "file", path: "/x.pem", passphrase: null }, false]]) {
    it(`classe ${classe} avec backend ${backend.type} : ${ok ? "admise" : "refusée, /signer/backend/type (EX-15.4 pas 3)"}`, function () {
      const c = base();
      c.signer = { ...c.signer, class: classe, key_id: "rec-x-01", backend };
      const v = valider(c);
      const e = v.erreurs.filter((x) => x.pointeur === "/signer/backend/type");
      expect(e, JSON.stringify(v.erreurs)).to.have.length(ok ? 0 : 1);
    });
  }

  it("production : classe D refusée (EX-11.8) ; A, B et C admises ; module SoftHSM2 déclaré en classe A : avertissement, pas erreur (EX-15.4 pas 3, lecture 181)", function () {
    for (const [classe, backend, attendu] of [["D", { type: "file", path: "/x.pem", passphrase: null }, "erreur"], ["A", pkcs11, "rien"], ["B", vault, "rien"], ["C", enveloppe, "rien"], ["A", { ...pkcs11, module: "/usr/lib/softhsm/libsofthsm2.so" }, "avertissement"]]) {
      const c = base();
      c.recorder.environment = "production";
      c.signer = { ...c.signer, class: classe, key_id: "rec-x-01", backend };
      const v = valider(c);
      const err = v.erreurs.filter((x) => x.pointeur.startsWith("/signer"));
      const av = v.avertissements.filter((x) => x.pointeur.startsWith("/signer"));
      expect(err.length, `${classe} ${JSON.stringify(err)}`).to.equal(attendu === "erreur" ? 1 : 0);
      expect(av.length, `${classe} ${JSON.stringify(av)}`).to.equal(attendu === "avertissement" ? 1 : 0);
    }
  });

  it("la fabrique rend le backend de chaque type, de la classe déclarée ; incohérence refusée même hors validation", async function () {
    const c = base();
    const s = new Map([["/signer/backend/token", new TextEncoder().encode("j")], ["/signer/backend/pin", new TextEncoder().encode("1")]]);
    const cas = [
      [{ class: "A", backend: pkcs11 }, SignatairePkcs11, "A", "pkcs11"],
      [{ class: "B", backend: vault }, SignataireTransit, "B", "vault-transit"],
      [{ class: "B", backend: { ...vault, type: "openbao-transit" } }, SignataireTransit, "B", "openbao-transit"],
      [{ class: "B", backend: { type: "aws-kms", key_arn: "arn:aws:kms:eu-west-3:111122223333:key/k1", region: "eu-west-3" } }, SignataireAwsKms, "B", "aws-kms"],
    ];
    for (const [signer, Classe, classe, type] of cas) {
      const b = await signataireDepuisConfiguration({ ...c, signer: { ...c.signer, ...signer, key_id: "rec-x-01" } }, s, { env: { AWS_ACCESS_KEY_ID: "a", AWS_SECRET_ACCESS_KEY: "b", PATH: "" } });
      expect(b).to.be.instanceOf(Classe);
      expect([b.classe, b.typeBackend]).to.deep.equal([classe, type]);
      b.effacer();
    }
    let e;
    try {
      await signataireDepuisConfiguration({ ...c, signer: { ...c.signer, class: "C", backend: vault } }, s);
    } catch (x) {
      e = x;
    }
    expect(e).to.be.instanceOf(ErreurSignataire);
    expect(e.message).to.match(/incohérent avec la classe C/);
  });

  it("aucun secret de la configuration n'est transmis à un auxiliaire (EX-15.3) : variables désignées par une référence { env } retirées", function () {
    const c = base();
    c.signer.backend = { ...pkcs11, pin: { env: "NOORTRACE_PKCS11_PIN" } };
    const env = environnementAuxiliaire(c, { PATH: "/bin", NOORTRACE_PKCS11_PIN: "1234", NOORTRACE_TEST_CLE_MAC: "x", SOFTHSM2_CONF: "/c" });
    expect(env).to.deep.equal({ PATH: "/bin", SOFTHSM2_CONF: "/c" });
  });

  it("CKM_CLOUDHSM_EDDSA : table de correspondance sans valeur établie → refus explicite plutôt qu'une valeur devinée (EX-11.10, lecture 176) ; CKM_EDDSA = 0x1057", function () {
    expect(MECANISMES_PKCS11.CKM_EDDSA).to.equal(0x1057);
    expect(() => new SignatairePkcs11({ backend: { ...pkcs11, mechanism: "CKM_CLOUDHSM_EDDSA" }, pin: new Uint8Array(1), keyId: "k" })).to.throw(ErreurSignataire, /valeur numérique non établie/);
    expect(() => new SignatairePkcs11({ backend: { ...pkcs11, mechanism: "CKM_ECDSA" }, pin: new Uint8Array(1), keyId: "k" })).to.throw(ErreurSignataire, /inconnu/);
  });

  it("outils : CRC32C (vecteur de la RFC 3720 B.4 : 32 octets nuls → 0x8a9136aa), SPKI Ed25519 (RFC 8410), contexte de chiffrement JCS (org_id, journal_id, key_id seulement)", function () {
    expect(crc32c(new Uint8Array(32))).to.equal(0x8a9136aa);
    expect(crc32c(new TextEncoder().encode("123456789"))).to.equal(0xe3069283);
    const p = N.clePubliqueEd25519(N.sha256(N.utf8("x")));
    expect(clePubliqueSpki(Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(p)]))).to.deep.equal(p);
    expect(() => clePubliqueSpki(Buffer.alloc(44))).to.throw(ErreurSignataire);
    const ctx = contexteChiffrement({ org_id: "0xab", journal_id: "0xcd", key_id: "rec-c-01", secret: "jamais" });
    expect(ctx.carte).to.deep.equal({ org_id: "0xab", journal_id: "0xcd", key_id: "rec-c-01" });
    expect(Buffer.from(ctx.octets).toString()).to.equal('{"journal_id":"0xcd","key_id":"rec-c-01","org_id":"0xab"}');
  });

  it("SigV4 du service kms : signature recalculée et vérifiée côté serveur par le simulateur ; clé secrète fausse refusée (403) ; forme de l'en-tête Authorization (portée kms, en-têtes signés)", async function () {
    const sim = await simulateurAwsKms(tls);
    try {
      const { arn } = sim.creerCle();
      const bon = new ClientKms({ region: sim.region, env: sim.env, ca: tls.caPem });
      expect((await bon.appeler("DescribeKey", { KeyId: arn })).KeyMetadata.KeyState).to.equal("Enabled");
      const faux = new ClientKms({ region: sim.region, env: { ...sim.env, AWS_SECRET_ACCESS_KEY: "autre" }, ca: tls.caPem });
      let e;
      try {
        await faux.appeler("DescribeKey", { KeyId: arn });
      } catch (x) {
        e = x;
      }
      expect(e.statut).to.equal(403);
      const h = entetesSigv4Kms({ hote: "kms.eu-west-3.amazonaws.com", region: "eu-west-3", cible: "TrentService.Sign", corps: Buffer.from("{}"), identifiants: { access_key_id: "AK", secret_access_key: "SK", session_token: "ST" }, instant: Date.UTC(2026, 10, 3) });
      expect(h["x-amz-date"]).to.equal("20261103T000000Z");
      expect(h.authorization).to.match(/^AWS4-HMAC-SHA256 Credential=AK\/20261103\/eu-west-3\/kms\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/);
    } finally {
      await sim.fermer();
    }
  });
});

// ------------------------------------------------------------------ classe A

describe("classe A : PKCS#11 (EX-11.10) sur SoftHSM2 réel, par l'auxiliaire", function () {
  this.timeout(120000);
  const dispo = softHsmDisponible();
  let j;
  before(function () {
    if (!dispo.ok) return;
    j = jetonSoftHsm(path.join(dir, "hsm"));
    j.pub = {
      "rec-a-01": j.ceremonie("rec-a-01", "curveName"),
      "rec-a-02": j.ceremonie("rec-a-02", "oid"),
      "rec-a-x": j.ceremonie("rec-a-x", "oid", true),
      "rec-a-autre": j.ceremonie("rec-a-autre", "oid"),
    };
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });
  const backendA = (label, o = {}) =>
    new SignatairePkcs11({ backend: { module: j.module, token_label: j.etiquette, key_label: label, mechanism: "CKM_EDDSA" }, pin: Buffer.from(o.pin ?? j.pin), keyId: label, nextKeyId: o.next ?? null, delaiMs: o.delaiMs ?? 5000, env: { PATH: process.env.PATH, ...j.env, ...(o.env ?? {}) }, auxiliaire: o.auxiliaire });

  it("CKA_EC_PARAMS sous ses deux formes (curveName edwards25519, OID 1.3.101.112) ; clé publique lue dans CKA_EC_POINT, égale à celle de la cérémonie ; forme consignée", async function () {
    for (const [label, forme] of [["rec-a-01", "curveName"], ["rec-a-02", "oid"]]) {
      const b = backendA(label);
      try {
        expect(N.octetsVersHex(await b.clePublique(label))).to.equal(`0x${j.pub[label]}`);
        expect(b.formes.get(label).ec_params).to.equal(forme);
      } finally {
        b.effacer();
      }
    }
  });

  it("CKM_EDDSA sans paramètre, C_Sign en une partie : signature de 64 octets R ‖ S vérifiée (EX-11.6) sur les trois formes de message (P_S, P_SM, P_R) ; message de 16 000 octets signé", async function () {
    const b = backendA("rec-a-01");
    const v = new SignataireVerifie(b, { timeout_ms: 5000 });
    try {
      const p = await v.clePublique("rec-a-01");
      for (const prefixe of [N.PREFIXES.P_S, N.PREFIXES.P_SM, N.PREFIXES.P_R]) {
        const m = new Uint8Array([...prefixe, ...new TextEncoder().encode('{"a":1}')]);
        const s = await v.signer("rec-a-01", m);
        expect(s).to.have.length(64);
        expect(N.verifierEd25519(p, m, s)).to.equal(true);
      }
      const grand = new Uint8Array(16000).fill(7);
      expect(N.verifierEd25519(p, grand, await v.signer("rec-a-01", grand))).to.equal(true);
      expect(await v.sante()).to.equal("ok");
    } finally {
      b.effacer();
    }
  });

  it("clé extractible ou non sensible refusée (EX-11.5) ; étiquette inconnue, PIN faux : erreur sans le PIN dans le message", async function () {
    for (const [b, motif] of [[backendA("rec-a-x"), /extractible/], [backendA("rec-a-inconnue"), /introuvable/], [backendA("rec-a-01", { pin: "0000" }), /C_Login/]]) {
      let e;
      try {
        await b.clePublique(b.keyId);
      } catch (x) {
        e = x;
      }
      b.effacer();
      expect(e, String(motif)).to.be.instanceOf(ErreurSignataire);
      expect(e.message).to.match(motif);
      expect(e.message).to.not.include("0000");
    }
  });

  it("entrées hostiles : signature tronquée, d'un autre message, d'une autre clé → panne « clé » consignée (EX-11.6) ; module qui ne répond pas → auxiliaire tué au délai, une seule seconde tentative (EX-11.18)", async function () {
    for (const mode of ["longueur", "autre_message", "autre_cle", "lent"]) {
      const b = backendA("rec-a-01", { auxiliaire: HOSTILE, delaiMs: 400, env: { NOORTRACE_TEST_PKCS11_MODE: mode, NOORTRACE_TEST_PKCS11_AUTRE: "rec-a-autre" } });
      const lignes = [];
      const v = new SignataireVerifie(b, { timeout_ms: 400 }, { journal: { consigner: (...a) => lignes.push(a) } });
      let e;
      const t0 = Date.now();
      try {
        await v.signer("rec-a-01", new Uint8Array([1, 2, 3]));
      } catch (x) {
        e = x;
      }
      const duree = Date.now() - t0;
      b.effacer();
      expect(e, mode).to.be.instanceOf(ErreurEnregistreur);
      expect(e.raison).to.equal("cle");
      expect(lignes.map((l) => l[2])).to.include("signer_unavailable");
      if (mode === "lent") {
        expect(e.donnees.raison).to.equal("signature");
        expect(duree, "deux essais de 400 ms, pas davantage").to.be.within(750, 2500);
      } else {
        expect(e.donnees.raison, mode).to.equal("signature_invalide");
      }
    }
  });

  it("dans un cœur réel : signer_ready (classe A, pkcs11, étiquettes, forme des paramètres ; jamais le PIN), appel signé, module injoignable → mode dégradé « clé » et sortie (EX-14.11), rotation vers rec-a-02, journal vérifié", async function () {
    const x = configuration(
      { class: "A", key_id: "rec-a-01", backend: { type: "pkcs11", module: j.module, token_label: j.etiquette, key_label: "rec-a-01", pin: { env: "NOORTRACE_TEST_PIN" }, mechanism: "CKM_EDDSA" }, rotation: { planned_every_days: null, next_key_id: "rec-a-02" } },
      { env: { NOORTRACE_TEST_PIN: j.pin, ...j.env } },
    );
    const backend = await signataireDepuisConfiguration(x.config, x.secrets, { env: { ...process.env, ...x.env } });
    const obs = await parcoursCoeur(x, {
      backend,
      casser: async () => {
        backend.auxiliaire = path.join(dir, "absent.py");
        backend.proc?.p.kill("SIGKILL");
        await attendreQue(() => backend.proc === null, 5000);
      },
      reparer: async () => {
        backend.auxiliaire = AUXILIAIRE_PKCS11;
      },
    });
    verifierParcours(obs, "A", "pkcs11", [`"${j.pin}"`]);
    expect(obs.pret[0].data.backend_key).to.deep.include({ token_label: j.etiquette, key_label: "rec-a-01", mechanism: "CKM_EDDSA" });
    expect(obs.pret[0].data.pkcs11).to.deep.equal({ ec_params: "curveName", ec_point: "der" });
    verifierPanne(obs);
    expect(obs.backend.pin.every((o) => o === 0), "PIN effacé à l'arrêt").to.equal(true);
    expect(obs.backend.proc).to.equal(null);
  });
});

// ------------------------------------------------------------------ classe B : Vault et OpenBao

for (const type of ["vault-transit", "openbao-transit"]) {
  describe(`classe B : ${type} réel (conteneur épinglé), Transit ed25519 non exportable`, function () {
    this.timeout(300000);
    const dispo = dockerEtImage(IMAGES_SIGNATAIRES[type]);
    let srv;
    let jeton;
    before(async function () {
      if (!dispo.ok) return;
      srv = await demarrerTransit(type, `noortrace-test-sign-${type}-${process.pid}`, tls);
      for (const k of ["rec-b-01", "rec-b-02", "rec-b-04"]) await srv.creerCle(k);
      await srv.creerCle("rec-b-exportable", { exportable: true });
      await srv.creerCle("rec-b-ecdsa", { type: "ecdsa-p256" });
      jeton = await srv.jetonUsage(["rec-b-01", "rec-b-02", "rec-b-04", "rec-b-exportable", "rec-b-ecdsa"]);
    });
    after(async function () {
      await srv?.arreter();
    });
    beforeEach(function () {
      if (!dispo.ok) enAttente(this, dispo.condition);
    });
    const backendB = (nom, o = {}) =>
      new SignataireTransit({ backend: { type, url: srv.origine, mount: "transit", key_name: nom, namespace: null }, jeton: new TextEncoder().encode(o.jeton ?? jeton), keyId: nom, delaiMs: o.delaiMs ?? 5000, ca: tls.caPem });

    it("clé publique de la dernière version (32 octets), signature Ed25519 pure vérifiée, version épinglée ; jeton d'usage seul (EX-11.4)", async function () {
      const b = backendB("rec-b-01");
      const v = new SignataireVerifie(b, { timeout_ms: 5000 });
      const p = await v.clePublique("rec-b-01");
      const m = new Uint8Array([...N.PREFIXES.P_S, 1, 2, 3]);
      expect(N.verifierEd25519(p, m, await v.signer("rec-b-01", m))).to.equal(true);
      expect(b.versions.get("rec-b-01")).to.equal(1);
      // Le jeton d'usage ne peut ni créer ni exporter de clé.
      const r = await fetch(`${srv.direct}/v1/transit/keys/rec-b-autre`, { method: "POST", headers: { "x-vault-token": jeton }, body: JSON.stringify({ type: "ed25519" }) });
      expect(r.status).to.equal(403);
    });

    it("rotation faite dans le backend (nouvelle version) : la version lue reste épinglée, la signature vérifie toujours sous la clé publique lue", async function () {
      const b = backendB("rec-b-04");
      const v = new SignataireVerifie(b, { timeout_ms: 5000 });
      const p = await v.clePublique("rec-b-04");
      await srv.tournerDansBackend("rec-b-04");
      const m = new Uint8Array([...N.PREFIXES.P_S, 9]);
      expect(N.verifierEd25519(p, m, await v.signer("rec-b-04", m))).to.equal(true);
      expect(b.versions.get("rec-b-04")).to.equal(1);
    });

    it("clé exportable refusée (EX-11.5) ; clé d'un autre type refusée (EX-11.1) ; jeton faux : 403, sans le jeton dans le message", async function () {
      for (const [b, motif] of [[backendB("rec-b-exportable"), /exportable/], [backendB("rec-b-ecdsa"), /ed25519 attendu/], [backendB("rec-b-01", { jeton: "jeton-faux-123" }), /statut 403/]]) {
        let e;
        try {
          await b.clePublique(b.keyId);
        } catch (x) {
          e = x;
        }
        expect(e, String(motif)).to.be.instanceOf(ErreurSignataire);
        expect(e.message).to.match(motif);
        expect(e.message).to.not.include("jeton-faux-123");
      }
    });

    it("service suspendu (lent) : délai timeout_ms, une seule seconde tentative, panne « clé » (EX-11.18)", async function () {
      const b = backendB("rec-b-01", { delaiMs: 500 });
      const v = new SignataireVerifie(b, { timeout_ms: 500 });
      await v.clePublique("rec-b-01");
      suspendreConteneur(srv.nom, true);
      const t0 = Date.now();
      let e;
      try {
        await v.signer("rec-b-01", new Uint8Array([...N.PREFIXES.P_S, 1]));
      } catch (x) {
        e = x;
      } finally {
        suspendreConteneur(srv.nom, false);
      }
      expect(e).to.be.instanceOf(ErreurEnregistreur);
      expect(e.raison).to.equal("cle");
      expect(Date.now() - t0).to.be.within(900, 3000);
    });

    it("dans un cœur réel : signer_ready (classe B, URL, clé, version ; jamais le jeton), service suspendu → mode dégradé « clé » puis sortie, rotation vers rec-b-02, journal vérifié", async function () {
      const x = configuration(
        { class: "B", key_id: "rec-b-01", timeout_ms: 800, backend: { type, url: srv.origine, mount: "transit", key_name: "rec-b-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null }, rotation: { planned_every_days: null, next_key_id: "rec-b-02" } },
        { env: { NOORTRACE_TEST_JETON_TRANSIT: jeton } },
      );
      const obs = await parcoursCoeur(x, { casser: async () => suspendreConteneur(srv.nom, true), reparer: async () => suspendreConteneur(srv.nom, false) });
      verifierParcours(obs, "B", type, [jeton]);
      expect(obs.pret[0].data.backend_key).to.deep.include({ url: srv.origine, mount: "transit", key_name: "rec-b-01", key_version: 1 });
      verifierPanne(obs);
      expect(obs.backend.jeton.every((o) => o === 0), "jeton effacé à l'arrêt").to.equal(true);
    });
  });
}

// ------------------------------------------------------------------ classe B : AWS KMS et Google Cloud KMS (simulateurs)

describe("classe B : AWS KMS (simulateur : LocalStack 4.0.3 n'implémente pas ECC_NIST_EDWARDS25519)", function () {
  this.timeout(120000);
  let sim;
  let arn;
  let arnP256;
  before(async function () {
    sim = await simulateurAwsKms(tls);
    ({ arn } = sim.creerCle("ECC_NIST_EDWARDS25519"));
    sim.creerCle("ECC_NIST_EDWARDS25519", { alias: "rec-b-aws-02" });
    ({ arn: arnP256 } = sim.creerCle("ECC_NIST_P256"));
  });
  after(async function () {
    await sim?.fermer();
  });
  beforeEach(function () {
    sim.etat.mode = null;
    sim.etat.delaiMs = 0;
  });
  const backendAws = (cle = arn, o = {}) => new SignataireAwsKms({ backend: { key_arn: cle, region: sim.region }, keyId: "rec-b-aws-01", nextKeyId: "rec-b-aws-02", client: new ClientKms({ region: sim.region, env: sim.env, ca: tls.caPem, delaiMs: o.delaiMs ?? 5000 }) });

  it("requêtes exactes : GetPublicKey (ECC_NIST_EDWARDS25519, SIGN_VERIFY), Sign avec MessageType RAW et ED25519_SHA_512, jamais ED25519_PH_SHA_512 ; signature vérifiée", async function () {
    const b = backendAws();
    const v = new SignataireVerifie(b, { timeout_ms: 5000 });
    const p = await v.clePublique("rec-b-aws-01");
    const m = new Uint8Array([...N.PREFIXES.P_S, 4, 5]);
    expect(N.verifierEd25519(p, m, await v.signer("rec-b-aws-01", m))).to.equal(true);
    const signe = sim.compte.requetes.filter((r) => r.entetes["x-amz-target"] === "TrentService.Sign").map((r) => JSON.parse(r.corps));
    expect(signe.at(-1)).to.deep.include({ KeyId: arn, MessageType: "RAW", SigningAlgorithm: "ED25519_SHA_512" });
    expect(Buffer.from(signe.at(-1).Message, "base64")).to.deep.equal(Buffer.from(m));
    expect(await v.sante()).to.equal("ok");
  });

  it("clé suivante par alias du même compte (lecture 177) ; clé ECC_NIST_P256 refusée (EX-11.1) ; message de plus de 4096 octets refusé (EX-11.7)", async function () {
    const b = backendAws();
    expect(b.identifiantKms("rec-b-aws-02")).to.equal(`arn:aws:kms:${sim.region}:111122223333:alias/rec-b-aws-02`);
    expect((await b.clePublique("rec-b-aws-02")).length).to.equal(32);
    let e;
    try {
      await backendAws(arnP256).clePublique("rec-b-aws-01");
    } catch (x) {
      e = x;
    }
    expect(e.message).to.match(/ECC_NIST_EDWARDS25519 attendue/);
    e = null;
    try {
      await b.signer("rec-b-aws-01", new Uint8Array(4097));
    } catch (x) {
      e = x;
    }
    expect(e.code).to.equal("borne");
  });

  it("service qui ment (signature d'une autre clé, d'un autre message, pré-hachée Ed25519ph, tronquée, illisible) → panne « clé » (EX-11.6) ; service lent → deux essais au plus (EX-11.18)", async function () {
    for (const mode of ["autre_cle", "prehache", "longueur", "illisible", "lent"]) {
      sim.etat.mode = mode === "lent" ? null : mode;
      sim.etat.delaiMs = mode === "lent" ? 2000 : 0;
      const b = backendAws(arn, { delaiMs: 300 });
      const v = new SignataireVerifie(b, { timeout_ms: 300 });
      if (mode !== "lent") await v.clePublique("rec-b-aws-01");
      else v.publiques.set("rec-b-aws-01", new Uint8Array(32));
      const avant = sim.compte.requetes.filter((r) => r.entetes["x-amz-target"] === "TrentService.Sign").length;
      let e;
      try {
        await v.signer("rec-b-aws-01", new Uint8Array([...N.PREFIXES.P_S, 7]));
      } catch (x) {
        e = x;
      }
      expect(e, mode).to.be.instanceOf(ErreurEnregistreur);
      expect(e.raison).to.equal("cle");
      if (mode === "lent") {
        await new Promise((r) => setTimeout(r, 2200));
        expect(sim.compte.requetes.filter((r) => r.entetes["x-amz-target"] === "TrentService.Sign").length - avant, "une seule seconde tentative").to.equal(2);
      }
    }
  });

  it("dans un cœur réel : signer_ready (classe B, aws-kms, ARN ; jamais la clé secrète IAM), service qui ment → mode dégradé « clé » puis sortie, rotation vers l'alias suivant, journal vérifié", async function () {
    const x = configuration({ class: "B", key_id: "rec-b-aws-01", backend: { type: "aws-kms", key_arn: arn, region: sim.region }, max_message_bytes: 4096, rotation: { planned_every_days: null, next_key_id: "rec-b-aws-02" } }, { env: sim.env });
    const obs = await parcoursCoeur(x, { casser: async () => (sim.etat.mode = "autre_cle"), reparer: async () => (sim.etat.mode = null) });
    verifierParcours(obs, "B", "aws-kms", [sim.identifiants.secret_access_key]);
    expect(obs.pret[0].data.backend_key).to.deep.equal({ key_arn: arn, region: sim.region });
    verifierPanne(obs);
  });
});

describe("classe B : Google Cloud KMS (simulateur ; aucun émulateur de KMS n'existe)", function () {
  this.timeout(120000);
  let sim;
  let env;
  const nom = "projects/p/locations/europe-west1/keyRings/noortrace/cryptoKeys/rec-b-gcp-01/cryptoKeyVersions/1";
  before(async function () {
    sim = await simulateurCloudKms(tls);
    env = sim.environnement(path.join(dir, "compte-service.json"));
    sim.creerVersion(nom);
    sim.creerVersion(nom.replace("rec-b-gcp-01", "rec-b-gcp-02"));
    sim.creerVersion(nom.replace("rec-b-gcp-01", "rec-b-gcp-p256"), "EC_SIGN_P256_SHA256");
  });
  after(async function () {
    await sim?.fermer();
  });
  beforeEach(function () {
    sim.etat.mode = null;
  });
  const backendGcp = (v = nom) => new SignataireCloudKms({ backend: { key_version: v }, keyId: "rec-b-gcp-01", nextKeyId: "rec-b-gcp-02", client: new ClientCloudKms({ env, ca: tls.caPem }) });

  it("jeton par assertion JWT du compte de service ; getPublicKey (EC_SIGN_ED25519, pemCrc32c) ; asymmetricSign sur data (jamais digest) avec dataCrc32c, verifiedDataCrc32c et signatureCrc32c contrôlés ; signature vérifiée", async function () {
    const v = new SignataireVerifie(backendGcp(), { timeout_ms: 5000 });
    const p = await v.clePublique("rec-b-gcp-01");
    const m = new Uint8Array([...N.PREFIXES.P_SM, 1]);
    expect(N.verifierEd25519(p, m, await v.signer("rec-b-gcp-01", m))).to.equal(true);
    const r = sim.compte.requetes.find((q) => q.url.endsWith(":asymmetricSign"));
    const corps = JSON.parse(r.corps);
    expect(Object.keys(corps).sort()).to.deep.equal(["data", "dataCrc32c"]);
    expect(corps.dataCrc32c).to.equal(String(crc32c(m)));
    expect(sim.compte.requetes.filter((q) => q.url === "/token")).to.have.length(1);
    expect(await v.sante()).to.equal("ok");
  });

  it("entrées hostiles : CRC32C faux, données non vérifiées, autre version, autre clé, signature tronquée → panne ; version EC_SIGN_P256_SHA256 refusée (EX-11.1)", async function () {
    for (const mode of ["crc_faux", "non_verifie", "autre_version", "autre_cle", "longueur"]) {
      sim.etat.mode = mode;
      const v = new SignataireVerifie(backendGcp(), { timeout_ms: 5000 });
      v.publiques.set("rec-b-gcp-01", await backendGcp().clePublique("rec-b-gcp-01"));
      let e;
      try {
        await v.signer("rec-b-gcp-01", new Uint8Array([...N.PREFIXES.P_S, 2]));
      } catch (x) {
        e = x;
      }
      expect(e, mode).to.be.instanceOf(ErreurEnregistreur);
    }
    sim.etat.mode = null;
    let e;
    try {
      await backendGcp(nom.replace("rec-b-gcp-01", "rec-b-gcp-p256")).clePublique("rec-b-gcp-01");
    } catch (x) {
      e = x;
    }
    expect(e.message).to.match(/EC_SIGN_ED25519 attendu/);
  });

  it("dans un cœur réel : signer_ready (classe B, gcp-kms, nom de ressource ; jamais la clé du compte de service), réponses fausses → mode dégradé « clé » puis sortie, rotation vers …/rec-b-gcp-02/cryptoKeyVersions/1, journal vérifié", async function () {
    const x = configuration({ class: "B", key_id: "rec-b-gcp-01", backend: { type: "gcp-kms", key_version: nom }, rotation: { planned_every_days: null, next_key_id: "rec-b-gcp-02" } }, { env });
    const obs = await parcoursCoeur(x, { casser: async () => (sim.etat.mode = "crc_faux"), reparer: async () => (sim.etat.mode = null) });
    verifierParcours(obs, "B", "gcp-kms", ["BEGIN PRIVATE KEY"]);
    verifierPanne(obs);
  });
});

// ------------------------------------------------------------------ classe C

/** Configuration de classe C (graine courante et suivante enveloppées par `envelopper`). */
async function configurationC(wrap, envelopper, o = {}) {
  const d = path.join(dir, `c${++nDir}`);
  fs.mkdirSync(d, { recursive: true });
  const graines = { "rec-c-01": N.sha256(N.utf8(`graine-c-01-${nDir}`)), "rec-c-02": N.sha256(N.utf8(`graine-c-02-${nDir}`)) };
  const fichier = path.join(d, "rec-c-01.bin");
  const x0 = configurationDev(d);
  const ctx = (k) => ({ org_id: x0.config.recorder.org_id, journal_id: x0.config.recorder.journal_id, key_id: k });
  const w = await envelopper(graines, ctx, d, fichier);
  const x = configuration({ class: "C", key_id: "rec-c-01", backend: { type: "envelope", sealed_seed_file: fichier, wrap: w ?? wrap }, rotation: { planned_every_days: null, next_key_id: "rec-c-02" } }, { env: o.env ?? {} });
  return { x, graines, fichier };
}

describe("classe C : enveloppe AWS KMS par LocalStack réel (Encrypt/Decrypt, contexte org_id, journal_id, key_id)", function () {
  this.timeout(300000);
  const dispo = dockerEtImage(IMAGES_SIGNATAIRES.kms);
  let ls;
  let arn;
  before(async function () {
    if (!dispo.ok) return;
    ls = await demarrerKmsLocalStack(`noortrace-test-sign-kms-${process.pid}`);
    arn = await ls.creerCleSymetrique();
  });
  after(function () {
    ls?.arreter();
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });
  const envelopper = async (graines, ctx, d, fichier) => {
    fs.writeFileSync(fichier, await ls.chiffrerGraine(arn, graines["rec-c-01"], ctx("rec-c-01")));
    fs.writeFileSync(path.join(d, "rec-c-02.bin"), await ls.chiffrerGraine(arn, graines["rec-c-02"], ctx("rec-c-02")));
    return { type: "aws-kms", key_arn: arn, region: "us-east-1" };
  };

  it("dans un cœur réel : graine déchiffrée au démarrage, signer_ready (classe C, envelope, aws-kms, ARN ; jamais la graine), appel signé, rotation vers rec-c-02, journal vérifié ; graines effacées à l'arrêt (EX-11.9)", async function () {
    const { x, graines } = await configurationC(null, envelopper, {});
    Object.assign(x.env, ls.env);
    const obs = await parcoursCoeur(x);
    verifierParcours(obs, "C", "envelope", [Buffer.from(graines["rec-c-01"]).toString("hex"), Buffer.from(graines["rec-c-01"]).toString("base64")]);
    expect(obs.pret[0].data.backend_key).to.deep.include({ wrap: "aws-kms", key_arn: arn });
    expect(N.octetsVersHex(obs.publique0)).to.equal(N.octetsVersHex(N.clePubliqueEd25519(graines["rec-c-01"])));
    expect(obs.backend.graines.size).to.equal(0);
  });

  it("contexte de chiffrement : une graine chiffrée sous un autre key_id (ou un autre journal) ne se déchiffre pas → démarrage refusé", async function () {
    const { x } = await configurationC(null, async (graines, ctx, d, fichier) => {
      fs.writeFileSync(fichier, await ls.chiffrerGraine(arn, graines["rec-c-01"], { ...ctx("rec-c-01"), key_id: "rec-c-autre" }));
      return { type: "aws-kms", key_arn: arn, region: "us-east-1" };
    });
    let e;
    try {
      await signataireDepuisConfiguration(x.config, x.secrets, { env: ls.env });
    } catch (y) {
      e = y;
    }
    expect(e).to.be.instanceOf(ErreurSignataire);
    expect(e.message).to.match(/aws-kms Decrypt : statut 400/);
  });

  it("graine de 31 octets enveloppée → refusée (EX-11.9 : 32 octets)", async function () {
    const { x } = await configurationC(null, async (graines, ctx, d, fichier) => {
      fs.writeFileSync(fichier, await ls.chiffrerGraine(arn, graines["rec-c-01"].subarray(0, 31), ctx("rec-c-01")));
      return { type: "aws-kms", key_arn: arn, region: "us-east-1" };
    });
    let e;
    try {
      await signataireDepuisConfiguration(x.config, x.secrets, { env: ls.env });
    } catch (y) {
      e = y;
    }
    expect(e.message).to.match(/32 attendus/);
  });
});

describe("classe C : enveloppe TPM 2.0 logiciel réel (swtpm, tpm2-tools), politique PCR", function () {
  this.timeout(120000);
  const dispo = tpmDisponible();
  let tpm;
  before(async function () {
    if (!dispo.ok) return;
    tpm = await demarrerSwtpm(path.join(dir, "tpm"));
  });
  after(function () {
    tpm?.arreter();
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });
  const envelopper = async (graines, ctx, d) => {
    tpm.sceller(graines["rec-c-02"], "sha256:0,1,2,3", path.join(d, "rec-c-02"));
    const w = tpm.sceller(graines["rec-c-01"], "sha256:0,1,2,3", path.join(d, "rec-c-01"));
    return { type: "tpm2", ...w, pcrs: "sha256:0,1,2,3" };
  };

  it("dans un cœur réel : graine descellée (tpm2_unseal -p pcr:sha256:0,1,2,3), signer_ready (classe C, tpm2, PCR), appel signé, rotation vers rec-c-02 (fichiers <next_key_id>.pub/.priv), journal vérifié ; graines effacées", async function () {
    const { x, graines } = await configurationC(null, envelopper, { env: tpm.env });
    Object.assign(x.env, tpm.env, { PATH: process.env.PATH });
    const obs = await parcoursCoeur(x);
    verifierParcours(obs, "C", "envelope", [Buffer.from(graines["rec-c-01"]).toString("hex")]);
    expect(obs.pret[0].data.backend_key).to.deep.include({ wrap: "tpm2", pcrs: "sha256:0,1,2,3" });
    expect(obs.backend.graines.size).to.equal(0);
  });

  it("PCR étendu après le scellement (micrologiciel ou chargeur changé) : graine indescellable, démarrage refusé (EX-11.9 : « ce qui est voulu »)", async function () {
    const d = path.join(dir, "tpm-pcr");
    fs.mkdirSync(d, { recursive: true });
    const w = tpm.sceller(N.sha256(N.utf8("graine-pcr")), "sha256:7", path.join(d, "k"));
    expect((await desceller({ wrap: { ...w, pcrs: "sha256:7" }, env: { PATH: process.env.PATH, ...tpm.env } })).length).to.equal(32);
    tpm.etendrePcr(7);
    let e;
    try {
      await desceller({ wrap: { ...w, pcrs: "sha256:7" }, env: { PATH: process.env.PATH, ...tpm.env } });
    } catch (y) {
      e = y;
    }
    expect(e).to.be.instanceOf(ErreurSignataire);
    expect(e.message).to.match(/tpm2_unseal/);
  });
});

describe("classe C : enveloppes Google Cloud KMS et Azure Key Vault (simulateurs)", function () {
  this.timeout(120000);
  let gcp;
  let az;
  let envG;
  const cle = "projects/p/locations/europe-west1/keyRings/noortrace/cryptoKeys/enveloppe";
  before(async function () {
    gcp = await simulateurCloudKms(tls);
    envG = gcp.environnement(path.join(dir, "compte-service-c.json"));
    gcp.creerCleSymetrique(cle);
    az = await simulateurAzure(tls);
    az.creerCle("enveloppe-rsa", "v1", "RSA");
    az.creerCle("enveloppe-aes", "v1", "AES");
  });
  after(async function () {
    await gcp?.fermer();
    await az?.fermer();
  });
  beforeEach(function () {
    gcp.etat.mode = null;
    az.etat.mode = null;
  });
  const chiffrerGcp = async (graine, ctx) => {
    const c = new ClientCloudKms({ env: envG, ca: tls.caPem });
    const o = contexteChiffrement(ctx).octets;
    return Buffer.from((await c.appeler("POST", `${cle}:encrypt`, { plaintext: Buffer.from(graine).toString("base64"), additionalAuthenticatedData: Buffer.from(o).toString("base64"), additionalAuthenticatedDataCrc32c: String(crc32c(o)) })).ciphertext, "base64");
  };

  it("Google : decrypt avec additionalAuthenticatedData = JCS(org_id, journal_id, key_id) et CRC32C ; cœur réel, rotation, journal vérifié ; autre contexte refusé ; plaintextCrc32c faux refusé", async function () {
    const { x, graines } = await configurationC(null, async (g, ctx, d, fichier) => {
      fs.writeFileSync(fichier, await chiffrerGcp(g["rec-c-01"], ctx("rec-c-01")));
      fs.writeFileSync(path.join(d, "rec-c-02.bin"), await chiffrerGcp(g["rec-c-02"], ctx("rec-c-02")));
      return { type: "gcp-kms", key: cle };
    }, { env: envG });
    const obs = await parcoursCoeur(x);
    verifierParcours(obs, "C", "envelope", [Buffer.from(graines["rec-c-01"]).toString("hex")]);
    const req = JSON.parse(gcp.compte.requetes.find((r) => r.url.endsWith(":decrypt")).corps);
    expect(Buffer.from(req.additionalAuthenticatedData, "base64").toString()).to.equal(JSON.stringify({ journal_id: x.config.recorder.journal_id, key_id: "rec-c-01", org_id: x.config.recorder.org_id }));
    // Autre contexte : la graine de rec-c-02 présentée comme rec-c-01.
    fs.copyFileSync(path.join(path.dirname(x.config.signer.backend.sealed_seed_file), "rec-c-02.bin"), x.config.signer.backend.sealed_seed_file);
    let e;
    try {
      await signataireDepuisConfiguration(x.config, x.secrets, { env: envG, ca: tls.caPem });
    } catch (y) {
      e = y;
    }
    expect(e.message).to.match(/statut 400 \(INVALID_ARGUMENT\)/);
    gcp.etat.mode = "crc_faux";
    fs.writeFileSync(x.config.signer.backend.sealed_seed_file, await chiffrerGcp(graines["rec-c-01"], { org_id: x.config.recorder.org_id, journal_id: x.config.recorder.journal_id, key_id: "rec-c-01" }));
    e = null;
    try {
      await signataireDepuisConfiguration(x.config, x.secrets, { env: envG, ca: tls.caPem });
    } catch (y) {
      e = y;
    }
    expect(e.message).to.match(/plaintextCrc32c/);
  });

  for (const [alg, nomCle] of [["RSA-OAEP-256", "enveloppe-rsa"], ["A256KW", "enveloppe-aes"]]) {
    it(`Azure : unwrapKey ${alg} (api-version 7.4, jeton Entra ID) ; cœur réel, rotation, journal vérifié ; kid d'une autre clé, graine de 33 octets refusés`, async function () {
      const wrap = { type: "azure-keyvault", vault_url: az.origine, key_name: nomCle, key_version: "v1", algorithm: alg };
      const { x, graines } = await configurationC(null, async (g, ctx, d, fichier) => {
        fs.writeFileSync(fichier, await az.envelopper(nomCle, "v1", alg, g["rec-c-01"]));
        fs.writeFileSync(path.join(d, "rec-c-02.bin"), await az.envelopper(nomCle, "v1", alg, g["rec-c-02"]));
        return wrap;
      }, { env: az.env });
      const obs = await parcoursCoeur(x);
      verifierParcours(obs, "C", "envelope", [Buffer.from(graines["rec-c-01"]).toString("hex"), az.client.secret]);
      for (const [mode, motif] of [["autre_kid", /kid d'une autre clé/], ["graine_longue", /32 attendus/]]) {
        az.etat.mode = mode;
        let e;
        try {
          await signataireDepuisConfiguration(x.config, x.secrets, { env: az.env, ca: tls.caPem });
        } catch (y) {
          e = y;
        }
        expect(e?.message, mode).to.match(motif);
      }
    });
  }
});

// ------------------------------------------------------------------ refus de démarrage du démon (codes et messages de §15)

describe("démarrage du démon : refus aux codes et messages de §15 (EX-15.4, EX-11.8, EX-11.18)", function () {
  this.timeout(120000);

  async function lancer(x) {
    const f = path.join(x.dir, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(x.config));
    let err = "";
    const r = await principal(["--config", f], { stdout: { write: () => true }, stderr: { write: (t) => (err += t) }, env: { ...process.env, ...x.env } });
    if (typeof r === "object") {
      await r.otel?.arreter();
      await r.sdk?.arreter();
      await r.mcp?.arreter();
      await r.modele?.arreter();
      await r.coeur.arreter();
      await r.coeur.o.redaction?.fermer?.();
      return { code: 0, err };
    }
    return { code: r, err };
  }

  it("classe et backend incohérents : code 2, « config_invalid : /signer/backend/type » ; classe D en production : code 2, « /signer/class »", async function () {
    const d = path.join(dir, `r${++nDir}`);
    fs.mkdirSync(d);
    const { config, env } = configurationDev(d);
    config.signer.class = "B";
    let f = path.join(d, "c.json");
    fs.writeFileSync(f, JSON.stringify(config));
    let err = "";
    expect(await principal(["--config", f], { stdout: { write: () => true }, stderr: { write: (t) => (err += t) }, env })).to.equal(2);
    expect(err).to.match(/^config_invalid : \/signer\/backend\/type : /m);
    config.signer.class = "D";
    config.recorder.environment = "production";
    f = path.join(d, "c2.json");
    fs.writeFileSync(f, JSON.stringify(config));
    err = "";
    expect(await principal(["--config", f], { stdout: { write: () => true }, stderr: { write: (t) => (err += t) }, env })).to.equal(2);
    expect(err).to.match(/^config_invalid : \/signer\/class : classe D refusée en production \(EX-11\.8\)/m);
  });

  it("backend injoignable au démarrage (pas 5) : code 2, « demarrage_refuse : cle : signataire aws-kms : … » ; rien n'écoute", async function () {
    const x = configuration({ class: "B", key_id: "rec-b-aws-01", backend: { type: "aws-kms", key_arn: "arn:aws:kms:eu-west-3:111122223333:key/k1", region: "eu-west-3" }, timeout_ms: 300 }, { env: { AWS_ACCESS_KEY_ID: "a", AWS_SECRET_ACCESS_KEY: "b", AWS_ENDPOINT_URL_KMS: "https://127.0.0.1:9" } });
    const r = await lancer(x);
    expect(r.code).to.equal(2);
    expect(r.err).to.match(/^demarrage_refuse : cle : noortrace: enregistreur en mode degrade \(cle\)/m);
  });

  it("clé publique du signataire différente de celle qu'annonce la chaîne pour la clé courante : code 2, « demarrage_refuse : cle : cle publique du signataire differente de la cle annoncee » (EX-11.18, lecture 183)", async function () {
    const sim = await simulateurAwsKms(tls);
    try {
      const { arn } = sim.creerCle("ECC_NIST_EDWARDS25519");
      const { arn: arn2, cle } = sim.creerCle("ECC_NIST_EDWARDS25519", { alias: "rec-b-aws-02" });
      const x = configuration({ class: "B", key_id: "rec-b-aws-01", backend: { type: "aws-kms", key_arn: arn, region: sim.region }, rotation: { planned_every_days: null, next_key_id: "rec-b-aws-02" } }, { env: sim.env });
      // Un premier cœur écrit puis tourne vers rec-b-aws-02 (clé annoncée dans la chaîne).
      const b = await signataireDepuisConfiguration(x.config, x.secrets, { env: sim.env, ca: tls.caPem });
      const c = await Coeur.demarrer({ config: x.config, secrets: x.secrets, signataire: b });
      await c.tournerCle("rec-b-aws-02");
      await c.arreter();
      // L'alias désigne désormais une autre clé : la clé publique lue ne concorde plus.
      cle.graine = N.sha256(N.utf8("autre graine"));
      expect(arn2).to.be.a("string");
      const b2 = await signataireDepuisConfiguration(x.config, x.secrets, { env: sim.env, ca: tls.caPem });
      let e;
      try {
        await Coeur.demarrer({ config: x.config, secrets: x.secrets, signataire: b2 });
      } catch (y) {
        e = y;
      }
      expect(e).to.be.instanceOf(ErreurEnregistreur);
      expect(e.raison).to.equal("cle");
      expect(e.message).to.match(/cle publique du signataire differente de la cle annoncee pour rec-b-aws-02/);
      expect(fs.readFileSync(x.config.supervision.ops_log.path, "utf8")).to.include('"event":"signer_key_mismatch"');
    } finally {
      await sim.fermer();
    }
  });

  it("santé du signataire toutes les health_interval_ms (EX-11.18) : un health() en échec fait entrer en mode dégradé « clé » sans aucun appel ; sa reprise et une signature de test en font sortir (EX-14.11)", async function () {
    const sim = await simulateurAwsKms(tls);
    try {
      const { arn, cle } = sim.creerCle("ECC_NIST_EDWARDS25519");
      const x = configuration({ class: "B", key_id: "rec-b-aws-01", backend: { type: "aws-kms", key_arn: arn, region: sim.region }, health_interval_ms: 50 }, { env: sim.env });
      const b = await signataireDepuisConfiguration(x.config, x.secrets, { env: sim.env, ca: tls.caPem });
      const c = await Coeur.demarrer({ config: x.config, secrets: x.secrets, signataire: b });
      try {
        await c.tic();
        expect(c.degrade.actif("cle")).to.equal(false);
        cle.etat = "Disabled";
        expect(await attendreQue(async () => {
          await c.tic();
          return c.degrade.actif("cle");
        })).to.equal(true);
        expect(c.journal.trouver("signer_unavailable").some((l) => l.data.raison === "health")).to.equal(true);
        cle.etat = "Enabled";
        expect(await attendreQue(async () => {
          await c.tic();
          return !c.degrade.actif("cle");
        })).to.equal(true);
      } finally {
        await c.arreter();
      }
    } finally {
      await sim.fermer();
    }
  });
});

// ------------------------------------------------------------------ références { vault } (15.2)

describe("références de secrets { vault } (CT-2 §15.2) contre Vault réel : lecture KV au démarrage", function () {
  this.timeout(300000);
  const dispo = dockerEtImage(IMAGES_SIGNATAIRES["vault-transit"]);
  let srv;
  let jeton;
  let jetonSansKv;
  const MAC = "ab".repeat(32);
  before(async function () {
    if (!dispo.ok) return;
    srv = await demarrerTransit("vault-transit", `noortrace-test-sign-kv-${process.pid}`, tls);
    await srv.creerCle("rec-kv-01");
    await srv.ecrireKv("noortrace/demon", { mac: MAC, texte: "valeur-de-test" });
    const transit = 'path "transit/keys/rec-kv-01" { capabilities = ["read"] }\npath "transit/sign/rec-kv-01" { capabilities = ["update"] }\n';
    jeton = await srv.jetonPolitique("signataire-kv", `${transit}path "kv/data/noortrace/*" { capabilities = ["read"] }\n`);
    jetonSansKv = await srv.jetonPolitique("signataire-seul", transit);
  });
  after(async function () {
    await srv?.arreter();
  });
  beforeEach(function () {
    if (!dispo.ok) enAttente(this, dispo.condition);
  });
  const avecVault = (jetonTransit, ref) => {
    const d = path.join(dir, `kv${++nDir}`);
    fs.mkdirSync(d);
    const { config, env } = configurationDev(d);
    config.signer = { ...config.signer, class: "B", key_id: "rec-kv-01", backend: { type: "vault-transit", url: srv.origine, mount: "transit", key_name: "rec-kv-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null }, rotation: { planned_every_days: null, next_key_id: null } };
    config.storage.relay_mac_key = ref;
    const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    return { config: v.config, env: { ...env, NOORTRACE_TEST_JETON_TRANSIT: jetonTransit }, dir: d };
  };

  it("à l'adresse et avec le jeton de signer.backend (vault-transit) : KV version 2, champ lu puis décodé selon encoding (hex, 32 octets) ; aucune valeur dans un message", async function () {
    const x = avecVault(jeton, { vault: { path: "kv/data/noortrace/demon", field: "mac" }, encoding: "hex" });
    const lus = await lireSecretsVault(x.config, { env: x.env, ca: tls.caPem });
    expect(lus.erreurs).to.deep.equal([]);
    const s = resoudreSecrets(x.config, { env: x.env, vault: lus.valeurs });
    expect(s.erreurs).to.deep.equal([]);
    expect(Buffer.from(s.secrets.get("/storage/relay_mac_key")).toString("hex")).to.equal(MAC);
  });

  it("sans signer.backend Vault : VAULT_ADDR et VAULT_TOKEN de l'environnement ; absents : erreur sur le pointeur ; sans référence lue : erreur « non lue »", async function () {
    const d = path.join(dir, `kv${++nDir}`);
    fs.mkdirSync(d);
    const { config, env } = configurationDev(d);
    config.storage.relay_mac_key = { vault: { path: "kv/data/noortrace/demon", field: "mac" }, encoding: "hex" };
    let lus = await lireSecretsVault(config, { env: { ...env, VAULT_ADDR: srv.direct, VAULT_TOKEN: jeton } });
    expect(lus.erreurs).to.deep.equal([]);
    expect(lus.valeurs.get("/storage/relay_mac_key")).to.have.length(64);
    lus = await lireSecretsVault(config, { env });
    expect(lus.erreurs.map((e) => [e.pointeur, e.secret])).to.deep.equal([["/storage/relay_mac_key", true]]);
    expect(lus.erreurs[0].regle).to.match(/VAULT_ADDR et VAULT_TOKEN/);
    expect(resoudreSecrets(config, { env }).erreurs[0].regle).to.match(/non lue/);
  });

  it("refus : champ absent, chemin hors de la politique du jeton (403), jeton du backend lui-même référencé dans Vault ; démarrage refusé (code 2, « config_invalid : /storage/relay_mac_key »)", async function () {
    let x = avecVault(jeton, { vault: { path: "kv/data/noortrace/demon", field: "absent" }, encoding: "hex" });
    expect((await lireSecretsVault(x.config, { env: x.env, ca: tls.caPem })).erreurs[0].regle).to.match(/champ absent/);
    x = avecVault(jetonSansKv, { vault: { path: "kv/data/noortrace/demon", field: "mac" }, encoding: "hex" });
    expect((await lireSecretsVault(x.config, { env: x.env, ca: tls.caPem })).erreurs[0].regle).to.match(/statut 403/);
    const y = structuredClone(x.config);
    y.signer.backend.token = { vault: { path: "kv/data/noortrace/demon", field: "texte" } };
    expect((await lireSecretsVault(y, { env: x.env })).erreurs[0].regle).to.match(/lui-même référencé/);
    const f = path.join(x.dir, "c.json");
    fs.writeFileSync(f, JSON.stringify(x.config));
    let err = "";
    const code = await principal(["--config", f], { stdout: { write: () => true }, stderr: { write: (t) => (err += t) }, env: { ...process.env, ...x.env } });
    expect(code).to.equal(2);
    expect(err).to.match(/^config_invalid : \/storage\/relay_mac_key : /m);
    expect(err).to.not.include(MAC);
  });

  it("démon réel `bin/noortrace` : clé du MAC de relais lue dans Vault au démarrage (signer.backend vault-transit), santé ok, arrêt propre", async function () {
    const service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    const serveurService = await service.servir(0);
    try {
      const d = path.join(dir, `kv${++nDir}`);
      fs.mkdirSync(d);
      const c = await configurationDemon(d, {
        approbation: serveurService.address().port,
        modifier: (config, env) => {
          config.signer = { ...config.signer, class: "B", key_id: "rec-kv-01", backend: { type: "vault-transit", url: srv.origine, mount: "transit", key_name: "rec-kv-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null }, rotation: { planned_every_days: null, next_key_id: null } };
          config.storage.relay_mac_key = { vault: { path: "kv/data/noortrace/demon", field: "mac" }, encoding: "hex" };
          Object.assign(env, { NOORTRACE_TEST_JETON_TRANSIT: jeton, NODE_EXTRA_CA_CERTS: tls.ca });
        },
      });
      service.org_id = c.config.recorder.org_id;
      service.journal_id = c.config.recorder.journal_id;
      const p = await demarrer(REFERENCE, c, path.join(d, "configuration.json"));
      await arreter(p);
      expect((await p.fin).code, p.sortie).to.equal(0);
      expect(p.lignes().some((l) => l.event === "startup")).to.equal(true);
      expect(fs.readFileSync(c.config.supervision.ops_log.path, "utf8")).to.not.include(MAC);
    } finally {
      serveurService.close();
    }
  });
});

// ------------------------------------------------------------------ identités d'instance (lecture 189)

describe("identités IAM d'instance (EX-11.18) : IMDSv2 d'EC2 et serveur de métadonnées de Compute Engine (serveurs simulés d'après les pages officielles)", function () {
  this.timeout(60000);
  it("AWS : sans variables d'identifiants, IMDSv2 au point AWS_EC2_METADATA_SERVICE_ENDPOINT (PUT du jeton, puis rôle et identifiants temporaires), Sign signé avec le jeton de session, identifiants gardés jusqu'à leur fin ; AWS_EC2_METADATA_DISABLED=true ou aucun point : refus « identité IAM absente »", async function () {
    const sim = await simulateurAwsKms(tls, { identifiants: { access_key_id: "ASIASIMULATEUR", secret_access_key: "secret-temporaire", session_token: "jeton-de-session" } });
    const imds = await simulateurImds(sim.identifiants);
    try {
      const { arn } = sim.creerCle();
      const env = { AWS_EC2_METADATA_SERVICE_ENDPOINT: imds.origine, AWS_ENDPOINT_URL_KMS: sim.origine };
      const b = new SignataireAwsKms({ backend: { key_arn: arn, region: sim.region }, keyId: "k", client: new ClientKms({ region: sim.region, env, ca: tls.caPem }) });
      const v = new SignataireVerifie(b, { timeout_ms: 5000 });
      const p = await v.clePublique("k");
      const m = new Uint8Array([...N.PREFIXES.P_S, 1]);
      expect(N.verifierEd25519(p, m, await v.signer("k", m))).to.equal(true);
      expect(imds.compte.requetes.map((r) => `${r.methode} ${r.url}`)).to.deep.equal(["PUT /latest/api/token", "GET /latest/meta-data/iam/security-credentials/", "GET /latest/meta-data/iam/security-credentials/role-signataire"]);
      expect(sim.compte.requetes.at(-1).entetes["x-amz-security-token"]).to.equal("jeton-de-session");
      for (const e of [{ ...env, AWS_EC2_METADATA_DISABLED: "true" }, { AWS_ENDPOINT_URL_KMS: sim.origine }]) {
        let err;
        try {
          await new ClientKms({ region: sim.region, env: e, ca: tls.caPem }).appeler("DescribeKey", { KeyId: arn });
        } catch (x) {
          err = x;
        }
        expect(err?.code).to.equal("identite");
      }
    } finally {
      await imds.fermer();
      await sim.fermer();
    }
  });

  it("Google : sans GOOGLE_APPLICATION_CREDENTIALS, jeton du compte de service de l'instance (GCE_METADATA_HOST, en-tête Metadata-Flavor: Google) ; réponse sans Metadata-Flavor refusée", async function () {
    const sim = await simulateurCloudKms(tls);
    const meta = await simulateurMetadonneesGoogle(() => sim.jetonInstance());
    const faux = await simulateurMetadonneesGoogle(() => sim.jetonInstance(), { sansEntete: true });
    try {
      const nom = "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1";
      sim.creerVersion(nom);
      const env = { GCE_METADATA_HOST: meta.hote, CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS: `${sim.origine}/` };
      const v = new SignataireVerifie(new SignataireCloudKms({ backend: { key_version: nom }, keyId: "k", client: new ClientCloudKms({ env, ca: tls.caPem }) }), { timeout_ms: 5000 });
      const p = await v.clePublique("k");
      const m = new Uint8Array([...N.PREFIXES.P_S, 2]);
      expect(N.verifierEd25519(p, m, await v.signer("k", m))).to.equal(true);
      expect(meta.compte.requetes).to.have.length(1);
      expect(meta.compte.requetes[0].entetes["metadata-flavor"]).to.equal("Google");
      let err;
      try {
        await new ClientCloudKms({ env: { ...env, GCE_METADATA_HOST: faux.hote }, ca: tls.caPem }).appeler("GET", nom);
      } catch (x) {
        err = x;
      }
      expect(err?.code).to.equal("identite");
    } finally {
      await meta.fermer();
      await faux.fermer();
      await sim.fermer();
    }
  });
});

// ------------------------------------------------------------------ rapprochement (CT-7 EX-3.7)

describe("rapprochement des signatures (CT-7 EX-3.7) : comptes du journal d'audit Transit et du journal", function () {
  it("compterAuditTransit ne compte que les réponses réussies de update sur <mount>/sign/<nom>, dans l'intervalle ; rapprocher : écart = backend − objets signés − signatures de test − tentatives non servies ; incident si positif", async function () {
    const l = (o) => JSON.stringify(o);
    const audit = [
      l({ type: "request", time: "2026-11-03T10:00:00Z", request: { path: "transit/sign/k", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:00Z", request: { path: "transit/sign/k", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:01Z", request: { path: "transit/sign/k", operation: "update" }, error: "permission denied" }),
      l({ type: "response", time: "2026-11-03T10:00:02Z", request: { path: "transit/keys/k", operation: "read" } }),
      l({ type: "response", time: "2026-11-03T10:00:03Z", request: { path: "transit/sign/autre", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T12:00:00Z", request: { path: "transit/sign/k", operation: "update" } }),
      "ligne illisible",
    ].join("\n");
    expect(compterAuditTransit(audit, { mount: "transit", nom: "k" })).to.equal(2);
    expect(compterAuditTransit(audit, { mount: "/transit/", nom: "k", de: Date.parse("2026-11-03T09:00:00Z"), a: Date.parse("2026-11-03T11:00:00Z") })).to.equal(1);
    const d = path.join(dir, `rap${++nDir}`);
    fs.mkdirSync(d);
    const ops = path.join(d, "ops.ndjson");
    fs.writeFileSync(ops, [l({ ts: "2026-11-03T10:00:00.000Z", event: "signer_test_signature", data: { key_id: "rec-k" } })].join("\n") + "\n");
    const r = await rapprocher({ audit, mount: "transit", nom: "k", repertoire: path.join(d, "journal"), journalExploitation: ops, keyId: "rec-k" });
    expect(r).to.deep.include({ backend_operations: 2, justifiees: 1, ecart: 1, incident: true });
    expect(r.objets.signatures_de_test).to.equal(1);
  });
});

// ------------------------------------------------------------------ noortrace-ctl cle rotation-urgence

describe("noortrace-ctl cle rotation-urgence (CT-8 EX-10.14 ; CT-2 EX-11.16) sur le démon réel", function () {
  this.timeout(180000);
  let service;
  let serveurService;
  before(async function () {
    service = new ServiceApprobationFactice({ org_id: "0x00", journal_id: null });
    serveurService = await service.servir(0);
  });
  after(function () {
    serveurService?.close();
  });

  it("SIGURG seul (sans demande) : ignoré et consigné ; la commande : rotation vers next_key_id scellée (signée par l'ancienne clé), code 0 ; une seconde : refusée (clé suivante absente), code 1 ; registre activé : refus « registre_non_branche » (le pas 1 d'EX-11.16 ne peut pas précéder le pas 2)", async function () {
    const d = path.join(dir, `ctl${++nDir}`);
    fs.mkdirSync(d);
    const c = await configurationDemon(d, { approbation: serveurService.address().port });
    service.org_id = c.config.recorder.org_id;
    service.journal_id = c.config.recorder.journal_id;
    const f = path.join(d, "configuration.json");
    const p = await demarrer(REFERENCE, c, f);
    const r = {};
    try {
      process.kill(p.pid, "SIGURG");
      await attendreQue(() => p.lignes().some((x) => x.event === "key_rotation_emergency_ignored"), 10000);
      r.ignore = p.lignes().filter((x) => x.event === "key_rotation_emergency_ignored").length;
      r.avant = (await lireEvenements(c.journal)).filter((e) => e.execution.tool === "noortrace.journal.rotation-cle").length;
      r.premiere = await ctl(REFERENCE, ["cle", "rotation-urgence", "--configuration", f], c.env);
      r.seconde = await ctl(REFERENCE, ["cle", "rotation-urgence", "--configuration", f], c.env);
      r.usage = await ctl(REFERENCE, ["cle", "autre"], c.env);
    } finally {
      await arreter(p);
    }
    expect(r.ignore).to.equal(1);
    expect(r.avant).to.equal(0);
    expect(r.premiere.code, r.premiere.erreur).to.equal(0);
    expect(JSON.parse(r.premiere.sortie).event).to.equal("key_rotation_emergency");
    expect(JSON.parse(r.premiere.sortie).data).to.deep.include({ old_key_id: "rec-test-01", new_key_id: "rec-test-02" });
    expect(r.seconde.code).to.equal(1);
    expect(JSON.parse(r.seconde.sortie).data.raison).to.equal("cle_suivante_absente");
    expect(r.usage.code).to.equal(2);
    const rot = (await lireEvenements(c.journal)).filter((e) => e.execution.tool === "noortrace.journal.rotation-cle");
    expect(rot).to.have.length(1);
    expect(rot[0].recorder_key_id).to.equal("rec-test-01");
    const v = await verifierRepertoireJournal(c.journal, { org_id: c.config.recorder.org_id, journal_id: c.config.recorder.journal_id, clePublique: async (id) => (id === "rec-test-01" ? N.clePubliqueEd25519(N.sha256(N.utf8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01"))) : null), dernierOuvert: true });
    expect(v.incidents, JSON.stringify(v.incidents)).to.deep.equal([]);
    // Registre activé : refus, dans un cœur.
    const x = configuration({ class: "D", key_id: "rec-test-01", backend: c.config.signer.backend, rotation: { planned_every_days: null, next_key_id: "rec-test-02" } });
    x.config.anchoring.registry.enabled = true;
    const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets });
    try {
      expect(await coeur.rotationUrgence()).to.deep.equal({ accepte: false, raison: "registre_non_branche" });
    } finally {
      await coeur.arreter();
    }
  });
});
