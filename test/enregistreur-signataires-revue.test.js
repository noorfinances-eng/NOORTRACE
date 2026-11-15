// Revue de sécurité interne de l'étape 8 : CT-7 MN-96 (rapprochement des
// signatures, CT-7 EX-3.7), CT-2 EX-18.4 (environnement des auxiliaires
// PKCS#11 et TPM), CT-2 EX-11.8 (SoftHSM2 en production, erreur) et CT-2
// EX-18.7, part des clés (secrets résolus effacés à l'arrêt, avertissement
// d'EX-18.7 consigné). Sans réseau ni matériel.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as E from "@noortrace/enregistreur";
import { environnementAuxiliaire } from "../paquets/enregistreur/src/signataires/fabrique.mjs";
import * as R from "../paquets/enregistreur/src/signataires/rapprochement.mjs";
import * as S from "../paquets/enregistreur/src/secrets.mjs";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const enc = (c) => new Uint8Array(Buffer.from(JSON.stringify(c)));
const l = (o) => JSON.stringify(o);

describe("revue signataires : rapprochement des signatures (CT-7 MN-96, CT-7 EX-3.7)", function () {
  this.timeout(60000);
  const audit5 = Array.from({ length: 5 }, (_, k) => l({ type: "response", time: `2026-11-01T00:00:0${k}Z`, request: { path: "transit/sign/cle", operation: "update" } })).join("\n");

  it("CT-7 MN-96 : une ligne signer_unavailable dont tentatives n'est pas un entier de 0 à 2 ne justifie rien, est une anomalie nommée, et l'incident reste vrai (écart 5) ; un écart non fini vaut incident", async function () {
    const d = repertoireTemporaire("noortrace-revue-signataires-1-");
    const base = { audit: audit5, mount: "transit", nom: "cle", repertoire: path.join(d, "journal"), keyId: "K", de: null, a: null };
    const ops = path.join(d, "ops.ndjson");
    fs.writeFileSync(ops, "");
    const sain = await R.rapprocher({ ...base, journalExploitation: ops });
    expect(sain).to.include({ backend_operations: 5, ecart: 5, incident: true });
    expect(sain.anomalies).to.deep.equal([]);
    for (const tentatives of ["x", 1000000, 3, -1, 1.5, null, true]) {
      fs.writeFileSync(ops, l({ ts: "2026-11-01T00:00:00.000Z", event: "signer_unavailable", data: { key_id: "K", tentatives } }) + "\n");
      const r = await R.rapprocher({ ...base, journalExploitation: ops });
      expect(r.incident, `tentatives ${JSON.stringify(tentatives)}`).to.equal(true);
      expect(r.ecart, `tentatives ${JSON.stringify(tentatives)}`).to.equal(5);
      expect(Number.isFinite(r.ecart)).to.equal(true);
      expect(r.objets.tentatives_non_servies).to.equal(0);
      expect(r.anomalies.length, `tentatives ${JSON.stringify(tentatives)} : anomalie`).to.be.above(0);
      expect(r.anomalies[0].raison).to.match(/tentatives/);
    }
    fs.writeFileSync(ops, l({ ts: "2026-11-01T00:00:00.000Z", event: "signer_unavailable", data: { key_id: "K", tentatives: 2 } }) + "\n");
    const deux = await R.rapprocher({ ...base, journalExploitation: ops });
    expect(deux).to.include({ ecart: 3, incident: true, justifiees: 2, justifiees_par_journal_exploitation: 2 });
    expect(deux.anomalies).to.deep.equal([]);
    expect(deux.signatures_verifiees, "la sortie dit que les objets sont comptés sur leurs champs, signatures non vérifiées").to.equal(false);
  });

  it("CT-7 EX-3.7 : les requêtes de signature sous <mount>/sign/<nom>/<algorithme> sont comptées ; une requête par lot compte ses entrées, un lot au nombre inconnu est un incident ; une autre opération du backend sur la clé est une ligne non classée (code non nul)", function () {
    const audit = [
      l({ type: "response", time: "2026-11-03T10:00:00Z", request: { path: "transit/sign/k", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:01Z", request: { path: "transit/sign/k/sha2-512", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:02Z", request: { path: "transit/sign/k/", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:03Z", request: { path: "transit/sign/k", operation: "update", data: { batch_input: [{ input: "hmac-sha256:1" }, { input: "hmac-sha256:2" }, { input: "hmac-sha256:3" }] } } }),
      l({ type: "response", time: "2026-11-03T10:00:04Z", request: { path: "transit/keys/k", operation: "read" } }),
      l({ type: "response", time: "2026-11-03T10:00:05Z", request: { path: "transit/sign/autre", operation: "update" } }),
      l({ type: "response", time: "2026-11-03T10:00:06Z", request: { path: "transit/sign/k", operation: "update" }, error: "permission denied" }),
    ].join("\n");
    expect(R.compterAuditTransit(audit, { mount: "transit", nom: "k" })).to.equal(6);
    const a = R.analyserAuditTransit(audit, { mount: "transit", nom: "k" });
    expect(a).to.include({ operations: 6, lots_indetermines: 0 });
    expect(a.non_classees).to.deep.equal([]);
    const hostile = [
      audit,
      l({ type: "response", time: "2026-11-03T10:00:07Z", request: { path: "transit/sign/k", operation: "update", data: { batch_input: "hmac-sha256:abc" } } }),
      l({ type: "response", time: "2026-11-03T10:00:08Z", request: { path: "transit/export/signing-key/k", operation: "read" } }),
      l({ type: "response", time: "2026-11-03T10:00:09Z", request: { path: "transit/keys/k/config", operation: "update" } }),
    ].join("\n");
    const b = R.analyserAuditTransit(hostile, { mount: "transit", nom: "k" });
    expect(b.operations).to.equal(6);
    expect(b.lots_indetermines).to.equal(1);
    expect(b.non_classees.map((x) => x.path).sort()).to.deep.equal(["transit/export/signing-key/k", "transit/keys/k/config"]);
  });

  it("CT-7 EX-3.7 : rapprocher rend incident pour un lot indéterminé, et des anomalies pour les lignes non classées ; noortrace-ctl cle rapprocher rend 3 sur incident, 1 sur anomalie seule, 0 sinon", async function () {
    const d = repertoireTemporaire("noortrace-revue-signataires-2-");
    const { config } = configurationDev(d);
    config.signer = { ...config.signer, class: "B", backend: { type: "vault-transit", url: "https://vault.example:8200", mount: "transit", key_name: "k", token: { env: "NOORTRACE_TEST_VAULT" } } };
    config.supervision.ops_log.path = path.join(d, "ops.ndjson");
    fs.mkdirSync(config.storage.root, { recursive: true });
    fs.writeFileSync(config.supervision.ops_log.path, "");
    const f = path.join(d, "configuration.json");
    fs.writeFileSync(f, JSON.stringify(config));
    const lancer = async (lignes) => {
      const audit = path.join(d, "audit.log");
      fs.writeFileSync(audit, lignes.join("\n") + "\n");
      const out = [];
      const code = await R.principalRapprochement(["--configuration", f, "--audit", audit], { stdout: { write: (x) => out.push(x) }, stderr: { write() {} } });
      return { code, r: JSON.parse(out.join("")) };
    };
    const rien = await lancer([l({ type: "response", time: "2026-11-03T10:00:04Z", request: { path: "transit/keys/k", operation: "read" } })]);
    expect(rien.code).to.equal(0);
    expect(rien.r).to.include({ ecart: 0, incident: false });
    const anomalie = await lancer([l({ type: "response", time: "2026-11-03T10:00:08Z", request: { path: "transit/export/signing-key/k", operation: "read" } })]);
    expect(anomalie.code).to.equal(1);
    expect(anomalie.r.incident).to.equal(false);
    expect(anomalie.r.anomalies.map((x) => x.raison)).to.deep.equal(["ligne_audit_non_classee"]);
    const lot = await lancer([l({ type: "response", time: "2026-11-03T10:00:07Z", request: { path: "transit/sign/k", operation: "update", data: { batch_input: "hmac-sha256:abc" } } })]);
    expect(lot.code).to.equal(3);
    expect(lot.r.incident).to.equal(true);
  });
});

describe("revue signataires : environnement des auxiliaires PKCS#11 et TPM (CT-2 EX-18.4)", function () {
  it("seules les variables d'une liste d'admission passent (PATH, TMPDIR, LANG, LC_ALL, SOFTHSM2_CONF, TPM2TOOLS_TCTI) ; les identités des fournisseurs et les secrets nommés par la configuration sont retirés", function () {
    const config = { signer: { backend: { type: "pkcs11", pin: { env: "PIN_HSM" } } }, storage: { relay_mac_key: { file: "/run/secrets/mac" } } };
    const env = {
      PATH: "/usr/bin", TMPDIR: "/tmp/x", LANG: "C.UTF-8", LC_ALL: "C", SOFTHSM2_CONF: "/etc/softhsm2.conf", TPM2TOOLS_TCTI: "device:/dev/tpmrm0",
      PIN_HSM: "1234", AWS_ACCESS_KEY_ID: "AKIAEXEMPLE", AWS_SECRET_ACCESS_KEY: "secret-aws", AWS_SESSION_TOKEN: "jeton-aws", AZURE_CLIENT_SECRET: "secret-azure", VAULT_TOKEN: "jeton-vault",
      GOOGLE_APPLICATION_CREDENTIALS: "/x.json", HOME: "/root", NODE_OPTIONS: "--inspect",
    };
    expect(environnementAuxiliaire(config, env)).to.deep.equal({ PATH: "/usr/bin", TMPDIR: "/tmp/x", LANG: "C.UTF-8", LC_ALL: "C", SOFTHSM2_CONF: "/etc/softhsm2.conf", TPM2TOOLS_TCTI: "device:/dev/tpmrm0" });
    expect(environnementAuxiliaire(config, { PATH: "/bin", SOFTHSM2_CONF: { toString: () => "x" } })).to.deep.equal({ PATH: "/bin" });
  });
});

describe("revue signataires : SoftHSM2 en production (CT-2 EX-11.8)", function () {
  it("signer.backend.module qui désigne libsofthsm2.so est une erreur de validation en production (/signer/backend/module) et un avertissement ailleurs", function () {
    const dir = repertoireTemporaire("noortrace-revue-signataires-3-");
    const prod = configurationDev(dir, { environment: "production" }).config;
    prod.signer = { ...prod.signer, class: "A", backend: { type: "pkcs11", module: "/usr/lib/softhsm/libsofthsm2.so", token_label: "noortrace", key_label: "rec-01", mechanism: "CKM_EDDSA", pin: { env: "NOORTRACE_TEST_PIN" } } };
    const v = E.validerConfiguration(enc(prod));
    expect(v.erreurs.map((e) => e.pointeur)).to.include("/signer/backend/module");
    expect(v.erreurs.find((e) => e.pointeur === "/signer/backend/module").regle).to.match(/SoftHSM2|logiciel/);
    const dev = configurationDev(dir).config;
    dev.signer = { ...prod.signer };
    const w = E.validerConfiguration(enc(dev));
    expect(w.erreurs.map((e) => e.pointeur)).to.not.include("/signer/backend/module");
    expect(w.avertissements.map((a) => a.pointeur)).to.include("/signer/backend/module");
    prod.signer.backend.module = "/opt/hsm/libcs_pkcs11_R3.so";
    expect(E.validerConfiguration(enc(prod)).erreurs.map((e) => e.pointeur)).to.not.include("/signer/backend/module");
  });
});

describe("revue signataires : secrets résolus effacés à l'arrêt, avertissement d'EX-18.7 (part des clés)", function () {
  this.timeout(60000);

  it("effacerSecrets met chaque tampon à zéro et vide la table", function () {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([9, 9]);
    const m = new Map([["/a", a], ["/b", b]]);
    S.effacerSecrets(m);
    expect(m.size).to.equal(0);
    expect([...a]).to.deep.equal([0, 0, 0]);
    expect([...b]).to.deep.equal([0, 0]);
  });

  it("le cœur tient ses propres copies des secrets, consigne au démarrage que la mémoire n'est pas verrouillée (ligne memory_*), et efface toutes les copies à l'arrêt", async function () {
    const dir = repertoireTemporaire("noortrace-revue-signataires-4-");
    const { config } = configurationDev(dir);
    const secrets = secretsDev();
    const original = secrets.get("/storage/relay_mac_key");
    const c = await E.Coeur.demarrer({ config: E.validerConfiguration(enc(config)).config, secrets });
    const copie = c.secrets.get("/storage/relay_mac_key");
    expect(copie).to.not.equal(original);
    expect([...copie]).to.deep.equal([...original]);
    await c.arreter();
    expect(c.secrets.size).to.equal(0);
    expect([...copie].every((x) => x === 0)).to.equal(true);
    expect([...original].some((x) => x !== 0), "la table de l'appelant n'est pas touchée (elle est à lui)").to.equal(true);
    const lignes = fs.readFileSync(config.supervision.ops_log.path, "utf8").split("\n").filter(Boolean).map((x) => JSON.parse(x));
    // L'avertissement d'EX-18.7 (mémoire non verrouillée, vidages non désactivés) : ligne `memory_protection_unavailable` du démon ou de l'outil des clés.
    const avert = lignes.filter((x) => /^memory_/.test(x.event));
    expect(avert.length).to.be.at.least(1);
    expect(avert[0].level).to.equal("warning");
    expect(lignes.findIndex((x) => x.event === "startup")).to.be.below(lignes.indexOf(avert[0]) + 1);
  });
});
