// Lot A du composant d'ancrage (CT-5 §5, §10.2, §11 ; CT-6 §9) : rejeu des
// familles de vecteurs qui jugent le client RFC 3161.
//
// - `spec/vecteurs/ct-5/requetes/` : six requêtes `TimeStampReq` octet pour
//   octet (EX-5.1, AN-5), cinq constructions refusées (AN-5, AN-6) ;
// - `spec/vecteurs/ct-5/reponses/` : vingt-huit réponses (`TimeStampResp` de
//   l'autorité de test et réponses HTTP représentées) classées selon EX-5.10 à
//   EX-5.12 (AN-8 à AN-11), jetons extraits identiques aux `.der` publiés ;
// - `spec/vecteurs/ct-6/rfc3161/attendu.json` : statut de T-1 à T-10 de chaque
//   jeton avec les ancres de `spec/vecteurs/ct-6/ancres/` (T-11 n'est jamais
//   exécutée à l'acquisition, EX-5.9) et les faits d'EX-9.19 ;
// - les jetons des dossiers `spec/vecteurs/ct-6/dossiers/*/jeton-rfc3161.der`
//   et des parties `points-de-controle.json` (base64, CT-1 §11.2) ;
// - confrontation par `openssl ts -verify -queryfile` (« Verification: OK »,
//   « nonce mismatch »), en attente sans openssl.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { decoderBase64Canonique, hacherManifeste } from "@noortrace/noyau";
import {
  construireRequete, relireRequete, ErreurRequete, lireReponse, verifierJeton, acquerir, classerErreur, VERIFICATIONS_ACQUISITION, decoderPem,
} from "@noortrace/ancrage/rfc3161";
import {
  CT5, CT6, CLES, JETONS, octets, texte, json, sha256Hex, nonceDepuisEtiquette, prestataireTest, horlogeFixe, transportFactice,
  reponse200, t10, enAttente, opensslDisponible, repertoireTemporaire,
} from "./fixtures/ancrage-rfc3161/outils.mjs";

const REQUETES = json(path.join(CT5, "requetes", "requetes.json"));
const REFUSEES = json(path.join(CT5, "requetes", "refusees.json"));
const REPONSES = json(path.join(CT5, "reponses", "reponses.json"));
const ATTENDU_CT6 = json(path.join(CT6, "rfc3161", "attendu.json"));

describe("ancrage rfc3161 : famille requetes de CT-5 (EX-5.1, EX-5.3, AN-5, AN-6)", function () {
  for (const cas of REQUETES.cases) {
    it(`${cas.id} : octets DER exacts, taille, SHA-256, nonce`, function () {
      const nonce = nonceDepuisEtiquette(cas.input.nonce_label);
      const r = construireRequete({ imprint: cas.input.digest, nonce, policy_oid: cas.input.policy_oid, certReq: cas.input.cert_req });
      expect(r.nonce).to.equal(cas.expected.nonce);
      expect("0x" + Buffer.from(r.octets).toString("hex")).to.equal(cas.expected.der);
      expect(Buffer.from(r.octets).equals(Buffer.from(octets(path.join(CT5, "requetes", cas.expected.file))))).to.equal(true, "octets du fichier .tsq");
      expect(r.octets.length).to.equal(cas.expected.size);
      expect(r.sha256).to.equal(cas.expected.sha256);
      const relue = relireRequete(r.octets);
      expect(relue.imprint).to.equal(cas.input.digest);
      expect(relue.nonce).to.equal(cas.expected.nonce);
      expect(relue.policy_oid).to.equal(cas.input.policy_oid);
    });
  }
  for (const cas of REFUSEES.cases) {
    it(`${cas.id} : refusé (${cas.expected.rule}, « ${cas.expected.message} »)`, function () {
      const f = () => (cas.input.der ? relireRequete(new Uint8Array(Buffer.from(cas.input.der.slice(2), "hex"))) : construireRequete({ imprint: cas.input.digest, nonce: BigInt(cas.input.nonce), policy_oid: cas.input.policy_oid, certReq: cas.input.cert_req }));
      expect(f).to.throw(ErreurRequete);
      try {
        f();
      } catch (e) {
        expect(e.regle).to.equal(cas.expected.rule);
        expect(e.message).to.equal(cas.expected.message);
      }
    });
  }
});

describe("ancrage rfc3161 : famille reponses de CT-5 (EX-5.10 à EX-5.12, AN-8 à AN-11)", function () {
  const acPem = texte(path.join(CT5, "reponses", REPONSES.provider.anchor_certificates[0]));
  for (const cas of REPONSES.cases) {
    it(`${cas.id} : ${cas.expected.outcome}${cas.expected.error_code ? " " + cas.expected.error_code : ""}`, async function () {
      const relue = relireRequete(octets(path.join(CT5, "reponses", cas.input.request)));
      expect(relue.imprint === relue.imprint && sha256Hex(octets(path.join(CT5, "reponses", cas.input.request)))).to.equal(cas.input.request_sha256);
      const prestataire = prestataireTest({ id: REPONSES.provider.id, policy_oid: relue.policy_oid, accepted_policies: REPONSES.provider.accepted_policies, anchor_certificates: [acPem], qualified: REPONSES.provider.qualified, correlation_header: null });
      const corps = cas.input.response ? octets(path.join(CT5, "reponses", cas.input.response)) : new Uint8Array(cas.input.http.body_size > 131072 ? 131072 : cas.input.http.body_size);
      if (cas.input.response) expect(sha256Hex(corps)).to.equal(cas.input.response_sha256);
      const h = cas.input.http;
      const sent = Date.parse(cas.input.sent_at);
      const transport = transportFactice({ status: h.status, entetes: { "content-type": h.content_type, ...(h.retry_after_s !== null ? { "retry-after": String(h.retry_after_s) } : {}) }, corps, tronque: h.body_size > 131072 });
      const k = cas.input.late_responses_before + 1;
      const r = await acquerir({
        prestataire, imprint: relue.imprint, objet: "point", nonce: relue.nonceBigint, attempt: k, periodStart: 1793710800,
        horloge: horlogeFixe(sent, Date.parse(cas.input.received_at) - sent), aleatoire: null, depot: null, transport,
        fraicheur: REPONSES.freshness, retry: REPONSES.retry, tardivesAvant: cas.input.late_responses_before, k,
      });
      const e = cas.expected;
      expect(r.enregistrement.outcome).to.equal(e.outcome);
      expect(r.enregistrement.error_code).to.equal(e.error_code);
      expect(r.classement.classe).to.equal(e.class);
      expect(r.classement.alerte === "critique").to.equal(e.critical);
      expect(r.warnings).to.deep.equal(e.warnings);
      expect(r.data.pki_status).to.equal(e.pki_status);
      expect(r.data.failure_info).to.equal(e.failure_info);
      expect(r.data.nonce_in_response).to.equal(e.nonce_in_response);
      expect(r.data.imprint_matches).to.equal(e.imprint_matches);
      expect(r.data.token_sha256).to.equal(e.token_sha256);
      expect(r.data.token_size).to.equal(e.token_size);
      if (e.token) expect(Buffer.from(r.jeton).equals(Buffer.from(octets(path.join(CT5, "reponses", e.token))))).to.equal(true, "jeton extrait identique au .der publié (octets tels que reçus)");
      expect(r.data.gen_time).to.equal(e.gen_time);
      expect(r.data.accuracy_s).to.equal(e.accuracy_s);
      expect(r.enregistrement.upper_bound).to.equal(e.upper_bound);
      const attente = r.classement.classe === "transitoire" ? { delay_ms: r.classement.attenteMs, reason: r.classement.raisonAttente } : null;
      expect(attente).to.deep.equal(e.retry);
      expect(r.data.checks_passed).to.deep.equal(cas.input.checks_passed, "T-1 à T-9 réussies, telles que déclarées par le vecteur");
      expect(r.data.http_status).to.equal(h.status);
      expect(r.data.content_type).to.equal(h.content_type);
      expect(r.data.body_size).to.equal(h.body_size);
      expect(r.data.retry_after_s).to.equal(h.retry_after_s);
      expect(r.enregistrement).to.not.have.property("secret");
      // Le classement seul (AN-11) rend la même classe et la même attente.
      const c = classerErreur({ code: e.error_code, httpStatus: h.status, retryAfter: h.retry_after_s, pkiStatus: e.pki_status, failureInfo: e.failure_info, retry: REPONSES.retry, k });
      expect(c.classe).to.equal(e.class);
      if (e.retry) expect(c.attenteMs).to.equal(e.retry.delay_ms);
    });
  }

  it("lireReponse lit chaque TimeStampResp publiée : statut, PKIFailureInfo, jeton (AN-8)", function () {
    for (const cas of REPONSES.cases) {
      if (!cas.input.response) continue;
      const r = lireReponse(octets(path.join(CT5, "reponses", cas.input.response)));
      expect(r.status).to.equal(cas.expected.pki_status);
      expect(r.failureInfo).to.equal(cas.expected.failure_info);
      expect(r.token === null).to.equal(cas.expected.token === null);
    }
  });
});

describe("ancrage rfc3161 : famille rfc3161 de CT-6 (T-1 à T-10 avec les ancres de test, EX-13.2)", function () {
  const ancresCache = new Map();
  const ancres = (rel) => {
    if (rel === null) return null;
    if (!ancresCache.has(rel)) ancresCache.set(rel, json(path.join(CT6, rel)));
    return ancresCache.get(rel);
  };
  it("attendu.json de CT-6 révision 0.5 : vingt-huit jetons et quarante et un cas, dont t1-cle-longueur-non-minimale et t1-extension-mal-formee (T-1 echoue, EX-9.7)", function () {
    expect(ATTENDU_CT6.tokens).to.have.lengthOf(28);
    expect(ATTENDU_CT6.cases).to.have.lengthOf(41);
    for (const f of ["jetons/t1-cle-longueur-non-minimale.der", "jetons/t1-extension-mal-formee.der"]) {
      expect(ATTENDU_CT6.tokens.find((t) => t.file === f).target).to.equal("T-1");
      const cas = ATTENDU_CT6.cases.filter((c) => c.token === f);
      expect(cas).to.have.lengthOf(1);
      expect(cas[0].checks.find((c) => c.id === "T-1").status).to.equal("echoue");
      const r = verifierJeton({ octets: octets(path.join(CT6, "rfc3161", f)), imprintAttendue: cas[0].dossier_period_hash, ancres: ancres(cas[0].anchors) });
      expect(r.checks["T-1"], r.details["T-1"]).to.equal("echoue");
      expect(Object.entries(r.checks).filter(([k]) => k !== "T-1").map(([, v]) => v)).to.deep.equal(Array(8).fill("non_execute"));
    }
    // La forme refusée est celle du certificat : une RSAPublicKey à longueur non minimale, une extension keyUsage en INTEGER (EX-9.4, EX-9.7).
    expect(verifierJeton({ octets: octets(path.join(CT6, "rfc3161", "jetons/t1-cle-longueur-non-minimale.der")), imprintAttendue: ATTENDU_CT6.cases[0].dossier_period_hash, ancres: null }).details["T-1"]).to.match(/non minimale/);
    expect(verifierJeton({ octets: octets(path.join(CT6, "rfc3161", "jetons/t1-extension-mal-formee.der")), imprintAttendue: ATTENDU_CT6.cases[0].dossier_period_hash, ancres: null }).details["T-1"]).to.match(/BIT STRING/);
  });

  it("les clés (DER des PEM) et jetons publiés ont les SHA-256 de l'attendu", function () {
    for (const [f, h] of Object.entries(ATTENDU_CT6.keys.files)) {
      const der = decoderPem(texte(path.join(CT6, "rfc3161", f)), f.endsWith(".cle.pem") ? "PRIVATE KEY" : "CERTIFICATE");
      expect(sha256Hex(der)).to.equal(h, f);
    }
    for (const t of ATTENDU_CT6.tokens) expect(sha256Hex(octets(path.join(CT6, "rfc3161", t.file)))).to.equal(t.sha256, t.file);
  });
  ATTENDU_CT6.cases.forEach((cas, i) => {
    it(`cas ${i + 1} : ${cas.token} avec ${cas.anchors ?? "aucune ancre"} → ${cas.control_status}`, function () {
      const r = verifierJeton({ octets: octets(path.join(CT6, "rfc3161", cas.token)), imprintAttendue: cas.dossier_period_hash, ancres: ancres(cas.anchors) });
      const dix = t10(r, ancres(cas.anchors));
      for (const c of cas.checks) {
        if (c.id === "T-11") continue; // jamais exécutée à l'acquisition (EX-5.9)
        const statut = c.id === "T-10" ? dix.statut : r.checks[c.id];
        const raison = c.id === "T-10" ? dix.raison ?? null : r.raisons[c.id] ?? null;
        expect(statut, `${c.id} (${r.details[c.id] ?? dix.detail ?? ""})`).to.equal(c.status);
        expect(raison, `raison de ${c.id}`).to.equal(c.reason ?? null);
      }
      if (cas.facts) {
        for (const k of ["authority", "tsu_certificate_sha256", "tsu_subject_cn", "gen_time", "upper_bound", "policy", "serial_number", "digest_algorithm", "signature_algorithm", "key_bits", "qualified_claim"]) {
          expect(r.faits[k], `fait ${k}`).to.deep.equal(cas.facts[k]);
        }
        expect(r.faits.accuracy).to.deep.equal(cas.facts.accuracy);
        expect(dix.preuves.map((p) => ({ certificate_sha256: p.certificate_sha256, evidence: p.evidence, issued_at: p.issued_at }))).to.deep.equal(cas.facts.revocation);
      }
    });
  });
});

describe("ancrage rfc3161 : jetons des dossiers de CT-6 (parties jeton-rfc3161.der et points-de-controle.json)", function () {
  const dossiers = fs.readdirSync(path.join(CT6, "dossiers")).filter((d) => fs.existsSync(path.join(CT6, "dossiers", d, "jeton-rfc3161.der"))).sort();
  it("au moins vingt dossiers portent un jeton", function () {
    expect(dossiers.length).to.be.at.least(20);
  });
  for (const d of dossiers) {
    it(`${d} : T-1 à T-10 sur periodHash recalculé, comme attendu.json`, function () {
      const rep = path.join(CT6, "dossiers", d);
      const attendu = json(path.join(rep, "attendu.json"));
      const ancres = attendu.anchors ? json(path.resolve(rep, attendu.anchors)) : null;
      const periodHash = hacherManifeste(json(path.join(rep, "manifeste.json")));
      const r = verifierJeton({ octets: octets(path.join(rep, "jeton-rfc3161.der")), imprintAttendue: periodHash, ancres });
      const dix = t10(r, ancres);
      const nonExecutes = new Map(attendu.not_executed.map((n) => [n.id, n.reason]));
      for (const id of [...VERIFICATIONS_ACQUISITION, "T-10"]) {
        // T-2 non exécutée dans le dossier parce que P-1 (manifeste, événement) n'a pas réussi : prérequis du dossier,
        // sans objet à l'acquisition, où l'empreinte demandée est toujours connue.
        if (id === "T-2" && nonExecutes.get("T-2") === "prerequis_en_echec") continue;
        const statut = id === "T-10" ? dix.statut : r.checks[id];
        const raison = id === "T-10" ? dix.raison ?? null : r.raisons[id] ?? null;
        if (attendu.failed_checks.includes(id)) expect(statut, id).to.equal("echoue");
        else if (nonExecutes.has(id)) {
          expect(statut, id).to.equal("non_execute");
          expect(raison, id).to.equal(nonExecutes.get(id));
        } else expect(statut, `${id} ${r.details[id] ?? ""}`).to.equal("reussi");
      }
    });
  }
  const points = fs.readdirSync(path.join(CT6, "dossiers")).filter((d) => fs.existsSync(path.join(CT6, "dossiers", d, "points-de-controle.json"))).sort();
  for (const d of points) {
    const partie = json(path.join(CT6, "dossiers", d, "points-de-controle.json"));
    if (!partie || !partie.anchors || !partie.anchors.rfc3161) continue;
    it(`${d} : jeton du point (base64 canonique, CT-1 §11.2) vérifié sur checkpoint_hash`, function () {
      const jeton = decoderBase64Canonique(partie.anchors.rfc3161.token, 65536);
      if (d.includes("base64-non-canonique")) {
        expect(jeton, "un base64 non canonique n'est pas décodé (CT-1 §3)").to.equal(null);
        return;
      }
      expect(jeton, "base64 canonique").to.not.equal(null);
      const ancres = json(path.join(CT6, "ancres", "ancres-test.json"));
      const r = verifierJeton({ octets: jeton, imprintAttendue: partie.checkpoint_hash, ancres });
      const attendus = { "T-1": "reussi", "T-2": "reussi", "T-3": "reussi", "T-4": "reussi", "T-5": "reussi", "T-6": "reussi", "T-7": "reussi", "T-8": "reussi", "T-9": "reussi" };
      if (d.includes("k7-jeton-signature")) Object.assign(attendus, { "T-6": "echoue", "T-7": "non_execute" });
      if (d.includes("k7-jeton-autre-empreinte")) Object.assign(attendus, { "T-2": "echoue" });
      for (const [id, s] of Object.entries(attendus)) expect(r.checks[id], `${id} ${r.details[id] ?? ""}`).to.equal(s);
    });
  }
});

describe("ancrage rfc3161 : confrontation par openssl ts -verify (CT-5 annexe A.6)", function () {
  let dir;
  before(function () {
    dir = repertoireTemporaire();
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });
  const verifier = (requete, reponse) => {
    try {
      return execFileSync("openssl", ["ts", "-verify", "-queryfile", requete, "-in", reponse, "-CAfile", path.join(CLES, "ac-test.pem"), "-untrusted", path.join(CLES, "tsa-test.pem")], { stdio: "pipe" }).toString();
    } catch (e) {
      return e.stderr.toString() + e.stdout.toString();
    }
  };
  for (const cas of REPONSES.cases.filter((c) => c.expected.openssl_verify !== null)) {
    it(`${cas.id} : openssl rend « ${cas.expected.openssl_verify === "OK" ? "Verification: OK" : cas.expected.openssl_verify} »`, function () {
      if (!opensslDisponible()) return enAttente(this, "openssl absent de la machine");
      const sortie = verifier(path.join(CT5, "reponses", cas.input.request), path.join(CT5, "reponses", cas.input.response));
      if (cas.expected.openssl_verify === "OK") expect(sortie).to.include("Verification: OK");
      else expect(sortie).to.include(cas.expected.openssl_verify);
      // Là où openssl dit OK, T-1 à T-9 réussissent ; sur « nonce mismatch », le client dit nonce_different (étape 4).
      const r = verifierJeton({ octets: lireReponse(octets(path.join(CT5, "reponses", cas.input.response))).token, imprintAttendue: relireRequete(octets(path.join(CT5, "reponses", cas.input.request))).imprint, ancres: { certificatsPem: [texte(path.join(CLES, "ac-test.pem"))], politiquesAdmises: null } });
      expect(VERIFICATIONS_ACQUISITION.every((id) => r.checks[id] === "reussi")).to.equal(true);
    });
  }
  it("les jetons valides de CT-6 passent openssl ts -verify -digest -token_in à genTime", function () {
    if (!opensslDisponible()) return enAttente(this, "openssl absent de la machine");
    for (const t of ATTENDU_CT6.tokens.filter((x) => x.target === null && !x.file.includes("ed25519"))) {
      const attime = String(Math.floor(Date.parse(t.gen_time) / 1000));
      const sortie = execFileSync("openssl", ["ts", "-verify", "-digest", t.period_hash.slice(2), "-in", path.join(JETONS, path.basename(t.file)), "-token_in", "-CAfile", path.join(CLES, "ac-test.pem"), "-attime", attime], { stdio: "pipe" }).toString();
      expect(sortie, t.file).to.include("Verification: OK");
    }
  });
});
