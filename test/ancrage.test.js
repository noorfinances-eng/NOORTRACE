import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as A from "../scripts/lib/ancrage.mjs";
import * as O from "../scripts/lib/ots.mjs";
import * as V from "../scripts/lib/verificateur.mjs";
import { genererCt5 } from "../scripts/vecteurs/generer-ct5.mjs";
import { verifierRepertoire } from "../scripts/vecteurs/generer-ct6.mjs";

// L'IMPLÉMENTATION DE RÉFÉRENCE DE CT-5 (scripts/lib/ancrage.mjs) et ses
// vecteurs spec/vecteurs/ct-5 (spec/CT-5-ancrage.md, annexe A, EX-A.6) :
// régénération déterministe, rejeu de chaque famille (requetes, reponses,
// ots, planification, reprise, cout), schémas ancrage-v0 et
// planificateur-ancrage-v0 sur les exemples annotés de la spécification et sur
// chaque vecteur, projection d'EX-8.2, requêtes reconstruites de la trace de
// référence, lecture des .ots par ots.mjs, formule de coût, verdict inchangé
// des quarante dossiers de CT-1 et des cinquante de CT-6, absence de secret,
// de prix et d'adresse dans les vecteurs.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT5 = path.join(SPEC, "vecteurs", "ct-5");
const CT1 = path.join(SPEC, "vecteurs", "ct-1");
const CT6 = path.join(SPEC, "vecteurs", "ct-6");
const MD = fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8");
const lire = (...p) => fs.readFileSync(path.join(...p));
const lireJSON = (...p) => JSON.parse(lire(...p).toString("utf8"));
const tmp = (prefixe) => fs.mkdtempSync(path.join(os.tmpdir(), prefixe));
const SCHEMAS = J.registreSchemas(["ancrage", "planificateur-ancrage"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"))));
const SCHEMA_ANCRAGE = SCHEMAS["https://noortrace.example/schemas/v0/ancrage.schema.json"];
const SCHEMA_PLANIFICATEUR = SCHEMAS["https://noortrace.example/schemas/v0/planificateur-ancrage.schema.json"];
const valider = (valeur, schema, fragment = "") => J.validerSchema(valeur, schema, { registre: SCHEMAS, fragment });
/** Les blocs JSON annotés `<!-- schema: … -->` de CT-5. */
const blocsSpec = (marque) => [...MD.matchAll(new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g"))].map((m) => JSON.parse(m[1]));
const TRACES = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();
const REFERENCE = lireJSON(CT5, "planification", "heure-nominale-reference.json");
const lister = (racine) => {
  const out = [];
  const marcher = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) marcher(p);
      else out.push(path.relative(racine, p).split(path.sep).join("/"));
    }
  };
  marcher(racine);
  return out.sort();
};

// ---------------------------------------------------------------------------
describe("CT-5 : génération déterministe de spec/vecteurs/ct-5 (EX-A.1, EX-A.6)", function () {
  this.timeout(300_000);

  it("rejouer scripts/vecteurs/generer-ct5.mjs dans un répertoire vide redonne les mêmes octets que le dépôt (verificateur-independant/ et confrontation/ exceptés)", function () {
    const sortie = tmp("noortrace-vecteurs-ct5-");
    try {
      genererCt5({ racine: sortie });
      const conservee = (f) => f.startsWith("verificateur-independant/") || f.startsWith("confrontation/");
      const produits = lister(sortie);
      expect(produits).to.deep.equal(lister(CT5).filter((f) => !conservee(f)));
      for (const f of produits) expect(J.sha256(lire(sortie, f)), f).to.equal(J.sha256(lire(CT5, f)));
      expect(produits.filter((f) => f.startsWith("planification/"))).to.have.length(21);
    } finally {
      fs.rmSync(sortie, { recursive: true, force: true });
    }
  });

  it("le générateur n'efface que ses propres entrées : une racine étrangère est refusée sans rien effacer", function () {
    const etrangere = tmp("noortrace-vecteurs-ct5-etrangere-");
    try {
      fs.writeFileSync(path.join(etrangere, "precieux.txt"), "à garder\n");
      expect(() => genererCt5({ racine: etrangere })).to.throw(/entrées que le générateur n'écrit pas \(precieux\.txt\)/);
      expect(fs.readdirSync(etrangere)).to.deep.equal(["precieux.txt"]);
    } finally {
      fs.rmSync(etrangere, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : schémas ancrage-v0 et planificateur-ancrage-v0 (EX-4.8, EX-8.16, EX-A.3)", function () {
  it("les deux schémas n'emploient que les mots-clés de validerSchema (motsClesHorsSousEnsemble vide)", function () {
    expect(J.motsClesHorsSousEnsemble(SCHEMA_ANCRAGE)).to.deep.equal([]);
    expect(J.motsClesHorsSousEnsemble(SCHEMA_PLANIFICATEUR)).to.deep.equal([]);
  });

  it("chaque exemple annoté <!-- schema: ancrage --> et <!-- schema: planificateur-ancrage --> de la spécification est conforme", function () {
    const ancrage = blocsSpec("ancrage");
    const planificateur = blocsSpec("planificateur-ancrage");
    expect(ancrage.length).to.be.at.least(1);
    expect(planificateur.length).to.be.at.least(1);
    for (const ex of ancrage) expect(valider(ex, SCHEMA_ANCRAGE)).to.deep.equal([]);
    for (const ex of planificateur) expect(valider(ex, SCHEMA_PLANIFICATEUR)).to.deep.equal([]);
    // L'exemple de 8.10 est la trace de référence des vecteurs, octet pour octet (forme canonique).
    expect(J.canonicaliserJCS(planificateur[0])).to.equal(J.canonicaliserJCS(REFERENCE));
  });

  it("les vingt et une traces sont conformes à la racine du schéma ; requetes.json, cout.json et completude.json à $defs/fichier_vecteurs ; chaque demande des files à $defs/demande", function () {
    for (const f of TRACES) {
      const trace = lireJSON(CT5, "planification", f);
      expect(valider(trace, SCHEMA_PLANIFICATEUR), f).to.deep.equal([]);
      expect(trace.id, f).to.equal(f.replace(/\.json$/, ""));
      for (const d of [...trace.queue_before, ...trace.queue_after]) expect(valider(d, SCHEMA_PLANIFICATEUR, "#/$defs/demande"), `${f} ${d.id}`).to.deep.equal([]);
    }
    expect(valider(lireJSON(CT5, "requetes", "requetes.json"), SCHEMA_PLANIFICATEUR, "#/$defs/fichier_vecteurs")).to.deep.equal([]);
    expect(valider(lireJSON(CT5, "cout", "cout.json"), SCHEMA_PLANIFICATEUR, "#/$defs/fichier_vecteurs")).to.deep.equal([]);
    expect(valider(lireJSON(CT5, "completude", "completude.json"), SCHEMA_PLANIFICATEUR, "#/$defs/fichier_vecteurs")).to.deep.equal([]);
    for (const f of fs.readdirSync(path.join(CT5, "reprise")).sort()) {
      for (const ligne of lire(CT5, "reprise", f).toString("utf8").split("\n").filter(Boolean)) expect(valider(JSON.parse(ligne), SCHEMA_PLANIFICATEUR, "#/$defs/demande"), f).to.deep.equal([]);
    }
  });

  it("la projection d'EX-8.2 de l'exemple d'EX-4.8, avec provider_role interne et les deux calendriers d'A.2, est le config de la trace de référence", function () {
    const ex = blocsSpec("ancrage")[0];
    ex.rfc3161.checkpoints.provider_role = "interne";
    ex.opentimestamps.calendars = [...A.CALENDRIERS_VECTEURS];
    expect(valider(ex, SCHEMA_ANCRAGE)).to.deep.equal([]);
    expect(A.projeterConfiguration(ex)).to.deep.equal(REFERENCE.config);
    // Règles hors schéma d'EX-4.9 (AN-1) : l'exemple les satisfait en production, avec la valeur de l'enregistreur (règle 1).
    const r = A.verifierConfiguration(ex, { lecteurCertificat: () => true, checkpoint_interval_s: 60 });
    expect(r.violations, JSON.stringify(r.violations)).to.deep.equal([]);
  });

  it("AN-1 (EX-4.9) : règle 1 sans la valeur de l'enregistreur en production, règle 4 pour un secours non qualifié, règle 1 pour une valeur différente", function () {
    const ex = blocsSpec("ancrage")[0];
    const lecteurCertificat = () => true;
    const regles = (doc, options) => A.verifierConfiguration(doc, { lecteurCertificat, ...options }).violations.map((v) => v.rule);
    // En production, la comparaison de la règle 1 n'est jamais sautée : valeur de l'enregistreur absente → violation.
    expect(regles(ex, {})).to.deep.equal([1]);
    expect(regles(ex, { profil: "developpement" })).to.deep.equal([]);
    expect(regles(ex, { checkpoint_interval_s: 30 })).to.deep.equal([1]);
    // Règle 4 : le secours, s'il existe, a qualified non nul (EX-5.6, AN-55).
    const sansQualif = JSON.parse(JSON.stringify(ex));
    sansQualif.rfc3161.providers.find((p) => p.role === "secours").qualified = null;
    expect(valider(sansQualif, SCHEMA_ANCRAGE)).to.deep.equal([]);
    expect(regles(sansQualif, { checkpoint_interval_s: 60 })).to.deep.equal([4]);
    expect(regles(sansQualif, { checkpoint_interval_s: 60, profil: "developpement" })).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : famille requetes (EX-5.1, EX-5.3, AN-5, AN-6)", function () {
  const fichier = lireJSON(CT5, "requetes", "requetes.json");

  it("chaque TimeStampReq est reconstruite octet pour octet depuis l'empreinte, l'étiquette du nonce et la politique ; relecture identique", function () {
    expect(fichier.cases.map((c) => c.id)).to.deep.equal(["requete-point-k2", "point-k2-exemple", "point-k2-exemple-politique-interne", "periode-1-reference", "periode-1-reference-tentative-2", "periode-1-vecteurs"]);
    for (const c of fichier.cases) {
      const nonce = A.nonceDepuisEtiquette(c.input.nonce_label);
      expect(A.hexNonce(nonce), c.id).to.equal(c.expected.nonce);
      const der = A.construireRequete({ digest: c.input.digest, nonce, policy_oid: c.input.policy_oid, cert_req: c.input.cert_req });
      expect("0x" + der.toString("hex"), c.id).to.equal(c.expected.der);
      expect(der.length, c.id).to.equal(c.expected.size);
      expect(J.sha256(der), c.id).to.equal(c.expected.sha256);
      expect(lire(CT5, "requetes", c.expected.file).equals(der), c.id).to.equal(true);
      const relue = A.lireRequete(der);
      expect({ digest: relue.digest, policy_oid: relue.policy_oid, nonce: A.hexNonce(relue.nonce) }, c.id).to.deep.equal({ digest: c.input.digest, policy_oid: c.input.policy_oid, nonce: c.expected.nonce });
    }
    // Le nonce de CT-1 §13 : 64 premiers bits de SHA-256 de l'étiquette documentée.
    expect(A.hexNonce(A.nonceDepuisEtiquette("noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple"))).to.equal("0x74a6f4979421411e");
  });

  it("refusees.json : chaque construction est refusée par la référence avec la règle et le message publiés", function () {
    const refusees = lireJSON(CT5, "requetes", "refusees.json");
    expect(refusees.cases.map((c) => c.id)).to.deep.equal(["condense-31-octets", "nonce-nul", "nonce-hors-64-bits", "certreq-faux", "nonce-zero-superflu"]);
    for (const c of refusees.cases) {
      let erreur = null;
      try {
        if (c.input.der) A.lireRequete(Buffer.from(c.input.der.slice(2), "hex"));
        else A.construireRequete({ digest: c.input.digest, nonce: BigInt(c.input.nonce), policy_oid: c.input.policy_oid, cert_req: c.input.cert_req });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, c.id).to.be.instanceOf(A.ErreurAncrage);
      expect(erreur.message, c.id).to.equal(c.expected.message);
      expect(erreur.regle ?? "AN-5", c.id).to.equal(c.expected.rule);
    }
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : famille reponses (EX-5.10 à EX-5.12, EX-8.9, AN-8 à AN-11)", function () {
  this.timeout(120_000);
  const fichier = lireJSON(CT5, "reponses", "reponses.json");
  const prestataire = { ...fichier.provider, anchor_certificates: fichier.provider.anchor_certificates.map((p) => lire(CT5, "reponses", p).toString("utf8")) };

  it("chaque réponse est classée comme reponses.json l'attend : issue, code, classe, avertissements, champs du TSTInfo, jeton extrait, attente de reprise", function () {
    expect(fichier.cases).to.have.length(28);
    for (const c of fichier.cases) {
      const requete = lire(CT5, "reponses", c.input.request);
      expect(J.sha256(requete), c.id).to.equal(c.input.request_sha256);
      const reponse = c.input.response === null ? null : lire(CT5, "reponses", c.input.response);
      if (reponse) expect(J.sha256(reponse), c.id).to.equal(c.input.response_sha256);
      const r = A.evaluerReponse({ requete, reponse, http: c.input.http, sent_at: c.input.sent_at, received_at: c.input.received_at, prestataire, freshness: fichier.freshness, tardives_precedentes: c.input.late_responses_before });
      expect(r.checks_passed, c.id).to.deep.equal(c.input.checks_passed);
      const obtenu = { outcome: r.outcome, error_code: r.error_code, class: r.class, critical: r.critical, warnings: r.warnings, pki_status: r.pki_status, failure_info: r.failure_info, nonce_in_response: r.nonce_in_response, imprint_matches: r.imprint_matches, token_sha256: r.token_sha256, token_size: r.token_size, gen_time: r.gen_time, accuracy_s: r.accuracy_s, upper_bound: r.upper_bound };
      const { token, retry, openssl_verify, ...attendu } = c.expected;
      expect(obtenu, c.id).to.deep.equal(attendu);
      if (token === null) expect(r.token, c.id).to.equal(null);
      else expect(lire(CT5, "reponses", token).equals(r.token), c.id).to.equal(true);
      // EX-8.9 : attente de la première reprise (gigue nulle), seulement pour une issue transitoire.
      const attente = r.class === "transitoire" ? A.calculerAttente({ http_status: c.input.http.status, retry_after_s: c.input.http.retry_after_s, k: c.input.late_responses_before + 1, premier_408_servi: false, retry: fichier.retry, gigue: 0 }) : null;
      expect(attente, c.id).to.deep.equal(retry);
      expect(typeof openssl_verify === "string" || openssl_verify === null, c.id).to.equal(true);
    }
  });

  it("construireReponseTsa et lireReponseTsa : aller-retour des statuts, du PKIFreeText et du PKIFailureInfo ; le rejet unacceptedPolicy fait 50 octets comme celui d'openssl", function () {
    const rejet = lire(CT5, "reponses", "rejet-unacceptedPolicy.tsr");
    expect(rejet).to.have.length(50);
    const lu = A.lireReponseTsa(rejet);
    expect([lu.status, lu.fail_info, lu.fail_info_bits, lu.token]).to.deep.equal([2, "unacceptedPolicy", [15], null]);
    expect(A.construireReponseTsa({ status: 2, status_string: lu.status_string, fail_info: "unacceptedPolicy" }).equals(rejet)).to.equal(true);
    for (const [status, fail] of [[3, null], [5, null], [2, "badAlg"], [2, ["timeNotAvailable", "systemFailure"]]]) {
      const octets = A.construireReponseTsa({ status, fail_info: fail });
      const r = A.lireReponseTsa(octets);
      expect([r.status, r.fail_info]).to.deep.equal([status, Array.isArray(fail) ? fail[0] : fail]);
    }
    expect(() => A.construireReponseTsa({ status: 0 })).to.throw(/timeStampToken/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : famille ots (EX-6.2 à EX-6.7, EX-8.11, AN-17 à AN-19)", function () {
  const fichier = lireJSON(CT5, "ots", "ots.json");
  const attestation = (uri) => ({ type: "attestation", attestation: { genre: "en_attente", uri } });
  const branche = (b) => O.chemin(b.ops.map((o) => (o.op === "sha256" ? { op: O.OP.sha256 } : { op: o.op === "prepend" ? O.OP.prepend : O.OP.append, argument: Buffer.from(o.argument.slice(2), "hex") })), [attestation(b.uri)]);

  it("chaque fichier .ots est reconstruit octet pour octet (en-tête, empreinte, f0 nonce, 08, branches dans l'ordre de la bibliothèque de référence) ; engagement, état, O-1 à O-3 réussies, O-7 non exécutée", function () {
    expect(fichier.cases.map((c) => c.id)).to.deep.equal(["point-k2-minimal", "point-k2-en-attente", "periode-1-en-attente"]);
    for (const c of fichier.cases) {
      const nonce = Buffer.from(c.nonce.slice(2), "hex");
      const octets = A.construireOts({ empreinte: c.digest, nonce, reponses: c.branches.map(branche) });
      const publie = lire(CT5, "ots", c.file);
      expect(octets.equals(publie), c.id).to.equal(true);
      expect([publie.length, J.sha256(publie)], c.id).to.deep.equal([c.size, c.sha256]);
      expect("0x" + A.engagementOts(c.digest, nonce).toString("hex"), c.id).to.equal(c.commitment);
      expect(A.etatPreuve(publie), c.id).to.equal(c.state);
      expect(A.attestationsOts(publie).map((a) => [a.genre, a.uri]).sort(), c.id).to.deep.equal(c.branches.map((b) => ["en_attente", b.uri]).sort());
      const verdict = O.verifierPreuve(publie, { periodHash: c.digest });
      const statuts = Object.fromEntries(verdict.checks.map((v) => [v.id, v.status]));
      expect({ "O-1": statuts["O-1"], "O-2": statuts["O-2"], "O-3": statuts["O-3"], "O-7": statuts["O-7"], "O-7_reason": verdict.checks.find((v) => v.id === "O-7").reason }, c.id).to.deep.equal(c.expected_checks);
    }
    // L'exemple minimal d'EX-6.4 : nonce de son étiquette propre, 195 octets.
    expect("0x" + A.nonceOtsDepuisEtiquette("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2").toString("hex")).to.equal(fichier.cases[0].nonce);
    expect(fichier.cases[0].size).to.equal(195);
  });

  it("mise-a-niveau.json : la réponse du calendrier remplace l'attestation en attente et la preuve resérialisée est periode-1.ots de CT-6 (en_attente → complete)", function () {
    const m = lireJSON(CT5, "ots", "mise-a-niveau.json");
    const avant = lire(CT5, "ots", m.before.file);
    const apres = lire(CT5, "ots", m.after.file);
    const reponse = Buffer.from(m.response.der.slice(2), "hex");
    expect([avant.length, J.sha256(avant), apres.length, J.sha256(apres), reponse.length, J.sha256(reponse)]).to.deep.equal([m.before.size, m.before.sha256, m.after.size, m.after.sha256, m.response.size, m.response.sha256]);
    expect([A.etatPreuve(avant), A.etatPreuve(apres)]).to.deep.equal([m.expected.state_before, m.expected.state_after]);
    const fusion = A.fusionnerOts(avant, { uri: m.calendar, reponse: A.lireReponseCalendrier(reponse) });
    expect(J.sha256(fusion)).to.equal(m.expected.merged_sha256);
    expect(fusion.equals(apres)).to.equal(m.expected.merged_equals_after);
    expect(() => A.fusionnerOts(avant, { uri: "https://bob.btc.calendar.opentimestamps.org", reponse: A.lireReponseCalendrier(reponse) })).to.throw(/aucune attestation en attente/);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : familles planification et reprise (EX-8.12, EX-8.16, EX-A.6)", function () {
  this.timeout(120_000);

  it("chaque trace est reproduite à l'identique par rejouerTrace (actions et file finale)", function () {
    expect(TRACES).to.have.length(21);
    for (const f of TRACES) {
      const trace = lireJSON(CT5, "planification", f);
      const ecarts = A.verifierTrace(trace);
      expect(ecarts, `${f} : ${JSON.stringify(ecarts.slice(0, 2))}`).to.deep.equal([]);
    }
  });

  it("trace de référence (8.10) : chaque request_sha256 est celui de la requête reconstruite avec le nonce et la politique indiqués", function () {
    const envois = REFERENCE.expected.filter((a) => a.action === "envoyer_rfc3161");
    expect(envois.length).to.be.at.least(4);
    for (const a of envois) {
      const der = A.construireRequete({ digest: a.detail.digest, nonce: BigInt(a.detail.nonce), policy_oid: a.detail.policy_oid });
      expect([J.sha256(der), der.length], a.request_id).to.deep.equal([a.detail.request_sha256, a.detail.request_size]);
    }
    // Le nonce de chaque tentative vient de l'étiquette d'A.2 (journal-principal, sorte, empreinte, rang).
    for (const d of REFERENCE.queue_after.filter((x) => x.kind.startsWith("jeton_"))) {
      for (const t of d.attempts.filter((x) => x.nonce !== null)) expect(t.nonce, t.correlation_id).to.equal(A.hexNonce(A.nonceDepuisEtiquette(A.ETIQUETTES.nonceTsa({ journal: "journal-principal", sorte: d.subject.kind, hash: d.subject.hash, n: t.n }))));
    }
  });

  it("EX-8.5, règle 1 (AN-32) : dans chaque trace, la ligne envoyee de la demande précède immédiatement chaque requête (envoi RFC 3161, transaction, soumission OpenTimestamps), sauf le renvoi d'une ancre déjà envoyee au démarrage", function () {
    for (const f of TRACES) {
      const trace = lireJSON(CT5, "planification", f);
      const demarrage = new Set(trace.inputs.filter((e) => e.type === "demarrage").map((e) => A.ms(e.t)));
      const dejaEnvoyees = new Set(trace.queue_before.filter((d) => d.state === "envoyee").map((d) => d.id));
      trace.expected.forEach((a, i) => {
        if (!["envoyer_rfc3161", "envoyer_registre", "soumettre_ots"].includes(a.action)) return;
        const prec = trace.expected[i - 1];
        const renvoi = a.action === "envoyer_registre" && dejaEnvoyees.has(a.request_id) && demarrage.has(A.ms(a.t));
        if (!renvoi) expect([prec?.action, prec?.request_id, prec?.detail?.state], `${f} action ${i}`).to.deep.equal(["ecrire_file", a.request_id, "envoyee"]);
      });
    }
  });

  it("reprise/ : chaque file avant est la forme canonique de queue_before ; relue puis rejouée, elle donne la file après, une demande par id ; les fichiers d'époques relus ensemble (lireFiles) donnent la file avant", function () {
    const noms = fs.readdirSync(path.join(CT5, "reprise")).filter((f) => f.endsWith(".avant.ndjson")).map((f) => f.replace(/\.avant\.ndjson$/, "")).sort();
    expect(noms).to.deep.equal(["bascule-epoque", "bascule-epoque-fichier-perdu", "file-pleine", "redemarrage-reprise", "refus-puis-preuve-de-vie-redemarrage", "registre-indisponible"]);
    const epoques = fs.readdirSync(path.join(CT5, "reprise")).filter((f) => /\.epoque-\d+\.ndjson$/.test(f)).sort();
    expect(epoques).to.deep.equal(["bascule-epoque.epoque-1.ndjson", "bascule-epoque.epoque-2.ndjson"]);
    const relue = A.lireFiles(epoques.map((f, i) => ({ nom: `file-${i + 1}.ndjson`, texte: lire(CT5, "reprise", f).toString("utf8") })));
    expect([relue.errors, relue.truncated]).to.deep.equal([[], []]);
    expect(A.ecrireFile(relue.demandes)).to.equal(lire(CT5, "reprise", "bascule-epoque.avant.ndjson").toString("utf8"));
    // Ordre des fichiers : par époque, compacté avant l'original d'une même époque ; un nom hors convention est refusé.
    expect(A.lireFiles([{ nom: "file-2.ndjson", texte: "" }, { nom: "file-1.3.compact.ndjson", texte: "" }, { nom: "file-1.ndjson", texte: "" }]).files).to.deep.equal(["file-1.3.compact.ndjson", "file-1.ndjson", "file-2.ndjson"]);
    expect(() => A.lireFiles([{ nom: "file.ndjson", texte: "" }])).to.throw(A.ErreurAncrage);
    for (const nom of noms) {
      const trace = lireJSON(CT5, "planification", `${nom}.json`);
      const avant = lire(CT5, "reprise", `${nom}.avant.ndjson`).toString("utf8");
      const apres = lire(CT5, "reprise", `${nom}.apres.ndjson`).toString("utf8");
      expect(avant, nom).to.equal(A.ecrireFile(trace.queue_before));
      expect(apres, nom).to.equal(A.ecrireFile(trace.queue_after));
      const lue = A.lireFile(avant);
      expect([lue.errors, lue.truncated, lue.lines], nom).to.deep.equal([[], false, trace.queue_before.length]);
      const { file } = A.rejouerTrace({ ...trace, queue_before: lue.demandes });
      expect(A.ecrireFile(file), nom).to.equal(apres);
      const ids = apres.split("\n").filter(Boolean).map((l) => JSON.parse(l).id);
      expect(new Set(ids).size, nom).to.equal(ids.length);
    }
    // EX-8.5, règle 3 : une dernière ligne tronquée est ignorée et signalée, jamais réparée.
    const texte = lire(CT5, "reprise", "redemarrage-reprise.avant.ndjson").toString("utf8");
    const tronquee = A.lireFile(texte.slice(0, -40));
    expect([tronquee.truncated, tronquee.demandes.length]).to.deep.equal([true, texte.split("\n").filter(Boolean).length - 1]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : comptages et coût (EX-4.11, section 12)", function () {
  /** Premier nombre d'une cellule (espaces de milliers, virgule décimale, gras et code ôtés). */
  const nombre = (texte) => Number((/[0-9][0-9  \u202f]*(?:,[0-9]+)?/.exec(texte.replace(/[*`]/g, "")) ?? ["NaN"])[0].replace(/[\s\u202f\u00a0]/g, "").replace(",", "."));
  /** Lignes d'une table Markdown de CT-5 qui suit l'en-tête donné. */
  const table = (entete) => {
    const lignes = MD.split("\n");
    const i = lignes.findIndex((l) => l.startsWith(entete));
    expect(i, entete).to.be.greaterThan(-1);
    const out = [];
    for (let j = i + 2; j < lignes.length && lignes[j].startsWith("|"); j++) out.push(lignes[j].split("|").slice(1, -1).map((c) => c.trim()));
    return out;
  };

  it("les onze cas de cout.json sont reproduits par la formule de coût, et leurs N_q, N_s, N_a et C_j sont ceux de la table imprimée de 12.3", function () {
    const fichier = lireJSON(CT5, "cout", "cout.json");
    expect(fichier.cases).to.have.length(11);
    for (const c of fichier.cases) expect(A.cout(c.input), c.id).to.deep.equal(c.expected);
    for (const c of fichier.cases) for (const k of ["unit_price_qualified", "unit_price_second_rank", "subscription_fee"]) expect(typeof c.input[k], `${c.id} ${k}`).to.equal("number");
    // Confrontation au texte (D59) : la table de §12.3 est lue dans CT-5, non recopiée.
    const imprimee = table("| Cas | Hypothèses |");
    expect(imprimee.map((l) => l[0].replace(/`/g, ""))).to.deep.equal(fichier.cases.map((c) => c.id));
    for (const [cas, , nq, ns, na, cj] of imprimee) {
      const c = fichier.cases.find((x) => x.id === cas.replace(/`/g, ""));
      expect([nombre(nq), nombre(ns), nombre(na)], c.id).to.deep.equal([c.expected.qualified_tokens_per_journal, c.expected.second_rank_tokens_per_journal, c.expected.registry_anchors_per_journal]);
      const total = /\*\*([0-9  ]+) p\*\*/.exec(cj);
      expect(total, `${c.id} : ${cj}`).to.not.equal(null);
      expect(nombre(total[1]), c.id).to.equal(c.id === "points-chez-principal-a1-dix-journaux" ? c.expected.cost_total : c.expected.cost_per_journal);
    }
  });

  it("compterJetons reproduit chaque ligne de la table de 4.6 (c_T de 60 à 3600 s, points chez le principal et chez un second rang), et le plafond d'ancres 2 + 3600 / c_K", function () {
    const lignes = table("| `c_T` | Jetons par heure");
    expect(lignes.map((l) => nombre(l[0]))).to.deep.equal([60, 120, 180, 300, 600, 900, 1800, 3600]);
    for (const [cT, parHeure, points, parJour, parAn, qualifiesPrincipal, secondRang] of lignes) {
      const config = (role) => ({ checkpoint_interval_s: 60, rfc3161: { checkpoints: { interval_s: nombre(cT), provider_role: role } }, registry: { checkpoints: "nouveaux_evenements" } });
      const p = A.compterJetons(config("principal"));
      const s = A.compterJetons(config("second_rang"));
      expect([p.per_hour.tokens, p.per_hour.checkpoint_tokens, p.per_day.tokens, p.per_year.tokens, p.per_year.qualified_tokens], cT).to.deep.equal([nombre(parHeure), nombre(points), nombre(parJour), nombre(parAn), nombre(qualifiesPrincipal)]);
      const attendu = secondRang.replace(/\*/g, "").split("+").map((x) => nombre(x.replace(/qualifiés|autres/g, "")));
      expect([s.per_year.qualified_tokens, ...(attendu.length > 1 ? [s.per_year.checkpoint_tokens] : [])], cT).to.deep.equal(attendu);
      expect(p.per_hour.registry_anchors_max, cT).to.equal(62);
    }
    const n = A.compterJetons(REFERENCE.config);
    expect(n.per_hour).to.deep.equal({ tokens: 12, qualified_tokens: 1, checkpoint_tokens: 11, checkpoint_provider_role: "interne", registry_anchors_max: 62, submit_period: 1, ots_submissions: 1 });
    expect(A.compterJetons({ checkpoint_interval_s: 300, registry: { checkpoints: "tous" } }).per_hour.registry_anchors_max).to.equal(14);
    expect(A.compterJetons({ registry: { checkpoints: "aucun" } }).per_hour.registry_anchors_max).to.equal(1);
    expect(() => A.compterJetons({ rfc3161: { checkpoints: { interval_s: 7 } } })).to.throw(A.ErreurAncrage);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : série des points, échéances, admission et complétude au registre (AN-2, AN-3, AN-61)", function () {
  const serie = JSON.parse(fs.readFileSync(path.join(CT1, "points-de-controle", "periode-1.json"), "utf8"));
  const resume = (p) => ({ checkpoint_hash: J.hachagePointDeControle(p), tree_size: p.tree_size, checkpoint_ts: p.checkpoint_ts });
  const points = serie.map(resume);
  const PERIODE = serie[0].period_start;
  const a = (hhmm) => points.find((p) => p.checkpoint_ts.slice(11, 16) === hhmm && p.checkpoint_ts.endsWith(":00.000Z"));
  const iso = (hhmmss) => `2026-11-05T${hhmmss}.000Z`;

  it("tableEcheances : un jeton refusé (absent des ancres) ne fait pas avancer le dernier point contresigné (EX-4.3) ; alertes jeton_anterieur_au_point et contresignature_tardive (AN-2)", function () {
    // Le point de 09:15 (D_3) n'a pas de jeton ; le point de 09:20 (même tree_size) en a un : D_4 n'est pas sans_objet.
    const t = A.tableEcheances({ period_start: PERIODE, points, ancres: [{ checkpoint_hash: a("09:20").checkpoint_hash, kind: "rfc3161", bound: iso("09:20:02") }] });
    const ligne = (k) => t.deadlines.find((l) => l.k === k);
    expect([ligne(3).state, ligne(4).state, ligne(5).state]).to.deep.equal(["remplacee", "satisfaite", "sans_objet"]);
    expect(t.cadence).to.deep.equal({ conforme: true, ecarts: [] });
    // Jeton antérieur au point déclaré (au-delà de clock_tolerance_s) et contresignature tardive (plus de c_T après le point).
    const u = A.tableEcheances({ period_start: PERIODE, points, ancres: [{ checkpoint_hash: a("09:15").checkpoint_hash, kind: "rfc3161", bound: iso("09:10:00") }, { checkpoint_hash: a("09:35").checkpoint_hash, kind: "rfc3161", bound: iso("09:55:00") }] });
    expect(u.alerts.filter((x) => x.code !== "checkpoint_anchor_late").map((x) => [x.code, x.k])).to.deep.equal([["jeton_anterieur_au_point", 3], ["contresignature_tardive", 7]]);
  });

  it("constaterCadence (AN-2, alerte point_manquant) : la série publiée est conforme ; une série creuse (09:00, 09:59, clôture) porte un écart de 3540 s", function () {
    expect(A.constaterCadence({ period_start: PERIODE, points }).conforme).to.equal(true);
    const creuse = [points[0], a("09:59"), points[points.length - 1]];
    const c = A.constaterCadence({ period_start: PERIODE, points: creuse });
    expect(c.ecarts).to.deep.equal([{ from: iso("09:00:00"), to: iso("09:59:00"), gap_s: 3540 }]);
    expect(A.tableEcheances({ period_start: PERIODE, points: creuse }).alerts.filter((x) => x.code === "point_manquant")).to.have.length(1);
  });

  it("admettrePoint (AN-3 ; CT-1 §10.5, règle 2) : avec les événements, une racine ou un last_hash faux est refusé ; le point publié est admis", function () {
    const evenements = JSON.parse(fs.readFileSync(path.join(CT1, "journal-valide", "evenements.json"), "utf8"));
    const cles = JSON.parse(fs.readFileSync(path.join(CT1, "dossiers", "valide-seq-7", "cles.json"), "utf8"));
    const i = serie.findIndex((p) => p.checkpoint_ts === iso("09:32:00"));
    expect(A.admettrePoint(serie[i], { serie: serie.slice(0, i), cles, evenements })).to.include({ admis: true });
    const racineFausse = { ...serie[i], root: "0x" + "11".repeat(32) };
    expect(A.admettrePoint(racineFausse, { serie: serie.slice(0, i), evenements }).regle).to.equal("racine");
    const lastFaux = { ...serie[i], last_hash: "0x" + "22".repeat(32) };
    expect(A.admettrePoint(lastFaux, { serie: serie.slice(0, i), evenements }).regle).to.equal("last_hash");
  });

  it("planification/ : chaque ligne checkpoint_countersigned porte les quatre composantes de d_jeton, dont la somme est d_jeton_s (EX-3.5, 8.9)", function () {
    const dir = path.join(CT5, "planification");
    let n = 0;
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith(".json"))) {
      const trace = lireJSON(CT5, "planification", f);
      for (const a of trace.expected.filter((x) => x.action === "journaliser" && x.detail.event === "checkpoint_countersigned")) {
        const d = a.detail;
        for (const k of ["d_point_s", "d_attente_s", "d_releve_s", "d_tsa_s"]) expect(Number.isInteger(d[k]) && d[k] >= 0, `${f} ${k}`).to.equal(true);
        expect(d.d_point_s + d.d_attente_s + d.d_releve_s + d.d_tsa_s, f).to.equal(d.d_jeton_s);
        n++;
      }
    }
    expect(n).to.be.greaterThan(20);
  });

  it("completude/ : chaque cas est reproduit par verifierCompletudeRegistre (AN-61) ; la série réécrite laisse deux ancres orphelines ; la série de la période suivante doit être servie", function () {
    const fichier = lireJSON(CT5, "completude", "completude.json");
    expect(fichier.cases.map((c) => c.id)).to.deep.equal(["serie-publiee-complete", "serie-reecrite-ancres-orphelines", "ancres-hors-ordre", "periode-suivante-dans-la-fenetre", "periode-suivante-non-servie", "emetteur-doctype-et-fenetre"]);
    for (const c of fichier.cases) {
      const r = A.verifierCompletudeRegistre({ journaux: c.input.journals, ancres: c.input.anchors, emetteurs: c.input.issuers, de_bloc: c.input.from_block, a_bloc: c.input.to_block });
      expect({ complete: r.complet, orphans: r.orphelines.map((o) => o.fingerprint), out_of_order: r.hors_ordre.map((o) => o.fingerprint), attached: r.rattachees.length }, c.id).to.deep.equal(c.expected);
    }
    expect(fichier.cases[1].expected.orphans).to.have.length(2);
    // EX-10.7 : servie, la période suivante rattache son point ; non servie, il paraît orphelin.
    expect(fichier.cases[3].expected).to.deep.include({ complete: true, attached: 4 });
    expect(fichier.cases[4].expected.complete).to.equal(false);
    expect(fichier.cases[4].expected.orphans).to.have.length(1);
  });
});

// ---------------------------------------------------------------------------
describe("CT-5 : les dossiers de CT-1 et de CT-6 gardent leur verdict ; aucun secret, prix ni adresse dans spec/vecteurs/ct-5 (EX-A.6)", function () {
  this.timeout(300_000);
  const NOUVEAUX_CT1 = ["invalide-k1-double-defaut", "invalide-k1-point-autre-periode", "invalide-k2-checkpoint-hash", "invalide-k3-signature-point", "invalide-k4-point-trop-court", "invalide-k5-coherence-tronquee", "invalide-k6-last-hash", "valide-seq-7-partie-declaree-absente", "valide-seq-7-point-de-cloture", "valide-seq-7-point-de-controle"];
  const NOUVEAUX_CT6 = ["invalide-k1-double-defaut", "invalide-k1-partie-inexploitable", "invalide-k7-base64-non-canonique", "invalide-k7-jeton-autre-empreinte", "invalide-k7-jeton-signature", "invalide-k8-contrat", "invalide-k8-empreinte", "invalide-k9-preuve-autre-empreinte", "invalide-r11-ancre-de-periode", "valide-point-de-controle-complet", "valide-point-de-controle-declare-absent", "valide-point-de-controle-jeton-seul", "valide-point-de-controle-ots-en-attente", "valide-point-de-controle-point-contresigne", "valide-point-de-controle-point-de-cloture", "valide-point-de-controle-reference-declarative", "valide-point-de-controle-sans-ancre", "valide-point-de-controle-sans-ancres-reviseur"];

  /** Vrai pour un dossier de la révision 0.4 de CT-1 : index à quatorze parties (partie attestation-perimetre.json déclarée). */
  const QUATORZE_PARTIES = (racine, nom) => JSON.parse(fs.readFileSync(path.join(racine, nom, "dossier.json"), "utf8")).parts.length === 14;

  it("les quarante dossiers de CT-1 (version 0.2) : même verdict et mêmes contrôles en échec que leur attendu.json", function () {
    const racine = path.join(CT1, "dossiers");
    // Les dossiers de la révision 0.4 de CT-1 (partie attestation-perimetre.json déclarée, quatorze parties) s'ajoutent eux aussi (CT-7 annexe A.7).
    const anciens = fs.readdirSync(racine).filter((n) => !NOUVEAUX_CT1.includes(n) && !QUATORZE_PARTIES(racine, n)).sort();
    expect(anciens).to.have.length(40);
    const schemas = J.registreSchemas(["evenement", "manifeste", "dossier", "point-de-controle"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"))));
    for (const nom of anciens) {
      const attendu = JSON.parse(fs.readFileSync(path.join(racine, nom, "attendu.json"), "utf8"));
      const fichiers = Object.fromEntries(fs.readdirSync(path.join(racine, nom)).filter((f) => f !== "attendu.json").map((f) => [f, lire(racine, nom, f)]));
      expect(fichiers["points-de-controle.json"], nom).to.equal(undefined);
      const rapport = J.verifierDossier(fichiers, { schemas });
      expect([rapport.valide, J.controlesEnEchec(rapport)], nom).to.deep.equal([attendu.valide, attendu.controles_en_echec]);
    }
  });

  it("les cinquante dossiers de CT-6 (version 0.1) : même code de retour et mêmes vérifications en échec que leur attendu.json", function () {
    const racine = path.join(CT6, "dossiers");
    const anciens = fs.readdirSync(racine).filter((n) => !NOUVEAUX_CT6.includes(n) && !QUATORZE_PARTIES(racine, n)).sort();
    expect(anciens).to.have.length(50);
    for (const nom of anciens) expect(fs.existsSync(path.join(racine, nom, "points-de-controle.json")), nom).to.equal(false);
    for (const nom of anciens) {
      const a = JSON.parse(fs.readFileSync(path.join(racine, nom, "attendu.json"), "utf8"));
      const corps = verifierRepertoire(path.join(racine, nom), { ancres: a.anchors ? path.resolve(racine, nom, a.anchors) : null, entetes: a.bitcoin_headers ? path.resolve(racine, nom, a.bitcoin_headers) : null });
      expect([corps.exit_code, corps.failed_checks], nom).to.deep.equal([a.exit_code, a.failed_checks]);
    }
  });

  it("EX-A.6 : aucun fichier de données de spec/vecteurs/ct-5 (sorties de confrontation comprises, sources et documents des modules exceptés) ne contient price, password, credential, une adresse IP ni une clé privée (les noms de champs unit_price_* imposés par planificateur-ancrage-v0 exceptés)", function () {
    // Portée d'EX-A.6 : les fichiers de données ; les sources et documents de verificateur-independant/ et de
    // confrontation/ (.go, go.mod, go.sum, .py, .md) nomment ces mots pour les interdire et citent des sections de RFC.
    const source = (f) => /^(verificateur-independant|confrontation)\//.test(f) && /\.(go|mod|sum|py|md)$/.test(f);
    const fichiers = lister(CT5).filter((f) => !source(f));
    expect(fichiers.length).to.be.at.least(60);
    expect(fichiers.some((f) => f.startsWith("confrontation/sorties/"))).to.equal(true);
    for (const f of fichiers) {
      const texte = lire(CT5, f).toString("utf8").replace(/unit_price_(qualified|second_rank)/g, "");
      expect(texte, f).not.to.match(/price|password|credential/i);
      // Quatre nombres séparés par des points, hors numéro de section (« §2.1.4.1 », « RFC 9162 2.1.4.1 »).
      expect(texte, f).not.to.match(/(?<![\d.§])(?<!RFC \d{4} )\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/);
      expect(texte, f).not.to.match(/PRIVATE KEY/);
    }
    // Le motif ne laisse pas passer une adresse, et ne prend pas un numéro de section pour une adresse.
    const motif = /(?<![\d.§])(?<!RFC \d{4} )\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/;
    expect(`vers ${[192, 0, 2, 1].join(".")} sur le port`).to.match(motif);
    expect("RFC 9162 §2.1.4.1").not.to.match(motif);
    // Les constantes sont publiques : les clés de l'autorité de test sont citées par chemin, jamais recopiées.
    const constantes = lireJSON(CT5, "constantes.json");
    expect(constantes.test_authority.ca).to.match(/^\.\.\/ct-6\/rfc3161\/cles\/ac-test\.pem$/);
    expect(JSON.stringify(constantes)).not.to.match(/BEGIN/);
  });
});
