// Binaire `noortrace-ancrage` (lot F1 ; CT-5 EX-8.13, EX-10.6, EX-10.7,
// EX-12.1, EX-12.2, AN-1, AN-2, AN-3, AN-42, AN-54, AN-59, AN-61) : chaque
// commande sur les vecteurs publiés (`configuration` sur l'exemple d'EX-4.8,
// `trace` sur les vingt-deux traces, `cout` sur les onze cas, `completude`
// sur les six cas, `serie` sur les séries valides et invalides de CT-1,
// `fiche` sur l'autorité de test, `acquisitions` sur un fichier
// d'enregistrements), codes de retour 0, 1, 2, messages en français, aucune
// valeur de secret affichée.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { RACINE, CT1, CT5, AC_TEST_PEM, POLITIQUE_TEST, lireJson, repertoireTemporaire } from "./fixtures/ancrage-composant/outils.mjs";

const BIN = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage");
const SPEC = path.join(RACINE, "spec");

function bin(args, options = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], { encoding: "utf8", timeout: 120000, ...options });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/** Bloc ```json qui suit un marqueur dans un texte de spécification. */
function blocApres(texte, marqueur) {
  const lignes = texte.split("\n");
  let i = lignes.findIndex((l) => l.includes(marqueur));
  if (i < 0) throw new Error(`marqueur introuvable : ${marqueur}`);
  while (!lignes[i].startsWith("```")) i++;
  let fin = i + 1;
  while (lignes[fin] !== "```") fin++;
  return lignes.slice(i + 1, fin).join("\n");
}

describe("ancrage, composant F1 : binaire noortrace-ancrage", function () {
  this.timeout(300000);
  let dir;
  let exemple;
  before(function () {
    dir = repertoireTemporaire("noortrace-ancrage-f1-cli-");
    exemple = path.join(dir, "ancrage-v0.json");
    fs.writeFileSync(exemple, blocApres(fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8"), "<!-- schema: ancrage -->"));
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("sans commande : usage et code 2 ; commande inconnue : code 2 ; aide : code 0", function () {
    const sans = bin([]);
    expect(sans.code).to.equal(2);
    expect(sans.stdout).to.include("Commandes :");
    const inconnue = bin(["inconnue"]);
    expect(inconnue.code).to.equal(2);
    expect(inconnue.stderr).to.include("commande inconnue");
    expect(bin(["aide"]).code).to.equal(0);
  });

  it("configuration (AN-1) : l'exemple d'EX-4.8 est valide hors production (code 0), refusé en production sans la cadence de l'enregistreur (règle 1, code 1), admis avec --checkpoint-interval 60 ; un document hors schéma est refusé avec le rapport nominatif ; --json", function () {
    const ok = bin(["configuration", exemple, "--profil", "developpement"]);
    expect(ok.code, ok.stderr).to.equal(0);
    expect(ok.stdout).to.include("configuration valide (AN-1, profil developpement)");
    const prod = bin(["configuration", exemple, "--profil", "production"]);
    expect(prod.code).to.equal(1);
    expect(prod.stdout).to.include("[1]");
    const prodOk = bin(["configuration", exemple, "--profil", "production", "--checkpoint-interval", "60", "--json"]);
    expect(prodOk.code).to.equal(0);
    expect(JSON.parse(prodOk.stdout)).to.deep.include({ valide: true, profil: "production", erreurs: [] });
    const trace = bin(["configuration", path.join(CT5, "planification", "heure-nominale-reference.json")]);
    expect(trace.code).to.equal(1);
    expect(trace.stdout).to.include("[schema]");
    const mauvais = structuredClone(lireJson(exemple));
    mauvais.rfc3161.retry.initial_ms = 400000;
    mauvais.rfc3161.providers.push({ ...mauvais.rfc3161.providers[0], id: "deuxieme-principal" });
    const f = path.join(dir, "mauvais.json");
    fs.writeFileSync(f, JSON.stringify(mauvais));
    const r = bin(["configuration", f, "--json"]);
    expect(r.code).to.equal(1);
    expect(JSON.parse(r.stdout).erreurs.map((e) => e.regle).sort()).to.deep.equal(["2", "6"]);
    expect(bin(["configuration", f, "--profil", "autre"]).code).to.equal(2);
    expect(bin(["configuration"]).code).to.equal(2);
    expect(bin(["configuration", path.join(dir, "absent.json")]).code).to.equal(1);
    // Aucune valeur de secret dans la sortie : les références sont des emplacements, le binaire n'en lit aucun.
    expect(ok.stdout + prod.stdout).to.not.include("NOORTRACE_TSA_PRINCIPAL");
  });

  it("trace (AN-42) : chacune des vingt-deux traces de planification/ est rejouée conforme (code 0) ; une trace altérée donne un écart et le code 1", function () {
    const traces = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();
    expect(traces).to.have.lengthOf(22);
    for (const f of traces) {
      const r = bin(["trace", path.join(CT5, "planification", f)]);
      expect(r.code, `${f} : ${r.stdout} ${r.stderr}`).to.equal(0);
      expect(r.stdout).to.include("conforme à expected et queue_after (AN-42)");
    }
    const t = lireJson(path.join(CT5, "planification", "heure-nominale-reference.json"));
    t.expected.pop();
    const f = path.join(dir, "trace-alteree.json");
    fs.writeFileSync(f, JSON.stringify(t));
    const r = bin(["trace", f, "--json"]);
    expect(r.code).to.equal(1);
    const j = JSON.parse(r.stdout);
    expect(j.conforme).to.equal(false);
    expect(j.ecarts.length).to.be.at.least(1);
  });

  it("cout (EX-12.1, EX-12.2, AN-59) : les onze cas de cout/ rendent exactement les six grandeurs attendues par --entrees ; les options reproduisent le cas defaut-second-rang-a1 ; unités symboliques, jamais un prix (AN-60)", function () {
    const famille = lireJson(path.join(CT5, "cout", "cout.json"));
    expect(famille.cases).to.have.lengthOf(11);
    for (const c of famille.cases) {
      const f = path.join(dir, `cout-${c.id}.json`);
      fs.writeFileSync(f, JSON.stringify(c));
      const r = bin(["cout", "--entrees", f, "--json"]);
      expect(r.code, c.id).to.equal(0);
      expect(JSON.parse(r.stdout).expected, c.id).to.deep.equal(c.expected);
    }
    const r = bin(["cout", "--role", "second_rang", "--activite", "1", "--json"]);
    expect(JSON.parse(r.stdout).expected).to.deep.equal(famille.cases.find((c) => c.id === "defaut-second-rang-a1").expected);
    const texte = bin(["cout", "--role", "interne", "--prix-second-rang", "0"]);
    expect(texte.code).to.equal(0);
    expect(texte.stdout).to.include("unités symboliques");
    expect(texte.stdout).to.include("coût par journal C_j      : 8760 p");
    expect(bin(["cout", "--activite", "2"]).code).to.equal(1);
  });

  it("completude (EX-10.7, AN-61) : la famille completude/ est reproduite cas par cas (attendu reproduit) ; un cas incomplet seul rend le code 1 ; des entrées hostiles sont refusées", function () {
    const r = bin(["completude", path.join(CT5, "completude", "completude.json")]);
    expect(r.code, r.stderr).to.equal(0);
    expect((r.stdout.match(/attendu reproduit/g) ?? []).length).to.equal(6);
    const famille = lireJson(path.join(CT5, "completude", "completude.json"));
    const orphelines = famille.cases.find((c) => c.id === "serie-reecrite-ancres-orphelines");
    const f = path.join(dir, "orphelines.json");
    fs.writeFileSync(f, JSON.stringify(orphelines.input));
    const seul = bin(["completude", f, "--json"]);
    expect(seul.code).to.equal(1);
    expect(JSON.parse(seul.stdout)).to.deep.equal(orphelines.expected);
    fs.writeFileSync(f, JSON.stringify({ ...orphelines.input, from_block: -5 }));
    expect(bin(["completude", f]).code).to.equal(1);
  });

  it("serie (AN-2, AN-3) : la série de la période 1 des vecteurs CT-1 (61 points, cles.json, événements, manifeste signé) est admise, table des échéances et cadence conformes (code 0) ; une série au chaînage faux est refusée (code 1) ; avec acquisitions, d_jeton rendu", function () {
    const evenements = lireJson(path.join(CT1, "journal-valide", "evenements.json"));
    const hashes = evenements.filter((e) => e.seq >= 1 && e.seq <= 9).map((e) => N.hacherEvenement(e));
    const fHashes = path.join(dir, "hashes-periode-1.json");
    fs.writeFileSync(fHashes, JSON.stringify(hashes));
    const args = ["serie", "--configuration", exemple, "--periode", "1793869200", "--points", path.join(CT1, "points-de-controle", "periode-1.json"), "--cles", path.join(CT1, "cles", "cles.json"), "--evenements", fHashes, "--manifeste", path.join(CT1, "manifestes", "periode-1.json"), "--signature", path.join(CT1, "manifestes", "periode-1.sig")];
    const r = bin(args);
    expect(r.code, r.stdout + r.stderr).to.equal(0);
    expect(r.stdout).to.include("61 point(s), 0 refus d'admission (AN-3)");
    expect(r.stdout).to.include("manifeste : admis");
    expect(r.stdout).to.include("cadence : conforme");
    expect(r.stdout).to.match(/D_11\s+2026-11-05T09:55:00\.000Z/);
    const j = JSON.parse(bin([...args, "--json"]).stdout);
    expect(j.admission.every((a) => a.admis === true)).to.equal(true);
    expect(j.echeances.echeances).to.have.lengthOf(11);
    expect(j.echeances.echeances.map((e) => e.state)).to.include.members(["en_attente", "sans_objet"]);
    expect(j.conforme).to.equal(true);
    // Série invalide : chaînage faux au rang attendu par attendu.json.
    const invalide = bin(["serie", "--configuration", exemple, "--periode", "1793869200", "--points", path.join(CT1, "points-de-controle", "invalides", "periode-1-chainage-faux.json"), "--cles", path.join(CT1, "cles", "cles.json")]);
    expect(invalide.code).to.equal(1);
    expect(invalide.stdout).to.match(/refusé .* : chainage/);
    // Avec des acquisitions : un jeton promu sur le point de 09:13 (D_3 en attente : son point est celui de 09:15) ; le jeton date la clôture.
    const points = lireJson(path.join(CT1, "points-de-controle", "periode-1.json"));
    const p15 = points.find((p) => p.checkpoint_ts === "2026-11-05T09:15:00.000Z");
    const acquisitions = [
      { attempt_id: "jeton_point:aaaa:1", attempt: 1, object: "point", object_name: `point-${N.hacherPoint(p15).slice(2)}`, imprint: N.hacherPoint(p15), provider_id: "tsa-interne", provider_role: "interne", qualified: null, outcome: "obtenue", promoted: true, revoked: false, gen_time: "2026-11-05T09:15:03Z", upper_bound: "2026-11-05T09:15:04.000Z", nonce: "0x0000000000000001" },
      { attempt_id: "jeton_periode:bbbb:1", attempt: 1, object: "manifeste", object_name: "manifeste", imprint: "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914", provider_id: "qtsa-principal", provider_role: "principal", qualified: { framework: "eidas" }, outcome: "obtenue", promoted: true, revoked: false, gen_time: "2026-11-05T10:00:05Z", upper_bound: "2026-11-05T10:00:06.000Z", nonce: "0x0000000000000002" },
    ];
    const fAcq = path.join(dir, "acquisitions.ndjson");
    fs.writeFileSync(fAcq, acquisitions.map((a) => N.jcs(a)).join("\n") + "\n");
    const avec = JSON.parse(bin([...args, "--acquisitions", fAcq, "--json"]).stdout);
    const d3 = avec.echeances.echeances.find((e) => e.k === 3);
    expect(d3).to.include({ state: "satisfaite", d_jeton_s: 4, d_point_s: 0 });
    expect(avec.echeances.cloture).to.include({ state: "satisfaite", d_jeton_s: 6 });
    expect(avec.alertes.map((a) => a.code)).to.include("checkpoint_anchor_late");
  });

  it("fiche (EX-10.6, AN-54) : construite depuis un prestataire ou une configuration, privée d'auth, SHA-256 des certificats, mention « non qualifié » pour l'interne ; --sortie écrit prestataire-<id>.json ; aucune valeur de secret", function () {
    const prestataire = {
      id: "tsa-interne-essai", role: "interne", url: "http://127.0.0.1:2020/", auth: { method: "basic", secret: { env: "SECRET_ESSAI_TSA" } }, hash: "sha256", policy_oid: POLITIQUE_TEST,
      accepted_policies: [POLITIQUE_TEST], anchor_certificates: [AC_TEST_PEM], qualified: null, min_interval_ms: 0, request_timeout_ms: 5000, correlation_header: null, source: "autorité de test de CT-6 (essai du binaire)",
    };
    const f = path.join(dir, "prestataire.json");
    fs.writeFileSync(f, JSON.stringify(prestataire));
    const sortie = path.join(dir, "prestataire-tsa-interne-essai.json");
    const r = bin(["fiche", "--prestataire", f, "--sortie", sortie], { env: { ...process.env, SECRET_ESSAI_TSA: "utilisateur:motdepasse-d-essai" } });
    expect(r.code, r.stderr).to.equal(0);
    expect(r.stdout).to.include("conforme (AN-54)");
    expect(r.stdout).to.include("non qualifie");
    expect(r.stdout).to.not.include("motdepasse");
    const fiche = lireJson(sortie);
    expect(fiche).to.not.have.property("auth");
    expect(JSON.stringify(fiche)).to.not.include("motdepasse");
    expect(fiche.anchor_certificates_sha256).to.deep.equal([N.sha256Hex(new Uint8Array(Buffer.from(AC_TEST_PEM.replace(/-----[A-Z ]+-----|\s/g, ""), "base64")))]);
    const depuisConfiguration = bin(["fiche", "--configuration", exemple, "--id", "tsa-interne", "--json"]);
    expect(depuisConfiguration.code).to.equal(0);
    const j = JSON.parse(depuisConfiguration.stdout);
    expect(j.fiche.id).to.equal("tsa-interne");
    expect(j.verification.conforme).to.equal(true);
    expect(bin(["fiche", "--configuration", exemple, "--id", "absent"]).code).to.equal(1);
    expect(bin(["fiche"]).code).to.equal(2);
  });

  it("acquisitions (EX-5.8, EX-5.13) : résumé par objet, jeton promu désigné, ligne de révocation prise en compte (dernier état d'une tentative), ligne non canonique ou deux promus non révoqués signalés (code 1)", function () {
    const base = { attempt: 1, object: "point", object_name: "point-" + "ab".repeat(32), imprint: "0x" + "ab".repeat(32), provider_role: "interne", qualified: null, outcome: "obtenue", promoted: true, revoked: false, gen_time: "2026-11-05T09:15:03Z", upper_bound: "2026-11-05T09:15:04.000Z", nonce: "0x0000000000000001", files: { token: "rfc3161/a.der" }, checks: { "T-10": "non_execute" } };
    const lignes = [
      { ...base, attempt_id: "jeton_point:ab:1", provider_id: "tsa-interne" },
      { ...base, attempt_id: "jeton_point:ab:1", provider_id: "tsa-interne", revoked: true, checks: { "T-10": "echoue" } },
      { ...base, attempt_id: "jeton_point:ab:2", attempt: 2, provider_id: "qtsa-secours", provider_role: "secours", qualified: { framework: "eidas" }, files: { token: "rfc3161/b.der" }, checks: { "T-10": "reussi" } },
      { ...base, attempt_id: "jeton_point:ab:3", attempt: 3, provider_id: "qtsa-secours", provider_role: "secours", outcome: "echec_transitoire", promoted: false, files: { token: null } },
    ];
    const f = path.join(dir, "acquisitions-resume.ndjson");
    fs.writeFileSync(f, lignes.map((l) => N.jcs(l)).join("\n") + "\n");
    const r = bin(["acquisitions", f, "--json"]);
    expect(r.code, r.stderr).to.equal(0);
    const j = JSON.parse(r.stdout);
    expect(j.conforme).to.equal(true);
    expect(j.objets).to.have.lengthOf(1);
    expect(j.objets[0]).to.include({ tentatives: 3, revoques: 1, doublon: false });
    expect(j.objets[0].promu).to.include({ attempt_id: "jeton_point:ab:2", provider_id: "qtsa-secours", qualified: true, token: "rfc3161/b.der", t10: "reussi" });
    const texte = bin(["acquisitions", f]);
    expect(texte.stdout).to.include("promu : rfc3161/b.der");
    // Deux promus non révoqués : défaut.
    fs.writeFileSync(f, [lignes[0], lignes[2]].map((l) => N.jcs(l)).join("\n") + "\n");
    const double = bin(["acquisitions", f]);
    expect(double.code).to.equal(1);
    expect(double.stdout).to.include("2 jetons promus non révoqués");
    // Ligne non canonique (clés désordonnées) et dernière ligne tronquée.
    fs.writeFileSync(f, JSON.stringify(lignes[0]) + "\n" + N.jcs(lignes[2]));
    const mauvais = bin(["acquisitions", f, "--json"]);
    expect(mauvais.code).to.equal(1);
    const jm = JSON.parse(mauvais.stdout);
    expect(jm.tronquee).to.equal(true);
    expect(jm.illisibles.map((x) => x.raison)).to.include("forme_non_canonique");
    expect(bin(["acquisitions"]).code).to.equal(2);
  });

  it("les commandes réseau ne sont pas jouées ici : fiche --epreuve sur un point d'accès local injoignable rend une épreuve en échec de transport (code 1), sans secret dans la sortie", function () {
    const prestataire = {
      id: "injoignable", role: "interne", url: "http://127.0.0.1:9/", auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: null, accepted_policies: null,
      anchor_certificates: [AC_TEST_PEM], qualified: null, min_interval_ms: 0, request_timeout_ms: 2000, correlation_header: null, source: "essai",
    };
    const f = path.join(dir, "injoignable.json");
    fs.writeFileSync(f, JSON.stringify(prestataire));
    const r = bin(["fiche", "--prestataire", f, "--epreuve", "--json"]);
    expect(r.code).to.equal(1);
    const j = JSON.parse(r.stdout);
    expect(j.fiche.acceptance_test.outcome).to.equal("echec_transitoire");
    expect(j.fiche.acceptance_test.error_code).to.equal("erreur_transport");
    expect(j.verification.conforme).to.equal(true);
  });
});
