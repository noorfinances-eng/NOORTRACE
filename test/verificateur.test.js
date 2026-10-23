import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as V from "../scripts/lib/verificateur.mjs";
import { genererCt6, verifierRepertoire } from "../scripts/vecteurs/generer-ct6.mjs";

// LE VÉRIFICATEUR DE RÉFÉRENCE DE CT-6 (spec/CT-6-verificateur.md) :
// scripts/verify/dossier.mjs et scripts/lib/verificateur.mjs, qui réunissent
// les huit contrôles. Les tests rejouent les dossiers de spec/vecteurs/ct-6
// par la ligne de commande (codes de retour, statuts, raisons, avertissements,
// énoncé et borne dans les deux langues), valident chaque rapport JSON contre
// rapport-verification-v0, reconstruisent l'énoncé du dossier complet
// fragment par fragment à partir des attendus des familles (eux-mêmes
// confrontés à openssl, python-opentimestamps et go-ethereum), vérifient la
// compatibilité avec les quarante dossiers de CT-1 (EX-6.14, V-7), les
// entrées inutilisables (code 2), les limites de taille, les options
// --pieces, --second-manifeste, --exiger et --langue, et la génération
// déterministe de spec/vecteurs/ct-6.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT6 = path.join(SPEC, "vecteurs", "ct-6");
const CT1 = path.join(SPEC, "vecteurs", "ct-1");
const DOSSIERS = path.join(CT6, "dossiers");
const ANCRES_TEST = path.join(CT6, "ancres", "ancres-test.json");
const CHAINE = path.join(CT6, "ots", "entetes", "chaine.json");
const COMPLET = path.join(DOSSIERS, "valide-seq-7-complet");
const SCHEMAS = J.registreSchemas(V.FICHIERS_SCHEMAS.map(({ fichier }) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", fichier), "utf8"))));
const lireJSON = (...p) => J.analyserJSONStrict(fs.readFileSync(path.join(...p)));
const tmp = (prefixe) => fs.mkdtempSync(path.join(os.tmpdir(), prefixe));

function lancer(args) {
  const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "verify", "dossier.mjs"), ...args], { encoding: "utf8", cwd: PROJECT_ROOT, maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
/** Rapport JSON validé contre rapport-verification-v0, et concordance code / exit_code. */
function rapportJSON(args) {
  const r = lancer([...args, "--json"]);
  const doc = JSON.parse(r.stdout);
  const erreurs = J.validerSchema(doc, SCHEMAS[V.ID_SCHEMA_RAPPORT], { registre: SCHEMAS });
  expect(erreurs, `${args.join(" ")} : rapport non conforme`).to.deep.equal([]);
  expect(doc.exit_code, args.join(" ")).to.equal(r.code);
  return { ...r, doc };
}
/** Arguments du vérificateur pour un dossier de spec/vecteurs/ct-6/dossiers, d'après son attendu.json. */
function argumentsDossier(nom) {
  const a = lireJSON(DOSSIERS, nom, "attendu.json");
  const args = [path.join(DOSSIERS, nom)];
  if (a.anchors) args.push("--ancres", path.resolve(DOSSIERS, nom, a.anchors));
  if (a.bitcoin_headers) args.push("--entetes-bitcoin", path.resolve(DOSSIERS, nom, a.bitcoin_headers));
  return { a, args };
}

// ---------------------------------------------------------------------------
describe("CT-6 : dossiers complets de spec/vecteurs/ct-6 par la ligne de commande", function () {
  this.timeout(300_000);
  const noms = fs.readdirSync(DOSSIERS).sort();

  it("les dossiers de l'annexe A.7 sont tous présents, chacun avec son attendu.json", function () {
    const attendus = [
      "valide-seq-7-complet", "valide-seq-7-complet-sans-ancres", "valide-seq-7-complet-sans-entetes", "valide-t11-qualification-declaree",
      ...["t1-octet-en-trop", "t2-jeton-autre-manifeste", "t3-message-digest", "t4-ess-autre-certificat", "t5-sha1", "t6-signature", "t7-tsa-expiree", "t8-eku-non-critique", "t9-extension-critique", "t10-tsa-revoquee"].map((x) => `invalide-${x}`),
      ...["o1-octet-en-trop", "o2-preuve-autre-manifeste", "o3-resultat-trop-long", "o4-mauvaise-hauteur", "o5-chaine-sans-travail"].map((x) => `invalide-${x}`),
      "non-execute-o6-profondeur", "non-execute-o7-en-attente", "valide-deux-attestations",
      ...["r1-sans-ancre", "r2-jeu-substitue", "r3-validateurs-declares", "r4-autre-chaine", "r5-quorum", "r6-entete-modifie", "r7-recu-falsifie", "r8-autre-contrat", "r9-cloture-autre-periode", "r10-inscription-cle-inconnue", "n3-cle-enregistreur", "n4-cle-chaine"].map((x) => `invalide-${x}`),
      // Ajoutés par la révision des constats : F3 selon la décision, provenance par clé, jeux multiples,
      // choix de l'autorité, CN illisible, révocation de l'ancre, valeur DEFAULT, URI vide, branche hors
      // profil, point de contrôle hors des en-têtes, P-1 en échec avec les cinq parties.
      "valide-decision-refusee", "valide-decision-expiree", "valide-provenance-mixte", "valide-deux-jeux-validateurs", "valide-t7-deux-autorites", "valide-unite-sans-cn",
      "invalide-t10-unite-epinglee-revoquee", "invalide-t1-default-explicite", "invalide-t1-cn-utf8-invalide", "valide-attente-uri-vide", "valide-o3-branche-hors-profil", "non-execute-o5-point-de-controle-hors-entetes", "invalide-p1-manifeste-membre-en-trop",
    ];
    expect(noms).to.include.members(attendus);
    for (const n of noms) expect(fs.existsSync(path.join(DOSSIERS, n, "attendu.json")), n).to.equal(true);
    // Chaque vérification T-, O-, R-, N-3, N-4 est visée par au moins un dossier invalide.
    const cibles = noms.map((n) => lireJSON(DOSSIERS, n, "attendu.json").target).filter(Boolean);
    for (const id of ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "O-1", "O-2", "O-3", "O-4", "O-5", "R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-3", "N-4"]) expect(cibles, id).to.include(id);
  });

  it("chaque dossier rend le code, les vérifications en échec, les statuts, les non-exécutions, les avertissements, l'énoncé et la borne de son attendu.json (V-1 à V-5)", function () {
    for (const nom of noms) {
      const { a, args } = argumentsDossier(nom);
      const { code, doc } = rapportJSON(args);
      expect(code, nom).to.equal(a.exit_code);
      expect(doc.verdict, nom).to.equal(a.valid ? "valide" : "invalide");
      // La borne posée par la conception (EX-6.12) suit les contrôles non exécutés et leur raison.
      const non = doc.controls.filter((c) => c.status === "non_execute");
      expect(a.bound, nom).to.deep.equal(non.length ? { fr: `verdict borné : ${non.map((c) => `contrôle ${c.number} non exécuté (${c.reason})`).join(", ")}`, en: `bounded verdict: ${non.map((c) => `control ${c.number} not run (${c.reason})`).join(", ")}` } : null);
      expect(doc.failed_checks, nom).to.deep.equal(a.failed_checks);
      expect(Object.fromEntries(doc.controls.map((c) => [String(c.number), c.status])), nom).to.deep.equal(a.control_statuses);
      expect(doc.checks.filter((c) => c.status === "non_execute").map((c) => ({ id: c.id, reason: c.reason })), nom).to.deep.equal(a.not_executed);
      expect(doc.warnings.map((w) => w.id), nom).to.deep.equal(a.warnings);
      expect(doc.statement, nom).to.deep.equal(a.statement);
      expect(doc.bound, nom).to.equal(a.bound === null ? null : a.bound.fr);
      // V-1 : admitted conforme à la table 6.2 ; blocking_unexecuted = non exécutées sans raison admise.
      for (const c of doc.checks) expect(c.admitted, `${nom} ${c.id}`).to.equal(c.status === "non_execute" ? c.reason !== "prerequis_en_echec" : null);
      expect(doc.blocking_unexecuted, nom).to.deep.equal(doc.checks.filter((c) => c.admitted === false).map((c) => c.id));
      // V-6 : un contrôle réussi n'a que des vérifications réussies, hors piece_hors_dossier et vérifications sans effet.
      const sansEffet = new Set(["T-11", "R-3", "R-10", "N-3", "N-4"]);
      for (const c of doc.controls.filter((x) => x.status === "reussi")) {
        for (const id of c.checks) {
          const v = doc.checks.find((x) => x.id === id);
          if (v.status !== "reussi") expect(v.status === "non_execute" && (v.reason === "piece_hors_dossier" || sansEffet.has(id)), `${nom} : ${id} dans le contrôle ${c.number} réussi`).to.equal(true);
        }
      }
      const faits = { 4: "timestamp", 5: "bitcoin", 6: "recorder_keys", 7: "approval", 8: "registry" };
      for (const [n, cle] of Object.entries(faits)) expect(doc.facts[cle] !== null, `${nom} : facts.${cle}`).to.equal(doc.controls[Number(n) - 1].status === "reussi");
    }
  });

  it("en anglais, les statuts, le verdict et l'énoncé sont les mêmes ; la borne est celle de attendu.bound.en (EX-8.3)", function () {
    for (const nom of noms) {
      const { a, args } = argumentsDossier(nom);
      const { doc } = rapportJSON([...args, "--langue", "en"]);
      expect(doc.language).to.equal("en");
      expect(doc.statement, nom).to.deep.equal(a.statement);
      expect(doc.bound, nom).to.equal(a.bound === null ? null : a.bound.en);
      expect(doc.failed_checks, nom).to.deep.equal(a.failed_checks);
    }
  });

  it("rapport lisible du dossier complet, en français et en anglais (section 8.5)", function () {
    const fr = lancer([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(fr.code, fr.stderr).to.equal(0);
    const a = lireJSON(COMPLET, "attendu.json");
    const lignes = fr.stdout.trimEnd().split("\n");
    expect(lignes[0]).to.equal("Vérification hors ligne d'un dossier de preuve NOORTRACE (format v0, CT-1 et CT-6)");
    expect(lignes).to.include("  [réussi]      4  jeton d'horodatage RFC 3161 sur periodHash — selon AC de test CT-6 (unité TSA de test CT-6), au plus tard 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré");
    expect(lignes).to.include("  [réussi]      5  preuve OpenTimestamps et en-têtes Bitcoin — bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)");
    expect(lignes).to.include("  [réussi]      6  signatures de l'enregistreur — rec-test-01 (événement), rec-test-02 (manifeste), clés fournies par le fichier d'ancres");
    expect(lignes).to.include("  [non exécuté] T-11 [4] statut qualifié déclaré par l'ancre");
    expect(lignes).to.include("  AV-O-3 (O-5) réseau regtest : réseau d'essai, sans valeur probante hors des tests");
    expect(lignes).to.include("Résultat      : VALIDE — aucune vérification en échec, aucune vérification non exécutée sans raison admise");
    expect(lignes[lignes.length - 1]).to.equal(`Énoncé        : ${a.statement.fr}`);
    const en = lancer([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE, "--langue", "en", "--detail"]);
    expect(en.code).to.equal(0);
    const le = en.stdout.trimEnd().split("\n");
    expect(le[0]).to.equal("Offline verification of a NOORTRACE evidence dossier (format v0, CT-1 and CT-6)");
    expect(le).to.include("Checks:");
    const { doc } = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(doc.checks).to.have.length(28 + 11 + 7 + 10 + 2);
    expect(le.filter((l) => /^ {2}\[(passed|FAILED|not run)\] +[A-Z]-\d+ /.test(l))).to.have.length(doc.checks.length);
    expect(le).to.include("Result        : VALID — no failed check, no check left unrun without an admitted reason");
    expect(le[le.length - 1]).to.equal(`Statement     : ${a.statement.en}`);
  });

  it("deux exécutions rendent le même rapport JSON, octet pour octet (V-8)", function () {
    const args = [COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE, "--json"];
    const r1 = lancer(args);
    const r2 = lancer(args);
    expect(r1.stdout).to.equal(r2.stdout);
    expect(r1.stdout.length).to.be.greaterThan(10000);
  });
});

// ---------------------------------------------------------------------------
describe("CT-6 : énoncé du dossier complet reconstruit fragment par fragment (EX-6.8, V-5)", function () {
  it("F0 à F8 à partir de evenement.json, du manifeste et des faits des familles rfc3161, ots et registre", function () {
    const ev = lireJSON(COMPLET, "evenement.json");
    const m = lireJSON(COMPLET, "manifeste.json");
    const ph = J.hachageManifeste(m);
    const ts = lireJSON(CT6, "rfc3161", "attendu.json").cases.find((c) => c.token === "jetons/periode-1.der" && c.anchors === "ancres/ancres-test.json" && c.dossier_period_hash === ph).facts;
    const btc = lireJSON(CT6, "ots", "attendu.json").cases.find((c) => c.proof === "preuves/periode-1.ots" && c.headers === "entetes/chaine.json" && c.anchors).facts;
    const reg = lireJSON(CT6, "registre", "attendu.json").jeux_de_parties.find((j) => j.parties === "periode-1" && j.ancres === "ancres-test.json" && j.validateurs_present).facts;
    const instant = (s) => new Date(s * 1000).toISOString().replace(".000Z", "Z");
    const ent = (role) => reg.entries.find((e) => e.role === role);
    const clo = ent("cloture");
    const anc = ent("ancre");
    const insc = reg.entries.find((e) => e.role === "inscription" && e.event.chainKey === anc.event.issuer);
    const cert = reg.certificates[0];
    const n = Math.min(...reg.certificates.map((c) => c.signers.length));
    const fr =
      `L'événement seq ${ev.seq} (hachage ${ev.hash}) du journal ${ev.journal_id} de l'organisation ${ev.org_id}` +
      ` est bien formé, chaîné à ses voisins seq 6 et 8 et inclus dans la période du ${instant(m.period_start)} au ${instant(m.period_end)} close par le manifeste ${ph}` +
      ` ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés fournies par le fichier d'ancres` +
      ` ; l'événement a été approuvé par ${ev.approval.approvers[0]} et ${ev.approval.approvers[1]} (2 signatures, seuil de ${ev.approval.threshold.required} sur ${ev.approval.threshold.size} du jeu déclaré par le dossier)` +
      ` ; selon ${ts.authority} (unité ${ts.tsu_subject_cn}), le manifeste d'empreinte ${ph} existait au plus tard le ${ts.upper_bound} UTC` +
      ` ; le manifeste d'empreinte ${ph} existait avant la création du bloc Bitcoin ${btc.retained_height} (${btc.block_hash}, réseau ${btc.network}), sous ${btc.confirmations} blocs dont le travail se rattache au point de contrôle ${btc.checkpoint.height} du réviseur ; heure inscrite par le mineur : ${btc.block_time} UTC, précision non garantie par le protocole ; borne sous hypothèse : ${btc.median_bound} UTC (réseau d'essai, sans valeur probante)` +
      ` ; sur le registre ${reg.chain_id}, la clôture de cette période (organisation ${m.org_id}, journal ${m.journal_id}) figure au bloc ${clo.block_number} (heure déclarée par le bloc : ${clo.block_time} UTC), émise par le contrat PeriodRegistry ${clo.emitter}, et son ancre ${anc.event.fingerprint} au bloc ${anc.block_number} (heure déclarée ${anc.block_time} UTC), émise par AttestationRegistry ${anc.emitter} pour l'émetteur ${anc.event.issuer}, clé de chaîne inscrite au bloc ${insc.block_number} pour la clé d'enregistreur rec-test-02, que le réviseur tient pour la clé de chaîne de rec-test-02 ; chacun de ces blocs est signé par ${n} des ${cert.set_size} validateurs du jeu ${cert.valset_hash} que le réviseur déclare (${cert.set_source})` +
      ".";
    const en =
      `Event seq ${ev.seq} (hash ${ev.hash}) of journal ${ev.journal_id} of organisation ${ev.org_id}` +
      ` is well-formed, chained to its neighbours seq 6 and 8 and included in the period from ${instant(m.period_start)} to ${instant(m.period_end)} closed by manifest ${ph}` +
      `; the event is signed by recorder key rec-test-01 and the manifest by key rec-test-02, keys given by the anchors file` +
      `; the event was approved by ${ev.approval.approvers[0]} and ${ev.approval.approvers[1]} (2 signatures, threshold ${ev.approval.threshold.required} of ${ev.approval.threshold.size} of the set declared by the dossier)` +
      `; according to ${ts.authority} (unit ${ts.tsu_subject_cn}), the manifest with digest ${ph} existed no later than ${ts.upper_bound} UTC` +
      `; the manifest with digest ${ph} existed before Bitcoin block ${btc.retained_height} (${btc.block_hash}, ${btc.network} network) was created, under ${btc.confirmations} blocks whose work connects to the reviewer's checkpoint ${btc.checkpoint.height}; time written by the miner: ${btc.block_time} UTC, accuracy not guaranteed by the protocol; bound under assumption: ${btc.median_bound} UTC (test network, no evidential value)` +
      `; on registry ${reg.chain_id}, the closing of this period (organisation ${m.org_id}, journal ${m.journal_id}) is in block ${clo.block_number} (time declared by the block: ${clo.block_time} UTC), emitted by contract PeriodRegistry ${clo.emitter}, and its anchor ${anc.event.fingerprint} in block ${anc.block_number} (declared time ${anc.block_time} UTC), emitted by AttestationRegistry ${anc.emitter} for issuer ${anc.event.issuer}, chain key registered in block ${insc.block_number} for recorder key rec-test-02, which the reviewer holds as the chain key of rec-test-02; each of these blocks is signed by ${n} of the ${cert.set_size} validators of set ${cert.valset_hash} declared by the reviewer (${cert.set_source})` +
      ".";
    const a = lireJSON(COMPLET, "attendu.json");
    expect(a.statement.fr).to.equal(fr);
    expect(a.statement.en).to.equal(en);
    // Les faits du rapport sont ceux des familles.
    const { doc } = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(doc.facts.timestamp).to.deep.equal(ts);
    expect(doc.facts.bitcoin).to.deep.equal(btc);
    expect(doc.facts.registry).to.deep.equal(reg);
    expect(doc.facts.recorder_keys).to.deep.equal({ event_key_id: "rec-test-01", manifest_key_id: "rec-test-02", source: "ancres", event_key_source: "ancres", manifest_key_source: "ancres" });
    expect(doc.controls.map((c) => c.anchors_used)).to.deep.equal([[], [], [], ["/tsa_authorities/0", "/revocation/crls/0"], ["/bitcoin"], ["/recorders/0", "/recorders/1"], [], ["/registry", "/registry/validator_sets/0", "/recorders/1"]]);
  });

  it("F7 et la borne : sans ancres, sans en-têtes, preuve en attente ; provenance « registre » des clés", function () {
    const sansAncres = lireJSON(DOSSIERS, "valide-seq-7-complet-sans-ancres", "attendu.json");
    expect(sansAncres.statement.fr).to.match(/, clés déclarées par le dossier ; .* ; ce dossier ne prouve rien sur sa date \(contrôles 4 et 5\) ni sur son inscription au registre \(contrôle 8\)\.$/);
    expect(sansAncres.statement.en).to.match(/; this dossier proves nothing about its date \(controls 4 and 5\) or its registration in the registry \(control 8\)\.$/);
    expect(sansAncres.bound).to.deep.equal({ fr: "verdict borné : contrôle 4 non exécuté (ancre_absente), contrôle 5 non exécuté (ancre_absente), contrôle 8 non exécuté (ancre_absente)", en: "bounded verdict: control 4 not run (ancre_absente), control 5 not run (ancre_absente), control 8 not run (ancre_absente)" });
    const sansEntetes = lireJSON(DOSSIERS, "valide-seq-7-complet-sans-entetes", "attendu.json");
    expect(sansEntetes.statement.fr).to.match(/ ; ce dossier ne prouve rien sur un ancrage dans Bitcoin \(contrôle 5\)\.$/);
    expect(sansEntetes.statement.fr).to.include("existait au plus tard le 2026-11-05T10:00:06Z UTC ; sur le registre");
    expect(sansEntetes.bound.fr).to.equal("verdict borné : contrôle 5 non exécuté (partie_absente)");
    const attente = lireJSON(DOSSIERS, "non-execute-o7-en-attente", "attendu.json");
    expect(attente.bound.fr).to.equal("verdict borné : contrôle 5 non exécuté (partie_absente)");
    const profondeur = lireJSON(DOSSIERS, "non-execute-o6-profondeur", "attendu.json");
    expect(profondeur.bound.fr).to.equal("verdict borné : contrôle 5 non exécuté (ancre_absente)");
    const qualifie = lireJSON(DOSSIERS, "valide-t11-qualification-declaree", "attendu.json");
    expect(qualifie.statement.fr).to.include(" ; horodatage qualifié eIDAS selon le réviseur (déclaration de test, sans valeur) ; le manifeste d'empreinte");
    expect(qualifie.statement.en).to.include("; eIDAS qualified timestamp according to the reviewer (déclaration de test, sans valeur); the manifest with digest");
    expect(qualifie.not_executed).to.deep.equal([{ id: "A-4", reason: "piece_hors_dossier" }]);
    const registre = lireJSON(DOSSIERS, "valide-provenance-registre", "attendu.json");
    expect(registre.statement.fr).to.include("clés inscrites au registre ;");
    expect(registre.statement.fr).to.include("clé de chaîne inscrite au bloc");
    expect(registre.statement.fr).to.not.include("que le réviseur tient pour la clé de chaîne");
    expect(registre.statement.en).to.include("keys registered in the registry;");
    const { doc } = rapportJSON(argumentsDossier("valide-provenance-registre").args);
    expect(doc.checks.map((c) => c.id)).to.not.include.members(["N-3"]);
    expect(doc.checks.map((c) => c.id)).to.not.include("N-4");
    expect(doc.facts.recorder_keys.source).to.equal("registre");
  });

  it("énoncé d'un dossier invalide : I0, I1, I2 (EX-6.9)", function () {
    expect(lireJSON(DOSSIERS, "invalide-t2-jeton-autre-manifeste", "attendu.json").statement).to.deep.equal({
      fr: "Dossier invalide : vérification(s) en échec : T-2 ; le vérificateur n'affirme rien sur cet événement.",
      en: "Invalid dossier: failed check(s): T-2; the verifier asserts nothing about this event.",
    });
    expect(lireJSON(DOSSIERS, "invalide-r6-entete-modifie", "attendu.json").statement).to.deep.equal({
      fr: "Dossier invalide : vérification(s) en échec : R-6 ; vérification(s) non exécutée(s) sans raison admise : R-8, R-9 ; le vérificateur n'affirme rien sur cet événement.",
      en: "Invalid dossier: failed check(s): R-6; check(s) not run without an admitted reason: R-8, R-9; the verifier asserts nothing about this event.",
    });
  });
});

// ---------------------------------------------------------------------------
describe("CT-6 : compatibilité avec les dossiers de CT-1 (EX-6.14, V-7)", function () {
  this.timeout(120_000);
  const racine = path.join(CT1, "dossiers");
  const noms = fs.readdirSync(racine).sort();
  const lireDossier = (rep) => Object.fromEntries(fs.readdirSync(rep).filter((f) => V.FICHIERS_DOSSIER.includes(f)).map((f) => [f, fs.readFileSync(path.join(rep, f))]));
  const ancres = V.controlerAncres(fs.readFileSync(ANCRES_TEST), SCHEMAS);

  it("les quarante dossiers, sans ancres et avec ancres-test.json : même code et mêmes vérifications en échec ; 4, 5, 8 hors_perimetre_version ; N-3 jamais en échec", function () {
    expect(noms).to.have.length(40);
    for (const nom of noms) {
      const a = lireJSON(racine, nom, "attendu.json");
      for (const avec of [null, ancres]) {
        const corps = V.verifierDossierComplet({ fichiers: lireDossier(path.join(racine, nom)), schemas: SCHEMAS, ancres: avec });
        const etiquette = `${nom}${avec ? " (ancres-test.json)" : ""}`;
        expect(corps.exit_code, etiquette).to.equal(a.valide ? 0 : 1);
        expect(corps.failed_checks, etiquette).to.deep.equal(a.controles_en_echec);
        for (const n of [4, 5, 8]) expect([corps.controls[n - 1].status, corps.controls[n - 1].reason], `${etiquette} contrôle ${n}`).to.deep.equal(["non_execute", "hors_perimetre_version"]);
        expect(corps.checks.filter((c) => /^[TOR]-/.test(c.id)), etiquette).to.deep.equal([]);
        expect(corps.checks.find((c) => c.id === "N-4"), etiquette).to.equal(undefined);
        if (!avec) expect(corps.checks.find((c) => c.id === "N-3"), etiquette).to.equal(undefined);
        else expect(corps.checks.find((c) => c.id === "N-3")?.status ?? "absente", etiquette).to.not.equal("echoue");
        expect(corps.checks.filter((c) => c.id !== "N-3").map((c) => c.id), etiquette).to.deep.equal(J.CONTROLES_DOSSIER.map((c) => c.id));
      }
    }
  });

  it("dossier complet et invalide-hash-faux : les exemples des sections 8.5 et 8.6 sont la sortie réelle (chemins abrégés en …/, version de Node exceptée)", function () {
    const md = fs.readFileSync(path.join(SPEC, "CT-6-verificateur.md"), "utf8");
    const abreger = (t) => t.split(PROJECT_ROOT.replace(/\/$/, "") + "/").join("…/");
    const normaliser = (t) => abreger(t).trimEnd().split("\n").map((l) => l.replace(/\(node v[0-9.]+\)$/, "(node)"));
    const relatifs = ["spec/vecteurs/ct-6/dossiers/valide-seq-7-complet", "--ancres", "spec/vecteurs/ct-6/ancres/ancres-test.json", "--entetes-bitcoin", "spec/vecteurs/ct-6/ots/entetes/chaine.json"];
    for (const args of [relatifs, [...relatifs, "--langue", "en"], ["spec/vecteurs/ct-1/dossiers/invalide-hash-faux"]]) {
      const commande = `$ node scripts/verify/dossier.mjs ${args.join(" ")}\n`;
      const bloc = md.split("```text\n" + commande)[1].split("\n$ echo $?\n");
      const r = lancer(args);
      expect(normaliser(r.stdout), commande).to.deep.equal(normaliser(bloc[0]));
      expect(String(r.code), commande).to.equal(bloc[1].split("\n")[0]);
    }
    // 8.6 : le premier exemple JSON est le rapport du dossier complet.
    const exemple = JSON.parse(/<!-- schema: rapport-verification -->\n```json\n([\s\S]*?)\n```/.exec(md)[1]);
    const { doc } = rapportJSON(relatifs);
    const sansRuntime = (d) => ({ ...JSON.parse(abreger(JSON.stringify(d))), verifier: { ...d.verifier, runtime: null } });
    expect(sansRuntime(exemple)).to.deep.equal(sansRuntime(doc));
  });

  it("chaque exemple JSON annoté <!-- schema: … --> de CT-6 est conforme à son schéma", function () {
    const md = fs.readFileSync(path.join(SPEC, "CT-6-verificateur.md"), "utf8");
    const exemples = [...md.matchAll(/<!-- schema: ([a-z-]+) -->\n```json\n([\s\S]*?)\n```/g)];
    expect(exemples.length).to.be.at.least(5);
    for (const [, nom, texte] of exemples) {
      const id = Object.keys(SCHEMAS).find((k) => k.endsWith(`/${nom}.schema.json`));
      expect(id, nom).to.be.a("string");
      expect(J.validerSchema(JSON.parse(texte), SCHEMAS[id], { registre: SCHEMAS }), nom).to.deep.equal([]);
    }
  });

  it("valide-seq-7 : le rapport lisible est celui de l'exemple de la section 8.5, ligne pour ligne (hors environnement et chemin)", function () {
    const md = fs.readFileSync(path.join(SPEC, "CT-6-verificateur.md"), "utf8");
    const bloc = md.split("$ node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7\n")[1].split("\n$ echo $?")[0];
    const r = lancer([path.join(racine, "valide-seq-7")]);
    expect(r.code).to.equal(0);
    const normaliser = (t) => t.trimEnd().split("\n").map((l) => l.replace(/^(Vérificateur {2}: scripts\/verify\/dossier\.mjs 0\.1\.0) \(node v[0-9.]+\)$/, "$1 (node)").replace(/^(Répertoire {4}: ).*$/, "$1…"));
    expect(normaliser(r.stdout)).to.deep.equal(normaliser(bloc));
    const exige = lancer([path.join(racine, "valide-seq-7"), "--exiger", "4,5,8"]);
    expect(exige.code).to.equal(3);
    expect(exige.stdout).to.include("Résultat      : INCOMPLET — contrôle(s) exigé(s) non réussi(s) : 4, 5, 8");
    expect(exige.stdout.split("\n").find((l) => l.startsWith("Énoncé"))).to.equal(r.stdout.split("\n").find((l) => l.startsWith("Énoncé")));
  });

  it("contrôle 7 non exécuté (partie_absente) pour un événement sans approbation ; --exiger tous sur le dossier complet : code 0", function () {
    // Dossier CT-1 de l'événement seq 3 du journal de référence (documents.search, sans approbation), assemblé par journal.mjs.
    const evs = lireJSON(CT1, "journal-valide", "evenements.json");
    const m = lireJSON(CT1, "manifestes", "periode-1.json");
    const { fichiers } = J.assemblerDossier({ evenement: evs[2], previous: evs[1], next: evs[3], hashesPeriode: evs.filter((e) => e.seq >= m.first_seq && e.seq <= m.last_seq).map((e) => e.hash), manifeste: m, manifesteSig: lireJSON(CT1, "manifestes", "periode-1.sig"), cles: lireJSON(CT1, "journal-valide", "cles.json"), generated_at: "2026-11-06T08:30:00.000Z" });
    const rep = tmp("noortrace-ct6-sans-approbation-");
    for (const [f, contenu] of Object.entries(fichiers)) fs.writeFileSync(path.join(rep, f), contenu);
    const { code, doc } = rapportJSON([rep]);
    expect(code).to.equal(0);
    expect([doc.controls[6].status, doc.controls[6].reason, doc.controls[6].summary]).to.deep.equal(["non_execute", "partie_absente", "approbations.json absent (aucune approbation liée)"]);
    expect(doc.checks.filter((c) => ["A-2", "A-3", "A-4"].includes(c.id)).map((c) => c.reason)).to.deep.equal(["partie_absente", "partie_absente", "partie_absente"]);
    expect(doc.statement.fr).to.equal(
      `L'événement seq 3 (hachage ${evs[2].hash}) du journal ${evs[2].journal_id} de l'organisation ${evs[2].org_id} est bien formé, chaîné à ses voisins seq 2 et 4 et inclus dans la période du 2026-11-05T09:00:00Z au 2026-11-05T10:00:00Z close par le manifeste ${J.hachageManifeste(m)} ; l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clés déclarées par le dossier ; ce dossier ne prouve rien sur sa date (contrôles 4 et 5), sur une approbation (contrôle 7) ni sur son inscription au registre (contrôle 8).`,
    );
    expect(doc.statement.en).to.match(/; this dossier proves nothing about its date \(controls 4 and 5\), an approval \(control 7\) or its registration in the registry \(control 8\)\.$/);
    expect(doc.bound).to.equal("verdict borné : contrôle 4 non exécuté (hors_perimetre_version), contrôle 5 non exécuté (hors_perimetre_version), contrôle 7 non exécuté (partie_absente), contrôle 8 non exécuté (hors_perimetre_version)");
    expect(doc.facts.approval).to.equal(null);
    fs.rmSync(rep, { recursive: true, force: true });
    const tous = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE, "--exiger", "tous"]);
    expect(tous.code).to.equal(0);
    expect(tous.doc.inputs.required_controls).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
    const sansEntetes = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--exiger", "5"]);
    expect([sansEntetes.code, sansEntetes.doc.verdict]).to.deep.equal([3, "incomplet"]);
  });
});

// ---------------------------------------------------------------------------
describe("CT-6 : entrées inutilisables (code 2) et limites", function () {
  this.timeout(120_000);

  it("usage, dossier, fichier d'ancres, fichier d'en-têtes, second manifeste : code 2, type et vérification N- nommés", function () {
    const rep = tmp("noortrace-ct6-entrees-");
    const ecrire = (nom, contenu) => {
      const f = path.join(rep, nom);
      fs.writeFileSync(f, contenu);
      return f;
    };
    const ancres = lireJSON(ANCRES_TEST);
    const recouvrement = { ...ancres, registry: { ...ancres.registry, validator_sets: [ancres.registry.validator_sets[0], { ...ancres.registry.validator_sets[0], from_height: 5 }] } };
    const doublon = { ...ancres, recorders: [ancres.recorders[0], ancres.recorders[0]] };
    const pemCasse = { ...ancres, tsa_authorities: [{ ...ancres.tsa_authorities[0], certificate: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n" }] };
    const cas = [
      [[COMPLET, "--inconnue"], "usage", null],
      [[COMPLET, "--langue", "de"], "usage", null],
      [[COMPLET, "--exiger", "0"], "usage", null],
      [[COMPLET, "--ancres", ANCRES_TEST, "--ancres", ANCRES_TEST], "usage", null],
      [[COMPLET, COMPLET], "usage", null],
      [[path.join(rep, "absent")], "dossier_illisible", null],
      [[rep], "dossier_illisible", null],
      [[COMPLET, "--ancres", path.join(rep, "nulle-part.json")], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--ancres", ecrire("pas-json.json", "{ ")], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--ancres", CHAINE], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--ancres", ecrire("recouvrement.json", JSON.stringify(recouvrement))], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--ancres", ecrire("doublon.json", JSON.stringify(doublon))], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--ancres", ecrire("pem.json", JSON.stringify(pemCasse))], "ancres_inutilisables", "N-1"],
      [[COMPLET, "--entetes-bitcoin", ANCRES_TEST], "entree_illisible", "N-2"],
      [[COMPLET, "--entetes-bitcoin", ecrire("trop-entetes.json", JSON.stringify({ version: 0, network: "regtest", start_height: 0, source: "x", headers: Array(200001).fill("0x") }))], "taille_depassee", "N-2"],
      [[COMPLET, "--second-manifeste", ANCRES_TEST], "entree_illisible", null],
      [[COMPLET, "--pieces", ANCRES_TEST], "entree_illisible", null],
      [[COMPLET, "--schemas", path.join(rep, "nulle-part")], "schemas_illisibles", null],
    ];
    for (const [args, kind, check] of cas) {
      const r = lancer([...args, "--json"]);
      expect(r.code, args.join(" ")).to.equal(2);
      const doc = JSON.parse(r.stdout);
      expect(J.validerSchema(doc, SCHEMAS[V.ID_SCHEMA_RAPPORT], { registre: SCHEMAS }), args.join(" ")).to.deep.equal([]);
      expect([doc.verdict, doc.error.kind, doc.error.check], args.join(" ")).to.deep.equal([null, kind, check]);
      expect(r.stderr, args.join(" ")).to.match(/^Erreur : /);
      expect(lancer(args).stdout, `${args.join(" ")} : rien sur la sortie standard sans --json`).to.equal("");
    }
    const anglais = lancer([path.join(rep, "absent"), "--langue", "en"]);
    expect([anglais.code, anglais.stderr]).to.deep.equal([2, `Error: unreadable directory (${path.join(rep, "absent")}): ENOENT: no such file or directory, scandir '${path.join(rep, "absent")}'\n`]);
    expect(lancer(["--aide"]).code).to.equal(0);
    expect(lancer(["--help", "--langue", "en"]).stdout).to.match(/^Usage:/);
    const version = lancer(["--version"]);
    expect(version.code).to.equal(0);
    expect(version.stdout).to.match(/^scripts\/verify\/dossier\.mjs 0\.1\.0 \(node v/);
    expect(version.stdout).to.include("https://noortrace.example/schemas/v0/rapport-verification.schema.json SHA-256 0x");
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("une partie au-delà de sa limite ou trop imbriquée est inexploitable : sa vérification échoue, sans lecture au-delà (EX-4.11, EX-4.13)", function () {
    const rep = tmp("noortrace-ct6-limites-");
    for (const f of fs.readdirSync(COMPLET)) if (f !== "attendu.json") fs.copyFileSync(path.join(COMPLET, f), path.join(rep, f));
    fs.writeFileSync(path.join(rep, "jeton-rfc3161.der"), Buffer.alloc(V.LIMITES.jeton + 1));
    fs.writeFileSync(path.join(rep, "preuve.ots"), Buffer.alloc(V.LIMITES.ots + 1));
    fs.writeFileSync(path.join(rep, "voisins.json"), "[".repeat(200) + "]".repeat(200));
    const { code, doc } = rapportJSON([rep, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(code).to.equal(1);
    expect(doc.failed_checks).to.deep.equal(["D-2", "C-1", "T-1", "O-1"]);
    expect(doc.checks.find((c) => c.id === "T-1").detail).to.equal(`jeton-rfc3161.der : fichier de ${V.LIMITES.jeton + 1} octets, au-delà de la limite de ${V.LIMITES.jeton} octets ; la partie est inexploitable`);
    expect(doc.checks.find((c) => c.id === "C-1").detail).to.match(/imbrication JSON de plus de 128 niveaux/);
    expect(doc.checks.filter((c) => /^T-/.test(c.id) && c.id !== "T-1").every((c) => c.reason === "prerequis_en_echec")).to.equal(true);
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("une partie déclarée présente mais absente du répertoire : D-2 et la première vérification de son contrôle échouent", function () {
    const rep = tmp("noortrace-ct6-manquante-");
    for (const f of fs.readdirSync(COMPLET)) if (!["attendu.json", "preuve.ots"].includes(f)) fs.copyFileSync(path.join(COMPLET, f), path.join(rep, f));
    const { code, doc } = rapportJSON([rep, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(code).to.equal(1);
    expect(doc.failed_checks).to.deep.equal(["D-2", "O-1"]);
    expect(doc.checks.find((c) => c.id === "O-1").detail).to.equal("preuve.ots déclaré présent mais absent du répertoire");
    fs.rmSync(rep, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
describe("CT-6 : pièces fournies à part et second manifeste (EX-4.6, EX-4.7)", function () {
  this.timeout(60_000);

  it("--pieces : E-6 vérifie sha256 et length des pièces nommées par leur sha256 ; une pièce altérée fait échouer E-6", function () {
    const dossier = path.join(SPEC, "vecteurs", "ct-2", "evenements", "journal-demo", "dossier-seq-7");
    const pieces = lireJSON(SPEC, "vecteurs", "ct-2", "evenements", "journal-demo", "pieces.json");
    const rep = tmp("noortrace-ct6-pieces-");
    for (const p of pieces) fs.writeFileSync(path.join(rep, p.sha256.slice(2)), Buffer.from(p.bytes, "utf8"));
    const ok = rapportJSON([dossier, "--pieces", rep]);
    expect(ok.code).to.equal(0);
    expect(ok.doc.inputs.pieces).to.deep.equal({ path: rep, files: 7 });
    expect(ok.doc.checks.find((c) => c.id === "E-6").detail).to.equal("7 pièce(s) fournie(s) à part vérifiée(s)");
    const cible = J.analyserJSONStrict(fs.readFileSync(path.join(dossier, "evenement.json"))).execution.result.sha256.slice(2);
    fs.appendFileSync(path.join(rep, cible), "x");
    const ko = rapportJSON([dossier, "--pieces", rep]);
    expect(ko.code).to.equal(1);
    expect(ko.doc.failed_checks).to.deep.equal(["E-6"]);
    expect(ko.doc.checks.find((c) => c.id === "E-6").detail).to.match(new RegExp(`^evenement : execution\\.result : pièce ${cible} : sha256 de la pièce fournie différent du sha256 déclaré`));
    fs.rmSync(rep, { recursive: true, force: true });
  });

  it("--second-manifeste : la période suivante se chaîne (P-5 réussie) ; une période non contiguë fait échouer P-5", function () {
    const dossier = path.join(CT1, "dossiers", "valide-seq-7");
    const suivant = rapportJSON([dossier, "--second-manifeste", path.join(CT1, "manifestes", "periode-2.json")]);
    expect(suivant.code).to.equal(0);
    expect(suivant.doc.checks.find((c) => c.id === "P-5").detail).to.equal("periodHash 0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914 signé par rec-test-02 ; continuité avec le manifeste suivant (periodHash 0xe867be7f64b77e49a9c3066d33aa39cffc5b5a588edec54f99cb2d07ff33bf19) vérifiée");
    expect(suivant.doc.inputs.second_manifest.path).to.equal(path.join(CT1, "manifestes", "periode-2.json"));
    const discontinu = rapportJSON([dossier, "--second-manifeste", path.join(CT1, "manifestes", "periode-3.json")]);
    expect(discontinu.code).to.equal(1);
    expect(discontinu.doc.failed_checks).to.deep.equal(["P-5"]);
    const meme = rapportJSON([dossier, "--second-manifeste", path.join(CT1, "manifestes", "periode-1.json")]);
    expect(meme.doc.failed_checks).to.deep.equal(["P-5"]);
    expect(meme.doc.checks.find((c) => c.id === "P-5").detail).to.include("ni précédent ni suivant");
  });
});

// ---------------------------------------------------------------------------
describe("CT-6 : génération déterministe de spec/vecteurs/ct-6", function () {
  this.timeout(300_000);

  it("rejouer scripts/vecteurs/generer-ct6.mjs dans un répertoire vide redonne les mêmes octets que le dépôt (entrées exceptées)", function () {
    const sortie = tmp("noortrace-vecteurs-ct6-");
    const r = genererCt6({ racine: sortie });
    expect(r.dossiers.length).to.be.at.least(34);
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
    // Entrées que le générateur lit et ne réécrit jamais (EX-A.1) : la capture et confrontation/.
    const entree = (f) => f.startsWith("registre/capture/") || f.startsWith("confrontation/");
    const produits = lister(sortie);
    expect(produits).to.deep.equal(lister(CT6).filter((f) => !entree(f)));
    for (const f of produits) expect(J.sha256(fs.readFileSync(path.join(sortie, f))), f).to.equal(J.sha256(fs.readFileSync(path.join(CT6, f))));
    fs.rmSync(sortie, { recursive: true, force: true });
  });

  it("le générateur n'efface que ses propres entrées : racine étrangère refusée sans rien effacer, --sortie sans répertoire refusée (code 2)", function () {
    const etrangere = tmp("noortrace-vecteurs-ct6-etrangere-");
    fs.writeFileSync(path.join(etrangere, "precieux.txt"), "à garder\n");
    expect(() => genererCt6({ racine: etrangere })).to.throw(/entrées que le générateur n'écrit pas \(precieux\.txt\)/);
    expect(fs.readdirSync(etrangere)).to.deep.equal(["precieux.txt"]);
    fs.rmSync(etrangere, { recursive: true, force: true });
    const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "vecteurs", "generer-ct6.mjs"), "--sortie"], { encoding: "utf8" });
    expect([r.status, r.stderr]).to.deep.equal([2, "generer-ct6 : --sortie attend un répertoire\n"]);
  });

  it("le vérificateur en mémoire (verifierRepertoire) et la ligne de commande donnent le même corps de rapport", function () {
    const corps = verifierRepertoire(COMPLET, { ancres: ANCRES_TEST, entetes: CHAINE });
    const { doc } = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    for (const cle of ["event", "org_id", "journal_id", "period", "controls", "checks", "failed_checks", "blocking_unexecuted", "absent_parts", "warnings", "facts", "verdict", "exit_code", "statement", "bound"]) expect(doc[cle], cle).to.deep.equal(corps[cle]);
  });
});

// ---------------------------------------------------------------------------
// Corrections de la revue de CT-6 : chaque règle corrigée a son test.
describe("CT-6 : règles précisées par la revue", function () {
  this.timeout(300_000);

  it("F3 selon approval.decision : refus signé, demande expirée sans signature ; facts.approval.decision (EX-6.8, EX-6.11)", function () {
    const refus = rapportJSON(argumentsDossier("valide-decision-refusee").args);
    expect(refus.code).to.equal(0);
    expect(refus.doc.statement.fr).to.include(" ; l'événement porte un refus signé par 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 et 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, seuil de 2 sur 3 du jeu déclaré par le dossier) ; ");
    expect(refus.doc.statement.en).to.include("; the event carries a refusal signed by 0x70997970c51812dc3a010c7d01b50e0d17dc79c8 and 0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc (2 signatures, threshold 2 of 3 of the set declared by the dossier); ");
    expect(refus.doc.statement.fr).to.not.include("approuvé");
    expect(refus.doc.facts.approval.decision).to.equal("refuse");
    expect(refus.doc.controls[6].summary).to.equal("apr-2201 (refus) : 2 signatures, seuil 2 sur 3");
    const expire = rapportJSON(argumentsDossier("valide-decision-expiree").args);
    expect(expire.code).to.equal(0);
    expect(expire.doc.statement.fr).to.include(" ; l'événement porte une demande d'approbation expirée sans signature (seuil de 2 sur 3 du jeu déclaré par le dossier) ; ");
    expect(expire.doc.statement.en).to.include("; the event carries an approval request that expired without signature (threshold 2 of 3 of the set declared by the dossier); ");
    expect(expire.doc.facts.approval).to.deep.equal({ decision: "expire", ticket: "apr-2201", approvers: [], required: 2, size: 3, set_source: "dossier" });
    expect(expire.doc.controls[6].summary).to.equal("apr-2201 (demande expirée) : aucune signature, seuil 2 sur 3");
    const complet = rapportJSON([COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]);
    expect(complet.doc.facts.approval.decision).to.equal("approuve");
  });

  it("provenance clé par clé : rec-test-01 confirmée par N-3 seulement, rec-test-02 par R-10 seulement (EX-6.8)", function () {
    const { doc } = rapportJSON(argumentsDossier("valide-provenance-mixte").args);
    expect(doc.facts.recorder_keys).to.deep.equal({ event_key_id: "rec-test-01", manifest_key_id: "rec-test-02", source: "mixte", event_key_source: "ancres", manifest_key_source: "registre" });
    expect(doc.statement.fr).to.include("l'événement est signé par la clé d'enregistreur rec-test-01 et le manifeste par la clé rec-test-02, clé rec-test-01 fournie par le fichier d'ancres, clé rec-test-02 inscrite au registre ; ");
    expect(doc.statement.en).to.include("; the event is signed by recorder key rec-test-01 and the manifest by key rec-test-02, key rec-test-01 given by the anchors file, key rec-test-02 registered in the registry; ");
    expect(doc.statement.fr).to.not.include("clés inscrites au registre");
    expect(doc.controls[5].summary).to.equal("rec-test-01 (événement, fournie par le fichier d'ancres), rec-test-02 (manifeste, inscrite au registre)");
    expect(doc.checks.map((c) => c.id)).to.include("N-3");
    expect(doc.checks.map((c) => c.id)).to.not.include("N-4");
  });

  it("P-1 en échec avec les cinq parties : seules T-2, O-2, R-9 et R-10 sont non exécutées sans raison admise (EX-5.4) ; contrôle 5 non réussi sans O-2 (EX-10.12)", function () {
    const { code, doc } = rapportJSON(argumentsDossier("invalide-p1-manifeste-membre-en-trop").args);
    expect(code).to.equal(1);
    expect(doc.failed_checks).to.deep.equal(["P-1", "P-5"]);
    expect(doc.blocking_unexecuted).to.deep.equal(["T-2", "O-2", "R-9", "R-10"]);
    expect([doc.controls[4].status, doc.controls[4].reason]).to.deep.equal(["non_execute", "prerequis_en_echec"]);
    expect(doc.facts.bitcoin).to.equal(null);
    expect(doc.checks.filter((c) => /^[OR]-/.test(c.id) && !["O-2", "R-9", "R-10"].includes(c.id)).every((c) => c.status === "reussi" || (c.id === "R-3" && c.status === "reussi"))).to.equal(true);
  });

  it("ordre des avertissements : vérification qui les lève dans l'ordre du rapport, puis identifiant, puis émission (EX-6.15)", function () {
    const liste = [{ id: "T-1" }, { id: "T-9" }, { id: "O-4" }, { id: "O-5" }, { id: "O-7" }, { id: "R-5" }, { id: "R-10" }];
    const a = [{ id: "AV-R-1", check: "R-10" }, { id: "AV-O-3", check: "O-5" }, { id: "AV-O-2", check: "O-7", n: 1 }, { id: "AV-O-1", check: "O-4" }, { id: "AV-O-2", check: "O-7", n: 2 }, { id: "AV-T-4", check: "T-9" }, { id: "AV-T-2", check: "T-9" }];
    expect(V.ordonnerAvertissements(a, liste).map((w) => `${w.id}${w.n ?? ""}`)).to.deep.equal(["AV-T-2", "AV-T-4", "AV-O-1", "AV-O-3", "AV-O-21", "AV-O-22", "AV-R-1"]);
    expect(lireJSON(DOSSIERS, "valide-deux-attestations", "attendu.json").warnings).to.deep.equal(["AV-O-1", "AV-O-3"]);
  });

  it("--version et --aide exclusives : avec un répertoire ou une autre option, code 2 (usage), en JSON avec --json (EX-8.2)", function () {
    expect(lancer(["--version"]).code).to.equal(0);
    expect(lancer(["--aide", "--langue", "en"]).code).to.equal(0);
    const r = lancer(["--version", "--json"]);
    expect(r.code).to.equal(2);
    const doc = JSON.parse(r.stdout);
    expect([doc.exit_code, doc.error.kind]).to.deep.equal([2, "usage"]);
    expect(J.validerSchema(doc, SCHEMAS[V.ID_SCHEMA_RAPPORT], { registre: SCHEMAS })).to.deep.equal([]);
    expect(lancer([COMPLET, "--version"]).code).to.equal(2);
    expect(lancer(["--aide", "--version"]).code).to.equal(2);
    expect(lancer(["--help", "--detail"]).code).to.equal(2);
  });

  it("verifier.schemas : les huit schémas embarqués, dans l'ordre fixé, quelles que soient les options (section 8.6)", function () {
    const ordre = ["evenement", "manifeste", "dossier", "registre", "validateurs", "ancres-confiance", "entetes-bitcoin", "rapport-verification"].map((n) => `https://noortrace.example/schemas/v0/${n}.schema.json`);
    for (const args of [[COMPLET], [COMPLET, "--ancres", ANCRES_TEST, "--entetes-bitcoin", CHAINE]]) expect(rapportJSON(args).doc.verifier.schemas.map((s) => s.id)).to.deep.equal(ordre);
  });

  it("période aux bornes extrêmes admises par le schéma : même code en lecture et en JSON, aucune RangeError (EX-8.4, EX-15.2)", function () {
    const rep = tmp("noortrace-ct6-periode-extreme-");
    try {
      for (const f of fs.readdirSync(COMPLET)) if (V.FICHIERS_DOSSIER.includes(f)) fs.copyFileSync(path.join(COMPLET, f), path.join(rep, f));
      const m = lireJSON(rep, "manifeste.json");
      fs.writeFileSync(path.join(rep, "manifeste.json"), JSON.stringify({ ...m, period_start: 9007199254735200, period_end: 9007199254738800 }, null, 2) + "\n");
      const fichiers = Object.fromEntries(fs.readdirSync(rep).map((f) => [f, fs.readFileSync(path.join(rep, f))]));
      for (const [f, contenu] of Object.entries(J.reindexerDossier(fichiers).fichiers)) fs.writeFileSync(path.join(rep, f), contenu);
      const json = rapportJSON([rep]);
      const lisible = lancer([rep]);
      const anglais = lancer([rep, "--langue", "en"]);
      expect([json.code, lisible.code, anglais.code], lisible.stderr).to.deep.equal([1, 1, 1]);
      expect(lisible.stdout).to.match(/^Période {7}: 285428751-11-12T06:00:00Z à 285428751-11-12T07:00:00Z, periodHash 0x[0-9a-f]{64}$/m);
    } finally {
      fs.rmSync(rep, { recursive: true, force: true });
    }
  });

  it("compatibilité CT-1 : un fichier d'ancres qui donne une autre clé pour l'organisation et le journal fait échouer N-3 (EX-6.14)", function () {
    const r = rapportJSON([path.join(CT1, "dossiers", "valide-seq-7"), "--ancres", path.join(CT6, "ancres", "ancres-cle-enregistreur-autre.json")]);
    expect([r.code, r.doc.failed_checks]).to.deep.equal([1, ["N-3"]]);
  });
});
