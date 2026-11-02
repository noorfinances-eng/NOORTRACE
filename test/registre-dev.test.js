import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { binaireAvecCertificat, verificateurGo } from "../scripts/e2e/reseau-dev.mjs";

// TE-4 de CT-9 (EX-9.2) : le parcours de CT-4 §7 sur le réseau de
// développement noorcore, par scripts/e2e/parcours-registre.mjs (npm run
// e2e:registre) : client fictif inscrit, clé inscrite, racine ancrée, période
// close, blocs, reçus et certificats capturés, parties du registre exportées,
// contrôle 8 de CT-6 rendu par l'implémentation de référence ET par le
// vérificateur Go. Le parcours démarre le réseau s'il ne tourne pas et
// l'arrête ensuite.
//
// Préconditions (EX-3.11 de CT-9) : le binaire <exécution>/bin/noorcore
// (chain/runtime, ou NOORTRACE_RUNTIME_DIR) porte noor_getCommitCertificate,
// et le vérificateur Go est disponible (NOORTRACE_VERIFICATEUR_GO,
// verificateur/dist/noortrace-verifier-linux-amd64, ou go1.27.3 dans le PATH
// pour le construire). Sans elles, le cas est mis en attente et son titre
// nomme la condition manquante ; aucune étape de la CI n'exécute noorcore.

const SCRIPT = path.join(PROJECT_ROOT, "scripts", "e2e", "parcours-registre.mjs");
const BINAIRE = binaireAvecCertificat();
const GO = verificateurGo();

function lancerParcours(sortie) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [SCRIPT, "--sortie", sortie], { cwd: PROJECT_ROOT, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.stderr.on("data", (d) => (stderr += d));
    p.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

describe("TE-4 — parcours du registre sur le réseau de développement noorcore (CT-4 §7 ; contrôle 8 par les deux vérificateurs)", function () {
  it("client fictif inscrit, racine ancrée, période close, six certificats capturés et valides ; contrôle 8 réussi par scripts/verify/dossier.mjs et par le binaire Go", async function () {
    const manque = !BINAIRE.ok ? BINAIRE.condition : !GO.ok ? GO.condition : null;
    if (manque) {
      this.test.title += ` — en attente (EX-3.11 de CT-9) : ${manque}`;
      this.skip();
    }
    this.timeout(20 * 60 * 1000);
    const sortie = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-te4-"));
    fs.rmdirSync(sortie);
    const r = await lancerParcours(sortie);
    let verdict = null;
    try {
      verdict = JSON.parse(r.stdout);
    } catch {
      verdict = null;
    }
    const contexte = `erreur du parcours : ${verdict?.error ?? "aucune"} ; parcours conservé dans ${sortie} ; fin de la sortie d'erreur :\n${r.stderr.slice(-3000)}`;
    expect(verdict, `verdict JSON illisible (code ${r.code}) ; ${contexte}`).to.be.an("object");
    // Les deux vérificateurs, d'abord : c'est l'oracle de TE-4.
    expect(verdict.verifiers.reference?.control_8?.status, `contrôle 8 de l'implémentation de référence ; ${contexte}`).to.equal("reussi");
    expect(verdict.verifiers.go?.control_8?.status, `contrôle 8 du vérificateur Go ; ${contexte}`).to.equal("reussi");
    expect(verdict.verifiers.parity.equal, JSON.stringify(verdict.verifiers.parity.differences)).to.equal(true);
    expect(r.code, `code de sortie du parcours ; ${verdict.error ?? ""} ; ${contexte}`).to.equal(0);
    expect(verdict.result).to.equal("reussi");
    for (const e of verdict.steps) expect(e.exit_code, `${e.number} ${e.name} : ${e.error ?? ""}`).to.equal(0);
    // Six transactions (jeu, assignation, approvisionnement, inscription, ancre, clôture), toutes incluses.
    expect(verdict.transactions.map((t) => t.step)).to.deep.equal(["jeu_approbateurs", "assignation", "approvisionnement", "inscription", "premiere_ancre", "premiere_cloture"]);
    for (const t of verdict.transactions) expect(t.status, t.step).to.equal("0x1");
    // Chaque bloc de ces transactions a son certificat capturé, vérifié par certificat-commit.mjs (EX-7.15).
    for (const h of verdict.blocks) expect(verdict.certificates.find((c) => c.height === h)?.exit_code, `certificat du bloc ${h}`).to.equal(0);
    // R-1 à R-10 réussis pour les deux vérificateurs, et pour verifier de l'outil de référence.
    for (const v of [verdict.verifiers.reference, verdict.verifiers.go]) {
      for (const id of ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"]) expect(v.checks.find((c) => c.id === id)?.status, id).to.equal("reussi");
    }
    expect(verdict.verifiers.tool_verifier.status).to.equal("reussi");
    // Parties et ancres conformes à leurs schémas.
    for (const [nom, etat] of Object.entries(verdict.dossier.schemas)) expect(etat, nom).to.equal("conforme");
    // Ce que le parcours a démarré, il l'a arrêté.
    if (verdict.network.started_by_run) expect(verdict.network.stopped).to.equal(true);
    fs.rmSync(sortie, { recursive: true, force: true });
  });

  it("TM-31 : un bloc de 64 transactions d'ancre, capture d'une transaction mesurée trois fois ; rapport conforme à plan-de-tests-v0#/$defs/rapport_mesure, ligne b_cap_bloc_plein aux trois échantillons égaux", async function () {
    const manque = !BINAIRE.ok ? BINAIRE.condition : null;
    if (manque) {
      this.test.title += ` — en attente (EX-3.11 de CT-9) : ${manque}`;
      this.skip();
    }
    this.timeout(30 * 60 * 1000);
    const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-tm31-"));
    const rapport = path.join(dossier, "rapport.json");
    const r = await new Promise((resolve) => {
      const p = spawn(process.execPath, [path.join(PROJECT_ROOT, "scripts", "e2e", "mesure-capture-bloc-plein.mjs"), "--sortie", path.join(dossier, "mesure"), "--rapport", rapport], { cwd: PROJECT_ROOT, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      p.stderr.on("data", (d) => (stderr += d));
      p.on("close", (code) => resolve({ code, stderr }));
    });
    expect(r.code, r.stderr.slice(-3000)).to.equal(0);
    const R = JSON.parse(fs.readFileSync(rapport, "utf8"));
    const schema = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", "plan-de-tests-v0.schema.json"), "utf8"));
    const { validerSchema } = await import("../scripts/lib/journal.mjs");
    expect(validerSchema(R, schema, { fragment: "#/$defs/rapport_mesure" })).to.deep.equal([]);
    const ligne = R.results.find((l) => l.name === "b_cap_bloc_plein");
    expect(ligne?.test_id).to.equal("TM-31");
    expect(ligne.samples).to.have.length(3);
    for (const x of ligne.samples) expect(x).to.be.a("number").and.to.be.greaterThan(0);
    expect(ligne.max).to.equal(Math.max(...ligne.samples));
    expect(R.counts_for_targets).to.equal(false);
    fs.rmSync(dossier, { recursive: true, force: true });
  });
});
