// TI-13 de CT-9 : SDK Python et TypeScript, interface publique (CT-2 6.5),
// versions de langage (6.4 : Python 3.10 et 3.13, Node.js 22), issues de
// politique rendues sans exception (EX-6.4, table d'EX-6.7), panne de
// l'enregistreur (EX-6.12, EX-6.15) et comportement identique dans les deux
// langages.
//
// Le même scénario (test/fixtures/enregistreur-sdk-langages/scenario.mjs et
// scenario.py : chaque fonction de l'interface publique, puis le démon arrêté
// après l'ouverture d'une session, puis un démon muet au-delà de `delai_s`)
// est joué par le SDK JavaScript (Node.js 22) et par le SDK Python sous 3.10
// et 3.13 (environnements `essais-py310` et `essais-py313` de
// paquets/sdk-python/.environnements, créés par `uv` depuis les verrous
// versionnés), contre le démon réel du banc du SDK Python
// (test/fixtures/enregistreur-sdk-python/banc.mjs : point d'entrée SDK sur
// prise Unix, alias `agent-py`, service d'approbation simulé qui rend
// `a_approuver` pour un outil `*approuver*`, `refuse` pour `*refuser*`). Les
// sorties normalisées des trois exécutions sont égales ; les événements de
// chaque exécution (une par `run_id`) portent les mêmes pièces ; le dossier
// d'un événement de chaque langage est vérifié par le banc (noyau et, si
// go1.27.3 est présent, binaire Go). Un environnement Python absent met son
// exécution en attente et le titre nomme la condition manquante.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";
import { lancerBanc } from "./fixtures/enregistreur-sdk-python/pilote.mjs";
import { interface_, arrete, muet } from "./fixtures/enregistreur-sdk-langages/scenario.mjs";

const SCENARIO_PY = path.join(RACINE, "test", "fixtures", "enregistreur-sdk-langages", "scenario.py");
const ENVS = path.join(RACINE, "paquets", "sdk-python", ".environnements");
const interpreteur = (env) => {
  const p = path.join(ENVS, env, "bin", "python");
  return fs.existsSync(p) ? p : null;
};

/** Lance une phase du scénario Python ; `surLigne(l)` reçoit chaque ligne (et peut écrire sur l'entrée). */
function phasePython(python, phase, prise, runId, surLigne = async () => {}) {
  return new Promise((resoudre, rejeter) => {
    const p = spawn(python, ["-I", SCENARIO_PY, phase, prise, runId], { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" } });
    const sorties = [];
    let erreur = "";
    p.stderr.on("data", (d) => (erreur += d));
    const lignes = readline.createInterface({ input: p.stdout });
    let chaine = Promise.resolve();
    lignes.on("line", (l) => {
      const o = JSON.parse(l);
      chaine = chaine.then(async () => {
        if (o.etape === "pret-a-couper") {
          await surLigne(o);
          p.stdin.write("\n");
        } else sorties.push(o);
      });
    });
    p.on("error", rejeter);
    p.on("exit", async (code) => {
      await chaine;
      if (code !== 0) rejeter(new Error(`scénario Python ${phase} : code ${code}\n${erreur}`));
      else resoudre(sorties);
    });
  });
}

/** Événements d'un run_id : ce que les deux langages doivent produire à l'identique. */
const projection = (evts, runId) =>
  evts
    .filter((e) => e.delegation.run_id === runId && !e.execution.tool.startsWith("noortrace.journal"))
    .map((e) => ({
      tool: e.execution.tool,
      status: e.execution.status,
      is_error: e.execution.is_error,
      decision: e.policy.decision,
      ticket: e.policy.ticket !== null,
      arguments: e.execution.arguments?.sha256 ?? null,
      result: e.execution.result?.sha256 ?? null,
      context: e.context.map((c) => c.sha256),
      launched_by: e.delegation.launched_by,
    }));

describe("TI-13 — SDK Python et TypeScript : interface publique de CT-2 6.5, Python 3.10 et 3.13 et Node.js 22, issues de politique sans exception, panne de l'enregistreur, comportement identique dans les deux langages", function () {
  this.timeout(600000);
  let dir;
  let prisemuette;
  let serveurMuet;
  const prisesMuettes = new Set();
  const resultats = {};

  before(async function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ti13-"));
    // Démon muet : il fait la preuve d'identité de la prise Unix (EX-6.10, défi neuf par connexion), puis ne répond à aucune requête.
    prisemuette = path.join(dir, "muet.sock");
    serveurMuet = net.createServer((c) => {
      prisesMuettes.add(c);
      c.on("close", () => prisesMuettes.delete(c));
      c.write(`${JSON.stringify({ noortrace_defi: randomBytes(16).toString("hex") })}\n`);
      let tampon = "";
      c.on("data", (d) => {
        tampon += d;
        if (tampon.includes("noortrace_preuve") && !c.accepte) {
          c.accepte = true;
          c.write(`${JSON.stringify({ noortrace_identite: "acceptee" })}\n`);
        }
      });
    });
    await new Promise((r) => serveurMuet.listen(prisemuette, r));
  });

  after(function () {
    for (const c of prisesMuettes) c.destroy();
    serveurMuet?.close();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  /**
   * Joue les trois phases d'un langage sur un banc neuf (démon réel et
   * service d'approbation simulé dans le même état initial pour chaque
   * langage), puis vérifie le dossier d'un événement de l'exécution.
   */
  async function jouer(langage, python) {
    const banc = await lancerBanc();
    try {
      const prise = banc.info.socket;
      const runId = "run-ti13";
      const couper = async () => {
        await banc.commande({ cmd: "arreter" });
      };
      let sorties;
      try {
        if (python) sorties = [...(await phasePython(python, "interface", prise, runId)), ...(await phasePython(python, "arrete", prise, `${runId}-arret`, couper))];
        else sorties = [...(await interface_(prise, runId)), ...(await arrete(prise, `${runId}-arret`, couper))];
      } finally {
        await banc.commande({ cmd: "demarrer" });
      }
      sorties.push(...(python ? await phasePython(python, "muet", prisemuette, runId) : await muet(prisemuette, runId)));
      const evts = await banc.evenements();
      const seq = evts.find((e) => e.delegation.run_id === runId && e.execution.tool === "agent-py__lire_fiche").seq;
      const verification = await banc.commande({ cmd: "verifier", seq, dossier: path.join(dir, `dossier-${langage}`) });
      resultats[langage] = { sorties, evenements: projection(evts, runId), verification };
      return resultats[langage];
    } finally {
      await banc.fermer();
    }
  }

  /** Journal accepté par le noyau, dossier valide pour le noyau et, si go1.27.3 est présent, pour le binaire Go ; rend vrai sans binaire Go. */
  function verifie(r) {
    const v = r.verification;
    expect(v.journal.valide, JSON.stringify(v.journal.diagnostics)).to.equal(true);
    expect(v.dossier.verdict, JSON.stringify(v.dossier.controles_en_echec)).to.equal("valide");
    if (v.go === null) return true;
    expect([v.go.status, v.go.verdict, v.go.failed_checks], JSON.stringify(v.go)).to.deep.equal([0, "valide", []]);
    return false;
  }

  it("SDK JavaScript (Node.js 22) : chaque fonction de l'interface publique ; issues de politique de la table d'EX-6.7 rendues sans exception par debutAppel ; démon arrêté : ErreurNoortraceIndisponible, outil d'écriture jamais exécuté ; démon muet au-delà de delai_s : ErreurNoortraceIndisponible, requête écrite ; événements conformes (journal et dossier vérifiés)", async function () {
    expect(Number(process.versions.node.split(".")[0])).to.be.at.least(22);
    const r = await jouer("js", null);
    const v = Object.fromEntries(r.sorties.map((x) => [x.etape, x.valeur]));
    expect(v.declarer_contexte.length).to.equal(Buffer.byteLength('{"note":"contexte ti13"}'));
    expect(v.debut_appel_lecture).to.deep.equal({ call: true, decision: "autorise", ticket: false, ticket_state: null });
    expect(v.fin_appel).to.deep.equal({ seq: true, hash: true });
    expect(v.appel_outil_ecriture).to.deep.equal({ resultat: { ok: true, id: "F1" }, executions: 1 });
    expect(v.debut_appel_a_approuver).to.deep.equal({ call: false, decision: "a_approuver", ticket: true, ticket_state: "nouveau" });
    expect(v.debut_appel_refuse).to.deep.equal({ call: false, decision: "refuse", ticket: false, ticket_state: null });
    expect(v.appel_outil_refuse).to.deep.equal({ classe: "AppelNonAutorise", decision: "refuse", ticket: false, ticket_state: null, texte: "noortrace: appel refuse par la politique", executions: 1 });
    expect(v.echange_modele).to.deep.equal({ seq: true, hash: true });
    expect(v.fermer).to.deep.equal({});
    expect(v.appel_outil_demon_arrete).to.deep.include({ classe: "NoortraceIndisponible", executions: 0 });
    expect(v.ouvrir_demon_arrete).to.deep.equal({ classe: "NoortraceIndisponible", envoyee: false });
    expect(v.ouvrir_demon_muet).to.deep.equal({ classe: "NoortraceIndisponible", envoyee: true });
    expect(r.evenements.map((e) => [e.tool, e.status, e.decision])).to.deep.equal([
      ["agent-py__lire_fiche", "executee", "autorise"],
      ["agent-py__ecrire_note", "executee", "autorise"],
      ["agent-py__approuver_virement", "retenue", "a_approuver"],
      ["agent-py__refuser_virement", "refusee", "refuse"],
      ["agent-py__refuser_virement", "refusee", "refuse"],
      ["noortrace.modele.echange", "executee", "sans_objet"],
    ]);
    if (verifie(r)) {
      this.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN ou PATH)";
      this.skip();
    }
  });

  /** Une version de Python : mêmes sorties et mêmes événements que le SDK JavaScript ; environnement absent : en attente. */
  async function comparerPython(ctx, env, version) {
    const python = interpreteur(env);
    if (!python) {
      ctx.test.title += ` — en attente : environnement absent (paquets/sdk-python/.environnements/${env} ; paquets/sdk-python/outils/environnements.sh preparer ${env})`;
      ctx.skip();
    }
    if (!resultats.js) ctx.skip();
    const r = await jouer(`py${version.replace(".", "")}`, python);
    expect(r.sorties).to.deep.equal(resultats.js.sorties);
    expect(r.evenements).to.deep.equal(resultats.js.evenements);
    if (verifie(r)) {
      ctx.test.title += " — binaire Go en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN ou PATH)";
      ctx.skip();
    }
  }

  it("SDK Python 3.10 : mêmes sorties normalisées que le SDK JavaScript, étape par étape (interface publique, issues de politique, démon arrêté puis muet), mêmes événements (outils, statuts, décisions, pièces) ; événements conformes (journal et dossier vérifiés)", async function () {
    await comparerPython(this, "essais-py310", "3.10");
  });

  it("SDK Python 3.13 : mêmes sorties normalisées que le SDK JavaScript, étape par étape (interface publique, issues de politique, démon arrêté puis muet), mêmes événements (outils, statuts, décisions, pièces) ; événements conformes (journal et dossier vérifiés)", async function () {
    await comparerPython(this, "essais-py313", "3.13");
  });
});
