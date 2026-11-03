// SDK Python `noortrace-sdk` et adaptateurs de cadres Python (CT-2 6.4 à 6.6) :
// lance la suite pytest de paquets/sdk-python/tests dans les environnements
// isolés créés par `uv` depuis les fichiers de verrou versionnés
// (paquets/sdk-python/outils/environnements.sh preparer) :
//   - le SDK seul (test_sdk.py, interface de 6.5, erreurs, reprise, démon
//     injoignable, fils, fork, asynchrone) et les vecteurs de l'annexe B qu'il
//     partage avec le SDK JavaScript (test_vecteurs.py : `redaction`,
//     `pieces-modele/gemini-sdk-*`, `pieces-mcp`, EX-6.5) sous Python 3.10 et 3.13 ;
//   - chaque adaptateur dans l'environnement de son cadre, à la version de la
//     table de 6.6 : les cinq essais d'EX-6.20 et un agent réel du cadre (outil
//     local et outil MCP passé par le frontal), journal accepté par
//     `N.verifierJournal`, dossier valide pour le noyau et, si go1.27.3 est
//     présent (NOORTRACE_GO_BIN, à défaut PATH), pour le binaire Go.
// Les essais pytest s'exécutent contre le démon réel `bin/noortrace` (banc de
// test/fixtures/enregistreur-sdk-python/banc.mjs).
//
// Un environnement absent (interpréteur ou cadre non installé) met l'essai en
// attente, avec un titre qui nomme la condition manquante ; jamais une
// réussite factice : un environnement présent exige que tous les essais
// pytest passent, sans essai sauté (NOORTRACE_ESSAI_EXIGER).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";

const PAQUET = path.join(RACINE, "paquets", "sdk-python");
const ENVS = path.join(PAQUET, ".environnements");

/** Interpréteur d'un environnement, ou null. */
function interpreteur(nom) {
  const p = path.join(ENVS, nom, "bin", "python");
  return fs.existsSync(p) ? p : null;
}

/** go1.27.3 est-il disponible (NOORTRACE_GO_BIN, à défaut PATH) ? */
function goDisponible() {
  const env = { ...process.env };
  if (process.env.NOORTRACE_GO_BIN) env.PATH = `${process.env.NOORTRACE_GO_BIN}${path.delimiter}${env.PATH}`;
  const v = spawnSync("go", ["version"], { env, encoding: "utf8" });
  return v.status === 0 && /go1\.27\.3 /.test(v.stdout);
}

/**
 * Lance pytest dans un environnement ; rend la sortie et le résumé.
 * @param {string} python
 * @param {string[]} fichiers
 */
function pytest(python, fichiers) {
  const r = spawnSync(python, ["-m", "pytest", "-q", "-s", "-p", "no:cacheprovider", "-p", "no:warnings", "-rfEs", ...fichiers], {
    cwd: PAQUET,
    env: { ...process.env, NOORTRACE_ESSAI_EXIGER: "1", NOORTRACE_NODE: process.execPath, PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 900000,
  });
  const sortie = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const resume = sortie.trim().split("\n").reverse().find((l) => /\d+ (passed|failed|error)/.test(l)) ?? "";
  return { code: r.status, sortie, resume };
}

/** Vérifie un passage pytest : code 0, essais passés, aucun échec, erreur ni essai sauté. */
function exigerSucces(r, minimum) {
  const passes = Number(/(\d+) passed/.exec(r.resume)?.[1] ?? 0);
  expect(r.code, r.sortie.slice(-6000)).to.equal(0);
  expect(r.resume, r.sortie.slice(-3000)).to.not.match(/failed|error|skipped|xfail|deselected/);
  expect(passes, r.resume).to.be.at.least(minimum);
}

const SUITES_SDK = [
  { env: "essais-py310", python: "3.10" },
  { env: "essais-py313", python: "3.13" },
];

const ADAPTATEURS = [
  { nom: "LangChain 1.4.7 et LangGraph 1.2.17", env: "langchain", fichier: "tests/test_adaptateur_langchain.py", minimum: 7 },
  { nom: "CrewAI 1.15.30", env: "crewai", fichier: "tests/test_adaptateur_crewai.py", minimum: 12 },
  { nom: "LlamaIndex (llama-index-core 0.14.25)", env: "llamaindex", fichier: "tests/test_adaptateur_llamaindex.py", minimum: 6 },
  { nom: "SDK Agents d'OpenAI 0.24.0 (Python)", env: "openai-agents", fichier: "tests/test_adaptateur_openai_agents.py", minimum: 6 },
  { nom: "LiteLLM 1.106.4 (bibliothèque)", env: "litellm", fichier: "tests/test_adaptateur_litellm.py", minimum: 6 },
];

const MANDATAIRE = { nom: "LiteLLM 1.106.4 en mandataire (litellm[proxy], EX-6.22 disposition (a))", env: "litellm-mandataire", fichier: "tests/test_mandataire_litellm.py" };

const PREPARER = "paquets/sdk-python/outils/environnements.sh preparer";

describe("enregistreur, SDK Python noortrace-sdk et adaptateurs de cadres Python (CT-2 6.4 à 6.6)", function () {
  this.timeout(900000);
  const go = goDisponible();

  describe("SDK Python seul et vecteurs de l'annexe B, contre le démon réel (6.4, 6.5, EX-6.5, EX-6.9 à EX-6.15)", function () {
    for (const s of SUITES_SDK) {
      const python = interpreteur(s.env);
      if (!python) {
        it(`en attente : environnement Python ${s.python} absent (paquets/sdk-python/.environnements/${s.env} ; ${PREPARER} ${s.env})`);
        continue;
      }
      it(`pytest tests/test_sdk.py et tests/test_vecteurs.py sous Python ${s.python} : tous les essais passent`, function () {
        const r = pytest(python, ["tests/test_sdk.py", "tests/test_vecteurs.py"]);
        exigerSucces(r, 26);
        // Vecteurs rejoués (annexe B) : nombre de cas par famille.
        expect(r.sortie).to.match(/noortrace-vecteurs redaction pii-v1 : 59 cas rejoues/);
        expect(r.sortie).to.match(/noortrace-vecteurs redaction pii-pseudo-test : 6 cas rejoues/);
        expect(r.sortie).to.match(/noortrace-vecteurs pieces-mcp : 17 cas rejoues/);
      });
    }
  });

  describe("adaptateurs Python : cinq essais d'EX-6.20 et agent réel du cadre", function () {
    for (const a of ADAPTATEURS) {
      const python = interpreteur(a.env);
      if (!python) {
        it(`${a.nom} — en attente : environnement du cadre absent (paquets/sdk-python/.environnements/${a.env} ; ${PREPARER} ${a.env})`);
        continue;
      }
      let r;
      it(`${a.nom} : pytest ${a.fichier}, essais (i) à (v) et compléments passent`, function () {
        r = pytest(python, [a.fichier]);
        exigerSucces(r, a.minimum);
      });
      it(`${a.nom} : journal du parcours accepté par N.verifierJournal, dossier valide pour le noyau`, function () {
        if (!r) this.skip();
        const l = r.sortie.split("\n").find((x) => x.startsWith("noortrace-parcours "));
        expect(l, r.sortie.slice(-2000)).to.match(/journal \d+ evenements valide ; dossier noyau valide/);
      });
      if (go) {
        it(`${a.nom} : dossier du parcours valide pour le binaire Go noortrace-verifier (go1.27.3)`, function () {
          if (!r) this.skip();
          const l = r.sortie.split("\n").find((x) => x.startsWith("noortrace-parcours "));
          expect(l).to.match(/binaire Go valide$/);
        });
      } else {
        it(`${a.nom} — en attente : go1.27.3 introuvable (NOORTRACE_GO_BIN ou PATH), dossier non soumis au binaire Go`);
      }
    }
  });

  describe("LiteLLM en mandataire : agent → passerelle → mandataire LiteLLM → fournisseur (EX-6.22)", function () {
    const python = interpreteur(MANDATAIRE.env);
    if (!python) {
      it(`${MANDATAIRE.nom} — en attente : environnement du mandataire absent (paquets/sdk-python/.environnements/${MANDATAIRE.env}, litellm[proxy]==1.106.4 ; ${PREPARER} ${MANDATAIRE.env})`);
      return;
    }
    it(`${MANDATAIRE.nom} : un échange, requête de l'agent sous la délégation de l'agent, réponse rendue par LiteLLM`, function () {
      const r = pytest(python, [MANDATAIRE.fichier]);
      exigerSucces(r, 1);
      expect(r.sortie).to.match(/noortrace-mandataire : agent -> passerelle -> LiteLLM/);
    });
  });
});
