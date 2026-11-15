// Revue de sécurité interne de l'étape 8 : SDK JavaScript (`noortrace-sdk`)
// et SDK Python (`paquets/sdk-python`, par pytest dans ses environnements).
// Chaque `it` nomme l'exigence ou le défaut qu'il reproduit ; chaque essai échoue sur
// le code d'avant la correction et passe après.
//
//   CT-2 EX-6.10   une prise TCP hors de la boucle locale n'est admise qu'en mTLS (JavaScript ; Python par pytest)
//     SDK Python : substitut isolé, motifs ancrés (pytest tests/test_revue.py)
//      SDK Python : propriétaire de la prise Unix (pytest tests/test_revue.py) ; JavaScript : test/enregistreur-revue-frontaux.test.js
//   EX-6.21   adaptateur CrewAI : `_arun` enveloppée (pytest tests/test_revue_crewai.py, environnement crewai)

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as SDK from "noortrace-sdk";
import { RACINE } from "./fixtures/enregistreur-coeur/outils.mjs";

const { ClientNoortrace, ErreurNoortraceConfiguration } = SDK;
// Fonction nouvelle : absente du code d'avant la correction (rejeu), l'essai échoue alors par son oracle.
const adresseDeBouclage = SDK.adresseDeBouclage ?? (() => undefined);
const PAQUET = path.join(RACINE, "paquets", "sdk-python");
const ENVS = path.join(PAQUET, ".environnements");
const PREPARER = "paquets/sdk-python/outils/environnements.sh preparer";

function interpreteur(nom) {
  const p = path.join(ENVS, nom, "bin", "python");
  return fs.existsSync(p) ? p : null;
}

/** Lance pytest dans un environnement ; rend code, sortie, résumé. */
function pytest(python, fichiers) {
  const r = spawnSync(python, ["-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:warnings", "-rfEs", ...fichiers], {
    cwd: PAQUET,
    env: { ...process.env, NOORTRACE_ESSAI_EXIGER: "1", PYTHONDONTWRITEBYTECODE: "1", CREWAI_DISABLE_TELEMETRY: "true", CREWAI_TRACING_ENABLED: "false", OTEL_SDK_DISABLED: "true" },
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    timeout: 600000,
  });
  const sortie = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  const resume = sortie.trim().split("\n").reverse().find((l) => /\d+ (passed|failed|error)/.test(l)) ?? "";
  return { code: r.status, sortie, resume };
}

function exigerSucces(r, minimum) {
  const passes = Number(/(\d+) passed/.exec(r.resume)?.[1] ?? 0);
  expect(r.code, r.sortie.slice(-6000)).to.equal(0);
  expect(r.resume, r.sortie.slice(-3000)).to.not.match(/failed|error|xfail|deselected/);
  expect(passes, r.resume).to.be.at.least(minimum);
}

describe("SDK, revue (étape 8) : SDK JavaScript et SDK Python", function () {
  this.timeout(600000);

  describe("CT-2 EX-6.10 : prise TCP hors de la boucle locale (SDK JavaScript)", function () {
    it("une prise TCP hors de la boucle locale avec un jeton seul est refusée à la construction (ErreurNoortraceConfiguration, mTLS exigé) ; la boucle locale est admise ; en mTLS un hôte distant est admis sans jeton", function () {
      expect(adresseDeBouclage("127.0.0.1")).to.equal(true);
      expect(adresseDeBouclage("localhost")).to.equal(true);
      expect(adresseDeBouclage("::1")).to.equal(true);
      expect(adresseDeBouclage("hote.example")).to.equal(false);
      expect(adresseDeBouclage("192.0.2.5")).to.equal(false);
      expect(new ClientNoortrace({ tcp: "127.0.0.1:8611", jeton: "jeton" })._adresse.tcp).to.deep.equal({ hote: "127.0.0.1", port: 8611 });
      let e = null;
      try {
        new ClientNoortrace({ tcp: "hote.example:8611", jeton: "jeton" });
      } catch (x) {
        e = x;
      }
      expect(e).to.be.instanceOf(ErreurNoortraceConfiguration);
      expect(e.message).to.match(/mTLS/).and.match(/en clair/);
      // Par l'environnement : même règle.
      const env = { ...process.env };
      delete process.env.NOORTRACE_SDK_SOCKET;
      process.env.NOORTRACE_SDK_TCP = "192.0.2.5:8611";
      process.env.NOORTRACE_SDK_TOKEN = "jeton";
      try {
        expect(() => ClientNoortrace.depuisEnvironnement()).to.throw(ErreurNoortraceConfiguration);
        // mTLS : certificat et clé éphémères (openssl), hôte distant admis, aucun jeton envoyé.
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-revue-sdk-"));
        try {
          const cle = path.join(dir, "c.key");
          const cert = path.join(dir, "c.pem");
          const r = spawnSync("openssl", ["req", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", cle, "-out", cert, "-subj", "/CN=agent", "-days", "2"], { encoding: "utf8" });
          expect(r.status, r.stderr).to.equal(0);
          process.env.NOORTRACE_SDK_TLS_CERT = cert;
          process.env.NOORTRACE_SDK_TLS_KEY = cle;
          delete process.env.NOORTRACE_SDK_TOKEN;
          const c = ClientNoortrace.depuisEnvironnement();
          expect(c._adresse.tcp.hote).to.equal("192.0.2.5");
          expect(c._adresse.jeton).to.equal(null);
          expect(c._adresse.tls).to.be.an("object");
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      } finally {
        for (const k of Object.keys(process.env)) if (k.startsWith("NOORTRACE_SDK_")) delete process.env[k];
        Object.assign(process.env, env);
      }
    });
  });

  describe("SDK Python : CT-2 EX-6.10 (tests/test_revue.py) et EX-6.21 (tests/test_revue_crewai.py)", function () {
    for (const s of [{ env: "essais-py313", python: "3.13" }, { env: "essais-py310", python: "3.10" }]) {
      const python = interpreteur(s.env);
      if (!python) {
        it(`en attente : environnement Python ${s.python} absent (paquets/sdk-python/.environnements/${s.env} ; ${PREPARER} ${s.env})`);
        continue;
      }
      it(`pytest tests/test_revue.py sous Python ${s.python} : substitut isolé non JSON et motifs ancrés, prise TCP distante en mTLS seulement (CT-2 EX-6.10), propriétaire de la prise Unix : tous passent`, function () {
        const r = pytest(python, ["tests/test_revue.py"]);
        exigerSucces(r, 3);
      });
    }
    const crew = interpreteur("crewai");
    if (!crew) {
      it(`en attente : environnement du cadre CrewAI absent (paquets/sdk-python/.environnements/crewai ; ${PREPARER} crewai)`);
    } else {
      it("pytest tests/test_revue_crewai.py (CrewAI 1.15.30) : une sous-classe de BaseTool à _arun propre est interceptée sur arun comme sur run (CT-2 EX-6.21)", function () {
        const r = pytest(crew, ["tests/test_revue_crewai.py"]);
        exigerSucces(r, 1);
      });
    }
  });
});
