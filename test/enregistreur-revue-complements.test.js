// Enregistreur (paquets/enregistreur), rédacteur : comptes du journal
// d'exploitation (CT-2 EX-10.17, annexe B.3 `expected.matches`) quand une
// règle porte plusieurs détecteurs du même type (revue de sécurité de l'étape 8).
//
// EX-10.17 : « par détecteur, le nombre de correspondances et leur type » ;
// annexe B.3 : `matches` est un tableau `[{ rule, detector, count }]`,
// additionné sur les passages, `detector` valant le type du détecteur. Deux
// motifs nommés d'une même règle (deux détecteurs `regex`) donnent donc deux
// entrées, une par détecteur, rangées par première apparition, et non une
// seule entrée `(règle, regex)` qui additionne les deux : c'est la forme du
// vecteur `redaction/passages-en-cascade` (CT-2 révision 0.11, EX-10.14).
// La politique est construite en mémoire ; le rédacteur éprouvé est celui du
// paquet, ou le répertoire `src` que nomme NOORTRACE_REVUE_ENREGISTREUR
// (copie avant correction ou mutant).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { BIN_NOORTRACE, configurationExemple, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";

const SRC = process.env.NOORTRACE_REVUE_ENREGISTREUR ? path.resolve(process.env.NOORTRACE_REVUE_ENREGISTREUR) : null;
const E = SRC ? await import(pathToFileURL(path.join(SRC, "redaction-moteur.mjs")).href) : await import("@noortrace/enregistreur");
const { PolitiqueCompilee, produirePiece, redigerEffetsDeclares } = E;
const CONF = SRC ? await import(pathToFileURL(path.join(SRC, "configuration.mjs")).href) : await import("@noortrace/enregistreur");
const { validerConfiguration } = CONF;
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

const politique = (detecteurs) => ({
  version: 0,
  name: "pii-regles-revue",
  description: "Politique d'essai : deux motifs nommés dans une règle.",
  pseudonym_key: null,
  named_patterns: {
    "cascade-a": { pattern: "A\\b", description: "Un A suivi d'une frontière de mot." },
    "cascade-b": { pattern: "B$", description: "Un B en fin de chaîne." },
    chiffres: { pattern: "[0-9]{4}", description: "Quatre chiffres." },
  },
  rules: [
    {
      id: "motifs",
      description: "Deux détecteurs regex et un détecteur nommé.",
      scopes: ["resultat", "arguments"],
      tools: ["revue__comptes"],
      detectors: detecteurs,
      action: { kind: "remplacer" },
    },
  ],
});
const A = { type: "regex", name: "cascade-a" };
const B = { type: "regex", name: "cascade-b" };

describe("enregistreur, revue de sécurité de l'étape 8 : comptes par détecteur (CT-2 EX-10.17, annexe B.3, EX-10.14)", function () {
  it("passages en cascade : deux détecteurs regex d'une même règle donnent deux entrées (1 puis 65), rangées par première apparition, non une entrée de 66", function () {
    const pol = new PolitiqueCompilee(politique([A, B]));
    const r = produirePiece(pol, { genre: "json", portee: "resultat", outil: "revue__comptes", valeur: { note: `${"A".repeat(65)}B` } }, { budgetMs: 1000 });
    expect(r.redacted).to.equal(true);
    expect(r.comptes).to.deep.equal([
      { rule: "motifs", detector: "regex", count: 1 },
      { rule: "motifs", detector: "regex", count: 65 },
    ]);
  });

  it("un détecteur qui ne trouve rien n'a pas d'entrée ; deux détecteurs du même type sur des chaînes distinctes restent deux entrées ; un même détecteur additionne ses correspondances", function () {
    const pol = new PolitiqueCompilee(politique([{ type: "regex", name: "chiffres" }, A, B]));
    const r = produirePiece(pol, { genre: "json", portee: "resultat", outil: "revue__comptes", valeur: { a: "x A y", b: "1234 5678", c: "fin B" } }, { budgetMs: 1000 });
    expect(r.comptes).to.deep.equal([
      { rule: "motifs", detector: "regex", count: 2 },
      { rule: "motifs", detector: "regex", count: 1 },
      { rule: "motifs", detector: "regex", count: 1 },
    ]);
    const vide = produirePiece(pol, { genre: "json", portee: "resultat", outil: "revue__comptes", valeur: { a: "rien" } }, { budgetMs: 1000 });
    expect(vide.comptes).to.deep.equal([]);
  });

  it("effets déclarés (EX-10.23) : les comptes des effets se cumulent par détecteur, non par type", function () {
    const pol = new PolitiqueCompilee(politique([A, B]));
    const effets = [{ system: "A B", object: "AB" }, { system: "fin B", object: "A " }];
    const r = redigerEffetsDeclares(pol, effets, { outil: "revue__comptes", budgetMs: 1000 });
    expect(r.omis).to.deep.equal([]);
    // `A B` : A suivi d'une frontière (1 pour cascade-a), B en fin (1 pour cascade-b) ; `AB` : B (cascade-b) puis A
    // libéré au passage suivant (cascade-a) ; `fin B` : cascade-b ; `A ` : cascade-a.
    expect(r.comptes).to.deep.equal([
      { rule: "motifs", detector: "regex", count: 3 },
      { rule: "motifs", detector: "regex", count: 3 },
    ]);
  });
});

// CT-2 EX-11.10 (révision 0.11) : « Le schéma nomme le mécanisme CKM_CLOUDHSM_EDDSA ; sa valeur numérique n'est pas
// établie (R3 F-9) : en version 0, un démon dont la configuration le nomme refuse de démarrer, et la commande de
// validation le dit. »
describe("enregistreur, revue de sécurité de l'étape 8 : CKM_CLOUDHSM_EDDSA refusé par la validation (CT-2 EX-11.10, révision 0.11)", function () {
  this.timeout(30000);
  const avec = (mecanisme) => {
    const c = configurationExemple();
    c.signer.backend.mechanism = mecanisme;
    return c;
  };

  it("validerConfiguration : CKM_CLOUDHSM_EDDSA est une erreur sur /signer/backend/mechanism (pas 3, configuration refusée) ; CKM_EDDSA n'en est pas une", function () {
    const v = validerConfiguration(enc(avec("CKM_CLOUDHSM_EDDSA")));
    expect(v.config).to.equal(null);
    const e = v.erreurs.filter((x) => x.pointeur === "/signer/backend/mechanism");
    expect(e, JSON.stringify(v.erreurs)).to.have.lengthOf(1);
    expect(e[0].regle).to.match(/CKM_CLOUDHSM_EDDSA/);
    expect(e[0].regle).to.match(/EX-11\.10/);
    const ok = validerConfiguration(enc(avec("CKM_EDDSA")));
    expect(ok.erreurs.filter((x) => x.pointeur === "/signer/backend/mechanism")).to.deep.equal([]);
  });

  it("noortrace validate-config le dit (code non nul, règle nommée) et le démon refuse de démarrer sur la même configuration (config_invalid, code 2)", function () {
    const dir = repertoireTemporaire();
    try {
      const f = path.join(dir, "c.json");
      fs.writeFileSync(f, JSON.stringify(avec("CKM_CLOUDHSM_EDDSA"), null, 2));
      const v = spawnSync(process.execPath, [BIN_NOORTRACE, "validate-config", f], { encoding: "utf8", timeout: 20000 });
      expect(v.status, v.stdout + v.stderr).to.not.equal(0);
      expect(v.stdout + v.stderr).to.match(/\/signer\/backend\/mechanism/);
      expect(v.stdout + v.stderr).to.match(/CKM_CLOUDHSM_EDDSA/);
      const d = spawnSync(process.execPath, [BIN_NOORTRACE, "--config", f], { encoding: "utf8", timeout: 20000 });
      expect(d.status, d.stdout + d.stderr).to.equal(2);
      expect(d.stderr).to.match(/config_invalid/);
      expect(d.stderr).to.match(/\/signer\/backend\/mechanism/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
