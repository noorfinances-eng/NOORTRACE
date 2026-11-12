// Banc « client fictif » de l'étape 7 : preuve du critère de
// livraison de l'étape 7 retenu : installation complète IC-1 à
// IC-18 (CT-8 §8.3), profil production, avec les substituts locaux de
// l'inventaire (section 2.3), en moins de 480 min, durées publiées. Le
// harnais est `scripts/deploiement/banc-client-fictif.mjs` ; ses substituts
// sont sous test/fixtures/banc-client/.
//
// Une installation complète attend réellement la clôture de l'heure (CT-8
// IC-15 ; CT-9 EX-11.5 : aucune horloge manipulée pendant une mesure) : elle
// dure jusqu'à plus d'une heure. Les essais de bout en bout lisent donc le
// procès-verbal d'une exécution du harnais :
//   - NOORTRACE_BANC_CLIENT=<répertoire --travail d'une exécution terminée> ;
//   - ou NOORTRACE_BANC_LANCER=1 : l'essai lance le harnais lui-même
//     (répertoire neuf sous NOORTRACE_TMP ou os.tmpdir(), adresse interne
//     NOORTRACE_BANC_IP ou la première adresse RFC 5737 de l'hôte).
// Sans Docker, sans les images `noortrace/*`, sans le réseau 2124 ou sans
// procès-verbal, chaque essai de bout en bout est en attente, sa condition
// nommée dans son titre. Les essais statiques tournent partout.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const HARNAIS = path.join(RACINE, "scripts", "deploiement", "banc-client-fictif.mjs");
const FIXTURES = path.join(RACINE, "test", "fixtures", "banc-client");
const IC = Array.from({ length: 18 }, (_, k) => `IC-${k + 1}`);

function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

/** Conditions du banc (Docker, images, réseau 2124…) par le harnais lui-même, en boîte noire. */
async function conditions() {
  const { conditionsBanc } = await import(HARNAIS);
  return conditionsBanc();
}

describe("Étape 7 : banc client fictif — harnais et substituts (statique)", function () {
  this.timeout(60000);

  it("Critère de l'étape 7, CT-8 §8.3 : les budgets du harnais sont ceux de CT-8 (IC-1 à IC-18, 450 min, réserve de 30 min jusqu'à 480)", async function () {
    const { BUDGETS_IC } = await import(HARNAIS);
    expect(Object.keys(BUDGETS_IC)).to.deep.equal(IC);
    expect(Object.values(BUDGETS_IC).reduce((a, b) => a + b, 0)).to.equal(450);
    const texte = fs.readFileSync(path.join(RACINE, "spec", "CT-8-deploiement-et-exploitation.md"), "utf8");
    for (const id of IC) {
      const m = new RegExp(`\\| ${id} \\| [^|]+ \\| (\\d+) min \\|`).exec(texte);
      expect(m, id).to.not.equal(null);
      expect(Number(m[1]), id).to.equal(BUDGETS_IC[id]);
    }
  });

  it("contraintes du dépôt : noms des substituts en .example ou .invalid seulement, adresses 127.0.0.1 ou RFC 5737 seulement, aucun nom de fournisseur public joint, aucune clé écrite dans les fichiers du banc", async function () {
    const fichiers = [HARNAIS, ...fs.readdirSync(FIXTURES).map((f) => path.join(FIXTURES, f))];
    const { NOMS, PORTS } = await import(path.join(FIXTURES, "substituts.mjs"));
    for (const n of Object.values(NOMS)) expect(n, n).to.match(/\.(example|invalid)$/);
    // Aucun port du banc n'est un port que production.yaml publie.
    const publies = [8300, 8400, 1344, 4318, 8500, 8601, 8700, 8545, 8080, 9090];
    for (const p of Object.values(PORTS)) expect(publies, String(p)).to.not.include(p);
    for (const f of fichiers) {
      const t = fs.readFileSync(f, "utf8");
      for (const ip of t.match(/(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])/g) ?? []) {
        expect(ip, `${path.basename(f)} : ${ip}`).to.match(/^(127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.\d+|198\.51\.100\.\d+|203\.0\.113\.\d+)$/);
      }
      for (const u of t.match(/https?:\/\/[A-Za-z0-9.-]+/g) ?? []) {
        const hote = new URL(u).hostname;
        expect(`${path.basename(f)} : ${u}`).to.satisfy(() => /\.(example|invalid)$/.test(hote) || ["127.0.0.1", "s3.amazonaws.com", "uri.etsi.org"].includes(hote) || !hote.includes(".") || hote.startsWith("${"));
      }
      expect(t, path.basename(f)).to.not.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
    }
  });

  it("usage : sans --travail, code 2 et l'usage ; répertoire existant refusé (code 2)", function () {
    const r = spawnSync(process.execPath, [HARNAIS], { encoding: "utf8" });
    expect(r.status).to.equal(2);
    expect(r.stderr).to.contain("Usage : node scripts/deploiement/banc-client-fictif.mjs");
    const r2 = spawnSync(process.execPath, [HARNAIS, "--travail", os.tmpdir()], { encoding: "utf8" });
    expect(r2.status).to.equal(2);
    expect(r2.stderr).to.contain("existe déjà");
  });

  it("conditions nommées : sans moteur de conteneurs (PATH sans docker), le harnais rend 3 et nomme « Docker absent »", function () {
    const d = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "banc-g-"));
    try {
      const r = spawnSync(process.execPath, [HARNAIS, "--travail", path.join(d, "t")], { encoding: "utf8", env: { ...process.env, PATH: path.dirname(process.execPath) } });
      expect(r.status).to.equal(3);
      expect(r.stderr).to.contain("Docker absent ou démon dockerd injoignable");
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("Étape 7 : banc client fictif — installation complète IC-1 à IC-18 de bout en bout (CT-9 TE-7, TM-22, TM-29)", function () {
  this.timeout(3 * 3600000);
  const s = { attente: null, travail: null, pv: null, banc: null };

  before(async function () {
    const donne = process.env.NOORTRACE_BANC_CLIENT ?? null;
    if (donne) {
      if (!fs.existsSync(path.join(donne, "banc", "proces-verbal-banc.json"))) {
        s.attente = `procès-verbal du banc absent sous NOORTRACE_BANC_CLIENT (${donne})`;
        return;
      }
      s.travail = donne;
    } else {
      const manque = await conditions();
      if (manque.length) {
        s.attente = manque.join(" ; ");
        return;
      }
      if (process.env.NOORTRACE_BANC_LANCER !== "1") {
        s.attente = "procès-verbal du banc absent : lancer node scripts/deploiement/banc-client-fictif.mjs --travail <rép.> --ip-interne <adresse> --images <archive docker save> (plus d'une heure : attente réelle de la clôture), puis NOORTRACE_BANC_CLIENT=<rép.> ; ou NOORTRACE_BANC_LANCER=1";
        return;
      }
      const base = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "banc-client-"));
      s.travail = path.join(base, "travail");
      const args = [HARNAIS, "--travail", s.travail];
      if (process.env.NOORTRACE_BANC_IP) args.push("--ip-interne", process.env.NOORTRACE_BANC_IP);
      if (process.env.NOORTRACE_BANC_IMAGES) args.push("--images", process.env.NOORTRACE_BANC_IMAGES);
      if (process.env.NOORTRACE_BANC_CONDENSES) args.push("--condenses", process.env.NOORTRACE_BANC_CONDENSES);
      if (process.env.NOORTRACE_BANC_ORG) args.push("--org", process.env.NOORTRACE_BANC_ORG);
      const r = spawnSync(process.execPath, args, { cwd: RACINE, encoding: "utf8", timeout: 3 * 3600000, maxBuffer: 64 * 1024 * 1024 });
      if (r.status === 3) {
        s.attente = `condition du banc absente : ${r.stderr.trim().split("\n").slice(1).join(" ; ")}`;
        return;
      }
    }
    s.pv = path.join(s.travail, "pv");
    s.banc = lireJson(path.join(s.travail, "banc", "proces-verbal-banc.json"));
  });

  function pret(ctx) {
    if (s.attente) {
      enAttente(ctx, s.attente);
      return false;
    }
    return true;
  }

  it("TE-7 (part de l'étape 7) : IC-1 à IC-18 déroulés dans l'ordre de CT-8, chacun réussi (écarts du banc nommés au procès-verbal) ; procès-verbal d'installation clos par IC-18 (sha256sum --strict -c IC-18-liste.sha256 rend 0) ; cérémonie vérifiée (npm run verify:ceremonie : 0) ; attestation signée vérifiée (conformite:attestation verifier : 0) ; contrôle préalable final consigné", function () {
    if (!pret(this)) return;
    const ids = s.banc.pas.filter((p) => /^IC-\d+$/.test(p.id)).map((p) => p.id);
    expect(ids).to.deep.equal(IC);
    for (const p of s.banc.pas) expect(p.resultat, `${p.id} : ${p.erreur ?? ""}`).to.be.oneOf(["reussi", "reussi_avec_ecarts"]);
    const c = spawnSync("sha256sum", ["--strict", "-c", "IC-18-liste.sha256", "--quiet"], { cwd: s.pv, encoding: "utf8" });
    expect(c.status, c.stdout + c.stderr).to.equal(0);
    expect(fs.readFileSync(path.join(s.pv, "IC-7-verification.txt"), "utf8")).to.match(/^code 0\n/);
    expect(fs.readFileSync(path.join(s.pv, "IC-17-verification.txt"), "utf8")).to.match(/^code 0\n/);
    const controle = lireJson(path.join(s.pv, "IC-14-controle.json"));
    // Verdict consigné tel quel ; les seules vérifications non réussies admises sont les écarts du banc (IP-3, IP-5, IP-6, IP-9).
    const nonReussies = controle.checks.filter((x) => x.status !== "reussi").map((x) => x.id);
    expect(nonReussies.every((id) => ["IP-3", "IP-5", "IP-6", "IP-9"].includes(id)), JSON.stringify(nonReussies)).to.equal(true);
    for (const id of ["IP-1", "IP-2", "IP-4", "IP-7", "IP-8", "IP-10", "IP-11", "IP-12", "IP-13"]) expect(controle.checks.find((x) => x.id === id).status, id).to.equal("reussi");
  });

  it("TE-7, IC-15 : un appel d'outil soumis à approbation, une décision signée par la console (deux approbateurs, portefeuille d'essai), la clôture réelle de l'heure, l'export du dossier ; noortrace-verifier (image et binaire) et npm run verify:dossier avec --exiger 7 : code 0, verdict valide, contrôles 4, 7 et 8 réussis", function () {
    if (!pret(this)) return;
    const v = path.join(s.travail, "banc", "verificateurs");
    for (const f of ["verificateur-conteneur.json", "noortrace-verifier.json", "verify-dossier.json"]) {
      const r = lireJson(path.join(v, f));
      const ctl = Object.fromEntries(r.controls.map((x) => [x.number, x.status]));
      expect(r.verdict, f).to.equal("valide");
      expect([ctl[4], ctl[7], ctl[8]], f).to.deep.equal(["reussi", "reussi", "reussi"]);
    }
    for (const f of ["noortrace-verifier.code", "verify-dossier.code"]) expect(fs.readFileSync(path.join(v, f), "utf8").trim(), f).to.equal("0");
    const appel = lireJson(path.join(s.pv, "IC-15-appel.json"));
    expect(appel.decision.approvers).to.have.length(2);
    expect(s.banc.dossier_sha256).to.match(/^[0-9a-f]{64}$/);
  });

  it("TM-22 : rapport de mesure (CT-9 §11.3, $defs/rapport_mesure) : lignes ic_1 à ic_18, ic_attente_cloture et ic_total publiées ; hors système de référence (counts_for_targets faux, met null) ; ic_total sous 480 min", function () {
    if (!pret(this)) return;
    const m = lireJson(path.join(s.travail, "banc", "mesures.json"));
    // Forme de $defs/rapport_mesure (membres exigés, aucun membre inconnu ; hors du système de référence : met null).
    const d = lireJson(path.join(RACINE, "spec", "schemas", "plan-de-tests-v0.schema.json")).$defs;
    const forme = (o, def, ou) => {
      for (const k of def.required) expect(o, `${ou} : ${k}`).to.have.property(k);
      for (const k of Object.keys(o)) expect(Object.keys(def.properties), `${ou} : ${k}`).to.include(k);
    };
    forme(m, d.rapport_mesure, "rapport");
    forme(m.system, d.systeme, "system");
    forme(m.method, d.rapport_mesure.properties.method, "method");
    for (const r of m.results) {
      forme(r, d.resultat_mesure, r.name);
      expect(r.met, r.name).to.equal(null);
      expect(r.excluded_reason, r.name).to.equal("hors_systeme_de_reference");
      expect(r.test_id).to.equal("TM-22");
      expect(r.unit).to.equal("min");
    }
    expect(m.results.map((r) => r.name)).to.deep.equal([...IC.map((x) => x.toLowerCase().replace("-", "_")), "ic_attente_cloture", "ic_total"]);
    expect(m.counts_for_targets).to.equal(false);
    expect(m.system.reference).to.equal(false);
    const total = m.results.find((r) => r.name === "ic_total");
    expect(total.value).to.be.a("number");
    expect(total.value).to.be.below(480);
  });

  it("TM-29 (relevé partiel, sans la charge de TM-3) : consommation des services en marche relevée (mémoire, processeur, volumes) et confrontée aux planchers de production (4 processeurs, 8 Gio)", function () {
    if (!pret(this)) return;
    const c = lireJson(path.join(s.travail, "banc", "consommation.json"));
    const octets = (t) => {
      const m = /^([\d.]+)\s*([KMG]i?B|B)/.exec(t);
      const f = { B: 1, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, kB: 1e3, MB: 1e6, GB: 1e9 }[m[2]] ?? 1;
      return Number(m[1]) * f;
    };
    const memoire = c.services.reduce((a, x) => a + octets(x.memoire.split("/")[0].trim()), 0);
    expect(c.services.map((x) => x.nom).join(" ")).to.match(/enregistreur/);
    expect(memoire).to.be.below(8 * 1024 ** 3);
    expect(c.load_avg[0]).to.be.below(4);
  });
});

describe("Étape 7 : entrées de CT-9 que le banc ne tient pas (rattachement motivé)", function () {
  it("TE-6, TM-21 : installation rapide IR-1 à IR-8 — non jouée par le banc de l'étape 7 (le banc tient l'installation complète, critère de l'étape 7) ; le remplacement du faux prestataire RFC 3161 de rapide.yaml par le serveur interne n'est pas fait (décision du porteur attendue sur le prestataire RFC 3161 hors production)", function () {
    enAttente(this, "installation rapide hors du banc de l'étape 7 : rapide.yaml n'a pas de service d'horodatage, et IR-7 exige un serveur d'outils joint par l'enregistreur en mode observation");
  });

  it("TE-8, TM-36 : flux FL-1 à FL-31 relevés et runbooks RB-1 à RB-8 rejoués sur le déploiement de test — non joués (incidents provoqués, supervision collectée : TE-17, étape 8)", function () {
    enAttente(this, "rejeu des runbooks et relevé des flux non construits sur le banc : à rattacher à l'étape 8 avec la démonstration de référence (TM-36 la nomme)");
  });

  it("TE-10 : mode observation de bout en bout — exige l'installation rapide (précondition de CT-9), hors du banc de l'étape 7", function () {
    enAttente(this, "installation rapide (mode observation) non jouée par le banc de l'étape 7");
  });
});
