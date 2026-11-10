// Configuration ancrage-v0 (CT-5 §4.4, lot C) : AN-1 (schéma puis les huit
// règles d'EX-4.9, rapport nominatif complet) sur l'exemple d'EX-4.8, en
// réussite et en échec règle par règle ; projection d'EX-8.2 égale au
// `config` de la trace de référence ; schémas embarqués identiques à
// spec/schemas ; entrées hostiles (profondeur, types, valeurs hors
// énumération, chaînes non UTF-8, nombres hors bornes, PEM illisibles).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import {
  validerConfiguration, projection, validerProjection, motifCertificatPemIllisible, SCHEMA_ANCRAGE, SCHEMA_PLANIFICATEUR, PROFILS, compterJetons,
} from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = path.join(RACINE, "spec");

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

const exemple = () => JSON.parse(blocApres(fs.readFileSync(path.join(SPEC, "CT-5-ancrage.md"), "utf8"), "<!-- schema: ancrage -->"));
const regles = (r) => [...new Set(r.erreurs.map((e) => e.regle))].sort();

describe("ancrage, planificateur : configuration ancrage-v0 (AN-1, EX-4.9) et projection (EX-8.2)", function () {
  it("les schémas embarqués sont identiques, membre pour membre, à spec/schemas", function () {
    const a = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "ancrage-v0.schema.json"), "utf8"));
    const p = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "planificateur-ancrage-v0.schema.json"), "utf8"));
    expect(N.egaliteJson(SCHEMA_ANCRAGE, a)).to.equal(true);
    expect(N.egaliteJson(SCHEMA_PLANIFICATEUR, p)).to.equal(true);
  });

  it("l'exemple d'EX-4.8 est valide hors production avec checkpoint_interval_s 60", function () {
    const r = validerConfiguration(exemple(), { profil: "developpement", checkpointIntervalEnregistreur: 60 });
    expect(r.erreurs).to.deep.equal([]);
    expect(r.valide).to.equal(true);
    expect(r.projection).to.be.an("object");
  });

  it("en production, l'exemple est refusé par la règle 1 quand la cadence de l'enregistreur n'est pas connue, et admis quand elle vaut 60 (EX-4.9, EX-5.9 déclaratif, EX-11.3)", function () {
    const sans = validerConfiguration(exemple(), { profil: "production" });
    expect(sans.valide).to.equal(false);
    expect(regles(sans)).to.deep.equal(["1"]);
    const avec = validerConfiguration(exemple(), { profil: "production", checkpointIntervalEnregistreur: 60 });
    expect(avec.valide, JSON.stringify(avec.erreurs)).to.equal(true);
    const autre = validerConfiguration(exemple(), { profil: "production", checkpointIntervalEnregistreur: 30 });
    expect(regles(autre)).to.deep.equal(["1"]);
  });

  it("le rapport est nominatif et complet : plusieurs règles violées à la fois sont toutes listées", function () {
    const d = exemple();
    d.checkpoint_interval_s = 70; // ne divise pas 3600 (1) et c_T n'en est pas un multiple (3)
    d.rfc3161.retention_years = 10;
    d.rfc3161.retry.initial_ms = 400000; // > max_ms (6)
    d.opentimestamps.calendars = ["https://a.example"]; // (5)
    const r = validerConfiguration(d, { checkpointIntervalEnregistreur: 70 });
    expect(regles(r)).to.deep.equal(["1", "3", "5", "6"]);
  });

  describe("chaque règle d'EX-4.9, en échec", function () {
    const cas = [
      ["1 : checkpoint_interval_s différent de l'enregistreur", (d) => d, { checkpointIntervalEnregistreur: 120 }, ["1"]],
      ["1 : checkpoint_interval_s qui ne divise pas 3600 (et donc 3 : c_T n'en est pas un multiple)", (d) => { d.checkpoint_interval_s = 11; }, { checkpointIntervalEnregistreur: 11 }, ["1", "3"]],
      ["2 : deux principaux", (d) => { d.rfc3161.providers[1].role = "principal"; }, {}, ["2"]],
      ["2 : aucun principal", (d) => { d.rfc3161.providers[0].role = "second_rang"; }, {}, ["2"]],
      ["2 : deux secours", (d) => { d.rfc3161.providers[2].role = "secours"; d.rfc3161.providers[2].url = "https://horodatage-trois.example/tsa"; d.rfc3161.providers[2].auth = { method: "basic", secret: { env: "NOORTRACE_TSA_TROIS" } }; }, {}, ["2"]],
      ["4 : principal en http:// hors production (EX-5.5 : TLS obligatoire hors du rôle interne, quel que soit le profil ; R-C-5)", (d) => { d.rfc3161.providers[0].url = "http://horodatage-principal.example/tsa"; }, {}, ["4"]],
      ["4 : second_rang en http:// vers une adresse locale hors production (seul le rôle interne l'admet)", (d) => { d.rfc3161.providers[1].role = "second_rang"; d.rfc3161.providers[1].url = "http://127.0.0.1:2020/"; }, {}, ["4"]],
      ["2 : id en double", (d) => { d.rfc3161.providers[1].id = "qtsa-principal"; }, {}, ["2"]],
      ["3 : interval_s non multiple de checkpoint_interval_s", (d) => { d.rfc3161.checkpoints.interval_s = 450; }, {}, ["3"]],
      ["3 : interval_s qui ne divise pas 3600", (d) => { d.checkpoint_interval_s = 10; d.rfc3161.checkpoints.interval_s = 70; }, { checkpointIntervalEnregistreur: 10 }, ["3"]],
      ["4 : provider_role aucun en production", (d) => { d.rfc3161.checkpoints.provider_role = "aucun"; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : registry.checkpoints aucun en production", (d) => { d.registry.checkpoints = "aucun"; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : opentimestamps désactivé en production", (d) => { d.opentimestamps.enabled = false; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : principal sans qualified en production", (d) => { d.rfc3161.providers[0].qualified = null; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : secours sans qualified en production (EX-5.7)", (d) => { d.rfc3161.providers[1].qualified = null; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : principal en http:// en production", (d) => { d.rfc3161.providers[0].url = "http://horodatage-principal.example/tsa"; }, { profil: "production", checkpointIntervalEnregistreur: 60 }, ["4"]],
      ["4 : interne en http:// vers une adresse non locale (tout profil)", (d) => { d.rfc3161.providers[2].url = "http://192.0.2.10:2020/"; }, {}, ["4"]],
      ["4 : auth aucune pour un prestataire extérieur (EX-5.5)", (d) => { d.rfc3161.providers[0].auth = { method: "aucune", secret: null }; }, {}, ["4"]],
      ["5 : un seul calendrier", (d) => { d.opentimestamps.calendars = ["https://a.pool.opentimestamps.org"]; }, {}, ["5"]],
      ["5 : min_responses supérieur au nombre de calendriers", (d) => { d.opentimestamps.min_responses = 5; }, {}, ["5"]],
      ["5 : liste blanche vide", (d) => { d.opentimestamps.upgrade.whitelist = []; }, {}, ["5"]],
      ["6 : retry.initial_ms > retry.max_ms", (d) => { d.rfc3161.retry.initial_ms = 600000; }, {}, ["6"]],
      ["7 : provider_role second_rang sans prestataire de ce rôle", (d) => { d.rfc3161.checkpoints.provider_role = "second_rang"; }, {}, ["7"]],
      ["7 : provider_role interne sans prestataire interne", (d) => { d.rfc3161.providers.pop(); d.rfc3161.checkpoints.provider_role = "interne"; }, {}, ["7"]],
      ["8 : PEM qui n'est pas un certificat", (d) => { d.rfc3161.providers[0].anchor_certificates = [`-----BEGIN CERTIFICATE-----\n${Buffer.from("pas un certificat").toString("base64")}\n-----END CERTIFICATE-----\n`]; }, {}, ["8"]],
    ];
    for (const [titre, muter, options, attendu] of cas) {
      it(`règle ${titre}`, function () {
        const d = exemple();
        muter(d);
        const r = validerConfiguration(d, { checkpointIntervalEnregistreur: 60, ...options });
        expect(r.valide).to.equal(false);
        expect(regles(r), JSON.stringify(r.erreurs)).to.deep.equal(attendu);
        expect(r.projection).to.equal(null);
        for (const e of r.erreurs) expect(e.message).to.be.a("string").and.not.match(/NOORTRACE_TSA|\/run\/secrets/);
      });
    }

    it("règle 6 : retention_years < 10 et upgrade.interval_s < 60 sont déjà refusés par le schéma (bornes), donc rapportés `schema`", function () {
      const d = exemple();
      d.rfc3161.retention_years = 9;
      const r = validerConfiguration(d);
      expect(regles(r)).to.deep.equal(["schema"]);
      const d2 = exemple();
      d2.opentimestamps.upgrade.interval_s = 30;
      expect(regles(validerConfiguration(d2))).to.deep.equal(["schema"]);
    });
  });

  describe("entrées hostiles", function () {
    const refuseSchema = (d) => {
      const r = validerConfiguration(d);
      expect(r.valide).to.equal(false);
      expect(regles(r)).to.deep.equal(["schema"]);
    };
    it("un document qui n'est pas un objet, ou vide", function () {
      for (const d of [null, [], "x", 42, {}, true]) refuseSchema(d);
    });
    it("une clé hors schéma, une valeur hors énumération, un type faux", function () {
      const d = exemple();
      d.prix = 1;
      refuseSchema(d);
      const d2 = exemple();
      d2.rfc3161.checkpoints.provider_role = "tiers";
      refuseSchema(d2);
      const d3 = exemple();
      d3.checkpoint_interval_s = "60";
      refuseSchema(d3);
    });
    it("des nombres hors bornes (c_K 5, max_pending 10^8, squat_wait_s 61, fallback 10)", function () {
      for (const muter of [(d) => (d.checkpoint_interval_s = 5), (d) => (d.queue.max_pending = 100000000), (d) => (d.registry.squat_wait_s = 61), (d) => (d.rfc3161.checkpoints.fallback_after_s = 10), (d) => (d.rfc3161.retry.factor = 1.5)]) {
        const d = exemple();
        muter(d);
        refuseSchema(d);
      }
    });
    it("un secret écrit en clair, une URL avec espace, une politique mal formée, un identifiant trop long", function () {
      const d = exemple();
      d.rfc3161.providers[0].auth.secret = { env: "minuscule" };
      refuseSchema(d);
      const d2 = exemple();
      d2.rfc3161.providers[0].url = "https://horodatage principal.example/";
      refuseSchema(d2);
      const d3 = exemple();
      d3.rfc3161.providers[2].policy_oid = "1.3.06.1";
      refuseSchema(d3);
      const d4 = exemple();
      d4.rfc3161.providers[0].id = "x".repeat(65);
      refuseSchema(d4);
    });
    it("une imbrication au-delà de 128 niveaux est refusée par le lecteur strict du noyau avant toute règle", function () {
      let texte = "{\"version\":0,\"profond\":";
      for (let i = 0; i < 140; i++) texte += "[";
      texte += "1";
      for (let i = 0; i < 140; i++) texte += "]";
      texte += "}";
      expect(() => N.analyserJson(Buffer.from(texte))).to.throw();
    });
    it("un texte qui n'est pas de l'UTF-8 bien formé n'est pas une configuration", function () {
      expect(() => N.analyserJson(Buffer.from([0x7b, 0xff, 0xfe, 0x7d]))).to.throw();
    });
    it("un profil inconnu est une erreur d'appel, pas un rapport", function () {
      expect(() => validerConfiguration(exemple(), { profil: "prod" })).to.throw(RangeError);
      expect(PROFILS).to.deep.equal(["developpement", "test", "production"]);
    });
    it("PEM : bloc multiple, base64 non canonique, DER tronqué, BIT STRING manquant", function () {
      const bon = exemple().rfc3161.providers[0].anchor_certificates[0];
      expect(motifCertificatPemIllisible(bon)).to.equal(null);
      expect(motifCertificatPemIllisible(bon + bon)).to.be.a("string");
      const corps = bon.split("\n").slice(1, -2).join("");
      const der = Buffer.from(corps, "base64");
      const tronque = `-----BEGIN CERTIFICATE-----\n${der.subarray(0, der.length - 10).toString("base64")}\n-----END CERTIFICATE-----\n`;
      expect(motifCertificatPemIllisible(tronque)).to.be.a("string");
      const sansSig = Buffer.concat([Buffer.from([0x30, 0x03, 0x30, 0x01, 0x00])]);
      expect(motifCertificatPemIllisible(`-----BEGIN CERTIFICATE-----\n${sansSig.toString("base64")}\n-----END CERTIFICATE-----\n`)).to.be.a("string");
      expect(motifCertificatPemIllisible(42)).to.be.a("string");
    });
  });

  describe("projection d'EX-8.2", function () {
    it("la projection de l'exemple, avec provider_role interne et les deux calendriers d'A.2, est le config de la trace heure-nominale-reference", function () {
      const p = projection(exemple());
      p.rfc3161.checkpoints.provider_role = "interne";
      p.opentimestamps.calendars = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org"];
      const trace = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-5", "planification", "heure-nominale-reference.json"), "utf8"));
      expect(N.jcs(p)).to.equal(N.jcs(trace.config));
      expect(validerProjection(p).valide).to.equal(true);
    });
    it("la projection ne porte ni secret, ni certificat, ni URL, ni source, ni chemin ; qualified est un booléen", function () {
      const texte = JSON.stringify(projection(exemple()));
      expect(texte).to.not.match(/secret|BEGIN CERTIFICATE|https?:\/\/horodatage|\/var\/lib|source|whitelist|retention|crl_capture|headers_source/);
      expect(projection(exemple()).rfc3161.providers.map((p) => p.qualified)).to.deep.equal([true, true, false]);
    });
    it("validerProjection refuse une projection hors de $defs/configuration (clé en trop, borne, énumération)", function () {
      const p = projection(exemple());
      p.queue.path = "/x";
      expect(validerProjection(p).valide).to.equal(false);
      const p2 = projection(exemple());
      p2.rfc3161.providers[0].qualified = "oui";
      expect(validerProjection(p2).valide).to.equal(false);
      expect(() => projection(null)).to.throw(TypeError);
    });
    it("les comptages d'EX-4.11 se lisent sur le document comme sur la projection", function () {
      const d = exemple();
      expect(compterJetons(d).par_an.jetons).to.equal(105120);
      expect(compterJetons(projection(d)).par_heure).to.deep.equal(compterJetons(d).par_heure);
    });
  });
});
