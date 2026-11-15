// Revue de sécurité interne de l'étape 8 (noyau) : un essai par constat
// de TQ-5 complément f sur @noortrace/noyau, chacun rouge sur le code relu
// (commit cd1d193) et vert après correction.
//
// CT-7 MN-68 : verifierSeriePointsDeControle bornée par les événements fournis,
//           jamais par tree_size (2^53 − 1 jugé en moins d'une seconde) ;
// CT-7 MN-68 : une valeur JSON qui porte un membre « toString » (prototype
//           masqué) ne fait lever aucune exception : statut, jamais TypeError,
//           sur les dix-neuf champs éprouvés par le relecteur, dans
//           verifierDossier, verifierJournal, verifierSeriePointsDeControle et
//           ecartsManifeste ; la garde commune des points d'entrée rend un
//           statut de refus nommé (erreur_interne) pour toute exception
//           résiduelle ;
// CT-6 EX-15.1 : approbations.json de petites valeurs dans sa limite de 16 Mio :
//           au plus 1 024 événements contrôlés un à un, détails bornés,
//           rapport et mémoire bornés, jamais d'arrêt sans rapport ;
// CT-1 A-3 : uniqueItems en temps linéaire (65 535 adresses sous deux
//           secondes) ; A-3 et AV-AT-2 par ensemble ;
// lireJournal refuse un texte qui n'est pas du JSON ;
// lireRepertoireDossier ne lève jamais : ENOTDIR, EACCES deviennent
//           un fichier non lisible, porté par D-2.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { lireRepertoireDossier, verifierRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V1 = path.join(RACINE, "spec", "vecteurs", "ct-1");
const lireV = (rel) => N.analyserJson(Uint8Array.from(fs.readFileSync(path.join(V1, rel))));
const texte = (octets) => Buffer.from(octets).toString("utf8");
const octets = (s) => new TextEncoder().encode(s);
const statut = (r, id) => r.controles.find((c) => c.id === id);

/** Le membre piégé : un objet JSON dont « toString » masque Object.prototype.toString par une valeur non appelable. */
const PIEGE_TEXTE = '{"toString":1}';
const piege = () => N.analyserJson(PIEGE_TEXTE);

/**
 * Dossier de ct-1 dont une partie JSON est réécrite par `mutation` (objet lu
 * par JSON.parse, réécrit par JSON.stringify), le SHA-256 de la partie
 * recalculé dans l'index ; `event.hash` de l'index n'est pas touché.
 */
function dossierMute(nom, fichier, partie, mutation) {
  const base = lireRepertoireDossier(path.join(V1, "dossiers", nom));
  const fichiers = new Map(base);
  const v = JSON.parse(texte(base.get(fichier)));
  mutation(v);
  const o = octets(JSON.stringify(v));
  fichiers.set(fichier, o);
  const index = JSON.parse(texte(base.get("dossier.json")));
  index.parts.find((p) => p.name === partie).sha256 = N.sha256Hex(o);
  fichiers.set("dossier.json", octets(JSON.stringify(index)));
  return fichiers;
}

describe("Noyau : revue de sécurité (étape 8)", function () {
  describe("CT-7 MN-68 : série de points bornée par les événements fournis", function () {
    const manifeste = lireV("manifestes/periode-1.json");
    const cles = lireV("journal-valide/cles.json");
    const evenements = lireV("journal-valide/evenements.json");
    const serie = lireV("points-de-controle/periode-1.json");
    const pointGeant = (tree_size) => ({ ...serie[0], tree_size, root: "0x" + "11".repeat(32), last_seq: manifeste.first_seq + tree_size - 1 });

    it("un point conforme au schéma de tree_size 2^53 − 1 est jugé en moins d'une seconde : root non évaluée (piece_hors_dossier), last_seq violée", function () {
      this.timeout(60000);
      for (const n of [2 ** 31 - 1, Number.MAX_SAFE_INTEGER]) {
        const p = pointGeant(n);
        expect(N.validerSchema("point-de-controle", p).valide, `tree_size ${n} : point conforme au schéma`).to.equal(true);
        const debut = process.hrtime.bigint();
        const r = N.verifierSeriePointsDeControle([p], manifeste, evenements, cles);
        const ms = Number(process.hrtime.bigint() - debut) / 1e6;
        expect(ms, `tree_size ${n} jugé en ${Math.round(ms)} ms`).to.be.below(1000);
        expect(r.valide).to.equal(false);
        expect(r.rules_failed).to.include("last_seq");
        expect(r.rules_failed).to.include("dernier_point");
        expect(r.rules_failed).not.to.include("root");
        expect(r.rules_not_evaluated).to.deep.include({ rule: "root", reason: "piece_hors_dossier" });
      }
    });

    it("la règle root se juge sur les événements fournis : série complète valide ; événement de l'intervalle sans forme canonique, prerequis_en_echec ; événement altéré, root violée", function () {
      expect(N.verifierSeriePointsDeControle(serie, manifeste, evenements, cles)).to.deep.equal({ valide: true, rules_failed: [], rules_not_evaluated: [], errors: [] });
      const sansForme = evenements.map((e) => (e.seq === 3 ? { ...e, execution: { ...e.execution, duration_ms: 1.5 } } : e));
      const rf = N.verifierSeriePointsDeControle(serie, manifeste, sansForme, cles);
      expect(rf.rules_failed).to.deep.equal([]);
      expect(rf.rules_not_evaluated.map((x) => x.rule + "|" + x.reason)).to.include("root|prerequis_en_echec");
      const altere = evenements.map((e) => (e.seq === 3 ? { ...e, intent: "altéré" } : e));
      expect(N.verifierSeriePointsDeControle(serie, manifeste, altere, cles).rules_failed).to.include("root");
      // Un événement d'un autre intervalle (seq 10, période 2) ne compte pas pour la période 1.
      const sans9 = evenements.filter((e) => e.seq !== 9);
      const r9 = N.verifierSeriePointsDeControle(serie, manifeste, sans9, cles);
      expect(r9.rules_failed).to.deep.equal([]);
      expect(r9.rules_not_evaluated).to.deep.equal([{ rule: "root", reason: "piece_hors_dossier" }, { rule: "last_hash", reason: "piece_hors_dossier" }]);
    });
  });

  describe("CT-7 MN-68 : membre toString piégé, statut et jamais exception (cause S-2)", function () {
    const P = PIEGE_TEXTE;
    // Les dix-neuf champs du relecteur (travail-f/f02b-sites.mjs), avec le contrôle visé.
    const CAS = [
      ["evenement.hash", "evenement.json", "evenement", (e) => (e.hash = piege()), ["D-1", "E-1", "E-7"]],
      ["evenement.ts", "evenement.json", "evenement", (e) => (e.ts = piege()), ["E-1", "C-1"]],
      ["evenement.prev_hash", "evenement.json", "evenement", (e) => (e.prev_hash = piege()), ["E-1", "C-2"]],
      ["evenement.recorder_key_id", "evenement.json", "evenement", (e) => (e.recorder_key_id = piege()), ["E-1", "E-8", "C-3"]],
      ["evenement.policy.decision", "evenement.json", "evenement", (e) => (e.policy.decision = piege()), ["E-1", "E-3"]],
      ["evenement.execution.status", "evenement.json", "evenement", (e) => (e.execution.status = piege()), ["E-1", "E-3"]],
      ["evenement.approval.approvers[0]", "evenement.json", "evenement", (e) => (e.approval.approvers[0] = piege()), ["E-1", "E-9"]],
      ["evenement.approval.ticket", "evenement.json", "evenement", (e) => (e.approval.ticket = piege()), ["E-1", "E-5"]],
      ["evenement.intent.sha256 (référence en ligne)", "evenement.json", "evenement", (e) => (e.intent = { sha256: piege(), length: 1, redacted: false, value: 1 }), ["E-1", "E-6"]],
      ["voisins.previous.ts", "voisins.json", "voisins", (v) => (v.previous.ts = piege()), ["E-1", "C-1"]],
      ["voisins.previous.recorder_key_id", "voisins.json", "voisins", (v) => (v.previous.recorder_key_id = piege()), ["E-1", "C-3"]],
      ["voisins.next.prev_hash", "voisins.json", "voisins", (v) => (v.next.prev_hash = piege()), ["E-1", "C-2"]],
      ["manifeste.period_end", "manifeste.json", "manifeste", (m) => (m.period_end = piege()), ["P-1"]],
      ["manifeste.count", "manifeste.json", "manifeste", (m) => (m.count = piege()), ["P-1"]],
      ["manifeste.recorder_key_id", "manifeste.json", "manifeste", (m) => (m.recorder_key_id = piege()), ["P-1", "P-5"]],
      ["manifeste.generated_at", "manifeste.json", "manifeste", (m) => (m.generated_at = piege()), ["P-1", "P-5"]],
      ["manifeste.sig.recorder_key_id", "manifeste.sig", "manifeste_sig", (s) => (s.recorder_key_id = piege()), ["P-5"]],
      ["approbations.events[0].execution.tool", "approbations.json", "approbations", (a) => (a.events[0].execution.tool = piege()), ["E-1", "A-2"]],
      [
        "rotation : execution.arguments.value.new_key_id",
        "evenement.json",
        "evenement",
        (e) => {
          e.execution.tool = "noortrace.journal.rotation-cle";
          e.execution.arguments = { sha256: "0x", length: 0, redacted: false, value: { journal_id: 1, new_key_id: piege(), new_public_key: 1, old_key_id: "a", org_id: 1, valid_from: "x", counter_sig: 1 } };
        },
        ["E-1", "E-3", "E-10"],
      ],
    ];

    for (const [nom, fichier, partie, mutation, vises] of CAS) {
      it(`verifierDossier, ${nom} = ${P} : rapport invalide, ${vises.join(", ")} en échec, aucune exception`, function () {
        const fichiers = dossierMute("valide-seq-7", fichier, partie, mutation);
        let r;
        expect(() => (r = N.verifierDossier(fichiers))).not.to.throw();
        expect(r.utilisable).to.equal(true);
        expect(r.type_erreur).to.equal(null);
        expect(r.verdict).to.equal("invalide");
        for (const id of vises) expect(r.controles_en_echec, nom).to.include(id);
        // Aucun détail n'écrit « [object Object] » : la valeur lue est montrée en JSON.
        for (const c of r.controles) for (const d of c.details) expect(d).not.to.include("[object Object]");
      });
    }

    it("verifierJournal : hash de seq 2 piégé, symptômes schema (E-1) et modification (E-7), chaîne intacte (le hash recalculé ne lit pas hash), aucune exception", function () {
      const evts = lireV("journal-valide/evenements.json");
      const cles = lireV("journal-valide/cles.json");
      const piegee = evts.map((e) => (e.seq === 2 ? { ...e, hash: piege() } : e));
      let r;
      expect(() => (r = N.verifierJournal(piegee, cles))).not.to.throw();
      expect(r.valide).to.equal(false);
      expect(r).not.to.have.property("erreur_interne");
      expect(r.controles_en_echec).to.deep.equal(["E-1", "E-7"]);
      expect(r.diagnostics.map((d) => [d.type, d.seq])).to.deep.equal([["schema", 2], ["modification", 2]]);
      for (const d of r.diagnostics) expect(d.message).not.to.include("[object Object]");
      expect(r.diagnostics[1].message).to.include(PIEGE_TEXTE);
      // Le prev_hash de seq 3 piégé (il entre dans le hash et la signature) : E-1, E-7, E-8 et rupture (C-2), aucune exception.
      const rupture = evts.map((e) => (e.seq === 3 ? { ...e, prev_hash: piege() } : e));
      const r2 = N.verifierJournal(rupture, cles);
      expect(r2.controles_en_echec).to.deep.equal(["E-1", "E-7", "E-8", "C-2"]);
      expect(r2.diagnostics.find((d) => d.type === "rupture").message).to.include(PIEGE_TEXTE);
    });

    it("verifierSeriePointsDeControle et ecartsManifeste : tree_size, period_end piégés, écarts nommés, aucune exception", function () {
      const m = lireV("manifestes/periode-1.json");
      const cles = lireV("journal-valide/cles.json");
      let r;
      expect(() => (r = N.verifierSeriePointsDeControle([N.analyserJson(`[{"tree_size":${P}}]`)[0]], m, [], cles))).not.to.throw();
      expect(r.valide).to.equal(false);
      expect(r.rules_failed).to.include.members(["period_start", "dernier_point"]);
      let ecarts;
      expect(() => (ecarts = N.ecartsManifeste({ ...m, period_end: piege() }))).not.to.throw();
      expect(ecarts.some((e) => e.includes("period_end"))).to.equal(true);
      expect(ecarts.join("\n")).not.to.include("[object Object]");
    });

    it("montrer : un objet ou un tableau lu s'écrit en JSON, jamais par toString ; une chaîne telle quelle, un nombre par son texte, undefined « absent »", function () {
      expect(N.montrer(piege())).to.equal(PIEGE_TEXTE);
      expect(N.montrer([piege()])).to.equal(`[${PIEGE_TEXTE}]`);
      expect(N.montrer({ valueOf: 1, toString: 1 })).to.equal('{"valueOf":1,"toString":1}');
      expect(N.montrer({ toJSON: 1 })).to.equal('{"toJSON":1}');
      expect(N.montrer("rec-test-01")).to.equal("rec-test-01");
      expect(N.montrer(7)).to.equal("7");
      expect(N.montrer(true)).to.equal("true");
      expect(N.montrer(null)).to.equal("null");
      expect(N.montrer(undefined)).to.equal("absent");
      expect(N.montrer(1n)).to.equal("(bigint)");
      expect(N.descriptionErreur(new TypeError("x"))).to.equal("TypeError : x");
      expect(N.descriptionErreur(piege())).to.equal(PIEGE_TEXTE);
    });

    it("garde des points d'entrée : une exception résiduelle devient un refus nommé erreur_interne, jamais une exception ni un verdict", function () {
      const base = lireRepertoireDossier(path.join(V1, "dossiers", "valide-seq-7"));
      const fichiers = Object.fromEntries(base);
      Object.defineProperty(fichiers, "voisins.json", { enumerable: true, get() { throw new Error("lecture piégée"); } });
      let r;
      expect(() => (r = N.verifierDossier(fichiers))).not.to.throw();
      expect(r).to.include({ utilisable: false, type_erreur: "erreur_interne", verdict: null, valide: null });
      expect(r.erreur).to.include("lecture piégée");
      const cles = lireV("journal-valide/cles.json");
      const hostile = { get seq() { throw new Error("accès piégé"); } };
      let j;
      expect(() => (j = N.verifierJournal([hostile], cles))).not.to.throw();
      expect(j.valide).to.equal(false);
      expect(j.erreur_interne).to.include("accès piégé");
      let s;
      expect(() => (s = N.verifierSeriePointsDeControle([hostile], lireV("manifestes/periode-1.json"), [], cles))).not.to.throw();
      expect(s.valide).to.equal(false);
      expect(s.erreur_interne).to.include("accès piégé");
      const partie = fs.readFileSync(path.join(V1, "dossiers", "valide-seq-12-attestation-inscrite", "attestation-perimetre.json"));
      let a;
      expect(() => (a = N.verifierPartieAttestation(Uint8Array.from(partie), { evenement: { get org_id() { throw new Error("événement piégé"); } }, indexCles: null, approbations: null }))).not.to.throw();
      expect(a.retenue).to.equal(false);
      expect(a.verifications[0]).to.include({ id: "AT-1", status: "echoue" });
      expect(a.verifications[0].details.join(" ")).to.include("événement piégé");
    });
  });

  describe("CT-6 EX-15.1 : approbations.json de petites valeurs, mémoire et rapport bornés", function () {
    /** Dossier valide-seq-7 dont approbations.json est réécrit avec events = [0,0,…] jusqu'à `octetsVises` octets. */
    function dossierApprobations(octetsVises) {
      const base = lireRepertoireDossier(path.join(V1, "dossiers", "valide-seq-7"));
      const fichiers = new Map(base);
      const a = JSON.parse(texte(base.get("approbations.json")));
      const { events: _e, ...reste } = a;
      const tete = JSON.stringify({ ...reste, events: [] }).slice(0, -2);
      const n = Math.floor((octetsVises - tete.length - 2) / 2);
      const o = octets(tete + "0,".repeat(n - 1) + "0]}");
      fichiers.set("approbations.json", o);
      const index = JSON.parse(texte(base.get("dossier.json")));
      index.parts.find((p) => p.name === "approbations").sha256 = N.sha256Hex(o);
      fichiers.set("dossier.json", octets(JSON.stringify(index)));
      return { fichiers, n };
    }

    it("1 Mio (524 099 éléments) : verdict invalide (E-1, A-1, A-2), au plus 1 024 événements contrôlés, détails bornés (DETAILS_MAX puis « … et n autres »)", function () {
      this.timeout(60000);
      const { fichiers } = dossierApprobations(1048576);
      const r = N.verifierDossier(fichiers);
      expect(r.utilisable).to.equal(true);
      expect(r.verdict).to.equal("invalide");
      expect(r.controles_en_echec).to.include.members(["E-1", "A-1", "A-2"]);
      for (const c of r.controles) expect(c.details.length, c.id).to.be.at.most(N.DETAILS_MAX + 1);
      const e1 = statut(r, "E-1");
      expect(e1.details.length).to.equal(N.DETAILS_MAX + 1);
      expect(e1.details[N.DETAILS_MAX]).to.match(/^… et \d+ autre/);
      // Les éléments au-delà de la borne ne sont pas contrôlés un à un : aucun détail d'E-1 ne cite events[1024] ou plus.
      expect(e1.details.some((d) => /events\[(102[4-9]|10[3-9]\d|1[1-9]\d\d|[2-9]\d{3,}|\d{5,})\]/.test(d))).to.equal(false);
      expect(statut(r, "A-2").details.join("\n")).to.include(String(N.EVENEMENTS_MAX_APPROBATIONS));
      expect(JSON.stringify(r).length).to.be.below(1048576);
    });

    it("16 Mio (la limite de la partie) : jugé sous 512 Mo de tas supplémentaire, rapport de moins de 1 Mo, jamais d'arrêt", function () {
      this.timeout(120000);
      const { fichiers, n } = dossierApprobations(16 * 1024 * 1024);
      expect(n).to.be.above(8_000_000);
      if (typeof globalThis.gc === "function") globalThis.gc();
      const avant = process.memoryUsage().heapUsed;
      const r = N.verifierDossier(fichiers);
      const apres = process.memoryUsage().heapUsed;
      expect(r.verdict).to.equal("invalide");
      expect(r.controles_en_echec).to.include.members(["E-1", "A-1", "A-2"]);
      expect(apres - avant, `tas supplémentaire ${Math.round((apres - avant) / 1048576)} Mo`).to.be.below(512 * 1048576);
      expect(JSON.stringify(r).length).to.be.below(1048576);
    });

    it("1 025 décisions : A-1 (schéma) et A-2 en échec, les 1 024 premières contrôlées une à une, la 1 025e non contrôlée ; 1 024 décisions : toutes contrôlées", function () {
      this.timeout(60000);
      const base = lireRepertoireDossier(path.join(V1, "dossiers", "valide-seq-7"));
      const a = JSON.parse(texte(base.get("approbations.json")));
      const decision = a.events[0];
      const avec = (k) => {
        const fichiers = new Map(base);
        const o = octets(JSON.stringify({ ...a, events: Array.from({ length: k }, () => decision) }));
        fichiers.set("approbations.json", o);
        const index = JSON.parse(texte(base.get("dossier.json")));
        index.parts.find((p) => p.name === "approbations").sha256 = N.sha256Hex(o);
        fichiers.set("dossier.json", octets(JSON.stringify(index)));
        return N.verifierDossier(fichiers);
      };
      const r1024 = avec(1024);
      expect(r1024.controles_en_echec).to.deep.equal([]);
      const r1025 = avec(1025);
      expect(r1025.controles_en_echec).to.deep.equal(["A-1", "A-2"]);
      expect(statut(r1025, "A-2").details.join("\n")).to.include("1025");
    });
  });

  describe("CT-1 A-3 : uniqueItems et appartenance en temps linéaire", function () {
    const adresses = (n) => Array.from({ length: n }, (_, k) => "0x" + k.toString(16).padStart(40, "0"));

    it("jeu de 65 535 adresses distinctes validé en moins de deux secondes ; un doublon toujours refusé, quel que soit l'ordre des membres d'un objet", function () {
      this.timeout(200000);
      const membres = adresses(65535);
      const debut = process.hrtime.bigint();
      const r = N.validerSchema("jeu-approbateurs", { threshold: { required: 1, size: 65535 }, members: membres, source: "essai" });
      const ms = Number(process.hrtime.bigint() - debut) / 1e6;
      expect(r.valide, r.erreurs[0]).to.equal(true);
      expect(ms, `${Math.round(ms)} ms`).to.be.below(2000);
      const double = [...membres.slice(0, 65534), membres[7]];
      const rd = N.validerSchema("jeu-approbateurs", { threshold: { required: 1, size: 65535 }, members: double, source: "essai" });
      expect(rd.valide).to.equal(false);
      expect(rd.erreurs.some((e) => e.includes("uniqueItems"))).to.equal(true);
      // Clés d'un objet dans un autre ordre : même valeur JSON (égalité membre à membre).
      const cles = lireV("journal-valide/cles.json");
      const [k1] = cles.keys;
      const permutee = Object.fromEntries(Object.entries(k1).reverse());
      const rk = N.validerSchema("cles", { ...cles, keys: [k1, permutee] });
      expect(rk.valide).to.equal(false);
      expect(rk.erreurs.some((e) => e.includes("uniqueItems"))).to.equal(true);
      // Les erreurs d'une validation sont bornées (DETAILS_MAX), le verdict reste faux.
      const rm = N.validerSchema("jeu-approbateurs", { threshold: { required: 1, size: 3 }, members: Array.from({ length: 5000 }, () => 0), source: "essai" });
      expect(rm.valide).to.equal(false);
      expect(rm.erreurs.length).to.equal(N.DETAILS_MAX + 1);
    });

    it("A-3 : 65 535 approbateurs distincts, aucun membre d'un jeu de 65 535, jugés en moins de deux secondes (appartenance par ensemble)", function () {
      this.timeout(200000);
      const base = lireRepertoireDossier(path.join(V1, "dossiers", "valide-seq-7"));
      const fichiers = new Map(base);
      const poserPartie = (fichier, partie, v) => {
        const o = octets(JSON.stringify(v));
        fichiers.set(fichier, o);
        const index = JSON.parse(texte(fichiers.get("dossier.json")));
        index.parts.find((p) => p.name === partie).sha256 = N.sha256Hex(o);
        fichiers.set("dossier.json", octets(JSON.stringify(index)));
      };
      const a = JSON.parse(texte(base.get("approbations.json")));
      poserPartie("approbations.json", "approbations", { ...a, approver_set: { ...a.approver_set, members: adresses(65535), threshold: { required: 2, size: 65535 } } });
      const e = JSON.parse(texte(base.get("evenement.json")));
      const etrangers = Array.from({ length: 65535 }, (_, k) => "0xff" + k.toString(16).padStart(38, "0"));
      poserPartie("evenement.json", "evenement", { ...e, approval: { ...e.approval, approvers: etrangers } });
      const debut = process.hrtime.bigint();
      const r = N.verifierDossier(fichiers);
      const ms = Number(process.hrtime.bigint() - debut) / 1e6;
      expect(ms, `${Math.round(ms)} ms`).to.be.below(2000);
      expect(r.verdict).to.equal("invalide");
      const a3 = statut(r, "A-3");
      expect(a3.statut).to.equal("echoue");
      expect(a3.details.filter((d) => d.includes("n'est pas membre du jeu déclaré")).length).to.equal(N.DETAILS_MAX);
      expect(a3.details.length).to.equal(N.DETAILS_MAX + 1);
    });
  });

  describe("lireJournal n'accepte qu'un texte JSON", function () {
    it("un fermant étranger entre deux éléments est une erreur de syntaxe, comme pour analyserJson ; un journal valide se lit toujours", function () {
      for (const t of ['[{"a":1}}{"b":2}]', "[1}2]", '[{"a":1}}]', "[1]]", "[1,]", "[,1]", "[1 2]"]) {
        expect(() => N.analyserJson(t), t).to.throw(N.ErreurJson).with.property("code", "syntaxe");
        expect(() => N.lireJournal(t), t).to.throw(N.ErreurJson).with.property("code", "syntaxe");
      }
      expect(N.lireJournal('[{"a":1},{"b":2}]')).to.deep.equal([{ a: 1 }, { b: 2 }]);
      expect(N.lireJournal(" [ 1 , [2,3] , {\"c\":[4]} ] ")).to.deep.equal([1, [2, 3], { c: [4] }]);
      expect(N.lireJournal("[]")).to.deep.equal([]);
      const evts = N.lireJournal(Uint8Array.from(fs.readFileSync(path.join(V1, "journal-valide", "evenements.json"))));
      expect(evts.length).to.equal(12);
      // Un élément sans forme canonique reste lisible et marqué (révision 0.5).
      const [x] = N.lireJournal('[{"duration_ms":530.0}]');
      expect(N.formeCanoniqueAbsente(x)).to.be.a("string");
    });
  });

  describe("lireRepertoireDossier ne lève jamais une erreur d'ouverture", function () {
    it("ENOTDIR (un composant du chemin est un fichier) : aucun fichier lu, entrée inutilisable (dossier_illisible), aucune exception", function () {
      const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noyau-revue-"));
      try {
        const fichier = path.join(rep, "pas-un-repertoire");
        fs.writeFileSync(fichier, "x");
        let lus;
        expect(() => (lus = lireRepertoireDossier(fichier))).not.to.throw();
        expect(lus.size).to.equal(N.FICHIERS_DOSSIER.length);
        for (const v of lus.values()) expect(v).to.deep.equal({ taille: null, sha256: null, erreur: "ENOTDIR" });
        const r = verifierRepertoireDossier(fichier);
        expect(r).to.include({ utilisable: false, type_erreur: "dossier_illisible" });
        expect(r.erreur).to.include("ENOTDIR");
      } finally {
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });

    it("EACCES (partie sans droit de lecture, essai joué sans privilège) : D-2 en échec avec le code d'erreur, le reste du dossier vérifié, aucune exception", function () {
      this.timeout(30000);
      const rep = fs.mkdtempSync(path.join(os.tmpdir(), "noyau-revue-"));
      try {
        const dossier = path.join(rep, "dossier");
        fs.mkdirSync(dossier, { mode: 0o755 });
        const source = path.join(V1, "dossiers", "valide-seq-7");
        for (const nom of fs.readdirSync(source)) fs.copyFileSync(path.join(source, nom), path.join(dossier, nom));
        fs.chmodSync(dossier, 0o755);
        fs.chmodSync(path.join(dossier, "cles.json"), 0o000);
        const script = path.join(rep, "essai.mjs");
        fs.writeFileSync(
          script,
          `import { verifierRepertoireDossier } from ${JSON.stringify(path.join(RACINE, "paquets", "noyau", "src", "dossier-fichiers.mjs"))};\n` +
            `let sortie;\n` +
            `try { const r = verifierRepertoireDossier(process.argv[2]); sortie = { utilisable: r.utilisable, verdict: r.verdict, en_echec: r.controles_en_echec, d2: r.controles.find((c) => c.id === "D-2") }; }\n` +
            `catch (e) { sortie = { exception: String(e) }; }\n` +
            `process.stdout.write(JSON.stringify(sortie));\n`,
        );
        // Sous root, la lecture est jouée par l'utilisateur « nobody », pour qui le mode 000 vaut EACCES.
        const options = { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] };
        if (typeof process.getuid === "function" && process.getuid() === 0) {
          fs.chmodSync(rep, 0o755);
          fs.chmodSync(script, 0o644);
          options.uid = 65534;
          options.gid = 65534;
        }
        const sortie = execFileSync(process.execPath, [script, dossier], options);
        const r = JSON.parse(sortie);
        expect(r.exception, "exception levée par verifierRepertoireDossier").to.equal(undefined);
        expect(r.utilisable).to.equal(true);
        expect(r.verdict).to.equal("invalide");
        expect(r.en_echec).to.include("D-2");
        expect(r.d2.details.join("\n")).to.include("cles.json");
        expect(r.d2.details.join("\n")).to.include("EACCES");
      } finally {
        fs.chmodSync(path.join(rep, "dossier", "cles.json"), 0o644);
        fs.rmSync(rep, { recursive: true, force: true });
      }
    });
  });
});
