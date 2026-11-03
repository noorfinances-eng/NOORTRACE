// Rejeu des vecteurs de CT-1 (spec/vecteurs/ct-1) par la bibliothèque noyau
// @noortrace/noyau, écrite d'après le seul texte de la spécification.
//
// Chaque famille est rejouée contre son attendu.json : cles, jcs,
// journal-valide et les cinq journaux altérés, merkle (arbres et cohérence),
// manifestes, points-de-controle, dossiers. Chaque fichier lu est noté ; le
// dernier test énumère les fichiers des familles et exige que chacun ait été
// consommé, pour qu'un vecteur ajouté sans test fasse échouer la suite.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { lireRepertoireDossier } from "@noortrace/noyau/dossier-fichiers";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = path.join(RACINE, "spec", "vecteurs", "ct-1");

// Les journaux altérés se comptent sur le disque (journal-* autre que
// journal-valide) : des journaux s'ajoutent d'une révision à l'autre, et
// chacun doit porter evenements.json et attendu.json.
const JOURNAUX_ALTERES = fs
  .readdirSync(V, { withFileTypes: true })
  .filter((e) => e.isDirectory() && e.name.startsWith("journal-") && e.name !== "journal-valide")
  .map((e) => e.name)
  .sort();
const FAMILLES = ["cles", "jcs", "journal-valide", ...JOURNAUX_ALTERES, "merkle", "manifestes", "points-de-controle", "dossiers"];

/** Fichiers de données consommés par les tests, chemins relatifs à V. */
const consommes = new Set();
const noter = (rel) => consommes.add(rel.split(path.sep).join("/"));
const octets = (rel) => {
  noter(rel);
  return Uint8Array.from(fs.readFileSync(path.join(V, rel)));
};
/** Lit un fichier de vecteur avec la lecture stricte du noyau (JCS v0). */
const lire = (rel) => N.analyserJson(octets(rel));
/** Lit un tableau d'événements : un élément sans forme canonique reste lisible (N.lireJournal). */
const lireEvenements = (rel) => N.lireJournal(octets(rel));
const hex = (o) => N.octetsVersHex(o);
const texte = (s) => N.utf8(s);

describe("Noyau : rejeu des vecteurs CT-1", function () {
  const clesJournal = () => lire("journal-valide/cles.json");
  const evenementsValides = () => lire("journal-valide/evenements.json");

  describe("cles/", function () {
    it("cles-test.json : graines, clés publiques, PKCS#8, org_id, journal_id, comptes et nonces se redérivent", function () {
      const t = lire("cles/cles-test.json");
      expect(t.org.org_id).to.equal(hex(N.keccak256(texte(t.org.slug))));
      expect(t.journal.journal_id).to.equal(hex(N.keccak256(texte(t.journal.nom))));
      expect(t.keys).to.have.length(2);
      for (const k of t.keys) {
        const graine = N.sha256(texte(k.seed_label));
        expect(k.seed).to.equal(hex(graine));
        expect(k.private_key_pkcs8_der).to.equal("0x302e020100300506032b657004220420" + k.seed.slice(2));
        expect(k.public_key).to.equal(hex(N.clePubliqueEd25519(graine)));
        expect(N.estHorodatage(k.valid_from)).to.equal(true);
      }
      expect(t.approbateurs.comptes).to.have.length(3);
      for (const c of t.approbateurs.comptes) {
        expect(N.adresseDepuisClePrivee(N.hexVersOctets(c.cle_privee, 32))).to.equal(c.adresse);
      }
      expect(t.approbateurs.seuil).to.deep.equal({ required: 2, size: 3 });
      for (const n of t.nonces) expect(n.nonce).to.equal(N.sha256Hex(texte(n.etiquette)));
    });

    it("cles.json : clés publiques et validités de cles-test.json, exploitable, identique à celui de journal-valide", function () {
      const t = lire("cles/cles-test.json");
      const c = lire("cles/cles.json");
      expect(N.validerSchema("cles", c).valide).to.equal(true);
      const idx = N.indexerCles(c, { org_id: t.org.org_id, journal_id: t.journal.journal_id });
      expect(idx.exploitable, idx.erreurs.join("\n")).to.equal(true);
      for (const k of t.keys) {
        const e = c.keys.find((x) => x.key_id === k.key_id);
        expect(e.public_key).to.equal(k.public_key);
        expect(e.valid_from).to.equal(k.valid_from);
        expect(e.valid_to).to.equal(k.valid_to);
        expect(idx.cles.get(k.key_id).admise).to.equal(true);
      }
      expect(N.egaliteJson(c, clesJournal())).to.equal(true);
    });
  });

  describe("jcs/", function () {
    it("cas-limites.json : forme canonique octet pour octet, ou refus", function () {
      const f = lire("jcs/cas-limites.json");
      expect(f.cas.length).to.be.greaterThan(15);
      for (const c of f.cas) {
        expect(N.canoniserTexte(c.input), c.name).to.equal(c.canonical);
        if (c.canonical !== null) expect(N.jcs(N.analyserJson(c.canonical)), c.name).to.equal(c.canonical);
        else expect(() => N.analyserJson(c.input), c.name).to.throw(N.ErreurJson);
      }
    });
  });

  describe("journal-valide/", function () {
    it("la chaîne de douze événements est valide, sans diagnostic", function () {
      const r = N.verifierJournal(evenementsValides(), clesJournal());
      const a = lire("journal-valide/attendu.json");
      expect(r.diagnostics).to.deep.equal(a.diagnostics);
      expect(r.valide).to.equal(a.valide).and.to.equal(true);
    });

    it("hash, signature, prev_hash, longueur canonique et clé de chaque événement", function () {
      const a = lire("journal-valide/attendu.json");
      const evs = evenementsValides();
      const idx = N.indexerCles(clesJournal(), { org_id: a.org_id, journal_id: a.journal_id });
      expect(evs.map((e) => e.seq)).to.deep.equal(a.hashes.map((h) => h.seq));
      expect(evs[0].seq).to.equal(a.first_seq);
      expect(evs[evs.length - 1].seq).to.equal(a.last_seq);
      a.hashes.forEach((h, i) => {
        const e = evs[i];
        expect(N.validerSchema("evenement", e).erreurs, `seq ${h.seq}`).to.deep.equal([]);
        expect(e.org_id).to.equal(a.org_id);
        expect(e.journal_id).to.equal(a.journal_id);
        expect(e.execution.tool).to.equal(h.tool);
        expect(e.recorder_key_id).to.equal(h.recorder_key_id);
        expect(e.prev_hash).to.equal(h.prev_hash);
        expect(N.hacherEvenement(e)).to.equal(h.hash).and.to.equal(e.hash);
        expect(e.sig).to.equal(h.sig);
        expect(N.utf8(N.formeCanoniqueEvenement(e)).length).to.equal(h.canonical_length);
        expect(N.verifierSignatureEvenement(e, idx.cles.get(e.recorder_key_id).octets)).to.equal(true);
      });
    });

    it("les signatures Ed25519 se reproduisent à l'identique depuis les graines (déterministes)", function () {
      const t = lire("cles/cles-test.json");
      const graines = new Map(t.keys.map((k) => [k.key_id, N.hexVersOctets(k.seed, 32)]));
      for (const e of evenementsValides()) {
        expect(N.scellerEvenement(e, graines.get(e.recorder_key_id))).to.deep.equal(e);
      }
    });

    it("objet d'approbation A, condensé D_A et adresses recouvrées de la décision", function () {
      const a = lire("journal-valide/attendu.json").approbation;
      const decision = evenementsValides().find((e) => e.execution.tool === N.NOMS_RESERVES.DECISION);
      expect(decision.approval.ticket).to.equal(a.ticket);
      expect(N.objetApprobation(decision)).to.deep.equal(a.A);
      const DA = N.condenseApprobation(a.A);
      expect(hex(DA)).to.equal(a.D_A);
      const recouvrees = decision.approval.signatures.map((s) => N.recouvrerAdresseEip191(DA, N.hexVersOctets(s)).adresse);
      expect(recouvrees).to.deep.equal(a.approvers);
      expect(decision.approval.approvers).to.deep.equal(a.approvers);
    });

    it("pieces.json : chaque pièce a son sha256 et sa length, et une référence du journal la désigne", function () {
      const { pieces } = lire("journal-valide/pieces.json");
      const refs = evenementsValides().flatMap((e) => N.referencesEvenement(e).map((x) => x.reference));
      // Une pièce est désignée par une référence, par code.prompt_version, ou par
      // policy_sha256 d'un changement de politique (CT-1 §5.3, §8).
      const empreintes = new Set(
        evenementsValides().flatMap((e) => [e.code.prompt_version, e.execution.arguments.value?.policy_sha256].filter(Boolean)),
      );
      for (const p of pieces) {
        const o = texte(p.texte);
        expect(N.sha256Hex(o), p.nom).to.equal(p.sha256);
        expect(o.length, p.nom).to.equal(p.length);
        const designee = refs.some((r) => N.verifierPiece(r, o)) || empreintes.has(p.sha256);
        expect(designee, p.nom).to.equal(true);
      }
    });
  });

  describe("journaux altérés (table 7.2 de CT-1)", function () {
    it("les cinq journaux de la version 0.2 au moins, chacun avec evenements.json et attendu.json", function () {
      expect(JOURNAUX_ALTERES).to.include.members(["journal-supprime", "journal-modifie", "journal-insere", "journal-insere-sans-cle", "journal-reordonne"]);
      for (const rep of JOURNAUX_ALTERES) {
        for (const f of ["evenements.json", "attendu.json"]) expect(fs.existsSync(path.join(V, rep, f)), `${rep}/${f}`).to.equal(true);
      }
    });

    for (const rep of JOURNAUX_ALTERES) {
      it(`${rep}/ : contrôles en échec, diagnostics et messages exacts`, function () {
        const a = lire(`${rep}/attendu.json`);
        // Un journal peut porter son propre cles.json (journal-cles-autre-organisation).
        const cles = fs.existsSync(path.join(V, rep, "cles.json")) ? lire(`${rep}/cles.json`) : clesJournal();
        const r = N.verifierJournal(lireEvenements(`${rep}/evenements.json`), cles);
        expect(r.valide).to.equal(a.valide).and.to.equal(false);
        expect(r.controles_en_echec).to.deep.equal(a.controles_en_echec);
        expect(r.diagnostics.map(({ type, controle, seq }) => ({ type, controle, seq }))).to.deep.equal(a.diagnostics);
        // Le texte des messages n'est pas normatif (CT-1 §7.2) : un message par symptôme.
        expect(r.diagnostics.map((d) => d.message)).to.have.length(a.messages.length);
      });
    }
  });

  describe("merkle/", function () {
    it("arbres.json : racines, période vide, preuves d'inclusion acceptées et régénérées, preuves altérées refusées", function () {
      const f = lire("merkle/arbres.json");
      const evs = evenementsValides();
      expect(f.periode_vide.root).to.equal(N.ZERO32);
      expect(N.racineMerkle([])).to.equal(N.ZERO32).and.not.to.equal(N.sha256Hex(new Uint8Array(0)));
      expect(f.arbres.map((t) => t.n)).to.deep.equal([0, 1, 2, 3, 5, 8, 12, 1000]);
      let preuves = 0;
      for (const t of f.arbres) {
        expect(t.leaves).to.have.length(t.n);
        if (t.n === 1000) {
          t.leaves.forEach((l, i) => expect(l).to.equal(N.sha256Hex(texte(`noortrace/vecteurs/v0/merkle/feuille/${i}`))));
        } else {
          expect(t.leaves).to.deep.equal(evs.slice(0, t.n).map((e) => e.hash));
        }
        expect(N.racineMerkle(t.leaves), `n = ${t.n}`).to.equal(t.root);
        if (t.n === 0) expect(t.proofs).to.deep.equal([]);
        for (const p of t.proofs) {
          preuves++;
          expect(N.verifierInclusion(p), `n = ${t.n}, m = ${p.leaf_index}`).to.equal(true);
          expect(N.preuveInclusion(p.leaf_index, t.leaves)).to.deep.equal(p);
          if (p.path.length) {
            const altere = { ...p, path: [...p.path] };
            altere.path[0] = "0x" + (altere.path[0][2] === "0" ? "1" : "0") + altere.path[0].slice(3);
            expect(N.verifierInclusion(altere)).to.equal(false);
            expect(N.verifierInclusion({ ...p, path: p.path.slice(0, -1) })).to.equal(false);
            expect(N.verifierInclusion({ ...p, path: [...p.path, p.root] })).to.equal(false);
          }
          expect(N.verifierInclusion({ ...p, leaf_index: p.tree_size })).to.equal(false);
        }
      }
      expect(preuves).to.be.greaterThan(20);
    });

    it("coherence.json : preuves régénérées nœud pour nœud et acceptées, sondes refusées", function () {
      const f = lire("merkle/coherence.json");
      expect(f.leaves).to.deep.equal(evenementsValides().map((e) => e.hash));
      expect(f.cases.length).to.be.greaterThan(15);
      for (const c of f.cases) {
        const r = N.verifierCoherence(c);
        expect(r.valide, c.name).to.equal(c.valid);
        if (c.valid) {
          const D = f.leaves.slice(0, c.second_size);
          expect(N.preuveCoherence(c.first_size, D), c.name).to.deep.equal(c.path);
          expect(N.racineMerkle(f.leaves.slice(0, c.first_size))).to.equal(c.first_root);
          expect(N.racineMerkle(D)).to.equal(c.second_root);
        } else {
          expect(r.raison, c.name).to.be.a("string");
        }
      }
    });
  });

  describe("manifestes/", function () {
    it("trois périodes : forme canonique, periodHash, signature, anchorFingerprint, PeriodMeta, racine et seq", function () {
      const a = lire("manifestes/attendu.json");
      const t = lire("cles/cles-test.json");
      const graines = new Map(t.keys.map((k) => [k.key_id, N.hexVersOctets(k.seed, 32)]));
      const idx = N.indexerCles(clesJournal(), {});
      const evs = evenementsValides();
      expect(a.periodes).to.have.length(3);
      for (const p of a.periodes) {
        const m = lire(`manifestes/${p.fichier}`);
        const sig = lire(`manifestes/${p.fichier.replace(/\.json$/, ".sig")}`);
        expect(N.ecartsManifeste(m), p.fichier).to.deep.equal([]);
        expect(N.formeCanoniqueManifeste(m)).to.equal(p.canonical);
        expect(N.hacherManifeste(m)).to.equal(p.period_hash);
        expect(m.count).to.equal(p.count);
        expect(m.root).to.equal(p.root);
        const periode = evs.filter((e) => e.seq >= m.first_seq && e.seq <= m.last_seq);
        expect(periode.map((e) => e.seq)).to.deep.equal(p.seq);
        expect(N.racineMerkle(periode.map((e) => e.hash))).to.equal(p.root);
        expect(N.validerSchema("manifeste_sig", sig).valide).to.equal(true);
        expect(sig).to.deep.equal({ version: 0, period_hash: p.period_hash, recorder_key_id: p.recorder_key_id, sig: p.sig });
        expect(N.verifierSignatureManifeste(m, sig.sig, idx.cles.get(sig.recorder_key_id).octets)).to.equal(true);
        expect(N.signerManifeste(m, graines.get(m.recorder_key_id))).to.deep.equal(sig);
        expect(N.empreinteAncre(m.org_id, m.journal_id, p.period_hash)).to.equal(p.anchor_fingerprint);
        expect(N.periodMeta(m)).to.deep.equal(p.period_meta);
      }
    });

    it("continuité des périodes consécutives et erreurs exactes du manifeste discontinu (sa signature reste valide)", function () {
      const a = lire("manifestes/attendu.json");
      for (const c of a.continuite) {
        const r = N.verifierContinuite(lire(`manifestes/${c.de}`), lire(`manifestes/${c.a}`));
        expect(r.valide).to.equal(c.valide);
        expect(r.erreurs).to.deep.equal(c.erreurs);
      }
      const d = a.discontinu;
      const m = lire(`manifestes/${d.fichier}`);
      const sig = lire("manifestes/discontinu.sig");
      const r = N.verifierContinuite(lire(`manifestes/${d.precedent}`), m);
      expect(r.valide).to.equal(d.valide).and.to.equal(false);
      expect(r.erreurs).to.deep.equal(d.erreurs);
      const idx = N.indexerCles(clesJournal(), {});
      expect(sig.period_hash).to.equal(N.hacherManifeste(m));
      expect(N.verifierSignatureManifeste(m, sig.sig, idx.cles.get(sig.recorder_key_id).octets)).to.equal(true);
    });
  });

  describe("points-de-controle/", function () {
    it("séries des trois périodes : hachage, forme canonique, chaînage, clé, signature, cohérence vers le manifeste", function () {
      const a = lire("points-de-controle/attendu.json");
      const t = lire("cles/cles-test.json");
      const graines = new Map(t.keys.map((k) => [k.key_id, N.hexVersOctets(k.seed, 32)]));
      const evs = evenementsValides();
      expect(a.periodes).to.have.length(3);
      for (const per of a.periodes) {
        const points = lire(`points-de-controle/${per.file}`);
        const m = lire(path.posix.join("points-de-controle", per.manifest));
        expect(m.period_start).to.equal(per.period_start);
        expect(points).to.have.length(per.count).and.to.have.length(per.points.length);
        const hashes = evs.filter((e) => e.seq >= m.first_seq && e.seq <= m.last_seq).map((e) => e.hash);
        per.points.forEach((x, i) => {
          const p = points[i];
          expect(N.validerSchema("point-de-controle", p).valide).to.equal(true);
          expect(x.index).to.equal(i);
          expect(p.checkpoint_ts).to.equal(x.checkpoint_ts);
          expect(p.tree_size).to.equal(x.tree_size);
          expect(p.last_seq).to.equal(x.last_seq);
          expect(p.key_id).to.equal(x.key_id);
          expect(p.prev_checkpoint_hash).to.equal(x.prev_checkpoint_hash);
          expect(N.formeCanoniquePoint(p)).to.equal(x.canonical);
          expect(N.hacherPoint(p)).to.equal(x.checkpoint_hash);
          expect(p.sig).to.equal(x.sig);
          expect(N.signerPoint(p, graines.get(p.key_id))).to.deep.equal(p);
          expect(N.coherencePoint(p.tree_size, hashes)).to.deep.equal(x.consistency);
          if (x.consistency) expect(N.verifierCoherence(x.consistency).valide).to.equal(true);
        });
        const dernier = points[points.length - 1];
        expect({ tree_size: dernier.tree_size, root: dernier.root, last_seq: dernier.last_seq }).to.deep.equal(per.last);
        const r = N.verifierSeriePointsDeControle(points, m, evs, clesJournal());
        expect(r, per.file).to.deep.equal({ valide: true, rules_failed: [], rules_not_evaluated: [], errors: [] });
      }
    });

    it("séries invalides : règles violées et erreurs exactes", function () {
      const a = lire("points-de-controle/attendu.json");
      // Chaque fichier de invalides/ a son entrée, et inversement.
      const fichiers = fs.readdirSync(path.join(V, "points-de-controle", "invalides")).map((f) => `invalides/${f}`).sort();
      expect(a.invalides.map((x) => x.file).sort()).to.deep.equal(fichiers);
      for (const inv of a.invalides) {
        const r = N.verifierSeriePointsDeControle(
          lire(`points-de-controle/${inv.file}`),
          lire(path.posix.join("points-de-controle", inv.manifest)),
          evenementsValides(),
          clesJournal(),
        );
        expect(r.valide, inv.file).to.equal(false);
        expect(r.rules_failed, inv.file).to.deep.equal(inv.rules_failed);
        // CT-1 §10.5 (révision 0.5) : rules_not_evaluated absent de l'attendu vaut liste vide.
        expect(r.rules_not_evaluated, inv.file).to.deep.equal(inv.rules_not_evaluated ?? []);
        expect(r.errors, inv.file).to.deep.equal(inv.errors);
      }
    });
  });

  describe("points-de-controle/ : evenements_partiels", function () {
    it("la série vérifiée avec une partie des événements (ou sans cles.json) : règles violées, non évaluées et erreurs exactes", function () {
      const a = lire("points-de-controle/attendu.json");
      const cas = a.evenements_partiels ?? [];
      // Chaque fichier de evenements/ est employé par une entrée.
      const rep = path.join(V, "points-de-controle", "evenements");
      const fichiers = fs.existsSync(rep) ? fs.readdirSync(rep).map((f) => `evenements/${f}`).sort() : [];
      expect([...new Set(cas.map((x) => x.events).filter((x) => x !== null && x !== undefined))].sort()).to.deep.equal(fichiers);
      for (const x of cas) {
        const evs = x.events === null || x.events === undefined ? [] : lireEvenements(path.posix.join("points-de-controle", x.events));
        const cles = x.keys === null || x.keys === undefined ? null : lire(path.posix.normalize(path.posix.join("points-de-controle", x.keys)));
        const r = N.verifierSeriePointsDeControle(
          lire(path.posix.join("points-de-controle", x.file)),
          lire(path.posix.normalize(path.posix.join("points-de-controle", x.manifest))),
          evs,
          cles,
        );
        const libelle = `${x.file} avec ${x.events ?? "aucun événement"}, ${x.keys ?? "sans cles.json"}`;
        expect(r.rules_failed, libelle).to.deep.equal(x.rules_failed);
        expect(r.rules_not_evaluated, libelle).to.deep.equal(x.rules_not_evaluated ?? []);
        if (x.errors) expect(r.errors, libelle).to.deep.equal(x.errors);
        expect(r.valide, libelle).to.equal(x.rules_failed.length === 0 && (x.rules_not_evaluated ?? []).length === 0);
      }
    });
  });

  describe("dossiers/", function () {
    const repertoires = fs.readdirSync(path.join(V, "dossiers")).sort();

    it("au moins les soixante-dix dossiers des révisions 0.2 à 0.4, chacun avec son attendu.json", function () {
      expect(repertoires.length).to.be.at.least(70);
      for (const d of repertoires) expect(fs.existsSync(path.join(V, "dossiers", d, "attendu.json")), d).to.equal(true);
    });

    for (const d of repertoires) {
      it(`${d} : verdict, liste exacte des contrôles en échec${d.includes("attestation") || d.startsWith("valide-at") || d.includes("at7") ? ", vérifications AT- et avertissements" : ""}`, function () {
        const rel = path.posix.join("dossiers", d);
        const a = lire(`${rel}/attendu.json`);
        const fichiers = lireRepertoireDossier(path.join(V, rel));
        for (const nom of fichiers.keys()) noter(`${rel}/${nom}`);
        const r = N.verifierDossier(fichiers);
        // Entrée inutilisable (CT-1 §11.5) : exit_code 2 et error_kind, sans verdict.
        if (a.exit_code === 2) {
          expect(r).to.include({ utilisable: false, verdict: null, type_erreur: a.error_kind });
          expect([a.valide, a.controle, a.controles_en_echec]).to.deep.equal([null, null, []]);
          return;
        }
        expect(r.utilisable).to.equal(true);
        expect(r.valide, `${d} : ${JSON.stringify(r.controles.filter((c) => c.statut !== "reussi"))}`).to.equal(a.valide);
        expect(r.verdict).to.equal(a.valide ? "valide" : "invalide");
        expect(r.controles_en_echec).to.deep.equal(a.controles_en_echec);
        if (a.controle !== null) expect(r.controles_en_echec).to.include(a.controle);
        if (a.valide) {
          const index = N.analyserJson(fichiers.get("dossier.json"));
          expect(r.evenement).to.deep.equal(index.event);
          expect(r.non_executes_bloquants).to.deep.equal([]);
          expect(r.borne).to.equal(N.BORNE);
        }
        if ("perimeter_checks" in a) {
          const p = r.perimetre;
          expect(p ? p.verifications.map(({ id, status, reason }) => ({ id, status, reason })) : []).to.deep.equal(a.perimeter_checks);
          expect(p ? p.retenue : null).to.equal(a.perimeter_retained);
          expect(p ? p.avertissements : []).to.deep.equal(a.warnings);
          if (a.perimeter_target !== null) expect(a.perimeter_checks.map((c) => c.id)).to.include(a.perimeter_target);
        } else {
          expect(r.perimetre).to.equal(null);
        }
      });
    }
  });

  // Les dossiers de CT-6 portent des parties réservées que la bibliothèque ne
  // vérifie pas (T-, O-, R-, N-) : seules les vérifications de CT-1 (D-1 à
  // A-4, K-1 à K-9) de leur attendu.json sont comparées, statut et raison.
  // K-7, K-8 et K-9 qu'une ancre non nulle laisse à CT-6 (prerequis_en_echec,
  // détail VERIFICATION_CT6_NON_EXECUTEE) ne sont pas comparées ; une partie réservée
  // présente rend toujours le verdict de la bibliothèque invalide (CT-1 §11.4,
  // révision 0.5).
  describe("dossiers de CT-6 : vérifications de CT-1", function () {
    const V6 = path.join(RACINE, "spec", "vecteurs", "ct-6", "dossiers");
    const ids = N.ORDRE_CONTROLES;
    const repertoires = fs.readdirSync(V6).sort();

    it("au moins soixante-treize dossiers publiés", function () {
      expect(repertoires.length).to.be.at.least(73);
    });

    for (const d of repertoires) {
      it(`${d} : statut et raison de chaque vérification de CT-1`, function () {
        const a = N.analyserJson(Uint8Array.from(fs.readFileSync(path.join(V6, d, "attendu.json"))));
        const r = N.verifierDossier(lireRepertoireDossier(path.join(V6, d)));
        const ct6 = (c) => c.statut === "non_execute" && c.details.includes(N.VERIFICATION_CT6_NON_EXECUTEE);
        expect(r.utilisable).to.equal(a.exit_code !== 2);
        if (!r.utilisable) return;
        const echecs = new Set(a.failed_checks);
        const nonExecutes = new Map(a.not_executed.map((x) => [x.id, x.reason]));
        const ecarts = [];
        for (const c of r.controles) {
          const attendu = echecs.has(c.id) ? "echoue" : nonExecutes.has(c.id) ? `non_execute:${nonExecutes.get(c.id)}` : "reussi";
          const obtenu = c.statut === "non_execute" ? `non_execute:${c.raison}` : c.statut;
          if (["K-7", "K-8", "K-9"].includes(c.id) && ct6(c)) {
            expect(c.raison, c.id).to.equal("prerequis_en_echec");
            continue;
          }
          if (attendu !== obtenu) ecarts.push(`${c.id} : attendu ${attendu}, obtenu ${obtenu}`);
        }
        const rapportes = new Set(r.controles.map((c) => c.id));
        for (const id of [...echecs, ...nonExecutes.keys()]) if (ids.includes(id) && !rapportes.has(id)) ecarts.push(`${id} absent du rapport`);
        expect(ecarts, d).to.deep.equal([]);
        if (!a.valid) expect(r.verdict).to.equal("invalide");
      });
    }
  });

  describe("inventaire", function () {
    it("chaque fichier de données des familles de spec/vecteurs/ct-1 est consommé par un test", function () {
      // Les entrées du répertoire : les familles, l'index et le vérificateur
      // indépendant (code Go, hors du champ de ce rejeu) ; toute autre entrée
      // serait une famille nouvelle sans test.
      const entrees = fs.readdirSync(V).sort();
      expect(entrees).to.deep.equal([...FAMILLES, "INDEX.md", "verificateur-independant"].sort());
      const enumeres = [];
      const parcourir = (rel) => {
        for (const e of fs.readdirSync(path.join(V, rel), { withFileTypes: true })) {
          const r = path.posix.join(rel, e.name);
          if (e.isDirectory()) parcourir(r);
          else enumeres.push(r);
        }
      };
      FAMILLES.forEach(parcourir);
      const nonConsommes = enumeres.filter((f) => !consommes.has(f));
      expect(nonConsommes, "fichiers non consommés").to.deep.equal([]);
      expect(consommes.size).to.equal(enumeres.length);
    });
  });
});
