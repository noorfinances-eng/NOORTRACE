// Planificateur d'ancrage (CT-5 §8, lot C) : rejeu des vingt-quatre traces
// normatives de spec/vecteurs/ct-5/planification (EX-8.16, AN-42) et des
// files de spec/vecteurs/ct-5/reprise (EX-8.5 règles 3 et 6, EX-8.12, AN-33).
// Chaque trace est validée contre le schéma planificateur-ancrage-v0, rejouée
// par `rejouerTrace`, et `expected` comme `queue_after` doivent être rendus à
// l'identique (égalité des formes canoniques JCS v0, action par action, dans
// l'ordre). Les invariants AN-32 (ligne `envoyee` avant l'envoi), AN-34
// (transitions d'EX-8.3), AN-35 (échéances), AN-36 (ordre des ancres), AN-37
// (attentes), AN-43 (aucun secret) sont vérifiés sur les actions produites.
// Aucun essai n'exige le réseau.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import {
  rejouerTrace, comparerTrace, creerPlanificateur, noncesVecteurs, FileDurable, lireFiles, trierDemandes, REGISTRE_ANCRAGE, ID_SCHEMA_PLANIFICATEUR,
  requeteTimeStampReq, ETATS_FINAUX,
} from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CT5 = path.join(RACINE, "spec", "vecteurs", "ct-5");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(CT5, ...p), "utf8"));
const lignesNdjson = (...p) => fs.readFileSync(path.join(CT5, ...p), "utf8").split("\n").filter(Boolean);

const TRACES = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json")).sort();

/** Transitions admises par EX-8.3, par état de départ. */
const TRANSITIONS = {
  a_envoyer: ["envoyee", "remplacee", "attente_registre"],
  attente_registre: ["envoyee", "remplacee"],
  envoyee: ["obtenue", "en_attente", "a_reprendre", "envoyee", "a_envoyer", "refusee", "remplacee"],
  a_reprendre: ["envoyee", "remplacee", "a_reprendre"],
  en_attente: ["complete", "en_attente"],
  obtenue: ["a_reprendre"],
  complete: [],
  sans_objet: [],
  refusee: [],
  remplacee: [],
};

describe("ancrage, planificateur : traces normatives de CT-5 §8.10", function () {
  this.timeout(60000);

  it("vingt-quatre traces sont publiées (révision 0.6 de CT-5 : file-fenetre-32 et file-fenetre-32-redemarrage en plus), toutes conformes à la racine du schéma planificateur-ancrage-v0", function () {
    expect(TRACES).to.have.lengthOf(24);
    for (const f of TRACES) {
      const v = REGISTRE_ANCRAGE.valider(ID_SCHEMA_PLANIFICATEUR, lire("planification", f));
      expect(v.valide, `${f} : ${v.erreurs[0]}`).to.equal(true);
    }
  });

  for (const f of TRACES) {
    describe(f, function () {
      const trace = lire("planification", f);
      let r;
      before(function () {
        r = rejouerTrace(trace);
      });

      it("rend `expected` à l'identique, action par action (AN-42)", function () {
        const ecarts = comparerTrace(trace.expected, r.actions, "expected");
        expect(ecarts, JSON.stringify(ecarts.slice(0, 2), null, 1)).to.have.lengthOf(0);
        expect(r.actions.map((a) => N.jcs(a))).to.deep.equal(trace.expected.map((a) => N.jcs(a)));
      });

      it("rend `queue_after` à l'identique, rangée par created_at puis id (AN-42)", function () {
        expect(r.file.map((d) => N.jcs(d))).to.deep.equal(trace.queue_after.map((d) => N.jcs(d)));
        expect(r.conforme).to.equal(true);
      });

      it("est déterministe : un second rejeu rend les mêmes octets", function () {
        const r2 = rejouerTrace(trace);
        expect(N.jcs(r2.actions)).to.equal(N.jcs(r.actions));
        expect(N.jcs(r2.file)).to.equal(N.jcs(r.file));
      });

      it("chaque envoyer_rfc3161 porte le SHA-256 et la taille de la TimeStampReq d'EX-5.1 reconstruite (EX-8.6)", function () {
        const envois = r.actions.filter((a) => a.action === "envoyer_rfc3161");
        for (const a of envois) {
          const q = requeteTimeStampReq({ imprint: a.detail.digest, nonce: a.detail.nonce, policy_oid: a.detail.policy_oid });
          expect(q.sha256).to.equal(a.detail.request_sha256);
          expect(q.taille).to.equal(a.detail.request_size);
          expect(q.taille).to.be.within(69, 82);
        }
      });

      it("AN-32 : toute action d'envoi est précédée, au même instant, de la ligne `envoyee` (ou `en_attente`) de la demande", function () {
        r.actions.forEach((a, i) => {
          if (!["envoyer_rfc3161", "soumettre_ots", "mettre_a_niveau_ots", "envoyer_registre"].includes(a.action)) return;
          const attendu = a.action === "mettre_a_niveau_ots" ? "en_attente" : "envoyee";
          const precedentes = r.actions.slice(0, i).filter((x) => x.request_id === a.request_id && x.t === a.t && x.action === "ecrire_file");
          const dernier = precedentes[precedentes.length - 1];
          const renvoi = a.action === "envoyer_registre" && r.actions.slice(0, i).some((x) => x.request_id === a.request_id && x.t === a.t && x.action === "journaliser" && x.detail.event === "anchor_retry");
          if (renvoi) return;
          expect(dernier, `${f} #${i} ${a.action} ${a.request_id}`).to.not.equal(undefined);
          expect(dernier.detail.state).to.equal(attendu);
        });
      });

      it("AN-34 : les transitions d'état suivent la table d'EX-8.3 ; aucun jeton_periode dans un état final autre qu'obtenue", function () {
        const etats = new Map(trace.queue_before.map((d) => [d.id, d.state]));
        for (const a of r.actions) {
          if (a.action !== "ecrire_file") continue;
          const avant = etats.get(a.request_id);
          if (avant !== undefined && avant !== a.detail.state) {
            expect(TRANSITIONS[avant], `${avant} → ${a.detail.state} (${a.request_id})`).to.include(a.detail.state);
          }
          etats.set(a.request_id, a.detail.state);
        }
        for (const d of r.file) if (d.kind === "jeton_periode" && ETATS_FINAUX.includes(d.state)) expect(d.state).to.equal("obtenue");
        for (const d of r.file) if (d.state === "remplacee") expect(d.replaced_by).to.be.a("string");
        for (const d of r.file) if (d.state === "obtenue" || d.state === "complete") expect(d.result).to.be.an("object");
      });

      it("AN-36 : un jeton_periode ne part qu'après l'inclusion de son ancre ; un jeton_point part au plus squat_wait_s après son admission", function () {
        const inclusions = new Map();
        for (const e of trace.inputs) if (e.type === "inclusion_registre") inclusions.set(e.data.request_id, e.t);
        for (const a of r.actions) {
          if (a.action !== "envoyer_rfc3161" || !a.request_id.startsWith("jeton_periode") || a.detail.attempt !== 1) continue;
          const ancre = `ancre_registre_periode:${a.request_id.split(":")[1]}`;
          const inclusion = inclusions.get(ancre) ?? trace.queue_before.find((d) => d.id === ancre && d.state === "obtenue")?.result?.obtained_at;
          expect(inclusion, a.request_id).to.not.equal(undefined);
          expect(a.t >= inclusion).to.equal(true);
        }
        const creations = new Map();
        for (const a of r.actions) if (a.action === "ecrire_file" && a.request_id.startsWith("jeton_point") && !creations.has(a.request_id)) creations.set(a.request_id, a.t);
        for (const a of r.actions) {
          if (a.action !== "envoyer_rfc3161" || !a.request_id.startsWith("jeton_point") || a.detail.attempt !== 1) continue;
          const creation = creations.get(a.request_id) ?? trace.queue_before.find((d) => d.id === a.request_id)?.created_at;
          const delai = N.decoderHorodatage(a.t) - N.decoderHorodatage(creation);
          expect(delai).to.be.at.most(trace.config.registry.squat_wait_s * 1000 + Math.max(0, N.decoderHorodatage(trace.inputs[0].t) - N.decoderHorodatage(creation)));
        }
      });

      it("AN-43 : aucune action ne porte un jeton, une pièce, un secret ni une adresse de compte", function () {
        const texte = JSON.stringify(r.actions) + JSON.stringify(r.file);
        expect(texte).to.not.match(/password|secret|-----BEGIN|Authorization|0x[0-9a-f]{40}(?![0-9a-f])/i);
        for (const a of r.actions) {
          if (a.action === "stocker") expect(Object.keys(a.detail).sort()).to.deep.equal(["bound", "sha256", "size"]);
          if (a.action === "journaliser") expect(JSON.stringify(a.detail).length).to.be.below(2048);
        }
      });
    });
  }

  describe("files de reprise (EX-8.5, EX-8.12, AN-33)", function () {
    const REPRISES = fs.readdirSync(path.join(CT5, "reprise")).filter((f) => f.endsWith(".avant.ndjson")).map((f) => f.replace(".avant.ndjson", "")).sort();
    let dir;
    before(function () {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-planificateur-reprise-"));
    });
    after(function () {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("sept traces ont une file avant et après (révision 0.6 : file-fenetre-32-redemarrage en plus)", function () {
      expect(REPRISES).to.have.lengthOf(7);
    });

    for (const nom of REPRISES) {
      it(`${nom} : la file .avant relue par lireFiles est queue_before, la file écrite par FileDurable après la trace est .apres`, function () {
        const trace = lire("planification", `${nom}.json`);
        const rep = path.join(dir, nom);
        fs.mkdirSync(rep, { recursive: true });
        fs.copyFileSync(path.join(CT5, "reprise", `${nom}.avant.ndjson`), path.join(rep, "file-1.ndjson"));
        const relue = lireFiles(rep);
        expect(relue.tronquees).to.deep.equal([]);
        expect(relue.demandes.map((d) => N.jcs(d))).to.deep.equal(trace.queue_before.map((d) => N.jcs(d)));
        // La file durable d'une seconde époque reçoit chaque ligne écrite par le planificateur.
        const file = FileDurable.ouvrir({ repertoire: rep, epoque: 2 });
        const planificateur = creerPlanificateur(trace.config, { gigues: trace.jitter_ms, nonces: noncesVecteurs(), fileInitiale: relue.demandes, file });
        const actions = [];
        for (const e of trace.inputs) actions.push(...planificateur.traiter(e));
        file.fermer();
        expect(actions.map((a) => N.jcs(a))).to.deep.equal(trace.expected.map((a) => N.jcs(a)));
        const ecritures = actions.filter((a) => a.action === "ecrire_file").length;
        expect(file.lignesEcrites).to.equal(ecritures);
        const fusion = lireFiles(rep);
        expect(fusion.fichiers).to.deep.equal(["file-1.ndjson", "file-2.ndjson"]);
        const apres = lignesNdjson("reprise", `${nom}.apres.ndjson`);
        expect(trierDemandes(fusion.demandes).map((d) => N.jcs(d))).to.deep.equal(apres);
        expect(trierDemandes(fusion.demandes).map((d) => N.jcs(d))).to.deep.equal(trace.queue_after.map((d) => N.jcs(d)));
      });
    }

    it("bascule-epoque : les fichiers d'époque 1 et 2 fusionnés par lireFiles donnent la file avant (EX-8.5, règle 6)", function () {
      const rep = path.join(dir, "epoques");
      fs.mkdirSync(rep, { recursive: true });
      fs.copyFileSync(path.join(CT5, "reprise", "bascule-epoque.epoque-1.ndjson"), path.join(rep, "file-1.ndjson"));
      fs.copyFileSync(path.join(CT5, "reprise", "bascule-epoque.epoque-2.ndjson"), path.join(rep, "file-2.ndjson"));
      const r = lireFiles(rep);
      expect(r.fichiers).to.deep.equal(["file-1.ndjson", "file-2.ndjson"]);
      expect(r.demandes.map((d) => N.jcs(d))).to.deep.equal(lignesNdjson("reprise", "bascule-epoque.avant.ndjson"));
      // Quinze lignes d'époque 1 pour quatre états successifs : la dernière ligne d'un id fait foi (règle 3).
      expect(lignesNdjson("reprise", "bascule-epoque.epoque-1.ndjson")).to.have.lengthOf(15);
      expect(r.demandes.filter((d) => d.id.startsWith("ancre_registre_point:0x7b93"))[0].state).to.equal("obtenue");
    });

    it("bascule-epoque-fichier-perdu : seul file-2 relu, la reconstruction recrée les trois demandes de la clôture (EX-8.12)", function () {
      const rep = path.join(dir, "perdu");
      fs.mkdirSync(rep, { recursive: true });
      fs.copyFileSync(path.join(CT5, "reprise", "bascule-epoque.epoque-2.ndjson"), path.join(rep, "file-2.ndjson"));
      const r = lireFiles(rep);
      expect(r.demandes.map((d) => N.jcs(d))).to.deep.equal(lignesNdjson("reprise", "bascule-epoque-fichier-perdu.avant.ndjson"));
      const trace = lire("planification", "bascule-epoque-fichier-perdu.json");
      const rejeu = rejouerTrace(trace);
      const reconstruit = rejeu.actions.find((a) => a.action === "journaliser" && a.detail.event === "anchoring_queue_rebuilt");
      expect(reconstruit.detail).to.deep.equal({ event: "anchoring_queue_rebuilt", recreated: 3, periods: 1, checkpoints: 0 });
      expect(rejeu.actions.some((a) => a.action === "alerter" && a.detail.code === "file_perdue")).to.equal(true);
    });
  });

  describe("règles exercées par les traces, lues sur les actions", function () {
    const rejeux = new Map();
    const rejeu = (nom) => {
      if (!rejeux.has(nom)) rejeux.set(nom, rejouerTrace(lire("planification", `${nom}.json`)));
      return rejeux.get(nom);
    };
    const journaux = (nom, event) => rejeu(nom).actions.filter((a) => a.action === "journaliser" && a.detail.event === event);

    it("EX-4.3 : K1 satisfait D_1 à D_8 en une requête, K2 D_9 et D_10, K4 D_11 ; K3 sans nouvel événement n'est ni ancré ni contresigné", function () {
      const r = rejeu("heure-nominale-reference");
      const contresignes = journaux("heure-nominale-reference", "checkpoint_countersigned").map((a) => a.detail.deadlines);
      expect(contresignes).to.deep.equal([[1, 2, 3, 4, 5, 6, 7, 8], [9, 10], [11]]);
      expect(journaux("heure-nominale-reference", "checkpoint_not_anchored")[0].detail.tree_size).to.equal(4);
      expect(r.file.some((d) => d.subject.hash.startsWith("0x3feb86ac"))).to.equal(false);
    });

    it("EX-3.5, EX-8.15 (révision 0.6) : les cinq composantes de d_jeton, d_admission_s compris, sont des secondes entières dont la somme est d_jeton_s", function () {
      for (const f of TRACES) {
        for (const a of rejouerTrace(lire("planification", f)).actions) {
          if (a.action !== "journaliser" || a.detail.event !== "checkpoint_countersigned") continue;
          const d = a.detail;
          for (const k of ["d_jeton_s", "d_point_s", "d_admission_s", "d_attente_s", "d_releve_s", "d_tsa_s"]) expect(Number.isInteger(d[k]), `${f} ${k}`).to.equal(true);
          expect(d.d_point_s + d.d_admission_s + d.d_attente_s + d.d_releve_s + d.d_tsa_s).to.equal(d.d_jeton_s);
        }
      }
    });

    it("EX-4.4 : une échéance non obtenue avant la suivante est close remplacee, avec checkpoint_anchor_late (mineure pour l'interne, majeure pour un prestataire extérieur)", function () {
      const interne = rejeu("echeance-remplacee");
      const late = interne.actions.filter((a) => a.action === "alerter" && a.detail.code === "checkpoint_anchor_late");
      expect(late.map((a) => a.detail.severity)).to.deep.equal(["mineure"]);
      expect(journaux("echeance-remplacee", "checkpoint_anchor_late")[0].detail.window_s).to.equal(2884);
      const exterieur = rejeu("prestataire-min-interval");
      expect(exterieur.actions.filter((a) => a.action === "alerter" && a.detail.code === "checkpoint_anchor_late").map((a) => a.detail.severity)).to.deep.equal(["majeure"]);
    });

    it("EX-8.9, AN-37 : attentes 5 s + gigue, Retry-After 30 s, 408 immédiat, 40 s + gigue, 80 s + gigue, puis plafond retry.max_ms", function () {
      const r = rejeu("principal-injoignable");
      const prog = r.actions.filter((a) => a.action === "programmer" && a.request_id.startsWith("jeton_periode")).map((a) => [a.detail.reason, a.detail.next_at]);
      expect(prog.slice(1)).to.deep.equal([
        ["backoff", "2026-11-03T14:00:17.100Z"],
        ["retry_after", "2026-11-03T14:00:47.600Z"],
        ["immediat", "2026-11-03T14:00:48.000Z"],
        ["backoff", "2026-11-03T14:01:38.200Z"],
        ["backoff", "2026-11-03T14:02:59.050Z"],
      ]);
      const plafond = rejeu("echeance-remplacee").actions.filter((a) => a.action === "programmer" && a.detail.reason === "backoff").map((a) => a.detail.next_at);
      expect(plafond).to.deep.equal(["2026-11-03T13:43:08.000Z", "2026-11-03T13:45:13.000Z", "2026-11-03T13:49:18.000Z", "2026-11-03T13:54:23.000Z"]);
    });

    it("EX-8.8, AN-38 : relève par le secours 300 s après la première tentative, réponse tardive du principal conservée sans être promue", function () {
      const r = rejeu("principal-injoignable");
      const releve = r.actions.find((a) => a.action === "releve");
      expect(releve.t).to.equal("2026-11-03T14:05:02.000Z");
      expect(releve.detail.provider).to.equal("qtsa-secours");
      const tardive = journaux("principal-injoignable", "anchor_response_rejected").find((a) => a.detail.error_code === "demande_close");
      expect(tardive.detail.kept).to.equal(true);
      expect(r.file.find((d) => d.kind === "jeton_periode").result.provider).to.equal("qtsa-secours");
    });

    it("EX-5.12 : une erreur permanente du principal relève sans réexpédition ; sans relève (second rang, interne) la demande de point est refusee et rend ses échéances", function () {
      const r = rejeu("refus-permanent-releve");
      const k1 = r.file.find((d) => d.id.startsWith("jeton_point:0xfbc4"));
      expect(k1.state).to.equal("refusee");
      expect(k1.attempts).to.have.lengthOf(1);
      const k4 = r.file.find((d) => d.id.startsWith("jeton_point:0x8045"));
      expect(k4.deadlines).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
      const periode = r.file.find((d) => d.kind === "jeton_periode");
      expect(periode.attempts.map((a) => [a.provider, a.outcome])).to.deep.equal([["qtsa-principal", "echec_permanente"], ["qtsa-secours", "obtenue"]]);
    });

    it("EX-5.11, AN-10 : deux réponses tardives rejouées avec un nouveau nonce, la troisième promue avec l'avertissement reponse_tardive", function () {
      const r = rejeu("reponse-tardive");
      const periode = r.file.find((d) => d.kind === "jeton_periode");
      expect(periode.attempts.map((a) => a.outcome)).to.deep.equal(["reponse_tardive", "reponse_tardive", "obtenue"]);
      expect(new Set(periode.attempts.map((a) => a.nonce)).size).to.equal(3);
      expect(r.actions.some((a) => a.action === "alerter" && a.detail.code === "reponse_tardive_promue")).to.equal(true);
      const horloge = rejeu("horloge-suspecte");
      expect(horloge.actions.some((a) => a.action === "alerter" && a.detail.code === "horloge_suspecte")).to.equal(true);
    });

    it("EX-9.5, AN-49 : après une indisponibilité du registre, une seule ancre est envoyée pour le dernier point admis, l'antérieure est remplacee ; aucune ancre de période remplacée", function () {
      const r = rejeu("registre-indisponible-cloture");
      const remplacees = r.file.filter((d) => d.state === "remplacee");
      expect(remplacees.map((d) => d.kind)).to.deep.equal(["ancre_registre_point"]);
      expect(remplacees[0].replaced_by).to.match(/^ancre_registre_point:0xc3240f32/);
      expect(r.file.filter((d) => d.kind === "ancre_registre_periode").every((d) => d.state === "obtenue")).to.equal(true);
      expect(journaux("registre-indisponible-cloture", "checkpoint_closing_fallback")).to.have.lengthOf(1);
    });

    it("EX-9.7, AN-40 : empreinte_squattee rend l'ancre refusee sans nouvel essai, alerte critique ; inclusion_late au-delà de inclusion_alert_s", function () {
      const r = rejeu("registre-indisponible");
      const k1 = r.file.find((d) => d.id.startsWith("ancre_registre_point:0xfbc4"));
      expect(k1.state).to.equal("refusee");
      expect(r.actions.filter((a) => a.action === "envoyer_registre" && a.request_id === k1.id)).to.have.lengthOf(3);
      expect(r.actions.filter((a) => a.action === "alerter" && a.detail.code === "inclusion_late").map((a) => a.detail.severity)).to.deep.equal(["mineure", "majeure", "mineure", "majeure", "majeure"]);
      expect(r.actions.some((a) => a.action === "alerter" && a.detail.code === "empreinte_squattee" && a.detail.severity === "critique")).to.equal(true);
    });

    it("EX-8.11, AN-41 : soumission, en_attente dès min_responses réponses, mise à niveau à first_after_s puis interval_s, complete à la première attestation Bitcoin, réexport", function () {
      const r = rejeu("ots-mise-a-niveau");
      const point = r.file.find((d) => d.kind === "ots_point");
      expect(point.state).to.equal("complete");
      expect(point.attempts.map((a) => a.outcome)).to.deep.equal(["obtenue", "echec_transitoire", "obtenue"]);
      expect(journaux("ots-mise-a-niveau", "ots_complete")[0].detail.reexport).to.equal(true);
      const mises = r.actions.filter((a) => a.action === "programmer" && a.detail.reason === "mise_a_niveau" && a.request_id === point.id).map((a) => a.detail.next_at);
      expect(mises).to.deep.equal(["2026-11-03T13:43:01.000Z", "2026-11-03T13:44:02.000Z"]);
    });

    it("EX-8.5 règle 4 : file pleine, les points ne sont plus ancrés mais la clôture crée ses trois demandes", function () {
      const r = rejeu("file-pleine");
      expect(journaux("file-pleine", "anchor_queue_full")).to.have.lengthOf(3);
      expect(r.file.filter((d) => d.subject.hash === "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1").map((d) => d.kind).sort()).to.deep.equal(["ancre_registre_periode", "jeton_periode", "ots_periode"]);
      expect(r.actions.filter((a) => a.action === "echeance" && a.detail.state === "remplacee")).to.have.lengthOf(11);
    });

    it("EX-8.7, AN-39 : à égalité, le jeton_periode part avant le jeton_point et min_interval_ms est tenu toutes demandes confondues", function () {
      const r = rejeu("prestataire-min-interval");
      const envois = r.actions.filter((a) => a.action === "envoyer_rfc3161" && a.detail.provider === "qtsa-principal").map((a) => [a.t, a.request_id.split(":")[0]]);
      for (let i = 1; i < envois.length; i++) expect(N.decoderHorodatage(envois[i][0]) - N.decoderHorodatage(envois[i - 1][0])).to.be.at.least(480000);
      expect(envois[envois.length - 1][1]).to.equal("jeton_periode");
    });

    it("EX-6.1 : mi_periode soumet le point sélectionné à l'échéance médiane (k_m = 6 pour c_T = 300, 3 pour c_T = 720) et lui seul", function () {
      expect(rejeu("ots-mise-a-niveau").file.filter((d) => d.kind === "ots_point").map((d) => d.subject.tree_size)).to.deep.equal([2]);
      const impair = rejeu("mi-periode-impair");
      expect(impair.file.filter((d) => d.kind === "ots_point")).to.have.lengthOf(1);
      expect(impair.actions.find((a) => a.action === "soumettre_ots").t).to.equal("2026-11-05T09:36:00.000Z");
    });

    it("EX-4.1, AN-2 : point_manquant à 2 × c_K sans point admis, jamais après la clôture", function () {
      expect(journaux("point-manquant", "point_manquant").map((a) => [a.t, a.detail.gap_s])).to.deep.equal([["2026-11-05T09:02:00.000Z", 120]]);
      expect(journaux("heure-nominale-reference", "point_manquant").map((a) => a.t)).to.deep.equal(["2026-11-03T13:44:00.000Z", "2026-11-03T13:56:00.000Z"]);
      expect(journaux("reponse-tardive", "point_manquant").map((a) => a.t)).to.deep.equal(["2026-11-03T14:03:00.000Z"]);
    });

    it("EX-8.12 : au démarrage, envoyee devient a_reprendre et repart avec un nouveau nonce ; une file perdue est reconstruite depuis le stockage", function () {
      const r = rejeu("redemarrage-reprise");
      const k4 = r.file.find((d) => d.id.startsWith("jeton_point:0x8045"));
      expect(k4.attempts.map((a) => [a.n, a.outcome, a.error_code])).to.deep.equal([[1, "echec_transitoire", "redemarrage"], [2, "obtenue", null]]);
      expect(k4.attempts[0].nonce).to.not.equal(k4.attempts[1].nonce);
      const perdue = rejeu("file-perdue");
      expect(journaux("file-perdue", "anchoring_queue_rebuilt")[0].detail).to.deep.equal({ event: "anchoring_queue_rebuilt", recreated: 2, periods: 0, checkpoints: 1 });
      const sansPerte = rejeu("bascule-epoque");
      expect(journaux("bascule-epoque", "anchoring_queue_rebuilt")[0].detail.recreated).to.equal(0);
      expect(sansPerte.actions.some((a) => a.action === "alerter" && a.detail.code === "file_perdue")).to.equal(false);
    });

    it("EX-4.3 : une demande refusée rend ses échéances, servies par le point suivant même sans nouvel événement", function () {
      const r = rejeu("refus-puis-preuve-de-vie");
      const servie = r.file.find((d) => d.id.startsWith("jeton_point:0x9f54"));
      expect(servie.state).to.equal("obtenue");
      expect(servie.deadlines).to.deep.equal([3]);
      const red = rejeu("refus-puis-preuve-de-vie-redemarrage");
      expect(red.file.find((d) => d.id.startsWith("jeton_point:0x9f54")).deadlines).to.deep.equal([1, 2, 3]);
    });

    it("EX-5.10 étapes 1 et 5, EX-5.12 : type_contenu, taille et politique_refusee sont permanents, les deux prestataires épuisés alternent au pas retry.max_ms", function () {
      const r = rejeu("reponse-hors-profil");
      const rejets = r.actions.filter((a) => a.action === "rejeter_reponse").map((a) => [a.detail.error_code, a.detail.class]);
      expect(rejets).to.deep.equal([["type_contenu", "permanente"], ["politique_refusee", "permanente"], ["taille", "permanente"]]);
      const envois = r.actions.filter((a) => a.action === "envoyer_rfc3161").map((a) => a.detail.provider);
      expect(envois).to.deep.equal(["qtsa-principal", "qtsa-secours", "qtsa-principal", "qtsa-secours"]);
      expect(r.actions.filter((a) => a.action === "alerter" && a.detail.code === "prestataires_epuises")).to.have.lengthOf(1);
    });
  });
});
