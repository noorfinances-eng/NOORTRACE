// Planificateur d'ancrage, révision 0.6 de CT-5 : fenêtre de 32 tentatives et
// `attempts_total` (EX-8.5, règle 7), rang de reprise `attempts_total + 1` et
// lecture des files d'avant la révision (EX-8.12), rang `n` et `attempt_id`
// des lignes `anchor_retry`, `anchor_fallback`, `anchor_response_rejected`
// (EX-8.15), `d_admission_s` et `d_attente_s` depuis l'admission (EX-3.5,
// 8.9) ; et la panne de l'étape 5 rejouée à l'horloge injectée sur la file
// durable : aucune ligne de plus de 32 tentatives, taille du fichier courant
// bornée par `max(compact_bytes, 2 × S_0)` plus une ligne, compactages
// consignés (EX-8.5, règle 5). Horloge injectée, nonces des vecteurs
// (annexe A.2), répertoires sous `os.tmpdir()` ; aucun réseau.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import {
  creerPlanificateur, noncesVecteurs, nonceVecteur, nonceHex, FileDurable, lireFiles, FENETRE_TENTATIVES, COMPACT_BYTES_DEFAUT, EVENEMENTS_TENTATIVE,
} from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CT5 = path.join(RACINE, "spec", "vecteurs", "ct-5");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(CT5, ...p), "utf8"));
const lignesVecteur = (nom) => fs.readFileSync(path.join(CT5, "reprise", nom), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
const JOURNAL = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const H = (ms) => N.ecrireHorodatage(ms);
const hex32 = (s) => N.octetsVersHex(N.sha256(N.utf8(s)));
const rangs = (de, a) => Array.from({ length: a - de + 1 }, (_, k) => de + k);

/** Réponse RFC 3161 d'échec de transport, ou 503 avec Retry-After. */
const echec = (request_id, attempt, { http = null, retryAfter = null } = {}) => ({
  request_id, attempt, transport: http === null ? "erreur_transport" : "reponse", http_status: http, pki_status: null, failure_info: null, retry_after_s: retryAfter,
  nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null,
});
/** Réponse accordée, vérifications T-1 à T-9 réussies. */
const accordee = (request_id, attempt, nonce, genTime, sel) => ({
  request_id, attempt, transport: "reponse", http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, nonce_in_response: nonce, imprint_matches: true,
  checks_passed: ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"], gen_time: genTime, accuracy_s: 1, token_sha256: hex32(`jeton-${sel}`), token_size: 2104,
});

describe("ancrage, planificateur : révision 0.6 de CT-5 (EX-8.5 règle 7, EX-8.12, EX-8.15, EX-3.5)", function () {
  this.timeout(600000);

  describe("EX-8.5, règle 7 : fenêtre de 32 tentatives", function () {
    it("relève : la tentative en_cours ancienne du principal reste dans la ligne malgré plus de 32 tentatives plus récentes du secours ; une réponse à une tentative sortie de la fenêtre est conservée, non promue ; n jamais renuméroté", function () {
      const trace = lire("planification", "principal-injoignable.json");
      const lignes = [];
      const p = creerPlanificateur(trace.config, { nonces: noncesVecteurs(), file: { ecrire: (d) => lignes.push(structuredClone(d)) } });
      const t0 = Date.parse("2026-11-03T13:59:00Z");
      const actions = [];
      const traiter = (e) => {
        const a = p.traiter(e);
        actions.push(...a);
        return a;
      };
      traiter({ t: H(t0), type: "demarrage", data: {} });
      for (const e of trace.inputs.filter((x) => x.type === "periode_close" || x.type === "reponse_ots" || x.type === "inclusion_registre")) traiter(e);
      const id = "jeton_periode:0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
      // Le principal ne répond jamais à la tentative 1 ; à fallback_after_s (300 s) la demande part au secours, qui répond 503 (Retry-After 5 s).
      let t = Date.parse("2026-11-03T14:05:03Z");
      traiter({ t: H(t), type: "tic", data: {} });
      for (let k = 0; k < 40; k++) {
        const envoi = [...actions].reverse().find((a) => a.action === "envoyer_rfc3161" && a.detail.provider === "qtsa-secours");
        t += 1000;
        traiter({ t: H(t), type: "reponse_rfc3161", data: echec(id, envoi.detail.attempt, { http: 503, retryAfter: 5 }) });
        t += 5000;
        traiter({ t: H(t), type: "tic", data: {} });
      }
      const d = p.file().find((x) => x.id === id);
      expect(d.attempts_total).to.equal(42);
      expect(d.attempts).to.have.lengthOf(FENETRE_TENTATIVES);
      expect(d.attempts[0]).to.include({ n: 1, provider: "qtsa-principal", outcome: "en_cours" });
      expect(d.attempts.slice(1).map((a) => a.n)).to.deep.equal(rangs(12, 42));
      for (const l of lignes) expect(l.attempts.length, `${l.id} ${l.state}`).to.be.at.most(FENETRE_TENTATIVES);
      for (const l of lignes.filter((x) => x.id === id)) expect(l.attempts_total).to.equal(Math.max(0, ...l.attempts.map((a) => a.n)));
      // Réponse accordée à la tentative 5 (secours), sortie de la fenêtre : stocker, tentative_close, état inchangé.
      const nonce5 = nonceHex(nonceVecteur({ journal: "journal-principal", sujet: "periode", empreinte: id.split(":")[1], n: 5 }));
      const avant = N.jcs(d);
      const a5 = traiter({ t: H(t + 500), type: "reponse_rfc3161", data: accordee(id, 5, nonce5, "2026-11-03T14:01:00Z", 5) });
      expect(a5.map((a) => a.action)).to.deep.equal(["stocker", "journaliser"]);
      expect(a5[1].detail).to.deep.include({ event: "anchor_response_rejected", error_code: "tentative_close", attempt: 5, attempt_id: "jeton_periode:a864281e05663ee5:5", kept: true });
      expect(N.jcs(p.file().find((x) => x.id === id))).to.equal(avant);
      // La tentative 1, toujours en cours dans la fenêtre, est encore celle d'une réponse classée (ici tardive, EX-5.11), non close.
      const nonce1 = d.attempts[0].nonce;
      const a1 = traiter({ t: H(t + 1000), type: "reponse_rfc3161", data: accordee(id, 1, nonce1, "2026-11-03T14:00:05Z", 1) });
      const ligne1 = a1.find((a) => a.action === "journaliser").detail;
      expect(ligne1).to.deep.include({ event: "anchor_response_rejected", error_code: "reponse_tardive", attempt: 1, attempt_id: "jeton_periode:a864281e05663ee5:1", provider: "qtsa-principal" });
    });

    it("lecture d'une file d'avant la révision : une ligne sans attempts_total de 40 tentatives est relue sans erreur ; au démarrage la demande repart au rang 41 et la ligne écrite porte les tentatives 9 à 40 puis 10 à 41, attempts_total 40 puis 41", function () {
      const trace = lire("planification", "file-fenetre-32-redemarrage.json");
      const avant = structuredClone(trace.queue_before);
      const jeton = avant.find((d) => d.kind === "jeton_periode");
      // Forme d'avant 0.6 : toutes les tentatives (1 à 40), sans attempts_total.
      const modele = jeton.attempts[0];
      const anciennes = rangs(1, 8).map((n) => ({ ...structuredClone(modele), n, correlation_id: `jeton_periode:a864281e05663ee5:${n}`, nonce: nonceHex(nonceVecteur({ journal: "journal-principal", sujet: "periode", empreinte: jeton.subject.hash, n })) }));
      jeton.attempts = [...anciennes, ...jeton.attempts];
      delete jeton.attempts_total;
      for (const d of avant) delete d.attempts_total;
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-fenetre-lecture-"));
      try {
        fs.writeFileSync(path.join(dir, "file-1.ndjson"), avant.map((d) => N.jcs(d) + "\n").join(""));
        const relue = lireFiles(dir);
        expect(relue.tronquees).to.deep.equal([]);
        expect(relue.parId.get(jeton.id).attempts).to.have.lengthOf(40);
        const f = FileDurable.ouvrir({ repertoire: dir, epoque: 2 });
        const p = creerPlanificateur(trace.config, { nonces: noncesVecteurs(), gigues: trace.jitter_ms, file: f, fileInitiale: relue.demandes });
        const actions = [];
        for (const e of trace.inputs) actions.push(...p.traiter(e));
        f.fermer();
        const envoi = actions.find((a) => a.action === "envoyer_rfc3161");
        expect(envoi.detail.attempt).to.equal(41);
        const ecrites = fs.readFileSync(path.join(dir, "file-2.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((d) => d.id === jeton.id);
        expect(ecrites[0]).to.deep.include({ state: "a_reprendre", attempts_total: 40 });
        expect(ecrites[0].attempts.map((a) => a.n)).to.deep.equal(rangs(9, 40));
        expect(ecrites[1]).to.deep.include({ state: "envoyee", attempts_total: 41 });
        expect(ecrites[1].attempts.map((a) => a.n)).to.deep.equal(rangs(10, 41));
        expect(ecrites[1].attempts.at(-1).correlation_id).to.equal("jeton_periode:a864281e05663ee5:41");
        // Même ligne finale que la trace, écrite sous la forme 0.6 ; les demandes que la trace ne réécrit pas gardent la forme lue.
        const finale = p.file();
        expect(N.jcs(finale.find((d) => d.id === jeton.id))).to.equal(N.jcs(trace.queue_after.find((d) => d.id === jeton.id)));
        for (const d of finale.filter((x) => x.id !== jeton.id)) expect(N.jcs(d)).to.equal(N.jcs(avant.find((x) => x.id === d.id)));
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("EX-8.12 : reprise d'une demande envoyee à 40 tentatives (file compactée, forme 0.6) au rang attempts_total + 1 = 41, nouveau nonce et attempt_id de rang 41", function () {
      const trace = lire("planification", "file-fenetre-32-redemarrage.json");
      const p = creerPlanificateur(trace.config, { nonces: noncesVecteurs(), gigues: trace.jitter_ms, fileInitiale: trace.queue_before });
      const actions = p.traiter(trace.inputs[0]);
      const envoi = actions.find((a) => a.action === "envoyer_rfc3161");
      expect(envoi.detail.attempt).to.equal(41);
      const d = p.file().find((x) => x.id === envoi.request_id);
      expect(d.attempts.at(-1)).to.include({ n: 41, correlation_id: "jeton_periode:a864281e05663ee5:41", nonce: envoi.detail.nonce });
      expect(d.attempts.find((a) => a.n === 40)).to.include({ outcome: "echec_transitoire", error_code: "redemarrage" });
      expect(new Set(d.attempts.map((a) => a.nonce)).size).to.equal(d.attempts.length);
    });
  });

  describe("EX-3.5, 8.9 : d_admission_s et d_attente_s depuis l'admission", function () {
    it("point produit 0,2 s après D_1 et admis 3,6 s après D_1 : d_point_s 0, d_admission_s 3, d_attente_s 1, d_releve_s 0, d_tsa_s 2 ; la somme des cinq est d_jeton_s", function () {
      const trace = lire("planification", "heure-nominale-reference.json");
      const p = creerPlanificateur(trace.config, { nonces: noncesVecteurs() });
      const P = 1793710800;
      const D1 = (P + 300) * 1000;
      const hash = "0x" + hex32("point-admission").slice(2);
      const actions = [];
      const traiter = (e) => actions.push(...p.traiter(e));
      traiter({ t: H(P * 1000), type: "demarrage", data: {} });
      traiter({ t: H(D1 + 3600), type: "point_produit", data: { org_id: ORG, journal_id: JOURNAL, period_start: P, tree_size: 2, checkpoint_hash: hash, checkpoint_ts: H(D1 + 200) } });
      traiter({ t: H(D1 + 4000), type: "inclusion_registre", data: { request_id: `ancre_registre_point:${hash}`, block_number: 1, capture_sha256: hex32("capture") } });
      const envoi = actions.find((a) => a.action === "envoyer_rfc3161");
      expect(envoi.t).to.equal(H(D1 + 4000));
      traiter({ t: H(D1 + 6500), type: "reponse_rfc3161", data: accordee(`jeton_point:${hash}`, 1, envoi.detail.nonce, H(D1 + 5000).replace(".000Z", "Z"), "admission") });
      const ligne = actions.find((a) => a.action === "journaliser" && a.detail.event === "checkpoint_countersigned").detail;
      expect(ligne).to.deep.include({ d_jeton_s: 6, d_point_s: 0, d_admission_s: 3, d_attente_s: 1, d_releve_s: 0, d_tsa_s: 2 });
      expect(ligne.d_point_s + ligne.d_admission_s + ligne.d_attente_s + ligne.d_releve_s + ligne.d_tsa_s).to.equal(ligne.d_jeton_s);
      expect(Object.keys(ligne)).to.deep.equal(["event", "tree_size", "provider", "deadlines", "d_jeton_s", "d_point_s", "d_admission_s", "d_attente_s", "d_releve_s", "d_tsa_s"]);
    });

    it("dans chaque trace, les cinq composantes sont des secondes entières de somme d_jeton_s, et d_admission_s = 0 quand l'entrée point_produit a t = checkpoint_ts", function () {
      for (const f of fs.readdirSync(path.join(CT5, "planification")).sort()) {
        const trace = lire("planification", f);
        for (const a of trace.expected) {
          if (a.action !== "journaliser" || a.detail.event !== "checkpoint_countersigned") continue;
          const d = a.detail;
          for (const k of ["d_jeton_s", "d_point_s", "d_admission_s", "d_attente_s", "d_releve_s", "d_tsa_s"]) expect(Number.isInteger(d[k]), `${f} ${k}`).to.equal(true);
          expect(d.d_point_s + d.d_admission_s + d.d_attente_s + d.d_releve_s + d.d_tsa_s, f).to.equal(d.d_jeton_s);
          const pts = trace.inputs.filter((e) => e.type === "point_produit" && e.data.tree_size === d.tree_size);
          if (pts.length === 1 && pts[0].t === pts[0].data.checkpoint_ts) expect(d.d_admission_s, `${f} tree_size ${d.tree_size}`).to.equal(0);
        }
      }
    });
  });

  describe("panne de l'étape 5 rejouée à l'horloge injectée sur la file durable (EX-8.5 règles 5 et 7, EX-8.15)", function () {
    /**
     * Une heure de panne des deux prestataires RFC 3161 (erreur de transport une
     * seconde après chaque envoi), c_T = 60 s (59 échéances, une demande de point
     * par échéance), relève par le secours, registre et calendriers joignables ;
     * clôture à la fin de l'heure. Rend les lignes écrites, les actions et la file.
     */
    function panne({ compactBytes, repertoire, retryMaxMs = 110000 }) {
      const base = lire("planification", "heure-nominale-reference.json").config;
      const config = structuredClone(base);
      config.rfc3161.checkpoints = { interval_s: 60, provider_role: "principal", fallback_after_s: 120, countersign_idle: true };
      config.rfc3161.providers = lire("planification", "principal-injoignable.json").config.rfc3161.providers;
      config.rfc3161.retry = { initial_ms: 5000, factor: 2, max_ms: retryMaxMs, jitter_ms: 250 };
      const journal = [];
      const f = FileDurable.ouvrir({ repertoire, epoque: 1, compactBytes, fdatasync: false, journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }) });
      let lignePlusLongue = 0;
      let tentativesMax = 0;
      let lignes = 0;
      let tailleMaxBornee = true;
      const ecrivain = {
        ecrire(d) {
          tentativesMax = Math.max(tentativesMax, d.attempts.length);
          const seuil = f.seuil();
          const r = f.ecrire(d);
          lignes += 1;
          lignePlusLongue = Math.max(lignePlusLongue, r.octets);
          if (f.mesures().taille_max > Math.max(seuil, f.seuil()) + lignePlusLongue) tailleMaxBornee = false;
          return r;
        },
      };
      const p = creerPlanificateur(config, { nonces: noncesVecteurs(), file: ecrivain });
      const P = 1793710800;
      const actions = [];
      const evenements = []; // {at, entree}
      const programmerEntree = (at, type, data) => evenements.push({ at, entree: { type, data } });
      const executer = (liste) => {
        for (const a of liste) {
          actions.push(a);
          const t = Date.parse(a.t);
          if (a.action === "envoyer_rfc3161") programmerEntree(t + 1000, "reponse_rfc3161", echec(a.request_id, a.detail.attempt));
          else if (a.action === "envoyer_registre") programmerEntree(t + 2000, "inclusion_registre", { request_id: a.request_id, block_number: 1000 + actions.length, capture_sha256: hex32(`capture-${a.request_id}`) });
          else if (a.action === "soumettre_ots") programmerEntree(t + 1000, "reponse_ots", { request_id: a.request_id, calendars_answered: 2, attestation: "en_attente", proof_sha256: hex32(`preuve-${a.request_id}`), proof_size: 233 });
        }
      };
      const traiter = (t, type, data) => executer(p.traiter({ t: H(t), type, data }));
      traiter(P * 1000, "demarrage", {});
      for (let m = 1; m <= 59; m++) programmerEntree((P + m * 60) * 1000, "point_produit", { org_id: ORG, journal_id: JOURNAL, period_start: P, tree_size: m + 1, checkpoint_hash: "0x" + hex32(`point-${m}`).slice(2), checkpoint_ts: H((P + m * 60) * 1000) });
      programmerEntree((P + 3600) * 1000 + 250, "point_produit", { org_id: ORG, journal_id: JOURNAL, period_start: P, tree_size: 61, checkpoint_hash: "0x" + hex32("point-cloture").slice(2), checkpoint_ts: H((P + 3600) * 1000 + 250) });
      programmerEntree((P + 3600) * 1000 + 250, "periode_close", { org_id: ORG, journal_id: JOURNAL, period_start: P, period_hash: "0x" + hex32("periode").slice(2), generated_at: H((P + 3600) * 1000 + 250) });
      const fin = (P + 3600) * 1000 + 30000;
      while (evenements.length) {
        evenements.sort((a, b) => a.at - b.at);
        const { at, entree } = evenements.shift();
        if (at > fin) break;
        // Les minuteries du planificateur échoient au plus tard à l'entrée suivante ; un tic chaque seconde les sert à l'heure.
        traiter(at, entree.type, entree.data);
        if (entree.type === "periode_close") f.compacter({ declencheur: "cloture" });
        if (!evenements.some((e) => e.at <= at + 1000)) programmerEntree(at + 1000, "tic", {});
      }
      traiter(fin, "arret", {});
      f.fermer();
      return { p, f, actions, journal, lignes, tentativesMax, lignePlusLongue, tailleMaxBornee, fichier: path.join(repertoire, "file-1.ndjson") };
    }

    let dir;
    before(function () {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-panne-etape5-"));
    });
    after(function () {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("compact_bytes petit (256 Kio) : 59 demandes de points et plus de 1 800 tentatives (l'étape 5 en a relevé 1 886) ; aucune ligne de plus de 32 tentatives ; taille du fichier courant ≤ max(compact_bytes, 2 × S_0) + une ligne ; compactages consignés, dont celui de la clôture ; chaque tentative sortie de la fenêtre se lit au journal par son rang et son attempt_id", function () {
      const r = panne({ compactBytes: 256 * 1024, repertoire: path.join(dir, "petit") });
      const file = r.p.file();
      const jetons = file.filter((d) => d.kind === "jeton_point");
      const total = file.reduce((s, d) => s + d.attempts_total, 0);
      expect(jetons).to.have.lengthOf(59);
      expect(total).to.be.at.least(1800);
      expect(r.tentativesMax).to.equal(FENETRE_TENTATIVES);
      expect(jetons.filter((d) => d.attempts_total > FENETRE_TENTATIVES).length).to.be.at.least(20);
      expect(r.tailleMaxBornee).to.equal(true);
      const compactages = r.journal.filter((l) => l.evenement === "anchor_queue_compacted");
      expect(compactages.length).to.be.at.least(2);
      expect(r.journal.filter((l) => l.evenement === "anchor_queue_compaction_failed")).to.deep.equal([]);
      const m = r.f.mesures();
      expect(m.taille_max).to.be.at.most(Math.max(256 * 1024, 2 * Math.max(...compactages.map((c) => c.champs.bytes_after))) + r.lignePlusLongue);
      expect(compactages.at(-1).champs.requests).to.equal(file.length);
      // Relecture : la file compactée rend la même file que le planificateur (EX-8.12).
      expect(lireFiles(path.dirname(r.fichier)).demandes.map((d) => N.jcs(d)).sort()).to.deep.equal(file.map((d) => N.jcs(d)).sort());
      // EX-8.15 : chaque tentative RFC 3161 sortie de la fenêtre a sa ligne anchor_response_rejected (rang, attempt_id).
      const auJournal = new Map();
      for (const a of r.actions) {
        if (a.action !== "journaliser" || !EVENEMENTS_TENTATIVE.includes(a.detail.event) || a.detail.attempt === null) continue;
        expect(a.detail.attempt_id).to.equal(`${a.request_id.split(":")[0]}:${a.request_id.split(":")[1].slice(2, 18)}:${a.detail.attempt}`);
        if (!auJournal.has(a.request_id)) auJournal.set(a.request_id, new Set());
        auJournal.get(a.request_id).add(a.detail.attempt);
      }
      let sorties = 0;
      for (const d of jetons) {
        const dansLaLigne = new Set(d.attempts.map((a) => a.n));
        for (const n of rangs(1, d.attempts_total)) {
          if (dansLaLigne.has(n)) continue;
          sorties += 1;
          expect(auJournal.get(d.id)?.has(n), `${d.id} tentative ${n}`).to.equal(true);
        }
      }
      expect(sorties).to.be.at.least(100);
    });

    it("valeurs par défaut (compact_bytes 16 777 216) : la taille maximale du fichier courant reste sous 16 777 216 octets plus une ligne, la ligne la plus longue sous 47 Ko, et la clôture compacte", function () {
      const r = panne({ compactBytes: COMPACT_BYTES_DEFAUT, repertoire: path.join(dir, "defaut"), retryMaxMs: 300000 });
      expect(r.tentativesMax).to.be.at.most(FENETRE_TENTATIVES);
      expect(r.f.mesures().taille_max).to.be.at.most(COMPACT_BYTES_DEFAUT + r.lignePlusLongue);
      expect(r.lignePlusLongue).to.be.below(47 * 1024);
      const compactages = r.journal.filter((l) => l.evenement === "anchor_queue_compacted");
      expect(compactages).to.have.lengthOf(1);
      expect(compactages[0].champs.bytes_after).to.be.below(compactages[0].champs.bytes_before);
    });
  });
});
