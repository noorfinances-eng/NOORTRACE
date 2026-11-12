// Composant d'ancrage, lot H1 : essais de non-régression des corrections
// apportées après la relecture adversariale de l'étape 5 (rapport G1).
// Chaque `describe` porte le numéro du défaut (R-C-1 …) ; chaque essai
// échouait avant la correction et passe après. Règle de texte retenue pour
// les attentes (EX-8.9 révisée) : l'attente après une erreur transitoire vaut
// `Retry-After` quand la réponse 429 ou 503 en porte un, bornée à
// [retry.initial_ms, retry.max_ms] ; la valeur consignée `retry_after_s` est
// celle lue, plafonnée à 604 800 ; sur 408, 500, 502, 504, `Retry-After` n'est
// pas suivi. Aucun essai n'exige le réseau ; tout fichier va sous `os.tmpdir()`.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import * as A from "@noortrace/ancrage/rfc3161";
import * as C from "@noortrace/ancrage/planificateur";
import * as R from "@noortrace/ancrage/registre";
import { Compteur, ErreurCompteur } from "@noortrace/ancrage/serveur-interne";
import { FileTolerante } from "../paquets/ancrage/src/composant.mjs";
import { NoeudFactice, validateursEssai } from "./fixtures/ancrage-registre/noeud-factice.mjs";
import { prestataireTest, horlogeFixe, aleaFixe, transportFactice, reponse200 } from "./fixtures/ancrage-rfc3161/outils.mjs";
import * as H from "./fixtures/ancrage-h1/outils.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const lireJson = (...p) => JSON.parse(fs.readFileSync(path.join(RACINE, ...p), "utf8"));
const octets = (...p) => new Uint8Array(fs.readFileSync(path.join(RACINE, ...p)));
const tmp = (prefixe) => fs.mkdtempSync(path.join(os.tmpdir(), `noortrace-ancrage-h1-${prefixe}-`));
const REPERTOIRES = [];
const temporaire = (prefixe) => {
  const d = tmp(prefixe);
  REPERTOIRES.push(d);
  return d;
};
const REF_ENTREE = `${C.ID_SCHEMA_PLANIFICATEUR}#/$defs/evenement_entree`;
const RETRY = { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 };

// Configuration et sujets de la trace de référence de CT-5 (heure-nominale-reference).
const TRACE = lireJson("spec", "vecteurs", "ct-5", "planification", "heure-nominale-reference.json");
const ORG = TRACE.inputs[1].data.org_id;
const JOURNAL = TRACE.inputs[1].data.journal_id;
const PERIODE_TRACE = 1793710800;
const PERIOD_HASH = "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
const T0 = "2026-11-03T14:00:01.000Z";
const CLOSE = { org_id: ORG, journal_id: JOURNAL, period_start: PERIODE_TRACE, period_hash: PERIOD_HASH, generated_at: "2026-11-03T14:00:00.250Z" };
const SHA = (texte) => N.sha256Hex(N.utf8(texte));
const e = (t, type, data = {}) => ({ t, type, data });
const REPONSE_HTTP = (request_id, attempt, http, retryAfter) => ({
  request_id, attempt, transport: "reponse", http_status: http, pki_status: null, failure_info: null, retry_after_s: retryAfter, nonce_in_response: null, imprint_matches: null,
  checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null, content_type: "text/plain", body_size: 0,
});
const GRANTED = (request_id, attempt, nonce, gen_time, nom) => ({
  request_id, attempt, transport: "reponse", http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, nonce_in_response: nonce, imprint_matches: true,
  checks_passed: ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"], gen_time, accuracy_s: 1, token_sha256: SHA(`jeton ${nom}`), token_size: 2104, content_type: "application/timestamp-reply", body_size: 2110, policy_check: "conforme",
});
const INCLUSION = (request_id, bloc) => ({ request_id, block_number: bloc, capture_sha256: SHA(`capture ${request_id} ${bloc}`) });
const NONCES_FIXES = { rfc3161: () => 0x1234567890abcdefn, ots: () => new Uint8Array(16).fill(1), gigue: () => 0 };

/** Planificateur de la configuration de référence sur une file durable d'un répertoire temporaire. */
function planificateurSurFile(prefixe, { config = null, ...options } = {}) {
  const dir = temporaire(prefixe);
  const file = C.FileDurable.ouvrir({ repertoire: dir, epoque: 1 });
  const p = C.creerPlanificateur(config ?? structuredClone(TRACE.config), { nonces: NONCES_FIXES, file, ...options });
  return { dir, file, p, relire: () => C.lireFiles(dir) };
}
/** Configuration de référence sans relève par délai (la reprise du principal s'observe seule). */
function configSansReleve() {
  const c = structuredClone(TRACE.config);
  c.rfc3161.manifest.fallback_after_s = 3600;
  return c;
}
const FIN_PERIODE_MS = (H.PERIODE + 3600) * 1000;

/** Clôture d'une période de la trace jusqu'à l'envoi du jeton de période au principal (inclusion de l'ancre reçue). */
function jusquAuJetonDePeriode(p) {
  const actions = [];
  actions.push(...p.traiter(e(T0, "demarrage")));
  actions.push(...p.traiter(e(T0, "periode_close", CLOSE)));
  actions.push(...p.traiter(e("2026-11-03T14:00:02.000Z", "inclusion_registre", INCLUSION(`ancre_registre_periode:${PERIOD_HASH}`, 20010))));
  return actions;
}

describe("ancrage, lot H1 : corrections après la relecture adversariale de l'étape 5", function () {
  this.timeout(120000);

  after(function () {
    for (const d of REPERTOIRES) fs.rmSync(d, { recursive: true, force: true });
  });

  // ------------------------------------------------------------------ R-C-1, R-C-2, R-C-3

  describe("R-C-1, R-C-2, R-C-3 : Retry-After borné, suivi sur 429 et 503 seulement, table unique du lot A (EX-8.9 révisée)", function () {
    it("attenteTransitoire : Retry-After 700 000 s → max_ms ; Retry-After 0 → initial_ms ; 30 s suivi tel quel ; 408, 500, 502, 504 : jamais suivi ; premier 408 immédiat ; lireRetryAfter plafonne à 604 800", function () {
      expect(A.attenteTransitoire({ httpStatus: 503, retryAfterS: 700000, retry: RETRY })).to.deep.equal({ attenteMs: 300000, raison: "retry_after" });
      expect(A.attenteTransitoire({ httpStatus: 429, retryAfterS: 0, retry: RETRY })).to.deep.equal({ attenteMs: 5000, raison: "retry_after" });
      expect(A.attenteTransitoire({ httpStatus: 503, retryAfterS: 30, retry: RETRY })).to.deep.equal({ attenteMs: 30000, raison: "retry_after" });
      for (const statut of [408, 500, 502, 504]) {
        expect(A.attenteTransitoire({ httpStatus: statut, retryAfterS: 7, retry: RETRY, k: 2, premier408: false }), String(statut)).to.deep.equal({ attenteMs: 10000, raison: "backoff" });
      }
      expect(A.attenteTransitoire({ httpStatus: 408, retryAfterS: 7, retry: RETRY, k: 1 })).to.deep.equal({ attenteMs: 0, raison: "immediat" });
      expect(A.attenteTransitoire({ httpStatus: 503, retryAfterS: null, retry: RETRY, k: 3 })).to.deep.equal({ attenteMs: 20000, raison: "backoff" });
      expect(A.lireRetryAfter("315360000", 0)).to.equal(604800);
      expect(A.lireRetryAfter("700000", 0)).to.equal(604800);
      expect(A.lireRetryAfter("30", 0)).to.equal(30);
      expect(A.bornerRetryAfter(9e15)).to.equal(604800);
      expect(A.bornerRetryAfter(12.7)).to.equal(12);
      expect(A.bornerRetryAfter(null)).to.equal(null);
      expect(A.bornerRetryAfter(-1)).to.equal(null);
      expect(A.RETRY_AFTER_MAX_S).to.equal(604800);
      // classerErreur (lot A) passe par la même table.
      expect(A.classerErreur({ code: "http_503", retryAfter: 700000, retry: RETRY })).to.include({ attenteMs: 300000, raisonAttente: "retry_after" });
      expect(A.classerErreur({ code: "http_429", retryAfter: 0, retry: RETRY })).to.include({ attenteMs: 5000, raisonAttente: "retry_after" });
      expect(A.classerErreur({ code: "http_502", retryAfter: 30, retry: RETRY, k: 1 })).to.include({ attenteMs: 5000, raisonAttente: "backoff" });
    });

    it("planificateur : 503 Retry-After 700 000 puis 429 Retry-After 315 360 000 → reprises à max_ms, retry_after_s consigné 604 800, lignes de file conformes au schéma ; 500 Retry-After 7 → backoff 5 s", function () {
      const { p, file, relire } = planificateurSurFile("rc1-planificateur", { config: configSansReleve() });
      const id = `jeton_periode:${PERIOD_HASH}`;
      const actions = jusquAuJetonDePeriode(p);
      actions.push(...p.traiter(e("2026-11-03T14:00:03.000Z", "reponse_rfc3161", REPONSE_HTTP(id, 1, 503, 700000))));
      let prog = actions.filter((a) => a.action === "programmer" && a.request_id === id).map((a) => [a.detail.reason, a.detail.next_at]);
      expect(prog.at(-1)).to.deep.equal(["retry_after", "2026-11-03T14:05:03.000Z"]);
      const d = p.demandes.get(id);
      expect(d.state).to.equal("a_reprendre");
      expect(d.attempts[0].retry_after_s).to.equal(604800);
      expect(d.due_at).to.equal("2026-11-03T14:05:03.000Z");
      // Reprise à l'échéance (aucune relève par délai dans cette configuration) : la tentative 2 part au principal.
      const suite = p.traiter(e("2026-11-03T14:05:03.000Z", "tic"));
      const envois = suite.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === id);
      expect(envois.map((a) => [a.detail.provider, a.detail.attempt])).to.deep.equal([["qtsa-principal", 2]]);
      const n = 2;
      const suite2 = p.traiter(e("2026-11-03T14:05:04.000Z", "reponse_rfc3161", REPONSE_HTTP(id, n, 429, 315360000)));
      prog = suite2.filter((a) => a.action === "programmer" && a.request_id === id).map((a) => [a.detail.reason, a.detail.next_at]);
      expect(prog.at(-1)).to.deep.equal(["retry_after", "2026-11-03T14:10:04.000Z"]);
      expect(d.attempts.find((a) => a.n === n).retry_after_s).to.equal(604800);
      // Toutes les lignes écrites sont conformes : aucune ligne tronquée ou refusée à la relecture, l'état relu est celui de la mémoire.
      file.fermer();
      const relue = relire();
      expect(relue.tronquees).to.deep.equal([]);
      const sur = relue.parId.get(id);
      expect(sur.state).to.equal("a_reprendre");
      expect(sur.attempts.map((a) => a.retry_after_s).filter((x) => x !== null)).to.deep.equal([604800, 604800]);
      // R-C-2 : Retry-After ignoré sur 500 (et 502, 504) : règle générale.
      for (const statut of [500, 502, 504]) {
        const { p: p2, file: f2 } = planificateurSurFile(`rc2-${statut}`);
        jusquAuJetonDePeriode(p2);
        const a2 = p2.traiter(e("2026-11-03T14:00:03.000Z", "reponse_rfc3161", REPONSE_HTTP(id, 1, statut, 7)));
        const pr = a2.filter((a) => a.action === "programmer" && a.request_id === id).map((a) => [a.detail.reason, a.detail.next_at]);
        expect(pr, String(statut)).to.deep.equal([["backoff", "2026-11-03T14:00:08.000Z"]]);
        f2.fermer();
      }
    });

    it("FileTolerante : une ligne refusée par le schéma est consignée (demande_non_conforme, chemin JSON) et abandonnée, les suivantes s'écrivent ; une panne de disque garde la ligne et la rejoue", function () {
      const ecrites = [];
      const refusees = new Set(["jeton_periode:0x" + "bb".repeat(32)]);
      let panne = false;
      const file = {
        ecrire(d) {
          if (panne) {
            const err = new Error("EIO");
            err.code = "EIO";
            throw err;
          }
          if (refusees.has(d.id)) throw new C.ErreurDemandeNonConforme("demande non conforme à $defs/demande : /attempts/0/retry_after_s : aucune branche de oneOf ne convient", "/attempts/0/retry_after_s");
          ecrites.push(d.id);
        },
      };
      const nonConformes = [];
      const echecs = [];
      let reprises = 0;
      const ft = new FileTolerante(file, { maxPending: 10, surEchec: (err, info) => echecs.push([err.code, info.premiere]), surReprise: () => reprises++, surNonConforme: (d, err, info) => nonConformes.push([d.id, err.chemin, info.abandonnees]) });
      const id = (k) => `jeton_periode:0x${k.repeat(32)}`;
      ft.ecrire({ id: id("aa"), state: "a_envoyer" });
      ft.ecrire({ id: id("bb"), state: "a_reprendre" });
      ft.ecrire({ id: id("cc"), state: "a_envoyer" });
      expect(ecrites).to.deep.equal([id("aa"), id("cc")]);
      expect(nonConformes).to.deep.equal([[id("bb"), "/attempts/0/retry_after_s", 1]]);
      expect(ft.enPanne).to.equal(false);
      expect(ft.enAttente.size).to.equal(0);
      expect(echecs).to.deep.equal([]);
      panne = true;
      ft.ecrire({ id: id("dd"), state: "a_envoyer" });
      expect(ft.enPanne).to.equal(true);
      expect(echecs).to.deep.equal([["EIO", true]]);
      panne = false;
      ft.ecrire({ id: id("ee"), state: "a_envoyer" });
      expect(ecrites).to.deep.equal([id("aa"), id("cc"), id("dd"), id("ee")]);
      expect(reprises).to.equal(1);
      expect(ft.enPanne).to.equal(false);
      // Une ligne gardée pour une panne de disque qui devient non conforme au rejeu est abandonnée, et la suivante s'écrit.
      panne = true;
      ft.ecrire({ id: id("bb"), state: "envoyee" });
      panne = false;
      ft.ecrire({ id: id("ff"), state: "a_envoyer" });
      expect(ecrites.at(-1)).to.equal(id("ff"));
      expect(ft.enAttente.size).to.equal(0);
      expect(ft.abandonnees).to.equal(2);
    });

    it("composant : 503 Retry-After 700 000 puis 429 Retry-After 315 360 000 puis granted : file conforme, jeton obtenu écrit dans la file, redémarrage sans nouvelle requête", async function () {
      const dir = temporaire("rc1-composant");
      const reponses = { 1: { status: 503, entetes: { "content-type": "text/plain", "retry-after": "700000" }, corps: new Uint8Array(0), tronque: false }, 2: { status: 429, entetes: { "content-type": "text/plain", "retry-after": "315360000" }, corps: new Uint8Array(0), tronque: false } };
      const m = await H.monter({ dir, debutMs: FIN_PERIODE_MS, evenements: { 0: 1 }, crochet: async (req, rep, n) => (req.url.includes("principal") && reponses[n] ? reponses[n] : rep), surcharges: { rfc3161: { manifest: { fallback_after_s: 3600 } } } });
      await m.remettreCloture();
      await m.calme();
      const principal = () => m.transport.appels.filter((r) => r.url.includes("principal")).length;
      expect(principal()).to.equal(1);
      let d = m.composant.demandes().find((x) => x.kind === "jeton_periode");
      expect(d.state).to.equal("a_reprendre");
      expect(d.attempts[0]).to.include({ http_status: 503, retry_after_s: 604800, outcome: "echec_transitoire", error_code: "http_503" });
      expect(Date.parse(d.due_at) - Date.parse(d.attempts[0].started_at)).to.equal(300000, "Retry-After borné à retry.max_ms");
      expect(m.composant.etat().file_en_panne).to.equal(false);
      expect(m.journal.de("anchor_queue_write_failed")).to.deep.equal([]);
      // Le tic (1 s) qui suit l'échéance sert la reprise : 301 s couvrent l'attente de 300 s.
      await m.horloge.avancer(301000, m.calme);
      expect(principal()).to.equal(2);
      d = m.composant.demandes().find((x) => x.kind === "jeton_periode");
      expect(d.attempts[1]).to.include({ http_status: 429, retry_after_s: 604800, outcome: "echec_transitoire" });
      await m.horloge.avancer(301000, m.calme);
      expect(principal()).to.equal(3);
      d = m.composant.demandes().find((x) => x.kind === "jeton_periode");
      expect(d.state).to.equal("obtenue");
      expect(d.result.provider).to.equal("qtsa-principal");
      // File sur disque : conforme (aucune ligne tronquée ni refusée), le jeton obtenu y est écrit.
      const relue = m.etatFile();
      expect(relue.tronquees).to.deep.equal([]);
      expect(relue.parId.get(d.id).state).to.equal("obtenue");
      expect(relue.parId.get(d.id).attempts.map((a) => a.retry_after_s)).to.deep.equal([604800, 604800, null]);
      expect(m.journal.de("anchor_queue_write_failed")).to.deep.equal([]);
      expect(m.acquisitions().filter((x) => x.outcome === "obtenue" && x.promoted)).to.have.lengthOf(1);
      await m.composant.arreter();
      // Redémarrage (époque 2) : le jeton est relu obtenue, aucune requête ne repart.
      const journal2 = H.F.journalMemoire();
      const c2 = m.creer({ epoque: 2, journal: journal2 });
      await c2.demarrer();
      const calme2 = H.F.attenteCalme(c2, { pasMs: 3, maxMs: 20000 });
      await calme2();
      await m.horloge.avancer(10000, calme2);
      expect(principal()).to.equal(3, "aucune nouvelle requête au principal après le redémarrage");
      expect(c2.demandes().find((x) => x.kind === "jeton_periode").state).to.equal("obtenue");
      expect(journal2.de("anchoring_queue_rebuilt")[0].data.recreated).to.equal(0);
      await c2.arreter();
    });

    it("R-C-3 : Retry-After 0 sur 503 : le plancher retry.initial_ms règle la boucle ; 2 minutes à l'horloge réglable produisent au plus ⌈120 s / initial_ms⌉ + 1 tentatives et la file reste sous 1 Mio", async function () {
      const dir = temporaire("rc3");
      const m = await H.monter({ dir, debutMs: FIN_PERIODE_MS, evenements: { 0: 1 }, crochet: async (req, rep) => (req.url.includes("principal") ? { status: 503, entetes: { "content-type": "text/plain", "retry-after": "0" }, corps: new Uint8Array(0), tronque: false } : rep), surcharges: { rfc3161: { manifest: { fallback_after_s: 3600 } } } });
      await m.remettreCloture();
      await m.calme();
      for (let i = 0; i < 12; i++) await m.horloge.avancer(10000, m.calme);
      const appels = m.transport.appels.filter((r) => r.url.includes("principal")).length;
      expect(appels).to.be.at.most(Math.ceil(120000 / 5000) + 1);
      expect(appels).to.be.at.least(20, "la reprise suit bien le plancher de 5 s");
      const d = m.composant.demandes().find((x) => x.kind === "jeton_periode");
      expect(d.attempts.every((a) => a.retry_after_s === 0 || a.outcome === "en_cours")).to.equal(true);
      for (const a of d.attempts.slice(0, -1)) expect(Date.parse(a.next_at) - Date.parse(a.started_at)).to.be.at.least(5000);
      expect(fs.statSync(path.join(dir, "file", "file-1.ndjson")).size).to.be.below(1048576);
      expect(fs.readdirSync(m.repertoirePeriode + "/rfc3161").filter((n) => n.endsWith(".tsq")).length).to.equal(appels);
      await m.composant.arreter({ attendre: false });
    });
  });

  // ------------------------------------------------------------------ R-C-4

  describe("R-C-4 : ligne de file dont id ≠ <kind>:<subject.hash> refusée à la lecture (EX-8.2)", function () {
    it("decoderFile signale id_incoherent et ne relit pas la ligne ; controlerDemande la refuse (/id) ; une ligne cohérente passe", function () {
      const lignes = fs.readdirSync(path.join(RACINE, "spec", "vecteurs", "ct-5", "reprise")).flatMap((n) => fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-5", "reprise", n), "utf8").split("\n").filter(Boolean));
      const demande = JSON.parse(lignes.find((l) => l.includes('"kind":"jeton_point"')));
      const saine = `${N.jcs(demande)}\n`;
      expect(C.decoderFile(Buffer.from(saine, "utf8"), "f").lignes).to.have.lengthOf(1);
      const autre = { ...demande, id: `jeton_periode:${demande.subject.hash}` };
      const r = C.decoderFile(Buffer.from(`${N.jcs(autre)}\n`, "utf8"), "f");
      expect(r.lignes).to.deep.equal([]);
      expect(r.tronquees).to.deep.equal([{ fichier: "f", ligne: 1, raison: "id_incoherent" }]);
      const autreHash = { ...demande, id: `jeton_point:0x${"77".repeat(32)}` };
      expect(C.decoderFile(Buffer.from(`${N.jcs(autreHash)}\n`, "utf8"), "f").tronquees[0].raison).to.equal("id_incoherent");
      expect(() => C.controlerDemande(autre)).to.throw(C.ErreurDemandeNonConforme).with.property("chemin", "/id");
      expect(C.idCoherent(demande)).to.equal(true);
      // Les six scénarios de reprise des vecteurs restent relus en entier (toutes leurs lignes sont cohérentes).
      for (const l of lignes) expect(C.idCoherent(JSON.parse(l)), l.slice(0, 60)).to.equal(true);
    });
  });

  // ------------------------------------------------------------------ R-C-5

  describe("R-C-5 : http:// hors du rôle interne refusé par AN-1 dans tout profil, comme par le transport (EX-5.5)", function () {
    it("AN-1 refuse un principal en http:// hors production avec un message qui nomme EX-5.5 ; le transport du lot A refuse la même url ; interne local en http:// admis", function () {
      const dir = temporaire("rc5");
      const d = H.configuration(dir);
      d.rfc3161.providers[0].url = "http://horodatage-principal.example/tsa";
      const v = C.validerConfiguration(d, { profil: "developpement", checkpointIntervalEnregistreur: 60 });
      expect(v.valide).to.equal(false);
      expect(v.erreurs.map((x) => x.regle)).to.deep.equal(["4"]);
      expect(v.erreurs[0].message).to.match(/EX-5\.5/).and.match(/https:\/\//);
      expect(() => A.controlerUrl("http://horodatage-principal.example/tsa", "principal")).to.throw(A.ErreurTransport).with.property("code", "url");
      const ok = H.configuration(dir);
      expect(C.validerConfiguration(ok, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).valide).to.equal(true);
      expect(A.controlerUrl("http://127.0.0.1:2020/", "interne").hostname).to.equal("127.0.0.1");
      for (const profil of ["test", "production"]) {
        const d2 = H.configuration(dir);
        d2.rfc3161.providers[1].url = "http://127.0.0.1:2021/";
        expect(C.validerConfiguration(d2, { profil, checkpointIntervalEnregistreur: 60 }).erreurs.map((x) => x.regle), profil).to.include("4");
      }
    });
  });

  // ------------------------------------------------------------------ R-F-1

  describe("R-F-1 : réponse hors schéma (statut hors [100, 599], Content-Type vide) normalisée ; entrée refusée par le schéma transformée en échec conforme", function () {
    const p = prestataireTest({ role: "interne", url: "http://127.0.0.1:1/", auth: { method: "aucune", secret: null } });
    const imprint = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
    const horloge = () => horlogeFixe(Date.UTC(2026, 10, 3, 13, 53, 0), 3000);
    const valide = (data) => C.REGISTRE_ANCRAGE.valider(REF_ENTREE, { t: "2026-11-03T13:53:03.000Z", type: "reponse_rfc3161", data });

    it("acquerir : statut 999 → transport erreur_transport, http_status null, code http_hors_bornes permanent ; statut 99 idem ; Content-Type vide → null et type_contenu ; data conforme au schéma", async function () {
      for (const statut of [999, 99, 600, 0]) {
        const r = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 1, horloge: horloge(), transport: transportFactice({ status: statut, entetes: { "content-type": "text/plain", "retry-after": "30" }, corps: new Uint8Array(0), tronque: false }), retry: RETRY });
        expect(r.data, String(statut)).to.include({ transport: "erreur_transport", http_status: null, retry_after_s: null, token_sha256: null });
        expect(r.enregistrement, String(statut)).to.include({ error_code: "http_hors_bornes", error_class: "permanente", alert: "alerte", outcome: "echec_permanente", http_status: null, transport: "erreur_transport" });
        expect(valide(r.data).valide, `${statut} : ${valide(r.data).erreurs[0]}`).to.equal(true);
      }
      const vide = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 1, horloge: horloge(), transport: transportFactice({ status: 200, entetes: { "content-type": "" }, corps: new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x02]), tronque: false }), retry: RETRY });
      expect(vide.data).to.include({ transport: "reponse", http_status: 200, content_type: null });
      expect(vide.enregistrement).to.include({ error_code: "type_contenu", error_class: "permanente", content_type: null });
      expect(valide(vide.data).valide, valide(vide.data).erreurs[0]).to.equal(true);
      const espaces = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 1, horloge: horloge(), transport: transportFactice({ status: 200, entetes: { "content-type": "   " }, corps: new Uint8Array(0), tronque: false }), retry: RETRY });
      expect(espaces.data.content_type).to.equal(null);
    });

    it("planificateur.rejeter (entrée hors schéma) : jeton → tentative echec_permanente entree_non_conforme puis relève ou refus ; ots → echec_transitoire et soumission rejouée ; registre → echec_registre", function () {
      const { p: pl, file } = planificateurSurFile("rf1-rejeter");
      jusquAuJetonDePeriode(pl);
      const idJeton = `jeton_periode:${PERIOD_HASH}`;
      const actions = pl.rejeter(idJeton, { t: "2026-11-03T14:00:03.000Z", attempt: 1, code: "entree_non_conforme", detail: "/data/http_status" });
      const d = pl.demandes.get(idJeton);
      expect(d.attempts[0]).to.include({ outcome: "echec_permanente", error_code: "entree_non_conforme" });
      expect(d.attempts[0].detail).to.include("/data/http_status");
      expect(actions.find((a) => a.action === "rejeter_reponse").detail).to.deep.equal({ error_code: "entree_non_conforme", class: "permanente" });
      expect(actions.find((a) => a.action === "journaliser" && a.detail.event === "anchor_response_rejected").detail).to.include({ error_code: "entree_non_conforme", attempt: 1, provider: "qtsa-principal" });
      // Erreur permanente chez le principal : relève immédiate au secours (EX-5.12, EX-8.8).
      expect(actions.find((a) => a.action === "releve").detail).to.deep.equal({ provider: "qtsa-secours" });
      expect(d.attempts[1]).to.include({ provider: "qtsa-secours", outcome: "en_cours" });
      expect(d.state).to.equal("envoyee");
      // OpenTimestamps : la soumission envoyée est rejouée au pas de retry (même engagement).
      const idOts = `ots_periode:${PERIOD_HASH}`;
      const a2 = pl.rejeter(idOts, { t: "2026-11-03T14:00:04.000Z", attempt: 1, code: "entree_non_conforme", detail: "/data/calendars_answered" });
      const o = pl.demandes.get(idOts);
      expect(o.attempts[0]).to.include({ outcome: "echec_transitoire", error_code: "entree_non_conforme" });
      expect(o.state).to.equal("a_reprendre");
      expect(a2.find((x) => x.action === "programmer" && x.request_id === idOts).detail).to.deep.equal({ reason: "backoff", next_at: "2026-11-03T14:00:09.000Z" });
      // Registre : traité comme un échec transitoire du registre (reprise), jamais abandonné pour une période.
      const idAncre = `ancre_registre_periode:${PERIOD_HASH}`;
      const avant = pl.demandes.get(idAncre).state;
      expect(avant).to.equal("obtenue");
      const a3 = pl.rejeter(idAncre, { t: "2026-11-03T14:00:05.000Z", code: "entree_non_conforme", detail: "/data/block_number" });
      expect(a3.find((x) => x.action === "journaliser").detail.event).to.equal("anchor_duplicate_ignored");
      // Demande inconnue : consignée, rien ne lève.
      const a4 = pl.rejeter(`jeton_point:0x${"ab".repeat(32)}`, { t: "2026-11-03T14:00:06.000Z", attempt: 1, detail: "/data" });
      expect(a4[0].detail).to.include({ event: "anchor_response_rejected", error_code: "entree_non_conforme" });
      // Le planificateur nomme le code et le chemin d'une entrée qu'il refuse.
      let err = null;
      try {
        pl.traiter(e("2026-11-03T14:00:07.000Z", "reponse_rfc3161", { ...REPONSE_HTTP(idJeton, 2, 503, 1), http_status: 999 }));
      } catch (x) {
        err = x;
      }
      expect(err).to.be.instanceOf(C.ErreurPlanificateur);
      expect(err.code).to.equal("entree_non_conforme");
      expect(err.chemin).to.equal("/data/http_status");
      file.fermer();
    });

    it("composant : un client qui rend un résultat hors schéma (block_number négatif) ne laisse aucune demande envoyee sans issue : echec entree_non_conforme, reprise programmée", async function () {
      const dir = temporaire("rf1-composant");
      const appels = [];
      const envoyeur = {
        repertoire: path.join(dir, "captures"),
        async ancrer({ requestId }) {
          appels.push(requestId);
          return { type: "inclusion_registre", data: { request_id: requestId, block_number: -1, capture_sha256: SHA("capture") }, outputs: {} };
        },
      };
      const m = await H.monter({
        dir, role: "aucun", evenements: { 0: 1, 5: 1 }, surcharges: { registry: { checkpoints: "tous" } },
        clients: { registre: { envoyeur } }, contexteSurcharges: { cleChaine: { adresse: () => `0x${"11".repeat(20)}`, signerCondense: () => ({ r: `0x${"22".repeat(32)}`, s: `0x${"33".repeat(32)}`, v: 27 }) } },
      });
      await m.remettrePoint(0);
      expect(appels).to.have.lengthOf(1);
      const d = m.composant.demandes().find((x) => x.kind === "ancre_registre_point");
      expect(d.state).to.equal("a_reprendre");
      expect(d.attempts[0]).to.include({ outcome: "echec_transitoire", error_code: "entree_non_conforme" });
      expect(d.due_at).to.not.equal(null);
      const rejets = m.journal.de("anchor_response_rejected");
      expect(rejets.some((l) => l.data.error_code === "entree_non_conforme" && l.data.detail === "/data/block_number")).to.equal(true);
      expect(rejets.some((l) => l.data.error_code === "entree_refusee")).to.equal(false);
      // La reprise programmée repart (le client répond de nouveau).
      await m.horloge.avancer(6000, m.calme);
      expect(appels.length).to.be.at.least(2);
      await m.composant.arreter({ attendre: false });
    });
  });

  // ------------------------------------------------------------------ R-A-1

  describe("R-A-1 : une ligne illisible d'acquisitions.ndjson est ignorée et signalée, jamais bloquante ; index des nonces en mémoire", function () {
    it("lireAcquisitions rend { enregistrements, tronquee, illisibles } ; dernieresAcquisitions, promu et nonceConnu servent ; signaler appelé une fois par fichier ; acquerir aboutit", async function () {
      const dir = temporaire("ra1");
      const signales = [];
      const depot = A.DepotAncres.ouvrir({ racine: dir, orgId: H.F.ORG, journalId: H.F.JOURNAL, signaler: (P, ill) => signales.push([P, ill.length, ill[0].raison]) });
      const P1 = 1793707200;
      const P2 = 1793710800;
      const saine = JSON.stringify({ attempt_id: "jeton_periode:aaaa:1", nonce: "0x0000000000000001", outcome: "echec_transitoire", object: "manifeste", imprint: `0x${"11".repeat(32)}` });
      fs.writeFileSync(path.join(depot.repertoire(P1), "acquisitions.ndjson"), `${saine}\n${saine.slice(0, 40)}${saine}\nnull\n[]\n42\n"x"\n${saine}\n`);
      const lu = depot.lireAcquisitions(P1);
      expect(lu.enregistrements).to.have.lengthOf(2);
      expect(lu.tronquee).to.equal(false);
      expect(lu.illisibles.map((x) => x.ligne)).to.deep.equal([2, 3, 4, 5, 6]);
      expect(lu.illisibles[0].raison).to.match(/^json_/);
      expect(lu.illisibles.slice(1).every((x) => x.raison === "enregistrement_non_objet")).to.equal(true);
      expect(depot.dernieresAcquisitions(P1).enregistrements).to.have.lengthOf(1);
      expect(depot.promu("manifeste", P1)).to.equal(null);
      expect(depot.nonceConnu(0x1n)).to.equal(true);
      expect(depot.nonceConnu(0x2n)).to.equal(false);
      depot.lireAcquisitions(P1);
      depot.dernieresAcquisitions(P1);
      expect(signales).to.deep.equal([[P1, 5, lu.illisibles[0].raison]], "signalé une fois par fichier et par ouverture");
      // Une acquisition d'une autre période aboutit malgré le fichier corrompu (aucune exception, une seule requête réseau).
      const p = prestataireTest({ role: "interne", url: "http://127.0.0.1:1/", auth: { method: "aucune", secret: null } });
      const tsr = octets("spec", "vecteurs", "ct-5", "reponses", "granted-requete-point-k2.tsr");
      const transport = transportFactice(reponse200(tsr));
      const imprint = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
      const r = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 1, periodStart: P2, horloge: horlogeFixe(Date.UTC(2026, 10, 3, 13, 53, 0), 3000), aleatoire: aleaFixe(new Uint8Array(8).fill(7)), depot, transport });
      expect(r.outcome).to.equal("obtenue");
      expect(transport.appels).to.have.lengthOf(1);
      // L'index des nonces est tenu à jour par ajouterAcquisition (sans relire les périodes).
      expect(depot.nonceConnu(0x74a6f4979421411en)).to.equal(true);
      expect(depot.promu("point", P2, imprint).attempt_id).to.equal("point:6a8e035ab9b90937:1");
      // Un second dépôt sur la même racine construit son index depuis le disque.
      const depot2 = new A.DepotAncres({ racine: dir, orgId: H.F.ORG, journalId: H.F.JOURNAL });
      expect(depot2.nonceConnu("0x74a6f4979421411e")).to.equal(true);
      expect(depot2.nonceConnu("0x0000000000000001")).to.equal(true);
      // Une ligne tronquée en fin de fichier reste signalée à part.
      fs.appendFileSync(path.join(depot.repertoire(P1), "acquisitions.ndjson"), '{"b":2');
      const lu2 = depot.lireAcquisitions(P1);
      expect(lu2.tronquee).to.equal(true);
      expect(lu2.enregistrements).to.have.lengthOf(2);
    });
  });

  // ------------------------------------------------------------------ R-D-1, R-D-4 (Envoyeur)

  describe("R-D-1 et R-D-4 : Envoyeur — reçu sans journal Anchored, deja_fait sans capture, index en mémoire des envois", function () {
    const CONSTANTES = lireJson("spec", "vecteurs", "ct-4", "constantes.json");
    const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
    const CONTRATS = { attestation_registry: CONSTANTES.contracts.attestation_registry, period_registry: CONSTANTES.contracts.period_registry, recorder_registry: CONSTANTES.contracts.recorder_registry };
    const ORG4 = CONSTANTES.organisation.org_id;
    const JOURNAL4 = CONSTANTES.journal.journal_id;
    const JOURNAL_REF = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
    const K2 = { hash: "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", fingerprint: "0x7f721a4526c614882ff41ac33792c6d05fa7fb6dd98bc1c369d0e277029f4e44" };
    const K3 = { hash: "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", fingerprint: "0xa1aeb874daa988a4833c394476c4ea740096a3496ed081ae6f8592fb4912a837" };
    const CLE = new R.SignataireChaineFichier(N.sha256(N.utf8("noortrace/ancrage/test/h1/cle-chaine-01")));
    const ED25519 = CONSTANTES.recorders[0].public_key;

    function contexte(prefixe, { altere = null } = {}) {
      const noeud = new NoeudFactice({ validateurs: validateursEssai(CONSTANTES), points: POINTS, contrats: CONTRATS });
      const base = noeud.transport();
      const etat = { strippes: 0, lectures: 0 };
      const transport = async (req) => {
        const r = await base(req);
        if (!altere) return r;
        const q = JSON.parse(Buffer.from(req.octets).toString("utf8"));
        const rep = JSON.parse(Buffer.from(r.octets).toString("utf8"));
        const modifiee = altere(q, rep, etat, req.url);
        return modifiee ? { status: 200, octets: N.utf8(JSON.stringify(modifiee)) } : r;
      };
      const rpc = new R.ClientRpc({ points: POINTS, transport, identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
      const repertoire = temporaire(prefixe);
      let monotone = 0;
      const horloge = { murale: () => Date.UTC(2026, 10, 9, 12, 0, 0) + monotone, monotone: () => monotone };
      const attendre = async (ms) => { monotone += ms; };
      const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats: CONTRATS, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux: { validators: validateursEssai(CONSTANTES).validators, source: "jeu d'essai de CT-4 annexe A.2" } };
      const journal = [];
      const creer = () => new R.Envoyeur({ rpc, repertoireEnvois: repertoire, instance, horloge, attendre, delais: { recuMs: 60000, sondageMs: 500 }, journal: (niveau, evenement, champs) => journal.push({ niveau, evenement, champs }) });
      noeud.approvisionner(CLE.adresse(), 4719000000n);
      noeud.inscrire({ orgId: ORG4, chainKey: CLE.adresse(), ed25519PubKey: ED25519, journalId: JOURNAL4 });
      return { noeud, rpc, repertoire, envoyeur: creer(), creer, etat, journal, instance };
    }
    const ancrer = (c, K, envoyeur = c.envoyeur) => envoyeur.ancrer({ orgId: ORG4, journalId: JOURNAL_REF, objet: K.hash, docType: R.DOC_TYPE_POINT_DE_CONTROLE, cle: CLE, fingerprint: K.fingerprint, clePublique: ED25519 });
    const fichiers = (c) => fs.readdirSync(c.repertoire).sort();

    it("R-D-1 : le nœud rend une fois un reçu 0x1 sans journal : le reçu est relu sur les autres points et l'ancre capturée (aucune issue 0x1 sans capture)", async function () {
      const c = contexte("rd1-une-fois", {
        altere: (q, rep, etat) => {
          if (q.method !== "eth_getTransactionReceipt" || !rep.result) return null;
          etat.lectures += 1;
          if (etat.strippes >= 1) return null;
          etat.strippes += 1;
          rep.result.logs = [];
          return rep;
        },
      });
      const r = await ancrer(c, K2);
      expect(r.type, JSON.stringify(r)).to.equal("inclusion_registre");
      expect(c.etat.strippes).to.equal(1);
      expect(c.etat.lectures).to.be.at.least(2, "le reçu a été relu sur un autre point");
      expect(fichiers(c).filter((n) => n.startsWith("capture-"))).to.have.lengthOf(1);
      expect(fichiers(c).filter((n) => n.startsWith("issue-"))).to.have.lengthOf(1);
    });

    it("R-D-1 : tous les points rendent le reçu sans journal : issue incertaine (recu_incertain, aucun fichier d'issue), envoi toujours sans issue ; au retour du registre, renvoyer conclut et capture", async function () {
      const c = contexte("rd1-panne", {
        altere: (q, rep, etat) => {
          if (!etat.actif || q.method !== "eth_getTransactionReceipt" || !rep.result) return null;
          etat.strippes += 1;
          rep.result.logs = [];
          return rep;
        },
      });
      c.etat.actif = true;
      const r = await ancrer(c, K2);
      expect(r.type).to.equal("echec_registre");
      expect(r.data.code).to.equal("recu_incertain");
      expect(c.etat.strippes).to.be.at.least(4, "relu sur chaque point");
      expect(fichiers(c).filter((n) => n.startsWith("issue-"))).to.deep.equal([], "aucune issue 0x1 écrite sans le journal");
      expect(fichiers(c).filter((n) => n.startsWith("capture-"))).to.deep.equal([]);
      const hash = r.outputs.transaction_hash;
      expect(c.envoyeur.envoisEnAttente(CLE.adresse()).map((x) => x.transaction_hash)).to.deep.equal([hash]);
      // Nouvelle tentative pendant la panne : l'envoi sans issue est renvoyé puis relu ; toujours incertain.
      const r2 = await ancrer(c, K2);
      expect(r2.type).to.equal("echec_registre");
      expect(r2.data.code).to.equal("attente_nonce");
      expect(r2.outputs.pending).to.deep.equal([hash]);
      const r3 = await c.envoyeur.renvoyer(hash, { requestId: `ancre_registre_point:${K2.hash}` });
      expect(r3.data.code).to.equal("recu_incertain");
      // Le registre redevient sain : le renvoi conclut, capture et écrit l'issue 0x1.
      c.etat.actif = false;
      const r4 = await c.envoyeur.renvoyer(hash, { requestId: `ancre_registre_point:${K2.hash}` });
      expect(r4.type, JSON.stringify(r4)).to.equal("inclusion_registre");
      expect(r4.data.request_id).to.equal(`ancre_registre_point:${K2.hash}`);
      expect(fichiers(c).filter((n) => n.startsWith("capture-"))).to.have.lengthOf(1);
      expect(fichiers(c).filter((n) => n.startsWith("issue-"))).to.have.lengthOf(1);
      expect(c.envoyeur.envoisEnAttente(CLE.adresse())).to.deep.equal([]);
      // Une ancre suivante part normalement (la clé est libre).
      expect((await ancrer(c, K3)).type).to.equal("inclusion_registre");
    });

    it("R-D-1 : deja_fait sous notre clé sans capture (fichiers de capture perdus) : la transaction de l'envoi connu est relue et capturée → inclusion_registre, plus jamais deja_fait", async function () {
      const c = contexte("rd1-deja-fait");
      const r = await ancrer(c, K2);
      expect(r.type).to.equal("inclusion_registre");
      for (const n of fichiers(c)) if (/^(capture|bloc|certificat)-/.test(n)) fs.rmSync(path.join(c.repertoire, n));
      const e2 = c.creer();
      const r2 = await ancrer(c, K2, e2);
      expect(r2.type, JSON.stringify(r2)).to.equal("inclusion_registre");
      expect(r2.data.request_id).to.equal(`ancre_registre_point:${K2.hash}`);
      expect(fichiers(c).filter((n) => n.startsWith("capture-"))).to.have.lengthOf(1);
      expect(c.journal.some((l) => l.evenement === "registry_capture_resumed")).to.equal(true);
      expect(c.journal.filter((l) => l.evenement === "registry_send_failed" && l.champs.code === "deja_fait")).to.deep.equal([]);
    });

    it("R-D-4 : l'Envoyeur tient un index en mémoire des envois et de leurs issues, chargé une fois et égal au répertoire ; envoi(hash) ; un second Envoyeur le reconstruit depuis le disque", async function () {
      const c = contexte("rd4", {
        altere: (q, rep, etat) => {
          if (!etat.absent || q.method !== "eth_getTransactionReceipt") return null;
          return { ...rep, result: null };
        },
      });
      c.etat.absent = true;
      const r = await ancrer(c, K2);
      expect(r.data.code).to.equal("recu_absent");
      const hash = r.outputs.transaction_hash;
      expect(c.envoyeur.envoi(hash)).to.not.equal(null);
      expect(c.envoyeur.envoi(hash).issue).to.equal(null);
      expect(c.envoyeur.envoi(`0x${"00".repeat(32)}`)).to.equal(null);
      expect(c.envoyeur.envoisEnAttente(CLE.adresse()).map((x) => x.transaction_hash)).to.deep.equal([hash]);
      expect(R.envoisSansIssue(c.repertoire, CLE.adresse()).map((x) => x.transaction_hash)).to.deep.equal([hash]);
      expect(R.envoisSansIssueParHash(new Map(R.lireEnvois(c.repertoire).map((x) => [x.envoi.transaction_hash, x])), CLE.adresse()).map((x) => x.transaction_hash)).to.deep.equal([hash]);
      // Second Envoyeur sur le même répertoire : l'index vient du disque.
      const e2 = c.creer();
      expect(e2.envoi(hash).envoi.transaction_hash).to.equal(hash);
      const r2 = await ancrer(c, K2, e2);
      expect(r2.data.code).to.equal("attente_nonce");
      expect(r2.outputs.pending).to.deep.equal([hash]);
      // Le reçu revient : renvoyer conclut ; l'index porte l'issue ; plus rien en attente, dans l'un et l'autre Envoyeur après rechargement.
      c.etat.absent = false;
      const r3 = await e2.renvoyer(hash, { requestId: `ancre_registre_point:${K2.hash}` });
      expect(r3.type).to.equal("inclusion_registre");
      expect(e2.envoi(hash).issue.block_number).to.be.a("number");
      expect(e2.envoisEnAttente(CLE.adresse())).to.deep.equal([]);
      c.envoyeur.oublierIndex();
      expect(c.envoyeur.envoisEnAttente(CLE.adresse())).to.deep.equal([]);
      expect((await ancrer(c, K3, e2)).type).to.equal("inclusion_registre");
    });
  });

  // ------------------------------------------------------------------ R-D-2, R-D-3 (capture)

  describe("R-D-2 et R-D-3 : capture — certificat jamais persisté, index ou fichiers corrompus", function () {
    const rep = path.join(RACINE, "spec", "vecteurs", "ct-4", "capture", "periode-1");
    const noms = fs.readdirSync(rep);
    const fichiers = Object.fromEntries(noms.map((n) => [n, new Uint8Array(fs.readFileSync(path.join(rep, n)))]));
    const validateurs = lireJson("test", "fixtures", "certificat-commit", "validators.json");
    const lecteurDe = (f) => ({ lire: (n) => (typeof n === "string" ? f[n] ?? null : null), existe: (n) => n in f });
    const POINT = "http://127.0.0.1:8645";
    const index = JSON.parse(Buffer.from(fichiers["capture-16660-0-ancre.json"]).toString("utf8"));

    it("R-D-2 : capturer rend { erreur: certificat_indisponible, check CP-4 } quand noor_getCommitCertificate répond toujours « not yet persisted » (plus de ReferenceError)", async function () {
      let appels = 0;
      const rpc = {
        points: () => [POINT],
        validateurDe: () => "v1",
        async appeler(methode, params, { point } = {}) {
          appels++;
          const ok = (result) => ({ point, octets: N.utf8(JSON.stringify({ jsonrpc: "2.0", id: 1, result })), erreur: null, resultat: result });
          const brut = (nom) => ({ point, octets: fichiers[nom], erreur: null, resultat: JSON.parse(Buffer.from(fichiers[nom]).toString("utf8")).result });
          if (methode === "eth_getTransactionReceipt") return brut(index.files.receipts[0].name);
          if (methode === "eth_chainId") return ok("0x84c");
          if (methode === "noor_txindexStatus") return ok({ last_indexed_height: 20000 });
          if (methode === "eth_getBlockByNumber") return brut(index.files.block.name);
          if (methode === "noor_getCommitCertificate") return { point, octets: new Uint8Array(0), erreur: { code: -32000, message: `commit certificate for block ${params[0]} not yet persisted; retry shortly` }, resultat: undefined };
          throw new Error(`méthode inattendue ${methode}`);
        },
      };
      const dir = temporaire("rd2");
      const r = await R.capturer({ rpc, transactionHash: index.transaction_hash, role: "ancre", contrat: index.contract, horloge: { murale: () => 0 }, repertoire: dir, instance: { evmChainId: 2124, bftChainId: "noortrace-2124-dev", jeux: validateurs }, attendre: async () => {}, point: POINT });
      expect(r.erreur).to.deep.equal({ code: "certificat_indisponible", check: "CP-4", message: `commit certificate for block 0x4114 not yet persisted; retry shortly` });
      expect(appels).to.be.at.least(100);
      expect(fs.readdirSync(dir).filter((n) => n.startsWith("capture-"))).to.deep.equal([]);
    });

    it("R-D-3 : verifierCapture rend CP-2 ou CP-6 echoue, jamais une exception : en-tête sans transactions, block_number chaîne, reçu nul dans l'index, index nul", function () {
      const bloc = JSON.parse(Buffer.from(fichiers[index.files.block.name]).toString("utf8"));
      const sansTransactions = { ...fichiers, [index.files.block.name]: N.utf8(JSON.stringify({ ...bloc, result: { ...bloc.result, transactions: undefined } })) };
      const v1 = R.verifierCapture({ fichiers: lecteurDe(sansTransactions), index, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
      expect(v1.verdicts["CP-2"]).to.equal("echoue");
      expect(v1.verdicts["CP-3"]).to.equal("echoue");
      const v2 = R.verifierCapture({ fichiers: lecteurDe(fichiers), index: { ...index, block_number: "\u000016648" }, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
      expect(v2.verdicts["CP-2"]).to.equal("echoue");
      expect(v2.verdicts["CP-6"]).to.equal("echoue");
      const v3 = R.verifierCapture({ fichiers: lecteurDe(fichiers), index: { ...index, files: { ...index.files, receipts: [null] } }, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
      expect(v3.verdicts["CP-3"]).to.equal("echoue");
      expect(v3.verdicts["CP-6"]).to.equal("echoue");
      for (const mauvais of [null, 42, "x", [], { files: null }, { ...index, transaction_index: -1 }, { ...index, transaction_index: 1e9 }, { ...index, log_index: "0" }, { ...index, role: 7 }]) {
        const v = R.verifierCapture({ fichiers: lecteurDe(fichiers), index: mauvais, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
        expect(Object.values(v.verdicts).some((x) => x !== "reussi"), JSON.stringify(mauvais).slice(0, 60)).to.equal(true);
      }
      const sain = R.verifierCapture({ fichiers: lecteurDe(fichiers), index, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
      expect(Object.values(sain.verdicts).every((x) => x === "reussi")).to.equal(true);
    });

    it("R-D-3 : 1 500 objets mutés (900 fichiers de réponses JSON-RPC, 600 index de capture, graine 606) : aucune exception, une capture mutée est refusée ou identique", function () {
      const indexes = noms.filter((n) => n.startsWith("capture-")).map((n) => JSON.parse(Buffer.from(fichiers[n]).toString("utf8")));
      const r = H.rng(606);
      let exceptions = 0;
      let refusees = 0;
      let identiques = 0;
      let acceptees = 0;
      for (let i = 0; i < 900; i++) {
        const ix = indexes[i % indexes.length];
        const cibles = [ix.files.block.name, ix.files.certificate.name, ...ix.files.receipts.map((x) => x.name)];
        const cible = cibles[Math.floor(r() * cibles.length)];
        const m = H.muterOctets(fichiers[cible], r);
        try {
          const v = R.verifierCapture({ fichiers: lecteurDe({ ...fichiers, [cible]: m.octets }), index: ix, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
          const tout = Object.values(v.verdicts).every((x) => x === "reussi");
          if (tout && Buffer.compare(Buffer.from(m.octets), Buffer.from(fichiers[cible])) !== 0) acceptees++;
          else if (tout) identiques++;
          else refusees++;
        } catch (err) {
          exceptions++;
          if (exceptions === 1) console.error("exception", cible, m.s, m.p, err);
        }
      }
      for (let i = 0; i < 600; i++) {
        const ix = indexes[i % indexes.length];
        const m = H.muterJson(ix, r);
        try {
          const v = R.verifierCapture({ fichiers: lecteurDe(fichiers), index: m.valeur, jeux: validateurs, bftChainId: "noortrace-2124-dev" });
          const tout = Object.values(v.verdicts).every((x) => x === "reussi");
          if (tout && JSON.stringify(m.valeur) !== JSON.stringify(ix)) acceptees++;
          else if (tout) identiques++;
          else refusees++;
        } catch (err) {
          exceptions++;
          if (exceptions === 1) console.error("exception index", m.s, m.chemin, err);
        }
      }
      expect(exceptions).to.equal(0);
      expect(refusees).to.be.at.least(1000);
      // Les « acceptations » d'un index muté portent toutes sur des membres que CP-2 à CP-6 ne jugent pas (node, captured_at, attempts, sending, checks).
      expect(acceptees).to.be.at.most(60);
      expect(identiques).to.be.at.least(1);
    });
  });

  // ------------------------------------------------------------------ R-E-1

  describe("R-E-1 : deux compteurs du même processus sur un même répertoire", function () {
    it("le second est refusé (déjà ouvert dans ce processus, AN-26) ; après fermeture, la réouverture sert la suite ; deux répertoires distincts coexistent", function () {
      const dir = temporaire("re1");
      const a = Compteur.ouvrir({ repertoire: dir });
      expect(a.suivant()).to.equal(1n);
      expect(() => Compteur.ouvrir({ repertoire: dir })).to.throw(ErreurCompteur, /déjà ouvert dans ce processus/);
      expect(() => Compteur.ouvrir({ repertoire: `${dir}${path.sep}..${path.sep}${path.basename(dir)}` })).to.throw(ErreurCompteur, /déjà ouvert/);
      expect(a.suivant()).to.equal(2n);
      expect(Compteur.ouverts()).to.include(fs.realpathSync(dir));
      a.fermer();
      expect(Compteur.ouverts()).to.not.include(fs.realpathSync(dir));
      const b = Compteur.ouvrir({ repertoire: dir });
      expect(b.suivant()).to.equal(3n);
      const autre = Compteur.ouvrir({ repertoire: temporaire("re1-autre") });
      expect(autre.suivant()).to.equal(1n);
      b.fermer();
      autre.fermer();
    });
  });

  // ------------------------------------------------------------------ R-F-2, R-F-5 (supervision)

  describe("R-F-2 et R-F-5 : supervision — valeurs d'étiquette normalisées, lignes bornées, journal servi même si une métrique échoue", function () {
    it("R-F-2 : un identifiant de prestataire TSA-Interne n'empêche plus la métrique : valeur abaissée en tsa-interne ; caractères hors motif remplacés par _", function () {
      const s = new C.Supervision();
      expect(() => s.compter("noortrace_anchoring_attempts_total", { kind: "jeton_point", provider: "TSA-Interne", outcome: "obtenue" })).to.not.throw();
      expect(s.metriques()).to.include('noortrace_anchoring_attempts_total{kind="jeton_point",provider="tsa-interne",outcome="obtenue"} 1');
      expect(C.normaliserValeurEtiquette("TSA-Interne")).to.equal("tsa-interne");
      expect(C.normaliserValeurEtiquette("Hote Ete/1 x")).to.equal("hote_ete_1_x");
      expect(C.normaliserValeurEtiquette("qtsa-principal")).to.equal("qtsa-principal");
      expect(() => s.compter("noortrace_anchoring_attempts_total", { kind: "jeton_point", provider: "x", outcome: "obtenue", autre: 1 })).to.throw(TypeError, /hors de la table/);
    });

    it("R-F-5 : Supervision.lignes est bornée (maxLignes, défaut 10 000) : les plus anciennes sont écartées et comptées (dropped), toutes remises au journal", function () {
      const recues = [];
      const s = new C.Supervision({ journal: { consigner: (n, c, ev) => recues.push(ev) }, maxLignes: 5 });
      for (let i = 0; i < 12; i++) s.consigner("info", "anchor_retry", { request_id: `jeton_point:0x${"ab".repeat(32)}`, i });
      expect(s.lignes).to.have.lengthOf(5);
      expect(s.lignes[0].data.i).to.equal(7);
      expect(s.dropped).to.equal(7);
      expect(recues).to.have.lengthOf(12);
      expect(new C.Supervision().maxLignes).to.equal(C.MAX_LIGNES_DEFAUT);
      expect(C.MAX_LIGNES_DEFAUT).to.equal(10000);
      const s2 = new C.Supervision({ maxLignes: 0 });
      s2.consigner("info", "anchor_retry", {});
      expect(s2.lignes).to.deep.equal([]);
      expect(s2.dropped).to.equal(1);
    });

    it("R-F-2 : dans le composant, un prestataire TSA-Interne donne métriques et checkpoint_countersigned ; une métrique en défaut est consignée une fois et les lignes d'EX-8.15 sont quand même écrites", async function () {
      const dir = temporaire("rf2-composant");
      const prestataires = [H.prestataire("qtsa-principal", "principal"), H.prestataire("qtsa-secours", "secours"), H.prestataire("TSA-Interne", "interne")];
      const m = await H.monter({ dir, prestataires, evenements: { 0: 1, 3: 1, 8: 1 } });
      for (let k = 0; k <= 5; k++) await m.remettrePoint(k);
      await m.horloge.avancer(5000, m.calme);
      expect(m.composant.demandes().find((x) => x.kind === "jeton_point").state).to.equal("obtenue");
      expect(m.journal.de("checkpoint_countersigned")).to.have.lengthOf(1);
      expect(m.journal.de("anchoring_supervision_failed")).to.deep.equal([]);
      expect(m.composant.metriques()).to.include('provider="tsa-interne"');
      expect(m.composant.metriques()).to.include("noortrace_anchoring_attempts_total{");
      // Métrique en défaut : le journal continue, l'erreur de métrique est consignée une seule fois.
      m.composant.supervision.releverActions = () => {
        throw new Error("metrique en defaut (essai)");
      };
      const avant = m.journal.de("checkpoint_countersigned").length;
      for (let k = 6; k <= 10; k++) await m.remettrePoint(k);
      await m.horloge.avancer(5000, m.calme);
      expect(m.journal.de("checkpoint_countersigned").length).to.equal(avant + 1);
      expect(m.journal.de("anchoring_supervision_failed")).to.have.lengthOf(1);
      expect(m.journal.de("anchoring_supervision_failed")[0].data).to.include({ what: "metriques" });
      await m.composant.arreter({ attendre: false });
    });
  });

  // ------------------------------------------------------------------ R-F-3

  describe("R-F-3 : stockage_relu borné : périodes closes sans leurs demandes finales et dernier point de chaque période ouverte (EX-8.12)", function () {
    it("10 001 points sur 170 périodes (169 closes) : l'entrée est acceptée, 1 point et 169 périodes examinés, aucune entrée refusée ; les séries en mémoire ne gardent que la période ouverte", async function () {
      const dir = temporaire("rf3");
      const ouverte = H.PERIODE;
      const periodes = [];
      const points = [];
      const ZERO = `0x${"00".repeat(32)}`;
      let seq = 1;
      for (let i = 169; i >= 0; i--) {
        const P = ouverte - 3600 * i;
        const n = i === 0 ? 30 : 59;
        for (let j = 0; j < n; j++) {
          points.push({ version: 0, org_id: H.F.ORG, journal_id: H.F.JOURNAL, period_start: P, tree_size: j, root: ZERO, last_seq: seq - 1, last_hash: ZERO, checkpoint_ts: N.ecrireHorodatage((P + 60 * j) * 1000), prev_checkpoint_hash: ZERO, key_id: "rec-test-01", sig: `0x${"00".repeat(64)}` });
        }
        if (i > 0) {
          const manifeste = N.construireManifeste({ org_id: H.F.ORG, journal_id: H.F.JOURNAL, period_start: P, first_seq: seq, hashes: [SHA(`evenement ${P}`)], prev_period_hash: ZERO, recorder_key_id: "rec-test-01", nonce: SHA(`nonce ${P}`), generated_at: N.ecrireHorodatage((P + 3600) * 1000 + 250) });
          periodes.push({ manifeste, signature: null });
          seq += 1;
        }
      }
      expect(points).to.have.lengthOf(10001);
      expect(periodes).to.have.lengthOf(169);
      const m = await H.monter({ dir, role: "aucun", contexteSurcharges: { listerPeriodes: async () => periodes, listerPoints: async () => points }, surcharges: { rfc3161: { manifest: { fallback_after_s: 3600 } } } });
      await m.calme();
      expect(m.journal.de("anchor_response_rejected").filter((l) => ["entree_refusee", "entree_non_conforme"].includes(l.data.error_code))).to.deep.equal([]);
      expect(m.journal.de("anchoring_storage_unreadable")).to.deep.equal([]);
      const rebuilt = m.journal.de("anchoring_queue_rebuilt")[0].data;
      expect(rebuilt).to.include({ periods: 169, checkpoints: 1 });
      // Montage sans registre : une demande jeton_periode recréée par période close, et aucune ancre au registre,
      // qui ne pourrait jamais partir (EX-8.4 règle 2 ; étape 6 : avant, chaque période recréait aussi son ancre).
      expect(m.composant.envoyeur).to.equal(null);
      expect(rebuilt.recreated).to.be.at.least(169);
      expect(m.composant.demandes().filter((d) => d.kind.startsWith("ancre_registre_"))).to.deep.equal([]);
      expect(m.composant.series.size).to.equal(1);
      expect(m.composant.series.get(ouverte)).to.have.lengthOf(30);
      expect(m.composant.points.size).to.equal(30);
      // Un redémarrage avec la file relue : les périodes closes ont leurs demandes (non finales : elles sont toujours transmises), l'entrée reste bornée.
      await m.composant.arreter({ attendre: false });
      const journal2 = H.F.journalMemoire();
      const c2 = m.creer({ epoque: 2, journal: journal2 });
      await c2.demarrer();
      await H.F.attenteCalme(c2, { pasMs: 3, maxMs: 20000 })();
      expect(journal2.de("anchor_response_rejected").filter((l) => ["entree_refusee", "entree_non_conforme"].includes(l.data.error_code))).to.deep.equal([]);
      expect(journal2.de("anchoring_queue_rebuilt")[0].data.recreated).to.equal(0);
      await c2.arreter({ attendre: false });
    });
  });

  // ------------------------------------------------------------------ R-F-4

  describe("R-F-4 : arrêt pendant une acquisition en vol (EX-5.8 : le choix est fait une fois)", function () {
    it("arreter() attend la réponse en vol : le jeton promu est écrit dans la file (obtenue) ; au redémarrage aucune requête ne repart et result.sha256 est le jeton promu", async function () {
      const dir = temporaire("rf4");
      let liberer = null;
      const barriere = new Promise((r) => { liberer = r; });
      const m = await H.monter({ dir, debutMs: FIN_PERIODE_MS, evenements: { 0: 1 }, crochet: async (req, rep) => { if (req.url.includes("principal")) await barriere; return rep; } });
      await m.remettreCloture();
      await new Promise((r) => setTimeout(r, 30));
      expect(m.transport.appels.filter((r) => r.url.includes("principal"))).to.have.lengthOf(1);
      const arret = m.composant.arreter({ attendre: true });
      await new Promise((r) => setTimeout(r, 30));
      expect(m.composant.etat().arret_demande).to.equal(true);
      liberer();
      await arret;
      const acq = m.acquisitions();
      expect(acq.filter((x) => x.outcome === "obtenue" && x.promoted)).to.have.lengthOf(1);
      const relue = m.etatFile();
      const sur = relue.parId.get(`jeton_periode:${m.serie.periodHash}`);
      expect(sur.state).to.equal("obtenue");
      expect(sur.result.sha256).to.equal(acq[0].token_sha256);
      expect(m.journal.de("anchoring_stopped")).to.have.lengthOf(1);
      // Redémarrage : le jeton est relu obtenue, aucune requête au principal ne repart.
      const journal2 = H.F.journalMemoire();
      const c2 = m.creer({ epoque: 2, journal: journal2 });
      await c2.demarrer();
      const calme2 = H.F.attenteCalme(c2, { pasMs: 3, maxMs: 20000 });
      await calme2();
      await m.horloge.avancer(10000, calme2);
      expect(m.transport.appels.filter((r) => r.url.includes("principal"))).to.have.lengthOf(1);
      const d = c2.demandes().find((x) => x.kind === "jeton_periode");
      expect(d.state).to.equal("obtenue");
      expect(d.result.sha256).to.equal(acq[0].token_sha256);
      expect(m.acquisitions()).to.have.lengthOf(1);
      await c2.arreter();
    });

    it("la borne de l'attente joue : une réponse qui ne vient jamais ne retient pas l'arrêt au-delà de request_timeout_ms + marge (horloge injectée)", async function () {
      const dir = temporaire("rf4-borne");
      const m = await H.monter({ dir, debutMs: FIN_PERIODE_MS, evenements: { 0: 1 }, crochet: async (req, rep) => (req.url.includes("principal") ? new Promise(() => {}) : rep) });
      await m.remettreCloture();
      await new Promise((r) => setTimeout(r, 30));
      let fini = false;
      const arret = m.composant.arreter({ attendre: true }).then(() => { fini = true; });
      await new Promise((r) => setTimeout(r, 30));
      expect(fini).to.equal(false);
      await m.horloge.avancer(15001);
      await arret;
      expect(fini).to.equal(true);
      expect(m.journal.de("anchoring_stop_timeout")).to.have.lengthOf(1);
      expect(m.journal.de("anchoring_stopped")).to.have.lengthOf(1);
    });
  });

  // ------------------------------------------------------------------ R-A-2

  describe("R-A-2 : une structure malformée dans signedAttrs (ou tout TLV d'un jeton) met T-1 en échec (CT-6 EX-9.7, EX-9.4), non T-4", function () {
    const cas = lireJson("test", "fixtures", "ancrage-h1", "jetons-mutes-t1.json").cases;

    it("les 21 jetons mutés de la relecture (T1) sont refusés par lireJeton et T-1 échoue ; leurs jetons d'origine se lisent toujours", function () {
      expect(cas).to.have.lengthOf(21);
      for (const c of cas) {
        const o = new Uint8Array(Buffer.from(c.hex, "hex"));
        expect(() => A.lireJeton(o), `${c.base} ${c.mutation} ${c.position}`).to.throw(A.ErreurDer);
        const v = A.verifierJeton({ octets: o, imprintAttendue: null, ancres: null, aGenTime: true });
        expect(v.checks["T-1"], `${c.base} ${c.mutation}`).to.equal("echoue");
        expect(v.checks["T-4"]).to.equal("non_execute");
      }
      for (const base of new Set(cas.map((c) => c.base))) expect(() => A.lireJeton(octets("spec", "vecteurs", "ct-6", "rfc3161", "jetons", base)), base).to.not.throw();
    });

    it("parcourirDer : étiquette universelle 0, SEQUENCE primitive, INTEGER construit, BOOLEAN hors 00/ff, longueur interne débordante : refusés ; une valeur d'attribut saine passe", function () {
      const lire = (hex) => A.lireUnique(new Uint8Array(Buffer.from(hex, "hex")), 1);
      expect(() => A.parcourirDer(lire("3003020101"))).to.not.throw();
      expect(() => A.parcourirDer(lire("30040000" + "0101"))).to.throw(A.ErreurDer);
      expect(() => lire("1003020101")).to.not.throw("la lecture d'un TLV seul n'interprète pas la forme");
      expect(() => A.parcourirDer(lire("1003020101"))).to.throw(A.ErreurDer, /forme primitive/);
      expect(() => A.parcourirDer(lire("3003220101"))).to.throw(A.ErreurDer, /forme construite/);
      expect(() => A.parcourirDer(lire("30030101ab"))).to.throw(A.ErreurDer, /BOOLEAN/);
      expect(() => A.parcourirDer(lire("3003020201"))).to.throw(A.ErreurDer);
      expect(() => A.parcourirDer(lire("3005300302010a"))).to.not.throw();
      expect(() => A.parcourirDer(lire("3005300202010a"))).to.throw(A.ErreurDer);
    });
  });

  // ------------------------------------------------------------------ Lectures H1 (soupçons du rapport)

  describe("lectures H1 : nonce OpenTimestamps durable avant soumission (a), prestataire révoqué hors de l'alternance (b), due_at d'une demande retenue par min_interval_ms (c), TimeStampToken illisible = reponse_illisible (e)", function () {
    it("(a) EX-6.2 : tant que ots/<objet>.nonce ne s'écrit pas, rien n'est soumis au calendrier (soumission rejouée) ; dès qu'il s'écrit, la soumission part avec ce nonce", async function () {
      const dir = temporaire("lecture-a");
      const posts = [];
      const transportOts = {
        async post(url, corps) {
          posts.push({ url, corps });
          return { status: 503, entetes: {}, corps: new Uint8Array(0) };
        },
        async get() {
          return { status: 404, entetes: {}, corps: new Uint8Array(0) };
        },
      };
      const m = await H.monter({ dir, debutMs: FIN_PERIODE_MS, evenements: { 0: 1 }, clients: { ots: { transport: transportOts } }, surcharges: { opentimestamps: { enabled: true }, rfc3161: { manifest: { fallback_after_s: 3600 } } } });
      // Le chemin du nonce est occupé par un répertoire : création exclusive impossible, lecture impossible.
      fs.mkdirSync(path.join(m.repertoirePeriode, "ots", "manifeste.nonce"), { recursive: true });
      await m.remettreCloture();
      await m.calme();
      expect(posts).to.have.lengthOf(0, "rien n'est soumis tant que le nonce n'est pas durable");
      expect(m.journal.de("anchor_queue_write_failed").some((l) => String(l.data.reason).startsWith("nonce_ots:"))).to.equal(true);
      expect(m.journal.de("ots_submitted").some((l) => l.data.errors === "nonce_non_durable")).to.equal(true);
      let d = m.composant.demandes().find((x) => x.kind === "ots_periode");
      expect(d.state).to.equal("a_reprendre");
      expect(d.attempts[0]).to.include({ outcome: "echec_transitoire", error_code: "calendriers_insuffisants" });
      const nonceMemoire = m.composant.planificateur.interne.get(d.id).nonceOts;
      // Le disque redevient écrivable : la reprise écrit le nonce puis soumet le même engagement.
      fs.rmdirSync(path.join(m.repertoirePeriode, "ots", "manifeste.nonce"));
      await m.horloge.avancer(6000, m.calme);
      expect(posts.length).to.be.at.least(2, "une soumission à chaque calendrier");
      expect(fs.readFileSync(path.join(m.repertoirePeriode, "ots", "manifeste.nonce"), "utf8").trim()).to.equal(nonceMemoire);
      d = m.composant.demandes().find((x) => x.kind === "ots_periode");
      expect(m.composant.planificateur.interne.get(d.id).nonceOts).to.equal(nonceMemoire);
      const engagement = N.sha256Hex(N.concatener(N.hexVersOctets(m.serie.periodHash, 32), N.hexVersOctets(nonceMemoire, 16)));
      expect(N.octetsVersHex(posts[0].corps)).to.equal(engagement);
      await m.composant.arreter({ attendre: false });
    });

    it("(b) après revoquer, l'alternance d'EX-8.9 ne revient jamais au prestataire révoqué tant qu'un autre candidat existe", function () {
      const { p, file } = planificateurSurFile("lecture-b");
      const id = `jeton_periode:${PERIOD_HASH}`;
      jusquAuJetonDePeriode(p);
      const d = p.demandes.get(id);
      expect(d.attempts[0].provider).to.equal("qtsa-principal");
      p.traiter(e("2026-11-03T14:00:05.000Z", "reponse_rfc3161", GRANTED(id, 1, d.attempts[0].nonce, "2026-11-03T14:00:04Z", "periode")));
      expect(d.state).to.equal("obtenue");
      const a1 = p.revoquer(id, { t: "2026-11-03T14:20:00.000Z", provider: "qtsa-principal" });
      expect(a1.find((a) => a.action === "releve").detail).to.deep.equal({ provider: "qtsa-secours" });
      expect(d.attempts[1]).to.include({ provider: "qtsa-secours", outcome: "en_cours" });
      // Le secours échoue de façon permanente : les deux candidats sont épuisés ; la reprise au pas max_ms ne va qu'au secours.
      p.traiter(e("2026-11-03T14:20:01.000Z", "reponse_rfc3161", REPONSE_HTTP(id, 2, 404, null)));
      expect(d.state).to.equal("a_reprendre");
      const a3 = p.traiter(e("2026-11-03T14:25:01.000Z", "tic"));
      const envoi = a3.find((a) => a.action === "envoyer_rfc3161" && a.request_id === id);
      expect(envoi.detail.provider).to.equal("qtsa-secours", "jamais le prestataire révoqué");
      p.traiter(e("2026-11-03T14:25:02.000Z", "reponse_rfc3161", REPONSE_HTTP(id, 3, 503, null)));
      const a4 = p.traiter(e("2026-11-03T14:30:03.000Z", "tic"));
      expect(a4.find((a) => a.action === "envoyer_rfc3161" && a.request_id === id).detail.provider).to.equal("qtsa-secours");
      expect(d.attempts.slice(1).every((a) => a.provider === "qtsa-secours")).to.equal(true);
      file.fermer();
    });

    it("(c) une demande retenue par min_interval_ms porte due_at = dernier envoi + min_interval_ms (EX-8.7, informatif)", function () {
      const config = structuredClone(TRACE.config);
      config.rfc3161.checkpoints.provider_role = "principal";
      config.rfc3161.providers[0].min_interval_ms = 480000;
      const p = C.creerPlanificateur(config, { nonces: NONCES_FIXES });
      const K = (ts, n, hash) => ({ org_id: ORG, journal_id: JOURNAL, period_start: PERIODE_TRACE, tree_size: n, checkpoint_hash: hash, checkpoint_ts: ts });
      const h1 = `0x${"a1".repeat(32)}`;
      const h2 = `0x${"a2".repeat(32)}`;
      p.traiter(e("2026-11-03T13:40:00.000Z", "demarrage"));
      p.traiter(e("2026-11-03T13:45:00.000Z", "point_produit", K("2026-11-03T13:45:00.000Z", 2, h1)));
      p.traiter(e("2026-11-03T13:45:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${h1}`, 20001)));
      expect(p.demandes.get(`jeton_point:${h1}`).state).to.equal("envoyee");
      p.traiter(e("2026-11-03T13:50:00.000Z", "point_produit", K("2026-11-03T13:50:00.000Z", 3, h2)));
      const a = p.traiter(e("2026-11-03T13:50:03.000Z", "inclusion_registre", INCLUSION(`ancre_registre_point:${h2}`, 20002)));
      const d2 = p.demandes.get(`jeton_point:${h2}`);
      expect(a.find((x) => x.action === "programmer" && x.request_id === d2.id).detail).to.deep.equal({ reason: "backoff", next_at: "2026-11-03T13:53:03.000Z" });
      expect(d2.state).to.equal("attente_registre");
      expect(d2.due_at).to.equal("2026-11-03T13:53:03.000Z");
      const b = p.traiter(e("2026-11-03T13:53:03.000Z", "tic"));
      expect(b.find((x) => x.action === "envoyer_rfc3161" && x.request_id === d2.id)).to.not.equal(undefined);
      expect(d2.state).to.equal("envoyee");
    });

    it("(e) un TimeStampToken qui ne se lit pas par le lecteur borné rend reponse_illisible (EX-5.10 étape 2), le .tsr est écrit tel que reçu, aucun .der", async function () {
      const dir = temporaire("lecture-e");
      const depot = A.DepotAncres.ouvrir({ racine: dir, orgId: H.F.ORG, journalId: H.F.JOURNAL });
      const mute = lireJson("test", "fixtures", "ancrage-h1", "jetons-mutes-t1.json").cases[0];
      const jeton = new Uint8Array(Buffer.from(mute.hex, "hex"));
      const tlv = (tag, contenu) => {
        const n = contenu.length;
        const longueur = n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
        return Uint8Array.from([tag, ...longueur, ...contenu]);
      };
      const corps = tlv(0x30, [...tlv(0x30, [...tlv(0x02, [0x00])]), ...jeton]);
      expect(() => A.lireReponse(corps)).to.not.throw("la TimeStampResp se lit, c'est le jeton qui ne se lit pas");
      const p = prestataireTest({ role: "interne", url: "http://127.0.0.1:1/", auth: { method: "aucune", secret: null } });
      const imprint = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
      const r = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 1, periodStart: 1793710800, horloge: horlogeFixe(Date.UTC(2026, 10, 3, 13, 53, 0), 3000), depot, transport: transportFactice(reponse200(corps)), retry: RETRY });
      expect(r.outcome).to.equal("echec_permanente");
      expect(r.code).to.equal("reponse_illisible");
      expect(r.data).to.include({ pki_status: 0, token_sha256: null, http_status: 200 });
      expect(r.data.checks_passed).to.deep.equal([]);
      expect(r.fichiers.response).to.match(/\.tsr$/);
      expect(r.fichiers.token).to.equal(null);
      expect(fs.readdirSync(path.join(depot.repertoire(1793710800), "rfc3161")).filter((n) => n.endsWith(".der"))).to.deep.equal([]);
      expect(Buffer.compare(fs.readFileSync(path.join(depot.repertoire(1793710800), r.fichiers.response)), Buffer.from(corps))).to.equal(0);
      expect(r.enregistrement).to.include({ error_code: "reponse_illisible", error_class: "permanente", token_sha256: null });
      // Un jeton sain traverse l'étape 2 (famille reponses/ inchangée : vérifiée par ancrage-rfc3161-vecteurs).
      const sain = await A.acquerir({ prestataire: p, imprint, objet: "point", nonce: 0x74a6f4979421411en, attempt: 2, periodStart: 1793710800, horloge: horlogeFixe(Date.UTC(2026, 10, 3, 13, 53, 0), 3000), depot: null, transport: transportFactice(reponse200(octets("spec", "vecteurs", "ct-5", "reponses", "granted-requete-point-k2.tsr"))), retry: RETRY });
      expect(sain.outcome).to.equal("obtenue");
    });
  });
});
