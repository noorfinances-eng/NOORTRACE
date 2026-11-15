// Revue de sécurité interne de l'étape 8 : planificateur et supervision.
// Pertes silencieuses et bornes de temps (causes S-1, S-2, S-6) : 
// (prestataire retiré pendant une tentative en vol : la demande n'est jamais
// orpheline), (EX-8.8 : les deux séries sont poursuivies en
// parallèle après la relève), (saut de l'horloge en avant : au plus un
// renvoi au registre par demande et par passe), CT-5 EX-4.9 (AN-1 règle 9 :
// policy_oid encodable), EX-5.13 (compteur des tentatives : une
// incrémentation par tentative, à son issue, toutes sortes ; séries à 0),
// EX-8.5 (coût d'une passe borné sur une file ancienne).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { Planificateur, noncesAleatoires, validerConfiguration, Supervision, METRIQUES_ANCRAGE, REJEUX_PAR_PASSE_MAX } from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const lire = (...p) => JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", ...p), "utf8"));
const TRACE = lire("ct-5", "planification", "principal-injoignable.json");
const SUJET = TRACE.inputs.find((e) => e.type === "periode_close").data;
const P = SUJET.period_start;
const T0 = (P + 3600) * 1000;
const h = (ms) => new Date(ms).toISOString();
const nonces = () => noncesAleatoires((n) => new Uint8Array(randomBytes(n)));
const echec = (id, n, transport) => ({ request_id: id, attempt: n, transport, http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null });

describe("ancrage, revue de sécurité de l'étape 8 : planificateur, reprises jamais perdues (CT-5 EX-8.8, EX-8.9)", function () {
  this.timeout(120000);

  it("CT-5 EX-8.8 : un rechargement qui retire le prestataire d'une tentative en vol ne laisse aucune demande sans minuterie : la réponse de la tentative est traitée sans exception et la demande repart au nouveau principal", function () {
    const config = structuredClone(TRACE.config);
    const pl = new Planificateur(config, { nonces: nonces(), sansRegistre: true });
    pl.traiter({ t: h(T0), type: "demarrage", data: {} });
    const a1 = pl.traiter({ t: h(T0 + 1000), type: "periode_close", data: SUJET });
    const envoi = a1.find((x) => x.action === "envoyer_rfc3161");
    expect(envoi.detail.provider).to.equal("qtsa-principal");
    // Rechargement : le principal change d'identifiant ; sans secours (régime de la version 0, EX-11.3).
    const c2 = structuredClone(config);
    c2.rfc3161.providers = c2.rfc3161.providers.filter((p) => p.role !== "secours");
    c2.rfc3161.providers.find((p) => p.role === "principal").id = "qtsa-nouveau";
    pl.reconfigurer(c2);
    const actions = pl.traiter({ t: h(T0 + 11000), type: "reponse_rfc3161", data: echec(envoi.request_id, envoi.detail.attempt, "delai") });
    const d = pl.file().find((x) => x.kind === "jeton_periode");
    expect(d.state).to.not.equal("envoyee");
    expect(actions.some((x) => x.action === "programmer"), "une reprise est programmée").to.equal(true);
    expect(pl.timers.filter((t) => t.id === d.id)).to.have.length.at.least(1);
    let envois = 0;
    const prestataires = new Set();
    for (let s = 60; s <= 86400; s += 60) {
      for (const a of pl.traiter({ t: h(T0 + 11000 + s * 1000), type: "tic", data: {} })) {
        if (a.action === "envoyer_rfc3161") {
          envois += 1;
          prestataires.add(a.detail.provider);
          // Réponse : erreur de transport, pour que la demande continue d'être reprise.
          pl.traiter({ t: h(T0 + 11000 + s * 1000), type: "reponse_rfc3161", data: echec(a.request_id, a.detail.attempt, "erreur_transport") });
        }
      }
    }
    expect(envois, "des envois repartent en vingt-quatre heures").to.be.at.least(100);
    expect([...prestataires]).to.deep.equal(["qtsa-nouveau"]);
  });

  it("CT-5 EX-8.8 : après la relève, la série du principal est poursuivie en parallèle de celle du secours : principal qui refuse en 1 s, secours qui expire en 30 s, six heures", function () {
    const config = structuredClone(TRACE.config);
    const principal = config.rfc3161.providers.find((p) => p.role === "principal").id;
    const pl = new Planificateur(config, { nonces: nonces(), sansRegistre: true });
    let now = T0;
    const enVol = [];
    const envois = [];
    pl.traiter({ t: h(now), type: "demarrage", data: {} });
    const faire = (a) => {
      if (a.action === "envoyer_rfc3161") {
        envois.push({ s: Math.round((now - T0) / 1000), p: a.detail.provider });
        enVol.push({ at: now + (a.detail.provider === principal ? 1000 : 30000), id: a.request_id, n: a.detail.attempt, p: a.detail.provider });
      }
    };
    now += 1000;
    for (const a of pl.traiter({ t: h(now), type: "periode_close", data: SUJET })) faire(a);
    for (let s = 1; s <= 6 * 3600; s++) {
      now += 1000;
      for (const x of enVol.filter((y) => y.at <= now)) {
        enVol.splice(enVol.indexOf(x), 1);
        for (const a of pl.traiter({ t: h(now), type: "reponse_rfc3161", data: echec(x.id, x.n, x.p === principal ? "erreur_transport" : "delai") })) faire(a);
      }
      for (const a of pl.traiter({ t: h(now), type: "tic", data: {} })) faire(a);
    }
    const auPrincipal = envois.filter((e) => e.p === principal);
    const auSecours = envois.filter((e) => e.p !== principal);
    expect(auSecours.length, "la relève sollicite le secours").to.be.at.least(50);
    expect(auPrincipal.at(-1).s, "la série du principal ne cesse pas pendant que le secours est en cours (dernier envoi au principal, en secondes)").to.be.at.least(5 * 3600);
    expect(auPrincipal.length, "au pas retry.max_ms (300 s), au moins 60 envois au principal en six heures").to.be.at.least(60);
  });

  it("CT-5 EX-8.8 : un saut de l'horloge de 24 h avec une ancre au registre en vol ne produit qu'au plus REJEUX_PAR_PASSE_MAX renvois par demande et par passe (était 48 pour 1 800 s, 1 440 pour 60 s), les échéances manquées étant comptées", function () {
    let ecritures = 0;
    const pl = new Planificateur(TRACE.config, { nonces: nonces(), file: { ecrire: () => { ecritures += 1; } } });
    pl.traiter({ t: h(T0), type: "demarrage", data: {} });
    pl.traiter({ t: h(T0 + 1000), type: "periode_close", data: SUJET });
    ecritures = 0;
    const actions = pl.traiter({ t: h(T0 + 1000 + 86400 * 1000), type: "tic", data: {} });
    const envoisRegistre = actions.filter((a) => a.action === "envoyer_registre");
    // Borne nommée plutôt qu'un seul renvoi : la trace normative registre-indisponible rejoue trois fenêtres franchies
    // d'affilée dans une même passe ; la borne (quatre) les respecte et coupe la rafale au-delà.
    expect(REJEUX_PAR_PASSE_MAX).to.be.within(3, 8);
    expect(envoisRegistre.length, "au plus REJEUX_PAR_PASSE_MAX renvois de l'ancre par passe").to.be.at.most(REJEUX_PAR_PASSE_MAX);
    expect(ecritures).to.be.below(10);
    const ancre = pl.file().find((d) => d.kind === "ancre_registre_periode");
    expect(ancre.attempts_total).to.be.at.most(1 + REJEUX_PAR_PASSE_MAX);
    expect(actions.filter((a) => a.action === "alerter" && a.detail.code === "inclusion_late").length).to.be.at.least(1);
    const manquees = actions.filter((a) => a.action === "journaliser" && a.detail.event === "anchor_retry" && a.detail.missed_deadlines > 0);
    expect(manquees, "les échéances manquées sont comptées sur une ligne anchor_retry").to.have.length(1);
    // Fenêtres franchies en 24 h au pas registry.inclusion_alert_s de la trace (60 s : 1 440), moins celles rejouées.
    expect(manquees[0].detail.missed_deadlines).to.equal(Math.floor(86400 / TRACE.config.registry.inclusion_alert_s) - REJEUX_PAR_PASSE_MAX);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : AN-1 règle 9, policy_oid encodable dans la requête d'EX-5.1 (CT-5 EX-4.9)", function () {
  const exemple = () => structuredClone(TRACE.config);
  it("un policy_oid au second arc ≥ 40 sous l'arc 1, ou de plus de 127 octets en DER, est refusé par AN-1 (règle 9) ; accepted_policies aussi ; un OID ordinaire reste admis", function () {
    const base = exemple();
    // La projection d'une trace n'est pas un document ancrage-v0 complet : on part de l'exemple de CT-5 §4.4.
    const texte = fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8");
    const m = /<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(texte);
    const doc = JSON.parse(m[1]);
    void base;
    const regles = (r) => [...new Set(r.erreurs.map((e) => e.regle))].sort();
    expect(validerConfiguration(doc, { profil: "developpement", checkpointIntervalEnregistreur: doc.checkpoint_interval_s }).valide).to.equal(true);
    // 130 arcs sous 1.3.6.1.4.1 : 138 octets de DER (un arc d'un octet chacun), au-delà de la borne de 127 ; 70 arcs n'en feraient que 77.
    for (const oid of ["1.40.1", "1.3.6.1.4.1." + Array.from({ length: 130 }, () => "1").join("."), "2.999." + "9".repeat(400)]) {
      const d = structuredClone(doc);
      d.rfc3161.providers[0].policy_oid = oid;
      const r = validerConfiguration(d, { profil: "developpement", checkpointIntervalEnregistreur: d.checkpoint_interval_s });
      expect(r.valide, oid.slice(0, 30)).to.equal(false);
      expect(regles(r), oid.slice(0, 30)).to.deep.equal(["9"]);
      expect(r.erreurs[0].message).to.match(/policy_oid/);
    }
    const d2 = structuredClone(doc);
    d2.rfc3161.providers[0].accepted_policies = [...(d2.rfc3161.providers[0].accepted_policies ?? []), "1.40.1"];
    expect(regles(validerConfiguration(d2, { profil: "developpement", checkpointIntervalEnregistreur: d2.checkpoint_interval_s }))).to.deep.equal(["9"]);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : supervision, noortrace_anchoring_attempts_total (CT-5 §8.9 ; EX-5.13, part « compteurs à 0 » de CT-8 EX-10.10)", function () {
  const serie = (s, nom, etiquettes) => s.series.get(nom).get(JSON.stringify(Object.keys(etiquettes).sort().map((k) => [k, etiquettes[k]])));

  it("une tentative RFC 3161 compte une fois, à son issue ; les tentatives du registre et des calendriers comptent aussi ; aucune valeur en_cours", function () {
    const s = new Supervision({ prestatairesExterieurs: ["qtsa-principal"], prestataires: ["qtsa-principal", "qtsa-secours", "tsa-interne"] });
    const config = structuredClone(TRACE.config);
    const pl = new Planificateur(config, { nonces: nonces(), sansRegistre: true });
    pl.traiter({ t: h(T0), type: "demarrage", data: {} });
    const a1 = pl.traiter({ t: h(T0 + 1000), type: "periode_close", data: SUJET });
    s.releverActions({ actions: a1, file: pl.file(), maintenant: T0 + 1000 });
    const envoi = a1.find((x) => x.action === "envoyer_rfc3161");
    const total = () => [...s.series.get("noortrace_anchoring_attempts_total").values()].filter((x) => x.etiquettes.kind === "jeton_periode").reduce((n, x) => n + x.valeur, 0);
    expect(total(), "aucune tentative n'a encore d'issue").to.equal(0);
    const a2 = pl.traiter({ t: h(T0 + 2000), type: "reponse_rfc3161", data: echec(envoi.request_id, envoi.detail.attempt, "erreur_transport") });
    s.releverActions({ actions: a2, file: pl.file(), maintenant: T0 + 2000 });
    expect(total(), "une tentative en échec transitoire compte une fois").to.equal(1);
    expect(serie(s, "noortrace_anchoring_attempts_total", { kind: "jeton_periode", provider: "qtsa-principal", outcome: "echec_transitoire" }).valeur).to.equal(1);
    expect([...s.series.get("noortrace_anchoring_attempts_total").values()].some((x) => x.etiquettes.outcome === "en_cours")).to.equal(false);
    // Issue permanente : une incrémentation, prestataire nommé.
    const a3 = pl.traiter({ t: h(T0 + 400000), type: "tic", data: {} });
    s.releverActions({ actions: a3, file: pl.file(), maintenant: T0 + 400000 });
    const envoi2 = a3.find((x) => x.action === "envoyer_rfc3161");
    expect(envoi2).to.not.equal(undefined);
    const a4 = pl.traiter({ t: h(T0 + 401000), type: "reponse_rfc3161", data: { ...echec(envoi2.request_id, envoi2.detail.attempt, "reponse"), http_status: 400 } });
    s.releverActions({ actions: a4, file: pl.file(), maintenant: T0 + 401000 });
    expect(serie(s, "noortrace_anchoring_attempts_total", { kind: "jeton_periode", provider: envoi2.detail.provider, outcome: "echec_permanente" }).valeur).to.equal(1);
    // Soumission OpenTimestamps sans assez de calendriers : une tentative, échec transitoire.
    const ots = a1.find((x) => x.action === "soumettre_ots");
    const a5 = pl.traiter({ t: h(T0 + 402000), type: "reponse_ots", data: { request_id: ots.request_id, calendars_answered: 1, attestation: "aucune", proof_sha256: null, proof_size: null } });
    s.releverActions({ actions: a5, file: pl.file(), maintenant: T0 + 402000 });
    expect(serie(s, "noortrace_anchoring_attempts_total", { kind: "ots_periode", provider: "calendriers", outcome: "echec_transitoire" }).valeur).to.equal(1);
  });

  it("les séries énumérées sont exposées à 0 dès la construction (sortes × prestataires × issues) et les jauges d'attente à 0", function () {
    const s = new Supervision({ prestataires: ["qtsa-principal", "tsa-interne"], registre: true });
    const texte = s.metriques();
    expect(texte).to.include('noortrace_anchoring_attempts_total{kind="jeton_periode",provider="qtsa-principal",outcome="echec_transitoire"} 0');
    expect(texte).to.include('noortrace_anchoring_attempts_total{kind="jeton_point",provider="tsa-interne",outcome="obtenue"} 0');
    expect(texte).to.include('noortrace_anchoring_attempts_total{kind="ancre_registre_periode",provider="registre",outcome="obtenue"} 0');
    expect(texte).to.include('noortrace_anchoring_attempts_total{kind="ots_periode",provider="calendriers",outcome="echec_transitoire"} 0');
    expect(texte).to.include('noortrace_anchor_pending{anchor="rfc3161"} 0');
    expect(texte).to.include('noortrace_anchoring_deadlines_total{state="satisfaite"} 0');
    expect(METRIQUES_ANCRAGE.noortrace_anchoring_attempts_total.etiquettes).to.deep.equal(["kind", "provider", "outcome"]);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : coût d'une passe sur une file ancienne (CT-5 EX-8.1, EX-8.5 règle 5 ; correction partielle)", function () {
  this.timeout(120000);
  it("une passe de tic et sa relève de supervision sur 20 000 demandes finales ne recopient ni ne trient la file : moins de 400 ms, et moins de 8 fois le coût de 2 500", function () {
    const mesurer = (n) => {
      const config = structuredClone(TRACE.config);
      const pl = new Planificateur(config, { nonces: nonces(), sansRegistre: true });
      const s = new Supervision({ prestatairesExterieurs: ["qtsa-principal"] });
      pl.traiter({ t: h(T0), type: "demarrage", data: {} });
      for (let k = 0; k < n; k++) {
        const hash = "0x" + Buffer.from(randomBytes(32)).toString("hex");
        const id = `jeton_point:${hash}`;
        pl.chargerDemande({ version: 0, id, kind: "jeton_point", subject: { kind: "point", org_id: SUJET.org_id, journal_id: SUJET.journal_id, period_start: P - 3600 * (1 + (k % 5000)), hash, tree_size: 1, declared_at: h(T0 - 1000) }, deadlines: [], state: "obtenue", created_at: h(T0 - 1000 - k), due_at: null, attempts: [{ n: 1, provider: "tsa-interne", started_at: h(T0 - 1000), nonce: "0x0000000000000001", correlation_id: `jeton_point:${hash.slice(2, 18)}:1`, outcome: "obtenue", error_code: null, http_status: 200, pki_status: 0, failure_info: null, retry_after_s: null, next_at: null, detail: "x" }], attempts_total: 1, result: { sha256: hash, size: 1000, provider: "tsa-interne", obtained_at: h(T0 - 900), bound: h(T0 - 900) }, replaced_by: null });
      }
      // Une minuterie existe (clôture en cours) : c'est le cas où la passe triait toute la file.
      pl.traiter({ t: h(T0 + 1000), type: "periode_close", data: SUJET });
      const debut = performance.now();
      for (let i = 0; i < 5; i++) {
        const actions = pl.traiter({ t: h(T0 + 2000 + i * 1000), type: "tic", data: {} });
        s.releverActions({ actions, file: pl.demandes.values(), maintenant: T0 + 2000 + i * 1000 });
      }
      return (performance.now() - debut) / 5;
    };
    const petit = mesurer(2500);
    const grand = mesurer(20000);
    expect(grand, `passe sur 20 000 demandes finales : ${grand.toFixed(1)} ms (2 500 : ${petit.toFixed(1)} ms)`).to.be.below(400);
    expect(grand / Math.max(petit, 1), "le coût ne croît pas linéairement avec les demandes finales").to.be.below(8);
  });
});
