// Composant d'ancrage (paquets/ancrage) : règles écrites par la revue de
// sécurité de l'étape 8 que les vecteurs régénérés exercent.
//
// - CT-6 EX-9.16, révision 0.9 : une CRL qui porte une
//   extension critique que la version 0 ne lit pas, sur la liste (autre
//   qu'authorityKeyIdentifier, cRLNumber, issuingDistributionPoint,
//   deltaCRLIndicator) ou sur une entrée (autre que cRLReasons), n'est pas
//   complète : elle n'est pas une preuve de non-révocation et ne disqualifie
//   pas le certificat de l'autorité ;
// - CT-5 EX-5.10, étape 2 : un PKIStatus hors de 0 à 5 rend
//   `statut_<n>`, permanente, sans lire le jeton ;
// - les quatre traces de planification de la revue (EX-8.8, EX-8.12)
// sont rejouées par test/ancrage-planificateur-traces.test.js sur
//   spec/vecteurs/ct-5/planification ; ici, les mêmes règles sur des files
//   construites en mémoire.
//
// Les CRL et réponses sont construites en mémoire par l'écrivain DER du
// serveur interne ; aucun essai n'exige le réseau.

import { expect } from "chai";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as D from "../paquets/ancrage/src/serveur-interne/der-ecriture.mjs";
import { CT5, octets, prestataireTest, horlogeFixe, transportFactice } from "./fixtures/ancrage-rfc3161/outils.mjs";

// Racine du composant éprouvé : le paquet du dépôt, ou le répertoire `src` que nomme NOORTRACE_REVUE_ANCRAGE (copie
// avant correction ou mutant).
const SRC = process.env.NOORTRACE_REVUE_ANCRAGE ? path.resolve(process.env.NOORTRACE_REVUE_ANCRAGE) : null;
const RFC = SRC ? await import(pathToFileURL(path.join(SRC, "rfc3161", "index.mjs")).href) : await import("@noortrace/ancrage/rfc3161");
const PLAN = SRC ? await import(pathToFileURL(path.join(SRC, "planificateur", "index.mjs")).href) : await import("@noortrace/ancrage/planificateur");
const { lireCrl, lireReponse, verifierRevocation, acquerir, relireRequete, classerErreur, politiqueCaptureCrl, controlerUrlCrl } = RFC;
const { Planificateur, noncesVecteurs } = PLAN;

const ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const INCONNUE = "1.3.6.1.4.1.99999.77.1";
const nom = (cn) => D.sequence(D.ensemble(D.sequence(D.oid("2.5.4.3"), D.utf8(cn))));
const extension = (o, critique, valeur) => D.sequence(D.oid(o), ...(critique ? [D.booleen(true)] : []), D.chaineOctets(valeur));
const T0 = Date.parse("2026-11-03T14:00:00Z");

/** CertificateList minimale : une entrée (numéro 7, raison keyCompromise), extensions de liste et d'entrée données. */
function crl({ extensionsListe = [], extensionsEntree = [] } = {}) {
  const raison = extension("2.5.29.21", false, D.tlv(0x0a, Uint8Array.of(1)));
  const entree = D.sequence(D.entier(7n), D.tempsUtc(T0 - 86400000), D.sequence(raison, ...extensionsEntree));
  const tbs = D.sequence(
    D.entier(1n),
    D.identifiantAlgorithme(ECDSA_SHA256),
    nom("AC de test"),
    D.tempsUtc(T0 + 3600000),
    D.sequence(entree),
    ...(extensionsListe.length ? [D.explicite(0, D.sequence(...extensionsListe))] : []),
  );
  return D.sequence(tbs, D.identifiantAlgorithme(ECDSA_SHA256), D.chaineBits(new Uint8Array(8)));
}

describe("ancrage, revue de sécurité de l'étape 8 : CRL à extension critique non lue (CT-6 EX-9.16, révision 0.9)", function () {
  it("EX-9.16 : une extension critique de liste ou d'entrée que la version 0 ne lit pas rend la CRL non complète ; les extensions lues, critiques ou non, et une extension inconnue non critique la laissent complète", function () {
    const cas = [
      [{}, true],
      [{ extensionsListe: [extension(INCONNUE, true, D.nul())] }, false],
      [{ extensionsListe: [extension(INCONNUE, false, D.nul())] }, true],
      [{ extensionsListe: [extension("2.5.29.20", true, D.entier(3n)), extension("2.5.29.35", true, D.sequence())] }, true],
      [{ extensionsEntree: [extension(INCONNUE, true, D.nul())] }, false],
      [{ extensionsEntree: [extension("2.5.29.24", false, D.tempsGeneralise(T0 - 86400000))] }, true],
      [{ extensionsListe: [extension("2.5.29.28", true, D.sequence())] }, false],
    ];
    for (const [options, complete] of cas) {
      const lue = lireCrl(crl(options));
      expect(lue.complete, JSON.stringify(Object.keys(options))).to.equal(complete);
    }
    expect(lireCrl(crl({ extensionsListe: [extension(INCONNUE, true, D.nul())] })).extensionCritiqueNonLue).to.equal(INCONNUE);
    expect(lireCrl(crl({ extensionsEntree: [extension(INCONNUE, true, D.nul())] })).extensionCritiqueNonLue).to.equal(INCONNUE);
  });

  it("EX-9.16 : la CRL du fichier d'ancres qui liste le certificat de l'autorité (keyCompromise) le disqualifie si elle est complète, ne le disqualifie pas si elle porte une extension critique non lue (sur la liste ou sur l'entrée)", function () {
    const autorite = {
      nom: "autorite-test",
      identite: true,
      certificat: { octets: new Uint8Array(1), sujet: { octets: D.utf8("s") }, emetteur: { octets: nom("AC de test") }, numeroSerie: Uint8Array.of(7), sha256: "0x" + "ab".repeat(32) },
    };
    const juger = (c) => verifierRevocation({ chemin: [], autorite, crls: [c], aInstant: T0 });
    expect(juger(crl()).statut).to.equal("echoue");
    expect(juger(crl({ extensionsListe: [extension(INCONNUE, true, D.nul())] })).statut).to.equal("reussi");
    expect(juger(crl({ extensionsEntree: [extension(INCONNUE, true, D.nul())] })).statut).to.equal("reussi");
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : hôtes de CRL d'un prestataire (CT-5 EX-4.9 règle 4 bis, révision 0.10 ; schéma ancrage-v0 aligné)", function () {
  it("en production, crl_hosts restreint la capture à ses hôtes (en plus du refus des adresses locales et privées) ; hors production la liste n'est pas appliquée ; crl_hosts nul : aucune liste", function () {
    const prestataire = { id: "qtsa", crl_hosts: ["crl.example"] };
    const prod = politiqueCaptureCrl({ production: true, prestataire });
    expect(prod).to.deep.equal({ production: true, hotesAdmis: ["crl.example"] });
    expect(controlerUrlCrl("http://crl.example/ac.crl", prod)).to.equal(null);
    expect(controlerUrlCrl("http://crl.autre.example/ac.crl", prod)).to.match(/hors de la liste/);
    expect(controlerUrlCrl("http://127.0.0.1/ac.crl", prod)).to.match(/refusée en production/);
    const dev = politiqueCaptureCrl({ production: false, prestataire });
    expect(dev).to.deep.equal({ production: false, hotesAdmis: null });
    expect(controlerUrlCrl("http://crl.autre.example/ac.crl", dev)).to.equal(null);
    expect(politiqueCaptureCrl({ production: true, prestataire: { id: "qtsa", crl_hosts: null } })).to.deep.equal({ production: true, hotesAdmis: null });
    expect(politiqueCaptureCrl({ production: true, prestataire: null })).to.deep.equal({ production: true, hotesAdmis: null });
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : PKIStatus hors de 0 à 5 (CT-5 EX-5.10 étape 2)", function () {
  const reponse = (statut, jeton) => D.sequence(D.sequence(D.entier(BigInt(statut))), ...(jeton ? [jeton] : []));
  const jeton = D.sequence(D.oid("1.2.840.113549.1.7.2"), D.explicite(0, D.sequence(D.entier(3n))));

  it("lireReponse rend le statut lu, sans jeton ni PKIFailureInfo, pour 6 et -1 suivis d'un jeton et pour 9 sans jeton ; 0 à 5 gardent leurs règles", function () {
    expect(lireReponse(reponse(6, jeton))).to.include({ status: 6, failureInfo: null, token: null });
    expect(lireReponse(reponse(9))).to.include({ status: 9, failureInfo: null, token: null });
    expect(lireReponse(reponse(-1, jeton))).to.include({ status: -1, failureInfo: null, token: null });
    expect(() => lireReponse(reponse(2, jeton))).to.throw(/rejet avec un TimeStampToken/);
    expect(() => lireReponse(reponse(0))).to.throw(/granted sans TimeStampToken/);
  });

  it("acquerir : PKIStatus 6 (et -1) rend echec_permanente statut_6 (statut_-1), alerte non critique, aucun jeton lu ni promu ; classerErreur range statut_6 en permanente", async function () {
    const requete = path.join(CT5, "requetes", "point-k2-exemple.tsq");
    const relue = relireRequete(octets(requete));
    const corps = reponse(6, jeton);
    const sent = Date.parse("2026-11-03T13:53:00.000Z");
    const r = await acquerir({
      prestataire: prestataireTest({ policy_oid: relue.policy_oid }), imprint: relue.imprint, objet: "point", nonce: relue.nonceBigint, attempt: 1, periodStart: 1793710800,
      horloge: horlogeFixe(sent, 3000), aleatoire: null, depot: null,
      transport: transportFactice({ status: 200, entetes: { "content-type": "application/timestamp-reply" }, corps }),
      tardivesAvant: 0, k: 1,
    });
    expect(r.enregistrement.outcome).to.equal("echec_permanente");
    expect(r.enregistrement.error_code).to.equal("statut_6");
    expect(r.classement.classe).to.equal("permanente");
    expect(r.classement.alerte).to.equal("alerte");
    expect(r.data.pki_status).to.equal(6);
    expect(r.data.failure_info).to.equal(null);
    expect(r.data.token_sha256).to.equal(null);
    expect(r.jeton ?? null).to.equal(null);
    expect(classerErreur({ pkiStatus: 6 }).classe).to.equal("permanente");
    expect(classerErreur({ pkiStatus: -1 }).code).to.equal("statut_-1");
    // Une exception rend l'issue illisible pour l'oracle (error_code), au lieu d'interrompre l'essai.
    const negatif = await acquerir({
      prestataire: prestataireTest({ policy_oid: relue.policy_oid }), imprint: relue.imprint, objet: "point", nonce: relue.nonceBigint, attempt: 1, periodStart: 1793710800,
      horloge: horlogeFixe(sent, 3000), aleatoire: null, depot: null,
      transport: transportFactice({ status: 200, entetes: { "content-type": "application/timestamp-reply" }, corps: reponse(-1, jeton) }),
      tardivesAvant: 0, k: 1,
    }).catch((e) => ({ enregistrement: { error_code: `exception : ${e.message}`, outcome: null } }));
    expect(negatif.enregistrement.error_code).to.equal("statut_-1");
    expect(negatif.enregistrement.outcome).to.equal("echec_permanente");
  });
});

// --- Planificateur : files construites en mémoire, sur la projection de la trace publiée redemarrage-reprise
// (principal, secours, serveur interne pour les points), fallback_after_s 300 s et gigue nulle.
describe("ancrage, revue de sécurité de l'étape 8 : planificateur au démarrage et séries parallèles (CT-5 EX-8.12, EX-8.8, EX-8.3, EX-8.9)", function () {
  const trace = JSON.parse(new TextDecoder().decode(octets(path.join(CT5, "planification", "redemarrage-reprise.json"))));
  const H = "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
  const ORG = trace.queue_before[0].subject.org_id;
  const JOURNAL = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
  const sujet = { kind: "periode", org_id: ORG, journal_id: JOURNAL, period_start: 1793710800, hash: H, tree_size: null, declared_at: "2026-11-03T14:00:00.250Z" };
  const tentative = (n, provider, outcome, error_code, started, next) => ({
    n, provider, started_at: started, nonce: "0x" + String(n).padStart(16, "0"), correlation_id: `jeton_periode:${H.slice(2, 18)}:${n}`, outcome, error_code,
    http_status: null, pki_status: null, failure_info: null, retry_after_s: null, next_at: next, detail: outcome === "en_cours" ? "requete envoyee" : "delai de reponse depasse",
  });
  const demande = (state, attempts) => ({
    version: 0, id: `jeton_periode:${H}`, kind: "jeton_periode", subject: sujet, deadlines: [], state, created_at: "2026-11-03T14:00:00.250Z",
    due_at: state === "a_reprendre" ? "2026-11-03T15:00:00.000Z" : null, attempts, attempts_total: attempts.length, result: null, replaced_by: null,
  });
  const config = () => {
    const c = structuredClone(trace.config);
    c.rfc3161.manifest.fallback_after_s = 300;
    c.rfc3161.retry = { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 0 };
    return c;
  };
  const principal = (c) => c.rfc3161.providers.find((p) => p.role === "principal").id;
  const secours = (c) => c.rfc3161.providers.find((p) => p.role === "secours").id;
  const reponseDelai = (t, attempt) => ({ t, type: "reponse_rfc3161", data: { request_id: `jeton_periode:${H}`, attempt, transport: "delai", http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null } });
  const planificateur = (c, file) => new Planificateur(c, { gigues: [], nonces: noncesVecteurs(), fileInitiale: file });

  it("EX-8.12 : la relève d'un jeton_periode relu envoyee est reposée à premier envoi + fallback_after_s, même si le processus redémarre après ; échue pendant l'arrêt, elle part au démarrage", function () {
    const c = config();
    const file = [demande("envoyee", [tentative(1, principal(c), "echec_transitoire", "delai", "2026-11-03T14:00:02.000Z", "2026-11-03T14:00:17.000Z"), tentative(2, principal(c), "en_cours", null, "2026-11-03T14:00:17.000Z", null)])];
    const p = planificateur(c, file);
    const a1 = p.traiter({ t: "2026-11-03T14:00:20.000Z", type: "demarrage", data: {} });
    expect(a1.filter((a) => a.action === "releve")).to.have.lengthOf(0);
    const a2 = p.traiter({ t: "2026-11-03T14:05:10.000Z", type: "tic", data: {} });
    const releve = a2.find((a) => a.action === "releve");
    expect(releve, "relève reposée").to.not.equal(undefined);
    expect(releve.t).to.equal("2026-11-03T14:05:02.000Z");
    expect(releve.detail.provider).to.equal(secours(c));
    // Redémarrage après l'échéance : la relève part à l'instant du démarrage.
    const q = planificateur(c, structuredClone(file));
    const b = q.traiter({ t: "2026-11-03T14:10:00.000Z", type: "demarrage", data: {} });
    expect(b.filter((a) => a.action === "releve").map((a) => a.t)).to.deep.equal(["2026-11-03T14:10:00.000Z"]);
    // Secours déjà engagé : aucune relève reposée.
    const engage = [demande("a_reprendre", [tentative(1, principal(c), "echec_transitoire", "delai", "2026-11-03T14:00:02.000Z", "2026-11-03T14:00:17.000Z"), tentative(2, secours(c), "echec_transitoire", "delai", "2026-11-03T14:05:02.000Z", "2026-11-03T15:00:00.000Z")])];
    const s = planificateur(c, engage);
    const d = [...s.traiter({ t: "2026-11-03T14:10:00.000Z", type: "demarrage", data: {} }), ...s.traiter({ t: "2026-11-03T14:20:00.000Z", type: "tic", data: {} })];
    expect(d.filter((a) => a.action === "releve")).to.have.lengthOf(0);
  });

  it("EX-8.9 : la tentative close par le redémarrage (redemarrage) rompt la série des échecs transitoires : la reprise suivante attend initial_ms", function () {
    const c = config();
    const file = [demande("envoyee", [tentative(1, principal(c), "echec_transitoire", "delai", "2026-11-03T14:00:02.000Z", "2026-11-03T14:00:17.000Z"), tentative(2, principal(c), "en_cours", null, "2026-11-03T14:00:17.000Z", null)])];
    const p = planificateur(c, file);
    p.traiter({ t: "2026-11-03T14:00:20.000Z", type: "demarrage", data: {} });
    const a = p.traiter(reponseDelai("2026-11-03T14:00:30.000Z", 3));
    const prog = a.find((x) => x.action === "programmer");
    expect(prog.detail).to.deep.equal({ next_at: "2026-11-03T14:00:35.000Z", reason: "backoff" });
  });

  it("EX-8.3, EX-8.8 : l'échec transitoire d'une série pendant qu'une tentative de l'autre est en cours laisse la demande envoyee, la reprise de la série est programmée", function () {
    const c = config();
    const file = [demande("envoyee", [
      tentative(1, principal(c), "echec_transitoire", "delai", "2026-11-03T14:00:02.000Z", "2026-11-03T14:00:17.000Z"),
      tentative(2, secours(c), "en_cours", null, "2026-11-03T14:05:02.000Z", null),
      tentative(3, principal(c), "en_cours", null, "2026-11-03T14:05:27.000Z", null),
    ])];
    const p = planificateur(c, file);
    // Le démarrage ferme les tentatives en cours ; on rejoue la situation par deux envois parallèles.
    p.traiter({ t: "2026-11-03T14:05:30.000Z", type: "demarrage", data: {} });
    const envois = p.file()[0].attempts.filter((x) => x.outcome === "en_cours");
    expect(envois.map((x) => x.provider).sort()).to.deep.equal([principal(c), secours(c)].sort());
    const auPrincipal = envois.find((x) => x.provider === principal(c)).n;
    const a = p.traiter(reponseDelai("2026-11-03T14:05:40.000Z", auPrincipal));
    expect(a.filter((x) => x.action === "ecrire_file").map((x) => x.detail.state)).to.deep.equal(["envoyee"]);
    expect(a.filter((x) => x.action === "programmer").map((x) => x.detail.reason)).to.deep.equal(["backoff"]);
  });

  it("EX-8.12 : une demande jeton_point relue a_reprendre dont les échéances précèdent une échéance satisfaite d'un jeton relu obtenu est close remplacee au démarrage, avec checkpoint_anchor_late", function () {
    const c = config();
    const point = (h, deadlines, state, extra = {}) => ({
      version: 0, id: `jeton_point:${h}`, kind: "jeton_point",
      subject: { kind: "point", org_id: ORG, journal_id: JOURNAL, period_start: 1793710800, hash: h, tree_size: deadlines[0] + 1, declared_at: "2026-11-03T13:42:00.000Z" },
      deadlines, state, created_at: "2026-11-03T13:42:00.000Z", due_at: state === "a_reprendre" ? "2026-11-03T13:54:23.000Z" : null,
      attempts: [], attempts_total: 0, result: null, replaced_by: null, ...extra,
    });
    const h1 = "0x" + "11".repeat(32);
    const h2 = "0x" + "22".repeat(32);
    const file = [
      point(h1, [1, 2, 3], "a_reprendre"),
      point(h2, [9, 10], "obtenue", { result: { sha256: "0x" + "33".repeat(32), size: 2000, provider: c.rfc3161.providers[0].id, obtained_at: "2026-11-03T13:53:03.000Z", bound: "2026-11-03T13:53:04.000Z" } }),
    ];
    const p = planificateur(c, file);
    const a = p.traiter({ t: "2026-11-03T13:53:04.500Z", type: "demarrage", data: {} });
    const remplacer = a.find((x) => x.action === "remplacer");
    expect(remplacer, "remplacer au démarrage").to.not.equal(undefined);
    expect(remplacer.request_id).to.equal(`jeton_point:${h1}`);
    expect(remplacer.detail.replaced_by).to.equal(`jeton_point:${h2}`);
    expect(a.find((x) => x.action === "journaliser" && x.detail.event === "checkpoint_anchor_late").detail).to.include({ window_s: 2884 });
    expect(p.file().find((d) => d.id === `jeton_point:${h1}`).state).to.equal("remplacee");
    expect(a.filter((x) => x.action === "envoyer_rfc3161" && x.request_id === `jeton_point:${h1}`)).to.have.lengthOf(0);
  });
});
