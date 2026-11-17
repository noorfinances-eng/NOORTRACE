// Bibliothèque de référence du composant d'ancrage (scripts/lib/ancrage.mjs,
// CT-5) : corrections de la revue de sécurité interne de l'étape 8
// (constats EX-5.10, EX-8.12, EX-5.1, EX-8.5).
//
// Chaque essai rejoue le scénario du relecteur sur la bibliothèque, puis
// éprouve un mutant de la règle corrigée : copie de scripts/lib sous
// NOORTRACE_TMP (défaut : os.tmpdir()), règle retirée, l'oracle de l'essai
// doit alors échouer ; la copie est détruite à la fin. La racine des scripts
// éprouvés est le dépôt, ou NOORTRACE_REVUE_RACINE (rejeu sur une copie).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const lireJSON = (...p) => JSON.parse(fs.readFileSync(path.join(...p), "utf8"));

/** Module ancrage.mjs d'une racine de scripts (le dépôt, la copie d'essai ou un mutant). */
const importer = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + `?t=${Date.now()}-${Math.random()}`);

/** Copie de scripts/lib avec une règle retirée (remplacement unique). */
function mutant(nom, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-ancrage-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, "scripts", "lib", "ancrage.mjs");
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
});

// --- DER générique (lecture et réécriture à longueurs recalculées), pour forger un TSTInfo.
function lireNoeud(buf, pos = 0) {
  const tag = buf[pos];
  let l = buf[pos + 1];
  let p = pos + 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let i = 0; i < n; i++) l = l * 256 + buf[p++]; }
  const contenu = buf.subarray(p, p + l);
  const n = { tag, fin: p + l };
  if (tag & 0x20) { n.enfants = []; let q = 0; while (q < contenu.length) { const e = lireNoeud(contenu, q); n.enfants.push(e); q = e.fin; } } else n.valeur = Buffer.from(contenu);
  return n;
}
function ecrireNoeud(n) {
  const corps = n.enfants ? Buffer.concat(n.enfants.map(ecrireNoeud)) : n.valeur;
  const L = corps.length;
  const lon = L < 0x80 ? Buffer.from([L]) : L < 0x100 ? Buffer.from([0x81, L]) : Buffer.from([0x82, L >> 8, L & 0xff]);
  return Buffer.concat([Buffer.from([n.tag]), lon, corps]);
}

/** La réponse granted du vecteur requete-point-k2 et ce qu'il faut pour l'évaluer. */
function casGranted() {
  const fichier = lireJSON(CT5, "reponses", "reponses.json");
  const lire = (...p) => fs.readFileSync(path.join(CT5, "reponses", ...p));
  const prestataire = { ...fichier.provider, anchor_certificates: fichier.provider.anchor_certificates.map((p) => lire(p).toString("utf8")) };
  const cas = fichier.cases.find((c) => c.id === "granted-requete-point-k2");
  return { requete: lire(cas.input.request), reponse: lire(cas.input.response), cas, prestataire, freshness: fichier.freshness };
}
const evaluer = (A, c, reponse) => A.evaluerReponse({ requete: c.requete, reponse, http: c.cas.input.http, sent_at: c.cas.input.sent_at, received_at: c.cas.input.received_at, prestataire: c.prestataire, freshness: c.freshness, tardives_precedentes: 0 });

describe("CT-5, référence : réponses RFC 3161 hors profil (EX-5.10 étape 2, EX-5.12)", function () {
  this.timeout(60000);
  let A;
  let c;
  before(async function () {
    A = await importer(RACINE);
    c = casGranted();
    expect(c.reponse.subarray(4, 9).toString("hex")).to.equal("3003020100");
  });

  // L'octet de l'INTEGER d'un octet est lu en complément à deux (X.690 §8.3.3 ; EX-5.10 étape 2 : status tel que lu) :
  // 0x06 vaut 6, 0x7f vaut 127, 0xff vaut -1.
  const oracleStatut = (M, c) => [[6, 6], [0x7f, 127], [0xff, -1]].every(([octet, st]) => {
    const r = Buffer.from(c.reponse);
    r[8] = octet;
    const res = evaluer(M, c, r);
    return res.outcome === "echec_permanente" && res.error_code === `statut_${st}` && res.class === "permanente" && res.token === null && res.pki_status === st;
  });

  it("CT-5 EX-5.10 : un PKIStatus 6, 127 ou -1 (octet FF, INTEGER signé) avec un jeton valable est classé statut_<n>, permanente, sans jeton promu, par evaluerReponse comme par le planificateur (classer) ; les statuts 0 et 1 restent obtenue", function () {
    expect(oracleStatut(A, c)).to.equal(true);
    for (const st of [0, 1]) {
      const r = Buffer.from(c.reponse);
      r[8] = st;
      expect(evaluer(A, c, r).outcome).to.equal("obtenue");
    }
    // Le planificateur rend le même code sur l'entrée reponse_rfc3161 correspondante.
    const trace = lireJSON(CT5, "planification", "heure-nominale-reference.json");
    const p = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues: trace.jitter_ms ?? [] }) });
    const envoi = trace.inputs.findIndex((e) => e.type === "reponse_rfc3161");
    for (const e of trace.inputs.slice(0, envoi)) p.recevoir(e);
    const rep = structuredClone(trace.inputs[envoi]);
    rep.data.pki_status = 6;
    const actions = p.recevoir(rep);
    const rejet = actions.find((a) => a.action === "rejeter_reponse");
    expect(rejet, "rejeter_reponse").to.not.equal(undefined);
    expect(rejet.detail).to.deep.equal({ error_code: "statut_6", class: "permanente" });
  });

  it("mutant CT-5 EX-5.10 : sans le refus des statuts hors de 0 à 5, le statut 6 est promu obtenue (tué par l'oracle)", async function () {
    const M = await importer(mutant("statut-pki", 'if (rep.status !== 0 && rep.status !== 1) return echec(`statut_${rep.status}`, "permanente", `PKIStatus ${rep.status} inconnu (0 a 5 attendus)`);\n', ""));
    expect(oracleStatut(M, c)).to.equal(false);
  });

  const reponseAccuracy = (c, octets) => {
    const racine = lireNoeud(c.reponse);
    const signedData = racine.enfants[1].enfants[1].enfants[0];
    const octetString = signedData.enfants[2].enfants[1].enfants[0];
    const tst = lireNoeud(octetString.valeur);
    const idx = tst.enfants.findIndex((e, i) => i > 3 && e.tag === 0x30 && e.enfants.length && e.enfants.every((x) => [0x02, 0x80, 0x81].includes(x.tag)));
    expect(idx, "accuracy dans le TSTInfo").to.be.greaterThan(3);
    tst.enfants[idx].enfants[0].valeur = octets;
    octetString.valeur = ecrireNoeud(tst);
    return ecrireNoeud(racine);
  };
  const oracleAccuracy = (M, c) => [Buffer.from("7fffffffffffffff", "hex"), Buffer.concat([Buffer.from([0x7f]), Buffer.alloc(15, 0xff)])].every((octets) => {
    try {
      const res = evaluer(M, c, reponseAccuracy(c, octets));
      return res.outcome === "echec_permanente" && /^verification_T-[1-9]$/.test(res.error_code) && res.upper_bound === null;
    } catch {
      return false;
    }
  });

  it("CT-5 EX-5.10 : un accuracy.seconds sur 8 ou 16 octets (hors de la plage d'un instant) est classé echec_permanente verification_T-n, upper_bound nul, sans exception ; le planificateur classe verification_T-7 une précision démesurée", function () {
    expect(oracleAccuracy(A, c)).to.equal(true);
    const trace = lireJSON(CT5, "planification", "heure-nominale-reference.json");
    const p = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues: trace.jitter_ms ?? [] }) });
    const envoi = trace.inputs.findIndex((e) => e.type === "reponse_rfc3161");
    for (const e of trace.inputs.slice(0, envoi)) p.recevoir(e);
    const rep = structuredClone(trace.inputs[envoi]);
    rep.data.accuracy_s = 9.2e18;
    const actions = p.recevoir(rep);
    expect(actions.find((a) => a.action === "rejeter_reponse")?.detail).to.deep.equal({ error_code: "verification_T-7", class: "permanente" });
  });

  it("mutant CT-5 EX-5.10 : sans la borne de la précision, l'évaluation lève RangeError au lieu de classer (tué par l'oracle)", async function () {
    const M = await importer(mutant("borne-instant", "res.upper_bound = borneInstantValide(msInstant(genTime), acc) ? iso(msInstant(genTime) + Math.round(acc * 1000)) : null;", "res.upper_bound = iso(msInstant(genTime) + Math.round(acc * 1000));"));
    expect(oracleAccuracy(M, c)).to.equal(false);
  });
});

describe("CT-5, référence : OID de politique à arcs longs (EX-5.1, AN-5)", function () {
  let A;
  before(async function () {
    A = await importer(RACINE);
  });
  const OID = "2.25.329800735698586629295641978511506172918";
  const b128 = (v) => { const o = [Number(v & 0x7fn)]; v >>= 7n; while (v > 0n) { o.unshift(Number(v & 0x7fn) | 0x80); v >>= 7n; } return o; };
  const derAttendu = (oid) => {
    const arcs = oid.split(".").map(BigInt);
    const corps = Buffer.from([...b128(arcs[0] * 40n + arcs[1]), ...arcs.slice(2).flatMap(b128)]);
    return Buffer.concat([Buffer.from([0x06, corps.length]), corps]);
  };
  const oracle = (M) => [OID, "1.3.6.1.4.1.9007199254740993.1", "1.3.6.1.4.1.340282366920938463463374607431768211455.7"].every((oid) => {
    const der = M.encoderOIDDER(oid);
    const relu = M.lireRequete(M.construireRequete({ digest: "0x" + "11".repeat(32), nonce: 5n, policy_oid: oid })).policy_oid;
    return der.equals(derAttendu(oid)) && relu === oid;
  });

  it("CT-5 EX-5.1 : un arc de 2.25.<UUID> (X.667) ou de 2^128 - 1 est encodé en base 128 exacte et relu à l'identique ; un arc de 2^128 est refusé par la construction et par la relecture", function () {
    expect(oracle(A)).to.equal(true);
    expect(() => A.encoderOIDDER("1.3.6.1.4.1.340282366920938463463374607431768211456.1")).to.throw(A.ErreurAncrage, /2\^128/);
    // Relecture d'un OID forgé à arc de 2^128 : refus du lecteur borné.
    const corps = Buffer.from([0x2b, 0x06, 0x01, 0x04, 0x01, ...b128(1n << 128n), 0x01]);
    const champ = Buffer.concat([Buffer.from([0x06, corps.length]), corps]);
    const req = A.construireRequete({ digest: "0x" + "11".repeat(32), nonce: 5n, policy_oid: "1.3.6.1.4.1.5.1" });
    const sans = A.encoderOIDDER("1.3.6.1.4.1.5.1");
    const i = req.indexOf(sans);
    const forge = Buffer.concat([req.subarray(0, i), champ, req.subarray(i + sans.length)]);
    forge[1] = forge.length - 2;
    expect(() => A.lireRequete(forge)).to.throw(A.ErreurAncrage, /2\^128/);
  });

  it("mutant CT-5 EX-5.1 : arcs ramenés à des flottants avant l'encodage, les octets du 2.25.<UUID> sont faux (tué par l'oracle)", async function () {
    const M = await importer(mutant("arcs-oid", 'const arcs = texte.split(".").map(BigInt);\n  if (arcs[0] < 2n && arcs[1] > 39n)', 'const arcs = texte.split(".").map((x) => BigInt(Number(x)));\n  if (arcs[0] < 2n && arcs[1] > 39n)'));
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-5, référence : file relue et reprise au démarrage (EX-8.5 règle 3, EX-8.8, EX-8.12)", function () {
  this.timeout(120000);
  let A;
  before(async function () {
    A = await importer(RACINE);
  });

  const oracleFile = (M) => {
    const trace = lireJSON(CT5, "planification", "redemarrage-reprise.json");
    const q = structuredClone(trace.queue_before);
    const j = q.find((d) => d.kind === "jeton_point" && d.state === "envoyee");
    delete j.attempts;
    const lu = M.lireFile(M.ecrireFile(q));
    if (lu.demandes.length !== q.length - 1 || !lu.errors.some((e) => /mal formée.*attempts/.test(e))) return false;
    try {
      const p = M.creerPlanificateur(trace.config);
      p.charger(lu.demandes);
      p.recevoir(trace.inputs[0]);
    } catch {
      return false;
    }
    return true;
  };

  it("CT-5 EX-8.5 : une ligne de file acceptée en JSON mais sans attempts est consignée « mal formée » et ignorée par lireFile ; le démarrage sur la file relue ne lève pas ; charger refuse la même ligne (ErreurAncrage) ; compacterFile ne la recopie pas", function () {
    expect(oracleFile(A)).to.equal(true);
    const trace = lireJSON(CT5, "planification", "redemarrage-reprise.json");
    const q = structuredClone(trace.queue_before);
    delete q[0].attempts;
    expect(() => A.creerPlanificateur(trace.config).charger(q)).to.throw(A.ErreurAncrage, /attempts/);
    const compacte = A.compacterFile(A.ecrireFile(q));
    expect(compacte.requests).to.equal(q.length - 1);
    expect(A.defautDemande(trace.queue_before[0])).to.equal(null);
    for (const [membre, valeur] of [["deadlines", "1"], ["subject", null], ["attempts_total", -1], ["created_at", 5]]) {
      const d = structuredClone(trace.queue_before[0]);
      d[membre] = valeur;
      expect(A.defautDemande(d), membre).to.be.a("string");
    }
  });

  it("mutant CT-5 EX-8.5 : sans le contrôle des attempts, la ligne est admise et le démarrage lève TypeError (tué par l'oracle)", async function () {
    const M = await importer(mutant("tentatives-forme", 'if (!Array.isArray(d.attempts) || d.attempts.some((a) => !estObjet(a) || !Number.isSafeInteger(a.n) || a.n < 1 || typeof a.outcome !== "string" || typeof a.started_at !== "string")) return "attempts mal formées";\n', ""));
    expect(oracleFile(M)).to.equal(false);
  });

  /** Panne du principal : chaque envoi RFC 3161 échoue (délai) une seconde après son départ, jusqu'à `fin`. */
  function poursuivre(M, p, jeton, depuis, fin) {
    const iso = (v) => new Date(v).toISOString();
    const echec = (t, n) => ({ t: iso(t), type: "reponse_rfc3161", data: { request_id: jeton, attempt: n, transport: "delai", http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null } });
    let vues = 0;
    const attente = [];
    const relever = () => { for (; vues < p.actions.length; vues++) { const a = p.actions[vues]; if (a.action === "envoyer_rfc3161" && a.request_id === jeton) attente.push({ at: Date.parse(a.t) + 1000, n: a.detail.attempt }); } };
    relever();
    for (let t = depuis; t <= fin; t += 1000) {
      while (attente.length && attente[0].at <= t) { const x = attente.shift(); p.recevoir(echec(Math.max(x.at, t), x.n)); relever(); }
      p.recevoir({ t: iso(t), type: "tic", data: {} });
      relever();
    }
  }
  const oracleReleve = (M) => {
    const trace = lireJSON(CT5, "planification", "principal-injoignable.json");
    const jeton = `jeton_periode:${trace.inputs[1].data.period_hash}`;
    const gigues = Array.from({ length: 500 }, () => 0);
    const p1 = M.creerPlanificateur(trace.config, { aleatoire: M.aleatoireVecteurs({ gigues }) });
    for (const e of trace.inputs.slice(0, 4)) p1.recevoir(e);
    poursuivre(M, p1, jeton, Date.parse("2026-11-03T14:00:03.000Z"), Date.parse("2026-11-03T14:00:19.000Z"));
    const lu = M.lireFile(p1.lignes.join("\n") + "\n");
    const p2 = M.creerPlanificateur(trace.config, { aleatoire: M.aleatoireVecteurs({ gigues }) });
    p2.charger(lu.demandes);
    p2.recevoir({ t: "2026-11-03T14:00:20.000Z", type: "demarrage", data: {} });
    poursuivre(M, p2, jeton, Date.parse("2026-11-03T14:00:21.000Z"), Date.parse("2026-11-03T14:10:00.000Z"));
    const releves = p2.actions.filter((a) => a.action === "releve");
    const auSecours = p2.actions.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === jeton && a.detail.provider === "qtsa-secours");
    return { ok: releves.length === 1 && releves[0].t === "2026-11-03T14:05:02.000Z" && auSecours.length > 0 && auSecours[0].t === "2026-11-03T14:05:02.000Z", releves, auSecours: auSecours.length, journal: p2.actions.filter((a) => a.action === "journaliser" && a.detail.event === "anchor_fallback") };
  };

  it("redémarré à 14:00:20 pendant la panne du principal, le planificateur relève le jeton de clôture vers le secours à 14:05:02, premier envoi (14:00:02) + fallback_after_s (300 s), avec la ligne anchor_fallback de raison delai (EX-8.8, EX-8.12)", function () {
    const r = oracleReleve(A);
    expect(r.ok, JSON.stringify(r.releves)).to.equal(true);
    expect(r.journal).to.have.length(1);
    expect(r.journal[0].detail).to.include({ to: "qtsa-secours", reason: "delai" });
  });

  it("CT-5 EX-8.12 : une demande déjà relevée (secours engagé) ou dont le secours est épuisé ne reçoit pas de seconde relève au redémarrage ; une relève dont l'instant est passé part dès le démarrage", function () {
    const trace = lireJSON(CT5, "planification", "principal-injoignable.json");
    const jeton = `jeton_periode:${trace.inputs[1].data.period_hash}`;
    const gigues = Array.from({ length: 500 }, () => 0);
    // Relève déjà faite avant l'arrêt : aucune nouvelle action releve.
    const p1 = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues }) });
    for (const e of trace.inputs.slice(0, 4)) p1.recevoir(e);
    poursuivre(A, p1, jeton, Date.parse("2026-11-03T14:00:03.000Z"), Date.parse("2026-11-03T14:05:30.000Z"));
    expect(p1.actions.filter((a) => a.action === "releve")).to.have.length(1);
    const lu = A.lireFile(p1.lignes.join("\n") + "\n");
    const p2 = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues }) });
    p2.charger(lu.demandes);
    p2.recevoir({ t: "2026-11-03T14:05:31.000Z", type: "demarrage", data: {} });
    poursuivre(A, p2, jeton, Date.parse("2026-11-03T14:05:32.000Z"), Date.parse("2026-11-03T14:08:00.000Z"));
    expect(p2.actions.filter((a) => a.action === "releve")).to.have.length(0);
    // Redémarrage après l'échéance de relève : la relève part au démarrage.
    const p3 = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues }) });
    for (const e of trace.inputs.slice(0, 4)) p3.recevoir(e);
    poursuivre(A, p3, jeton, Date.parse("2026-11-03T14:00:03.000Z"), Date.parse("2026-11-03T14:00:19.000Z"));
    const lu3 = A.lireFile(p3.lignes.join("\n") + "\n");
    const p4 = A.creerPlanificateur(trace.config, { aleatoire: A.aleatoireVecteurs({ gigues }) });
    p4.charger(lu3.demandes);
    const actions = p4.recevoir({ t: "2026-11-03T14:30:00.000Z", type: "demarrage", data: {} });
    const releve = actions.find((a) => a.action === "releve");
    expect(releve?.t).to.equal("2026-11-03T14:30:00.000Z");
    expect(actions.some((a) => a.action === "envoyer_rfc3161" && a.detail.provider === "qtsa-secours")).to.equal(true);
  });

  it("mutant CT-5 EX-8.12 : sans la minuterie reposée au démarrage, aucune relève après le redémarrage (tué par l'oracle)", async function () {
    const M = await importer(mutant("releve", 'this.timer(Math.max(s.premierEnvoi + this.delaiReleve(d), t), "releve", d.id);\n', ""));
    expect(oracleReleve(M).ok).to.equal(false);
  });

  /** File coupée entre la ligne obtenue du jeton de K2 et la ligne remplacee du jeton de K1 (trace echeance-remplacee), puis redémarrage. */
  const scenarioRemplacee = (M) => {
    const ref = lireJSON(CT5, "planification", "echeance-remplacee.json");
    const p1 = M.creerPlanificateur(ref.config, { aleatoire: M.aleatoireVecteurs({ gigues: ref.jitter_ms ?? [] }) });
    p1.charger(ref.queue_before ?? []);
    let coupe = -1;
    let remplacee = null;
    let tCoupe = null;
    for (const e of ref.inputs) {
      const n0 = p1.lignes.length;
      p1.recevoir(e);
      const nouvelles = p1.lignes.slice(n0).map((l) => JSON.parse(l));
      const iR = nouvelles.findIndex((l) => l.kind === "jeton_point" && l.state === "remplacee");
      if (iR >= 0 && coupe < 0) {
        const iO = nouvelles.slice(0, iR).map((l, i) => [l, i]).filter(([l]) => l.kind === "jeton_point" && l.state === "obtenue").pop();
        coupe = n0 + iO[1] + 1;
        remplacee = nouvelles[iR];
        tCoupe = e.t;
      }
    }
    const lu = M.lireFile(p1.lignes.slice(0, coupe).join("\n") + "\n");
    const p2 = M.creerPlanificateur(ref.config, { aleatoire: M.aleatoireVecteurs({ gigues: Array.from({ length: 50 }, () => 0) }) });
    p2.charger(lu.demandes);
    const t0 = Date.parse(tCoupe) + 500;
    const demarrage = p2.recevoir({ t: new Date(t0).toISOString(), type: "demarrage", data: {} });
    for (let t = t0 + 1000; t <= t0 + 900000; t += 1000) p2.recevoir({ t: new Date(t).toISOString(), type: "tic", data: {} });
    return { p2, demarrage, remplacee, apres: p2.file().find((d) => d.id === remplacee.id), avant: lu.demandes.find((d) => d.id === remplacee.id) };
  };
  const oracleRemplacee = (M) => {
    const r = scenarioRemplacee(M);
    return r.apres.state === "remplacee" && r.p2.actions.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === r.remplacee.id).length === 0 && r.demarrage.some((a) => a.action === "remplacer" && a.request_id === r.remplacee.id);
  };

  it("au redémarrage, la demande de point dont toutes les échéances (D_1 à D_8) sont inférieures à une échéance satisfaite (D_9, D_10 par K2) est close remplacee, replaced_by le jeton de K2, avec la ligne checkpoint_anchor_late et son alerte ; aucune nouvelle requête RFC 3161 pour ce point (EX-4.4, EX-8.12)", function () {
    const r = scenarioRemplacee(A);
    expect(r.avant.state).to.equal("a_reprendre");
    expect(oracleRemplacee(A)).to.equal(true);
    const remplacer = r.demarrage.find((a) => a.action === "remplacer" && a.request_id === r.remplacee.id);
    expect(remplacer.detail.replaced_by).to.match(/^jeton_point:0x/);
    expect(r.apres.replaced_by).to.equal(remplacer.detail.replaced_by);
    const tardif = r.demarrage.find((a) => a.action === "journaliser" && a.request_id === r.remplacee.id && a.detail.event === "checkpoint_anchor_late");
    expect(tardif.detail).to.include({ replaced_by: remplacer.detail.replaced_by });
    expect(tardif.detail.deadlines).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(tardif.detail.window_s).to.be.a("number");
    expect(r.demarrage.some((a) => a.action === "alerter" && a.request_id === r.remplacee.id && a.detail.code === "checkpoint_anchor_late")).to.equal(true);
    expect(r.demarrage.filter((a) => a.action === "echeance" && a.request_id === r.remplacee.id && a.detail.state === "remplacee")).to.have.length(8);
    // La file réécrite relue redonne le même état.
    const relue = A.lireFile(r.p2.lignes.join("\n") + "\n");
    expect(relue.errors).to.deep.equal([]);
  });

  it("mutant CT-5 EX-8.12 : sans l'application d'EX-4.4 aux demandes relues, la demande antérieure est renvoyée au prestataire (tué par l'oracle)", async function () {
    const M = await importer(mutant("cloture-points", "      this.clorePointsAnterieurs(d, t, p, bound);\n", ""));
    expect(oracleRemplacee(M)).to.equal(false);
  });
});

// --- (variante B) : jeton de période après le refus empreinte_squattee de son ancre.
import { traceEmpreinteSquattee } from "../scripts/vecteurs/generer-ct5.mjs";

describe("CT-5, référence : ancre de période refusée empreinte_squattee, jeton de clôture retenu (EX-8.4 règle 2, AN-36, EX-9.7 ; CT-4 EX-8.6 ; variante B)", function () {
  this.timeout(120000);
  let A;
  let trace;
  before(async function () {
    A = await importer(RACINE);
    trace = traceEmpreinteSquattee();
  });
  const demande = (t, kind) => t.queue_after.find((d) => d.kind === kind);
  const actions = (t, action, pred = () => true) => t.expected.filter((a) => a.action === action && pred(a));
  /** La trace B : aucune requête RFC 3161 sur periodHash, jeton de clôture en attente_registre, registry_pending à chaque inclusion_alert_s, alerte une fois ; rejouée sans écart par M. */
  const oracle = (M, t) => {
    const jeton = demande(t, "jeton_periode");
    const ancre = demande(t, "ancre_registre_periode");
    const pendings = actions(t, "journaliser", (a) => a.request_id === jeton.id && a.detail.event === "registry_pending").map((a) => a.t);
    return ancre.state === "refusee" && jeton.state === "attente_registre" && jeton.attempts.length === 0 && actions(t, "envoyer_rfc3161", (a) => a.request_id === jeton.id).length === 0 && JSON.stringify(pendings) === JSON.stringify(["2026-11-03T14:01:00.250Z", "2026-11-03T14:02:00.250Z"]) && actions(t, "alerter", (a) => a.request_id === jeton.id && a.detail.code === "registry_pending").length === 1 && M.verifierTrace(t).length === 0;
  };
  it("CT-5 EX-9.7 (variante B) : après le refus empreinte_squattee de l'ancre de la période, la requête RFC 3161 du periodHash ne part jamais, le jeton de clôture reste attente_registre et la période est signalée registry_pending à 14:01:00.250 et 14:02:00.250 (alerte majeure une fois) ; la preuve OpenTimestamps reste en attente et le jeton du point K4 est obtenu", function () {
    expect(oracle(A, trace)).to.equal(true);
    expect(demande(trace, "ots_periode").state).to.equal("en_attente");
    expect(demande(trace, "jeton_point").state).to.equal("obtenue");
    expect(demande(trace, "ancre_registre_point").state).to.equal("obtenue");
  });
  it("mutant CT-5 EX-9.7 (refus) : un refus empreinte_squattee qui libère le jeton de période l'envoie au prestataire ; la trace B rejouée porte des écarts (tué par l'oracle)", async function () {
    const M = await importer(mutant("squat-refus", 'if (j && j.kind === "jeton_point" && j.state === "attente_registre") this.pret(j, this.designe(j), t);', 'if (j && j.state === "attente_registre") this.pret(j, this.designe(j), t);'));
    expect(oracle(M, trace)).to.equal(false);
  });
  it("mutant CT-5 EX-9.7 (attente) : l'examen de l'attente du registre qui libère un jeton de période sur une ancre refusée (tué par l'oracle)", async function () {
    const M = await importer(mutant("squat-attente", '(ancre.state === "refusee" && d.kind === "jeton_point")', 'ancre.state === "refusee"'));
    expect(oracle(M, trace)).to.equal(false);
  });
});

// --- : cohérence d'auth.method et d'auth.secret (règle 4 d'EX-4.9 ; schéma ancrage-v0, auth : « aucune : null »).
describe("CT-5, référence : règle 4 d'AN-1, auth.method et auth.secret cohérents (EX-4.9, schéma ancrage-v0)", function () {
  this.timeout(60000);
  let A;
  const MD = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8");
  const exemple = () => JSON.parse(/<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
  before(async function () {
    A = await importer(RACINE);
  });
  const violations = (M, profil, modifier) => {
    const doc = exemple();
    modifier((role) => doc.rfc3161.providers.find((p) => p.role === role));
    return M.verifierConfiguration(doc, { profil, checkpoint_interval_s: 60, lecteurCertificat: () => true }).violations;
  };
  const oracle = (M) =>
    ["developpement", "production"].every((profil) => {
      const sansSecret = violations(M, profil, (de) => (de("principal").auth = { method: "basic", secret: null }));
      const secretEnTrop = violations(M, profil, (de) => (de("interne").auth = { method: "aucune", secret: { env: "NOORTRACE_TSA_ESSAI" } }));
      return sansSecret.length === 1 && sansSecret[0].rule === 4 && /sans secret/.test(sansSecret[0].message) && secretEnTrop.length === 1 && secretEnTrop[0].rule === 4 && /aucune avec un secret non nul/.test(secretEnTrop[0].message);
    });
  it("CT-5 EX-4.9 : un principal basic sans secret, ou un prestataire interne aucune avec un secret non nul, violent la règle 4 dans tout profil ; l'exemple d'EX-4.8 reste sans violation", function () {
    expect(oracle(A)).to.equal(true);
    for (const profil of ["developpement", "test", "production"]) expect(violations(A, profil, () => {}), profil).to.deep.equal([]);
  });
  it("mutant CT-5 EX-4.9 : sans les deux contrôles, aucune violation (tué par l'oracle)", async function () {
    const M = await importer(mutant("auth-secret", '    if (sansAuthentification && p.auth?.secret !== null && p.auth?.secret !== undefined) v(4, `prestataire ${p.id} : auth.method aucune avec un secret non nul`);\n    if (!sansAuthentification && p.auth && (p.auth.secret === null || p.auth.secret === undefined)) v(4, `prestataire ${p.id} : auth.method ${p.auth.method} sans secret`);\n', ""));
    expect(oracle(M)).to.equal(false);
  });
});

// --- Décision du porteur du 2026-11-16 (variante B) : repli de clôture après le refus empreinte_squattee de l'ancre de
// la période. EX-8.4, règle 2 : squat_wait_s après la clôture, si jeton_periode est encore attente_registre, le point
// de clôture reçoit une demande jeton_point sans échéance ; EX-9.7 : sur l'ancre d'une période refusée, ce jeton date la
// tête. Scénario : période 1 de référence avec c_T = 600 s (n_T = 6) ; D_5 (13:50) est servie par K2, de sorte que le
// point de clôture K4 (tree_size 5) n'a aucune échéance ; l'ancre de la période est refusée à 14:00:03, avant
// squat_wait_s (5 s) après la clôture.
import * as Composant from "@noortrace/ancrage/planificateur";

/** Trace du repli après refus, construite sur les entrées de la trace de référence (sans attendu). */
function traceRepliApresRefus() {
  const ref = lireJSON(CT5, "planification", "heure-nominale-reference.json");
  const config = JSON.parse(JSON.stringify(ref.config));
  config.rfc3161.checkpoints.interval_s = 600;
  const e = ref.inputs;
  const ap1 = e[16].data.request_id;
  const jetonK4 = { ...e[15], t: "2026-11-03T14:00:07.000Z", data: { ...e[15].data, gen_time: "2026-11-03T14:00:06Z" } };
  const inputs = [
    ...e.slice(0, 15),
    { t: "2026-11-03T14:00:03.000Z", type: "echec_registre", data: { request_id: ap1, code: "empreinte_squattee" } },
    jetonK4,
    { t: "2026-11-03T14:01:10.000Z", type: "tic", data: {} },
    { t: "2026-11-03T14:02:10.000Z", type: "tic", data: {} },
    { t: "2026-11-03T14:03:00.000Z", type: "arret", data: {} },
  ];
  return { ...ref, id: "repli-apres-refus", description: "essai", config, inputs, expected: [], queue_after: [] };
}

describe("CT-5, référence : repli de clôture après le refus empreinte_squattee de l'ancre de la période (EX-8.4 règle 2, EX-9.7 ; décision du porteur du 2026-11-16)", function () {
  this.timeout(120000);
  let A;
  before(async function () {
    A = await importer(RACINE);
  });
  const oracle = (M) => {
    const base = traceRepliApresRefus();
    const r = M.rejouerTrace(base);
    const jk4 = r.file.find((d) => d.kind === "jeton_point" && d.subject.declared_at === "2026-11-03T14:00:00.250Z");
    const repli = r.actions.filter((a) => a.action === "journaliser" && a.detail.event === "checkpoint_closing_fallback");
    const pendings = r.actions.filter((a) => a.action === "journaliser" && a.detail.event === "registry_pending").map((a) => a.t);
    const jp = r.file.find((d) => d.kind === "jeton_periode");
    return { r, ok: repli.length === 1 && repli[0].t === "2026-11-03T14:00:05.250Z" && Boolean(jk4) && jk4.state === "obtenue" && jk4.deadlines.length === 0 && jp.state === "attente_registre" && r.actions.filter((a) => a.action === "envoyer_rfc3161" && a.request_id === jp.id).length === 0 && JSON.stringify(pendings) === JSON.stringify(["2026-11-03T14:01:00.250Z", "2026-11-03T14:02:00.250Z"]) };
  };
  it("CT-5 EX-9.7, EX-8.4 règle 2 : l'ancre de la période refusée avant squat_wait_s, le point de clôture sans échéance reçoit son jeton de repli à 14:00:05.250 (checkpoint_closing_fallback) et l'obtient ; le jeton de clôture reste attente_registre, registry_pending à 14:01:00.250 et 14:02:00.250 ; le composant d'ancrage rejoue la trace sans écart", function () {
    const { r, ok } = oracle(A);
    expect(ok).to.equal(true);
    const trace = { ...traceRepliApresRefus(), expected: r.actions, queue_after: r.file };
    expect(A.verifierTrace(trace)).to.deep.equal([]);
    expect(Composant.rejouerTrace(trace).ecarts).to.deep.equal([]);
  });
  it("mutant CT-5 EX-9.7 (repli) : un repli de clôture abandonné sur une ancre refusée laisse la tête de la période sans jeton (tué par l'oracle)", async function () {
    const M = await importer(mutant("squat-repli", "if (!ancre) return;\n        this.repliCloture(d, t);", "if (!ancre || ancre.state === \"refusee\") return;\n        this.repliCloture(d, t);"));
    expect(oracle(M).ok).to.equal(false);
  });
});

// --- Revue de l'étape 8 (EX-8.10) : au plus REJEUX_PAR_PASSE_MAX rejeux d'une minuterie périodique (renvoi d'une ancre,
// examen de l'attente du registre) par demande et par passe ; au-delà, les échéances sautées sont comptées sur la ligne
// anchor_retry (missed_deadlines), jamais rejouées une à une. Scénario : clôture de la période 1 de référence, l'ancre de
// la période envoyée à 14:00:02 n'est pas incluse ; l'horloge saute de 14:00:03 à 14:40:00 (inclusion_alert_s = 60 s).
function traceSautHorloge() {
  const ref = lireJSON(CT5, "planification", "heure-nominale-reference.json");
  const e = ref.inputs;
  const inclusionAp1 = { ...e[16], t: "2026-11-03T14:40:01.000Z" };
  const jetonPh1 = { ...e[17], t: "2026-11-03T14:40:03.000Z", data: { ...e[17].data, gen_time: "2026-11-03T14:40:02Z" } };
  const inputs = [
    { ...e[0], t: "2026-11-03T13:59:00.000Z" },
    ...e.slice(11, 16),
    { t: "2026-11-03T14:40:00.000Z", type: "tic", data: {} },
    inclusionAp1,
    jetonPh1,
    { t: "2026-11-03T14:41:00.000Z", type: "arret", data: {} },
  ];
  return { ...ref, id: "saut-horloge", description: "essai", inputs, expected: [], queue_after: [] };
}

describe("CT-5, référence : rejeux par passe bornés après un saut d'horloge (EX-8.10, REJEUX_PAR_PASSE_MAX)", function () {
  this.timeout(120000);
  let A;
  before(async function () {
    A = await importer(RACINE);
  });
  const oracle = (M) => {
    const r = M.rejouerTrace(traceSautHorloge());
    const ap1 = r.file.find((d) => d.kind === "ancre_registre_periode");
    const ph1 = r.file.find((d) => d.kind === "jeton_periode");
    const envois = r.actions.filter((a) => a.action === "envoyer_registre" && a.request_id === ap1.id).map((a) => a.t);
    const retry = r.actions.filter((a) => a.action === "journaliser" && a.request_id === ap1.id && a.detail.event === "anchor_retry");
    const pendings = r.actions.filter((a) => a.action === "journaliser" && a.request_id === ph1.id && a.detail.event === "registry_pending").map((a) => [a.t, a.detail.age_s]);
    return {
      r,
      ok:
        JSON.stringify(envois) === JSON.stringify(["2026-11-03T14:00:02.000Z", "2026-11-03T14:01:02.000Z", "2026-11-03T14:02:02.000Z", "2026-11-03T14:03:02.000Z", "2026-11-03T14:04:02.000Z"]) &&
        retry.length === 1 && retry[0].t === "2026-11-03T14:04:02.000Z" &&
        JSON.stringify(retry[0].detail) === JSON.stringify({ event: "anchor_retry", kind: "ancre_registre_periode", mode: "renvoi", error_code: "recu_absent", missed_deadlines: 35, attempt: 4, attempt_id: A.identifiantCorrelation("ancre_registre_periode", ap1.subject.hash, 4) }) &&
        JSON.stringify(pendings) === JSON.stringify([["2026-11-03T14:01:00.250Z", 60], ["2026-11-03T14:02:00.250Z", 120], ["2026-11-03T14:03:00.250Z", 180], ["2026-11-03T14:04:00.250Z", 240], ["2026-11-03T14:40:00.250Z", 2400]]) &&
        ap1.state === "obtenue" && ap1.attempts_total === 5 && ph1.state === "obtenue",
    };
  };
  it("CT-5 EX-8.10 : saut d'horloge de 14:00:03 à 14:40:00 : l'ancre de la période est renvoyée quatre fois dans la passe (14:01:02 à 14:04:02), la ligne anchor_retry du quatrième rejeu compte les 35 échéances sautées (missed_deadlines) ; l'attente du registre est examinée quatre fois, puis à 14:40:00.250 ; le composant d'ancrage rejoue la trace sans écart", function () {
    const { r, ok } = oracle(A);
    expect(ok).to.equal(true);
    const trace = { ...traceSautHorloge(), expected: r.actions, queue_after: r.file };
    expect(A.verifierTrace(trace)).to.deep.equal([]);
    expect(Composant.rejouerTrace(trace).ecarts).to.deep.equal([]);
  });
  it("mutant CT-5 EX-8.10 : sans la borne des rejeux par passe, chaque échéance franchie est rejouée (tué par l'oracle)", async function () {
    const M = await importer(mutant("rejeux-passe", "const REJEUX_PAR_PASSE_MAX = 4;", "const REJEUX_PAR_PASSE_MAX = Infinity;"));
    expect(oracle(M).ok).to.equal(false);
  });
});

// --- EX-8.9 : `k` compte les échecs transitoires consécutifs de la demande chez ce prestataire ; une tentative obtenue,
// en échec permanent ou close par le redémarrage interrompt la série, en cours de marche comme relue au démarrage.
// Scénario : jeton de clôture ; principal : deux délais (5 s, puis 10 s), puis unacceptedPolicy (relève) ; secours :
// unacceptedPolicy (les deux épuisés, alternance au pas retry.max_ms) ; principal à 14:05:41 : délai. La série du
// principal repart de k = 1 : reprise 5 s après (14:05:56), et non 20 s après comme si les deux délais d'avant l'échec
// permanent comptaient encore.
function traceSerieInterrompue() {
  const ref = lireJSON(CT5, "planification", "heure-nominale-reference.json");
  const e = ref.inputs;
  const ph1 = e[17].data.request_id;
  const echec = (t, n, extra) => ({ t, type: "reponse_rfc3161", data: { request_id: ph1, attempt: n, transport: "reponse", http_status: 200, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null, ...extra } });
  const delai = (t, n) => echec(t, n, { transport: "delai", http_status: null });
  const permanent = (t, n) => echec(t, n, { pki_status: 2, failure_info: "unacceptedPolicy" });
  const inputs = [
    { ...e[0], t: "2026-11-03T13:59:00.000Z" },
    ...e.slice(11, 17),
    delai("2026-11-03T14:00:14.000Z", 1),
    delai("2026-11-03T14:00:29.000Z", 2),
    permanent("2026-11-03T14:00:40.000Z", 3),
    permanent("2026-11-03T14:00:41.000Z", 4),
    delai("2026-11-03T14:05:51.000Z", 5),
    { t: "2026-11-03T14:06:30.000Z", type: "arret", data: {} },
  ];
  return { ...ref, id: "serie-interrompue", description: "essai", jitter_ms: [0, 0, 0, 0, 0, 0, 0, 0], inputs, expected: [], queue_after: [] };
}

describe("CT-5, référence : série k interrompue par un résultat non transitoire en cours de marche (EX-8.9)", function () {
  this.timeout(120000);
  let A;
  before(async function () {
    A = await importer(RACINE);
  });
  const oracle = (M) => {
    const r = M.rejouerTrace(traceSerieInterrompue());
    const reprises = r.actions.filter((a) => a.action === "programmer" && a.request_id.startsWith("jeton_periode:") && a.detail.reason === "backoff").map((a) => [a.t, a.detail.next_at]);
    return { r, ok: JSON.stringify(reprises) === JSON.stringify([["2026-11-03T14:00:14.000Z", "2026-11-03T14:00:19.000Z"], ["2026-11-03T14:00:29.000Z", "2026-11-03T14:00:39.000Z"], ["2026-11-03T14:00:41.000Z", "2026-11-03T14:05:41.000Z"], ["2026-11-03T14:05:51.000Z", "2026-11-03T14:05:56.000Z"]]) };
  };
  it("CT-5 EX-8.9 : après deux délais puis un échec permanent chez le principal, le délai suivant chez lui attend retry.initial_ms (k = 1) ; le composant d'ancrage programme les mêmes reprises aux mêmes instants (le prestataire de la reprise en alternance n'est pas comparé ici)", function () {
    const { r, ok } = oracle(A);
    expect(ok).to.equal(true);
    const trace = { ...traceSerieInterrompue(), expected: r.actions, queue_after: r.file };
    expect(A.verifierTrace(trace)).to.deep.equal([]);
    const reprises = (actions) => actions.filter((a) => a.action === "programmer" && a.request_id.startsWith("jeton_periode:") && a.detail.reason === "backoff").map((a) => [a.t, a.detail.next_at]);
    expect(reprises(Composant.rejouerTrace(trace).actions)).to.deep.equal(reprises(r.actions));
  });
  it("mutant CT-5 EX-8.9 : une série qui n'est pas interrompue par l'échec permanent attend 20 s (tué par l'oracle)", async function () {
    const M = await importer(mutant("serie-rompue", '    if (precedente !== null && precedente.outcome !== "echec_transitoire" && precedente.outcome !== "reponse_tardive") s.k.set(cle, 0);\n', ""));
    expect(oracle(M).ok).to.equal(false);
  });
});

// --- EX-8.12, demandes de points relues (complément du 2026-11-16) : l'échéance n_T est satisfaite par le jeton_periode
// (EX-8.4, règle 1) ; une demande jeton_point non finale relue dont toutes les échéances lui sont inférieures est close
// remplacee au démarrage, replaced_by le jeton_periode, comme à la promotion de celui-ci. Scénario : file finale de la
// trace de référence, la demande du jeton de K4 (D_11) relue a_reprendre après un délai, le jeton de clôture obtenu.
function traceRelueJetonPeriode() {
  const ref = lireJSON(CT5, "planification", "heure-nominale-reference.json");
  const file = JSON.parse(JSON.stringify(ref.queue_after));
  const k4 = file.find((d) => d.kind === "jeton_point" && JSON.stringify(d.deadlines) === "[11]");
  k4.state = "a_reprendre";
  k4.result = null;
  k4.due_at = "2026-11-03T14:00:08.000Z";
  Object.assign(k4.attempts[0], { outcome: "echec_transitoire", error_code: "delai", detail: "delai de reponse depasse", next_at: "2026-11-03T14:00:08.000Z" });
  const inputs = [{ t: "2026-11-03T14:00:07.000Z", type: "demarrage", data: {} }, { t: "2026-11-03T14:00:30.000Z", type: "tic", data: {} }, { t: "2026-11-03T14:01:00.000Z", type: "arret", data: {} }];
  return { ...ref, id: "relue-jeton-periode", description: "essai", queue_before: file, inputs, expected: [], queue_after: [] };
}

describe("CT-5, référence : demande de point relue close par le jeton de clôture obtenu (EX-8.12, EX-4.4 ; complément du 2026-11-16)", function () {
  this.timeout(120000);
  let A;
  before(async function () {
    A = await importer(RACINE);
  });
  const oracle = (M) => {
    const r = M.rejouerTrace(traceRelueJetonPeriode());
    const k4 = r.file.find((d) => d.kind === "jeton_point" && JSON.stringify(d.deadlines) === "[11]");
    const ph1 = r.file.find((d) => d.kind === "jeton_periode");
    const tard = r.actions.filter((a) => a.action === "journaliser" && a.detail.event === "checkpoint_anchor_late");
    return k4.state === "remplacee" && k4.replaced_by === ph1.id && tard.length === 1 && tard[0].t === "2026-11-03T14:00:07.000Z" && JSON.stringify(tard[0].detail) === JSON.stringify({ event: "checkpoint_anchor_late", tree_size: 5, deadlines: [11], replaced_by: ph1.id, window_s: 306 }) && r.actions.filter((a) => a.action === "envoyer_rfc3161").length === 0;
  };
  it("CT-5 EX-8.12 : la demande du jeton de K4 relue a_reprendre est close remplacee au démarrage, replaced_by le jeton de clôture obtenu, checkpoint_anchor_late avec window_s = 306 (borne du jeton de clôture moins D_11) ; aucune requête ne part", function () {
    expect(oracle(A)).to.equal(true);
  });
  it("mutant CT-5 EX-8.12 : sans le jeton de clôture parmi les demandes couvrantes relues, la demande de K4 est renvoyée au prestataire (tué par l'oracle)", async function () {
    const M = await importer(mutant("relue-periode", 'const couvrantes = file.filter((d) => (d.kind === "jeton_point" || d.kind === "jeton_periode") && d.state === "obtenue")', 'const couvrantes = file.filter((d) => d.kind === "jeton_point" && d.state === "obtenue")'));
    expect(oracle(M)).to.equal(false);
  });
});
