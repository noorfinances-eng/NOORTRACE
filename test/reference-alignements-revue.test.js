// Alignements des bibliothèques de référence sur les textes révisés (étape 8,
// arbitrages du 14 novembre) :
// - CT-1 §11.4, « Autres termes mal typés » et règle générale des relations :
//   un `approval` objet dont `request_hash` est absent ou n'est pas une chaîne
//   met A-4 en échec (terme de sa propre règle qui ne se lit pas), même quand
//   voisins.json est inexploitable (scripts/lib/journal.mjs) ;
// - CT-8 §10.4 et EX-10.6 : ordre et étiquettes `exigence` de la table, forme
//   « première occurrence » des règles `increase|rate(x[w]) OP n` sur un
//   compteur de l'extracteur, du démon ou du composant d'ancrage, forme courte
//   pour noor_bft_equivocations_total, que le nœud expose dès son démarrage
//   (CT-4 EX-10.9 : « vaut 0 et est supervisée ») (scripts/lib/supervision.mjs) ;
// - CT-5 EX-8.9 : une tentative close par le redémarrage (`redemarrage`)
//   interrompt la série des échecs transitoires ; sans elle, la série d'une
//   demande relue continue (scripts/lib/ancrage.mjs) ;
// - CT-5 EX-5.10 étape 2 : `status` est un INTEGER signé ; hors de 0 à 5,
//   `statut_<n>`, permanente, jeton non lu ; hors des entiers représentables
//   (±(2^53 − 1)), `reponse_illisible` (scripts/lib/ancrage.mjs).
//
// Chaque essai échoue sur le code d'avant et passe sur le code aligné ; chaque
// règle a son mutant (copie de scripts/lib sous NOORTRACE_TMP, règle retirée,
// oracle en échec, copie détruite). Racine des scripts éprouvés : le dépôt, ou
// NOORTRACE_REVUE_RACINE (copie d'avant).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const SPEC = path.join(PROJECT_ROOT, "spec");
const CT1 = path.join(SPEC, "vecteurs", "ct-1", "dossiers");
const COPIES = [];
after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

const importer = (racine, module) => import(pathToFileURL(path.join(racine, "scripts", "lib", module)).href + `?t=${Date.now()}-${Math.random()}`);
/** Copie de scripts/lib (racine éprouvée) sous NOORTRACE_TMP, `ancien` remplacé par `nouveau` dans `module` ; node_modules lié. */
function mutant(nom, module, ancien, nouveau) {
  return mutantTexte(nom, module, (texte) => {
    const n = texte.split(ancien).length - 1;
    if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
    return texte.replace(ancien, () => nouveau);
  });
}
/** Même copie, le texte du module transformé par `f`. */
function mutantTexte(nom, module, f) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-alignements-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  fs.symlinkSync(path.join(PROJECT_ROOT, "node_modules"), path.join(racine, "node_modules"));
  const fichier = path.join(racine, "scripts", "lib", module);
  fs.writeFileSync(fichier, f(fs.readFileSync(fichier, "utf8")));
  return racine;
}
/** Racine éprouvée importable hors du dépôt (node_modules lié) : la copie d'avant de NOORTRACE_REVUE_RACINE, sinon le dépôt. */
function racineImportable() {
  if (RACINE === PROJECT_ROOT) return PROJECT_ROOT;
  const lien = path.join(RACINE, "node_modules");
  if (!fs.existsSync(lien)) fs.symlinkSync(path.join(PROJECT_ROOT, "node_modules"), lien);
  return RACINE;
}

// ---------------------------------------------------------------------------
// CT-1 §11.4 : A-4 sur un approval objet sans request_hash lisible
// ---------------------------------------------------------------------------

describe("Référence CT-1 §11.4 : A-4 échoue quand request_hash, terme de sa propre règle, est absent ou mal typé", function () {
  this.timeout(120000);
  const lireFichiers = (rep) => Object.fromEntries(fs.readdirSync(rep).filter((f) => f !== "attendu.json").map((f) => [f, fs.readFileSync(path.join(rep, f))]));
  let schemas = null;
  const base = (J) => {
    if (!schemas) {
      const fichiers = ["evenement-v0", "manifeste-v0", "dossier-v0", "point-de-controle-v0", "attestation-perimetre-v0"].map((n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}.schema.json`), "utf8")));
      schemas = J.registreSchemas(fichiers);
    }
    return schemas;
  };
  /** Statut d'A-4 du dossier valide-seq-6 (A-4 exécutée : la demande est le voisin seq 5) après `modifier`. */
  function a4(J, modifier) {
    const fichiers = lireFichiers(path.join(CT1, "valide-seq-6"));
    const ev = JSON.parse(fichiers["evenement.json"].toString("utf8"));
    const voisins = modifier(ev);
    fichiers["evenement.json"] = Buffer.from(J.texteJSON(ev));
    if (voisins !== undefined) fichiers["voisins.json"] = Buffer.from(voisins);
    const r = J.verifierDossier(J.reindexerDossier(fichiers).fichiers, { schemas: base(J) });
    const c = r.controles.find((x) => x.id === "A-4");
    return { ok: c.ok, execute: c.execute, detail: c.detail };
  }
  const CAS = [
    ["approval {} (vecteur invalide-a3-approval-vide)", (ev) => { ev.approval = {}; }],
    ["request_hash retiré, les autres membres gardés", (ev) => { delete ev.approval.request_hash; }],
    ["request_hash nombre", (ev) => { ev.approval.request_hash = 7; }],
    ["request_hash null", (ev) => { ev.approval.request_hash = null; }],
    ["approval {} et voisins.json inexploitable (texte « { »)", (ev) => { ev.approval = {}; return "{"; }],
  ];
  const oracle = (J) => CAS.every(([, m]) => {
    const s = a4(J, m);
    return s.ok === false && s.execute === true && /request_hash/.test(s.detail ?? "");
  });

  it("A-4 : approval {}, request_hash retiré, nombre ou null, et approval {} avec voisins.json inexploitable → A-4 en échec ; un request_hash chaîne d'un autre hash reste non exécuté, raison admise (demande hors du dossier) ; le dossier publié reste A-4 réussie", async function () {
    const J = await importer(racineImportable(), "journal.mjs");
    for (const [nom, m] of CAS) {
      const s = a4(J, m);
      expect(s, nom).to.include({ ok: false, execute: true });
      expect(s.detail, nom).to.match(/request_hash/);
    }
    const autre = a4(J, (ev) => { ev.approval.request_hash = "0x" + "ab".repeat(32); });
    expect(autre).to.include({ ok: null, execute: false });
    expect(autre.detail).to.match(/absent du dossier/);
    expect(a4(J, () => undefined)).to.include({ ok: true, execute: true });
  });

  it("mutant : sans la règle du terme request_hash, A-4 redevient non exécutée sur approval {} (tué par l'oracle)", async function () {
    const J = await importer(mutant("a4", "journal.mjs", "    if (typeof app.request_hash !== \"string\") return rapport.echec(\"A-4\",", "    if (false) return rapport.echec(\"A-4\","), "journal.mjs");
    expect(oracle(J)).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
// CT-8 §10.4 à §10.7, EX-10.6 : référence de supervision alignée sur les tables
// ---------------------------------------------------------------------------

describe("Référence CT-8 §10.4 à §10.7 et EX-10.6 : ordre, étiquettes exigence et forme « première occurrence » des règles de supervision", function () {
  this.timeout(120000);
  const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
  const section = (texte, debut, fin) => {
    const i = texte.indexOf(debut);
    return texte.slice(i, texte.indexOf(fin, i + debut.length));
  };
  /** Cellules d'une ligne de table Markdown (« \| » rendu par « | »). */
  function cellules(l) {
    const out = [];
    let cur = "";
    for (let i = 1; i < l.length - 1; i++) {
      if (l[i] === "\\" && l[i + 1] === "|") { cur += "|"; i++; continue; }
      if (l[i] === "|") { out.push(cur.trim()); cur = ""; continue; }
      cur += l[i];
    }
    out.push(cur.trim());
    return out;
  }
  const TABLES = [["### 10.4 ", "### 10.5 "], ["### 10.5 ", "### 10.6 "], ["### 10.6 ", "### 10.7 "], ["### 10.7 ", "### 10.8 "]].flatMap(([a, b]) => section(CT8, a, b).split("\n").filter((l) => l.startsWith("| `noortrace_")).map((l) => {
    const c = cellules(l);
    return { nom: c[0].replaceAll("`", ""), exigence: c[4].replaceAll("`", "") };
  }));
  const oracleTable = (S) => {
    const rs = S.reglesCalculees(S.PARAMETRES_DEFAUT);
    return TABLES.length === 99 && JSON.stringify(rs.map((r) => r.alert)) === JSON.stringify(TABLES.map((t) => t.nom)) && TABLES.every((t) => rs.find((r) => r.alert === t.nom).labels.exigence === t.exigence);
  };
  const oracleForme = (S) => {
    const par = Object.fromEntries(S.reglesCalculees(S.PARAMETRES_DEFAUT).map((r) => [r.alert, r]));
    return par.noortrace_registre_equivocation.expr === "increase(noor_bft_equivocations_total[5m]) > 0" && par.noortrace_registre_equivocation.naissance === null
      && par.noortrace_appels_bloques.expr === "(rate(noortrace_calls_blocked_total[5m]) > 0) or ((noortrace_calls_blocked_total unless noortrace_calls_blocked_total offset 5m) > 0)"
      && par.noortrace_fourche.expr.startsWith("(increase(noortrace_journal_lignes_total{event=\"journal_fork\"}[5m]) > 0) or ((");
  };

  it("SV-1 (table de CT-8 §10.4 à §10.7 qui fait foi) : les 99 règles de la référence sont celles des tables, dans leur ordre (noortrace_enregistreur_cible_muette, noortrace_journal_exploitation_lignes_perdues et noortrace_image_differente avant noortrace_export_refuse), avec l'étiquette exigence de leur ligne mot pour mot", async function () {
    const S = await importer(racineImportable(), "supervision.mjs");
    const rs = S.reglesCalculees(S.PARAMETRES_DEFAUT);
    expect(TABLES).to.have.length(99);
    expect(rs.map((r) => r.alert)).to.deep.equal(TABLES.map((t) => t.nom));
    for (const t of TABLES) expect(rs.find((r) => r.alert === t.nom).labels.exigence, t.nom).to.equal(t.exigence);
    expect(oracleTable(S)).to.equal(true);
  });

  it("mutant : noortrace_export_refuse remise à sa place d'avant, juste après noortrace_export_lecture_impossible (tué par l'oracle de l'ordre)", async function () {
    const S = await importer(mutantTexte("ordre", "supervision.mjs", (texte) => {
      const lignes = texte.split("\n");
      const i = lignes.findIndex((l) => l.includes('["10.4", "noortrace_export_refuse"'));
      if (i < 0) throw new Error("mutant ordre : ligne de noortrace_export_refuse introuvable");
      const [l] = lignes.splice(i, 1);
      const j = lignes.findIndex((x) => x.includes('["10.4", "noortrace_export_lecture_impossible"'));
      lignes.splice(j + 1, 0, l);
      return lignes.join("\n");
    }), "supervision.mjs");
    expect(oracleTable(S)).to.equal(false);
  });

  it("mutant : étiquette exigence de noortrace_image_differente remise à « … (PA-4, révision demandée, B-§8.4) » (tué par l'oracle des étiquettes)", async function () {
    const S = await importer(mutant("exigence", "supervision.mjs", "Image différente de la version publiée (PA-4)\"", "Image différente de la version publiée (PA-4, révision demandée, B-§8.4)\""), "supervision.mjs");
    expect(oracleTable(S)).to.equal(false);
  });

  it("EX-10.6 (arbitrage du 14 novembre) : la règle en rate() noortrace_appels_bloques prend la forme « première occurrence » ; noortrace_registre_equivocation garde la forme courte : noor_bft_equivocations_total est exposé à 0 par le nœud dès son démarrage (CT-4 EX-10.9, core/metrics/snapshot.go), ce n'est pas un compteur que l'extracteur, le démon ou le composant d'ancrage crée à sa première occurrence", async function () {
    const S = await importer(racineImportable(), "supervision.mjs");
    expect(oracleForme(S)).to.equal(true);
    const rs = S.reglesCalculees(S.PARAMETRES_DEFAUT);
    // Aucune règle réécrite ne porte une série noor_* ; toute forme simple réécrite porte une série noortrace_.
    expect(rs.filter((r) => r.naissance && !r.naissance.serie.startsWith("noortrace_"))).to.deep.equal([]);
    expect(rs.filter((r) => /noor_[a-z_]+ unless/.test(r.expr)).map((r) => r.alert)).to.deep.equal([]);
  });

  it("mutant : les séries noor_* remises dans la forme simple réécrite (tué par l'oracle de la forme)", async function () {
    const S = await importer(mutant("noor", "supervision.mjs", "(noortrace_[a-z_]+(?:\\{[^}]*\\})?)\\[([0-9]+[smhd])\\]\\) (>=?) ([0-9]+)$/;", "(noortrace_[a-z_]+(?:\\{[^}]*\\})?|noor_[a-z_]+)\\[([0-9]+[smhd])\\]\\) (>=?) ([0-9]+)$/;"), "supervision.mjs");
    expect(oracleForme(S)).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
// CT-5 EX-8.9 : série des échecs transitoires d'une demande relue
// ---------------------------------------------------------------------------

describe("Référence CT-5 EX-8.9 : une tentative close par le redémarrage interrompt la série des échecs transitoires ; sans elle, la série d'une demande relue continue", function () {
  this.timeout(120000);
  const BASE = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-5", "planification", "file-fenetre-32-redemarrage.json"), "utf8"));
  const ID = BASE.queue_before.find((d) => d.kind === "jeton_periode").id;
  const REPONSE_41 = "2026-11-03T14:05:10.000Z";
  /**
   * File de file-fenetre-32-redemarrage réduite aux tentatives 38 à 40 (toutes chez qtsa-principal) ; la tentative 40 :
   * « en_cours » (close par ce redémarrage), « redemarrage » (close par un redémarrage antérieur) ou « delai » (échec
   * transitoire ordinaire, demande a_reprendre). Redémarrage à 14:05:00, reprise (tentative 41) qui échoue par délai à
   * 14:05:10 ; rend l'attente programmée après cet échec, en ms (gigue injectée nulle).
   */
  function attenteApres41(A, tentative40) {
    const t = structuredClone(BASE);
    const d = t.queue_before.find((x) => x.id === ID);
    d.attempts = d.attempts.slice(-3);
    const a40 = d.attempts.at(-1);
    if (tentative40 !== "en_cours") {
      Object.assign(a40, { outcome: "echec_transitoire", error_code: tentative40, next_at: "2026-11-03T14:04:30.000Z", detail: tentative40 === "redemarrage" ? "redemarrage : reponse non recue" : "delai de reponse depasse" });
      d.state = "a_reprendre";
      d.due_at = a40.next_at;
    }
    const delai = { request_id: ID, attempt: 41, transport: "delai", http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null };
    const p = A.creerPlanificateur(t.config, { aleatoire: A.aleatoireVecteurs({ gigues: [0, 0, 0, 0, 0, 0, 0, 0] }) });
    p.charger(t.queue_before);
    for (const e of [{ t: "2026-11-03T14:05:00.000Z", type: "demarrage", data: {} }, { t: REPONSE_41, type: "reponse_rfc3161", data: delai }]) p.recevoir(e);
    const envoi41 = p.actions.find((x) => x.action === "envoyer_rfc3161" && x.request_id === ID && x.detail.attempt === 41);
    const prog = p.actions.find((x) => x.action === "programmer" && x.request_id === ID && x.t === REPONSE_41);
    if (!envoi41 || !prog) return null;
    return Date.parse(prog.detail.next_at) - Date.parse(REPONSE_41);
  }
  const oracle = (A) => attenteApres41(A, "delai") === 40000 && attenteApres41(A, "redemarrage") === 5000 && attenteApres41(A, "en_cours") === 5000;

  it("tentatives 38 à 40 en échec transitoire, sans tentative redemarrage : la série continue, l'échec de la tentative 41 attend initial_ms × factor^3 = 40 s ; tentative 40 close par un redémarrage (antérieur ou celui-ci) : la série repart, 5 s (initial_ms)", async function () {
    const A = await importer(racineImportable(), "ancrage.mjs");
    expect(attenteApres41(A, "delai")).to.equal(40000);
    expect(attenteApres41(A, "redemarrage")).to.equal(5000);
    expect(attenteApres41(A, "en_cours")).to.equal(5000);
  });

  it("mutant : sans l'amorce de la série depuis les tentatives relues, la série repart à chaque redémarrage (tué par l'oracle)", async function () {
    const A = await importer(mutant("ex89", "ancrage.mjs", "    if (!s.k.has(cle)) s.k.set(cle, echecsTransitoiresRelus(d, cle, att));\n", ""), "ancrage.mjs");
    expect(oracle(A)).to.equal(false);
  });

  it("mutant : une tentative redemarrage comptée comme un échec ordinaire (tué par l'oracle)", async function () {
    const A = await importer(mutant("ex89-redemarrage", "ancrage.mjs", "    if (a.error_code === \"redemarrage\") break;\n", ""), "ancrage.mjs");
    expect(oracle(A)).to.equal(false);
  });
});

// ---------------------------------------------------------------------------
// CT-5 EX-5.10 étape 2 : PKIStatus, INTEGER signé, hors de 0 à 5
// ---------------------------------------------------------------------------

describe("Référence CT-5 EX-5.10 étape 2 : status est un INTEGER signé ; hors de 0 à 5 : statut_<n>, permanente, jeton non lu ; hors des entiers représentables : reponse_illisible", function () {
  this.timeout(120000);
  const tlv = (etiquette, contenu) => {
    const n = contenu.length;
    const l = n < 0x80 ? Buffer.from([n]) : Buffer.from([0x81, n]);
    return Buffer.concat([Buffer.from([etiquette]), l, contenu]);
  };
  /** TimeStampResp { PKIStatusInfo { status (octets de l'INTEGER) } } sans jeton. */
  const reponse = (octetsStatus) => tlv(0x30, tlv(0x30, tlv(0x02, Buffer.from(octetsStatus))));
  const evaluer = (A, octetsStatus) => A.evaluerReponse({ requete: A.construireRequete({ digest: "0x" + "11".repeat(32), nonce: 7 }), reponse: reponse(octetsStatus), http: { status: 200, content_type: "application/timestamp-reply" }, sent_at: "2026-11-03T14:00:00.000Z", received_at: "2026-11-03T14:00:01.000Z" });
  const CAS = [
    ["-1 (02 01 FF)", [0xff], -1, "statut_-1"],
    ["-128 (02 01 80)", [0x80], -128, "statut_-128"],
    ["6 (02 01 06)", [0x06], 6, "statut_6"],
    ["256 (02 02 01 00)", [0x01, 0x00], 256, "statut_256"],
    ["2^53 − 1 (02 07 1F FF FF FF FF FF FF)", [0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 9007199254740991, "statut_9007199254740991"],
    ["−(2^53 − 1) (02 07 E0 00 00 00 00 00 01)", [0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], -9007199254740991, "statut_-9007199254740991"],
  ];
  const oracle = (A) => CAS.every(([, o, v, code]) => A.lireReponseTsa(reponse(o)).status === v && evaluer(A, o).error_code === code && evaluer(A, o).outcome === "echec_permanente")
    && evaluer(A, [0x20, 0, 0, 0, 0, 0, 0]).error_code === "reponse_illisible" && evaluer(A, []).error_code === "reponse_illisible";

  it("lireReponseTsa lit -1, -128, 6, 256, ±(2^53 − 1) ; evaluerReponse rend statut_<n>, permanente ; 2^53 et un INTEGER vide rendent reponse_illisible ; 0 à 5 inchangés (statut_3 transitoire, statut_4 critique)", async function () {
    const A = await importer(racineImportable(), "ancrage.mjs");
    for (const [nom, o, v, code] of CAS) {
      expect(A.lireReponseTsa(reponse(o)).status, nom).to.equal(v);
      expect(evaluer(A, o), nom).to.include({ error_code: code, outcome: "echec_permanente", class: "permanente", token: null });
    }
    expect(evaluer(A, [0x20, 0, 0, 0, 0, 0, 0]).error_code, "2^53").to.equal("reponse_illisible");
    expect(evaluer(A, []).error_code, "INTEGER vide").to.equal("reponse_illisible");
    expect(evaluer(A, [0x03])).to.include({ error_code: "statut_3", outcome: "echec_transitoire" });
    expect(evaluer(A, [0x04])).to.include({ error_code: "statut_4", critical: true });
    expect(oracle(A)).to.equal(true);
  });

  it("une réponse de status -1 qui porte l'empreinte d'un jeton, reçue pour une tentative close (redémarrage), n'est pas conservée comme pièce : le jeton d'un status hors de 0 et 1 n'est pas lu", async function () {
    const A = await importer(racineImportable(), "ancrage.mjs");
    const t = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-5", "planification", "file-fenetre-32-redemarrage.json"), "utf8"));
    const r40 = t.inputs.find((e) => e.type === "reponse_rfc3161" && e.data.attempt === 40);
    expect(r40.data.token_sha256).to.be.a("string");
    const p = A.creerPlanificateur(t.config, { aleatoire: A.aleatoireVecteurs({ gigues: [0, 0, 0, 0] }) });
    p.charger(t.queue_before);
    p.recevoir(t.inputs[0]);
    p.recevoir({ ...r40, data: { ...r40.data, pki_status: -1 } });
    expect(p.actions.filter((x) => x.t === r40.t && x.action === "stocker")).to.deep.equal([]);
    // Témoin : le même message de status 0 est conservé (pièce gardée, jamais promue, EX-8.5 règle 2).
    const q = A.creerPlanificateur(t.config, { aleatoire: A.aleatoireVecteurs({ gigues: [0, 0, 0, 0] }) });
    q.charger(t.queue_before);
    q.recevoir(t.inputs[0]);
    q.recevoir(r40);
    expect(q.actions.filter((x) => x.t === r40.t && x.action === "stocker")).to.have.length(1);
  });

  it("mutant : sans la borne des entiers représentables, 2^53 rend statut_9007199254740992 au lieu de reponse_illisible (tué par l'oracle)", async function () {
    const A = await importer(mutant("statut-borne", "ancrage.mjs", "  if (n > BigInt(Number.MAX_SAFE_INTEGER) || n < -BigInt(Number.MAX_SAFE_INTEGER)) throw", "  if (false) throw"), "ancrage.mjs");
    expect(oracle(A)).to.equal(false);
  });

  it("mutant : jeton d'une réponse reconnu pour tout status au plus 1, négatifs compris (tué par l'oracle de la pièce conservée)", async function () {
    const A = await importer(mutant("jeton-negatif", "ancrage.mjs", "const jeton = (data.pki_status === 0 || data.pki_status === 1) && ", "const jeton = Number.isInteger(data.pki_status) && data.pki_status <= 1 && "), "ancrage.mjs");
    const t = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-5", "planification", "file-fenetre-32-redemarrage.json"), "utf8"));
    const r40 = t.inputs.find((e) => e.type === "reponse_rfc3161" && e.data.attempt === 40);
    const p = A.creerPlanificateur(t.config, { aleatoire: A.aleatoireVecteurs({ gigues: [0, 0, 0, 0] }) });
    p.charger(t.queue_before);
    p.recevoir(t.inputs[0]);
    p.recevoir({ ...r40, data: { ...r40.data, pki_status: -1 } });
    expect(p.actions.filter((x) => x.t === r40.t && x.action === "stocker")).to.not.deep.equal([]);
  });

  it("mutant : status relu comme un octet non signé (tué par l'oracle)", async function () {
    const A = await importer(mutant("statut-signe", "ancrage.mjs", "const status = entierSigneStatut(st);", "const status = st.valeur()[0];"), "ancrage.mjs");
    expect(oracle(A)).to.equal(false);
  });
});
