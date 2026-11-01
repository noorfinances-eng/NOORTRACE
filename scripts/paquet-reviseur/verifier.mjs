#!/usr/bin/env node
// Outil de vérification d'un paquet réviseur en une commande (CT-8 §13.7).
//
//   node scripts/paquet-reviseur/verifier.mjs <paquet.tar> [--empreinte <sha256>]
//        [--ancres <fichier>] [--exiger <contrôles>] [--langue fr|en] [--json]
//        [--conserver <répertoire à créer>]
//   node scripts/paquet-reviseur/verifier.mjs --version | --aide
//   npm run paquet:verifier -- <paquet.tar> [mêmes options]
//
// Contrôle l'archive sans rien écrire (PR-1 à PR-9), puis seulement l'extrait
// dans un répertoire neuf (PR-10), compare le vérificateur joint à l'outil
// exécuté (PR-11 ; sans valeur quand l'outil exécuté est lui-même la copie
// d'un paquet extrait : raison auto_comparaison), vérifie
// l'attestation jointe (PR-12, sans effet sur le code), puis vérifie chaque
// dossier avec SON vérificateur de référence (scripts/verify/dossier.mjs de
// sa propre racine), jamais avec du code du paquet. Aucun accès au réseau.
// Codes : 0 intact et tous valides ; 1 au moins un invalide ; 2 entrée
// inutilisable ; 3 au moins un incomplet ; 4 paquet non conforme.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "../lib/journal.mjs";
import * as S from "../lib/securite.mjs";
import * as P from "../lib/paquet.mjs";

export const NOM = "scripts/paquet-reviseur/verifier.mjs";
export const VERSION = "0.1.0";
const DOSSIER_MJS = path.join(P.RACINE_OUTIL, "scripts", "verify", "dossier.mjs");
const MARQUE = / \[observation (autorise|a_approuver|refuse|inconnu)\]$/;
/** Suffixe de policy.version d'un ensemble en mode observation (CT-2 révision 0.6, EX-15.8). */
export const SUFFIXE_OBSERVATION = "-observation";

/**
 * Mode observation de l'événement prouvé (EX-12.9, EX-13.28) : vrai quand
 * code.policy_version finit par « -observation » (CT-2 EX-15.8 l'impose à tout
 * ensemble en mode observation et l'interdit aux autres) ou que policy.rule
 * porte une marque d'observation ; vaut pour tout type d'événement (appel
 * d'outil, échange de modèle, span, décision, rotation).
 */
export function modeObservation(ev) {
  const v = ev?.code?.policy_version;
  return (typeof v === "string" && v.endsWith(SUFFIXE_OBSERVATION)) || marqueObservation(ev?.policy?.rule) !== null;
}

/** Forme visible des caractères de contrôle (C0 sauf \n, DEL, C1) d'un texte venu du paquet (EX-13.27). */
export const visible = (s) => String(s).replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, "0")}`);

/** Vrai quand l'outil exécuté est le vérificateur joint d'un paquet extrait (PR-11 sans valeur). */
export function outilExtraitDUnPaquet(racine = P.RACINE_OUTIL) {
  return path.basename(racine) === "verificateur" && fs.existsSync(path.join(racine, "..", "MANIFESTE.json"));
}

/**
 * Décision de la marque d'observation de `policy.rule` (EX-13.28, section 12) :
 * la valeur `<x>` du suffixe « [observation <x>] », lu après la dernière
 * occurrence de « [observation », ou null sans marque reconnue.
 */
export function marqueObservation(regle) {
  if (typeof regle !== "string") return null;
  const m = regle.match(MARQUE);
  return m && regle.lastIndexOf(" [observation ") === m.index ? m[1] : null;
}

/** Erreur d'usage, dans les deux langues (EX-13.24, EX-13.27). */
class Usage extends Error {
  constructor(fr, en = fr) {
    super(fr);
    this.textes = { fr, en };
    this.type = "usage";
  }
}

function lireOptions(argv) {
  const o = { positionnels: [], langue: "fr", json: false, exiger: [] };
  const valeur = new Set(["empreinte", "ancres", "exiger", "langue", "conserver"]);
  const vus = new Set();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      o.positionnels.push(a);
      continue;
    }
    let [nom, v] = a.slice(2).split(/=(.*)/s);
    if (vus.has(nom)) throw new Usage(`option répétée : --${nom}`, `repeated option: --${nom}`);
    vus.add(nom);
    if (valeur.has(nom)) {
      if (v === undefined) v = argv[++i];
      if (v === undefined) throw new Usage(`--${nom} sans valeur`, `--${nom} without a value`);
      o[nom] = v;
    } else if (["json", "version", "aide", "help"].includes(nom)) {
      if (v !== undefined) throw new Usage(`--${nom} ne prend pas de valeur`, `--${nom} takes no value`);
      o[nom] = true;
    } else throw new Usage(`option inconnue : --${nom}`, `unknown option: --${nom}`);
  }
  if (!["fr", "en"].includes(o.langue)) throw new Usage(`--langue : fr ou en, pas ${o.langue}`, `--langue: fr or en, not ${o.langue}`);
  if (typeof o.exiger === "string") {
    const brut = o.exiger;
    o.exiger = brut === "tous" ? [1, 2, 3, 4, 5, 6, 7, 8] : brut.split(",").map((x) => (/^[1-8]$/.test(x) ? Number(x) : NaN));
    if (o.exiger.some((n) => !Number.isInteger(n)) || new Set(o.exiger).size !== o.exiger.length) throw new Usage(`--exiger : numéros de 1 à 8 distincts séparés par des virgules, ou tous (reçu « ${brut} »)`, `--exiger: distinct numbers 1 to 8 separated by commas, or tous (received "${brut}")`);
    o.exiger.sort((a, b) => a - b);
  }
  if (o.empreinte !== undefined) {
    const e = o.empreinte.toLowerCase().replace(/^0x/, "");
    if (!/^[0-9a-f]{64}$/.test(e)) throw new Usage("--empreinte : 64 chiffres hexadécimaux, avec ou sans 0x", "--empreinte: 64 hexadecimal digits, with or without 0x");
    o.empreinte = "0x" + e;
  }
  if (o.version || o.aide || o.help) {
    const exclusives = [...vus].filter((n) => ["version", "aide", "help"].includes(n));
    const autres = [...vus].filter((n) => !["version", "aide", "help", "langue"].includes(n));
    if (exclusives.length > 1 || autres.length || o.positionnels.length) throw new Usage("--version et --aide ne se combinent qu'avec --langue", "--version and --aide combine only with --langue");
    return o;
  }
  if (o.positionnels.length !== 1) throw new Usage("exactement une archive attendue", "exactly one archive expected");
  return o;
}

const t = (langue, x) => (typeof x === "string" ? x : x[langue]);

/** Écrit le paquet sous dest, sans jamais suivre un lien ni écraser un fichier (PR-10). */
function extraire(entrees, manifeste, dest) {
  fs.mkdirSync(dest, { mode: 0o700 });
  const rep = fs.realpathSync(dest);
  for (const e of entrees) {
    const comps = e.nom.split("/");
    let courant = rep;
    for (const c of comps.slice(0, -1)) {
      courant = path.join(courant, c);
      try {
        fs.mkdirSync(courant, { mode: 0o700 });
      } catch (err) {
        if (err.code !== "EEXIST") throw err;
        if (!fs.lstatSync(courant).isDirectory()) throw new Error(`${courant} n'est pas un répertoire`);
      }
    }
    const cible = path.join(courant, comps.at(-1));
    const fd = fs.openSync(cible, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
      // Écritures courtes reprises jusqu'à la longueur complète.
      for (let ecrit = 0; ecrit < e.donnees.length; ) {
        const n = fs.writeSync(fd, e.donnees, ecrit, e.donnees.length - ecrit);
        if (n <= 0) throw new Error(`${e.nom} : écriture interrompue après ${ecrit} octets`);
        ecrit += n;
      }
    } finally {
      fs.closeSync(fd);
    }
  }
  const attendu = new Map(manifeste.files.map((f) => [f.path, f.sha256]));
  for (const [p, h] of attendu) {
    const relu = fs.readFileSync(path.join(rep, P.RACINE, p));
    if (P.sha256(relu) !== h) throw new Error(`${p} relu avec un SHA-256 différent`);
  }
  return path.join(rep, P.RACINE);
}

function verifierDossier(racine, d, ancresLigne, options) {
  const rep = path.join(racine, d.path);
  const args = [DOSSIER_MJS, rep, "--json", "--langue", options.langue];
  let ancres = null;
  if (ancresLigne) {
    args.push("--ancres", ancresLigne.path);
    ancres = { source: "ligne_de_commande", path: ancresLigne.path, sha256: ancresLigne.sha256 };
  } else if (d.anchors) {
    const p = path.join(racine, d.anchors);
    args.push("--ancres", p);
    ancres = { source: "paquet", path: d.anchors, sha256: P.sha256(fs.readFileSync(p)) };
  }
  if (d.bitcoin_headers) args.push("--entetes-bitcoin", path.join(racine, d.bitcoin_headers));
  if (options.exiger.length) args.push("--exiger", options.exiger.join(","));
  const r = spawnSync(process.execPath, args, { encoding: "utf8", env: {}, maxBuffer: 64 * 1024 * 1024 });
  let rapport;
  try {
    rapport = JSON.parse(r.stdout);
  } catch {
    throw new Error(`${d.path} : rapport du vérificateur illisible (code ${r.status})`);
  }
  if (rapport.exit_code !== r.status) throw new Error(`${d.path} : code ${r.status} différent de exit_code ${rapport.exit_code}`);
  const statuts = rapport.controls ? rapport.controls.map((c) => c.status) : null;
  let observation = null;
  let observationMode = null;
  if (statuts && statuts[0] === "reussi" && statuts[5] === "reussi") {
    try {
      const ev = J.analyserJSONStrict(fs.readFileSync(path.join(rep, "evenement.json")));
      observation = marqueObservation(ev?.policy?.rule);
      observationMode = modeObservation(ev);
    } catch {
      observation = null;
      observationMode = null;
    }
  }
  return {
    path: d.path,
    anchors: ancres,
    bitcoin_headers: d.bitcoin_headers,
    exit_code: r.status,
    verdict: rapport.verdict ?? null,
    index_sha256: rapport.inputs?.dossier?.index_sha256 ?? null,
    failed_checks: rapport.failed_checks ?? [],
    control_statuses: statuts,
    observation,
    observation_mode: observationMode,
    statement: rapport.statement ?? null,
  };
}

/** Rapport vide (paquet-reviseur-v0#/$defs/rapport), code 2 tant que rien n'est établi. */
export function rapportInitial({ langue = "fr", empreinte = null, exiger = [] } = {}) {
  return {
    format: "noortrace/rapport-paquet-reviseur",
    version: 0,
    tool: { name: NOM, version: VERSION, runtime: `node ${process.version}` },
    language: langue,
    inputs: { archive: null, expected_sha256: empreinte, anchors_override: null, required_controls: exiger },
    manifest: null,
    checks: [],
    package_status: null,
    warnings: [],
    attestation: null,
    dossiers: [],
    summary: { dossiers: 0, valid: 0, invalid: 0, incomplete: 0, unusable: 0, observation: { dossiers: 0, autorise: 0, a_approuver: 0, refuse: 0, inconnu: 0 } },
    exit_code: 2,
    error: null,
  };
}

export function verifierPaquet(cheminArchive, options) {
  const rapport = rapportInitial({ langue: options.langue, empreinte: options.empreinte ?? null, exiger: options.exiger });
  const L = options.langue;
  // Erreurs d'usage décelables avant toute lecture de l'archive (EX-13.24).
  if (options.conserver !== undefined) {
    let present = true;
    try {
      fs.lstatSync(options.conserver);
    } catch (err) {
      present = err.code !== "ENOENT";
    }
    if (present) {
      rapport.error = { type: "usage", message: L === "en" ? `--conserver ${options.conserver}: the directory already exists; give a path that does not exist` : `--conserver ${options.conserver} : le répertoire existe déjà ; donnez un chemin qui n'existe pas` };
      return rapport;
    }
  }
  let ancresLigne = null;
  if (options.ancres !== undefined) {
    try {
      const a = fs.readFileSync(options.ancres);
      ancresLigne = { path: path.resolve(options.ancres), sha256: P.sha256(a) };
      rapport.inputs.anchors_override = ancresLigne;
    } catch (err) {
      rapport.error = { type: "usage", message: L === "en" ? `--ancres ${options.ancres}: unreadable (${err.code ?? err.message})` : `--ancres ${options.ancres} : illisible (${err.code ?? err.message})` };
      return rapport;
    }
  }
  let octets;
  try {
    const st = fs.statSync(cheminArchive);
    if (!st.isFile()) throw new Error(L === "en" ? "not a file" : "pas un fichier");
    if (st.size > P.LIMITE_ARCHIVE) throw new Error(L === "en" ? `${st.size} bytes, beyond ${P.LIMITE_ARCHIVE}` : `${st.size} octets, au-delà de ${P.LIMITE_ARCHIVE}`);
    octets = fs.readFileSync(cheminArchive);
  } catch (err) {
    rapport.error = { type: "archive_illisible", message: L === "en" ? `${cheminArchive}: ${err.code ?? err.message}` : `${cheminArchive} : ${err.code ?? err.message}` };
    return rapport;
  }
  rapport.inputs.archive = { path: path.resolve(cheminArchive), size: octets.length, sha256: P.sha256(octets) };
  const r = P.verifierArchive(octets, { empreinte: options.empreinte ?? null });
  const poser = (c) => rapport.checks.push({ id: c.id, status: c.status, reason: c.reason, detail: t(L, c.detail) });
  r.checks.forEach(poser);
  if (r.manifeste && r.octetsManifeste && r.checks.find((c) => c.id === "PR-7")?.status === "reussi") {
    rapport.manifest = { sha256: P.sha256(r.octetsManifeste), label: r.manifeste.label, created_at: r.manifeste.created_at, prepared_by: r.manifeste.prepared_by, files: r.manifeste.files.length, bytes: r.manifeste.files.reduce((s, f) => s + f.size, 0) };
  }
  if (r.checks.some((c) => c.status === "echoue")) {
    rapport.package_status = "non_conforme";
    for (const id of ["PR-10", "PR-11", "PR-12"]) poser({ id, status: "non_execute", reason: "prerequis_en_echec", detail: { fr: "une vérification précédente a échoué", en: "a previous check failed" } });
    rapport.exit_code = 4;
    return rapport;
  }
  rapport.package_status = "intact";
  const m = r.manifeste;
  // PR-10 : extraction
  const conserver = options.conserver ? path.resolve(options.conserver) : null;
  const dest = conserver ?? path.join(fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-paquet-")), "extrait");
  let racine;
  // Le répertoire temporaire est effacé dans tous les cas, échec de PR-10
  // compris (EX-13.25, pas 7).
  try {
    try {
      racine = extraire(r.entrees, m, dest);
      poser({ id: "PR-10", status: "reussi", reason: null, detail: { fr: `${m.files.length + 1} fichiers écrits dans un répertoire neuf et relus`, en: `${m.files.length + 1} files written to a new directory and read back` } });
    } catch (err) {
      poser({ id: "PR-10", status: "echoue", reason: null, detail: { fr: `extraction impossible : ${err.message}`, en: `extraction impossible: ${err.message}` } });
      for (const id of ["PR-11", "PR-12"]) poser({ id, status: "non_execute", reason: "prerequis_en_echec", detail: { fr: "une vérification précédente a échoué", en: "a previous check failed" } });
      rapport.error = { type: "extraction_impossible", message: err.message };
      rapport.exit_code = 2;
      return rapport;
    }
    // PR-11 : vérificateur joint
    if (m.verifier === null) poser({ id: "PR-11", status: "non_execute", reason: "sans_objet", detail: { fr: "aucun vérificateur joint", en: "no verifier enclosed" } });
    else if (outilExtraitDUnPaquet()) poser({ id: "PR-11", status: "non_execute", reason: "auto_comparaison", detail: { fr: "l'outil exécuté est le vérificateur joint d'un paquet extrait : la comparaison serait celle de la copie à elle-même ; comparez-la au SHA256SUMS publié (EX-3.14)", en: "the running tool is the enclosed verifier of an extracted package: the comparison would be of the copy with itself; compare it with the published SHA256SUMS (EX-3.14)" } });
    else {
      const miens = P.fichiersVerificateur();
      const joints = new Map(r.entrees.filter((e) => e.nom.startsWith(`${P.RACINE}/verificateur/`)).map((e) => [e.nom.slice(P.RACINE.length + 1), e.donnees]));
      const diff = [...new Set([...miens.keys(), ...joints.keys()])].sort().filter((p) => !miens.has(p) || !joints.has(p) || !miens.get(p).equals(joints.get(p)));
      if (diff.length) {
        poser({ id: "PR-11", status: "echoue", reason: null, detail: { fr: `vérificateur joint différent de l'outil exécuté : ${diff.join(", ")}`, en: `enclosed verifier differs from the running tool: ${diff.join(", ")}` } });
        rapport.warnings.push({ id: "AV-PR-1", detail: t(L, { fr: `${diff.length} fichier(s) du vérificateur joint diffèrent de l'outil exécuté : n'employez la copie jointe qu'après comparaison aux empreintes publiées`, en: `${diff.length} file(s) of the enclosed verifier differ from the running tool: use the enclosed copy only after comparing it with the published digests` }) });
      } else poser({ id: "PR-11", status: "reussi", reason: null, detail: { fr: `${joints.size} fichiers du vérificateur joint identiques à l'outil exécuté`, en: `${joints.size} files of the enclosed verifier identical to the running tool` } });
    }
    // PR-12 : attestation jointe
    if (m.attestation === null) poser({ id: "PR-12", status: "non_execute", reason: "sans_objet", detail: { fr: "aucune attestation jointe", en: "no attestation enclosed" } });
    else {
      let res;
      try {
        const jeu = J.analyserJSONStrict(fs.readFileSync(path.join(racine, m.attestation.approver_set)));
        res = S.verifierAttestation(fs.readFileSync(path.join(racine, m.attestation.signed)), jeu);
      } catch (err) {
        res = { retained: false, checks: [{ id: "AT-1", status: "echoue" }], details: { "AT-1": { fr: err.message, en: err.message } } };
      }
      rapport.attestation = { retained: res.retained, checks: res.checks.map((c) => ({ id: c.id, status: c.status })) };
      const resume = res.checks.map((c) => `${c.id} ${c.status}`).join(", ");
      poser({ id: "PR-12", status: res.retained ? "reussi" : "echoue", reason: null, detail: { fr: `attestation ${res.retained ? "retenue" : "non retenue"} (${resume}) ; périmètre déclaré, non prouvé`, en: `attestation ${res.retained ? "retained" : "not retained"} (${resume}); scope declared, not proven` } });
      if (!res.retained) rapport.warnings.push({ id: "AV-PR-2", detail: t(L, { fr: "attestation de périmètre non retenue", en: "scope attestation not retained" }) });
    }
    // Dossiers
    if (!ancresLigne && m.dossiers.some((d) => d.anchors)) {
      const fichiersAncres = [...new Set(m.dossiers.map((d) => d.anchors).filter(Boolean))];
      const h = fichiersAncres.map((a) => `${a} (SHA-256 ${P.sha256(fs.readFileSync(path.join(racine, a)))})`).join(", ");
      rapport.warnings.push({ id: "AV-PR-3", detail: t(L, { fr: `ancres prises dans le paquet : ${h} ; comparez-les à votre fichier, ou passez le vôtre par --ancres`, en: `anchors taken from the package: ${h}; compare them with your file, or pass yours with --ancres` }) });
    }
    if (!ancresLigne && m.dossiers.some((d) => !d.anchors)) rapport.warnings.push({ id: "AV-PR-4", detail: t(L, { fr: "au moins un dossier vérifié sans fichier d'ancres : contrôles 4, 5 et 8 non exécutés", en: "at least one dossier verified without an anchors file: controls 4, 5 and 8 not run" }) });
    for (const d of m.dossiers) rapport.dossiers.push(verifierDossier(racine, d, ancresLigne, options));
  } finally {
    if (!conserver) fs.rmSync(path.dirname(dest), { recursive: true, force: true });
  }
  const s = rapport.summary;
  s.dossiers = rapport.dossiers.length;
  for (const d of rapport.dossiers) {
    if (d.observation_mode) s.observation.dossiers++;
    if (d.observation) s.observation[d.observation]++;
    if (d.exit_code === 0) s.valid++;
    else if (d.exit_code === 1) s.invalid++;
    else if (d.exit_code === 3) s.incomplete++;
    else s.unusable++;
  }
  rapport.exit_code = s.invalid ? 1 : s.unusable ? 2 : s.incomplete ? 3 : 0;
  return rapport;
}

const ETIQ = {
  fr: { titre: "Vérification d'un paquet réviseur NOORTRACE (paquet-reviseur v0, CT-8 et CT-6)", outil: "Outil", archive: "Archive", manifeste: "Manifeste", paquet: "Paquet", empreinte: "Empreinte", verificateur: "Vérificateur", observation: "Observation", ancres: "Ancres", attestation: "Attestation", dossiers: "Dossiers", resultat: "Résultat", octets: "octets", nonReussies: "Vérifications non réussies :", avert: "Avertissements :", enonce: "Énoncé" },
  en: { titre: "Verification of a NOORTRACE reviewer package (paquet-reviseur v0, CT-8 and CT-6)", outil: "Tool", archive: "Archive", manifeste: "Manifest", paquet: "Package", empreinte: "Digest", verificateur: "Verifier", observation: "Observation", ancres: "Anchors", attestation: "Attestation", dossiers: "Dossiers", resultat: "Result", octets: "bytes", nonReussies: "Checks not passed:", avert: "Warnings:", enonce: "Statement" },
};
const etiquette = (s) => (s + " ".repeat(14)).slice(0, 14) + ": ";
const STATUT = { fr: { reussi: "[réussi]", echoue: "[ÉCHEC]", non_execute: "[non exécuté]" }, en: { reussi: "[passed]", echoue: "[FAILED]", non_execute: "[not run]" } };
const VERDICT = { fr: { 0: "[VALIDE]", 1: "[INVALIDE]", 2: "[INUTILISABLE]", 3: "[INCOMPLET]" }, en: { 0: "[VALID]", 1: "[INVALID]", 2: "[UNUSABLE]", 3: "[INCOMPLETE]" } };

export function rapportLisible(r) {
  const L = r.language;
  const E = ETIQ[L];
  const lignes = [E.titre, etiquette(E.outil) + `${r.tool.name} ${r.tool.version} (${r.tool.runtime})`];
  if (r.inputs.archive) lignes.push(etiquette(E.archive) + `${r.inputs.archive.path}, ${r.inputs.archive.size} ${E.octets}, SHA-256 ${r.inputs.archive.sha256}`);
  if (r.manifest) lignes.push(etiquette(E.manifeste) + (L === "fr" ? `SHA-256 ${r.manifest.sha256} ; « ${r.manifest.label} » ; créé le ${r.manifest.created_at} ; préparé par ${r.manifest.prepared_by}` : `SHA-256 ${r.manifest.sha256}; "${r.manifest.label}"; created ${r.manifest.created_at}; prepared by ${r.manifest.prepared_by}`));
  if (r.package_status === "intact") lignes.push(etiquette(E.paquet) + (L === "fr" ? `INTACT — ${r.manifest.files} fichiers, ${r.manifest.bytes} octets décrits par le manifeste, ${r.dossiers.length} dossier(s)` : `INTACT — ${r.manifest.files} files, ${r.manifest.bytes} bytes described by the manifest, ${r.dossiers.length} dossier(s)`));
  else if (r.package_status === "non_conforme") {
    const c = r.checks.find((x) => x.status === "echoue");
    lignes.push(etiquette(E.paquet) + (L === "fr" ? `NON CONFORME — ${c.id} : ${c.detail}` : `NOT CONFORMING — ${c.id}: ${c.detail}`));
  }
  // PR-2 et PR-11 réussies : la précaution prise est dite (EX-13.38).
  for (const [id, lib] of [["PR-2", E.empreinte], ["PR-11", E.verificateur]]) {
    const c = r.checks.find((x) => x.id === id && x.status === "reussi");
    if (c) lignes.push(etiquette(lib) + `${c.detail} (${id})`);
  }
  const non = r.checks.filter((c) => c.status !== "reussi");
  if (non.length) {
    lignes.push(E.nonReussies);
    for (const c of non) lignes.push(`  ${(STATUT[L][c.status] + "              ").slice(0, 14)}${(c.id + "     ").slice(0, 6)}${c.detail}${c.reason ? ` (${c.reason})` : ""}`);
  }
  if (r.warnings.length) {
    lignes.push(E.avert);
    for (const w of r.warnings) lignes.push(`  ${w.id} ${w.detail}`);
  }
  if (r.attestation) lignes.push(etiquette(E.attestation) + (L === "fr" ? (r.attestation.retained ? "retenue (AT-1 à AT-4 réussies) — périmètre déclaré par ses signataires, non prouvé" : "non retenue") : r.attestation.retained ? "retained (AT-1 to AT-4 passed) — scope declared by its signatories, not proven" : "not retained"));
  if (r.dossiers.length) {
    lignes.push(E.dossiers + (L === "fr" ? " :" : ":"));
    for (const d of r.dossiers) {
      const par = (st) => (d.control_statuses ?? []).map((s, i) => (s === st ? i + 1 : null)).filter((x) => x !== null).join(" ");
      const ctl = !d.control_statuses ? (L === "fr" ? "aucun contrôle rapporté" : "no control reported") : [["reussi", L === "fr" ? "réussis" : "passed"], ["non_execute", L === "fr" ? "non exécutés" : "not run"], ["echoue", L === "fr" ? "en échec" : "failed"]].filter(([st]) => par(st)).map(([st, lib]) => `${lib} ${par(st)}`).join(" ; ");
      const anc = d.anchors ? (d.anchors.source === "paquet" ? (L === "fr" ? "ancres du paquet" : "package anchors") : L === "fr" ? "ancres de la ligne de commande" : "command-line anchors") : L === "fr" ? "sans ancres" : "no anchors";
      const obs = d.observation ? (L === "fr" ? ` ; mode observation, la politique aurait rendu ${d.observation}` : `; observation mode, the policy would have returned ${d.observation}`) : d.observation_mode ? (L === "fr" ? " ; mode observation (version de politique en observation), aucune approbation n'a été exigée" : "; observation mode (policy version in observation), no approval was required") : "";
      const ech = d.failed_checks.length ? (L === "fr" ? ` ; vérifications en échec : ${d.failed_checks.join(", ")}` : `; failed checks: ${d.failed_checks.join(", ")}`) : "";
      const sep = L === "fr" ? " ; " : "; ";
      lignes.push(`  ${(VERDICT[L][d.exit_code] + "              ").slice(0, 14)}${d.path} — code ${d.exit_code}${sep}${L === "fr" ? "contrôles" : "controls"} ${ctl.replaceAll(" ; ", sep)}${sep}${anc}${ech}${obs}`);
      if (d.statement) lignes.push(`                ${E.enonce} : ${d.statement[L]}`);
    }
  }
  const s = r.summary;
  const o = s.observation;
  if (o.dossiers) lignes.push(etiquette(E.observation) + (L === "fr" ? `${o.dossiers} dossier(s) en mode observation ; marques : autorise ${o.autorise}, a_approuver ${o.a_approuver}, refuse ${o.refuse}, inconnu ${o.inconnu}` : `${o.dossiers} dossier(s) in observation mode; marks: autorise ${o.autorise}, a_approuver ${o.a_approuver}, refuse ${o.refuse}, inconnu ${o.inconnu}`));
  let res;
  if (r.exit_code === 4) res = L === "fr" ? "PAQUET NON CONFORME — aucun dossier n'est vérifié" : "PACKAGE NOT CONFORMING — no dossier is verified";
  else if (r.error) res = L === "fr" ? `ERREUR (${r.error.type}) : ${r.error.message}` : `ERROR (${r.error.type}): ${r.error.message}`;
  else res = L === "fr" ? `${s.valid} dossier(s) valide(s) sur ${s.dossiers}, ${s.invalid} invalide(s), ${s.incomplete} incomplet(s), ${s.unusable} inutilisable(s)` : `${s.valid} valid dossier(s) of ${s.dossiers}, ${s.invalid} invalid, ${s.incomplete} incomplete, ${s.unusable} unusable`;
  lignes.push(etiquette(E.resultat) + `${res} — code ${r.exit_code}`);
  // Aucun caractère de contrôle venu du paquet n'atteint le terminal (EX-13.27).
  return lignes.map(visible).join("\n") + "\n";
}

const AIDE = {
  fr: `Vérification d'un paquet réviseur NOORTRACE en une commande (CT-8 §13.7)

usage :
  node <outil>/scripts/paquet-reviseur/verifier.mjs <paquet.tar> [--empreinte <sha256>]
       [--ancres <fichier>] [--exiger <contrôles>] [--langue fr|en] [--json]
       [--conserver <répertoire à créer>]
  node <outil>/scripts/paquet-reviseur/verifier.mjs --version | --aide [--langue fr|en]

<outil> est la racine du dépôt public, ou le répertoire verificateur/ d'un
paquet complet extrait.

  <paquet.tar>   l'archive (.tar non compressé) ; exactement une
  --empreinte    SHA-256 attendu de l'archive, 64 chiffres hexadécimaux avec ou
                 sans 0x, reçu par un autre canal (PR-2) ; sans elle, PR-2 n'est
                 pas exécutée
  --ancres       votre fichier d'ancres (CT-6 §12), employé pour tous les
                 dossiers à la place de ceux du paquet
  --exiger       contrôles de CT-6 à exiger : numéros de 1 à 8 séparés par des
                 virgules, ou tous
  --langue       langue du résumé et des textes du rapport : fr (défaut) ou en
  --json         rapport JSON (paquet-reviseur-v0#/$defs/rapport) au lieu du
                 résumé lisible
  --conserver    répertoire, qui ne doit pas exister, où le paquet est extrait
                 et gardé ; sans elle, un répertoire temporaire est effacé
  --version      nom, version, environnement, puis SHA-256 de chaque fichier
                 du vérificateur que cet outil joindrait, calculés par l'outil
                 lui-même : une copie se contrôle par le SHA256SUMS publié,
                 jamais par cette sortie
  --aide         cette aide

L'outil contrôle l'archive sans rien écrire (PR-1 à PR-9), puis seulement
l'extrait dans un répertoire neuf sous le répertoire temporaire du système
(ou celui de --conserver), qu'il efface à la fin (PR-10) ; il compare le
vérificateur joint à l'outil exécuté (PR-11), vérifie l'attestation jointe
(PR-12), puis vérifie chaque dossier avec son propre vérificateur de CT-6.
Il n'exécute aucun code du paquet et n'ouvre aucune connexion réseau.

Codes de retour (priorité : 4, puis 1, 2, 3, 0) :
  0  paquet intact, tous les dossiers valides
  1  paquet intact, au moins un dossier invalide
  2  entrée inutilisable : usage, archive illisible, extraction impossible,
     erreur interne, ou dossier inutilisable (fichier d'ancres refusé)
  3  paquet intact, au moins un dossier incomplet (--exiger)
  4  paquet non conforme : aucun dossier n'est vérifié
`,
  en: `One-command verification of a NOORTRACE reviewer package (CT-8 §13.7)

usage:
  node <tool>/scripts/paquet-reviseur/verifier.mjs <package.tar> [--empreinte <sha256>]
       [--ancres <file>] [--exiger <controls>] [--langue fr|en] [--json]
       [--conserver <directory to create>]
  node <tool>/scripts/paquet-reviseur/verifier.mjs --version | --aide [--langue fr|en]

<tool> is the root of the public repository, or the verificateur/ directory
of an extracted full package.

  <package.tar>  the archive (uncompressed .tar); exactly one
  --empreinte    expected SHA-256 of the archive, 64 hexadecimal digits with
                 or without 0x, received over another channel (PR-2); without
                 it, PR-2 is not run
  --ancres       your anchors file (CT-6 §12), used for every dossier instead
                 of those of the package
  --exiger       CT-6 controls to require: numbers 1 to 8 separated by commas,
                 or tous (all)
  --langue       language of the summary and of the report texts: fr
                 (default) or en
  --json         JSON report (paquet-reviseur-v0#/$defs/rapport) instead of
                 the readable summary
  --conserver    directory, which must not exist, where the package is
                 extracted and kept; without it, a temporary directory is
                 deleted
  --version      name, version, runtime, then SHA-256 of each file of the
                 verifier this tool would enclose, computed by the tool
                 itself: a copy is checked against the published SHA256SUMS,
                 never against this output
  --aide         this help

The tool checks the archive without writing anything (PR-1 to PR-9), then
only extracts it into a new directory under the system temporary directory
(or that of --conserver), which it deletes at the end (PR-10); it compares
the enclosed verifier with the running tool (PR-11), checks the enclosed
attestation (PR-12), then verifies each dossier with its own CT-6 verifier.
It runs no code from the package and opens no network connection.

Exit codes (priority: 4, then 1, 2, 3, 0):
  0  package intact, every dossier valid
  1  package intact, at least one dossier invalid
  2  unusable input: usage, unreadable archive, extraction impossible,
     internal error, or unusable dossier (anchors file refused)
  3  package intact, at least one dossier incomplete (--exiger)
  4  package not conforming: no dossier is verified
`,
};

/** Langue et --json annoncés, lus sans analyse complète (rapport d'une erreur d'usage). */
function annonce(argv) {
  let langue = "fr";
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--langue=en" || (argv[i] === "--langue" && argv[i + 1] === "en")) langue = "en";
  }
  return { langue, json: argv.includes("--json") };
}

/** Écrit une erreur de code 2 : rapport JSON avec --json, sinon une ligne sur la sortie d'erreur (EX-13.24, EX-13.27). */
function sortirEnErreur(json, rapport) {
  if (json) process.stdout.write(JSON.stringify(rapport, null, 2) + "\n");
  else console.error(rapport.language === "en" ? `Error: ${rapport.error.message}` : `Erreur : ${rapport.error.message}`);
  process.exit(2);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  const argv = process.argv.slice(2);
  const a = annonce(argv);
  let options;
  try {
    options = lireOptions(argv);
  } catch (err) {
    const r = rapportInitial({ langue: a.langue });
    r.error = { type: "usage", message: err.textes ? err.textes[a.langue] : err.message };
    sortirEnErreur(a.json, r);
  }
  if (options.version) {
    process.stdout.write(`${NOM} ${VERSION} (node ${process.version})\n`);
    for (const [p, o] of P.fichiersVerificateur()) process.stdout.write(`${P.sha256(o)}  ${p}\n`);
    process.exit(0);
  }
  if (options.aide || options.help) {
    process.stdout.write(AIDE[options.langue]);
    process.exit(0);
  }
  let rapport;
  try {
    rapport = verifierPaquet(options.positionnels[0], options);
  } catch (err) {
    const r = rapportInitial({ langue: options.langue, empreinte: options.empreinte ?? null, exiger: options.exiger });
    r.error = { type: "erreur_interne", message: String(err?.message ?? err).slice(0, 4000) };
    sortirEnErreur(options.json, r);
  }
  if (rapport.exit_code === 2 && rapport.error && !options.json) {
    // Code 2 avant ou pendant la lecture : la ligne d'erreur, puis le résumé s'il y a de quoi le faire.
    if (rapport.error.type === "usage" || rapport.error.type === "archive_illisible") sortirEnErreur(false, rapport);
  }
  if (options.json) process.stdout.write(JSON.stringify(rapport, null, 2) + "\n");
  else process.stdout.write(rapportLisible(rapport));
  process.exit(rapport.exit_code);
}
