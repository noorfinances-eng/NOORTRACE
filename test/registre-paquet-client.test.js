// TE-21 (CT-9) : paquet client de CT-4 §7.13 (révision 0.7), produit par
// l'outil de référence scripts/registre/noortrace-registre.mjs
// (paquet-client produire) depuis un dossier d'inscription fini et ses
// captures, puis contrôlé comme le client à la réception (paquet-client
// controler) : contenu fermé (EX-7.18), manifeste (EX-7.19), gabarit du
// service d'approbation (EX-7.20), aucun secret (EX-7.21), contrôle de
// réception point par point (EX-7.22), chaque exigence en réussite et en
// échec, chaque refus avec son code.
//
// Entrées : le dossier fini de l'exemple de CT-4 §7.10
// (spec/vecteurs/ct-4/inscription/valides/relecteur-exemple-fini.json), les
// manifestes d'instance des vecteurs de CT-4, et des captures que l'essai
// construit pour les six étapes à transaction du dossier (réponses JSON-RPC
// synthétiques, index conformes à operations-registre-v0, noms et SHA-256 de
// CP-6). Les clés viennent du mnémonique public « test test … junk »
// (m/44'/60'/0'/0/i), dérivées au moment de l'essai et écrites dans un
// répertoire temporaire hors du dépôt ; le jeton est tiré au hasard.
//
// Les sorties sont validées contre operations-registre-v0#/$defs/sortie tel
// que la révision 0.7 de CT-4 l'a étendu (EX-7.30, §13 : `command` admet
// `paquet-client`, `error.code` admet `dossier_inacheve`, `paquet_manifeste`
// à `paquet_captures` et `secret_present`), lu dans spec/schemas sans aucune
// copie complétée par l'essai.
//
// S'y ajoute, sur le réseau Hardhat en mémoire derrière un pont qui sert des
// certificats synthétiques (EX-A.6), la reprise d'EX-7.29 par l'outil : une
// étape `echec` accomplie par une transaction d'un autre expéditeur reste
// `echec` à la relance (`deja_fait`), puis `capturer --transaction --dossier`
// de cette transaction la passe à `capturee` après OP-11, la capture et OP-12
// sur les valeurs de l'étape ; et un approvisionnement fait sans transaction
// laisse `result.recorders[].funding` nul.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import http from "node:http";
import { network } from "hardhat";
import { HDNodeWallet, Transaction, keccak256 } from "ethers";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/conventions-registre.mjs";
import { deployNoortrace } from "../scripts/lib/noortrace.mjs";
import { certifierBloc } from "../scripts/vecteurs/generer-ct4.mjs";
import { executer } from "../scripts/registre/noortrace-registre.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VECTEURS = path.join(RACINE, "spec", "vecteurs", "ct-4");
const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const sha = (b) => "0x" + createHash("sha256").update(b).digest("hex");
const ecrit = (v) => JSON.stringify(v, null, 2) + "\n";
const keccakTexte = (s) => keccak256(Buffer.from(s, "utf8"));
const MNEMONIQUE = "test test test test test test test test test test test junk";
const cleHardhat = (i) => HDNodeWallet.fromPhrase(MNEMONIQUE, undefined, `m/44'/60'/0'/0/${i}`).privateKey;

const NOMS_SCHEMAS = ["paquet-client", "inscription-client", "configuration-approbation", "annuaire-approbateurs", "evenement", "ticket", "politique-approbation", "operations-registre", "instance-registre"];
const SCHEMAS = J.registreSchemas(NOMS_SCHEMAS.map((n) => lireJSON(path.join(RACINE, "spec", "schemas", `${n}-v0.schema.json`))));
const id = (n) => `https://noortrace.example/schemas/v0/${n}.schema.json`;
const valider = (v, n, fragment = "") => J.validerSchema(v, SCHEMAS[id(n)], { registre: SCHEMAS, fragment });

/** Codes de refus de paquet-client (CT-4 EX-7.30, révision 0.7), que le schéma révisé admet. */
const CODES_PAQUET = ["dossier_inacheve", "secret_present", "paquet_manifeste", "paquet_fichiers", "paquet_forme", "paquet_organisation", "paquet_jeu", "paquet_captures"];
/** Sortie d'une commande validée contre operations-registre-v0#/$defs/sortie de spec/schemas (révision 0.7), sans copie complétée. */
const validerSortie = (s) => J.validerSchema(s, SCHEMAS[id("operations-registre")], { registre: SCHEMAS, fragment: "#/$defs/sortie" });

const TEMPORAIRES = [];
function temporaire(prefixe) {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), `noortrace-${prefixe}-`));
  TEMPORAIRES.push(d);
  return d;
}

/** Exécute une commande de l'outil en processus ; rend la sortie JSON, validée, avec stdout et stderr bruts. */
async function outil(args, env = {}) {
  let out = "";
  let err = "";
  const avant = {};
  for (const [k, v] of Object.entries(env)) {
    avant[k] = process.env[k];
    process.env[k] = v;
  }
  try {
    const { code } = await executer(args, { stdout: { write: (s) => (out += s) }, stderr: { write: (s) => (err += s) } });
    const s = JSON.parse(out);
    const e = validerSortie(s);
    expect(e, JSON.stringify(e.slice(0, 3))).to.deep.equal([]);
    expect(s.command).to.equal("paquet-client");
    expect(s.exit_code).to.equal(code);
    s.brut = out + err;
    return s;
  } finally {
    for (const [k, v] of Object.entries(avant)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

function attendreRefus(s, code, { result = "refuse", point } = {}) {
  expect(s.result, JSON.stringify(s.error)).to.equal(result);
  expect(s.error?.code, JSON.stringify(s.error)).to.equal(code);
  expect(s.exit_code).to.equal(result === "inutilisable" ? 2 : 1);
  if (point !== undefined) expect(s.outputs.point, JSON.stringify(s.error)).to.equal(point);
}

function attendreReussite(s) {
  expect(s.result, JSON.stringify(s.error)).to.equal("reussi");
  expect(s.error).to.equal(null);
  expect(s.exit_code).to.equal(0);
}

// ---------------------------------------------------------------------------
// Inscription construite : dossier fini, captures, clés et jeton d'essai
// ---------------------------------------------------------------------------

const ROLE_ETAPE = { jeu_approbateurs: "jeu_approbateurs", assignation: "assignation", approvisionnement: "approvisionnement", inscription: "inscription", premiere_ancre: "ancre", premiere_cloture: "cloture" };
const reponse = (result) => Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), "utf8");
const quantite = (n) => "0x" + n.toString(16);

/**
 * Captures des étapes du dossier, comme l'outil les écrit (CP-6) : pour
 * chaque étape dont capture n'est pas nul, l'en-tête, les reçus de toutes les
 * transactions du bloc (celui de premiere_ancre porte aussi la transaction
 * d'une autre organisation), le certificat et l'index. S'y ajoutent ce que le
 * paquet ne contient jamais : envois, issues, refus, demande de clôture,
 * capture d'une autre organisation.
 */
function ecrireCaptures(d, rep) {
  fs.mkdirSync(rep, { recursive: true });
  const contrat = { jeu_approbateurs: d.result?.curator_set ?? d.steps.find((s) => s.step === "jeu_approbateurs").contract ?? "0x" + "a1".repeat(20), assignation: d.instance.contracts.curator_set_registry, approvisionnement: null, inscription: d.instance.contracts.recorder_registry, ancre: d.instance.contracts.attestation_registry, cloture: d.instance.contracts.period_registry };
  const ecrire = (nom, octets) => fs.writeFileSync(path.join(rep, nom), octets);
  const capturer = ({ role, transaction_hash, block_number: h, block_hash, autres = [] }) => {
    const txs = [transaction_hash, ...autres];
    const bloc = reponse({ number: quantite(h), hash: block_hash, transactions: txs });
    const recus = txs.map((t, i) => reponse({ transactionHash: t, transactionIndex: quantite(i), blockNumber: quantite(h), blockHash: block_hash, status: "0x1", logs: [] }));
    const cert = reponse({ height: quantite(h), chainId: d.instance.bft_chain_id, blockHash: block_hash, valsetHash: d.instance.validator_set_hash });
    const noms = { block: `bloc-${h}.json`, receipts: txs.map((t) => `recu-${t}.json`), certificate: `certificat-${h}.json` };
    ecrire(noms.block, bloc);
    txs.forEach((t, i) => ecrire(noms.receipts[i], recus[i]));
    ecrire(noms.certificate, cert);
    const index = {
      version: 0,
      role,
      evm_chain_id: d.instance.evm_chain_id,
      bft_chain_id: d.instance.bft_chain_id,
      contract: contrat[role],
      transaction_hash,
      block_number: h,
      block_hash,
      transaction_index: 0,
      log_index: role === "approvisionnement" ? null : 0,
      files: { block: { name: noms.block, sha256: sha(bloc) }, receipts: noms.receipts.map((name, i) => ({ name, sha256: sha(recus[i]) })), certificate: { name: noms.certificate, sha256: sha(cert) } },
      node: { rpc: "http://127.0.0.1:8645", validator_id: "v1" },
      validator_set_hash: d.instance.validator_set_hash,
      captured_at: "2026-11-01T09:00:00.000Z",
      attempts: 1,
      checks: [1, 2, 3, 4, 5, 6].map((i) => ({ id: `CP-${i}`, status: "reussi", detail: "" })),
      sending: null,
    };
    expect(valider(index, "operations-registre"), role).to.deep.equal([]);
    const nom = `capture-${h}-0-${role}.json`;
    ecrire(nom, ecrit(index));
    return nom;
  };
  for (const s of d.steps) {
    if (s.capture === null) continue;
    const nom = capturer({ role: ROLE_ETAPE[s.step], transaction_hash: s.transaction_hash, block_number: s.block_number, block_hash: s.block_hash, autres: s.step === "premiere_ancre" ? [sha("noortrace/essai/te-21/autre-organisation")] : [] });
    expect(nom).to.equal(s.capture);
    ecrire(`envoi-${s.transaction_hash}.json`, ecrit({ version: 0, transaction_hash: s.transaction_hash }));
    ecrire(`issue-${s.transaction_hash}.json`, ecrit({ block_number: s.block_number, status: "0x1" }));
  }
  ecrire(`refus-envoi-${sha("noortrace/essai/te-21/refus")}.json`, ecrit({ version: 0 }));
  ecrire(`demande-cloture-${d.steps.at(-1).subject}.json`, ecrit({ version: 0 }));
  capturer({ role: "inscription", transaction_hash: sha("noortrace/essai/te-21/autre-inscription"), block_number: 30000, block_hash: sha("noortrace/essai/te-21/bloc-30000") });
}

/** Clés et jeton d'essai : références d'EX-7.3 et valeurs (32 octets), gardées hors du dépôt. */
function secretsEssai(rep) {
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const cleChaine = cleHardhat(7);
  const graine = cleHardhat(8);
  fs.writeFileSync(path.join(rep, "cle-chaine-rec-exemple-01.cle"), cleChaine + "\n", { mode: 0o600 });
  fs.writeFileSync(path.join(rep, "rec-exemple-01.graine"), graine + "\n", { mode: 0o600 });
  const jeton = randomBytes(24).toString("base64url");
  return {
    args: ["--exploitant", "hardhat:0", "--cle-chaine", `fichier:${path.join(rep, "cle-chaine-rec-exemple-01.cle")}`, "--graine", `graine:${path.join(rep, "rec-exemple-01.graine")}`, "--jeton", "env:NOORTRACE_ESSAI_JETON_NOEUD"],
    env: { NOORTRACE_ESSAI_JETON_NOEUD: jeton },
    valeurs: { "--exploitant": cleHardhat(0), "--cle-chaine": cleChaine, "--graine": graine },
    jeton,
  };
}

/** Toutes les formes textuelles d'EX-7.21 d'un secret de 32 octets (0x… en entrée). */
function formes(hexa) {
  const b = Buffer.from(hexa.slice(2), "hex");
  const b64 = b.toString("base64");
  const b64u = b.toString("base64url");
  const remplir = (s) => s + "=".repeat((4 - (s.length % 4)) % 4);
  return {
    "hexadécimal 0x minuscules": hexa.toLowerCase(),
    "hexadécimal sans 0x majuscules": hexa.slice(2).toUpperCase(),
    "hexadécimal 0x casse mêlée": "0x" + [...hexa.slice(2)].map((c, i) => (i % 2 ? c.toUpperCase() : c)).join(""),
    "base64 avec remplissage": b64,
    "base64 sans remplissage": b64.replace(/=+$/, ""),
    "base64url avec remplissage": remplir(b64u),
    "base64url sans remplissage": b64u,
  };
}

/** Une inscription finie : dossier (octets donnés ou ceux du vecteur), captures, clés ; et le répertoire de sortie. */
function inscription(prefixe, { dossier = null } = {}) {
  const base = temporaire(prefixe);
  const octets = dossier ?? fs.readFileSync(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-fini.json"));
  const fDossier = path.join(base, "dossier.json");
  fs.writeFileSync(fDossier, octets);
  const d = JSON.parse(octets.toString("utf8"));
  const captures = path.join(base, "captures");
  ecrireCaptures(d, captures);
  return { base, fDossier, d, captures, sortie: path.join(base, "paquets"), secrets: secretsEssai(path.join(base, "cles")) };
}

const produire = (x, extra = [], env = {}) => outil(["paquet-client", "produire", "--dossier", x.fDossier, "--captures", x.captures, "--sortie", x.sortie, ...extra], env);
const controler = (rep, extra = [], env = {}) => outil(["paquet-client", "controler", "--paquet", rep, ...extra], env);

/** Le répertoire de sortie ne porte ni paquet ni répertoire temporaire. */
function aucunPaquet(x) {
  expect(fs.existsSync(x.sortie) ? fs.readdirSync(x.sortie) : []).to.deep.equal([]);
}

/** Chemins relatifs de tous les fichiers d'un répertoire. */
function inventaire(rep, relatif = "") {
  return fs.readdirSync(path.join(rep, relatif)).flatMap((n) => {
    const r = relatif ? `${relatif}/${n}` : n;
    return fs.lstatSync(path.join(rep, r)).isDirectory() ? inventaire(rep, r) : [r];
  });
}

const EXEMPLES_713 = (() => {
  const md = fs.readFileSync(path.join(RACINE, "spec", "CT-4-registre.md"), "utf8");
  const [manifeste, gabarit] = [...md.matchAll(/<!-- exemple: ([a-z-]+)(?:\/([a-z_]+))? -->\n```json\n([\s\S]*?)\n```/g)].map(([, , , t]) => JSON.parse(t));
  return { manifeste, gabarit };
})();
const CLIENT = ["--console-origin", EXEMPLES_713.gabarit.console_origin, ...EXEMPLES_713.gabarit.administrators.flatMap((a) => ["--administrateur-annuaire", a])];

after(function () {
  for (const d of TEMPORAIRES) fs.rmSync(d, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------

describe("TE-21 — paquet client produit puis contrôlé par l'outil de référence (CT-4 §7.13, EX-7.18 à EX-7.22)", function () {
  this.timeout(60000);

  let x;
  let paquet;
  before(async function () {
    x = inscription("te21");
    const s = await produire(x, [...CLIENT, "--prepare-par", "exploitant de l'essai TE-21", ...x.secrets.args], x.secrets.env);
    attendreReussite(s);
    paquet = s.outputs.directory;
  });

  it("paquet produit à la fin de l'inscription : exactement les fichiers d'EX-7.18, écrits selon EX-7.18 ; manifeste (EX-7.19) et gabarit (EX-7.20) conformes à paquet-client-v0 ; aucun secret (EX-7.21) ; contrôle de réception d'EX-7.22 réussi", async function () {
    expect(path.basename(paquet)).to.equal("paquet-client-relecteur-exemple");
    expect(path.dirname(paquet)).to.equal(path.resolve(x.sortie));
    expect(fs.readdirSync(x.sortie)).to.deep.equal(["paquet-client-relecteur-exemple"]);

    // EX-7.18 : contenu fermé. Les captures sont celles que nomment les index des étapes, rien d'autre.
    const attendus = new Set(["paquet-client.json", "inscription-client.json", "jeu-approbateurs.json", "gabarit-service-approbation.json"]);
    for (const s of x.d.steps) {
      if (s.capture === null) continue;
      attendus.add(`captures/${s.capture}`);
      const idx = lireJSON(path.join(x.captures, s.capture));
      for (const f of [idx.files.block, ...idx.files.receipts, idx.files.certificate]) attendus.add(`captures/${f.name}`);
    }
    const presents = inventaire(paquet);
    expect(new Set(presents)).to.deep.equal(attendus);
    expect(presents.length).to.equal(attendus.size);
    expect(presents.filter((p) => /envoi-|issue-|refus-|demande-|30000|\.cle$|\.graine$|cles-essai/.test(p))).to.deep.equal([]);
    expect(presents).to.include("captures/recu-" + sha("noortrace/essai/te-21/autre-organisation") + ".json");
    expect(presents).to.not.include("instance-registre.json");
    // Dossier et captures recopiés octet pour octet ; les trois documents créés écrits par JSON.stringify(objet, null, 2) et un saut de ligne.
    expect(fs.readFileSync(path.join(paquet, "inscription-client.json")).equals(fs.readFileSync(x.fDossier))).to.equal(true);
    for (const p of presents.filter((p) => p.startsWith("captures/"))) expect(fs.readFileSync(path.join(paquet, p)).equals(fs.readFileSync(path.join(x.captures, p.slice(9)))), p).to.equal(true);
    for (const p of ["paquet-client.json", "jeu-approbateurs.json", "gabarit-service-approbation.json"]) {
      const t = fs.readFileSync(path.join(paquet, p), "utf8");
      expect(ecrit(JSON.parse(t)), p).to.equal(t);
    }

    // EX-7.19 : manifeste conforme, membres, ordre, SHA-256 et longueurs.
    const m = lireJSON(path.join(paquet, "paquet-client.json"));
    expect(valider(m, "paquet-client")).to.deep.equal([]);
    expect(Object.keys(m)).to.deep.equal(["version", "org", "org_id", "instance", "files", "prepared_by", "prepared_at", "source"]);
    expect([m.org, m.org_id]).to.deep.equal([x.d.organisation.slug, x.d.organisation.org_id]);
    expect(m.org_id).to.equal(keccakTexte(m.org));
    expect(m.instance).to.deep.equal({ evm_chain_id: 2124, bft_chain_id: "noortrace-2124-dev", manifest_sha256: null });
    expect(m.prepared_by).to.equal("exploitant de l'essai TE-21");
    expect(m.source).to.match(/noortrace-registre\.mjs paquet-client produire, version \d+\.\d+\.\d+/);
    const chemins = m.files.map((f) => f.path);
    expect(chemins.slice(0, 3)).to.deep.equal(["inscription-client.json", "jeu-approbateurs.json", "gabarit-service-approbation.json"]);
    const captures = chemins.slice(3);
    expect(captures).to.deep.equal([...captures].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b))));
    expect(new Set(chemins)).to.deep.equal(new Set(presents.filter((p) => p !== "paquet-client.json")));
    const roles = { bloc: "capture_bloc", capture: "capture_index", certificat: "capture_certificat", recu: "capture_recu" };
    for (const f of m.files) {
      const b = fs.readFileSync(path.join(paquet, f.path));
      expect([f.sha256, f.length], f.path).to.deep.equal([sha(b), b.length]);
      if (f.path.startsWith("captures/")) expect(f.role, f.path).to.equal(roles[f.path.slice(9).split("-")[0]]);
    }
    // Les SHA-256 et longueurs du dossier, du jeu et du gabarit sont ceux de l'exemple de 7.13 (mêmes documents, même écriture).
    for (const p of ["inscription-client.json", "jeu-approbateurs.json", "gabarit-service-approbation.json"]) {
      expect(m.files.find((f) => f.path === p), p).to.deep.equal(EXEMPLES_713.manifeste.files.find((f) => f.path === p));
    }

    // jeu-approbateurs.json : result.approver_set, membre pour membre, à la forme de politique-approbation-v0.
    const jeu = lireJSON(path.join(paquet, "jeu-approbateurs.json"));
    expect(valider(jeu, "politique-approbation", "#/$defs/jeu_approbateurs")).to.deep.equal([]);
    expect(Object.entries(jeu)).to.deep.equal(Object.entries(x.d.result.approver_set));

    // EX-7.20 : gabarit = celui de l'exemple de 7.13 ; chaque membre non nul valide contre la propriété de même nom de configuration-approbation-v0.
    const g = lireJSON(path.join(paquet, "gabarit-service-approbation.json"));
    expect(g).to.deep.equal(EXEMPLES_713.gabarit);
    expect(valider(g, "paquet-client", "#/$defs/gabarit_service")).to.deep.equal([]);
    for (const [k, v] of Object.entries(g)) if (v !== null) expect(valider(v, "configuration-approbation", `#/properties/${k}`), k).to.deep.equal([]);

    // EX-7.21 : aucune forme d'aucun secret employé dans aucun fichier (recherche propre à l'essai).
    for (const p of presents) {
      const t = fs.readFileSync(path.join(paquet, p), "latin1");
      for (const [nom, v] of Object.entries(x.secrets.valeurs)) {
        for (const [forme, f] of Object.entries(formes(v))) expect(forme.startsWith("hexa") ? t.toLowerCase().includes(f.toLowerCase()) : t.includes(f), `${p} : ${nom} (${forme})`).to.equal(false);
      }
      expect(t.includes(x.secrets.jeton), `${p} : jeton`).to.equal(false);
    }

    // EX-7.22 : le client contrôle le paquet ; le producteur, avec ses références, refait EX-7.21.
    const r = await controler(paquet);
    attendreReussite(r);
    expect(r.outputs).to.include({ org: "relecteur-exemple", org_id: m.org_id, files: m.files.length, manifest_sha256: sha(fs.readFileSync(path.join(paquet, "paquet-client.json"))) });
    expect(r.outputs.secrets_checked).to.deep.equal({ count: 0, references: [] });
    const rs = await controler(paquet, x.secrets.args, x.secrets.env);
    attendreReussite(rs);
    // EX-7.21, EX-7.30 : la sortie nomme les options cherchées et leur nombre, avec la référence de chacune, jamais une valeur.
    expect(rs.outputs.secrets_checked).to.deep.equal({
      count: 4,
      references: [
        { option: "--cle-chaine", reference: x.secrets.args[3] },
        { option: "--exploitant", reference: "hardhat:0" },
        { option: "--graine", reference: x.secrets.args[5] },
        { option: "--jeton", reference: "env:NOORTRACE_ESSAI_JETON_NOEUD" },
      ],
    });
    const texteSortie = JSON.stringify(rs);
    for (const v of [...Object.values(x.secrets.valeurs), x.secrets.jeton]) {
      expect(texteSortie.includes(v), "aucune valeur de secret dans la sortie").to.equal(false);
      expect(texteSortie.toLowerCase().includes(v.replace(/^0x/, "").toLowerCase()), "aucune valeur de secret dans la sortie (hexadécimal)").to.equal(false);
    }
    // Un même couple option et référence donné deux fois n'est cherché qu'une fois.
    const deux = await controler(paquet, [...x.secrets.args, "--cle-chaine", x.secrets.args[3]], x.secrets.env);
    attendreReussite(deux);
    expect(deux.outputs.secrets_checked).to.deep.equal(rs.outputs.secrets_checked);
  });

  it("EX-7.18, EX-7.19 : avec un manifeste d'instance, instance-registre.json est recopié octet pour octet au deuxième rang de files et le paquet passe EX-7.22", async function () {
    const fInstance = path.join(VECTEURS, "manifestes", "valides", "developpement", "instance-r1.json");
    const d = lireJSON(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-fini.json"));
    d.instance.manifest_sha256 = sha(fs.readFileSync(fInstance));
    const y = inscription("te21-instance", { dossier: Buffer.from(ecrit(d)) });
    const s = await produire(y, ["--instance", fInstance, ...y.secrets.args], y.secrets.env);
    attendreReussite(s);
    const m = lireJSON(path.join(s.outputs.directory, "paquet-client.json"));
    expect(m.files.slice(0, 4).map((f) => [f.path, f.role])).to.deep.equal([
      ["inscription-client.json", "dossier"],
      ["instance-registre.json", "manifeste_instance"],
      ["jeu-approbateurs.json", "jeu_approbateurs"],
      ["gabarit-service-approbation.json", "gabarit_service"],
    ]);
    expect(m.instance.manifest_sha256).to.equal(d.instance.manifest_sha256);
    expect(fs.readFileSync(path.join(s.outputs.directory, "instance-registre.json")).equals(fs.readFileSync(fInstance))).to.equal(true);
    attendreReussite(await controler(s.outputs.directory));
    // Sans --instance, ou avec une autre révision : refus, aucun paquet.
    const z = inscription("te21-instance-refus", { dossier: Buffer.from(ecrit(d)) });
    attendreRefus(await produire(z), "usage", { result: "inutilisable" });
    attendreRefus(await produire(z, ["--instance", path.join(VECTEURS, "manifestes", "valides", "production", "instance-r1.json")]), "chaine_differente");
    aucunPaquet(z);
    // --instance pour un dossier sans manifeste d'instance (EX-7.2) : refus.
    attendreRefus(await produire(x, ["--instance", fInstance]), "usage", { result: "inutilisable" });
  });

  it("EX-7.18 : la production refuse un dossier non fini, incohérent ou hors de son schéma, une capture absente, altérée, liée ou d'une autre étape, et un paquet déjà présent, chacun avec son code, sans laisser de paquet", async function () {
    // Dossier non fini (étape à l'état incluse, result nul).
    const inacheve = inscription("te21-inacheve", { dossier: fs.readFileSync(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-5-inscription.json")) });
    attendreRefus(await produire(inacheve), "dossier_inacheve");
    aucunPaquet(inacheve);
    // Dossier hors de son schéma ; org_id qui n'est pas keccak256 du slug (OP-4).
    const horsSchema = inscription("te21-schema");
    fs.writeFileSync(horsSchema.fDossier, fs.readFileSync(path.join(VECTEURS, "inscription", "invalides", "schema-slug.json")));
    attendreRefus(await produire(horsSchema), "entree_illisible", { result: "inutilisable" });
    const orgFaux = inscription("te21-org-faux", { dossier: fs.readFileSync(path.join(VECTEURS, "inscription", "invalides", "org-id-faux.json")) });
    const so = await produire(orgFaux);
    attendreRefus(so, "jeu_invalide");
    expect(so.error.check).to.equal("OP-4");
    aucunPaquet(orgFaux);

    const cas = [
      ["certificat absent", (y) => fs.rmSync(path.join(y.captures, "certificat-20012.json"))],
      ["reçu altéré", (y) => fs.appendFileSync(path.join(y.captures, `recu-${y.d.steps[4].transaction_hash}.json`), " ")],
      ["index absent", (y) => fs.rmSync(path.join(y.captures, "capture-20020-0-cloture.json"))],
      [
        "index d'une autre transaction",
        (y) => {
          const f = path.join(y.captures, "capture-20004-0-assignation.json");
          const i = lireJSON(f);
          i.transaction_hash = sha("noortrace/essai/te-21/autre-transaction");
          fs.writeFileSync(f, ecrit(i));
        },
      ],
      [
        "capture en lien symbolique",
        (y) => {
          const f = path.join(y.captures, "bloc-20008.json");
          const copie = path.join(y.base, "bloc-20008.json");
          fs.copyFileSync(f, copie);
          fs.rmSync(f);
          fs.symlinkSync(copie, f);
        },
      ],
    ];
    for (const [nom, alterer] of cas) {
      const y = inscription("te21-capture");
      alterer(y);
      const s = await produire(y);
      attendreRefus(s, "capture_incomplete");
      expect(s.error.check, nom).to.match(/^CP-[1-6]$/);
      aucunPaquet(y);
    }
    // Paquet déjà présent : jamais écrasé.
    const avant = fs.readFileSync(path.join(paquet, "paquet-client.json"));
    attendreRefus(await produire(x), "usage", { result: "inutilisable" });
    expect(fs.readFileSync(path.join(paquet, "paquet-client.json")).equals(avant)).to.equal(true);
    // Dossier sans manifeste d'instance hors du réseau de développement (EX-7.2).
    const d = lireJSON(x.fDossier);
    d.instance.evm_chain_id = 1912124;
    d.instance.bft_chain_id = "noortrace-1912124-vecteur";
    const autre = inscription("te21-autre-reseau", { dossier: Buffer.from(ecrit(d)) });
    attendreRefus(await produire(autre), "reseau_non_developpement");
    aucunPaquet(autre);
  });

  it("EX-7.20 : sans les valeurs données par le client, console_origin et administrators valent null et le gabarit ne donne pas une configuration valide ; une valeur hors de la forme de configuration-approbation-v0 est refusée (entree_illisible)", async function () {
    const y = inscription("te21-gabarit-nul");
    const s = await produire(y);
    attendreReussite(s);
    const g = lireJSON(path.join(s.outputs.directory, "gabarit-service-approbation.json"));
    expect(g).to.deep.equal({ version: 0, org: "relecteur-exemple", org_id: y.d.organisation.org_id, console_origin: null, administrators: null });
    expect(valider(g, "paquet-client", "#/$defs/gabarit_service")).to.deep.equal([]);
    expect(valider(null, "configuration-approbation", "#/properties/console_origin")).to.not.deep.equal([]);
    expect(valider(null, "configuration-approbation", "#/properties/administrators")).to.not.deep.equal([]);
    attendreReussite(await controler(s.outputs.directory));
    for (const extra of [
      ["--console-origin", "http://console.relecteur-exemple.example"],
      ["--console-origin", "https://console.relecteur-exemple.example/"],
      ["--administrateur-annuaire", EXEMPLES_713.gabarit.administrators[0], "--administrateur-annuaire", EXEMPLES_713.gabarit.administrators[0]],
    ]) {
      const z = inscription("te21-gabarit-refus");
      attendreRefus(await produire(z, extra), "entree_illisible", { result: "inutilisable" });
      aucunPaquet(z);
    }
  });

  it("EX-7.21 : la valeur d'une clé, d'une graine ou du jeton employés pour l'inscription, glissée dans le dossier ou dans une capture sous chaque forme (hexadécimal des deux casses avec et sans 0x, base64 et base64url avec et sans remplissage, jeton tel quel), interdit la remise (secret_present) : le refus nomme le fichier et l'option, jamais la valeur, et aucun paquet n'est écrit", async function () {
    const base = lireJSON(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-fini.json"));
    const essais = [];
    for (const [nom, v] of Object.entries(x.secrets.valeurs)) for (const [forme, f] of Object.entries(formes(v))) essais.push({ nom, forme, texte: f, valeur: v });
    for (const e of essais) {
      const d = structuredClone(base);
      d.source = `note de l'exploitant : ${e.texte}`;
      const y = inscription("te21-secret", { dossier: Buffer.from(ecrit(d)) });
      // Les références désignent les mêmes valeurs que celles de x (mêmes dérivations), sous les fichiers de y.
      const s = await produire(y, y.secrets.args, { NOORTRACE_ESSAI_JETON_NOEUD: x.secrets.jeton });
      attendreRefus(s, "secret_present");
      expect(s.outputs, `${e.nom} ${e.forme}`).to.deep.equal({ requirement: "EX-7.21", point: null, file: "inscription-client.json" });
      expect(s.error.message).to.include(e.nom);
      for (const f of Object.values(formes(e.valeur))) expect(s.brut.toLowerCase().includes(f.toLowerCase()), `${e.nom} ${e.forme} : valeur consignée`).to.equal(false);
      aucunPaquet(y);
    }
    // Le jeton, tel quel, dans une réponse capturée (index mis à jour) : le fichier nommé est la capture.
    const y = inscription("te21-secret-jeton");
    const nomRecu = `recu-${y.d.steps[3].transaction_hash}.json`;
    const recu = JSON.parse(fs.readFileSync(path.join(y.captures, nomRecu), "utf8"));
    recu.result.note = `Bearer ${x.secrets.jeton}`;
    const octets = Buffer.from(JSON.stringify(recu));
    fs.writeFileSync(path.join(y.captures, nomRecu), octets);
    const fIdx = path.join(y.captures, y.d.steps[3].capture);
    const idx = lireJSON(fIdx);
    idx.files.receipts[0].sha256 = sha(octets);
    fs.writeFileSync(fIdx, ecrit(idx));
    const s = await produire(y, y.secrets.args, { NOORTRACE_ESSAI_JETON_NOEUD: x.secrets.jeton });
    attendreRefus(s, "secret_present");
    expect(s.outputs.file).to.equal(`captures/${nomRecu}`);
    expect(s.error.message).to.include("--jeton");
    expect(s.brut.includes(x.secrets.jeton)).to.equal(false);
    aucunPaquet(y);
    // Sans référence, la même production passe : la recherche ne porte que sur les secrets désignés.
    attendreReussite(await produire(y));
  });

  it("EX-7.21, EX-7.3 : les références de clés de développement (hardhat:, graine:, --exploitant) sont refusées pour un paquet d'instance de production (reseau_non_developpement)", async function () {
    const fInstance = path.join(VECTEURS, "manifestes", "valides", "production", "instance-r1.json");
    const mi = lireJSON(fInstance);
    const d = lireJSON(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-fini.json"));
    const slug = "o-" + "5e".repeat(16);
    const contrat = (n) => mi.contracts.find((c) => c.name === n && c.to_height === null).address;
    d.organisation = { slug, org_id: keccakTexte(slug) };
    for (const s of d.steps) if (s.subject === "relecteur-exemple") s.subject = slug;
    d.instance = { ...d.instance, evm_chain_id: mi.evm_chain_id, bft_chain_id: mi.bft_chain_id, genesis_sha256: mi.genesis.sha256, contracts: { curator_set_registry: contrat("CuratorSetRegistry"), recorder_registry: contrat("RecorderRegistry"), period_registry: contrat("PeriodRegistry"), attestation_registry: contrat("AttestationRegistry") }, manifest_sha256: sha(fs.readFileSync(fInstance)), validator_set_hash: mi.validator_sets[0].valset_hash };
    for (const r of d.recorders) Object.assign(r, { custody_class: "B", chain_key_class: "B" });
    Object.assign(d.result.approver_set, { chain_id: mi.evm_chain_id, registry: contrat("CuratorSetRegistry") });
    expect(valider(d, "inscription-client")).to.deep.equal([]);
    const y = inscription("te21-production", { dossier: Buffer.from(ecrit(d)) });
    const cleFichier = ["--cle-chaine", y.secrets.args[3]];
    for (const refs of [["--exploitant", "hardhat:0"], ["--tresorerie", "hardhat:0"], ["--graine", y.secrets.args[5]]]) {
      attendreRefus(await produire(y, ["--instance", fInstance, ...refs]), "reseau_non_developpement");
      aucunPaquet(y);
    }
    const s = await produire(y, ["--instance", fInstance, ...cleFichier, "--jeton", "env:NOORTRACE_ESSAI_JETON_NOEUD"], y.secrets.env);
    attendreReussite(s);
    expect(s.outputs.secrets_checked).to.deep.equal({ count: 2, references: [{ option: "--cle-chaine", reference: y.secrets.args[3] }, { option: "--jeton", reference: "env:NOORTRACE_ESSAI_JETON_NOEUD" }] });
    expect(path.basename(s.outputs.directory)).to.equal(`paquet-client-${slug}`);
    attendreReussite(await controler(s.outputs.directory));
  });

  it("EX-7.22 : chaque copie altérée du paquet est refusée au point qui la vise, avec son code (fichier en plus, fichier en moins, empreinte ou longueur fausse, ordre, lien symbolique, forme, org_id, instance, jeu, gabarit, capture incomplète, secret glissé)", async function () {
    const m0 = lireJSON(path.join(paquet, "paquet-client.json"));
    const copie = () => {
      const d = path.join(temporaire("te21-copie"), path.basename(paquet));
      fs.cpSync(paquet, d, { recursive: true });
      return d;
    };
    /** Réécrit le manifeste : f(m) le modifie ; les entrées des chemins de `recalculer` reprennent SHA-256 et longueur. */
    const majManifeste = (rep, f = () => {}, recalculer = []) => {
      const fm = path.join(rep, "paquet-client.json");
      const m = lireJSON(fm);
      f(m);
      for (const e of m.files) {
        if (!recalculer.includes(e.path)) continue;
        const b = fs.readFileSync(path.join(rep, e.path));
        Object.assign(e, { sha256: sha(b), length: b.length });
      }
      fs.writeFileSync(fm, ecrit(m));
    };
    const remplacer = (rep, p, contenu) => {
      fs.writeFileSync(path.join(rep, p), contenu);
      majManifeste(rep, () => {}, [p]);
    };
    const entree = (rep, p) => {
      const b = fs.readFileSync(path.join(rep, p));
      return { path: p, sha256: sha(b), length: b.length };
    };
    const recu = `captures/recu-${x.d.steps[4].transaction_hash}.json`;
    const cleChaine = x.secrets.valeurs["--cle-chaine"];
    const cas = [
      // 1. Manifeste conforme à son schéma.
      [1, "paquet_manifeste", "manifeste absent", (r) => fs.rmSync(path.join(r, "paquet-client.json"))],
      [1, "paquet_manifeste", "manifeste en lien symbolique", (r) => {
        const ailleurs = path.join(path.dirname(r), "paquet-client.json");
        fs.renameSync(path.join(r, "paquet-client.json"), ailleurs);
        fs.symlinkSync(ailleurs, path.join(r, "paquet-client.json"));
      }],
      [1, "paquet_manifeste", "membre en plus dans le manifeste", (r) => majManifeste(r, (m) => (m.signature = "0x00"))],
      [1, "paquet_manifeste", "rôle et chemin incohérents", (r) => majManifeste(r, (m) => (m.files[1].role = "gabarit_service"))],
      // 2. Fichiers listés une fois, fichiers ordinaires, SHA-256, longueur, ordre.
      [2, "paquet_fichiers", "fichier en plus à la racine", (r) => fs.writeFileSync(path.join(r, "cles-essai.json"), ecrit({ version: 0 }))],
      [2, "paquet_fichiers", "envoi en plus dans captures/", (r) => fs.copyFileSync(path.join(x.captures, `envoi-${x.d.steps[0].transaction_hash}.json`), path.join(r, "captures", `envoi-${x.d.steps[0].transaction_hash}.json`))],
      [2, "paquet_fichiers", "secret glissé dans un fichier en plus", (r) => fs.writeFileSync(path.join(r, "captures", "cle-chaine-rec-exemple-01.cle"), cleChaine + "\n")],
      [2, "paquet_fichiers", "fichier en moins", (r) => fs.rmSync(path.join(r, recu))],
      [2, "paquet_fichiers", "empreinte fausse (même longueur)", (r) => {
        const f = path.join(r, "captures", "certificat-20012.json");
        const b = fs.readFileSync(f);
        b[b.length - 3] = b[b.length - 3] === 0x30 ? 0x31 : 0x30;
        fs.writeFileSync(f, b);
      }],
      [2, "paquet_fichiers", "longueur fausse", (r) => majManifeste(r, (m) => (m.files[0].length += 1))],
      [2, "paquet_fichiers", "ordre de files", (r) => majManifeste(r, (m) => ([m.files[3], m.files[4]] = [m.files[4], m.files[3]]))],
      [2, "paquet_fichiers", "entrée en double", (r) => majManifeste(r, (m) => m.files.push({ ...m.files.at(-1) }))],
      [2, "paquet_fichiers", "capture en lien symbolique", (r) => {
        const f = path.join(r, "captures", "bloc-20000.json");
        const ailleurs = path.join(path.dirname(r), "bloc-20000.json");
        fs.renameSync(f, ailleurs);
        fs.symlinkSync(ailleurs, f);
      }],
      [2, "paquet_fichiers", "répertoire en plus", (r) => fs.mkdirSync(path.join(r, "captures", "sous-repertoire"))],
      // 3. Forme de chaque rôle ; écriture d'EX-7.18 ; dossier fini.
      [3, "paquet_forme", "secret glissé comme membre du gabarit", (r) => remplacer(r, "gabarit-service-approbation.json", ecrit({ ...EXEMPLES_713.gabarit, private_key: cleChaine }))],
      [3, "paquet_forme", "jeu d'approbateurs écrit sans la mise en forme d'EX-7.18", (r) => remplacer(r, "jeu-approbateurs.json", JSON.stringify(x.d.result.approver_set))],
      [3, "paquet_forme", "manifeste écrit sans la mise en forme d'EX-7.18", (r) => fs.writeFileSync(path.join(r, "paquet-client.json"), JSON.stringify(m0))],
      [3, "paquet_forme", "dossier non fini", (r) => remplacer(r, "inscription-client.json", fs.readFileSync(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-5-inscription.json")))],
      [3, "paquet_forme", "certificat qui n'est pas une réponse JSON-RPC", (r) => remplacer(r, "captures/certificat-20016.json", ecrit({ height: "0x4e30" }))],
      [3, "paquet_forme", "index hors de son schéma", (r) => {
        const p = `captures/${x.d.steps[0].capture}`;
        remplacer(r, p, ecrit({ ...lireJSON(path.join(r, p)), node: { rpc: "http://127.0.0.1:8645" } }));
      }],
      // 4. org, org_id, instance, manifeste d'instance, nom du répertoire.
      [4, "paquet_organisation", "org_id d'une autre organisation", (r) => majManifeste(r, (m) => (m.org_id = keccakTexte("autre-organisation")))],
      [4, "paquet_organisation", "instance différente", (r) => majManifeste(r, (m) => (m.instance.evm_chain_id = 31337))],
      [4, "paquet_organisation", "manifeste d'instance alors que manifest_sha256 est nul", (r) => {
        fs.copyFileSync(path.join(VECTEURS, "manifestes", "valides", "developpement", "instance-r1.json"), path.join(r, "instance-registre.json"));
        majManifeste(r, (m) => m.files.splice(1, 0, { ...entree(r, "instance-registre.json"), role: "manifeste_instance" }));
      }],
      [4, "paquet_organisation", "répertoire renommé", (r) => {
        const autre = path.join(path.dirname(r), "paquet-client-autre-organisation");
        fs.renameSync(r, autre);
        return autre;
      }],
      // 5. Jeu d'approbateurs et gabarit.
      [5, "paquet_jeu", "jeu d'approbateurs d'un autre CuratorSet", (r) => remplacer(r, "jeu-approbateurs.json", ecrit({ ...x.d.result.approver_set, set: "0x" + "ab".repeat(20) }))],
      [5, "paquet_jeu", "gabarit d'une autre organisation", (r) => remplacer(r, "gabarit-service-approbation.json", ecrit({ ...EXEMPLES_713.gabarit, org: "autre-organisation", org_id: keccakTexte("autre-organisation") }))],
      // 6. Captures complètes, nommées, à leur SHA-256.
      [6, "paquet_captures", "capture incomplète : index d'une étape retiré avec ses fichiers", (r) => {
        const p = `captures/${x.d.steps.at(-1).capture}`;
        const idx = lireJSON(path.join(r, p));
        const retires = [p, ...[idx.files.block, ...idx.files.receipts, idx.files.certificate].map((f) => `captures/${f.name}`)];
        for (const q of retires) fs.rmSync(path.join(r, q));
        majManifeste(r, (m) => (m.files = m.files.filter((f) => !retires.includes(f.path))));
      }],
      [6, "paquet_captures", "reçu dont le SHA-256 n'est plus celui de l'index", (r) => remplacer(r, recu, reponse({ transactionHash: x.d.steps[4].transaction_hash, status: "0x0" }))],
      [6, "paquet_captures", "fichier de captures/ nommé par aucun index", (r) => {
        fs.copyFileSync(path.join(x.captures, "bloc-30000.json"), path.join(r, "captures", "bloc-30000.json"));
        majManifeste(r, (m) => {
          m.files.push({ ...entree(r, "captures/bloc-30000.json"), role: "capture_bloc" });
          m.files = [...m.files.slice(0, 3), ...m.files.slice(3).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))];
        });
      }],
      [6, "paquet_captures", "index qu'aucune étape ne nomme (capture d'une autre organisation)", (r) => {
        const idx = lireJSON(path.join(x.captures, "capture-30000-0-inscription.json"));
        const noms = ["capture-30000-0-inscription.json", idx.files.block.name, ...idx.files.receipts.map((f) => f.name), idx.files.certificate.name];
        for (const n of noms) fs.copyFileSync(path.join(x.captures, n), path.join(r, "captures", n));
        const role = (n) => ({ capture: "capture_index", bloc: "capture_bloc", recu: "capture_recu", certificat: "capture_certificat" })[n.split("-")[0]];
        majManifeste(r, (m) => {
          for (const n of noms) m.files.push({ ...entree(r, `captures/${n}`), role: role(n) });
          m.files = [...m.files.slice(0, 3), ...m.files.slice(3).sort((a, b) => Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)))];
        });
      }],
    ];
    for (const [point, code, nom, alterer] of cas) {
      let r = copie();
      r = alterer(r) ?? r;
      const s = await controler(r);
      expect([s.result, s.error?.code, s.outputs.point], `${nom} : ${JSON.stringify(s.error)}`).to.deep.equal(["refuse", code, point]);
      expect(s.outputs.requirement).to.equal("EX-7.22");
      expect(s.error.message).to.match(new RegExp(`^EX-7\\.22, point ${point} : `));
    }
    // Chaque point a au moins un refus.
    expect(new Set(cas.map(([p]) => p))).to.deep.equal(new Set([1, 2, 3, 4, 5, 6]));

    // Secret glissé dans un membre libre du dossier, manifeste mis à jour : la forme ne le voit pas ;
    // le contrôle d'EX-7.21, avec les références des secrets employés, le refuse.
    const r = copie();
    const d = lireJSON(path.join(r, "inscription-client.json"));
    d.prepared_by = `exploitant ${formes(cleChaine)["base64 sans remplissage"]}`;
    remplacer(r, "inscription-client.json", ecrit(d));
    attendreReussite(await controler(r));
    const s = await controler(r, x.secrets.args, x.secrets.env);
    attendreRefus(s, "secret_present");
    expect(s.outputs).to.deep.equal({ requirement: "EX-7.21", point: null, file: "inscription-client.json" });
    expect(s.brut.includes(formes(cleChaine)["base64 sans remplissage"])).to.equal(false);

    // Le paquet d'origine n'a pas changé et passe toujours.
    attendreReussite(await controler(paquet));
    // Usage : opération inconnue, répertoire absent.
    attendreRefus(await outil(["paquet-client", "verifier", "--paquet", paquet]), "usage", { result: "inutilisable" });
    attendreRefus(await controler(path.join(temporaire("te21-absent"), "paquet-client-relecteur-exemple")), "entree_illisible", { result: "inutilisable" });
  });
});

// ---------------------------------------------------------------------------
// Schéma de sortie révisé (CT-4 §13, révision 0.7)
// ---------------------------------------------------------------------------

describe("CT-4 §13, révision 0.7 : operations-registre-v0#/$defs/sortie admet la commande paquet-client et ses codes, sans complément", function () {
  it("command admet paquet-client ; error.code admet les huit codes d'EX-7.30 ; inscription-client-v0 admet funding nul", function () {
    const sortie = SCHEMAS[id("operations-registre")].$defs.sortie.properties;
    expect(sortie.command.enum).to.include("paquet-client");
    const codes = sortie.error.oneOf.find((x) => x.properties?.code).properties.code.enum;
    for (const c of CODES_PAQUET) expect(codes, c).to.include(c);
    const exemple = { version: 0, command: "paquet-client", result: "refuse", exit_code: 1, checks: [], error: { code: "paquet_captures", check: null, message: "EX-7.22, point 6 : exemple" }, outputs: { requirement: "EX-7.22", point: 6, file: "captures/bloc-1.json" } };
    expect(validerSortie(exemple)).to.deep.equal([]);
    const d = lireJSON(path.join(VECTEURS, "inscription", "valides", "relecteur-exemple-fini.json"));
    d.result.recorders[0].funding = null;
    expect(valider(d, "inscription-client")).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
// Reprise d'EX-7.29 et funding nul, sur le réseau Hardhat en mémoire
// ---------------------------------------------------------------------------

/** Pont JSON-RPC vers le fournisseur Hardhat ; `crochets.intercepter(method, params)` peut rendre une promesse de résultat. */
function pontJsonRpc(provider, crochets, synthese) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const r = JSON.parse(corps);
    let reponse;
    try {
      const f = crochets.intercepter?.(r.method, r.params);
      let result;
      if (f !== undefined) result = await f;
      else {
        const v = await synthese(r.method, r.params);
        result = v !== undefined ? v : await provider.request({ method: r.method, params: r.params });
      }
      reponse = { jsonrpc: "2.0", id: r.id, result };
    } catch (err) {
      reponse = { jsonrpc: "2.0", id: r.id, error: { code: err.code ?? -32000, message: err.message } };
    }
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(reponse));
  });
  return new Promise((ok) => serveur.listen(0, "127.0.0.1", () => ok({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

/** Synthèse de capture (EX-A.6) : en-têtes au BFTBlockHash, reçus qui le portent, certificats signés par le jeu d'essai de CT-4 A.2. */
function syntheseCertificats(provider, { jeu, bftChainId }) {
  const rpc = (method, params) => provider.request({ method, params });
  const cache = new Map();
  const brute = (t) => {
    const v = Number(BigInt(t.yParity ?? t.v));
    const tx = Transaction.from({ type: Number(BigInt(t.type)), chainId: BigInt(t.chainId), nonce: Number(BigInt(t.nonce)), maxPriorityFeePerGas: BigInt(t.maxPriorityFeePerGas), maxFeePerGas: BigInt(t.maxFeePerGas), gasLimit: BigInt(t.gas), to: t.to ?? null, value: BigInt(t.value), data: t.input, accessList: t.accessList ?? [], signature: { r: t.r, s: t.s, v: 27 + (v >= 27 ? v - 27 : v) } });
    return tx.serialized;
  };
  const bloc = async (q) => {
    const reel = await rpc("eth_getBlockByNumber", [q, true]);
    if (!reel) return null;
    const h = Number(BigInt(reel.number));
    if (cache.has(h)) return cache.get(h);
    const recus = [];
    for (const t of reel.transactions) recus.push(await rpc("eth_getTransactionReceipt", [t.hash]));
    const r = certifierBloc({ h, txsRaw: reel.transactions.map(brute), recus, bftChainId, validateurs: jeu, entete: reel });
    cache.set(h, r);
    return r;
  };
  return async (method, params) => {
    if (method === "eth_getBlockByNumber") return (await bloc(params[0]))?.entete ?? null;
    if (method === "eth_getTransactionReceipt") {
      const r = await rpc(method, params);
      return r ? { ...r, blockHash: (await bloc(r.blockNumber)).entete.hash } : null;
    }
    if (method === "noor_getCommitCertificate") {
      const b = await bloc(params[0]);
      if (!b) throw Object.assign(new Error("unknown block"), { code: -32000 });
      return b.certificat;
    }
    if (method === "noor_txindexStatus") return { last_indexed_height: Number(BigInt(await rpc("eth_blockNumber", []))) };
    return undefined;
  };
}

/** Manifeste d'essai de l'instance Hardhat (EX-A.6) : quatre comptes de rôle au déployeur, jeu de validateurs d'essai. */
function manifesteHardhat(E, deploiement, jeu) {
  const deployeur = deploiement.deployeur.toLowerCase();
  const genese = { chainId: 31337, alloc: [{ address: deployeur, balanceWei: "10000000000000000000000" }], rules: { chainId: "noortrace-31337-essai", ...C.REGLES_SANS_EMISSION } };
  fs.writeFileSync(path.join(E, "genese.json"), JSON.stringify(genese, null, 2) + "\n");
  const csr = deploiement.contrats.CuratorSetRegistry.adresse.toLowerCase();
  const validators = jeu.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex }));
  const manifeste = {
    version: 0, revision: 1, previous_sha256: null, published_at: "2026-10-25T00:00:00.000Z", nature: "developpement",
    bft_chain_id: "noortrace-31337-essai", evm_chain_id: 31337,
    evm_chain_id_registration: { status: "attribue_a_un_tiers", checked_at: "2026-10-25T00:00:00.000Z", source: "réseau Hardhat en mémoire des tests (CT-4 EX-A.6)" },
    genesis: { file: "genese.json", sha256: J.sha256(fs.readFileSync(path.join(E, "genese.json"))), rules_line: C.ligneRegles(genese), alloc_total_wei: "10000000000000000000000" },
    noorcore: { repository: "https://github.com/noorfinances-eng/noorchain-core", commit: "618fcef8805ef5b4cb9291a3dd97be710e489297", go_version: "1.26.9", patches: [], artifacts: [{ kind: "binaire", name: "sans objet : réseau Hardhat", sha256: C.HACHAGE_NUL, build: "sans objet" }] },
    validator_sets: [{ from_height: 1, to_height: null, validators, source: "jeu d'essai de CT-4 A.2, qui signe les certificats synthétiques du pont des essais (EX-A.6)", valset_hash: C.hachageJeuValidateurs(validators), operators: validators.map((v) => ({ validator: v.id, operator: "essai", site: "essai", retention_heights: null })) }],
    fees: { ...C.FRAIS_DEFAUT },
    contracts: ["AttestationRegistry", "CuratorSetRegistry", "PeriodRegistry", "RecorderRegistry"].map((n, i) => ({ name: n, address: deploiement.contrats[n].adresse.toLowerCase(), deployer: deployeur, nonce: i, constructor_args: n === "AttestationRegistry" ? [] : n === "CuratorSetRegistry" ? [deployeur] : [csr], transaction_hash: deploiement.contrats[n].tx, block_number: deploiement.contrats[n].bloc, block_hash: null, evidence: null, to_height: null })),
    compilation: { solc: "0.8.20", via_ir: true, optimizer_runs: 200, source_commit: null },
    accounts: ["tresorerie", "deployeur", "administrateur_registre", "relayeur"].map((role) => ({ role, address: deployeur, from_height: 0, to_height: null })),
    source: "manifeste d'essai du réseau Hardhat en mémoire (CT-4 EX-A.6)",
  };
  const fichier = path.join(E, "instance.json");
  fs.writeFileSync(fichier, JSON.stringify(manifeste, null, 2) + "\n");
  expect(J.validerSchema(manifeste, SCHEMAS[id("instance-registre")], { registre: SCHEMAS })).to.deep.equal([]);
  return fichier;
}

describe("CT-4 EX-7.29 (révision 0.7) : reprise d'une étape echec déjà accomplie et funding nul, par l'outil de référence sur le réseau Hardhat en mémoire", function () {
  this.timeout(600000);
  let conn;
  let srv;
  let url;
  let E;
  let instance;
  const crochets = {};
  const jeu = lireJSON(path.join(VECTEURS, "constantes.json")).test_validators.validators;

  /** Une commande de l'outil, en processus ; sortie validée contre le schéma révisé. */
  const R = async (args) => {
    let out = "";
    const { code } = await executer([...args, "--instance", instance, "--rpc", url], { stdout: { write: (x) => (out += x) }, stderr: { write: () => {} } });
    const s = JSON.parse(out);
    expect(validerSortie(s), `${args[0]} : ${JSON.stringify(validerSortie(s).slice(0, 2))}`).to.deep.equal([]);
    expect(s.exit_code).to.equal(code);
    return s;
  };
  const lire = (f) => lireJSON(f);

  /** Client préparé avec les clés d'essai de l'outil, pas 2 à 5 faits et capturés ; rend ses chemins. */
  const client = async (org, { avantPas2 = null } = {}) => {
    const rep = path.join(E, org);
    fs.mkdirSync(rep);
    attendreReussite(await R(["cles-essai", "--sortie", path.join(rep, "cles")]));
    const dossier = path.join(rep, "dossier.json");
    const captures = path.join(rep, "captures");
    attendreReussite(await R(["inscrire-client", "--preparer", "--org", org, "--journal", "journal-principal", "--seuil", "2", "--cles-essai", path.join(rep, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--sortie", dossier]));
    if (avantPas2) await avantPas2(lire(dossier));
    attendreReussite(await R(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", captures]));
    return { rep, dossier, captures, cleChaine: `fichier:${path.join(rep, "cles", "cle-chaine-rec-essai-01.cle")}`, graine: `graine:${path.join(rep, "cles", "rec-essai-01.graine")}`, cles: path.join(rep, "cles") };
  };
  /** Demande d'inscription de la clé du client, signée par deux approbateurs d'essai. */
  const demandeSignee = async (x) => {
    const f = path.join(x.rep, "demande-inscription.json");
    attendreReussite(await R(["condense", "inscription", "--dossier", x.dossier, "--key-id", "rec-essai-01", "--sortie", f]));
    for (const i of [1, 2]) attendreReussite(await R(["signer", "--demande", f, "--cle", `fichier:${path.join(x.cles, `approbateur-${i}.cle`)}`]));
    return f;
  };

  before(async function () {
    conn = await network.create({ network: "hardhat", override: { throwOnTransactionFailures: false } });
    await conn.provider.request({ method: "hardhat_setNextBlockBaseFeePerGas", params: ["0x1"] });
    const { deployment } = await deployNoortrace(conn.ethers, { networkName: "essai-ex-7-29" });
    ({ serveur: srv, url } = await pontJsonRpc(conn.provider, crochets, syntheseCertificats(conn.provider, { jeu, bftChainId: "noortrace-31337-essai" })));
    E = temporaire("ex-7-29");
    instance = manifesteHardhat(E, deployment, jeu);
  });

  after(function () {
    srv?.close();
  });

  afterEach(function () {
    delete crochets.intercepter;
  });

  it("étape inscription echec (une autre transaction a inscrit la clé avant la sienne) : deja_fait à la relance sans rien envoyer, l'étape reste echec ; capturer --transaction --dossier de la transaction qui l'a accomplie la passe à capturee après OP-11, CP-1 à CP-6 et OP-12 ; celle de l'étape, à status 0x0, est refusée", async function () {
    const x = await client("essai-reprise");
    const fDemande = await demandeSignee(x);
    const demande = lire(fDemande);
    const f = demande.fields;
    // Juste avant l'envoi de l'outil, un autre expéditeur relaie la même demande signée : sa transaction est incluse d'abord.
    const signataires = await conn.ethers.getSigners();
    let concurrente = null;
    crochets.intercepter = (method, params) => {
      if (method !== "eth_sendRawTransaction" || concurrente) return undefined;
      return (async () => {
        const data = C.donneesAppel("registerRecorder", { org_id: f.org_id, journal_id: f.journal_id, chain_key: f.chain_key, ed25519_public_key: f.ed25519_public_key, signatures: demande.signatures.map((x) => ({ v: x.v, r: x.r, s: x.s })) });
        const tx = await signataires[9].sendTransaction({ to: demande.contract, data, gasLimit: 3000000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 });
        concurrente = String((await tx.wait()).hash).toLowerCase();
        return conn.provider.request({ method, params });
      })();
    };
    const ic = await R(["inscrire-cle", "--demande", fDemande, "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures, "--delai", "5"]);
    delete crochets.intercepter;
    expect(ic.result, JSON.stringify(ic.error)).to.equal("echoue");
    expect(ic.error).to.deep.include({ code: "transaction_annulee", check: "OP-11" });
    let e = lire(x.dossier).steps.find((s) => s.step === "inscription");
    expect(e.state).to.equal("echec");
    const echouee = e.transaction_hash;
    expect(concurrente).to.be.a("string").and.not.equal(echouee);
    // Relance : deja_fait, rien n'est envoyé, l'étape reste echec (la commande ne devine pas la transaction).
    const nonce = await conn.provider.request({ method: "eth_getTransactionCount", params: [f.chain_key, "latest"] });
    const re = await R(["inscrire-cle", "--demande", fDemande, "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures, "--delai", "5"]);
    expect(re.result).to.equal("deja_fait");
    expect(await conn.provider.request({ method: "eth_getTransactionCount", params: [f.chain_key, "latest"] })).to.equal(nonce);
    expect(lire(x.dossier).steps.find((s) => s.step === "inscription").state).to.equal("echec");
    // La transaction de l'étape elle-même (status 0x0) : refus OP-11, dossier inchangé.
    const refus = await R(["capturer", "--transaction", echouee, "--role", "inscription", "--dossier", x.dossier, "--captures", x.captures]);
    expect(refus.result).to.equal("echoue");
    expect(refus.error).to.deep.include({ code: "transaction_annulee", check: "OP-11" });
    expect(lire(x.dossier).steps.find((s) => s.step === "inscription").state).to.equal("echec");
    // EX-7.29 : la transaction établie par l'exploitant passe l'étape à capturee.
    const cap = await R(["capturer", "--transaction", concurrente, "--role", "inscription", "--dossier", x.dossier, "--captures", x.captures]);
    attendreReussite(cap);
    expect(cap.checks.map((c) => `${c.id}:${c.status}`)).to.deep.equal(["OP-2:reussi", "OP-1:reussi", "OP-11:reussi", "CP-1:reussi", "CP-2:reussi", "CP-3:reussi", "CP-4:reussi", "CP-5:reussi", "CP-6:reussi", "OP-12:reussi"]);
    expect(cap.outputs.dossier).to.deep.equal({ step: "inscription", subject: "rec-essai-01", state: "capturee" });
    e = lire(x.dossier).steps.find((s) => s.step === "inscription");
    expect(e).to.deep.include({ state: "capturee", transaction_hash: concurrente, block_number: cap.outputs.block_number, block_hash: cap.outputs.block_hash, capture: cap.outputs.capture, error: null });
    expect(valider(lire(x.dossier), "inscription-client")).to.deep.equal([]);
    const index = lire(path.join(x.captures, cap.outputs.capture));
    expect(index).to.deep.include({ role: "inscription", transaction_hash: concurrente });
    // Une seconde capture de la même transaction ne change plus rien (l'étape la porte désormais).
    attendreReussite(await R(["capturer", "--transaction", concurrente, "--role", "inscription", "--dossier", x.dossier, "--captures", x.captures]));
    expect(lire(x.dossier).steps.find((s) => s.step === "inscription").transaction_hash).to.equal(concurrente);
  });

  it("une transaction qui n'accomplit l'étape echec qu'avec d'autres valeurs (inscription d'une autre organisation) ne la change pas", async function () {
    const x = await client("essai-autres-valeurs");
    const y = await client("essai-autre-organisation");
    // L'inscription de y, faite par l'outil ; puis celle de x échoue, et l'on tente de la reprendre par la transaction de y.
    attendreReussite(await R(["inscrire-cle", "--demande", await demandeSignee(y), "--cle-chaine", y.cleChaine, "--dossier", y.dossier, "--captures", y.captures]));
    const hY = lire(y.dossier).steps.find((s) => s.step === "inscription").transaction_hash;
    const fx = await demandeSignee(x);
    const dx = lire(fx);
    const signataires = await conn.ethers.getSigners();
    let fait = false;
    crochets.intercepter = (method, params) => {
      if (method !== "eth_sendRawTransaction" || fait) return undefined;
      fait = true;
      return (async () => {
        const data = C.donneesAppel("registerRecorder", { org_id: dx.fields.org_id, journal_id: dx.fields.journal_id, chain_key: dx.fields.chain_key, ed25519_public_key: dx.fields.ed25519_public_key, signatures: dx.signatures.map((s) => ({ v: s.v, r: s.r, s: s.s })) });
        await (await signataires[9].sendTransaction({ to: dx.contract, data, gasLimit: 3000000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 })).wait();
        return conn.provider.request({ method, params });
      })();
    };
    expect((await R(["inscrire-cle", "--demande", fx, "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures, "--delai", "5"])).result).to.equal("echoue");
    delete crochets.intercepter;
    const avant = fs.readFileSync(x.dossier);
    const cap = await R(["capturer", "--transaction", hY, "--role", "inscription", "--dossier", x.dossier, "--captures", x.captures]);
    attendreReussite(cap);
    expect(cap.outputs.dossier).to.equal(null);
    expect(cap.checks.some((c) => c.id === "OP-12")).to.equal(false);
    expect(fs.readFileSync(x.dossier).equals(avant)).to.equal(true);
  });

  it("approvisionnement d'une clé déjà pourvue d'au moins P_k : étape faite sans transaction ; à la fin de l'inscription, result.recorders[].funding vaut null, le dossier est conforme et le paquet se produit", async function () {
    const signataires = await conn.ethers.getSigners();
    const x = await client("essai-pourvue", {
      avantPas2: async (d) => {
        await (await signataires[8].sendTransaction({ to: d.recorders[0].chain_key, value: BigInt(d.funding.amount_wei), gasLimit: 21000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 })).wait();
      },
    });
    let d = lire(x.dossier);
    expect(d.steps.find((s) => s.step === "approvisionnement")).to.deep.include({ state: "faite", transaction_hash: null, capture: null });
    attendreReussite(await R(["inscrire-cle", "--demande", await demandeSignee(x), "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures]));
    attendreReussite(await R(["manifeste-essai", "--dossier", x.dossier, "--key-id", "rec-essai-01", "--graine", x.graine, "--sortie", path.join(x.rep, "periode-1")]));
    const man = path.join(x.rep, "periode-1", "manifeste.json");
    attendreReussite(await R(["ancrer", "--manifeste", man, "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures]));
    const fc = path.join(x.rep, "demande-cloture.json");
    attendreReussite(await R(["condense", "cloture", "--manifeste", man, "--captures", x.captures, "--sortie", fc]));
    for (const i of [1, 2]) attendreReussite(await R(["signer", "--demande", fc, "--cle", `fichier:${path.join(x.cles, `approbateur-${i}.cle`)}`]));
    attendreReussite(await R(["clore", "--demande", fc, "--manifeste", man, "--cle-chaine", x.cleChaine, "--dossier", x.dossier, "--captures", x.captures]));
    d = lire(x.dossier);
    expect(d.result, "result rempli").to.not.equal(null);
    expect(d.result.recorders).to.have.length(1);
    expect(d.result.recorders[0].funding).to.equal(null);
    expect(d.result.recorders[0].registration.transaction_hash).to.equal(d.steps.find((s) => s.step === "inscription").transaction_hash);
    expect(valider(d, "inscription-client")).to.deep.equal([]);
    // Le dossier fini se met en paquet ; l'étape sans transaction n'y apporte aucune capture.
    const sortie = path.join(x.rep, "paquets");
    const p = await R(["paquet-client", "produire", "--dossier", x.dossier, "--captures", x.captures, "--sortie", sortie]);
    attendreReussite(p);
    expect(fs.readdirSync(path.join(p.outputs.directory, "captures")).some((n) => n.endsWith("-approvisionnement.json"))).to.equal(false);
    attendreReussite(await R(["paquet-client", "controler", "--paquet", p.outputs.directory]));
  });
});
