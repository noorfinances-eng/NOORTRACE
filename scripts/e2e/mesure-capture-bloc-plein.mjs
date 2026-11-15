#!/usr/bin/env node
// TM-31 de CT-9 : octets de la capture d'une transaction d'un bloc plein, le
// coefficient `b_cap` de CT-8 §9.2 (CT-8 EX-9.1), que CT-4 §9.2 laisse « non
// mesuré » pour un bloc de 64 transactions.
//
//   node scripts/e2e/mesure-capture-bloc-plein.mjs [--sortie <répertoire>]
//        [--rapport <fichier>] [--repetitions 3] [--garder-reseau]
//        [--clotures <k>[,<k>…]]
//
// Extension TM-44 (étape 8 ; CT-8 §9.2, réserve que TM-31 ne lève pas) :
// avec `--clotures`, chaque bloc plein MÊLE des clôtures de journaux
// distincts (`PeriodRegistry.submitPeriod`, seuil de deux approbateurs) et
// des ancres ; une composition par valeur de la liste (`--clotures 1,4` :
// une clôture et 63 ancres, puis quatre clôtures et 60 ancres), `--repetitions`
// blocs par composition. Chaque clôture consomme un journal : avant chaque
// bloc, autant d'organisations neuves que de clôtures sont inscrites au
// registre par l'outil de référence (inscrire-client, condense inscription,
// signer × 2, inscrire-cle, ancrer, condense cloture, signer × 2, comme
// scripts/e2e/parcours-registre.mjs), chacune avec ses clés de test PUBLIÉES
// (secret SHA-256(UTF-8("noortrace/tm-44/v0/<organisation>/<nom>"))), et la
// transaction de clôture est construite depuis la demande signée
// (`fields.period_meta`, `signatures`) et envoyée par la clé de chaîne du
// journal, dans le même lot que les ancres. Une clôture et une ancre de
// chaque bloc sont capturées (`capturer --role cloture`, `--role ancre`) ;
// la ligne `b_cap_bloc_plein_clotures` porte les octets de chaque capture
// (index exclu, relevé dans `notes`), `max` ; le rapport est validé par
// `scripts/tests/mesures.mjs` avant d'être écrit (CT-9 EX-11.11). Un bloc
// dont les reçus se dispersent est repris avec des clôtures neuves (les
// journaux dont la clôture a été incluse ailleurs sont abandonnés).
//
// Méthode (entrée TM-31 du catalogue de CT-9 : 64 expéditeurs, une capture par
// bloc plein, trois répétitions, ligne `b_cap_bloc_plein`, `max`) :
//   1. réseau de développement démarré s'il ne tourne pas (dev-net.sh), arrêté
//      à la fin s'il a été démarré ici ;
//   2. 64 expéditeurs de test PUBLIÉS : la clé secp256k1 de l'expéditeur i est
//      SHA-256(UTF-8("noortrace/tm-31/v0/expediteur/<i>")), i de 1 à 64 ;
//      approvisionnés au besoin par les comptes Hardhat 0 à 3 (mnémonique
//      publique), chaque virement soumis aux quatre validateurs ;
//   3. par répétition : 64 transactions `AttestationRegistry.anchor`, une par
//      expéditeur (au plus une transaction par expéditeur et par bloc, au plus
//      64 par bloc, inclusion au tour du validateur qui l'a reçue : CT-4 §4.4,
//      8.6), signées par leur expéditeur comme émetteur, docType de période,
//      empreinte d'essai ; toutes soumises au validateur v1 juste après un bloc
//      qu'il a proposé, pour qu'elles entrent ensemble dans son bloc suivant ;
//      une répétition dont les 64 reçus ne sont pas dans un même bloc est
//      reprise (au plus cinq essais) et consignée ;
//   4. capture de l'une d'elles (la dernière du bloc) par l'outil de référence,
//      `capturer --transaction … --role ancre` (CT-4 §9.4 : en-tête, reçu de
//      chaque transaction du bloc, certificat de commit, CP-1 à CP-6) ;
//   5. octets : la capture d'une transaction est l'ensemble des fichiers que
//      son index désigne (bloc-<h>.json, les 64 recu-<hachage>.json,
//      certificat-<h>.json), réponses JSON-RPC telles que reçues (CP-6) ; c'est
//      la ligne du rapport. La décomposition (en-tête, certificat, reçus, index,
//      et la somme en-tête + certificat + un seul reçu, forme de la mesure de
//      CT-8 §9.2 sur des blocs d'une transaction) va dans `notes`.
//
// Le rapport suit `plan-de-tests-v0#/$defs/rapport_mesure` (CT-9 §11.3) et est
// validé contre lui avant d'être écrit ; il n'est pas publié par l'outil
// (EX-11.11 : l'ingénieur le place sous spec/vecteurs/ct-9/mesures/). Une
// mesure hors du système de référence de CT-9 §11.1 ne compte pour aucune
// cible (TM-31 n'en a pas) : `counts_for_targets` faux, `excluded_reason`
// `hors_systeme_de_reference`.
//
// Codes : 0 rapport écrit ; 1 échec de la mesure ; 2 préalable absent.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, Interface, Signature, SigningKey, Wallet, computeAddress, solidityPackedKeccak256 } from "ethers";
import * as J from "../lib/journal.mjs";
import * as C from "../lib/conventions-registre.mjs";
import { DOC_TYPE_PERIODE, deploymentsDir } from "../lib/noortrace.mjs";
import { executer } from "../registre/noortrace-registre.mjs";
import { RACINE, RPC_DEV, RPC_VALIDATEURS, METHODE_CERTIFICAT, arreterReseau, assurerReseau, binaireAvecCertificat, dormir, rpc, rpcResultat, typeDisque } from "./reseau-dev.mjs";
import { periodeDemo, KEY_ID } from "./parcours-registre.mjs";
import { validerRapport, lireJson, CATALOGUE } from "../mesures/commun.mjs";

const MNEMONIQUE_TEST = "test test test test test test test test test test test junk";
const PREFIXE = "noortrace/tm-31/v0/";
const EXPEDITEURS = 64;
const GAZ_ANCRE = 150_000n; // anchor : au plus 96 977 gaz mesurés (CT-4 4.5) ; 64 × 150 000 = 9,6 M ≤ 30 M par bloc
const PROVISION = 20_000_000n; // wei par expéditeur, assez pour plus de cent ancres à 1 wei par gaz
const SEUIL_RECOMPLEMENT = 2_000_000n;
const ESSAIS_PAR_REPETITION = 5;
const TAG_ANCRE = "noor-attestation-ancre";
/** TM-44 : préfixe des clés de test publiées des organisations de clôture, et nom de leur journal. */
const PREFIXE_TM44 = "noortrace/tm-44/v0/";
const JOURNAL_TM44 = "journal-tm44";
const GAZ_CLOTURE = 400_000n; // submitPeriod à deux signatures : 248 710 gaz observés (parcours du registre du 2026-11-02)

export function cleExpediteur(i) {
  return J.sha256(Buffer.from(`${PREFIXE}expediteur/${i}`, "utf8"));
}

class Echec extends Error {
  constructor(message, code = 1) {
    super(message);
    this.code = code;
  }
}

const hex = (n) => "0x" + BigInt(n).toString(16);

async function attendreRecu(hash, { delaiMs = 90_000, url = RPC_DEV } = {}) {
  const fin = Date.now() + delaiMs;
  while (Date.now() < fin) {
    const r = await rpc(url, "eth_getTransactionReceipt", [hash]);
    if (r.result) return r.result;
    await dormir(100);
  }
  throw new Echec(`aucun reçu pour ${hash} en ${delaiMs / 1000} s`);
}

async function frais() {
  const bloc = await rpcResultat(RPC_DEV, "eth_getBlockByNumber", ["latest", false]);
  const base = BigInt(bloc.baseFeePerGas ?? "0x1");
  const max = base > 1n ? base : 1n;
  return { maxFeePerGas: max, maxPriorityFeePerGas: 1n > max ? max : 1n, base };
}

/** Soumet les mêmes octets à chaque validateur ; rend le hachage (le premier accepté). */
async function soumettreATous(brut) {
  let hash = null;
  const erreurs = [];
  for (const url of RPC_VALIDATEURS) {
    const r = await rpc(url, "eth_sendRawTransaction", [brut]);
    if (r.result) hash ??= r.result;
    else erreurs.push(`${url} : ${r.error?.message}`);
  }
  if (!hash && !erreurs.some((e) => /already known|known transaction/i.test(e))) throw new Echec(`virement refusé : ${erreurs.join(" ; ")}`);
  return hash;
}

/**
 * Soumet les transactions au validateur v1 par lots de 16 requêtes simultanées :
 * le serveur JSON-RPC refuse au-delà de 32 requêtes simultanées (« server busy »,
 * CT-4 §12) ; un refus « server busy » est réessayé.
 */
async function envoyerParLots(bruts, { lot = 16 } = {}) {
  const resultats = [];
  for (let i = 0; i < bruts.length; i += lot) {
    resultats.push(
      ...(await Promise.all(
        bruts.slice(i, i + lot).map(async (x) => {
          for (let essai = 0; ; essai++) {
            const r = await rpc(RPC_DEV, "eth_sendRawTransaction", [x]);
            if (!r.error || !/server busy/i.test(r.error.message ?? "") || essai >= 20) return r;
            await dormir(20);
          }
        }),
      )),
    );
  }
  return resultats;
}

/** Proposant d'un bloc, lu dans la proposition signée de son certificat (réessai court sur « not yet persisted »). */
async function proposant(h) {
  for (let i = 0; i < 100; i++) {
    const r = await rpc(RPC_DEV, METHODE_CERTIFICAT, [hex(h)]);
    if (r.result) return r.result.proposal.validatorId;
    await dormir(30);
  }
  return null;
}

/** Attend le prochain bloc proposé par `id` et rend sa hauteur dès qu'il est connu. */
async function apresBlocDe(id, { delaiMs = 60_000 } = {}) {
  const fin = Date.now() + delaiMs;
  let vu = Number(BigInt(await rpcResultat(RPC_DEV, "eth_blockNumber")));
  while (Date.now() < fin) {
    const h = Number(BigInt(await rpcResultat(RPC_DEV, "eth_blockNumber")));
    if (h > vu) {
      if ((await proposant(h)) === id) return h;
      vu = h;
    }
    await dormir(20);
  }
  throw new Echec(`aucun bloc proposé par ${id} en ${delaiMs / 1000} s`);
}

function systeme() {
  const lire = (f) => {
    try {
      return fs.readFileSync(f, "utf8");
    } catch {
      return null;
    }
  };
  const osRelease = lire("/etc/os-release");
  const nomOs = osRelease?.match(/^PRETTY_NAME="?([^"\n]+)"?/m)?.[1] ?? `${os.type()} ${os.release()}`;
  const aslr = lire("/proc/sys/kernel/randomize_va_space")?.trim();
  const cpuinfo = lire("/proc/cpuinfo") ?? "";
  const version = (cmd, args, re) => {
    const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, GOTOOLCHAIN: "local" } });
    if (r.status !== 0) return null;
    return (r.stdout + r.stderr).match(re)?.[1] ?? null;
  };
  const gouverneur = lire("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")?.trim();
  return {
    reference: false,
    cpu: os.cpus()[0]?.model?.trim() || "inconnu",
    cores: os.cpus().length,
    memory_bytes: os.totalmem(),
    disk: { type: typeDisque(RACINE), fsync: null },
    os: nomOs,
    kernel: os.release(),
    node: process.version,
    go: version("go", ["env", "GOVERSION"], /(go[0-9.]+)/),
    python: version("python3", ["--version"], /Python ([0-9.]+)/),
    cpu_scaling: gouverneur ? (gouverneur === "performance" ? "inactif" : "actif") : "inconnu",
    aslr: aslr === undefined || aslr === null ? "inconnu" : aslr === "0" ? "inactif" : "actif",
    load_avg_1m: Math.round(os.loadavg()[0] * 100) / 100,
    virtualized: /\bhypervisor\b/.test(cpuinfo) ? true : null,
  };
}

// ----------------------------------------------------------------- TM-44

/**
 * Clés de test publiées d'une organisation de clôture (même disposition que
 * `cles-essai`, CT-4 7.5) : secrets SHA-256(UTF-8(PREFIXE_TM44 + slug + "/" + nom)).
 */
function ecrireClesTm44(rep, slug, journalId) {
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const ecrire = (nom, contenu) => fs.writeFileSync(path.join(rep, nom), contenu, { mode: 0o600 });
  const secret = (nom) => J.sha256(Buffer.from(`${PREFIXE_TM44}${slug}/${nom}`, "utf8"));
  const adresses = {};
  for (const nom of ["admin-jeu", "approbateur-1", "approbateur-2", "approbateur-3", `cle-chaine-${KEY_ID}`]) {
    const k = secret(nom);
    ecrire(`${nom}.cle`, k + "\n");
    adresses[nom] = computeAddress(new SigningKey(k).publicKey).toLowerCase();
  }
  const graine = secret(KEY_ID);
  ecrire(`${KEY_ID}.graine`, graine + "\n");
  const pub = J.cleEd25519DepuisGraine(graine).clePublique;
  const cle = { key_id: KEY_ID, journal_id: journalId, algorithm: "ed25519", public_key: pub, custody_class: "D", backend_type: "fichier", created_at: new Date().toISOString(), chain_key: adresses[`cle-chaine-${KEY_ID}`], chain_key_class: "D", origin_proof: null };
  ecrire(`${KEY_ID}.json`, J.texteJSON(cle));
  ecrire("cles-essai.json", J.texteJSON({
    version: 0,
    description: `Clés de test publiées de la mesure TM-44 : chaque secret est SHA-256(UTF-8("${PREFIXE_TM44}${slug}/<nom>")) ; adresses et clé publique seulement ici.`,
    journal: { name: JOURNAL_TM44, journal_id: journalId },
    set_admin: adresses["admin-jeu"],
    approvers: [1, 2, 3].map((i) => adresses[`approbateur-${i}`]),
    recorders: [{ key_id: KEY_ID, file: `${KEY_ID}.json`, public_key: pub, chain_key: cle.chain_key }],
  }));
  return { graine, cleChaine: secret(`cle-chaine-${KEY_ID}`), adresses };
}

/**
 * Prépare une clôture : organisation neuve inscrite au registre par l'outil de
 * référence (CT-4 7.4 à 7.8), manifeste de la première période (trois
 * événements fictifs, `periodeDemo`), ancre, demande de clôture signée par
 * deux approbateurs ; rend la transaction `submitPeriod` signée par la clé de
 * chaîne du journal, prête à être envoyée, sans l'envoyer.
 */
async function preparerCloture({ E, k, horodatage, chainId, ifacePeriode, stderr, log }) {
  const slug = `mesure-tm44-${horodatage}-${String(k).padStart(2, "0")}`;
  const rep = path.join(E, "clotures", slug);
  fs.mkdirSync(path.join(rep, "sorties"), { recursive: true });
  const journalId = C.journalIdDuNom(JOURNAL_TM44);
  const cles = ecrireClesTm44(path.join(rep, "cles"), slug, journalId);
  const kf = (nom) => `fichier:${path.join(rep, "cles", `${nom}.cle`)}`;
  let numero = 0;
  const outil = async (args, attendu = ["reussi", "deja_fait"]) => {
    numero++;
    let texte = "";
    const { code, sortie } = await executer(args, { stdout: { write: (x) => ((texte += x), true) }, stderr: { write: (x) => (stderr.write(x), true) } });
    fs.writeFileSync(path.join(rep, "sorties", `${String(numero).padStart(2, "0")}-${args[0]}.json`), texte);
    if (!attendu.includes(sortie.result)) throw new Echec(`${slug} : ${args[0]} : ${sortie.error ? `${sortie.error.code} : ${sortie.error.message}` : sortie.result} (code ${code})`);
    return sortie;
  };
  const dossier = path.join(rep, "dossier.json");
  const caps = path.join(rep, "captures");
  const prep = await outil(["inscrire-client", "--preparer", "--org", slug, "--journal", JOURNAL_TM44, "--seuil", "2", "--cles-essai", path.join(rep, "cles", "cles-essai.json"), "--exploitant", "hardhat:0", "--prepare-par", "mesure TM-44 (scripts/e2e/mesure-capture-bloc-plein.mjs)", "--sortie", dossier]);
  await outil(["inscrire-client", "--dossier", dossier, "--exploitant", "hardhat:0", "--captures", caps]);
  const demInsc = path.join(rep, "demande-inscription.json");
  await outil(["condense", "inscription", "--dossier", dossier, "--key-id", KEY_ID, "--sortie", demInsc]);
  await outil(["signer", "--demande", demInsc, "--cle", kf("approbateur-1")]);
  await outil(["signer", "--demande", demInsc, "--cle", kf("approbateur-2")]);
  await outil(["inscrire-cle", "--demande", demInsc, "--cle-chaine", kf(`cle-chaine-${KEY_ID}`), "--dossier", dossier, "--captures", caps]);
  const per = path.join(rep, "periode-1");
  fs.mkdirSync(per, { recursive: true });
  const periode = periodeDemo({ org_id: prep.outputs.org_id, journal_id: journalId, graine: cles.graine });
  const fMan = path.join(per, "manifeste.json");
  fs.writeFileSync(path.join(per, "evenements.json"), J.texteJSON(periode.evenements));
  fs.writeFileSync(fMan, J.texteJSON(periode.manifeste));
  fs.writeFileSync(path.join(per, "manifeste.sig"), J.texteJSON(periode.sig));
  await outil(["ancrer", "--manifeste", fMan, "--cle-chaine", kf(`cle-chaine-${KEY_ID}`), "--dossier", dossier, "--captures", caps]);
  const demClo = path.join(rep, "demande-cloture-1.json");
  await outil(["condense", "cloture", "--manifeste", fMan, "--captures", caps, "--sortie", demClo]);
  await outil(["signer", "--demande", demClo, "--cle", kf("approbateur-1")]);
  await outil(["signer", "--demande", demClo, "--cle", kf("approbateur-3")]);
  const demande = JSON.parse(fs.readFileSync(demClo, "utf8"));
  if (demande.operation !== "cloture" || demande.signatures.length < 2) throw new Echec(`${slug} : demande de clôture incomplète`);
  const m = demande.fields.period_meta;
  const meta = { orgId: m.org_id, journalId: m.journal_id, periodHash: m.period_hash, root: m.root, periodStart: BigInt(m.period_start), periodEnd: BigInt(m.period_end), firstSeq: BigInt(m.first_seq), lastSeq: BigInt(m.last_seq), version: m.version, uri: m.uri };
  const sigs = demande.signatures.map((x) => ({ v: x.v, r: x.r, s: x.s }));
  const data = ifacePeriode.encodeFunctionData("submitPeriod", [meta, sigs]);
  const portefeuille = new Wallet(cles.cleChaine);
  const contrat = demande.contract.toLowerCase();
  const estimation = await rpc(RPC_DEV, "eth_estimateGas", [{ from: portefeuille.address, to: contrat, data }]);
  if (estimation.error) throw new Echec(`${slug} : eth_estimateGas refuse la clôture : ${estimation.error.message}`);
  const f = await frais();
  const nonce = BigInt(await rpcResultat(RPC_DEV, "eth_getTransactionCount", [portefeuille.address, "pending"]));
  const brut = await portefeuille.signTransaction({ type: 2, chainId, nonce, to: contrat, value: 0n, data, gasLimit: GAZ_CLOTURE, maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas });
  log(`clôture préparée : ${slug} (journal ${journalId.slice(0, 10)}…, clé de chaîne ${portefeuille.address}, gaz estimé ${Number(BigInt(estimation.result))})`);
  return { slug, org_id: prep.outputs.org_id, journal_id: journalId, contrat, portefeuille: portefeuille.address, brut, demande: path.relative(E, demClo), gaz_estime: Number(BigInt(estimation.result)) };
}

/**
 * Reçus d'un lot envoyé à v1 : attente de chaque reçu ; une transaction sans
 * reçu après `delaiMs` est renvoyée en mêmes octets aux quatre validateurs
 * (CT-4 EX-8.15, EX-8.16 : noorcore n'inclut une transaction qu'au tour du
 * validateur qui l'a reçue, et un lot resté dans la réserve de v1 après un
 * tour de proposition sans quorum n'est pas reproposé par lui, observé le
 * 2026-11-13), puis attendue encore ; rend { recus, renvoyees } ou lève si
 * une transaction reste sans reçu.
 */
async function recusAvecReprise(hachages, bruts, { delaiMs = 90_000, log = () => {} } = {}) {
  const recus = new Array(hachages.length).fill(null);
  const fin = Date.now() + delaiMs;
  for (let i = 0; i < hachages.length; i++) {
    while (recus[i] === null && Date.now() < fin) {
      const r = await rpc(RPC_DEV, "eth_getTransactionReceipt", [hachages[i]]);
      if (r.result) recus[i] = r.result;
      else await dormir(100);
    }
  }
  const manquantes = recus.map((r, i) => (r === null ? i : -1)).filter((i) => i >= 0);
  if (manquantes.length) {
    log(`${manquantes.length} transaction(s) sans reçu en ${delaiMs / 1000} s : renvoi en mêmes octets aux quatre validateurs (EX-8.16)`);
    for (const i of manquantes) await soumettreATous(bruts[i]);
    for (const i of manquantes) recus[i] = await attendreRecu(hachages[i], { delaiMs: 120_000 });
  }
  return { recus, renvoyees: manquantes.length };
}

/** Capture d'une transaction par l'outil de référence et octets de la capture (comme TM-31) ; rend la décomposition. */
async function capturerEtMesurer({ hash, role, contrat, repCaptures, E, nomSortie, stderr }) {
  let texte = "";
  const r = await executer(["capturer", "--transaction", hash, "--role", role, "--contrat", contrat, "--captures", repCaptures], { stdout: { write: (x) => ((texte += x), true) }, stderr: { write: (x) => (stderr.write(x), true) } });
  fs.writeFileSync(path.join(E, `${nomSortie}.json`), texte);
  if (r.code !== 0) throw new Echec(`capturer (${role}) : ${JSON.stringify(r.sortie.error)}`);
  const index = JSON.parse(fs.readFileSync(path.join(repCaptures, r.sortie.outputs.capture), "utf8"));
  const taille = (n) => fs.statSync(path.join(repCaptures, n)).size;
  const enTete = taille(index.files.block.name);
  const certificat = taille(index.files.certificate.name);
  const recusOctets = index.files.receipts.map((x) => taille(x.name));
  const totalRecus = recusOctets.reduce((a, x) => a + x, 0);
  return {
    role, transaction: hash, transaction_index: index.transaction_index, capture_index: r.sortie.outputs.capture, checks: index.checks.map((c) => `${c.id}:${c.status}`),
    octets: { capture: enTete + totalRecus + certificat, en_tete: enTete, certificat, recus: totalRecus, recu_min: Math.min(...recusOctets), recu_max: Math.max(...recusOctets), recu_capture: recusOctets[index.transaction_index], index: taille(r.sortie.outputs.capture) },
  };
}

export async function mesurer(argv = process.argv.slice(2), { stdout = process.stdout, stderr = process.stderr } = {}) {
  const { values: o } = parseArgs({ args: argv, options: { sortie: { type: "string" }, rapport: { type: "string" }, repetitions: { type: "string" }, "garder-reseau": { type: "boolean" }, clotures: { type: "string" } }, strict: true });
  const log = (m) => stderr.write(`mesure-capture-bloc-plein : ${m}\n`);
  const repetitions = Number(o.repetitions ?? 3);
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 20) throw new Echec("--repetitions : entier de 1 à 20", 2);
  const compositions = o.clotures === undefined ? [] : o.clotures.split(",").map((x) => Number(x.trim()));
  if (compositions.some((k) => !Number.isInteger(k) || k < 1 || k >= EXPEDITEURS) || new Set(compositions).size !== compositions.length) throw new Echec(`--clotures : entiers distincts de 1 à ${EXPEDITEURS - 1}, séparés par des virgules`, 2);
  if (compositions.length) return mesurerClotures({ o, compositions, repetitions, stdout, stderr, log });
  const E = path.resolve(o.sortie ?? fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-tm31-")));
  if (fs.existsSync(E) && fs.readdirSync(E).length) throw new Echec(`${E} n'est pas vide`, 2);
  fs.mkdirSync(E, { recursive: true });
  const b = binaireAvecCertificat();
  if (!b.ok) throw new Echec(b.condition, 2);
  const shaBinaire = J.sha256(fs.readFileSync(b.binaire)).slice(2);
  const fDep = path.join(deploymentsDir(), "noorcore.json");
  if (!fs.existsSync(fDep)) throw new Echec(`${fDep} absent : déployer d'abord les contrats (CT-4 7.4, ou npm run e2e:registre)`, 2);
  const attestation = JSON.parse(fs.readFileSync(fDep, "utf8")).contrats.AttestationRegistry.adresse.toLowerCase();
  const artefact = path.join(RACINE, "hh-artifacts", "contracts", "AttestationRegistry.sol", "AttestationRegistry.json");
  if (!fs.existsSync(artefact)) throw new Echec("ABI absente de hh-artifacts/ (npm run compile)", 2);
  const iface = new Interface(JSON.parse(fs.readFileSync(artefact, "utf8")).abi);
  if (process.env.NOORTRACE_RUNTIME_DIR && !process.env.NOORTRACE_VALIDATORS_FILE) process.env.NOORTRACE_VALIDATORS_FILE = path.join(process.env.NOORTRACE_RUNTIME_DIR, "validators.json");

  const debut = new Date();
  let reseau = null;
  const repetitionsFaites = [];
  const essaisRates = [];
  let code = 1;
  try {
    reseau = assurerReseau({ journal: stderr });
    const chainId = BigInt(await rpcResultat(RPC_DEV, "eth_chainId"));
    if (chainId !== 2124n) throw new Echec(`eth_chainId ${chainId} : le réseau de développement 2124 est attendu`, 2);
    if ((await rpcResultat(RPC_DEV, "eth_getCode", [attestation, "latest"])) === "0x") throw new Echec(`aucun code à ${attestation} (réseau recréé ?)`, 2);

    // --- expéditeurs et approvisionnement ----------------------------------
    const expediteurs = Array.from({ length: EXPEDITEURS }, (_, k) => new Wallet(cleExpediteur(k + 1)));
    const f0 = await frais();
    const besoin = [];
    for (const w of expediteurs) {
      const s = BigInt(await rpcResultat(RPC_DEV, "eth_getBalance", [w.address, "latest"]));
      if (s < SEUIL_RECOMPLEMENT) besoin.push({ w, montant: PROVISION - s });
    }
    if (besoin.length) {
      log(`approvisionnement de ${besoin.length} expéditeur(s) par les comptes Hardhat 0 à 3…`);
      const comptes = [0, 1, 2, 3].map((i) => new Wallet(HDNodeWallet.fromPhrase(MNEMONIQUE_TEST, undefined, `m/44'/60'/0'/0/${i}`).privateKey));
      const nonces = await Promise.all(comptes.map(async (c) => BigInt(await rpcResultat(RPC_DEV, "eth_getTransactionCount", [c.address, "pending"]))));
      const hachages = [];
      for (let k = 0; k < besoin.length; k++) {
        const j = k % 4;
        const brut = await comptes[j].signTransaction({ type: 2, chainId, nonce: nonces[j]++, to: besoin[k].w.address, value: besoin[k].montant, data: "0x", gasLimit: 21000n, maxFeePerGas: f0.maxFeePerGas, maxPriorityFeePerGas: f0.maxPriorityFeePerGas });
        hachages.push(await soumettreATous(brut));
      }
      for (const h of hachages) {
        const r = await attendreRecu(h, { delaiMs: 300_000 });
        if (r.status !== "0x1") throw new Echec(`virement ${h} : status ${r.status}`);
      }
      log("approvisionnement fait");
    }

    // --- répétitions ----------------------------------------------------------
    const docType = DOC_TYPE_PERIODE;
    for (let rep = 1; rep <= repetitions; rep++) {
      let fait = null;
      for (let essai = 1; essai <= ESSAIS_PAR_REPETITION && !fait; essai++) {
        const f = await frais();
        const nonces = await Promise.all(expediteurs.map(async (w) => BigInt(await rpcResultat(RPC_DEV, "eth_getTransactionCount", [w.address, "pending"]))));
        const sel = J.sha256(Buffer.from(`${PREFIXE}empreinte/${debut.toISOString()}/${rep}/${essai}`, "utf8"));
        const bruts = [];
        for (let k = 0; k < EXPEDITEURS; k++) {
          const w = expediteurs[k];
          const fp = J.sha256(Buffer.from(`${sel}/${k + 1}`, "utf8"));
          const digest = solidityPackedKeccak256(["uint256", "address", "string", "bytes32", "bytes32"], [chainId, attestation, TAG_ANCRE, fp, docType]);
          const sig = Signature.from(w.signingKey.sign(solidityPackedKeccak256(["string", "bytes32"], ["\x19Ethereum Signed Message:\n32", digest])));
          const data = iface.encodeFunctionData("anchor", [fp, docType, w.address, { v: sig.v, r: sig.r, s: sig.s }]);
          bruts.push(await w.signTransaction({ type: 2, chainId, nonce: nonces[k], to: attestation, value: 0n, data, gasLimit: GAZ_ANCRE, maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas }));
        }
        const hApres = await apresBlocDe("v1");
        const envoi = await envoyerParLots(bruts);
        const refus = envoi.filter((r) => r.error);
        if (refus.length) throw new Echec(`${refus.length} envoi(s) refusé(s) : ${refus[0].error.message}`);
        const hachages = envoi.map((r) => r.result);
        const recus = [];
        for (const h of hachages) recus.push(await attendreRecu(h));
        const parBloc = new Map();
        for (const r of recus) parBloc.set(r.blockNumber, (parBloc.get(r.blockNumber) ?? 0) + 1);
        const annulees = recus.filter((r) => r.status !== "0x1").length;
        if (parBloc.size !== 1 || annulees) {
          essaisRates.push({ repetition: rep, essai, apres_bloc_v1: hApres, blocs: Object.fromEntries([...parBloc].map(([k, v]) => [Number(BigInt(k)), v])), annulees });
          log(`répétition ${rep}, essai ${essai} : reçus répartis sur ${parBloc.size} bloc(s), ${annulees} annulée(s) : repris`);
          continue;
        }
        const h = Number(BigInt(recus[0].blockNumber));
        const bloc = await rpcResultat(RPC_DEV, "eth_getBlockByNumber", [hex(h), false]);
        if (bloc.transactions.length !== EXPEDITEURS) {
          essaisRates.push({ repetition: rep, essai, apres_bloc_v1: hApres, blocs: { [h]: bloc.transactions.length }, annulees: 0 });
          log(`répétition ${rep}, essai ${essai} : bloc ${h} de ${bloc.transactions.length} transactions : repris`);
          continue;
        }
        // Capture de la dernière transaction du bloc par l'outil de référence (CT-4 §9.4).
        const derniere = bloc.transactions[bloc.transactions.length - 1];
        const repCaptures = path.join(E, `repetition-${rep}`);
        let texte = "";
        const r = await executer(["capturer", "--transaction", derniere, "--role", "ancre", "--contrat", attestation, "--captures", repCaptures], { stdout: { write: (s) => ((texte += s), true) }, stderr: { write: (s) => (stderr.write(s), true) } });
        fs.writeFileSync(path.join(E, `capturer-${rep}.json`), texte);
        if (r.code !== 0) throw new Echec(`capturer : ${JSON.stringify(r.sortie.error)}`);
        const index = JSON.parse(fs.readFileSync(path.join(repCaptures, r.sortie.outputs.capture), "utf8"));
        const taille = (n) => fs.statSync(path.join(repCaptures, n)).size;
        const enTete = taille(index.files.block.name);
        const certificat = taille(index.files.certificate.name);
        const recusOctets = index.files.receipts.map((x) => taille(x.name));
        const totalRecus = recusOctets.reduce((a, x) => a + x, 0);
        fait = {
          repetition: rep,
          essai,
          block_number: h,
          block_hash: bloc.hash,
          transactions: bloc.transactions.length,
          gas_used: Number(BigInt(bloc.gasUsed)),
          captured_transaction: derniere,
          transaction_index: index.transaction_index,
          capture_index: r.sortie.outputs.capture,
          octets: {
            capture: enTete + totalRecus + certificat,
            en_tete: enTete,
            certificat,
            recus: totalRecus,
            recu_min: Math.min(...recusOctets),
            recu_max: Math.max(...recusOctets),
            recu_capture: recusOctets[index.transaction_index],
            index: taille(r.sortie.outputs.capture),
            en_tete_certificat_un_recu_max: enTete + certificat + Math.max(...recusOctets),
          },
          checks: index.checks.map((c) => `${c.id}:${c.status}`),
        };
        repetitionsFaites.push(fait);
        log(`répétition ${rep} : bloc ${h} de ${bloc.transactions.length} transactions, capture ${fait.octets.capture} octets (en-tête ${enTete}, certificat ${certificat}, reçus ${totalRecus})`);
      }
      if (!fait) throw new Echec(`répétition ${rep} : aucun bloc plein en ${ESSAIS_PAR_REPETITION} essais`);
    }
    code = 0;
  } finally {
    if (reseau?.demarre && !o["garder-reseau"]) {
      log("arrêt du réseau démarré par la mesure…");
      arreterReseau({ journal: stderr });
    }
  }

  // --- rapport (CT-9 §11.3) ---------------------------------------------------
  const echantillons = repetitionsFaites.map((x) => x.octets.capture);
  const commit = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" }).stdout.trim();
  const arbreModifie = spawnSync("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: RACINE, encoding: "utf8" }).stdout.trim() !== "" || spawnSync("git", ["ls-files", "--others", "--exclude-standard", "scripts"], { cwd: RACINE, encoding: "utf8" }).stdout.trim() !== "";
  const configuration = { outil: "scripts/e2e/mesure-capture-bloc-plein.mjs", expediteurs: EXPEDITEURS, graines: `${PREFIXE}expediteur/<i>`, gas_limit_ancre: Number(GAZ_ANCRE), frais: "type 2, maxFeePerGas = max(baseFee, 1), maxPriorityFeePerGas 1 wei", soumission: "validateur v1 (127.0.0.1:8645), juste après un bloc qu'il a proposé", capture: "noortrace-registre capturer --role ancre (CT-4 §9.4)", repetitions, reseau: "noortrace-2124-dev, 4 validateurs BFT en boucle locale (chain/scripts/dev-net.sh)" };
  fs.writeFileSync(path.join(E, "configuration.json"), J.texteJSON(configuration));
  const configurationSha = J.sha256(fs.readFileSync(path.join(E, "configuration.json"))).slice(2);
  const fin = new Date();
  const moyenne = Math.round((echantillons.reduce((a, x) => a + x, 0) / echantillons.length) * 100) / 100;
  const decomposition = repetitionsFaites
    .map((x) => `répétition ${x.repetition} : bloc ${x.block_number} (${x.transactions} transactions, ${x.gas_used} gaz), capture de la transaction d'indice ${x.transaction_index} = ${x.octets.capture} octets = en-tête ${x.octets.en_tete} + certificat ${x.octets.certificat} + ${x.transactions} reçus ${x.octets.recus} (${x.octets.recu_min} à ${x.octets.recu_max} par reçu) ; index de capture ${x.octets.index} octets en plus ; en-tête + certificat + un seul reçu (forme de CT-8 §9.2) : au plus ${x.octets.en_tete_certificat_un_recu_max} octets ; CP-1 à CP-6 : ${x.checks.join(" ")}`)
    .join(". ");
  const rapport = {
    version: 0,
    kind: "rapport-mesure",
    date: debut.toISOString().slice(0, 10),
    measured_at: debut.toISOString().replace(/\.\d{3}Z$/, "Z"),
    commit,
    spec_version: lireJson(CATALOGUE).spec_version,
    system: systeme(),
    method: { warmup: 0, repetitions, percentile_method: "plus_proche_rang", clock: "sans_objet", pair_with_without: false, samples_published: true },
    configuration_sha256: configurationSha,
    counts_for_targets: false,
    results: [
      {
        name: "b_cap_bloc_plein",
        test_id: "TM-31",
        unit: "octets",
        n: echantillons.length,
        connections: null,
        samples: echantillons,
        samples_sha256: null,
        value: null,
        p50: null,
        p95: null,
        p99: null,
        min: Math.min(...echantillons),
        max: Math.max(...echantillons),
        mean: moyenne,
        text_value: null,
        target: null,
        met: null,
        conditions: [
          `bloc de ${EXPEDITEURS} transactions sur le réseau de développement (noortrace-2124-dev, quatre validateurs BFT en boucle locale, binaire noorcore du répertoire d'exécution avec ${METHODE_CERTIFICAT}, SHA-256 ${shaBinaire})`,
          "capture d'une transaction d'ancre (AttestationRegistry.anchor) par noortrace-registre capturer --role ancre : bloc-<h>.json, recu-<hachage>.json de chacune des 64 transactions du bloc et certificat-<h>.json, réponses JSON-RPC telles que reçues (CT-4 CP-6) ; index de capture exclu",
          `64 expéditeurs de test publiés (clé SHA-256(UTF-8("${PREFIXE}expediteur/<i>"))), une transaction chacun, soumises au validateur v1 après un bloc qu'il a proposé ; limite de gaz ${GAZ_ANCRE} par transaction`,
        ],
        excluded_reason: "hors_systeme_de_reference",
      },
    ],
    notes:
      `TM-31 (CT-8 EX-9.1, coefficient b_cap de CT-8 §9.2 ; CT-4 §9.2 : bloc plein non mesuré). Relevé de tailles, une exécution par répétition, ${repetitions} répétitions sans échauffement (EX-11.3, catalogue de TM-31), max ${Math.max(...echantillons)} octets (ligne b_cap_bloc_plein). ${decomposition}. ` +
      `Ce que la ligne compte : la capture que CT-4 §9.4 écrit pour une transaction d'un bloc plein, qui contient le reçu de chaque transaction du bloc (CP-3, EX-9.5) ; CT-8 §9.2 mesurait 11 096 octets (en-tête 1 498, certificat 7 782, reçu 1 816) sur des blocs d'une transaction. ` +
      (essaisRates.length ? `Essais repris (reçus hors d'un bloc unique) : ${JSON.stringify(essaisRates)}. ` : "Aucun essai repris. ") +
      `Mesure faite du ${debut.toISOString()} au ${fin.toISOString()} hors du système de référence de CT-9 §11.1 (machine virtuelle, disque virtuel) : elle ne compte pour aucune cible ; TM-31 n'a pas de cible (aucune_cible). ` +
      `Configuration (configuration_sha256) : ${JSON.stringify(configuration)}.` +
      (arbreModifie ? " Commit : tête du dépôt au moment de la mesure, arbre de travail modifié ou fichiers non suivis sous scripts/." : ""),
  };
  const schema = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", "plan-de-tests-v0.schema.json"), "utf8"));
  const erreurs = J.validerSchema(rapport, schema, { registre: { [schema.$id]: schema }, fragment: "#/$defs/rapport_mesure" });
  if (erreurs.length) throw new Echec(`rapport non conforme à plan-de-tests-v0#/$defs/rapport_mesure : ${erreurs[0].chemin} : ${erreurs[0].message}`);
  const fRapport = path.resolve(o.rapport ?? path.join(E, `rapport-${rapport.date}-capture-bloc-plein.json`));
  if (fs.existsSync(fRapport)) throw new Echec(`${fRapport} existe déjà : un rapport n'est jamais remplacé (EX-11.11)`, 2);
  fs.writeFileSync(fRapport, J.texteJSON(rapport));
  fs.writeFileSync(path.join(E, "repetitions.json"), J.texteJSON({ repetitions: repetitionsFaites, essais_repris: essaisRates }));
  log(`rapport écrit : ${fRapport}`);
  stdout.write(J.texteJSON(rapport));
  return { code, rapport, fichier: fRapport };
}

/** TM-44 : blocs pleins qui mêlent des clôtures et des ancres. */
async function mesurerClotures({ o, compositions, repetitions, stdout, stderr, log }) {
  const E = path.resolve(o.sortie ?? fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-tm44-")));
  if (fs.existsSync(E) && fs.readdirSync(E).length) throw new Echec(`${E} n'est pas vide`, 2);
  fs.mkdirSync(E, { recursive: true });
  const b = binaireAvecCertificat();
  if (!b.ok) throw new Echec(b.condition, 2);
  const shaBinaire = J.sha256(fs.readFileSync(b.binaire)).slice(2);
  const fDep = path.join(deploymentsDir(), "noorcore.json");
  if (!fs.existsSync(fDep)) throw new Echec(`${fDep} absent : déployer d'abord les contrats (CT-4 7.4, ou npm run e2e:registre)`, 2);
  const contrats = JSON.parse(fs.readFileSync(fDep, "utf8")).contrats;
  const attestation = contrats.AttestationRegistry.adresse.toLowerCase();
  const periodes = contrats.PeriodRegistry.adresse.toLowerCase();
  const artefact = (nom) => path.join(RACINE, "hh-artifacts", "contracts", `${nom}.sol`, `${nom}.json`);
  for (const nom of ["AttestationRegistry", "PeriodRegistry"]) if (!fs.existsSync(artefact(nom))) throw new Echec("ABI absente de hh-artifacts/ (npm run compile)", 2);
  const iface = new Interface(JSON.parse(fs.readFileSync(artefact("AttestationRegistry"), "utf8")).abi);
  const ifacePeriode = new Interface(JSON.parse(fs.readFileSync(artefact("PeriodRegistry"), "utf8")).abi);
  if (process.env.NOORTRACE_RUNTIME_DIR && !process.env.NOORTRACE_VALIDATORS_FILE) process.env.NOORTRACE_VALIDATORS_FILE = path.join(process.env.NOORTRACE_RUNTIME_DIR, "validators.json");
  const catalogue = lireJson(CATALOGUE);
  const debut = new Date();
  const horodatage = debut.toISOString().replace(/[-:T]/g, "").slice(0, 14);
  let reseau = null;
  const blocs = [];
  const essaisRates = [];
  const cloturesAbandonnees = [];
  let code = 1;
  try {
    reseau = assurerReseau({ journal: stderr });
    const chainId = BigInt(await rpcResultat(RPC_DEV, "eth_chainId"));
    if (chainId !== 2124n) throw new Echec(`eth_chainId ${chainId} : le réseau de développement 2124 est attendu`, 2);
    for (const c of [attestation, periodes]) if ((await rpcResultat(RPC_DEV, "eth_getCode", [c, "latest"])) === "0x") throw new Echec(`aucun code à ${c} (réseau recréé ?)`, 2);

    // Expéditeurs des ancres (les mêmes que TM-31) et leur approvisionnement.
    const expediteurs = Array.from({ length: EXPEDITEURS }, (_, k) => new Wallet(cleExpediteur(k + 1)));
    const f0 = await frais();
    const besoin = [];
    for (const w of expediteurs) {
      const sld = BigInt(await rpcResultat(RPC_DEV, "eth_getBalance", [w.address, "latest"]));
      if (sld < SEUIL_RECOMPLEMENT) besoin.push({ w, montant: PROVISION - sld });
    }
    if (besoin.length) {
      log(`approvisionnement de ${besoin.length} expéditeur(s) par les comptes Hardhat 0 à 3…`);
      const comptes = [0, 1, 2, 3].map((i) => new Wallet(HDNodeWallet.fromPhrase(MNEMONIQUE_TEST, undefined, `m/44'/60'/0'/0/${i}`).privateKey));
      const nonces = await Promise.all(comptes.map(async (c) => BigInt(await rpcResultat(RPC_DEV, "eth_getTransactionCount", [c.address, "pending"]))));
      const hachages = [];
      for (let k = 0; k < besoin.length; k++) {
        const j = k % 4;
        const brut = await comptes[j].signTransaction({ type: 2, chainId, nonce: nonces[j]++, to: besoin[k].w.address, value: besoin[k].montant, data: "0x", gasLimit: 21000n, maxFeePerGas: f0.maxFeePerGas, maxPriorityFeePerGas: f0.maxPriorityFeePerGas });
        hachages.push(await soumettreATous(brut));
      }
      for (const h of hachages) {
        const r = await attendreRecu(h, { delaiMs: 300_000 });
        if (r.status !== "0x1") throw new Echec(`virement ${h} : status ${r.status}`);
      }
      log("approvisionnement fait");
    }

    let numeroCloture = 0;
    const docType = DOC_TYPE_PERIODE;
    for (const K of compositions) {
      for (let rep = 1; rep <= repetitions; rep++) {
        let fait = null;
        for (let essai = 1; essai <= ESSAIS_PAR_REPETITION && !fait; essai++) {
          const clotures = [];
          while (clotures.length < K) clotures.push(await preparerCloture({ E, k: ++numeroCloture, horodatage, chainId, ifacePeriode, stderr, log }));
          const nbAncres = EXPEDITEURS - K;
          const f = await frais();
          const ancreurs = expediteurs.slice(0, nbAncres);
          const nonces = await Promise.all(ancreurs.map(async (w) => BigInt(await rpcResultat(RPC_DEV, "eth_getTransactionCount", [w.address, "pending"]))));
          const sel = J.sha256(Buffer.from(`${PREFIXE}tm-44/empreinte/${debut.toISOString()}/${K}/${rep}/${essai}`, "utf8"));
          const bruts = clotures.map((c) => c.brut);
          for (let k = 0; k < nbAncres; k++) {
            const w = ancreurs[k];
            const fp = J.sha256(Buffer.from(`${sel}/${k + 1}`, "utf8"));
            const digest = solidityPackedKeccak256(["uint256", "address", "string", "bytes32", "bytes32"], [chainId, attestation, TAG_ANCRE, fp, docType]);
            const sig = Signature.from(w.signingKey.sign(solidityPackedKeccak256(["string", "bytes32"], ["\x19Ethereum Signed Message:\n32", digest])));
            const data = iface.encodeFunctionData("anchor", [fp, docType, w.address, { v: sig.v, r: sig.r, s: sig.s }]);
            bruts.push(await w.signTransaction({ type: 2, chainId, nonce: nonces[k], to: attestation, value: 0n, data, gasLimit: GAZ_ANCRE, maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas }));
          }
          const hApres = await apresBlocDe("v1");
          const envoi = await envoyerParLots(bruts);
          const refus = envoi.filter((r) => r.error);
          if (refus.length) throw new Echec(`${refus.length} envoi(s) refusé(s) : ${refus[0].error.message}`);
          const hachages = envoi.map((r) => r.result);
          const { recus, renvoyees } = await recusAvecReprise(hachages, bruts, { log });
          const parBloc = new Map();
          for (const r of recus) parBloc.set(r.blockNumber, (parBloc.get(r.blockNumber) ?? 0) + 1);
          const annulees = recus.filter((r) => r.status !== "0x1").length;
          const h = Number(BigInt(recus[0].blockNumber));
          const bloc = parBloc.size === 1 ? await rpcResultat(RPC_DEV, "eth_getBlockByNumber", [hex(h), false]) : null;
          if (parBloc.size !== 1 || annulees || bloc.transactions.length !== EXPEDITEURS) {
            essaisRates.push({ composition: K, repetition: rep, essai, apres_bloc_v1: hApres, blocs: Object.fromEntries([...parBloc].map(([k2, v]) => [Number(BigInt(k2)), v])), annulees, transactions: bloc?.transactions.length ?? null, renvoyees });
            // Les clôtures de cet essai sont consommées (incluses ou annulées) : journaux abandonnés, clôtures neuves à l'essai suivant.
            cloturesAbandonnees.push(...clotures.map((c) => c.slug));
            log(`composition ${K}, répétition ${rep}, essai ${essai} : reçus sur ${parBloc.size} bloc(s), ${annulees} annulée(s)${bloc ? `, bloc de ${bloc.transactions.length} transactions` : ""} : repris`);
            continue;
          }
          const repCaptures = path.join(E, `composition-${K}-repetition-${rep}`);
          const cloture = await capturerEtMesurer({ hash: hachages[0], role: "cloture", contrat: periodes, repCaptures: path.join(repCaptures, "cloture"), E, nomSortie: `capturer-${K}-${rep}-cloture`, stderr });
          const ancre = await capturerEtMesurer({ hash: hachages[hachages.length - 1], role: "ancre", contrat: attestation, repCaptures: path.join(repCaptures, "ancre"), E, nomSortie: `capturer-${K}-${rep}-ancre`, stderr });
          fait = { composition: K, repetition: rep, essai, block_number: h, block_hash: bloc.hash, transactions: bloc.transactions.length, gas_used: Number(BigInt(bloc.gasUsed)), clotures: clotures.map((c) => ({ slug: c.slug, org_id: c.org_id, journal_id: c.journal_id, transaction: hachages[clotures.indexOf(c)], gaz_estime: c.gaz_estime })), ancres: nbAncres, captures: [cloture, ancre] };
          blocs.push(fait);
          log(`composition ${K}, répétition ${rep} : bloc ${h} (${K} clôture(s), ${nbAncres} ancres, ${fait.gas_used} gaz) ; capture d'une clôture ${cloture.octets.capture} octets, d'une ancre ${ancre.octets.capture} octets`);
        }
        if (!fait) throw new Echec(`composition ${K}, répétition ${rep} : aucun bloc plein en ${ESSAIS_PAR_REPETITION} essais`);
      }
    }
    code = 0;
  } finally {
    if (reseau?.demarre && !o["garder-reseau"]) {
      log("arrêt du réseau démarré par la mesure…");
      arreterReseau({ journal: stderr });
    }
  }

  // --- rapport (CT-9 §11.3), ligne b_cap_bloc_plein_clotures de TM-44 -------
  const captures = blocs.flatMap((x) => x.captures.map((c) => ({ ...c, bloc: x })));
  const echantillons = captures.map((c) => c.octets.capture);
  const commit = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" }).stdout.trim();
  const arbreModifie = spawnSync("git", ["status", "--porcelain"], { cwd: RACINE, encoding: "utf8" }).stdout.trim() !== "";
  const configuration = { outil: "scripts/e2e/mesure-capture-bloc-plein.mjs --clotures", compositions, expediteurs_ancres: `${PREFIXE}expediteur/<i>`, cles_clotures: `${PREFIXE_TM44}<organisation>/<nom>`, gas_limit_ancre: Number(GAZ_ANCRE), gas_limit_cloture: Number(GAZ_CLOTURE), seuil_approbateurs: 2, frais: "type 2, maxFeePerGas = max(baseFee, 1), maxPriorityFeePerGas 1 wei", soumission: "validateur v1 (127.0.0.1:8645), juste après un bloc qu'il a proposé, clôtures puis ancres dans le même lot", capture: "noortrace-registre capturer --role cloture et --role ancre (CT-4 §9.4)", repetitions, reseau: "noortrace-2124-dev, 4 validateurs BFT en boucle locale (chain/scripts/dev-net.sh)" };
  fs.writeFileSync(path.join(E, "configuration.json"), J.texteJSON(configuration));
  const configurationSha = J.sha256(fs.readFileSync(path.join(E, "configuration.json"))).slice(2);
  const fin = new Date();
  const moyenne = Math.round((echantillons.reduce((a, x) => a + x, 0) / echantillons.length) * 100) / 100;
  const maxIndexCompris = Math.max(...captures.map((c) => c.octets.capture + c.octets.index));
  const B_CAP = 123761;
  const decomposition = captures.map((c) => `composition ${c.bloc.composition} répétition ${c.bloc.repetition}, bloc ${c.bloc.block_number} (${c.bloc.clotures.length} clôture(s) + ${c.bloc.ancres} ancres, ${c.bloc.gas_used} gaz), capture de la transaction de ${c.role} d'indice ${c.transaction_index} = ${c.octets.capture} octets = en-tête ${c.octets.en_tete} + certificat ${c.octets.certificat} + ${c.bloc.transactions} reçus ${c.octets.recus} (${c.octets.recu_min} à ${c.octets.recu_max} par reçu, ${c.octets.recu_capture} pour la transaction capturée) ; index de capture ${c.octets.index} octets en plus ; CP-1 à CP-6 : ${c.checks.join(" ")}`).join(". ");
  const rapport = {
    version: 0,
    kind: "rapport-mesure",
    date: debut.toISOString().slice(0, 10),
    measured_at: debut.toISOString().replace(/\.\d{3}Z$/, "Z"),
    commit,
    spec_version: catalogue.spec_version,
    system: systeme(),
    method: { warmup: 0, repetitions, percentile_method: "plus_proche_rang", clock: "sans_objet", pair_with_without: false, samples_published: true },
    configuration_sha256: configurationSha,
    counts_for_targets: false,
    results: [
      {
        name: "b_cap_bloc_plein_clotures",
        test_id: "TM-44",
        unit: "octets",
        n: echantillons.length,
        connections: null,
        samples: echantillons,
        samples_sha256: null,
        value: null,
        p50: null,
        p95: null,
        p99: null,
        min: Math.min(...echantillons),
        max: Math.max(...echantillons),
        mean: moyenne,
        text_value: null,
        target: null,
        met: null,
        conditions: [
          `bloc de ${EXPEDITEURS} transactions sur le réseau de développement (noortrace-2124-dev, quatre validateurs BFT en boucle locale, binaire noorcore du répertoire d'exécution avec ${METHODE_CERTIFICAT}, SHA-256 ${shaBinaire}), clôtures et ancres mêlées`,
          ...blocs.map((x) => `composition ${x.composition}, répétition ${x.repetition} : bloc ${x.block_number}, ${x.clotures.length} clôture(s) de journaux distincts (${x.clotures.map((c) => c.slug).join(", ")}) et ${x.ancres} ancres`),
          "seuil de deux approbateurs par clôture (PeriodRegistry.submitPeriod, deux signatures) ; une clôture et une ancre capturées par bloc par noortrace-registre capturer --role cloture / --role ancre : bloc-<h>.json, recu-<hachage>.json de chacune des 64 transactions et certificat-<h>.json, réponses JSON-RPC telles que reçues (CT-4 CP-6)",
          "index de capture exclu de la ligne, relevé dans notes",
          `64 expéditeurs d'ancres de test publiés (clé SHA-256(UTF-8("${PREFIXE}expediteur/<i>"))), une organisation neuve par clôture (clés SHA-256(UTF-8("${PREFIXE_TM44}<organisation>/<nom>"))) ; limite de gaz ${GAZ_ANCRE} par ancre, ${GAZ_CLOTURE} par clôture`,
        ],
        excluded_reason: "hors_systeme_de_reference",
      },
    ],
    notes:
      `TM-44 (CT-8 EX-9.1 ; réserve de CT-8 §9.2 sur b_cap, mesuré par TM-31 sur un bloc d'ancres seules). Relevé de tailles, ${compositions.length} composition(s) (${compositions.map((k) => `${k} clôture(s) et ${EXPEDITEURS - k} ancres`).join(" ; ")}), ${repetitions} répétitions par composition sans échauffement, deux captures par bloc : max ${Math.max(...echantillons)} octets (ligne b_cap_bloc_plein_clotures, index exclu). ${decomposition}. ` +
      `Plus grande capture index compris : ${maxIndexCompris} octets, ${maxIndexCompris > B_CAP ? "au-delà" : "en deçà ou égale"} de b_cap = ${B_CAP} octets de CT-8 §9.2 (TM-31, index compris). ` +
      (essaisRates.length ? `Essais repris : ${JSON.stringify(essaisRates)} ; clôtures abandonnées (journaux dont la clôture a été incluse hors d'un bloc plein) : ${cloturesAbandonnees.join(", ")}. ` : "Aucun essai repris. ") +
      `Mesure faite du ${debut.toISOString()} au ${fin.toISOString()} hors du système de référence de CT-9 §11.1 (machine virtuelle, disque virtuel) : elle ne compte pour aucune cible ; TM-44 n'a pas de cible (aucune_cible). ` +
      `Configuration (configuration_sha256) : ${JSON.stringify(configuration)}.` +
      (arbreModifie ? " Commit : tête du dépôt au moment de la mesure, arbre de travail modifié." : ""),
  };
  const schema = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", "plan-de-tests-v0.schema.json"), "utf8"));
  const erreurs = J.validerSchema(rapport, schema, { registre: { [schema.$id]: schema }, fragment: "#/$defs/rapport_mesure" });
  if (erreurs.length) throw new Echec(`rapport non conforme à plan-de-tests-v0#/$defs/rapport_mesure : ${erreurs[0].chemin} : ${erreurs[0].message}`);
  const fRapport = path.resolve(o.rapport ?? path.join(E, `rapport-${rapport.date}-capture-bloc-plein-clotures.json`));
  if (fs.existsSync(fRapport)) throw new Echec(`${fRapport} existe déjà : un rapport n'est jamais remplacé (EX-11.11)`, 2);
  fs.writeFileSync(fRapport, J.texteJSON(rapport));
  const v = validerRapport(fRapport, path.basename(fRapport));
  if (v.code !== 0) throw new Echec(`rapport refusé par scripts/tests/mesures.mjs : ${(v.ecarts ?? []).join(" ; ") || v.texte.slice(-1000)}`);
  fs.writeFileSync(path.join(E, "blocs.json"), J.texteJSON({ blocs, essais_repris: essaisRates, clotures_abandonnees: cloturesAbandonnees }));
  log(`rapport écrit et validé par scripts/tests/mesures.mjs : ${fRapport}`);
  stdout.write(J.texteJSON(rapport));
  return { code, rapport, fichier: fRapport };
}

/** Chemin réel d'un fichier (liens symboliques résolus), ou null ; la garde de lancement le compare à celui du module. */
function cheminReel(p) {
  try {
    return fs.realpathSync(path.resolve(p));
  } catch {
    return null;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === cheminReel(process.argv[1])) {
  mesurer().then(
    ({ code }) => {
      process.exitCode = code;
    },
    (err) => {
      process.stderr.write(`mesure-capture-bloc-plein : ${err?.message ?? err}\n`);
      process.exitCode = err instanceof Echec ? err.code : 1;
    },
  );
}
