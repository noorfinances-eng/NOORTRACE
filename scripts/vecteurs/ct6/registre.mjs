// Vecteurs CT-6 de la famille registre (spec/CT-6-verificateur.md, annexe A,
// A.2, A.5 et A.7) : module appelé par le générateur des vecteurs CT-6, et
// exécutable seul.
//
//   node scripts/vecteurs/ct6/registre.mjs [--sortie spec/vecteurs/ct-6/registre]
//
// Entrée : la capture unique registre/capture/ (scripts/vecteurs/capturer-ct6.mjs),
// lue et jamais réécrite. Sorties, réécrites à l'identique à chaque exécution
// (aucune date, aucun aléa : signatures secp256k1 RFC 6979) :
//
//   periode-1/   registre.json, certificat-commit.json, validateurs.json de la
//                période 1 (inscriptions de rec-test-01 et rec-test-02, ancre
//                et clôture de la période 1), parties du dossier
//                valide-seq-7-complet ;
//   periode-2/   idem pour la période 2 (inscription de rec-test-02, ancre et
//                clôture de la période 2), qui sert à R-9 ;
//   variantes/   les parties altérées des dossiers invalides de A.7, une
//                variante par vérification R- (et N-4), plus deux variantes
//                valides qui portent un avertissement (AV-R-1, AV-R-2) ;
//   attendu.json hachages BFT et préimages, racines et encodages des reçus,
//                événements décodés, signataires des certificats ; vecteurs de
//                trie synthétiques ; ancres registry et recorders de test ;
//                statut attendu de chaque vérification pour chaque jeu de
//                parties.
//
// Les statuts attendus sont écrits par construction (ce que chaque variante
// altère), puis confrontés à scripts/lib/registre.mjs : un écart arrête la
// génération. Les implémentations tierces de spec/vecteurs/ct-6/confrontation/
// (go-ethereum, noorcore, scripts/verify/certificat-commit.mjs) les recalculent.

import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { analyserEnveloppe, clePubliqueDe, hachageJeuValidateurs, signerEnveloppe } from "../../lib/certificat-commit.mjs";
import { hachageManifeste } from "../../lib/journal.mjs";
import * as R from "../../lib/registre.mjs";

const RACINE = fileURLToPath(new URL("../../../", import.meta.url));
export const REPERTOIRE_REGISTRE = path.join(RACINE, "spec", "vecteurs", "ct-6", "registre");

/** Entrées que le générateur efface et réécrit sous registre/ ; capture/ n'en fait jamais partie. */
export const ENTREES_GENEREES = ["periode-1", "periode-2", "variantes", "trie.json", "attendu.json"];

const SOURCE_JEU = "validators.json du réseau de développement, clés publiques seulement";
const SOURCE_REGISTRE_ANCRE = "réseau de développement noortrace-2124-dev de chain/README.md ; adresses de deployments/noorcore.json reprises dans capture.json";
const SOURCE_CLE = "clé de test de CT-1 §13 ; clé de chaîne de l'annexe A de CT-6 (graine publiée)";
const ETIQUETTE_SUBSTITUT = (n) => `noortrace/vecteurs/v0/ct-6/validateur-substitue/v${n}`;

function exiger(condition, message) {
  if (!condition) throw new Error(`génération interrompue : ${message}`);
}

function sha256Hex(octets) {
  return "0x" + createHash("sha256").update(octets).digest("hex");
}

function lireJSON(fichier) {
  return JSON.parse(fs.readFileSync(fichier, "utf8"));
}

function texteJSON(valeur) {
  return JSON.stringify(valeur, null, 2) + "\n";
}

function copie(valeur) {
  return JSON.parse(JSON.stringify(valeur));
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

/**
 * Lit la capture : capture.json, réponses JSON-RPC brutes des blocs, reçus et
 * certificats, validators.json. Rend {description, blocs (Map h -> result),
 * recus (Map hash -> result), certificats (Map h -> result), validators}.
 */
export function lireCapture(repertoire = path.join(REPERTOIRE_REGISTRE, "capture")) {
  const description = lireJSON(path.join(repertoire, "capture.json"));
  const blocs = new Map();
  const recus = new Map();
  const certificats = new Map();
  for (const t of description.transactions) {
    const h = t.bloc;
    const bloc = lireJSON(path.join(repertoire, t.fichiers.bloc));
    exiger(bloc.result && Number(BigInt(bloc.result.number)) === h, `bloc ${h} de la capture`);
    blocs.set(h, bloc.result);
    for (const f of t.fichiers.recus) {
      const r = lireJSON(path.join(repertoire, f)).result;
      recus.set(r.transactionHash.toLowerCase(), r);
    }
    const c = lireJSON(path.join(repertoire, t.fichiers.certificat));
    exiger(c.result && Number(BigInt(c.result.height)) === h, `certificat ${h} de la capture`);
    certificats.set(h, c.result);
  }
  const validators = lireJSON(path.join(repertoire, "validators.json"));
  return { repertoire, description, blocs, recus, certificats, validators };
}

/** Transaction de la capture par rôle et clé ou période. */
function transaction(capture, role, { key_id, periode } = {}) {
  const t = capture.description.transactions.find((x) => x.role === role && (key_id === undefined || x.key_id === key_id) && (periode === undefined || x.periode === periode));
  exiger(t, `transaction ${role} ${key_id ?? periode ?? ""} absente de la capture`);
  return t;
}

/** Entrée de registre.json d'une transaction de la capture. */
function entree(capture, t) {
  const bloc = capture.blocs.get(t.bloc);
  const recus = bloc.transactions.map((x) => capture.recus.get(x.toLowerCase()));
  return R.entreeRegistre({ role: t.role, bloc, recus, transactionHash: t.hash, logIndex: 0 });
}

function sourceRegistre(capture) {
  return `réseau de développement ${capture.description.chain_id}, nœud v1, capture unique du ${capture.description.date.slice(0, 10)} (spec/vecteurs/ct-6/registre/capture, capture.json)`;
}

/** Jeu de validateurs du réseau, dans la forme de validateurs.json et de l'ancre (hauteurs 1 et suivantes). */
function jeuReseau(capture, validators = capture.validators.validators) {
  return { from_height: 1, to_height: null, validators: validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex.toLowerCase() })), source: SOURCE_JEU };
}

/** Les trois parties du contrôle 8 d'une liste de transactions de la capture. */
function parties(capture, transactions) {
  const entrees = transactions.map((t) => entree(capture, t));
  const hauteurs = [...new Set(transactions.map((t) => t.bloc))];
  return {
    registre: { version: 0, source: sourceRegistre(capture), entries: entrees },
    certificat_commit: { version: 0, certificates: hauteurs.map((h) => copie(capture.certificats.get(h))) },
    validateurs: { version: 0, sets: [jeuReseau(capture)] },
  };
}

/** Parties de la période 1 (dossier valide-seq-7-complet) ou de la période 2. */
export function partiesPeriode(capture, n) {
  const transactions =
    n === 1
      ? [transaction(capture, "inscription", { key_id: "rec-test-01" }), transaction(capture, "inscription", { key_id: "rec-test-02" }), transaction(capture, "ancre", { periode: 1 }), transaction(capture, "cloture", { periode: 1 })]
      : [transaction(capture, "inscription", { key_id: "rec-test-02" }), transaction(capture, "ancre", { periode: 2 }), transaction(capture, "cloture", { periode: 2 })];
  return parties(capture, transactions);
}

// ---------------------------------------------------------------------------
// Ancres de test (A.6) : parties registry et recorders
// ---------------------------------------------------------------------------

/** Ancre `registry` de ancres-test.json : chain_id, adresses et jeu de validateurs de la capture. */
export function ancreRegistre(capture) {
  const c = capture.description.contrats;
  return {
    chain_id: capture.description.chain_id,
    contracts: { period_registry: c.period_registry, attestation_registry: c.attestation_registry, recorder_registry: c.recorder_registry },
    validator_sets: [jeuReseau(capture)],
    source: SOURCE_REGISTRE_ANCRE,
  };
}

/** Entrées `recorders` de ancres-test.json : rec-test-01 et rec-test-02 avec leurs clés de chaîne. */
export function ancresEnregistreurs(capture) {
  return ["rec-test-01", "rec-test-02"].map((key_id) => {
    const t = transaction(capture, "inscription", { key_id });
    return {
      org_id: capture.description.organisation.org_id,
      journal_id: capture.description.journal.journal_id,
      key_id,
      public_key: t.ed25519_public_key,
      chain_key: t.chain_key,
      source: SOURCE_CLE,
    };
  });
}

/**
 * Modifications des fichiers d'ancres de A.6 qui touchent le contrôle 8, en
 * pointeurs JSON (RFC 6901) appliqués à ancres-test.json.
 */
export function modificationsAncres(capture) {
  const enregistreurs = ancresEnregistreurs(capture);
  const jeu = jeuReseau(capture);
  const hauteurs = capture.description.transactions.filter((t) => ["inscription", "ancre", "cloture"].includes(t.role)).map((t) => BigInt(t.bloc));
  // Coupure entre l'ancre (période 1) et la clôture (période 1) : les blocs de
  // la période 1 relèvent de deux jeux (EX-11.22, proposition à deux groupes).
  const tAncre = BigInt(transaction(capture, "ancre", { periode: 1 }).bloc);
  const tCloture = BigInt(transaction(capture, "cloture", { periode: 1 }).bloc);
  exiger(tAncre < tCloture && hauteurs.length > 0, "ancre de la période 1 avant sa clôture");
  const coupure = Number(tAncre + 1n);
  return {
    "ancres-autre-chaine.json": [{ pointer: "/registry/chain_id", value: "noortrace-9999-test" }],
    "ancres-autre-registre.json": [{ pointer: "/registry/contracts/period_registry", value: capture.description.contrats.attestation_registry }],
    "ancres-cle-chaine-autre.json": [{ pointer: "/recorders/1/chain_key", value: enregistreurs[0].chain_key }],
    "ancres-sans-enregistreurs.json": [{ pointer: "/recorders", value: [] }],
    "ancres-enregistreur-01-seul.json": [{ pointer: "/recorders", value: [enregistreurs[0]] }],
    "ancres-deux-jeux.json": [
      {
        pointer: "/registry/validator_sets",
        value: [
          { ...jeu, from_height: 1, to_height: coupure - 1, source: `${SOURCE_JEU} (premier jeu déclaré : hauteurs 1 à ${coupure - 1})` },
          { ...jeu, from_height: coupure, to_height: null, source: `${SOURCE_JEU} (second jeu déclaré : hauteurs ${coupure} et suivantes)` },
        ],
      },
    ],
  };
}

/** Applique des modifications {pointer, value} à une copie d'un objet. */
export function appliquerModifications(objet, modifications = []) {
  const out = copie(objet);
  for (const { pointer, value } of modifications) {
    const segments = pointer.split("/").slice(1).map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cible = out;
    for (const s of segments.slice(0, -1)) cible = cible[s];
    cible[segments[segments.length - 1]] = value;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Variantes (A.7)
// ---------------------------------------------------------------------------

function clePriveeSubstitut(n) {
  return sha256Hex(Buffer.from(ETIQUETTE_SUBSTITUT(n), "utf8"));
}

/** Jeu substitué v1 à v4 (clés publiques non compressées). */
export function jeuSubstitue() {
  return [1, 2, 3, 4].map((n) => ({ id: `v${n}`, pubKeyHex: clePubliqueDe(clePriveeSubstitut(n)) }));
}

/**
 * Re-signe un certificat par le jeu substitué : mêmes corps, même blockHash,
 * mêmes identifiants de validateurs ; valsetHash = hachage du jeu substitué.
 * Les champs informatifs du nœud (sig décodée, validatorSet,
 * validatorSetHash) sont mis en accord, comme le ferait un faussaire soigneux.
 */
function reSigner(certificat) {
  const jeu = jeuSubstitue();
  const hachage = hachageJeuValidateurs(jeu);
  const cles = new Map([1, 2, 3, 4].map((n) => [`v${n}`, clePriveeSubstitut(n)]));
  const resigner = (ligne) => {
    const env = analyserEnveloppe(ligne);
    const nouvelle = signerEnveloppe(
      { type: env.type, chainId: env.chainId, valsetHash: hachage, validatorId: env.validatorId, height: env.height, round: env.round, blockHash: env.blockHash, body: env.corpsBrut },
      cles.get(env.validatorId),
    );
    return { ligne: nouvelle, sig: "0x" + analyserEnveloppe(nouvelle).sig.toString("hex") };
  };
  const c = copie(certificat);
  c.valsetHash = hachage;
  const p = resigner(c.proposal.line);
  c.proposal.line = p.ligne;
  if ("sig" in c.proposal) c.proposal.sig = p.sig;
  for (const pc of c.precommits) {
    const r = resigner(pc.line);
    pc.line = r.ligne;
    if ("sig" in pc) pc.sig = r.sig;
  }
  if ("validatorSet" in c) c.validatorSet = jeu;
  if ("validatorSetHash" in c) c.validatorSetHash = hachage;
  return c;
}

function quantiteHex(n) {
  return "0x" + BigInt(n).toString(16);
}

/**
 * Les variantes du contrôle 8. Chacune : {nom, cible, description, parties
 * (objet {registre, certificat_commit, validateurs} ou null quand les parties
 * sont celles de la période 1), modifications_ancres (null : ancres-test.json),
 * ancres (nom du fichier d'ancres de A.6), attendu}.
 */
export function variantes(capture) {
  const p1 = partiesPeriode(capture, 1);
  const p2 = partiesPeriode(capture, 2);
  const mods = modificationsAncres(capture);
  const indice = (p, role) => p.registre.entries.findIndex((e) => e.role === role);
  const hauteur = (e) => e.block.number;
  const out = [];
  const ajouter = (v) => out.push({ parties: null, ancres: "ancres-test.json", modifications_ancres: null, ...v });

  // R-1 : entrée ancre retirée.
  {
    const p = copie(p1);
    p.registre.entries.splice(indice(p, "ancre"), 1);
    ajouter({
      nom: "invalide-r1-sans-ancre",
      cible: "R-1",
      description: "entrée ancre retirée de registre.json (son certificat reste) : le schéma exige une entrée ancre",
      parties: p,
      attendu: { failed_checks: ["R-1"], not_executed: ["R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-4"].map((id) => ({ id, reason: "prerequis_en_echec" })), warnings: [] },
    });
  }
  // R-2 : jeu substitué, validateurs.json assorti.
  {
    const p = copie(p1);
    p.certificat_commit.certificates = p.certificat_commit.certificates.map(reSigner);
    p.validateurs.sets = [{ ...jeuReseau(capture, jeuSubstitue()), source: "jeu substitué des vecteurs CT-6 (graines publiées), déclaré par l'exportateur" }];
    ajouter({
      nom: "invalide-r2-jeu-substitue",
      cible: "R-2",
      description: "certificats re-signés (mêmes corps, même blockHash) par quatre validateurs v1 à v4 de clés SHA-256(UTF-8(\"noortrace/vecteurs/v0/ct-6/validateur-substitue/vN\")) ; validateurs.json déclare ce jeu",
      parties: p,
      attendu: { failed_checks: ["R-2"], not_executed: [{ id: "R-5", reason: "prerequis_en_echec" }, { id: "N-4", reason: "prerequis_en_echec" }], warnings: [] },
    });
  }
  // R-3 : validateurs.json déclare un autre jeu.
  {
    const p = copie(p1);
    const v4 = p.validateurs.sets[0].validators.find((v) => v.id === "v4");
    v4.pubKeyHex = jeuSubstitue()[0].pubKeyHex;
    ajouter({
      nom: "invalide-r3-validateurs-declares",
      cible: "R-3",
      description: "clé de v4 remplacée, dans validateurs.json, par celle du v1 substitué",
      parties: p,
      attendu: { failed_checks: ["R-3"], not_executed: [], warnings: [] },
    });
  }
  // R-4 : ancre d'une autre chaîne.
  ajouter({
    nom: "invalide-r4-autre-chaine",
    cible: "R-4",
    description: "ancres ancres-autre-chaine.json : chain_id noortrace-9999-test",
    ancres: "ancres-autre-chaine.json",
    modifications_ancres: mods["ancres-autre-chaine.json"],
    attendu: { failed_checks: ["R-4"], not_executed: [], warnings: [] },
  });
  // R-5 : une ligne de precommit retirée du certificat de la clôture.
  {
    const p = copie(p1);
    const h = hauteur(p.registre.entries[indice(p, "cloture")]);
    const c = p.certificat_commit.certificates.find((x) => x.height === h);
    exiger(c.precommits.length === 3, "le certificat de la clôture capturé porte exactement le quorum (3 precommits)");
    c.precommits.pop();
    if (c.quorum && typeof c.quorum === "object") c.quorum.precommits = c.precommits.length;
    ajouter({
      nom: "invalide-r5-quorum",
      cible: "R-5",
      description: "dernière ligne de precommit retirée du certificat de la clôture, qui portait le quorum exact (3 sur 4) : 2 signataires",
      parties: p,
      attendu: { failed_checks: ["R-5"], not_executed: [], warnings: [] },
    });
  }
  // R-6 : en-tête de la clôture modifié.
  {
    const p = copie(p1);
    const e = p.registre.entries[indice(p, "cloture")];
    e.block.timestamp = quantiteHex(BigInt(e.block.timestamp) + 1n);
    ajouter({
      nom: "invalide-r6-entete-modifie",
      cible: "R-6",
      description: "timestamp + 1 dans block de l'entrée cloture",
      parties: p,
      attendu: { failed_checks: ["R-6"], not_executed: [{ id: "R-8", reason: "prerequis_en_echec" }, { id: "R-9", reason: "prerequis_en_echec" }], warnings: [] },
    });
  }
  // R-7 : reçu de la clôture falsifié, blockHash certifié intact.
  {
    const p = copie(p1);
    const e = p.registre.entries[indice(p, "cloture")];
    e.receipts[e.transaction_index].logs[e.log_index].topics[2] = "0x" + "11".repeat(32);
    ajouter({
      nom: "invalide-r7-recu-falsifie",
      cible: "R-7",
      description: "topics[2] (periodHash) du journal de la clôture remplacé par 0x11…11",
      parties: p,
      attendu: { failed_checks: ["R-7"], not_executed: [{ id: "R-8", reason: "prerequis_en_echec" }, { id: "R-9", reason: "prerequis_en_echec" }], warnings: [] },
    });
  }
  // R-8 : l'ancre désigne un autre contrat pour la clôture.
  ajouter({
    nom: "invalide-r8-autre-contrat",
    cible: "R-8",
    description: "ancres ancres-autre-registre.json : period_registry = adresse d'AttestationRegistry",
    ancres: "ancres-autre-registre.json",
    modifications_ancres: mods["ancres-autre-registre.json"],
    attendu: { failed_checks: ["R-8"], not_executed: [], warnings: [] },
  });
  // R-9 : clôture et ancre d'une autre période.
  {
    const p = copie(p1);
    for (const role of ["ancre", "cloture"]) {
      const i = indice(p, role);
      const ancienne = hauteur(p.registre.entries[i]);
      const nouvelle = copie(p2.registre.entries[indice(p2, role)]);
      p.registre.entries[i] = nouvelle;
      const j = p.certificat_commit.certificates.findIndex((x) => x.height === ancienne);
      p.certificat_commit.certificates[j] = copie(p2.certificat_commit.certificates.find((x) => x.height === hauteur(nouvelle)));
    }
    ajouter({
      nom: "invalide-r9-cloture-autre-periode",
      cible: "R-9",
      description: "entrées cloture et ancre et leurs certificats pris dans registre/periode-2/",
      parties: p,
      attendu: { failed_checks: ["R-9"], not_executed: [], warnings: [] },
    });
  }
  // R-10 : inscription d'une clé étrangère au dossier.
  {
    const p = copie(p1);
    const t = transaction(capture, "inscription", { key_id: "rec-test-03" });
    p.registre.entries.splice(indice(p, "ancre"), 0, entree(capture, t));
    const certs = p.certificat_commit.certificates;
    certs.splice(certs.findIndex((x) => BigInt(x.height) > BigInt(t.bloc)), 0, copie(capture.certificats.get(t.bloc)));
    ajouter({
      nom: "invalide-r10-inscription-cle-inconnue",
      cible: "R-10",
      description: "entrée inscription de rec-test-03 (clé absente de cles.json) et certificat de son bloc ajoutés",
      parties: p,
      attendu: { failed_checks: ["R-10"], not_executed: [], warnings: [] },
    });
  }
  // N-4 : l'ancre donne une autre clé de chaîne pour la clé du manifeste.
  ajouter({
    nom: "invalide-n4-cle-chaine",
    cible: "N-4",
    description: "ancres ancres-cle-chaine-autre.json : chain_key de rec-test-02 remplacée par celle de rec-test-01",
    ancres: "ancres-cle-chaine-autre.json",
    modifications_ancres: mods["ancres-cle-chaine-autre.json"],
    attendu: { failed_checks: ["N-4"], not_executed: [], warnings: [] },
  });
  // Valide, sans inscription : R-10 non exécutée, AV-R-1.
  {
    const p = copie(p1);
    const garder = p.registre.entries.filter((e) => e.role !== "inscription");
    const hauteurs = new Set(garder.map((e) => e.block.number));
    p.registre.entries = garder;
    p.certificat_commit.certificates = p.certificat_commit.certificates.filter((c) => hauteurs.has(c.height));
    ajouter({
      nom: "valide-sans-inscription",
      cible: null,
      description: "entrées inscription et leurs certificats retirés : R-10 non exécutée (partie_absente), sans effet sur le contrôle 8 ; avertissement AV-R-1",
      parties: p,
      attendu: { failed_checks: [], not_executed: [{ id: "R-10", reason: "partie_absente" }], warnings: ["AV-R-1"] },
    });
  }
  // Valide, provenance mixte des clés (EX-6.8) : l'inscription de rec-test-01 et le
  // certificat de son bloc retirés ; le fichier d'ancres ne donne que rec-test-01.
  {
    const p = copie(p1);
    const h01 = transaction(capture, "inscription", { key_id: "rec-test-01" }).bloc;
    p.registre.entries = p.registre.entries.filter((e) => !(e.role === "inscription" && BigInt(e.block.number) === BigInt(h01)));
    p.certificat_commit.certificates = p.certificat_commit.certificates.filter((c) => BigInt(c.height) !== BigInt(h01));
    ajouter({
      nom: "valide-provenance-mixte",
      cible: null,
      description: "inscription de rec-test-01 et certificat de son bloc retirés ; ancres ancres-enregistreur-01-seul.json (recorders réduit à rec-test-01) : N-3 confirme rec-test-01, R-10 prouve l'inscription de rec-test-02, N-4 ne figure pas",
      parties: p,
      ancres: "ancres-enregistreur-01-seul.json",
      modifications_ancres: mods["ancres-enregistreur-01-seul.json"],
      attendu: { failed_checks: [], not_executed: [], warnings: [], n4_present: false },
    });
  }
  // Valide, deux jeux de validateurs déclarés par l'ancre (EX-11.22) : les blocs de la
  // période 1 relèvent de l'un ou de l'autre.
  ajouter({
    nom: "valide-deux-jeux",
    cible: null,
    description: "ancres ancres-deux-jeux.json : registry.validator_sets coupé en deux jeux de mêmes clés, l'un jusqu'au bloc de l'ancre, l'autre au-delà ; la proposition de l'énoncé nomme deux groupes de blocs",
    ancres: "ancres-deux-jeux.json",
    modifications_ancres: mods["ancres-deux-jeux.json"],
    attendu: { failed_checks: [], not_executed: [], warnings: [] },
  });
  // Valide, ligne acceptée sous une forme non canonique : AV-R-2.
  {
    const p = copie(p1);
    const h = hauteur(p.registre.entries[indice(p, "cloture")]);
    const c = p.certificat_commit.certificates.find((x) => x.height === h);
    exiger(c.precommits[0].line.startsWith('{"domain":'), "forme canonique de la première ligne de precommit");
    c.precommits[0].line = '{"Domain":' + c.precommits[0].line.slice('{"domain":'.length);
    ajouter({
      nom: "valide-ligne-non-canonique",
      cible: null,
      description: "membre « domain » écrit « Domain » dans la première ligne de precommit de la clôture : le décodeur du nœud l'accepte (noms sans casse) et la signature ne couvre pas les noms ; avertissement AV-R-2",
      parties: p,
      attendu: { failed_checks: [], not_executed: [], warnings: ["AV-R-2"] },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Vecteurs de trie synthétiques
// ---------------------------------------------------------------------------

function octetsEtiquette(etiquette, longueur) {
  let out = Buffer.alloc(0);
  for (let i = 0; out.length < longueur; i++) out = Buffer.concat([out, R.keccak(Buffer.from(`${etiquette}/${i}`, "utf8"))]);
  return out.subarray(0, longueur);
}

/** Reçus synthétiques déterministes : types 0 à 4, statuts 0 et 1, 0 à 3 journaux de 0 à 4 sujets (24 premiers reçus). */
export function recusSynthetiques(n) {
  const recus = [];
  let cumul = 0n;
  for (let i = 0; i < n; i++) {
    cumul += 21000n + BigInt(i * 1013);
    const logs = [];
    // Journaux sur les 24 premiers reçus seulement : au-delà, la taille du fichier
    // ne sert pas le trie, que des reçus sans journal exercent aussi bien.
    for (let j = 0; j < (i < 24 ? i % 4 : 0); j++) {
      const base = `noortrace/vecteurs/v0/ct-6/trie/${n}/${i}/${j}`;
      logs.push({
        address: "0x" + octetsEtiquette(`${base}/adresse`, 20).toString("hex"),
        topics: Array.from({ length: (i + j) % 5 }, (_, k) => "0x" + octetsEtiquette(`${base}/sujet/${k}`, 32).toString("hex")),
        data: "0x" + octetsEtiquette(`${base}/donnees`, (i * 7 + j * 13) % 97).toString("hex"),
      });
    }
    recus.push({ type: "0x" + (i % 5).toString(16), status: i % 3 === 0 ? "0x0" : "0x1", cumulativeGasUsed: "0x" + cumul.toString(16), logs });
  }
  return recus;
}

/** Couples synthétiques à petites valeurs : nœuds de moins de 32 octets insérés dans leur parent. */
export function couplesGeneriques(n) {
  return Array.from({ length: n }, (_, i) => ({
    cle: R.rlp(R.octetsEntier(i)),
    valeur: octetsEtiquette(`noortrace/vecteurs/v0/ct-6/trie-generique/${n}/${i}`, (i % 31) + 1),
  }));
}

export const TAILLES_TRIE_RECUS = [1, 2, 3, 16, 17, 130];
export const TAILLES_TRIE_GENERIQUE = [1, 2, 3, 20, 200];

// ---------------------------------------------------------------------------
// Attendus
// ---------------------------------------------------------------------------

function manifeste(n) {
  return lireJSON(path.join(RACINE, `spec/vecteurs/ct-1/manifestes/periode-${n}.json`));
}

function clesDossier() {
  return lireJSON(path.join(RACINE, "spec/vecteurs/ct-1/dossiers/valide-seq-7/cles.json")).keys.map((k) => ({ key_id: k.key_id, public_key: k.public_key }));
}

/** Registre des schémas employés par le contrôle 8. */
export function schemasRegistre() {
  const docs = ["registre-v0.schema.json", "validateurs-v0.schema.json"].map((f) => lireJSON(path.join(RACINE, "spec", "schemas", f)));
  return Object.fromEntries(docs.map((d) => [d.$id, d]));
}

/** Octets des trois parties, comme le dossier les écrit (JSON indenté de 2 espaces et saut de ligne). */
export function octetsParties(p) {
  const o = (v) => (v === null ? { present: false, raison: "absent de cette variante" } : { present: true, octets: Buffer.from(texteJSON(v)) });
  return { registre: o(p.registre), certificat_commit: o(p.certificat_commit), validateurs: o(p.validateurs) };
}

/** Exécute le contrôle 8 de référence sur un jeu de parties. */
export function executer(capture, p, { periode = 1, ancres = "test", modifications = null, schemas = schemasRegistre(), langue = "fr" } = {}) {
  const m = manifeste(periode);
  let fichierAncres = null;
  if (ancres === "test") fichierAncres = appliquerModifications({ registry: ancreRegistre(capture), recorders: ancresEnregistreurs(capture) }, modifications ?? []);
  return R.verifierControle8({ parties: octetsParties(p), manifeste: m, periodHash: hachageManifeste(m), cles: clesDossier(), ancres: fichierAncres, schemas, langue });
}

/** Résumé d'un résultat du contrôle 8 dans la forme des attendus. */
export function resumer(r) {
  const toutes = [...r.verifications, ...(r.n4 ? [r.n4] : [])];
  return {
    control_status: r.statut,
    control_reason: r.raison,
    failed_checks: toutes.filter((v) => v.status === "echoue").map((v) => v.id),
    not_executed: toutes.filter((v) => v.status === "non_execute").map((v) => ({ id: v.id, reason: v.reason })),
    warnings: r.avertissements.map((a) => a.id),
    n4_present: r.n4 !== null,
  };
}

function statutsDe(r) {
  return Object.fromEntries([...r.verifications, ...(r.n4 ? [r.n4] : [])].map((v) => [v.id, v.status === "non_execute" ? `non_execute:${v.reason}` : v.status]));
}

function confronter(nom, attendu, obtenu) {
  const a = JSON.stringify(attendu);
  const o = JSON.stringify(obtenu);
  exiger(a === o, `${nom} : attendu ${a}, obtenu ${o}`);
}

/** Description d'un bloc capturé pour attendu.json (recalculs et décodages). */
function descriptionBloc(capture, t) {
  const e = entree(capture, t);
  const c = capture.certificats.get(t.bloc);
  const journal = e.receipts[e.transaction_index].logs[e.log_index];
  const decode = R.decoderJournal(t.role, journal);
  exiger(decode.erreurs.length === 0, `journal du bloc ${t.bloc} : ${decode.erreurs.join(" ; ")}`);
  const jeu = capture.validators;
  const env = (l) => analyserEnveloppe(l);
  return {
    height: t.bloc,
    role: t.role,
    ...(t.key_id ? { key_id: t.key_id } : {}),
    ...(t.periode ? { periode: t.periode } : {}),
    transaction_hash: t.hash,
    transaction_index: e.transaction_index,
    bft_preimage: "0x" + R.preimageBloc(e.block).toString("hex"),
    bft_block_hash: R.hachageBlocBFT(e.block),
    block_hash_served: e.block.hash,
    receipts_root: R.racineRecus(e.receipts),
    receipts_root_served: e.block.receiptsRoot,
    receipt_encodings: e.receipts.map((r) => "0x" + R.encodageRecu(r).toString("hex")),
    block_time: R.instantRFC3339(BigInt(e.block.timestamp)),
    emitter: journal.address,
    event: decode.valeurs,
    certificate: {
      chain_id: c.chainId,
      round: Number(BigInt(c.round)),
      valset_hash: c.valsetHash,
      valset_hash_recomputed: hachageJeuValidateurs(jeu),
      proposer: env(c.proposal.line).validatorId,
      precommit_signers: c.precommits.map((p) => env(p.line).validatorId),
    },
  };
}

/**
 * Construit tout le contenu de registre/ (hors capture/) en mémoire et le
 * confronte au contrôle 8 de référence. Rend {fichiers: Map(relatif -> texte), attendu}.
 */
export function construireRegistre(capture = lireCapture()) {
  const d = capture.description;
  exiger(d.chain_id === "noortrace-2124-dev", "chain_id de la capture");
  exiger(hachageJeuValidateurs(capture.validators) === capture.certificats.values().next().value.valsetHash, "valsetHash des certificats = hachage de validators.json");
  const schemas = schemasRegistre();
  const fichiers = new Map();
  const p1 = partiesPeriode(capture, 1);
  const p2 = partiesPeriode(capture, 2);
  for (const [nom, p] of [["periode-1", p1], ["periode-2", p2]]) {
    fichiers.set(`${nom}/registre.json`, texteJSON(p.registre));
    fichiers.set(`${nom}/certificat-commit.json`, texteJSON(p.certificat_commit));
    fichiers.set(`${nom}/validateurs.json`, texteJSON(p.validateurs));
  }

  // Jeux de parties valides : statuts attendus par construction.
  const tousReussis = ["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-4"];
  const configurations = [
    { nom: "periode-1, ancres-test.json", repertoire: "periode-1", parties: p1, periode: 1, ancres: "test", attendu: { control_status: "reussi", control_reason: null, failed_checks: [], not_executed: [], warnings: [], n4_present: true } },
    { nom: "periode-2, ancres-test.json", repertoire: "periode-2", parties: p2, periode: 2, ancres: "test", attendu: { control_status: "reussi", control_reason: null, failed_checks: [], not_executed: [], warnings: [], n4_present: true } },
    {
      nom: "periode-1, sans fichier d'ancres",
      repertoire: "periode-1",
      parties: p1,
      periode: 1,
      ancres: null,
      attendu: { control_status: "non_execute", control_reason: "ancre_absente", failed_checks: [], not_executed: ["R-2", "R-4", "R-5", "R-8"].map((id) => ({ id, reason: "ancre_absente" })), warnings: [], n4_present: false },
    },
    {
      nom: "periode-1, ancres-sans-enregistreurs.json",
      repertoire: "periode-1",
      parties: p1,
      periode: 1,
      ancres: "test",
      fichierAncres: "ancres-sans-enregistreurs.json",
      modifications: modificationsAncres(capture)["ancres-sans-enregistreurs.json"],
      attendu: { control_status: "reussi", control_reason: null, failed_checks: [], not_executed: [], warnings: [], n4_present: false },
    },
    {
      nom: "periode-1, validateurs.json absent",
      repertoire: "periode-1",
      parties: { ...p1, validateurs: null },
      periode: 1,
      ancres: "test",
      attendu: { control_status: "reussi", control_reason: null, failed_checks: [], not_executed: [{ id: "R-3", reason: "partie_absente" }], warnings: [], n4_present: true },
    },
  ];
  const jeuxAttendus = [];
  for (const cfg of configurations) {
    const r = executer(capture, cfg.parties, { periode: cfg.periode, ancres: cfg.ancres, modifications: cfg.modifications ?? null, schemas });
    confronter(cfg.nom, cfg.attendu, resumer(r));
    jeuxAttendus.push({
      nom: cfg.nom,
      parties: cfg.repertoire,
      validateurs_present: cfg.parties.validateurs !== null,
      manifeste: `spec/vecteurs/ct-1/manifestes/periode-${cfg.periode}.json`,
      ancres: cfg.ancres === "test" ? cfg.fichierAncres ?? "ancres-test.json" : null,
      modifications_ancres: cfg.modifications ?? [],
      ...cfg.attendu,
      statuses: statutsDe(r),
      statement: r.enonce,
      facts: r.faits,
    });
  }
  exiger(Object.keys(statutsDe(executer(capture, p1, { schemas }))).join() === tousReussis.join(), "ordre des vérifications R-1 à R-10 puis N-4");

  // Variantes.
  const listeVariantes = [];
  for (const v of variantes(capture)) {
    const p = v.parties ?? p1;
    const r = executer(capture, p, { periode: 1, ancres: "test", modifications: v.modifications_ancres, schemas });
    const attendu = { control_status: v.attendu.failed_checks.length ? "echoue" : "reussi", control_reason: null, n4_present: true, ...v.attendu };
    const ordre = { control_status: attendu.control_status, control_reason: null, failed_checks: attendu.failed_checks, not_executed: attendu.not_executed, warnings: attendu.warnings, n4_present: attendu.n4_present };
    confronter(v.nom, ordre, resumer(r));
    if (v.parties) {
      fichiers.set(`variantes/${v.nom}/registre.json`, texteJSON(v.parties.registre));
      fichiers.set(`variantes/${v.nom}/certificat-commit.json`, texteJSON(v.parties.certificat_commit));
      fichiers.set(`variantes/${v.nom}/validateurs.json`, texteJSON(v.parties.validateurs));
    }
    listeVariantes.push({
      nom: v.nom,
      cible: v.cible,
      description: v.description,
      parties: v.parties ? `variantes/${v.nom}` : "periode-1",
      validateurs_present: true,
      manifeste: "spec/vecteurs/ct-1/manifestes/periode-1.json",
      ancres: v.ancres,
      modifications_ancres: v.modifications_ancres ?? [],
      ...ordre,
      statuses: statutsDe(r),
    });
  }

  const m1 = manifeste(1);
  const m2 = manifeste(2);
  const attendu = {
    version: 0,
    description:
      "Vecteurs CT-6 de la famille registre (spec/CT-6-verificateur.md, section 11 et annexe A) : recalculs sur la capture unique du réseau de développement, vecteurs de trie synthétiques, ancres de test du contrôle 8 et statuts attendus de R-1 à R-10 et N-4. Les heures des blocs sont celles de la capture (octobre 2026), antérieures aux dates fictives des manifestes (novembre 2026) : sans effet, aucune vérification ne les compare (EX-A.9).",
    capture: {
      date: d.date,
      chain_id: d.chain_id,
      evm_chain_id: d.evm_chain_id,
      noorcore: d.noorcore,
      contrats: d.contrats,
      validators_sha256: d.validateurs.sha256,
      valset_hash: hachageJeuValidateurs(capture.validators),
    },
    manifestes: {
      "periode-1": { fichier: "spec/vecteurs/ct-1/manifestes/periode-1.json", period_hash: hachageManifeste(m1), anchor_fingerprint: R.empreinteAncre(m1.org_id, m1.journal_id, hachageManifeste(m1)) },
      "periode-2": { fichier: "spec/vecteurs/ct-1/manifestes/periode-2.json", period_hash: hachageManifeste(m2), anchor_fingerprint: R.empreinteAncre(m2.org_id, m2.journal_id, hachageManifeste(m2)) },
    },
    constantes: { domaine_bloc_bft: R.DOMAINE_BLOC_BFT, sujets: R.SUJETS_EVENEMENTS, signatures: R.SIGNATURES_EVENEMENTS, doc_type_periode: R.DOC_TYPE_PERIODE },
    blocs: d.transactions.map((t) => descriptionBloc(capture, t)),
    trie: "trie.json",
    ancres: { registry: ancreRegistre(capture), recorders: ancresEnregistreurs(capture), modifications: modificationsAncres(capture) },
    jeu_substitue: { validators: jeuSubstitue(), valset_hash: hachageJeuValidateurs(jeuSubstitue()) },
    jeux_de_parties: jeuxAttendus,
    variantes: listeVariantes,
  };
  fichiers.set("attendu.json", texteJSON(attendu));
  const trie = {
    version: 0,
    description:
      "Vecteurs synthétiques de la racine des reçus (EX-11.5) : listes de reçus de types 0 à 4, de statuts 0 et 1, de 0 à 3 journaux de 0 à 4 sujets, et couples à petites valeurs (nœuds de moins de 32 octets insérés dans leur parent). Octets dérivés d'étiquettes publiées par keccak256 ; racines recalculées par go-ethereum (types.DeriveSha, trie.StackTrie) dans confrontation/.",
    recus: TAILLES_TRIE_RECUS.map((n) => {
      const recus = recusSynthetiques(n);
      return { n, receipts: recus, root: R.racineRecus(recus) };
    }),
    generique: TAILLES_TRIE_GENERIQUE.map((n) => {
      const couples = couplesGeneriques(n);
      return { n, pairs: couples.map((c) => ({ key: "0x" + c.cle.toString("hex"), value: "0x" + c.valeur.toString("hex") })), root: "0x" + R.racineTrie(couples).toString("hex") };
    }),
    vide: "0x" + R.racineTrie([]).toString("hex"),
  };
  fichiers.set("trie.json", texteJSON(trie));
  return { fichiers, attendu, trie };
}

/**
 * Section « registre » de spec/vecteurs/ct-6/INDEX.md (Markdown), à partir de
 * attendu.json : capture, jeux de parties valides, variantes et leur attendu.
 */
export function sectionIndex(attendu) {
  const c = attendu.capture;
  const lignes = [
    "## registre/ (contrôle 8)",
    "",
    `Capture unique du ${c.date} sur le réseau de développement \`${c.chain_id}\` (noorcore \`${c.noorcore.commit.slice(0, 7)}\` et correctif \`${c.noorcore.correctif}\`), procédure dans \`registre/capture/CAPTURE.md\`. Jeu de validateurs de hachage \`${c.valset_hash}\`.`,
    "",
    "| Bloc | Rôle | Hachage BFT | Racine des reçus |",
    "|---|---|---|---|",
    ...attendu.blocs.map((b) => `| ${b.height} | ${b.role}${b.key_id ? ` (${b.key_id})` : ""}${b.periode ? ` (période ${b.periode})` : ""} | \`${b.bft_block_hash}\` | \`${b.receipts_root}\` |`),
    "",
    "| Jeu de parties | Ancres | Contrôle 8 | Non exécutées |",
    "|---|---|---|---|",
    ...attendu.jeux_de_parties.map((j) => `| ${j.nom} | ${j.ancres ?? "aucune"} | ${j.control_status}${j.control_reason ? ` (${j.control_reason})` : ""} | ${j.not_executed.map((n) => `${n.id} (${n.reason})`).join(", ") || "—"} |`),
    "",
    "| Variante | Vérification visée | Ancres | En échec | Non exécutées | Avertissements |",
    "|---|---|---|---|---|---|",
    ...attendu.variantes.map((v) => `| \`${v.nom}\` | ${v.cible ?? "—"} | ${v.ancres} | ${v.failed_checks.join(", ") || "aucune"} | ${v.not_executed.map((n) => `${n.id} (${n.reason})`).join(", ") || "—"} | ${v.warnings.join(", ") || "—"} |`),
    "",
    "Les racines des reçus synthétiques et des couples génériques sont dans `registre/trie.json` ; go-ethereum et noorcore les recalculent dans `confrontation/registre/` (sortie : `confrontation/sorties/registre.txt`).",
    "",
  ];
  return lignes.join("\n");
}

/** Écrit registre/ : efface et réécrit les entrées générées, jamais capture/. Rend la liste des fichiers écrits. */
export function genererRegistre({ sortie = REPERTOIRE_REGISTRE, capture = lireCapture(path.join(sortie, "capture")) } = {}) {
  const { fichiers } = construireRegistre(capture);
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(sortie, e), { recursive: true, force: true });
  for (const [relatif, texte] of fichiers) {
    const f = path.join(sortie, relatif);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, texte);
  }
  return [...fichiers.keys()];
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  const sortie = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_REGISTRE;
  const ecrits = genererRegistre({ sortie });
  process.stdout.write(`registre : ${ecrits.length} fichiers écrits sous ${sortie}\n`);
}
