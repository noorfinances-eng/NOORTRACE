// Capture d'une transaction du registre au moment de son reçu (CT-4 §9.4,
// EX-9.2 à EX-9.5 ; CT-6 EX-13.8) : en-tête `eth_getBlockByNumber(h, false)`,
// reçu de chaque transaction du bloc par `eth_getTransactionReceipt`,
// certificat `noor_getCommitCertificate(h)` (conduite de §9.3), puis CP-1 à
// CP-6 et l'index de capture `operations-registre-v0`. Les réponses sont
// écrites telles que reçues (octets de la réponse JSON-RPC complète) sous
// `bloc-<h>.json`, `recu-<hachage>.json`, `certificat-<h>.json`, l'index sous
// `capture-<h>-<transaction_index>-<rôle>.json`, tous dans le répertoire des
// captures, en création exclusive, synchronisés sur le disque ; une capture
// est idempotente (EX-9.3 : un fichier présent n'est jamais réécrit, il est
// repris s'il passe CP-2 à CP-4).
//
// `verifierCapture` applique CP-2 à CP-6 hors ligne sur des fichiers déjà
// écrits (vecteurs `capture.json` de CT-4) ; `capturer` s'en sert après avoir
// obtenu les réponses.

import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { keccak256 } from "@noortrace/noyau";
import { classerErreurCertificat, jeuPourHauteur, lireCertificat, lireJeux, verifierCertificat } from "./certificat.mjs";
import { EVENEMENT_PAR_ROLE, SUJETS, adresseMinuscule, decoderJournal } from "./encodage.mjs";
import { estHexOctets, octetsEgaux, octetsVersHex, quantiteVersEntier, utf8Octets, utf8Texte, MAX_U64 } from "./octets.mjs";
import { ErreurRpc } from "./rpc.mjs";
import { verifierIndexCapture } from "./schemas.mjs";
import { champsEntete, hachageBlocBft, lireRecu, racineRecus, racineTransactions } from "./trie.mjs";
import { ecrireEntierPuisLier } from "../rfc3161/depot.mjs";

/** Rôles d'un index de capture (schéma). */
export const ROLES_CAPTURE = Object.freeze([
  "deploiement", "jeu_approbateurs", "assignation", "approvisionnement", "inscription", "revocation", "ancre", "cloture", "administration_jeu", "reassignation",
]);

/**
 * Bornes de lecture : réponses JSON-RPC au plus 16 Mio, 256 reçus par bloc
 * (CT-6 §15.1) ; certificat de commit au plus 1 Mio (CT-4 CP-4 : un
 * certificat de quatre validateurs et 64 reçus fait 33 199 octets, campagne
 * TM-44 ; un membre inconnu de 15 Mio passait CP-1 à CP-6 et grossissait
 * `certificat-commit.json` jusqu'aux 64 Mio du dossier).
 */
export const BORNES_CAPTURE = Object.freeze({ fichier: 16 * 1024 * 1024, recus: 256, certificat: 1024 * 1024 });

/** Noms de fichiers d'une capture (CP-6). */
export const nomBloc = (h) => `bloc-${h}.json`;
export const nomRecu = (hash) => `recu-${hash}.json`;
export const nomCertificat = (h) => `certificat-${h}.json`;
export const nomIndex = (h, i, role) => `capture-${h}-${i}-${role}.json`;

const MOTIF_NOM_FICHIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.json$/;

// ----------------------------------------------------------- Lecture

/** Lit un fichier JSON-RPC conservé : octets, SHA-256 et `result` ; null si absent ou illisible. */
export function lireFichierRpc(octets) {
  if (!(octets instanceof Uint8Array) || octets.length === 0 || octets.length > BORNES_CAPTURE.fichier) return null;
  const texte = utf8Texte(octets);
  if (texte === null) return null;
  let json;
  try {
    json = JSON.parse(texte);
  } catch {
    return null;
  }
  if (!json || typeof json !== "object" || !("result" in json)) return null;
  return { octets, sha256: sha256Hex(octets), resultat: json.result, json };
}

/** Lecteur de fichiers d'un répertoire de captures : fichiers ordinaires seulement, sans sous-répertoire. */
export function lecteurRepertoire(repertoire) {
  return {
    lire(nom) {
      if (typeof nom !== "string" || !MOTIF_NOM_FICHIER.test(nom)) return null;
      const chemin = path.join(repertoire, nom);
      try {
        const st = fs.lstatSync(chemin);
        if (!st.isFile() || st.size > BORNES_CAPTURE.fichier) return null;
        return new Uint8Array(fs.readFileSync(chemin));
      } catch {
        return null;
      }
    },
    existe(nom) {
      try {
        return fs.lstatSync(path.join(repertoire, nom)).isFile();
      } catch {
        return false;
      }
    },
  };
}

/** Liste les index de capture (`capture-*.json`) d'un répertoire, lus et validés contre leur schéma. */
export function listerCaptures(repertoire) {
  let noms;
  try {
    noms = fs.readdirSync(repertoire);
  } catch {
    return [];
  }
  const lecteur = lecteurRepertoire(repertoire);
  const sortie = [];
  for (const nom of noms.sort()) {
    const m = /^capture-(\d+)-(\d+)-([a-z_]+)\.json$/.exec(nom);
    if (!m) continue;
    const octets = lecteur.lire(nom);
    const texte = octets ? utf8Texte(octets) : null;
    if (texte === null) continue;
    let index;
    try {
      index = JSON.parse(texte);
    } catch {
      continue;
    }
    if (!verifierIndexCapture(index).valide) continue;
    sortie.push({ nom, index, sha256: sha256Hex(octets), octets });
  }
  return sortie;
}

// ------------------------------------------------------- Vérification

function verif(id, statut, detail = "") {
  return { id, status: statut, detail: detail.slice(0, 1024) };
}

function trouverJournal(recu, { role, contrat, attendu }) {
  const evenement = EVENEMENT_PAR_ROLE[role];
  if (!evenement) return { logIndex: null, journal: null };
  const sujet = SUJETS[evenement];
  for (let k = 0; k < recu.logs.length; k++) {
    const j = recu.logs[k];
    if (j.address !== contrat || j.topics[0] !== sujet) continue;
    if (attendu?.fingerprint && j.topics[1] !== attendu.fingerprint) continue;
    if (attendu?.periodHash && j.topics[2] !== attendu.periodHash) continue;
    return { logIndex: k, journal: j };
  }
  return { logIndex: null, journal: null };
}

/**
 * CP-2 à CP-6 hors ligne. `fichiers` : lecteur `{ lire(nom) → octets|null }`
 * (ou répertoire) ; `index` : l'index de capture (objet) ; `jeux` : jeux de
 * validateurs par hauteur (`lireJeux`) ou un jeu unique ; `bftChainId`.
 * Rend `{ checks: [CP-2…CP-6], verdicts, premierEchec: { check, code }|null,
 * entete, recus, certificat, journal }`.
 */
export function verifierCapture({ fichiers, index, jeux, bftChainId }) {
  const lecteur = typeof fichiers === "string" ? lecteurRepertoire(fichiers) : fichiers;
  const checks = [];
  const echecs = [];
  const noter = (id, ok, detail, code = "capture_incomplete") => {
    checks.push(verif(id, ok ? "reussi" : "echoue", ok ? "" : detail));
    if (!ok) echecs.push({ check: id, code });
  };
  let entete = null;
  let recus = null;
  let certificat = null;
  let journal = null;
  let hauteur = null;

  // Lecture des fichiers désignés par l'index ; la forme de l'index est contrôlée avant tout usage (un index
  // ou un bloc corrompu rend CP-2 à CP-6 `echoue`, jamais une exception).
  if (!index || typeof index !== "object") index = {};
  const nomDe = (f) => (f && typeof f === "object" && typeof f.name === "string" ? f.name : null);
  const fichierBloc = nomDe(index?.files?.block) ? lireFichierRpc(lecteur.lire(index.files.block.name)) : null;
  const fichiersRecus = Array.isArray(index?.files?.receipts) ? index.files.receipts.map((f) => (nomDe(f) ? lireFichierRpc(lecteur.lire(f.name)) : null)) : [];
  const fichierCert = nomDe(index?.files?.certificate) ? lireFichierRpc(lecteur.lire(index.files.certificate.name)) : null;
  const blockNumber = Number.isSafeInteger(index.block_number) && index.block_number >= 0 ? BigInt(index.block_number) : null;
  const indexTxValide = Number.isSafeInteger(index.transaction_index) && index.transaction_index >= 0;

  // CP-2 : en-tête.
  {
    const detail = [];
    entete = fichierBloc ? champsEntete(fichierBloc.resultat) : null;
    const transactions = fichierBloc?.resultat && Array.isArray(fichierBloc.resultat.transactions) ? fichierBloc.resultat.transactions : null;
    if (!entete || !transactions || !transactions.every((t) => estHexOctets(t, 32))) {
      detail.push("en-tête absent ou mal formé");
      entete = null;
    } else {
      hauteur = quantiteVersEntier(entete.number, MAX_U64);
      if (hauteur === null || blockNumber === null || blockNumber !== hauteur) detail.push(`number ${entete.number} différent de block_number ${index.block_number}`);
      if (entete.hash !== index.block_hash) detail.push("hash de l'en-tête différent de block_hash");
      const bft = hachageBlocBft(entete);
      if (!bft || octetsVersHex(bft.hash) !== entete.hash) detail.push("BFTBlockHash recalculé différent de hash");
      const recuCible = indexTxValide ? fichiersRecus[index.transaction_index] : null;
      if (recuCible?.resultat && typeof recuCible.resultat === "object" && estHexOctets(recuCible.resultat.blockHash, 32) && recuCible.resultat.blockHash !== entete.hash) {
        detail.push("blockHash du reçu capturé différent de hash");
      }
      entete = { ...entete, transactions };
    }
    noter("CP-2", detail.length === 0, detail.join(" ; "));
  }

  // Reçus lus un à un (CP-5 s'évalue sur les reçus lisibles même si CP-3 échoue).
  const recusLus = fichiersRecus.map((f) => {
    try {
      return f ? lireRecu(f.resultat) : null;
    } catch {
      return null;
    }
  });

  // CP-3 : reçus.
  {
    const detail = [];
    if (!entete) detail.push("en-tête inexploitable");
    else if (entete.transactions.length !== fichiersRecus.length) detail.push(`${fichiersRecus.length} reçu(s) pour ${entete.transactions.length} transaction(s)`);
    else if (entete.transactions.length > BORNES_CAPTURE.recus) detail.push("plus de 256 reçus");
    else {
      let complets = true;
      for (let k = 0; k < fichiersRecus.length; k++) {
        const f = fichiersRecus[k];
        if (!recusLus[k] || !f.resultat || f.resultat.transactionHash !== entete.transactions[k]) {
          detail.push(`reçu de rang ${k} absent, mal formé ou d'une autre transaction`);
          complets = false;
          break;
        }
      }
      if (complets) {
        recus = recusLus;
        let racine = null;
        try {
          racine = octetsVersHex(racineRecus(recus));
        } catch {
          racine = null;
        }
        if (racine !== entete.receiptsRoot) detail.push("racine des reçus recalculée différente de receiptsRoot");
        if (!indexTxValide || entete.transactions[index.transaction_index] !== index.transaction_hash) detail.push("transaction capturée absente à transaction_index");
      }
    }
    noter("CP-3", detail.length === 0, detail.join(" ; "));
  }

  // CP-4 : certificat.
  {
    let detail = "";
    let code = "certificat_invalide";
    const liste = Array.isArray(jeux) ? jeux : lireJeux(jeux);
    const jeu = liste && hauteur !== null ? jeuPourHauteur(liste, hauteur) : null;
    if (!fichierCert) {
      detail = "certificat absent";
      code = "certificat_indisponible";
    } else if (fichierCert.octets.length > BORNES_CAPTURE.certificat) detail = `certificat de ${fichierCert.octets.length} octets, au-delà de ${BORNES_CAPTURE.certificat} (CT-4 CP-4)`;
    else if (!jeu) detail = "aucun jeu de validateurs pour cette hauteur";
    else if (!entete) detail = "en-tête inexploitable";
    else {
      let v;
      try {
        v = verifierCertificat(fichierCert.resultat, { bftChainId, hauteur, blockHash: entete.hash, jeu: jeu.jeu });
      } catch (e) {
        v = { ok: false, raison: `certificat illisible : ${String(e?.message ?? e).slice(0, 120)}` };
      }
      if (!v.ok) detail = v.raison;
      else {
        certificat = v;
        if (octetsVersHex(jeu.jeu.hash) !== index.validator_set_hash) detail = "validator_set_hash de l'index différent du hachage du jeu";
        else if (!Array.isArray(v.txsRaw) || v.txsRaw.length !== entete.transactions.length) detail = "txsRaw absent ou d'une autre longueur que transactions";
        else {
          const tx = indexTxValide ? v.txsRaw[index.transaction_index] : null;
          let racine = null;
          try {
            racine = octetsVersHex(racineTransactions(v.txsRaw));
          } catch {
            racine = null;
          }
          if (!tx || octetsVersHex(keccak256(tx)) !== index.transaction_hash) detail = "txsRaw[transaction_index] n'a pas pour hachage transaction_hash";
          else if (racine !== entete.transactionsRoot) detail = "racine des transactions différente de transactionsRoot";
        }
      }
    }
    noter("CP-4", detail === "", detail, code);
  }

  // CP-5 : journal prouvé.
  {
    let detail = "";
    const evenement = EVENEMENT_PAR_ROLE[index.role];
    if (!evenement) {
      if (index.log_index !== null) detail = "rôle sans événement avec un log_index";
    } else {
      const recu = indexTxValide ? recusLus[index.transaction_index] : null;
      const j = recu && Number.isInteger(index.log_index) && index.log_index >= 0 ? recu.logs[index.log_index] : undefined;
      let decode = null;
      if (j && ["inscription", "ancre", "cloture"].includes(index.role)) {
        try {
          decode = decoderJournal(index.role, j);
        } catch {
          decode = null;
        }
      }
      if (!j) detail = "aucun journal à log_index";
      else if (adresseMinuscule(j.address) !== index.contract) detail = "journal émis par un autre contrat";
      else if (!Array.isArray(j.topics) || j.topics[0] !== SUJETS[evenement]) detail = `topics[0] différent du sujet de ${evenement}`;
      else if (["inscription", "ancre", "cloture"].includes(index.role) && decode === null) detail = "disposition du journal différente de CT-6 EX-11.9";
      else journal = j;
    }
    noter("CP-5", detail === "", detail);
  }

  // CP-6 : écriture (noms, SHA-256, schéma).
  {
    const detail = [];
    const schema = verifierIndexCapture(index);
    if (!schema.valide) detail.push(`index hors schéma : ${schema.erreurs[0] ?? ""}`);
    else {
      if (index.files.block.name !== nomBloc(index.block_number)) detail.push("nom du fichier d'en-tête hors convention");
      if (!fichierBloc) detail.push("fichier d'en-tête absent");
      else if (fichierBloc.sha256 !== index.files.block.sha256) detail.push("SHA-256 de l'en-tête différent");
      if (index.files.certificate.name !== nomCertificat(index.block_number)) detail.push("nom du certificat hors convention");
      if (!fichierCert) detail.push("certificat absent");
      else if (fichierCert.sha256 !== index.files.certificate.sha256) detail.push("SHA-256 du certificat différent");
      index.files.receipts.forEach((f, k) => {
        const tx = entete?.transactions?.[k];
        if (tx && f.name !== nomRecu(tx)) detail.push(`nom du reçu ${k} hors convention`);
        const lu = fichiersRecus[k];
        if (!lu) detail.push(`reçu ${k} absent`);
        else if (lu.sha256 !== f.sha256) detail.push(`SHA-256 du reçu ${k} différent`);
      });
    }
    noter("CP-6", detail.length === 0, detail.join(" ; "));
  }

  const verdicts = Object.fromEntries(checks.map((c) => [c.id, c.status]));
  return { checks, verdicts, premierEchec: echecs[0] ?? null, entete, recus, certificat, journal };
}

// ----------------------------------------------------------- Écriture

/**
 * Écrit un fichier sans jamais réécrire : fichier provisoire écrit en entier
 * et synchronisé, puis lien exclusif (CT-4 EX-9.3 : une coupure ne
 * laisse jamais un fichier incomplet sous son nom). Rend `true` s'il a été
 * écrit, `false` s'il existait. Droits 0644 (avant le masque), ceux de
 * l'écriture exclusive d'avant le lien : une capture est déposée par un
 * compte et remise à l'enregistreur par un autre (CT-2 §19.2 :
 * approbateur-demo dépose la capture de l'inscription, exploitation-demo,
 * sous le compte du démon, la remet), qui doit pouvoir la lire.
 */
export function ecrireExclusif(chemin, octets) {
  return ecrireEntierPuisLier(chemin, octets, (message, cause) => Object.assign(new Error(message), { cause, code: cause?.code ?? null }), path.basename(chemin), 0o644);
}

/**
 * Met de côté un fichier présent qui ne passe pas la vérification (CT-4 EX-9.3
 * ne dit pas quoi en faire) sous `<nom>.rejete-<SHA-256
 * du contenu>` : jamais supprimé, jamais relu comme capture, et la réponse est
 * redemandée. Rend le nom du fichier mis de côté, ou null.
 */
export function mettreDeCote(repertoire, nom) {
  const chemin = path.join(repertoire, nom);
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    return null;
  }
  const cible = `${nom}.rejete-${sha256Hex(new Uint8Array(octets)).slice(2)}`;
  try {
    fs.renameSync(chemin, path.join(repertoire, cible));
  } catch {
    return null;
  }
  synchroniserRepertoire(repertoire);
  return cible;
}

/** `fsync` d'un répertoire (entrées de répertoire durables). */
export function synchroniserRepertoire(repertoire) {
  let fd;
  try {
    fd = fs.openSync(repertoire, "r");
  } catch {
    return;
  }
  try {
    fs.fsyncSync(fd);
  } catch {
    // Certains systèmes de fichiers refusent fsync sur un répertoire : sans effet.
  } finally {
    fs.closeSync(fd);
  }
}

/** Sérialisation d'un index (JSON indenté, saut de ligne final), comme les captures publiées. */
export function serialiserIndex(index) {
  return utf8Octets(JSON.stringify(index, null, 2) + "\n");
}

// ------------------------------------------------------------ Capture

/**
 * Obtient le certificat d'une hauteur selon CT-4 §9.3 : réessai toutes les
 * 50 ms sur « not yet persisted » (au plus 100 fois), validateur suivant sur
 * un nœud qui n'a pas le certificat, `certificat_elague` sur l'élagage.
 * Rend `{ fichier, attempts, point }` ou `{ erreur: { code, message }, attempts }`.
 */
export async function obtenirCertificat({ rpc, hauteur, attendre, points = rpc.points(), essaisMax = 100, pauseMs = 50 }) {
  const h = "0x" + BigInt(hauteur).toString(16);
  let attempts = 0;
  let derniere = { code: "certificat_indisponible", message: "aucun point" };
  for (const point of points) {
    let essais = 0;
    for (;;) {
      let reponse;
      attempts++;
      try {
        reponse = await rpc.appeler("noor_getCommitCertificate", [h], { point });
      } catch (e) {
        if (!(e instanceof ErreurRpc)) throw e;
        derniere = { code: "noeud_injoignable", message: e.message };
        break;
      }
      if (!reponse.erreur) {
        if (reponse.octets.length > BORNES_CAPTURE.certificat) {
          derniere = { code: "certificat_invalide", message: `certificat de ${reponse.octets.length} octets, au-delà de ${BORNES_CAPTURE.certificat} (CT-4 CP-4)` };
          break;
        }
        if (lireCertificat(reponse.resultat)) return { fichier: reponse, attempts, point };
        derniere = { code: "certificat_invalide", message: "certificat illisible" };
        break;
      }
      const c = classerErreurCertificat(reponse.erreur);
      derniere = { code: c.code, message: reponse.erreur.message };
      if (c.reessayer && ++essais < essaisMax) {
        await attendre(pauseMs);
        continue;
      }
      if (c.code === "certificat_elague" || c.code === "inutilisable") return { erreur: derniere, attempts };
      break;
    }
  }
  return { erreur: derniere, attempts };
}

/**
 * Capture une transaction du registre dès son reçu (CT-4 §9.4) et écrit
 * l'index. Paramètres : `rpc` (`ClientRpc`), `transactionHash`, `role`,
 * `contrat` (adresse du contrat appelé, null pour un approvisionnement),
 * `horloge` (`{ murale() }`), `repertoire`, `instance` (`{ evmChainId,
 * bftChainId, jeux }` ; `jeux` : manifeste, `validateurs-v0` ou
 * `validators.json`), `attendre(ms)`, `sending` (envoi, ou null),
 * `attendu` (`{ fingerprint }` ou `{ periodHash }` pour choisir le journal),
 * `point` (validateur interrogé, le premier par défaut), `recu` (déjà
 * obtenu, facultatif).
 * Rend `{ index, nom, chemin, sha256, octets, checks }` ou `{ erreur: { code,
 * check, message }, checks }` ; idempotente (EX-9.3).
 */
export async function capturer({ rpc, transactionHash, role, contrat, horloge, repertoire, instance, attendre, sending = null, attendu = null, point = rpc.points()[0], recu = null }) {
  if (!ROLES_CAPTURE.includes(role)) throw new TypeError(`rôle de capture inconnu : ${role}`);
  if (!estHexOctets(transactionHash, 32)) throw new TypeError("hachage de transaction attendu");
  const contratMin = contrat === null ? null : adresseMinuscule(contrat);
  if (contrat !== null && contratMin === null) throw new TypeError("adresse de contrat attendue");
  const jeux = lireJeux(instance.jeux);
  if (!jeux) throw new TypeError("jeux de validateurs illisibles");
  fs.mkdirSync(repertoire, { recursive: true });
  const lecteur = lecteurRepertoire(repertoire);
  const erreur = (code, check, message, checks = []) => ({ erreur: { code, check, message }, checks });

  // Reçu de la transaction capturée.
  let fichierRecuCible = null;
  if (recu && recu.octets) fichierRecuCible = lireFichierRpc(recu.octets);
  if (!fichierRecuCible) {
    let r;
    try {
      r = await rpc.appeler("eth_getTransactionReceipt", [transactionHash], { point });
    } catch (e) {
      if (e instanceof ErreurRpc) return erreur("noeud_injoignable", null, e.message);
      throw e;
    }
    if (r.erreur || r.resultat === null) return erreur("recu_absent", null, "le validateur ne rend pas de reçu");
    fichierRecuCible = lireFichierRpc(r.octets);
  }
  const recuCible = fichierRecuCible?.resultat;
  if (!recuCible || typeof recuCible !== "object" || !estHexOctets(recuCible.blockHash, 32)) return erreur("recu_absent", null, "reçu illisible");
  const hauteur = quantiteVersEntier(recuCible.blockNumber, MAX_U64);
  if (hauteur === null || hauteur === 0n) return erreur("recu_absent", null, "reçu sans hauteur");
  const h = Number(hauteur);

  // CP-1 : nœud validateur de l'instance.
  const cp1 = [];
  try {
    const c = await rpc.appeler("eth_chainId", [], { point });
    if (c.erreur || quantiteVersEntier(c.resultat, MAX_U64) !== BigInt(instance.evmChainId)) cp1.push({ code: "chaine_differente", message: `eth_chainId ${c.resultat}` });
    const s = await rpc.appeler("noor_txindexStatus", [], { point });
    const dernier = s.erreur ? null : s.resultat?.last_indexed_height;
    if (s.erreur || !Number.isSafeInteger(dernier) || dernier < h || dernier === 0) cp1.push({ code: "noeud_suiveur", message: `noor_txindexStatus last_indexed_height ${dernier ?? s.erreur?.message}` });
  } catch (e) {
    if (e instanceof ErreurRpc) return erreur("noeud_injoignable", "CP-1", e.message);
    throw e;
  }
  const checkCp1 = verif("CP-1", cp1.length === 0 ? "reussi" : "echoue", cp1.map((c) => c.message).join(" ; "));
  if (cp1.length > 0) return erreur(cp1[0].code, "CP-1", cp1[0].message, [checkCp1]);

  // Fichiers : en-tête, reçus, certificat. Revue de sécurité de l'étape 8 (règle d'écriture unique de S-4) : les réponses sont
  // tenues en mémoire, vérifiées par CP-2 à CP-6, et seulement alors écrites sous leur nom (nom provisoire, écriture
  // complète, `fsync`, lien exclusif). Un fichier présent et lisible est repris (EX-9.3) ; s'il ne passe pas la
  // vérification, il est mis de côté (`<nom>.rejete-<SHA-256>`) et la réponse est redemandée à un autre validateur ;
  // un fichier présent illisible est mis de côté d'emblée. Rien de faux ni d'incomplet ne reste sous un nom de capture.
  const ecrits = [];
  const ecartes = [];
  const reponses = new Map(); // nom → { fichier (lireFichierRpc), repris }
  const lecteurMemoire = { lire: (nom) => reponses.get(nom)?.fichier?.octets ?? null, existe: (nom) => reponses.has(nom) };
  const autresPoints = rpc.points().filter((p) => p !== point);
  const appel = async (methode, params, surPoint = point) => {
    try {
      const r = await rpc.appeler(methode, params, { point: surPoint });
      return r.erreur || r.resultat === null ? null : r;
    } catch (e) {
      if (e instanceof ErreurRpc) return null;
      throw e;
    }
  };
  /** Reprend un fichier présent lisible, sinon demande la réponse (`obtenir(point)`), sans rien écrire. */
  const obtenirReponse = async (nom, obtenir, { redemander = false } = {}) => {
    if (!redemander && lecteur.existe(nom)) {
      const present = lecteur.lire(nom);
      const lu = present ? lireFichierRpc(present) : null;
      if (lu) {
        reponses.set(nom, { fichier: lu, repris: true });
        return lu;
      }
      const mis = mettreDeCote(repertoire, nom);
      if (mis) ecartes.push({ nom, mis_de_cote: mis, raison: "illisible" });
    }
    // Une réponse redemandée après la mise de côté d'un fichier faux vient d'un autre validateur quand il y en a un.
    const pointsEssayes = redemander ? [...autresPoints, point] : [point, ...autresPoints];
    for (const p of pointsEssayes) {
      const reponse = await obtenir(p);
      if (!reponse) continue;
      const lu = lireFichierRpc(reponse.octets);
      if (!lu) continue;
      reponses.set(nom, { fichier: lu, repris: false, point: p });
      return lu;
    }
    reponses.delete(nom);
    return null;
  };

  let attempts = 1;
  let erreurCertificat = null; // hors de la fermeture : `cert` n'est lisible qu'après son initialisation
  /** Rassemble les trois réponses et les vérifie ; `redemander` : noms dont le fichier présent a été écarté. */
  const rassembler = async (redemander) => {
    const bloc = await obtenirReponse(nomBloc(h), (p) => appel("eth_getBlockByNumber", ["0x" + hauteur.toString(16), false], p), { redemander: redemander.has(nomBloc(h)) });
    if (!bloc) return { echec: erreur("capture_incomplete", "CP-2", "en-tête indisponible", [checkCp1]) };
    const transactions = Array.isArray(bloc.resultat?.transactions) ? bloc.resultat.transactions : null;
    if (!transactions || !transactions.every((t) => estHexOctets(t, 32)) || transactions.length > BORNES_CAPTURE.recus) {
      return { echec: erreur("capture_incomplete", "CP-2", "liste de transactions de l'en-tête illisible", [checkCp1]), suspects: [nomBloc(h)] };
    }
    const indexTx = transactions.indexOf(transactionHash);
    if (indexTx < 0) return { echec: erreur("capture_incomplete", "CP-3", "transaction absente de l'en-tête", [checkCp1]), suspects: [nomBloc(h)] };
    const recus = [];
    for (const tx of transactions) {
      const r = await obtenirReponse(nomRecu(tx), (p) => (tx === transactionHash && fichierRecuCible && p === point ? { octets: fichierRecuCible.octets } : appel("eth_getTransactionReceipt", [tx], p)), { redemander: redemander.has(nomRecu(tx)) });
      if (!r) return { echec: erreur("capture_incomplete", "CP-3", `reçu de ${tx} indisponible`, [checkCp1]) };
      recus.push(r);
    }
    const cert = await obtenirReponse(nomCertificat(h), async (p) => {
      const o = await obtenirCertificat({ rpc, hauteur: h, attendre, points: [p, ...rpc.points().filter((x) => x !== p)] });
      attempts = o.attempts;
      if (o.erreur) {
        erreurCertificat = o.erreur;
        return null;
      }
      return o.fichier;
    }, { redemander: redemander.has(nomCertificat(h)) });
    if (!cert) return { echec: erreur(erreurCertificat?.code ?? "certificat_indisponible", "CP-4", erreurCertificat?.message ?? "certificat indisponible", [checkCp1]) };
    // Journal prouvé et jeu de la hauteur.
    const recuLu = lireRecu(recus[indexTx].resultat);
    const { logIndex } = recuLu ? trouverJournal(recuLu, { role, contrat: contratMin, attendu }) : { logIndex: null };
    const jeu = jeuPourHauteur(jeux, h);
    const index = {
      version: 0,
      role,
      evm_chain_id: Number(instance.evmChainId),
      bft_chain_id: instance.bftChainId,
      contract: contratMin,
      transaction_hash: transactionHash,
      block_number: h,
      block_hash: typeof bloc.resultat?.hash === "string" ? bloc.resultat.hash : "0x" + "00".repeat(32),
      transaction_index: indexTx,
      log_index: logIndex,
      files: {
        block: { name: nomBloc(h), sha256: bloc.sha256 },
        receipts: transactions.map((tx, k) => ({ name: nomRecu(tx), sha256: recus[k].sha256 })),
        certificate: { name: nomCertificat(h), sha256: cert.sha256 },
      },
      node: { rpc: point, validator_id: rpc.validateurDe(point) },
      validator_set_hash: jeu ? octetsVersHex(jeu.jeu.hash) : "0x" + "00".repeat(32),
      captured_at: ecrireHorodatage(horloge.murale()),
      attempts: Math.min(Math.max(attempts, 1), 1000),
      // Six vérifications provisoires, pour que CP-6 juge un index complet ; remplacées par les résultats réels.
      checks: [checkCp1, ...["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => verif(id, "reussi"))],
      sending,
    };
    const v = verifierCapture({ fichiers: lecteurMemoire, index, jeux, bftChainId: instance.bftChainId });
    index.checks = [checkCp1, ...v.checks];
    if (!v.premierEchec) return { index, indexTx };
    // Fichiers repris du disque mis en cause par la vérification en échec : en-tête (CP-2), reçus (CP-3), certificat (CP-4), tous (CP-5, CP-6).
    const parCheck = { "CP-2": [nomBloc(h)], "CP-3": [nomBloc(h), ...transactions.map(nomRecu)], "CP-4": [nomCertificat(h)] };
    const suspects = parCheck[v.premierEchec.check] ?? [nomBloc(h), nomCertificat(h), ...transactions.map(nomRecu)];
    return { echec: { erreur: { code: v.premierEchec.code, check: v.premierEchec.check, message: v.checks.find((c) => c.id === v.premierEchec.check)?.detail ?? "" }, checks: index.checks, index }, suspects };
  };

  let resultat = await rassembler(new Set());
  if (resultat.echec && Array.isArray(resultat.suspects)) {
    const aEcarter = resultat.suspects.filter((nom) => reponses.get(nom)?.repris);
    if (aEcarter.length) {
      for (const nom of aEcarter) {
        const mis = mettreDeCote(repertoire, nom);
        if (mis) ecartes.push({ nom, mis_de_cote: mis, raison: resultat.echec.erreur.check });
        reponses.delete(nom);
      }
      resultat = await rassembler(new Set(aEcarter));
    }
  }
  if (resultat.echec) return { ...resultat.echec, ecrits, ecartes };
  const { index, indexTx } = resultat;
  // Vérification faite : les réponses venues du réseau sont écrites, puis l'index.
  for (const [nomFichier, r] of reponses) {
    if (r.repris) continue;
    if (ecrireExclusif(path.join(repertoire, nomFichier), r.fichier.octets)) ecrits.push(nomFichier);
    else if (lireFichierRpc(lecteur.lire(nomFichier))?.sha256 !== r.fichier.sha256) {
      return { erreur: { code: "capture_incomplete", check: "CP-6", message: `${nomFichier} présent avec d'autres octets` }, checks: index.checks, index, ecrits, ecartes };
    }
  }
  if (ecrits.length) synchroniserRepertoire(repertoire);
  const nom = nomIndex(h, indexTx, role);
  const octets = serialiserIndex(index);
  const chemin = path.join(repertoire, nom);
  if (!ecrireExclusif(chemin, octets)) {
    // Index déjà présent : la capture avait été faite ; on le relit (idempotence) s'il passe encore CP-2 à CP-6 sur les
    // fichiers présents ; sinon (fichier mis de côté et réécrit, CT-4 EX-9.3) il est mis de côté à son tour et le
    // nôtre, vérifié, prend le nom.
    const present = lecteur.lire(nom);
    const texte = present ? utf8Texte(present) : null;
    let relu = null;
    try {
      relu = texte ? JSON.parse(texte) : null;
    } catch {
      relu = null;
    }
    if (relu && verifierIndexCapture(relu).valide && verifierCapture({ fichiers: lecteur, index: relu, jeux, bftChainId: instance.bftChainId }).premierEchec === null) {
      return { index: relu, nom, chemin, sha256: sha256Hex(present), octets: present, checks: relu.checks, repris: true, ecrits, ecartes };
    }
    const mis = mettreDeCote(repertoire, nom);
    if (mis) ecartes.push({ nom, mis_de_cote: mis, raison: "index présent qui ne passe plus CP-2 à CP-6" });
    if (!ecrireExclusif(chemin, octets)) return erreur("capture_incomplete", "CP-6", "index présent mais illisible", index.checks);
  }
  synchroniserRepertoire(repertoire);
  return { index, nom, chemin, sha256: sha256Hex(octets), octets, checks: index.checks, repris: false, ecrits, ecartes };
}

/** Compare deux suites d'octets (pour les tests de reprise). */
export { octetsEgaux };
