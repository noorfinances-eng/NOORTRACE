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

/** Rôles d'un index de capture (schéma). */
export const ROLES_CAPTURE = Object.freeze([
  "deploiement", "jeu_approbateurs", "assignation", "approvisionnement", "inscription", "revocation", "ancre", "cloture", "administration_jeu", "reassignation",
]);

/** Bornes de lecture : réponses JSON-RPC au plus 16 Mio, 256 reçus par bloc (CT-6 §15.1). */
export const BORNES_CAPTURE = Object.freeze({ fichier: 16 * 1024 * 1024, recus: 256 });

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

  // Lecture des fichiers désignés par l'index ; la forme de l'index est contrôlée avant tout usage (R-D-3 : un index
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
    } else if (!jeu) detail = "aucun jeu de validateurs pour cette hauteur";
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

/** Écrit un fichier en création exclusive puis `fsync` ; rend `true` s'il a été écrit, `false` s'il existait. */
export function ecrireExclusif(chemin, octets) {
  let fd;
  try {
    fd = fs.openSync(chemin, "wx", 0o644);
  } catch (e) {
    if (e && e.code === "EEXIST") return false;
    throw e;
  }
  try {
    fs.writeFileSync(fd, octets);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  return true;
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

  // Fichiers : en-tête, reçus, certificat ; les fichiers présents sont repris (EX-9.3).
  const ecrits = [];
  const reprendreOuEcrire = async (nom, obtenir) => {
    const present = lecteur.lire(nom);
    if (present) {
      const lu = lireFichierRpc(present);
      if (lu) return { fichier: lu, repris: true };
    }
    const reponse = await obtenir();
    if (!reponse) return { fichier: null, repris: false };
    const lu = lireFichierRpc(reponse.octets);
    if (!lu) return { fichier: null, repris: false };
    if (ecrireExclusif(path.join(repertoire, nom), reponse.octets)) ecrits.push(nom);
    else {
      const relu = lireFichierRpc(lecteur.lire(nom));
      return { fichier: relu, repris: true };
    }
    return { fichier: lu, repris: false };
  };
  const appel = async (methode, params) => {
    try {
      const r = await rpc.appeler(methode, params, { point });
      return r.erreur || r.resultat === null ? null : r;
    } catch (e) {
      if (e instanceof ErreurRpc) return null;
      throw e;
    }
  };

  const bloc = await reprendreOuEcrire(nomBloc(h), () => appel("eth_getBlockByNumber", ["0x" + hauteur.toString(16), false]));
  if (!bloc.fichier) return erreur("capture_incomplete", "CP-2", "en-tête indisponible", [checkCp1]);
  const transactions = Array.isArray(bloc.fichier.resultat?.transactions) ? bloc.fichier.resultat.transactions : null;
  if (!transactions || !transactions.every((t) => estHexOctets(t, 32)) || transactions.length > BORNES_CAPTURE.recus) {
    return erreur("capture_incomplete", "CP-2", "liste de transactions de l'en-tête illisible", [checkCp1]);
  }
  const indexTx = transactions.indexOf(transactionHash);
  if (indexTx < 0) return erreur("capture_incomplete", "CP-3", "transaction absente de l'en-tête", [checkCp1]);

  const recus = [];
  for (const tx of transactions) {
    const r = await reprendreOuEcrire(nomRecu(tx), () => (tx === transactionHash && fichierRecuCible ? { octets: fichierRecuCible.octets } : appel("eth_getTransactionReceipt", [tx])));
    if (!r.fichier) return erreur("capture_incomplete", "CP-3", `reçu de ${tx} indisponible`, [checkCp1]);
    recus.push(r.fichier);
  }

  let attempts = 1;
  let erreurCertificat = null; // hors de la fermeture : `cert` n'est lisible qu'après son initialisation (R-D-2)
  const cert = await reprendreOuEcrire(nomCertificat(h), async () => {
    const o = await obtenirCertificat({ rpc, hauteur: h, attendre, points: [point, ...rpc.points().filter((p) => p !== point)] });
    attempts = o.attempts;
    if (o.erreur) {
      erreurCertificat = o.erreur;
      return null;
    }
    return o.fichier;
  });
  if (!cert.fichier) return erreur(erreurCertificat?.code ?? "certificat_indisponible", "CP-4", erreurCertificat?.message ?? "certificat indisponible", [checkCp1]);

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
    block_hash: typeof bloc.fichier.resultat?.hash === "string" ? bloc.fichier.resultat.hash : "0x" + "00".repeat(32),
    transaction_index: indexTx,
    log_index: logIndex,
    files: {
      block: { name: nomBloc(h), sha256: bloc.fichier.sha256 },
      receipts: transactions.map((tx, k) => ({ name: nomRecu(tx), sha256: recus[k].sha256 })),
      certificate: { name: nomCertificat(h), sha256: cert.fichier.sha256 },
    },
    node: { rpc: point, validator_id: rpc.validateurDe(point) },
    validator_set_hash: jeu ? octetsVersHex(jeu.jeu.hash) : "0x" + "00".repeat(32),
    captured_at: ecrireHorodatage(horloge.murale()),
    attempts: Math.min(Math.max(attempts, 1), 1000),
    // Six vérifications provisoires, pour que CP-6 juge un index complet ; remplacées par les résultats réels.
    checks: [checkCp1, ...["CP-2", "CP-3", "CP-4", "CP-5", "CP-6"].map((id) => verif(id, "reussi"))],
    sending,
  };
  const v = verifierCapture({ fichiers: lecteur, index, jeux, bftChainId: instance.bftChainId });
  index.checks = [checkCp1, ...v.checks];
  if (v.premierEchec) {
    return { erreur: { code: v.premierEchec.code, check: v.premierEchec.check, message: v.checks.find((c) => c.id === v.premierEchec.check)?.detail ?? "" }, checks: index.checks, index, ecrits };
  }
  const nom = nomIndex(h, indexTx, role);
  const octets = serialiserIndex(index);
  const chemin = path.join(repertoire, nom);
  if (!ecrireExclusif(chemin, octets)) {
    // Index déjà présent : la capture avait été faite ; on le relit (idempotence).
    const present = lecteur.lire(nom);
    const texte = present ? utf8Texte(present) : null;
    let relu = null;
    try {
      relu = texte ? JSON.parse(texte) : null;
    } catch {
      relu = null;
    }
    if (relu && verifierIndexCapture(relu).valide) return { index: relu, nom, chemin, sha256: sha256Hex(present), octets: present, checks: relu.checks, repris: true, ecrits };
    return erreur("capture_incomplete", "CP-6", "index présent mais illisible", index.checks);
  }
  synchroniserRepertoire(repertoire);
  return { index, nom, chemin, sha256: sha256Hex(octets), octets, checks: index.checks, repris: false, ecrits };
}

/** Compare deux suites d'octets (pour les tests de reprise). */
export { octetsEgaux };
