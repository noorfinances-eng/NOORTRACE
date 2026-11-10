// Export des parties du dossier qui viennent du registre (CT-4 §9.6, EX-9.8
// à EX-9.10 ; CT-6 §11.2 ; CT-5 EX-10.4) : `registre.json` construit depuis
// les seules captures (`entreeRegistre` : champs engagés de l'en-tête, reçus
// réduits à `type`, `status`, `cumulativeGasUsed`, `logs`, hexadécimal en
// minuscules), `certificat-commit.json` (le `result` de chaque certificat,
// tel quel, une hauteur distincte à la fois, croissantes) et
// `validateurs.json` (jeux du manifeste dont l'intervalle contient les
// hauteurs, réduits à `from_height`, `to_height`, `validators`, `source`).
//
// Une entrée de rôle `ancre_point_de_controle` est celle d'une capture de
// rôle `ancre` dont le journal porte le `docType` du point de contrôle
// (CT-5 EX-10.4, CT-6 EX-11.23) ; une seule par dossier.

import { DOC_TYPE_PERIODE, DOC_TYPE_POINT_DE_CONTROLE, SUJETS, adresseMinuscule, decoderJournal } from "./encodage.mjs";
import { lireFichierRpc, lecteurRepertoire } from "./capture.mjs";
import { champsEntete, lireRecu } from "./trie.mjs";
import { utf8Octets } from "./octets.mjs";
import { verifierCertificatCommitV0, verifierRegistreV0, verifierValidateursV0 } from "./schemas.mjs";
import { lireJeux } from "./certificat.mjs";

/** Rôles d'index de capture qui deviennent des entrées de `registre.json`. */
export const ROLES_EXPORTES = Object.freeze(["inscription", "ancre", "cloture"]);

/** Bornes de CT-6 EX-11.10, EX-11.23. */
export const BORNES_EXPORT = Object.freeze({ entrees: 17, inscriptions: 8, certificats: 16, source: 512 });

/**
 * Lit les fichiers d'une capture depuis son index : `{ entete, recus,
 * certificat }` (objets `result`), ou lève si un fichier manque ou est
 * illisible (CT-4 EX-9.11 : une capture manquante arrête l'export).
 */
export function lireCapture(repertoire, index) {
  const lecteur = typeof repertoire === "string" ? lecteurRepertoire(repertoire) : repertoire;
  const bloc = lireFichierRpc(lecteur.lire(index.files.block.name));
  if (!bloc) throw new Error(`capture_incomplete : ${index.files.block.name} absent ou illisible`);
  const recus = index.files.receipts.map((f) => {
    const r = lireFichierRpc(lecteur.lire(f.name));
    if (!r) throw new Error(`capture_incomplete : ${f.name} absent ou illisible`);
    return r.resultat;
  });
  const cert = lireFichierRpc(lecteur.lire(index.files.certificate.name));
  if (!cert) throw new Error(`capture_incomplete : ${index.files.certificate.name} absent ou illisible`);
  return { entete: bloc.resultat, recus, certificat: cert.resultat };
}

/**
 * Rôle de l'entrée de `registre.json` d'une capture : `inscription`,
 * `cloture`, `ancre` (journal de `docType` de période) ou
 * `ancre_point_de_controle` (journal de `docType` du point) ; null pour un
 * rôle non exporté.
 */
export function roleEntree(index, journal) {
  if (index.role === "inscription" || index.role === "cloture") return index.role;
  if (index.role !== "ancre") return null;
  const j = decoderJournal("ancre", journal);
  if (!j) return null;
  if (j.docType === DOC_TYPE_POINT_DE_CONTROLE) return "ancre_point_de_controle";
  if (j.docType === DOC_TYPE_PERIODE) return "ancre";
  return null;
}

/**
 * CT-4 EX-9.8 : entrée de `registre.json` depuis une capture. `role`
 * force le rôle de l'entrée (sinon dérivé du journal). Lève si la capture
 * est incomplète ou si son journal n'a pas la forme du rôle.
 */
export function entreeRegistre({ repertoire, index, role = null }) {
  const { entete, recus } = lireCapture(repertoire, index);
  const block = champsEntete(entete);
  if (!block) throw new Error("capture_incomplete : en-tête sans ses dix champs");
  const receipts = recus.map((r) => {
    const lu = lireRecu(r);
    if (!lu) throw new Error("capture_incomplete : reçu illisible");
    return { type: lu.type, status: lu.status, cumulativeGasUsed: lu.cumulativeGasUsed, logs: lu.logs.map((j) => ({ address: adresseMinuscule(j.address), topics: j.topics, data: j.data })) };
  });
  const recu = receipts[index.transaction_index];
  if (!recu || !Number.isInteger(index.log_index) || !recu.logs[index.log_index]) throw new Error("capture_incomplete : journal prouvé introuvable");
  const journal = recu.logs[index.log_index];
  const r = role ?? roleEntree(index, journal);
  if (!r) throw new Error(`rôle d'export indéterminé pour la capture ${index.transaction_hash}`);
  const decode = decoderJournal(r, journal);
  if (decode === null) throw new Error(`journal prouvé sans la forme du rôle ${r}`);
  // R-9 : l'entrée `ancre` d'un dossier porte le docType de période (CT-6 EX-11.18) ; un point n'est jamais exporté sous ce rôle (AN-45).
  if (r === "ancre" && decode.docType !== DOC_TYPE_PERIODE) throw new Error("journal prouvé sans la forme du rôle ancre : docType de période attendu");
  return {
    role: r,
    block,
    receipts,
    transaction_index: index.transaction_index,
    log_index: index.log_index,
    transaction_hash: index.transaction_hash,
  };
}

function hauteurDe(entree) {
  return BigInt(entree.block.number);
}

/**
 * CT-4 §9.6 : construit `registre.json`, `certificat-commit.json` et
 * `validateurs.json` depuis des captures. `captures` : `[{ index, role? }]`
 * (index de capture lus dans `repertoire`) ; `jeux` : manifeste d'instance,
 * fichier `validateurs-v0` ou `validators.json` avec `source` ; `source` :
 * texte de `registre.json` (nœud, dates ; 1 à 512 caractères).
 * Rend `{ registre, certificatCommit, validateurs, octets: { registre,
 * certificatCommit, validateurs } }` ; lève si une borne de CT-6 est
 * dépassée ou si une capture manque (EX-9.11).
 */
export function exporterPartiesRegistre({ repertoire, captures, jeux, source, sourceJeu = null }) {
  if (typeof source !== "string" || source.length < 1 || source.length > BORNES_EXPORT.source) throw new TypeError("source de 1 à 512 caractères attendue");
  const entrees = [];
  const certificats = new Map();
  for (const c of captures) {
    const e = entreeRegistre({ repertoire, index: c.index, role: c.role ?? null });
    entrees.push(e);
    const h = hauteurDe(e);
    if (!certificats.has(h)) certificats.set(h, lireCapture(repertoire, c.index).certificat);
  }
  entrees.sort((a, b) => (hauteurDe(a) < hauteurDe(b) ? -1 : hauteurDe(a) > hauteurDe(b) ? 1 : a.transaction_index - b.transaction_index));
  if (entrees.length > BORNES_EXPORT.entrees) throw new Error(`plus de ${BORNES_EXPORT.entrees} entrées`);
  const registre = { version: 0, source, entries: entrees };
  const vr = verifierRegistreV0(registre);
  if (!vr.valide) throw new Error(`registre.json hors schéma : ${vr.erreurs.join(" ; ")}`);
  const hauteurs = [...certificats.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (hauteurs.length > BORNES_EXPORT.certificats) throw new Error(`plus de ${BORNES_EXPORT.certificats} certificats`);
  const certificatCommit = { version: 0, certificates: hauteurs.map((h) => certificats.get(h)) };
  const vc = verifierCertificatCommitV0(certificatCommit);
  if (!vc.valide) throw new Error(`certificat-commit.json hors schéma : ${vc.erreurs.join(" ; ")}`);
  const listeJeux = lireJeux(jeux);
  if (!listeJeux) throw new TypeError("jeux de validateurs illisibles");
  const retenus = listeJeux.filter((j) => hauteurs.some((h) => j.from_height <= Number(h) && (j.to_height === null || Number(h) <= j.to_height)));
  if (retenus.length === 0) throw new Error("aucun jeu de validateurs ne couvre les hauteurs exportées");
  const validateurs = {
    version: 0,
    sets: retenus.map((j) => ({
      from_height: j.from_height,
      to_height: j.to_height,
      validators: j.jeu.validateurs.map((v, k) => ({ id: j.validators[k].id, pubKeyHex: j.validators[k].pubKeyHex })),
      source: j.source ?? sourceJeu ?? source,
    })),
  };
  const vv = verifierValidateursV0(validateurs);
  if (!vv.valide) throw new Error(`validateurs.json hors schéma : ${vv.erreurs.join(" ; ")}`);
  const serialiser = (v) => utf8Octets(JSON.stringify(v, null, 2) + "\n");
  return {
    registre, certificatCommit, validateurs,
    octets: { registre: serialiser(registre), certificatCommit: serialiser(certificatCommit), validateurs: serialiser(validateurs) },
  };
}

/**
 * Choisit, parmi des index de capture, ceux que CT-4 EX-9.8 retient pour un
 * dossier : la clôture dont `PeriodSubmitted` porte `periodHash`, l'ancre
 * dont `Anchored` porte l'empreinte de la période, l'inscription de chaque
 * clé demandée (`inscriptions` : `[{ clePublique, chainKey? }]`, la dernière
 * inscription de chacune), et, si `empreintePoint` est donnée, l'ancre du
 * point couvrant (rôle `ancre_point_de_controle`). Rend `[{ index, role }]`
 * ou lève si une capture attendue manque.
 */
export function choisirCaptures({ repertoire, indexes, periodHash, fingerprint, inscriptions = [], empreintePoint = null }) {
  const lecteur = lecteurRepertoire(repertoire);
  const avecJournal = indexes.map((index) => {
    const recu = lireFichierRpc(lecteur.lire(index.files.receipts[index.transaction_index]?.name));
    const lu = recu ? lireRecu(recu.resultat) : null;
    const j = lu && Number.isInteger(index.log_index) ? lu.logs[index.log_index] : null;
    return { index, journal: j ? decoderJournal(index.role === "ancre" ? "ancre" : index.role, j) : null };
  });
  const choisis = [];
  const cloture = avecJournal.find((c) => c.index.role === "cloture" && c.journal && c.journal.periodHash === periodHash);
  if (!cloture) throw new Error("capture_incomplete : clôture de la période absente");
  choisis.push({ index: cloture.index, role: "cloture" });
  const ancre = avecJournal.find((c) => c.index.role === "ancre" && c.journal && c.journal.fingerprint === fingerprint && c.journal.docType === DOC_TYPE_PERIODE);
  if (!ancre) throw new Error("capture_incomplete : ancre de la période absente");
  choisis.push({ index: ancre.index, role: "ancre" });
  for (const demande of inscriptions) {
    const candidats = avecJournal.filter((c) => c.index.role === "inscription" && c.journal && c.journal.ed25519PubKey === demande.clePublique && (!demande.chainKey || c.journal.chainKey === demande.chainKey));
    if (candidats.length === 0) throw new Error(`capture_incomplete : inscription de ${demande.clePublique} absente`);
    candidats.sort((a, b) => b.index.block_number - a.index.block_number || b.index.transaction_index - a.index.transaction_index);
    choisis.push({ index: candidats[0].index, role: "inscription" });
  }
  if (choisis.filter((c) => c.role === "inscription").length > BORNES_EXPORT.inscriptions) throw new Error("plus de 8 inscriptions");
  if (empreintePoint) {
    const point = avecJournal.find((c) => c.index.role === "ancre" && c.journal && c.journal.fingerprint === empreintePoint && c.journal.docType === DOC_TYPE_POINT_DE_CONTROLE);
    if (!point) throw new Error("capture_incomplete : ancre du point couvrant absente");
    choisis.push({ index: point.index, role: "ancre_point_de_controle" });
  }
  return choisis;
}

export { SUJETS };
