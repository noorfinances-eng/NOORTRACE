// Envoi des transactions du registre (CT-4 §8.6, EX-8.13 à EX-8.17 ; CT-5
// EX-9.3, EX-9.4, EX-9.7, EX-8.10) : l'`Envoyeur` construit et signe
// `anchor` (ancre d'un point ou d'une période) et `submitPeriod` (clôture)
// avec la clé de chaîne, vérifie RG-15 sur les octets signés avant l'envoi,
// tient ses envois dans `envoi-<hachage>.json` et leurs issues dans
// `issue-<hachage>.json` (schéma `operations-registre-v0`), soumet les mêmes
// octets à chaque validateur, attend le reçu, capture (CT-4 §9.4) et rend le
// `data` d'une entrée `inclusion_registre` ou `echec_registre` du schéma
// `planificateur-ancrage-v0`. Il refuse un second envoi d'une même clé tant
// que le premier est sans issue (OP-3, `attente_nonce`) ; `renvoyer` et
// `remplacer` appliquent la reprise d'EX-8.16.
//
// Horloge et attentes sont injectées : `horloge.murale()` (ms UTC) date les
// fichiers, `horloge.monotone()` borne l'attente du reçu, `attendre(ms)`
// suspend entre deux sondages. Aucun secret n'est écrit : la clé de chaîne
// n'est vue que par `signerCondense`.

import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { capturer, ecrireExclusif, lecteurRepertoire, synchroniserRepertoire } from "./capture.mjs";
import {
  DOC_TYPE_PERIODE, DOC_TYPE_POINT_DE_CONTROLE, SUJETS, anchorDigest, decoderJournal, empreinteAncre, encoderAnchor,
  encoderSubmitPeriod, hachageSigne, lirePeriodMeta, periodDigest, verifierJeuSignatures, verifierPeriodMeta,
} from "./encodage.mjs";
import { lireSignature } from "./cle-chaine.mjs";
import {
  ErreurLecture, anchorDigestContrat, classerEmpreinte, getPeriod, isActiveRecorder, isKnown, latestPeriodOf, lookup, periodDigestContrat,
  recorderByPubKey,
} from "./lookup.mjs";
import { estHexOctets, hexVersOctets, octetsVersHex, quantiteVersEntier, utf8Octets, utf8Texte, versEntier, MAX_U256, MAX_U64 } from "./octets.mjs";
import { ErreurRpc } from "./rpc.mjs";
import { verifierEnvoi, verifierIssue } from "./schemas.mjs";
import { construireTransaction, fraisRemplacement, lireTransaction, signerTransaction, verifierRG15 } from "./transaction.mjs";
import { listerCaptures } from "./capture.mjs";

/** Délais par défaut : attente du reçu `registry.inclusion_alert_s` (60 s), sondage toutes les 500 ms. */
export const DELAIS_DEFAUT = Object.freeze({ recuMs: 60000, sondageMs: 500 });

const nomEnvoi = (hash) => `envoi-${hash}.json`;
const nomIssue = (hash) => `issue-${hash}.json`;

function serialiser(objet) {
  return utf8Octets(JSON.stringify(objet, null, 2) + "\n");
}

function lireJson(octets) {
  const texte = octets ? utf8Texte(octets) : null;
  if (texte === null) return null;
  try {
    return JSON.parse(texte);
  } catch {
    return null;
  }
}

/** Lit les envois et issues d'un répertoire ; rend `[{ envoi, issue|null }]`. */
export function lireEnvois(repertoire) {
  let noms;
  try {
    noms = fs.readdirSync(repertoire);
  } catch {
    return [];
  }
  const lecteur = lecteurRepertoire(repertoire);
  const sortie = [];
  for (const nom of noms.sort()) {
    const m = /^envoi-(0x[0-9a-f]{64})\.json$/.exec(nom);
    if (!m) continue;
    const envoi = lireJson(lecteur.lire(nom));
    if (!envoi || !verifierEnvoi(envoi).valide || envoi.transaction_hash !== m[1]) continue;
    const issue = lireJson(lecteur.lire(nomIssue(m[1])));
    sortie.push({ envoi, issue: issue && verifierIssue(issue).valide ? issue : null });
  }
  return sortie;
}

/**
 * Un envoi est sans issue connue tant qu'aucun fichier d'issue ne le clôt
 * (OP-3), ou quand il est `remplacee` par un remplaçant lui-même sans issue
 * d'inclusion (EX-8.16) ; un envoi `ecartee` ou inclus a une issue.
 */
export function envoisSansIssue(repertoire, expediteur) {
  const tous = lireEnvois(repertoire);
  return envoisSansIssueParHash(new Map(tous.map((e) => [e.envoi.transaction_hash, e])), expediteur);
}

/**
 * Même règle sur un index `hash → { envoi, issue|null }` (celui que
 * l'`Envoyeur` tient en mémoire, R-D-4) ; rend les envois dans l'ordre des
 * hachages, comme la lecture du répertoire.
 */
export function envoisSansIssueParHash(parHash, expediteur) {
  const inclus = (e) => e.issue && typeof e.issue.block_number === "number";
  const sansIssue = (e, profondeur = 0) => {
    if (!e.issue) return true;
    if (inclus(e) || e.issue.state === "ecartee") return false;
    if (e.issue.state === "remplacee") {
      const remplacant = parHash.get(e.issue.replaced_by);
      if (!remplacant || profondeur > 64) return true;
      return sansIssue(remplacant, profondeur + 1);
    }
    return true;
  };
  return [...parHash.keys()].sort().map((h) => parHash.get(h)).filter((e) => e.envoi.from === expediteur && sansIssue(e)).map((e) => e.envoi);
}

/**
 * Envoyeur des transactions d'une instance.
 * @param {object} p
 * @param {import("./rpc.mjs").ClientRpc} p.rpc
 * @param {string} p.repertoireEnvois répertoire des envois, issues et captures (`--captures` de CT-4)
 * @param {{evmChainId: number, bftChainId: string, contrats: {attestation_registry: string, period_registry: string, recorder_registry: string}, fees: {gas_limit: number, gas_limit_max?: number}, jeux: object}} p.instance
 * @param {{murale(): number, monotone(): number}} p.horloge
 * @param {(ms: number) => Promise<void>} p.attendre
 * @param {{recuMs?: number, sondageMs?: number}} [p.delais]
 * @param {(niveau: string, evenement: string, champs: object) => void} [p.journal]
 */
export class Envoyeur {
  #rpc;
  #repertoire;
  #instance;
  #horloge;
  #attendre;
  #delais;
  #journal;
  /** request_id des envois faits par cette instance (hachage → identifiant), pour `renvoyer` et `remplacer`. */
  #demandes = new Map();
  /** Index en mémoire des envois et de leurs issues (`hash → { envoi, issue }`), chargé une fois du répertoire puis tenu à jour (R-D-4). */
  #index = null;
  /** Index des captures d'ancre par empreinte et de clôture par `periodHash`, chargé une fois puis tenu à jour. */
  #captures = null;

  constructor({ rpc, repertoireEnvois, instance, horloge, attendre, delais = {}, journal = null }) {
    if (!rpc || typeof rpc.appeler !== "function") throw new TypeError("client JSON-RPC attendu");
    if (typeof repertoireEnvois !== "string" || repertoireEnvois.length === 0) throw new TypeError("répertoire des envois attendu");
    if (!instance || versEntier(instance.evmChainId) === null || typeof instance.bftChainId !== "string" || !instance.contrats) throw new TypeError("instance : evmChainId, bftChainId, contrats attendus");
    for (const nom of ["attestation_registry", "period_registry", "recorder_registry"]) {
      if (!estHexOctets(instance.contrats[nom], 20)) throw new TypeError(`instance.contrats.${nom} : adresse attendue`);
    }
    if (!horloge || typeof horloge.murale !== "function" || typeof horloge.monotone !== "function") throw new TypeError("horloge { murale, monotone } attendue");
    if (typeof attendre !== "function") throw new TypeError("fonction attendre(ms) attendue");
    this.#rpc = rpc;
    this.#repertoire = repertoireEnvois;
    this.#instance = { ...instance, fees: { gas_limit: 3000000, gas_limit_max: 16777216, ...(instance.fees ?? {}) } };
    this.#horloge = horloge;
    this.#attendre = attendre;
    this.#delais = { ...DELAIS_DEFAUT, ...delais };
    this.#journal = journal;
  }

  get repertoire() {
    return this.#repertoire;
  }

  #consigner(niveau, evenement, champs) {
    if (this.#journal) this.#journal(niveau, evenement, champs);
  }

  #echec(requestId, code, detail = {}) {
    this.#consigner("warn", "registry_send_failed", { request_id: requestId, code, ...detail });
    return { type: "echec_registre", data: { request_id: requestId, code }, outputs: { ...detail } };
  }

  /** Index des envois : chargé du répertoire à la première demande (une lecture), puis tenu à jour par l'`Envoyeur`. */
  #chargerIndex() {
    if (this.#index === null) {
      this.#index = new Map();
      for (const e of lireEnvois(this.#repertoire)) this.#index.set(e.envoi.transaction_hash, { envoi: e.envoi, issue: e.issue });
    }
    return this.#index;
  }

  /** Oublie l'index des envois et des captures (rechargés à la prochaine demande) : après une écriture par un autre processus. */
  oublierIndex() {
    this.#index = null;
    this.#captures = null;
  }

  /** L'envoi d'un hachage (`{ envoi, issue|null }`) connu de l'index, ou `null`. */
  envoi(transactionHash) {
    return this.#chargerIndex().get(transactionHash) ?? null;
  }

  /** Les envois de cette clé sans issue connue (OP-3). */
  envoisEnAttente(adresse) {
    return envoisSansIssueParHash(this.#chargerIndex(), adresse);
  }

  // ----------------------------------------------------------- ancrer

  /**
   * Ancre une empreinte (CT-5 EX-9.3 ; CT-4 §8.6, §9.4). Entrées : `orgId`,
   * `journalId`, `objet` (`checkpointHash` ou `periodHash`, 32 octets),
   * `docType` (point ou période), `cle` (`SignataireChaine`), `fingerprint`
   * facultative (comparée à l'empreinte recalculée, AN-44), `clePublique`
   * Ed25519 facultative (AN-46 : la clé de chaîne est celle sous laquelle
   * elle est inscrite), `requestId` facultatif (sinon dérivé de `docType`
   * et `objet`), `sansInscription` (vrai : l'émetteur n'est pas contrôlé au
   * `RecorderRegistry`, pour un essai ; jamais en exploitation).
   * Rend `{ type: "inclusion_registre", data: { request_id, block_number,
   * capture_sha256 }, outputs }` ou `{ type: "echec_registre", data: {
   * request_id, code }, outputs }`. Le `request_id` d'un envoi est retenu
   * en mémoire pour `renvoyer` et `remplacer` ; après un redémarrage,
   * l'appelant (qui tient la file) le passe lui-même, faute de quoi il est
   * reconstruit avec l'empreinte à la place de l'objet (`objet` n'est pas
   * recouvrable depuis la transaction : LISEZMOI-D.md, « Lectures »).
   */
  async ancrer({ orgId, journalId, objet, docType, cle, fingerprint = null, clePublique = null, requestId = null, sansInscription = false }) {
    if (docType !== DOC_TYPE_POINT_DE_CONTROLE && docType !== DOC_TYPE_PERIODE) throw new TypeError("docType du point ou de la période attendu (AN-45)");
    const sorte = docType === DOC_TYPE_POINT_DE_CONTROLE ? "ancre_registre_point" : "ancre_registre_periode";
    if (!estHexOctets(objet, 32)) throw new TypeError("objet : checkpointHash ou periodHash de 32 octets attendu");
    const id = requestId ?? `${sorte}:${objet}`;
    if (!/^(ancre_registre_periode|ancre_registre_point):0x[0-9a-f]{64}$/.test(id)) throw new TypeError("request_id hors de sa forme");
    const emp = empreinteAncre(orgId, journalId, objet, fingerprint);
    if (emp.statut !== "reussi") return this.#echec(id, `empreinte_${emp.motif}`);
    const fp = emp.fingerprint;
    const adresse = cle.adresse();
    const contrat = this.#instance.contrats.attestation_registry;

    // OP-3 : un seul envoi sans issue par expéditeur (EX-9.4, EX-8.14).
    const enAttente = this.envoisEnAttente(adresse);
    if (enAttente.length > 0) return this.#echec(id, "attente_nonce", { pending: enAttente.map((e) => e.transaction_hash) });

    try {
      // OP-9 : clé de chaîne inscrite et active (AN-46 ; `sansInscription` : émetteur hors du registre des
      // enregistreurs, pour un essai de tiers), empreinte libre.
      if (!sansInscription) {
        const active = await isActiveRecorder({ rpc: this.#rpc, contrat: this.#instance.contrats.recorder_registry, orgId, chainKey: adresse });
        if (!active) return this.#echec(id, "cle_chaine_non_inscrite");
        if (clePublique) {
          const r = await recorderByPubKey({ rpc: this.#rpc, contrat: this.#instance.contrats.recorder_registry, orgId, clePublique });
          if (r.chainKey !== adresse) return this.#echec(id, "cle_chaine_non_inscrite", { registered_chain_key: r.chainKey });
        }
      }
      const classe = await classerEmpreinte({ rpc: this.#rpc, contrat, fingerprint: fp, emetteur: adresse, docType });
      if (classe.etat === "empreinte_squattee") {
        return this.#echec(id, "empreinte_squattee", { lookup: { issuer: classe.lookup.issuer, doc_type: classe.lookup.docType, issued_at: classe.lookup.issuedAt.toString() } });
      }
      if (classe.etat === "deja_fait") {
        const existante = this.#captureDe(fp);
        if (existante) return this.#inclusion(id, existante, null);
        // R-D-1 : l'ancre est au registre sous cette clé sans capture (reçu sans journal, capture manquée) : la
        // transaction de l'envoi connu est relue et capturée (EX-9.9 : « reprise tant que la fenêtre le permet »).
        const reprise = await this.#capturerEnvoiConnu({ id, adresse, choisir: (o) => o.role === "ancre" && o.attendu.fingerprint === fp });
        if (reprise) return reprise;
        return this.#echec(id, "deja_fait", { lookup: { issuer: classe.lookup.issuer, doc_type: classe.lookup.docType, issued_at: classe.lookup.issuedAt.toString() } });
      }
      // Condensé d'ancre (RG-9), comparé à celui du contrat (EX-6.1, OP-6), signé par la clé de chaîne (RG-12).
      const condense = anchorDigest(this.#instance.evmChainId, contrat, fp, docType);
      const duContrat = await anchorDigestContrat({ rpc: this.#rpc, contrat, fingerprint: fp, docType });
      if (duContrat !== condense) return this.#echec(id, "condense_different");
      const sig = await cle.signerCondense(hachageSigne(condense));
      if (!lireSignature(sig)) return this.#echec(id, "signature_non_canonique");
      const donnees = encoderAnchor({ fingerprint: fp, doc_type: docType, issuer: adresse, signature: { v: sig.v, r: sig.r, s: sig.s } });
      // Envoi, reçu, capture.
      return await this.#envoyerEtCapturer({
        id, cle, to: contrat, donnees, role: "ancre", contrat,
        verifierRecu: (journal) => journal && journal.fingerprint === fp && journal.issuer === adresse && journal.docType === docType,
        attendu: { fingerprint: fp },
        detail: { fingerprint: fp, doc_type: docType },
      });
    } catch (e) {
      if (e instanceof ErreurLecture || e instanceof ErreurRpc) return this.#echec(id, e.code === "noeud_injoignable" ? "noeud_injoignable" : `lecture_${e.code}`, { message: e.message });
      throw e;
    }
  }

  // ------------------------------------------------------------ clore

  /**
   * Clôture d'une période (CT-4 §8.2, `submitPeriod`) : `periodMeta`
   * (format `meta_periode`), `signatures` des approbateurs (`[{ signer, v,
   * r, s }]`, rangées par adresse croissante, RG-13), `cle` (clé de chaîne),
   * `membres` et `seuil` du jeu quand l'appelant les connaît (RG-13 ; sinon
   * l'ordre et la distinction seuls sont vérifiés), `periodePrecedente`
   * facultative (`{ period_end, last_seq }`), `requestId` (par défaut
   * `cloture:<periodHash>`, hors du schéma du planificateur).
   * Rend `{ type: "inclusion_registre"|"echec_registre", data, outputs }`.
   */
  async clore({ periodMeta, signatures, cle, membres = null, seuil = undefined, periodePrecedente = null, requestId = null }) {
    const meta = lirePeriodMeta(periodMeta);
    const id = requestId ?? `cloture:${meta?.period_hash ?? "0x" + "00".repeat(32)}`;
    const rg5 = verifierPeriodMeta(periodMeta, periodePrecedente);
    if (rg5.statut !== "reussi") return this.#echec(id, rg5.motif);
    const adresse = cle.adresse();
    const contrat = this.#instance.contrats.period_registry;
    const enAttente = this.envoisEnAttente(adresse);
    if (enAttente.length > 0) return this.#echec(id, "attente_nonce", { pending: enAttente.map((e) => e.transaction_hash) });
    try {
      // OP-10 : periodHash inconnu ; continuité avec la dernière période du journal ; ancre présente et capturée (EX-8.4).
      const connu = await isKnown({ rpc: this.#rpc, contrat, orgId: meta.org_id, periodHash: meta.period_hash });
      if (connu) {
        const dernier = await latestPeriodOf({ rpc: this.#rpc, contrat, orgId: meta.org_id, journalId: meta.journal_id });
        const derniere = dernier > 0n ? await getPeriod({ rpc: this.#rpc, contrat, id: dernier }) : null;
        if (derniere && derniere.periodHash === meta.period_hash) {
          const existante = this.#captureDeCloture(meta.period_hash);
          if (existante) return this.#inclusion(id, existante, null);
          const reprise = await this.#capturerEnvoiConnu({ id, adresse, choisir: (o) => o.role === "cloture" && o.attendu.periodHash === meta.period_hash });
          return reprise ?? this.#echec(id, "deja_fait");
        }
        return this.#echec(id, "doublon");
      }
      const dernier = await latestPeriodOf({ rpc: this.#rpc, contrat, orgId: meta.org_id, journalId: meta.journal_id });
      if (dernier > 0n) {
        const derniere = await getPeriod({ rpc: this.#rpc, contrat, id: dernier });
        if (derniere.periodEnd !== meta.period_start) return this.#echec(id, "discontinuite_temporelle");
        if (derniere.lastSeq + 1n !== meta.first_seq) return this.#echec(id, "discontinuite_sequence");
      }
      // EX-8.4 : l'ancre de la période est incluse et capturée ; lookup est lu sur le validateur qui a servi la capture
      // (les validateurs ne commettent pas tous un bloc au même instant), à défaut sur le premier point.
      const emp = empreinteAncre(meta.org_id, meta.journal_id, meta.period_hash);
      const captureAncre = this.#captureDe(emp.fingerprint);
      const pointCapture = captureAncre && this.#rpc.points().includes(captureAncre.index.node.rpc) ? captureAncre.index.node.rpc : undefined;
      const l = await lookup({ rpc: this.#rpc, contrat: this.#instance.contrats.attestation_registry, fingerprint: emp.fingerprint, point: pointCapture });
      if (!l.anchored || l.issuer !== adresse || !captureAncre) return this.#echec(id, "ancre_manquante");
      // Condensé de clôture (RG-6), comparé au contrat (OP-6) ; signatures (RG-12, RG-13, OP-7).
      const condense = periodDigest(this.#instance.evmChainId, contrat, periodMeta);
      const duContrat = await periodDigestContrat({ rpc: this.#rpc, contrat, meta: periodMeta });
      if (duContrat !== condense) return this.#echec(id, "condense_different");
      const jeu = verifierJeuSignatures(condense, signatures, { membres, seuil });
      if (jeu.statut !== "reussi") return this.#echec(id, jeu.check === "RG-12" ? "signature_non_canonique" : jeu.motif === "signataire_hors_jeu" ? "signataire_hors_jeu" : jeu.motif === "nombre_signatures" ? "signatures_insuffisantes" : "signature_non_canonique");
      const donnees = encoderSubmitPeriod({ period_meta: periodMeta, signatures: signatures.map((s) => ({ v: s.v, r: s.r, s: s.s })) });
      return await this.#envoyerEtCapturer({
        id, cle, to: contrat, donnees, role: "cloture", contrat,
        verifierRecu: (journal) => journal && journal.periodHash === meta.period_hash && journal.orgId === meta.org_id && journal.journalId === meta.journal_id,
        attendu: { periodHash: meta.period_hash },
        detail: { period_hash: meta.period_hash },
      });
    } catch (e) {
      if (e instanceof ErreurLecture || e instanceof ErreurRpc) return this.#echec(id, e.code === "noeud_injoignable" ? "noeud_injoignable" : `lecture_${e.code}`, { message: e.message });
      throw e;
    }
  }

  // ------------------------------------------------------ mécanique

  /** Index des captures (`ancres` par empreinte, `clotures` par periodHash, `parTransaction`), chargé une fois du répertoire. */
  #chargerCaptures() {
    if (this.#captures === null) {
      this.#captures = { ancres: new Map(), clotures: new Map(), parTransaction: new Map() };
      for (const c of listerCaptures(this.#repertoire)) this.#indexerCapture(c);
    }
    return this.#captures;
  }

  #indexerCapture(c) {
    const idx = this.#chargerCaptures();
    idx.parTransaction.set(c.index.transaction_hash, c);
    if (c.index.role !== "ancre" && c.index.role !== "cloture") return;
    const journal = this.#journalDe(c.index);
    if (!journal) return;
    if (c.index.role === "ancre" && journal.fingerprint) idx.ancres.set(journal.fingerprint, c);
    if (c.index.role === "cloture" && journal.periodHash) idx.clotures.set(journal.periodHash, c);
  }

  /** Capture d'ancre de cette empreinte ; en cas d'absence, le répertoire est relu une fois (capture faite hors de cet `Envoyeur`). */
  #captureDe(fingerprint) {
    const idx = this.#chargerCaptures();
    if (idx.ancres.has(fingerprint)) return idx.ancres.get(fingerprint);
    this.#captures = null;
    return this.#chargerCaptures().ancres.get(fingerprint) ?? null;
  }

  #captureDeCloture(periodHash) {
    const idx = this.#chargerCaptures();
    if (idx.clotures.has(periodHash)) return idx.clotures.get(periodHash);
    this.#captures = null;
    return this.#chargerCaptures().clotures.get(periodHash) ?? null;
  }

  #captureParTransaction(transactionHash) {
    const idx = this.#chargerCaptures();
    if (idx.parTransaction.has(transactionHash)) return idx.parTransaction.get(transactionHash);
    this.#captures = null;
    return this.#chargerCaptures().parTransaction.get(transactionHash) ?? null;
  }

  /**
   * R-D-1 : relit le reçu de l'envoi connu de cette clé qui porte l'objet
   * cherché (`choisir(objet de #roleDeEnvoi)`), l'envoi inclus d'abord, et le
   * conclut (journal, capture, issue). Rend un résultat, ou `null` quand aucun
   * envoi ne convient ou qu'aucun point ne rend de reçu.
   */
  async #capturerEnvoiConnu({ id, adresse, choisir }) {
    const candidats = [];
    for (const e of this.#chargerIndex().values()) {
      if (e.envoi.from !== adresse) continue;
      let objet;
      try {
        objet = this.#roleDeEnvoi(e.envoi);
      } catch {
        objet = null;
      }
      if (objet && choisir(objet)) candidats.push({ e, objet });
    }
    candidats.sort((a, b) => Number(Boolean(b.e.issue && typeof b.e.issue.block_number === "number")) - Number(Boolean(a.e.issue && typeof a.e.issue.block_number === "number")));
    for (const { e, objet } of candidats) {
      if (e.issue && e.issue.state === "ecartee") continue;
      const obtenu = await this.#attendreRecu([e.envoi.transaction_hash], 0);
      if (!obtenu) continue;
      this.#consigner("info", "registry_capture_resumed", { request_id: id, transaction_hash: e.envoi.transaction_hash });
      return this.#conclure({ ...objet, id, envoi: e.envoi, recu: obtenu.recu, point: obtenu.point });
    }
    return null;
  }

  #journalDe(index) {
    const lecteur = lecteurRepertoire(this.#repertoire);
    const recu = lireJson(lecteur.lire(index.files.receipts[index.transaction_index]?.name));
    const j = recu?.result?.logs?.[index.log_index];
    return j ? decoderJournal(index.role, { address: j.address, topics: j.topics, data: j.data }) : null;
  }

  #inclusion(id, capture, envoi, extra = {}) {
    const data = { request_id: id, block_number: capture.index.block_number, capture_sha256: capture.sha256 };
    this.#consigner("info", "registry_included", { request_id: id, block_number: data.block_number, transaction_hash: capture.index.transaction_hash });
    return { type: "inclusion_registre", data, outputs: { transaction_hash: capture.index.transaction_hash, capture: capture.nom ?? null, envoi: envoi ? nomEnvoi(envoi.transaction_hash) : null, ...extra } };
  }

  /**
   * Nonce d'EX-8.14 de CT-4 : `eth_getTransactionCount(expéditeur, "latest")`,
   * le plus grand que rendent les validateurs. Un validateur en retard d'un
   * bloc rend le nonce d'une transaction déjà incluse ailleurs : signée à ce
   * nonce, la transaction serait refusée partout (« nonce too low », ou
   * « replacement transaction underpriced » par le validateur en retard qui
   * la tient encore en mempool), observé sur le réseau de développement à
   * l'étape 5.
   */
  async #nonce(adresse) {
    const reponses = await this.#rpc.appelerTous("eth_getTransactionCount", [adresse, "latest"]);
    if (reponses.every((r) => r.panne)) throw reponses[0]?.panne ?? new ErreurRpc("noeud_injoignable", "aucun point", null);
    let n = null;
    for (const r of reponses) {
      const v = r.panne || r.erreur ? null : quantiteVersEntier(r.resultat, MAX_U64);
      if (v !== null && (n === null || v > n)) n = v;
    }
    if (n === null) throw new ErreurLecture("retour_illisible", "eth_getTransactionCount illisible");
    return n;
  }

  async #solde(adresse) {
    const r = await this.#rpc.appelerPremier("eth_getBalance", [adresse, "latest"]);
    const n = r.erreur ? null : quantiteVersEntier(r.resultat, MAX_U256);
    if (n === null) throw new ErreurLecture("retour_illisible", "eth_getBalance illisible");
    return n;
  }

  /** Construit, signe (RG-15 vérifiée sur les octets signés, EX-8.13) et écrit l'envoi ; rend l'envoi ou `{ echec }`. */
  async #signerEtEcrire({ cle, to, donnees, nonce, frais, remplace = null }) {
    const fees = this.#instance.fees;
    const tx = construireTransaction({
      chain_id: this.#instance.evmChainId, nonce, max_priority_fee_per_gas: frais, max_fee_per_gas: frais,
      gas_limit: fees.gas_limit, to, value: 0n, data: donnees,
    });
    const signee = await signerTransaction(tx, cle);
    const rg15 = verifierRG15(signee.octets, { evm_chain_id: this.#instance.evmChainId, fees, objet: "appel", to, data: octetsVersHex(donnees), remplace });
    if (rg15.statut !== "reussi") return { echec: `rg15_${rg15.motif}` };
    // OP-3 : solde ≥ gasLimit × maxFeePerGas + value (EX-4.18).
    const solde = await this.#solde(cle.adresse());
    if (solde < BigInt(fees.gas_limit) * frais) return { echec: "solde_insuffisant", solde: solde.toString() };
    const envoi = {
      from: signee.from, to, nonce: Number(nonce), type: 2,
      max_fee_per_gas: frais.toString(), max_priority_fee_per_gas: frais.toString(), gas_limit: String(fees.gas_limit), value: "0",
      raw_transaction: signee.raw_transaction, transaction_hash: signee.transaction_hash,
      submitted_to: this.#rpc.points().slice(0, 8), submitted_at: ecrireHorodatage(this.#horloge.murale()),
    };
    const v = verifierEnvoi(envoi);
    if (!v.valide) throw new Error(`envoi hors schéma : ${v.erreurs.join(" ; ")}`);
    fs.mkdirSync(this.#repertoire, { recursive: true });
    if (!ecrireExclusif(path.join(this.#repertoire, nomEnvoi(envoi.transaction_hash)), serialiser(envoi))) {
      return { echec: "envoi_existant", transaction_hash: envoi.transaction_hash };
    }
    synchroniserRepertoire(this.#repertoire);
    this.#chargerIndex().set(envoi.transaction_hash, { envoi, issue: null });
    return { envoi, octets: signee.octets };
  }

  /** Soumet les mêmes octets à chaque validateur (EX-8.15) ; rend `{ acceptes, refus, pannes }`. */
  async #soumettre(raw) {
    const reponses = await this.#rpc.appelerTous("eth_sendRawTransaction", [raw]);
    const acceptes = [];
    const refus = [];
    const pannes = [];
    for (const r of reponses) {
      if (r.panne) pannes.push({ point: r.point, message: r.panne.message });
      else if (r.erreur) refus.push({ point: r.point, code: r.erreur.code, message: r.erreur.message });
      else acceptes.push(r.point);
    }
    return { acceptes, refus, pannes };
  }

  /** Sonde le reçu sur tous les points jusqu'à `recuMs` ; rend `{ recu, point }` ou null. */
  async #attendreRecu(hashes, recuMs = this.#delais.recuMs) {
    const debut = this.#horloge.monotone();
    for (;;) {
      for (const hash of hashes) {
        for (const point of this.#rpc.points()) {
          try {
            const r = await this.#rpc.appeler("eth_getTransactionReceipt", [hash], { point });
            if (!r.erreur && r.resultat && typeof r.resultat === "object") return { recu: r, point, hash };
          } catch (e) {
            if (!(e instanceof ErreurRpc)) throw e;
          }
        }
      }
      if (this.#horloge.monotone() - debut >= recuMs) return null;
      await this.#attendre(this.#delais.sondageMs);
    }
  }

  #ecrireIssue(issue) {
    const v = verifierIssue(issue);
    if (!v.valide) throw new Error(`issue hors schéma : ${v.erreurs.join(" ; ")}`);
    const ecrite = ecrireExclusif(path.join(this.#repertoire, nomIssue(issue.transaction_hash)), serialiser(issue));
    synchroniserRepertoire(this.#repertoire);
    const entree = this.#chargerIndex().get(issue.transaction_hash);
    if (entree && (ecrite || entree.issue === null)) entree.issue = ecrite ? issue : lireJson(lecteurRepertoire(this.#repertoire).lire(nomIssue(issue.transaction_hash))) ?? issue;
  }

  /** Après un reçu : statut, journal attendu (OP-11), capture (CP-1 à CP-6), issue, résultat. */
  async #conclure({ id, envoi, recu, point, role, contrat, verifierRecu, attendu, detail }) {
    const statut = recu.resultat.status;
    const hauteur = quantiteVersEntier(recu.resultat.blockNumber, MAX_U64);
    if (statut !== "0x1" || hauteur === null) {
      this.#ecrireIssue({ version: 0, transaction_hash: envoi.transaction_hash, block_number: Number(hauteur ?? 0n) || 1, status: statut === "0x0" ? "0x0" : "0x1", recorded_at: ecrireHorodatage(this.#horloge.murale()) });
      // Une ancre refusée par le contrat : l'empreinte a pu être prise entre la lecture d'OP-9 et l'inclusion (course
      // entre validateurs, CT-4 §8.3) ; l'état relu la classe (EX-5.12 : jamais le texte du refus).
      if (role === "ancre" && attendu?.fingerprint) {
        try {
          const l = await lookup({ rpc: this.#rpc, contrat, fingerprint: attendu.fingerprint });
          if (l.anchored && l.issuer !== envoi.from) {
            return this.#echec(id, "empreinte_squattee", { transaction_hash: envoi.transaction_hash, block_number: Number(hauteur ?? 0n), lookup: { issuer: l.issuer, doc_type: l.docType, issued_at: l.issuedAt.toString() } });
          }
        } catch (e) {
          if (!(e instanceof ErreurLecture) && !(e instanceof ErreurRpc)) throw e;
        }
      }
      return this.#echec(id, "transaction_annulee", { transaction_hash: envoi.transaction_hash, block_number: Number(hauteur ?? 0n) });
    }
    const sujet = role === "ancre" ? SUJETS.Anchored : SUJETS.PeriodSubmitted;
    const journalAttendu = (resultat) => {
      const journaux = Array.isArray(resultat?.logs) ? resultat.logs : [];
      for (let k = 0; k < journaux.length; k++) {
        const j = journaux[k];
        if (!j || typeof j.address !== "string" || j.address.toLowerCase() !== contrat || !Array.isArray(j.topics) || j.topics[0] !== sujet) continue;
        let decode = null;
        try {
          decode = decoderJournal(role, { address: j.address.toLowerCase(), topics: j.topics, data: j.data });
        } catch {
          decode = null;
        }
        if (verifierRecu(decode)) return k;
      }
      return -1;
    };
    let logIndex = journalAttendu(recu.resultat);
    if (logIndex < 0) {
      // R-D-1 : un reçu `0x1` sans le journal attendu (OP-11) ne clôt jamais l'envoi : le reçu est relu sur chaque
      // autre point ; si aucun ne rend le journal, l'issue reste incertaine (aucun fichier d'issue) et l'envoi, toujours
      // sans issue, sera renvoyé puis relu (EX-8.16) jusqu'à la capture. L'ancre de la période n'est jamais perdue (EX-4.5).
      for (const autre of this.#rpc.points().filter((x) => x !== point)) {
        try {
          const r = await this.#rpc.appeler("eth_getTransactionReceipt", [envoi.transaction_hash], { point: autre });
          if (r.erreur || !r.resultat || typeof r.resultat !== "object" || r.resultat.status !== "0x1") continue;
          const k = journalAttendu(r.resultat);
          if (k >= 0) {
            recu = r;
            point = autre;
            logIndex = k;
            break;
          }
        } catch (e) {
          if (!(e instanceof ErreurRpc)) throw e;
        }
      }
      if (logIndex < 0) {
        return this.#echec(id, "recu_incertain", { transaction_hash: envoi.transaction_hash, block_number: Number(hauteur), message: "journal attendu absent du reçu sur chaque point (OP-11) : issue incertaine, le reçu sera relu" });
      }
    }
    const capture = await capturer({
      rpc: this.#rpc, transactionHash: envoi.transaction_hash, role, contrat, horloge: this.#horloge, repertoire: this.#repertoire,
      instance: this.#instance, attendre: this.#attendre, sending: envoi, attendu, point, recu,
    });
    // L'issue d'inclusion est écrite dès le reçu : le nonce est consommé, quel que soit l'état de la capture.
    this.#ecrireIssue({ version: 0, transaction_hash: envoi.transaction_hash, block_number: Number(hauteur), status: "0x1", recorded_at: ecrireHorodatage(this.#horloge.murale()) });
    const gasUsed = quantiteVersEntier(recu.resultat.gasUsed, MAX_U64) ?? 0n;
    const coutWei = (gasUsed * BigInt(envoi.max_fee_per_gas)).toString();
    if (capture.erreur) {
      return this.#echec(id, capture.erreur.code, { transaction_hash: envoi.transaction_hash, block_number: Number(hauteur), check: capture.erreur.check, message: capture.erreur.message, cost_wei: coutWei, ...detail });
    }
    this.#indexerCapture(capture);
    return this.#inclusion(id, capture, envoi, { cost_wei: coutWei, gas_used: gasUsed.toString(), log_index: logIndex, ...detail });
  }

  async #envoyerEtCapturer({ id, cle, to, donnees, role, contrat, verifierRecu, attendu, detail }) {
    const nonce = await this.#nonce(cle.adresse());
    const prepare = await this.#signerEtEcrire({ cle, to, donnees, nonce, frais: 1n });
    if (prepare.echec) return this.#echec(id, prepare.echec, { ...prepare, echec: undefined });
    const { envoi, octets } = prepare;
    this.#demandes.set(envoi.transaction_hash, id);
    this.#consigner("info", "registry_sent", { request_id: id, transaction_hash: envoi.transaction_hash, nonce: envoi.nonce, ...detail });
    const soumission = await this.#soumettre(envoi.raw_transaction);
    if (soumission.acceptes.length === 0) {
      // Refusée ou injoignable partout : la transaction n'est dans aucune mempool, l'envoi est écarté.
      this.#ecrireIssue({ version: 0, transaction_hash: envoi.transaction_hash, state: "ecartee", recorded_at: ecrireHorodatage(this.#horloge.murale()) });
      const code = soumission.refus.length > 0 ? "transaction_refusee" : "noeud_injoignable";
      return this.#echec(id, code, { transaction_hash: envoi.transaction_hash, refus: soumission.refus, pannes: soumission.pannes });
    }
    const obtenu = await this.#attendreRecu([envoi.transaction_hash]);
    if (!obtenu) return this.#echec(id, "recu_absent", { transaction_hash: envoi.transaction_hash, nonce: envoi.nonce, submitted_to: soumission.acceptes });
    return this.#conclure({ id, envoi, recu: obtenu.recu, point: obtenu.point, role, contrat, verifierRecu, attendu, detail });
  }

  // ------------------------------------------------------------ reprise

  #envoiDe(transactionHash) {
    return this.envoi(transactionHash);
  }

  #roleDeEnvoi(envoi) {
    const tx = lireTransaction(envoi.raw_transaction);
    const selecteur = octetsVersHex(tx.data.subarray(0, 4));
    if (tx.to === this.#instance.contrats.attestation_registry && selecteur === "0x73deb4ad") {
      const fp = octetsVersHex(tx.data.subarray(4, 36));
      const dt = octetsVersHex(tx.data.subarray(36, 68));
      const issuer = octetsVersHex(tx.data.subarray(80, 100));
      return { role: "ancre", contrat: tx.to, tx, verifierRecu: (j) => j && j.fingerprint === fp && j.issuer === issuer && j.docType === dt, attendu: { fingerprint: fp }, detail: { fingerprint: fp, doc_type: dt }, id: `${dt === DOC_TYPE_POINT_DE_CONTROLE ? "ancre_registre_point" : "ancre_registre_periode"}:${fp}` };
    }
    if (tx.to === this.#instance.contrats.period_registry && selecteur === "0x8af03732") {
      const periodHash = octetsVersHex(tx.data.subarray(4 + 64 + 64, 4 + 64 + 96));
      return { role: "cloture", contrat: tx.to, tx, verifierRecu: (j) => j && j.periodHash === periodHash, attendu: { periodHash }, detail: { period_hash: periodHash }, id: `cloture:${periodHash}` };
    }
    return null;
  }

  /**
   * EX-8.16, premier temps : renvoie les mêmes octets d'un envoi sans issue
   * à chaque validateur et attend de nouveau le reçu (un refus « nonce too
   * low » signifie que le nonce est consommé : les reçus sont relus, le refus
   * n'est pas compté). `requestId` facultatif.
   */
  async renvoyer(transactionHash, { requestId = null } = {}) {
    const e = this.#envoiDe(transactionHash);
    if (!e) throw new Error(`envoi ${transactionHash} inconnu`);
    const objet = this.#roleDeEnvoi(e.envoi);
    if (!objet) throw new Error("envoi dont l'objet n'est pas reconnu");
    const id = requestId ?? this.#demandes.get(transactionHash) ?? objet.id;
    if (e.issue && typeof e.issue.block_number === "number") {
      const capture = this.#captureParTransaction(transactionHash);
      if (capture) return this.#inclusion(id, capture, e.envoi);
      // Inclus sans capture (R-D-1) : le reçu est relu et la capture reprise.
      const obtenu = await this.#attendreRecu([transactionHash], 0);
      if (obtenu) return this.#conclure({ ...objet, id, envoi: e.envoi, recu: obtenu.recu, point: obtenu.point });
      return this.#echec(id, "capture_incomplete", { transaction_hash: transactionHash });
    }
    const soumission = await this.#soumettre(e.envoi.raw_transaction);
    const obtenu = await this.#attendreRecu([transactionHash]);
    if (!obtenu) {
      return this.#echec(id, soumission.pannes.length === this.#rpc.points().length ? "noeud_injoignable" : "recu_absent", { transaction_hash: transactionHash, refus: soumission.refus, pannes: soumission.pannes });
    }
    return this.#conclure({ ...objet, id, envoi: e.envoi, recu: obtenu.recu, point: obtenu.point });
  }

  /**
   * EX-8.16, second temps : si la transaction reste inconnue de tous les
   * points (`eth_getTransactionByHash` nul partout ; un point injoignable
   * compte comme un refus : `noeud_injoignable`), signe le même appel au
   * même nonce avec les frais `⌈1,1 × p⌉`, l'envoie, écrit l'issue
   * `remplacee` de l'original dès qu'un point accepte le remplaçant, puis
   * sonde les deux hachages : l'inclus est capturé, l'autre reçoit l'issue
   * `remplacee` ou `ecartee`.
   */
  async remplacer(transactionHash, { cle, requestId = null }) {
    const e = this.#envoiDe(transactionHash);
    if (!e) throw new Error(`envoi ${transactionHash} inconnu`);
    if (cle.adresse() !== e.envoi.from) throw new Error("la clé ne correspond pas à l'expéditeur de l'envoi");
    const objet = this.#roleDeEnvoi(e.envoi);
    if (!objet) throw new Error("envoi dont l'objet n'est pas reconnu");
    const id = requestId ?? this.#demandes.get(transactionHash) ?? objet.id;
    if (e.issue) return this.#echec(id, "envoi_avec_issue", { transaction_hash: transactionHash, issue: e.issue });
    // Inconnue de tous les points ?
    const reponses = await this.#rpc.appelerTous("eth_getTransactionByHash", [transactionHash]);
    for (const r of reponses) {
      if (r.panne) return this.#echec(id, "noeud_injoignable", { point: r.point });
      if (!r.erreur && r.resultat !== null) return this.#echec(id, "transaction_connue", { point: r.point, transaction_hash: transactionHash });
    }
    const frais = fraisRemplacement(e.envoi.max_fee_per_gas);
    const prepare = await this.#signerEtEcrire({ cle, to: e.envoi.to, donnees: objet.tx.data, nonce: BigInt(e.envoi.nonce), frais, remplace: e.envoi.max_fee_per_gas });
    if (prepare.echec) return this.#echec(id, prepare.echec, { ...prepare, echec: undefined });
    const remplacant = prepare.envoi;
    this.#demandes.set(remplacant.transaction_hash, id);
    const soumission = await this.#soumettre(remplacant.raw_transaction);
    if (soumission.acceptes.length === 0) {
      // Remplaçant refusé partout : aucune issue pour l'original (EX-8.16) ; le remplaçant est écarté.
      this.#ecrireIssue({ version: 0, transaction_hash: remplacant.transaction_hash, state: "ecartee", replaces: transactionHash, recorded_at: ecrireHorodatage(this.#horloge.murale()) });
      return this.#echec(id, soumission.refus.length > 0 ? "transaction_refusee" : "noeud_injoignable", { transaction_hash: remplacant.transaction_hash, refus: soumission.refus, pannes: soumission.pannes });
    }
    this.#ecrireIssue({ version: 0, transaction_hash: transactionHash, state: "remplacee", replaced_by: remplacant.transaction_hash, recorded_at: ecrireHorodatage(this.#horloge.murale()) });
    this.#consigner("info", "registry_replaced", { request_id: id, transaction_hash: transactionHash, replaced_by: remplacant.transaction_hash, fee_wei: frais.toString() });
    const obtenu = await this.#attendreRecu([remplacant.transaction_hash, transactionHash]);
    if (!obtenu) return this.#echec(id, "recu_absent", { transaction_hash: remplacant.transaction_hash, replaces: transactionHash });
    if (obtenu.hash === transactionHash) {
      // L'original a été inclus : le remplaçant est écarté ; l'issue « remplacee » de l'original est corrigée par une inclusion
      // (un fichier d'issue n'est jamais réécrit : l'inclusion est consignée dans l'index de capture et l'issue du remplaçant).
      this.#ecrireIssue({ version: 0, transaction_hash: remplacant.transaction_hash, state: "ecartee", replaces: transactionHash, recorded_at: ecrireHorodatage(this.#horloge.murale()) });
      return this.#conclure({ ...objet, id, envoi: { ...e.envoi }, recu: obtenu.recu, point: obtenu.point });
    }
    return this.#conclure({ ...objet, id, envoi: remplacant, recu: obtenu.recu, point: obtenu.point });
  }
}

export { nomEnvoi, nomIssue, hexVersOctets };
