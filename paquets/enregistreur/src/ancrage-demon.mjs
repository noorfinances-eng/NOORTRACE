// Branchement du composant d'ancrage de CT-5 (`@noortrace/ancrage`) dans le
// démon (CT-2 §15 `anchoring.ancrage`, §15.2, §15.4 pas 4 ; CT-5 EX-4.8,
// EX-4.9, EX-4.12 ; rubrique F d'`INTERFACES.md` du composant ; lot F2).
//
// Au démarrage, quand `anchoring.ancrage` n'est pas `null` : le document
// `ancrage-v0` est lu en JSON strict, ses références de secrets (`auth.secret`
// des prestataires, `headers_source.auth`) sont résolues par le résolveur de
// secrets de l'enregistreur (jamais écrites, jamais consignées), la clé de
// chaîne de `anchoring.registry.chain_key` est construite (classe D par
// `SignataireChaineFichier` ; une autre classe refuse le démarrage du démon
// avec un message qui nomme le reste), le manifeste d'instance du registre
// (CT-4 §4.8) est lu, puis le composant est construit sur un `contexte` dont
// tout vient du stockage de l'enregistreur (séries `points/`, manifestes,
// segments, clés de la chaîne, époque du bail) et démarré une fois le bail
// acquis et l'écrivain prêt. Une configuration d'ancrage invalide (AN-1,
// secret non résolu, document illisible) n'empêche jamais le démon de
// démarrer (CT-5 EX-4.8 ; CT-2 §14.2) : chaque remise est consignée
// `anchor_pending` et la raison nommée, sans valeur de secret.
//
// L'horloge du composant est celle de l'enregistreur (CT-2 §7.4), étendue de
// `programmer` (`setTimeout` du démon, ou la minuterie de l'horloge injectée
// par les tests) ; l'aléa est `crypto.randomBytes` ; le journal est le
// `JournalExploitation` du cœur (composant `ancrage`) et les métriques
// d'EX-8.15 sont exposées avec celles du cœur (`/metrics`, CT-2 §17.2).

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { decoderHorodatage, ecrireHorodatage, hacherManifeste, hacherPoint, octetsVersHex } from "@noortrace/noyau";
import {
  creerComposantAncrage, ErreurConfigurationAncrage, SignataireChaineFichier, verifierDemande, exporterDossier as exporterDossierAncrage, etatAncresPeriode, reexportsDus,
} from "@noortrace/ancrage";
import { analyserJsonIntegral } from "./jcs-integral.mjs";
import { parcourirSecrets } from "./configuration.mjs";
import { lireSecretsVault } from "./secrets-vault.mjs";
import { resoudreSecret, ErreurSecret } from "./secrets.mjs";
import { decouperLignes } from "./fichiers.mjs";
import { listerSegments, relireSegment } from "./segments.mjs";
import { nomSerie } from "./points.mjs";
import { nomsManifeste } from "./periodes.mjs";

/** Nom du manifeste d'instance du registre (CT-4 §4.8) lu à côté du document `ancrage-v0` (lecture F2-6 du LISEZMOI). */
export const FICHIER_INSTANCE_REGISTRE = "instance-registre.json";
/** Sous-répertoire du journal où vont les envois et les captures du registre (CT-4 §8.6, §9.4). */
export const REPERTOIRE_REGISTRE = "registre";
/** Classes de garde de la clé de chaîne que ce lot sait servir (CT-2 EX-11.19). */
export const CLASSES_CLE_CHAINE_SERVIES = Object.freeze(["D"]);
/** Taille maximale lue pour un document de configuration ou un manifeste (1 Mio). */
const TAILLE_MAX_DOCUMENT = 1024 * 1024;

const sansPrefixe = (h) => h.slice(2);
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Refus du démarrage du démon par le branchement (classe de clé de chaîne non servie). */
export class ErreurBranchementAncrage extends Error {
  constructor(raison, message) {
    super(message);
    this.name = "ErreurBranchementAncrage";
    this.raison = raison;
  }
}

/**
 * Lit un document JSON strict borné ; rend `{ document }` ou `{ erreur }` (sans le contenu).
 * @param {string} chemin
 */
export function lireDocumentJson(chemin) {
  let st;
  try {
    st = fs.statSync(chemin);
  } catch {
    return { document: null, erreur: "fichier illisible" };
  }
  if (!st.isFile()) return { document: null, erreur: "pas un fichier ordinaire" };
  if (st.size > TAILLE_MAX_DOCUMENT) return { document: null, erreur: `fichier de plus de ${TAILLE_MAX_DOCUMENT} octets` };
  try {
    return { document: analyserJsonIntegral(new Uint8Array(fs.readFileSync(chemin))), erreur: null };
  } catch (e) {
    return { document: null, erreur: `JSON strict : ${String(e?.message ?? e).slice(0, 120)}` };
  }
}

/**
 * Pas 4 d'EX-15.4 appliqué au document `ancrage-v0` : résout chaque référence
 * de secret (`env`, `file`, `vault`) en octets, par pointeur JSON relatif au
 * document (`/rfc3161/providers/<i>/auth/secret`, `/opentimestamps/headers_source/auth`).
 * Une chaîne en clair à la place d'une référence n'est pas une référence :
 * elle est laissée au schéma `ancrage-v0`, qui la refuse (AN-1). Rend
 * `{ secrets: Map, erreurs: [{ pointeur, regle }] }` ; aucune valeur n'y figure.
 * @param {object} document
 * @param {{env?: NodeJS.ProcessEnv, uid?: number|null, config?: object}} [o] `config` : la configuration du démon (adresse Vault du signataire, 15.2)
 */
export async function resoudreSecretsAncrage(document, o = {}) {
  const secrets = new Map();
  const erreurs = [];
  if (!estObjet(document)) return { secrets, erreurs };
  // Les seuls secrets d'`ancrage-v0` (CT-5 EX-4.8) : prestataires et source d'en-têtes.
  const porteur = { rfc3161: document.rfc3161, opentimestamps: document.opentimestamps };
  const refs = [];
  parcourirSecrets(porteur, "", (ref, pointeur) => {
    if (/^\/rfc3161\/providers\/[0-9]+\/auth\/secret$/.test(pointeur) || pointeur === "/opentimestamps/headers_source/auth") refs.push({ ref, pointeur });
  });
  let vault = new Map();
  if (refs.some((r) => r.ref.vault)) {
    const lus = await lireSecretsVault({ ...porteur, signer: o.config?.signer ?? null }, { env: o.env });
    vault = lus.valeurs;
    for (const e of lus.erreurs) if (refs.some((r) => r.pointeur === e.pointeur)) erreurs.push({ pointeur: e.pointeur, regle: e.regle });
  }
  for (const { ref, pointeur } of refs) {
    if (erreurs.some((e) => e.pointeur === pointeur)) continue;
    try {
      secrets.set(pointeur, resoudreSecret(ref, pointeur, { env: o.env, uid: o.uid, vault }));
    } catch (e) {
      if (!(e instanceof ErreurSecret)) throw e;
      erreurs.push({ pointeur, regle: e.regle });
    }
  }
  return { secrets, erreurs };
}

/**
 * Instance du registre pour le composant (`{ evmChainId, bftChainId, contrats,
 * fees, jeux }`) depuis un manifeste d'instance de CT-4 §4.8
 * (`instance-registre-v0` : `evm_chain_id`, `bft_chain_id`, `contracts[]`
 * nommés, `fees`, `validator_sets[]`). Rend `{ instance }` ou `{ erreur }`.
 */
export function instanceDepuisManifeste(manifeste) {
  if (!estObjet(manifeste)) return { instance: null, erreur: "manifeste d'instance : objet attendu" };
  const evm = manifeste.evm_chain_id;
  const bft = manifeste.bft_chain_id;
  if (!Number.isSafeInteger(evm) || evm < 1) return { instance: null, erreur: "evm_chain_id entier attendu" };
  if (typeof bft !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(bft)) return { instance: null, erreur: "bft_chain_id attendu" };
  const contrats = {};
  const noms = { AttestationRegistry: "attestation_registry", PeriodRegistry: "period_registry", RecorderRegistry: "recorder_registry" };
  if (Array.isArray(manifeste.contracts)) {
    for (const c of manifeste.contracts) {
      if (estObjet(c) && noms[c.name] && /^0x[0-9a-fA-F]{40}$/.test(c.address)) contrats[noms[c.name]] = c.address.toLowerCase();
    }
  } else if (estObjet(manifeste.contracts)) {
    for (const k of Object.values(noms)) if (/^0x[0-9a-fA-F]{40}$/.test(manifeste.contracts[k])) contrats[k] = manifeste.contracts[k].toLowerCase();
  }
  for (const k of Object.values(noms)) if (!contrats[k]) return { instance: null, erreur: `contrat ${k} absent du manifeste d'instance` };
  if (!Array.isArray(manifeste.validator_sets) || manifeste.validator_sets.length === 0) return { instance: null, erreur: "validator_sets attendus" };
  const fees = estObjet(manifeste.fees) ? manifeste.fees : {};
  const gasLimit = Number.isSafeInteger(fees.gas_limit) ? fees.gas_limit : 3000000;
  const gasLimitMax = Number.isSafeInteger(fees.gas_limit_max) ? fees.gas_limit_max : 16777216;
  return {
    instance: {
      evmChainId: evm, bftChainId: bft, contrats, fees: { gas_limit: gasLimit, gas_limit_max: gasLimitMax },
      jeux: { validator_sets: manifeste.validator_sets, source: typeof manifeste.source === "string" ? manifeste.source : `manifeste d'instance ${bft}` },
    },
    erreur: null,
  };
}

/**
 * Clé de chaîne de `anchoring.registry.chain_key` (CT-2 EX-11.19) : classe D
 * par `SignataireChaineFichier` depuis le secret résolu (pas 4) ; une classe
 * A à C lève `ErreurBranchementAncrage` (`classe_cle_chaine`) : le démarrage
 * est refusé avec un message qui nomme le reste (étape 7).
 * @param {object} config
 * @param {Map<string, Uint8Array>} secrets secrets résolus du démon (pointeur `/anchoring/registry/chain_key/secret`)
 */
export function cleChaineDepuisConfiguration(config, secrets) {
  const ck = config.anchoring?.registry?.chain_key ?? null;
  if (!ck) return null;
  if (!CLASSES_CLE_CHAINE_SERVIES.includes(ck.class)) {
    throw new ErreurBranchementAncrage("classe_cle_chaine", `clé de chaîne de classe ${ck.class} (anchoring.registry.chain_key) : seule la classe D est servie par ce lot ; les classes A à C (module de garde, service de signature) sont l'étape 7 (CT-2 EX-11.19)`);
  }
  const octets = secrets.get("/anchoring/registry/chain_key/secret");
  if (!(octets instanceof Uint8Array)) throw new ErreurBranchementAncrage("cle_chaine", "secret de la clé de chaîne non résolu (anchoring.registry.chain_key.secret)");
  let signataire;
  try {
    signataire = SignataireChaineFichier.depuisOctets(octets);
  } catch (e) {
    throw new ErreurBranchementAncrage("cle_chaine", `clé de chaîne illisible : ${String(e?.message ?? e).slice(0, 120)}`);
  }
  if (signataire.adresse() !== ck.address.toLowerCase()) {
    throw new ErreurBranchementAncrage("cle_chaine", `adresse de la clé de chaîne différente de anchoring.registry.chain_key.address (${ck.address})`);
  }
  return signataire;
}

/** Points JSON-RPC de `anchoring.registry.rpc_url` (chaîne, ou liste depuis CT-5 §14). */
function pointsRpc(registry) {
  const u = registry?.rpc_url;
  const liste = Array.isArray(u) ? u : typeof u === "string" ? [u] : [];
  return liste.filter((x) => typeof x === "string" && /^https?:\/\//.test(x));
}

/** Points d'une série relus sans rien modifier (une dernière ligne incomplète est ignorée). */
export function lireSerieSansModifier(chemin) {
  let octets;
  try {
    octets = new Uint8Array(fs.readFileSync(chemin));
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
  const points = [];
  for (const l of decouperLignes(octets)) {
    if (!l.complete) break;
    try {
      points.push(analyserJsonIntegral(l.octets));
    } catch {
      break;
    }
  }
  return points;
}

/**
 * Composant d'ancrage branché sur le démon : interface `ComposantAncrage` de
 * la rubrique g (`remettrePoint`, `remettreCloture`), `lier(coeur)` qui
 * construit le contexte depuis le stockage et démarre le composant,
 * `recharger`, `arreter`, `etat`, `metriques`, `retirerQualification`,
 * `exporterDossier` (exportateur de CT-5 §10) et `reexportsDus` (EX-10.5).
 */
export class BranchementAncrage {
  /**
   * @param {object} o
   * @param {object} o.config configuration validée du démon
   * @param {Map<string, Uint8Array>} o.secrets secrets résolus du démon
   * @param {NodeJS.ProcessEnv} [o.env]
   * @param {object|null} [o.document] document `ancrage-v0` déjà lu
   * @param {string|null} [o.erreurDocument]
   * @param {Map<string, Uint8Array>} [o.secretsAncrage]
   * @param {{pointeur: string, regle: string}[]} [o.erreursSecrets]
   * @param {object|null} [o.instance]
   * @param {string|null} [o.erreurInstance]
   * @param {import("@noortrace/ancrage").SignataireChaine|null} [o.cleChaine]
   * @param {{murale: () => number, monotone: () => number, programmer?: Function}} [o.horloge]
   * @param {(n: number) => Uint8Array} [o.aleatoire]
   * @param {object} [o.clients] clients injectés (tests)
   */
  constructor(o) {
    this.config = o.config;
    this.env = o.env ?? process.env;
    this.chemin = o.config.anchoring.ancrage;
    this.document = o.document ?? null;
    this.erreurDocument = o.erreurDocument ?? null;
    this.secretsAncrage = o.secretsAncrage ?? new Map();
    this.erreursSecrets = o.erreursSecrets ?? [];
    this.instance = o.instance ?? null;
    this.erreurInstance = o.erreurInstance ?? null;
    this.cleChaine = o.cleChaine ?? null;
    this.horlogeDonnee = o.horloge ?? null;
    this.aleatoire = o.aleatoire ?? ((n) => new Uint8Array(randomBytes(n)));
    this.clients = o.clients ?? {};
    this.composant = null;
    this.coeur = null;
    this.raison = null;
    this.clesPubliques = new Map();
    /** @type {Map<string, object>} résumé du dernier dossier exporté de chaque événement (EX-10.5), clé `<hash>:<seq>` */
    this.produits = new Map();
    /** @type {Map<string, {taille: number, mtimeMs: number, tsMin: number|null, tsMax: number|null}>} segments déjà relus par `lireHashesPeriode` */
    this.segmentsLus = new Map();
    /** Nombre de segments relus par `lireHashesPeriode` depuis le démarrage (supervision, essais). */
    this.segmentsRelus = 0;
    /** @type {Map<string, {generated_at: string, constat: string}>} dernier dossier_reexport_due écrit par événement (EX-15.13 point 4) */
    this.reexportsSignales = new Map();
    this.reexportPlanifie = false;
  }

  /** Résumés des dossiers exportés (EX-10.5) : le dernier de chaque événement, seul pris en compte par `reexportsDus`. */
  get dossiersProduits() {
    return [...this.produits.values()];
  }

  /** Configuration `ancrage-v0` en vigueur (celle du composant quand il existe). */
  get configuration() {
    return this.composant?.configuration ?? this.document;
  }

  /** Le composant est-il démarré ? */
  get demarre() {
    return this.composant?.etat().demarre === true && !this.composant.etat().arrete;
  }

  #journal(niveau, evenement, data = {}) {
    this.coeur?.journal?.consigner(niveau, "ancrage", evenement, data);
  }

  #horloge() {
    const base = this.coeur?.horlogeBrute ?? this.horlogeDonnee;
    const programmer = typeof this.horlogeDonnee?.programmer === "function"
      ? (ms, fn) => this.horlogeDonnee.programmer(ms, fn)
      : (ms, fn) => {
        const t = setTimeout(fn, Math.max(0, ms));
        t.unref?.();
        return () => clearTimeout(t);
      };
    return { murale: () => base.murale(), monotone: () => base.monotone(), programmer };
  }

  /** Répertoire des envois et des captures du registre, sous le répertoire du journal (CT-4 §8.6, §9.4). */
  get repertoireRegistre() {
    return this.coeur ? path.join(this.coeur.repertoire, REPERTOIRE_REGISTRE) : null;
  }

  // ------------------------------------------------------------ contexte

  /**
   * Hash des événements d'une période dans l'ordre des `seq`, relus dans les
   * segments (CT-1 §10.5 règle 2). Un segment dont la taille et la date de
   * modification n'ont pas changé depuis sa dernière lecture n'est relu que
   * s'il peut porter des événements de la période (bornes `ts` gardées en
   * mémoire) : les segments fermés ne changent plus et l'écrivain ferme le
   * segment à chaque clôture (EX-12.8), si bien qu'une admission ne relit que
   * le segment de la période. Avant, chaque point relisait tout l'historique
   * du journal (épreuves de l'étape 5 : délai d'admission croissant avec le
   * journal).
   */
  async lireHashesPeriode(periodStart) {
    const debut = periodStart * 1000;
    const fin = debut + 3600000;
    const hashes = [];
    const vus = new Set();
    for (const s of await listerSegments(path.join(this.coeur.repertoire, "segments"))) {
      vus.add(s.chemin);
      let st;
      try {
        st = fs.statSync(s.chemin);
      } catch {
        continue;
      }
      const connu = this.segmentsLus.get(s.chemin);
      const inchange = connu && connu.taille === st.size && connu.mtimeMs === st.mtimeMs;
      if (inchange && (connu.tsMax === null || connu.tsMax < debut || connu.tsMin >= fin)) continue;
      let octets;
      try {
        octets = new Uint8Array(fs.readFileSync(s.chemin));
      } catch {
        continue;
      }
      const r = relireSegment(octets, {});
      let tsMin = null;
      let tsMax = null;
      for (const e of r.evenements) {
        const ts = decoderHorodatage(e.ts);
        if (ts === null) continue;
        if (tsMin === null || ts < tsMin) tsMin = ts;
        if (tsMax === null || ts > tsMax) tsMax = ts;
        if (ts >= debut && ts < fin) hashes.push({ seq: e.seq, hash: e.hash });
      }
      this.segmentsLus.set(s.chemin, { taille: octets.length === st.size ? st.size : -1, mtimeMs: st.mtimeMs, tsMin, tsMax });
      this.segmentsRelus += 1;
    }
    for (const chemin of this.segmentsLus.keys()) if (!vus.has(chemin)) this.segmentsLus.delete(chemin);
    hashes.sort((a, b) => a.seq - b.seq);
    return hashes.map((x) => x.hash);
  }

  /** Série d'une période relue depuis `points/periode-<P>.ndjson` (sans troncature). */
  async lireSerie(periodStart) {
    return lireSerieSansModifier(path.join(this.coeur.repertoire, "points", nomSerie(periodStart)));
  }

  /** Manifestes et signatures durables (EX-8.12). */
  async listerPeriodes() {
    const dir = path.join(this.coeur.repertoire, "manifestes");
    let noms = [];
    try {
      noms = fs.readdirSync(dir).filter((n) => /^periode-[0-9]{10}\.json$/.test(n)).sort();
    } catch {
      return [];
    }
    const sortie = [];
    for (const n of noms) {
      try {
        const manifeste = analyserJsonIntegral(new Uint8Array(fs.readFileSync(path.join(dir, n))));
        const sig = path.join(dir, nomsManifeste(manifeste.period_start).signature);
        const signature = fs.existsSync(sig) ? analyserJsonIntegral(new Uint8Array(fs.readFileSync(sig))) : null;
        sortie.push({ manifeste, signature, periodHash: hacherManifeste(manifeste) });
      } catch {
        // manifeste illisible : ignoré ici, la relecture du cœur le signale
      }
    }
    return sortie;
  }

  /** Points de toutes les séries durables (EX-8.12). */
  async listerPoints() {
    const dir = path.join(this.coeur.repertoire, "points");
    let noms = [];
    try {
      noms = fs.readdirSync(dir).filter((n) => /^periode-[0-9]{10}\.ndjson$/.test(n)).sort();
    } catch {
      return [];
    }
    const points = [];
    for (const n of noms) points.push(...lireSerieSansModifier(path.join(dir, n)));
    return points;
  }

  /** Clés de la chaîne (index du cœur, clé courante du signataire) sous la forme d'un tableau de `cles.json`. */
  cles() {
    const liste = [];
    for (const [key_id, c] of this.coeur?.index?.cles ?? []) {
      const publique = c.public_key ?? (this.clesPubliques.has(key_id) ? octetsVersHex(this.clesPubliques.get(key_id)) : null);
      if (!publique) continue;
      liste.push({ key_id, algorithm: "ed25519", public_key: publique.toLowerCase(), valid_from: c.valid_from === null || c.valid_from === undefined ? "1970-01-01T00:00:00.000Z" : ecrireHorodatage(c.valid_from), valid_to: c.valid_to === null || c.valid_to === undefined ? null : ecrireHorodatage(c.valid_to), source: "chaîne du journal et signataire de l'enregistreur" });
    }
    for (const [key_id, octets] of this.clesPubliques) {
      if (!liste.some((k) => k.key_id === key_id)) liste.push({ key_id, algorithm: "ed25519", public_key: octetsVersHex(octets), valid_from: "1970-01-01T00:00:00.000Z", valid_to: null, source: "signataire de l'enregistreur" });
    }
    return liste;
  }

  /** Clé publique Ed25519 (octets) d'une clé connue, ou null. */
  clePublique(keyId) {
    if (this.clesPubliques.has(keyId)) return this.clesPubliques.get(keyId);
    const c = this.coeur?.index?.cles?.get(keyId);
    if (c?.public_key) {
      const h = c.public_key.slice(2);
      return Uint8Array.from(Buffer.from(h, "hex"));
    }
    return null;
  }

  /**
   * CT-4 §8.2, pas 4 et 5 : les signatures de clôture viennent des
   * approbateurs, par leur outil de signature, hors du démon. Le démon relaie
   * `submitPeriod` quand la demande signée au seuil a été déposée par
   * l'exploitant dans le répertoire du registre du journal sous
   * `demande-cloture-<periodHash>.json` (forme `demande_signature` de CT-4,
   * vérifiée par OP-6 et OP-7) ; sinon il rend `null` : la clôture reste à
   * relayer (`period_close_delegated`, reprise au tic).
   */
  async signaturesCloture(periodMeta) {
    const chemin = path.join(this.repertoireRegistre, `demande-cloture-${periodMeta.period_hash}.json`);
    const { document } = lireDocumentJson(chemin);
    if (!document) return null;
    const v = verifierDemande(document, { complete: true });
    if (v.resultat !== "valide" || document.operation !== "cloture" || document.fields?.period_meta?.period_hash !== periodMeta.period_hash) {
      this.#journal("error", "period_close_request_refused", { period_hash: periodMeta.period_hash, check: v.check ?? null, code: v.code ?? "operation_differente" });
      return null;
    }
    return { signatures: document.signatures, membres: null, seuil: document.signer_set?.threshold, periodePrecedente: null };
  }

  // ------------------------------------------------------------ démarrage

  /**
   * Construit le contexte depuis le cœur (époque du bail, stockage, clés) et
   * démarre le composant. Ne lève jamais : une configuration refusée (AN-1,
   * secrets, instance absente) laisse le démon en service et consigne
   * `anchor_pending` à chaque remise (EX-4.8).
   * @param {import("./coeur.mjs").Coeur} coeur
   */
  async lier(coeur) {
    this.coeur = coeur;
    // CT-2 EX-15.13 point 4 : dossier_reexport_due à chaque ancre arrivée (lignes du composant).
    if (typeof coeur.journal?.abonner === "function") this.#suivreReexports(coeur);
    const refuser = (raison, data = {}) => {
      this.raison = raison;
      this.#journal("error", "anchoring_not_started", { reason: raison, ...data });
      this.#journal("warning", "anchor_pending", { reason: raison });
    };
    if (this.erreurDocument) return refuser("document_illisible", { detail: this.erreurDocument });
    if (this.erreursSecrets.length) return refuser("secret_non_resolu", { pointers: this.erreursSecrets.map((e) => e.pointeur).join(","), count: this.erreursSecrets.length });
    const registry = this.config.anchoring?.registry ?? {};
    if (registry.enabled && this.erreurInstance) return refuser("instance_registre_absente", { detail: this.erreurInstance });
    try {
      const cleCourante = coeur.ecrivain?.cleCourante ?? this.config.signer.key_id;
      const publique = await coeur.signataire.clePublique(cleCourante);
      if (publique instanceof Uint8Array) this.clesPubliques.set(cleCourante, publique);
    } catch {
      // la clé courante est déjà dans l'index de la chaîne pour un journal non vide
    }
    const racineStockage = this.config.storage.root;
    const contexte = {
      org_id: this.config.recorder.org_id,
      journal_id: this.config.recorder.journal_id,
      epoque: coeur.ecrivain?.epoque ?? 1,
      racineStockage,
      secrets: this.secretsAncrage,
      cles: () => this.cles(),
      clePublique: (k) => this.clePublique(k),
      lireSerie: (P) => this.lireSerie(P),
      lireHashesPeriode: (P) => this.lireHashesPeriode(P),
      listerPeriodes: () => this.listerPeriodes(),
      listerPoints: () => this.listerPoints(),
      cleChaine: this.cleChaine,
      instance: this.instance,
      signaturesCloture: (periodMeta) => this.signaturesCloture(periodMeta),
    };
    const clients = { ...this.clients };
    if (registry.enabled && this.cleChaine && this.instance && !clients.registre) {
      const points = pointsRpc(registry);
      if (!points.length) return refuser("rpc_url_absente");
      clients.registre = { points, identifiants: Object.fromEntries(points.map((p, k) => [p, `v${k + 1}`])), instance: this.instance, repertoireEnvois: this.repertoireRegistre };
    }
    if (clients.registre && typeof clients.registre === "object" && !clients.registre.repertoireEnvois && !clients.registre.envoyeur) clients.registre.repertoireEnvois = this.repertoireRegistre;
    if (clients.registre) fs.mkdirSync(this.repertoireRegistre, { recursive: true, mode: 0o700 });
    const profil = this.config.recorder.environment === "production" ? "production" : "developpement";
    try {
      this.composant = creerComposantAncrage({
        configuration: this.document,
        profil,
        checkpointIntervalEnregistreur: this.config.checkpoint_interval_s ?? 60,
        contexte,
        horloge: this.#horloge(),
        aleatoire: this.aleatoire,
        journal: coeur.journal,
        clients,
      });
      await this.composant.demarrer();
    } catch (e) {
      const raison = e instanceof ErreurConfigurationAncrage ? "configuration_invalide" : "demarrage_impossible";
      refuser(raison, e instanceof ErreurConfigurationAncrage ? { rules: e.erreurs.map((x) => x.regle).join(","), count: e.erreurs.length } : { detail: String(e?.message ?? e).slice(0, 200) });
      if (this.composant && this.composant.etat().demarre) await this.composant.arreter({ attendre: false }).catch(() => {});
      return;
    }
    this.raison = null;
    this.#journal("info", "anchoring_attached", { profile: profil, registry: Boolean(clients.registre), providers: this.document.rfc3161.providers.length, queue_in_journal: this.fileSousJournal() });
  }

  /** La file durable (`queue.path`) est-elle sous le répertoire du journal (copie WORM avec `ancres/`, EX-8.14) ? */
  fileSousJournal() {
    const q = this.document?.queue?.path;
    if (!this.coeur || typeof q !== "string") return false;
    const rel = path.relative(this.coeur.repertoire, q);
    return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
  }

  // ------------------------------------------------------------ remises (rubrique g)

  remettrePoint(remise) {
    if (!this.demarre) {
      this.#journal("warning", "anchor_pending", { reason: this.raison ?? "composant_non_demarre", period_start: remise?.point?.period_start ?? null, tree_size: remise?.point?.tree_size ?? null });
      return Promise.resolve({ admis: false, regle: this.raison ?? "composant_non_demarre" });
    }
    return this.composant.remettrePoint(remise);
  }

  remettreCloture(remise) {
    if (!this.demarre) {
      this.#journal("warning", "anchor_pending", { reason: this.raison ?? "composant_non_demarre", period_start: remise?.manifeste?.period_start ?? null });
      return Promise.resolve({ admis: false, regle: this.raison ?? "composant_non_demarre" });
    }
    return this.composant.remettreCloture(remise);
  }

  // ------------------------------------------------------------ exploitation

  /**
   * `noortrace-ctl reload` (EX-15.5, EX-4.9) : relit le document, résout de
   * nouveau ses secrets (les pointeurs résolus remplacent les anciens dans la
   * carte du composant) et demande au composant de recharger ; refusé sans
   * changer l'ancienne configuration. Rend `{ accepte, erreurs }`.
   */
  async recharger() {
    const { document, erreur } = lireDocumentJson(this.chemin);
    if (!document) {
      this.#journal("error", "config_reload_rejected", { component: "ancrage", reason: "document_illisible", detail: erreur });
      return { accepte: false, erreurs: [{ regle: "document", message: erreur }] };
    }
    const s = await resoudreSecretsAncrage(document, { env: this.env, config: this.config });
    if (s.erreurs.length) {
      this.#journal("error", "config_reload_rejected", { component: "ancrage", reason: "secret_non_resolu", pointers: s.erreurs.map((e) => e.pointeur).join(",") });
      return { accepte: false, erreurs: s.erreurs.map((e) => ({ regle: "secrets", message: `${e.pointeur} : ${e.regle}` })) };
    }
    if (!this.composant) {
      this.#journal("error", "config_reload_rejected", { component: "ancrage", reason: this.raison ?? "composant_non_demarre" });
      return { accepte: false, erreurs: [{ regle: "demarrage", message: "composant non démarré : un redémarrage du démon est requis" }] };
    }
    for (const [k, v] of s.secrets) this.secretsAncrage.set(k, v);
    const r = this.composant.recharger(document);
    if (r.accepte) this.document = structuredClone(document);
    return r;
  }

  /** Arrêt propre, après la fermeture de l'écrivain. */
  async arreter() {
    this.desabonnerReexports?.();
    if (this.composant && this.composant.etat().demarre) await this.composant.arreter({ attendre: false }).catch(() => {});
  }

  /** État exposé à l'exploitation (`noortrace-ctl ancrage etat`). */
  etat() {
    const e = this.composant ? this.composant.etat() : { demarre: false, arrete: false };
    return { ...e, attached: this.composant !== null, reason: this.raison, document: path.basename(this.chemin), registry: Boolean(this.composant?.envoyeur) };
  }

  /** Métriques d'EX-8.15 au format d'exposition, ou chaîne vide. */
  metriques() {
    return this.composant ? this.composant.metriques() : "";
  }

  /** EX-5.9 : retrait de `qualified` d'un prestataire jusqu'au rechargement. */
  async retirerQualification(providerId) {
    if (!this.composant) throw new Error("composant non démarré");
    return this.composant.retirerQualification(providerId);
  }

  // ------------------------------------------------------------ export (CT-5 §10)

  /** Inscriptions demandées pour `registre.json` (CT-4 EX-9.8) : la clé du manifeste puis les autres clés du dossier. */
  #inscriptions(manifeste, cles) {
    const liste = [];
    const ajouter = (key_id) => {
      const k = (cles?.keys ?? []).find((x) => x.key_id === key_id);
      if (k && !liste.some((x) => x.clePublique === k.public_key)) liste.push({ clePublique: k.public_key, chainKey: key_id === manifeste.recorder_key_id ? this.cleChaine?.adresse() ?? null : null });
    };
    ajouter(manifeste.recorder_key_id);
    for (const k of cles?.keys ?? []) ajouter(k.key_id);
    return liste;
  }

  /**
   * Exporte le dossier d'un événement avec ses ancres (EX-10.1 à EX-10.4) ;
   * `base` est l'assemblage de l'enregistreur (`dossier.mjs`). Les fichiers
   * sont écrits dans `destination` : le répertoire temporaire de l'export
   * (CT-2 EX-15.13, point 2), ou la destination des essais. Le résumé est
   * gardé pour `reexportsDus` avec `destinationFinale` (la destination
   * demandée, jamais le répertoire temporaire, EX-15.13 point 2). La ligne
   * `dossier_exported` est écrite par l'appelant (EX-15.14 : une ligne par
   * demande, avec son `request_id`).
   * @param {object} base
   * @param {{destination: string, generated_at: number, destinationFinale?: string}} o
   */
  exporterDossier(base, { destination, generated_at, destinationFinale = destination }) {
    const registre = this.coeur && this.instance && fs.existsSync(this.repertoireRegistre)
      ? { repertoireCaptures: this.repertoireRegistre, jeux: this.instance.jeux, source: `${this.instance.bftChainId}, captures de l'enregistreur (${path.basename(this.coeur.repertoire)}), export du ${ecrireHorodatage(generated_at)}`, inscriptions: this.#inscriptions(base.manifeste, base.cles) }
      : null;
    const r = exporterDossierAncrage({
      event: { seq: base.evenement.seq, hash: base.evenement.hash },
      org_id: base.evenement.org_id,
      journal_id: base.evenement.journal_id,
      partiesBase: base.fichiers,
      raisonsBase: base.raisons,
      leafIndex: base.leafIndex,
      hashes: base.hashes,
      manifeste: base.manifeste,
      periodHash: hacherManifeste(base.manifeste),
      serie: base.serie,
      racineStockage: this.config.storage.root,
      registre,
      destination,
      generated_at,
    });
    r.resume = { ...r.resume, destination: destinationFinale };
    // Un seul résumé par événement, le plus récent par generated_at (la règle de reexportsDus) : la liste ne grandit plus
    // à chaque export d'un même dossier (épreuves de l'étape 5).
    const cle = `${r.resume.hash}:${r.resume.seq}`;
    const precedent = this.produits.get(cle);
    if (!precedent || decoderHorodatage(r.resume.generated_at) >= decoderHorodatage(precedent.generated_at)) this.produits.set(cle, r.resume);
    return r;
  }

  /**
   * EX-10.5 : dossiers exportés par ce démon qu'une ancre arrivée depuis rend à réexporter.
   * @returns {Promise<object[]>}
   */
  async reexportsDus() {
    return (await this.etatReexports()).dus;
  }

  /**
   * Dossiers dus (EX-10.5) et état des ancres de chaque période d'un dossier
   * exporté (`etatAncresPeriode`), lus dans le stockage.
   * @returns {Promise<{dus: object[], etats: Map<number, object>}>}
   */
  async etatReexports() {
    const etats = new Map();
    const produits = this.dossiersProduits;
    for (const d of produits) {
      if (etats.has(d.period_start)) continue;
      const serie = await this.lireSerie(d.period_start);
      const manifeste = (await this.listerPeriodes()).find((m) => m.manifeste.period_start === d.period_start) ?? null;
      etats.set(d.period_start, etatAncresPeriode({
        racineStockage: this.config.storage.root, orgId: this.config.recorder.org_id, journalId: this.config.recorder.journal_id, periodStart: d.period_start, serie,
        repertoireCaptures: this.instance && fs.existsSync(this.repertoireRegistre) ? this.repertoireRegistre : null, periodHash: manifeste?.periodHash ?? null,
      }));
    }
    return { dus: reexportsDus({ dossiersProduits: produits, etatAncres: etats }), etats };
  }

  /**
   * Ancres qui rendent un dossier dû (EX-10.5) : pour chaque raison, la
   * valeur courante de l'ancre qui la fonde. Deux constats égaux viennent de
   * la même arrivée ; un constat changé, d'une ancre arrivée depuis.
   */
  #constatDu(du, etat) {
    const resume = this.produits.get(`${du.hash}:${du.seq}`) ?? null;
    const pointCourant = resume?.point && etat?.points instanceof Map ? etat.points.get(resume.point.checkpointHash) ?? null : null;
    const constat = {};
    for (const r of du.raisons) {
      switch (r) {
        case "jeton_periode": constat[r] = etat?.periode?.rfc3161 ?? null; break;
        case "ots_periode": constat[r] = etat?.periode?.ots ?? null; break;
        case "registre_periode": constat[r] = etat?.periode?.registre ?? null; break;
        case "entetes_bitcoin": constat[r] = etat?.periode?.entetes ?? null; break;
        case "jeton_point": constat[r] = pointCourant?.rfc3161 ?? null; break;
        case "ots_point": constat[r] = pointCourant?.ots ?? null; break;
        case "registre_point": constat[r] = pointCourant?.registre ?? null; break;
        case "point_couvrant_meilleur": constat[r] = etat?.points instanceof Map ? [...etat.points].filter(([h, c]) => h !== resume?.point?.checkpointHash && c.rfc3161).map(([h]) => h).sort() : null; break;
        case "point_apparu": constat[r] = etat?.points instanceof Map ? [...etat.points.keys()].sort() : null; break;
        default: constat[r] = null;
      }
    }
    return JSON.stringify(constat);
  }

  /**
   * CT-2 EX-15.13 point 4, EX-15.14 : une ligne `dossier_reexport_due` par
   * dossier dû et par ancre arrivée, pour le seul dossier le plus récent de
   * chaque événement exporté depuis le démarrage. Appelé après chaque ligne
   * du composant d'ancrage (une ancre arrivée en écrit une) : un dossier dû
   * dont le constat des ancres n'a pas changé depuis la dernière ligne n'en
   * reçoit pas d'autre.
   */
  async signalerReexports() {
    if (!this.produits.size || !this.coeur) return [];
    const { dus, etats } = await this.etatReexports();
    const lignes = [];
    for (const du of dus) {
      const cle = `${du.hash}:${du.seq}`;
      const constat = this.#constatDu(du, etats.get(du.period_start));
      const avant = this.reexportsSignales.get(cle);
      if (avant && avant.generated_at === du.generated_at && avant.constat === constat) continue;
      this.reexportsSignales.set(cle, { generated_at: du.generated_at, constat });
      const data = { seq: du.seq, hash: du.hash, period_start: du.period_start, destination: du.destination, generated_at: du.generated_at, reasons: [...new Set(du.raisons)] };
      this.coeur.journal.consigner("info", "ancrage", "dossier_reexport_due", data, { seq: du.seq });
      lignes.push(data);
    }
    return lignes;
  }

  /** Planifie `signalerReexports` après une ligne du composant (une à la fois, jamais bloquant). */
  #planifierReexports() {
    if (this.reexportPlanifie || !this.produits.size) return;
    this.reexportPlanifie = true;
    const t = setTimeout(() => {
      this.reexportEnCours = (this.reexportEnCours ?? Promise.resolve())
        .then(() => {
          this.reexportPlanifie = false;
          return this.signalerReexports();
        })
        .catch((e) => {
          this.reexportPlanifie = false;
          // Cette ligne ne replanifie pas de constat (sinon une erreur durable bouclerait).
          this.sansReplanifier = true;
          try {
            this.#journal("error", "anchoring_supervision_failed", { detail: `dossier_reexport_due : ${String(e?.message ?? e).slice(0, 180)}` });
          } finally {
            this.sansReplanifier = false;
          }
        });
    }, 0);
    t.unref?.();
  }

  /** Abonnement au journal d'exploitation : chaque ligne du composant (hors lignes de dossier) planifie le constat des réexports. */
  #suivreReexports(coeur) {
    this.desabonnerReexports?.();
    this.desabonnerReexports = coeur.journal.abonner((l) => {
      if (!this.sansReplanifier && l.component === "ancrage" && typeof l.event === "string" && !l.event.startsWith("dossier_")) this.#planifierReexports();
    });
  }
}

/**
 * Prépare le branchement d'`anchoring.ancrage` avant `Coeur.demarrer` (pas 4
 * d'EX-15.4 pour le document `ancrage-v0`) : lecture du document, résolution
 * de ses secrets, manifeste d'instance, clé de chaîne. Rend `null` quand
 * `anchoring.ancrage` est `null` ou absent (comportement inchangé) ; lève
 * `ErreurBranchementAncrage` seulement pour une clé de chaîne d'une classe non
 * servie ou illisible (le démon refuse alors de démarrer).
 * @param {{config: object, secrets: Map<string, Uint8Array>, env?: NodeJS.ProcessEnv, horloge?: object, aleatoire?: Function, clients?: object}} o
 * @returns {Promise<BranchementAncrage|null>}
 */
export async function preparerAncrage(o) {
  const chemin = o.config.anchoring?.ancrage ?? null;
  if (chemin === null || chemin === undefined) return null;
  const registry = o.config.anchoring?.registry ?? {};
  const cleChaine = registry.enabled ? cleChaineDepuisConfiguration(o.config, o.secrets) : null;
  const { document, erreur } = lireDocumentJson(chemin);
  let secretsAncrage = new Map();
  let erreursSecrets = [];
  if (document) {
    const s = await resoudreSecretsAncrage(document, { env: o.env, config: o.config });
    secretsAncrage = s.secrets;
    erreursSecrets = s.erreurs;
  }
  let instance = null;
  let erreurInstance = null;
  if (registry.enabled) {
    const m = lireDocumentJson(path.join(path.dirname(chemin), FICHIER_INSTANCE_REGISTRE));
    if (!m.document) erreurInstance = `${FICHIER_INSTANCE_REGISTRE} : ${m.erreur}`;
    else {
      const r = instanceDepuisManifeste(m.document);
      instance = r.instance;
      erreurInstance = r.erreur;
    }
  }
  return new BranchementAncrage({
    config: o.config, secrets: o.secrets, env: o.env, document, erreurDocument: erreur, secretsAncrage, erreursSecrets, instance, erreurInstance, cleChaine,
    horloge: o.horloge ?? null, aleatoire: o.aleatoire, clients: o.clients,
  });
}

export { hacherPoint };
