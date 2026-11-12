// Composant d'ancrage temps réel (CT-5 §4, §5, §6, §8, §9 ; lot F1) : il
// satisfait l'interface `ComposantAncrage` de l'enregistreur (CT-2 rubrique g :
// `remettrePoint`, `remettreCloture`, jamais bloquant, EX-4.12, EX-8.1), tient
// le planificateur du lot C et sa file durable, exécute chaque action émise
// avec les clients A (RFC 3161), B (OpenTimestamps) et D (registre), réinjecte
// leurs résultats comme entrées du planificateur, programme les tics et les
// reprises sur une horloge injectée, relit le stockage au démarrage
// (EX-8.12), tient la supervision (EX-8.15) et les différés de T-10
// (EX-5.10, étape 10). Il ne lit ni fichier ni variable d'environnement pour
// un secret : il reçoit les secrets déjà résolus (CT-2 §15.2,
// `contexte.secrets`). Aucun `Date.now`, `setTimeout` ni `randomBytes` : tout
// passe par `horloge` et `aleatoire` (règle 2 d'INTERFACES.md).
//
// Interfaces attendues (rubrique F d'INTERFACES.md) :
//   horloge  = { murale(): ms UTC, monotone(): ms, programmer(delaiMs, fn) → annuler() }
//   contexte = { org_id, journal_id, epoque, racineStockage, secrets: Map<pointeur JSON, Uint8Array>,
//                clePublique(keyId) → Uint8Array|null, cles?, lireSerie(periodStart), lireHashesPeriode?(periodStart),
//                listerPeriodes(), listerPoints(), cleChaine?: SignataireChaine, signaturesCloture?(periodMeta, manifeste),
//                cleChainePour?(keyId) → SignataireChaine|null, clesChaine?() → SignataireChaine[] (étape 7 : rotation),
//                instance?: { evmChainId, bftChainId, contrats, fees, jeux } }
//   clients  = { rfc3161?: { transport }, ots?: { transport }, registre?: { envoyeur } | { rpc | points, instance, repertoireEnvois, delais },
//                file?: { ouvrir } }

import fs from "node:fs";
import path from "node:path";
import { decoderHorodatage, ecrireHorodatage, empreinteAncre, hacherManifeste, hacherPoint, hexVersOctets, octetsVersHex, sha256Hex, utf8 } from "@noortrace/noyau";
import { COMPACT_BYTES_DEFAUT, FileDurable, Supervision, admettreManifeste, admettrePoint, commeServeurInterne, creerPlanificateur, lireFiles, noncesAleatoires, validerConfiguration } from "./planificateur/index.mjs";
import {
  DepotAncres, acquerir, attenteReprise, capturerCrls, construireFiche, epreuveAcceptation, tirerNonce, transportHttps as transportRfc3161,
  verifierFiche, verifierJeton, verifierRevocation,
} from "./rfc3161/index.mjs";
import { DepotOts, fichierEntetes, hauteursAttestees, lireOts, mettreANiveau, rpcBitcoinHttp, soumettre, transportHttps as transportOts } from "./ots/index.mjs";
import { ClientRpc, Envoyeur, lireEnvois, lireTransaction } from "./registre/index.mjs";

/** Cadence du tic de l'horloge injectée (ms) quand aucune minuterie plus proche n'est programmée. */
export const TIC_MS = 1000;
const MOTIF_HEX32 = /^0x[0-9a-f]{64}$/;

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Configuration refusée par AN-1 (EX-4.9) ou secrets non résolus (CT-2 §15.2). */
export class ErreurConfigurationAncrage extends Error {
  constructor(erreurs) {
    super(`configuration ancrage-v0 refusée : ${erreurs.map((e) => `[${e.regle}] ${e.message}`).join(" ; ")}`);
    this.name = "ErreurConfigurationAncrage";
    this.erreurs = erreurs;
  }
}

/**
 * Valide un document `ancrage-v0` (AN-1) et la présence des secrets résolus
 * que les prestataires et la source d'en-têtes désignent (CT-2 §15.2) ;
 * rend `{ valide, erreurs, projection }` (règle `secrets` pour un secret absent).
 */
export function validerConfigurationComposant(configuration, { profil = "developpement", checkpointIntervalEnregistreur = null, secrets = null } = {}) {
  const v = validerConfiguration(configuration, { profil, checkpointIntervalEnregistreur });
  if (!v.valide) return v;
  const erreurs = [];
  const pointeurs = pointeursSecrets(configuration);
  for (const [pointeur, quoi] of pointeurs) {
    const octets = secrets instanceof Map ? secrets.get(pointeur) : null;
    if (!(octets instanceof Uint8Array) || octets.length === 0) erreurs.push({ regle: "secrets", message: `${quoi} : secret ${pointeur} non résolu (CT-2 §15.2)` });
  }
  return { valide: erreurs.length === 0, erreurs, projection: erreurs.length === 0 ? v.projection : null };
}

/** Pointeurs JSON des secrets qu'un document `ancrage-v0` désigne, avec ce qu'ils servent. */
export function pointeursSecrets(configuration) {
  const liste = [];
  configuration.rfc3161.providers.forEach((p, i) => {
    if (p.auth && p.auth.method !== "aucune") liste.push([`/rfc3161/providers/${i}/auth/secret`, `prestataire ${p.id} (${p.auth.method})`]);
  });
  const hs = configuration.opentimestamps.headers_source;
  if (hs && hs.type === "bitcoin_rpc" && hs.auth !== null) liste.push(["/opentimestamps/headers_source/auth", "source d'en-têtes bitcoin_rpc"]);
  return liste;
}

/** Objet `point_produit` du schéma depuis un point signé (CT-1 §10.5). */
export function entreePoint(point, checkpointHash = null) {
  return {
    org_id: point.org_id,
    journal_id: point.journal_id,
    period_start: point.period_start,
    tree_size: point.tree_size,
    checkpoint_hash: checkpointHash ?? hacherPoint(point),
    checkpoint_ts: point.checkpoint_ts,
  };
}

/** Objet `periode_close` du schéma depuis un manifeste signé (CT-1 §10.1). */
export function entreePeriode(manifeste, periodHash = null) {
  return { org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_start: manifeste.period_start, period_hash: periodHash ?? hacherManifeste(manifeste), generated_at: manifeste.generated_at };
}

/** `PeriodMeta` de CT-4 §6.4 (forme `meta_periode`) depuis un manifeste (CT-1 §10.4), `uri` vide. */
export function periodMetaRegistre(manifeste, periodHash = null) {
  return {
    org_id: manifeste.org_id,
    journal_id: manifeste.journal_id,
    period_hash: periodHash ?? hacherManifeste(manifeste),
    root: manifeste.root,
    period_start: String(manifeste.period_start),
    period_end: String(manifeste.period_end),
    first_seq: String(manifeste.first_seq),
    last_seq: String(manifeste.last_seq),
    version: manifeste.version,
    uri: "",
  };
}

/**
 * File durable qui ne lève jamais vers le planificateur (EX-8.1) : une ligne
 * qui ne s'écrit pas (disque) est gardée en mémoire (borne `max_pending`),
 * consignée (`anchor_queue_write_failed`) et réécrite à la prochaine écriture
 * réussie ; une ligne que le schéma refuse (`demande_non_conforme`) n'est
 * jamais rejouée : consignée avec le chemin JSON de l'écart puis abandonnée,
 * elle n'empêche pas les lignes suivantes de s'écrire (R-C-1).
 */
export class FileTolerante {
  constructor(file, { maxPending, surEchec, surReprise, surNonConforme = null }) {
    this.file = file;
    this.maxPending = maxPending;
    this.enAttente = new Map();
    this.perdues = 0;
    this.abandonnees = 0;
    this.enPanne = false;
    this.surEchec = surEchec;
    this.surReprise = surReprise;
    this.surNonConforme = surNonConforme;
  }

  #ecrireBrut(demande) {
    this.file.ecrire(demande);
  }

  static estNonConforme(e) {
    return e !== null && typeof e === "object" && e.code === "demande_non_conforme";
  }

  ecrire(demande) {
    if (this.enAttente.size) {
      for (const [id, d] of [...this.enAttente]) {
        try {
          this.#ecrireBrut(d);
          this.enAttente.delete(id);
        } catch (e) {
          if (FileTolerante.estNonConforme(e)) {
            this.enAttente.delete(id);
            this.#abandonner(d, e);
            continue;
          }
          this.#garder(demande, e);
          return;
        }
      }
      if (this.enPanne) {
        this.enPanne = false;
        this.surReprise?.();
      }
    }
    try {
      this.#ecrireBrut(demande);
    } catch (e) {
      if (FileTolerante.estNonConforme(e)) this.#abandonner(demande, e);
      else this.#garder(demande, e);
    }
  }

  #abandonner(demande, erreur) {
    this.abandonnees += 1;
    this.surNonConforme?.(demande, erreur, { abandonnees: this.abandonnees });
  }

  #garder(demande, erreur) {
    this.enAttente.set(demande.id, demande);
    while (this.enAttente.size > this.maxPending) {
      const [premier] = this.enAttente.keys();
      this.enAttente.delete(premier);
      this.perdues += 1;
    }
    const premiere = !this.enPanne;
    this.enPanne = true;
    this.surEchec?.(erreur, { gardees: this.enAttente.size, perdues: this.perdues, premiere });
  }

  fermer() {
    this.file.fermer?.();
  }
}

/**
 * Composant d'ancrage. Construit par `creerComposantAncrage`.
 */
export class ComposantAncrage {
  #chaine = Promise.resolve();
  #minuterie = null;

  constructor({ configuration, profil = "developpement", checkpointIntervalEnregistreur = null, contexte, horloge, aleatoire, journal = null, clients = {}, options = {} }) {
    if (!estObjet(contexte)) throw new TypeError("contexte attendu");
    if (!horloge || typeof horloge.murale !== "function" || typeof horloge.monotone !== "function" || typeof horloge.programmer !== "function") {
      throw new TypeError("horloge { murale, monotone, programmer } attendue (règle 2 d'INTERFACES.md)");
    }
    if (typeof aleatoire !== "function") throw new TypeError("aleatoire(n) attendu");
    for (const k of ["org_id", "journal_id"]) if (!MOTIF_HEX32.test(contexte[k] ?? "")) throw new TypeError(`contexte.${k} : hex32 attendu`);
    if (typeof contexte.racineStockage !== "string" || !contexte.racineStockage) throw new TypeError("contexte.racineStockage attendu");
    if (!(Number.isSafeInteger(contexte.epoque) || typeof contexte.epoque === "bigint")) throw new TypeError("contexte.epoque : entier attendu");
    this.profil = profil;
    this.checkpointIntervalEnregistreur = checkpointIntervalEnregistreur;
    this.contexte = contexte;
    this.horloge = horloge;
    this.aleatoire = aleatoire;
    this.journal = journal;
    this.clients = clients;
    this.options = { ticMs: TIC_MS, ...options };
    this.orgId = contexte.org_id;
    this.journalId = contexte.journal_id;
    this.demarre = false;
    this.arrete = false;
    this.enVol = 0;
    this.attentes = 0;
    /** @type {Set<Promise<unknown>>} actions en vol (clients) */
    this.promessesEnVol = new Set();
    this.planificateur = null;
    this.file = null;
    this.depotAncres = null;
    this.depotOts = null;
    this.envoyeur = null;
    this.qualificationsRetirees = new Set();
    /** @type {Map<string, object>} points admis par empreinte (`checkpoint_hash` → point signé) */
    this.points = new Map();
    /** @type {Map<number, object[]>} série admise par période */
    this.series = new Map();
    /** @type {Map<string, {manifeste: object, periodMeta: object, periodStart: number}>} clôtures connues par periodHash */
    this.clotures = new Map();
    /** @type {Map<string, {due: number, k: number, periodHash: string}>} clôtures au registre à (re)tenter */
    this.cloturesEnAttente = new Map();
    /** @type {object[]} T-10 différées (EX-5.10 étape 10) */
    this.t10 = [];
    /** @type {object[]} pièces d'acquisition dont l'écriture a échoué (étape 9 : rejouée) */
    this.ecrituresEnAttente = [];
    /** @type {Map<string, Uint8Array>} nonces OpenTimestamps tirés mais pas encore durables (`ots/<objet>.nonce`), par `<periode>/<objet>` (lecture H1-a) */
    this.noncesNonDurables = new Map();
    /** Arrêt demandé : plus aucune action réseau nouvelle ne part, les actions en vol s'achèvent (R-F-4). */
    this.arretDemande = false;
    this.erreurMetriqueConsignee = false;
    this.fileTolerante = null;
    this.validation = validerConfigurationComposant(configuration, { profil, checkpointIntervalEnregistreur, secrets: contexte.secrets ?? null });
    this.configuration = structuredClone(configuration);
    this.supervision = new Supervision({
      journal,
      horloge,
      prestatairesExterieurs: this.validation.valide ? configuration.rfc3161.providers.filter((p) => p.role !== "interne").map((p) => p.id) : [],
      journalAbrege: this.journalId.slice(2, 10),
    });
  }

  // ------------------------------------------------------------ état

  /** Rapport AN-1 de la configuration courante. */
  configurationValide() {
    return { valide: this.validation.valide, erreurs: this.validation.erreurs };
  }

  etat() {
    return {
      demarre: this.demarre,
      arrete: this.arrete,
      configuration_valide: this.validation.valide,
      en_vol: this.enVol,
      attentes_horloge: this.attentes,
      demandes: this.planificateur ? this.planificateur.demandes.size : 0,
      actives: this.planificateur ? this.planificateur.actives() : 0,
      qualifications_retirees: [...this.qualificationsRetirees],
      t10_en_attente: this.t10.length,
      clotures_en_attente: this.cloturesEnAttente.size,
      ecritures_en_attente: this.ecrituresEnAttente.length,
      file_en_panne: this.fileTolerante ? this.fileTolerante.enPanne : false,
      file_lignes_abandonnees: this.fileTolerante ? this.fileTolerante.abandonnees : 0,
      // Révision 0.6 (EX-8.5, règle 5 ; mesure TM-17) : taille du fichier courant, `S_0`, seuil, compactages.
      file: typeof this.file?.mesures === "function" ? this.file.mesures() : null,
      arret_demande: this.arretDemande,
    };
  }

  metriques() {
    return this.supervision.metriques();
  }

  /** Demandes de la file, rangées comme `queue_after` (copies). */
  demandes() {
    return this.planificateur ? this.planificateur.file() : [];
  }

  // -------------------------------------------------------- démarrage

  async demarrer() {
    if (this.demarre) throw new Error("composant déjà démarré");
    if (!this.validation.valide) {
      const e = new ErreurConfigurationAncrage(this.validation.erreurs);
      this.supervision.consigner("error", "config_invalid", { rules: this.validation.erreurs.map((x) => x.regle), count: this.validation.erreurs.length });
      throw e;
    }
    const c = this.configuration;
    this.depotAncres = DepotAncres.ouvrir({
      racine: this.contexte.racineStockage, orgId: this.orgId, journalId: this.journalId,
      // R-A-1 : une ligne illisible d'`acquisitions.ndjson` est ignorée et consignée une fois par fichier et par démarrage.
      signaler: (periodStart, illisibles) => this.supervision.consigner("error", "acquisitions_ligne_illisible", { period_start: periodStart, lines: illisibles.length, line: illisibles[0]?.ligne ?? null, reason: String(illisibles[0]?.raison ?? "").slice(0, 64) }),
    });
    this.depotOts = DepotOts.ouvrir({ racine: this.contexte.racineStockage, orgId: this.orgId, journalId: this.journalId });
    this.#preparerClients();
    const relue = lireFiles(c.queue.path);
    for (const t of relue.tronquees) {
      this.supervision.consigner("error", "anchor_queue_truncated_line", { file: t.fichier, line: t.ligne, reason: t.raison });
    }
    if (relue.tronquees.length) this.supervision.consigner("error", "alerte_file_perdue", { severity: "critique", reason: "anchor_queue_truncated_line", count: relue.tronquees.length });
    const ouvrir = this.clients.file?.ouvrir ?? ((p) => FileDurable.ouvrir(p));
    // Révision 0.6 : `queue.compact_bytes` (facultative, défaut 16 777 216) est lue ici, par la couche de fichier,
    // hors de la projection du planificateur (EX-4.8, EX-8.2) ; un `.compactage` resté d'un arrêt est supprimé à
    // l'ouverture (EX-8.12) ; compactages et échecs sont consignés (EX-8.5, règle 5 ; 8.9).
    this.file = ouvrir({
      repertoire: c.queue.path, epoque: this.contexte.epoque, fdatasync: true,
      compactBytes: c.queue.compact_bytes ?? COMPACT_BYTES_DEFAUT,
      monotone: () => this.horloge.monotone(),
      journal: (niveau, evenement, champs) => this.supervision.consigner(niveau, evenement, champs),
      ...(this.clients.file?.crochet ? { crochet: this.clients.file.crochet } : {}),
    });
    if (typeof this.file.declencher === "function") this.file.declencher();
    this.fileTolerante = new FileTolerante(this.file, {
      maxPending: c.queue.max_pending,
      surEchec: (erreur, info) => {
        this.supervision.consigner("error", "anchor_queue_write_failed", { reason: String(erreur?.code ?? erreur?.message ?? "inconnue").slice(0, 200), kept: info.gardees, dropped: info.perdues });
        if (info.premiere) this.supervision.consigner("error", "alerte_file_perdue", { severity: "critique", reason: "anchor_queue_write_failed" });
      },
      surReprise: () => this.supervision.consigner("info", "anchor_queue_write_recovered", { kept: 0 }),
      surNonConforme: (demande, erreur, info) => {
        this.supervision.consigner("error", "anchor_queue_write_failed", { reason: "demande_non_conforme", request_id: demande?.id ?? null, state: demande?.state ?? null, path: String(erreur?.chemin ?? "").slice(0, 200), dropped: info.abandonnees });
        this.supervision.consigner("error", "alerte_file_perdue", { severity: "critique", reason: "demande_non_conforme", request_id: demande?.id ?? null });
      },
    });
    this.planificateur = creerPlanificateur(this.validation.projection, {
      maintenant: () => this.#maintenant(),
      nonces: this.#nonces(),
      file: this.fileTolerante,
      fileInitiale: relue.demandes,
      sansRegistre: this.envoyeur === null,
    });
    this.demarre = true;
    await this.#injecter({ type: "demarrage", data: {} });
    await this.#relireStockage();
    this.#reconstruireT10();
    this.#reprendreClotures();
    this.#armerTic();
  }

  #preparerClients() {
    const r = this.clients.registre ?? null;
    if (r && r.envoyeur) this.envoyeur = r.envoyeur;
    else if (r && (r.rpc || r.points)) {
      const rpc = r.rpc ?? new ClientRpc({ points: r.points, identifiants: r.identifiants ?? {}, delaiMs: r.delaiMs ?? 10000 });
      const instance = r.instance ?? this.contexte.instance;
      if (!instance) throw new TypeError("clients.registre.instance (ou contexte.instance) attendu : evmChainId, bftChainId, contrats, jeux");
      if (typeof r.repertoireEnvois !== "string") throw new TypeError("clients.registre.repertoireEnvois attendu");
      this.envoyeur = new Envoyeur({
        rpc, repertoireEnvois: r.repertoireEnvois, instance, horloge: this.horloge, attendre: (ms) => this.#attendre(ms), delais: r.delais ?? {},
        journal: (niveau, evenement, champs) => this.#consignerRegistre(niveau, evenement, champs),
      });
    }
    if (this.envoyeur && !this.contexte.cleChaine) throw new TypeError("contexte.cleChaine (SignataireChaine) attendu avec un registre");
    if (this.envoyeur === null && this.profil === "production") throw new ErreurConfigurationAncrage([{ regle: "4", message: "registre absent : refusé en production (EX-8.4)" }]);
    this.transportRfc3161 = this.clients.rfc3161?.transport ?? transportRfc3161();
    this.transportOts = this.clients.ots?.transport ?? transportOts();
  }

  #consignerRegistre(niveau, evenement, champs) {
    const n = niveau === "warn" ? "warning" : ["debug", "info", "warning", "error"].includes(niveau) ? niveau : "info";
    const propres = {};
    for (const [k, v] of Object.entries(champs ?? {})) {
      if (["lookup", "refus", "pannes", "pending", "issue", "message"].includes(k)) continue;
      if (typeof v === "string" || typeof v === "number" || typeof v === "boolean" || v === null) propres[k] = v;
    }
    try {
      this.supervision.consigner(n, evenement, propres);
    } catch {
      this.supervision.consigner(n, evenement, { request_id: propres.request_id ?? null });
    }
  }

  /**
   * EX-8.12 : confrontation du stockage de l'enregistreur aux demandes relues
   * (`stockage_relu`). Ne sont transmises que les périodes closes sans leurs
   * trois demandes finales et, pour chaque période ouverte, son dernier point
   * (« le dernier point d'une période ouverte sans demande ») : l'entrée reste
   * sous les bornes du schéma (10 000) quelle que soit la profondeur du
   * stockage (R-F-3). Les séries en mémoire (AN-3) ne gardent que les périodes
   * ouvertes ; `points` garde les points des périodes ouvertes et ceux qu'une
   * demande relue désigne.
   */
  async #relireStockage() {
    const periodes = [];
    const checkpoints = [];
    try {
      const demandes = this.planificateur ? [...this.planificateur.demandes.values()] : [];
      const hashesDemandes = new Set(demandes.filter((d) => !["obtenue", "complete", "sans_objet", "refusee", "remplacee"].includes(d.state)).map((d) => d.subject.hash));
      const periodesCloses = new Set(demandes.filter((d) => d.subject.kind === "periode").map((d) => d.subject.period_start));
      const sortesPeriode = [...(this.envoyeur ? ["ancre_registre_periode"] : []), "jeton_periode", ...(this.configuration.opentimestamps.enabled ? ["ots_periode"] : [])];
      const finales = new Set(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);
      const manifestes = (await this.contexte.listerPeriodes?.()) ?? [];
      for (const m of manifestes) {
        const manifeste = m.manifeste ?? m;
        if (!estObjet(manifeste) || !Number.isSafeInteger(manifeste.period_start)) continue;
        if (manifeste.org_id !== this.orgId || manifeste.journal_id !== this.journalId) continue;
        const periodHash = m.periodHash ?? hacherManifeste(manifeste);
        this.clotures.set(periodHash, { manifeste, periodMeta: periodMetaRegistre(manifeste, periodHash), periodStart: manifeste.period_start });
        periodesCloses.add(manifeste.period_start);
        const complete = sortesPeriode.every((k) => {
          const d = this.planificateur?.demandes.get(`${k}:${periodHash}`);
          return d && finales.has(d.state);
        });
        if (!complete) periodes.push(entreePeriode(manifeste, periodHash));
      }
      const points = (await this.contexte.listerPoints?.()) ?? [];
      const derniers = new Map();
      for (const p of points) {
        const point = p.point ?? p;
        if (!estObjet(point) || point.org_id !== this.orgId || point.journal_id !== this.journalId || !Number.isSafeInteger(point.period_start)) continue;
        const ouverte = !periodesCloses.has(point.period_start);
        let hash = null;
        if (ouverte || hashesDemandes.size) hash = p.checkpointHash ?? this.#hashSur(point);
        if (hash === null) continue;
        if (ouverte) {
          this.points.set(hash, point);
          const serie = this.series.get(point.period_start) ?? [];
          if (!serie.some((x) => this.#hashSur(x) === hash)) serie.push(point);
          this.series.set(point.period_start, serie);
          const ts = decoderHorodatage(point.checkpoint_ts) ?? -1;
          const courant = derniers.get(point.period_start);
          if (!courant || ts > courant.ts || (ts === courant.ts && point.tree_size > courant.point.tree_size)) derniers.set(point.period_start, { point, hash, ts });
        } else if (hashesDemandes.has(hash)) this.points.set(hash, point);
      }
      for (const { point, hash } of derniers.values()) checkpoints.push(entreePoint(point, hash));
    } catch (e) {
      this.supervision.consigner("error", "anchoring_storage_unreadable", { reason: String(e?.message ?? e).slice(0, 200) });
    }
    await this.#injecter({ type: "stockage_relu", data: { periods: periodes.slice(0, 10000), checkpoints: checkpoints.slice(0, 10000) } });
  }

  // ------------------------------------------------------- remises (CT-2 g)

  /** Remise d'un point écrit et synchronisé (EX-12.27) : AN-3 puis `point_produit` ; rend la main sans attendre le réseau (EX-4.12). */
  remettrePoint(remise) {
    return this.#serialiser(async () => {
      if (!this.demarre || this.arrete) {
        this.supervision.consigner("warning", "anchor_pending", { reason: "composant_non_demarre", period_start: remise?.point?.period_start ?? null });
        return { admis: false, regle: "composant_non_demarre" };
      }
      const point = remise?.point;
      if (!estObjet(point)) {
        this.supervision.consigner("error", "anchor_admission_refused", { object: "point", rule: "format", detail: "remise sans point" });
        this.supervision.consigner("error", "alerte_admission_refusee", { severity: "critique", object: "point", rule: "format" });
        return { admis: false, regle: "format" };
      }
      let admission;
      try {
        const P = point.period_start;
        let serie = this.series.get(P) ?? null;
        if (serie === null) {
          const lue = (await this.contexte.lireSerie?.(P)) ?? [];
          const hashCourant = Number.isSafeInteger(P) ? this.#hashSur(point) : null;
          serie = [];
          for (const x of lue) {
            if (!estObjet(x) || x.period_start !== P) continue;
            if (this.#hashSur(x) === hashCourant) break;
            serie.push(x);
          }
        }
        const hashes = (await this.contexte.lireHashesPeriode?.(P)) ?? null;
        admission = admettrePoint({ point, serie, cles: this.#cles(point.key_id), hashesPeriode: hashes, periodStart: P, org_id: this.orgId, journal_id: this.journalId });
        if (admission.admis && typeof remise.checkpointHash === "string" && remise.checkpointHash !== admission.empreinte) {
          admission = { admis: false, empreinte: null, regle: "empreinte", detail: "checkpointHash remis différent de l'empreinte recalculée" };
        }
        if (admission.admis) {
          serie.push(point);
          this.series.set(P, serie);
          this.points.set(admission.empreinte, point);
        }
      } catch (e) {
        admission = { admis: false, empreinte: null, regle: "format", detail: String(e?.message ?? e).slice(0, 200) };
      }
      if (!admission.admis) {
        this.supervision.consigner("error", "anchor_admission_refused", { object: "point", rule: admission.regle, detail: String(admission.detail ?? "").slice(0, 200), period_start: point.period_start ?? null, tree_size: point.tree_size ?? null });
        this.supervision.consigner("error", "alerte_admission_refusee", { severity: "critique", object: "point", rule: admission.regle });
        return { admis: false, regle: admission.regle };
      }
      await this.#traiter({ type: "point_produit", data: entreePoint(point, admission.empreinte) });
      return { admis: true, empreinte: admission.empreinte };
    });
  }

  /** Remise d'une clôture (manifeste et signature) : AN-3 puis `periode_close`. */
  remettreCloture(remise) {
    return this.#serialiser(async () => {
      if (!this.demarre || this.arrete) {
        this.supervision.consigner("warning", "anchor_pending", { reason: "composant_non_demarre", period_start: remise?.manifeste?.period_start ?? null });
        return { admis: false, regle: "composant_non_demarre" };
      }
      const manifeste = remise?.manifeste;
      let admission;
      try {
        admission = admettreManifeste({ manifeste, signature: remise?.signature, cles: this.#cles(manifeste?.recorder_key_id) });
        if (admission.admis && typeof remise.periodHash === "string" && remise.periodHash !== admission.empreinte) {
          admission = { admis: false, empreinte: null, regle: "empreinte", detail: "periodHash remis différent de l'empreinte recalculée" };
        }
        if (admission.admis && (manifeste.org_id !== this.orgId || manifeste.journal_id !== this.journalId)) {
          admission = { admis: false, empreinte: null, regle: "period_start", detail: "manifeste d'un autre journal" };
        }
      } catch (e) {
        admission = { admis: false, empreinte: null, regle: "format", detail: String(e?.message ?? e).slice(0, 200) };
      }
      if (!admission.admis) {
        this.supervision.consigner("error", "anchor_admission_refused", { object: "manifeste", rule: admission.regle, detail: String(admission.detail ?? "").slice(0, 200), period_start: manifeste?.period_start ?? null });
        this.supervision.consigner("error", "alerte_admission_refusee", { severity: "critique", object: "manifeste", rule: admission.regle });
        return { admis: false, regle: admission.regle };
      }
      this.clotures.set(admission.empreinte, { manifeste, periodMeta: periodMetaRegistre(manifeste, admission.empreinte), periodStart: manifeste.period_start });
      await this.#traiter({ type: "periode_close", data: entreePeriode(manifeste, admission.empreinte) });
      // EX-8.5, règle 5 (révision 0.6) : compactage à chaque clôture, après l'écriture des trois demandes, entre deux
      // écritures (sous le verrou de `#serialiser`) ; un échec est consigné et ne bloque rien.
      if (!this.arrete && typeof this.file?.compacter === "function") this.file.compacter({ declencheur: "cloture" });
      return { admis: true, empreinte: admission.empreinte };
    });
  }

  #hashSur(point) {
    try {
      return hacherPoint(point);
    } catch {
      return null;
    }
  }

  /** Index des clés de l'enregistreur pour AN-3 : `contexte.cles` ou la clé de `contexte.clePublique(keyId)`. */
  #cles(keyId) {
    if (this.contexte.cles) return typeof this.contexte.cles === "function" ? this.contexte.cles() : this.contexte.cles;
    const octets = typeof keyId === "string" ? this.contexte.clePublique?.(keyId) : null;
    const index = new Map();
    if (octets instanceof Uint8Array && octets.length === 32) index.set(keyId, { key_id: keyId, public_key: octetsVersHex(octets), octets });
    return index;
  }

  // -------------------------------------------------- tic, arrêt, rechargement

  /** Un tic de l'horloge injectée (tests) : minuteries du planificateur, T-10 différées, clôtures et écritures en attente. */
  tic() {
    return this.#serialiser(async () => {
      if (!this.demarre || this.arrete) return [];
      const actions = await this.#traiter({ type: "tic", data: {} });
      this.#servirDifferes();
      return actions;
    });
  }

  /**
   * Arrêt (EX-8.12, EX-5.8) : plus aucune action réseau nouvelle ne part ; les
   * acquisitions en vol s'achèvent et leurs réponses sont injectées (le jeton
   * obtenu est écrit dans la file et n'est jamais redemandé au redémarrage,
   * R-F-4), dans la borne `request_timeout_ms` (plus une marge) de l'horloge
   * injectée ; puis l'entrée `arret` est traitée et la file fermée.
   */
  async arreter({ attendre = true } = {}) {
    if (!this.demarre || this.arrete) return;
    this.arretDemande = true;
    if (this.#minuterie) {
      this.#minuterie();
      this.#minuterie = null;
    }
    const borneAtteinte = attendre ? await this.#attendreEnVol() : false;
    this.arrete = true;
    await this.#chaine;
    try {
      const actions = this.planificateur.traiter({ t: ecrireHorodatage(this.#maintenant()), type: "arret", data: {} });
      this.supervision.consignerActions(actions);
    } catch (e) {
      this.supervision.consigner("error", "anchoring_stopped", { reason: String(e?.message ?? e).slice(0, 200) });
    }
    if (attendre && !borneAtteinte && this.promessesEnVol.size) {
      // Ce qui resterait en vol s'achève sans être réinjecté (composant_arrete) ; au-delà de la borne, rien n'est plus attendu.
      await Promise.allSettled([...this.promessesEnVol].filter((p) => !p.attendHorloge));
    }
    this.fileTolerante?.fermer();
  }

  /** Borne de l'attente des actions en vol à l'arrêt : le plus long délai de transport configuré, plus une marge. */
  #borneArretMs() {
    const c = this.configuration;
    const delais = c.rfc3161.providers.map((p) => p.request_timeout_ms ?? 10000);
    delais.push(c.opentimestamps?.timeout_ms ?? 5000);
    if (this.envoyeur) delais.push(this.clients.registre?.delais?.recuMs ?? 60000);
    return Math.max(...delais, 0) + 5000;
  }

  /** Attend les promesses en vol (et celles qu'elles déclenchent), au plus `#borneArretMs()` sur l'horloge injectée ; rend vrai si la borne a joué. */
  async #attendreEnVol() {
    if (!this.promessesEnVol.size) return false;
    let borneAtteinte = false;
    let annuler = null;
    const limite = new Promise((resoudre) => {
      annuler = this.horloge.programmer(this.#borneArretMs(), () => {
        borneAtteinte = true;
        resoudre();
      });
    });
    try {
      while (this.promessesEnVol.size && !borneAtteinte) {
        await Promise.race([Promise.allSettled([...this.promessesEnVol]), limite]);
        if (!borneAtteinte) await this.#chaine;
      }
    } finally {
      annuler?.();
    }
    if (borneAtteinte && this.promessesEnVol.size) this.supervision.consigner("warning", "anchoring_stop_timeout", { in_flight: this.promessesEnVol.size, bound_ms: this.#borneArretMs() });
    return borneAtteinte && this.promessesEnVol.size > 0;
  }

  /** EX-4.9 : rechargement ; refusé sans changer l'ancienne configuration quand AN-1 échoue. */
  recharger(configuration) {
    const v = validerConfigurationComposant(configuration, { profil: this.profil, checkpointIntervalEnregistreur: this.checkpointIntervalEnregistreur, secrets: this.contexte.secrets ?? null });
    if (!v.valide) {
      this.supervision.consigner("error", "config_reload_rejected", { rules: v.erreurs.map((x) => x.regle), count: v.erreurs.length });
      return { accepte: false, erreurs: v.erreurs };
    }
    this.configuration = structuredClone(configuration);
    this.validation = v;
    this.qualificationsRetirees.clear();
    this.supervision.prestatairesExterieurs = new Set(configuration.rfc3161.providers.filter((p) => p.role !== "interne").map((p) => p.id));
    if (this.planificateur) this.planificateur.reconfigurer(v.projection);
    this.supervision.consigner("info", "config_reloaded", { providers: configuration.rfc3161.providers.length });
    return { accepte: true, erreurs: [] };
  }

  /** EX-5.9 : retrait de `qualified` d'un prestataire jusqu'au rechargement ; relève des `jeton_periode` ouverts chez lui. */
  retirerQualification(providerId) {
    return this.#serialiser(async () => {
      const p = this.configuration.rfc3161.providers.find((x) => x.id === providerId);
      if (!p) throw new RangeError(`prestataire inconnu : ${providerId}`);
      this.qualificationsRetirees.add(providerId);
      this.supervision.consigner("warning", "provider_qualification_withdrawn", { provider: providerId, role: p.role });
      if (!this.demarre || this.arrete) return [];
      const actions = [];
      for (const d of this.planificateur.file()) {
        if (d.kind !== "jeton_periode" || ["obtenue", "remplacee", "refusee", "sans_objet", "complete"].includes(d.state)) continue;
        if (!d.attempts.some((a) => a.provider === providerId)) continue;
        const a = this.planificateur.relever(d.id, { t: ecrireHorodatage(this.#maintenant()), reason: "qualification_retiree" });
        actions.push(...a);
      }
      this.#apresActions(actions);
      return actions;
    });
  }

  /** Fiche de prestataire (EX-10.6, AN-54), avec l'épreuve d'EX-11.4 en option (réseau). */
  async fiche(providerId, { epreuve = false } = {}) {
    const index = this.configuration.rfc3161.providers.findIndex((x) => x.id === providerId);
    if (index < 0) throw new RangeError(`prestataire inconnu : ${providerId}`);
    const prestataire = this.#prestataire(index);
    let resultat = null;
    const transport = this.transportRfc3161 ?? this.clients.rfc3161?.transport ?? transportRfc3161();
    if (epreuve) resultat = await epreuveAcceptation({ prestataire, transport, horloge: this.horloge, aleatoire: this.aleatoire, fraicheur: this.configuration.rfc3161.freshness });
    const fiche = construireFiche(prestataire, { epreuve: resultat });
    return { fiche, verification: verifierFiche(fiche) };
  }

  // --------------------------------------------------- mécanique interne

  #maintenant() {
    const m = this.horloge.murale();
    const n = this.planificateur?.now ?? null;
    return n !== null && m < n ? n : m;
  }

  #serialiser(f) {
    const suite = this.#chaine.then(f, f);
    this.#chaine = suite.then(() => undefined, () => undefined);
    return suite;
  }

  #injecter(entree) {
    return this.#serialiser(() => this.#traiter(entree));
  }

  /** Traite une entrée (sous le verrou de `#serialiser`), consigne et exécute ses actions. */
  async #traiter(entree) {
    if (!this.planificateur) return [];
    if (this.arrete) {
      this.supervision.consigner("debug", "anchor_response_rejected", { error_code: "composant_arrete", type: entree.type, request_id: entree.data?.request_id ?? null });
      return [];
    }
    const e = { t: ecrireHorodatage(this.#maintenant()), type: entree.type, data: entree.data };
    let actions;
    try {
      actions = this.planificateur.traiter(e);
    } catch (err) {
      const requestId = typeof entree.data?.request_id === "string" ? entree.data.request_id : null;
      if (err?.code === "entree_non_conforme" && requestId !== null && ["reponse_rfc3161", "reponse_ots", "inclusion_registre", "echec_registre"].includes(entree.type)) {
        // R-F-1 : un résultat de client que le schéma refuse devient une issue d'échec conforme (`entree_non_conforme`,
        // détail : chemin JSON de l'écart) : aucune demande ne reste `envoyee` sans issue.
        const chemin = String(err.chemin ?? "").slice(0, 200);
        this.supervision.consigner("error", "anchor_response_rejected", { error_code: "entree_non_conforme", type: entree.type, request_id: requestId, detail: chemin });
        try {
          actions = this.planificateur.rejeter(requestId, { t: e.t, attempt: Number.isSafeInteger(entree.data?.attempt) ? entree.data.attempt : null, code: "entree_non_conforme", detail: chemin });
        } catch (err2) {
          this.supervision.consigner("error", "anchor_response_rejected", { error_code: "entree_refusee", type: entree.type, request_id: requestId, detail: String(err2?.message ?? err2).slice(0, 200) });
          return [];
        }
        this.#apresActions(actions);
        return actions;
      }
      this.supervision.consigner("error", "anchor_response_rejected", { error_code: "entree_refusee", type: entree.type, request_id: requestId, detail: String(err?.message ?? err).slice(0, 200) });
      return [];
    }
    this.#apresActions(actions);
    return actions;
  }

  /** Métriques puis lignes d'EX-8.15, chacune dans son propre essai : une métrique en défaut ne fait jamais perdre une ligne (R-F-2). */
  #apresActions(actions) {
    try {
      this.supervision.releverActions({ actions, file: this.planificateur.file(), maintenant: this.#maintenant() });
    } catch (err) {
      if (!this.erreurMetriqueConsignee) {
        this.erreurMetriqueConsignee = true;
        this.supervision.consigner("error", "anchoring_supervision_failed", { what: "metriques", detail: String(err?.message ?? err).slice(0, 200) });
      }
    }
    try {
      this.supervision.consignerActions(actions);
    } catch (err) {
      this.supervision.consigner("error", "anchoring_supervision_failed", { what: "journal", detail: String(err?.message ?? err).slice(0, 200) });
    }
    this.#executer(actions);
  }

  /** Exécute les actions dans l'ordre (EX-8.7) ; les envois partent sans attendre. */
  #executer(actions) {
    let prochain = null;
    for (const a of actions) {
      if (this.arretDemande && ["envoyer_rfc3161", "envoyer_registre", "soumettre_ots", "mettre_a_niveau_ots"].includes(a.action)) {
        // Arrêt demandé (R-F-4) : la ligne `envoyee` est écrite, la requête ne part pas ; le redémarrage la reprend (EX-8.12).
        this.supervision.consigner("debug", "anchor_send_deferred", { request_id: a.request_id, action: a.action, reason: "arret_demande" });
        continue;
      }
      switch (a.action) {
        case "envoyer_rfc3161":
          this.#lancer(this.#envoyerRfc3161(a), a);
          break;
        case "envoyer_registre":
          this.#lancer(this.#envoyerRegistre(a), a);
          break;
        case "soumettre_ots":
          this.#lancer(this.#soumettreOts(a), a);
          break;
        case "mettre_a_niveau_ots":
          this.#lancer(this.#mettreANiveauOts(a), a);
          break;
        case "programmer": {
          const at = decoderHorodatage(a.detail.next_at);
          if (at !== null && (prochain === null || at < prochain)) prochain = at;
          // EX-8.15 `anchor_retry` : reprise d'une demande RFC 3161 ou OpenTimestamps (le planificateur ne la consigne que pour le registre).
          if (["backoff", "retry_after", "immediat"].includes(a.detail.reason) && a.request_id && !a.request_id.startsWith("ancre_registre_")) {
            // Révision 0.6 : rang `n` (`attempt`) et `attempt_id` de la tentative reprise (EX-8.15).
            const tentative = this.planificateur.tentativeDe(a);
            this.supervision.consigner("warning", "anchor_retry", { request_id: a.request_id, kind: a.request_id.split(":")[0], mode: "reprise", reason: a.detail.reason, next_at: a.detail.next_at, attempt: tentative?.n ?? null, attempt_id: tentative?.attempt_id ?? null });
          }
          break;
        }
        case "ecrire_file":
          this.#surEcriture(a);
          break;
        case "releve":
        case "remplacer":
        case "rejeter_reponse":
        case "echeance":
          this.supervision.consigner("debug", `planificateur_${a.action}`, { request_id: a.request_id, at: a.t, ...a.detail });
          break;
        default:
          break; // stocker, alerter, journaliser : déjà relevés par la supervision
      }
    }
    if (prochain !== null) this.#armerTic(Math.max(0, prochain - this.#maintenant()));
  }

  #surEcriture(a) {
    if (a.detail.state === "obtenue" && a.request_id?.startsWith("ancre_registre_periode:")) {
      const periodHash = a.request_id.split(":")[1];
      this.#programmerCloture(periodHash, this.#maintenant());
    }
  }

  #lancer(promesse, action) {
    this.enVol += 1;
    const suivie = promesse
      .catch((err) => {
        this.supervision.consigner("error", "anchor_response_rejected", { request_id: action.request_id, error_code: "exception_client", action: action.action, detail: String(err?.message ?? err).slice(0, 200) });
        return this.#echecClient(action, err);
      })
      .catch(() => undefined)
      .finally(() => {
        this.enVol -= 1;
        this.promessesEnVol.delete(suivie);
      });
    this.promessesEnVol.add(suivie);
  }

  /** Toute exception d'un client devient une entrée d'échec du planificateur (jamais de perte silencieuse). */
  async #echecClient(action, err) {
    void err;
    const id = action.request_id;
    if (action.action === "envoyer_rfc3161") {
      await this.#injecter({ type: "reponse_rfc3161", data: this.#reponseTransport(id, action.detail.attempt) });
    } else if (action.action === "envoyer_registre") {
      await this.#injecter({ type: "echec_registre", data: { request_id: id, code: "exception_client" } });
    } else if (action.action === "soumettre_ots" || action.action === "mettre_a_niveau_ots") {
      await this.#injecter({ type: "reponse_ots", data: { request_id: id, calendars_answered: 0, attestation: action.action === "soumettre_ots" ? "aucune" : "en_attente", proof_sha256: null, proof_size: null } });
    }
  }

  #reponseTransport(requestId, attempt) {
    return { request_id: requestId, attempt, transport: "erreur_transport", http_status: null, pki_status: null, failure_info: null, retry_after_s: null, nonce_in_response: null, imprint_matches: null, checks_passed: [], gen_time: null, accuracy_s: null, token_sha256: null, token_size: null };
  }

  #attendre(ms) {
    return new Promise((resoudre) => {
      this.attentes += 1;
      this.horloge.programmer(Math.max(0, ms), () => {
        this.attentes -= 1;
        resoudre();
      });
    });
  }

  #armerTic(delaiMs = null) {
    if (this.arrete || this.arretDemande) return;
    const d = delaiMs === null ? this.options.ticMs : Math.min(this.options.ticMs, delaiMs);
    if (this.#minuterie) {
      if (this.#ticAt !== null && this.#maintenant() + d >= this.#ticAt) return;
      this.#minuterie();
    }
    this.#ticAt = this.#maintenant() + d;
    this.#minuterie = this.horloge.programmer(d, () => {
      this.#minuterie = null;
      this.#ticAt = null;
      this.tic().then(() => this.#armerTic(), () => this.#armerTic());
    });
  }
  #ticAt = null;

  // ------------------------------------------------- nonces (EX-5.3, EX-6.2)

  #nonces() {
    const base = noncesAleatoires(this.aleatoire);
    return {
      rfc3161: () => {
        for (let k = 0; k < 64; k++) {
          const n = tirerNonce(this.aleatoire);
          if (!this.depotAncres.nonceConnu(n)) return n;
        }
        throw new Error("aucun nonce RFC 3161 frais après 64 tirages (AN-6)");
      },
      ots: ({ hash, period_start, subjectKind }) => this.#nonceOts(period_start, subjectKind === "periode" ? "manifeste" : `point-${hash.slice(2)}`),
      gigue: base.gigue,
    };
  }

  /**
   * Nonce OpenTimestamps durable (EX-6.2 : le rejeu après redémarrage garde le
   * même engagement) : `ots/<objet>.nonce`. Une écriture impossible est
   * consignée ; le nonce est retenu comme non durable et la soumission attend
   * (`#nonceOtsDurable`) qu'il soit écrit (lecture H1-a).
   */
  #nonceOts(periodStart, objet) {
    const nom = `${objet}.nonce`;
    const chemin = path.join(this.depotAncres.repertoire(periodStart), "ots", nom);
    const cle = `${periodStart}/${objet}`;
    try {
      const texte = fs.readFileSync(chemin, "utf8").trim();
      if (/^0x[0-9a-f]{32}$/.test(texte)) {
        this.noncesNonDurables.delete(cle);
        return hexVersOctets(texte, 16);
      }
    } catch {
      // Absent : tiré puis écrit.
    }
    const n = this.noncesNonDurables.get(cle) ?? this.aleatoire(16);
    if (!(n instanceof Uint8Array) || n.length !== 16) throw new TypeError("aleatoire(16) : 16 octets attendus");
    try {
      this.depotAncres.ecrirePiece(periodStart, "ots", nom, utf8(`${octetsVersHex(n)}\n`));
      this.noncesNonDurables.delete(cle);
    } catch (e) {
      this.noncesNonDurables.set(cle, n);
      this.supervision.consigner("error", "anchor_queue_write_failed", { reason: `nonce_ots:${String(e?.code ?? e?.message ?? "").slice(0, 120)}` });
    }
    return n;
  }

  /** Le nonce d'une soumission est-il durable (`ots/<objet>.nonce` porte cette valeur) ? Sinon l'écriture est retentée. */
  #nonceOtsDurable(periodStart, objet, nonceHex) {
    const nom = `${objet}.nonce`;
    const chemin = path.join(this.depotAncres.repertoire(periodStart), "ots", nom);
    try {
      if (fs.readFileSync(chemin, "utf8").trim() === nonceHex) {
        this.noncesNonDurables.delete(`${periodStart}/${objet}`);
        return true;
      }
    } catch {
      // Absent : écriture retentée.
    }
    try {
      this.depotAncres.ecrirePiece(periodStart, "ots", nom, utf8(`${nonceHex}\n`));
      this.noncesNonDurables.delete(`${periodStart}/${objet}`);
      return true;
    } catch (e) {
      this.supervision.consigner("error", "anchor_queue_write_failed", { reason: `nonce_ots:${String(e?.code ?? e?.message ?? "").slice(0, 120)}` });
      return false;
    }
  }

  // ----------------------------------------------- RFC 3161 (EX-5.5, EX-5.10)

  /**
   * Prestataire résolu : secret remplacé par ses octets (CT-2 §15.2), `qualified` retiré s'il l'a été (EX-5.9) ;
   * `serveur_interne` vrai quand, hors production, le principal non qualifié est le serveur RFC 3161 interne
   * (EX-4.9, règle 4, révision 0.9 de CT-5) : le transport l'admet alors en `http://` local, comme le rôle `interne`.
   */
  #prestataire(index) {
    const brut = this.configuration.rfc3161.providers[index];
    const p = structuredClone(brut);
    if (p.auth.method !== "aucune") p.auth = { method: p.auth.method, secret: this.contexte.secrets.get(`/rfc3161/providers/${index}/auth/secret`) };
    p.serveur_interne = brut.role !== "interne" && commeServeurInterne(brut, this.profil === "production");
    if (this.qualificationsRetirees.has(p.id)) p.qualified = null;
    return p;
  }

  #prestataireParId(id) {
    const index = this.configuration.rfc3161.providers.findIndex((x) => x.id === id);
    return index < 0 ? null : this.#prestataire(index);
  }

  async #envoyerRfc3161(a) {
    const req = this.planificateur.demandes.get(a.request_id);
    if (!req) return;
    const prestataire = this.#prestataireParId(a.detail.provider);
    if (!prestataire) {
      await this.#injecter({ type: "reponse_rfc3161", data: this.#reponseTransport(a.request_id, a.detail.attempt) });
      return;
    }
    const attempt = req.attempts.find((x) => x.n === a.detail.attempt) ?? null;
    const objet = req.kind === "jeton_periode" ? "manifeste" : "point";
    let k = 0;
    let tardives = 0;
    let premier408 = true;
    for (let j = req.attempts.length - 1; j >= 0; j--) {
      const x = req.attempts[j];
      if (x.n === a.detail.attempt || x.provider !== prestataire.id) continue;
      if (x.outcome === "echec_transitoire" || x.outcome === "reponse_tardive") k += 1;
      else break;
    }
    for (let j = req.attempts.length - 1; j >= 0; j--) {
      const x = req.attempts[j];
      if (x.n === a.detail.attempt) continue;
      if (x.outcome === "reponse_tardive") tardives += 1;
      else break;
    }
    for (const x of req.attempts) if (x.provider === prestataire.id && x.http_status === 408 && x.n !== a.detail.attempt) premier408 = false;
    const r = await acquerir({
      prestataire,
      imprint: a.detail.digest,
      objet,
      nonce: a.detail.nonce,
      attemptId: attempt?.correlation_id ?? `${req.kind}:${req.subject.hash.slice(2, 18)}:${a.detail.attempt}`,
      attempt: a.detail.attempt,
      periodStart: req.subject.period_start,
      deadlineIndex: req.deadlines.length ? Math.max(...req.deadlines) : null,
      horloge: this.horloge,
      aleatoire: this.aleatoire,
      depot: this.depotAncres,
      transport: this.transportRfc3161,
      fraicheur: this.configuration.rfc3161.freshness,
      retry: this.configuration.rfc3161.retry,
      tardivesAvant: tardives,
      k: k + 1,
      premier408,
    });
    if (r.erreurEcriture) {
      // Étape 9 en échec : l'écriture est rejouée, la réponse n'est pas renvoyée (EX-5.12).
      this.supervision.consigner("error", "anchor_piece_write_failed", { request_id: a.request_id, attempt: a.detail.attempt, reason: String(r.erreurEcriture.message ?? "").slice(0, 200) });
      this.supervision.consigner("error", "alerte_file_perdue", { severity: "critique", reason: "anchor_piece_write_failed", request_id: a.request_id });
      this.ecrituresEnAttente.push({ action: a, resultat: r, prestataire, objet, k: 0 });
      return;
    }
    this.#apresAcquisition(a, r, prestataire, objet);
    await this.#injecter({ type: "reponse_rfc3161", data: r.data });
  }

  #apresAcquisition(a, r, prestataire, objet) {
    const req = this.planificateur.demandes.get(a.request_id);
    if (r.outcome === "obtenue" && r.enregistrement.promoted && this.configuration.rfc3161.crl_capture.enabled && r.verification && r.verification.chemin.length) {
      const genTime = r.verification.tstInfo.genTime;
      this.t10.push({
        due: genTime + this.configuration.rfc3161.crl_capture.delay_s * 1000,
        k: 0,
        request_id: a.request_id,
        attempt: a.detail.attempt,
        provider: prestataire.id,
        periodStart: req?.subject.period_start ?? r.enregistrement.period_start,
        objet,
        imprint: a.detail.digest,
        nomBase: this.depotAncres.nomPiece({ objet, imprint: a.detail.digest, providerId: prestataire.id, attemptId: r.enregistrement.attempt_id }),
        enregistrement: r.enregistrement,
        verification: r.verification,
      });
    }
  }

  /** Rejoue l'écriture des pièces d'une tentative (EX-5.10 étape 9, `ecriture` transitoire). */
  #rejouerEcriture(e) {
    const r = e.resultat;
    const periodStart = r.enregistrement.period_start;
    const base = this.depotAncres.nomPiece({ objet: e.objet, imprint: r.enregistrement.imprint, providerId: e.prestataire.id, attemptId: r.enregistrement.attempt_id });
    const existe = (nom) => fs.existsSync(path.join(this.depotAncres.repertoire(periodStart), "rfc3161", nom));
    try {
      if (!existe(`${base}.tsq`)) r.enregistrement.files.request = this.depotAncres.ecrirePiece(periodStart, "rfc3161", `${base}.tsq`, r.requete);
      if (r.reponse && r.reponse.length && r.data.http_status === 200 && !existe(`${base}.tsr`) && r.enregistrement.response_sha256) {
        r.enregistrement.files.response = this.depotAncres.ecrirePiece(periodStart, "rfc3161", `${base}.tsr`, r.reponse);
      }
      if (r.jeton && !existe(`${base}.der`)) r.enregistrement.files.token = this.depotAncres.ecrirePiece(periodStart, "rfc3161", `${base}.der`, r.jeton);
      const outcome = r.data.token_sha256 && r.verification && r.verification.checks["T-1"] === "reussi" && r.code === null ? "obtenue" : r.enregistrement.outcome;
      if (outcome === "obtenue") {
        r.enregistrement.outcome = "obtenue";
        r.enregistrement.error_code = null;
        r.enregistrement.promoted = !this.depotAncres.dejaPromu(e.objet, r.enregistrement.imprint, periodStart);
        r.outcome = "obtenue";
      }
      this.depotAncres.ajouterAcquisition(periodStart, r.enregistrement);
      return true;
    } catch (err) {
      e.k += 1;
      this.supervision.consigner("error", "anchor_piece_write_failed", { request_id: e.action.request_id, attempt: e.action.detail.attempt, retries: e.k, reason: String(err?.message ?? "").slice(0, 200) });
      return false;
    }
  }

  // ----------------------------------------------- T-10 différée (EX-5.10 étape 10)

  /** Au démarrage : les jetons promus dont T-10 n'est pas encore faite sont reprogrammés depuis `acquisitions.ndjson`. */
  #reconstruireT10() {
    if (!this.configuration.rfc3161.crl_capture.enabled) return;
    for (const P of this.depotAncres.periodes()) {
      let lues;
      try {
        lues = this.depotAncres.dernieresAcquisitions(P).enregistrements;
      } catch {
        continue;
      }
      for (const e of lues) {
        if (e.outcome !== "obtenue" || e.promoted !== true || e.revoked === true || e.checks?.["T-10"] !== "non_execute" || !e.files?.token) continue;
        const prestataire = this.#prestataireParId(e.provider_id);
        if (!prestataire) continue;
        let octets;
        try {
          octets = new Uint8Array(fs.readFileSync(path.join(this.depotAncres.repertoire(P), e.files.token)));
        } catch {
          continue;
        }
        const v = verifierJeton({ octets, imprintAttendue: e.imprint, ancres: { certificatsPem: prestataire.anchor_certificates, politiquesAdmises: prestataire.accepted_policies ?? null }, aGenTime: true });
        if (!v.tstInfo || !v.chemin.length) continue;
        const kind = e.object === "manifeste" ? "jeton_periode" : "jeton_point";
        this.t10.push({
          due: v.tstInfo.genTime + this.configuration.rfc3161.crl_capture.delay_s * 1000,
          k: 0,
          request_id: `${kind}:${e.imprint}`,
          attempt: e.attempt,
          provider: e.provider_id,
          periodStart: P,
          objet: e.object,
          imprint: e.imprint,
          nomBase: this.depotAncres.nomPiece({ objet: e.object, imprint: e.imprint, providerId: e.provider_id, attemptId: e.attempt_id }),
          enregistrement: e,
          verification: v,
        });
      }
    }
  }

  async #executerT10(item) {
    const v = item.verification;
    const genTime = v.tstInfo.genTime;
    let captures;
    try {
      captures = await capturerCrls({ chemin: v.chemin, transport: this.transportRfc3161, horloge: this.horloge, apresInstant: genTime });
    } catch (err) {
      captures = v.chemin.map((c) => ({ certificate_sha256: c.sha256, crl: null, pem: null, erreur: String(err?.message ?? err) }));
    }
    const manquantes = captures.filter((c) => !c.crl);
    if (manquantes.length && !v.identite) {
      item.k += 1;
      item.due = this.#maintenant() + attenteReprise(this.configuration.rfc3161.retry, item.k);
      this.supervision.consigner("warning", "crl_indisponible", { request_id: item.request_id, attempt: item.attempt, provider: item.provider, retries: item.k, reasons: manquantes.map((m) => String(m.erreur ?? "").slice(0, 60)).join(" | ").slice(0, 200) });
      this.t10.push(item);
      return;
    }
    const crls = captures.filter((c) => c.crl).map((c) => c.crl);
    const dix = verifierRevocation({ chemin: v.chemin, autorite: v.autorite ? { nom: v.autorite.nom, certificat: v.autorite.certificat, identite: v.identite } : null, crls, crlsJeton: v.jeton?.crls ?? [], aInstant: genTime });
    const fichiers = [];
    if (crls.length) {
      const pem = captures.filter((c) => c.pem).map((c) => c.pem.endsWith("\n") ? c.pem : `${c.pem}\n`).join("");
      try {
        fichiers.push(this.depotAncres.ecrirePiece(item.periodStart, "rfc3161", `${item.nomBase}.crl.pem`, utf8(pem)));
      } catch (err) {
        this.supervision.consigner("error", "anchor_piece_write_failed", { request_id: item.request_id, attempt: item.attempt, reason: String(err?.message ?? "").slice(0, 200) });
      }
    }
    const revoque = dix.statut === "echoue";
    const ligne = structuredClone(item.enregistrement);
    ligne.checks = { ...ligne.checks, "T-10": dix.statut };
    ligne.revoked = revoque;
    ligne.files = { ...ligne.files, crls: fichiers };
    ligne.revocation = { status: dix.statut, reason: dix.raison, captured_at: ecrireHorodatage(this.#maintenant()), proofs: dix.preuves.length, detail: revoque ? String(dix.detail ?? "").slice(0, 200) : null };
    try {
      this.depotAncres.ajouterAcquisition(item.periodStart, ligne);
    } catch (err) {
      this.supervision.consigner("error", "anchor_piece_write_failed", { request_id: item.request_id, attempt: item.attempt, reason: String(err?.message ?? "").slice(0, 200) });
    }
    this.supervision.consigner(revoque ? "error" : "info", "crl_captured", { request_id: item.request_id, attempt: item.attempt, provider: item.provider, status: dix.statut, proofs: dix.preuves.length, files: fichiers.length });
    if (revoque) {
      await this.#serialiser(async () => {
        const actions = this.planificateur.revoquer(item.request_id, { t: ecrireHorodatage(this.#maintenant()), provider: item.provider });
        this.#apresActions(actions);
      });
    }
  }

  // ------------------------------------------------------ registre (EX-8.10)

  async #envoyerRegistre(a) {
    const req = this.planificateur.demandes.get(a.request_id);
    if (!req) return;
    if (!this.envoyeur) {
      await this.#injecter({ type: "echec_registre", data: { request_id: a.request_id, code: "registre_absent" } });
      return;
    }
    const point = req.subject.kind === "point" ? this.points.get(req.subject.hash) : null;
    const clePublique = point ? this.contexte.clePublique?.(point.key_id) ?? null : null;
    let r = await this.envoyeur.ancrer({
      orgId: req.subject.org_id, journalId: req.subject.journal_id, objet: req.subject.hash, docType: a.detail.doc_type, cle: this.#cleChaineDe(req),
      fingerprint: a.detail.fingerprint, clePublique: clePublique instanceof Uint8Array ? octetsVersHex(clePublique) : clePublique, requestId: a.request_id,
    });
    if (r.type === "echec_registre" && r.data.code === "attente_nonce") r = await this.#reprendreEnvoi(a, r);
    await this.#injecterResultatRegistre(a.request_id, r);
  }

  /**
   * Clé de chaîne d'un document (CT-2 EX-11.19, point 3 ; étape 7) : celle
   * sous laquelle est inscrite la clé Ed25519 `keyId` qui a signé le point ou
   * le manifeste, quand le contexte sait la dire (`contexte.cleChainePour`,
   * démon qui tient une clé de chaîne courante et une suivante) ; sinon
   * `contexte.cleChaine`, relue à chaque envoi (le démon peut la basculer).
   */
  #cleChainePour(keyId) {
    const f = this.contexte.cleChainePour;
    return (typeof f === "function" && typeof keyId === "string" ? f(keyId) : null) ?? this.contexte.cleChaine;
  }

  #cleChaineDe(req) {
    if (req.subject.kind === "point") return this.#cleChainePour(this.points.get(req.subject.hash)?.key_id);
    return this.#cleChainePour(this.clotures.get(req.subject.hash)?.manifeste?.recorder_key_id);
  }

  /** La clé de chaîne connue dont l'adresse est l'expéditeur d'un envoi (remplacement au même nonce, EX-8.16). */
  #cleChaineExpeditrice(hash) {
    const from = this.envoyeur.envoi(hash)?.envoi?.from ?? null;
    const f = this.contexte.clesChaine;
    const cles = typeof f === "function" ? f() : [this.contexte.cleChaine];
    return cles.find((c) => c && c.adresse() === from) ?? null;
  }

  /** CT-4 §8.6, EX-8.16 : un envoi sans issue est renvoyé (mêmes octets) puis remplacé au même nonce. */
  async #reprendreEnvoi(a, attente) {
    const pending = attente.outputs?.pending ?? [];
    let dernier = attente;
    for (const hash of pending) {
      const id = this.#requestIdDe(hash) ?? a.request_id;
      let r;
      try {
        r = await this.envoyeur.renvoyer(hash, { requestId: id });
        if (r.type === "echec_registre" && (r.data.code === "recu_absent" || r.data.code === "noeud_injoignable")) {
          const rr = await this.envoyeur.remplacer(hash, { cle: this.#cleChaineExpeditrice(hash) ?? this.contexte.cleChaine, requestId: id });
          if (rr.type === "inclusion_registre" || !["transaction_connue", "envoi_avec_issue"].includes(rr.data.code)) r = rr;
        }
      } catch (err) {
        r = { type: "echec_registre", data: { request_id: id, code: "reprise_impossible" }, outputs: { message: String(err?.message ?? err) } };
      }
      if (id !== a.request_id) await this.#injecterResultatRegistre(id, r);
      else dernier = r;
    }
    return dernier;
  }

  /** `request_id` de la demande dont l'empreinte d'ancre est celle d'un envoi (lot D, lecture 1 : l'objet n'est pas recouvrable depuis la transaction). */
  #requestIdDe(transactionHash) {
    try {
      const e = typeof this.envoyeur.envoi === "function" ? this.envoyeur.envoi(transactionHash) : lireEnvois(this.envoyeur.repertoire).find((x) => x.envoi.transaction_hash === transactionHash);
      if (!e) return null;
      const tx = lireTransaction(e.envoi.raw_transaction);
      if (tx.data.length < 68) return null;
      const fingerprint = octetsVersHex(tx.data.subarray(4, 36));
      for (const d of this.planificateur.demandes.values()) {
        if (d.kind.startsWith("ancre_registre_") && empreinteAncre(d.subject.org_id, d.subject.journal_id, d.subject.hash) === fingerprint) return d.id;
      }
    } catch {
      return null;
    }
    return null;
  }

  async #injecterResultatRegistre(requestId, r) {
    if (r.type === "inclusion_registre") {
      const data = { request_id: requestId, block_number: r.data.block_number, capture_sha256: r.data.capture_sha256 };
      try {
        if (r.outputs?.capture) data.capture_size = fs.statSync(path.join(this.envoyeur.repertoire, r.outputs.capture)).size;
      } catch {
        // Taille représentée du planificateur.
      }
      await this.#injecter({ type: "inclusion_registre", data });
    } else {
      await this.#injecter({ type: "echec_registre", data: { request_id: requestId, code: String(r.data.code).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64) } });
    }
  }

  /** Clôture au registre (CT-4 §8.2, pas 3 à 5) une fois l'ancre de la période incluse et capturée (EX-8.4). */
  #programmerCloture(periodHash, due) {
    if (!this.envoyeur || !this.clotures.has(periodHash)) return;
    if (!this.cloturesEnAttente.has(periodHash)) this.cloturesEnAttente.set(periodHash, { due, k: 0, periodHash });
  }

  #reprendreClotures() {
    if (!this.envoyeur) return;
    for (const d of this.planificateur.file()) {
      if (d.kind === "ancre_registre_periode" && d.state === "obtenue" && this.clotures.has(d.subject.hash)) this.#programmerCloture(d.subject.hash, this.#maintenant());
    }
  }

  async #clore(item) {
    const info = this.clotures.get(item.periodHash);
    if (!info) return;
    if (typeof this.contexte.signaturesCloture !== "function") {
      this.supervision.consigner("info", "period_close_delegated", { period_start: info.periodStart, reason: "aucun_signataire_de_cloture" });
      return;
    }
    let r;
    try {
      const s = await this.contexte.signaturesCloture(info.periodMeta, info.manifeste);
      if (s === null || s === undefined) {
        // Lecture F2 : `null` dit que les signatures des approbateurs ne sont pas encore disponibles (CT-4 §8.2, pas 4) :
        // la clôture reste à relayer, consignée une fois par essai, et reprise au pas `retry.max_ms` sans alerte.
        this.supervision.consigner("info", "period_close_delegated", { period_start: info.periodStart, reason: "signatures_en_attente", retries: item.k });
        item.k += 1;
        item.due = this.#maintenant() + this.configuration.rfc3161.retry.max_ms;
        this.cloturesEnAttente.set(item.periodHash, item);
        return;
      }
      if (!Array.isArray(s.signatures)) throw new Error("signatures de clôture absentes");
      r = await this.envoyeur.clore({ periodMeta: info.periodMeta, signatures: s.signatures, cle: this.#cleChainePour(info.manifeste?.recorder_key_id), membres: s.membres ?? null, seuil: s.seuil, periodePrecedente: s.periodePrecedente ?? null, requestId: `cloture:${item.periodHash}` });
    } catch (err) {
      r = { type: "echec_registre", data: { code: "exception_client" }, outputs: { message: String(err?.message ?? err) } };
    }
    if (r.type === "inclusion_registre") {
      this.supervision.consigner("info", "period_submitted", { period_start: info.periodStart, block_number: r.data.block_number, capture_sha256: r.data.capture_sha256 });
      return;
    }
    item.k += 1;
    item.due = this.#maintenant() + attenteReprise(this.configuration.rfc3161.retry, item.k);
    this.supervision.consigner("warning", "registry_pending", { period_start: info.periodStart, code: String(r.data.code).slice(0, 64), retries: item.k, submit_period: true });
    this.cloturesEnAttente.set(item.periodHash, item);
  }

  // ------------------------------------------------- OpenTimestamps (EX-8.11)

  #objetOts(req) {
    return req.subject.kind === "periode" ? "manifeste" : `point-${req.subject.hash.slice(2)}`;
  }

  async #soumettreOts(a) {
    const req = this.planificateur.demandes.get(a.request_id);
    if (!req) return;
    const o = this.configuration.opentimestamps;
    if (!this.#nonceOtsDurable(req.subject.period_start, this.#objetOts(req), a.detail.nonce)) {
      // Lecture H1-a (EX-6.2) : rien n'est soumis tant que le nonce n'est pas durable ; la soumission est rejouée
      // avec le même engagement au pas de `retry` (calendriers_insuffisants).
      this.supervision.consigner("warning", "ots_submitted", { request_id: a.request_id, calendars_answered: 0, attestation: "aucune", errors: "nonce_non_durable" });
      await this.#injecter({ type: "reponse_ots", data: { request_id: a.request_id, calendars_answered: 0, attestation: "aucune", proof_sha256: null, proof_size: null } });
      return;
    }
    const r = await soumettre({ empreinte: a.detail.digest, nonce: hexVersOctets(a.detail.nonce, 16), calendriers: a.detail.calendars, minReponses: o.min_responses, delaiMs: o.timeout_ms, transport: this.transportOts, horloge: this.horloge });
    let data = { request_id: a.request_id, calendars_answered: r.valides, attestation: "aucune", proof_sha256: null, proof_size: null };
    if (r.ecrire) {
      const objet = this.#objetOts(req);
      const derniere = this.depotOts.derniere({ periodStart: req.subject.period_start, objet });
      let octets = r.octets;
      if (derniere && sha256Hex(derniere.octets) === sha256Hex(r.octets)) octets = derniere.octets; // rejeu avec le même engagement : rien à réécrire
      else this.depotOts.ecrire({ periodStart: req.subject.period_start, objet, octets: r.octets });
      data = { request_id: a.request_id, calendars_answered: r.valides, attestation: r.attestation, proof_sha256: sha256Hex(octets), proof_size: octets.length };
      this.supervision.consigner("info", "ots_submitted", { request_id: a.request_id, calendars_answered: r.valides, attestation: r.attestation, proof_size: octets.length });
    } else {
      this.supervision.consigner("warning", "ots_submitted", { request_id: a.request_id, calendars_answered: r.valides, attestation: "aucune", errors: r.reponses.map((x) => x.erreur ?? "ok").join("|").slice(0, 200) });
    }
    await this.#injecter({ type: "reponse_ots", data });
    if (data.attestation === "complete") await this.#entetesBitcoin(req.subject.period_start);
  }

  async #mettreANiveauOts(a) {
    const req = this.planificateur.demandes.get(a.request_id);
    if (!req) return;
    const o = this.configuration.opentimestamps;
    const objet = this.#objetOts(req);
    const derniere = this.depotOts.derniere({ periodStart: req.subject.period_start, objet });
    if (!derniere) {
      this.supervision.consigner("error", "anchor_response_rejected", { request_id: a.request_id, error_code: "preuve_absente", attempt: a.detail.attempt });
      await this.#injecter({ type: "reponse_ots", data: { request_id: a.request_id, calendars_answered: 0, attestation: "en_attente", proof_sha256: null, proof_size: null } });
      return;
    }
    const r = await mettreANiveau({
      preuve: derniere.octets, listeBlanche: o.upgrade.whitelist, transport: this.transportOts, horloge: this.horloge, delaiMs: o.timeout_ms,
      entetes: o.headers_source ? ({ hauteurs }) => this.#documentEntetes(hauteurs) : null, reseau: o.headers_source?.network ?? null,
    });
    const repondu = r.reponses.filter((x) => x.status !== null).length;
    for (const refus of r.refus) {
      if (refus.motif === "hors_liste_blanche") continue;
      this.supervision.consigner("warning", "ots_upgrade_refused", { request_id: a.request_id, reason: String(refus.motif).slice(0, 64), detail: String(refus.detail ?? "").slice(0, 200) });
    }
    let octets = derniere.octets;
    let etat = r.etat;
    if (r.nouvelle) {
      this.depotOts.ecrire({ periodStart: req.subject.period_start, objet, octets: r.nouvelle });
      octets = r.nouvelle;
      this.supervision.consigner("info", "ots_upgraded", { request_id: a.request_id, state: r.etat, heights: r.hauteurs ? `${r.hauteurs[0]}-${r.hauteurs[1]}` : null, proof_size: r.nouvelle.length });
    }
    if (etat !== "complete" && etat !== "en_attente") etat = "en_attente";
    await this.#injecter({ type: "reponse_ots", data: { request_id: a.request_id, calendars_answered: repondu, attestation: etat, proof_sha256: sha256Hex(octets), proof_size: octets.length } });
    if (etat === "complete") await this.#entetesBitcoin(req.subject.period_start);
  }

  /** Document d'en-têtes couvrant `[h, h']` depuis la source configurée (EX-6.8), ou null. */
  async #documentEntetes(hauteurs) {
    const hs = this.configuration.opentimestamps.headers_source;
    if (!hs) return null;
    try {
      if (hs.type === "fichier") return await fichierEntetes({ source: hs, hauteurs, fichier: new Uint8Array(fs.readFileSync(hs.path)) });
      const auth = hs.auth === null ? null : this.contexte.secrets.get("/opentimestamps/headers_source/auth");
      const rpc = this.clients.bitcoinRpc ?? rpcBitcoinHttp({ url: hs.url, auth, transport: this.transportOts });
      return await fichierEntetes({ source: hs, hauteurs, rpc });
    } catch (e) {
      this.supervision.consigner("warning", "bitcoin_headers_unavailable", { reason: String(e?.code ?? e?.message ?? "").slice(0, 200), heights: `${hauteurs[0]}-${hauteurs[1]}` });
      return null;
    }
  }

  /** EX-6.8 : `entetes-bitcoin.json` de la période, écrit une fois toutes les preuves de la période complètes (lecture 5 du lot B). */
  async #entetesBitcoin(periodStart) {
    const hs = this.configuration.opentimestamps.headers_source;
    if (!hs || this.depotOts.lireEntetes(periodStart)) return;
    const demandes = this.planificateur.file().filter((d) => d.kind.startsWith("ots_") && d.subject.period_start === periodStart && d.subject.org_id === this.orgId);
    if (!demandes.length || demandes.some((d) => d.state !== "complete")) return;
    let min = null;
    let max = null;
    for (const d of demandes) {
      const derniere = this.depotOts.derniere({ periodStart, objet: this.#objetOts(d) });
      if (!derniere) return;
      const h = hauteursAttestees(lireOts(derniere.octets).arbre);
      if (!h) return;
      min = min === null ? h.min : Math.min(min, h.min);
      max = max === null ? h.max : Math.max(max, h.max);
    }
    const document = await this.#documentEntetes([min, max]);
    if (!document) return;
    try {
      const r = this.depotOts.ecrireEntetes({ periodStart, document });
      this.supervision.consigner("info", "bitcoin_headers_written", { period_start: periodStart, heights: `${min}-${max}`, size: r.taille, headers: document.headers.length });
    } catch (e) {
      if (e?.code !== "fichier_existant") this.supervision.consigner("error", "anchor_piece_write_failed", { reason: `entetes-bitcoin:${String(e?.code ?? e?.message ?? "").slice(0, 120)}`, period_start: periodStart });
    }
  }

  // --------------------------------------------------------- différés au tic

  #servirDifferes() {
    const now = this.#maintenant();
    if (this.t10.length) {
      const echus = this.t10.filter((x) => x.due <= now);
      this.t10 = this.t10.filter((x) => x.due > now);
      for (const item of echus) this.#lancer(this.#executerT10(item), { action: "t10", request_id: item.request_id });
    }
    for (const [hash, item] of [...this.cloturesEnAttente]) {
      if (item.due > now) continue;
      this.cloturesEnAttente.delete(hash);
      this.#lancer(this.#clore(item), { action: "clore", request_id: null });
    }
    if (this.ecrituresEnAttente.length) {
      const restantes = [];
      for (const e of this.ecrituresEnAttente) {
        if (this.#rejouerEcriture(e)) {
          this.#apresAcquisition(e.action, e.resultat, e.prestataire, e.objet);
          this.#lancer(this.#injecter({ type: "reponse_rfc3161", data: e.resultat.data }), e.action);
        } else restantes.push(e);
      }
      this.ecrituresEnAttente = restantes;
    }
  }
}

/**
 * Crée le composant d'ancrage (rubrique F d'INTERFACES.md). La configuration
 * est validée (AN-1, secrets résolus) à la construction ; `demarrer()` refuse
 * un document invalide et lève `ErreurConfigurationAncrage`.
 */
export function creerComposantAncrage(options) {
  return new ComposantAncrage(options);
}

