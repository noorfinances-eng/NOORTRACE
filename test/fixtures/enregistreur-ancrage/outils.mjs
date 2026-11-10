// Outils des essais du composant d'ancrage branché dans l'enregistreur
// (test/enregistreur-ancrage-*.test.js, lot F2) : le montage hors réseau
// public autour d'un démon `noortrace` réel (processus enfant `demon.mjs`,
// horloge hybride) : autorités RFC 3161 du lot E (interne en HTTP local,
// principal en TLS mutuel), serveur de CRL, calendriers OpenTimestamps
// factices servis en TLS (le document `ancrage-v0` n'admet que `https://`),
// nœud noorcore factice du lot D servi en HTTP JSON-RPC, configuration de
// l'enregistreur et document `ancrage-v0`, manifeste d'instance, clé de
// chaîne de classe D, fichier d'ancres du réviseur écrit sous `os.tmpdir()`,
// et les deux vérificateurs de CT-6 lancés comme boîtes noires. Tout fichier
// va sous `os.tmpdir()`.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes as cryptoRandomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { Noeud, OP, attestationEnAttente, attestationBitcoin, ecrireTimestamp, executerArbre } from "@noortrace/ancrage/ots";
import { SignataireChaineFichier, periodDigest, hachageSigne, crlVersPem } from "@noortrace/ancrage";
import { publierCrl } from "@noortrace/ancrage/serveur-interne";
import { chaineRegtest } from "../ancrage-ots/outils.mjs";
import { NoeudFactice, validateursEssai } from "../ancrage-registre/noeud-factice.mjs";
import { configurationDev, pemPkcs8, repertoireTemporaire, RACINE, SPEC } from "../enregistreur-coeur/outils.mjs";
import { CONSTANTES_CT4, ORG, JOURNAL, HorlogeHybride, aleatoireFixe, materielTls, serveurCrl, autoriteInterne, qualifiedExemple } from "../ancrage-composant/outils.mjs";

export { RACINE, SPEC, ORG, JOURNAL, repertoireTemporaire, HorlogeHybride, materielTls, serveurCrl, autoriteInterne, qualifiedExemple, aleatoireFixe };

export const DEMON_ENFANT = path.join(path.dirname(fileURLToPath(import.meta.url)), "demon.mjs");
export const VERIFICATEUR_JS = path.join(RACINE, "scripts", "verify", "dossier.mjs");
/** Clé de chaîne de classe D des essais (graine documentée, sans valeur). */
export const GRAINE_CLE_CHAINE = N.sha256(N.utf8("noortrace/enregistreur/test/ancrage/cle-chaine-01"));

/** Marque l'essai courant en attente, condition dans le titre. */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Vérificateur Go de CT-6 (`NOORTRACE_VERIFIER_BIN`, `NOORTRACE_GO_BIN`, ou `verificateur/dist/`), ou null. */
export function binaireGo() {
  for (const c of [process.env.NOORTRACE_VERIFIER_BIN, process.env.NOORTRACE_GO_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")]) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
}

/** Port TCP libre de la boucle locale au moment de l'appel. */
export function portLibre() {
  return new Promise((res) => {
    const s = http.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

// ----------------------------------------------------- calendriers TLS

/** Chemin Bitcoin synthétique d'un engagement (même forme que les essais des lots B et F1). */
function cheminBitcoin(hauteur, graine) {
  const n = new Noeud();
  n.operation(OP.PREPEND, N.sha256(N.utf8(`${graine}/agregation`)))
    .operation(OP.SHA256, null)
    .operation(OP.APPEND, N.sha256(N.utf8(`${graine}/transaction`)))
    .operation(OP.SHA256, null)
    .operation(OP.SHA256, null)
    .ajouterAttestation(attestationBitcoin(hauteur));
  return n;
}

/**
 * Deux calendriers factices servis en TLS sur 127.0.0.1 (certificat de
 * `materielTls`) : `POST /digest` rend une promesse (attestation en attente
 * de l'URI du calendrier), `GET /timestamp/<e>` rend 404 « Pending » tant que
 * `completer(hauteur)` n'a pas été appelé, puis un chemin Bitcoin à cette
 * hauteur dont la racine est posée dans la chaîne regtest écrite dans
 * `fichierEntetes` (EX-6.9). `chaine()` rend la chaîne courante.
 */
export async function calendriersTls({ tls, fichierEntetes, nombreEnTetes = 1040 }) {
  const racines = new Map();
  const etat = { hauteur: null, requetes: [] };
  let derniere = null;
  const ecrireChaine = () => {
    derniere = chaineRegtest({ debut: 0, nombre: nombreEnTetes, racines });
    fs.writeFileSync(fichierEntetes, JSON.stringify(derniere.document, null, 2) + "\n");
  };
  ecrireChaine();
  const serveurs = [];
  const uris = [];
  for (let k = 0; k < 2; k++) {
    let uri = null;
    const serveur = https.createServer({ key: tls.serveur.cle, cert: tls.serveur.certificat }, (req, rep) => {
      const morceaux = [];
      req.on("data", (d) => morceaux.push(d));
      req.on("end", () => {
        const corps = Buffer.concat(morceaux);
        etat.requetes.push({ uri, methode: req.method, url: req.url });
        if (req.method === "POST" && req.url === "/digest") {
          if (corps.length !== 32) {
            rep.writeHead(400);
            rep.end();
            return;
          }
          const n = new Noeud();
          n.ajouterAttestation(attestationEnAttente(uri));
          rep.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1" });
          rep.end(Buffer.from(ecrireTimestamp(n)));
          return;
        }
        const m = /^\/timestamp\/([0-9a-f]{64})$/.exec(req.url ?? "");
        if (req.method === "GET" && m) {
          if (etat.hauteur === null) {
            rep.writeHead(404, { "content-type": "text/plain", "cache-control": "public, max-age=60" });
            rep.end("Pending confirmation in Bitcoin blockchain");
            return;
          }
          const engagement = N.hexVersOctets("0x" + m[1], 32);
          const chemin = cheminBitcoin(etat.hauteur, `${uri}/${m[1]}`);
          const resultat = executerArbre(chemin, engagement).attestations.find((a) => a.genre === "bitcoin").resultat;
          racines.set(etat.hauteur, resultat);
          ecrireChaine();
          etat.hauteur += 1;
          rep.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1", "cache-control": "public, max-age=31536000" });
          rep.end(Buffer.from(ecrireTimestamp(chemin)));
          return;
        }
        rep.writeHead(404);
        rep.end();
      });
    });
    await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
    uri = `https://127.0.0.1:${serveur.address().port}`;
    uris.push(uri);
    serveurs.push(serveur);
  }
  return {
    uris,
    etat,
    racines,
    chaine: () => derniere,
    completer: (hauteur) => {
      etat.hauteur = hauteur;
    },
    fermer: () => Promise.all(serveurs.map((s) => new Promise((r) => {
      s.closeAllConnections?.();
      s.close(() => r());
    }))),
  };
}

// ----------------------------------------------------- registre HTTP

/**
 * Nœud noorcore factice du lot D servi en JSON-RPC sur 127.0.0.1 (un point),
 * clé de chaîne de classe D inscrite pour la clé Ed25519 donnée, approbateurs
 * d'essai de CT-4 (comptes 1 à 3, seuil 2) et manifeste d'instance réduit.
 * @param {{clePublique: Uint8Array, orgId?: string, journalId?: string}} p
 */
export async function registreHttp({ clePublique, orgId = ORG, journalId = JOURNAL }) {
  const contrats = {
    attestation_registry: CONSTANTES_CT4.contracts.attestation_registry,
    period_registry: CONSTANTES_CT4.contracts.period_registry,
    recorder_registry: CONSTANTES_CT4.contracts.recorder_registry,
  };
  const validateurs = validateursEssai(CONSTANTES_CT4);
  let noeud = null;
  const serveur = http.createServer((req, rep) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", () => {
      let requete;
      try {
        requete = JSON.parse(Buffer.concat(morceaux).toString("utf8"));
      } catch {
        rep.writeHead(400);
        rep.end();
        return;
      }
      const reponse = Array.isArray(requete) ? requete.map((q) => noeud.repondre(url, q)) : noeud.repondre(url, requete);
      rep.writeHead(200, { "content-type": "application/json" });
      rep.end(JSON.stringify(reponse));
    });
  });
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${serveur.address().port}`;
  noeud = new NoeudFactice({ validateurs, points: [url], contrats });
  const cleChaine = new SignataireChaineFichier(GRAINE_CLE_CHAINE);
  noeud.approvisionner(cleChaine.adresse(), 4719000000n);
  noeud.inscrire({ orgId, chainKey: cleChaine.adresse(), ed25519PubKey: N.octetsVersHex(clePublique), journalId });
  const approbateurs = [1, 2, 3].map((k) => new SignataireChaineFichier(N.hexVersOctets(CONSTANTES_CT4.accounts[k].private_key)));
  const manifeste = {
    version: 0,
    bft_chain_id: "noortrace-2124-dev",
    evm_chain_id: 2124,
    contracts: [
      { name: "AttestationRegistry", address: contrats.attestation_registry },
      { name: "PeriodRegistry", address: contrats.period_registry },
      { name: "RecorderRegistry", address: contrats.recorder_registry },
    ],
    fees: { gas_limit: 3000000, gas_limit_max: 16777216 },
    validator_sets: [{ from_height: 0, to_height: null, validators: validateurs.validators, source: "jeu d'essai de CT-4 annexe A.2, clés publiques seulement" }],
    source: "manifeste d'instance réduit des essais (nœud factice du lot D), sans valeur hors des tests",
  };
  return {
    url, noeud, contrats, cleChaine, approbateurs, manifeste, validateurs,
    membres: approbateurs.map((a) => a.adresse()), seuil: 2, evmChainId: 2124, bftChainId: "noortrace-2124-dev",
    fermer: () => new Promise((r) => {
      serveur.closeAllConnections?.();
      serveur.close(() => r());
    }),
  };
}

/**
 * Demande de clôture signée au seuil par les approbateurs d'essai (CT-4 §7.7,
 * `demande_signature`), à déposer dans le répertoire du registre du journal
 * sous `demande-cloture-<periodHash>.json` pour que le démon relaie
 * `submitPeriod` (CT-4 §8.2, pas 4 et 5).
 */
export function demandeCloture({ manifeste, registre, preparedAt }) {
  const periodHash = N.hacherManifeste(manifeste);
  const periodMeta = {
    org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHash, root: manifeste.root,
    period_start: String(manifeste.period_start), period_end: String(manifeste.period_end), first_seq: String(manifeste.first_seq), last_seq: String(manifeste.last_seq), version: manifeste.version, uri: "",
  };
  const digest = periodDigest(registre.evmChainId, registre.contrats.period_registry, periodMeta);
  const hache = hachageSigne(digest);
  const signatures = registre.approbateurs.slice(0, registre.seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hache) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
  return {
    version: 0, operation: "cloture", evm_chain_id: registre.evmChainId, contract: registre.contrats.period_registry,
    fields: { period_meta: periodMeta }, digest, eip191_digest: N.octetsVersHex(hache),
    signer_set: { curator_set: CONSTANTES_CT4.curator_set?.address ?? "0x" + "11".repeat(20), threshold: registre.seuil, height: 1000, block_hash: "0x" + "22".repeat(32) },
    signatures, prepared_at: preparedAt,
  };
}

// ----------------------------------------------------- configuration

/**
 * Document `ancrage-v0` d'essai à cadence réduite admise par le schéma
 * (`checkpoint_interval_s` 10, `interval_s` 60) : prestataires donnés,
 * calendriers TLS, file sous le répertoire du journal (copie WORM avec
 * `ancres/`, EX-8.14), source d'en-têtes `fichier` regtest.
 */
export function documentAncrage({ prestataires, calendriers, fichierEntetes, repertoireJournal, surcharges = {} }) {
  const base = {
    version: 0,
    checkpoint_interval_s: 10,
    rfc3161: {
      providers: prestataires,
      manifest: { fallback_after_s: 60 },
      checkpoints: { interval_s: 60, provider_role: "interne", fallback_after_s: 30, countersign_idle: false },
      freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
      retry: { initial_ms: 2000, factor: 2, max_ms: 60000, jitter_ms: 100 },
      retention_years: 10,
      crl_capture: { enabled: true, delay_s: 0 },
    },
    registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 1, inclusion_alert_s: 60 },
    opentimestamps: {
      enabled: true,
      calendars: calendriers.uris,
      min_responses: 2,
      timeout_ms: 5000,
      checkpoint: "mi_periode",
      upgrade: { whitelist: calendriers.uris, first_after_s: 60, interval_s: 60, give_up_after_s: 3600 },
      headers_source: { type: "fichier", network: "regtest", path: fichierEntetes },
    },
    queue: { path: path.join(repertoireJournal, "ancres", "file"), max_pending: 100, anchor_pending_alert_s: 60 },
  };
  return fusionner(base, surcharges);
}

function fusionner(base, surcharges) {
  const r = structuredClone(base);
  for (const [k, v] of Object.entries(surcharges)) {
    if (v !== null && typeof v === "object" && !Array.isArray(v) && r[k] && typeof r[k] === "object" && !Array.isArray(r[k])) r[k] = fusionner(r[k], v);
    else r[k] = structuredClone(v);
  }
  return r;
}

/** Répertoire du journal de l'exemple de CT-2 sous `storage.root` (EX-12.1 : identifiants sans 0x). */
export function repertoireJournal(config) {
  return path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
}

/**
 * Monte le décor du démon : TLS, CRL, autorités (interne HTTP pour les
 * points ; principal TLS mutuel, `qualified` d'exemple), calendriers TLS,
 * registre HTTP (ou `null`), puis écrit la configuration de l'enregistreur
 * (`anchoring.ancrage`, `anchoring.registry` de classe D), le document
 * `ancrage-v0`, le manifeste d'instance et les secrets (fichiers 0600).
 * @param {{dir: string, baseMs: number, registre?: boolean, surchargesAncrage?: object, surchargesConfig?: (c: object) => void,
 *   secretPrincipal?: object|null, sansSecours?: boolean}} o
 */
export async function monterDemon(o) {
  const dir = o.dir;
  const tls = materielTls(path.join(dir, "tls"));
  if (!tls) return { condition: "openssl indisponible pour le matériel TLS" };
  const horloge = new HorlogeHybride(o.baseMs);
  const aleatoire = aleatoireFixe(23);
  const crl = await serveurCrl(horloge);
  const interne = await autoriteInterne({ nom: "tsa-interne", dir, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1" });
  const principal = await autoriteInterne({ nom: "qtsa-principal", dir, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
  const fichierEntetes = path.join(dir, "entetes-regtest.json");
  const calendriers = await calendriersTls({ tls, fichierEntetes });
  const { config, env } = configurationDev(path.join(dir, "enregistreur"), { checkpoint_interval_s: 10 });
  // Toutes les lignes au fichier (les points écrits sont consignés en `debug`).
  config.supervision.ops_log.level = "debug";
  const repertoire = repertoireJournal(config);
  const secretClient = path.join(dir, "secrets", "client-tls.pem");
  fs.mkdirSync(path.dirname(secretClient), { recursive: true, mode: 0o700 });
  fs.writeFileSync(secretClient, Buffer.from(tls.client), { mode: 0o600 });
  const prestataires = [principal.prestataire, interne.prestataire].map((p) => structuredClone(p));
  prestataires[0].auth = { method: "certificat_client", secret: o.secretPrincipal === undefined ? { file: secretClient } : o.secretPrincipal };
  const documentAncrageV0 = documentAncrage({ prestataires, calendriers, fichierEntetes, repertoireJournal: repertoire, surcharges: o.surchargesAncrage ?? {} });
  const cheminAncrage = path.join(dir, "ancrage", "ancrage.json");
  fs.mkdirSync(path.dirname(cheminAncrage), { recursive: true });
  fs.writeFileSync(cheminAncrage, JSON.stringify(documentAncrageV0, null, 2) + "\n");
  config.anchoring.ancrage = cheminAncrage;
  let registre = null;
  if (o.registre !== false) {
    const graineRec = N.sha256(N.utf8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01"));
    const publique = N.clePubliqueEd25519(graineRec);
    registre = await registreHttp({ clePublique: publique, orgId: config.recorder.org_id, journalId: config.recorder.journal_id });
    fs.writeFileSync(path.join(path.dirname(cheminAncrage), "instance-registre.json"), JSON.stringify(registre.manifeste, null, 2) + "\n");
    const cleFichier = path.join(dir, "secrets", "cle-chaine.hex");
    fs.writeFileSync(cleFichier, N.octetsVersHex(GRAINE_CLE_CHAINE), { mode: 0o600 });
    config.anchoring.registry = { enabled: true, rpc_url: registre.url, chain_key: { class: "D", address: registre.cleChaine.adresse(), secret: { file: cleFichier }, service_url: null }, next_chain_key: null };
  }
  if (o.surchargesConfig) o.surchargesConfig(config);
  const cheminConfig = path.join(dir, "configuration.json");
  fs.writeFileSync(cheminConfig, JSON.stringify(config, null, 2));
  fs.writeFileSync(path.join(dir, "tls", "ca-extra.pem"), tls.ca);
  const envDemon = { ...env, NODE_EXTRA_CA_CERTS: path.join(dir, "tls", "ca-extra.pem"), NOORTRACE_TEST_HORLOGE_BASE_MS: String(o.baseMs) };
  return {
    dir, tls, horloge, crl, interne, principal, calendriers, registre, config, env: envDemon, cheminConfig, cheminAncrage, documentAncrage: documentAncrageV0, repertoire, fichierEntetes,
    fermer: async () => {
      await Promise.all([interne.fermer(), principal.fermer(), calendriers.fermer(), crl.fermer(), registre?.fermer()].filter(Boolean));
    },
  };
}

// ----------------------------------------------------- démon enfant

/** Démon réel dans un processus enfant (`demon.mjs`), piloté par des commandes JSON. */
export class Demon {
  constructor(montage, o = {}) {
    this.montage = montage;
    this.horloge = montage.horloge;
    this.o = o;
    this.p = null;
    this.sortie = "";
    this.attentes = [];
    this.compteur = 0;
    this.demarrage = null;
  }

  async demarrer() {
    const m = this.montage;
    this.p = spawn(process.execPath, [DEMON_ENFANT, "noortrace", "--config", m.cheminConfig], { env: { ...process.env, ...m.env, ...(this.o.env ?? {}) }, stdio: ["pipe", "pipe", "pipe"] });
    this.p.stderr.on("data", (d) => (this.sortie += d));
    let reste = "";
    this.p.stdout.on("data", (d) => {
      reste += d;
      let k;
      while ((k = reste.indexOf("\n")) >= 0) {
        const ligne = reste.slice(0, k);
        reste = reste.slice(k + 1);
        if (!ligne.trim()) continue;
        let o;
        try {
          o = JSON.parse(ligne);
        } catch {
          continue;
        }
        if (o.started !== undefined) {
          this.demarrage = o;
          this.attentes.shift()?.(o);
        } else this.attentes.shift()?.(o);
      }
    });
    this.fin = new Promise((r) => this.p.on("exit", (code, signal) => r({ code, signal })));
    const premiere = await Promise.race([new Promise((r) => this.attentes.push(r)), this.fin.then((f) => ({ started: false, ...f }))]);
    if (!premiere.started) throw new Error(`démon non démarré : ${JSON.stringify(premiere)}\n${this.sortie}`);
    // L'horloge miroir du décor (autorités, CRL) est calée sur celle du démon, créée plus tard que la sienne.
    if (Number.isFinite(premiere.murale)) this.horloge.decalage -= this.horloge.murale() - premiere.murale;
    this.port = premiere.port;
    this.pid = premiere.pid;
    return premiere;
  }

  commande(c, delaiMs = 120000) {
    const id = ++this.compteur;
    return new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error(`commande ${c.cmd} sans réponse en ${delaiMs} ms\n${this.sortie.slice(-2000)}`)), delaiMs);
      this.attentes.push((o) => {
        clearTimeout(t);
        if (o.ok === false) rej(new Error(`commande ${c.cmd} refusée : ${o.erreur}`));
        else res(o);
      });
      this.p.stdin.write(`${JSON.stringify({ ...c, id })}\n`);
    });
  }

  /** Saute de `ms` : l'horloge miroir du décor (autorités, CRL) et celle du démon avancent ensemble. */
  async avancer(ms) {
    await this.horloge.avancer(ms);
    return this.commande({ cmd: "avancer", ms });
  }

  evenement(n = 1) {
    return this.commande({ cmd: "evenement", n });
  }

  /** Recule ou avance la seule horloge murale (décor et démon ensemble), la monotone suivant le temps réel (CT-2 EX-7.9, EX-7.13). */
  decalerMurale(ms) {
    this.horloge.decalerMurale(ms);
    return this.commande({ cmd: "decaler-murale", ms });
  }

  exporter(seq, destination) {
    return this.commande({ cmd: "exporter", seq, destination });
  }

  etat() {
    return this.commande({ cmd: "etat" });
  }

  /** Lignes du journal d'exploitation (fichier) du démon. */
  lignes() {
    const f = this.montage.config.supervision.ops_log.path;
    return fs.existsSync(f) ? fs.readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  }

  de(evenement) {
    return this.lignes().filter((l) => l.event === evenement);
  }

  /** Attend qu'un prédicat sur les lignes du journal soit vrai (temps réel), ou lève après `delaiMs`. */
  async attendre(predicat, delaiMs = 60000, description = "condition") {
    const limite = Date.now() + delaiMs;
    for (;;) {
      const lignes = this.lignes();
      if (predicat(lignes)) return lignes;
      if (Date.now() > limite) throw new Error(`${description} non atteinte en ${delaiMs} ms ; derniers événements : ${lignes.slice(-12).map((l) => l.event).join(", ")}\n${this.sortie.slice(-1500)}`);
      await new Promise((r) => setTimeout(r, 200));
    }
  }

  async arreter() {
    if (!this.p || this.p.exitCode !== null) return this.fin;
    this.p.stdin.write(`${JSON.stringify({ cmd: "arreter", id: ++this.compteur })}\n`);
    const r = await Promise.race([this.fin, new Promise((res) => setTimeout(() => res(null), 30000))]);
    if (r === null) {
      this.p.kill("SIGKILL");
      return this.fin;
    }
    return r;
  }
}

// ----------------------------------------------------- fichier d'ancres et vérificateurs

/**
 * Fichier d'ancres du réviseur (CT-6 §12, schéma `ancres-confiance-v0`) pour
 * le décor : autorités des serveurs internes de test (l'autorité des points
 * « non qualifiée » : `qualified: null` ; le principal avec son `qualified`
 * déclaratif en option), CRL courantes des autorités, point de contrôle de
 * la chaîne regtest, registre du décor, clé de l'enregistreur. Écrit sous
 * `os.tmpdir()`, jamais dans le dépôt.
 */
export function fichierAncres({ chemin, montage, bitcoin = null, registry = true, qualifiedPrincipal = null, preparedAt = "2026-11-05T12:00:00.000Z", recorders = null }) {
  const m = montage;
  const autorite = (a, qualified) => ({ name: `AC ${a.nom} (essai)`, certificate: a.init.acPem, intermediates: [], accepted_policies: [a.prestataire.policy_oid], qualified, source: `AC d'essai du lot E (${a.nom}), sans valeur hors des tests` });
  const crls = [m.interne, m.principal].map((a) => crlVersPem(publierCrl({ repertoire: a.repertoire, horloge: { murale: () => m.horloge.murale() }, revoques: [] }).octets));
  const graineRec = N.sha256(N.utf8("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01"));
  const ancres = {
    version: 0,
    label: "Ancres des essais du lot F2",
    prepared_by: "essai automatique",
    prepared_at: preparedAt,
    tsa_authorities: [autorite(m.interne, null), autorite(m.principal, qualifiedPrincipal)],
    revocation: { crls, statements: [] },
    bitcoin: bitcoin ? { network: "regtest", checkpoint: { height: bitcoin.height, hash: bitcoin.hash }, min_confirmations: 1, source: "chaîne regtest synthétique des essais, sans valeur hors des tests" } : null,
    registry: registry && m.registre ? {
      chain_id: m.registre.bftChainId,
      contracts: m.registre.contrats,
      validator_sets: m.registre.manifeste.validator_sets.map((s) => ({ from_height: s.from_height, to_height: s.to_height, validators: s.validators, source: s.source })),
      source: "nœud noorcore factice des essais (jeu d'essai de CT-4), sans valeur hors des tests",
    } : null,
    recorders: recorders ?? [{ org_id: m.config.recorder.org_id, journal_id: m.config.recorder.journal_id, key_id: "rec-test-01", public_key: N.octetsVersHex(N.clePubliqueEd25519(graineRec)), chain_key: m.registre ? m.registre.cleChaine.adresse() : null, source: "clé de test de CT-1 §13 ; clé de chaîne de classe D des essais" }],
  };
  fs.writeFileSync(chemin, JSON.stringify(ancres, null, 2) + "\n");
  return ancres;
}

/** Point de contrôle Bitcoin d'un décor : hauteur et hachage affiché d'un en-tête de la chaîne regtest courante. */
export function pointDeControleBitcoin(montage, hauteur) {
  const e = montage.calendriers.chaine().enTetes.find((x) => x.hauteur === hauteur);
  return { height: hauteur, hash: e.hashAffiche };
}

/** Rapport JSON du vérificateur JavaScript de référence (boîte noire). */
export function verifierJs(repertoire, { ancres = null, entetes = null } = {}) {
  const args = [VERIFICATEUR_JS, repertoire, "--json", ...(ancres ? ["--ancres", ancres] : []), ...(entetes ? ["--entetes-bitcoin", entetes] : [])];
  const r = spawnSync(process.execPath, args, { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

/** Rapport JSON du binaire Go de CT-6 (boîte noire), ou null sans binaire. */
export function verifierGo(repertoire, { ancres = null, entetes = null, bin = binaireGo() } = {}) {
  if (!bin) return null;
  const args = [repertoire, "--json", ...(ancres ? ["--ancres", ancres] : []), ...(entetes ? ["--entetes-bitcoin", entetes] : [])];
  const r = spawnSync(bin, args, { cwd: RACINE, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: r.stdout ? JSON.parse(r.stdout) : null, stderr: r.stderr };
}

/** Statuts des vérifications d'un rapport, par identifiant. */
export function statuts(rapport) {
  return Object.fromEntries(rapport.checks.map((c) => [c.id, c.status]));
}

/** Répertoires créés par `fichierTemporaire`, supprimés à la sortie du processus d'essai. */
const REPERTOIRES_TEMPORAIRES = new Set();
process.once("exit", () => {
  for (const d of REPERTOIRES_TEMPORAIRES) fs.rmSync(d, { recursive: true, force: true });
});

/** Nom temporaire sous os.tmpdir(). */
export function fichierTemporaire(nom) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-ancrage-f2-"));
  REPERTOIRES_TEMPORAIRES.add(dir);
  return path.join(dir, nom);
}

// ----------------------------------------------------- montage en cours de processus

/**
 * Montage en cours de processus (essais d'exigences) : le décor du lot F1
 * (`monterComposant` : horloge réglable, autorités, calendriers factices,
 * registre factice, configuration `ancrage-v0`), la configuration de
 * développement de l'enregistreur qui désigne ce document (`anchoring.ancrage`,
 * `anchoring.registry` de classe D, manifeste d'instance), et le branchement
 * préparé avec les clients du décor injectés. `Coeur.demarrer` est laissé à
 * l'essai (horloge réglable, pas de minuteurs).
 * @param {{dir: string, periodStart: number, surchargesAncrage?: object, document?: (doc: object) => void, config?: (c: object) => void,
 *   registre?: boolean, ErreurTransport?: Function|null, chainKey?: object|null}} o
 */
export async function monterEnProcessus(o) {
  const { monterComposant } = await import("../ancrage-composant/outils.mjs");
  const { validerConfiguration, resoudreSecrets, preparerAncrage } = await import("@noortrace/enregistreur");
  const m = await monterComposant({ dir: path.join(o.dir, "montage"), periodStart: o.periodStart, evenements: { 1: 1 }, ErreurTransport: o.ErreurTransport ?? null, surcharges: o.surchargesAncrage ?? {} });
  if (m.condition) return { condition: m.condition };
  const { config, env } = configurationDev(path.join(o.dir, "enregistreur"), { checkpoint_interval_s: 60 });
  config.supervision.ops_log.level = "debug";
  const repertoire = repertoireJournal(config);
  const doc = structuredClone(m.configuration);
  doc.queue.path = path.join(repertoire, "ancres", "file");
  const secretClient = path.join(o.dir, "secrets", "client-tls.pem");
  fs.mkdirSync(path.dirname(secretClient), { recursive: true, mode: 0o700 });
  fs.writeFileSync(secretClient, Buffer.from(m.tls.client), { mode: 0o600 });
  for (const p of doc.rfc3161.providers) if (p.auth.method !== "aucune") p.auth.secret = { file: secretClient };
  if (o.document) o.document(doc);
  const cheminAncrage = path.join(o.dir, "ancrage", "ancrage.json");
  fs.mkdirSync(path.dirname(cheminAncrage), { recursive: true });
  fs.writeFileSync(cheminAncrage, JSON.stringify(doc, null, 2) + "\n");
  config.anchoring.ancrage = cheminAncrage;
  if (o.registre !== false) {
    const i = m.registre.instance;
    fs.writeFileSync(path.join(path.dirname(cheminAncrage), "instance-registre.json"), JSON.stringify({
      version: 0, bft_chain_id: i.bftChainId, evm_chain_id: i.evmChainId,
      contracts: [{ name: "AttestationRegistry", address: i.contrats.attestation_registry }, { name: "PeriodRegistry", address: i.contrats.period_registry }, { name: "RecorderRegistry", address: i.contrats.recorder_registry }],
      fees: i.fees, validator_sets: [{ from_height: 0, to_height: null, validators: i.jeux.validators, source: i.jeux.source }], source: "manifeste d'instance réduit des essais",
    }, null, 2));
    const cleFichier = path.join(o.dir, "secrets", "cle-chaine.hex");
    fs.writeFileSync(cleFichier, N.octetsVersHex(N.sha256(N.utf8("noortrace/ancrage/test/composant/cle-chaine-01"))), { mode: 0o600 });
    config.anchoring.registry = { enabled: true, rpc_url: "http://127.0.0.1:8645", chain_key: o.chainKey ?? { class: "D", address: m.registre.cleChaine.adresse(), secret: { file: cleFichier }, service_url: null }, next_chain_key: null };
  }
  if (o.config) o.config(config);
  const cheminConfig = path.join(o.dir, "configuration.json");
  const octets = N.utf8(JSON.stringify(config, null, 2));
  fs.writeFileSync(cheminConfig, octets);
  const v = validerConfiguration(octets);
  if (v.erreurs.length) throw new Error(`configuration de l'essai invalide : ${JSON.stringify(v.erreurs)}`);
  const s = resoudreSecrets(v.config, { env });
  if (s.erreurs.length) throw new Error(`secrets de l'essai : ${JSON.stringify(s.erreurs)}`);
  const clients = { rfc3161: { transport: m.transport }, ots: { transport: m.calendriers.transport } };
  if (o.registre !== false) clients.registre = { rpc: m.registre.rpc, instance: m.registre.instance, delais: { recuMs: 60000, sondageMs: 500 } };
  const preparer = () => preparerAncrage({ config: v.config, secrets: s.secrets, env, horloge: m.horloge, clients });
  return { m, config: v.config, secrets: s.secrets, env, octets, cheminConfig, cheminAncrage, document: doc, repertoire, preparer, horloge: m.horloge, fermer: () => m.fermer() };
}



/** Échange de modèle factice scellé par le cœur (événement durable). */
export async function echangeFactice(coeur, n) {
  const { pieceJson } = await import("@noortrace/enregistreur");
  const req = pieceJson({ n, messages: [{ role: "user", content: `requete ${n}` }] });
  const rep = pieceJson({ n, content: [{ type: "text", text: `reponse ${n}` }] });
  await coeur.ecrirePiece(req);
  await coeur.ecrirePiece(rep);
  return coeur.scellerEchange({ delegation: { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement", run_id: null }, code: { model: "fournisseur/modele-test", prompt_version: null }, intent: null, requete: req.reference, reponse: rep.reference, duration_ms: 10, is_error: false });
}

/**
 * Opérations d'un support WORM en mémoire (interface d'`OperationsS3`
 * employée par `ServiceCopiesWorm`) : versions, écriture conditionnelle à
 * l'absence (412 sinon), verrou `COMPLIANCE` à l'échéance donnée.
 */
export function operationsWormMemoire({ retainUntil = "2040-01-01T00:00:00.000Z", lastModified = "Thu, 05 Nov 2026 08:00:00 GMT" } = {}) {
  const objets = new Map();
  let n = 0;
  return {
    objets,
    async copier(cle, octets) {
      if (objets.has(cle)) return { statut: 412, version_id: null, code: "PreconditionFailed" };
      const version_id = `v${++n}`;
      objets.set(cle, { octets: Uint8Array.from(octets), version_id, sha256: N.sha256Hex(octets) });
      return { statut: 200, version_id, code: null };
    },
    async empreinte(cle) {
      const o = objets.get(cle);
      if (!o) return { statut: 404, sha256: null, longueur: null, version_id: null, last_modified: null };
      return { statut: 200, sha256: o.sha256, longueur: o.octets.length, version_id: o.version_id, last_modified: lastModified };
    },
    async etat(cle, versionId) {
      const o = objets.get(cle);
      if (!o || o.version_id !== versionId) return { statut: 404, entetes: {}, json: null };
      return { statut: 200, entetes: { "x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": retainUntil }, json: null };
    },
    async listerVersions(prefixe) {
      return { statut: 200, versions: [...objets].filter(([k]) => k.startsWith(prefixe)).map(([key, o]) => ({ key, version_id: o.version_id, is_latest: true, delete_marker: false })), page: 1, code: null };
    },
  };
}

// ----------------------------------------------------- réseau de développement réel

/** Points JSON-RPC des quatre validateurs du réseau de développement (chain/scripts/dev-net.sh). */
export const POINTS_RESEAU_DEV = Object.freeze(["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"]);
export const EVM_RESEAU_DEV = 2124;
export const BFT_RESEAU_DEV = "noortrace-2124-dev";

/**
 * Lit la sortie d'un parcours de référence du registre (`npm run e2e:registre
 * -- --garder-reseau --sortie <répertoire>`, boîte noire) : clés du journal
 * inscrit (graine Ed25519, clé de chaîne de classe D, approbateurs 1 à 3),
 * identifiants de l'organisation et du journal, jeu de signataires de
 * l'inscription, contrats déployés (`deployments/noorcore.json`) et jeu de
 * validateurs du réseau.
 * @param {string} repertoire sortie du parcours
 */
export function lireParcours(repertoire) {
  const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
  const cles = lireJson(path.join(repertoire, "cles", "cles-essai.json"));
  const inscription = lireJson(path.join(repertoire, "demande-inscription.json"));
  const recorder = lireJson(path.join(repertoire, "cles", "rec-demo-01.json"));
  const graine = N.hexVersOctets(fs.readFileSync(path.join(repertoire, "cles", "rec-demo-01.graine"), "utf8").trim(), 32);
  const cleChaineOctets = new Uint8Array(fs.readFileSync(path.join(repertoire, "cles", "cle-chaine-rec-demo-01.cle")));
  const cleChaine = SignataireChaineFichier.depuisOctets(cleChaineOctets);
  const approbateurs = [1, 2, 3].map((k) => SignataireChaineFichier.depuisOctets(new Uint8Array(fs.readFileSync(path.join(repertoire, "cles", `approbateur-${k}.cle`)))));
  const deploiement = lireJson(path.join(RACINE, "deployments", "noorcore.json"));
  const contrats = {
    attestation_registry: deploiement.contrats.AttestationRegistry.adresse.toLowerCase(),
    period_registry: deploiement.contrats.PeriodRegistry.adresse.toLowerCase(),
    recorder_registry: deploiement.contrats.RecorderRegistry.adresse.toLowerCase(),
  };
  const fichierJeu = [path.join(RACINE, "chain", "runtime", "validators.json"), path.join(RACINE, "test", "fixtures", "certificat-commit", "validators.json")].find((f) => fs.existsSync(f));
  const validators = lireJson(fichierJeu).validators;
  return {
    repertoire, cles, inscription, recorder, graine, cleChaineOctets, cleChaine, approbateurs, contrats, validators,
    orgId: inscription.fields.org_id, journalId: inscription.fields.journal_id,
    clePublique: N.clePubliqueEd25519(graine),
    seuil: inscription.signer_set.threshold,
    membres: cles.approvers.map((a) => a.toLowerCase()),
  };
}

/**
 * Demande de clôture (CT-4 §7.7, `demande_signature`, `operation` `cloture`)
 * d'un manifeste du journal inscrit par le parcours de référence, signée au
 * seuil par ses approbateurs (RG-13 : signatures rangées par adresse), à
 * déposer sous `<journal>/registre/demande-cloture-<period_hash>.json` pour
 * que le démon relaie `submitPeriod` (CT-4 §8.2 pas 4 et 5 ; lecture F2-3).
 * `signer_set` reprend celui de l'inscription (jeu, seuil, tête lue alors).
 */
export function demandeClotureParcours({ manifeste, parcours, preparedAt, uri = "" }) {
  const periodHash = N.hacherManifeste(manifeste);
  const periodMeta = {
    org_id: manifeste.org_id, journal_id: manifeste.journal_id, period_hash: periodHash, root: manifeste.root,
    period_start: String(manifeste.period_start), period_end: String(manifeste.period_end), first_seq: String(manifeste.first_seq), last_seq: String(manifeste.last_seq), version: manifeste.version, uri,
  };
  const digest = periodDigest(EVM_RESEAU_DEV, parcours.contrats.period_registry, periodMeta);
  const hache = hachageSigne(digest);
  const signatures = parcours.approbateurs.slice(0, parcours.seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hache) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
  return {
    version: 0, operation: "cloture", evm_chain_id: EVM_RESEAU_DEV, contract: parcours.contrats.period_registry,
    fields: { period_meta: periodMeta }, digest, eip191_digest: N.octetsVersHex(hache),
    signer_set: { ...parcours.inscription.signer_set },
    signatures, prepared_at: preparedAt,
  };
}

/**
 * Monte le décor d'un démon réel branché sur le réseau de développement
 * (quatre validateurs noorcore) avec le journal inscrit par un parcours de
 * référence : autorités RFC 3161 du lot E (interne en HTTP local, principal
 * en TLS mutuel avec un `qualified` d'exemple), serveur de CRL, calendriers
 * factices TLS à chaîne regtest, configuration de l'enregistreur (clé du
 * parcours, `anchoring.registry` de classe D vers les validateurs), document
 * `ancrage-v0` et manifeste d'instance du réseau. Horloge hybride calée sur
 * `baseMs` (temps réel sans saut quand `baseMs` est l'instant courant).
 * @param {{travail: string, parcours: object, baseMs: number, cK?: number, surchargesAncrage?: object, surchargesConfig?: (c: object) => void,
 *   journalTsa?: {consigner: Function}|null, graineAlea?: number}} o
 */
export async function monterDemonReseauReel(o) {
  const { travail, parcours } = o;
  const tls = materielTls(path.join(travail, "tls"));
  if (!tls) return { condition: "openssl indisponible pour le matériel TLS" };
  const horloge = new HorlogeHybride(o.baseMs);
  const aleatoire = aleatoireFixe(o.graineAlea ?? 29);
  const crl = await serveurCrl(horloge);
  const journalTsa = o.journalTsa ?? null;
  const interne = await autoriteInterne({ nom: "tsa-interne", dir: travail, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1", journal: journalTsa });
  const principal = await autoriteInterne({ nom: "qtsa-principal", dir: travail, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1", journal: journalTsa });
  const fichierEntetes = path.join(travail, "entetes-regtest.json");
  const calendriers = await calendriersTls({ tls, fichierEntetes });
  const cK = o.cK ?? 10;
  const { config, env } = configurationDev(path.join(travail, "enregistreur"), { checkpoint_interval_s: cK, journal_id: parcours.journalId });
  config.recorder.org_id = parcours.orgId;
  config.signer.key_id = parcours.recorder.key_id;
  fs.writeFileSync(path.join(travail, "enregistreur", "cles", `${parcours.recorder.key_id}.pem`), pemPkcs8(parcours.graine), { mode: 0o600 });
  config.signer.backend.path = path.join(travail, "enregistreur", "cles", `${parcours.recorder.key_id}.pem`);
  config.signer.rotation.next_key_id = null;
  config.supervision.ops_log.level = "debug";
  const repertoire = repertoireJournal(config);
  const secretClient = path.join(travail, "secrets", "client-tls.pem");
  fs.mkdirSync(path.dirname(secretClient), { recursive: true, mode: 0o700 });
  fs.writeFileSync(secretClient, Buffer.from(tls.client), { mode: 0o600 });
  const prestataires = [structuredClone(principal.prestataire), structuredClone(interne.prestataire)];
  prestataires[0].auth = { method: "certificat_client", secret: { file: secretClient } };
  const doc = documentAncrage({ prestataires, calendriers, fichierEntetes, repertoireJournal: repertoire, surcharges: fusionner({ checkpoint_interval_s: cK, registry: { checkpoints: "tous", inclusion_alert_s: 120 } }, o.surchargesAncrage ?? {}) });
  const cheminAncrage = path.join(travail, "ancrage", "ancrage.json");
  fs.mkdirSync(path.dirname(cheminAncrage), { recursive: true });
  fs.writeFileSync(cheminAncrage, JSON.stringify(doc, null, 2));
  const manifesteInstance = {
    version: 0, bft_chain_id: BFT_RESEAU_DEV, evm_chain_id: EVM_RESEAU_DEV,
    contracts: Object.entries({ AttestationRegistry: parcours.contrats.attestation_registry, PeriodRegistry: parcours.contrats.period_registry, RecorderRegistry: parcours.contrats.recorder_registry }).map(([name, address]) => ({ name, address })),
    fees: { gas_limit: 3000000, gas_limit_max: 16777216 },
    validator_sets: [{ from_height: 1, to_height: null, validators: parcours.validators, source: "validators.json du réseau de développement, clés publiques seulement" }],
    source: "réseau de développement (deployments/noorcore.json, chain/runtime/validators.json)",
  };
  fs.writeFileSync(path.join(path.dirname(cheminAncrage), "instance-registre.json"), JSON.stringify(manifesteInstance, null, 2));
  const cleFichier = path.join(travail, "secrets", "cle-chaine.cle");
  fs.writeFileSync(cleFichier, parcours.cleChaineOctets, { mode: 0o600 });
  config.anchoring.ancrage = cheminAncrage;
  config.anchoring.registry = { enabled: true, rpc_url: POINTS_RESEAU_DEV[0], chain_key: { class: "D", address: parcours.cleChaine.adresse(), secret: { file: cleFichier }, service_url: null }, next_chain_key: null };
  config.supervision.health_listen = `127.0.0.1:${await portLibre()}`;
  if (o.surchargesConfig) o.surchargesConfig(config);
  const cheminConfig = path.join(travail, "configuration.json");
  fs.writeFileSync(cheminConfig, JSON.stringify(config, null, 2));
  fs.writeFileSync(path.join(travail, "tls", "ca-extra.pem"), Buffer.concat([Buffer.from(tls.ca), ...(o.caSupplementaires ?? []).map((c) => Buffer.from(c))]));
  return {
    dir: travail, tls, horloge, crl, interne, principal, calendriers, config, cheminConfig, cheminAncrage, documentAncrage: doc, repertoire, fichierEntetes, parcours,
    registre: {
      bftChainId: BFT_RESEAU_DEV, evmChainId: EVM_RESEAU_DEV, contrats: parcours.contrats, cleChaine: parcours.cleChaine,
      manifeste: { validator_sets: manifesteInstance.validator_sets },
    },
    env: { ...env, NODE_EXTRA_CA_CERTS: path.join(travail, "tls", "ca-extra.pem"), NOORTRACE_TEST_HORLOGE_BASE_MS: String(o.baseMs) },
    fermer: async () => {
      await Promise.all([interne.fermer(), principal.fermer(), calendriers.fermer(), crl.fermer()]);
    },
  };
}

/**
 * Lance une commande sans réseau, par `unshare -n` (espace de noms réseau
 * vide : seule la boucle locale existe, sans route), pour éprouver P-5 de
 * CT-5 (vérification hors ligne). Rend `{ disponible, code, stdout, stderr }` ;
 * `disponible` faux quand `unshare` est refusé dans ce conteneur.
 */
export function sansReseau(commande, args, { cwd = RACINE } = {}) {
  const essai = spawnSync("unshare", ["-n", "true"], { encoding: "utf8" });
  if (essai.status !== 0) return { disponible: false, code: null, stdout: "", stderr: essai.stderr ?? "" };
  const r = spawnSync("unshare", ["-n", commande, ...args], { cwd, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { disponible: true, code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * Inscrit un journal neuf (clé Ed25519 et clé de chaîne de classe D neuves)
 * sous l'organisation d'un parcours de référence, par l'outil de référence
 * du registre exécuté comme une boîte noire (CT-4 §7.7, §8.7 : `condense
 * inscription`, `signer` par deux approbateurs du parcours, `approvisionner`
 * par la trésorerie de développement `hardhat:0`, `inscrire-cle`). Le journal
 * n'a aucune période au registre : sa première clôture ne dépend d'aucune
 * continuité (CT-4 OP-10). Rend un objet de la forme de `lireParcours`, ou
 * `{ condition }` quand une étape échoue. La graine Ed25519 est
 * SHA-256(UTF-8("noortrace/enregistreur/test/ancrage/journal-neuf/<etiquette>")),
 * la clé de chaîne est tirée au hasard et n'est écrite que sous `travail`.
 * @param {{parcours: object, travail: string, etiquette: string, keyId?: string, aleatoire?: (n: number) => Uint8Array}} o
 */
export function inscrireJournal({ parcours, travail, etiquette, keyId = "rec-neuf-01", aleatoire = null }) {
  const rep = path.join(travail, "inscription");
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const graine = N.sha256(N.utf8(`noortrace/enregistreur/test/ancrage/journal-neuf/${etiquette}`));
  const cleChaineOctets = aleatoire ? aleatoire(32) : new Uint8Array(cryptoRandomBytes(32));
  const cleChaine = SignataireChaineFichier.depuisOctets(cleChaineOctets);
  const fichierCle = path.join(rep, "cle-chaine.cle");
  fs.writeFileSync(fichierCle, `${N.octetsVersHex(cleChaineOctets)}\n`, { mode: 0o600 });
  const journalId = N.octetsVersHex(N.keccak256(N.utf8(`noortrace/enregistreur/test/ancrage/journal-neuf/${etiquette}/journal`)));
  const clePublique = N.clePubliqueEd25519(graine);
  const demande = path.join(rep, "demande-inscription.json");
  const outil = path.join(RACINE, "scripts", "registre", "noortrace-registre.mjs");
  const etapes = [
    ["condense", "inscription", "--org-id", parcours.orgId, "--journal-id", journalId, "--cle-chaine-adresse", cleChaine.adresse(), "--cle-ed25519", N.octetsVersHex(clePublique), "--sortie", demande],
    ["signer", "--demande", demande, "--cle", `fichier:${path.join(parcours.repertoire, "cles", "approbateur-1.cle")}`],
    ["signer", "--demande", demande, "--cle", `fichier:${path.join(parcours.repertoire, "cles", "approbateur-2.cle")}`],
    ["approvisionner", "--vers", cleChaine.adresse(), "--demande", demande, "--tresorerie", "hardhat:0", "--captures", path.join(rep, "captures")],
    ["inscrire-cle", "--demande", demande, "--cle-chaine", `fichier:${fichierCle}`, "--captures", path.join(rep, "captures")],
  ];
  const sorties = [];
  for (const args of etapes) {
    const r = spawnSync(process.execPath, [outil, ...args], { cwd: RACINE, encoding: "utf8", timeout: 300000, maxBuffer: 16 * 1024 * 1024 });
    let j = null;
    try {
      j = JSON.parse(r.stdout);
    } catch {
      j = null;
    }
    sorties.push({ commande: args[0], result: j?.result ?? null, code: r.status });
    if (r.status !== 0 || j?.result !== "reussi") return { condition: `inscription du journal neuf : ${args[0]} a rendu ${j?.result ?? `code ${r.status}`} (${j?.error?.message ?? (r.stderr ?? "").trim().slice(-200)})` };
  }
  const inscription = JSON.parse(fs.readFileSync(demande, "utf8"));
  return {
    repertoire: parcours.repertoire, cles: parcours.cles, inscription, recorder: { key_id: keyId }, graine, cleChaineOctets, cleChaine, approbateurs: parcours.approbateurs,
    contrats: parcours.contrats, validators: parcours.validators, orgId: parcours.orgId, journalId, clePublique, seuil: inscription.signer_set.threshold, membres: parcours.membres,
    neuf: true, sorties,
  };
}
