// Outils des tests du composant d'ancrage (lot F1) : horloge réglable à
// minuteries injectées, matériel TLS produit par `openssl` (boîte noire),
// autorités et serveurs RFC 3161 du lot E (HTTP local et TLS mutuel), serveur
// de CRL local, calendriers OpenTimestamps factices (promesses, puis chemin
// Bitcoin complet sur une chaîne regtest du lot B dont le fichier d'en-têtes
// est tenu à jour), série de points et manifeste synthétiques signés avec les
// clés de test publiées de CT-1, nœud noorcore factice du lot D et contexte
// d'exécution. Tout fichier va sous `os.tmpdir()`.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { initialiserAutorite, chargerAutorite, publierCrl, CompteurMemoire, demarrerServeur } from "@noortrace/ancrage/serveur-interne";
import { transportHttps as transportRfc3161 } from "@noortrace/ancrage/rfc3161";
import { transportHttps as transportOts, Noeud, OP, attestationEnAttente, attestationBitcoin, ecrireTimestamp, lireTimestamp, executerArbre } from "@noortrace/ancrage/ots";
import { ClientRpc, SignataireChaineFichier } from "@noortrace/ancrage/registre";
import { NoeudFactice, validateursEssai } from "../ancrage-registre/noeud-factice.mjs";
import { chaineRegtest } from "../ancrage-ots/outils.mjs";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const SPEC = path.join(RACINE, "spec");
export const CT1 = path.join(SPEC, "vecteurs", "ct-1");
export const CT4 = path.join(SPEC, "vecteurs", "ct-4");
export const CT5 = path.join(SPEC, "vecteurs", "ct-5");
export const CT6 = path.join(SPEC, "vecteurs", "ct-6");

export const lireJson = (p) => JSON.parse(fs.readFileSync(p, "utf8"));
export const texte = (p) => fs.readFileSync(p, "utf8");
export const repertoireTemporaire = (prefixe = "noortrace-ancrage-f1-") => fs.mkdtempSync(path.join(os.tmpdir(), prefixe));

/** Clés de test publiées de CT-1 (graines documentées, sans valeur). */
export const CLES_TEST = lireJson(path.join(CT1, "cles", "cles-test.json"));
export const CLES_JSON = lireJson(path.join(CT1, "cles", "cles.json"));
export const CONSTANTES_CT4 = lireJson(path.join(CT4, "constantes.json"));
export const ORG = CLES_JSON.org_id;
export const JOURNAL = CLES_JSON.journal_id;
export const AC_TEST_PEM = texte(path.join(CT6, "rfc3161", "cles", "ac-test.pem"));
export const POLITIQUE_TEST = "1.3.6.1.4.1.99999.1.1";

/** Marque l'essai courant en attente avec sa condition dans le titre. */
export function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}

/** Aléa déterministe des essais (jamais une source de production). */
export function aleatoireFixe(graine = 11) {
  let x = graine >>> 0;
  return (n) => {
    const u = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      x = (Math.imul(x, 1103515245) + 12345) >>> 0;
      u[i] = (x >>> 16) & 0xff;
    }
    return u;
  };
}

// ------------------------------------------------------------- horloge

/**
 * Horloge réglable : murale et monotone avancent ensemble ; `programmer`
 * garde les minuteries, `avancer(ms, calme)` les déclenche dans l'ordre de
 * leurs échéances (l'horloge est placée à chaque échéance avant l'appel), en
 * attendant le calme du composant entre deux.
 */
export class HorlogeReglable {
  constructor(debutMs) {
    this.m = debutMs;
    this.mono = 1_000_000;
    this.minuteries = [];
    this.seq = 0;
    this.ecartMs = 0;
  }

  murale() {
    return this.m;
  }

  monotone() {
    return this.mono;
  }

  programmer(delaiMs, fn) {
    const t = { due: this.m + Math.max(0, delaiMs), fn, seq: this.seq++, actif: true };
    this.minuteries.push(t);
    return () => {
      t.actif = false;
    };
  }

  #prochaine(cible) {
    let meilleure = null;
    for (const t of this.minuteries) {
      if (!t.actif || t.due > cible) continue;
      if (!meilleure || t.due < meilleure.due || (t.due === meilleure.due && t.seq < meilleure.seq)) meilleure = t;
    }
    return meilleure;
  }

  /** Avance de `ms` ; `calme` est attendu après chaque minuterie déclenchée et à la fin. */
  async avancer(ms, calme = null) {
    const cible = this.m + ms;
    for (;;) {
      const t = this.#prochaine(cible);
      if (!t) break;
      this.minuteries = this.minuteries.filter((x) => x !== t && x.actif);
      const delta = Math.max(0, t.due - this.m);
      this.m = t.due;
      this.mono += delta;
      t.fn();
      if (calme) await calme();
    }
    const d = Math.max(0, cible - this.m);
    this.m = cible;
    this.mono += d;
    if (calme) await calme();
  }

  async aller(instantMs, calme = null) {
    await this.avancer(Math.max(0, instantMs - this.m), calme);
  }
}

/**
 * Horloge hybride (réseau de développement) : le temps mural simulé avance
 * avec le temps réel, `programmer` arme une minuterie réelle, et `avancer`
 * saute en avant en déclenchant aussitôt les minuteries échues.
 */
export class HorlogeHybride {
  constructor(debutMs) {
    this.base = debutMs;
    this.depart = Date.now();
    this.decalage = 0;
    /** Décalage de la seule horloge murale (recul ou saut simulé, CT-2 EX-7.9, EX-7.13) ; la monotone n'en sait rien. */
    this.decalageMurale = 0;
    this.minuteries = new Set();
    this.ecartMs = 0;
  }

  murale() {
    return this.base + this.decalage + this.decalageMurale + (Date.now() - this.depart);
  }

  /** Déplace la seule horloge murale de `ms` (négatif : recul), sans toucher aux minuteries ni à la monotone. */
  decalerMurale(ms) {
    this.decalageMurale += ms;
  }

  monotone() {
    return this.decalage + (Date.now() - this.depart);
  }

  programmer(delaiMs, fn) {
    const t = { due: this.murale() + Math.max(0, delaiMs), fn, actif: true, reel: null };
    t.reel = setTimeout(() => {
      if (!t.actif) return;
      t.actif = false;
      this.minuteries.delete(t);
      fn();
    }, Math.max(0, delaiMs));
    this.minuteries.add(t);
    return () => {
      t.actif = false;
      clearTimeout(t.reel);
      this.minuteries.delete(t);
    };
  }

  async avancer(ms, calme = null) {
    this.decalage += ms;
    for (;;) {
      const echues = [...this.minuteries].filter((t) => t.actif && t.due <= this.murale()).sort((a, b) => a.due - b.due);
      if (!echues.length) break;
      for (const t of echues) {
        // Une minuterie réelle a pu se déclencher pendant l'attente du calme : elle n'est jamais servie deux fois.
        if (!t.actif) continue;
        t.actif = false;
        clearTimeout(t.reel);
        this.minuteries.delete(t);
        t.fn();
        if (calme) await calme();
      }
    }
    if (calme) await calme();
  }

  async aller(instantMs, calme = null) {
    await this.avancer(Math.max(0, instantMs - this.murale()), calme);
  }
}

/** Attend que le composant n'ait plus d'action en vol hors des attentes d'horloge (deux lectures stables). */
export function attenteCalme(composant, { pasMs = 4, maxMs = 20000, tolerance = () => 0, attentesReelles = false } = {}) {
  return async () => {
    const debut = Date.now();
    let stables = 0;
    for (;;) {
      await new Promise((r) => setTimeout(r, pasMs));
      const e = composant.etat();
      // Horloge réglable : une action qui attend une minuterie ne progresse plus tant que l'essai n'avance pas l'horloge ;
      // horloge hybride (`attentesReelles`) : ses attentes se résolvent seules, le calme est l'absence d'action en vol.
      const bloquees = attentesReelles ? 0 : e.attentes_horloge;
      if (e.en_vol - bloquees - tolerance() <= 0) stables += 1;
      else stables = 0;
      if (stables >= 2) return;
      if (Date.now() - debut > maxMs) throw new Error(`le composant n'atteint pas le calme en ${maxMs} ms (en vol ${e.en_vol}, attentes ${e.attentes_horloge})`);
    }
  };
}

// ----------------------------------------------------------- TLS, CRL

/** AC, serveur (127.0.0.1) et client TLS d'essai, par `openssl` ; null si openssl manque. */
export function materielTls(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const o = (args) => execFileSync("openssl", args, { cwd: dir, stdio: "pipe" });
    o(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=AC TLS d'essai noortrace"]);
    o(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "serveur.key", "-out", "serveur.csr", "-subj", "/CN=127.0.0.1"]);
    fs.writeFileSync(path.join(dir, "ext-serveur.cnf"), "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n");
    o(["x509", "-req", "-in", "serveur.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "serveur.pem", "-days", "2", "-extfile", "ext-serveur.cnf"]);
    o(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "client.key", "-out", "client.csr", "-subj", "/CN=enregistreur d'essai"]);
    fs.writeFileSync(path.join(dir, "ext-client.cnf"), "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n");
    o(["x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "client.pem", "-days", "2", "-extfile", "ext-client.cnf"]);
    const lire = (n) => fs.readFileSync(path.join(dir, n));
    return { ca: lire("ca.pem"), serveur: { cle: lire("serveur.key"), certificat: lire("serveur.pem") }, client: new Uint8Array(Buffer.concat([lire("client.key"), lire("client.pem")])) };
  } catch {
    return null;
  }
}

/**
 * Serveur HTTP local de CRL : `GET /<nom>/crl.pem` republie la CRL de
 * l'autorité `nom` à l'instant de l'horloge (thisUpdate courant), avec les
 * révocations déclarées par `revoquer(nom, { serie, date, raison })`.
 */
export async function serveurCrl(horloge) {
  const autorites = new Map(); // nom → { repertoire, revoques: [] }
  const requetes = [];
  const serveur = http.createServer((req, rep) => {
    const m = /^\/([a-z0-9-]+)\/crl\.pem$/.exec(req.url ?? "");
    const a = m ? autorites.get(m[1]) : null;
    requetes.push(req.url);
    if (!a) {
      rep.writeHead(404);
      rep.end();
      return;
    }
    try {
      const r = publierCrl({ repertoire: a.repertoire, horloge: { murale: () => horloge.murale() }, revoques: a.revoques });
      rep.writeHead(200, { "content-type": "application/pkix-crl" });
      rep.end(Buffer.from(r.octets));
    } catch (e) {
      rep.writeHead(500);
      rep.end(String(e.message));
    }
  });
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  const port = serveur.address().port;
  return {
    port,
    requetes,
    url: (nom) => `http://127.0.0.1:${port}/${nom}/crl.pem`,
    declarer: (nom, repertoire) => autorites.set(nom, { repertoire, revoques: [] }),
    revoquer: (nom, entree) => autorites.get(nom).revoques.push(entree),
    fermer: () => new Promise((r) => {
      serveur.closeAllConnections?.();
      serveur.close(() => r());
    }),
  };
}

/**
 * Autorité RFC 3161 du lot E et son serveur : `initialiserAutorite`
 * (algorithme `p-256` par défaut, politique privée, CRL publiée au serveur de
 * CRL), puis `demarrerServeur` en HTTP local ou en TLS avec authentification
 * du client. Rend le prestataire `ancrage-v0` correspondant (secret par
 * emplacement) et les octets de l'autorité.
 */
export async function autoriteInterne({ nom, dir, role, horloge, aleatoire, crl, tls = null, algorithme = "p-256", politique = "1.3.6.1.4.1.99999.2.1", qualified = null, validiteJours = 365, journal = null, debutCertificatMs = null }) {
  const repertoire = path.join(dir, nom);
  crl.declarer(nom, repertoire);
  const debut = debutCertificatMs ?? horloge.murale() - 86400000;
  const init = initialiserAutorite({ repertoire, algorithme, politique, crlUrl: crl.url(nom), validiteJours, horloge: { murale: () => debut }, aleatoire, sujetUnite: { O: "NOORTRACE essai", CN: `TSA ${nom} non qualifiee` } });
  const autorite = chargerAutorite({ repertoire, compteur: new CompteurMemoire(1n) });
  const ecoute = tls ? { tls: { cle: tls.serveur.cle, certificat: tls.serveur.certificat, acClients: tls.ca, hote: "127.0.0.1", port: 0 } } : { hote: "127.0.0.1", port: 0 };
  const serveur = await demarrerServeur({ autorite, ecoute, horloge, journal: journal ?? { consigner() {} } });
  const unite = autorite.certificat;
  const serieUnite = BigInt("0x" + Buffer.from(unite.serie.subarray(2)).toString("hex"));
  const prestataire = {
    id: nom,
    role,
    url: serveur.adresse.url,
    auth: tls ? { method: "certificat_client", secret: { file: `/run/secrets/${nom}-client.pem` } } : { method: "aucune", secret: null },
    hash: "sha256",
    policy_oid: politique,
    accepted_policies: [politique],
    anchor_certificates: [init.acPem],
    qualified,
    min_interval_ms: 0,
    request_timeout_ms: 5000,
    correlation_header: "X-Request-ID",
    source: `autorité d'essai ${nom} (lot E, initialiserAutorite ${algorithme}), sans valeur hors des tests`,
  };
  return { nom, repertoire, init, autorite, serveur, prestataire, serieUnite, fermer: () => serveur.fermer() };
}

/** Objet `qualified` d'exemple (EX-4.8), déclaratif, profil `test` seulement. */
export function qualifiedExemple(territoire = "AT") {
  return {
    framework: "eidas",
    service_type: "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST",
    status: "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    trusted_list: { territory: territoire, sequence_number: 75, issue_date: "2026-06-15T14:44:12.000Z", url: "https://www.signatur.rtr.at/vertrauensliste.xml" },
    source: "exemple d'EX-4.8 : instantané déclaratif pour l'essai, sans valeur",
  };
}

// --------------------------------------------------- calendriers factices

/** Chemin Bitcoin synthétique d'un engagement : f1, 08, f0, 08, 08, attestation Bitcoin à `hauteur` (même forme que les essais du lot B). */
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
 * Deux calendriers factices sur 127.0.0.1 joués sous des URI `https://…example`
 * (le transport injecté réécrit l'hôte) : `POST /digest` rend une promesse
 * nue (attestation en attente de l'URI), `GET /timestamp/<e>` rend 404
 * « Pending confirmation » tant que `completer(hauteur)` n'a pas été appelé,
 * puis un chemin Bitcoin à cette hauteur ; la racine de l'en-tête à cette
 * hauteur est posée dans le fichier d'en-têtes regtest `fichierEntetes`
 * avant la réponse, pour que O-4 et O-5 passent (EX-6.9).
 */
export async function calendriersFactices({ fichierEntetes, nombreEnTetes = 1040, muets = false }) {
  const uris = ["https://alice.calendrier.example", "https://bob.calendrier.example"];
  const racines = new Map();
  const etat = { hauteur: null, muets, panne: false, requetes: [] };
  const serveurs = new Map();
  const ecrireChaine = () => {
    const { document } = chaineRegtest({ debut: 0, nombre: nombreEnTetes, racines });
    fs.writeFileSync(fichierEntetes, JSON.stringify(document, null, 2) + "\n");
  };
  ecrireChaine();
  for (const uri of uris) {
    const serveur = http.createServer((req, rep) => {
      const morceaux = [];
      req.on("data", (d) => morceaux.push(d));
      req.on("end", () => {
        const corps = Buffer.concat(morceaux);
        etat.requetes.push({ uri, methode: req.method, url: req.url, corps: new Uint8Array(corps) });
        if (etat.panne) {
          rep.writeHead(503, { "content-type": "text/plain" });
          rep.end("indisponible");
          return;
        }
        if (etat.muets) return; // délai
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
    serveurs.set(uri, serveur);
  }
  const correspondance = new Map([...serveurs].map(([uri, s]) => [new URL(uri).host, `127.0.0.1:${s.address().port}`]));
  const fetchLocal = (url, init) => {
    const u = new URL(url);
    const cible = correspondance.get(u.host);
    if (!cible) return Promise.reject(new TypeError(`hôte inconnu ${u.host}`));
    return fetch(`http://${cible}${u.pathname}${u.search}`, init);
  };
  return {
    uris,
    etat,
    racines,
    transport: transportOts({ fetch: fetchLocal }),
    completer: (hauteur) => {
      etat.hauteur = hauteur;
    },
    fermer: () => Promise.all([...serveurs.values()].map((s) => new Promise((r) => {
      s.closeAllConnections?.();
      s.close(() => r());
    }))),
  };
}

// -------------------------------------------------- série synthétique

/**
 * Série de points d'une période à la cadence `cK` (un point par instant
 * aligné, puis la clôture à `generated_at`), signée par la clé de test
 * `keyId` de CT-1, avec des événements synthétiques aux minutes données
 * (`evenementsAuxMinutes` : minute → nombre d'événements nouveaux). Rend les
 * points, les hash des événements, le manifeste signé et la signature.
 */
export function serieSynthetique({ periodStart, cK = 60, keyId = "rec-test-01", evenementsAuxMinutes, evenementsCloture = 0, generatedAtMs = null, nonce = null, graine: graineDonnee = null, orgId = ORG, journalId = JOURNAL, firstSeq = 1, prevPeriodHash = N.ZERO32, lastHashAvant = N.ZERO32, sel = "" }) {
  const cle = CLES_TEST.keys.find((k) => k.key_id === keyId) ?? null;
  const graine = graineDonnee ?? N.hexVersOctets(cle.seed, 32);
  const clePublique = cle ? N.hexVersOctets(cle.public_key, 32) : N.clePubliqueEd25519(graine);
  const hashes = [];
  const points = [];
  let prev = N.ZERO32;
  let n = 0;
  for (let j = 0; j * cK < 3600; j++) {
    const minute = (j * cK) / 60;
    const nouveaux = evenementsAuxMinutes[minute] ?? 0;
    for (let k = 0; k < nouveaux; k++) hashes.push(N.sha256Hex(N.utf8(`noortrace/ancrage/test/evenement/${periodStart}/${sel}${hashes.length + 1}`)));
    n = hashes.length;
    const corps = {
      version: 0, org_id: orgId, journal_id: journalId, period_start: periodStart, tree_size: n, root: N.racineMerkle(hashes.slice(0, n)),
      last_seq: n === 0 ? firstSeq - 1 : firstSeq + n - 1, last_hash: n === 0 ? lastHashAvant : hashes[n - 1], checkpoint_ts: N.ecrireHorodatage((periodStart + j * cK) * 1000), prev_checkpoint_hash: prev, key_id: keyId,
    };
    const point = N.signerPoint(corps, graine);
    points.push(point);
    prev = N.hacherPoint(point);
  }
  for (let k = 0; k < evenementsCloture; k++) hashes.push(N.sha256Hex(N.utf8(`noortrace/ancrage/test/evenement/${periodStart}/${sel}${hashes.length + 1}`)));
  const generatedAt = generatedAtMs ?? (periodStart + 3600) * 1000 + 250;
  const manifeste = N.construireManifeste({
    org_id: orgId, journal_id: journalId, period_start: periodStart, first_seq: firstSeq, hashes, prev_period_hash: prevPeriodHash, recorder_key_id: keyId,
    nonce: nonce ?? N.sha256Hex(N.utf8(`noortrace/ancrage/test/nonce/${periodStart}/${sel}`)), generated_at: N.ecrireHorodatage(generatedAt),
  });
  const signature = N.signerManifeste(manifeste, graine);
  const cloture = N.signerPoint({
    version: 0, org_id: orgId, journal_id: journalId, period_start: periodStart, tree_size: hashes.length, root: manifeste.root, last_seq: hashes.length === 0 ? firstSeq - 1 : firstSeq + hashes.length - 1,
    last_hash: hashes.length ? hashes[hashes.length - 1] : lastHashAvant, checkpoint_ts: manifeste.generated_at, prev_checkpoint_hash: prev, key_id: keyId,
  }, graine);
  points.push(cloture);
  return { points, hashes, manifeste, signature, periodHash: N.hacherManifeste(manifeste), clePublique };
}

/** Remise d'un point (forme de l'enregistreur, rubrique g). */
export function remisePoint(point) {
  const checkpointHash = N.hacherPoint(point);
  return { point, checkpointHash, fingerprint: N.empreinteAncre(point.org_id, point.journal_id, checkpointHash), chemin: `points/periode-${String(point.period_start).padStart(10, "0")}.ndjson` };
}

/** Remise d'une clôture (forme de l'enregistreur, rubrique g). */
export function remiseCloture(serie) {
  const { manifeste, signature, periodHash } = serie;
  return {
    manifeste, signature, periodHash, fingerprint: N.empreinteAncre(manifeste.org_id, manifeste.journal_id, periodHash), periodMeta: N.periodMeta(manifeste),
    cheminManifeste: "manifestes/periode.json", cheminSignature: "manifestes/periode.sig", cheminSerie: "points/periode.ndjson",
  };
}

// --------------------------------------------------------- registre

/** Nœud noorcore factice du lot D, client JSON-RPC, clé de chaîne inscrite pour la clé Ed25519 donnée, approbateurs de test. */
export function registreFactice({ clePublique, tiers = false } = {}) {
  const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
  const contrats = {
    attestation_registry: CONSTANTES_CT4.contracts.attestation_registry,
    period_registry: CONSTANTES_CT4.contracts.period_registry,
    recorder_registry: CONSTANTES_CT4.contracts.recorder_registry,
  };
  const validateurs = validateursEssai(CONSTANTES_CT4);
  const noeud = new NoeudFactice({ validateurs, points: POINTS, contrats });
  const rpc = new ClientRpc({ points: POINTS, transport: noeud.transport(), identifiants: Object.fromEntries(POINTS.map((p, k) => [p, `v${k + 1}`])) });
  const cleChaine = new SignataireChaineFichier(N.sha256(N.utf8("noortrace/ancrage/test/composant/cle-chaine-01")));
  noeud.approvisionner(cleChaine.adresse(), 4719000000n);
  noeud.inscrire({ orgId: ORG, chainKey: cleChaine.adresse(), ed25519PubKey: N.octetsVersHex(clePublique), journalId: JOURNAL });
  const approbateurs = [1, 2, 3].map((k) => new SignataireChaineFichier(N.hexVersOctets(CONSTANTES_CT4.accounts[k].private_key)));
  let cleTiers = null;
  if (tiers) {
    cleTiers = new SignataireChaineFichier(N.hexVersOctets(CONSTANTES_CT4.accounts[0].private_key));
    noeud.approvisionner(cleTiers.adresse(), 4719000000n);
  }
  const instance = { evmChainId: 2124, bftChainId: "noortrace-2124-dev", contrats, fees: { gas_limit: 3000000, gas_limit_max: 16777216 }, jeux: { validators: validateurs.validators, source: "jeu d'essai de CT-4 annexe A.2" } };
  return { noeud, rpc, points: POINTS, contrats, cleChaine, cleTiers, approbateurs, instance, membres: approbateurs.map((a) => a.adresse()), seuil: 2 };
}

/** Signatures de clôture (CT-4 §8.2, pas 4) des approbateurs d'essai, rangées par adresse (RG-13). */
export function signaturesClotureEssai(registre, R) {
  return async (periodMeta) => {
    const condense = R.periodDigest(registre.instance.evmChainId, registre.contrats.period_registry, periodMeta);
    const hachage = R.hachageSigne(condense);
    const signatures = registre.approbateurs.slice(0, registre.seuil).map((a) => ({ signer: a.adresse(), ...a.signerCondense(hachage) })).sort((x, y) => (x.signer < y.signer ? -1 : 1));
    return { signatures, membres: registre.membres, seuil: registre.seuil };
  };
}

// ------------------------------------------------------- configuration

/** Document `ancrage-v0` d'essai : prestataires donnés, calendriers factices, file et dépôt sous `dir`. */
export function configurationEssai({ prestataires, dir, calendriers, fichierEntetes, surcharges = {} }) {
  const base = {
    version: 0,
    checkpoint_interval_s: 60,
    rfc3161: {
      providers: prestataires,
      manifest: { fallback_after_s: 300 },
      checkpoints: { interval_s: 300, provider_role: "interne", fallback_after_s: 120, countersign_idle: false },
      freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
      retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 },
      retention_years: 10,
      crl_capture: { enabled: true, delay_s: 600 },
    },
    registry: { checkpoints: "nouveaux_evenements", squat_wait_s: 5, inclusion_alert_s: 60 },
    opentimestamps: {
      enabled: true,
      calendars: calendriers.uris,
      min_responses: 2,
      timeout_ms: 5000,
      checkpoint: "mi_periode",
      upgrade: { whitelist: calendriers.uris, first_after_s: 600, interval_s: 60, give_up_after_s: 3600 },
      headers_source: fichierEntetes ? { type: "fichier", network: "regtest", path: fichierEntetes } : null,
    },
    queue: { path: path.join(dir, "file"), max_pending: 100, anchor_pending_alert_s: 7200 },
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

/** Journal d'exploitation en mémoire (forme de CT-2 §17.3). */
export function journalMemoire() {
  const lignes = [];
  return {
    lignes,
    consigner(niveau, composant, evenement, data = {}) {
      lignes.push({ level: niveau, component: composant, event: evenement, data });
    },
    evenements: () => lignes.map((l) => l.event),
    de: (evenement) => lignes.filter((l) => l.event === evenement),
  };
}

/** Transport RFC 3161 du lot A pour les serveurs locaux (AC TLS d'essai). */
export function transportRfc3161Local(tls) {
  return transportRfc3161(tls ? { ca: tls.ca } : {});
}

export { lireTimestamp };

// ------------------------------------------------------------ montage

/**
 * Transport RFC 3161 commutable des essais de pannes : une URL de
 * `pannes` lève une erreur de connexion (EX-5.12 : transitoire), une URL de
 * `pendantes` ne répond jamais (arrêt brutal entre l'écriture et l'envoi),
 * les autres passent au transport du lot A ; `requetes` garde ce qui est parti.
 */
export function transportCommutable(base, ErreurTransport) {
  const pannes = new Set();
  const pendantes = new Set();
  const requetes = [];
  const etat = { pendantesEnVol: 0 };
  return {
    pannes,
    pendantes,
    requetes,
    etat,
    async envoyer(req) {
      if (pannes.has(req.url)) throw new ErreurTransport("connexion", "connexion refusée (essai)");
      if (pendantes.has(req.url)) {
        etat.pendantesEnVol += 1;
        return new Promise(() => {});
      }
      requetes.push({ url: req.url, octets: req.octets });
      return base.envoyer(req);
    },
    obtenir: (url, delaiMs) => base.obtenir(url, delaiMs),
  };
}

/**
 * Monte un composant complet : horloge réglable, serveur de CRL, trois
 * autorités du lot E (interne en HTTP ; principal et secours en TLS mutuel
 * avec `qualified` d'exemple), calendriers factices, série synthétique,
 * registre factice, configuration d'essai. `creer({ epoque, clients })`
 * construit un composant sur ce contexte (un second pour un redémarrage).
 */
export async function monterComposant({ dir, periodStart, evenements, evenementsCloture = 0, surcharges = {}, graineAlea = 5, transportRfc3161: transportDonne = null, calendriersOptions = {}, registreOptions = {}, contexteSurcharges = {}, ErreurTransport = null }) {
  const tls = materielTls(path.join(dir, "tls"));
  if (!tls) return { condition: "openssl indisponible pour le matériel TLS" };
  const horloge = new HorlogeReglable(periodStart * 1000);
  const aleatoire = aleatoireFixe(graineAlea);
  const crl = await serveurCrl(horloge);
  const interne = await autoriteInterne({ nom: "tsa-interne", dir, role: "interne", horloge, aleatoire, crl, politique: "1.3.6.1.4.1.99999.2.1" });
  const principal = await autoriteInterne({ nom: "qtsa-principal", dir, role: "principal", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("AT"), politique: "1.3.6.1.4.1.99999.3.1" });
  const secours = await autoriteInterne({ nom: "qtsa-secours", dir, role: "secours", horloge, aleatoire, crl, tls, qualified: qualifiedExemple("PL"), politique: "1.3.6.1.4.1.99999.3.2" });
  const fichierEntetes = path.join(dir, "entetes-regtest.json");
  const calendriers = await calendriersFactices({ fichierEntetes, ...calendriersOptions });
  const serie = serieSynthetique({ periodStart, evenementsAuxMinutes: evenements, evenementsCloture });
  const registre = registreFactice({ clePublique: serie.clePublique, ...registreOptions });
  const configuration = configurationEssai({ prestataires: [principal.prestataire, secours.prestataire, interne.prestataire], dir, calendriers, fichierEntetes, surcharges });
  const secrets = new Map([["/rfc3161/providers/0/auth/secret", tls.client], ["/rfc3161/providers/1/auth/secret", tls.client]]);
  const transportBase = transportRfc3161Local(tls);
  const transport = transportDonne ?? (ErreurTransport ? transportCommutable(transportBase, ErreurTransport) : transportBase);
  const remis = [];
  const journal = journalMemoire();
  const Rmod = await import("@noortrace/ancrage/registre");
  const contexte = {
    org_id: ORG,
    journal_id: JOURNAL,
    epoque: 1,
    racineStockage: path.join(dir, "stockage"),
    secrets,
    cles: CLES_JSON,
    clePublique: (keyId) => (keyId === "rec-test-01" ? serie.clePublique : null),
    lireSerie: async () => remis.slice(),
    lireHashesPeriode: async (P) => (P === periodStart ? serie.hashes : null),
    listerPeriodes: async () => [],
    listerPoints: async () => [],
    cleChaine: registre.cleChaine,
    signaturesCloture: signaturesClotureEssai(registre, Rmod),
    ...contexteSurcharges,
  };
  const { creerComposantAncrage } = await import("../../../paquets/ancrage/src/composant.mjs");
  const creer = ({ epoque = 1, clients = {}, configuration: conf = configuration, profil = "test", journal: j = journal, options = {} } = {}) => creerComposantAncrage({
    configuration: conf,
    profil,
    checkpointIntervalEnregistreur: 60,
    contexte: { ...contexte, epoque },
    horloge,
    aleatoire,
    journal: j,
    clients: {
      rfc3161: { transport },
      ots: { transport: calendriers.transport },
      registre: { rpc: registre.rpc, instance: registre.instance, repertoireEnvois: path.join(dir, "captures"), delais: { recuMs: 60000, sondageMs: 500 } },
      ...clients,
    },
    options,
  });
  return {
    tls, horloge, aleatoire, crl, interne, principal, secours, calendriers, serie, registre, configuration, secrets, transport, remis, journal, contexte, creer,
    fermer: async () => {
      await Promise.all([interne.fermer(), principal.fermer(), secours.fermer(), calendriers.fermer(), crl.fermer()]);
    },
  };
}
