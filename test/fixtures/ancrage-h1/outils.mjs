// Outils des essais de non-régression du lot H1 (corrections du composant
// d'ancrage après la relecture adversariale de l'étape 5) : montage léger du
// composant dont le transport RFC 3161 est l'autorité du lot E tenue en
// mémoire (clé et certificat de test publiés de CT-6, politique de test),
// avec un crochet qui altère ou retarde chaque réponse ; horloge réglable,
// série synthétique et journal en mémoire des outils du lot F1 ; mutateur
// déterministe d'octets et de JSON pour les rejeux hostiles. Tout fichier va
// sous `os.tmpdir()`.

import fs from "node:fs";
import path from "node:path";
import { Autorite, CompteurMemoire, repondre } from "@noortrace/ancrage/serveur-interne";
import { creerComposantAncrage } from "../../../paquets/ancrage/src/composant.mjs";
import { lireFiles } from "@noortrace/ancrage/planificateur";
import * as F from "../ancrage-composant/outils.mjs";
import { AUTORITE_TEST, POLITIQUE_TEST } from "../ancrage-tsa-interne/outils.mjs";

export { F };
export const AC_TEST_PEM = F.AC_TEST_PEM;
export const POLITIQUE = POLITIQUE_TEST;
export const PERIODE = 1793862000; // 2026-11-05T07:00:00Z, dans la validité de rec-test-01 et de l'unité de test de CT-6

/** Autorité RFC 3161 du lot E en mémoire : unité de test de CT-6, compteur en mémoire. */
export function autoriteTest(serie = 1n) {
  return new Autorite({ clePrivee: fs.readFileSync(AUTORITE_TEST.cleUnite), certificat: fs.readFileSync(AUTORITE_TEST.unite), politique: POLITIQUE, compteur: new CompteurMemoire(serie) });
}

/** Prestataire `ancrage-v0` d'essai sur l'autorité de test (AC de test pour ancre). */
export function prestataire(id, role, surcharges = {}) {
  const base = {
    id,
    role,
    url: role === "interne" ? "http://127.0.0.1:2020/" : `https://${id}.example/tsa`,
    auth: role === "interne" ? { method: "aucune", secret: null } : { method: "basic", secret: { env: "NOORTRACE_H1_SECRET" } },
    hash: "sha256",
    policy_oid: null,
    accepted_policies: [POLITIQUE],
    anchor_certificates: [AC_TEST_PEM],
    qualified: role === "interne" || role === "second_rang" ? null : F.qualifiedExemple(role === "principal" ? "AT" : "PL"),
    min_interval_ms: 0,
    request_timeout_ms: 10000,
    correlation_header: "X-Request-ID",
    source: "autorité de test des vecteurs CT-6 (lot E en mémoire), sans valeur hors des tests",
  };
  return { ...base, ...surcharges };
}

/** Document `ancrage-v0` d'essai : trois prestataires (principal, secours, interne), registre et OpenTimestamps désactivés par défaut. */
export function configuration(dir, { prestataires = null, role = "interne", registry = "aucun", surcharges = {} } = {}) {
  const base = {
    version: 0,
    checkpoint_interval_s: 60,
    rfc3161: {
      providers: prestataires ?? [prestataire("qtsa-principal", "principal"), prestataire("qtsa-secours", "secours"), prestataire("tsa-interne", "interne")],
      manifest: { fallback_after_s: 300 },
      checkpoints: { interval_s: 300, provider_role: role, fallback_after_s: 120, countersign_idle: false },
      freshness: { max_response_delay_s: 60, clock_tolerance_s: 120 },
      retry: { initial_ms: 5000, factor: 2, max_ms: 300000, jitter_ms: 250 },
      retention_years: 10,
      crl_capture: { enabled: false, delay_s: 600 },
    },
    registry: { checkpoints: registry, squat_wait_s: 5, inclusion_alert_s: 60 },
    opentimestamps: {
      enabled: false,
      calendars: ["https://alice.calendrier.example", "https://bob.calendrier.example"],
      min_responses: 2,
      timeout_ms: 5000,
      checkpoint: "aucun",
      upgrade: { whitelist: ["https://alice.calendrier.example", "https://bob.calendrier.example"], first_after_s: 600, interval_s: 60, give_up_after_s: 3600 },
      headers_source: null,
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

/**
 * Transport RFC 3161 injectable : l'autorité répond en mémoire ; `crochet(req,
 * reponse, n)` (facultatif, asynchrone) peut rendre une autre réponse ou
 * retarder. `appels` garde les requêtes parties.
 */
export function transportTsa(autorite, horloge, crochet = null) {
  const appels = [];
  return {
    appels,
    async envoyer(req) {
      appels.push(req);
      const r = autorite ? repondre({ requete: req.octets, autorite, horloge: { murale: () => horloge.murale(), ecartMs: 0 } }) : null;
      let reponse = r
        ? { status: 200, entetes: { "content-type": "application/timestamp-reply" }, corps: r.octets, tronque: false }
        : { status: 503, entetes: {}, corps: new Uint8Array(0), tronque: false };
      if (crochet) reponse = (await crochet(req, reponse, appels.length)) ?? reponse;
      return reponse;
    },
    async obtenir() {
      return { status: 404, entetes: {}, corps: new Uint8Array(0) };
    },
  };
}

/**
 * Monte un composant léger : horloge réglable, série synthétique de la
 * période, autorité en mémoire, aucun registre (profil `developpement`).
 * `creer({ epoque, journal, clients, options })` construit un composant sur le
 * même contexte (un second pour un redémarrage). `debutMs` place l'horloge
 * (par défaut au début de la période ; à la fin pour un essai de clôture seule,
 * ce qui épargne les tics d'une heure).
 */
export async function monter({ dir, periodStart = PERIODE, debutMs = null, evenements = { 0: 1, 10: 1, 20: 1 }, evenementsCloture = 1, role = "interne", crochet = null, surcharges = {}, prestataires = null, contexteSurcharges = {}, clients = {}, epoque = 1, graine = 7, demarrer = true } = {}) {
  const horloge = new F.HorlogeReglable(debutMs ?? periodStart * 1000);
  const serie = F.serieSynthetique({ periodStart, evenementsAuxMinutes: evenements, evenementsCloture });
  const journal = F.journalMemoire();
  const autorite = autoriteTest();
  const transport = transportTsa(autorite, horloge, crochet);
  const conf = configuration(dir, { role, surcharges, prestataires });
  const remis = [];
  const contexte = {
    org_id: F.ORG,
    journal_id: F.JOURNAL,
    epoque,
    racineStockage: path.join(dir, "stockage"),
    secrets: new Map([["/rfc3161/providers/0/auth/secret", new TextEncoder().encode("u:p")], ["/rfc3161/providers/1/auth/secret", new TextEncoder().encode("u:p")]]),
    cles: F.CLES_JSON,
    clePublique: (k) => (k === "rec-test-01" ? serie.clePublique : null),
    lireSerie: async () => remis.slice(),
    lireHashesPeriode: async (P) => (P === periodStart ? serie.hashes : null),
    listerPeriodes: async () => [],
    listerPoints: async () => [],
    ...contexteSurcharges,
  };
  const creer = (o = {}) => creerComposantAncrage({
    configuration: o.configuration ?? conf,
    profil: "developpement",
    checkpointIntervalEnregistreur: 60,
    contexte: { ...contexte, epoque: o.epoque ?? epoque, ...(o.contexte ?? {}) },
    horloge,
    aleatoire: F.aleatoireFixe(graine),
    journal: o.journal ?? journal,
    clients: { rfc3161: { transport }, ...clients, ...(o.clients ?? {}) },
    options: o.options ?? {},
  });
  const composant = creer();
  if (demarrer) await composant.demarrer();
  const calme = F.attenteCalme(composant, { pasMs: 3, maxMs: 20000 });
  const repertoirePeriode = path.join(dir, "stockage", F.ORG.slice(2), F.JOURNAL.slice(2), "ancres", `periode-${String(periodStart).padStart(10, "0")}`);
  return {
    dir, horloge, serie, journal, transport, composant, calme, remis, creer, conf, contexte, periodStart, repertoirePeriode,
    remettrePoint: async (k) => {
      const p = serie.points[k];
      await horloge.aller(Math.max(horloge.murale(), Date.parse(p.checkpoint_ts)), calme);
      const r = await composant.remettrePoint(F.remisePoint(p));
      remis.push(p);
      await calme();
      return r;
    },
    remettreCloture: async (c = composant) => {
      await horloge.aller(Math.max(horloge.murale(), Date.parse(serie.manifeste.generated_at)), calme);
      return c.remettreCloture(F.remiseCloture(serie));
    },
    etatFile: () => lireFiles(path.join(dir, "file")),
    acquisitions: () => {
      const chemin = path.join(repertoirePeriode, "acquisitions.ndjson");
      return fs.existsSync(chemin) ? fs.readFileSync(chemin, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
    },
  };
}

// ------------------------------------------------------------ mutations

/** Générateur congruentiel déterministe (jamais une source de production). */
export function rng(graine = 1) {
  let x = graine >>> 0;
  return () => {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    return x / 4294967296;
  };
}

/** Mutation d'octets : bit, octet, insertion, suppression, troncature, ajout, longueur DER, zéros, duplication, forme longue. */
export function muterOctets(base, r) {
  const b = Uint8Array.from(base);
  const n = b.length;
  const s = Math.floor(r() * 10);
  const pos = () => Math.floor(r() * Math.max(1, n));
  switch (s) {
    case 0: { const p = pos(); b[p] ^= 1 << Math.floor(r() * 8); return { octets: b, s: "flip_bit", p }; }
    case 1: { const p = pos(); b[p] = Math.floor(r() * 256); return { octets: b, s: "octet_aleatoire", p }; }
    case 2: { const p = pos(); const o = new Uint8Array(n + 1); o.set(b.subarray(0, p)); o[p] = Math.floor(r() * 256); o.set(b.subarray(p), p + 1); return { octets: o, s: "insertion", p }; }
    case 3: { const p = pos(); const o = new Uint8Array(Math.max(0, n - 1)); o.set(b.subarray(0, p)); o.set(b.subarray(p + 1), p); return { octets: o, s: "suppression", p }; }
    case 4: { const k = Math.floor(r() * n); return { octets: b.subarray(0, k), s: "troncature", p: k }; }
    case 5: { const k = 1 + Math.floor(r() * 4); const o = new Uint8Array(n + k); o.set(b); for (let i = 0; i < k; i++) o[n + i] = Math.floor(r() * 256); return { octets: o, s: "ajout_fin", p: n }; }
    case 6: {
      const cands = [];
      for (let i = 0; i + 1 < n; i++) if ([0x30, 0x31, 0x04, 0x02, 0x03, 0x06, 0xa0, 0xa1, 0x0c, 0x13, 0x18, 0x7b, 0x22].includes(b[i])) cands.push(i + 1);
      if (!cands.length) { const p = pos(); b[p] ^= 1; return { octets: b, s: "flip_bit", p }; }
      const p = cands[Math.floor(r() * cands.length)];
      b[p] = (b[p] + (r() < 0.5 ? 1 : 255)) & 0xff;
      return { octets: b, s: "longueur", p };
    }
    case 7: { const p = pos(); const l = 1 + Math.floor(r() * 8); for (let i = p; i < Math.min(n, p + l); i++) b[i] = 0; return { octets: b, s: "zeros", p }; }
    case 8: { const p = pos(); const l = 1 + Math.floor(r() * 16); const o = new Uint8Array(n + l); o.set(b.subarray(0, p)); o.set(b.subarray(p, Math.min(n, p + l)), p); o.set(b.subarray(p), p + Math.min(n - p, l)); return { octets: o.subarray(0, n + Math.min(n - p, l)), s: "duplication", p }; }
    default: { const p = pos(); b[p] = 0x80 | (b[p] & 0x7f); return { octets: b, s: "forme_longue", p }; }
  }
}

/** Mutation d'une valeur JSON : suppression, type ou borne, décalage, hexadécimal altéré, clé en trop, signe, casse, échelle, doublon, nul, traversée. */
export function muterJson(base, r) {
  const v = structuredClone(base);
  const chemins = [];
  const parcourir = (o, chemin) => {
    if (o && typeof o === "object") for (const k of Object.keys(o)) { chemins.push([...chemin, k]); parcourir(o[k], [...chemin, k]); }
  };
  parcourir(v, []);
  if (!chemins.length) return { valeur: v, s: "rien", chemin: [] };
  const chemin = chemins[Math.floor(r() * chemins.length)];
  let parent = v;
  for (const k of chemin.slice(0, -1)) parent = parent[k];
  const k = chemin[chemin.length - 1];
  const ancien = parent[k];
  const s = Math.floor(r() * 12);
  const nouvelles = [null, 0, -1, 1e21, "", "x".repeat(2000), true, [], {}, 9007199254740992, "0x" + "g".repeat(64), 1.5];
  switch (s) {
    case 0: if (Array.isArray(parent)) parent.splice(Number(k), 1); else delete parent[k]; return { valeur: v, s: "suppression", chemin };
    case 1: parent[k] = nouvelles[Math.floor(r() * nouvelles.length)]; return { valeur: v, s: "type_ou_borne", chemin };
    case 2: if (typeof ancien === "number") parent[k] = ancien + (r() < 0.5 ? 1 : -1); else if (typeof ancien === "string" && ancien.length) parent[k] = ancien.slice(0, -1); else parent[k] = 0; return { valeur: v, s: "decalage", chemin };
    case 3: if (typeof ancien === "string" && /^0x[0-9a-f]+$/.test(ancien)) { const i = 2 + Math.floor(r() * (ancien.length - 2)); parent[k] = ancien.slice(0, i) + (ancien[i] === "0" ? "1" : "0") + ancien.slice(i + 1); } else parent[k] = String(ancien); return { valeur: v, s: "hex_altere", chemin };
    case 4: if (!Array.isArray(parent)) parent[`cle_inconnue_${Math.floor(r() * 1000)}`] = 1; return { valeur: v, s: "cle_en_trop", chemin };
    case 5: if (!Array.isArray(parent)) Object.defineProperty(parent, "__proto__", { value: { pollue: true }, enumerable: true, configurable: true, writable: true }); return { valeur: v, s: "proto", chemin };
    case 6: if (typeof ancien === "number") parent[k] = -ancien; else parent[k] = ancien === null ? 0 : null; return { valeur: v, s: "signe_ou_null", chemin };
    case 7: if (typeof ancien === "string") parent[k] = ancien.toUpperCase(); else parent[k] = [ancien]; return { valeur: v, s: "casse_ou_tableau", chemin };
    case 8: if (typeof ancien === "number") parent[k] = ancien * 1000; else parent[k] = typeof ancien === "string" ? ancien + ancien : [ancien, ancien]; return { valeur: v, s: "echelle", chemin };
    case 9: if (Array.isArray(ancien) && ancien.length) ancien.push(ancien[0]); else parent[k] = `\u0000${String(ancien)}`; return { valeur: v, s: "doublon_ou_nul", chemin };
    case 10: if (typeof ancien === "string") parent[k] = `${ancien} `; else parent[k] = String(ancien); return { valeur: v, s: "espace_ou_chaine", chemin };
    default: if (typeof ancien === "number") parent[k] = Number.MAX_SAFE_INTEGER; else parent[k] = `../../${String(ancien)}`; return { valeur: v, s: "max_ou_traversee", chemin };
  }
}
