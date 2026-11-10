// CT-2 §14.2, lignes « Mémoire » et « Disque presque plein », éprouvées sur
// le chemin du relais : bornes de la file d'attente d'EX-14.9
// (`policy.failure.pending_max_events`, `limits.pending_max_bytes`,
// `policy.failure.pending_max_ms`) pour une lecture passante du frontal MCP
// (colonne L) et pour un échange de modèle passant (`failure.modele:
// "passant"`, colonne M), puis sortie du mode dégradé et scellement de la
// file (EX-14.10) ; `storage.min_free_bytes` au-dessus de l'espace libre du
// volume (colonnes E, L, M « comme le stockage indisponible », ligne
// `disk_low`), puis retour au régime normal sur un nouveau cœur.
// Cœur réel en cours de processus (stockage sous os.tmpdir()), horloge
// injectée (HorlogeReglable), serveur d'outils stdio factice, fournisseur de
// modèle simulé sur 127.0.0.1. Le stockage indisponible est monté comme à la
// ligne « Stockage indisponible » des essais du frontal modèle (écriture des
// pièces en erreur), le segment courant étant fermé comme après toute panne
// de stockage (EX-12.8), pour que la sortie suive EX-14.11 au tic.

import { expect } from "chai";
import fs from "node:fs";
import * as N from "@noortrace/noyau";
import { Coeur, HorlogeReglable, FrontalMcp, PasserelleModele, validerConfiguration, lireEvenements, ErreurEnregistreur, octetsLibres } from "@noortrace/enregistreur";
import { repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, serveurStdio, ServiceFixe, AUTORISE, EnfantFactice } from "./fixtures/enregistreur-mcp/outils.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule } from "./fixtures/enregistreur-modele/fournisseur.mjs";
import { demarrerDemonSdk } from "./fixtures/enregistreur-sdk/outils.mjs";

const META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const OUTILS = [
  { name: "claims.get", description: "Lire", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
  { name: "payments.create", description: "Ecrire", inputSchema: { type: "object" }, annotations: { readOnlyHint: false } },
];
const DEBUT = N.decoderHorodatage("2026-11-10T10:20:00.000Z");
/** Cadence du contrôle « disque presque plein » (14.2 : « toutes les 10 s »), ms. */
const CONTROLE_DISQUE_MS = 10000;
const appel = (id, nom, args) => JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: nom, arguments: args, _meta: META } });
const MSG = { model: "modele-messages-simule", max_tokens: 64, system: "Tu es un agent de test.", messages: [{ role: "user", content: "Statut ?" }] };
const BASE = { "content-type": "application/json", "x-noortrace-token": JETON_MODELE };
const BLOQUE_ATTENTE = { code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "attente" } };
const CORPS_DEGRADE = { type: "error", error: { type: "noortrace_degrade", message: "noortrace: echange bloque, enregistreur en mode degrade" } };

/** Les trois bornes d'EX-14.9 : réglage, et ce qui la fait atteindre après une première mise en attente. */
const BORNES = [
  {
    nom: "policy.failure.pending_max_events",
    borne: "pending_max_events",
    regler: (c) => (c.policy.failure.pending_max_events = 1),
    atteindre: () => {},
  },
  {
    nom: "limits.pending_max_bytes",
    borne: "pending_max_bytes",
    // Minimum du schéma (1024) : une seule mise en attente le dépasse (pièces de plus de 1024 octets).
    regler: (c) => (c.limits.pending_max_bytes = 1024),
    atteindre: () => {},
  },
  {
    nom: "policy.failure.pending_max_ms",
    borne: "pending_max_ms",
    regler: (c) => (c.policy.failure.pending_max_ms = 60000),
    // L'événement le plus ancien attend depuis plus de 60 s à l'horloge murale du cœur.
    atteindre: (horloge) => horloge.avancer(60001),
  },
];

/** Panne du stockage : écriture des pièces en erreur et segment fermé (EX-12.8). Rend la remise en état. */
async function pannerStockage(coeur) {
  const ecrire = coeur.pieces.ecrire;
  coeur.pieces.ecrire = async () => {
    throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { donnees: { errno: "EIO" } });
  };
  await coeur.ecrivain.signalerPanneStockage(Object.assign(new Error("panne de test"), { code: "EIO" })).catch(() => {});
  expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
  return () => {
    coeur.pieces.ecrire = ecrire;
  };
}

/** Banc MCP : cœur, frontal, enfant stdio factice qui répond à tout appel d'outil. */
async function bancMcp(o = {}) {
  const dir = repertoireTemporaire("noortrace-attente-bornes-mcp-");
  const servers = { demo: serveurStdio(["/opt/mcp/demo"], { protocol: "2026-07-28", tools: {}, class_default: null }) };
  const { config: brute } = configurationMcp(dir, { servers });
  if (o.ajuster) o.ajuster(brute);
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  const horloge = new HorlogeReglable(DEBUT);
  // `octetsLibres` : mesure de l'espace libre du volume injectée (« disque presque plein »).
  let coeur;
  try {
    coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service: new ServiceFixe(() => AUTORISE), octetsLibres: o.octetsLibres });
  } catch (e) {
    fs.rmSync(dir, { recursive: true, force: true });
    throw e;
  }
  const relayes = [];
  const lanceur = () =>
    new EnfantFactice((l, enfant) => {
      const m = JSON.parse(l);
      if (m.id === undefined) return;
      let r;
      if (m.method === "server/discover") r = { result: { supportedVersions: ["2026-07-28"] } };
      else if (m.method === "tools/list") r = { result: { tools: OUTILS, ttlMs: 60000 } };
      else if (m.method === "subscriptions/listen") r = null;
      else {
        relayes.push(m);
        r = { result: { content: [{ type: "text", text: `ok ${m.params.name} ${"r".repeat(1200)}` }], isError: false } };
      }
      if (r) setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r })));
    });
  const frontal = new FrontalMcp({ coeur, lanceur });
  frontal.chargerListe("demo", OUTILS, { ttlMs: 60000, cacheScope: null, ere: "moderne" });
  const session = frontal.ouvrirSession({ hote: v.config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio", emettre: () => {} });
  const recevoir = async (texte) => {
    const r = await frontal.recevoir(session, texte);
    return r === null ? null : JSON.parse(r);
  };
  const evenements = async () => (await lireEvenements(coeur.repertoire)).filter((e) => !e.execution.tool.startsWith("noortrace."));
  const fermer = async () => {
    await frontal.arreter();
    await coeur.arreter();
    fs.rmSync(dir, { recursive: true, force: true });
  };
  return { dir, coeur, horloge, recevoir, evenements, fermer, relayes };
}

describe("enregistreur, CT-2 §14.2 lignes « Mémoire » et « Disque presque plein » sur le chemin du relais (EX-14.9, EX-14.10)", function () {
  this.timeout(60000);
  // Les bancs du SDK copient les variables de la configuration de développement dans process.env (fixture
  // enregistreur-sdk) : l'environnement est rendu tel quel à la fin, pour ne rien laisser aux fichiers suivants.
  let environnement;
  before(function () {
    environnement = { ...process.env };
  });
  after(function () {
    for (const k of Object.keys(process.env)) if (!(k in environnement)) delete process.env[k];
    Object.assign(process.env, environnement);
  });

  describe("CT-2 §14.2 ligne « Mémoire », colonne L : lecture passante du frontal MCP, stockage indisponible", function () {
    for (const b of BORNES) {
      it(`CT-2 §14.2 ligne « Mémoire », EX-14.9 : ${b.nom} atteinte → la lecture suivante est refusée (-31010, reason attente), pending_limit_reached, mode dégradé attente ; EX-14.10 : stockage revenu, file scellée, sortie du mode attente`, async function () {
        const banc = await bancMcp({ ajuster: b.regler });
        const { coeur, horloge } = banc;
        try {
          const remettre = await pannerStockage(coeur);
          // Première lecture : passante, relayée, événement en attente (EX-14.8).
          const r1 = await banc.recevoir(appel(1, "demo__claims.get", { claim_id: "c-1" }));
          expect(r1.result.isError).to.equal(false);
          expect(coeur.attente.length).to.equal(1);
          b.atteindre(horloge);
          // Mise en attente suivante : borne atteinte, la lecture devient bloquante.
          const r2 = await banc.recevoir(appel(2, "demo__claims.get", { claim_id: "c-2" }));
          expect(r2.error).to.deep.equal(BLOQUE_ATTENTE);
          expect(coeur.attente.length).to.equal(1);
          expect(coeur.degrade.raisons()).to.deep.equal(["stockage", "attente"]);
          const limite = coeur.journal.trouver("pending_limit_reached");
          expect(limite.length).to.equal(1);
          expect(limite[0].data).to.include({ events: 1, limit: b.borne });
          expect(coeur.journal.trouver("degraded_enter").map((l) => l.data.reason)).to.include("attente");
          expect(coeur.journal.trouver("event_lost")).to.deep.equal([]);
          // L'écriture reste bloquée par le stockage (colonne E).
          expect((await banc.recevoir(appel(3, "demo__payments.create", { claim_id: "c-3" }))).error.data).to.deep.equal({ reason: "stockage" });
          // Le stockage revient : nouveau segment au tic (EX-14.11), file scellée (EX-14.10), sortie du mode attente.
          remettre();
          await coeur.tic();
          expect(coeur.degrade.raisons()).to.deep.equal([]);
          expect(coeur.attente.length).to.equal(0);
          const ev = await banc.evenements();
          expect(ev.length).to.equal(1);
          expect(ev[0].execution.tool).to.equal("demo__claims.get");
          expect(N.decoderHorodatage(ev[0].ts)).to.equal(DEBUT);
          expect(coeur.journal.trouver("pending_flushed").at(-1).data).to.include({ count: 1 });
          expect(coeur.journal.trouver("degraded_exit").map((l) => l.data.reason)).to.include.members(["stockage", "attente"]);
          // Régime normal : la lecture suivante est relayée et scellée.
          const r4 = await banc.recevoir(appel(4, "demo__claims.get", { claim_id: "c-4" }));
          expect(r4.result.isError).to.equal(false);
          expect((await banc.evenements()).length).to.equal(2);
        } finally {
          await banc.fermer();
        }
      });
    }
  });

  describe("CT-2 §14.2 ligne « Mémoire », colonne M : échange de modèle avec failure.modele passant, stockage indisponible", function () {
    let fournisseur;

    before(async function () {
      fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
    });

    after(async function () {
      await fournisseur?.arreter();
    });

    async function bancModele(regler) {
      const dir = repertoireTemporaire("noortrace-attente-bornes-modele-");
      const c = configurationModele(dir, fournisseur.url, { failure: { modele: "passant" } });
      regler(c.config);
      const { config, secrets } = valider(c.config, c.env);
      const horloge = new HorlogeReglable(DEBUT);
      const { coeur } = await demarrerCoeur(config, secrets, { horloge });
      const passerelle = new PasserelleModele({ coeur, secrets, config });
      await passerelle.ecouter();
      const envoyer = async () => {
        const r = await fetch(`http://127.0.0.1:${passerelle.adresse().port}/v1/messages`, { method: "POST", headers: BASE, body: JSON.stringify(MSG) });
        return { statut: r.status, texte: await r.text() };
      };
      const fermer = async () => {
        await passerelle.arreter();
        await coeur.arreter();
        fs.rmSync(dir, { recursive: true, force: true });
      };
      return { coeur, horloge, envoyer, fermer };
    }

    for (const b of BORNES) {
      it(`CT-2 §14.2 ligne « Mémoire », EX-14.9 : ${b.nom} atteinte → l'échange suivant est bloqué (503 noortrace_degrade, non relayé), pending_limit_reached, mode dégradé attente ; EX-14.10 : stockage revenu, file scellée, sortie du mode attente`, async function () {
        const banc = await bancModele((c) => {
          b.regler(c);
          // Une seule mise en attente doit dépasser 1024 octets de pièces gardées en mémoire.
          if (b.borne === "pending_max_bytes") MSG.messages[0].content = `Statut ? ${"q".repeat(1200)}`;
        });
        const { coeur, horloge } = banc;
        try {
          const remettre = await pannerStockage(coeur);
          const avant = fournisseur.requetes.length;
          const a = await banc.envoyer();
          expect(a.statut).to.equal(200);
          expect(coeur.attente.length).to.equal(1);
          b.atteindre(horloge);
          const r = await banc.envoyer();
          expect(r.statut).to.equal(503);
          expect(JSON.parse(r.texte)).to.deep.equal(CORPS_DEGRADE);
          // Rien n'a atteint le fournisseur pour l'échange bloqué (14.2).
          expect(fournisseur.requetes.length).to.equal(avant + 1);
          expect(coeur.attente.length).to.equal(1);
          expect(coeur.degrade.raisons()).to.deep.equal(["stockage", "attente"]);
          expect(coeur.journal.trouver("pending_limit_reached")[0].data).to.include({ events: 1, limit: b.borne });
          expect(coeur.journal.trouver("exchange_lost")).to.deep.equal([]);
          // EX-14.4 : `stockage` et `attente` actifs, la plus restrictive (`attente`) est la raison consignée.
          const bloque = () => coeur.journal.trouver("call_blocked").filter((l) => l.data.class === "modele").map((l) => l.data.reason);
          expect(bloque()).to.deep.equal(["attente"]);
          expect((await banc.envoyer()).statut).to.equal(503);
          expect(bloque()).to.deep.equal(["attente", "attente"]);
          expect(fournisseur.requetes.length).to.equal(avant + 1);
          remettre();
          await coeur.tic();
          expect(coeur.degrade.raisons()).to.deep.equal([]);
          expect(coeur.attente.length).to.equal(0);
          const ev = (await lireEvenements(coeur.repertoire)).filter((e) => e.execution.tool === "noortrace.modele.echange");
          expect(ev.length).to.equal(1);
          expect(N.decoderHorodatage(ev[0].ts)).to.equal(DEBUT);
          const ok = await banc.envoyer();
          expect(ok.statut).to.equal(200);
          // L'événement de l'échange est scellé après la réponse : attendu un instant.
          const echanges = async () => (await lireEvenements(coeur.repertoire)).filter((e) => e.execution.tool === "noortrace.modele.echange").length;
          for (let i = 0; i < 100 && (await echanges()) < 2; i++) await new Promise((r) => setTimeout(r, 10));
          expect(await echanges()).to.equal(2);
        } finally {
          MSG.messages[0].content = "Statut ?";
          await banc.fermer();
        }
      });
    }
  });

  describe("CT-2 §14.2 ligne « Disque presque plein » : storage.min_free_bytes au-dessus de l'espace libre du volume", function () {
    it("CT-2 §14.2 ligne « Disque presque plein », colonne E : écriture -31010 reason stockage sans relais, ligne disk_low (octets libres) ; puis espace libre au-dessus de min_free_bytes (nouveau cœur, le rechargement étant refusé) : régime normal", async function () {
      const dir = repertoireTemporaire("noortrace-attente-bornes-disque-");
      const libres = await octetsLibres(dir);
      expect(libres).to.be.a("number");
      // Au-dessus de l'espace libre réel, dans la borne du schéma (1 Tio).
      const seuil = Math.min(1099511627776, libres + 1024 ** 3);
      expect(seuil).to.be.greaterThan(libres);
      const servers = { demo: serveurStdio(["/opt/mcp/demo"], { protocol: "2026-07-28", tools: {}, class_default: null }) };
      const { config: brute, env } = configurationMcp(dir, { servers });
      const octets = (c) => new TextEncoder().encode(JSON.stringify(c));
      const v = validerConfiguration(octets(brute));
      expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
      const horloge = new HorlogeReglable(DEBUT);
      const enfants = [];
      const lanceur = () => {
        const e = new EnfantFactice((l, enfant) => {
          const m = JSON.parse(l);
          if (m.id === undefined) return;
          let r;
          if (m.method === "server/discover") r = { result: { supportedVersions: ["2026-07-28"] } };
          else if (m.method === "tools/list") r = { result: { tools: OUTILS, ttlMs: 60000 } };
          else if (m.method === "subscriptions/listen") r = null;
          else r = { result: { content: [{ type: "text", text: `ok ${m.params.name}` }], isError: false } };
          if (r) setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, ...r })));
        });
        enfants.push(e);
        return e;
      };
      const monter = async (config) => {
        const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service: new ServiceFixe(() => AUTORISE) });
        const frontal = new FrontalMcp({ coeur, lanceur });
        frontal.chargerListe("demo", OUTILS, { ttlMs: 60000, cacheScope: null, ere: "moderne" });
        const session = frontal.ouvrirSession({ hote: config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio", emettre: () => {} });
        const recevoir = async (texte) => JSON.parse(await frontal.recevoir(session, texte));
        return { coeur, frontal, recevoir };
      };
      const relayes = () => enfants.flatMap((e) => e.ecrit.map((l) => JSON.parse(l)).filter((m) => m.method === "tools/call"));
      let m = await monter(v.config);
      try {
        // Le volume passe sous le seuil après le démarrage : seuil effectif de
        // storage.min_free_bytes (MagasinPieces) porté au-dessus de l'espace libre réel.
        m.coeur.pieces.minOctetsLibres = seuil;
        // Colonne E : écriture bloquée, préventif, rien n'est relayé.
        const e = await m.recevoir(appel(1, "demo__payments.create", { claim_id: "c-1" }));
        expect(e.error).to.deep.equal({ code: -31010, message: "noortrace: appel bloque, enregistreur en mode degrade", data: { reason: "stockage" } });
        expect(relayes()).to.deep.equal([]);
        expect(m.coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        const disque = m.coeur.journal.trouver("disk_low");
        expect(disque.length).to.equal(1);
        expect(disque[0].data.free_bytes).to.be.a("number").and.below(seuil);
        expect(disque[0].data.min_free_bytes).to.equal(seuil);
        // Le rechargement ne ramène pas min_free_bytes : refusé en mode dégradé, et
        // `storage` est hors `policy` (redémarrage requis, EX-15.5).
        const ramene = structuredClone(brute);
        ramene.storage.min_free_bytes = 2048;
        ramene.policy.version = `${brute.policy.version}-disque`;
        expect(await m.coeur.recharger(octets(ramene), { env })).to.deep.include({ accepte: false, raison: "mode_degrade" });
        // Nouveau cœur, seuil sous l'espace libre (storage.min_free_bytes de la configuration, 1024).
        await m.frontal.arreter();
        await m.coeur.arreter();
        horloge.avancer(1000);
        m = await monter(v.config);
        expect(m.coeur.pieces.minOctetsLibres).to.equal(1024);
        expect(m.coeur.degrade.raisons()).to.deep.equal([]);
        const ok = await m.recevoir(appel(3, "demo__payments.create", { claim_id: "c-3" }));
        expect(ok.result.isError).to.equal(false);
        expect(relayes().length).to.equal(1);
        const scelles = (await lireEvenements(m.coeur.repertoire)).filter((x) => !x.execution.tool.startsWith("noortrace."));
        expect(scelles.map((x) => x.execution.tool)).to.deep.equal(["demo__payments.create"]);
      } finally {
        await m.frontal.arreter().catch(() => {});
        await m.coeur.arreter().catch(() => {});
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it("CT-2 §14.2 ligne « Disque presque plein », colonne L : disque presque plein constaté (disk_low), lecture passante relayée, événement en attente (call_passthrough_pending)", async function () {
      const banc = await bancMcp();
      try {
        const libres = await octetsLibres(banc.dir);
        banc.coeur.pieces.minOctetsLibres = Math.min(1099511627776, libres + 1024 ** 3);
        // Constat à l'écriture des pièces de la première lecture (pas 4) : elle est
        // passante elle aussi (colonne L), pièces gardées en mémoire (EX-14.8).
        const l1 = await banc.recevoir(appel(1, "demo__claims.get", { claim_id: "c-1" }));
        expect(l1.result.isError).to.equal(false);
        expect(banc.coeur.journal.trouver("disk_low").length).to.equal(1);
        expect(banc.coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        const l = await banc.recevoir(appel(2, "demo__claims.get", { claim_id: "c-2" }));
        expect(l.result.isError).to.equal(false);
        expect(banc.coeur.attente.length).to.equal(2);
        expect(banc.coeur.journal.trouver("call_passthrough_pending").length).to.equal(2);
        expect(banc.relayes.length).to.equal(2);
      } finally {
        await banc.fermer();
      }
    });

    it("CT-2 §14.2 ligne « Disque presque plein », colonne M « comme le stockage indisponible » : échange de modèle bloqué (503 noortrace_degrade), ligne disk_low", async function () {
      const fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
      const dir = repertoireTemporaire("noortrace-attente-bornes-disque-modele-");
      const libres = await octetsLibres(dir);
      const seuil = Math.min(1099511627776, libres + 1024 ** 3);
      const c = configurationModele(dir, fournisseur.url);
      const { config, secrets } = valider(c.config, c.env);
      const { coeur } = await demarrerCoeur(config, secrets, { horloge: new HorlogeReglable(DEBUT) });
      // Le volume passe sous storage.min_free_bytes après le démarrage.
      coeur.pieces.minOctetsLibres = seuil;
      const passerelle = new PasserelleModele({ coeur, secrets, config });
      await passerelle.ecouter();
      try {
        const r = await fetch(`http://127.0.0.1:${passerelle.adresse().port}/v1/messages`, { method: "POST", headers: BASE, body: JSON.stringify(MSG) });
        expect(r.status).to.equal(503);
        expect(await r.json()).to.deep.equal(CORPS_DEGRADE);
        expect(fournisseur.requetes.length).to.equal(0);
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(coeur.journal.trouver("disk_low")[0].data).to.include({ min_free_bytes: seuil });
      } finally {
        await passerelle.arreter();
        await coeur.arreter();
        await fournisseur.arreter();
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
  describe("CT-2 §14.2 ligne « Disque presque plein » : vérification au démarrage, avant ouverture de segment et toutes les 10 s ; sortie quand l'espace revient", function () {
    it("CT-2 §14.2 ligne « Disque presque plein », EX-15.4 pas 5, EX-9.8 : démarrage sous storage.min_free_bytes → le démon démarre en mode dégradé stockage (disk_low, aucun segment ouvert) ; écriture -31010 stockage, lecture passante en attente ; espace revenu : au tic, nouveau segment, événement de politique puis lecture scellés dans cet ordre, sortie du mode", async function () {
      let libres = 512;
      const banc = await bancMcp({ octetsLibres: async () => libres });
      const { coeur, horloge } = banc;
      try {
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(coeur.journal.trouver("disk_low").map((l) => l.data)).to.deep.equal([{ free_bytes: 512, min_free_bytes: 1024 }]);
        expect(coeur.journal.trouver("startup").length).to.equal(1);
        expect(fs.readdirSync(`${coeur.repertoire}/segments`)).to.deep.equal([]);
        expect((await banc.recevoir(appel(1, "demo__payments.create", { claim_id: "c-1" }))).error.data).to.deep.equal({ reason: "stockage" });
        expect((await banc.recevoir(appel(2, "demo__claims.get", { claim_id: "c-2" }))).result.isError).to.equal(false);
        expect(coeur.attente.length).to.equal(1);
        expect(banc.relayes.map((m) => m.params.name)).to.deep.equal(["claims.get"]);
        // Encore sous le seuil : la reprise vérifie l'espace avant d'ouvrir le segment.
        horloge.avancer(1000);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(fs.readdirSync(`${coeur.repertoire}/segments`)).to.deep.equal([]);
        // L'espace revient.
        libres = 1024 ** 4;
        horloge.avancer(1000);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        expect(coeur.attente.length).to.equal(0);
        const ev = await lireEvenements(coeur.repertoire);
        expect(ev.map((e) => e.execution.tool)).to.deep.equal(["noortrace.journal.politique", "demo__claims.get"]);
        // EX-14.10 : ts = max(captured_at, ts précédent), le précédent étant l'événement de politique.
        expect(N.decoderHorodatage(ev[1].ts)).to.equal(N.decoderHorodatage(ev[0].ts));
        expect((await banc.recevoir(appel(3, "demo__payments.create", { claim_id: "c-3" }))).result.isError).to.equal(false);
        expect((await banc.evenements()).map((e) => e.execution.tool)).to.deep.equal(["demo__claims.get", "demo__payments.create"]);
      } finally {
        await banc.fermer();
      }
    });

    it(`CT-2 §14.2 ligne « Disque presque plein » : contrôle toutes les 10 s au tic (horloge injectée) → mode dégradé stockage sans aucune écriture, une ligne disk_low ; la reprise vérifie l'espace avant d'ouvrir le segment ; espace revenu : sortie au tic, écriture relayée et scellée`, async function () {
      let libres = 1024 ** 4;
      const banc = await bancMcp({ octetsLibres: async () => libres });
      const { coeur, horloge } = banc;
      try {
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        libres = 512;
        // Moins de 10 s depuis le contrôle précédent : pas de contrôle.
        horloge.avancer(CONTROLE_DISQUE_MS - 1);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        horloge.avancer(1);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(coeur.journal.trouver("disk_low").map((l) => l.data)).to.deep.equal([{ free_bytes: 512, min_free_bytes: 1024 }]);
        expect((await banc.recevoir(appel(1, "demo__payments.create", { claim_id: "c-1" }))).error.data).to.deep.equal({ reason: "stockage" });
        const segments = fs.readdirSync(`${coeur.repertoire}/segments`).length;
        horloge.avancer(1000);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(fs.readdirSync(`${coeur.repertoire}/segments`).length).to.equal(segments);
        expect(coeur.journal.trouver("disk_low").length).to.equal(1);
        libres = 1024 ** 4;
        horloge.avancer(1000);
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        expect(fs.readdirSync(`${coeur.repertoire}/segments`).length).to.equal(segments + 1);
        expect((await banc.recevoir(appel(2, "demo__payments.create", { claim_id: "c-2" }))).result.isError).to.equal(false);
        expect((await banc.evenements()).map((e) => e.execution.tool)).to.deep.equal(["demo__payments.create"]);
      } finally {
        await banc.fermer();
      }
    });
  });

  describe("CT-2 EX-12.8, EX-14.11 : sortie du mode « stockage » après un échec d'écriture de pièce", function () {
    it("CT-2 EX-12.8, EX-14.11 : une pièce qui ne s'écrit pas ferme le segment et fait entrer le mode stockage ; le stockage répond de nouveau : au tic, nouveau segment et sortie du mode sans degrade.sortir, écriture relayée et scellée", async function () {
      const banc = await bancMcp();
      const { coeur } = banc;
      try {
        const ecrire = coeur.pieces.ecrire;
        coeur.pieces.ecrire = async () => {
          throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: Object.assign(new Error("panne de test"), { code: "EIO" }), donnees: { errno: "EIO" } });
        };
        expect((await banc.recevoir(appel(1, "demo__payments.create", { claim_id: "c-1" }))).error.data).to.deep.equal({ reason: "stockage" });
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(banc.relayes).to.deep.equal([]);
        coeur.pieces.ecrire = ecrire;
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        expect(coeur.journal.trouver("degraded_exit").map((l) => l.data.reason)).to.deep.equal(["stockage"]);
        expect((await banc.recevoir(appel(2, "demo__payments.create", { claim_id: "c-2" }))).result.isError).to.equal(false);
        expect((await banc.evenements()).map((e) => e.execution.tool)).to.deep.equal(["demo__payments.create"]);
      } finally {
        await banc.fermer();
      }
    });
  });

  describe("CT-2 §14.2 colonne L, EX-14.8 : la lecture qui constate la panne de stockage est passante", function () {
    const panne = (coeur) => {
      const ecrire = coeur.pieces.ecrire;
      coeur.pieces.ecrire = async () => {
        throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible", { cause: Object.assign(new Error("panne de test"), { code: "EIO" }), donnees: { errno: "EIO" } });
      };
      return () => {
        coeur.pieces.ecrire = ecrire;
      };
    };

    it("CT-2 §14.2 colonne L, EX-14.8 : frontal MCP, lecture dont l'écriture des pièces échoue → relayée, réponse normale, événement en attente (pièces en mémoire) ; scellé à la sortie du mode", async function () {
      const banc = await bancMcp();
      const { coeur } = banc;
      try {
        const remettre = panne(coeur);
        const r = await banc.recevoir(appel(1, "demo__claims.get", { claim_id: "c-1" }));
        expect(r.result.isError).to.equal(false);
        expect(banc.relayes.length).to.equal(1);
        expect(coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(coeur.attente.length).to.equal(1);
        expect(coeur.journal.trouver("call_passthrough_pending").length).to.equal(1);
        expect(coeur.journal.trouver("call_blocked")).to.deep.equal([]);
        remettre();
        await coeur.tic();
        expect(coeur.degrade.raisons()).to.deep.equal([]);
        const ev = await banc.evenements();
        expect(ev.map((e) => e.execution.tool)).to.deep.equal(["demo__claims.get"]);
        expect(ev[0].execution.is_error).to.equal(false);
        expect(fs.existsSync(coeur.pieces.chemin(ev[0].execution.arguments.sha256))).to.equal(true);
      } finally {
        await banc.fermer();
      }
    });

    it("CT-2 §14.2 colonne L, EX-14.8 : SDK, debutAppel d'une lecture dont l'écriture des pièces échoue → autorise, finAppel { seq: null, hash: null }, événement en attente ; scellé à la sortie du mode", async function () {
      const d = await demarrerDemonSdk({ horloge: new HorlogeReglable(DEBUT) });
      try {
        const s = await d.client().ouvrir({});
        const remettre = panne(d.coeur);
        const debut = await s.debutAppel({ tool: "lire", arguments: { id: 1 }, classe: "lecture" });
        expect(debut.decision).to.equal("autorise");
        expect(await s.finAppel(debut, { resultat: { ok: 1 }, isError: false, durationMs: 2 })).to.deep.equal({ seq: null, hash: null });
        expect(d.coeur.degrade.raisons()).to.deep.equal(["stockage"]);
        expect(d.coeur.attente.length).to.equal(1);
        remettre();
        await d.coeur.tic();
        expect(d.coeur.degrade.raisons()).to.deep.equal([]);
        expect((await d.evenements()).at(-1).execution.tool).to.equal("agent-local__lire");
        await s.fermer();
      } finally {
        await d.arreter();
        fs.rmSync(d.dir, { recursive: true, force: true });
      }
    });
  });

  describe("CT-2 §17 : jauge noortrace_pending_oldest_ms", function () {
    it("CT-2 §17 : noortrace_pending_oldest_ms = âge de l'événement en attente le plus ancien, tenu au tic (horloge injectée) ; 0 après scellement de la file", async function () {
      const banc = await bancMcp();
      const { coeur, horloge } = banc;
      const age = () => coeur.metriques.valeur("noortrace_pending_oldest_ms", {});
      try {
        const remettre = await pannerStockage(coeur);
        expect((await banc.recevoir(appel(1, "demo__claims.get", { claim_id: "c-1" }))).result.isError).to.equal(false);
        expect(age()).to.equal(0);
        horloge.avancer(4000);
        expect((await banc.recevoir(appel(2, "demo__claims.get", { claim_id: "c-2" }))).result.isError).to.equal(false);
        expect(age()).to.equal(4000);
        horloge.avancer(3000);
        await coeur.tic();
        expect(age()).to.equal(7000);
        expect(coeur.metriques.exposer()).to.match(/^noortrace_pending_oldest_ms 7000$/m);
        remettre();
        await coeur.tic();
        expect(coeur.attente.length).to.equal(0);
        expect(age()).to.equal(0);
      } finally {
        await banc.fermer();
      }
    });
  });
});
