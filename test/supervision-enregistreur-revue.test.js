// Supervision du démon de l'enregistreur (CT-2 §17.2, EX-4.18, EX-14.7,
// EX-14.11 ; CT-5 EX-8.15 ; CT-9 TE-17) : ce que TE-17 lit sous Prometheus,
// éprouvé ici sans collecteur, en quelques secondes.
//
// - Chaque métrique des tables de CT-2 §17.2 et de CT-5 EX-8.15 est déclarée
//   (ligne `# TYPE`, type de la table) dans `/metrics` du démon dès son
//   démarrage, série ou non, composant d'ancrage branché ou non, et une seule
//   fois quand le composant d'ancrage expose les siennes.
// - Un relais vers un serveur d'outils injoignable met la raison de santé
//   `serveur:<alias>` et `noortrace_degraded{reason="serveur:<alias>"}` à 1 ;
//   elles reviennent à 0 au premier `tools/list` réussi, que le frontal tente
//   à l'expiration du `ttlMs` de la dernière liste du serveur.
// - `noortrace_clock_skew_ms` porte le dernier écart mesuré (EX-7.10) ;
//   `noortrace_sse_first_byte_ms` est observée pour chaque flux relayé par la
//   passerelle.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as E from "@noortrace/enregistreur";
import { RACINE, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { preparerMontage, demarrerDemon, arreterMontage, lireSupervision, HoteCadence } from "./fixtures/supervision-collecteur/montage.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule } from "./fixtures/enregistreur-modele/fournisseur.mjs";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const CT2 = fs.readFileSync(path.join(RACINE, "spec", "CT-2-enregistreur.md"), "utf8");
const CT5 = fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8");

/** Lignes `| `noortrace_…` | type | …` d'un passage de spécification : [{ nom, type }]. */
function tableMetriques(texte, debut, fin) {
  const i = texte.indexOf(debut);
  const j = texte.indexOf(fin, i + debut.length);
  expect(i, debut).to.be.at.least(0);
  expect(j, fin).to.be.above(i);
  const out = [];
  for (const l of texte.slice(i, j).split("\n")) {
    const m = /^\| `(noortrace_[a-z_]+)` \| (compteur|jauge|histogramme)/.exec(l);
    if (m) out.push({ nom: m[1], type: { compteur: "counter", jauge: "gauge", histogramme: "histogram" }[m[2]] });
  }
  return out;
}

/** Lignes `# TYPE` d'une exposition : nom → [types]. */
function declarations(texte) {
  const r = new Map();
  for (const l of texte.split("\n")) {
    const m = /^# TYPE (\S+) (\S+)$/.exec(l);
    if (m) r.set(m[1], [...(r.get(m[1]) ?? []), m[2]]);
  }
  return r;
}

/** Valeur d'une série de l'exposition (nom et étiquettes écrits tels quels), ou undefined. */
function serie(texte, nomEtEtiquettes) {
  for (const l of texte.split("\n")) if (l.startsWith(nomEtEtiquettes + " ")) return Number(l.slice(nomEtEtiquettes.length + 1));
  return undefined;
}

/** Attend `cond()` vrai au plus `ms` millisecondes ; rend la dernière valeur lue. */
async function attendre(cond, ms, pas = 250) {
  const limite = Date.now() + ms;
  let v;
  for (;;) {
    v = await cond();
    if (v.ok || Date.now() > limite) return v;
    await pause(pas);
  }
}

const TABLES = [
  ...tableMetriques(CT2, "### 17.2 Métriques", "### 17.3 "),
  ...tableMetriques(CT5, "**EX-8.15**", "Alertes prescrites").filter((m) => m.nom !== "noortrace_anchor_pending"),
];

describe("revue supervision de l'enregistreur : démon réel, serveur d'outils nul (CT-2 §17.2, EX-4.18, EX-14.7, EX-14.11 ; CT-5 EX-8.15)", function () {
  this.timeout(120000);
  let m;
  let demon;
  let hote;

  before(async function () {
    m = await preparerMontage(repertoireTemporaire("noortrace-supervision-revue-"));
    demon = await demarrerDemon(m);
    hote = new HoteCadence({ socket: m.config.mcp.socket, connexions: 1, cadence: 1 });
    await hote.ouvrir();
  });

  after(async function () {
    fs.rmSync(path.join(m?.etat ?? "/nonexistent", "panne"), { force: true });
    await hote?.fermer().catch(() => {});
    if (demon) await demon.arreter();
    if (m) await arreterMontage(m);
  });

  it("au démarrage, sans composant d'ancrage branché, /metrics déclare une fois chaque métrique des tables de CT-2 §17.2 (45) et de CT-5 EX-8.15 (9 de plus) par une ligne # TYPE au type de la table, série ou non ; noortrace_clock_skew_ms a sa série à 0 ; noortrace_degraded{reason=\"serveur:nul\"} est à 0", async function () {
    expect(TABLES.length, "45 métriques de CT-2 §17.2 et 9 propres à CT-5 EX-8.15").to.equal(54);
    const { statut, texte } = await lireSupervision(m, "/metrics");
    expect(statut).to.equal(200);
    const d = declarations(texte);
    const ecarts = [];
    for (const t of TABLES) {
      const types = d.get(t.nom) ?? [];
      if (types.length !== 1 || types[0] !== t.type) ecarts.push(`${t.nom} : ${types.length ? types.join(", ") : "aucune ligne # TYPE"} (table : ${t.type})`);
    }
    expect(ecarts).to.deep.equal([]);
    expect(serie(texte, "noortrace_clock_skew_ms")).to.equal(0);
    expect(serie(texte, 'noortrace_degraded{reason="serveur:nul"}')).to.equal(0);
  });

  it("un relais tools/call vers le serveur d'outils arrêté (-31014, upstream_unreachable) met la raison serveur:nul de /healthz et noortrace_degraded{reason=\"serveur:nul\"} à 1 ; serveur revenu et sans aucun appel, le tools/list que le frontal retente à l'expiration du ttlMs de la dernière liste (5 s) les remet à 0, avec la ligne upstream_reachable", async function () {
    const r0 = await hote.appeler("nul__nul.lire", { cle: "avant" });
    expect(r0.result?.isError, JSON.stringify(r0)).to.equal(false);
    expect(JSON.parse((await lireSupervision(m, "/healthz")).texte)).to.deep.equal({ status: "ok" });
    fs.writeFileSync(path.join(m.etat, "panne"), "");
    await pause(1000);
    // Appels relayés pendant la panne : -31014 (le serveur s'arrête aussi à chaque relance).
    const codes = [];
    for (let k = 0; k < 3; k++) {
      const r = await Promise.race([hote.appeler("nul__nul.lire", { cle: `panne-${k}` }), pause(20000).then(() => ({ delai: true }))]);
      codes.push(r.error?.code ?? (r.delai ? "delai" : "ok"));
    }
    expect(codes, "réponses des relais pendant la panne").to.include(-31014);
    const degrade = await attendre(async () => {
      const s = JSON.parse((await lireSupervision(m, "/healthz")).texte);
      const g = serie((await lireSupervision(m, "/metrics")).texte, 'noortrace_degraded{reason="serveur:nul"}');
      return { ok: s.status === "degraded" && g === 1, s, g };
    }, 3000);
    expect([degrade.s.status, degrade.s.reasons, degrade.g], "santé et jauge après des relais vers un serveur injoignable").to.deep.equal(["degraded", ["serveur:nul"], 1]);
    // Serveur revenu ; aucun appel de l'hôte : seule la relecture à l'expiration du ttlMs peut lever la raison.
    fs.rmSync(path.join(m.etat, "panne"), { force: true });
    const leve = await attendre(async () => {
      const s = JSON.parse((await lireSupervision(m, "/healthz")).texte);
      const g = serie((await lireSupervision(m, "/metrics")).texte, 'noortrace_degraded{reason="serveur:nul"}');
      return { ok: s.status === "ok" && g === 0, s, g };
    }, 20000);
    expect([leve.s, leve.g], "santé et jauge après le retour du serveur, sans appel").to.deep.equal([{ status: "ok" }, 0]);
    const lignes = fs.readFileSync(m.journalExploitation, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const i = lignes.findIndex((l) => l.event === "upstream_unreachable" && l.data?.server === "nul");
    expect(i, "ligne upstream_unreachable").to.be.at.least(0);
    expect(lignes.slice(i).some((l) => l.event === "upstream_reachable" && l.data?.server === "nul"), "ligne upstream_reachable après l'entrée").to.equal(true);
    const r1 = await hote.appeler("nul__nul.lire", { cle: "apres" });
    expect(r1.result?.isError, JSON.stringify(r1)).to.equal(false);
  });
});

/** Serveur d'outils stdio d'essai : `nul.lire` répond ; `nul.meurs` arrête le processus sans répondre (connexion perdue pendant l'appel). */
const SERVEUR_MORTEL = `
const readline = require("node:readline");
const ecrire = (o) => process.stdout.write(JSON.stringify(o) + "\\n");
const resultat = (id, r) => ecrire({ jsonrpc: "2.0", id, result: { resultType: "complete", ...r } });
const outils = [
  { name: "nul.lire", description: "Rend un texte fixe", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
  { name: "nul.meurs", description: "Arrete le serveur sans repondre", inputSchema: { type: "object" }, annotations: { readOnlyHint: true } },
];
readline.createInterface({ input: process.stdin }).on("line", (l) => {
  let m;
  try { m = JSON.parse(l); } catch { return; }
  if (m.id === undefined) return;
  if (m.method === "server/discover") return resultat(m.id, { supportedVersions: ["2026-07-28"], capabilities: { tools: { listChanged: true } }, serverInfo: { name: "outils-mortels", version: "1.0.0" } });
  if (m.method === "subscriptions/listen") return;
  if (m.method === "tools/list") return resultat(m.id, { tools: outils, ttlMs: 5000, cacheScope: "private" });
  if (m.method === "tools/call" && m.params?.name === "nul.meurs") process.exit(3);
  if (m.method === "tools/call") return resultat(m.id, { content: [{ type: "text", text: "lu" }], isError: false });
  ecrire({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } });
});
`;

describe("revue supervision de l'enregistreur : connexion au serveur d'outils perdue pendant un appel (CT-2 EX-4.18, EX-14.7)", function () {
  this.timeout(120000);
  let m;
  let demon;
  let hote;

  before(async function () {
    const dir = repertoireTemporaire("noortrace-supervision-revue-perte-");
    const script = path.join(dir, "serveur-mortel.cjs");
    fs.writeFileSync(script, SERVEUR_MORTEL);
    m = await preparerMontage(path.join(dir, "montage"), {
      modifier: (c) => {
        c.policy.servers.nul.transport.command = [process.execPath, script];
        c.policy.servers.nul.tools = {};
      },
    });
    demon = await demarrerDemon(m);
    hote = new HoteCadence({ socket: m.config.mcp.socket, connexions: 1, cadence: 1 });
    await hote.ouvrir();
  });

  after(async function () {
    await hote?.fermer().catch(() => {});
    if (demon) await demon.arreter();
    if (m) await arreterMontage(m);
  });

  it("le serveur s'arrête pendant un appel relayé (-31014, upstream_unreachable de raison perte) : la raison serveur:nul de /healthz et noortrace_degraded{reason=\"serveur:nul\"} passent à 1 aussitôt ; le serveur relancé, la relecture de sa liste à l'expiration du ttlMs les remet à 0", async function () {
    expect(JSON.parse((await lireSupervision(m, "/healthz")).texte)).to.deep.equal({ status: "ok" });
    const r = await Promise.race([hote.appeler("nul__nul.meurs", {}), pause(30000).then(() => ({ delai: true }))]);
    expect(r.error?.code, JSON.stringify(r)).to.equal(-31014);
    const lignes = fs.readFileSync(m.journalExploitation, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    expect(lignes.some((l) => l.event === "upstream_unreachable" && l.data?.server === "nul" && l.data?.reason === "perte"), "ligne upstream_unreachable, raison perte").to.equal(true);
    const s = JSON.parse((await lireSupervision(m, "/healthz")).texte);
    const g = serie((await lireSupervision(m, "/metrics")).texte, 'noortrace_degraded{reason="serveur:nul"}');
    expect([s.status, s.reasons, g], "santé et jauge aussitôt après la perte").to.deep.equal(["degraded", ["serveur:nul"], 1]);
    const leve = await attendre(async () => {
      const x = JSON.parse((await lireSupervision(m, "/healthz")).texte);
      const y = serie((await lireSupervision(m, "/metrics")).texte, 'noortrace_degraded{reason="serveur:nul"}');
      return { ok: x.status === "ok" && y === 0, x, y };
    }, 20000);
    expect([leve.x, leve.y], "santé et jauge après la relecture").to.deep.equal([{ status: "ok" }, 0]);
  });
});

describe("revue supervision de l'enregistreur : exposition, horloge, premier octet d'un flux (CT-2 §17.2, EX-7.10, §16.1)", function () {
  this.timeout(60000);

  it("Metriques.declarer sans combinaison déclare la famille (ligne # TYPE) sans série ; un histogramme déclaré sans bornes prend celles de sa première observation", function () {
    const m = new E.Metriques();
    m.declarer("x_ms", "histogram", []);
    m.declarer("y", "gauge", []);
    expect(m.exposer()).to.equal("# TYPE x_ms histogram\n# TYPE y gauge\n");
    m.observer("x_ms", {}, 3, [1, 4]);
    expect(m.exposer()).to.equal('# TYPE x_ms histogram\nx_ms_bucket{le="1"} 0\nx_ms_bucket{le="4"} 1\nx_ms_bucket{le="+Inf"} 1\nx_ms_sum 3\nx_ms_count 1\n# TYPE y gauge\n');
  });

  it("exposition du démon avec le composant d'ancrage branché : une famille que le composant déclare n'est écrite qu'une fois (la sienne), les autres déclarations du démon restent", function () {
    const m = new E.Metriques();
    E.declarerCompteursDemon(m, {});
    const ancrage = '# TYPE noortrace_anchor_pending gauge\nnoortrace_anchor_pending{anchor="ots"} 0\n# TYPE noortrace_anchoring_window_s gauge\n';
    const texte = E.exposerMetriquesDemon(m, ancrage);
    const d = declarations(texte);
    expect(d.get("noortrace_anchor_pending")).to.deep.equal(["gauge"]);
    expect(d.get("noortrace_anchoring_window_s")).to.deep.equal(["gauge"]);
    expect(d.get("noortrace_anchoring_d_point_s")).to.deep.equal(["histogram"]);
    expect([...d.values()].every((t) => t.length === 1), "une ligne # TYPE par nom").to.equal(true);
    expect(texte.endsWith(ancrage)).to.equal(true);
  });

  it("noortrace_clock_skew_ms (EX-7.10) : ts précédent moins l'heure murale lue au scellement, 0 quand l'heure ne recule pas ; la valeur suit chaque mesure", function () {
    const m = new E.Metriques();
    const h = new E.HorlogeReglable(1_794_000_000_000);
    const degrade = { entrer() {}, sortir() {}, actif: () => false };
    const lignes = [];
    const c = new E.ControleurHorloge(h, { warn_skew_ms: 1000, max_backstep_ms: 5000 }, degrade, { consigner: (...a) => lignes.push(a) }, m);
    const ts1 = c.fixerTs(null);
    expect(m.valeur("noortrace_clock_skew_ms")).to.equal(0);
    h.avancer(10);
    const ts2 = c.fixerTs(ts1);
    expect(m.valeur("noortrace_clock_skew_ms")).to.equal(0);
    h.placerMurale(ts2 - 1500);
    c.fixerTs(ts2);
    expect(m.valeur("noortrace_clock_skew_ms")).to.equal(1500);
    expect(lignes.map((l) => l[2])).to.include("clock_skew");
    h.placerMurale(ts2 + 20);
    c.fixerTs(ts2);
    expect(m.valeur("noortrace_clock_skew_ms")).to.equal(0);
  });

  describe("passerelle de modèle et fournisseur simulé", function () {
    let fournisseur;
    let coeur;
    let p;

    before(async function () {
      const dir = repertoireTemporaire("noortrace-supervision-revue-modele-");
      fournisseur = await new FournisseurSimule({ pauseMs: 2 }).demarrer();
      const c = configurationModele(dir, fournisseur.url);
      const { config, secrets } = valider(c.config, c.env);
      ({ coeur } = await demarrerCoeur(config, secrets));
      p = new E.PasserelleModele({ coeur, secrets, config });
      await p.ecouter();
    });

    after(async function () {
      await p?.arreter();
      await coeur?.arreter();
      await fournisseur?.arreter();
    });

    it("noortrace_sse_first_byte_ms{provider} (CT-2 §17.2, §16.1) : une observation par échange en flux relayé, aucune pour un échange hors flux", async function () {
      const envoyer = async (corps) => {
        const r = await fetch(`http://127.0.0.1:${p.adresse().port}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "x-noortrace-token": JETON_MODELE }, body: JSON.stringify(corps) });
        await r.arrayBuffer();
        return r.status;
      };
      const MSG = { model: "modele-messages-simule", max_tokens: 64, messages: [{ role: "user", content: "Statut ?" }] };
      const n = () => coeur.metriques.valeur("noortrace_sse_first_byte_ms", { provider: "anthropic" }) ?? 0;
      expect(await envoyer(MSG)).to.equal(200);
      await pause(200);
      expect(n(), "hors flux").to.equal(0);
      expect(await envoyer({ ...MSG, stream: true })).to.equal(200);
      await pause(200);
      expect(n(), "en flux").to.equal(1);
      expect(coeur.metriques.exposer()).to.match(/^noortrace_sse_first_byte_ms_count\{provider="anthropic"\} 1$/m);
    });
  });
});
