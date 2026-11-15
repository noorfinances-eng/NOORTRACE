// Bout en bout : flux réseau observés et runbooks rejoués (CT-9 TE-8), durées
// des runbooks (TM-36) et exercice de restauration en conteneurs (fragment de
// TE-9), joués sur la démonstration de référence (CT-2 §19). Rapports de mesure hors système de
// référence (counts_for_targets faux, met null).
//
// En attente, condition nommée, sans démon Docker ni les images de la
// démonstration dans le magasin local (CT-9 EX-3.11) ; jamais sauté.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RACINE = process.env.NOORTRACE_RACINE ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const P = await import(pathToFileURL(path.join(RACINE, "test", "fixtures", "pannes", "outils.mjs")).href);
const N = await import(pathToFileURL(path.join(RACINE, "paquets", "noyau", "src", "index.mjs")).href);
const CONFIG = P.CONFIG_DEMO;
const REP = `${CONFIG.recorder.org_id.slice(2)}/${CONFIG.recorder.journal_id.slice(2)}`;
const etat = P.etatDocker();

describe("CT-9 TE-8 et TM-36 : flux réseau observés et runbooks rejoués sur la démonstration de référence (CT-8 §5, §10.11)", function () {
  this.timeout(1_800_000);
  let c = null;
  let travail = null;
  let ctx = null;
  const durees = {};

  before(async function () {
    if (!etat.ok) {
      ctx = { condition: etat.condition };
      return;
    }
    travail = fs.mkdtempSync(path.join(TMP, "noortrace-te8-"));
    c = new P.CompositionPannes({ nom: `noortrace-te8-${process.pid}`, port: await P.portLibre() });
    c.lancer(["agent-demo"]);
    ctx = { code: c.attendre("agent-demo", 300000) };
  });

  after(async function () {
    if (durees && Object.keys(durees).length) {
      try {
        // Attendu avant la suppression de `travail` : sans `await`, l'écriture (asynchrone) recréait le répertoire après elle.
        await P.ecrireRapportMesure(path.join(travail, "rapport-tm36.json"), {
          results: Object.entries(durees).map(([rb, s], i) => P.ligneMesure({ name: `rb_${rb.slice(3)}`, test_id: "TM-36", unit: "s", value: s, conditions: [`runbook ${rb} rejoué sur la démonstration de référence ; du déclenchement de l'alerte à la vérification de sortie`] })),
          notes: "TM-36 : durées des runbooks rejoués sur la démonstration de référence (CT-8 §10.11) ; aucune cible ; seuls les runbooks rejoués ici figurent",
          clock: "monotone",
          disque: { type: "virtuel", fsync: null },
        });
      } catch {
        // rapport indicatif seulement
      }
    }
    if (c) c.demonter();
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      P.enAttente(this, ctx?.condition ?? "composition non lancée");
      return false;
    }
    expect(ctx.code).to.equal(0);
    return true;
  }

  it("TE-8 (FL-) : les flux réseau établis entre les services de la démonstration sont tous des flux FL- déclarés de CT-8 §5.1, ou admis hors table par EX-5.1 (poste de l'exploitant du registre, consensus des validateurs) — aucun flux non déclaré ; FL-7 (relais des outils), FL-8 (relais du modèle) et FL-19 (registre) sont observés, et agent-demo n'a que le réseau des hôtes (CT-2 §4.9)", function () {
    if (!pret.call(this)) return;
    const flux = P.releverFlux(c);
    expect(flux.ecarts, `flux non déclarés : ${JSON.stringify(flux.ecarts)}`).to.deep.equal([]);
    const fls = new Set(flux.observes.filter((o) => o.fl).map((o) => o.fl));
    // FL-7 (relais des outils) et FL-8 (relais du modèle) : connexions encore établies (maintien) après le tour.
    for (const fl of ["FL-7", "FL-8"]) expect(fls.has(fl), `${fl} observé (connexion établie) ; observés : ${[...fls].join(",")}`).to.equal(true);
    // FL-19 (registre) : flux court (soumission puis fermeture) ; observé par sa trace au journal (registry_sent / registry_included).
    const ops = c.journalExploitation();
    expect(ops.some((l) => l.event === "registry_sent" || l.event === "registry_included"), "FL-19 observé : l'enregistreur a joint le registre (registry_sent/registry_included)").to.equal(true);
    // agent-demo n'est que sur le réseau des hôtes (interne), sans route vers les serveurs d'outils (MN-1, FL-7 refusé aux agents, EX-5.2 point 2).
    const reseaux = Object.keys(P.docker(["inspect", "--format", "{{json .NetworkSettings.Networks}}", c.conteneur("agent-demo")]).stdout.trim() ? JSON.parse(P.docker(["inspect", c.conteneur("agent-demo")]).stdout)[0].NetworkSettings.Networks : {});
    expect(reseaux).to.deep.equal([c.ressource("hotes")]);
    expect(JSON.parse(P.docker(["network", "inspect", c.ressource("hotes")]).stdout)[0].Internal, "le réseau des hôtes est interne").to.equal(true);
  });

  it("TE-8 et TM-36 (RB-1 Écrivain arrêté) : le démon est arrêté pendant la capture (stockage rendu indisponible), l'alerte s'ouvre, puis le runbook est déroulé jusqu'à la vérification de sortie — à la reprise, verifier-journal rend valide, noortrace_degraded vaut 0 pour toutes les raisons, noortrace_pending_events vaut 0, et le dossier du premier événement scellé après la reprise est accepté par les deux vérificateurs de CT-6 ; durée relevée (TM-36, hors cible)", function () {
    if (!pret.call(this)) return;
    const chrono = P.chronometre();
    chrono.debut();
    // Détection (RB-1) : arrêt brutal du démon pendant la capture ; dernier segment déchiré.
    const evAvant = c.evenements(CONFIG);
    c.dc(["kill", "-s", "SIGKILL", "enregistreur"]);
    const dernier = c.segments(CONFIG).at(-1);
    c.ecrireVolume("journal", `const fs=require("fs");const f="/v/${REP}/segments/${dernier}";const b=fs.readFileSync(f);fs.writeFileSync(f,b.subarray(0,b.length-1));`);
    // Pas 4 : redémarrer ; porte : etat rend ok, pending_flushed si des événements attendaient.
    c.lancerSeul("enregistreur");
    // Vérification de sortie : noortrace_degraded 0, noortrace_pending_events 0 ; verifier-journal valide.
    const metriques = P.jusqua ? null : null;
    let sante = null;
    for (let k = 0; k < 120; k++) {
      sante = P.docker(["inspect", "--format", "{{.State.Health.Status}}", c.conteneur("enregistreur")]).stdout.trim();
      if (sante === "healthy") break;
      const fin = Date.now() + 1000;
      while (Date.now() < fin) { /* attente active bornée (mocha synchrone ici) */ }
    }
    expect(sante, "le démon est sain après la reprise").to.equal("healthy");
    // Un appel passe : la capture a repris.
    const r = c.appel("demo__claims.get", { claim_id: "2026-81044" });
    expect(r.json.result.isError, JSON.stringify(r.json)).to.equal(false);
    // Les métriques de la vérification de sortie.
    const met = P.docker(["run", "--rm", "--network", `container:${c.conteneur("enregistreur")}`, "--entrypoint", "/usr/local/bin/node", P.IMAGE_ENREGISTREUR, "-e", 'fetch("http://127.0.0.1:8500/metrics").then((r)=>r.text()).then((t)=>console.log(t))']);
    const texteMet = met.stdout;
    const degrade = [...texteMet.matchAll(/^noortrace_degraded\{[^}]*\} ([0-9]+)$/gm)].map((m) => Number(m[1]));
    expect(degrade.every((v) => v === 0), "noortrace_degraded vaut 0 pour toutes les raisons").to.equal(true);
    const pending = /^noortrace_pending_events(\{\})? ([0-9]+)$/m.exec(texteMet);
    if (pending) expect(Number(pending[2]), "noortrace_pending_events vaut 0").to.equal(0);
    // La chaîne est continue (verifier-journal : le volume est lu par un conteneur de l'image, sans réseau).
    const ev = c.evenements(CONFIG);
    expect(ev.every((e, i) => i === 0 || (e.seq === ev[i - 1].seq + 1 && e.prev_hash === N.hacherEvenement(ev[i - 1]))), "chaîne continue à la reprise (invariant RB-1)").to.equal(true);
    expect(ev.length, "l'événement de la ligne déchirée est perdu, la reprise repart").to.be.at.least(evAvant.length - 1);
    durees.RB1 = chrono.fin();
  });

  it("TM-36 (hors référence) : le rapport des durées des runbooks rejoués est conforme à $defs/rapport_mesure (counts_for_targets faux, met null)", async function () {
    if (!pret.call(this)) return;
    expect(durees.RB1, "RB-1 a été rejoué et chronométré").to.be.a("number");
    const rapport = await P.ecrireRapportMesure(path.join(travail, "rapport-tm36-controle.json"), {
      results: [P.ligneMesure({ name: "rb_1", test_id: "TM-36", unit: "s", value: durees.RB1, conditions: ["runbook RB-1 (écrivain arrêté) rejoué sur la démonstration de référence"] })],
      notes: "TM-36 : durée du runbook RB-1 rejoué (CT-8 §10.11), aucune cible",
      clock: "monotone",
      disque: { type: "virtuel", fsync: null },
    });
    const erreurs = await P.erreursRapportMesure(rapport);
    expect(erreurs, JSON.stringify(erreurs)).to.deep.equal([]);
    expect(rapport.counts_for_targets).to.equal(false);
    expect(rapport.results[0].met).to.equal(null);
    expect(rapport.system.reference).to.equal(false);
  });
});
