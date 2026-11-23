// Démonstration de référence en une commande (CT-2 §19 ; CT-9 TE-3) : la
// composition `demo/compose.yaml` est lancée sous un projet Compose propre à
// l'essai, jusqu'au verdict imprimé par le service `verificateur`.
//
// En attente, condition nommée, sans démon Docker ou sans les huit images
// `noortrace/*:0.1.0` dans le magasin local : les images se construisent par
// `node scripts/deploiement/construire-images.mjs` et
// `node demo/construire-images.mjs`, jamais par un essai. Aucun essai ne
// joint un réseau public : les quatre réseaux de la composition sont
// internes, et le cinquième ne publie que le port de santé sur la boucle
// locale, sans traduction d'adresse en sortie.
//
// La durée imprimée est comparée à la cible de CT-2 EX-19.1 (moins de 120 s)
// parce que l'oracle de TE-3 le demande ; la mesure qui compte pour la cible
// est celle de TM-43, sur le système de référence (`demo/mesurer-duree.mjs`).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import {
  Composition, DEMO, RACINE, binaireGo, dureeImprimee, enAttente, etatDocker, normaliser, portLibre, repertoireTemporaire, sortieDeLaSpecification, verifierGo, verifierJs,
} from "./fixtures/demonstration/outils.mjs";

const CONFIG = JSON.parse(fs.readFileSync(path.join(DEMO, "configuration-demo.json"), "utf8"));
const ANCRES = path.join(DEMO, "ancres-demo.json");
const CLES_APPROBATEURS = JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-3", "constantes.json"), "utf8")).accounts.filter((a) => [1, 2, 3].includes(a.index)).map((a) => a.private_key.slice(2));

describe("CT-9 TE-3 : démonstration de référence en une commande (CT-2 §19), composition lancée", function () {
  this.timeout(600000);
  let ctx = null;
  let c = null;
  let travail = null;

  before(async function () {
    const etat = etatDocker();
    if (!etat.ok) {
      ctx = { condition: etat.condition };
      return;
    }
    travail = repertoireTemporaire("noortrace-demonstration-");
    c = new Composition({ nom: `noortrace-demo-essai-${process.pid}`, port: await portLibre() });
    const t0 = Date.now();
    c.lancer();
    const code = c.attendre("verificateur", 300000);
    ctx = { code, murale_s: (Date.now() - t0) / 1000, sortie: c.journal("verificateur"), agent: c.journal("agent-demo"), exploitation: c.journal("exploitation-demo") };
  });

  after(function () {
    if (c) c.demonter();
    if (travail) fs.rmSync(travail, { recursive: true, force: true });
  });

  function pret() {
    if (!ctx || ctx.condition) {
      enAttente(this, ctx?.condition ?? "composition non lancée");
      return false;
    }
    return true;
  }

  it("TE-3 : docker compose up, puis fin du service verificateur : code 0 ; sortie égale à CT-2 §19.4 (texte fixe mot pour mot, valeurs variables au format) ; 8 événements, clé rec-test-01 de classe D, bail file, époque 1 ; clé inscrite, période enregistrée, racine ancrée, bloc certifié par un quorum ; six contrôles réussis, deux non exécutés (T-*, O-*) ; « Il ne prouve pas la date » ; durée imprimée à la milliseconde, inférieure à 120 s", function () {
    if (!pret.call(this)) return;
    expect(ctx.code, `${ctx.sortie}\n${ctx.agent}\n${ctx.exploitation}`).to.equal(0);
    const lignes = ctx.sortie.replace(/\n$/, "").split("\n");
    const attendue = sortieDeLaSpecification();
    expect(lignes.map(normaliser)).to.deep.equal(attendue.map(normaliser));
    expect(lignes[1]).to.equal("  enregistreur    : 0.1.0, clé rec-test-01 (classe D, démonstration), bail file, époque 1");
    expect(lignes[2]).to.match(/^ {2}journal {9}: assureur-demo \/ journal-demo, 8 événements, période [0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:00:00Z → [0-9]{2}:00:00Z$/);
    expect(lignes[3]).to.match(/^ {2}registre-dev {4}: clé inscrite \(RecorderRegistry\), période enregistrée \(PeriodRegistry\), racine ancrée \(AttestationRegistry\), bloc certifié par [34] validateurs$/);
    expect(lignes[4]).to.equal("  dossier         : dossiers/seq-7/ (demo__payments.create, approuvé par 0x7099…79c8 et 0x3c44…93bc, seuil 2 sur 3)");
    expect(lignes[5]).to.equal("  vérificateur    : 6 contrôles [ok], 2 non exécutés avec raison admise (T-*, O-* : démonstration hors ligne)");
    expect(lignes[8]).to.equal("             Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne).");
    expect(lignes[10]).to.equal("  le résultat de payments.create avant qu'un événement durable existe ; effacer seq 5 (sa demande retenue).");
    const duree = dureeImprimee(ctx.sortie);
    expect(duree, lignes.at(-1)).to.be.a("number");
    expect(duree).to.be.below(120);
    // La durée imprimée court du démarrage du processus verificateur à l'impression : elle ne dépasse pas la durée murale de la commande.
    expect(duree).to.be.at.most(ctx.murale_s);
  });

  it("TE-3, MN-1 (CT-2 §4.9) : agent-demo n'est attaché qu'au réseau hotes ; il a tenté de joindre outils-demo et modele-demo par leur nom et affiché qu'il ne joint que l'enregistreur ; le serveur d'outils n'a reçu que les deux appels que l'enregistreur a relayés", function () {
    if (!pret.call(this)) return;
    const i = c.inspecter("agent-demo");
    expect(Object.keys(i.NetworkSettings.Networks)).to.deep.equal([c.ressource("hotes")]);
    expect(i.State.ExitCode).to.equal(0);
    expect(i.Mounts).to.deep.equal([]);
    expect(ctx.agent).to.match(/agent-demo : connexion directe, sans l'enregistreur : outils-demo:8000 injoignable \([A-Z_]+\) ; modele-demo:8080 injoignable \([A-Z_]+\)/);
    expect(ctx.agent).to.include("agent-demo : l'agent ne joint que l'enregistreur");
    expect(ctx.agent).to.include("agent-demo : demo__payments.create : en attente d'approbation (ticket apr-");
    expect(ctx.agent).to.include("agent-demo : demo__payments.create : exécuté après approbation (PAY-2026-90417)");
    // Compteur du serveur d'outils, lu depuis son propre réseau : claims.get et payments.create, relayés une fois chacun.
    const sante = c.executer("outils-demo", 'fetch("http://outils-demo:8000/sante").then((r)=>r.text()).then((t)=>console.log(t))');
    expect(sante.code, sante.stderr).to.equal(0);
    expect(JSON.parse(sante.stdout.trim().split("\n").at(-1))).to.deep.equal({ ok: true, appels: 2 });
  });

  it("CT-2 §19.2 : le journal porte les huit événements de la séquence, dans l'ordre : politique demo-2026-12, échange de modèle, claims.get relayé, échange en flux à la réponse rédigée, payments.create retenu (a_approuver), décision approuvée par les comptes 1 et 2, payments.create exécuté avec ses effets (système demo, écriture, PAY-2026-90417, 7400.00 CHF), échange de fin de tour", function () {
    if (!pret.call(this)) return;
    const ev = c.evenements(CONFIG);
    expect(ev.map((e) => [e.seq, e.execution.tool, e.execution.status])).to.deep.equal([
      [1, "noortrace.journal.politique", "executee"], [2, "noortrace.modele.echange", "executee"], [3, "demo__claims.get", "executee"], [4, "noortrace.modele.echange", "executee"],
      [5, "demo__payments.create", "retenue"], [6, "noortrace.approbation.decision", "executee"], [7, "demo__payments.create", "executee"], [8, "noortrace.modele.echange", "executee"],
    ]);
    expect(ev[0].code.policy_version).to.equal("demo-2026-12");
    expect(ev[1].code.model).to.equal("demo/modele-demo-1");
    expect(ev[1].delegation).to.deep.include({ launched_by: "agent-demo", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement" });
    expect(ev[3].execution.result.redacted).to.equal(true);
    expect(ev[4].policy).to.deep.include({ decision: "a_approuver", rule: "montant > 5000" });
    expect(ev[4].policy.ticket).to.match(/^apr-/);
    expect(ev[5].approval).to.deep.include({ decision: "approuve", ticket: ev[4].policy.ticket, approvers: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"] });
    expect(ev[5].approval.at).to.equal(ev[5].ts);
    expect(ev[6].policy).to.deep.include({ decision: "a_approuver", rule: "montant > 5000", ticket: ev[4].policy.ticket });
    expect(ev[6].effects).to.deep.equal([{ system: "demo", action: "ecriture", object: "PAY-2026-90417", amount: "7400.00", currency: "CHF" }]);
    expect(ev[6].approval.ticket).to.equal(ev[4].policy.ticket);
    for (const e of ev) expect(e.recorder_key_id).to.equal("rec-test-01");
    // Ligne startup du journal d'exploitation : mode passerelle, classe D, époque 1 (TA-14, partie sur la démonstration).
    const demarrage = c.journalExploitation().find((l) => l.event === "startup");
    expect(demarrage.data).to.deep.include({ class: "D", backend: "file", recorder_key_id: "rec-test-01", model_mode: "passerelle", epoch: 1 });
  });

  it("TE-3 : le dossier de seq 7, sorti du volume des exports, est vérifié hors ligne par les deux vérificateurs de CT-6 (référence JavaScript et binaire Go) : verdict incomplet, code 3, pour les seules pièces d'essai (CT-6 EX-6.26), contrôles 1, 2, 3, 6, 7 et 8 réussis, 4 et 5 non exécutés pour partie absente, mêmes statuts de vérification et même énoncé ; l'inscription de la clé y est prouvée (R-10 réussie, aucun avertissement)", function () {
    if (!pret.call(this)) return;
    const copie = c.extraire("exports", "dossiers/seq-7", path.join(travail, "seq-7"));
    expect(fs.readdirSync(copie).sort()).to.deep.equal(["approbations.json", "certificat-commit.json", "chemin.json", "cles.json", "dossier.json", "evenement.json", "manifeste.json", "manifeste.sig", "points-de-controle.json", "registre.json", "validateurs.json", "voisins.json"]);
    const index = JSON.parse(fs.readFileSync(path.join(copie, "dossier.json"), "utf8"));
    expect(index.parts.filter((p) => !p.present).map((p) => p.file).sort()).to.deep.equal(["jeton-rfc3161.der", "preuve.ots"]);
    const js = verifierJs(copie, ANCRES);
    // Complément du 2026-11-23 de CT-6 (EX-6.26) : la démonstration signe avec rec-test-01, approuve avec des comptes
    // Hardhat et inscrit au registre de développement, pièces d'essai : rien n'échoue, mais le code est 3, non 0, et le
    // rapport dit pourquoi (EX-8.12).
    expect([js.code, js.rapport.incomplete_reasons], js.stderr).to.deep.equal([3, ["piece_essai"]]);
    expect(js.rapport.verdict).to.equal("incomplet");
    expect(js.rapport.controls.map((x) => [x.number, x.status, x.reason])).to.deep.equal([[1, "reussi", null], [2, "reussi", null], [3, "reussi", null], [4, "non_execute", "partie_absente"], [5, "non_execute", "partie_absente"], [6, "reussi", null], [7, "reussi", null], [8, "reussi", null]]);
    expect(js.rapport.failed_checks).to.deep.equal([]);
    // Aucun avertissement hors ceux des pièces d'essai (EX-6.24), qui sont présents.
    const ESSAI = ["AV-O-3", "AV-T-5", "AV-R-4", "AV-N-1", "AV-N-2"];
    expect(js.rapport.warnings.filter((w) => !ESSAI.includes(w.id))).to.deep.equal([]);
    expect(js.rapport.warnings.some((w) => ESSAI.includes(w.id))).to.equal(true);
    expect(js.rapport.checks.find((x) => x.id === "R-10").status).to.equal("reussi");
    expect(js.rapport.facts.registry.entries.map((e) => e.role).sort()).to.deep.equal(["ancre", "ancre_point_de_controle", "cloture", "inscription"]);
    expect(js.rapport.statement.fr).to.include("ce dossier ne prouve rien sur la date de son manifeste");
    const go = verifierGo(copie, ANCRES);
    if (!go) return enAttente(this, "binaire du vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN) : vérification JavaScript faite, vérification Go faite seulement dans le conteneur verificateur");
    expect([go.code, go.rapport.incomplete_reasons], go.stderr).to.deep.equal([3, ["piece_essai"]]);
    expect(go.rapport.verdict).to.equal("incomplet");
    const statuts = (r) => Object.fromEntries(r.checks.map((x) => [x.id, x.status]));
    expect(statuts(go.rapport)).to.deep.equal(statuts(js.rapport));
    expect(go.rapport.statement.fr).to.equal(js.rapport.statement.fr);
    expect(binaireGo()).to.be.a("string");
  });

  it("CT-2 EX-19.4 : après la clôture anticipée, le journal est terminé : un nouvel appel d'outil est refusé (-31010, journal_clos) et un nouvel échange de modèle rend 503 avec le corps d'erreur du format (raison journal_clos au journal d'exploitation) ; aucun événement n'est ajouté", function () {
    if (!pret.call(this)) return;
    const avant = c.evenements(CONFIG).length;
    const script = `
      const env = process.env;
      const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "agent-demo", version: "0.1.0" } };
      (async () => {
        const a = await fetch(env.NOORTRACE_MCP_URL, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: "Bearer " + env.NOORTRACE_MCP_TOKEN, "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "demo__claims.get" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "demo__claims.get", arguments: { claim_id: "2026-81044" }, _meta: meta } }) });
        const m = await fetch(env.ANTHROPIC_BASE_URL + "/v1/messages", { method: "POST", headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": "x", "x-noortrace-token": env.NOORTRACE_GATEWAY_TOKEN }, body: JSON.stringify({ model: "modele-demo-1", max_tokens: 16, messages: [{ role: "user", content: "Traite le sinistre 2026-81044." }] }) });
        console.log(JSON.stringify({ appel: JSON.parse(await a.text()), modele: m.status, corps: await m.text() }));
      })();`;
    const r = c.executer("agent-demo", script);
    expect(r.code, r.stderr).to.equal(0);
    const o = JSON.parse(r.stdout.trim().split("\n").at(-1));
    expect(o.appel.error.code, JSON.stringify(o.appel)).to.equal(-31010);
    expect(o.appel.error.data.reason).to.equal("journal_clos");
    // Corps d'erreur du format de la route (CT-2 14.2) ; la raison `journal_clos` est celle de la ligne call_blocked du journal d'exploitation.
    expect(o.modele, o.corps).to.equal(503);
    expect(JSON.parse(o.corps)).to.deep.equal({ type: "error", error: { type: "noortrace_degrade", message: "noortrace: echange bloque, enregistreur en mode degrade" } });
    expect(c.evenements(CONFIG).length).to.equal(avant);
    const journal = c.journalExploitation();
    expect(journal.filter((l) => l.event === "period_closed_early")).to.have.lengthOf(1);
    expect(journal.filter((l) => l.component === "frontal_modele" && l.event === "call_blocked" && l.data?.reason === "journal_clos" && l.data?.code === 503)).to.have.lengthOf(1);
  });

  it("CT-3 EX-3.3 : aucune clé d'approbateur dans l'environnement d'un conteneur ; le service d'approbation tourne sans réseau, l'exploitation dans l'espace de processus de l'enregistreur et sans réseau, le vérificateur sans réseau et avec le volume des exports en lecture seule", function () {
    if (!pret.call(this)) return;
    for (const service of ["registre-dev", "outils-demo", "modele-demo", "approbateur-demo", "approbation", "enregistreur", "agent-demo", "exploitation-demo", "verificateur"]) {
      const i = c.inspecter(service);
      const env = i.Config.Env.join("\n").toLowerCase();
      for (const k of CLES_APPROBATEURS) expect(env.includes(k), `${service} : clé d'approbateur dans l'environnement`).to.equal(false);
      expect(i.HostConfig.ReadonlyRootfs, service).to.equal(true);
      expect(i.HostConfig.CapDrop, service).to.deep.equal(["ALL"]);
    }
    expect(c.inspecter("approbation").HostConfig.NetworkMode).to.equal("none");
    expect(c.inspecter("verificateur").HostConfig.NetworkMode).to.equal("none");
    expect(c.inspecter("verificateur").Mounts.find((m) => m.Destination === "/var/lib/noortrace-exports").RW).to.equal(false);
    const exploitation = c.inspecter("exploitation-demo");
    expect(exploitation.HostConfig.NetworkMode).to.equal("none");
    expect(exploitation.HostConfig.PidMode).to.equal(`container:${c.inspecter("enregistreur").Id}`);
    expect(exploitation.State.ExitCode).to.equal(0);
    // Le démon est sain après la démonstration, et le port de santé est le seul publié.
    const ports = Object.fromEntries(["registre-dev", "outils-demo", "modele-demo", "approbateur-demo", "enregistreur"].map((s) => [s, Object.entries(c.inspecter(s).NetworkSettings.Ports ?? {}).filter(([, v]) => v).map(([k, v]) => `${v[0].HostIp}:${k}`)]));
    expect(ports).to.deep.equal({ "registre-dev": [], "outils-demo": [], "modele-demo": [], "approbateur-demo": [], enregistreur: ["127.0.0.1:8500/tcp"] });
  });
});
