// Vecteurs de CT-2 attribués au moteur de politique (INTERFACES.md, section
// d), rejoués de bout en bout par le frontal MCP, le moteur de politique, le
// cœur et un service d'approbation simulé d'après CT-3 §12 :
//   - pieces-mcp/appels/approbation-en-attente : ré-émission reconnue d'un
//     ticket en attente, hôte hérité, mode erreur ; ligne rendue octet pour
//     octet, aucun événement, aucun relais, pièce « arguments » du pas 4 ;
//   - pieces-mcp/appels/approbation-refus : refus par la politique sans
//     ticket, hôte moderne ; ligne rendue octet pour octet, événement
//     `refusee`, pièces stockées ;
//   - evenements/journal-demo, seq 5 à 7 : appel retenu, décision
//     d'approbation remise et scellée, ré-émission relayée après approbation
//     (EX-7.12), champs des événements publiés (hors enveloppe, horodatages et
//     signatures des approbateurs, qui dépendent du request_hash) ;
//   - spec/vecteurs/ct-3/politiques et politiques-invalides : validation de
//     policy.approval.rules par le démon (CT-3 EX-4.2, EX-8.2, AP-1 à AP-4).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { utf8 } from "@noortrace/noyau";
import { Coeur, FrontalMcp, Piece, analyserJsonIntegral, lireEvenements, validerPolitiqueApprobation } from "@noortrace/enregistreur";
import { SPEC, VECTEURS_CT2, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { EnfantFactice, RedacteurTest, hoteDemo, serveurStdio, reglageOutil } from "./fixtures/enregistreur-mcp/outils.mjs";
import { ServiceSimule, HorlogeDecalee, configurationPolitique, attendre } from "./fixtures/enregistreur-politique/outils.mjs";

const lireJson = (rel) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, rel), "utf8"));
const lignesJsonl = (rel) =>
  fs
    .readFileSync(path.join(VECTEURS_CT2, rel), "utf8")
    .split("\n")
    .filter((l) => l.length)
    .map((l) => JSON.parse(l));

/** Lanceur des serveurs stdio : enfant factice qui sert une liste et répond aux appels. */
function lanceurFactice(listes, appel = () => ({ content: [], isError: false }), enfants = []) {
  return (p) => {
    const e = new EnfantFactice((ligne, enfant) => {
      const m = JSON.parse(ligne);
      if (m.id === undefined) return;
      const repondre = (result) => setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, result })));
      if (m.method === "server/discover") repondre({ resultType: "complete", supportedVersions: ["2026-07-28"], capabilities: { tools: { listChanged: true } }, serverInfo: { name: p.alias, version: "1.0.0" } });
      else if (m.method === "tools/list") repondre({ resultType: "complete", tools: listes[p.alias] ?? [], cacheScope: "private" });
      else if (m.method === "tools/call") repondre(appel(m));
      else setImmediate(() => enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "Method not found" } })));
    });
    enfants.push(e);
    return e;
  };
}

/** Définitions telles que le serveur les annonce : nom d'origine sans le préfixe `<alias>__`. */
function parServeur(definitions) {
  const r = {};
  for (const d of definitions) {
    const k = d.name.indexOf("__");
    const alias = d.name.slice(0, k);
    (r[alias] ??= []).push({ ...d, name: d.name.slice(k + 2) });
  }
  return r;
}

async function monter({ policy, servers, lanceur, decider, nommer, correlateur, reponseForcee }) {
  const dir = repertoireTemporaire("noortrace-politique-vec-");
  const { config } = configurationPolitique(dir);
  if (policy) config.policy = policy;
  config.policy.servers = servers;
  config.mcp.hosts = [hoteDemo()];
  config.checkpoint_interval_s ??= 60;
  const service = new ServiceSimule({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider, nommer });
  const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), service, horloge: new HorlogeDecalee() });
  const redacteur = new RedacteurTest();
  const frontal = new FrontalMcp({ coeur, redacteur, correlateur: correlateur ?? null, lanceur });
  await frontal.demarrer();
  await attendre(() => coeur.candidats !== null);
  service.reponseForcee = reponseForcee ?? null;
  const session = frontal.ouvrirSession({ hote: config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio" });
  return {
    config,
    coeur,
    frontal,
    service,
    redacteur,
    session,
    async arreter() {
      service.liberer();
      await frontal.arreter();
      await coeur.arreter();
    },
  };
}

/** Rejoue une transcription hote.jsonl : chaque ligne `out` est comparée, octet pour octet, à la réponse du frontal. */
async function rejouerHote(b, lignes) {
  let derniere;
  for (const l of lignes) {
    if (l.dir === "in") {
      derniere = await b.frontal.recevoir(b.session, l.line);
    } else {
      expect(derniere, l.line.slice(0, 60)).to.equal(l.line);
    }
  }
}

describe("enregistreur, moteur de politique : vecteurs de CT-2 et de CT-3", function () {
  this.timeout(60000);

  for (const cas of ["approbation-en-attente", "approbation-refus"]) {
    describe(`pieces-mcp/appels/${cas} (B.4), de bout en bout`, function () {
      const R = `pieces-mcp/appels/${cas}`;
      let attendu;
      let b;
      let hote;
      let avant;
      before(async function () {
        attendu = lireJson(`${R}/attendu.json`);
        hote = lignesJsonl(`${R}/hote.jsonl`);
        expect(fs.readFileSync(path.join(VECTEURS_CT2, R, "amont.jsonl"), "utf8")).to.equal("");
        // La liste servie : définitions de la liste annoncée (pièce « liste annoncée »).
        const liste = JSON.parse(attendu.pieces.list.bytes).tools;
        // Les membres des définitions servies gardent l'ordre de la ligne tools/list publiée.
        const ligneListe = hote.find((l) => l.dir === "out" && l.line.includes('"tools":['));
        const servies = ligneListe ? JSON.parse(ligneListe.line).result.tools : liste;
        const enfants = [];
        b = await monter({
          servers: {
            archives: serveurStdio(["serveur-factice"], { protocol: "2026-07-28" }),
            demo: serveurStdio(["serveur-factice"], { protocol: "2026-07-28", tools: { "payments.create": reglageOutil({ class: "ecriture" }) } }),
          },
          lanceur: lanceurFactice(parServeur(servies), undefined, enfants),
          reponseForcee: () => attendu.approval.response,
        });
        b.enfants = enfants;
        if (attendu.protocols.host !== "2026-07-28") {
          // Hôte hérité : poignée de main (hors transcription).
          await b.frontal.recevoir(b.session, JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: attendu.protocols.host, capabilities: {}, clientInfo: { name: "agent-demo", version: "0.1.0" } } }));
          await b.frontal.recevoir(b.session, JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
        } else {
          await b.frontal.recevoir(
            b.session,
            JSON.stringify({ jsonrpc: "2.0", id: "liste-0", method: "tools/list", params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": { name: "agent-demo", version: "0.1.0" } } } }),
          );
        }
        avant = (await lireEvenements(b.coeur.repertoire)).length;
        await rejouerHote(b, hote);
      });
      after(async function () {
        await b?.arreter();
      });

      it("la ligne rendue à l'hôte est celle de la transcription, octet pour octet (EX-4.49), et rend result_rendered", function () {
        const sortie = hote.filter((l) => l.dir === "out").at(-1);
        expect(JSON.parse(sortie.line).result).to.deep.equal(attendu.result_rendered);
      });

      it("evaluer porte l'outil, les arguments en clair, la classe et les pièces de contexte attendues (EX-7.4)", function () {
        const e = b.service.messages.filter((m) => m.methode === "evaluer").at(-1).corps;
        expect([e.tool_announced, e.tool_original, e.server_alias, e.class]).to.deep.equal([attendu.tool_announced, attendu.tool_original, attendu.server_alias, attendu.class]);
        const appel = JSON.parse(hote.filter((l) => l.dir === "in").at(-1).line);
        expect(e.arguments).to.deep.equal(appel.params.arguments);
        expect(e.context.map((c) => [c.sha256, c.length])).to.deep.equal(attendu.context.map((c) => [c.sha256, c.length]));
      });

      it("la pièce « arguments » du pas 4 est celle du vecteur ; aucun relais (amont.jsonl vide)", function () {
        const p = b.redacteur.pieces.filter((x) => x.portee === "arguments").at(-1).piece;
        expect([p.reference.sha256, p.reference.length, p.reference.redacted]).to.deep.equal([attendu.pieces.arguments.sha256, attendu.pieces.arguments.length, attendu.pieces.arguments.redacted]);
        expect(new TextDecoder().decode(p.octets)).to.equal(attendu.pieces.arguments.bytes);
        const amont = b.enfants.flatMap((e) => e.ecrit);
        expect(amont.length).to.be.greaterThan(0);
        expect(amont.filter((l) => l.includes('"tools/call"'))).to.deep.equal([]);
      });

      it(cas === "approbation-refus" ? "un événement refusee (policy.decision refuse, ticket null), pièces stockées" : "aucun événement (CT-3 EX-7.19), approval_pending consigné", async function () {
        const evts = await lireEvenements(b.coeur.repertoire);
        if (cas === "approbation-en-attente") {
          expect(evts.length).to.equal(avant);
          expect(b.coeur.journal.trouver("approval_pending").length).to.equal(1);
          return;
        }
        expect(evts.length).to.equal(avant + 1);
        const e = evts.at(-1);
        expect(e.execution.tool).to.equal(attendu.tool_announced);
        expect(e.execution).to.include({ status: "refusee", result: null, duration_ms: null, is_error: null });
        expect(e.policy).to.deep.equal({ rule: attendu.approval.response.rule, decision: "refuse", ticket: null, redaction: b.config.policy.redaction.name });
        expect(e.approval).to.equal(null);
        expect(e.effects).to.deep.equal([]);
        expect(e.execution.arguments).to.deep.equal({ sha256: attendu.pieces.arguments.sha256, length: attendu.pieces.arguments.length, redacted: true });
        expect(e.context).to.deep.equal(attendu.context);
        for (const ref of [e.execution.arguments, ...e.context]) expect(fs.existsSync(b.coeur.pieces.chemin(ref.sha256)), ref.sha256).to.equal(true);
      });
    });
  }

  describe("evenements/journal-demo (B.6), seq 5 à 7, de bout en bout", function () {
    const R = "evenements/journal-demo";
    let publies;
    let produits;
    let b;
    let resultat;
    before(async function () {
      publies = lireJson(`${R}/evenements.json`);
      const entrees = lireJson(`${R}/entrees.json`);
      const pieces = lireJson(`${R}/pieces.json`);
      const politique = lireJson(`${R}/politique.json`);
      // Transport stdio factice à la place du serveur HTTP de la démonstration (hors des champs comparés).
      politique.servers.demo.transport = serveurStdio(["serveur-factice"]).transport;
      const e5 = publies[4];
      const e7 = publies[6];
      const piece = (sha) => pieces.find((p) => p.sha256 === sha);
      resultat = analyserJsonIntegral(utf8(piece(e7.execution.result.sha256).bytes));
      // Corrélation (5.6) : celle de seq 5 ; la ré-émission (seq 7) n'est pas corrélée (EX-7.12).
      const pIntent = piece(e5.intent.sha256);
      const pieceIntention = new Piece(utf8(pIntent.bytes), { redacted: pIntent.redacted, media_type: pIntent.media_type });
      let n = 0;
      const correlateur = {
        correler: () => (++n === 1 ? { intent: pieceIntention.reference, code: { model: e5.code.model, prompt_version: e5.code.prompt_version }, seq: 4 } : null),
      };
      b = await monter({
        policy: politique,
        servers: politique.servers,
        lanceur: lanceurFactice(parServeur(entrees.served_list), () => resultat),
        decider: (r) => (r.tool_announced === "demo__payments.create" ? { decision: "a_approuver", rule: e5.policy.rule } : { decision: "autorise", rule: null }),
        nommer: () => e5.policy.ticket,
        correlateur,
      });
      await b.coeur.ecrirePiece(pieceIntention);
      await b.frontal.recevoir(b.session, JSON.stringify({ jsonrpc: "2.0", id: "agent-demo-liste", method: "tools/list", params: { _meta: JSON.parse(entrees.calls[1].host_line).params._meta } }));
      produits = {};
      // seq 5 : appel retenu, mode erreur, signal en_attente.
      const r5 = JSON.parse(await b.frontal.recevoir(b.session, entrees.calls[1].host_line));
      expect(r5.result._meta["noortrace/approval"]).to.deep.equal({ ticket: e5.policy.ticket, state: "en_attente" });
      produits[5] = (await lireEvenements(b.coeur.repertoire)).at(-1);
      // seq 6 : les comptes Hardhat 1 et 2 votent ; remise vérifiée (SG-1 à SG-7) et scellée.
      await attendre(() => b.service.tickets.get(e5.policy.ticket)?.request);
      b.service.decider_ticket(e5.policy.ticket, { reason: publies[5].approval.reason });
      const acq = await b.coeur.traiterRemises();
      expect(acq.map((x) => x.result)).to.deep.equal(["scelle"]);
      produits[6] = (await lireEvenements(b.coeur.repertoire)).at(-1);
      // seq 7 : ré-émission approuvée, relayée.
      const r7 = JSON.parse(await b.frontal.recevoir(b.session, entrees.calls[2].host_line));
      expect(r7.result.structuredContent).to.deep.equal(resultat.structuredContent);
      produits[7] = (await lireEvenements(b.coeur.repertoire)).at(-1);
    });
    after(async function () {
      await b?.arreter();
    });

    const champs = (e) => ({ delegation: e.delegation, code: e.code, intent: e.intent, policy: e.policy, effects: e.effects, context: e.context });

    it("seq 5 : l'appel retenu a les champs publiés (délégation, code corrélé, intention, policy, pièces, contexte)", function () {
      const p = publies[4];
      expect(champs(produits[5])).to.deep.equal(champs(p));
      expect(produits[5].approval).to.equal(null);
      expect(produits[5].execution).to.deep.equal(p.execution);
      // EX-7.4 : l'intention, portée par une référence, est transmise à evaluer par le texte de sa pièce.
      const e = b.service.messages.filter((m) => m.methode === "evaluer")[0].corps;
      expect(e.intent).to.equal(lireJson(`${R}/pieces.json`).find((x) => x.sha256 === p.intent.sha256).bytes);
    });

    it("seq 6 : la décision reprend délégation et code de la retenue (lecture 1), approval de la remise, at = ts (EX-7.11)", function () {
      const p = publies[5];
      const e = produits[6];
      expect(champs(e)).to.deep.equal({ ...champs(p), code: p.code });
      const sansLien = ({ request_hash, signatures, at, ...x }) => (void request_hash, void signatures, void at, x);
      expect(sansLien(e.approval)).to.deep.equal(sansLien(p.approval));
      expect(e.approval.request_hash).to.equal(produits[5].hash);
      expect(e.approval.at).to.equal(e.ts);
      expect(e.execution.tool).to.equal(p.execution.tool);
      expect(Object.keys(e.execution.arguments.value).sort()).to.deep.equal(Object.keys(p.execution.arguments.value).sort());
      expect(e.execution.arguments.value.request_hash).to.equal(produits[5].hash);
    });

    it("seq 7 : la ré-émission relayée reprend la retenue clé pour clé (EX-7.12), porte l'approval scellé, le résultat et les effets publiés", function () {
      const p = publies[6];
      const e = produits[7];
      expect(champs(e)).to.deep.equal(champs(p));
      expect(e.approval).to.deep.equal(produits[6].approval);
      const { duration_ms, ...ex } = e.execution;
      const { duration_ms: d2, ...px } = p.execution;
      void duration_ms;
      void d2;
      expect(ex).to.deep.equal(px);
      // Consommation de l'approbation (EX-7.20).
      return attendre(() => b.service.messages.some((m) => m.methode === "consommer" && m.corps.seq === e.seq));
    });

    it("la remise passe SG-1 à SG-7 et est acquittée scelle ; retenue et décision ont leurs lignes des fichiers des approbations (EX-12.23)", function () {
      const remise = b.service.messages.find((m) => m.methode === "acquitter").corps;
      expect(remise.result).to.equal("scelle");
      const l = b.coeur.approbations.retenues.get(publies[4].policy.ticket)[0];
      expect(l).to.include({ request_hash: produits[5].hash, request_seq: produits[5].seq });
      expect(b.coeur.approbations.decisions.get(publies[4].policy.ticket)).to.include({ hash: produits[6].hash });
    });
  });

  describe("spec/vecteurs/ct-3 : validation de policy.approval.rules (CT-3 EX-4.2, EX-8.2 ; AP-1 à AP-4)", function () {
    const D = path.join(SPEC, "vecteurs", "ct-3");
    it("chaque politique invalide rend exactement les erreurs attendues, triées par pointeur puis par code", function () {
      const a = JSON.parse(fs.readFileSync(path.join(D, "politiques-invalides", "attendu.json"), "utf8"));
      expect(a.cases.length).to.be.greaterThan(25);
      for (const c of a.cases) {
        const doc = JSON.parse(fs.readFileSync(path.join(D, "politiques-invalides", c.file), "utf8"));
        expect(validerPolitiqueApprobation(doc, { environment: c.environment, expire_after_ms: c.expire_after_ms }), c.file).to.deep.equal(c.errors);
      }
    });

    it("chaque politique valide est admise", function () {
      const noms = fs.readdirSync(path.join(D, "politiques"));
      expect(noms.length).to.be.greaterThan(5);
      for (const n of noms) {
        const doc = JSON.parse(fs.readFileSync(path.join(D, "politiques", n), "utf8"));
        expect(validerPolitiqueApprobation(doc, { environment: "developpement", expire_after_ms: 3600000 }), n).to.deep.equal([]);
      }
    });
  });
});
