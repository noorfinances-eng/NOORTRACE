// Frontal MCP (CT-2 §4) : rejeu des vecteurs `spec/vecteurs/ct-2/pieces-mcp`
// contre le frontal lui-même, écrit d'après le seul texte de la
// spécification.
//
//   - pieces-mcp/appels/* : chaque transcription est rejouée de bout en bout.
//     L'hôte simulé envoie les lignes `in` de hote.jsonl à leur horodatage ;
//     l'enfant stdio factice du serveur d'outils reçoit ce que le frontal
//     écrit et répond par les lignes `in` d'amont.jsonl (ou par une fin de
//     fichier) ; l'horloge suit les horodatages, de sorte que `duration_ms`
//     est celui de la transcription. Sont comparés octet pour octet : chaque
//     ligne envoyée au serveur, chaque ligne rendue à l'hôte ; puis
//     l'événement scellé (arguments, résultat, contexte, durée, erreur) et
//     les octets des pièces stockées ; le journal est vérifié par le noyau.
//   - pieces-mcp/agregation : noms annoncés, rejets, classes, empreintes,
//     pages, refus de configuration sans préfixe.
//   - evenements/journal-demo/entrees.json : les appels de seq 3, 5 et 7
//     relayés par le frontal donnent les pièces publiées.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, FrontalMcp, validerConfiguration, lireEvenements, clesDuJournal, agreger, paginer, reglesHorsSchema,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, repertoireTemporaire, secretsDev, texteCT2, blocApres } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  configurationMcp, serveurStdio, reglageOutil, RedacteurTest, ServiceFixe, AUTORISE, MinuteurVirtuel, EnfantFactice, laisserTourner, t,
} from "./fixtures/enregistreur-mcp/outils.mjs";

const lireJsonl = (rel) =>
  fs
    .readFileSync(path.join(VECTEURS_CT2, rel), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
const lireJson = (rel) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, rel), "utf8"));
const octets = (s) => new Uint8Array(Buffer.from(s, "utf8"));
const ref = (p) => (p ? { sha256: p.sha256, length: p.length, redacted: p.redacted, ...(p.media_type ? { media_type: p.media_type } : {}) } : null);

/**
 * Rejoue un cas de pieces-mcp/appels. Rend ce que le test compare.
 * @param {string} cas
 */
async function rejouer(cas) {
  const R = `pieces-mcp/appels/${cas}`;
  const a = lireJson(`${R}/attendu.json`);
  const hote = lireJsonl(`${R}/hote.jsonl`);
  const amont = lireJsonl(`${R}/amont.jsonl`);
  const listesServies = hote.filter((x) => x.dir === "out").map((x) => JSON.parse(x.line)).filter((m) => Array.isArray(m.result?.tools));
  const servie = listesServies[0].result.tools;
  // Serveurs du cas, d'après les noms servis : `<alias>__<nom d'origine>`.
  const parAlias = new Map();
  for (const d of servie) {
    const k = d.name.indexOf("__");
    const alias = d.name.slice(0, k);
    const outil = Object.fromEntries(Object.entries(d).map(([c, v]) => [c, c === "name" ? d.name.slice(k + 2) : v]));
    if (!parAlias.has(alias)) parAlias.set(alias, []);
    parAlias.get(alias).push(outil);
  }
  const dir = repertoireTemporaire("noortrace-mcp-vecteurs-");
  const servers = {};
  for (const alias of parAlias.keys()) {
    const moderne = alias !== "archives";
    servers[alias] = serveurStdio(["/opt/mcp/" + alias], {
      protocol: moderne ? "2026-07-28" : "auto",
      tools: alias === a.server_alias && a.timeout_ms ? { [a.tool_original]: reglageOutil({ timeout_ms: a.timeout_ms }) } : {},
      relay: alias === "demo" ? { sampling: false, elicitation: true, roots: false } : null,
    });
  }
  const { config: brute } = configurationMcp(dir, { servers, journal_id: N.octetsVersHex(N.keccak256(N.utf8(`journal-mcp-${cas}`))) });
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
  expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
  // `limits` du cas (taille-depassee : 512 octets, sous le minimum de 1024 de
  // `$defs/bytes` du schéma) : appliquées après la validation, lecture
  // consignée au LISEZMOI du paquet.
  Object.assign(v.config.limits, a.limits ?? {});
  const horloge = new HorlogeReglable(t(hote[0].t) - 60000);
  const service = new ServiceFixe(() => a.approval?.response ?? AUTORISE);
  const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service });
  const minuteur = new MinuteurVirtuel(horloge);
  const redacteur = new RedacteurTest();
  // Enfants factices : chaque ligne écrite par le frontal est notée ; l'horloge
  // prend alors l'horodatage de la ligne `out` attendue (t_envoi, 4.4 pas 9).
  const attendusAmont = amont.filter((x) => x.dir === "out");
  const ecritAmont = [];
  let preparation = true;
  const enfants = new Map();
  const lanceur = ({ alias }) => {
    const e = new EnfantFactice((ligne) => {
      if (preparation) return;
      ecritAmont.push(ligne);
      const x = attendusAmont[ecritAmont.length - 1];
      if (x) horloge.aller(t(x.t));
    });
    enfants.set(alias, e);
    return e;
  };
  const frontal = new FrontalMcp({ coeur, redacteur, lanceur, minuteur });
  for (const [alias, tools] of parAlias) {
    frontal.chargerListe(alias, tools, alias === "archives" ? { ttlMs: null, cacheScope: null, ere: "heritee" } : { ttlMs: 300000, cacheScope: "private", ere: "moderne" });
  }
  // Serveur moderne déjà connecté avant la transcription (sa sonde et son
  // `subscriptions/listen` n'y figurent pas) ; serveur hérité connecté au premier appel.
  if (parAlias.has("demo")) await frontal.connexions.get("demo").assurer("{}");
  const premierId = attendusAmont.length ? Number(JSON.parse(attendusAmont[0].line).id.slice(2)) : null;
  if (premierId !== null) frontal.connexions.get(a.server_alias).compteur = premierId - 1;
  const ere = a.protocols.host === "2026-07-28" ? "moderne" : "heritee";
  const session = frontal.ouvrirSession({ hote: v.config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: a.transports.host });
  if (ere === "heritee") {
    const init = await frontal.recevoir(session, '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"agent-demo","version":"0.1.0"}}}');
    expect(JSON.parse(init).result.protocolVersion).to.equal("2025-11-25");
    expect(await frontal.recevoir(session, '{"jsonrpc":"2.0","method":"notifications/initialized"}')).to.equal(null);
  }
  preparation = false;
  // Pompe : entrées dans l'ordre des horodatages. Une entrée n'est livrée
  // qu'une fois produites les sorties (amont et hôte) qui la précèdent ; un
  // minuteur ne part que s'il échoit avant la prochaine sortie attendue.
  const entrees = [...hote.filter((x) => x.dir === "in").map((x) => ({ ...x, canal: "hote" })), ...amont.filter((x) => x.dir === "in").map((x) => ({ ...x, canal: "amont" }))];
  entrees.sort((x, y) => t(x.t) - t(y.t));
  const attenduesHote = hote.filter((x) => x.dir === "out");
  const sortiesHote = [];
  const enCours = [];
  const echeanceMurale = (p) => p - horloge.monotone() + horloge.murale();
  const attendre = async (limite) => {
    for (let k = 0; k < 20000; k++) {
      const hoteDu = attenduesHote.filter((x) => t(x.t) < limite).length;
      const amontDu = attendusAmont.filter((x) => t(x.t) < limite).length;
      if (sortiesHote.length >= hoteDu && ecritAmont.length >= amontDu) return;
      await laisserTourner(1);
      const prochaines = [attenduesHote[sortiesHote.length], attendusAmont[ecritAmont.length]].filter(Boolean).map((x) => t(x.t));
      const p = minuteur.prochaine();
      if (p !== null && prochaines.length && echeanceMurale(p) <= Math.min(...prochaines)) {
        horloge.avancer(Math.max(0, p - horloge.monotone()));
        minuteur.lancerEchues();
      }
    }
    throw new Error(`pompe bloquée avant ${limite}`);
  };
  let definitionChangee = false;
  for (const e of entrees) {
    await attendre(t(e.t));
    await laisserTourner(1);
    if (e.canal === "hote" && a.pieces?.definition_current && !definitionChangee && JSON.parse(e.line).method === "tools/call") {
      // La définition courante a changé depuis la liste servie (EX-4.45).
      const courante = JSON.parse(a.pieces.definition_current.bytes);
      const outils = parAlias.get(a.server_alias).map((o) => (o.name === a.tool_original ? { ...courante, name: a.tool_original } : o));
      frontal.chargerListe(a.server_alias, outils, { ttlMs: 300000, cacheScope: "private", ere: "moderne" });
      definitionChangee = true;
    }
    horloge.aller(t(e.t));
    if (e.canal === "hote") {
      enCours.push(frontal.recevoir(session, octets(e.line), { cadre: a.transports.host === "http" ? "corps" : "ligne" }).then((r) => r !== null && sortiesHote.push(r)));
    } else if (e.eof) {
      enfants.get(a.server_alias).finDeFichier();
    } else {
      enfants.get(a.server_alias).repondre(e.line);
    }
  }
  await attendre(Infinity);
  await Promise.all(enCours);
  await laisserTourner(30);
  const evenements = await lireEvenements(coeur.repertoire);
  const journalJson = JSON.parse(fs.readFileSync(path.join(coeur.repertoire, "journal.json"), "utf8"));
  const cles = await clesDuJournal({ org_id: v.config.recorder.org_id, journal_id: v.config.recorder.journal_id, evenements, creeLe: journalJson.created_at, clePublique: (id) => coeur.signataire.clePubliqueHex(id) });
  const lirePiece = async (sha) => {
    const o = await coeur.pieces.lire(sha);
    return o ? Buffer.from(o).toString("utf8") : null;
  };
  await frontal.arreter();
  await coeur.arreter();
  return { a, hote, amont, attendusAmont, ecritAmont, sortiesHote, evenements, cles, lirePiece, redacteur, coeur, frontal };
}

describe("enregistreur, frontal MCP : vecteurs CT-2 rejoués", function () {
  this.timeout(180000);

  describe("pieces-mcp/appels (B.4) : transcriptions rejouées de bout en bout", function () {
    const dirs = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-mcp", "appels")).sort();
    for (const cas of dirs) {
      it(cas, async function () {
        const r = await rejouer(cas);
        const { a } = r;
        // Lignes envoyées au serveur d'outils, octet pour octet.
        expect(r.ecritAmont, "lignes amont").to.deep.equal(r.attendusAmont.map((x) => x.line));
        // Lignes rendues à l'hôte, octet pour octet.
        expect(r.sortiesHote, "lignes rendues").to.deep.equal(r.hote.filter((x) => x.dir === "out").map((x) => x.line));
        if (a.result_rendered) expect(JSON.parse(r.sortiesHote.at(-1)).result).to.deep.equal(a.result_rendered);
        if (a.error_rendered) expect(JSON.parse(r.sortiesHote.at(-1)).error).to.deep.equal(a.error_rendered);
        // Journal vérifié par le noyau (CT-1 §7, E-1 à E-11).
        const verdict = N.verifierJournal(r.evenements, r.cles);
        expect(verdict.valide, JSON.stringify(verdict.diagnostics)).to.equal(true);
        const appels = r.evenements.filter((e) => !e.execution.tool.startsWith("noortrace."));
        if (a.rejected) {
          expect(appels, "aucun événement pour un refus au pas 1").to.deep.equal([]);
          expect(r.redacteur.pieces, "aucune pièce").to.deep.equal([]);
          return;
        }
        if (a.approval && a.approval.response.ticket_state === "en_attente") {
          expect(appels, "aucun événement pour un ticket en attente (CT-3 EX-7.19)").to.deep.equal([]);
          expect(ref(r.redacteur.pieces[0].piece.reference)).to.deep.equal(ref(a.pieces.arguments));
          return;
        }
        expect(appels.length).to.equal(1);
        const e = appels[0];
        expect(e.execution.tool).to.equal(a.tool_announced);
        expect(e.execution.arguments).to.deep.equal(ref(a.pieces.arguments));
        expect(e.execution.result).to.deep.equal(ref(a.pieces.result));
        expect(e.execution.duration_ms).to.equal(a.duration_ms);
        expect(e.execution.is_error).to.equal(a.is_error);
        expect(e.context).to.deep.equal(a.context);
        expect(e.delegation).to.deep.equal({ launched_by: "agent-demo", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: e.delegation.run_id });
        if (a.approval) expect(e.execution.status).to.equal("refusee");
        else expect(e.execution.status).to.equal("executee");
        for (const [nom, p] of Object.entries(a.pieces)) {
          if (p) expect(await r.lirePiece(p.sha256), `pièce ${nom}`).to.equal(p.bytes);
        }
      });
    }
  });

  describe("evenements/journal-demo/entrees.json : appels de seq 3 et 5 par le frontal (corrélation 5.6)", function () {
    it("les événements produits ont la délégation, le code, l'intention, la politique, les effets et le contexte publiés", async function () {
      const E = "evenements/journal-demo";
      const entrees = lireJson(`${E}/entrees.json`);
      const publies = lireJson(`${E}/evenements.json`);
      const pieces = lireJson(`${E}/pieces.json`);
      const politique = lireJson(`${E}/politique.json`);
      const parSha = new Map(pieces.map((p) => [p.sha256, p]));
      const dir = repertoireTemporaire("noortrace-mcp-demo-");
      const servers = { demo: { ...serveurStdio(["/opt/mcp/demo"], { protocol: "2026-07-28" }), tools: politique.servers.demo.tools } };
      const h = entrees.host;
      const hote = { ...configurationMcp(dir, { servers }).config.mcp.hosts[0], id: h.id, launched_by: h.launched_by, scope: h.scope, on_behalf_of: h.on_behalf_of, host_group: h.host_group, tool_name_template: h.tool_name_template, tool_name_sanitize: h.tool_name_sanitize };
      const { config: brute } = configurationMcp(dir, { servers, hosts: [hote], journal_id: publies[0].journal_id });
      brute.policy.version = publies[0].code.policy_version;
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
      expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
      const horloge = new HorlogeReglable(t(publies[0].ts));
      const jeu = { threshold: { required: 2, size: 3 }, members: ["0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"], source: "jeu statique de la politique de demonstration" };
      const service = new ServiceFixe((r) =>
        r.tool_announced === "demo__payments.create"
          ? { rule: publies[4].policy.rule, decision: "a_approuver", ticket: publies[4].policy.ticket, ticket_state: "nouveau", approval: null, approver_set: jeu }
          : AUTORISE,
      );
      const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service });
      // Rédacteur de test : IBAN, et le résultat publié de seq 3 (rédigé par pii-v1) reconnu tel quel.
      const redacteur = new RedacteurTest();
      const resultatPublie = parSha.get(publies[2].execution.result.sha256);
      const redigerResultat = redacteur.redigerResultat.bind(redacteur);
      redacteur.redigerResultat = async (valeur, o) => {
        const { pieceJson: pj } = await import("@noortrace/enregistreur");
        const p = pj(valeur, { redacted: true });
        return p.sha256 === resultatPublie.sha256 ? { piece: p, valeur, redacted: true, non_redigeable: null, comptes: [] } : redigerResultat(valeur, o);
      };
      // Corrélateur de test (5.6) : l'échange de seq 2 pour l'appel de seq 3, celui de seq 4 pour seq 5.
      const { pieceTexte } = await import("@noortrace/enregistreur");
      const intention4 = parSha.get(publies[3].intent.sha256);
      await coeur.ecrirePiece(pieceTexte(intention4.bytes, { redacted: true }));
      const correlateur = {
        correler: async (q) => {
          const e = q.tool_announced === "demo__claims.get" ? publies[1] : publies[3];
          return { intent: e.intent, code: { model: e.code.model, prompt_version: e.code.prompt_version }, seq: e.seq };
        },
      };
      const minuteur = new MinuteurVirtuel(horloge);
      let enfant;
      const frontal = new FrontalMcp({ coeur, redacteur, correlateur, minuteur, lanceur: () => (enfant = new EnfantFactice()) });
      const outils = entrees.served_list.map((d) => ({ ...d, name: d.name.slice("demo__".length) }));
      frontal.chargerListe("demo", outils, { ttlMs: 300000, cacheScope: "private", ere: "moderne" });
      await frontal.connexions.get("demo").assurer("{}");
      const session = frontal.ouvrirSession({ hote: v.config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio" });
      horloge.aller(t(entrees.calls[0].t_recu) - 100);
      const liste = JSON.parse(await frontal.recevoir(session, '{"jsonrpc":"2.0","id":"l","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'));
      expect(liste.result.tools).to.deep.equal(entrees.served_list);
      // seq 3 : lecture relayée, réponse 184 ms plus tard.
      horloge.aller(t(entrees.calls[0].t_recu));
      const r3 = frontal.recevoir(session, entrees.calls[0].host_line);
      await laisserTourner(20);
      const envoye = JSON.parse(enfant.ecrit.at(-1));
      horloge.avancer(publies[2].execution.duration_ms);
      enfant.repondre(JSON.stringify({ jsonrpc: "2.0", id: envoye.id, result: JSON.parse(resultatPublie.bytes) }));
      await r3;
      // seq 5 : écriture soumise à approbation, retenue (mode erreur : signal en_attente).
      horloge.aller(t(entrees.calls[1].t_recu));
      const r5 = JSON.parse(await frontal.recevoir(session, entrees.calls[1].host_line));
      expect(r5.result._meta["noortrace/approval"]).to.deep.equal({ ticket: publies[4].policy.ticket, state: "en_attente" });
      await laisserTourner(20);
      const produits = (await lireEvenements(coeur.repertoire)).filter((e) => !e.execution.tool.startsWith("noortrace."));
      expect(produits.length).to.equal(2);
      const champs = (e) => ({ delegation: e.delegation, code: e.code, intent: e.intent, policy: e.policy, approval: e.approval, execution: e.execution, effects: e.effects, context: e.context });
      expect(champs(produits[0])).to.deep.equal(champs(publies[2]));
      expect(champs(produits[1])).to.deep.equal(champs(publies[4]));
      await frontal.arreter();
      await coeur.arreter();
    });
  });

  describe("annexe A de CT-2 : ce que le frontal reçoit, rend et relaie", function () {
    it("A.1 à A.3 : pièces, signal d'approbation (359 octets), ligne amont (420 octets), réponse à l'hôte (252 octets)", async function () {
      const texte = texteCT2();
      const blocs = [];
      let ligne = texte.split("\n").findIndex((l) => l.startsWith("## Annexe A"));
      for (const m of ["Ligne reçue de l'hôte", "La définition courante de l'outil", "reçoit aussitôt le signal d'approbation", "Ligne écrite sur l'entrée standard du serveur", "Ligne lue sur la sortie standard du serveur", "Ligne écrite sur la sortie standard du"]) {
        const b = blocApres(texte, m, ligne);
        blocs.push(b.texte);
        ligne = b.ligne;
      }
      const [ligneHote, definition, signal, ligneAmont, reponseAmont, reponseHote] = blocs;
      expect(Buffer.byteLength(ligneHote)).to.equal(408);
      expect(Buffer.byteLength(signal)).to.equal(359);
      expect(Buffer.byteLength(ligneAmont)).to.equal(420);
      expect(Buffer.byteLength(reponseHote)).to.equal(252);
      const def = JSON.parse(definition);
      const lancer = async (reponse) => {
        const dir = repertoireTemporaire("noortrace-mcp-annexe-a-");
        const { config: brute } = configurationMcp(dir, { servers: { sap: serveurStdio(["/opt/mcp/sap"], { protocol: "2026-07-28", tools: { "payments.create": reglageOutil({ class: "ecriture" }) } }) }, tools: { prefix: false } });
        const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(brute)));
        expect(v.erreurs).to.deep.equal([]);
        const horloge = new HorlogeReglable(t("2026-11-03T13:41:07.000Z"));
        const coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), horloge, service: new ServiceFixe(() => reponse) });
        let enfant;
        const frontal = new FrontalMcp({ coeur, redacteur: new RedacteurTest(), minuteur: new MinuteurVirtuel(horloge), lanceur: () => (enfant = new EnfantFactice()) });
        frontal.chargerListe("sap", [def], { ttlMs: 300000, cacheScope: "private", ere: "moderne" });
        await frontal.connexions.get("sap").assurer("{}");
        frontal.connexions.get("sap").compteur = 40;
        const session = frontal.ouvrirSession({ hote: v.config.mcp.hosts[0], identite: { peer_user: "agent-demo" }, transport: "stdio" });
        await frontal.recevoir(session, '{"jsonrpc":"2.0","id":"l","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}');
        const p = frontal.recevoir(session, ligneHote);
        await laisserTourner(20);
        const ecrit = enfant.ecrit.filter((l) => JSON.parse(l).method === "tools/call");
        if (ecrit.length) enfant.repondre(reponseAmont);
        const r = await p;
        await laisserTourner(20);
        const evts = (await lireEvenements(coeur.repertoire)).filter((e) => !e.execution.tool.startsWith("noortrace."));
        await frontal.arreter();
        await coeur.arreter();
        return { r, ecrit, evts };
      };
      // Mode erreur : ticket nouveau, événement retenue, signal rendu aussitôt (A.2).
      const jeu = { threshold: { required: 2, size: 3 }, members: ["0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"], source: "jeu statique de la politique 2026-11-01" };
      const a2 = await lancer({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: "apr-1192", ticket_state: "nouveau", approval: null, approver_set: jeu });
      expect(a2.r).to.equal(signal);
      expect(a2.ecrit).to.deep.equal([]);
      expect(a2.evts.length).to.equal(1);
      expect(a2.evts[0].execution.arguments).to.deep.equal({ sha256: "0x6cfc43b54a70eee0141d2fc7d1acc06003ee23354ac76f2097ef74958d91bbb4", length: 96, redacted: true });
      expect(a2.evts[0].context.map((c) => [c.sha256, c.length])).to.deep.equal([
        ["0x7d2ffcd2cba25dbd90b54926be79c845131109b2e1bc4ccc22389fb8a26a498a", 406],
        ["0xbce6c768f26f72d7377fa3098262b61db83bcc740fc528be536acaa7f168033e", 418],
      ]);
      expect(a2.evts[0].policy).to.deep.equal({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: "apr-1192", redaction: a2.evts[0].policy.redaction });
      // Relais (A.3) : ligne amont et réponse rendue, octet pour octet.
      const a3 = await lancer(AUTORISE);
      expect(a3.ecrit).to.deep.equal([ligneAmont]);
      expect(a3.r).to.equal(reponseHote);
      expect(a3.evts[0].execution.result).to.deep.equal({ sha256: "0x850627f5a2216e1d592b9a6a21d5df8f5a9454e7330809ba6a4d070a7f633b8c", length: 109, redacted: false });
    });
  });

  describe("pieces-mcp/agregation (B.4, EX-4.9 à EX-4.16)", function () {
    for (const d of ["", "normalisation", "sans-prefixe-un-serveur"]) {
      it(d || "agregation", function () {
        const R = `pieces-mcp/agregation${d ? `/${d}` : ""}`;
        const s = lireJson(`${R}/serveurs.json`);
        const a = lireJson(`${R}/attendu.json`);
        const r = agreger({ serveurs: s, prefixe: a.prefix, normalisations: a.normalisations ?? [] });
        expect(r.annonces.map((x) => ({ server_alias: x.server_alias, original: x.original, announced: x.announced, class: x.class, definition_sha256: x.definition_sha256 }))).to.deep.equal(a.announced);
        expect(r.rejets).to.deep.equal(a.rejected);
        expect(paginer(r.annonces, a.page_size).map((p) => p.map((x) => x.announced))).to.deep.equal(a.pages);
      });
    }
    it("sans-prefixe : deux serveurs et tools.prefix false, configuration refusée (EX-4.10)", function () {
      const R = "pieces-mcp/agregation/sans-prefixe";
      const s = lireJson(`${R}/serveurs.json`);
      const a = lireJson(`${R}/attendu.json`);
      expect(a.configuration_refusee).to.equal(true);
      const dir = repertoireTemporaire("noortrace-mcp-agreg-");
      const servers = Object.fromEntries(s.map((x) => [x.alias, serveurStdio(["/opt/mcp/" + x.alias])]));
      const { config } = configurationMcp(dir, { servers, tools: { prefix: a.prefix } });
      const r = reglesHorsSchema(config);
      expect(r.erreurs.map((x) => x.pointeur)).to.include("/tools/prefix");
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
      expect(v.config).to.equal(null);
    });
  });
});
