// Exigences du point d'entrée SDK du démon (CT-2 §6.1 à §6.3, §6.7, EX-6.1 à
// EX-6.8, EX-6.24, EX-7.7, EX-12.12, EX-12.15, table de 6.2, 14.2 et 14.6
// pour le SDK), en réussite et en échec, et entrées hostiles : un agent parle
// au démon en processus (cœur, rédacteur pii-v1, service d'approbation
// factice) par le SDK JavaScript `noortrace-sdk` ou par une prise brute.
// Écrit d'après le seul texte de CT-2.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";
import tls from "node:tls";
import { createHash } from "node:crypto";
import {
  Coeur, demarrerSdk, lireEvenements, controleSdk, validerConfiguration, classeSdk, classeConfigureeSdk, pieceDeclarationSource,
  RegistreCorrelation, pieceReprise, jcsIntegral, HorlogeReglable,
} from "@noortrace/enregistreur";
import {
  ClientNoortrace, ErreurNoortraceDegrade, ErreurNoortraceEntreeInvalide, ErreurNoortraceLimite, ErreurNoortraceIndisponible, AppelNonAutorise,
} from "noortrace-sdk";
import { configurationDev, configurationExemple, secretsDev, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { demarrerDemonSdk, hoteSdk, priseBrute, ServiceApprobationFactice, autoriteDeTest } from "./fixtures/enregistreur-sdk/outils.mjs";

const lirePiece = async (d, sha) => JSON.parse(Buffer.from(await d.coeur.pieces.lire(sha)).toString("utf8"));
const ARGS = { sinistre: "2026-77812", montant: "7400.00", devise: "CHF" };

async function avecDemon(o, f) {
  const d = await demarrerDemonSdk(o);
  try {
    return await f(d);
  } finally {
    await d.arreter();
  }
}

/** Attend que le service factice ait reçu `ouvrir` pour un ticket (EX-7.18 : envoyé sans attendre). */
async function ouvert(d, ticket) {
  for (let k = 0; k < 100 && !d.service.tickets.get(ticket)?.request; k++) await new Promise((x) => setTimeout(x, 10));
}

/** Fichier d'intention de l'époque courante (EX-12.12). */
function lignesIntention(d) {
  const dir = path.join(d.coeur.repertoire, "intentions");
  return fs.readdirSync(dir).flatMap((n) => fs.readFileSync(path.join(dir, n), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)));
}

describe("enregistreur, SDK : exigences du point d'entrée (§6.1 à §6.3, §6.7)", function () {
  this.timeout(60000);

  describe("EX-6.1 : prise locale, identité du pair, entrée de sdk.hosts, délégation", function () {
    it("réussite : prise Unix, utilisateur du pair, launched_by et scope de la configuration, run_id et on_behalf_of déclarés (EX-7.2)", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({ runId: "run-2026-11-10-0007", onBehalfOf: "service-sinistres" });
        const debut = await s.debutAppel({ tool: "lire_sinistre", arguments: { id: "1" }, classe: "lecture" });
        await s.finAppel(debut, { resultat: { ok: true }, isError: false, durationMs: 3 });
        await s.fermer();
        const e = (await d.evenements()).at(-1);
        expect(e.delegation).to.deep.equal({ launched_by: (await import("node:os")).userInfo().username, on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-2026-11-10-0007" });
        expect(fs.statSync(d.config.sdk.socket).mode & 0o777).to.equal(0o660);
      });
    });

    it("échec : un pair sans entrée de sdk.hosts est refusé (auth_failed) ; run_id hors motif ou détecté et on_behalf_of hors liste remplacés (delegation_refused)", async function () {
      await avecDemon({ hotes: [hoteSdk({ match: { peer_user: "utilisateur-absent" } })] }, async (d) => {
        let erreur = null;
        try {
          await d.client({ delaiMs: 2000, reprises: 0 }).ouvrir({});
        } catch (e) {
          erreur = e;
        }
        expect(erreur).to.be.instanceOf(ErreurNoortraceIndisponible);
        expect(d.lignes("auth_failed").map((l) => l.data.reason)).to.include("hote_inconnu");
      });
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({ runId: "conv jean.exemple@assureur-demo.example", onBehalfOf: "autre-service" });
        const s2 = await d.client().ouvrir({ runId: "CH9300762011623852957" });
        for (const x of [s, s2]) {
          const debut = await x.debutAppel({ tool: "lire_sinistre", arguments: {}, classe: "lecture" });
          await x.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
          await x.fermer();
        }
        const evts = (await d.evenements()).slice(-2);
        for (const e of evts) expect(e.delegation.run_id).to.equal(null);
        expect(evts[0].delegation.on_behalf_of).to.equal(null);
        const refus = d.lignes("delegation_refused").map((l) => `${l.data.field}:${l.data.reason}`);
        expect(refus).to.include.members(["run_id:motif", "on_behalf_of:hors_liste", "run_id:detecteur"]);
        // Aucune valeur refusée au journal d'exploitation (EX-7.2, EX-17.3).
        expect(JSON.stringify(d.coeur.journal.lignes)).to.not.contain("jean.exemple@");
        expect(JSON.stringify(d.coeur.journal.lignes)).to.not.contain("CH9300762011623852957");
      });
    });

    it("prise TCP : jeton en première ligne comparé en temps constant (EX-4.39, EX-6.10) ; jeton faux refusé, limité par identifiant de jeton (EX-18.3)", async function () {
      const dir = repertoireTemporaire("noortrace-sdk-tcp-");
      const { config, env } = configurationDev(dir, { sdk: { hosts: [hoteSdk({ match: { static_token: "agent-sdk" }, launched_by: "svc-agent-local" })] } });
      config.sdk.socket = null;
      config.sdk.tcp_listen = { listen: "127.0.0.1:0", client_auth: "jeton", tls: null };
      config.mcp.http = { ...(config.mcp.http ?? {}), static_tokens: [...(config.mcp.http?.static_tokens ?? []), { id: "agent-sdk", token: { env: "NOORTRACE_TEST_JETON_SDK" } }] };
      Object.assign(process.env, env, { NOORTRACE_TEST_JETON_SDK: "jeton-sdk-de-test" });
      const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)), { reglesSupplementaires: [controleSdk] });
      expect(v.erreurs).to.deep.equal([]);
      const secrets = secretsDev();
      config.mcp.http.static_tokens.forEach((t, k) => secrets.set(`/mcp/http/static_tokens/${k}/token`, new Uint8Array(Buffer.from(t.id === "agent-sdk" ? "jeton-sdk-de-test" : "autre"))));
      const coeur = await Coeur.demarrer({ config, secrets, service: new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }) });
      const sdk = await demarrerSdk(coeur, secrets);
      try {
        const a = sdk.serveur.adresseTcp();
        const bon = new ClientNoortrace({ tcp: `127.0.0.1:${a.port}`, jeton: "jeton-sdk-de-test" });
        const s = await bon.ouvrir({});
        const debut = await s.debutAppel({ tool: "lire_sinistre", arguments: {}, classe: "lecture" });
        await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        await s.fermer();
        expect((await lireEvenements(coeur.repertoire)).at(-1).delegation.launched_by).to.equal("svc-agent-local");
        for (let k = 0; k < 11; k++) {
          let err = null;
          try {
            await new ClientNoortrace({ tcp: `127.0.0.1:${a.port}`, jeton: "faux-jeton", reprises: 0, delaiMs: 2000 }).ouvrir({});
          } catch (e) {
            err = e;
          }
          expect(err).to.be.instanceOf(ErreurNoortraceIndisponible);
        }
        const raisons = coeur.journal.lignes.filter((l) => l.event === "auth_failed").map((l) => l.data.reason);
        expect(raisons).to.include("jeton_limite");
        // Un jeton valide n'est jamais refusé à cause des échecs d'un autre (EX-18.3).
        const s2 = await bon.ouvrir({});
        await s2.fermer();
        expect(JSON.stringify(coeur.journal.lignes)).to.not.contain("faux-jeton");
      } finally {
        await sdk.arreter();
        await coeur.arreter();
      }
    });

    it("prise TCP en mTLS (EX-4.39, EX-6.1, EX-6.10, lecture 113) : certificat valide accepté et rattaché à son entrée ; autre autorité, expiré, absent ou sans entrée refusés", async function () {
      const dir = repertoireTemporaire("noortrace-sdk-mtls-");
      const pki = autoriteDeTest(path.join(dir, "pki"));
      const hotes = [
        hoteSdk({ id: "agent-a", alias: "agent-a", match: { peer_user: "agent-a" }, host_group: "groupe-a" }),
        hoteSdk({ id: "agent-b", alias: "agent-b", match: { peer_user: "agent-b" }, host_group: "groupe-b" }),
      ];
      const { config, env } = configurationDev(dir, { sdk: { hosts: hotes } });
      config.sdk.socket = null;
      config.sdk.tcp_listen = { listen: "127.0.0.1:0", client_auth: "mtls", tls: { cert_file: pki.serveur.cert_file, key_file: pki.serveur.key_file } };
      Object.assign(process.env, env);
      const octets = (c) => new TextEncoder().encode(JSON.stringify(c));
      expect(validerConfiguration(octets(config), { reglesSupplementaires: [controleSdk] }).erreurs).to.deep.equal([]);
      // mTLS sans TLS : refusé par la validation (pas 3 d'EX-15.4).
      const sansTls = structuredClone(config);
      sansTls.sdk.tcp_listen.tls = null;
      expect(validerConfiguration(octets(sansTls), { reglesSupplementaires: [controleSdk] }).erreurs.map((e) => e.pointeur)).to.include("/sdk/tcp_listen/tls");
      const secrets = secretsDev();
      const coeur = await Coeur.demarrer({ config, secrets, service: new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }) });
      const sdk = await demarrerSdk(coeur, secrets);
      const variables = ["NOORTRACE_SDK_TLS_CA", "NOORTRACE_SDK_TLS_CERT", "NOORTRACE_SDK_TLS_KEY"];
      const avant = Object.fromEntries(variables.map((v) => [v, process.env[v]]));
      const avecCertificat = async (c, f) => {
        Object.assign(process.env, { NOORTRACE_SDK_TLS_CA: pki.ca, NOORTRACE_SDK_TLS_CERT: c.cert, NOORTRACE_SDK_TLS_KEY: c.key });
        try {
          return await f();
        } finally {
          for (const v of variables) if (avant[v] === undefined) delete process.env[v];
          else process.env[v] = avant[v];
        }
      };
      const refuse = async (c) =>
        avecCertificat(c, async () => {
          try {
            await new ClientNoortrace({ tcp: `127.0.0.1:${sdk.serveur.adresseTcp().port}`, reprises: 0, delaiMs: 3000 }).ouvrir({});
          } catch (e) {
            return e;
          }
          return null;
        });
      try {
        const port = sdk.serveur.adresseTcp().port;
        // Réussite : le certificat CN=agent-b est rattaché à l'entrée agent-b, pas à agent-a.
        await avecCertificat(pki.client("agent-b"), async () => {
          const s = await new ClientNoortrace({ tcp: `127.0.0.1:${port}` }).ouvrir({});
          const debut = await s.debutAppel({ tool: "lire_sinistre", arguments: {}, classe: "lecture" });
          await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
          await s.fermer();
        });
        const e = (await lireEvenements(coeur.repertoire)).at(-1);
        expect(e.delegation.launched_by).to.equal("agent-b");
        expect(e.execution.tool).to.equal("agent-b__lire_sinistre");
        const connecte = coeur.journal.lignes.filter((l) => l.event === "sdk_connected");
        expect(connecte.map((l) => [l.host, l.data.transport])).to.deep.equal([["agent-b", "mtls"]]);
        // Échecs : autre autorité, expiré, certificat valide sans entrée de sdk.hosts.
        for (const c of [pki.etranger("agent-a"), pki.expire("agent-a"), pki.client("agent-inconnu")]) expect(await refuse(c)).to.be.instanceOf(ErreurNoortraceIndisponible);
        // Sans certificat : la poignée de main est refusée, aucune identité acceptée.
        const sansCertificat = await new Promise((r) => {
          const c = tls.connect({ host: "127.0.0.1", port, ca: fs.readFileSync(pki.ca) });
          let recu = "";
          c.on("data", (x) => (recu += x));
          c.on("error", () => {});
          c.on("close", () => r(recu));
          c.on("secureConnect", () => c.write(JSON.stringify({ noortrace_token: "sans-objet" }) + "\n"));
        });
        expect(sansCertificat).to.not.contain("acceptee");
        for (let k = 0; k < 100 && coeur.journal.lignes.filter((l) => l.event === "auth_failed").length < 4; k++) await new Promise((x) => setTimeout(x, 10));
        const refus = coeur.journal.lignes.filter((l) => l.event === "auth_failed").map((l) => `${l.data.transport}:${l.data.reason}`);
        expect(refus).to.include("tls:hote_inconnu");
        expect(refus).to.include.members(["tls:certificat:UNABLE_TO_VERIFY_LEAF_SIGNATURE", "tls:certificat:CERT_HAS_EXPIRED", "tls:certificat:absent"]);
        expect(coeur.journal.lignes.filter((l) => l.event === "sdk_connected").length).to.equal(1);
      } finally {
        await sdk.arreter();
        await coeur.arreter();
      }
    });

    it("prise TCP : chaîne de cert_file sans autorité avec client_auth mtls, refus de démarrer le point d'entrée", async function () {
      const dir = repertoireTemporaire("noortrace-sdk-mtls-");
      const pki = autoriteDeTest(path.join(dir, "pki"));
      const { config, env } = configurationDev(dir, { sdk: { hosts: [hoteSdk({ match: { peer_user: "agent-a" } })] } });
      config.sdk.socket = null;
      config.sdk.tcp_listen = { listen: "127.0.0.1:0", client_auth: "mtls", tls: { cert_file: pki.serveur.seul, key_file: pki.serveur.key_file } };
      Object.assign(process.env, env);
      const secrets = secretsDev();
      const coeur = await Coeur.demarrer({ config, secrets, service: new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id }) });
      try {
        let erreur = null;
        try {
          await demarrerSdk(coeur, secrets);
        } catch (e) {
          erreur = e;
        }
        expect(String(erreur?.message)).to.contain("autorité des certificats clients");
      } finally {
        await coeur.arreter();
      }
    });

    it("le SDK ne contient ni hachage, ni signature, ni écriture de journal (EX-6.1)", function () {
      const dir = path.resolve("paquets/sdk-js/src");
      for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".mjs"))) {
        const t = fs.readFileSync(path.join(dir, f), "utf8");
        expect(t, f).to.not.match(/createHash|createSign|\bsign\(|@noortrace\/|ed25519|appendFile|writeFile/i);
      }
      expect(JSON.parse(fs.readFileSync("paquets/sdk-js/package.json", "utf8")).dependencies ?? {}).to.deep.equal({});
    });

    it("EX-6.2 : la documentation du SDK dit en tête qu'il n'est acceptable qu'avec un pare-feu de sortie", function () {
      const t = fs.readFileSync("paquets/sdk-js/LISEZMOI.md", "utf8");
      const tete = t.split("\n").slice(0, 25).join("\n");
      expect(tete).to.match(/pare-feu de sortie/);
    });
  });

  describe("EX-6.3 : debutAppel avant l'exécution, intention durable, finAppel après", function () {
    it("réussite : pour une écriture, l'intention (deux lignes) est sur disque quand debutAppel répond ; finAppel rend { seq, hash } de l'événement durable, intention levée", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const debut = await s.debutAppel({ tool: "preparer_paiement", arguments: ARGS, classe: "ecriture" });
        const l = lignesIntention(d);
        expect(l).to.have.length(2);
        expect(l[0].upstream_id).to.equal(debut.call);
        expect(l[0].tool).to.equal("agent-local__preparer_paiement");
        expect(l[0].host).to.equal("agent-local");
        expect(l[1].intent_context).to.equal(l[0].intent_id);
        const fin = await s.finAppel(debut, { resultat: { reference: "PAY-1" }, isError: false, durationMs: 41 });
        const e = (await d.evenements()).find((x) => x.seq === fin.seq);
        expect(e.hash).to.equal(fin.hash);
        expect(e.execution.duration_ms).to.equal(41);
        expect(lignesIntention(d).at(-1)).to.deep.equal({ lifted: l[0].intent_id, seq: fin.seq });
        // Effet par défaut d'une écriture sans gabarit (EX-7.6).
        expect(e.effects).to.deep.equal([{ system: "agent-local", action: "ecriture", object: "preparer_paiement", amount: null, currency: null }]);
        await s.fermer();
      });
    });

    it("lecture : aucune intention ; échec : finAppel sans debutAppel connu refusé par -32602 (call_inconnu)", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const debut = await s.debutAppel({ tool: "lire_sinistre", arguments: {}, classe: "lecture" });
        expect(fs.existsSync(path.join(d.coeur.repertoire, "intentions")) ? lignesIntention(d) : []).to.deep.equal([]);
        await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        const p = await priseBrute(d.config.sdk.socket);
        const r = await p.appel("finAppel", { call: "c-00000000000000000001-000000000099", result: null, is_error: false, duration_ms: 0 });
        expect(r.error.code).to.equal(-32602);
        expect(r.error.data.reason).to.equal("call_inconnu");
        // Le call d'une autre connexion n'est pas connu non plus.
        const autre = await s.debutAppel({ tool: "lire_sinistre", arguments: {}, classe: "lecture" });
        const r2 = await p.appel("finAppel", { call: autre.call, result: null, is_error: false, duration_ms: 0 }, 2);
        expect(r2.error.data.reason).to.equal("call_inconnu");
        p.fermer();
        await s.finAppel(autre, { resultat: null, isError: false, durationMs: 0 });
        await s.fermer();
      });
    });
  });

  describe("EX-6.4, EX-6.7 : approbation par le SDK (table d'EX-6.7)", function () {
    const decider = (r) => {
      if (r.tool_announced.endsWith("refuser")) return { decision: "refuse", rule: "interdit" };
      if (r.tool_announced.endsWith("payer")) return { decision: "a_approuver", rule: "paiement" };
      return { decision: "autorise", rule: "lecture libre" };
    };

    it("autorise sans ticket ; refuse sans ticket (refusee) ; a_approuver nouveau (retenue, ouvrir) ; en_attente (aucun événement) ; approuve (RL-1 à RL-4, intention, approbation, consommer) ; refuse d'un ticket (refusee avec approval)", async function () {
      await avecDemon({ decider }, async (d) => {
        const s = await d.client().ouvrir({});
        const a = await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });
        expect(a.decision).to.equal("autorise");
        expect(a.call).to.be.a("string");
        await s.finAppel(a, { resultat: null, isError: false, durationMs: 0 });
        const r = await s.debutAppel({ tool: "refuser", arguments: { x: 1 }, classe: "ecriture" });
        expect(r).to.deep.equal({ call: null, decision: "refuse", ticket: null, ticket_state: null });
        const refusee = (await d.evenements()).at(-1);
        expect(refusee.execution.status).to.equal("refusee");
        expect(refusee.policy.rule).to.equal("interdit");
        const n = await s.debutAppel({ tool: "payer", arguments: ARGS, classe: "ecriture" });
        expect(n.decision).to.equal("a_approuver");
        expect(n.ticket_state).to.equal("nouveau");
        expect(n.call).to.equal(null);
        const retenue = (await d.evenements()).at(-1);
        expect(retenue.execution.status).to.equal("retenue");
        expect(retenue.execution.tool).to.equal("agent-local__payer");
        await new Promise((x) => setTimeout(x, 50));
        expect(d.service.messages.map((m) => m.methode)).to.include("ouvrir");
        const nEvt = (await d.evenements()).length;
        const att = await s.debutAppel({ tool: "payer", arguments: ARGS, classe: "ecriture" });
        expect(att).to.deep.equal({ call: null, decision: "a_approuver", ticket: n.ticket, ticket_state: "en_attente" });
        expect((await d.evenements()).length).to.equal(nEvt);
        expect(d.lignes("approval_pending").length).to.be.greaterThan(0);
        // Décision approuvée remise, vérifiée et scellée (SG-1 à SG-7).
        await ouvert(d, n.ticket);
        d.service.decider_ticket(n.ticket, { decision: "approuve" });
        await d.coeur.traiterRemises();
        const ok = await s.debutAppel({ tool: "payer", arguments: ARGS, classe: "ecriture" });
        expect(ok.decision).to.equal("autorise");
        expect(ok.ticket).to.equal(n.ticket);
        expect(ok.ticket_state).to.equal("approuve");
        expect(lignesIntention(d).filter((l) => l.ticket === n.ticket)).to.have.length(1);
        const fin = await s.finAppel(ok, { resultat: { reference: "PAY-2" }, isError: false, durationMs: 12 });
        const ex = (await d.evenements()).find((e) => e.seq === fin.seq);
        expect(ex.policy).to.deep.equal({ ...retenue.policy, redaction: ex.policy.redaction });
        expect(ex.approval.decision).to.equal("approuve");
        await new Promise((x) => setTimeout(x, 50));
        expect(d.service.messages.filter((m) => m.methode === "consommer").map((m) => m.corps.seq)).to.include(fin.seq);
        // RL-3 : l'approbation déjà servie ne relaie pas une seconde fois (-31010 approbation).
        let rl3 = null;
        try {
          await s.debutAppel({ tool: "payer", arguments: ARGS, classe: "ecriture" });
        } catch (e) {
          rl3 = e;
        }
        expect(rl3).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(rl3.raison).to.equal("approbation");
        // Ticket refusé : refusee qui reprend la retenue et porte l'approval scellé (EX-7.12).
        const n2 = await s.debutAppel({ tool: "payer", arguments: { ...ARGS, montant: "1.00" }, classe: "ecriture" });
        await ouvert(d, n2.ticket);
        d.service.decider_ticket(n2.ticket, { decision: "refuse", reason: "montant" });
        await d.coeur.traiterRemises();
        const rf = await s.debutAppel({ tool: "payer", arguments: { ...ARGS, montant: "1.00" }, classe: "ecriture" });
        expect(rf).to.deep.equal({ call: null, decision: "refuse", ticket: n2.ticket, ticket_state: "refuse" });
        const ev = (await d.evenements()).at(-1);
        expect(ev.execution.status).to.equal("refusee");
        expect(ev.approval.decision).to.equal("refuse");
        expect(ev.policy.decision).to.equal("a_approuver");
        // appelOutil change une décision non autorisée en exception, sans exécuter la fonction.
        let execute = false;
        let e2 = null;
        try {
          await s.appelOutil({ tool: "refuser", arguments: { x: 2 }, classe: "ecriture" }, () => (execute = true));
        } catch (e) {
          e2 = e;
        }
        expect(execute).to.equal(false);
        expect(e2).to.be.instanceOf(AppelNonAutorise);
        expect(e2.texte).to.equal("noortrace: appel refuse par la politique");
        await s.fermer();
      });
    });

    it("échec : service indisponible ou réponse invalide : -31010 approbation pour une écriture ; lecture passante (14.2)", async function () {
      await avecDemon({}, async (d) => {
        d.service.panne = "non_pret";
        const s = await d.client().ouvrir({});
        let e1 = null;
        try {
          await s.debutAppel({ tool: "ecrire_note", arguments: {}, classe: "ecriture" });
        } catch (e) {
          e1 = e;
        }
        expect(e1).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(e1.raison).to.equal("approbation");
        // Lecture : bloquante tant que la liste des candidats manque (EX-7.4), comme pour le frontal MCP.
        let e2 = null;
        try {
          await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });
        } catch (e) {
          e2 = e;
        }
        expect(e2).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(d.lignes("call_blocked").some((l) => l.data.reason === "approbation")).to.equal(true);
        await s.fermer();
      });
    });

    it("EX-6.7, EX-10.23 : pièce « arguments » au-delà de la borne de temps : -31010 redaction pour une écriture, avant l'intention", async function () {
      await avecDemon({ modifier: (c) => (c.limits.redaction_budget_ms = 1) }, async (d) => {
        const s = await d.client().ouvrir({});
        const gros = { texte: Array.from({ length: 40000 }, (_, k) => `contact${k}@exemple-${k}.ch`).join(" ") };
        let err = null;
        try {
          await s.debutAppel({ tool: "ecrire_note", arguments: gros, classe: "ecriture" });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(err.raison).to.equal("redaction");
        expect(fs.existsSync(path.join(d.coeur.repertoire, "intentions")) ? lignesIntention(d) : []).to.deep.equal([]);
        await s.fermer();
      });
    });
  });

  describe("EX-6.6 : espace de noms et validation des entrées", function () {
    it("réussite : nom <alias>__<tool> ; effets déclarés soumis aux détecteurs de la portée arguments, recopiés, marqués déclarés (6.3)", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const effects = [{ system: "SAP", action: "ecriture", object: "paiement pour jean.exemple@assureur-demo.example", amount: "7400.00", currency: "CHF" }];
        const debut = await s.debutAppel({ tool: "preparer_paiement", arguments: ARGS, classe: "ecriture", effects });
        // L'intention porte les effets déclarés (EX-12.12).
        expect(lignesIntention(d)[1].event.effects[0].object).to.equal("paiement pour [REDIGE:email]");
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 1 });
        const e = (await d.evenements()).find((x) => x.seq === fin.seq);
        expect(e.execution.tool).to.equal("agent-local__preparer_paiement");
        expect(e.effects).to.deep.equal([{ system: "SAP", action: "ecriture", object: "paiement pour [REDIGE:email]", amount: "7400.00", currency: "CHF" }]);
        expect(d.lignes("sdk_effects_declared")).to.have.length(1);
        await s.fermer();
      });
    });

    it("échec : -32602 sans pièce, sans événement, sans mode dégradé pour chaque entrée invalide", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const autre = await d.client().ouvrir({});
        const refAutre = await autre.declarerContexte({ kind: "document", octets: "doc" });
        const avant = (await d.evenements()).length;
        const cas = [
          [{ tool: "a__b", arguments: {} }, "tool_double_soulignement"],
          [{ tool: "noortrace.outil", arguments: {} }, "tool_reserve"],
          [{ tool: "outil avec espace", arguments: {} }, "tool_hors_motif"],
          [{ tool: "x".repeat(130), arguments: {} }, "tool_hors_motif"],
          [{ tool: "ok", arguments: {}, contexte: ["0xABC"] }, "context_hors_motif"],
          [{ tool: "ok", arguments: {}, contexte: ["0x" + "1".repeat(64)] }, "context_non_declare"],
          [{ tool: "ok", arguments: {}, contexte: [refAutre.sha256] }, "context_non_declare"],
          [{ tool: "ok", arguments: {}, intent: "x".repeat(1048577) }, "intent_trop_long"],
          [{ tool: "ok", arguments: {}, effects: [{ system: "S", action: "voler", object: "o", amount: null, currency: null }] }, "effects_hors_forme"],
          [{ tool: "ok", arguments: {}, effects: [{ system: "S", action: "ecriture", object: "o", amount: "1", currency: null }] }, "effects_hors_forme"],
          [{ tool: "ok", arguments: {}, classe: "suppression" }, "class_hors_forme"],
        ];
        for (const [p, raison] of cas) {
          let err = null;
          try {
            await s.debutAppel(p);
          } catch (e) {
            err = e;
          }
          expect(err, raison).to.be.instanceOf(ErreurNoortraceEntreeInvalide);
          expect(err.raison, raison).to.equal(raison);
        }
        expect((await d.evenements()).length).to.equal(avant);
        expect(d.coeur.degrade.enModeDegrade).to.equal(false);
        expect(fs.existsSync(path.join(d.coeur.repertoire, "intentions")) ? lignesIntention(d) : []).to.deep.equal([]);
        await s.fermer();
        await autre.fermer();
      });
    });
  });

  describe("EX-7.7 : context d'un appel du SDK et d'un échange déclaré", function () {
    it("appel : les références déclarées par declarerContexte, dans l'ordre déclaré ; échange : la pièce de déclaration de source du SDK, seule", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const r1 = await s.declarerContexte({ kind: "memoire", octets: "note de memoire", mediaType: "text/plain" });
        const r2 = await s.declarerContexte({ kind: "document", octets: JSON.stringify({ iban: "CH93 0076 2011 6238 5295 7" }), mediaType: "application/json" });
        expect(r2.redacted).to.equal(true);
        const debut = await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture", contexte: [r2.sha256, r1.sha256] });
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        const e = (await d.evenements()).find((x) => x.seq === fin.seq);
        expect(e.context.map((c) => [c.sha256, c.kind])).to.deep.equal([[r2.sha256, "document"], [r1.sha256, "memoire"]]);
        expect(e.context[0].media_type).to.equal("application/json");
        expect(e.policy.redaction).to.equal("pii-v1");
        expect(await lirePiece(d, r2.sha256)).to.deep.equal({ iban: "[REDIGE:iban]" });
        const x = await s.echangeModele({ format: "autre", providerLabel: "local", request: { model: "modele-local", q: "?" }, response: { r: "!" }, status: 200, durationMs: 9, isError: false });
        const ex = (await d.evenements()).find((y) => y.seq === x.seq);
        expect(ex.context).to.deep.equal([pieceDeclarationSource("sdk", "agent-local").referenceContexte("autre")]);
        expect(ex.code.model).to.equal("local/modele-local");
        expect(ex.code.prompt_version).to.equal(null);
        expect(ex.intent).to.equal(null);
        await s.fermer();
      });
    });
  });

  describe("EX-6.8 : échange Gemini déclaré", function () {
    it("mcpServers et cachedContent consignés sans refus ; status ≥ 400 : noortrace_http_error et is_error ; tableau vide : flux incomplet ; request.model sans « models/ » en repli", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const req = { model: "models/gemini-exemple", contents: [{ role: "user", parts: [{ text: "Bonjour" }] }], tools: [{ mcpServers: [{ name: "x" }] }], cachedContent: "cachedContents/abc" };
        const e1 = await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: req, response: { error: { code: 429, message: "quota" } }, status: 429, durationMs: 5, isError: false });
        const ev1 = (await d.evenements()).find((x) => x.seq === e1.seq);
        expect(ev1.execution.is_error).to.equal(true);
        expect(await lirePiece(d, ev1.execution.result.sha256)).to.deep.equal({ noortrace_http_error: { status: 429, content_type: null, body: { error: { code: 429, message: "quota" } } } });
        expect(ev1.code.model).to.equal("gemini/gemini-exemple");
        expect(d.lignes("provider_mcp_bypass")).to.have.length(1);
        expect(d.lignes("provider_cache_reference")).to.have.length(1);
        const e2 = await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: { contents: [] }, response: [], status: 200, durationMs: 5, isError: false });
        const ev2 = (await d.evenements()).find((x) => x.seq === e2.seq);
        expect(ev2.execution.is_error).to.equal(true);
        expect(await lirePiece(d, ev2.execution.result.sha256)).to.deep.equal({ noortrace_flux_incomplet: true });
        expect(ev2.code.model).to.equal(null);
        // Segment de modèle qui déclenche un détecteur : refusé (EX-5.36), code.model null.
        const e3 = await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: { model: "models/jean@exemple.ch", contents: [] }, response: { candidates: [] }, status: 200, durationMs: 1, isError: false });
        expect((await d.evenements()).find((x) => x.seq === e3.seq).code.model).to.equal(null);
        // Réponse hors forme (ni objet ni tableau d'objets) : -32602.
        let err = null;
        try {
          await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: {}, response: [1, 2], status: 200, durationMs: 1, isError: false });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceEntreeInvalide);
        await s.fermer();
      });
    });

    it("corrélation (5.6, EX-5.22, 6.3) : code.model d'un appel déclaré vient d'un échange déclaré, consignée comme déclarée ; un échange interposé lui est préféré ; l'intent est la valeur déclarée", async function () {
      const dir0 = {};
      const registre = new RegistreCorrelation({
        fenetreMs: 600000,
        monotone: () => dir0.coeur.horlogeBrute.monotone(),
        ecrirePiece: (p) => dir0.coeur.ecrirePiece(p),
        journal: { consigner: (...a) => dir0.coeur.journal.consigner(...a) },
      });
      await avecDemon({ correlateur: registre }, async (d) => {
        dir0.coeur = d.coeur;
        const s = await d.client().ouvrir({});
        const reponse = { candidates: [{ content: { role: "model", parts: [{ text: "Je lis le sinistre." }, { functionCall: { name: "lire_sinistre", args: { id: "77812" } } }] } }], modelVersion: "gemini-declare-001" };
        await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: { contents: [] }, response: reponse, status: 200, durationMs: 3, isError: false });
        const debut = await s.debutAppel({ tool: "lire_sinistre", arguments: { id: "77812" }, classe: "lecture", intent: "Lire le sinistre" });
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 1 });
        const e = (await d.evenements()).find((x) => x.seq === fin.seq);
        expect(e.code.model).to.equal("gemini/gemini-declare-001");
        expect(e.intent).to.equal("Lire le sinistre");
        expect(d.lignes("correlation_declaree")).to.have.length(1);
        // Échange interposé inscrit (passerelle) puis échange déclaré : l'interposé est préféré.
        const forme = { candidates: [{ content: { role: "model", parts: [{ functionCall: { name: "lire_sinistre", args: { id: "1" } } }] } }], modelVersion: "gemini-interpose-002" };
        const ent = registre.inscrire({ host: hoteSdk(), host_group: "agent-sinistres", run_id: null, format: "gemini", formeClair: forme, interpose: true });
        registre.completer(ent, { formeRedigee: forme, code: { model: "passerelle/gemini-interpose-002", prompt_version: null } });
        await s.echangeModele({ format: "gemini", providerLabel: "gemini", request: { contents: [] }, response: { ...forme, modelVersion: "gemini-declare-003" }, status: 200, durationMs: 3, isError: false });
        const d2 = await s.debutAppel({ tool: "lire_sinistre", arguments: { id: "1" }, classe: "lecture" });
        const f2 = await s.finAppel(d2, { resultat: null, isError: false, durationMs: 1 });
        expect((await d.evenements()).find((x) => x.seq === f2.seq).code.model).to.equal("passerelle/gemini-interpose-002");
        await s.fermer();
      });
    });
  });

  describe("table de 6.2 (classe), EX-6.15, EX-6.18 : la classe de la configuration prime", function () {
    it("une classe déclarée ne fait que renforcer ; sans classe configurée (version 0), la déclarée, à défaut ecriture", function () {
      expect(classeSdk("ecriture", "lecture")).to.deep.equal({ classe: "ecriture", ecart: true });
      expect(classeSdk("lecture", "ecriture")).to.deep.equal({ classe: "ecriture", ecart: false });
      expect(classeSdk("lecture", null)).to.deep.equal({ classe: "lecture", ecart: false });
      expect(classeSdk(null, null)).to.deep.equal({ classe: "ecriture", ecart: false });
      expect(classeSdk(null, "lecture")).to.deep.equal({ classe: "lecture", ecart: false });
      expect(classeConfigureeSdk(configurationExemple(), "agent-local", "x")).to.equal(null);
    });

    it("sans classe déclarée, un appel est une écriture : intention et effet par défaut", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        const debut = await s.debutAppel({ tool: "outil_inconnu", arguments: {} });
        expect(lignesIntention(d)).to.have.length(2);
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        expect((await d.evenements()).find((x) => x.seq === fin.seq).effects[0].action).to.equal("ecriture");
        await s.fermer();
      });
    });
  });

  describe("EX-12.15, EX-6.13, table de 6.2 (fermer) : reprise d'un appel resté ouvert", function () {
    it("à chaud : fermer avec un debutAppel d'écriture sans finAppel donne l'événement de reprise ; une lecture non soumise à approbation n'en donne aucun", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        await s.debutAppel({ tool: "preparer_paiement", arguments: ARGS, classe: "ecriture" });
        await s.debutAppel({ tool: "lire", arguments: {}, classe: "lecture" });
        const avant = (await d.evenements()).length;
        await s.fermer();
        const evts = await d.evenements();
        expect(evts.length).to.equal(avant + 1);
        const e = evts.at(-1);
        expect(e.execution.tool).to.equal("agent-local__preparer_paiement");
        expect(e.execution.status).to.equal("executee");
        expect(e.execution.is_error).to.equal(true);
        expect(e.execution.duration_ms).to.equal(0);
        const l = lignesIntention(d);
        expect(await lirePiece(d, e.execution.result.sha256)).to.deep.equal({ intention_sha256: N_sha(l[0]), noortrace_reprise: "resultat inconnu : enregistreur arrete pendant le relais" });
        expect(e.execution.result.sha256).to.equal(pieceReprise(N_sha(l[0])).sha256);
        expect(l.at(-1)).to.deep.equal({ lifted: l[0].intent_id, seq: e.seq });
        expect(d.lignes("intent_recovered")).to.have.length(1);
      });
    });

    it("à chaud : une connexion perdue clôt la session et donne la reprise ; un appel approuvé repris porte l'approbation et la consomme (EX-6.7)", async function () {
      await avecDemon({ decider: (r) => (r.tool_announced.endsWith("payer") ? { decision: "a_approuver", rule: "paiement" } : { decision: "autorise", rule: null }) }, async (d) => {
        const p = await priseBrute(d.config.sdk.socket);
        const o = await p.appel("ouvrir", { run_id: null, on_behalf_of: null });
        const n = await p.appel("debutAppel", { session: o.result.session, tool: "payer", arguments: { m: "lecture" }, class: "lecture" }, 2);
        await ouvert(d, n.result.ticket);
        d.service.decider_ticket(n.result.ticket, { decision: "approuve" });
        await d.coeur.traiterRemises();
        const ok = await p.appel("debutAppel", { session: o.result.session, tool: "payer", arguments: { m: "lecture" }, class: "lecture" }, 3);
        expect(ok.result.ticket_state).to.equal("approuve");
        const avant = (await d.evenements()).length;
        p.fermer();
        for (let k = 0; k < 50 && (await d.evenements()).length === avant; k++) await new Promise((x) => setTimeout(x, 20));
        const e = (await d.evenements()).at(-1);
        expect(e.execution.is_error).to.equal(true);
        expect(e.approval.decision).to.equal("approuve");
        // Classe tirée du journal d'intention et de la configuration, comme à
        // froid : outil du SDK sans classe configurée, « à défaut ecriture »
        // (EX-12.15, table de 6.2, lecture 117) : effet par défaut d'EX-7.6.
        expect(e.effects).to.deep.equal([{ system: "agent-local", action: "ecriture", object: "payer", amount: null, currency: null }]);
        await new Promise((x) => setTimeout(x, 50));
        expect(d.service.messages.filter((m) => m.methode === "consommer").map((m) => m.corps.seq)).to.include(e.seq);
        expect(d.lignes("sdk_session_closed").at(-1).data.reason).to.equal("connexion_perdue");
      });
    });

    it("à froid : le démon arrêté avec un debutAppel d'écriture ouvert ; la relecture du journal d'intention scelle la reprise au démarrage (EX-12.14)", async function () {
      const d = await demarrerDemonSdk({});
      const s = await d.client().ouvrir({});
      await s.debutAppel({ tool: "preparer_paiement", arguments: ARGS, classe: "ecriture" });
      const avant = (await d.evenements()).length;
      await d.arreter();
      const coeur = await Coeur.demarrer({ config: d.config, secrets: secretsDev() });
      try {
        const evts = await lireEvenements(coeur.repertoire);
        expect(evts.length).to.equal(avant + 1);
        expect(evts.at(-1).execution.tool).to.equal("agent-local__preparer_paiement");
        expect(evts.at(-1).execution.is_error).to.equal(true);
      } finally {
        await coeur.arreter();
      }
    });
    it("à chaud et à froid, la même reprise d'une lecture approuvée (EX-12.14, EX-12.15, lecture 117) : mêmes effets, même politique, même approbation, même forme", async function () {
      const decider = (r) => (r.tool_announced.endsWith("payer") ? { decision: "a_approuver", rule: "paiement" } : { decision: "autorise", rule: null });
      // Lecture approuvée ouverte : debutAppel retenu, approuvé, puis rendu autorise (intention écrite, EX-12.12).
      const ouvrirLectureApprouvee = async (d) => {
        const p = await priseBrute(d.config.sdk.socket);
        const o = await p.appel("ouvrir", { run_id: null, on_behalf_of: null });
        const n = await p.appel("debutAppel", { session: o.result.session, tool: "payer", arguments: { m: "lecture" }, class: "lecture" }, 2);
        await ouvert(d, n.result.ticket);
        d.service.decider_ticket(n.result.ticket, { decision: "approuve" });
        await d.coeur.traiterRemises();
        const ok = await p.appel("debutAppel", { session: o.result.session, tool: "payer", arguments: { m: "lecture" }, class: "lecture" }, 3);
        expect(ok.result.decision).to.equal("autorise");
        expect(lignesIntention(d).filter((l) => l.intent_id)).to.have.length(1);
        return p;
      };
      // À chaud : connexion perdue, le démon tourne.
      const dc = await demarrerDemonSdk({ decider });
      let chaud;
      try {
        const p = await ouvrirLectureApprouvee(dc);
        const avant = (await dc.evenements()).length;
        p.fermer();
        for (let k = 0; k < 50 && (await dc.evenements()).length === avant; k++) await new Promise((x) => setTimeout(x, 20));
        chaud = (await dc.evenements()).at(-1);
      } finally {
        await dc.arreter();
      }
      // À froid : le démon s'arrête avec l'appel ouvert ; relecture au démarrage.
      const df = await demarrerDemonSdk({ decider });
      const p = await ouvrirLectureApprouvee(df);
      const avant = (await df.evenements()).length;
      await df.arreter();
      p.fermer();
      const coeur = await Coeur.demarrer({ config: df.config, secrets: secretsDev() });
      let froid;
      try {
        const evts = await lireEvenements(coeur.repertoire);
        expect(evts.length).to.equal(avant + 1);
        froid = evts.at(-1);
      } finally {
        await coeur.arreter();
      }
      for (const e of [chaud, froid]) {
        expect(e.execution.tool).to.equal("agent-local__payer");
        expect(e.execution.is_error).to.equal(true);
        expect(e.approval.decision).to.equal("approuve");
      }
      // Seules diffèrent les valeurs propres à chaque démon (ticket, seq, horodatage, pièce de reprise de son intention).
      const forme = (e) => ({
        cles: Object.keys(e).sort(),
        effects: e.effects,
        delegation: { ...e.delegation, launched_by: typeof e.delegation.launched_by },
        code: e.code,
        intent: e.intent,
        context: e.context,
        policy: { ...e.policy, ticket: typeof e.policy.ticket },
        approval: { decision: e.approval.decision, cles: Object.keys(e.approval).sort() },
        execution: { ...e.execution, result: Object.keys(e.execution.result).sort() },
      });
      expect(forme(froid)).to.deep.equal(forme(chaud));
      expect(froid.effects).to.deep.equal([{ system: "agent-local", action: "ecriture", object: "payer", amount: null, currency: null }]);
    });
  });

  describe("14.2, 14.5, 14.6 pour le SDK", function () {
    it("mode dégradé « stockage » : écriture -31010 ; lecture passante, événement en attente puis scellé ; finAppel rend { seq: null, hash: null }", async function () {
      await avecDemon({}, async (d) => {
        const s = await d.client().ouvrir({});
        d.coeur.degrade.entrer("stockage");
        let err = null;
        try {
          await s.debutAppel({ tool: "ecrire_note", arguments: {}, classe: "ecriture" });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceDegrade);
        expect(err.raison).to.equal("stockage");
        const debut = await s.debutAppel({ tool: "lire", arguments: { id: 1 }, classe: "lecture" });
        expect(debut.decision).to.equal("autorise");
        const fin = await s.finAppel(debut, { resultat: { ok: 1 }, isError: false, durationMs: 2 });
        expect(fin).to.deep.equal({ seq: null, hash: null });
        expect(d.coeur.attente).to.have.length(1);
        d.coeur.degrade.sortir("stockage");
        await d.coeur.viderAttente();
        const e = (await d.evenements()).at(-1);
        expect(e.execution.tool).to.equal("agent-local__lire");
        expect(e.execution.duration_ms).to.equal(2);
        await s.fermer();
      });
    });

    it("mode observation (14.6) : la politique est évaluée sans être appliquée ; aucune panne ne bloque ; marque [observation …] ; observation_would_block", async function () {
      await avecDemon(
        {
          // Service en mode observation (CT-3 EX-12.20) : la réponse ne porte pas de ticket.
          service: Object.assign(new ServiceApprobationFactice({ org_id: "0x", journal_id: "0x" }), {
            async evaluer(r) {
              this.enregistrer("evaluer", r);
              return { rule: "revue", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null };
            },
          }),
          modifier: (c) => {
            c.policy.approval.mode = "observation";
            c.policy.version = `${c.policy.version}-observation`;
          },
        },
        async (d) => {
          const s = await d.client().ouvrir({});
          const debut = await s.debutAppel({ tool: "payer", arguments: ARGS, classe: "ecriture" });
          expect(debut.decision).to.equal("autorise");
          expect(debut.ticket).to.equal(null);
          const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
          const e = (await d.evenements()).find((x) => x.seq === fin.seq);
          expect(e.policy.rule).to.equal("revue [observation a_approuver]");
          expect(e.policy.decision).to.equal("autorise");
          expect(d.lignes("observation_would_block").map((l) => l.data.reason)).to.include("approbation");
          // Panne : l'écriture passe, événement en attente, jamais -31017.
          d.coeur.degrade.entrer("stockage");
          const d2 = await s.debutAppel({ tool: "payer", arguments: { ...ARGS, montant: "2.00" }, classe: "ecriture" });
          expect(d2.decision).to.equal("autorise");
          expect(await s.finAppel(d2, { resultat: null, isError: false, durationMs: 0 })).to.deep.equal({ seq: null, hash: null });
          d.coeur.degrade.sortir("stockage");
          await s.fermer();
        },
      );
    });

    it("quota de la connexion d'hôte (EX-4.47) : -31013 direction quota ; jamais pour finAppel", async function () {
      await avecDemon({ hotes: [hoteSdk({ quota: { received_bytes_per_minute: 1024 } })] }, async (d) => {
        const s = await d.client().ouvrir({});
        const debut = await s.debutAppel({ tool: "lire", arguments: { x: "y".repeat(600) }, classe: "lecture" });
        let err = null;
        try {
          await s.debutAppel({ tool: "lire", arguments: { x: "z".repeat(600) }, classe: "lecture" });
        } catch (e) {
          err = e;
        }
        expect(err).to.be.instanceOf(ErreurNoortraceLimite);
        expect(err.direction).to.equal("quota");
        expect(err.limite).to.equal(1024);
        const fin = await s.finAppel(debut, { resultat: null, isError: false, durationMs: 0 });
        expect(fin.seq).to.be.a("number");
      });
    });
  });

  describe("entrées hostiles sur la prise", function () {
    it("JSON invalide, CR, lot, méthode inconnue, paramètres non objet, paramètre inconnu, session inconnue ou d'une autre connexion, nombre non représentable, notification, ligne trop longue", async function () {
      await avecDemon({ modifier: (c) => (c.limits.line_max_bytes = 4096) }, async (d) => {
        const p = await priseBrute(d.config.sdk.socket);
        const q = await priseBrute(d.config.sdk.socket);
        expect(p.identite).to.deep.equal({ noortrace_identite: "acceptee" });
        p.envoyer("{pas du json");
        expect((await p.suivante()).error.code).to.equal(-32700);
        p.envoyer('{"jsonrpc":"2.0","id":1,"method":"noortrace/sdk/ouvrir","params":{}}\r');
        expect((await p.suivante()).error.data.reason).to.equal("cr_dans_la_ligne");
        p.envoyer('[{"jsonrpc":"2.0","id":1,"method":"noortrace/sdk/ouvrir"}]');
        expect((await p.suivante()).error.code).to.equal(-32600);
        expect((await p.appel("inconnue", {})).error.code).to.equal(-32601);
        p.envoyer('{"jsonrpc":"2.0","id":2,"method":"noortrace/sdk/ouvrir","params":[1]}');
        expect((await p.suivante()).error.code).to.equal(-32602);
        expect((await p.appel("ouvrir", { run_id: null, extra: 1 })).error.data.reason).to.equal("parametre_inconnu");
        p.envoyer('{"jsonrpc":"2.0","id":3,"method":"noortrace/sdk/ouvrir","params":{"run_id":null,"run_id":"x"}}');
        expect((await p.suivante()).error.data.reason).to.equal("cle_double");
        const o = (await p.appel("ouvrir", { run_id: null, on_behalf_of: null }, 4)).result;
        expect((await q.appel("debutAppel", { session: o.session, tool: "x", arguments: {} })).error.data.reason).to.equal("session_inconnue");
        expect((await p.appel("debutAppel", { session: "s-inconnue", tool: "x", arguments: {} }, 5)).error.data.reason).to.equal("session_inconnue");
        p.envoyer(`{"jsonrpc":"2.0","id":6,"method":"noortrace/sdk/debutAppel","params":{"session":"${o.session}","tool":"x","arguments":{"n":12345678901234567890}}}`);
        expect((await p.suivante()).error.data.reason).to.equal("nombre_non_representable");
        p.envoyer('{"jsonrpc":"2.0","method":"noortrace/sdk/ouvrir","params":{}}');
        p.envoyer("x".repeat(5000));
        expect(await p.suivante()).to.deep.include({ id: null });
        expect(d.lignes("request_too_large")).to.have.length(1);
        // finAppel d'un call inconnu, fermer d'une session d'une autre connexion.
        expect((await q.appel("fermer", { session: o.session }, 7)).error.data.reason).to.equal("session_inconnue");
        expect((await p.appel("fermer", { session: o.session }, 8)).result).to.deep.equal({});
        expect((await p.appel("fermer", { session: o.session }, 9)).error.data.reason).to.equal("session_inconnue");
        p.fermer();
        q.fermer();
        expect(d.coeur.degrade.enModeDegrade).to.equal(false);
      });
    });

    it("une preuve d'identité fausse ou absente est refusée", async function () {
      await avecDemon({}, async (d) => {
        const c = net.createConnection(d.config.sdk.socket);
        await new Promise((r) => c.once("data", r));
        c.write(JSON.stringify({ noortrace_preuve: "0".repeat(32) }) + "\n");
        await new Promise((r) => c.once("close", r));
        expect(d.lignes("auth_failed").map((l) => l.data.reason)).to.include("preuve");
      });
    });
  });

  // Défauts démontrés par la relecture adversariale B des frontaux.
  describe("relecture B : non-régression du point d'entrée SDK", function () {
    const req = (id, m, p) => new TextEncoder().encode(JSON.stringify({ jsonrpc: "2.0", id, method: "noortrace/sdk/" + m, params: p }));

    it("R-B-7 (EX-6.13, EX-12.15) : connexion perdue pendant un debutAppel d'écriture : l'intention écrite après la clôture est reprise à chaud", async function () {
      await avecDemon({}, async (d) => {
        const f = d.sdk.frontal;
        const hote = d.config.sdk.hosts[0];
        const cx = f.ouvrirConnexion({ hote, identite: { peer_user: hote.match.peer_user } });
        const session = JSON.parse(await f.recevoir(cx, req(1, "ouvrir", { run_id: null, on_behalf_of: null }))).result.session;
        const p = f.recevoir(cx, req(2, "debutAppel", { session, tool: "payer", arguments: { montant: "10.00" }, class: "ecriture", context: [], intent: null, effects: null }));
        await new Promise((r) => setImmediate(r));
        await f.fermerConnexion(cx);
        expect(JSON.parse(await p).result.decision).to.equal("autorise");
        const ev = (await d.evenements()).filter((e) => !e.execution.tool.startsWith("noortrace."));
        expect(ev.map((e) => [e.execution.tool, e.execution.status, e.execution.is_error])).to.deep.equal([["agent-local__payer", "executee", true]]);
        expect(d.lignes("intent_recovered").map((l) => l.data.session_closed)).to.deep.equal([true]);
        expect(d.coeur.relaisEnCours.size).to.equal(0);
      });
    });

    it("R-B-6 (4.4 pas 1, EX-4.47) : lignes au-delà de line_max_bytes comptées ; temps d'analyse d'une requête refusée compté", async function () {
      await avecDemon({ hotes: [hoteSdk({ quota: { received_bytes_per_minute: 50000 } })], modifier: (c) => (c.limits.line_max_bytes = 4096) }, async (d) => {
        const p = await priseBrute(d.config.sdk.socket);
        for (let k = 0; k < 3; k++) p.envoyer("x".repeat(20000));
        for (let k = 0; k < 3; k++) expect((await p.suivante()).error.data).to.deep.equal({ limit_bytes: 4096, direction: "requete" });
        const o = await p.appel("ouvrir", { run_id: null, on_behalf_of: null }, 7);
        expect(o.error).to.deep.equal({ code: -31013, message: "noortrace: taille maximale depassee", data: { limit_bytes: 50000, direction: "quota" } });
        p.fermer();
      });
      class HorlogeQuiAvance extends HorlogeReglable {
        monotone() {
          this.mono += 1;
          return this.mono;
        }
      }
      await avecDemon({ horloge: new HorlogeQuiAvance(Date.now()) }, async (d) => {
        const f = d.sdk.frontal;
        const hote = d.config.sdk.hosts[0];
        const cx = f.ouvrirConnexion({ hote, identite: { peer_user: hote.match.peer_user } });
        for (const x of ["{", "[1]", '{"jsonrpc":"2.0","id":1,"method":"noortrace/sdk/inconnue"}']) await f.recevoir(cx, new TextEncoder().encode(x));
        expect(f.quotas.get(hote.id).capture.total(f.monotone())).to.be.greaterThan(0);
      });
    });

    it("R-B-11 (EX-18.1) : sdk.socket a le mode 0660 dès sa création, sans fenêtre où elle serait plus ouverte", async function () {
      const origine = net.Server.prototype.listen;
      const modes = [];
      net.Server.prototype.listen = function (...a) {
        const x = origine.apply(this, a);
        if (typeof a[0] === "string" && a[0].endsWith("sdk.sock")) modes.push(fs.statSync(a[0]).mode & 0o777);
        return x;
      };
      const masque = process.umask(0o000);
      try {
        await avecDemon({}, async (d) => {
          expect(fs.statSync(d.config.sdk.socket).mode & 0o777).to.equal(0o660);
        });
      } finally {
        process.umask(masque);
        net.Server.prototype.listen = origine;
      }
      expect(modes).to.deep.equal([0o660]);
    });
  });

  describe("EX-15.4 pas 3 (SDK), EX-6.24 : validation de la configuration", function () {
    const base = () => {
      const dir = repertoireTemporaire("noortrace-sdk-cfg-");
      return configurationDev(dir, { sdk: { hosts: [hoteSdk()] } }).config;
    };
    const valider = (c) => validerConfiguration(new TextEncoder().encode(JSON.stringify(c)), { reglesSupplementaires: [controleSdk] });

    it("réussite : alias annoncés égaux à ceux de sdk.hosts ; avertissement sans policy.sdk", function () {
      expect(valider(base()).erreurs).to.deep.equal([]);
      const c = base();
      delete c.policy.sdk;
      const v = valider(c);
      expect(v.erreurs).to.deep.equal([]);
      expect(v.avertissements.map((a) => a.pointeur)).to.include("/policy/sdk");
    });

    it("échec : alias nul, égal à un serveur, en double, alias hors de sdk.hosts, policy.sdk différent, jeton inconnu, aucune entrée", function () {
      const cas = [
        [(c) => (c.sdk.hosts[0].alias = null), "/sdk/hosts/0/alias"],
        [(c) => ((c.sdk.hosts[0].alias = "sap"), (c.policy.sdk.aliases = ["sap"])), "/sdk/hosts/0/alias"],
        [(c) => c.sdk.hosts.push({ ...c.sdk.hosts[0], id: "autre" }), "/sdk/hosts/1/alias"],
        [(c) => (c.mcp.hosts[0].alias = "agent-local"), "/mcp/hosts/0/alias"],
        [(c) => (c.policy.sdk.aliases = ["autre"]), "/policy/sdk/aliases"],
        [(c) => (c.sdk.hosts[0].match = { static_token: "inconnu" }), "/sdk/hosts/0/match/static_token"],
        [(c) => (c.sdk.hosts = []), "/sdk/hosts"],
      ];
      for (const [f, pointeur] of cas) {
        const c = base();
        f(c);
        expect(valider(c).erreurs.map((e) => e.pointeur), pointeur).to.include(pointeur);
      }
    });
  });
});

/** SHA-256 du JCS intégral de la ligne intention à neuf clés (EX-12.12). */
function N_sha(ligne) {
  return "0x" + createHash("sha256").update(jcsIntegral(ligne)).digest("hex");
}
