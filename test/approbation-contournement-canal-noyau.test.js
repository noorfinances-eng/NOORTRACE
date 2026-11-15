// Revue de sécurité de l'étape 8 — correction du contournement de l'approbation
// humaine par le canal du noyau (CT-3 EX-12.5, CT-2 EX-7.16). Trois règles
// nouvelles :
//   1. service : règle de configuration `canaux_meme_autorite_sans_jeton` —
//      deux canaux en mTLS, même autorité de clients, qu'aucun jeton ne
//      distingue, sont refusés (le certificat « console » ouvrirait le canal
//      du noyau). Un certificat de l'autre canal, sans le jeton du canal,
//      reçoit 401.
//   2. service : durcissement de `charger` — à empreinte déclarée égale, la
//      politique gardée doit être identique (sinon réécriture de la version en
//      vigueur) ; un `environment` différent de celui du service est refusé.
//   3. noyau : `peutAutoriserOutil` et garde de `coeur.evaluer` — une réponse
//      `autorise`/`null` pour un outil que la politique épinglée classe comme
//      toujours soumis à approbation ou interdit est refusée (code
//      `autorise_incoherent_politique_epinglee`, ligne d'exploitation
//      `approval_autorise_rejete_politique_epinglee`) ; l'appel n'est pas
//      relayé. La preuve par mutant (oracle qui échoue quand la règle est
//      retirée) est jouée hors du dépôt.

import { expect } from "chai";
import fs from "node:fs";
import * as A from "@noortrace/approbation";
import * as N from "@noortrace/noyau";
import {
  Coeur, HorlogeReglable, ErreurEnregistreur, peutAutoriserOutil,
} from "@noortrace/enregistreur";
const { Ecoute } = A;
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import {
  ORG_ID, JOURNAL_ID, SESSIONS, ANNUAIRE_REFERENCE, messageCharger, politiqueParcours, JEU_STATIQUE,
} from "./fixtures/approbation-service/outils.mjs";

const ms = (t) => N.decoderHorodatage(t);
const enc = (o) => new TextEncoder().encode(JSON.stringify(o));

// ----------------------------------------------------------------------------
// 1. Règle de configuration canaux_meme_autorite_sans_jeton (CT-3 EX-10.12, EX-12.4)
// ----------------------------------------------------------------------------
describe("Contournement de l'approbation, 1 : configuration du service, canaux_meme_autorite_sans_jeton (CT-3 EX-10.12, EX-12.4)", function () {
  const tls = () => ({ cert: { file: "/run/secrets/srv.pem" }, key: { file: "/run/secrets/srv.key" }, client_ca: { file: "/run/secrets/ca.pem" } });
  const base = () => ({
    version: 0, environment: "production", org: "assureur-demo", org_id: ORG_ID, journal_id: JOURNAL_ID,
    state_dir: "/var/lib/noortrace-approbation", storage_key: { file: "/run/secrets/cle" },
    administrators: [SESSIONS.admin], console_origin: "https://console.assureur-demo.example",
    rpc: { url: "https://rpc.assureur-demo.example", validator: "client", token: null },
  });

  it("deux canaux mTLS, MÊME autorité de clients, SANS jeton : configuration refusée (canaux_meme_autorite_sans_jeton)", function () {
    const c = { ...base(), noyau: { tcp: { host: "0.0.0.0", port: 8500 }, tls: tls(), token: null }, console: { tcp: { host: "0.0.0.0", port: 8600 }, tls: tls(), token: null, annuaire: null } };
    const r = A.validerConfiguration(c);
    expect(r.valide).to.equal(false);
    expect(r.errors).to.deep.include({ code: "canaux_meme_autorite_sans_jeton", pointer: "/noyau/tls/client_ca" });
  });

  it("MÊME autorité mais jetons DISTINCTS : accepté (le jeton distingue les canaux)", function () {
    const c = { ...base(), noyau: { tcp: { host: "0.0.0.0", port: 8500 }, tls: tls(), token: { file: "/run/secrets/jeton-noyau" } }, console: { tcp: { host: "0.0.0.0", port: 8600 }, tls: tls(), token: { file: "/run/secrets/jeton-console" }, annuaire: null } };
    const r = A.validerConfiguration(c);
    expect(r.errors.filter((e) => e.code === "canaux_meme_autorite_sans_jeton")).to.deep.equal([]);
    expect(r.valide).to.equal(true);
  });

  it("autorités de clients DIFFÉRENTES, sans jeton : la règle ne s'applique pas", function () {
    const tlsC = { cert: { file: "/run/secrets/srv.pem" }, key: { file: "/run/secrets/srv.key" }, client_ca: { file: "/run/secrets/ca-console.pem" } };
    const c = { ...base(), noyau: { tcp: { host: "0.0.0.0", port: 8500 }, tls: tls(), token: null }, console: { tcp: { host: "0.0.0.0", port: 8600 }, tls: tlsC, token: null, annuaire: null } };
    const r = A.validerConfiguration(c);
    expect(r.errors.filter((e) => e.code === "canaux_meme_autorite_sans_jeton")).to.deep.equal([]);
  });

  it("un canal sans mTLS (jeton seul) : la règle ne s'applique pas", function () {
    const c = { ...base(), noyau: { socket: "/run/noortrace/approbation.sock", token: { file: "/run/secrets/jeton-noyau" } }, console: { tcp: { host: "0.0.0.0", port: 8600 }, tls: tls(), token: { file: "/run/secrets/jeton-console" }, annuaire: null } };
    const r = A.validerConfiguration(c);
    expect(r.errors.filter((e) => e.code === "canaux_meme_autorite_sans_jeton")).to.deep.equal([]);
  });

  it("l'écoute du noyau protégée par jeton rejette 401 un appel sans le porteur (le détenteur du cert de l'autre canal n'a pas le jeton)", async function () {
    this.timeout(10000);
    const appels = [];
    const service = { supervision: { consigner: () => {} }, etat: () => ({ ready: true }), charger: async (x) => { appels.push(x.policy_version ?? null); return { recu: "charger" }; } };
    const e = new Ecoute({ canal: "noyau", service, config: { socket: null, tcp: { host: "127.0.0.1", port: 0 } }, tls: null, jeton: "jeton-du-canal-du-noyau-16+", bodyMax: 65536 });
    const adr = await e.demarrer();
    try {
      const sans = await fetch(`http://127.0.0.1:${adr.port}/v0/charger`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ policy_version: "x" }) });
      expect(sans.status).to.equal(401);
      const mauvais = await fetch(`http://127.0.0.1:${adr.port}/v0/charger`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer jeton-de-la-console-distinct" }, body: JSON.stringify({ policy_version: "x" }) });
      expect(mauvais.status).to.equal(401);
      expect(appels).to.deep.equal([]);
    } finally {
      await e.arreter();
    }
  });
});

// ----------------------------------------------------------------------------
// 2. Durcissement de charger (CT-3 EX-12.5)
// ----------------------------------------------------------------------------
describe("Contournement de l'approbation, 2 : service, durcissement de charger (CT-3 EX-12.5)", function () {
  let dir;
  let service;
  const permissive = { version: 0, default: { name: "tout autorise", description: null, level: "automatique", decision: "autorise", contest_ms: null }, rules: [], approver_set: JEU_STATIQUE, separation: { self_approval: "permise", identities: [] } };

  beforeEach(function () {
    dir = repertoireTemporaire("noortrace-s1-charger-");
    const config = { org_id: ORG_ID, journal_id: JOURNAL_ID, environment: "developpement", set_poll_interval_ms: 30, remise_representation_ms: 30000, body_max_bytes: 1 << 24, escalation: [], administrators: [SESSIONS.admin] };
    const machine = new A.Machine({ org_id: ORG_ID, journal_id: JOURNAL_ID, identifiants: { mode: "compteur" }, administrators: config.administrators });
    const supervision = new A.Supervision({ journal: `${dir}/j.ndjson`, notifications: `${dir}/n.ndjson` });
    const annuaire = new A.EtatAnnuaire({ document: JSON.parse(fs.readFileSync(ANNUAIRE_REFERENCE, "utf8")), defis: [], persiste: false });
    service = new A.ServiceApprobation({ config, machine, magasin: null, supervision, lecteur: null, annuaire });
  });

  const rejet = async (p) => { try { await p; return null; } catch (e) { return e; } };

  it("réécriture de la version en vigueur à empreinte égale (politique différente) : requete_invalide", async function () {
    const strict = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
    await service.charger(strict);
    const ecrase = { ...strict, approval: { ...strict.approval, rules: permissive } };
    const e = await rejet(service.charger(ecrase));
    expect(e, "la réécriture doit être refusée").to.be.instanceOf(A.ErreurService);
    expect(e.code).to.equal("requete_invalide");
    // la version en vigueur reste la politique stricte
    expect(service.machine.version("parcours-1").approval.rules.default.name).to.equal(politiqueParcours().default.name);
  });

  it("re-charger identique de la même version : accepté", async function () {
    const strict = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
    await service.charger(strict);
    const r = await service.charger(strict);
    expect(r.policy_version).to.equal("parcours-1");
  });

  it("même version, même politique, liste d'outils enrichie : accepté (pas de faux positif)", async function () {
    const strict = messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() });
    await service.charger(strict);
    const plus = { ...strict, tools: [...strict.tools, { tool_announced: "sap__claims.list", tool_original: "claims.list", server_alias: "sap", class: "lecture", effects: null }] };
    const r = await service.charger(plus);
    expect(r.policy_version).to.equal("parcours-1");
  });

  it("environment différent de celui du service : requete_invalide (CT-3 EX-12.5)", async function () {
    const prod = messageCharger({ policy_version: "parcours-9", rules: politiqueParcours(), environment: "production" });
    const e = await rejet(service.charger(prod));
    expect(e).to.be.instanceOf(A.ErreurService);
    expect(e.code).to.equal("requete_invalide");
  });
});

// ----------------------------------------------------------------------------
// 3. Noyau : défense en profondeur (CT-2 EX-7.16, TQ-1)
// ----------------------------------------------------------------------------
describe("Contournement de l'approbation, 3 : noyau, défense en profondeur contre autorise/null (CT-2 EX-7.16)", function () {
  describe("peutAutoriserOutil (politique épinglée)", function () {
    const dev = configurationDev(repertoireTemporaire("noortrace-s1-pol-")).config;
    const regles = dev.policy.approval.rules;
    it("un outil qu'aucune règle n'autorise automatiquement (défaut revue) : ne peut pas être autorisé", function () {
      expect(peutAutoriserOutil(regles, "sap__claims.delete")).to.equal(false);
      expect(peutAutoriserOutil(regles, "sap__inconnu.faire")).to.equal(false);
    });
    it("un outil avec une règle automatique autorise, ou une fenêtre : peut être autorisé", function () {
      expect(peutAutoriserOutil(regles, "sap__claims.get")).to.equal(true);
      expect(peutAutoriserOutil(regles, "sap__payments.create")).to.equal(true); // ≤ 5000 CHF autorisé
    });
    it("défaut permissif, ou document absent : peut être autorisé (aucune garde)", function () {
      expect(peutAutoriserOutil({ version: 0, default: { level: "automatique", decision: "autorise" }, rules: [] }, "n'importe")).to.equal(true);
      expect(peutAutoriserOutil(null, "x")).to.equal(true);
    });
  });

  describe("coeur.evaluer refuse autorise/null pour un outil toujours soumis à approbation", function () {
    let coeur;
    let service;
    let exploitation;
    beforeEach(async function () {
      const dir = repertoireTemporaire("noortrace-s1-coeur-");
      let { config } = configurationDev(dir);
      const { validerConfiguration } = await import("@noortrace/enregistreur");
      config = validerConfiguration(enc(config)).config;
      const horloge = new HorlogeReglable(ms("2026-11-10T10:14:02.000Z"));
      // Forme de l'attaque (CT-3 EX-12.5) : à `charger`, le service déclare les
      // outils candidats (décideur a_approuver → CANDIDATS = outils envoyés) ;
      // puis, à `evaluer`, il rend `autorise`/`null`, y compris pour la
      // suppression, que la politique épinglée soumet toujours à approbation.
      service = new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: () => ({ decision: "a_approuver", rule: "revue" }) });
      coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge, service });
      coeur.definirOutils([
        { tool_announced: "sap__claims.delete", tool_original: "claims.delete", server_alias: "sap", class: "ecriture", effects: null },
        { tool_announced: "sap__claims.get", tool_original: "claims.get", server_alias: "sap", class: "lecture", effects: null },
      ]);
      for (let k = 0; k < 200 && !coeur.candidats?.liste.has("sap__claims.delete"); k++) await new Promise((x) => setTimeout(x, 10));
      expect(coeur.candidats?.liste.has("sap__claims.delete"), "le service a déclaré la suppression candidate à charger").to.equal(true);
      // Décision du porteur du 14 novembre 2026 et son addendum : neuf membres, couple chargé recopié comme le service factice (la garde du noyau est éprouvée seule).
      service.evaluer = async (r) => ({ rule: "tout autorise", decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null, policy_version: r.code.policy_version, policy_sha256: service.empreintes.get(r.code.policy_version) ?? null, approval_sha256: service.condenses.get(r.code.policy_version) ?? null });
      exploitation = [];
      const brut = coeur.journal.consigner.bind(coeur.journal);
      coeur.journal.consigner = (niveau, comp, evt, data, ctx) => { exploitation.push({ niveau, comp, evt, data }); return brut(niveau, comp, evt, data, ctx); };
    });
    afterEach(async function () { await coeur.arreter(); });

    const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:paiement", run_id: null };
    const appel = (tool) => ({ tool_announced: tool, tool_original: tool.split("__")[1], server_alias: tool.split("__")[0], arguments: { claim_id: "2026-7" }, class: "ecriture", delegation, intent: null, code: { model: null, prompt_version: null, policy_version: coeur.versionPolitique, recorder: "0.1.0" }, context: [] });

    it("sap__claims.delete (toujours soumis à approbation) + service qui rend autorise/null : coeur.evaluer refuse, l'appel n'est pas relayé", async function () {
      let err;
      try { await coeur.evaluer(appel("sap__claims.delete")); } catch (e) { err = e; }
      expect(err, "coeur.evaluer doit lever").to.be.instanceOf(ErreurEnregistreur);
      expect(err.raison).to.equal("approbation"); // raison de la matrice 14.2
      expect(err.donnees?.raison).to.equal("autorise_incoherent_politique_epinglee"); // code de refus nommé
      expect(err.code).to.equal(-31010);
      // ligne d'exploitation nommée
      expect(exploitation.some((l) => l.evt === "approval_autorise_rejete_politique_epinglee" && l.data.tool_announced === "sap__claims.delete")).to.equal(true);
      // le service a bien été interrogé (charger a déclaré le candidat), aucune retenue/relais n'a été scellé
      expect(service.messages.some((m) => m.methode === "charger")).to.equal(true);
    });

    it("sans liste CANDIDATS qui nomme l'outil (aucun charger réussi), le noyau ne contredit pas le service : autorise/null passe (pas de faux positif, CT-2 EX-7.15)", async function () {
      coeur.candidats = null;
      const r = await coeur.evaluer(appel("sap__claims.delete"));
      expect(r.decision).to.equal("autorise");
    });

    it("sap__claims.get (lecture autorisée par la politique épinglée) + service qui rend autorise/null : accepté (pas de faux positif)", async function () {
      const r = await coeur.evaluer({ ...appel("sap__claims.get"), class: "lecture" });
      expect(r.decision).to.equal("autorise");
      expect(r.ticket).to.equal(null);
    });
  });
});
