import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/capture.mjs";
import * as AP from "../scripts/lib/approbation.mjs";

// MODE OBSERVATION, partie de l'approbation (CT-3 révision 0.4 : EX-6.8,
// EX-11.11 à EX-11.15, EX-12.20 ; CT-2 révision 0.6 : EX-4.51, EX-7.23,
// EX-14.14, EX-14.15, EX-15.8 ; CT-8 §12.1 à §12.3, EX-A.18) : evaluerObservation
// sur chaque cas d'évaluation de CT-3, sans ticket ni unité de fenêtre
// consommée ; réponse admise sous une version en mode observation ; marque
// « [observation <x>] » ; relais toujours, jamais de refus ni de signal ;
// avertissement de validation et refus d'entrer en observation avec des
// retenues ouvertes ; schéma de configuration étendu de façon compatible.
// Les vérifications OB-1 à OB-6 des vecteurs spec/vecteurs/ct-8/observation/
// relèvent de scripts/lib/exploitation.mjs (CT-8 EX-A.5).

const SPEC = path.join(PROJECT_ROOT, "spec");
const lireSchema = (n) => JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8"));
const NOMS = ["evenement", "manifeste", "dossier", "politique-redaction", "politique-approbation", "ticket", "configuration-enregistreur", "worm", "cout-agent"];
const SCHEMAS = J.registreSchemas(NOMS.map(lireSchema));
const CT2 = fs.readFileSync(path.join(SPEC, "CT-2-enregistreur.md"), "utf8");
const CT3 = fs.readFileSync(path.join(SPEC, "CT-3-approbations.md"), "utf8");
const CT8 = fs.readFileSync(path.join(SPEC, "CT-8-deploiement-et-exploitation.md"), "utf8");
const blocs = (md, marque) => [...md.matchAll(new RegExp(`<!-- schema: ${marque} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``, "g"))].map((m) => m[1]);
const CONFIG = C.analyserJSONIntegral(blocs(CT2, "configuration-enregistreur")[0]);
const ASSUREUR = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-3", "evaluation", "assureur.json"), "utf8"));
/** La politique désignée par le fichier d'évaluation (chemin relatif à spec/vecteurs/ct-3/). */
const P_ASSUREUR = JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-3", ASSUREUR.policy), "utf8"));
const copie = (x) => structuredClone(x);

/** Schéma de configuration tel que CT-2 0.5 l'écrivait : policy.approval.mode ∈ { retenir, erreur }. */
function schemaConfiguration05() {
  const s = lireSchema("configuration-enregistreur");
  let trouve = 0;
  const parcourir = (x) => {
    if (!x || typeof x !== "object") return;
    if (Array.isArray(x.enum) && J.egalJSON(x.enum, ["retenir", "erreur", "observation"])) {
      x.enum = ["retenir", "erreur"];
      trouve++;
    }
    for (const v of Object.values(x)) parcourir(v);
  };
  parcourir(s);
  expect(trouve, "une seule énumération du mode d'attente").to.equal(1);
  return J.registreSchemas([...NOMS.filter((n) => n !== "configuration-enregistreur").map(lireSchema), s]);
}

describe("CT-3 révision 0.4 : evaluerObservation (EX-11.12, EX-11.13, EX-12.20)", function () {
  it("rend, pour chaque cas de evaluation/assureur.json, la règle et la décision d'evaluer, sans ticket, et ne consomme aucune unité de fenêtre", function () {
    expect(ASSUREUR.cases.length).to.equal(24);
    for (const c of ASSUREUR.cases) {
      const fenetres = copie(c.windows);
      const avant = copie(fenetres);
      const e = AP.evaluer(P_ASSUREUR, c.request, { fenetres, t: c.t, policy_version: ASSUREUR.policy_version });
      const o = AP.evaluerObservation(P_ASSUREUR, c.request, { fenetres, t: c.t, policy_version: ASSUREUR.policy_version });
      expect(o, c.id).to.deep.equal({ rule: e.rule, decision: e.decision, ticket: null, ticket_state: null, approval: null, approver_set: null });
      expect([o.rule, o.decision], c.id).to.deep.equal([c.expected.rule, c.expected.decision]);
      expect(fenetres, `${c.id} : fenêtres d'entrée inchangées`).to.deep.equal(avant);
      expect(AP.reponseObservationAdmise(o), c.id).to.equal(true);
      expect(J.validerSchema(o, SCHEMAS["https://noortrace.example/schemas/v0/ticket.schema.json"], { registre: SCHEMAS, fragment: "#/$defs/reponse_evaluer" }), c.id).to.deep.equal([]);
    }
  });

  it("une fenêtre ouverte donne le rang 2 et la marque [fenetre …] sans être décomptée (EX-11.13)", function () {
    const c = ASSUREUR.cases.find((x) => x.id === "paiement-2500-fenetre-ouverte");
    const e = AP.evaluer(P_ASSUREUR, c.request, { fenetres: c.windows, t: c.t, policy_version: ASSUREUR.policy_version });
    expect(e.fenetreConsommee).to.equal(0);
    expect(e.fenetres[0].remaining).to.equal(c.windows[0].remaining - 1);
    const o = AP.evaluerObservation(P_ASSUREUR, c.request, { fenetres: c.windows, t: c.t, policy_version: ASSUREUR.policy_version });
    expect(o.rule).to.match(/ \[fenetre [^ ]+ [0-9T:.Z-]+\]$/);
    expect(o.decision).to.equal("autorise");
    expect(c.windows[0].remaining).to.equal(20);
  });

  it("le bloc annoté d'EX-12.20 est conforme à ticket/reponse_evaluer et égal à evaluerObservation sur le paiement de 7 400 CHF", function () {
    const [texte] = blocs(CT3, "ticket/reponse_evaluer").filter((b) => b.includes('"ticket": null') && b.includes("paiement > 5000 CHF"));
    const bloc = JSON.parse(texte);
    expect(J.validerSchema(bloc, SCHEMAS["https://noortrace.example/schemas/v0/ticket.schema.json"], { registre: SCHEMAS, fragment: "#/$defs/reponse_evaluer" })).to.deep.equal([]);
    const c = ASSUREUR.cases.find((x) => x.id === "paiement-7400");
    expect(AP.evaluerObservation(P_ASSUREUR, c.request, { fenetres: c.windows, t: c.t, policy_version: ASSUREUR.policy_version })).to.deep.equal(bloc);
    // La politique de l'exemple de CT-2 §15.3 rend la même réponse pour ce paiement.
    const d = { ...copie(c.request), tool_announced: "sap__payments.create", code: { ...c.request.code, policy_version: CONFIG.policy.version } };
    const o = AP.evaluerObservation(CONFIG.policy.approval.rules, d, { fenetres: [], t: c.t });
    expect(o).to.deep.equal(bloc);
  });

  it("reponseObservationAdmise : la seule réponse admise sous une version en mode observation (EX-12.20, CT-2 EX-7.23)", function () {
    const ok = { rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null };
    expect(AP.reponseObservationAdmise(ok)).to.equal(true);
    for (const [k, v] of [["ticket", "apr-3001"], ["ticket_state", "nouveau"], ["approval", {}], ["approver_set", { threshold: { required: 1, size: 1 }, members: [], source: "statique" }], ["rule", null], ["rule", ""], ["decision", "sans_objet"]]) {
      expect(AP.reponseObservationAdmise({ ...ok, [k]: v }), `${k} = ${JSON.stringify(v)}`).to.equal(false);
    }
    expect(AP.reponseObservationAdmise({ ...ok, extra: 1 })).to.equal(false);
    const { approver_set, ...sansMembre } = ok;
    expect(AP.reponseObservationAdmise(sansMembre)).to.equal(false);
    // Une réponse sans ticket est aussi l'une des sept combinaisons d'EX-7.16 pour autorise et refuse, jamais pour a_approuver.
    expect(AP.combinaisonAdmise(ok)).to.equal(false);
    expect(AP.combinaisonAdmise({ ...ok, decision: "refuse" })).to.equal(true);
  });
});

describe("CT-3 EX-6.8 et CT-2 EX-14.14, EX-14.15 : marque d'observation et relais", function () {
  it("regleObservation : règle suivie de « [observation <x>] », nom fixe pour inconnu ; table d'EX-12.6 de CT-8", function () {
    const table = [
      ["lectures autorisees", "autorise", "lectures autorisees [observation autorise]"],
      ["paiement > 5000 CHF", "a_approuver", "paiement > 5000 CHF [observation a_approuver]"],
      ["paiement hors CHF", "refuse", "paiement hors CHF [observation refuse]"],
      ["defaut : revue", "a_approuver", "defaut : revue [observation a_approuver]"],
      ["paiement > 5000 CHF [indetermine]", "a_approuver", "paiement > 5000 CHF [indetermine] [observation a_approuver]"],
      [null, "inconnu", "evaluation impossible [observation inconnu]"],
    ];
    for (const [r, x, attendu] of table) {
      expect(AP.regleObservation(r, x)).to.equal(attendu);
      expect(CT8, `table d'EX-12.6 : ${attendu}`).to.include(`\`${attendu}\``);
    }
    expect(() => AP.regleObservation("r", "approuve")).to.throw(/inconnue/);
    expect(() => AP.regleObservation("", "autorise")).to.throw(/non vide/);
    // Bornes de CT-1 : nom de 256, marque de 6.4 de 164 au plus, marque d'observation de 26 au plus ; la chaîne reste sous 1 024.
    expect(" [observation a_approuver]".length).to.equal(26);
    expect(Math.max(...AP.VALEURS_OBSERVATION.map((x) => ` [observation ${x}]`.length))).to.equal(26);
    const longue = AP.regleObservation("n".repeat(256) + " [fenetre " + "t".repeat(128) + " 2026-11-05T16:00:00.000Z]", "autorise");
    expect(longue.length).to.be.below(1024);
    expect(longue.lastIndexOf(" [observation ")).to.equal(longue.length - " [observation autorise]".length);
  });

  it("actionMandataire en mode observation : toujours le relais, policy autorise sans ticket, marque de la décision ; inconnu sans réponse ou sur réponse invalide", function () {
    const base = { rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null };
    const a = AP.actionMandataire(base, { mode: "observation" });
    expect(a).to.deep.equal({ action: "relayer", approval: null, policy: { rule: "paiement > 5000 CHF [observation a_approuver]", decision: "autorise", ticket: null }, would: "a_approuver", raison: "approbation", consigner: null });
    expect(AP.actionMandataire({ ...base, rule: "lectures autorisees", decision: "autorise" }, { mode: "observation" })).to.include({ action: "relayer", would: "autorise", raison: null });
    expect(AP.actionMandataire({ ...base, rule: "paiement hors CHF", decision: "refuse" }, { mode: "observation" })).to.include({ would: "refuse", raison: "politique" });
    const sans = AP.actionMandataire(null, { mode: "observation" });
    expect(sans).to.deep.equal({ action: "relayer", approval: null, policy: { rule: "evaluation impossible [observation inconnu]", decision: "autorise", ticket: null }, would: "inconnu", raison: "approbation", consigner: "approval_service_unavailable" });
    // Une réponse qui porte un ticket est invalide sous une version en mode observation (EX-7.23) : relayée avec inconnu, jamais bloquée.
    const avecTicket = AP.actionMandataire({ ...base, ticket: "apr-3001", ticket_state: "en_attente" }, { mode: "observation" });
    expect(avecTicket).to.include({ action: "relayer", would: "inconnu", consigner: "approval_response_invalid" });
    expect(avecTicket.policy.rule).to.equal("evaluation impossible [observation inconnu]");
    // Les autres modes ne changent pas : la même réponse sans ticket n'est pas applicable (-31010).
    expect(AP.actionMandataire(base, { mode: "erreur" }).action).to.equal("erreur");
  });

  it("l'événement d'un appel relayé en mode observation est un événement executee de CT-1 v0 : policy autorise, ticket null, approval null (EX-12.6)", function () {
    const policy = AP.actionObservation({ rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: null, ticket_state: null, approval: null, approver_set: null }).policy;
    const p = C.partielAppelOutil({
      delegation: { launched_by: "agent-sinistres", on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-2026-11-05-0042" },
      code: { model: "fournisseur/modele@2026-09", prompt_version: null, policy_version: "2026-11-05-observation", recorder: "0.1.0" },
      policy,
      tool: "sap__payments.create",
      arguments: C.referencePiece(Buffer.from('{"amount":"7400.00"}')),
      status: "executee",
      result: C.referencePiece(Buffer.from('{"id":"PAY-000981"}')),
      duration_ms: 213,
      is_error: false,
    });
    expect(p.policy).to.deep.equal({ rule: "paiement > 5000 CHF [observation a_approuver]", decision: "autorise", ticket: null, redaction: null });
    expect(p.approval).to.equal(null);
    // L'exemple seq 3 de CT-8 §12.4 porte la même policy et valide contre evenement-v0.
    const [texte] = blocs(CT8, "evenement");
    const ev = JSON.parse(texte);
    expect(ev.policy).to.deep.equal(p.policy);
    expect(J.validerSchema(ev, SCHEMAS["https://noortrace.example/schemas/v0/evenement.schema.json"], { registre: SCHEMAS })).to.deep.equal([]);
  });
});

describe("CT-2 révision 0.6 : configuration du mode observation (EX-15.8, EX-11.15 de CT-3)", function () {
  it("MODES_ATTENTE a trois valeurs ; le schéma de configuration les énumère", function () {
    expect(AP.MODES_ATTENTE).to.deep.equal(["retenir", "erreur", "observation"]);
    expect(AP.MODE_ATTENTE_DEFAUT).to.equal("erreur");
    expect(JSON.stringify(lireSchema("configuration-enregistreur"))).to.include('"enum":["retenir","erreur","observation"]');
  });

  it("l'exemple de CT-2 §15.3 en mode observation valide contre le schéma étendu et non contre celui de CT-2 0.5 ; toutes les configurations existantes valident encore", function () {
    const id = C.ID_SCHEMA_CONFIGURATION;
    const obs = copie(CONFIG);
    obs.policy.approval.mode = "observation";
    expect(J.validerSchema(obs, SCHEMAS[id], { registre: SCHEMAS })).to.deep.equal([]);
    const ancien = schemaConfiguration05();
    expect(J.validerSchema(obs, ancien[id], { registre: ancien }).map((e) => e.chemin)).to.deep.equal(["/policy/approval/mode"]);
    // Compatibilité : chaque configuration complète annotée de CT-2, celle du vérificateur indépendant de ct-2 et la configuration rapide de CT-8.
    const configurations = [...blocs(CT2, "configuration-enregistreur").map((t) => C.analyserJSONIntegral(t))];
    configurations.push(JSON.parse(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-2", "verificateur-independant", "testdata", "spec", "configuration-exemple.json"), "utf8")));
    expect(configurations.length).to.be.at.least(2);
    for (const c of configurations) {
      expect(J.validerSchema(c, SCHEMAS[id], { registre: SCHEMAS })).to.deep.equal([]);
      expect(J.validerSchema(c, ancien[id], { registre: ancien })).to.deep.equal([]);
    }
    const rapide = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "deploiement", "config", "rapide", "configuration.json"), "utf8"));
    expect(rapide.policy.approval.mode).to.equal("observation");
    expect(J.validerSchema(rapide, SCHEMAS[id], { registre: SCHEMAS })).to.deep.equal([]);
    expect(J.validerSchema(rapide, ancien[id], { registre: ancien }).map((e) => e.chemin)).to.deep.equal(["/policy/approval/mode"]);
  });

  it("l'empreinte de l'ensemble de politique de §15.3 en mode observation est celle de CT-8 EX-12.2", function () {
    const policy = copie(CONFIG.policy);
    policy.approval.mode = "observation";
    policy.version = "2026-11-05-observation";
    expect(C.octetsJCSIntegral(policy).length).to.equal(6607);
    expect(C.empreinteEnsemblePolitique(policy).policy_sha256).to.equal("0x94f80d3b8ee9935923e612b2f96a474b4955d656411c3a53eb1f810578fd2912");
    expect(CT8).to.include("0x94f80d3b8ee9935923e612b2f96a474b4955d656411c3a53eb1f810578fd2912");
  });

  it("la validation avertit en mode observation par le texte fixe d'EX-15.8, et refuse le démarrage avec des retenues sans décision", function () {
    const obs = copie(CONFIG);
    obs.policy.approval.mode = "observation";
    // Le nom d'un ensemble en mode observation finit par « -observation » (EX-15.8, révision 0.6).
    expect(AP.controlesConfiguration(obs, { schemas: SCHEMAS }).erreurs).to.deep.equal(["/policy/version : version_observation_sans_suffixe (CT-2 EX-15.8)"]);
    obs.policy.version = `${obs.policy.version}-observation`;
    const r = AP.controlesConfiguration(obs, { schemas: SCHEMAS });
    expect(r.erreurs).to.deep.equal([]);
    expect(r.avertissements).to.deep.equal([`/policy/approval/mode : ${AP.AVERTISSEMENT_OBSERVATION}`]);
    expect(CT2).to.include("« mode observation : aucun appel ne sera bloque ni soumis a\napprobation ; une ecriture peut n'avoir qu'un evenement en attente, ou aucun\nau-dela des bornes de 14.5 »");
    const ko = AP.controlesConfiguration(obs, { schemas: SCHEMAS, retenuesSansDecision: 2 });
    expect(ko.erreurs).to.have.length(1);
    expect(ko.erreurs[0]).to.include("tickets_ouverts");
    // Le mode erreur n'est pas concerné par les retenues ouvertes au démarrage.
    expect(AP.controlesConfiguration(CONFIG, { schemas: SCHEMAS, retenuesSansDecision: 2 }).erreurs).to.deep.equal([]);
  });

  it("refusEntreeObservation : rechargement vers l'observation refusé tant qu'une retenue n'a pas de décision ; sortie sans condition (EX-15.8, CT-3 EX-11.15)", function () {
    expect(AP.refusEntreeObservation({ modeEnVigueur: "erreur", modeNouveau: "observation", retenuesSansDecision: 1 })).to.deep.equal({ event: "config_reload_rejected", reason: "tickets_ouverts" });
    expect(AP.refusEntreeObservation({ modeEnVigueur: "retenir", modeNouveau: "observation", retenuesSansDecision: 0 })).to.equal(null);
    expect(AP.refusEntreeObservation({ modeEnVigueur: "observation", modeNouveau: "observation", retenuesSansDecision: 3 })).to.equal(null);
    expect(AP.refusEntreeObservation({ modeEnVigueur: "observation", modeNouveau: "erreur", retenuesSansDecision: 3 })).to.equal(null);
  });
});
