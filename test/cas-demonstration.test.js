// Les deux cas de démonstration (CT-9 TE-1 « assurance », TE-2
// « administration »), sans moteur de conteneurs : la partie statique et en
// processus de ce que test/cas-demonstration-composition.test.js joue en
// composition.
//
// 1. configuration de l'enregistreur de chaque cas : validée par le démon
//    (`noortrace validate-config`, boîte noire), identifiants du cas, outils
//    du catalogue égaux à ceux de la politique, politique d'approbation
//    évaluée en processus par le moteur du service (`evaluer`) sur les appels
//    du scénario : lectures autorisées, écriture soumise à revue, et les
//    variantes automatiques ;
// 2. scénario du simulateur de modèle : chaque appel nomme un outil annoncé
//    sous son nom assaini et respecte le schéma d'entrée ; les réponses en flux
//    SSE se consolident en la réponse hors flux (agent-demo) ;
// 3. serveur d'outils du cas, en processus : conduites lecture, recherche,
//    écriture, erreurs ; sélection des dossiers à exporter ;
// 4. surcharge demo/cas/compose.cas.yaml : chaque fichier monté existe,
//    aucun réseau ni port nouveau, le vérificateur de la démonstration de
//    référence sous profil, le serveur RFC 3161 interne dans l'espace réseau
//    de l'enregistreur ; attestation de périmètre de forme AT-1, dont
//    rules_sha256 est le SHA-256 de la surcharge ;
// 5. règles de contenu des cas (CT-2 EX-19.1) : rien qui se paie, aucune
//    devise, aucun nombre à deux décimales, aucun des mots qui désignent une
//    somme à payer ; domaines en .example, adresses IP de la boucle locale
//    seulement, aucun chemin de machine, aucun secret d'approbateur.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import yaml from "js-yaml";
import { evaluer } from "@noortrace/approbation";
import { ADRESSE_IPV4, CAS, CAS_DIR, CHEMINS_DE_MACHINE, DEMO, DOMAINE_HORS_EXAMPLE, INTERDITS, RACINE, configurationCas, envCas, fichiersDesCas } from "./fixtures/cas/outils.mjs";
import { appelerOutil, chargerCatalogue, definitions, repondre } from "../demo/cas/commun/outils-cas.mjs";
import { choisir, entree } from "../demo/cas/commun/modele-cas.mjs";
import { selectionner } from "../demo/cas/commun/exploitation-cas.mjs";
import { argumentsCompose, lireEnv } from "../demo/cas/preparer.mjs";
import { assainir, consoliderFlux } from "../conteneurs/agent-demo/agent-demo.mjs";
import { corpsFlux } from "../conteneurs/modele-demo/modele-demo.mjs";

const sha256 = (o) => crypto.createHash("sha256").update(o).digest("hex");
const lire = (...p) => fs.readFileSync(path.join(...p), "utf8");
const COMPTES_HARDHAT = ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x90f79bf6eb2c4f870365e785982e1f101e93b906"];
const CLES_PRIVEES = JSON.parse(lire(RACINE, "spec", "vecteurs", "ct-3", "constantes.json")).accounts.map((a) => a.private_key.slice(2).toLowerCase());
const SURCHARGE = yaml.load(lire(CAS_DIR, "compose.cas.yaml"));
const BASE = yaml.load(lire(DEMO, "compose.yaml"));

/** Requête `evaluer` d'un appel du scénario (CT-2 EX-7.4), réduite aux membres que le moteur lit. */
const requete = (tool, args) => ({ tool_announced: tool, arguments: args, code: { policy_version: "x" }, delegation: { launched_by: "agent", on_behalf_of: null, scope: null, run_id: null } });

for (const cas of CAS) {
  const te = cas === "assurance" ? "TE-1" : "TE-2";
  const CONFIG = configurationCas(cas);
  const ENV = envCas(cas);
  const CATALOGUE = chargerCatalogue(path.join(CAS_DIR, cas, "outils.json"));
  const SCENARIO = JSON.parse(lire(CAS_DIR, cas, "modele.json"));
  const [ALIAS, SERVEUR] = Object.entries(CONFIG.policy.servers)[0];
  const annonce = (nom) => `${ALIAS}__${nom}`;

  describe(`CT-9 ${te} : cas « ${cas} », sans moteur de conteneurs (partie statique)`, function () {
    this.timeout(60000);

    it(`${te} : configuration-cas.json validée par le démon (noortrace validate-config : code 0 ; avertissements admis : approbateurs_de_test (EX-15.8) et, comme pour la démonstration de référence, les points d'accès http:// des réseaux internes de la composition) ; identifiants d'organisation et de journal de cas.env ; version de politique sans suffixe -observation ; mode erreur ; serveur ${ALIAS} dont les outils sont ceux du catalogue, écritures en classe ecriture sans amount ni currency ; jeu statique des comptes 1 à 3 au seuil 2, séparation interdite pour le demandeur`, function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace"), "validate-config", path.join(CAS_DIR, cas, "configuration-cas.json")], { encoding: "utf8", cwd: RACINE });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      const avertissements = (r.stdout + r.stderr).trim().split("\n").filter((l) => l.startsWith("avertissement"));
      expect(avertissements).to.include("avertissement : /policy/approval/rules/approver_set/members : approbateurs_de_test (EX-15.8)");
      for (const a of avertissements) expect(a).to.match(/approbateurs_de_test|http:\/\/ hors de la boucle locale/);
      expect((r.stdout + r.stderr)).to.not.match(/^erreur/m);
      expect(CONFIG.recorder).to.include({ org_id: ENV.NOORTRACE_CAS_ORG_ID, journal_id: ENV.NOORTRACE_CAS_JOURNAL_ID, environment: "developpement" });
      expect(CONFIG.policy.version).to.match(new RegExp(`^${cas}-20[0-9]{2}-[0-9]{2}$`));
      expect(CONFIG.policy.approval.mode).to.equal("erreur");
      expect(Object.keys(CONFIG.policy.servers)).to.deep.equal([ALIAS]);
      expect(Object.keys(SERVEUR.tools).sort()).to.deep.equal(CATALOGUE.outils.map((o) => o.name).sort());
      for (const o of CATALOGUE.outils) {
        const t = SERVEUR.tools[o.name];
        expect(t.class, o.name).to.equal(o.kind === "ecriture" ? "ecriture" : "lecture");
        for (const e of t.effects ?? []) expect([e.amount, e.currency], o.name).to.deep.equal([null, null]);
      }
      expect(CONFIG.policy.approval.rules.approver_set).to.deep.include({ source: "statique", members: COMPTES_HARDHAT, threshold: { required: 2, size: 3 } });
      expect(CONFIG.policy.approval.rules.separation.self_approval).to.equal("interdite");
      expect(CONFIG.policy.approval.rules.separation.identities.map((i) => i.launched_by)).to.deep.equal([CONFIG.mcp.hosts[0].launched_by]);
      expect(CONFIG.model.hosts[0].launched_by).to.equal(CONFIG.mcp.hosts[0].launched_by);
      expect(SERVEUR.transport.url).to.equal("http://outils-demo:8000/mcp");
    });

    it(`${te} : la politique d'approbation, évaluée par le moteur du service d'approbation sur les appels du scénario : chaque lecture autorisée par la règle « lectures autorisees », l'écriture du scénario soumise à revue, et les variantes automatiques de l'écriture (${cas === "assurance" ? "acceptation sans majoration et renvoi autorisés, refus et majoration en revue" : "demande de pièces autorisée, accord et refus en revue"}) ; un argument absent ne laisse pas passer l'écriture (défaut : revue)`, function () {
      const P = CONFIG.policy.approval.rules;
      const ev = (tool, args) => evaluer(P, requete(tool, args), [], Date.now());
      const appels = SCENARIO.etapes.filter((e) => e.outil).map((e) => e.outil);
      const outilDe = (nomModele) => CATALOGUE.outils.find((o) => assainir(annonce(o.name)) === nomModele);
      for (const a of appels) {
        const o = outilDe(a.name);
        const r = ev(annonce(o.name), a.input);
        if (o.kind !== "ecriture") expect([r.rule, r.decision], a.name).to.deep.equal(["lectures autorisees", "autorise"]);
      }
      const ecriture = CATALOGUE.outils.find((o) => o.kind === "ecriture");
      const scenario = appels.find((a) => outilDe(a.name) === ecriture);
      expect(ev(annonce(ecriture.name), scenario.input).decision).to.equal("a_approuver");
      if (cas === "assurance") {
        const base = { proposition_id: "PRP-2026-00431", classe_risque: "A", majoration_pct: "0", motif: "m" };
        expect(ev(annonce(ecriture.name), { ...base, decision: "accepter" })).to.include({ rule: "acceptation sans majoration", decision: "autorise" });
        expect(ev(annonce(ecriture.name), { ...base, decision: "renvoyer" })).to.include({ rule: "renvoi au souscripteur", decision: "autorise" });
        expect(ev(annonce(ecriture.name), { ...base, decision: "refuser" })).to.include({ rule: "decision defavorable : revue", decision: "a_approuver" });
        expect(ev(annonce(ecriture.name), { ...base, decision: "accepter", majoration_pct: "25" })).to.include({ rule: "decision defavorable : revue", decision: "a_approuver" });
        expect(ev(annonce(ecriture.name), { proposition_id: "PRP-2026-00431", decision: "accepter", classe_risque: "A", motif: "m" }).decision).to.equal("a_approuver");
      } else {
        const base = { demande_id: "DEM-2026-01877", motif: "m" };
        expect(ev(annonce(ecriture.name), { ...base, decision: "completer" })).to.include({ rule: "demande de pieces", decision: "autorise" });
        expect(ev(annonce(ecriture.name), { ...base, decision: "accorder" })).to.include({ rule: "decision sur le droit : revue", decision: "a_approuver" });
        expect(ev(annonce(ecriture.name), { ...base, decision: "refuser" })).to.include({ rule: "decision sur le droit : revue", decision: "a_approuver" });
        expect(ev(annonce(ecriture.name), { demande_id: "DEM-2026-01877", motif: "m" }).decision).to.equal("a_approuver");
      }
    });

    it(`${te} : scénario du simulateur (modele.json) : une étape « texte » qui ouvre le tour, chaque appel nomme un outil du catalogue sous son nom assaini (CT-2 EX-4.12) avec les arguments requis et eux seuls, chaque tool_use_id a son étape suivante, la dernière étape clôt le tour ; la réponse en flux SSE (corpsFlux de la démonstration) se consolide en la réponse hors flux`, function () {
      expect(SCENARIO.etapes[0].quand).to.equal("texte");
      expect(SCENARIO.etapes.at(-1).outil).to.equal(null);
      const ids = new Set(SCENARIO.etapes.filter((e) => e.outil).map((e) => e.outil.id));
      expect(ids.size).to.equal(SCENARIO.etapes.length - 1);
      for (const e of SCENARIO.etapes.slice(1)) expect(ids.has(e.quand), e.quand).to.equal(true);
      for (const e of SCENARIO.etapes) {
        if (!e.outil) continue;
        const o = CATALOGUE.outils.find((x) => assainir(annonce(x.name)) === e.outil.name);
        expect(o, e.outil.name).to.not.equal(undefined);
        const schema = o.inputSchema;
        for (const k of schema.required ?? []) expect(e.outil.input, `${e.outil.name} ${k}`).to.have.property(k);
        if (schema.additionalProperties === false) for (const k of Object.keys(e.outil.input)) expect(schema.properties, `${e.outil.name} ${k}`).to.have.property(k);
        for (const [k, v] of Object.entries(e.outil.input)) if (schema.properties[k]?.enum) expect(schema.properties[k].enum, `${e.outil.name} ${k}`).to.include(v);
        const en = entree(SCENARIO, e);
        expect(consoliderFlux(corpsFlux(en).join(""))).to.deep.equal(en.message);
        const suivante = choisir(SCENARIO, [{ role: "user", content: [{ type: "tool_result", tool_use_id: e.outil.id, content: "x" }] }]);
        expect(suivante, e.outil.id).to.not.equal(null);
      }
      expect(choisir(SCENARIO, [{ role: "user", content: "demande" }])).to.equal(SCENARIO.etapes[0]);
      expect(choisir(SCENARIO, [{ role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_inconnu", content: "x" }] }])).to.equal(null);
    });

    it(`${te} : serveur d'outils du cas, en processus : tools/list annonce les définitions sans les membres de conduite ; lecture par identifiant, recherche, écriture numérotée avec structuredContent, identifiant inconnu en erreur d'outil, outil inconnu -32602 ; le compteur d'appels compte chaque tools/call ; données fictives (pseudonymes, domaines .example)`, function () {
      const etat = { appels: 0, ecritures: new Map() };
      const liste = repondre(CATALOGUE, { jsonrpc: "2.0", id: 1, method: "tools/list" }, etat);
      expect(liste.result.tools).to.deep.equal(definitions(CATALOGUE));
      for (const t of liste.result.tools) expect(Object.keys(t)).to.not.include.members(["kind", "id_field", "prefixe"]);
      const lecture = CATALOGUE.outils.find((o) => o.kind === "lecture_par_id");
      const recherche = CATALOGUE.outils.find((o) => o.kind === "recherche");
      const ecriture = CATALOGUE.outils.find((o) => o.kind === "ecriture");
      const [id, enregistrement] = Object.entries(CATALOGUE.enregistrements)[0];
      expect(appelerOutil(CATALOGUE, lecture.name, { [lecture.id_field]: id }, etat).content[0].text).to.equal(`${id} : ${enregistrement.texte}`);
      expect(appelerOutil(CATALOGUE, recherche.name, { query: id.slice(-5) }, etat).content[0].text).to.include(id);
      expect(appelerOutil(CATALOGUE, lecture.name, { [lecture.id_field]: "INCONNU" }, etat).isError).to.equal(true);
      const args = SCENARIO.etapes.map((e) => e.outil).find((a) => a && assainir(annonce(ecriture.name)) === a.name).input;
      const e1 = appelerOutil(CATALOGUE, ecriture.name, args, etat);
      const e2 = appelerOutil(CATALOGUE, ecriture.name, args, etat);
      expect(e1.structuredContent[ecriture.cle_resultat]).to.equal(`${ecriture.prefixe}${ecriture.compteur_depart}`);
      expect(e2.structuredContent[ecriture.cle_resultat]).to.equal(`${ecriture.prefixe}${ecriture.compteur_depart + 1}`);
      expect(appelerOutil(CATALOGUE, "inconnu", {}, etat).erreur.code).to.equal(-32602);
      const r = repondre(CATALOGUE, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: lecture.name, arguments: { [lecture.id_field]: id } } }, etat);
      expect(r.result.content[0].text).to.include(id);
      expect(etat.appels).to.equal(1);
      for (const [k, v] of Object.entries(CATALOGUE.enregistrements)) {
        expect(JSON.stringify(v)).to.not.match(/[0-9]{2}\.[0-9]{2}\.(19|20)[0-9]{2}|(19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}/);
        for (const m of JSON.stringify(v).matchAll(/@([a-z0-9.-]+)/g)) expect(m[1], k).to.match(/\.example$/);
      }
    });

    it(`${te} : sélection des dossiers à exporter (exploitation-cas, selectionner) sur une suite d'événements synthétique : ${ENV.NOORTRACE_CAS_EXPORTS} désignent les bons seq ; une sélection sans événement rend null ; une sélection inconnue lève`, function () {
      const ev = (seq, tool, status, decision, approval) => ({ seq, execution: { tool, status }, policy: { decision }, approval });
      const outil = annonce(CATALOGUE.outils.find((o) => o.kind === "ecriture").name);
      const suite = [
        ev(1, "noortrace.journal.politique", "executee", "autorise", null), ev(2, annonce("x.get"), "executee", "autorise", null),
        ev(3, outil, "retenue", "a_approuver", null), ev(4, "noortrace.approbation.decision", "executee", "a_approuver", { decision: cas === "assurance" ? "approuve" : "refuse" }),
        ...(cas === "assurance" ? [ev(5, outil, "executee", "a_approuver", { decision: "approuve" })] : [ev(5, outil, "executee", "autorise", null)]),
      ];
      const attendu = cas === "assurance" ? { "appel-approuve": 5, "decision-approuvee": 4 } : { "decision-refusee": 4, [`appel-autorise=${outil}`]: 5 };
      for (const sel of ENV.NOORTRACE_CAS_EXPORTS.split(",")) expect(selectionner(suite, sel), sel).to.equal(attendu[sel]);
      expect(selectionner(suite, cas === "assurance" ? "decision-refusee" : "appel-approuve")).to.equal(null);
      expect(() => selectionner(suite, "autre")).to.throw(/inconnue/);
    });

    it(`${te} : attestation de périmètre du cas : forme AT-1 (attestation.mjs verifier --forme : code 0), journal et organisation du cas, rules_sha256 égal au SHA-256 de demo/cas/compose.cas.yaml, signataires = comptes de test 1 et 2`, function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "verifier", path.join(CAS_DIR, cas, "attestation-perimetre-cas.json"), "--forme"], { encoding: "utf8", cwd: RACINE });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      expect(r.stdout).to.include("Forme : AT-1 réussie");
      const a = JSON.parse(lire(CAS_DIR, cas, "attestation-perimetre-cas.json"));
      expect(a.org.org_id).to.equal(ENV.NOORTRACE_CAS_ORG_ID);
      expect(a.journals.map((j) => j.journal_id)).to.deep.equal([ENV.NOORTRACE_CAS_JOURNAL_ID]);
      expect(a.agents.map((x) => x.journal_id)).to.deep.equal([ENV.NOORTRACE_CAS_JOURNAL_ID]);
      expect(a.egress.rules_sha256).to.equal(`0x${sha256(fs.readFileSync(path.join(CAS_DIR, "compose.cas.yaml")))}`);
      expect(a.signatories.map((x) => x.address)).to.deep.equal(COMPTES_HARDHAT.slice(0, 2));
      expect(a.tools_via_proxy_only.map((x) => x.server_alias)).to.deep.equal([ALIAS]);
    });

    it(`${te} : cas.env et preparer.mjs : les variables de la surcharge sont toutes définies, NOORTRACE_CAS_TRAVAIL n'y est pas (donnée par la commande), les arguments Compose nomment le projet, le fichier de variables et les deux fichiers de composition`, function () {
      expect(lireEnv(cas)).to.deep.equal(ENV);
      for (const k of ["NOORTRACE_CAS", "NOORTRACE_CAS_ORG", "NOORTRACE_CAS_ORG_ID", "NOORTRACE_CAS_JOURNAL", "NOORTRACE_CAS_JOURNAL_ID", "NOORTRACE_CAS_EXPORTS", "NOORTRACE_CAS_SYSTEME", "NOORTRACE_CAS_DEMANDE"]) expect(ENV, k).to.have.property(k);
      expect(ENV.NOORTRACE_CAS).to.equal(cas);
      expect(ENV).to.not.have.property("NOORTRACE_CAS_TRAVAIL");
      const a = argumentsCompose({ cas, projet: "p", travail: "/t" });
      expect(a.args).to.deep.equal(["compose", "-p", "p", "--project-directory", DEMO, "--env-file", path.join(CAS_DIR, cas, "cas.env"), "-f", path.join(DEMO, "compose.yaml"), "-f", path.join(CAS_DIR, "compose.cas.yaml")]);
      expect(a.env.NOORTRACE_CAS_TRAVAIL).to.equal("/t");
    });
  });
}

describe("CT-9 TE-1, TE-2 : surcharge demo/cas/compose.cas.yaml et règles de contenu des cas, sans moteur de conteneurs", function () {
  it("surcharge : chaque fichier monté par un bind existe (variables de cas.env résolues, répertoire de travail excepté) ; les programmes des cas sont montés au côté des programmes de la démonstration qu'ils importent ; aucun réseau, aucun port publié ni service nouveau hors horodatage et horodatage-init ; verificateur sous le profil reference ; horodatage dans l'espace réseau de l'enregistreur, durci comme les autres services ; agent-demo garde le seul réseau hotes", function () {
    const services = SURCHARGE.services;
    expect(Object.keys(services).filter((n) => !BASE.services[n]).sort()).to.deep.equal(["horodatage", "horodatage-init"]);
    expect(SURCHARGE.networks).to.equal(undefined);
    expect(Object.keys(SURCHARGE.volumes)).to.deep.equal(["horodatage"]);
    for (const [nom, s] of Object.entries(services)) {
      expect(s.ports, nom).to.equal(undefined);
      expect(s.networks, nom).to.equal(undefined);
      for (const v of s.volumes ?? []) {
        if (v.type !== "bind") continue;
        if (v.source.includes("NOORTRACE_CAS_TRAVAIL")) continue;
        for (const cas of CAS) {
          const source = v.source.replace(/\$\{NOORTRACE_CAS(:\?[^}]*)?\}/g, cas);
          expect(fs.existsSync(path.join(DEMO, source)), `${nom} : ${source}`).to.equal(true);
          expect(v.read_only, `${nom} : ${source}`).to.equal(true);
        }
      }
      if (s.entrypoint) {
        expect(s.entrypoint[0]).to.equal("/usr/local/bin/node");
        expect((s.volumes ?? []).some((v) => v.target === s.entrypoint[1]), `${nom} : programme ${s.entrypoint[1]} monté`).to.equal(true);
      }
    }
    expect(services.verificateur).to.deep.equal({ profiles: ["reference"] });
    expect(services.horodatage).to.include({ image: "noortrace/tsa-interne:0.1.0", network_mode: "service:enregistreur", read_only: true, user: "10004:10004" });
    expect(services.horodatage.cap_drop).to.deep.equal(["ALL"]);
    expect(services["horodatage-init"].profiles).to.deep.equal(["outils"]);
    expect(services["horodatage-init"].network_mode).to.equal("none");
    // Les programmes des cas importent ceux de la démonstration par chemin relatif : même répertoire dans l'image.
    expect(services["outils-demo"].entrypoint[1]).to.equal("/opt/noortrace-demo/outils-cas.mjs");
    expect(services["modele-demo"].entrypoint[1]).to.equal("/opt/noortrace-demo/modele-cas.mjs");
    expect(services["agent-demo"].entrypoint[1]).to.equal("/opt/noortrace-demo/agent-cas.mjs");
    expect(services["approbateur-demo"].entrypoint[1]).to.equal("/opt/noortrace/conteneurs/approbateur-demo/approbateur-cas.mjs");
    expect(lire(CAS_DIR, "commun", "modele-cas.mjs")).to.include('"./modele-demo.mjs"');
    expect(lire(CAS_DIR, "commun", "agent-cas.mjs")).to.include('"./agent-demo.mjs"');
    expect(lire(CAS_DIR, "commun", "approbateur-cas.mjs")).to.include('"../demo-commun/chaine.mjs"');
  });

  it("règles de contenu des cas et règles communes, sur tout fichier de demo/cas/ et les essais des cas : aucun code de devise, aucun symbole monétaire, aucun nombre à deux décimales, aucun des mots qui désignent une somme à payer, aucun amount ni currency non nul ; domaines inventés en .example ; adresses IP de la boucle locale et 0.0.0.0 d'écoute seulement ; aucun chemin de machine ; aucune clé privée d'approbateur hors de l'image qui les détient", async function () {
    const fichiers = [...fichiersDesCas(), ...["cas-demonstration.test.js", "cas-demonstration-composition.test.js", "cas-observation.test.js"].map((f) => path.join(RACINE, "test", f)), ...["outils.mjs", "client-mcp.mjs"].map((f) => path.join(RACINE, "test", "fixtures", "cas", f))];
    expect(fichiers.length).to.be.at.least(20);
    const violations = [];
    for (const f of fichiers) {
      const texte = fs.readFileSync(f, "utf8");
      const rel = path.relative(RACINE, f);
      for (const { nom, motif } of INTERDITS) {
        // Les motifs eux-mêmes, dans la fixture et dans cet essai, ne sont pas des occurrences.
        const lignes = texte.split("\n").filter((l) => motif.test(l) && !/INTERDITS|motif:|\.match\(|to\.not\.match|matchAll/.test(l));
        for (const l of lignes) violations.push(`${rel} : ${nom} : ${l.trim().slice(0, 100)}`);
      }
      for (const m of texte.matchAll(DOMAINE_HORS_EXAMPLE)) violations.push(`${rel} : domaine ${m[0]}`);
      for (const m of texte.matchAll(ADRESSE_IPV4)) if (!["127.0.0.1", "0.0.0.0"].includes(m[0])) violations.push(`${rel} : adresse IP ${m[0]}`);
      if (CHEMINS_DE_MACHINE.test(texte)) violations.push(`${rel} : chemin de machine`);
      for (const k of CLES_PRIVEES) if (texte.toLowerCase().includes(k)) violations.push(`${rel} : clé privée d'approbateur`);
    }
    expect(violations).to.deep.equal([]);
    // L'image approbateur-demo seule détient les clés (CT-3 EX-3.3, EX-3.4) : le programme du cas qui y tourne n'en écrit aucune et
    // prend les trois du programme de l'image, seul fichier de la démonstration qui les écrive.
    const prog = lire(CAS_DIR, "commun", "approbateur-cas.mjs");
    expect(CLES_PRIVEES.filter((k) => prog.includes(k))).to.deep.equal([]);
    expect(prog).to.include('"./approbateur-demo.mjs"');
    expect(prog).to.include('"../../../conteneurs/approbateur-demo/approbateur-demo.mjs"');
    const { CLES_APPROBATEURS } = await import("../conteneurs/approbateur-demo/approbateur-demo.mjs");
    const comptes = JSON.parse(lire(RACINE, "spec", "vecteurs", "ct-3", "constantes.json")).accounts.filter((a) => [1, 2, 3].includes(a.index));
    expect(CLES_APPROBATEURS.map((k) => k.toLowerCase())).to.deep.equal(comptes.map((a) => a.private_key.toLowerCase()));
  });
});
