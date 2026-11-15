// Démonstration de référence (CT-2 §19 ; CT-9 TE-3) : ce qui s'éprouve sans
// moteur de conteneurs. La composition lancée est dans
// test/demonstration-composition.test.js.
//
//   1. `demo/compose.yaml` lu en analyse statique : services, images, réseaux
//      (l'agent ne joint que l'enregistreur), volumes (le journal n'est monté
//      que par l'enregistreur), durcissement, séparation des clés des
//      approbateurs (CT-3 EX-3.3 : seul approbateur-demo les détient) ;
//   2. les documents de `demo/` : configuration de l'enregistreur,
//      document d'ancrage, configuration du service d'approbation, manifeste
//      d'instance du registre, fichier d'ancres du réviseur, attestation de
//      périmètre ; cohérents entre eux ;
//   3. les programmes des services, en processus : simulateur de l'API
//      Messages (EX-19.2), serveur d'outils, agent, impression du
//      vérificateur (§19.4, comparée au texte de la spécification), outil de
//      rapprochement (CT-7 EX-3.8) ;
//   4. les règles de contenu : aucun prix, aucune donnée de tarif, noms de
//      domaine en `.example`, adresses IP admises seulement, fichiers de
//      construction épinglés.
//
// Aucun essai ne joint un réseau : les serveurs écoutent sur la boucle locale.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import * as R from "@noortrace/ancrage/registre";
import { controlerEpinglage, lignesFrom } from "../scripts/deploiement/construire-images.mjs";
import { IMAGES_DEMO, ARTEFACTS, identifiantsCache, purgerCacheCree } from "../demo/construire-images.mjs";
import * as modele from "../conteneurs/modele-demo/modele-demo.mjs";
import * as outils from "../conteneurs/outils-demo/outils-demo.mjs";
import * as agent from "../conteneurs/agent-demo/agent-demo.mjs";
import * as registreDev from "../conteneurs/registre-dev/registre-dev.mjs";
import * as verificateur from "../conteneurs/verificateur-demo/verificateur-demo.mjs";
import * as rapprochement from "../demo/rapprochement.mjs";
import * as mesure from "../demo/mesurer-duree.mjs";
import { validerSchema } from "../scripts/lib/journal.mjs";
import { normaliser, sortieDeLaSpecification } from "./fixtures/demonstration/outils.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEMO = path.join(RACINE, "demo");
const CONTENEURS = path.join(RACINE, "conteneurs");
const lire = (...p) => fs.readFileSync(path.join(RACINE, ...p), "utf8");
const lireJson = (...p) => JSON.parse(lire(...p));
const COMPOSE = yaml.load(lire("demo", "compose.yaml"));
const CONFIG = lireJson("demo", "configuration-demo.json");
const CONSTANTES_CT3 = lireJson("spec", "vecteurs", "ct-3", "constantes.json");
const CONSTANTES_CT4 = lireJson("spec", "vecteurs", "ct-4", "constantes.json");
const ENTREES_DEMO = lireJson("spec", "vecteurs", "ct-2", "evenements", "journal-demo", "entrees.json");
const sha256 = (octets) => createHash("sha256").update(octets).digest("hex");

/** Fichiers de la démonstration : `demo/` et les répertoires de construction de ses images, sous-répertoires compris (`demo/cas/`, `demo/pannes/`). */
function fichiersDemo() {
  const r = [];
  const parcourir = (relatif) => {
    for (const e of fs.readdirSync(path.join(RACINE, relatif), { withFileTypes: true })) {
      const f = path.join(relatif, e.name);
      if (e.isDirectory()) parcourir(f);
      else r.push(f);
    }
  };
  parcourir("demo");
  for (const d of [...IMAGES_DEMO, "demo-commun"]) parcourir(path.join("conteneurs", d));
  return r.sort();
}

/** Variables d'environnement des secrets de démonstration, telles que `compose.yaml` les donne au service. */
const envDe = (service) => ({ ...process.env, ...(COMPOSE.services[service].environment ?? {}) });

/** Serveur HTTP d'un service sur un port libre de la boucle locale ; rend son URL et sa fermeture. */
async function ecouter(serveur) {
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${serveur.address().port}`, fermer: () => new Promise((r) => serveur.close(r)) };
}

describe("CT-2 §19 : démonstration de référence, sans moteur de conteneurs (TE-3, partie statique)", function () {
  this.timeout(120000);

  describe("§19.1 : composition demo/compose.yaml", function () {
    const S = COMPOSE.services;

    it("§19.1 : neuf services — enregistreur, outils-demo, modele-demo, agent-demo, registre-dev, verificateur, plus le service d'approbation, approbateur-demo et exploitation-demo — chacun désigné par une image noortrace/* à version exacte, aucun par une construction", function () {
      expect(Object.keys(S).sort()).to.deep.equal(["agent-demo", "approbateur-demo", "approbation", "enregistreur", "exploitation-demo", "modele-demo", "outils-demo", "registre-dev", "verificateur"]);
      const images = Object.fromEntries(Object.entries(S).map(([n, s]) => [n, s.image]));
      expect(images).to.deep.equal({
        "agent-demo": "noortrace/agent-demo:0.1.0", "approbateur-demo": "noortrace/approbateur-demo:0.1.0", approbation: "noortrace/approbation:0.1.0",
        enregistreur: "noortrace/enregistreur:0.1.0", "exploitation-demo": "noortrace/enregistreur:0.1.0", "modele-demo": "noortrace/modele-demo:0.1.0",
        "outils-demo": "noortrace/outils-demo:0.1.0", "registre-dev": "noortrace/registre-dev:0.1.0", verificateur: "noortrace/verificateur-demo:0.1.0",
      });
      for (const [n, s] of Object.entries(S)) expect(s, n).to.not.have.property("build");
    });

    it("§19.1, CT-2 §4.9, MN-1 : agent-demo n'est attaché qu'au réseau hotes, où il n'y a que lui et l'enregistreur ; outils-demo n'est que sur outils, modele-demo que sur fournisseurs ; les quatre réseaux de la démonstration sont internes", function () {
      expect(S["agent-demo"].networks).to.deep.equal(["hotes"]);
      const sur = (reseau) => Object.entries(S).filter(([, s]) => (s.networks ?? []).includes(reseau)).map(([n]) => n).sort();
      expect(sur("hotes")).to.deep.equal(["agent-demo", "enregistreur"]);
      expect(sur("outils")).to.deep.equal(["enregistreur", "outils-demo"]);
      expect(sur("fournisseurs")).to.deep.equal(["enregistreur", "modele-demo"]);
      expect(sur("registre")).to.deep.equal(["approbateur-demo", "enregistreur", "registre-dev"]);
      expect(sur("sante")).to.deep.equal(["enregistreur"]);
      for (const n of ["hotes", "outils", "fournisseurs", "registre"]) expect(COMPOSE.networks[n], n).to.deep.equal({ internal: true });
      expect(COMPOSE.networks.sante.driver_opts["com.docker.network.bridge.enable_ip_masquerade"]).to.equal("false");
      for (const n of ["approbation", "exploitation-demo", "verificateur"]) expect(S[n].network_mode, n).to.equal("none");
      expect(S["agent-demo"]).to.not.have.property("network_mode");
    });

    it("§19.1 : aucun port n'est publié sur l'hôte, sauf la santé de l'enregistreur (8500) sur la boucle locale", function () {
      const publies = Object.entries(S).filter(([, s]) => s.ports).map(([n, s]) => [n, s.ports]);
      expect(publies).to.deep.equal([["enregistreur", ["127.0.0.1:${NOORTRACE_DEMO_PORT_SANTE:-8500}:8500"]]]);
    });

    it("MN-22, CT-2 EX-3.2, EX-18.5 : le volume du journal n'est monté que par l'enregistreur et par l'exploitation, qui tourne sous son compte et dans son espace de processus ; agent-demo ne monte rien ; le volume des exports n'est en écriture que chez l'enregistreur", function () {
      const montent = (volume) => Object.entries(S).filter(([, s]) => (s.volumes ?? []).some((v) => v.type === "volume" && v.source === volume)).map(([n]) => n).sort();
      expect(montent("journal")).to.deep.equal(["enregistreur", "exploitation-demo"]);
      expect(S["agent-demo"]).to.not.have.property("volumes");
      expect(S["exploitation-demo"].pid).to.equal("service:enregistreur");
      expect(S["exploitation-demo"].user).to.equal(S.enregistreur.user);
      expect(S["exploitation-demo"].image).to.equal(S.enregistreur.image);
      const exportsDe = (n) => S[n].volumes.find((v) => v.source === "exports");
      expect(exportsDe("verificateur").read_only).to.equal(true);
      expect(montent("exports")).to.deep.equal(["enregistreur", "exploitation-demo", "verificateur"]);
      expect(montent("prises")).to.deep.equal(["approbation", "enregistreur"]);
      expect(montent("prise-console")).to.deep.equal(["approbateur-demo", "approbation"]);
      expect(montent("demandes")).to.deep.equal(["approbateur-demo", "exploitation-demo"]);
    });

    it("CT-8 CO-4 à CO-8 appliquées à la démonstration : chaque service en lecture seule, toutes capacités retirées, no-new-privileges, compte numérique non nul, sans redémarrage ; les services qui se terminent n'ont pas de sonde", function () {
      for (const [n, s] of Object.entries(S)) {
        expect(s.read_only, n).to.equal(true);
        expect(s.cap_drop, n).to.deep.equal(["ALL"]);
        expect(s.security_opt, n).to.deep.equal(["no-new-privileges:true"]);
        expect(s.user, n).to.match(/^[1-9][0-9]*:[1-9][0-9]*$/);
        expect(s.restart, n).to.equal("no");
        expect(s, n).to.not.have.property("privileged");
      }
      for (const n of ["agent-demo", "exploitation-demo", "verificateur"]) expect(S[n].healthcheck, n).to.deep.equal({ disable: true });
      for (const n of ["registre-dev", "outils-demo", "modele-demo", "approbateur-demo", "approbation", "enregistreur"]) expect(S[n].healthcheck.test[0], n).to.equal("CMD");
    });

    it("§19.2, ordre de démarrage : la clé est inscrite au registre (approbateur-demo sain) avant le démon ; l'agent attend le démon sain ; l'exploitation attend la fin réussie de l'agent ; le vérificateur démarre avec la composition (sa durée couvre la démonstration)", function () {
      expect(S["approbateur-demo"].depends_on).to.deep.equal({ "registre-dev": { condition: "service_healthy" } });
      expect(Object.keys(S.enregistreur.depends_on).sort()).to.deep.equal(["approbateur-demo", "approbation", "modele-demo", "outils-demo", "registre-dev"]);
      for (const c of Object.values(S.enregistreur.depends_on)) expect(c.condition).to.equal("service_healthy");
      expect(S["agent-demo"].depends_on).to.deep.equal({ enregistreur: { condition: "service_healthy" } });
      expect(S["exploitation-demo"].depends_on).to.deep.equal({ "agent-demo": { condition: "service_completed_successfully" } });
      expect(S.verificateur).to.not.have.property("depends_on");
    });

    it("CT-3 EX-3.3, EX-3.4, §19.2 pas 6 : les clés privées des comptes Hardhat 1 à 3 ne sont écrites que dans le programme d'approbateur-demo ; ni compose.yaml, ni la configuration du démon, ni celle du service d'approbation, ni aucun autre programme de la démonstration ne les portent ; le service d'approbation est l'image de CT-3, sans réseau", function () {
      const cles = CONSTANTES_CT3.accounts.filter((a) => [1, 2, 3].includes(a.index)).map((a) => a.private_key.slice(2));
      expect(cles).to.have.lengthOf(3);
      const porteurs = fichiersDemo().filter((f) => cles.some((k) => lire(f).toLowerCase().includes(k)));
      expect(porteurs).to.deep.equal(["conteneurs/approbateur-demo/approbateur-demo.mjs"]);
      for (const k of cles) expect(lire("conteneurs", "approbateur-demo", "approbateur-demo.mjs")).to.include(k);
      // Le démon et le service réels : aucune clé d'approbateur dans leurs paquets (le service factice des essais n'est pas employé).
      expect(JSON.stringify(CONFIG)).to.not.include("factice");
      expect(COMPOSE.services.approbation.image).to.equal("noortrace/approbation:0.1.0");
      expect(CONFIG.policy.approval.service).to.deep.equal({ url: null, socket: "/run/noortrace/approbation.sock", token: null, peer_user: "noortrace-approbation" });
      // Les trois approbateurs sont des adresses dans la politique et dans le programme du registre de développement.
      expect(CONFIG.policy.approval.rules.approver_set.members).to.deep.equal(CONSTANTES_CT3.accounts.slice(0, 3).map((a) => a.address));
      expect([...registreDev.APPROBATEURS]).to.deep.equal(CONSTANTES_CT3.accounts.slice(0, 3).map((a) => a.address));
    });

    it("CT-7 §7.1 : l'attestation de périmètre de la démonstration a la forme d'AT-1, déclare agent-demo sur les canaux mandataire_mcp et passerelle, et son empreinte des règles de sortie est le SHA-256 de demo/compose.yaml", function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "conformite", "attestation.mjs"), "verifier", path.join(DEMO, "attestation-perimetre-demo.json"), "--forme"], { cwd: RACINE, encoding: "utf8" });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      const a = lireJson("demo", "attestation-perimetre-demo.json");
      expect(a.agents.map((x) => [x.agent_id, x.capture_channels])).to.deep.equal([["agent-demo", ["mandataire_mcp", "passerelle"]]]);
      expect(CONFIG.model.mode).to.equal("passerelle");
      expect(CONFIG.mcp.enabled).to.equal(true);
      expect(a.org.org_id).to.equal(CONFIG.recorder.org_id);
      expect(a.journals[0].journal_id).to.equal(CONFIG.recorder.journal_id);
      expect(a.gateway_credentials).to.deep.equal(CONFIG.policy.model.routes.map((x) => ({ route: x.path, provider_label: x.provider_label, secret_ref: x.secret })));
      expect(a.egress.rules_sha256, "recalculer : sha256sum demo/compose.yaml").to.equal(`0x${sha256(fs.readFileSync(path.join(DEMO, "compose.yaml")))}`);
    });
  });

  describe("§19.1, §19.2 : documents de demo/", function () {
    it("EX-15.4 : demo/configuration-demo.json est valide pour le démon (noortrace validate-config, code 0 ; avertissements : canaux http:// hors de la boucle locale de la route du modèle et du serveur demo, EX-15.4 pas 3, révision 0.11 ; approbateurs de test, EX-15.8) ; développement, classe D, clé rec-test-01, bail file, mode passerelle, politique demo-2026-12 en mode erreur, serveur demo en ère 2026-07-28, route /v1/messages vers modele-demo à clé propre", function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace"), "validate-config", path.join(DEMO, "configuration-demo.json")], { encoding: "utf8", env: envDe("enregistreur") });
      expect(r.status, r.stderr).to.equal(0);
      expect(`${r.stdout}${r.stderr}`.trim().split("\n").filter(Boolean)).to.deep.equal([
        "avertissement : /policy/model/routes/0/upstream : http:// hors de la boucle locale : l'identifiant du fournisseur part en clair (refusé en production)",
        "avertissement : /policy/servers/demo/transport/url : http:// hors de la boucle locale : requêtes et résultats partent en clair (CT-7 §3.2)",
        "avertissement : /policy/approval/rules/approver_set/members : approbateurs_de_test (EX-15.8)",
      ]);
      expect(CONFIG.recorder.environment).to.equal("developpement");
      expect([CONFIG.signer.class, CONFIG.signer.key_id, CONFIG.signer.backend.type, CONFIG.lease.store.type, CONFIG.model.mode]).to.deep.equal(["D", "rec-test-01", "file", "file", "passerelle"]);
      expect([CONFIG.policy.version, CONFIG.policy.approval.mode]).to.deep.equal(["demo-2026-12", "erreur"]);
      expect(CONFIG.policy.approval.rules.version).to.equal(0);
      const serveur = CONFIG.policy.servers.demo;
      expect([serveur.transport.type, serveur.transport.url, serveur.protocol]).to.deep.equal(["http", "http://outils-demo:8000/mcp", "2026-07-28"]);
      expect(Object.entries(serveur.tools).map(([n, t]) => [n, t.class])).to.deep.equal([["claims.get", "lecture"], ["claims.search", "lecture"], ["payments.create", "ecriture"]]);
      expect(CONFIG.policy.model.routes).to.have.lengthOf(1);
      expect(CONFIG.policy.model.routes[0]).to.include({ path: "/v1/messages", format: "anthropic-messages", upstream: "http://modele-demo:8080", provider_label: "demo", credentials: "propre" });
      // Connexions d'hôte de l'agent : celles du vecteur journal-demo.
      for (const h of [CONFIG.mcp.hosts[0], CONFIG.model.hosts[0]]) {
        expect({ id: h.id, host_group: h.host_group, launched_by: h.launched_by, on_behalf_of: h.on_behalf_of, scope: h.scope, tool_name_template: h.tool_name_template, tool_name_sanitize: h.tool_name_sanitize }).to.deep.equal(ENTREES_DEMO.host);
      }
    });

    it("§19.1 : chaque secret de la configuration du démon est une référence à une variable d'environnement que compose.yaml donne au seul service enregistreur ; la clé du signataire est le fichier PKCS#8 de la clé de test rec-test-01 de CT-1 §13, dont la clé publique est celle des ancres", function () {
      const references = [];
      const parcourir = (o) => {
        if (o === null || typeof o !== "object") return;
        if (typeof o.env === "string" && Object.keys(o).every((k) => ["env", "encoding"].includes(k))) references.push(o.env);
        if (typeof o.file === "string" && Object.keys(o).every((k) => ["file", "encoding"].includes(k))) references.push(`fichier ${o.file}`);
        for (const v of Object.values(o)) parcourir(v);
      };
      parcourir(CONFIG);
      expect(references.sort()).to.deep.equal(["NOORTRACE_DEMO_CLE_CHAINE", "NOORTRACE_DEMO_CLE_MAC_RELAIS", "NOORTRACE_DEMO_CLE_MODELE", "NOORTRACE_DEMO_JETON_HOTE", "NOORTRACE_DEMO_JETON_PASSERELLE"]);
      for (const v of references) {
        const services = Object.entries(COMPOSE.services).filter(([, s]) => s.environment && v in s.environment).map(([n]) => n);
        expect(services, v).to.deep.equal(["enregistreur"]);
      }
      const graine = createHash("sha256").update("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01").digest();
      const cle = createPrivateKey(lire("demo", "cle-rec-test-01.pem"));
      expect(cle.export({ format: "der", type: "pkcs8" }).subarray(-32).equals(graine)).to.equal(true);
      const publique = `0x${createPublicKey(cle).export({ format: "der", type: "spki" }).subarray(-32).toString("hex")}`;
      expect(publique).to.equal(lireJson("demo", "ancres-demo.json").recorders[0].public_key);
      expect(COMPOSE.services.enregistreur.volumes.find((v) => v.target === CONFIG.signer.backend.path).source).to.equal("./cle-rec-test-01.pem");
      // Clé de chaîne de test de CT-4 : l'adresse de la configuration est celle de la clé que compose.yaml donne.
      const cleChaine = R.SignataireChaineFichier.depuisOctets(COMPOSE.services.enregistreur.environment.NOORTRACE_DEMO_CLE_CHAINE);
      expect(cleChaine.adresse()).to.equal(CONFIG.anchoring.registry.chain_key.address);
      expect(CONSTANTES_CT4.recorders[0]).to.include({ key_id: "rec-test-01", chain_key: cleChaine.adresse(), public_key: publique });
    });

    it("CT-5 AN-1 : demo/ancrage-demo.json est valide en développement à la cadence des points de la configuration ; ni calendrier OpenTimestamps ni serveur RFC 3161 joint (le prestataire exigé par le schéma désigne la boucle locale, où rien n'écoute) : la démonstration est hors ligne", function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage"), "configuration", path.join(DEMO, "ancrage-demo.json"), "--profil", "developpement", "--checkpoint-interval", String(CONFIG.checkpoint_interval_s)], { encoding: "utf8" });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      const a = lireJson("demo", "ancrage-demo.json");
      expect(a.opentimestamps.enabled).to.equal(false);
      expect(a.rfc3161.providers.map((p) => p.url)).to.deep.equal(["http://127.0.0.1:2020/"]);
      expect(a.checkpoint_interval_s).to.equal(CONFIG.checkpoint_interval_s);
      expect(CONFIG.anchoring.ancrage).to.equal("/etc/noortrace/ancrage.json");
      // Le manifeste d'instance est monté à côté du document d'ancrage (lecture 199 de l'enregistreur).
      const cibles = COMPOSE.services.enregistreur.volumes.map((v) => v.target);
      expect(cibles).to.include.members(["/etc/noortrace/ancrage.json", "/etc/noortrace/instance-registre.json"]);
      expect(Object.values(COMPOSE.services).some((s) => /tsa|horodatage/.test(s.image))).to.equal(false);
    });

    it("CT-3 EX-10.12 : demo/approbation-demo.json est valide (valider-configuration) ; même organisation et même journal que le démon ; canal du noyau et canal de la console sur deux prises ; aucun secret en fichier", function () {
      const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "approbation", "bin", "noortrace-approbation"), "valider-configuration", path.join(DEMO, "approbation-demo.json")], { encoding: "utf8" });
      expect(r.status, r.stdout + r.stderr).to.equal(0);
      expect(r.stdout.trim()).to.equal('{"valide":true,"errors":[]}');
      const a = lireJson("demo", "approbation-demo.json");
      expect([a.environment, a.org, a.org_id, a.journal_id]).to.deep.equal(["developpement", "assureur-demo", CONFIG.recorder.org_id, CONFIG.recorder.journal_id]);
      expect(a.noyau.socket).to.equal(CONFIG.policy.approval.service.socket);
      expect(a.console.socket).to.equal("/run/noortrace-console/console.sock");
      expect(a.rpc).to.equal(null);
      expect(COMPOSE.services.approbation.environment.NOORTRACE_DEMO_JETON_CONSOLE).to.equal(COMPOSE.services["approbateur-demo"].environment.APPROBATEUR_CONSOLE_JETON);
    });

    it("CT-4 §4.8, §6.7.3 : demo/instance-registre.json est le manifeste que registre-dev calcule (adresses CREATE du déployeur de développement aux nonces 0 à 3, validateurs de test de CT-4) ; demo/ancres-demo.json déclare la même instance, la clé rec-test-01 et sa clé de chaîne ; les identifiants de l'organisation et du journal sont keccak256 de leurs noms", function () {
      const instance = lireJson("demo", "instance-registre.json");
      expect(instance).to.deep.equal(registreDev.manifesteInstance());
      const attendues = registreDev.adressesAttendues();
      expect(attendues.deployeur).to.equal(CONSTANTES_CT4.accounts[0].address);
      registreDev.CONTRATS.forEach((nom, k) => expect(attendues[nom], nom).to.equal(R.adresseCreation(attendues.deployeur, k)));
      expect(instance.validator_sets[0].validators).to.deep.equal(CONSTANTES_CT4.test_validators.validators.map((v) => ({ id: v.id, pubKeyHex: v.pubKeyHex })));
      expect(R.hachageJeuHex(R.lireJeu(instance.validator_sets[0].validators))).to.equal(CONSTANTES_CT4.test_validators.valset_hash);
      expect([instance.bft_chain_id, instance.evm_chain_id]).to.deep.equal([CONSTANTES_CT4.chain.bft_chain_id, CONSTANTES_CT4.chain.evm_chain_id]);
      const ancres = lireJson("demo", "ancres-demo.json");
      const adresse = (n) => instance.contracts.find((c) => c.name === n).address;
      expect(ancres.registry.contracts).to.deep.equal({ attestation_registry: adresse("AttestationRegistry"), period_registry: adresse("PeriodRegistry"), recorder_registry: adresse("RecorderRegistry") });
      expect(ancres.registry.validator_sets[0].validators).to.deep.equal(instance.validator_sets[0].validators);
      expect(ancres.recorders[0]).to.include({ org_id: CONFIG.recorder.org_id, journal_id: CONFIG.recorder.journal_id, key_id: "rec-test-01", chain_key: CONFIG.anchoring.registry.chain_key.address });
      expect([ancres.tsa_authorities, ancres.bitcoin]).to.deep.equal([[], null]);
      expect(R.verifierSlug("assureur-demo").org_id).to.equal(CONFIG.recorder.org_id);
      expect(R.verifierNomJournal("journal-demo").journal_id).to.equal(CONFIG.recorder.journal_id);
      const E = COMPOSE.services;
      expect(E["registre-dev"].environment.REGISTRE_DEV_ORG_ID).to.equal(CONFIG.recorder.org_id);
      expect(E["registre-dev"].environment.REGISTRE_DEV_CLE_CHAINE).to.equal(CONFIG.anchoring.registry.chain_key.address);
      expect(E["approbateur-demo"].environment).to.include({ APPROBATEUR_ORG_ID: CONFIG.recorder.org_id, APPROBATEUR_JOURNAL_ID: CONFIG.recorder.journal_id, APPROBATEUR_CLE_CHAINE: CONFIG.anchoring.registry.chain_key.address, APPROBATEUR_CLE_ED25519: ancres.recorders[0].public_key });
      expect([E.verificateur.environment.DEMO_ORGANISATION, E.verificateur.environment.DEMO_JOURNAL]).to.deep.equal(["assureur-demo", "journal-demo"]);
    });
  });

  describe("EX-19.3 : option « modèle réel », lue sans la lancer", function () {
    const SURCHARGE = yaml.load(lire("demo", "compose.modele-reel.yaml"));
    const REEL = lireJson("demo", "configuration-demo-modele-reel.json");

    it("la configuration de l'option est celle de la démonstration, à la route /v1/messages près : fournisseur réel, credentials « propre », secret lu dans la variable ANTHROPIC_API_KEY, jamais dans un fichier ; elle est valide pour le démon", function () {
      const attendue = structuredClone(CONFIG);
      Object.assign(attendue.policy.model.routes[0], { upstream: "https://api.anthropic.com", provider_label: "anthropic", secret: { env: "ANTHROPIC_API_KEY" } });
      expect(REEL).to.deep.equal(attendue);
      expect(REEL.policy.model.routes[0].credentials).to.equal("propre");
      const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace"), "validate-config", path.join(DEMO, "configuration-demo-modele-reel.json")], { encoding: "utf8", env: { ...envDe("enregistreur"), ANTHROPIC_API_KEY: "valeur-d-essai-sans-valeur" } });
      expect(r.status, r.stderr).to.equal(0);
    });

    it("la surcharge compose.modele-reel.yaml ne change que la configuration montée (enregistreur et exploitation), la clé donnée à l'enregistreur seul, le nom du modèle donné à l'agent, et la sortie du réseau fournisseurs ; l'agent ne reçoit pas la clé et reste sur le seul réseau hotes ; aucune clé n'y est écrite", function () {
      expect(Object.keys(SURCHARGE).sort()).to.deep.equal(["networks", "services"]);
      expect(Object.keys(SURCHARGE.services).sort()).to.deep.equal(["agent-demo", "enregistreur", "exploitation-demo"]);
      expect(SURCHARGE.networks).to.deep.equal({ fournisseurs: { internal: false } });
      for (const n of ["enregistreur", "exploitation-demo"]) {
        expect(SURCHARGE.services[n].volumes.map((v) => [v.source, v.target, v.read_only]), n).to.deep.equal([["./configuration-demo-modele-reel.json", "/etc/noortrace/configuration.json", true]]);
      }
      expect(Object.keys(SURCHARGE.services.enregistreur.environment)).to.deep.equal(["ANTHROPIC_API_KEY"]);
      expect(SURCHARGE.services.enregistreur.environment.ANTHROPIC_API_KEY).to.match(/^\$\{ANTHROPIC_API_KEY:\?/);
      expect(SURCHARGE.services["agent-demo"]).to.deep.equal({ environment: { AGENT_DEMO_MODELE: "${MODELE_REEL:?identifiant du modèle exigé}" } });
      expect(SURCHARGE.services["exploitation-demo"]).to.not.have.property("environment");
      // Dans la composition de base, la clé de l'agent est factice.
      expect(COMPOSE.services["agent-demo"].environment.ANTHROPIC_API_KEY).to.equal("cle-factice-agent-demo");
    });
  });

  describe("§19.3, EX-19.2 : simulateur de l'API Messages (modele-demo), en processus", function () {
    let s;
    const corps1 = { model: "modele-demo-1", max_tokens: 1024, system: agent.SYSTEME, messages: [{ role: "user", content: agent.DEMANDE }], tools: [] };
    const poster = (corps, entetes = {}) => fetch(`${s.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": "cle-d-essai", ...entetes }, body: typeof corps === "string" ? corps : JSON.stringify(corps) });

    before(async function () {
      s = await ecouter(modele.creerServeur().serveur);
    });
    after(async function () {
      await s?.fermer();
    });

    it("réponse hors flux = objet Message (id, type, role, model, content, stop_reason, stop_sequence, usage), octets égaux au vecteur journal-demo ; anthropic-version recopié tel quel ; x-api-key ou Authorization: Bearer acceptés sans vérification", async function () {
      const r = await poster(corps1);
      expect(r.status).to.equal(200);
      expect(r.headers.get("anthropic-version")).to.equal("2023-06-01");
      const texte = await r.text();
      expect(texte).to.equal(ENTREES_DEMO.exchanges[0].response_body);
      expect(Object.keys(JSON.parse(texte))).to.deep.equal(["id", "type", "role", "model", "content", "stop_reason", "stop_sequence", "usage"]);
      const porteur = await fetch(`${s.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", authorization: "Bearer n-importe-quoi" }, body: JSON.stringify(corps1) });
      expect(porteur.status).to.equal(200);
      const sansCle = await fetch(`${s.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "anthropic-version": "2023-06-01" }, body: JSON.stringify(corps1) });
      expect(sansCle.status).to.equal(200);
    });

    it("réponse en flux = text/event-stream, séquence message_start, content_block_start, content_block_delta (text_delta ; input_json_delta au premier partial_json vide), content_block_stop, message_delta (stop_reason, usage cumulatif), message_stop, un ping inséré ; octets égaux au vecteur ; le scénario est choisi par le dernier message utilisateur (trois réponses, identifiants msg_… et toolu_… fixes)", async function () {
      const e2 = ENTREES_DEMO.exchanges[1];
      const r = await poster(e2.request);
      expect(r.status).to.equal(200);
      expect(r.headers.get("content-type")).to.equal("text/event-stream");
      const texte = await r.text();
      expect(texte).to.equal(e2.response_body);
      const types = texte.split("\n\n").filter(Boolean).map((b) => /^event: (.*)$/m.exec(b)[1]);
      expect(types).to.deep.equal(["message_start", "content_block_start", "content_block_delta", "ping", "content_block_delta", "content_block_stop", "content_block_start", "content_block_delta", "content_block_delta", "content_block_delta", "content_block_stop", "message_delta", "message_stop"]);
      expect(texte).to.include('"delta":{"type":"input_json_delta","partial_json":""}');
      const e3 = ENTREES_DEMO.exchanges[2];
      expect(await (await poster(e3.request)).text()).to.equal(e3.response_body);
      expect(modele.SCENARIO.map((x) => x.message.id)).to.deep.equal(["msg_demo_0001", "msg_demo_0002", "msg_demo_0003"]);
      // Le flux relu par l'agent redonne le message consolidé.
      expect(agent.consoliderFlux(texte)).to.deep.equal({ ...modele.SCENARIO[1].message });
      // Chaque réponse du scénario existe aussi en flux, et se consolide en elle-même.
      for (const x of modele.SCENARIO) expect(agent.consoliderFlux(modele.corpsFlux(x).join("")), x.nom).to.deep.equal(x.message);
    });

    it("erreurs au format {type: error, error: {type, message}, request_id} : corps sans messages (400 invalid_request_error), anthropic-version absent (400), corps illisible (400), dernier message hors scénario (400), route inconnue (404), méthode (405)", async function () {
      const lireErreur = async (r) => {
        const j = await r.json();
        expect(Object.keys(j)).to.deep.equal(["type", "error", "request_id"]);
        expect(j.type).to.equal("error");
        expect(Object.keys(j.error)).to.deep.equal(["type", "message"]);
        expect(j.request_id).to.equal(r.headers.get("request-id"));
        return [r.status, j.error.type];
      };
      expect(await lireErreur(await poster({ model: "modele-demo-1", max_tokens: 16 }))).to.deep.equal([400, "invalid_request_error"]);
      expect(await lireErreur(await fetch(`${s.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(corps1) }))).to.deep.equal([400, "invalid_request_error"]);
      expect(await lireErreur(await poster("{pas du json"))).to.deep.equal([400, "invalid_request_error"]);
      expect(await lireErreur(await poster({ ...corps1, messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_inconnu", content: "x" }] }] }))).to.deep.equal([400, "invalid_request_error"]);
      expect(await lireErreur(await fetch(`${s.url}/v1/autre`, { method: "POST", body: "{}" }))).to.deep.equal([404, "not_found_error"]);
      expect(await lireErreur(await fetch(`${s.url}/v1/messages`))).to.deep.equal([405, "invalid_request_error"]);
    });

    it("TA-18, précondition : GET /demo/usage rend le nombre de requêtes reçues par clé et par route, la clé nommée par les 16 premiers chiffres de son SHA-256, jamais par sa valeur", async function () {
      const frais = await ecouter(modele.creerServeur().serveur);
      try {
        const envoyer = (cle) => fetch(`${frais.url}/v1/messages`, { method: "POST", headers: { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-api-key": cle }, body: JSON.stringify(corps1) });
        await envoyer("cle-a");
        await envoyer("cle-a");
        await envoyer("cle-b");
        const texte = await (await fetch(`${frais.url}/demo/usage`)).text();
        expect(texte).to.not.include("cle-a");
        const attendu = [["cle-a", 2], ["cle-b", 1]].map(([k, n]) => ({ key_sha256_16: sha256(k).slice(0, 16), route: "/v1/messages", requests: n })).sort((a, b) => (a.key_sha256_16 < b.key_sha256_16 ? -1 : 1));
        expect(JSON.parse(texte)).to.deep.equal({ version: 0, usage: attendu });
      } finally {
        await frais.fermer();
      }
    });
  });

  describe("§19.1 : serveur d'outils de démonstration (outils-demo), en processus", function () {
    let s;
    const rpc = async (m) => {
      const r = await fetch(`${s.url}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(m) });
      return { statut: r.status, json: r.status === 200 ? await r.json() : null };
    };

    before(async function () {
      s = await ecouter(outils.creerServeur().serveur);
    });
    after(async function () {
      await s?.fermer();
    });

    it("ère 2026-07-28 en Streamable HTTP : server/discover, tools/list (trois outils : claims.get et claims.search en lecture, payments.create en écriture, avec son schéma de sortie), notification acquittée par 202, méthode inconnue -32601", async function () {
      const d = await rpc({ jsonrpc: "2.0", id: 1, method: "server/discover", params: {} });
      expect(d.json.result).to.deep.include({ resultType: "complete", supportedVersions: ["2026-07-28"] });
      const l = await rpc({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
      expect(l.json.result.tools.map((t) => [t.name, t.annotations.readOnlyHint])).to.deep.equal([["claims.get", true], ["claims.search", true], ["payments.create", false]]);
      expect(l.json.result.tools[2].outputSchema.required).to.deep.equal(["payment_id"]);
      expect((await rpc({ jsonrpc: "2.0", method: "notifications/initialized" })).statut).to.equal(202);
      expect((await rpc({ jsonrpc: "2.0", id: 3, method: "resources/list", params: {} })).json.error.code).to.equal(-32601);
      // Les noms que l'enregistreur annonce sont ceux de la politique et du scénario du simulateur.
      expect(l.json.result.tools.map((t) => t.name)).to.deep.equal(Object.keys(CONFIG.policy.servers.demo.tools));
      expect(modele.SCENARIO.flatMap((x) => x.message.content.filter((b) => b.type === "tool_use").map((b) => b.name))).to.deep.equal(["demo__claims_get", "demo__payments_create"].map((n) => n));
      expect(l.json.result.tools.map((t) => agent.assainir(`demo__${t.name}`))).to.include.members(["demo__claims_get", "demo__payments_create"]);
    });

    it("tools/call : claims.get rend le dossier fictif (adresse en .example), payments.create rend PAY-2026-90417 en contenu structuré ; sinistre inconnu : isError ; outil inconnu : -32602 ; /sante compte les appels reçus", async function () {
      const appeler = (name, args, id = 10) => rpc({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });
      const lu = (await appeler("claims.get", { claim_id: "2026-81044" })).json.result;
      expect(lu.isError).to.equal(false);
      expect(lu.content[0].text).to.equal("Sinistre 2026-81044 : collision du 2026-11-02, dommages 7400.00 CHF, assuré joignable à j.dupont@assure.example ou au +41 44 123 45 67");
      const paye = (await appeler("payments.create", { claim_id: "2026-81044", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH93 0076 2011 6238 5295 7" })).json.result;
      expect(paye).to.deep.include({ structuredContent: { payment_id: "PAY-2026-90417" }, isError: false });
      expect(paye.content[0].text).to.equal("Paiement PAY-2026-90417 créé pour le sinistre 2026-81044");
      expect((await appeler("claims.get", { claim_id: "0000-00000" })).json.result.isError).to.equal(true);
      expect((await appeler("payments.create", { claim_id: "0000-00000", amount: "1", currency: "CHF", beneficiary_iban: "x" })).json.result.isError).to.equal(true);
      expect((await appeler("claims.search", { query: "collision" })).json.result.content[0].text).to.include("2026-81044");
      expect((await appeler("inconnu", {})).json.error.code).to.equal(-32602);
      expect(await (await fetch(`${s.url}/sante`)).json()).to.deep.equal({ ok: true, appels: 6 });
    });
  });

  describe("§19.4 : sortie du vérificateur de la démonstration", function () {
    /** Rapport de vérification réduit aux membres que l'impression lit (forme de rapport-verification-v0). */
    const rapport = (o = {}) => ({
      verdict: "valide", exit_code: 0, bound: "verdict borné : contrôle 4 non exécuté (partie_absente), contrôle 5 non exécuté (partie_absente)",
      event: { seq: 7, tool: "demo__payments.create" },
      period: { period_start: 1794304800, period_end: 1794308400 },
      controls: [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ number: n, status: [4, 5].includes(n) ? "non_execute" : "reussi", reason: [4, 5].includes(n) ? "partie_absente" : null })),
      facts: {
        recorder_keys: { event_key_id: "rec-test-01" },
        approval: { decision: "approuve", approvers: ["0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"], required: 2, size: 3 },
        registry: { entries: ["inscription", "ancre_point_de_controle", "ancre", "cloture"].map((role) => ({ role })), certificates: [{ signers: ["v1", "v2", "v3", "v4"] }, { signers: ["v1", "v2", "v3", "v4"] }] },
      },
      ...o,
    });
    const contexte = { recorder: { class: "D", key_id: "rec-test-01", lease_store: "file", epoch: 1 }, closure: { count: 8 }, retained_seq: 5 };
    const imprimer = (r, dureeMs = 41000) => verificateur.sortie({ rapport: r, contexte, evenement: { code: { recorder: "0.1.0" } }, organisation: "assureur-demo", journal: "journal-demo", dossier: "dossiers/seq-7", dureeMs });

    it("TE-3 : pour le dossier que la démonstration attend, la sortie est celle de CT-2 §19.4, mot pour mot, aux valeurs variables près (version, clé, bail, époque, nombre d'événements, période, validateurs, dossier, approbateurs, seuil, nombre de contrôles, seq de la demande retenue, durée) ; la phrase « Il ne prouve pas la date » y figure", function () {
      const s = imprimer(rapport());
      expect(s.reference).to.equal(true);
      const attendue = sortieDeLaSpecification();
      expect(s.lignes.map(normaliser)).to.deep.equal(attendue.map(normaliser));
      // Les valeurs du vecteur journal-demo que la spécification imprime sont celles de la démonstration.
      expect(s.lignes[1]).to.equal(attendue[1]);
      expect(s.lignes[2]).to.equal("  journal         : assureur-demo / journal-demo, 8 événements, période 2026-11-10T10:00:00Z → 11:00:00Z");
      expect(s.lignes[2]).to.equal(attendue[2]);
      expect(s.lignes[3]).to.equal(attendue[3]);
      expect(s.lignes[4]).to.equal(attendue[4]);
      expect(s.lignes.slice(6, 11)).to.deep.equal(attendue.slice(6, 11));
      expect(s.lignes.join("\n")).to.include("Il ne prouve pas la date (ancres RFC 3161 et OpenTimestamps absentes : démonstration hors ligne).");
    });

    it("PD-25 : la durée est imprimée en secondes à trois décimales, virgule décimale (119,600 s ne s'imprime pas « 120 s ») ; les contrôles comptés sont les huit contrôles de l'architecture : six réussis, deux non exécutés (4 et 5 : T-*, O-*)", function () {
      expect(verificateur.secondes(119600)).to.equal("119,600");
      expect(verificateur.secondes(41237.4)).to.equal("41,237");
      expect(verificateur.secondes(999.6)).to.equal("1,000");
      expect(imprimer(rapport(), 52108).lignes.at(-1)).to.equal("  Durée totale : 52,108 s");
      expect(imprimer(rapport()).lignes[5]).to.equal("  vérificateur    : 6 contrôles [ok], 2 non exécutés avec raison admise (T-*, O-* : démonstration hors ligne)");
      expect(verificateur.periode(1794304800, 1794308400)).to.equal("2026-11-10T10:00:00Z → 11:00:00Z");
      expect(verificateur.abreger("0x70997970c51812dc3a010c7d01b50e0d17dc79c8")).to.equal("0x7099…79c8");
    });

    it("un dossier qui n'est pas celui de la démonstration n'imprime jamais « VALIDE — cet événement… » : verdict invalide, contrôle en échec, inscription non prouvée par le dossier, bloc certifié par moins de validateurs que le jeu ; la phrase sur ce que le dossier ne prouve pas reste", function () {
      const invalide = imprimer(rapport({ verdict: "invalide", exit_code: 1, controls: [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ number: n, status: n === 2 ? "echoue" : [4, 5].includes(n) ? "non_execute" : "reussi", reason: [4, 5].includes(n) ? "partie_absente" : null })) }));
      expect(invalide.reference).to.equal(false);
      expect(invalide.lignes.join("\n")).to.not.include("VALIDE — cet événement");
      expect(invalide.lignes[6]).to.match(/^ {2}Résultat : INVALIDE — le dossier n'est pas vérifié/);
      expect(invalide.lignes[5]).to.include("1 en échec (2)");
      expect(invalide.lignes[7]).to.include("Il ne prouve pas la date");
      const sansInscription = rapport();
      sansInscription.facts.registry.entries = sansInscription.facts.registry.entries.filter((e) => e.role !== "inscription");
      const s2 = imprimer(sansInscription);
      expect(s2.reference).to.equal(false);
      expect(s2.lignes[3]).to.include("inscription de la clé non prouvée par le dossier");
      expect(s2.lignes.join("\n")).to.not.include("VALIDE — cet événement");
      const troisSignataires = rapport();
      troisSignataires.facts.registry.certificates[1].signers = ["v1", "v2", "v4"];
      expect(imprimer(troisSignataires).lignes[3]).to.include("bloc certifié par 3 validateurs");
      const avecJeton = rapport({ controls: [1, 2, 3, 4, 5, 6, 7, 8].map((n) => ({ number: n, status: n === 5 ? "non_execute" : "reussi", reason: n === 5 ? "partie_absente" : null })) });
      const s3 = imprimer(avecJeton);
      expect(s3.reference).to.equal(false);
      expect(s3.lignes[5]).to.equal("  vérificateur    : 7 contrôles [ok], 1 non exécutés avec raison admise (contrôle 5 : partie_absente)");
      expect(s3.lignes[7]).to.include("Ce que ce dossier ne prouve pas est dit par le rapport du vérificateur");
    });
  });

  describe("CT-7 EX-3.8 : outil de rapprochement de la démonstration (TA-18), sur des segments d'essai", function () {
    let dir;
    const CLE = "cle-de-la-passerelle-d-essai";
    const configuration = { policy: { model: { routes: [{ path: "/v1/messages", provider_label: "demo", credentials: "propre", secret: { env: "NOORTRACE_ESSAI_CLE" } }, { path: "/v1/chat/completions", provider_label: "autre", credentials: "relayer", secret: null }] } } };
    const evenement = (seq, outil, modeleCode) => JSON.stringify({ seq, execution: { tool: outil }, code: { model: modeleCode } });
    const lancer = (usage, env = { NOORTRACE_ESSAI_CLE: CLE }) => {
      fs.writeFileSync(path.join(dir, "usage.json"), JSON.stringify(usage));
      const sortie = [];
      const erreurs = [];
      const code = rapprochement.principal(["--configuration", path.join(dir, "configuration.json"), "--segments", path.join(dir, "segments"), "--usage", path.join(dir, "usage.json"), "--json"], { stdout: { write: (x) => sortie.push(x) }, stderr: { write: (x) => erreurs.push(x) }, env });
      return { code, rapport: sortie.length ? JSON.parse(sortie.join("")) : null, erreurs: erreurs.join("") };
    };

    before(function () {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-rapprochement-"));
      fs.mkdirSync(path.join(dir, "segments"));
      fs.writeFileSync(path.join(dir, "configuration.json"), JSON.stringify(configuration));
      fs.writeFileSync(path.join(dir, "segments", "seg-0000000000000001-00000000000000000001.ndjson"), [JSON.stringify({ noortrace_segment: 0, first_seq: 1 }), evenement(1, "noortrace.journal.politique", null), evenement(2, "noortrace.modele.echange", "demo/modele-demo-1"), evenement(3, "demo__claims.get", "demo/modele-demo-1"), evenement(4, "noortrace.modele.echange", "demo/modele-demo-1")].join("\n") + "\n");
      fs.writeFileSync(path.join(dir, "segments", "seg-0000000000000005-00000000000000000001.ndjson"), [JSON.stringify({ noortrace_segment: 0, first_seq: 5 }), evenement(5, "noortrace.modele.echange", "demo/modele-demo-1"), evenement(6, "noortrace.modele.echange", "autre/x")].join("\n") + "\n");
    });
    after(function () {
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it("aucun écart quand le fournisseur déclare, pour la clé de la passerelle, autant de requêtes que le journal a d'échanges de la route : code 0 ; la clé est nommée par son empreinte, jamais par sa valeur", function () {
      const empreinte = sha256(CLE).slice(0, 16);
      const r = lancer({ version: 0, usage: [{ key_sha256_16: empreinte, route: "/v1/messages", requests: 3 }, { key_sha256_16: "0".repeat(16), route: "/v1/messages", requests: 9 }] });
      expect(r.code).to.equal(0);
      expect(r.rapport).to.deep.equal({ version: 0, lignes: [{ key_sha256_16: empreinte, route: "/v1/messages", provider_label: "demo", declared: 3, journaled: 3, gap: 0 }], incident: false });
      expect(JSON.stringify(r.rapport)).to.not.include(CLE);
      expect(rapprochement.empreinteCle(CLE)).to.equal(modele.empreinteCle(CLE));
    });

    it("une requête de plus déclarée par le fournisseur pour la clé de la passerelle : écart de 1 rapporté avec la clé et la route, code 3 ; une clé de la passerelle vue sur une route que la configuration ne lui donne pas : incident aussi ; un relevé inférieur au journal est rapporté sans être un incident", function () {
      const empreinte = sha256(CLE).slice(0, 16);
      const r = lancer({ version: 0, usage: [{ key_sha256_16: empreinte, route: "/v1/messages", requests: 4 }] });
      expect(r.code).to.equal(3);
      expect(r.rapport.lignes).to.deep.equal([{ key_sha256_16: empreinte, route: "/v1/messages", provider_label: "demo", declared: 4, journaled: 3, gap: 1 }]);
      expect(r.rapport.incident).to.equal(true);
      const autreRoute = lancer({ version: 0, usage: [{ key_sha256_16: empreinte, route: "/v1/messages", requests: 3 }, { key_sha256_16: empreinte, route: "/v1/complete", requests: 2 }] });
      expect(autreRoute.code).to.equal(3);
      expect(autreRoute.rapport.lignes[1]).to.deep.equal({ key_sha256_16: empreinte, route: "/v1/complete", provider_label: null, declared: 2, journaled: 0, gap: 2 });
      const moins = lancer({ version: 0, usage: [{ key_sha256_16: empreinte, route: "/v1/messages", requests: 2 }] });
      expect([moins.code, moins.rapport.lignes[0].gap, moins.rapport.incident]).to.deep.equal([0, -1, false]);
    });

    it("entrées illisibles : secret de la route non résolu, relevé hors forme (code 1) ; usage (code 2)", function () {
      expect(lancer({ version: 0, usage: [] }, {}).code).to.equal(1);
      expect(lancer({ version: 0 }).code).to.equal(1);
      expect(rapprochement.principal([], { stdout: { write() {} }, stderr: { write() {} } })).to.equal(2);
    });
  });

  describe("CT-9 TM-43 : outil de mesure de la durée (demo/mesurer-duree.mjs), sans lancer la composition", function () {
    const SCHEMA = lireJson("spec", "schemas", "plan-de-tests-v0.schema.json");
    const campagne = (o = {}) => mesure.rapport({
      repetitions: Array.from({ length: 10 }, (_, i) => ({ imprimee_s: 50 + i * 0.5, murale_s: 55.25 + i * 0.5, code: 0 })), echauffement: 3, demandees: 10, reference: false,
      commit: "cd1d1938a3ddf817617a47d487c405c339cb3570", mesureA: "2026-11-13T07:30:00Z", configuration: { outil: "demo/mesurer-duree.mjs" }, images: ["noortrace/enregistreur:0.1.0@sha256:" + "0".repeat(64)], ...o,
    });

    it("EX-11.14 : la grandeur est la durée imprimée par le vérificateur, lue à la milliseconde ; une sortie sans durée n'est pas un échantillon", function () {
      expect(mesure.dureeImprimee("noortrace — démonstration de référence\n  Durée totale : 41,237 s\n")).to.equal(41.237);
      expect(mesure.dureeImprimee("  Durée totale : 119,600 s\n")).to.equal(119.6);
      expect(mesure.dureeImprimee("  Durée totale : 41 s\n")).to.equal(null);
      expect(mesure.dureeImprimee("")).to.equal(null);
      expect(mesure.CIBLE_S).to.equal(120);
    });

    it("EX-11.2, EX-11.3 : hors du système de référence, le rapport est conforme à rapport_mesure, porte counts_for_targets faux, et la ligne demonstration_duree de TM-43 (secondes, max, cible 120) porte met nul et hors_systeme_de_reference ; la durée murale, l'écart et les codes de retour sont publiés dans conditions, sans être comparés à la cible", function () {
      const r = campagne();
      expect(validerSchema(r, SCHEMA, { fragment: "#/$defs/rapport_mesure" })).to.deep.equal([]);
      expect([r.counts_for_targets, r.system.reference]).to.deep.equal([false, false]);
      const l = r.results[0];
      expect(l).to.deep.include({ name: "demonstration_duree", test_id: "TM-43", unit: "s", n: 10, min: 50, max: 54.5, mean: 52.25, target: 120, met: null, excluded_reason: "hors_systeme_de_reference" });
      expect(l.samples).to.have.lengthOf(10);
      expect(r.method).to.deep.include({ warmup: 3, repetitions: 10, clock: "monotone", samples_published: true });
      expect(l.conditions.join("\n")).to.include("durée murale de l'outil").and.to.include("codes de retour de verificateur par répétition : 0, 0, 0, 0, 0, 0, 0, 0, 0, 0").and.to.include("5.25, 5.25");
    });

    it("EX-11.3, EX-11.4 : sur le système de référence, dix échantillons et trois échauffements donnent met vrai sous 120 s et faux à 120,000 s ; une répétition qui imprime une durée compte quel que soit son code de retour ; sous dix échantillons : echantillon_insuffisant, met nul", function () {
      const vrai = campagne({ reference: true });
      expect(validerSchema(vrai, SCHEMA, { fragment: "#/$defs/rapport_mesure" })).to.deep.equal([]);
      expect([vrai.counts_for_targets, vrai.results[0].met, vrai.results[0].excluded_reason]).to.deep.equal([true, true, null]);
      const limite = campagne({ reference: true, repetitions: Array.from({ length: 10 }, (_, i) => ({ imprimee_s: i === 4 ? 120 : 60, murale_s: 125, code: i === 2 ? 1 : 0 })) });
      expect([limite.results[0].n, limite.results[0].max, limite.results[0].met]).to.deep.equal([10, 120, false]);
      const court = campagne({ reference: true, repetitions: [{ imprimee_s: 50, murale_s: 55, code: 0 }, { imprimee_s: null, murale_s: 300, code: null }] });
      expect(validerSchema(court, SCHEMA, { fragment: "#/$defs/rapport_mesure" })).to.deep.equal([]);
      expect([court.counts_for_targets, court.results[0].n, court.results[0].met, court.results[0].excluded_reason]).to.deep.equal([false, 1, null, "echantillon_insuffisant"]);
      expect(mesure.principal([], { stderr: { write() {} } })).to.equal(2);
    });
  });

  describe("règles de contenu de la démonstration", function () {
    const textes = () => fichiersDemo().filter((f) => !f.endsWith(".pem")).map((f) => [f, lire(f)]);

    it("CT-2 EX-19.1 : aucun prix, aucune donnée de tarif, aucun symbole monétaire dans demo/ ni dans les programmes de la démonstration ; les seuls montants sont ceux du sinistre fictif de CT-2 §19.2 (7400.00 CHF) et le seuil de la règle d'approbation (5000)", function () {
      for (const [f, t] of textes()) {
        expect(t, f).to.not.match(/\b(prix|tarif|tarifs|tarification|prime|primes|price|pricing|cost|coût|coûts)\b/i);
        expect(t, f).to.not.match(/[€$£]\s?[0-9]|[0-9]\s?(€|EUR|USD|GBP)\b/);
        const montants = [...t.matchAll(/([0-9]+(?:\.[0-9]{2})?) CHF/g)].map((m) => m[1]);
        expect([...new Set(montants)].filter((m) => !["7400.00", "5000"].includes(m)), f).to.deep.equal([]);
      }
    });

    it("domaines réservés (décision du porteur du 13 novembre 2026) : tout nom d'hôte d'une URL ou d'une adresse électronique est un nom de service de la composition, la boucle locale, l'adresse d'écoute 0.0.0.0, ou un nom du domaine réservé .example ; les seuls registres d'images nommés sont ceux des images de base épinglées ; toute adresse IPv4 écrite est admise", function () {
      const services = new Set([...Object.keys(COMPOSE.services), "127.0.0.1", "0.0.0.0"]);
      // Seul point d'accès réel : celui du fournisseur de l'option « modèle réel » (EX-19.3), dans sa configuration et nulle part ailleurs.
      const admis = (h, f) => services.has(h) || h.endsWith(".example") || (h === "api.anthropic.com" && f === "demo/configuration-demo-modele-reel.json");
      for (const [f, t] of textes()) {
        const hotes = [...t.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)].map((m) => m[1].replace(/\.$/, ""));
        const courriels = [...t.matchAll(/[A-Za-z0-9._-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)/g)].map((m) => m[1]);
        expect([...new Set([...hotes, ...courriels])].filter((h) => !admis(h, f)), f).to.deep.equal([]);
        const ips = [...t.matchAll(/\b([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\b/g)].map((m) => m[1]).filter((ip) => !/^(1\.3\.6\.1|22\.23\.[0-9]+\.[0-9]+)/.test(ip));
        expect([...new Set(ips)].filter((ip) => !["127.0.0.1", "0.0.0.0"].includes(ip) && !/^(192\.0\.2|198\.51\.100|203\.0\.113)\./.test(ip)), f).to.deep.equal([]);
      }
      const bases = new Set();
      for (const nom of IMAGES_DEMO) for (const { image } of lignesFrom(lire("conteneurs", nom, "Dockerfile"))) if (image.includes("@")) bases.add(image.split(":")[0]);
      expect([...bases].sort()).to.deep.equal(["gcr.io/distroless/cc-debian12", "golang", "node", "noortrace/noorcore"]);
    });

    it("CT-8 EX-3.13, EX-3.6 appliquées aux images de la démonstration : un répertoire de construction par image (Dockerfile, contexte filtré, passwd, group) ; chaque FROM épinglé par étiquette exacte et condensé ; étape finale sans RUN, point d'entrée = le programme en forme exec, compte numérique de compose.yaml ; registre-dev prend le nœud de l'image locale noortrace/noorcore:618fcef-noortrace et les cinq codes de création de hh-artifacts/", function () {
      expect([...IMAGES_DEMO]).to.deep.equal(["outils-demo", "modele-demo", "agent-demo", "approbateur-demo", "registre-dev", "verificateur-demo"]);
      const serviceDe = (nom) => Object.entries(COMPOSE.services).find(([, s]) => s.image === `noortrace/${nom}:0.1.0`);
      for (const nom of IMAGES_DEMO) {
        for (const f of ["Dockerfile", "Dockerfile.dockerignore", "passwd", "group", `${nom}.mjs`]) expect(fs.existsSync(path.join(CONTENEURS, nom, f)), `${nom}/${f}`).to.equal(true);
        const texte = lire("conteneurs", nom, "Dockerfile");
        expect(controlerEpinglage(texte), nom).to.deep.equal([]);
        const instructions = texte.replace(/\\\n/g, " ").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
        const finale = instructions.slice(instructions.findLastIndex((l) => /^FROM\b/i.test(l)));
        for (const i of finale) expect(/^(RUN|SHELL|CMD|HEALTHCHECK|ONBUILD|VOLUME|ADD)\b/i.test(i), `${nom} : ${i}`).to.equal(false);
        expect(finale.filter((i) => /^ENTRYPOINT\b/i.test(i)), nom).to.deep.equal([`ENTRYPOINT ["/usr/local/bin/noortrace-${nom}"]`]);
        const [service, s] = serviceDe(nom);
        expect(finale.filter((i) => /^USER\b/i.test(i)), nom).to.deep.equal([`USER ${s.user}`]);
        expect(lire("conteneurs", nom, "passwd"), nom).to.include(`:x:${s.user.split(":")[0]}:`);
        expect(lire("conteneurs", nom, "Dockerfile.dockerignore").split("\n").find((l) => l && !l.startsWith("#")), nom).to.equal("*");
        if (s.healthcheck.test) expect(s.healthcheck.test[1], service).to.equal(`/usr/local/bin/noortrace-${nom}`);
        expect(lire("conteneurs", nom, `${nom}.mjs`).split("\n")[0], nom).to.equal("#!/usr/bin/env node");
      }
      const registre = lire("conteneurs", "registre-dev", "Dockerfile");
      expect(lignesFrom(registre)[0]).to.deep.equal({ image: "noortrace/noorcore:618fcef-noortrace@sha256:4e6cb6795d49d1f39a69bd2b9ce097ede675f36fa842ebb07ef88c8e3fd50d52", etape: "noeud" });
      const ignore = lire("conteneurs", "registre-dev", "Dockerfile.dockerignore");
      for (const f of ARTEFACTS) expect(ignore, f).to.include(`!${f}`);
      // Les répertoires partagés par un volume ont les mêmes droits dans chaque image qui les monte (CT-8 EX-3.5).
      expect(lire("conteneurs", "verificateur-demo", "Dockerfile")).to.include("install -d -o 10001 -g 10005 -m 2750 /out/var/lib/noortrace-exports");
      expect(lire("conteneurs", "enregistreur", "Dockerfile")).to.include("install -d -o 10001 -g 10005 -m 2750 /out/var/lib/noortrace-exports");
      expect(lire("conteneurs", "approbateur-demo", "Dockerfile")).to.include("install -d -o 0 -g 10010 -m 3770 /out/run/noortrace-console");
    });
  });

  describe("demo/construire-images.mjs : purge du cache de construction créé par chaque image, sur un docker simulé", function () {
    // Docker simulé : `buildx du --verbose` liste les enregistrements ; `buildx prune --filter id=…` suit BuildKit avec le
    // magasin containerd (constaté avec Docker 29.8.2) : sans --all, un enregistrement partagé avec une image du magasin
    // n'est pas purgé (« Total: 0B », code 0) ; avec --all, l'enregistrement filtré est purgé, et lui seul, une fois ses
    // enfants partis.
    const FAUX = `const fs = require("fs");
const etat = process.env.FAUX_DOCKER_ETAT;
const e = JSON.parse(fs.readFileSync(etat, "utf8"));
const a = process.argv.slice(2);
fs.appendFileSync(etat + ".appels", a.join(" ") + "\\n");
if (a[0] === "buildx" && a[1] === "du") {
  for (const r of e) process.stdout.write("ID:\\t\\t" + r.id + "\\nParents:\\n" + r.parents.map((p) => " - " + p + "\\n").join("") + "Shared:\\t\\t" + r.partage + "\\n\\n");
  process.exit(0);
}
if (a[0] === "buildx" && a[1] === "prune") {
  const id = a[a.indexOf("--filter") + 1].replace(/^id=/, "");
  const r = e.find((x) => x.id === id);
  const purgeable = r && (!r.partage || a.includes("--all")) && !e.some((x) => x.parents.includes(id));
  if (purgeable) e.splice(e.indexOf(r), 1);
  fs.writeFileSync(etat, JSON.stringify(e));
  process.stdout.write("Total:\\t" + (purgeable ? "98.04MB" : "0B") + "\\n");
  process.exit(0);
}
process.exit(1);
`;

    it("CT-8 EX-3.13 (outil de construction de la démonstration) : chaque enregistrement créé par la construction est purgé, partagé avec une image ou non, parents après enfants ; le nombre rendu est celui des enregistrements disparus ; les enregistrements antérieurs ne sont jamais visés", function () {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "noortrace-demo-cache-"));
      const chemin = process.env.PATH;
      try {
        fs.writeFileSync(path.join(dir, "docker"), `#!${process.execPath}\n${FAUX}`, { mode: 0o755 });
        const etat = path.join(dir, "etat.json");
        const avant = [{ id: "ancien1", parents: [], partage: true }, { id: "ancien2", parents: ["ancien1"], partage: false }];
        const crees = [
          { id: "neuf1", parents: ["ancien1"], partage: true },
          { id: "neuf2", parents: ["neuf1"], partage: true },
          { id: "neuf3", parents: ["neuf2"], partage: true },
          { id: "neuf4", parents: ["neuf1"], partage: false },
        ];
        fs.writeFileSync(etat, JSON.stringify([...avant, ...crees]));
        process.env.PATH = `${dir}${path.delimiter}${chemin}`;
        process.env.FAUX_DOCKER_ETAT = etat;
        expect([...identifiantsCache()].sort()).to.deep.equal(["ancien1", "ancien2", "neuf1", "neuf2", "neuf3", "neuf4"]);
        const n = purgerCacheCree(new Set(["ancien1", "ancien2"]));
        expect([...identifiantsCache()].sort()).to.deep.equal(["ancien1", "ancien2"]);
        expect(n).to.equal(4);
        const prunes = fs.readFileSync(`${etat}.appels`, "utf8").split("\n").filter((l) => l.startsWith("buildx prune"));
        expect(prunes.length).to.be.above(0);
        for (const l of prunes) expect(l, l).to.match(/^buildx prune --builder default --force --all --filter id=neuf[1-4]$/);
      } finally {
        process.env.PATH = chemin;
        delete process.env.FAUX_DOCKER_ETAT;
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});
