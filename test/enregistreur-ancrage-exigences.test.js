// Branchement du composant d'ancrage dans l'enregistreur (lot F2), essais en
// cours de processus (cœur à l'horloge réglable, décor du lot F1 : autorités
// RFC 3161 du lot E, calendriers factices, registre factice) : CT-5 EX-4.8
// (configuration d'ancrage invalide, l'enregistreur démarre et consigne
// `anchor_pending`), EX-4.12 (une remise rend la main sans réseau), EX-4.9
// (rechargement), CT-2 §15.2 et TA-41 de CT-9 (secrets : chaîne en clair
// refusée, référence absente, valeur jamais écrite ni consignée), EX-11.19
// (clé de chaîne de classe D ; classes A à C : démarrage refusé, reste nommé),
// TA-62 (relève d'une demande en cours), EX-5.15, EX-8.14 et TM-16 (copie WORM
// du répertoire `ancres/` et de la file, fichiers fermés seulement, SHA-256
// égaux, 0 fichier non conforme), TI-17 (TM-18 : série croissante à travers
// un redémarrage du serveur interne ; TM-19 : précision ≤ 1 s), `anchoring.ancrage`
// nul (aucun composant), rotation d'urgence (refus `registre_non_branche`
// inchangé : reste de l'étape).

import { expect } from "chai";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { Coeur, principal, preparerAncrage, ErreurBranchementAncrage, resoudreSecretsAncrage, instanceDepuisManifeste, cleChaineDepuisConfiguration, ServiceCopiesWorm, lireRegistres, validerConfiguration, resoudreSecrets } from "@noortrace/enregistreur";
import { DepotAncres, ErreurTransport, acquerir, lireJeton, lireReponse, verifierJeton } from "@noortrace/ancrage/rfc3161";
import { DepotOts } from "@noortrace/ancrage/ots";
import { initialiserAutorite, chargerAutorite, demarrerServeur } from "@noortrace/ancrage/serveur-interne";
import { lireFiles } from "@noortrace/ancrage/planificateur";
import { attenteCalme, serveurCrl } from "./fixtures/ancrage-composant/outils.mjs";
import { monterEnProcessus, echangeFactice, operationsWormMemoire, repertoireTemporaire, enAttente, aleatoireFixe, HorlogeHybride, portLibre } from "./fixtures/enregistreur-ancrage/outils.mjs";
import { configurationDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;
/** Chaîne marqueur de TA-41 (CT-9 §10.4) : valeur résolue d'une référence de secret, jamais écrite nulle part. */
const MARQUEUR_TA41 = "MARQUEUR-TA-41-7c1e9b2d4f60a8e3";

/** Rejoue des minutes de la période : à chaque instant aligné, un tic du cœur (point) et, aux minutes données, un échange. */
async function rejouer({ coeur, horloge, calme, de, a, evenementsAuxMinutes = {} }) {
  const seqs = [];
  for (let j = de; j <= a; j++) {
    await horloge.aller(T0 + j * 60000, calme);
    await coeur.tic();
    await calme();
    for (let k = 0; k < (evenementsAuxMinutes[j] ?? 0); k++) seqs.push((await echangeFactice(coeur, j)).seq);
    await calme();
  }
  return seqs;
}

describe("enregistreur + ancrage (lot F2) : branchement d'anchoring.ancrage, configuration refusée, secrets, clé de chaîne (CT-5 EX-4.8, EX-4.9 ; CT-2 §15.2, EX-11.19 ; TA-41)", function () {
  this.timeout(300000);
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-f2-exigences-");
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("anchoring.ancrage nul : aucun composant (preparerAncrage rend null), le cœur démarre et s'arrête comme avant, aucune ligne du composant `ancrage`, noortrace-ctl ancrage refusé (ancrage_non_configure)", async function () {
    const d = path.join(dir, "nul");
    const { config, env } = configurationDev(d);
    expect(config.anchoring.ancrage ?? null).to.equal(null);
    const v = validerConfiguration(N.utf8(JSON.stringify(config)));
    const s = resoudreSecrets(v.config, { env });
    const ancrage = await preparerAncrage({ config: v.config, secrets: s.secrets, env });
    expect(ancrage).to.equal(null);
    const coeur = await Coeur.demarrer({ config: v.config, secrets: s.secrets, ancrage, horloge: { murale: () => T0 + 5000, monotone: () => 1e6 } });
    try {
      expect(coeur.journal.lignes.filter((l) => l.component === "ancrage")).to.deep.equal([]);
      expect(await coeur.commandeAncrage({ commande: "etat" })).to.deep.equal({ accepte: false, raison: "ancrage_non_configure" });
      expect(await coeur.reexportsDus()).to.deep.equal([]);
    } finally {
      await coeur.arreter();
    }
    expect(coeur.journal.trouver("shutdown")).to.have.lengthOf(1);
  });

  it("EX-4.8 : document ancrage-v0 refusé par AN-1 (deux principaux, cadence différente de celle de l'enregistreur) : le démon démarre, produit points et manifestes, consigne config_invalid puis anchor_pending (configuration_invalide) à chaque remise ; /healthz ok ; rechargement refusé", async function () {
    const d = path.join(dir, "invalide");
    const x = await monterEnProcessus({
      dir: d, periodStart: PERIODE,
      document: (doc) => {
        doc.rfc3161.providers.push({ ...doc.rfc3161.providers[0], id: "second-principal" });
        doc.checkpoint_interval_s = 300;
      },
    });
    if (x.condition) return enAttente(this, x.condition);
    const ancrage = await x.preparer();
    expect(ancrage.erreurDocument).to.equal(null);
    expect(ancrage.erreursSecrets).to.deep.equal([]);
    x.horloge.m = T0 + 5000;
    const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage, horloge: x.horloge });
    try {
      const refus = coeur.journal.trouver("anchoring_not_started");
      expect(refus).to.have.lengthOf(1);
      expect(refus[0].data).to.include({ reason: "configuration_invalide" });
      expect(refus[0].data.rules.split(",")).to.include.members(["1", "2"]);
      expect(coeur.journal.trouver("config_invalid")[0].component).to.equal("ancrage");
      expect(ancrage.etat()).to.include({ attached: true, demarre: false, reason: "configuration_invalide" });
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
      // Points et clôture produits quand même (EX-4.8, 14.2) ; chaque remise est consignée anchor_pending.
      for (let j = 1; j <= 3; j++) {
        x.horloge.aller(T0 + j * 60000);
        await coeur.tic();
      }
      await echangeFactice(coeur, 1);
      x.horloge.aller((PERIODE + 3600) * 1000 + 300);
      await coeur.tic();
      expect(fs.existsSync(path.join(x.repertoire, "manifestes", `periode-${PERIODE}.json`))).to.equal(true);
      const attentes = coeur.journal.trouver("anchor_pending");
      expect(attentes.length).to.be.at.least(5);
      expect(attentes.every((l) => l.data.reason === "configuration_invalide")).to.equal(true);
      expect(coeur.journal.trouver("checkpoint_written").length).to.be.at.least(4);
      expect(await ancrage.recharger()).to.include({ accepte: false });
      expect(await coeur.commandeAncrage({ commande: "retirer-qualification", id: "qtsa-principal" })).to.deep.equal({ accepte: false, raison: "composant_non_demarre" });
      // L'export d'un dossier passe par la voie sans ancrage : parties réservées « hors périmètre CT-1 ».
      const dossier = await coeur.exporterDossier(2, path.join(d, "dossier"));
      expect(dossier.parts.find((p) => p.name === "jeton_rfc3161").reason_if_absent).to.equal("hors périmètre CT-1");
      expect(dossier.parts.find((p) => p.name === "points_de_controle").present).to.equal(true);
    } finally {
      await coeur.arreter();
      await x.fermer();
    }
  });

  it("document illisible (fichier absent ou JSON non strict) : anchoring_not_started document_illisible, le démon démarre ; manifeste d'instance absent avec le registre activé : instance_registre_absente", async function () {
    const d = path.join(dir, "illisible");
    const x = await monterEnProcessus({ dir: d, periodStart: PERIODE, config: (c) => { c.anchoring.ancrage = path.join(d, "absent.json"); } });
    if (x.condition) return enAttente(this, x.condition);
    const ancrage = await x.preparer();
    expect(ancrage.erreurDocument).to.equal("fichier illisible");
    const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage, horloge: x.horloge });
    try {
      expect(coeur.journal.trouver("anchoring_not_started")[0].data).to.include({ reason: "document_illisible" });
      expect(coeur.sante().corps).to.deep.equal({ status: "ok" });
    } finally {
      await coeur.arreter();
    }
    fs.writeFileSync(path.join(d, "absent.json"), '{"version":0,"version":0}');
    const ancrage2 = await x.preparer();
    expect(ancrage2.erreurDocument).to.match(/^JSON strict/);
    // Instance absente : le branchement le dit avant de démarrer ; sans registre, le composant démarre sans lui.
    fs.rmSync(path.join(path.dirname(x.cheminAncrage), "instance-registre.json"));
    fs.copyFileSync(x.cheminAncrage, path.join(d, "absent.json"));
    const ancrage3 = await x.preparer();
    expect(ancrage3.erreurInstance).to.match(/instance-registre\.json/);
    const coeur3 = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage: ancrage3, horloge: x.horloge });
    try {
      expect(coeur3.journal.trouver("anchoring_not_started")[0].data).to.include({ reason: "instance_registre_absente" });
    } finally {
      await coeur3.arreter();
      await x.fermer();
    }
  });

  it("TA-41 : une chaîne en clair à la place d'une référence de secret est refusée (schéma ancrage-v0, AN-1) ; une référence env absente refuse le démarrage de l'ancrage sans arrêter l'enregistreur (secret_non_resolu, pointeur consigné, jamais une valeur) ; resoudreSecretsAncrage ne touche qu'aux pointeurs d'ancrage-v0", async function () {
    const d = path.join(dir, "secrets");
    const x = await monterEnProcessus({ dir: d, periodStart: PERIODE, document: (doc) => { doc.rfc3161.providers[0].auth.secret = "mot-de-passe-en-clair"; } });
    if (x.condition) return enAttente(this, x.condition);
    const a = await x.preparer();
    expect(a.erreursSecrets).to.deep.equal([]);
    expect(a.secretsAncrage.has("/rfc3161/providers/0/auth/secret")).to.equal(false);
    const coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage: a, horloge: x.horloge });
    try {
      expect(coeur.journal.trouver("anchoring_not_started")[0].data.reason).to.equal("configuration_invalide");
      expect(coeur.journal.trouver("config_invalid")[0].data.rules).to.include("schema");
      expect(JSON.stringify(coeur.journal.lignes)).to.not.include("mot-de-passe-en-clair");
    } finally {
      await coeur.arreter();
    }
    // Référence env absente.
    const doc = JSON.parse(fs.readFileSync(x.cheminAncrage, "utf8"));
    doc.rfc3161.providers[0].auth.secret = { env: "NOORTRACE_TEST_SECRET_ABSENT_F2" };
    fs.writeFileSync(x.cheminAncrage, JSON.stringify(doc));
    const b = await x.preparer();
    expect(b.erreursSecrets).to.deep.equal([{ pointeur: "/rfc3161/providers/0/auth/secret", regle: "variable d'environnement NOORTRACE_TEST_SECRET_ABSENT_F2 absente" }]);
    const coeur2 = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage: b, horloge: x.horloge });
    try {
      const l = coeur2.journal.trouver("anchoring_not_started")[0];
      expect(l.data).to.include({ reason: "secret_non_resolu", pointers: "/rfc3161/providers/0/auth/secret", count: 1 });
      expect(coeur2.sante().corps).to.deep.equal({ status: "ok" });
      x.horloge.aller(T0 + 60000);
      await coeur2.tic();
      expect(coeur2.journal.trouver("anchor_pending").at(-1).data.reason).to.equal("secret_non_resolu");
    } finally {
      await coeur2.arreter();
    }
    // Résolution : pointeurs relatifs au document, formes env (utf8, hex) et file (0600) ; un fichier lisible par d'autres est refusé.
    const fichier = path.join(d, "secret-lisible");
    fs.writeFileSync(fichier, "abc", { mode: 0o644 });
    const r = await resoudreSecretsAncrage({
      rfc3161: { providers: [{ auth: { method: "basic", secret: { env: "F2_A", encoding: "hex" } } }, { auth: { method: "aucune", secret: null } }, { auth: { method: "certificat_client", secret: { file: fichier } } }] },
      opentimestamps: { headers_source: { type: "bitcoin_rpc", auth: { env: "F2_B" } } },
    }, { env: { F2_A: "0x0102", F2_B: "u:p" } });
    expect([...r.secrets.keys()]).to.deep.equal(["/rfc3161/providers/0/auth/secret", "/opentimestamps/headers_source/auth"]);
    expect(Array.from(r.secrets.get("/rfc3161/providers/0/auth/secret"))).to.deep.equal([1, 2]);
    expect(r.erreurs).to.have.lengthOf(1);
    expect(r.erreurs[0].pointeur).to.equal("/rfc3161/providers/2/auth/secret");
    expect(r.erreurs[0].regle).to.match(/lisible par d'autres/);
    await x.fermer();
  });

  it("EX-11.19 : clé de chaîne de classe D construite depuis le secret résolu (adresse confrontée) ; classes A, B ou C : démarrage du démon refusé avec un message qui nomme le reste (étape 7) ; adresse différente ou secret illisible : refus nommé", async function () {
    const d = path.join(dir, "cle-chaine");
    const x = await monterEnProcessus({ dir: d, periodStart: PERIODE });
    if (x.condition) return enAttente(this, x.condition);
    const cle = cleChaineDepuisConfiguration(x.config, x.secrets);
    expect(cle.adresse()).to.equal(x.config.anchoring.registry.chain_key.address);
    for (const classe of ["A", "B", "C"]) {
      const c = structuredClone(x.config);
      c.anchoring.registry.chain_key.class = classe;
      expect(() => cleChaineDepuisConfiguration(c, x.secrets)).to.throw(ErreurBranchementAncrage, /étape 7/).with.property("raison", "classe_cle_chaine");
    }
    const autre = structuredClone(x.config);
    autre.anchoring.registry.chain_key.address = "0x" + "11".repeat(20);
    expect(() => cleChaineDepuisConfiguration(autre, x.secrets)).to.throw(ErreurBranchementAncrage, /adresse/).with.property("raison", "cle_chaine");
    expect(() => cleChaineDepuisConfiguration(x.config, new Map([["/anchoring/registry/chain_key/secret", N.utf8("pas une clé")]]))).to.throw(ErreurBranchementAncrage, /illisible/);
    // Le démon lui-même : `principal` rend 2 avec demarrage_refuse : ancrage : classe_cle_chaine.
    const config = JSON.parse(fs.readFileSync(x.cheminConfig, "utf8"));
    config.anchoring.registry.chain_key.class = "C";
    config.anchoring.registry.chain_key.service_url = "https://coffre.exploitant.example/transit";
    const chemin = path.join(d, "configuration-classe-c.json");
    fs.writeFileSync(chemin, JSON.stringify(config));
    let err = "";
    const code = await principal(["--config", chemin], { env: x.env, stdout: { write() {} }, stderr: { write: (s) => (err += s) } });
    expect(code).to.equal(2);
    expect(err).to.match(/^demarrage_refuse : ancrage : classe_cle_chaine : clé de chaîne de classe C .*étape 7/m);
    // Manifeste d'instance : forme réduite et forme complète acceptées ; contrat manquant refusé.
    expect(instanceDepuisManifeste({ bft_chain_id: "noortrace-2124-dev", evm_chain_id: 2124, contracts: { attestation_registry: "0x" + "aa".repeat(20), period_registry: "0x" + "bb".repeat(20), recorder_registry: "0x" + "cc".repeat(20) }, validator_sets: [{}], fees: {} }).instance).to.include({ evmChainId: 2124, bftChainId: "noortrace-2124-dev" });
    expect(instanceDepuisManifeste({ bft_chain_id: "noortrace-2124-dev", evm_chain_id: 2124, contracts: [{ name: "AttestationRegistry", address: "0x" + "aa".repeat(20) }], validator_sets: [{}] }).erreur).to.match(/period_registry/);
    expect(instanceDepuisManifeste(null).erreur).to.match(/objet attendu/);
    await x.fermer();
  });
});

describe("enregistreur + ancrage (lot F2) : période rejouée à l'horloge réglable (EX-4.12, AN-43, TA-62, EX-4.9), copie WORM d'ancres/ et de la file (EX-5.15, EX-8.14, TM-16), rotation d'urgence", function () {
  this.timeout(600000);
  let dir;
  let x;
  let ancrage;
  let coeur;
  let calme;
  let worm;
  let seqs = [];

  before(async function () {
    dir = repertoireTemporaire("noortrace-f2-parcours-process-");
    x = await monterEnProcessus({ dir, periodStart: PERIODE, ErreurTransport, surchargesAncrage: { rfc3161: { crl_capture: { delay_s: 60 } }, registry: { checkpoints: "tous" } } });
    if (x.condition) return;
    // TA-41 : la valeur résolue du secret du principal (référence `file`) porte une chaîne marqueur injectée par l'essai,
    // hors des blocs PEM (le lecteur TLS l'admet : la requête authentifiée part quand même) ; elle ne doit figurer nulle part.
    const secretPath = path.join(dir, "secrets", "client-tls.pem");
    fs.writeFileSync(secretPath, `${MARQUEUR_TA41}\n${fs.readFileSync(secretPath, "utf8")}`, { mode: 0o600 });
    worm = new ServiceCopiesWorm({ worm: { type: "s3-object-lock", bucket: "essai", prefix: "journal-f2/", mode: "compliance", retain_days: 4018, legal_hold_on_write: false, copy_pieces: false, lock_audit_interval_days: 30, endpoint: "https://worm.example", region: null }, operations: operationsWormMemoire() });
    ancrage = await x.preparer();
    x.horloge.m = T0 + 5000;
    coeur = await Coeur.demarrer({ config: x.config, secrets: x.secrets, ancrage, worm, horloge: x.horloge });
    calme = attenteCalme(ancrage.composant, { tolerance: () => x.m.transport.etat.pendantesEnVol });
  });

  after(async function () {
    if (coeur) await coeur.arreter().catch(() => {});
    await x?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (!x || x.condition) {
      enAttente(this, x?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  it("le composant est attaché après l'écrivain (anchoring_attached, contexte depuis le stockage) ; EX-4.12 : avec un prestataire qui ne répond jamais, le tic qui produit et remet un point rend la main sans attendre le réseau", async function () {
    if (!pret.call(this)) return;
    expect(coeur.journal.trouver("anchoring_attached")).to.have.lengthOf(1);
    expect(ancrage.etat()).to.include({ attached: true, demarre: true, registry: true });
    x.m.transport.pendantes.add(x.m.interne.prestataire.url);
    seqs = await rejouer({ coeur, horloge: x.horloge, calme, de: 1, a: 1, evenementsAuxMinutes: { 1: 1 } });
    x.horloge.aller(T0 + 2 * 60000);
    const debut = Date.now();
    await coeur.tic();
    expect(Date.now() - debut).to.be.below(3000);
    await calme();
    expect(coeur.journal.trouver("checkpoint_written").length).to.be.at.least(2);
    x.m.transport.pendantes.clear();
  });

  it("TA-62 (complément) : relève d'une demande en cours : le principal ne répond pas à la clôture, retirerQualification relève la demande envoyee vers le secours (anchor_fallback consigné, reason qualification_retiree), le jeton du secours est promu ; la file garde la tentative pendante comme envoyée", async function () {
    if (!pret.call(this)) return;
    await rejouer({ coeur, horloge: x.horloge, calme, de: 3, a: 8, evenementsAuxMinutes: { 4: 1, 7: 1 } });
    // Points toutes les minutes jusqu'à la fin de l'heure, sans nouvel événement ; échéances toutes les 5 minutes.
    for (let j = 9; j < 60; j += 1) {
      x.horloge.aller(T0 + j * 60000);
      await coeur.tic();
    }
    await calme();
    expect(coeur.journal.trouver("checkpoint_countersigned").length).to.be.at.least(2);
    x.m.transport.pendantes.add(x.m.principal.prestataire.url);
    x.horloge.aller((PERIODE + 3600) * 1000 + 300);
    await coeur.tic();
    await calme();
    await x.horloge.avancer(10000, calme);
    const avant = ancrage.composant.demandes().find((d) => d.kind === "jeton_periode");
    expect(avant.state).to.equal("envoyee");
    expect(avant.attempts.map((a) => a.provider)).to.deep.equal(["qtsa-principal"]);
    const actions = await ancrage.retirerQualification("qtsa-principal");
    expect(actions.some((a) => a.action === "releve" && a.detail.provider === "qtsa-secours")).to.equal(true);
    await calme();
    await x.horloge.avancer(2000, calme);
    const apres = ancrage.composant.demandes().find((d) => d.kind === "jeton_periode");
    expect(apres.state).to.equal("obtenue");
    expect(apres.result.provider).to.equal("qtsa-secours");
    // TA-62 (oracle du catalogue) : la relève de la demande en cours est consignée `anchor_fallback` (CT-5 EX-8.15), vers le secours, raison nommée.
    const releve = coeur.journal.trouver("anchor_fallback").find((l) => l.data.reason === "qualification_retiree");
    expect(releve, "relève consignée anchor_fallback").to.not.equal(undefined);
    expect(releve.component).to.equal("ancrage");
    expect(releve.data).to.include({ to: "qtsa-secours" });
    expect(releve.data.request_id).to.equal(avant.id);
    expect(coeur.journal.trouver("provider_qualification_withdrawn")[0].data).to.include({ provider: "qtsa-principal" });
    expect(coeur.journal.trouver("period_timestamped")).to.have.lengthOf(1);
    expect(coeur.journal.trouver("period_close_delegated").at(-1).data.reason).to.equal("signatures_en_attente");
    x.m.transport.pendantes.clear();
  });

  it("AN-43 et TA-41 : des requêtes RFC 3161 authentifiées sont parties vers le principal avec un secret dont la valeur résolue porte la chaîne marqueur ; ni le marqueur, ni le secret TLS, ni la clé de chaîne ne figurent dans la file durable, les traces du planificateur, acquisitions.ndjson, le journal d'exploitation ni les métriques ; seule la référence (file) y figure ; métriques d'EX-8.15 exposées avec celles du cœur", async function () {
    if (!pret.call(this)) return;
    const secretPath = path.join(dir, "secrets", "client-tls.pem");
    expect(fs.readFileSync(secretPath, "utf8")).to.include(MARQUEUR_TA41, "contrôle positif : le marqueur est bien dans la valeur résolue");
    expect(coeur.journal.trouver("period_timestamped").length + coeur.journal.trouver("checkpoint_countersigned").length).to.be.at.least(1, "des requêtes authentifiées sont parties");
    const secret = Buffer.from(x.m.tls.client).toString("utf8").split("\n")[1];
    const cle = N.octetsVersHex(N.sha256(N.utf8("noortrace/ancrage/test/composant/cle-chaine-01"))).slice(2);
    const file = lireFiles(x.document.queue.path);
    const traces = JSON.stringify(coeur.journal.lignes.filter((l) => l.component === "ancrage" && l.event.startsWith("planificateur_")));
    expect(traces.length).to.be.greaterThan(2, "des traces du planificateur ont été consignées");
    const textes = [JSON.stringify(coeur.journal.lignes), traces, fs.readFileSync(path.join(x.document.queue.path, file.fichiers[0]), "utf8"), fs.readFileSync(path.join(x.repertoire, "ancres", `periode-${PERIODE}`, "acquisitions.ndjson"), "utf8"), ancrage.metriques()];
    for (const t of textes) {
      expect(t.includes(MARQUEUR_TA41)).to.equal(false);
      expect(t.includes(secret)).to.equal(false);
      expect(t.toLowerCase().includes(cle.toLowerCase())).to.equal(false);
      expect(t.toLowerCase()).to.not.include("private key");
    }
    // La référence du secret (emplacement, pas sa valeur) est ce que porte la configuration d'ancrage en vigueur.
    expect(ancrage.configuration.rfc3161.providers.find((p) => p.id === "qtsa-principal").auth.secret).to.deep.equal({ file: secretPath });
    const m = ancrage.metriques();
    expect(m).to.include("# TYPE noortrace_anchoring_attempts_total counter");
    expect(m).to.include('noortrace_anchoring_attempts_total{kind="jeton_periode",provider="qtsa-secours",outcome="obtenue"} 1');
  });

  it("EX-5.15, EX-8.14, TM-16 : la copie WORM couvre le répertoire ancres/ (rfc3161/, ots/, entetes-bitcoin.json, acquisitions.ndjson une fois la période close et la T-10 différée décidée) et la file sous queue.path quand son époque est fermée ; SHA-256 égaux ; 0 fichier non conforme", async function () {
    if (!pret.call(this)) return;
    const rel = (f) => path.posix.join("ancres", path.relative(path.join(x.repertoire, "ancres"), f).split(path.sep).join("/"));
    const fichiers = () => fs.readdirSync(path.join(x.repertoire, "ancres"), { recursive: true }).map((f) => path.join(x.repertoire, "ancres", String(f))).filter((f) => fs.statSync(f).isFile()).map(rel);
    // Avant la T-10 différée : acquisitions.ndjson n'est pas fermé ; la file de l'époque courante non plus.
    const avant = (await worm.fichiersACopier()).map((f) => f.cle.replace("journal-f2/", ""));
    expect(avant.some((f) => f.endsWith("/acquisitions.ndjson"))).to.equal(false);
    expect(avant.some((f) => /ancres\/file\/file-/.test(f))).to.equal(false);
    expect(avant.filter((f) => /ancres\/periode-[0-9]{10}\/rfc3161\//.test(f)).length).to.be.at.least(2);
    expect(avant.filter((f) => /ancres\/periode-[0-9]{10}\/ots\//.test(f)).length).to.be.at.least(2);
    // T-10 différée (delay_s 60), puis mise à niveau OpenTimestamps et en-têtes.
    await x.horloge.avancer(120000, calme);
    expect(ancrage.composant.etat().t10_en_attente).to.equal(0);
    x.m.calendriers.completer(1010);
    await x.horloge.avancer(11 * 60000, calme);
    expect(coeur.journal.trouver("bitcoin_headers_written")).to.have.lengthOf(1);
    const apres = (await worm.fichiersACopier()).map((f) => f.cle.replace("journal-f2/", ""));
    const attendus = fichiers().filter((f) => !/^ancres\/file\//.test(f));
    expect(apres.filter((f) => f.startsWith("ancres/")).sort()).to.deep.equal(attendus.sort());
    expect(apres).to.include(`ancres/periode-${PERIODE}/acquisitions.ndjson`);
    expect(apres).to.include(`ancres/periode-${PERIODE}/entetes-bitcoin.json`);
    // Une file d'époque fermée (inférieure à celle de l'écrivain) est copiée avec le répertoire d'ancres.
    fs.writeFileSync(path.join(x.document.queue.path, "file-0.ndjson"), "");
    expect((await worm.fichiersACopier()).map((f) => f.cle)).to.include("journal-f2/ancres/file/file-0.ndjson");
    fs.rmSync(path.join(x.document.queue.path, "file-0.ndjson"));
    // Balayage : chaque fichier a une version au même SHA-256, en mode COMPLIANCE à l'échéance attendue (TM-16 : 0 non conforme).
    const r = await worm.balayer();
    expect(r.manquantes).to.equal(0);
    const registre = await lireRegistres(path.join(x.repertoire, "worm"));
    const parCle = new Map(registre.map((l) => [l.ligne.key, l.ligne]));
    let nonConformes = 0;
    for (const f of attendus) {
      const ligne = parCle.get(`journal-f2/${f}`);
      const local = N.sha256Hex(new Uint8Array(fs.readFileSync(path.join(x.repertoire, f))));
      const objet = worm.operations.objets.get(`journal-f2/${f}`);
      if (!ligne || !objet || objet.sha256 !== local || ligne.lock.verdict !== "conforme") nonConformes += 1;
    }
    expect(nonConformes, JSON.stringify([...parCle.keys()])).to.equal(0);
    expect(attendus.length).to.be.at.least(8);
    // Les autres fichiers du journal sont copiés aussi (manifeste, signature, série) : la part d'ancres s'ajoute sans rien retirer.
    for (const f of [`manifestes/periode-${PERIODE}.json`, `manifestes/periode-${PERIODE}.sig`, `points/periode-${PERIODE}.ndjson`]) expect(parCle.has(`journal-f2/${f}`), f).to.equal(true);
  });

  it("contexte du composant, lireHashesPeriode (CT-1 §10.5 règle 2) : hashes de la période égaux à ceux du manifeste ; un segment inchangé hors de la période n'est plus relu (épreuves de l'étape 5 : chaque admission relisait tout l'historique du journal)", async function () {
    if (!pret.call(this)) return;
    const ancrage = coeur.o.ancrage;
    const manifeste = (await ancrage.listerPeriodes()).find((m) => m.manifeste.period_start === PERIODE);
    expect(manifeste, "période close").to.not.equal(undefined);
    const segments = fs.readdirSync(path.join(x.repertoire, "segments")).filter((n) => n.endsWith(".ndjson"));
    expect(segments.length, "au moins deux segments : la clôture ferme le segment de la période").to.be.at.least(2);
    const premier = await ancrage.lireHashesPeriode(PERIODE);
    expect(premier.length).to.equal(manifeste.manifeste.count);
    expect(N.racineMerkle(premier)).to.equal(manifeste.manifeste.root);
    const avant = ancrage.segmentsRelus;
    const second = await ancrage.lireHashesPeriode(PERIODE);
    expect(second).to.deep.equal(premier);
    // Seuls les segments qui peuvent porter des événements de la période sont relus ; avant, tous l'étaient à chaque appel.
    const relus = ancrage.segmentsRelus - avant;
    const horsPeriode = [...ancrage.segmentsLus.values()].filter((v) => v.tsMax === null || v.tsMax < PERIODE * 1000 || v.tsMin >= (PERIODE + 3600) * 1000).length;
    expect(horsPeriode, "segments hors de la période").to.be.at.least(1);
    expect(relus).to.equal(segments.length - horsPeriode);
    expect(relus).to.be.lessThan(segments.length);
  });

  it("export d'un dossier par le cœur avec l'ancrage branché : treize parties, point couvrant avec jeton, ancre et preuve, réexport dû puis fait ; rotation d'urgence : refus registre_non_branche inchangé (reste de l'étape)", async function () {
    if (!pret.call(this)) return;
    const dossier = await coeur.exporterDossier(seqs[0], path.join(dir, "dossier-1"));
    const parts = Object.fromEntries(dossier.parts.map((p) => [p.name, p]));
    expect(parts.points_de_controle.present).to.equal(true);
    expect(parts.jeton_rfc3161.present).to.equal(true);
    expect(parts.preuve_ots.present).to.equal(true);
    expect(parts.registre.present).to.equal(false);
    expect(parts.registre.reason_if_absent).to.match(/capture_incomplete : clôture/);
    const partie = JSON.parse(fs.readFileSync(path.join(dir, "dossier-1", "points-de-controle.json"), "utf8"));
    expect(partie.anchors.rfc3161).to.not.equal(null);
    expect(partie.anchors.registry).to.not.equal(null);
    expect(coeur.journal.trouver("dossier_exported")).to.have.lengthOf(1);
    expect(await coeur.reexportsDus()).to.deep.equal([]);
    // Épreuves de l'étape 5 : un seul résumé gardé par événement, le plus récent, quel que soit le nombre d'exports (la liste grandissait
    // d'une entrée par export) ; ses chaînes sont des copies autonomes, sans retenue du texte d'acquisitions.ndjson.
    const ancrage = coeur.o.ancrage;
    await coeur.exporterDossier(seqs[0], path.join(dir, "dossier-1-bis"));
    await coeur.exporterDossier(seqs[0], path.join(dir, "dossier-1-ter"));
    expect(coeur.journal.trouver("dossier_exported")).to.have.lengthOf(3);
    expect(ancrage.dossiersProduits).to.have.lengthOf(1);
    expect(ancrage.dossiersProduits[0].destination).to.equal(path.join(dir, "dossier-1-ter"));
    if (seqs[1] !== undefined) {
      await coeur.exporterDossier(seqs[1], path.join(dir, "dossier-2"));
      expect(ancrage.dossiersProduits.map((d) => d.seq)).to.deep.equal([seqs[0], seqs[1]]);
    }
    expect(await coeur.reexportsDus()).to.deep.equal([]);
    const r = await coeur.rotationUrgence();
    expect(r).to.deep.equal({ accepte: false, raison: "registre_non_branche" });
  });

  it("arrêt propre : le composant s'arrête après l'écrivain (anchoring_stopped avant shutdown)", async function () {
    if (!pret.call(this)) return;
    await coeur.arreter();
    const evenements = coeur.journal.lignes.map((l) => l.event);
    expect(evenements.indexOf("anchoring_stopped")).to.be.greaterThan(-1);
    expect(evenements.indexOf("anchoring_stopped")).to.be.lessThan(evenements.lastIndexOf("shutdown"));
    coeur = null;
  });
});

describe("enregistreur + ancrage (lot F2), TI-17 : serveur RFC 3161 interne du lot E éprouvé par le client du composant à travers un redémarrage (AN-26, TM-18 : 0 paire non croissante ; AN-24, TM-19 : précision ≤ 1 s ; AN-22, AN-25, AN-29, AN-30)", function () {
  this.timeout(120000);
  let dir;
  before(function () {
    dir = repertoireTemporaire("noortrace-f2-ti17-");
  });
  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("quatre jetons avant, quatre après un redémarrage du serveur (compteur de série durable) : numéros strictement croissants, accuracy ≤ 1 s, nonce recopié, politique privée, certificat de l'unité inclus (EKU critique et unique, ESSCertIDv2 SHA-256 : T-8, T-4), T-1 à T-9 réussies ; badAlg sur un condensé SHA-1 et unacceptedPolicy sur une politique étrangère rendus et lus par le client ; journal des jetons hors du serveur (AN-28)", async function () {
    const horloge = new HorlogeHybride(T0);
    const aleatoire = aleatoireFixe(31);
    const crl = await serveurCrl(horloge);
    const repertoire = path.join(dir, "tsa");
    crl.declarer("tsa", repertoire);
    const init = initialiserAutorite({ repertoire, algorithme: "p-256", politique: "1.3.6.1.4.1.99999.2.9", crlUrl: crl.url("tsa"), validiteJours: 365, horloge: { murale: () => T0 - 86400000 }, aleatoire, sujetUnite: { O: "NOORTRACE essai", CN: "TSA interne non qualifiee" } });
    const port = await portLibre();
    const journal = { consigner() {} };
    let autorite = chargerAutorite({ repertoire });
    let serveur = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port }, horloge, journal });
    const prestataire = { id: "tsa-interne", role: "interne", url: serveur.adresse.url, auth: { method: "aucune", secret: null }, hash: "sha256", policy_oid: "1.3.6.1.4.1.99999.2.9", accepted_policies: ["1.3.6.1.4.1.99999.2.9"], anchor_certificates: [init.acPem], qualified: null, min_interval_ms: 0, request_timeout_ms: 5000, correlation_header: "X-Request-ID", source: "autorité d'essai (lot E)" };
    const depot = DepotAncres.ouvrir({ racine: path.join(dir, "stockage"), orgId: "0x" + "11".repeat(32), journalId: "0x" + "22".repeat(32) });
    const { transportHttps } = await import("@noortrace/ancrage/rfc3161");
    // Sans connexion persistante : après le redémarrage du serveur, une connexion gardée ouverte par l'agent par défaut
    // donnerait une première tentative `erreur_transport` (que le composant absorberait par sa reprise, EX-5.11) ;
    // l'essai mesure la série du serveur, pas la reprise du client.
    const transport = transportHttps({ agentHttp: new http.Agent({ keepAlive: false }) });
    const series = [];
    const acquisitions = [];
    const acquerirUn = async (k) => {
      const imprint = N.sha256Hex(N.utf8(`noortrace/enregistreur/test/ti17/${k}`));
      const r = await acquerir({ prestataire, imprint, objet: "point", attempt: 1, attemptId: `jeton_point:${imprint.slice(2, 18)}:${k}`, periodStart: PERIODE, horloge, aleatoire, depot, transport, fraicheur: { max_response_delay_s: 60, clock_tolerance_s: 120 }, retry: { initial_ms: 1000, factor: 2, max_ms: 10000, jitter_ms: 0 } });
      expect(r.outcome, JSON.stringify(r.data)).to.equal("obtenue");
      const jeton = lireJeton(r.jeton);
      series.push(BigInt(jeton.tstInfo.serialNumber));
      acquisitions.push({ r, jeton, imprint });
    };
    for (let k = 1; k <= 4; k++) await acquerirUn(k);
    // Redémarrage : le serveur est fermé, le compteur relu depuis le disque, le serveur relancé sur le même port.
    await serveur.fermer();
    autorite.compteur.fermer?.();
    autorite = chargerAutorite({ repertoire });
    serveur = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port }, horloge, journal });
    for (let k = 5; k <= 8; k++) await acquerirUn(k);
    // AN-23 : un condensé SHA-1 (requête produite par openssl ts -query, boîte noire) reçoit PKIStatus 2 avec badAlg, lu par le client.
    const requeteSha1 = path.join(dir, "sha1.tsq");
    const q = spawnSync("openssl", ["ts", "-query", "-digest", createHash("sha1").update("noortrace/enregistreur/test/ti17/sha1").digest("hex"), "-sha1", "-cert", "-out", requeteSha1], { encoding: "utf8" });
    expect(q.status, q.stderr).to.equal(0);
    const refus = await transport.envoyer({ url: prestataire.url, octets: new Uint8Array(fs.readFileSync(requeteSha1)), entetes: { "Content-Type": "application/timestamp-query" }, delaiMs: 5000, role: "interne" });
    expect(refus.status).to.equal(200);
    const luRefus = lireReponse(refus.corps);
    expect(luRefus.status).to.equal(2);
    expect(luRefus.failureInfo).to.equal("badAlg");
    expect(luRefus.token).to.equal(null);
    // AN-29 : une politique étrangère à l'arc privé reçoit unacceptedPolicy ; le client la classe permanente (EX-5.12).
    const autre = await acquerir({ prestataire: { ...prestataire, policy_oid: "1.3.6.1.4.1.99999.9.9", accepted_policies: ["1.3.6.1.4.1.99999.9.9"] }, imprint: N.sha256Hex(N.utf8("noortrace/enregistreur/test/ti17/politique")), objet: "point", attempt: 1, attemptId: `jeton_point:${"ab".repeat(8)}:9`, periodStart: PERIODE, horloge, aleatoire, depot, transport, fraicheur: { max_response_delay_s: 60, clock_tolerance_s: 120 }, retry: { initial_ms: 1000, factor: 2, max_ms: 10000, jitter_ms: 0 } });
    expect(autre.outcome).to.equal("echec_permanente");
    expect(autre.data.pki_status).to.equal(2);
    expect(autre.data.failure_info).to.equal("unacceptedPolicy");
    expect(autre.jeton).to.equal(null);
    await serveur.fermer();
    autorite.compteur.fermer?.();
    await crl.fermer();
    let nonCroissantes = 0;
    for (let k = 1; k < series.length; k++) if (!(series[k] > series[k - 1])) nonCroissantes += 1;
    expect(series).to.have.lengthOf(8);
    expect(nonCroissantes).to.equal(0);
    for (const { r, jeton, imprint } of acquisitions) {
      expect(jeton.tstInfo.accuracy).to.not.equal(null);
      expect(Number(jeton.tstInfo.accuracy.seconds ?? 0n)).to.be.at.most(1);
      expect(r.data.accuracy_s).to.be.at.most(1);
      expect(jeton.tstInfo.policy).to.equal("1.3.6.1.4.1.99999.2.9");
      expect(jeton.certificatsPresents).to.equal(true);
      expect(`0x${jeton.tstInfo.nonce.toString(16).padStart(16, "0")}`).to.equal(r.enregistrement.nonce);
      const v = verifierJeton({ octets: r.jeton, imprintAttendue: imprint, ancres: { certificatsPem: [init.acPem], politiquesAdmises: ["1.3.6.1.4.1.99999.2.9"] }, aGenTime: true });
      for (const t of ["T-1", "T-2", "T-3", "T-4", "T-5", "T-6", "T-7", "T-8", "T-9"]) expect(v.checks[t], t).to.equal("reussi");
      // AN-22 : extKeyUsage critique, réduit à la seule valeur id-kp-timeStamping (T-8) ; AN-30 : attribut signé
      // signingCertificateV2 (jamais signingCertificate v1 à SHA-1) dont l'ESSCertIDv2 porte le SHA-256 du certificat de l'unité (T-4).
      const S = v.certificatSignataire;
      expect(S.usagesEtendus.critique).to.equal(true);
      expect(S.usagesEtendus.oids).to.deep.equal(["1.3.6.1.5.5.7.3.8"]);
      const attributs = v.jeton.signerInfo.signedAttrs.attributs;
      const v2 = attributs.find((a) => a.oid === "1.2.840.113549.1.9.16.2.47");
      expect(v2, "signingCertificateV2").to.not.equal(undefined);
      expect(attributs.some((a) => a.oid === "1.2.840.113549.1.9.16.2.12")).to.equal(false, "pas de signingCertificate v1 (SHA-1)");
      const brut = v2.valeurs[0]?.octets ?? null;
      if (brut instanceof Uint8Array) expect(Buffer.from(brut).includes(Buffer.from(N.sha256(S.octets)))).to.equal(true, "certHash de l'ESSCertIDv2 = SHA-256 du certificat de l'unité");
    }
    // AN-28 : une ligne d'acquisition par jeton reçu, écrite par le client, hors du serveur.
    expect(depot.lireAcquisitions(PERIODE).enregistrements.filter((e) => e.outcome === "obtenue")).to.have.lengthOf(8);
  });
});
