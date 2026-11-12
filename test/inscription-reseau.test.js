// Inscription des clients, étape 6 : épreuve sur le réseau de développement
// (CT-4 §7.4 : quatre validateurs noorcore locaux, `bash chain/scripts/dev-net.sh
// start`, JSON-RPC sur 127.0.0.1:8645 à 8648, identifiant EVM 2124, BFT
// noortrace-2124-dev, sans manifeste : EX-7.2). En attente, condition nommée
// dans le titre, quand le réseau n'est pas debout.
//
// Un client fictif (jeu de trois approbateurs, seuil 2, clé de gouvernance,
// clé d'enregistreur de classe D) est inscrit par l'application (interface
// Next.js construite et lancée par l'essai) et l'agent ; les pas 7 à 9, ceux
// de l'enregistreur, sont joués par l'outil de référence lancé en boîte noire
// sur le dossier et les captures de l'agent. Puis l'épreuve d'EX-7.24 :
// l'outil relancé sur le même dossier et les mêmes captures rend `deja_fait`
// pour chaque étape et n'envoie rien ; `verifier` (outil, boîte noire) rend
// R-1 à R-10 `reussi` ; chaque certificat capturé passe
// scripts/verify/certificat-commit.mjs (boîte noire) ; le paquet passe
// `controlerPaquet` (EX-7.22).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import * as R from "@noortrace/ancrage/registre";
import * as E from "./fixtures/inscription/reseau-essai.mjs";
import * as O from "./fixtures/inscription/outils.mjs";
import * as I from "./fixtures/inscription/interface.mjs";
import { controlerPaquet } from "../paquets/inscription/src/commun/paquet.mjs";

const POINTS = ["http://127.0.0.1:8645", "http://127.0.0.1:8646", "http://127.0.0.1:8647", "http://127.0.0.1:8648"];
const JOURNAL = "journal-principal";
const JID = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

/**
 * L'outil de référence sur le réseau de développement : un point dont
 * l'indexeur a un bloc de retard sur la tête est refusé (`noeud_suiveur`,
 * OP-2, 10.3) ; ce retard est passager, la commande est relancée (au plus
 * vingt fois, à 500 ms d'intervalle). Un refus OP-2 n'envoie rien.
 */
async function referenceSurReseau(args) {
  let r;
  for (let i = 0; i < 20; i += 1) {
    r = await O.outilReference(args);
    if (r.sortie?.error?.code !== "noeud_suiveur") return r;
    await new Promise((ok) => setTimeout(ok, 500));
  }
  return r;
}

async function reseauDebout() {
  const rpc = new R.ClientRpc({ points: POINTS, delaiMs: 3000 });
  try {
    for (const p of POINTS) {
      const c = await rpc.appeler("eth_chainId", [], { point: p });
      if (c.erreur || c.resultat !== "0x84c") return `le validateur ${p} ne répond pas eth_chainId 0x84c (bash chain/scripts/dev-net.sh start)`;
    }
    const m = await rpc.appeler("noor_getCommitCertificate", ["latest"]);
    if (m.erreur && m.erreur.code === -32601) return "le binaire noorcore ne sert pas noor_getCommitCertificate (CT-4 §9.1)";
    if (!fs.existsSync(path.join(E.RACINE, "deployments", "noorcore.json"))) return "deployments/noorcore.json absent (CT-4 §7.4)";
    return null;
  } catch (e) {
    return `le réseau de développement n'est pas debout (${e.message}) : bash chain/scripts/dev-net.sh start`;
  }
}

/** Lance un script de vérification de référence en boîte noire ; rend `{ code, sortie }`. */
function verifierCertificat(fichier) {
  return new Promise((ok) => {
    const p = spawn(process.execPath, [path.join(E.RACINE, "scripts", "verify", "certificat-commit.mjs"), fichier, "--validateurs", path.join(E.RACINE, "chain", "runtime", "validators.json"), "--chaine", "noortrace-2124-dev"], { cwd: E.RACINE, stdio: ["ignore", "pipe", "pipe"] });
    let s = "";
    p.stdout.on("data", (d) => (s += d));
    p.stderr.on("data", (d) => (s += d));
    p.on("close", (code) => ok({ code, sortie: s }));
  });
}

describe("inscription : client fictif inscrit par l'application et l'agent sur le réseau de développement 2124 (EX-7.24, EX-7.15)", function () {
  this.timeout(1800000);
  let absent = null;
  let dir;
  let a;
  let web;
  let slug;
  let cleChaine;
  let graine;
  let demandeSignee;
  const ex = "exploitant operateur-1";
  /** Un travail par l'interface ; relancé, comme l'outil de référence, sur le refus passager `noeud_suiveur` (OP-2, rien n'est envoyé). */
  async function travailSurReseau(spec) {
    let t;
    for (let i = 0; i < 20; i += 1) {
      t = await web.travail(spec);
      if (t.sortie?.error?.code !== "noeud_suiveur") return t;
      await new Promise((ok) => setTimeout(ok, 500));
    }
    return t;
  }

  before(async function () {
    absent = await reseauDebout();
    if (absent) return;
    dir = O.repertoireTemporaire();
    a = await O.demarrerAgentEssai({ manifeste: null, rpc: POINTS[0], delai_s: 120 });
    // Les quatre validateurs, comme --rpc (EX-8.15) : configuration réécrite et agent relancé.
    await a.arreter();
    const config = JSON.parse(fs.readFileSync(a.cheminConfig, "utf8"));
    config.rpc = POINTS;
    fs.writeFileSync(a.cheminConfig, JSON.stringify(config));
    const relance = await O.lancerAgent(a.cheminConfig);
    expect(relance.pret, String(relance.stderr)).to.be.an("object");
    a.agent = relance.processus;
    const b = I.construire();
    expect(b.code, b.sortie).to.equal(0);
    web = await I.lancerInterface({ dir, prise: a.prise, donnees: a.donnees });
    await web.connecter();
    slug = `inscription-reseau-${Date.now()}`;
    const k = crypto.createHash("sha256").update(`noortrace/essai/inscription/reseau/${slug}`).digest();
    const f = path.join(dir, "chaine.cle");
    fs.writeFileSync(f, k.toString("hex"), { mode: 0o600 });
    cleChaine = { reference: `fichier:${f}`, adresse: new R.SignataireChaineFichier(new Uint8Array(k)).adresse() };
    graine = path.join(dir, "rec.graine");
    fs.writeFileSync(graine, Buffer.from(O.cleEd25519(slug).graine).toString("hex"), { mode: 0o600 });
  });

  after(async function () {
    await web?.arreter();
    await a?.arreter();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (a?.base) fs.rmSync(a.base, { recursive: true, force: true });
  });

  it("pas 1 à 6 par l'application et l'agent : dossier préparé, confirmation consignée, jeu, assignation, lecture, approvisionnement, inscription de la clé", async function () {
    if (absent) return enAttente(this, absent);
    const doc = O.documentCle({ keyId: "rec-reseau-01", journalId: JID, chainKey: cleChaine.adresse, publique: O.cleEd25519(slug).publique, classe: "D" });
    const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
    let t = await travailSurReseau({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
    expect(t.sortie?.result, JSON.stringify(t)).to.equal("reussi");
    const dossier = (await web.requete(`/api/clients/${slug}`)).json.dossier;
    expect(dossier.instance).to.include({ evm_chain_id: 2124, bft_chain_id: "noortrace-2124-dev", manifest_sha256: null });
    const c = await web.requete(`/api/clients/${slug}/confirmations`, { methode: "POST", corps: { operation: "approvisionnement", objet: { org_id: dossier.organisation.org_id, cle_chaine: cleChaine.adresse }, personne_client: "Responsable du client fictif", canal: "appel au numéro du contrat", instant: new Date().toISOString(), piece_sha256: "0x" + "5a".repeat(32) } });
    expect(c.statut, c.texte).to.equal(200);
    t = await travailSurReseau({ commande: "inscrire-client", slug, parametres: {} });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    t = await travailSurReseau({ commande: "condense-inscription", slug, parametres: { key_id: "rec-reseau-01" } });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    demandeSignee = O.signerDemande(JSON.parse(fs.readFileSync(t.sortie.outputs.demande, "utf8")), [1, 2]);
    t = await travailSurReseau({ commande: "inscrire-cle", slug, parametres: { demande: demandeSignee, cle_chaine: cleChaine.reference } });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    const d = JSON.parse(fs.readFileSync(a.client(slug).dossier, "utf8"));
    expect(d.steps.slice(0, 5).map((s) => s.state)).to.deep.equal(["capturee", "capturee", "faite", "capturee", "capturee"]);
  });

  it("pas 7 à 9 (enregistreur : outil de référence en boîte noire) : chaque étape est capturee ou faite, result rempli et conforme", async function () {
    if (absent) return enAttente(this, absent);
    const cl = a.client(slug);
    const periode = path.join(cl.dir, "periode-1");
    const etapes = [
      ["manifeste-essai", "--dossier", cl.dossier, "--key-id", "rec-reseau-01", "--graine", `graine:${graine}`, "--sortie", periode],
      ["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
      ["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", cl.captures, "--sortie", path.join(dir, "cloture.json")],
      ["signer", "--demande", path.join(dir, "cloture.json"), "--cle", "hardhat:1"],
      ["signer", "--demande", path.join(dir, "cloture.json"), "--cle", "hardhat:3"],
      ["clore", "--demande", path.join(dir, "cloture.json"), "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
    ];
    for (const e of etapes) {
      const r = await referenceSurReseau([...e, "--rpc", POINTS.join(",")]);
      expect(r.sortie?.result, `${e[0]} : ${r.err}`).to.equal("reussi");
    }
    const d = JSON.parse(fs.readFileSync(cl.dossier, "utf8"));
    expect(d.steps.every((s) => s.state === "capturee" || s.state === "faite"), JSON.stringify(d.steps.map((s) => s.state))).to.equal(true);
    expect(d.result).to.be.an("object");
    expect(d.result.approver_set).to.deep.include({ source: "registre", chain_id: 2124 });
  });

  it("pas 10 par l'application : export et contrôle 8 ; verifier de l'outil de référence (boîte noire) rend R-1 à R-10 reussi ; chaque certificat capturé passe certificat-commit.mjs", async function () {
    if (absent) return enAttente(this, absent);
    const cl = a.client(slug);
    let t = await travailSurReseau({ commande: "exporter", slug, parametres: { manifeste: "periode-1/manifeste.json" } });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    // Les parties exportées par l'application égalent celles de l'outil sur les mêmes captures (source de registre.json exceptée).
    const refEx = await referenceSurReseau(["exporter", "--manifeste", path.join(cl.dir, "periode-1", "manifeste.json"), "--dossier", cl.dossier, "--captures", cl.captures, "--sortie", path.join(dir, "parties-ref"), "--rpc", POINTS.join(",")]);
    expect(refEx.sortie?.result, refEx.err).to.equal("reussi");
    for (const n of ["registre.json", "certificat-commit.json", "validateurs.json"]) {
      const pa = JSON.parse(fs.readFileSync(path.join(cl.dir, "parties", "1", n), "utf8"));
      const pb = JSON.parse(fs.readFileSync(path.join(dir, "parties-ref", n), "utf8"));
      expect(n === "registre.json" ? { ...pa, source: null } : pa, n).to.deep.equal(n === "registre.json" ? { ...pb, source: null } : pb);
    }
    t = await travailSurReseau({ commande: "verifier", slug, parametres: { parties: "parties/1", manifeste: "periode-1/manifeste.json" } });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    expect(t.sortie.outputs.verifications.map((v) => `${v.id}:${v.status}`)).to.deep.equal(["R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"].map((x) => `${x}:reussi`));
    const ref = await O.outilReference(["verifier", "--parties", path.join(cl.dir, "parties", "1"), "--manifeste", path.join(cl.dir, "periode-1", "manifeste.json"), "--dossier", cl.dossier]);
    expect(ref.sortie?.result, ref.err).to.equal("reussi");
    expect(ref.sortie.outputs.verifications.map((v) => `${v.id}:${v.status}`)).to.deep.equal(t.sortie.outputs.verifications.map((v) => `${v.id}:${v.status}`));
    expect(ref.sortie.outputs.statement).to.deep.equal(t.sortie.outputs.statement);
    const certificats = fs.readdirSync(cl.captures).filter((n) => /^certificat-\d+\.json$/.test(n));
    expect(certificats).to.have.length(6);
    for (const c of certificats) {
      const v = await verifierCertificat(path.join(cl.captures, c));
      expect(v.code, `${c} : ${v.sortie}`).to.equal(0);
      expect(v.sortie).to.contain("VALIDE");
    }
  });

  it("épreuve d'EX-7.24 : l'outil de référence relancé sur le dossier et les captures de l'application rend deja_fait pour chaque étape et n'envoie rien", async function () {
    if (absent) return enAttente(this, absent);
    const cl = a.client(slug);
    const rpc = new R.ClientRpc({ points: POINTS });
    const nonce = async (adr) => (await rpc.appeler("eth_getTransactionCount", [adr, "latest"])).resultat;
    const avant = { exploitant: await nonce(O.compteHardhat(0).adresse), chaine: await nonce(cleChaine.adresse), envois: fs.readdirSync(cl.captures).filter((n) => n.startsWith("envoi-")).length };
    const fd = path.join(dir, "demande-inscription-signee.json");
    fs.writeFileSync(fd, JSON.stringify(demandeSignee));
    const periode = path.join(cl.dir, "periode-1");
    const relances = [
      ["inscrire-client", "--dossier", cl.dossier, "--exploitant", "hardhat:0", "--captures", cl.captures],
      ["inscrire-cle", "--demande", fd, "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
      ["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
      ["clore", "--demande", path.join(dir, "cloture.json"), "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
    ];
    for (const e of relances) {
      const r = await referenceSurReseau([...e, "--rpc", POINTS.join(",")]);
      expect(r.sortie?.result, `${e[0]} : ${JSON.stringify(r.sortie?.error)} ${r.err}`).to.equal("deja_fait");
      expect(r.sortie.exit_code).to.equal(0);
    }
    expect(await nonce(O.compteHardhat(0).adresse)).to.equal(avant.exploitant);
    expect(await nonce(cleChaine.adresse)).to.equal(avant.chaine);
    expect(fs.readdirSync(cl.captures).filter((n) => n.startsWith("envoi-")).length).to.equal(avant.envois);
  });

  it("TE-21 chaîné : le paquet de l'application et celui de l'outil de référence pour le client de 2124 rendent la même sortie paquet-client, les mêmes fichiers hors du manifeste, et passent EX-7.22 ; l'archive se remet par l'interface", async function () {
    if (absent) return enAttente(this, absent);
    const gabarit = { console_origin: "https://console.client-fictif.example", administrators: ["oidc https://idp.client-fictif.example administrateur-1"] };
    const t = await travailSurReseau({ commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'épreuve sur le réseau de développement", ...gabarit } });
    expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
    const paquet = t.sortie.outputs.directory;
    expect(controlerPaquet(paquet)).to.deep.equal({ valide: true, ecarts: [] });
    expect(fs.existsSync(path.join(paquet, "instance-registre.json"))).to.equal(false);
    // L'outil de référence, en boîte noire, sur le même dossier et les mêmes captures (hors ligne, sans manifeste : EX-7.2).
    const cl = a.client(slug);
    const sortieRef = path.join(dir, "paquet-outil");
    fs.mkdirSync(sortieRef);
    const ref = await O.outilReference(["paquet-client", "produire", "--dossier", cl.dossier, "--captures", cl.captures, "--sortie", sortieRef, "--console-origin", gabarit.console_origin, "--administrateur-annuaire", gabarit.administrators[0], "--prepare-par", "exploitant de l'épreuve sur le réseau de développement", "--cle-chaine", cleChaine.reference, "--exploitant", "hardhat:0"]);
    expect(ref.sortie?.result, ref.err).to.equal("reussi");
    expect(O.formeSortie(t.sortie)).to.deep.equal(O.formeSortie(ref.sortie));
    expect({ ...t.sortie.outputs, directory: null, manifest_sha256: null, secrets_checked: null }).to.deep.equal({ ...ref.sortie.outputs, directory: null, manifest_sha256: null, secrets_checked: null });
    const fichiers = (d) => fs.readdirSync(d, { recursive: true }).filter((n) => fs.statSync(path.join(d, n)).isFile()).sort();
    expect(fichiers(paquet)).to.deep.equal(fichiers(ref.sortie.outputs.directory));
    for (const n of fichiers(paquet).filter((x) => x !== "paquet-client.json")) expect(fs.readFileSync(path.join(paquet, n)).equals(fs.readFileSync(path.join(ref.sortie.outputs.directory, n))), n).to.equal(true);
    // Le contrôle de l'outil sur le paquet de l'application, et celui de l'application sur le paquet de l'outil.
    const c = await O.outilReference(["paquet-client", "controler", "--paquet", paquet]);
    expect(c.sortie?.result, c.err).to.equal("reussi");
    expect(controlerPaquet(ref.sortie.outputs.directory)).to.deep.equal({ valide: true, ecarts: [] });
    const sansSession = await fetch(`${web.url}/api/clients/${slug}/paquet`);
    expect(sansSession.status).to.equal(401);
    const archive = await web.requete(`/api/clients/${slug}/paquet`);
    expect(archive.statut).to.equal(200);
    expect(archive.entetes.get("content-type")).to.equal("application/x-tar");
  });
});
