// Inscription des clients, étape 6 : paquet client (CT-4 §7.13, EX-7.18 à
// EX-7.22 ; TE-21 pour le paquet produit par l'application). Le dossier fini
// vient de l'agent pour les pas 1 à 6 et 10 ; les pas 7 à 9, ceux de
// l'enregistreur (CT-4 0.1 du contrat), sont joués par l'outil de référence
// lancé en boîte noire sur le dossier et le répertoire des captures de
// l'agent, comme le ferait l'enregistreur du client. Réseau Hardhat 31337 et
// pont noorcore de l'essai.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { RegistreSchemas } from "@noortrace/approbation";
import { sha256Hex } from "@noortrace/noyau";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import * as E from "./fixtures/inscription/reseau-essai.mjs";
import * as O from "./fixtures/inscription/outils.mjs";
import { controlerPaquet, serialiserDocument, sortieControle } from "../paquets/inscription/src/commun/paquet.mjs";
import { IDS, registreSchemas } from "../paquets/inscription/src/commun/schemas.mjs";

const X = "exploitant operateur-1";
const REGISTRE = registreSchemas();
const SORTIE = `${IDS.operations}#/$defs/sortie`;
const JOURNAL = "journal-principal";
const JID = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const CT4 = fs.readFileSync(path.join(E.RACINE, "spec", "CT-4-registre.md"), "utf8");

/** Arborescence relative d'un répertoire (fichiers seulement), triée. */
function arborescence(dir, base = "") {
  const sortie = [];
  for (const n of fs.readdirSync(path.join(dir, base)).sort()) {
    const rel = base ? `${base}/${n}` : n;
    if (fs.statSync(path.join(dir, rel)).isDirectory()) sortie.push(...arborescence(dir, rel));
    else sortie.push(rel);
  }
  return sortie;
}

describe("inscription : paquet client produit par l'application (CT-4 §7.13, EX-7.18 à EX-7.22, TE-21)", function () {
  this.timeout(900000);
  let reseau;
  let pont;
  let dir;
  let manifeste;
  let a;
  let slug;
  let cleChaine;
  let paquet;
  let travailPaquet;

  const C = () => ["--instance", manifeste, "--rpc", pont.url];
  const outil = async (args) => {
    const r = await O.outilReference([...args, ...C()]);
    expect(r.sortie, `${args[0]} : ${r.err}`).to.be.an("object");
    return r.sortie;
  };

  before(async function () {
    dir = O.repertoireTemporaire();
    reseau = await E.demarrerReseau();
    pont = await E.ouvrirPont(reseau.provider, { noorcore: true });
    manifeste = E.ecrireManifesteEssai(path.join(dir, "instance"), reseau);
    // Un relayeur configuré qu'aucun travail du client n'emploie : la recherche d'EX-7.21 ne le compte pas (secrets_checked comme l'outil).
    a = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, delai_s: 5, comptes: { exploitant: "hardhat:0", relayeur: "hardhat:9" }, jeton: "env:NOORTRACE_ESSAI_JETON", env: { NOORTRACE_ESSAI_JETON: "jeton-essai-Kq3vN8sT2xLp" } });
    slug = "paquet-essai";
    const k = crypto.createHash("sha256").update("noortrace/essai/inscription/paquet/chaine").digest();
    const f = path.join(dir, "chaine.cle");
    fs.writeFileSync(f, k.toString("hex"), { mode: 0o600 });
    cleChaine = { reference: `fichier:${f}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse(), octets: k };
    const ed = O.cleEd25519("paquet");
    const graine = path.join(dir, "rec.graine");
    fs.writeFileSync(graine, Buffer.from(ed.graine).toString("hex"), { mode: 0o600 });
    const doc = O.documentCle({ keyId: "rec-paquet-01", journalId: JID, chainKey: cleChaine.adresse, publique: ed.publique });
    const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
    const ex = async (travail) => {
      const t = await a.executer(X, travail);
      expect(t.sortie, JSON.stringify(t)).to.be.an("object");
      return t;
    };
    // Pas 1 à 6 par l'agent.
    await ex({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
    const d = JSON.parse(fs.readFileSync(a.client(slug).dossier, "utf8"));
    await a.confirmation(X, { operation: "approvisionnement", objet: { org_id: d.organisation.org_id, cle_chaine: cleChaine.adresse }, personne_client: "Responsable de l'essai", canal: "courrier signé", instant: "2026-11-11T10:00:00.000Z", piece_sha256: "0x" + "ef".repeat(32) });
    expect((await ex({ commande: "inscrire-client", slug, parametres: {} })).sortie.result).to.equal("reussi");
    const c = await ex({ commande: "condense-inscription", slug, parametres: { key_id: "rec-paquet-01" } });
    const signee = O.signerDemande(JSON.parse(fs.readFileSync(c.sortie.outputs.demande, "utf8")), [1, 3]);
    expect((await ex({ commande: "inscrire-cle", slug, parametres: { demande: signee, cle_chaine: cleChaine.reference } })).sortie.result).to.equal("reussi");
    // Pas 7 à 9 : l'outil de référence tient lieu d'enregistreur, sur le dossier et les captures de l'agent.
    const cl = a.client(slug);
    const periode = path.join(cl.dir, "periode-1");
    expect((await outil(["manifeste-essai", "--dossier", cl.dossier, "--key-id", "rec-paquet-01", "--graine", `graine:${graine}`, "--sortie", periode])).result).to.equal("reussi");
    expect((await outil(["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures])).result).to.equal("reussi");
    const demande = path.join(dir, "demande-cloture.json");
    expect((await outil(["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", cl.captures, "--sortie", demande])).result).to.equal("reussi");
    for (const i of [1, 2]) expect((await O.outilReference(["signer", "--demande", demande, "--cle", `hardhat:${i}`, ...C()])).sortie.result).to.equal("reussi");
    expect((await outil(["clore", "--demande", demande, "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures])).result).to.equal("reussi");
    const fini = JSON.parse(fs.readFileSync(cl.dossier, "utf8"));
    expect(fini.steps.every((s) => s.state === "capturee" || s.state === "faite"), JSON.stringify(fini.steps.map((s) => s.state))).to.equal(true);
    expect(fini.result).to.not.equal(null);
  });

  after(async function () {
    await a?.arreter();
    await pont?.fermer();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (a?.base) fs.rmSync(a.base, { recursive: true, force: true });
  });

  it("pas 10 : exporter puis verifier par l'agent, mêmes sorties que l'outil, R-1 à R-10 réussies", async function () {
    const cl = a.client(slug);
    const ex = await a.executer(X, { commande: "exporter", slug, parametres: { manifeste: "periode-1/manifeste.json" } });
    const exRef = await outil(["exporter", "--manifeste", path.join(cl.dir, "periode-1", "manifeste.json"), "--dossier", cl.dossier, "--captures", cl.captures, "--sortie", path.join(dir, "parties-ref")]);
    expect(O.formeSortie(ex.sortie)).to.deep.equal(O.formeSortie(exRef));
    expect(ex.sortie.outputs.entries).to.deep.equal(exRef.outputs.entries);
    expect(ex.sortie.outputs.certificates).to.deep.equal(exRef.outputs.certificates);
    for (const n of ["registre.json", "certificat-commit.json", "validateurs.json"]) {
      const ja = JSON.parse(fs.readFileSync(path.join(cl.dir, "parties", "1", n), "utf8"));
      const jb = JSON.parse(fs.readFileSync(path.join(dir, "parties-ref", n), "utf8"));
      if (n === "registre.json") expect({ ...ja, source: null }, n).to.deep.equal({ ...jb, source: null });
      else expect(ja, n).to.deep.equal(jb);
    }
    const ve = await a.executer(X, { commande: "verifier", slug, parametres: { parties: "parties/1", manifeste: "periode-1/manifeste.json" } });
    const veRef = await outil(["verifier", "--parties", path.join(cl.dir, "parties", "1"), "--manifeste", path.join(cl.dir, "periode-1", "manifeste.json"), "--dossier", cl.dossier]);
    expect(O.formeSortie(ve.sortie)).to.deep.equal(O.formeSortie(veRef));
    expect(ve.sortie.result).to.equal("reussi");
    expect(ve.sortie.outputs.status).to.equal("reussi");
    expect(ve.sortie.outputs.verifications.map((v) => `${v.id}:${v.status}`)).to.deep.equal(veRef.outputs.verifications.map((v) => `${v.id}:${v.status}`));
    expect(ve.sortie.outputs.verifications.every((v) => v.status === "reussi")).to.equal(true);
    expect(ve.sortie.outputs.n4.status).to.equal(veRef.outputs.n4.status);
    expect(ve.sortie.outputs.statement).to.deep.equal(veRef.outputs.statement);
    expect(ve.sortie.outputs.anchor_source).to.equal("publication_exploitant");
  });

  it("le paquet est produit exactement selon EX-7.18 à EX-7.20, passe le contrôle d'EX-7.22, et le travail rend la sortie paquet-client de l'outil (EX-7.30)", async function () {
    const cl = a.client(slug);
    travailPaquet = await a.executer(X, { commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'essai", console_origin: "https://console.client-essai.example", administrators: ["oidc https://idp.client-essai.example admin-1"] } });
    expect(travailPaquet.etat).to.equal("fini");
    expect(travailPaquet.resultat_paquet, "plus de resultat_paquet (révision 0.7)").to.equal(undefined);
    const s = travailPaquet.sortie;
    expect(s.result, JSON.stringify(s)).to.equal("reussi");
    expect(REGISTRE.valider(SORTIE, s).valide, JSON.stringify(REGISTRE.valider(SORTIE, s).erreurs)).to.equal(true);
    paquet = s.outputs.directory;
    expect(path.basename(paquet)).to.equal(`paquet-client-${slug}`);
    expect(path.relative(cl.dir, paquet)).to.equal(path.join("paquets", "1", `paquet-client-${slug}`));
    // Même sortie que `paquet-client produire` de l'outil sur le même dossier, les mêmes captures et le même gabarit.
    const sortieRef = path.join(dir, "sortie-ref");
    fs.mkdirSync(sortieRef);
    const ref = await O.outilReference(["paquet-client", "produire", "--dossier", cl.dossier, "--captures", cl.captures, "--sortie", sortieRef, "--instance", manifeste, "--console-origin", "https://console.client-essai.example", "--administrateur-annuaire", "oidc https://idp.client-essai.example admin-1", "--prepare-par", "exploitant de l'essai", "--cle-chaine", cleChaine.reference, "--exploitant", "hardhat:0", "--jeton", "env:NOORTRACE_ESSAI_JETON"], { env: { NOORTRACE_ESSAI_JETON: "jeton-essai-Kq3vN8sT2xLp" } });
    expect(ref.sortie, ref.err).to.be.an("object");
    expect(O.formeSortie(s)).to.deep.equal(O.formeSortie(ref.sortie));
    // secrets_checked compris (EX-7.24 ne l'excepte pas) : l'application compte les références qu'ont employées les travaux du
    // client (EX-7.21), l'outil celles que l'exploitant lui donne pour cette inscription ; le relayeur configuré, jamais employé, n'y est pas.
    expect({ ...s.outputs, directory: null, manifest_sha256: null }).to.deep.equal({ ...ref.sortie.outputs, directory: null, manifest_sha256: null });
    // EX-7.21, EX-7.30 : les options cherchées sont nommées avec leur référence, et leur nombre ; jamais une valeur.
    expect(s.outputs.secrets_checked, "clé de chaîne, clé de l'exploitant, jeton").to.deep.equal({
      count: 3,
      references: [
        { option: "--cle-chaine", reference: cleChaine.reference },
        { option: "--exploitant", reference: "hardhat:0" },
        { option: "--jeton", reference: "env:NOORTRACE_ESSAI_JETON" },
      ],
    });
    expect(s.outputs.secrets_checked).to.deep.equal(ref.sortie.outputs.secrets_checked);
    const texteSortie = JSON.stringify(s);
    expect(texteSortie.includes("jeton-essai-Kq3vN8sT2xLp"), "jeton absent de la sortie").to.equal(false);
    expect(texteSortie.toLowerCase().includes(cleChaine.octets.toString("hex")), "clé de chaîne absente de la sortie").to.equal(false);
    expect(s.outputs.manifest_sha256).to.equal(sha256Hex(fs.readFileSync(path.join(paquet, "paquet-client.json"))));
    // Mêmes fichiers, octet pour octet, hors du manifeste du paquet (source, prepared_at : EX-7.24, révision 0.7).
    const paquetRef = ref.sortie.outputs.directory;
    expect(arborescence(paquet)).to.deep.equal(arborescence(paquetRef));
    for (const n of arborescence(paquet).filter((x) => x !== "paquet-client.json")) expect(fs.readFileSync(path.join(paquet, n)).equals(fs.readFileSync(path.join(paquetRef, n))), n).to.equal(true);
    const mRef = JSON.parse(fs.readFileSync(path.join(paquetRef, "paquet-client.json"), "utf8"));
    const mApp = JSON.parse(fs.readFileSync(path.join(paquet, "paquet-client.json"), "utf8"));
    expect({ ...mApp, source: null, prepared_at: null }).to.deep.equal({ ...mRef, source: null, prepared_at: null });
    // Le contrôle de réception de l'application rend la sortie de `paquet-client controler` de l'outil.
    const c = await O.outilReference(["paquet-client", "controler", "--paquet", paquet]);
    expect(O.formeSortie(sortieControle(paquet))).to.deep.equal(O.formeSortie(c.sortie));
    expect(sortieControle(paquet).outputs).to.deep.equal(c.sortie.outputs);
    const d = JSON.parse(fs.readFileSync(cl.dossier, "utf8"));
    const m = JSON.parse(fs.readFileSync(path.join(paquet, "paquet-client.json"), "utf8"));
    // Fichiers attendus : exactement ceux d'EX-7.18.
    const captures = new Set();
    for (const e of d.steps.filter((x) => x.capture)) {
      captures.add(e.capture);
      const idx = JSON.parse(fs.readFileSync(path.join(cl.captures, e.capture), "utf8"));
      for (const f of [idx.files.block, ...idx.files.receipts, idx.files.certificate]) captures.add(f.name);
    }
    const attendus = ["gabarit-service-approbation.json", "inscription-client.json", "instance-registre.json", "jeu-approbateurs.json", "paquet-client.json", ...[...captures].map((n) => `captures/${n}`)].sort();
    expect(arborescence(paquet)).to.deep.equal(attendus);
    expect(arborescence(paquet).some((n) => /envoi-|issue-|refus-envoi-|demande-|\.cle$|\.graine$|cles-essai/.test(n))).to.equal(false);
    // Copies octet pour octet ; documents créés par JSON.stringify(objet, null, 2) et un saut de ligne.
    expect(fs.readFileSync(path.join(paquet, "inscription-client.json")).equals(fs.readFileSync(cl.dossier))).to.equal(true);
    expect(fs.readFileSync(path.join(paquet, "instance-registre.json")).equals(fs.readFileSync(manifeste))).to.equal(true);
    expect(sha256Hex(fs.readFileSync(path.join(paquet, "instance-registre.json")))).to.equal(d.instance.manifest_sha256);
    for (const n of captures) expect(fs.readFileSync(path.join(paquet, "captures", n)).equals(fs.readFileSync(path.join(cl.captures, n))), n).to.equal(true);
    expect(fs.readFileSync(path.join(paquet, "jeu-approbateurs.json"), "utf8")).to.equal(JSON.stringify(d.result.approver_set, null, 2) + "\n");
    const gabarit = { version: 0, org: slug, org_id: d.organisation.org_id, console_origin: "https://console.client-essai.example", administrators: ["oidc https://idp.client-essai.example admin-1"] };
    expect(fs.readFileSync(path.join(paquet, "gabarit-service-approbation.json"), "utf8")).to.equal(JSON.stringify(gabarit, null, 2) + "\n");
    expect(fs.readFileSync(path.join(paquet, "paquet-client.json"), "utf8")).to.equal(JSON.stringify(m, null, 2) + "\n");
    // Manifeste d'EX-7.19 : membres, ordre des fichiers, rôles, SHA-256 et longueurs, source avec version.
    expect(registreSchemas().valider(IDS.paquet, m).valide).to.equal(true);
    expect(m).to.include({ version: 0, org: slug, org_id: d.organisation.org_id, prepared_by: "exploitant de l'essai", source: "@noortrace/inscription 0.1.0" });
    expect(m.instance).to.deep.equal({ evm_chain_id: d.instance.evm_chain_id, bft_chain_id: d.instance.bft_chain_id, manifest_sha256: d.instance.manifest_sha256 });
    expect(m.files.map((f) => f.path)).to.deep.equal(["inscription-client.json", "instance-registre.json", "jeu-approbateurs.json", "gabarit-service-approbation.json", ...[...captures].map((n) => `captures/${n}`).sort((x, y) => Buffer.compare(Buffer.from(x), Buffer.from(y)))]);
    for (const f of m.files) {
      const o = fs.readFileSync(path.join(paquet, f.path));
      expect(f.sha256, f.path).to.equal(sha256Hex(o));
      expect(f.length, f.path).to.equal(o.length);
    }
    expect(controlerPaquet(paquet)).to.deep.equal({ valide: true, ecarts: [] });
    // Un paquet remis n'est jamais remplacé : une seconde production a son propre répertoire (EX-7.30).
    const avant = fs.readFileSync(path.join(paquet, "paquet-client.json"));
    const t2 = await a.executer(X, { commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: null } });
    expect(t2.sortie.result).to.equal("reussi");
    expect(path.relative(cl.dir, t2.sortie.outputs.directory)).to.equal(path.join("paquets", "2", `paquet-client-${slug}`));
    expect(fs.readFileSync(path.join(paquet, "paquet-client.json")).equals(avant)).to.equal(true);
    // Le gabarit est valide, membre par membre, contre configuration-approbation-v0 (EX-7.20).
    for (const k of ["version", "org", "org_id", "console_origin", "administrators"]) {
      expect(registreSchemas().valider(`${IDS.configurationApprobation}#/properties/${k}`, gabarit[k]).valide, k).to.equal(true);
    }
  });

  it("les deux exemples de CT-4 §7.13 sont valides contre paquet-client-v0 (avec inscription-client-v0, configuration-approbation-v0 et leurs références)", function () {
    const exemples = [...CT4.matchAll(/<!-- exemple: (paquet-client(?:\/[a-z_]+)?) -->\n```json\n([\s\S]*?)\n```/g)];
    expect(exemples.map((x) => x[1])).to.deep.equal(["paquet-client", "paquet-client/gabarit_service"]);
    const r = new RegistreSchemas();
    for (const f of ["inscription-client-v0", "configuration-approbation-v0", "annuaire-approbateurs-v0", "evenement-v0", "ticket-v0", "paquet-client-v0"]) {
      r.ajouter(JSON.parse(fs.readFileSync(path.join(E.RACINE, "paquets", "inscription", "schemas", `${f}.schema.json`), "utf8")));
    }
    for (const [, marqueur, json] of exemples) {
      const ref = marqueur === "paquet-client" ? IDS.paquet : `${IDS.paquet}#/$defs/gabarit_service`;
      const v = r.valider(ref, JSON.parse(json));
      expect(v.valide, `${marqueur} : ${JSON.stringify(v.erreurs)}`).to.equal(true);
    }
  });

  it("EX-7.21 : chaque forme d'encodage d'un secret employé glissée dans un fichier interdit la remise (secret_present, comme l'outil) ; le nom du fichier est consigné, jamais la valeur", async function () {
    const cl = a.client(slug);
    const productions = () => fs.readdirSync(path.join(cl.dir, "paquets")).sort();
    const avant = productions();
    const b = Buffer.from(cleChaine.octets);
    const hardhat0 = Buffer.from(O.compteHardhat(0).cle);
    const formes = [
      ["clé de chaîne, hexadécimal", b.toString("hex")],
      ["clé de chaîne, hexadécimal majuscule avec 0x", "0x" + b.toString("hex").toUpperCase()],
      ["clé de chaîne, base64 avec remplissage", b.toString("base64")],
      ["clé de chaîne, base64 sans remplissage", b.toString("base64").replace(/=+$/, "")],
      ["clé de chaîne, base64url", b.toString("base64url")],
      ["clé de chaîne, base64url avec remplissage", b.toString("base64url") + "="],
      ["clé de l'exploitant (hardhat:0), hexadécimal", hardhat0.toString("hex")],
      ["jeton du nœud, tel quel", "jeton-essai-Kq3vN8sT2xLp"],
    ];
    for (const [nom, valeur] of formes) {
      const t = await a.executer(X, { commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: [`oidc https://idp.client-essai.example ${valeur}`] } });
      const r = t.sortie;
      expect(r.result, nom).to.equal("refuse");
      expect(r.exit_code, nom).to.equal(1);
      expect(r.error, nom).to.deep.include({ code: "secret_present", check: null });
      expect(r.error.message, nom).to.match(/^EX-7\.21 : /);
      expect(r.checks.map((c) => `${c.id}:${c.status}`), nom).to.deep.equal(["OP-4:reussi"]);
      expect(r.outputs, nom).to.deep.equal({ requirement: "EX-7.21", point: null, file: "gabarit-service-approbation.json" });
      expect(productions(), `${nom} : aucun paquet laissé`).to.deep.equal(avant);
      expect(JSON.stringify(t), nom).to.not.contain(valeur);
      const journal = fs.readFileSync(path.join(a.donnees, "journal-agent.ndjson"), "utf8");
      expect(journal, nom).to.not.contain(valeur);
      expect(journal).to.contain("gabarit-service-approbation.json");
    }
    // Même refus que l'outil pour la clé de chaîne glissée dans le gabarit.
    const sortieRef = path.join(dir, "sortie-ref-secret");
    fs.mkdirSync(sortieRef);
    const t = await a.executer(X, { commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: [`oidc https://idp.client-essai.example ${b.toString("hex")}`] } });
    const ref = await O.outilReference(["paquet-client", "produire", "--dossier", cl.dossier, "--captures", cl.captures, "--sortie", sortieRef, "--instance", manifeste, "--administrateur-annuaire", `oidc https://idp.client-essai.example ${b.toString("hex")}`, "--cle-chaine", cleChaine.reference]);
    expect(O.formeSortie(t.sortie, { valeursOutputs: true })).to.deep.equal(O.formeSortie(ref.sortie, { valeursOutputs: true }));
    expect(fs.readdirSync(sortieRef)).to.deep.equal([]);
    // Le paquet remis précédemment n'est pas altéré par une production refusée.
    expect(controlerPaquet(paquet)).to.deep.equal({ valide: true, ecarts: [] });
  });

  it("dossier non fini : le paquet n'est pas produit (dossier_inacheve, comme l'outil)", async function () {
    const doc = O.documentCle({ keyId: "rec-inacheve-01", journalId: JID, chainKey: O.compteHardhat(8).adresse, publique: O.cleEd25519("inacheve").publique });
    await a.executer(X, { commande: "inscrire-client-preparer", slug: "inacheve", parametres: { org: "inacheve", journaux: [JOURNAL], approbateurs: [O.compteHardhat(1).adresse], seuil: 1, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
    const t = await a.executer(X, { commande: "paquet", slug: "inacheve", parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: null } });
    expect(t.sortie).to.deep.include({ command: "paquet-client", result: "refuse", exit_code: 1 });
    expect(t.sortie.error).to.deep.include({ code: "dossier_inacheve", check: null });
    expect(fs.existsSync(path.join(a.client("inacheve").dir, "paquets"))).to.equal(false);
    const sortieRef = path.join(dir, "sortie-ref-inacheve");
    fs.mkdirSync(sortieRef);
    fs.mkdirSync(path.join(dir, "aucune-capture"));
    const ref = await O.outilReference(["paquet-client", "produire", "--dossier", a.client("inacheve").dossier, "--captures", path.join(dir, "aucune-capture"), "--sortie", sortieRef, "--instance", manifeste]);
    expect(O.formeSortie(t.sortie)).to.deep.equal(O.formeSortie(ref.sortie));
  });

  describe("controlerPaquet : chaque copie altérée est refusée au point d'EX-7.22 qui la vise", function () {
    // Chaque copie garde le nom du paquet (point 4 d'EX-7.22, révision 0.7), sous un répertoire tiré au hasard.
    const copie = () => {
      const c = path.join(dir, `copie-${crypto.randomBytes(4).toString("hex")}`, path.basename(paquet));
      fs.cpSync(paquet, c, { recursive: true });
      return c;
    };
    const manif = (c) => JSON.parse(fs.readFileSync(path.join(c, "paquet-client.json"), "utf8"));
    const ecrireManif = (c, m) => fs.writeFileSync(path.join(c, "paquet-client.json"), serialiserDocument(m));
    /** Réécrit un fichier du paquet et met à jour son entrée de `files` (le point 2 reste juste). */
    const reecrire = (c, rel, octets) => {
      fs.writeFileSync(path.join(c, rel), octets);
      const m = manif(c);
      const f = m.files.find((x) => x.path === rel);
      f.sha256 = sha256Hex(octets);
      f.length = octets.length;
      ecrireManif(c, m);
    };
    /** Premier écart, sans le code d'EX-7.30 ; et contrôle que la sortie de l'application égale celle de `paquet-client controler`. */
    const jugements = [];
    const premier = (c) => {
      const { erreur, ...e } = controlerPaquet(c).ecarts[0];
      jugements.push(O.outilReference(["paquet-client", "controler", "--paquet", c]).then((r) => ({ c, app: sortieControle(c), ref: r.sortie, erreur })));
      return e;
    };
    afterEach(async function () {
      for (const j of await Promise.all(jugements.splice(0))) {
        expect(j.ref, j.c).to.be.an("object");
        expect(j.app.error.code, j.c).to.equal(j.erreur);
        expect(O.formeSortie(j.app, { valeursOutputs: true }), `${j.c} : ${j.ref.error?.message}`).to.deep.equal(O.formeSortie(j.ref, { valeursOutputs: true }));
      }
    });

    it("le répertoire n'est pas nommé paquet-client-<org> : point 4 (révision 0.7)", function () {
      const c = copie();
      const autre = path.join(path.dirname(c), "paquet-recu");
      fs.renameSync(c, autre);
      expect(premier(autre)).to.deep.equal({ point: 4, fichier: null, code: "nom_repertoire" });
    });

    it("point 3 (révision 0.7) : écriture d'EX-7.18, réponse brute qui n'est pas une réponse JSON-RPC 2.0 complète, index qu'aucune étape ne nomme (point 6)", function () {
      let c = copie();
      const j = JSON.parse(fs.readFileSync(path.join(c, "jeu-approbateurs.json"), "utf8"));
      reecrire(c, "jeu-approbateurs.json", Buffer.from(JSON.stringify(j) + "\n"));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: "jeu-approbateurs.json", code: "ecriture" });
      c = copie();
      fs.writeFileSync(path.join(c, "paquet-client.json"), JSON.stringify(manif(c)));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: "paquet-client.json", code: "ecriture" });
      c = copie();
      const recu = manif(c).files.find((f) => f.role === "capture_recu").path;
      const r = JSON.parse(fs.readFileSync(path.join(c, recu), "utf8"));
      delete r.jsonrpc;
      reecrire(c, recu, Buffer.from(JSON.stringify(r)));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: recu, code: "forme" });
      // Un index valide, listé dans files, qu'aucune étape du dossier ne nomme.
      c = copie();
      const m = manif(c);
      const index = m.files.find((f) => f.role === "capture_index").path;
      const intrus = "captures/capture-999999-0-ancre.json";
      const o = fs.readFileSync(path.join(c, index));
      fs.writeFileSync(path.join(c, intrus), o);
      m.files.push({ path: intrus, role: "capture_index", sha256: sha256Hex(o), length: o.length });
      const debut = m.files.filter((f) => !f.path.startsWith("captures/"));
      const fin = m.files.filter((f) => f.path.startsWith("captures/")).sort((x, y) => Buffer.compare(Buffer.from(x.path), Buffer.from(y.path)));
      ecrireManif(c, { ...m, files: [...debut, ...fin] });
      expect(premier(c)).to.deep.equal({ point: 6, fichier: intrus, code: "capture_non_nommee" });
    });

    it("point 1 : paquet-client.json hors de son schéma, illisible, absent", function () {
      let c = copie();
      ecrireManif(c, { ...manif(c), version: 1 });
      expect(premier(c)).to.deep.equal({ point: 1, fichier: "paquet-client.json", code: "schema" });
      c = copie();
      fs.writeFileSync(path.join(c, "paquet-client.json"), '{"version":0,"version":0}');
      expect(premier(c)).to.deep.include({ point: 1, code: "illisible" });
      c = copie();
      fs.rmSync(path.join(c, "paquet-client.json"));
      expect(premier(c)).to.deep.include({ point: 1, code: "absent" });
    });

    it("point 2 : fichier modifié, fichier en trop, fichier manquant, ordre de files, lien symbolique", function () {
      let c = copie();
      const m = manif(c);
      const recu = m.files.find((f) => f.role === "capture_recu").path;
      fs.appendFileSync(path.join(c, recu), " ");
      expect(premier(c)).to.deep.include({ point: 2, fichier: recu });
      c = copie();
      fs.writeFileSync(path.join(c, "notes.txt"), "hors du paquet");
      expect(premier(c)).to.deep.equal({ point: 2, fichier: "notes.txt", code: "fichier_non_liste" });
      c = copie();
      fs.rmSync(path.join(c, "jeu-approbateurs.json"));
      expect(premier(c)).to.deep.equal({ point: 2, fichier: "jeu-approbateurs.json", code: "fichier_absent" });
      c = copie();
      const m2 = manif(c);
      [m2.files[2], m2.files[3]] = [m2.files[3], m2.files[2]];
      ecrireManif(c, m2);
      expect(premier(c)).to.deep.equal({ point: 2, fichier: "gabarit-service-approbation.json", code: "ordre_files" });
      c = copie();
      const cible = path.join(c, "captures", m.files.find((f) => f.role === "capture_bloc").path.slice("captures/".length));
      fs.rmSync(cible);
      fs.symlinkSync(path.join(paquet, path.relative(c, cible)), cible);
      expect(premier(c)).to.deep.include({ point: 2, code: "fichier_non_ordinaire" });
    });

    it("point 3 : fichier hors de la forme de son rôle (dossier, gabarit, index de capture, réponse brute)", function () {
      let c = copie();
      const g = JSON.parse(fs.readFileSync(path.join(c, "gabarit-service-approbation.json"), "utf8"));
      reecrire(c, "gabarit-service-approbation.json", serialiserDocument({ ...g, reglage: 1 }));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: "gabarit-service-approbation.json", code: "forme" });
      c = copie();
      const d = JSON.parse(fs.readFileSync(path.join(c, "inscription-client.json"), "utf8"));
      reecrire(c, "inscription-client.json", serialiserDocument({ ...d, version: 1 }));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: "inscription-client.json", code: "forme" });
      c = copie();
      d.steps[d.steps.length - 1].state = "incluse";
      reecrire(c, "inscription-client.json", serialiserDocument(d));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: "inscription-client.json", code: "dossier_non_fini" });
      c = copie();
      const bloc = manif(c).files.find((f) => f.role === "capture_bloc").path;
      reecrire(c, bloc, Buffer.from("pas du JSON-RPC"));
      expect(premier(c)).to.deep.equal({ point: 3, fichier: bloc, code: "forme" });
    });

    it("point 4 : org, org_id, instance, manifeste d'instance", function () {
      let c = copie();
      ecrireManif(c, { ...manif(c), org: "autre-organisation" });
      expect(premier(c)).to.deep.equal({ point: 4, fichier: "paquet-client.json", code: "org_different" });
      c = copie();
      const m = manif(c);
      ecrireManif(c, { ...m, instance: { ...m.instance, bft_chain_id: "noortrace-31337-autre" } });
      expect(premier(c)).to.deep.equal({ point: 4, fichier: "paquet-client.json", code: "instance_differente" });
      c = copie();
      reecrire(c, "instance-registre.json", Buffer.concat([fs.readFileSync(path.join(c, "instance-registre.json")), Buffer.from(" ")]));
      expect(premier(c)).to.deep.equal({ point: 4, fichier: "instance-registre.json", code: "manifeste_instance_different" });
    });

    it("point 5 : jeu d'approbateurs différent du dossier, gabarit d'une autre organisation", function () {
      let c = copie();
      const j = JSON.parse(fs.readFileSync(path.join(c, "jeu-approbateurs.json"), "utf8"));
      reecrire(c, "jeu-approbateurs.json", serialiserDocument({ ...j, set: "0x" + "12".repeat(20) }));
      expect(premier(c)).to.deep.equal({ point: 5, fichier: "jeu-approbateurs.json", code: "jeu_different" });
      c = copie();
      const g = JSON.parse(fs.readFileSync(path.join(c, "gabarit-service-approbation.json"), "utf8"));
      reecrire(c, "gabarit-service-approbation.json", serialiserDocument({ ...g, org: "autre-organisation" }));
      expect(premier(c)).to.deep.equal({ point: 5, fichier: "gabarit-service-approbation.json", code: "gabarit_different" });
    });

    it("point 6 : fichier nommé par un index absent ou d'un autre SHA-256, capture non nommée", function () {
      let c = copie();
      let m = manif(c);
      const recu = m.files.find((f) => f.role === "capture_recu").path;
      fs.rmSync(path.join(c, recu));
      ecrireManif(c, { ...m, files: m.files.filter((f) => f.path !== recu) });
      expect(premier(c)).to.deep.equal({ point: 6, fichier: recu, code: "fichier_capture_absent" });
      c = copie();
      const cert = manif(c).files.find((f) => f.role === "capture_certificat").path;
      reecrire(c, cert, Buffer.concat([fs.readFileSync(path.join(c, cert)), Buffer.from("\n")]));
      expect(premier(c)).to.deep.equal({ point: 6, fichier: cert, code: "sha256_capture_different" });
      c = copie();
      m = manif(c);
      const intrus = "captures/bloc-999999.json";
      const o = Buffer.from('{"jsonrpc":"2.0","id":1,"result":{}}');
      fs.writeFileSync(path.join(c, intrus), o);
      m.files.push({ path: intrus, role: "capture_bloc", sha256: sha256Hex(o), length: o.length });
      const debut = m.files.filter((f) => !f.path.startsWith("captures/"));
      const fin = m.files.filter((f) => f.path.startsWith("captures/")).sort((x, y) => Buffer.compare(Buffer.from(x.path), Buffer.from(y.path)));
      ecrireManif(c, { ...m, files: [...debut, ...fin] });
      expect(premier(c)).to.deep.equal({ point: 6, fichier: intrus, code: "capture_non_nommee" });
    });
  });
});
