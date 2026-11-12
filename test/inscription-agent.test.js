// Inscription des clients, étape 6 : l'agent d'inscription (CT-4 §7.14,
// EX-7.23 à EX-7.28 ; paquets/inscription/INTERFACES.md 3), éprouvé sur le
// réseau Hardhat en mémoire (identifiant EVM 31337), démarré par l'essai et
// présenté comme un validateur noorcore par le pont de
// test/fixtures/inscription/reseau-essai.mjs (en-têtes BFT, certificats
// signés par le jeu d'essai de CT-4 A.2).
//
// Oracle d'EX-7.24 : l'outil de référence scripts/registre/noortrace-registre.mjs,
// lancé en boîte noire (ses sorties seules sont lues), sur un second client
// symétrique du même réseau et dans le même état ; la forme de chaque sortie
// (commande, résultat, code de sortie, code et vérification d'erreur,
// vérifications et leurs statuts dans l'ordre, membres des `outputs`) doit
// être la même. Les clés d'essai sont dérivées à l'essai du mnémonique public
// ou de graines publiques ; aucune n'est écrite dans le dépôt.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { SignataireChaineFichier, REGISTRE_SCHEMAS } from "@noortrace/ancrage/registre";
import * as E from "./fixtures/inscription/reseau-essai.mjs";
import * as O from "./fixtures/inscription/outils.mjs";
import { SELECTEURS as SEL_JEU, SIGNATURES as SIG_JEU } from "../paquets/inscription/src/agent/jeu.mjs";
import { FICHIERS_SCHEMAS, REPERTOIRE_SCHEMAS } from "../paquets/inscription/src/commun/schemas.mjs";
import { keccak256, octetsVersHex, utf8 } from "@noortrace/noyau";

const X = "exploitant operateur-1";
const JOURNAL = "journal-principal";
const JID = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const SORTIE = "https://noortrace.example/schemas/v0/operations-registre.schema.json#/$defs/sortie";

const enAttente = (ctx, condition) => {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
};

describe("inscription : agent d'inscription sur le réseau Hardhat 31337 (CT-4 §7.14, EX-7.23 à EX-7.28)", function () {
  this.timeout(900000);
  let reseau;
  let pont;
  let dir;
  let manifeste;
  let a;
  const sorties = [];

  /** Clé de chaîne d'essai neuve, dans un fichier 0600 (référence fichier:, classe D). */
  const cleFichier = (nom) => {
    const k = crypto.createHash("sha256").update(`noortrace/essai/inscription/chaine/${nom}`).digest();
    const f = path.join(dir, `${nom}.cle`);
    fs.writeFileSync(f, k.toString("hex"), { mode: 0o600 });
    return { reference: `fichier:${f}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse(), octets: k };
  };
  const C = () => ["--instance", manifeste, "--rpc", pont.url];
  const APP = () => [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
  const ADMIN = () => O.compteHardhat(4).adresse;

  /** Deux clients symétriques : `A` conduit par l'agent, `B` par l'outil de référence. */
  function paire(nom, { cles = 1, memeCle = null } = {}) {
    const cote = (lettre) => {
      const slug = `${nom}-${lettre}`;
      const liste = [];
      for (let k = 1; k <= cles; k++) {
        const ch = memeCle === "chaine" && k > 1 ? liste[0].chaine : cleFichier(`${slug}-${k}`);
        const ed = memeCle === "ed25519" && k > 1 ? liste[0].ed : O.cleEd25519(`${slug}-${k}`);
        const doc = O.documentCle({ keyId: `rec-${slug}-${k}`, journalId: JID, chainKey: ch.adresse, publique: ed.publique });
        liste.push({ chaine: ch, ed, doc });
      }
      const docs = liste.map((x, k) => {
        const f = path.join(dir, `${slug}-cle-${k + 1}.json`);
        fs.writeFileSync(f, JSON.stringify(x.doc));
        return f;
      });
      return { slug, cles: liste, docs, dossier: path.join(dir, `${slug}.json`), captures: path.join(dir, `${slug}-captures`) };
    };
    return { A: cote("a"), B: cote("b") };
  }

  const garder = (s) => {
    if (s) sorties.push(s);
    return s;
  };
  const agent = async (travail) => {
    const t = await a.executer(X, travail);
    if (t.sortie) garder(t.sortie);
    return t;
  };
  const outil = async (args) => {
    const r = await O.outilReference([...args, ...C()]);
    expect(r.sortie, `sortie de l'outil de référence (${args[0]}) : ${r.err}`).to.be.an("object");
    return r.sortie;
  };
  const memeForme = (sa, sb) => expect(O.formeSortie(sa)).to.deep.equal(O.formeSortie(sb));

  const preparer = async (p, { seuil = 2, approbateurs = APP(), admin = ADMIN(), tresorerieA = undefined, tresorerieB = "hardhat:0" } = {}) => {
    const t = await agent({ commande: "inscrire-client-preparer", slug: p.A.slug, parametres: { org: p.A.slug, journaux: [JOURNAL], approbateurs, seuil, admin_jeu: admin, cles_enregistreur: p.A.cles.map((c) => c.doc), ...(tresorerieA ? { tresorerie: tresorerieA } : {}) } });
    const args = ["inscrire-client", "--preparer", "--org", p.B.slug, "--journal", JOURNAL, "--seuil", String(seuil), "--approbateurs", approbateurs.join(","), "--admin-jeu", admin];
    for (const f of p.B.docs) args.push("--cle-enregistreur", f);
    args.push("--tresorerie", tresorerieB, "--sortie", p.B.dossier);
    const sb = await outil(args);
    return { ta: t, sa: t.sortie, sb };
  };
  const dossierA = (p) => JSON.parse(fs.readFileSync(a.client(p.A.slug).dossier, "utf8"));
  const dossierB = (p) => JSON.parse(fs.readFileSync(p.B.dossier, "utf8"));
  const confirmer = async (p, operation = "approvisionnement") => {
    const d = dossierA(p);
    for (const c of p.A.cles) {
      const r = await a.confirmation(X, { operation, objet: { org_id: d.organisation.org_id, cle_chaine: c.chaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel téléphonique au numéro du contrat", instant: "2026-11-11T10:00:00.000Z", piece_sha256: "0x" + "ab".repeat(32) });
      expect(r.accepte, JSON.stringify(r)).to.equal(true);
    }
  };
  const inscrireClient = async (p, { confirmation = true } = {}) => {
    if (confirmation) await confirmer(p);
    const t = await agent({ commande: "inscrire-client", slug: p.A.slug, parametres: {} });
    const sb = await outil(["inscrire-client", "--dossier", p.B.dossier, "--exploitant", "hardhat:0", "--captures", p.B.captures, "--delai", "3"]);
    return { ta: t, sa: t.sortie, sb };
  };
  const condense = async (p, k = 1) => {
    const t = await agent({ commande: "condense-inscription", slug: p.A.slug, parametres: { key_id: `rec-${p.A.slug}-${k}` } });
    const fb = path.join(dir, `${p.B.slug}-demande-${k}.json`);
    fs.rmSync(fb, { force: true });
    const sb = await outil(["condense", "inscription", "--dossier", p.B.dossier, "--key-id", `rec-${p.B.slug}-${k}`, "--sortie", fb]);
    return { sa: t.sortie, sb, demA: t.sortie.result === "reussi" ? JSON.parse(fs.readFileSync(t.sortie.outputs.demande, "utf8")) : null, demB: sb.result === "reussi" ? JSON.parse(fs.readFileSync(fb, "utf8")) : null };
  };
  const inscrireCle = async (p, demA, demB, k = 1) => {
    const t = await agent({ commande: "inscrire-cle", slug: p.A.slug, parametres: { demande: demA, cle_chaine: p.A.cles[k - 1].chaine.reference } });
    const fb = path.join(dir, `${p.B.slug}-demande-signee.json`);
    fs.writeFileSync(fb, JSON.stringify(demB));
    const sb = await outil(["inscrire-cle", "--demande", fb, "--cle-chaine", p.B.cles[k - 1].chaine.reference, "--dossier", p.B.dossier, "--captures", p.B.captures, "--delai", "3"]);
    return { ta: t, sa: t.sortie, sb };
  };
  /** Client entièrement inscrit (pas 1 à 6) des deux côtés. */
  const inscrit = async (nom, options = {}) => {
    const p = paire(nom, options);
    await preparer(p);
    await inscrireClient(p);
    const c = await condense(p);
    await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
    return p;
  };

  before(async function () {
    dir = O.repertoireTemporaire();
    reseau = await E.demarrerReseau();
    pont = await E.ouvrirPont(reseau.provider, { noorcore: true });
    manifeste = E.ecrireManifesteEssai(path.join(dir, "instance"), reseau);
    a = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, delai_s: 3 });
  });

  afterEach(async function () {
    // Un essai qui échoue en cours de route ne laisse pas le pont dans un état de panne pour les suivants.
    if (this.currentTest?.ctx?.retablir) {
      await this.currentTest.ctx.retablir();
      this.currentTest.ctx.retablir = null;
    }
    pont.avantEnvoi = null;
    pont.suiveur = false;
    pont.certificatsIndisponiblesDepuis = null;
    pont.refuserEnvois = null;
  });

  after(async function () {
    await a?.arreter();
    await pont?.fermer();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (a?.base) fs.rmSync(a.base, { recursive: true, force: true });
  });

  describe("contrat du paquet", function () {
    it("les neuf schémas embarqués sont des copies octet pour octet de spec/schemas (INTERFACES.md 0.4)", function () {
      for (const f of FICHIERS_SCHEMAS) {
        expect(Buffer.compare(fs.readFileSync(path.join(REPERTOIRE_SCHEMAS, f)), fs.readFileSync(path.join(E.RACINE, "spec", "schemas", f))), f).to.equal(0);
      }
      expect(FICHIERS_SCHEMAS).to.have.length(9);
    });

    it("chaque sélecteur écrit par l'agent est recalculé et égal à l'ABI des artefacts de compilation (INTERFACES.md 0.5)", function () {
      const abi = (nom, fichier) => JSON.parse(fs.readFileSync(path.join(E.RACINE, "hh-artifacts", "contracts", `${fichier}.sol`, `${fichier}.json`), "utf8")).abi.filter((x) => x.type === "function" && x.name === nom);
      const verifier = (cle, contrat) => {
        const [nom] = SIG_JEU[cle].split("(");
        const f = abi(nom, contrat);
        expect(f, `${cle} dans ${contrat}`).to.have.length.greaterThan(0);
        const signatures = f.map((x) => `${x.name}(${x.inputs.map((i) => i.type).join(",")})`);
        expect(signatures).to.include(SIG_JEU[cle]);
        expect(SEL_JEU[cle]).to.equal(octetsVersHex(keccak256(utf8(SIG_JEU[cle]))).slice(0, 10));
      };
      for (const cle of ["setCuratorSet", "admin", "isRegistered", "curatorSetOf"]) verifier(cle, "CuratorSetRegistry");
      for (const cle of ["getThreshold", "getCuratorCount", "isCurator", "admin"]) verifier(cle, "CuratorSet");
      // Administration du jeu (CT-4 §8.5) : types canoniques de l'ABI, tuple de la signature compris.
      const canonique = (i) => (i.type === "tuple" ? `(${i.components.map(canonique).join(",")})` : i.type);
      for (const cle of ["opNonce", "pendingAdmin", "adminOpDigest", "addCuratorSigned", "removeCuratorSigned", "setThresholdSigned", "proposeAdminSigned", "acceptAdminSigned"]) {
        const [nom] = SIG_JEU[cle].split("(");
        const f = abi(nom, "CuratorSet");
        expect(f.map((x) => `${x.name}(${x.inputs.map(canonique).join(",")})`), cle).to.include(SIG_JEU[cle]);
        expect(SEL_JEU[cle]).to.equal(octetsVersHex(keccak256(utf8(SIG_JEU[cle]))).slice(0, 10));
      }
      const ctor = JSON.parse(fs.readFileSync(path.join(E.RACINE, "hh-artifacts", "contracts", "CuratorSet.sol", "CuratorSet.json"), "utf8")).abi.find((x) => x.type === "constructor");
      expect(ctor.inputs.map((i) => i.type)).to.deep.equal(["address", "address[]", "uint256"]);
    });

    it("l'agent démarré écrit sa ligne de disponibilité et n'a aucune prise d'écoute AF_INET ni AF_INET6 (EX-7.28)", function () {
      expect(a.pret).to.deep.equal({ pret: true, pid: a.agent.pid, prise: a.prise });
      expect(fs.statSync(a.prise).isSocket()).to.equal(true);
      expect(fs.statSync(a.prise).mode & 0o777).to.equal(0o660);
      const inodes = new Set();
      for (const fd of fs.readdirSync(`/proc/${a.agent.pid}/fd`)) {
        try {
          const m = /^socket:\[(\d+)\]$/.exec(fs.readlinkSync(`/proc/${a.agent.pid}/fd/${fd}`));
          if (m) inodes.add(m[1]);
        } catch {
          // descripteur fermé entre-temps
        }
      }
      expect(inodes.size).to.be.greaterThan(0);
      for (const table of ["tcp", "tcp6", "udp", "udp6"]) {
        if (!fs.existsSync(`/proc/${a.agent.pid}/net/${table}`)) continue;
        const lignes = fs.readFileSync(`/proc/${a.agent.pid}/net/${table}`, "utf8").split("\n").slice(1).map((l) => l.trim().split(/\s+/)).filter((p) => p.length >= 10);
        const ecoutes = lignes.filter((p) => inodes.has(p[9]) && (table.startsWith("udp") || p[3] === "0A"));
        expect(ecoutes, `prise ${table} d'écoute de l'agent`).to.deep.equal([]);
      }
      const unix = fs.readFileSync(`/proc/${a.agent.pid}/net/unix`, "utf8");
      expect(unix).to.contain(a.prise);
    });
  });

  describe("pas 1 à 6 : mêmes sorties que l'outil de référence (EX-7.24)", function () {
    let p;

    it("préparation (pas 1) : même sortie, dossier conforme, étapes à a_faire, result nul", async function () {
      p = paire("pas");
      const r = await preparer(p);
      memeForme(r.sa, r.sb);
      expect(r.sa.result).to.equal("reussi");
      const d = dossierA(p);
      expect(d.steps.map((s) => [s.step, s.state])).to.deep.equal(dossierB(p).steps.map((s) => [s.step, s.state]));
      expect(d.steps.every((s) => s.state === "a_faire")).to.equal(true);
      expect(d.result).to.equal(null);
      expect(d.prepared_by).to.equal(X);
      expect(d.approvers.members).to.deep.equal([...APP()].sort());
    });

    it("refus de la préparation : organisation_existante, jeu_invalide (seuil, administrateur nul, doublon), compte_inattendu, comme l'outil", async function () {
      const envois = pont.envoisRecus.length;
      const cas = [
        { nom: "seuil", o: { seuil: 4 } },
        { nom: "admin-nul", o: { admin: "0x" + "00".repeat(20) } },
        { nom: "doublon", o: { approbateurs: [APP()[0], APP()[0]] } },
        { nom: "tresorerie", o: { tresorerieA: "hardhat:1", tresorerieB: "hardhat:1" } },
      ];
      for (const c of cas) {
        const q = paire(`ref-${c.nom}`);
        const r = await preparer(q, c.o);
        memeForme(r.sa, r.sb);
        expect(r.sa.result, c.nom).to.equal("refuse");
        expect(fs.existsSync(a.client(q.A.slug).dossier), c.nom).to.equal(false);
      }
      // organisation_existante : un slug déjà enregistré sur la chaîne, sans dossier local (EX-6.3) ; chaque côté reprend le slug de l'autre.
      const ex = await inscrit("existante");
      const t = await agent({ commande: "inscrire-client-preparer", slug: ex.B.slug, parametres: { org: ex.B.slug, journaux: [JOURNAL], approbateurs: APP(), seuil: 2, admin_jeu: ADMIN(), cles_enregistreur: [ex.A.cles[0].doc] } });
      const sb = await outil(["inscrire-client", "--preparer", "--org", ex.A.slug, "--journal", JOURNAL, "--seuil", "2", "--approbateurs", APP().join(","), "--admin-jeu", ADMIN(), "--cle-enregistreur", ex.B.docs[0], "--tresorerie", "hardhat:0", "--sortie", path.join(dir, "existante-bis.json")]);
      memeForme(t.sortie, sb);
      expect(t.sortie.error).to.deep.include({ code: "organisation_existante", check: "OP-4" });
      // Dossier déjà présent : usage, comme un fichier de sortie existant pour l'outil.
      const t2 = await agent({ commande: "inscrire-client-preparer", slug: ex.A.slug, parametres: { org: ex.A.slug, journaux: [JOURNAL], approbateurs: APP(), seuil: 2, admin_jeu: ADMIN(), cles_enregistreur: [ex.A.cles[0].doc] } });
      const sb2 = await outil(["inscrire-client", "--preparer", "--org", "existante-c", "--journal", JOURNAL, "--seuil", "2", "--approbateurs", APP().join(","), "--admin-jeu", ADMIN(), "--cle-enregistreur", ex.B.docs[0], "--tresorerie", "hardhat:0", "--sortie", ex.B.dossier]);
      memeForme(t2.sortie, sb2);
      expect(t2.sortie.error.code).to.equal("usage");
      expect(pont.envoisRecus.length - envois, "seule l'inscription des deux clients témoins envoie").to.equal(8);
    });

    it("confirmation hors bande absente : refus confirmation_absente, rien n'est envoyé, aucune sortie (EX-7.26)", async function () {
      const envois = pont.envoisRecus.length;
      const nonce = await reseau.provider.request({ method: "eth_getTransactionCount", params: [O.compteHardhat(0).adresse, "latest"] });
      const sortiesAvant = fs.existsSync(path.join(a.client(p.A.slug).dir, "sorties")) ? fs.readdirSync(path.join(a.client(p.A.slug).dir, "sorties")).length : 0;
      const travauxAvant = fs.readdirSync(path.join(a.donnees, "travaux")).length;
      const r = await a.travail(X, { commande: "inscrire-client", slug: p.A.slug, parametres: {} });
      expect(r).to.deep.include({ accepte: false, code: "confirmation_absente" });
      expect(r.message).to.match(/confirmation hors bande absente/);
      const r2 = await a.travail(X, { commande: "approvisionner", slug: p.A.slug, parametres: { cle_chaine: p.A.cles[0].chaine.adresse } });
      expect(r2).to.deep.include({ accepte: false, code: "confirmation_absente" });
      expect(pont.envoisRecus.length).to.equal(envois);
      expect(await reseau.provider.request({ method: "eth_getTransactionCount", params: [O.compteHardhat(0).adresse, "latest"] })).to.equal(nonce);
      expect(fs.readdirSync(path.join(a.donnees, "travaux")).length).to.equal(travauxAvant);
      const sortiesApres = fs.existsSync(path.join(a.client(p.A.slug).dir, "sorties")) ? fs.readdirSync(path.join(a.client(p.A.slug).dir, "sorties")).length : 0;
      expect(sortiesApres).to.equal(sortiesAvant);
      expect(fs.existsSync(path.join(a.client(p.A.slug).dir, "captures"))).to.equal(false);
      expect(a.journal().filter((l) => l.evenement === "travail_refuse" && l.code === "confirmation_absente").length).to.be.greaterThan(1);
    });

    it("une confirmation consigne l'exploitant, la personne du client, le canal, l'instant, l'opération, son objet et la pièce, en ajout seul (EX-7.26)", async function () {
      await confirmer(p);
      const lignes = fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const c = lignes[lignes.length - 1];
      expect(c).to.include({ operation: "approvisionnement", personne_client: "Responsable de l'essai", canal: "appel téléphonique au numéro du contrat", instant: "2026-11-11T10:00:00.000Z", piece_sha256: "0x" + "ab".repeat(32), exploitant: X });
      expect(c.objet).to.deep.equal({ org_id: dossierA(p).organisation.org_id, cle_chaine: p.A.cles[0].chaine.adresse });
      expect(c.id).to.match(/^cnf-[0-9a-f]{32}$/);
      expect(c.recu_a).to.match(/^\d{4}-\d{2}-\d{2}T/);
      const inconnu = await a.confirmation(X, { ...c, objet: { org_id: "0x" + "11".repeat(32), cle_chaine: c.objet.cle_chaine }, id: undefined, exploitant: undefined, recu_a: undefined });
      expect(inconnu.accepte).to.equal(false);
    });

    it("pas 2 à 5 : même sortie que l'outil, étapes capturee ou faite, captures écrites", async function () {
      const r = await inscrireClient(p, { confirmation: false });
      memeForme(r.sa, r.sb);
      expect(r.sa.result).to.equal("reussi");
      expect(dossierA(p).steps.slice(0, 4).map((s) => s.state)).to.deep.equal(["capturee", "capturee", "faite", "capturee"]);
      for (const s of dossierA(p).steps.filter((x) => x.capture)) expect(fs.existsSync(path.join(a.client(p.A.slug).captures, s.capture))).to.equal(true);
    });

    it("pas 6 : condensé, refus OP-6 et OP-7, inscription, reprise deja_fait : mêmes sorties que l'outil", async function () {
      const c = await condense(p);
      memeForme(c.sa, c.sb);
      expect(c.sa.result).to.equal("reussi");
      expect(c.demA.signatures).to.deep.equal([]);
      const envois = pont.envoisRecus.length;
      // OP-7 : une seule signature (seuil 2), signataires non rangés, signataire hors du jeu.
      const une = await inscrireCle(p, O.signerDemande(c.demA, [1]), O.signerDemande(c.demB, [1]));
      memeForme(une.sa, une.sb);
      expect(une.sa.error.code).to.equal("signatures_insuffisantes");
      const desordre = (d) => ({ ...d, signatures: [...d.signatures].reverse() });
      const dd = await inscrireCle(p, desordre(O.signerDemande(c.demA, [1, 2])), desordre(O.signerDemande(c.demB, [1, 2])));
      memeForme(dd.sa, dd.sb);
      expect(dd.sa.error.code).to.equal("signature_non_canonique");
      const hors = await inscrireCle(p, O.signerDemande(c.demA, [1, 7]), O.signerDemande(c.demB, [1, 7]));
      memeForme(hors.sa, hors.sb);
      expect(hors.sa.error.code).to.equal("signataire_hors_jeu");
      // OP-6 : demande altérée après la signature.
      const altere = (d) => ({ ...d, digest: "0x" + "00".repeat(31) + "01" });
      const al = await inscrireCle(p, altere(O.signerDemande(c.demA, [1, 2])), altere(O.signerDemande(c.demB, [1, 2])));
      memeForme(al.sa, al.sb);
      expect(al.sa.error.code).to.equal("condense_different");
      expect(pont.envoisRecus.length, "aucun envoi sur un refus préalable").to.equal(envois);
      // Inscription, puis relance : deja_fait sans nouvel envoi (EX-7.13).
      const ok = await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
      memeForme(ok.sa, ok.sb);
      expect(ok.sa.result).to.equal("reussi");
      const envois2 = pont.envoisRecus.length;
      const bis = await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
      memeForme(bis.sa, bis.sb);
      expect(bis.sa.result).to.equal("deja_fait");
      expect(pont.envoisRecus.length).to.equal(envois2);
    });

    it("relance des pas 2 à 5 sur un dossier avancé : deja_fait, rien d'envoyé, comme l'outil", async function () {
      const envois = pont.envoisRecus.length;
      const r = await inscrireClient(p, { confirmation: false });
      memeForme(r.sa, r.sb);
      expect(r.sa.result).to.equal("deja_fait");
      expect(pont.envoisRecus.length).to.equal(envois);
    });

    it("approvisionner (8.7) : clé au-dessus du seuil (deja_fait), destinataire hors d'EX-8.20 (compte_inattendu), comme l'outil", async function () {
      await confirmer(p, "approvisionner");
      let t = await agent({ commande: "approvisionner", slug: p.A.slug, parametres: { cle_chaine: p.A.cles[0].chaine.adresse } });
      let sb = await outil(["approvisionner", "--vers", p.B.cles[0].chaine.adresse, "--dossier", p.B.dossier, "--tresorerie", "hardhat:0", "--captures", p.B.captures]);
      memeForme(t.sortie, sb);
      expect(t.sortie.result).to.equal("deja_fait");
      const autre = O.compteHardhat(9).adresse;
      const dA = dossierA(p);
      await a.confirmation(X, { operation: "approvisionner", objet: { org_id: dA.organisation.org_id, cle_chaine: autre }, personne_client: "Responsable de l'essai", canal: "courrier signé", instant: "2026-11-11T10:00:00.000Z", piece_sha256: "0x" + "cd".repeat(32) });
      t = await agent({ commande: "approvisionner", slug: p.A.slug, parametres: { cle_chaine: autre } });
      sb = await outil(["approvisionner", "--vers", autre, "--dossier", p.B.dossier, "--tresorerie", "hardhat:0", "--captures", p.B.captures]);
      memeForme(t.sortie, sb);
      expect(t.sortie.error.code).to.equal("compte_inattendu");
    });

    it("approvisionner une clé neuve du dossier : versement capturé, même sortie que l'outil", async function () {
      const q = paire("verse");
      await preparer(q);
      await confirmer(q, "approvisionner");
      const t = await agent({ commande: "approvisionner", slug: q.A.slug, parametres: { cle_chaine: q.A.cles[0].chaine.adresse } });
      const sb = await outil(["approvisionner", "--vers", q.B.cles[0].chaine.adresse, "--dossier", q.B.dossier, "--tresorerie", "hardhat:0", "--captures", q.B.captures]);
      memeForme(t.sortie, sb);
      expect(t.sortie.result).to.equal("reussi");
      expect(dossierA(q).steps.find((s) => s.step === "approvisionnement").state).to.equal("capturee");
    });

    it("une confirmation hors bande n'autorise qu'un approvisionnement : consommée par le versement, un second approvisionner de la même clé est refusé (relecture R4)", async function () {
      const q = paire("unique");
      await preparer(q);
      await confirmer(q, "approvisionner");
      const cle = q.A.cles[0].chaine.adresse;
      const t1 = await agent({ commande: "approvisionner", slug: q.A.slug, parametres: { cle_chaine: cle } });
      expect(t1.sortie.result, JSON.stringify(t1.sortie.error)).to.equal("reussi");
      const lignes = () => fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      const conf = lignes().filter((l) => l.objet?.cle_chaine === cle);
      expect(conf.length).to.equal(1);
      const consommations = lignes().filter((l) => l.consommation === conf[0].id);
      expect(consommations.length, "une ligne de consommation, en ajout seul").to.equal(1);
      expect(consommations[0]).to.include({ travail: t1.id, org_id: dossierA(q).organisation.org_id, cle_chaine: cle });
      // La même confirmation ne sert pas une seconde fois : refus à la remise, rien n'est envoyé, aucune sortie.
      const envois = pont.envoisRecus.length;
      const r = await a.travail(X, { commande: "approvisionner", slug: q.A.slug, parametres: { cle_chaine: cle } });
      expect(r).to.deep.include({ accepte: false, code: "confirmation_absente" });
      expect(pont.envoisRecus.length).to.equal(envois);
      // Une nouvelle confirmation : admis ; la clé est au-dessus du seuil, rien n'est versé, la confirmation n'est pas consommée.
      await confirmer(q, "approvisionner");
      const t2 = await agent({ commande: "approvisionner", slug: q.A.slug, parametres: { cle_chaine: cle } });
      expect(t2.sortie.result).to.equal("deja_fait");
      expect(lignes().filter((l) => l.consommation && l.cle_chaine === cle).length).to.equal(1);
      expect(pont.envoisRecus.length).to.equal(envois);
    });

    it("capturer une transaction incluse (8.6) : même sortie que l'outil, étape capturee", async function () {
      const ta = dossierA(p).steps.find((s) => s.step === "inscription").transaction_hash;
      const tb = dossierB(p).steps.find((s) => s.step === "inscription").transaction_hash;
      const t = await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: ta } });
      const sb = await outil(["capturer", "--transaction", tb, "--role", "inscription", "--dossier", p.B.dossier, "--captures", p.B.captures]);
      memeForme(t.sortie, sb);
      expect(t.sortie.result).to.equal("reussi");
    });

    it("OP-8 : organisation_inconnue avant l'assignation, cle_deja_active et cle_ed25519_active, comme l'outil", async function () {
      const q = paire("op8");
      await preparer(q);
      const c = await condense(q);
      memeForme(c.sa, c.sb);
      expect(c.sa.error.code).to.equal("organisation_inconnue");
      for (const memeCle of ["chaine", "ed25519"]) {
        const r = paire(`op8-${memeCle}`, { cles: 2, memeCle });
        await preparer(r);
        await inscrireClient(r);
        const c1 = await condense(r, 1);
        await inscrireCle(r, O.signerDemande(c1.demA, [1, 2]), O.signerDemande(c1.demB, [1, 2]), 1);
        const c2 = await condense(r, 2);
        const s = await inscrireCle(r, O.signerDemande(c2.demA, [1, 2]), O.signerDemande(c2.demB, [1, 2]), 2);
        memeForme(s.sa, s.sb);
        expect(s.sa.error.code).to.equal(memeCle === "chaine" ? "cle_deja_active" : "cle_ed25519_active");
      }
    });
  });

  describe("administration du jeu : condense-administration et administrer-jeu (CT-4 §8.5, EX-7.26, EX-8.21)", function () {
    it("demande préparée et relayée après confirmation hors bande, mêmes sorties que l'outil ; sans confirmation rien n'est envoyé ; la confirmation ne sert qu'une fois", async function () {
      const p = paire("admin");
      await preparer(p);
      await inscrireClient(p);
      const setA = dossierA(p).steps.find((s) => s.step === "jeu_approbateurs").contract;
      const setB = dossierB(p).steps.find((s) => s.step === "jeu_approbateurs").contract;
      const membre = O.compteHardhat(5).adresse;
      // Préparation (condense administration_jeu).
      const ca = await agent({ commande: "condense-administration", slug: p.A.slug, parametres: { op: "CuratorSet.addCurator", arg: membre } });
      const fb = path.join(dir, `${p.B.slug}-administration.json`);
      const cb = await outil(["condense", "administration_jeu", "--jeu", setB, "--op", "CuratorSet.addCurator", "--arg", membre, "--sortie", fb]);
      memeForme(ca.sortie, cb);
      expect(ca.sortie.result, JSON.stringify(ca.sortie.error)).to.equal("reussi");
      const demA = JSON.parse(fs.readFileSync(ca.sortie.outputs.demande, "utf8"));
      expect(demA).to.deep.include({ operation: "administration_jeu", contract: setA, signatures: [] });
      expect({ ...demA.fields, arg: null }).to.deep.equal({ ...JSON.parse(fs.readFileSync(fb, "utf8")).fields, arg: null });
      // L'administrateur du jeu (compte 4) signe hors de l'application ; une signature d'un autre compte (5) aussi, pour le refus.
      const bonneA = O.signerDemande(demA, [4]);
      const mauvaiseA = O.signerDemande(demA, [5]);
      const bonneB = O.signerDemande(JSON.parse(fs.readFileSync(fb, "utf8")), [4]);
      const mauvaiseB = O.signerDemande(JSON.parse(fs.readFileSync(fb, "utf8")), [5]);
      const ecrire = (nom, d) => {
        const f = path.join(dir, `${p.B.slug}-${nom}.json`);
        fs.writeFileSync(f, JSON.stringify(d));
        return f;
      };
      const relaisB = (d) => outil(["administrer-jeu", "--demande", d, "--captures", p.B.captures, "--relayeur", "hardhat:0", "--delai", "3"]);
      // Sans confirmation : refus confirmation_absente, rien n'est envoyé, aucune sortie (EX-7.26).
      const envois = pont.envoisRecus.length;
      const r = await a.travail(X, { commande: "administrer-jeu", slug: p.A.slug, parametres: { demande: bonneA, relayeur: true } });
      expect(r).to.deep.include({ accepte: false, code: "confirmation_absente" });
      expect(pont.envoisRecus.length).to.equal(envois);
      // Confirmation consignée pour cette demande (objet : son condensé).
      const conf = await a.confirmation(X, { operation: "administrer-jeu", objet: { org_id: dossierA(p).organisation.org_id, digest: demA.digest }, personne_client: "Responsable de l'essai", canal: "courrier signé", instant: "2026-11-11T10:00:00.000Z", piece_sha256: "0x" + "ad".repeat(32) });
      expect(conf.accepte, JSON.stringify(conf)).to.equal(true);
      // Signataire qui n'est pas l'administrateur : pas_administrateur (OP-5), comme l'outil ; la confirmation n'est pas consommée.
      let t = await agent({ commande: "administrer-jeu", slug: p.A.slug, parametres: { demande: mauvaiseA, relayeur: true } });
      let sb = await relaisB(ecrire("mauvaise", mauvaiseB));
      memeForme(t.sortie, sb);
      expect(t.sortie.error).to.deep.include({ code: "pas_administrateur", check: "OP-5" });
      expect(pont.envoisRecus.length).to.equal(envois);
      // Demande signée par l'administrateur : relayée, capturée, même sortie que l'outil.
      t = await agent({ commande: "administrer-jeu", slug: p.A.slug, parametres: { demande: bonneA, relayeur: true } });
      sb = await relaisB(ecrire("bonne", bonneB));
      memeForme(t.sortie, sb);
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      expect(t.sortie.outputs.operation).to.equal("CuratorSet.addCurator");
      expect(fs.existsSync(path.join(a.client(p.A.slug).captures, t.sortie.outputs.capture))).to.equal(true);
      expect(t.sortie.outputs.capture).to.match(/-administration_jeu\.json$/);
      const lignes = fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes.filter((l) => l.consommation === conf.id).map((l) => l.travail)).to.deep.equal([t.id]);
      // La même confirmation ne sert pas deux fois ; avec une nouvelle, le relais d'une demande consommée rend le refus de l'outil.
      const r2 = await a.travail(X, { commande: "administrer-jeu", slug: p.A.slug, parametres: { demande: bonneA, relayeur: true } });
      expect(r2).to.deep.include({ accepte: false, code: "confirmation_absente" });
      await a.confirmation(X, { operation: "administrer-jeu", objet: { org_id: dossierA(p).organisation.org_id, digest: demA.digest }, personne_client: "Responsable de l'essai", canal: "courrier signé", instant: "2026-11-11T10:05:00.000Z", piece_sha256: "0x" + "ae".repeat(32) });
      const envois2 = pont.envoisRecus.length;
      t = await agent({ commande: "administrer-jeu", slug: p.A.slug, parametres: { demande: bonneA, relayeur: true } });
      sb = await relaisB(ecrire("bonne", bonneB));
      memeForme(t.sortie, sb);
      expect(t.sortie.error).to.deep.include({ code: "pas_administrateur", check: "OP-5" });
      expect(pont.envoisRecus.length).to.equal(envois2);
    });

    it("setThreshold, removeCurator, proposeAdmin puis acceptAdmin, envoyées par une clé désignée (expediteur) ou par le relayeur : mêmes sorties que l'outil à chaque opération, état du jeu relu égal des deux côtés ; acceptAdmin signée par l'ancien administrateur : pas_administrateur, comme l'outil", async function () {
      const p = paire("admin-ops");
      await preparer(p);
      await inscrireClient(p);
      const setA = dossierA(p).steps.find((s) => s.step === "jeu_approbateurs").contract;
      const setB = dossierB(p).steps.find((s) => s.step === "jeu_approbateurs").contract;
      const orgA = dossierA(p).organisation.org_id;
      const appel = async (set, donnees) => reseau.provider.request({ method: "eth_call", params: [{ to: set, data: donnees }, "latest"] });
      const mot = (hex) => BigInt("0x" + hex.slice(2, 66));
      const etatJeu = async (set) => ({
        admin: "0x" + (await appel(set, SEL_JEU.admin)).slice(26, 66),
        pendingAdmin: "0x" + (await appel(set, SEL_JEU.pendingAdmin)).slice(26, 66),
        seuil: mot(await appel(set, SEL_JEU.getThreshold)),
        membres: mot(await appel(set, SEL_JEU.getCuratorCount)),
        nonce: mot(await appel(set, SEL_JEU.opNonce)),
      });
      let n = 0;
      /** Une opération des deux côtés : condense, signature hors de l'application, confirmation (agent), relais ou expéditeur désigné. */
      const operation = async (op, arg, signataire, envoi) => {
        n += 1;
        const ca = await agent({ commande: "condense-administration", slug: p.A.slug, parametres: arg === null ? { op } : { op, arg } });
        const fb = path.join(dir, `${p.B.slug}-administration-${n}.json`);
        const cb = await outil(["condense", "administration_jeu", "--jeu", setB, "--op", op, ...(arg === null ? [] : ["--arg", String(arg)]), "--sortie", fb]);
        memeForme(ca.sortie, cb);
        expect(ca.sortie.result, `${op} : ${JSON.stringify(ca.sortie.error)}`).to.equal("reussi");
        expect(cb.result, `${op} (outil) : ${JSON.stringify(cb.error)}`).to.equal("reussi");
        const demA = O.signerDemande(JSON.parse(fs.readFileSync(ca.sortie.outputs.demande, "utf8")), [signataire]);
        const demB = O.signerDemande(JSON.parse(fs.readFileSync(fb, "utf8")), [signataire]);
        expect({ ...demA.fields, nonce: null }).to.deep.equal({ ...demB.fields, nonce: null });
        const fbs = path.join(dir, `${p.B.slug}-administration-${n}-signee.json`);
        fs.writeFileSync(fbs, JSON.stringify(demB));
        const conf = await a.confirmation(X, { operation: "administrer-jeu", objet: { org_id: orgA, digest: demA.digest }, personne_client: "Responsable de l'essai", canal: "courrier signé", instant: "2026-11-11T11:00:00.000Z", piece_sha256: "0x" + "ac".repeat(32) });
        expect(conf.accepte, JSON.stringify(conf)).to.equal(true);
        const t = await agent({ commande: "administrer-jeu", slug: p.A.slug, parametres: envoi === "relayeur" ? { demande: demA, relayeur: true } : { demande: demA, expediteur: envoi } });
        const sb = await outil(["administrer-jeu", "--demande", fbs, "--captures", p.B.captures, ...(envoi === "relayeur" ? ["--relayeur", "hardhat:0"] : ["--expediteur", envoi]), "--delai", "3"]);
        memeForme(t.sortie, sb);
        expect(t.sortie.checks.map((x) => `${x.id}:${x.status}`), op).to.deep.equal(sb.checks.map((x) => `${x.id}:${x.status}`));
        return { t, sb };
      };
      const membre3 = O.compteHardhat(3).adresse;
      const nouveau = O.compteHardhat(5).adresse;
      // Seuil abaissé d'abord (removeCurator refuse de laisser le seuil au-dessus du nombre de membres, EX-8.10).
      let r = await operation("CuratorSet.setThreshold", 1, 4, "hardhat:6");
      expect(r.t.sortie.result, JSON.stringify(r.t.sortie.error)).to.equal("reussi");
      expect(r.t.sortie.outputs.operation).to.equal("CuratorSet.setThreshold");
      r = await operation("CuratorSet.removeCurator", membre3, 4, "relayeur");
      expect(r.t.sortie.result, JSON.stringify(r.t.sortie.error)).to.equal("reussi");
      r = await operation("CuratorSet.proposeAdmin", nouveau, 4, "hardhat:7");
      expect(r.t.sortie.result, JSON.stringify(r.t.sortie.error)).to.equal("reussi");
      // acceptAdmin signée par l'administrateur en place, et non par l'administrateur proposé : pas_administrateur (OP-5).
      r = await operation("CuratorSet.acceptAdmin", null, 4, "relayeur");
      expect(r.t.sortie.error, JSON.stringify(r.t.sortie)).to.deep.include({ code: "pas_administrateur", check: "OP-5" });
      expect(r.sb.error).to.deep.include({ code: "pas_administrateur", check: "OP-5" });
      r = await operation("CuratorSet.acceptAdmin", null, 5, "relayeur");
      expect(r.t.sortie.result, JSON.stringify(r.t.sortie.error)).to.equal("reussi");
      expect(r.t.sortie.outputs.operation).to.equal("CuratorSet.acceptAdmin");
      const eA = await etatJeu(setA);
      const eB = await etatJeu(setB);
      expect(eA).to.deep.equal(eB);
      expect(eA).to.deep.include({ admin: nouveau.toLowerCase(), seuil: 1n, membres: 2n, nonce: 4n });
      expect(BigInt(eA.pendingAdmin)).to.equal(0n);
    });
  });

  describe("reprise de chaque état d'EX-7.16, jamais un nouvel envoi", function () {
    it("étape envoyee sans reçu : recu_absent, puis transaction_en_attente sans nouvel envoi, puis capturee par le travail capturer, comme l'outil", async function () {
      const p = paire("envoyee");
      await preparer(p);
      await confirmer(p);
      pont.retenir = true;
      this.retablir = () => {
        pont.retenir = false;
      };
      let t = await agent({ commande: "inscrire-client", slug: p.A.slug, parametres: {} });
      let sb = await outil(["inscrire-client", "--dossier", p.B.dossier, "--exploitant", "hardhat:0", "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t.sortie, sb);
      expect(t.sortie.error.code).to.equal("recu_absent");
      expect(dossierA(p).steps[0].state).to.equal("envoyee");
      const hash = dossierA(p).steps[0].transaction_hash;
      const envois = pont.envoisRecus.length;
      t = await agent({ commande: "inscrire-client", slug: p.A.slug, parametres: {} });
      sb = await outil(["inscrire-client", "--dossier", p.B.dossier, "--exploitant", "hardhat:0", "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t.sortie, sb);
      expect(t.sortie).to.deep.include({ result: "refuse" });
      expect(t.sortie.error).to.deep.include({ code: "transaction_en_attente", check: "OP-3" });
      expect(pont.envoisRecus.length, "aucun nouvel envoi").to.equal(envois);
      pont.retenir = false;
      await pont.relacher();
      t = await agent({ commande: "capturer", slug: p.A.slug, parametres: { envoi: hash } });
      const envoiB = fs.readdirSync(p.B.captures).find((n) => n.startsWith("envoi-"));
      sb = await outil(["capturer", "--envoi", path.join(p.B.captures, envoiB), "--dossier", p.B.dossier, "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t.sortie, sb);
      expect(t.sortie.result).to.equal("reussi");
      expect(dossierA(p).steps[0].state).to.equal("capturee");
      expect(pont.envoisRecus.length, "le relâchement n'est pas un nouvel envoi de l'agent").to.equal(envois);
    });

    it("étape incluse sans capture : certificat_indisponible (incertain), puis capture reprise sans nouvel envoi, comme l'outil", async function () {
      const p = paire("incluse");
      await preparer(p);
      await confirmer(p);
      const tete = Number(BigInt(await reseau.provider.request({ method: "eth_blockNumber", params: [] })));
      pont.certificatsIndisponiblesDepuis = tete + 1;
      this.retablir = () => {
        pont.certificatsIndisponiblesDepuis = null;
      };
      const t = await agent({ commande: "inscrire-client", slug: p.A.slug, parametres: {} });
      expect(t.sortie.result).to.equal("incertain");
      expect(t.sortie.error.code).to.equal("certificat_indisponible");
      expect(dossierA(p).steps[0].state).to.equal("incluse");
      const tete2 = Number(BigInt(await reseau.provider.request({ method: "eth_blockNumber", params: [] })));
      pont.certificatsIndisponiblesDepuis = tete2 + 1;
      const sb = await outil(["inscrire-client", "--dossier", p.B.dossier, "--exploitant", "hardhat:0", "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t.sortie, sb);
      expect(dossierB(p).steps[0].state).to.equal("incluse");
      pont.certificatsIndisponiblesDepuis = null;
      const envois = pont.envoisRecus.length;
      const hash = dossierA(p).steps[0].transaction_hash;
      const t2 = await agent({ commande: "inscrire-client", slug: p.A.slug, parametres: {} });
      const sb2 = await outil(["inscrire-client", "--dossier", p.B.dossier, "--exploitant", "hardhat:0", "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t2.sortie, sb2);
      expect(t2.sortie.result).to.equal("reussi");
      expect(dossierA(p).steps[0]).to.deep.include({ state: "capturee", transaction_hash: hash });
      // Les étapes suivantes envoient leurs propres transactions (assignation, approvisionnement), jamais celle du jeu de nouveau.
      expect(pont.envoisRecus.slice(envois).includes(hash)).to.equal(false);
    });

    it("étape echec (transaction incluse à status 0x0) : echoue, puis relance deja_fait sans nouvel envoi, puis capturer --transaction de la transaction qui l'a accomplie la passe à capturee, comme l'outil (EX-7.13, EX-7.16, EX-7.29)", async function () {
      const p = paire("echec");
      await preparer(p);
      await inscrireClient(p);
      const c = await condense(p);
      const demA = O.signerDemande(c.demA, [1, 2]);
      const demB = O.signerDemande(c.demB, [1, 2]);
      // Une transaction concurrente inclut d'abord la même inscription (relayée par un autre expéditeur) : celle qui suit échoue.
      const accomplies = [];
      const concurrente = (dem) => async () => {
        const relayeur = reseau.signataires[9];
        const { encoderRegisterRecorder } = await import("@noortrace/ancrage/registre");
        const donnees = octetsVersHex(encoderRegisterRecorder({ ...dem.fields, signatures: dem.signatures.map((x) => ({ v: x.v, r: x.r, s: x.s })) }));
        const tx = await relayeur.sendTransaction({ to: dem.contract, data: donnees, gasLimit: 3000000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 });
        await tx.wait();
        accomplies.push(tx.hash.toLowerCase());
      };
      pont.avantEnvoi = concurrente(demA);
      const t = await agent({ commande: "inscrire-cle", slug: p.A.slug, parametres: { demande: demA, cle_chaine: p.A.cles[0].chaine.reference } });
      expect(t.sortie, JSON.stringify(t)).to.be.an("object");
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("echoue");
      expect(t.sortie.exit_code).to.equal(1);
      expect(t.sortie.error).to.deep.include({ code: "transaction_annulee", check: "OP-11" });
      const e = dossierA(p).steps.find((s) => s.step === "inscription");
      expect(e.state).to.equal("echec");
      expect(e.error.code).to.equal("transaction_annulee");
      const fb = path.join(dir, `${p.B.slug}-demande-echec.json`);
      fs.writeFileSync(fb, JSON.stringify(demB));
      pont.avantEnvoi = concurrente(demB);
      const sb = await outil(["inscrire-cle", "--demande", fb, "--cle-chaine", p.B.cles[0].chaine.reference, "--dossier", p.B.dossier, "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t.sortie, sb);
      expect(dossierB(p).steps.find((s) => s.step === "inscription").state).to.equal("echec");
      const envois = pont.envoisRecus.length;
      const t2 = await agent({ commande: "inscrire-cle", slug: p.A.slug, parametres: { demande: demA, cle_chaine: p.A.cles[0].chaine.reference } });
      const sb2 = await outil(["inscrire-cle", "--demande", fb, "--cle-chaine", p.B.cles[0].chaine.reference, "--dossier", p.B.dossier, "--captures", p.B.captures, "--delai", "3"]);
      memeForme(t2.sortie, sb2);
      expect(t2.sortie.result).to.equal("deja_fait");
      expect(pont.envoisRecus.length, "aucun nouvel envoi").to.equal(envois);
      expect(dossierB(p).steps.find((s) => s.step === "inscription").state, "état de l'étape après relance, outil").to.equal(dossierA(p).steps.find((s) => s.step === "inscription").state);
      // L'étape reste `echec` des deux côtés : la relance ne devine pas la transaction qui l'a accomplie (EX-7.29).
      expect(dossierA(p).steps.find((s) => s.step === "inscription").state).to.equal("echec");
      // EX-7.29 : l'exploitant établit la transaction et la donne à capturer --transaction --dossier ; OP-11 et OP-12
      // réussissent sur les valeurs de l'étape, le bloc est capturé, l'étape passe à capturee avec cette transaction.
      const [hA, hB] = accomplies;
      const t3 = await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: hA } });
      const sb3 = await outil(["capturer", "--transaction", hB, "--role", "inscription", "--dossier", p.B.dossier, "--captures", p.B.captures]);
      memeForme(t3.sortie, sb3);
      expect(t3.sortie.result, JSON.stringify(t3.sortie.error)).to.equal("reussi");
      const eA = dossierA(p).steps.find((s) => s.step === "inscription");
      expect(eA).to.deep.include({ state: "capturee", transaction_hash: hA, error: null, capture: t3.sortie.outputs.capture });
      expect(eA.block_number).to.equal(t3.sortie.outputs.block_number);
      expect(t3.sortie.outputs.dossier).to.deep.equal({ step: "inscription", subject: `rec-${p.A.slug}-1`, state: "capturee" });
      expect(dossierB(p).steps.find((s) => s.step === "inscription")).to.deep.include({ state: "capturee", transaction_hash: hB });
      expect(pont.envoisRecus.length, "aucun nouvel envoi").to.equal(envois);
      // Une transaction qui n'accomplit pas l'étape (l'assignation, déjà capturée) ne la change pas.
      const autre = dossierA(p).steps.find((s) => s.step === "assignation").transaction_hash;
      const t4 = await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: autre } });
      expect(t4.sortie.result).to.equal("reussi");
      expect(dossierA(p).steps.find((s) => s.step === "inscription").transaction_hash).to.equal(hA);
    });

    it("étape echec dont la transaction concurrente porte d'autres valeurs : capturer --transaction ne la change pas (EX-7.29)", async function () {
      const p = paire("echec-autre", { cles: 2 });
      await preparer(p);
      await inscrireClient(p);
      // La clé 2 est inscrite par l'agent ; la clé 1 échoue (status 0x0) : une demande dont la signature ne vaut pas.
      const c2 = await condense(p, 2);
      const t2 = await inscrireCle(p, O.signerDemande(c2.demA, [1, 2]), O.signerDemande(c2.demB, [1, 2]), 2);
      expect(t2.sa.result).to.equal("reussi");
      const c1 = await condense(p, 1);
      const demA = O.signerDemande(c1.demA, [1, 2]);
      pont.avantEnvoi = async () => {
        const { encoderRegisterRecorder } = await import("@noortrace/ancrage/registre");
        const donnees = octetsVersHex(encoderRegisterRecorder({ ...demA.fields, signatures: demA.signatures.map((x) => ({ v: x.v, r: x.r, s: x.s })) }));
        await (await reseau.signataires[9].sendTransaction({ to: demA.contract, data: donnees, gasLimit: 3000000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 })).wait();
      };
      const t = await agent({ commande: "inscrire-cle", slug: p.A.slug, parametres: { demande: demA, cle_chaine: p.A.cles[0].chaine.reference } });
      pont.avantEnvoi = null;
      expect(t.sortie.result).to.equal("echoue");
      // La transaction de la clé 2 n'accomplit pas l'étape de la clé 1 : elle reste echec.
      const h2 = dossierA(p).steps.find((s) => s.step === "inscription" && s.subject === `rec-${p.A.slug}-2`).transaction_hash;
      await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: h2 } });
      expect(dossierA(p).steps.find((s) => s.step === "inscription" && s.subject === `rec-${p.A.slug}-1`).state).to.equal("echec");
    });

    it("approvisionnement d'une clé déjà pourvue (solde au moins P_k) : étape faite sans transaction, comme l'outil ; result.recorders[].funding vaut null (EX-7.29)", async function () {
      const p = paire("pourvue");
      await preparer(p);
      for (const cote of [p.A, p.B]) {
        await (await reseau.signataires[8].sendTransaction({ to: cote.cles[0].chaine.adresse, value: 10n ** 18n, gasLimit: 21000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 })).wait();
      }
      const r = await inscrireClient(p);
      memeForme(r.sa, r.sb);
      expect(r.sa.result).to.equal("reussi");
      const eA = dossierA(p).steps.find((s) => s.step === "approvisionnement");
      expect(eA).to.deep.include({ state: "faite", transaction_hash: null, capture: null });
      expect(dossierB(p).steps.find((s) => s.step === "approvisionnement").state).to.equal("faite");
      // La confirmation de l'approvisionnement n'est pas consommée : rien n'a été versé.
      const lignes = fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignes.filter((l) => l.consommation && l.cle_chaine === p.A.cles[0].chaine.adresse)).to.deep.equal([]);
      // result rempli à la fin de l'inscription, funding nul pour cette clé (fonction de complétion, sur un dossier fini).
      const { completerResult } = await import("../paquets/inscription/src/agent/commandes/inscrire-client.mjs");
      const c = await condense(p);
      await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
      const d = dossierA(p);
      for (const e of d.steps) if (e.step === "premiere_ancre" || e.step === "premiere_cloture") Object.assign(e, { state: "faite" });
      const { clientRpc } = await import("../paquets/inscription/src/agent/reseau.mjs");
      const ctx = { client: { lectureJeu: path.join(a.client(p.A.slug).dir, "lecture-jeu.json") }, rpc: clientRpc([pont.url]), instance: {} };
      const result = await completerResult(ctx)(d, "2026-11-11T12:00:00.000Z");
      expect(result, "result rempli").to.be.an("object");
      expect(result.recorders).to.have.length(1);
      expect(result.recorders[0].funding).to.equal(null);
      expect(result.recorders[0].registration.transaction_hash).to.equal(d.steps.find((s) => s.step === "inscription").transaction_hash);
      const { IDS, valider } = await import("../paquets/inscription/src/commun/schemas.mjs");
      expect(valider(IDS.inscription, { ...d, result }).valide, "dossier conforme au schéma révisé").to.equal(true);
    });

    it("EX-7.29, étapes jeu_approbateurs, assignation, premiere_ancre et premiere_cloture : une étape echec dont l'effet est en place passe à capturee par capturer --transaction de la transaction qui l'a accomplie, comme l'outil ; la transaction d'une autre organisation ne la change pas", async function () {
      const p = await inscrit("reprise-etapes");
      // Pas 7 à 9 joués par l'outil (il tient lieu d'enregistreur) sur chaque dossier : première ancre et première clôture.
      const cotes = [
        { cote: p.A, dossier: () => a.client(p.A.slug).dossier, captures: () => a.client(p.A.slug).captures, rep: path.join(dir, `${p.A.slug}-periode`) },
        { cote: p.B, dossier: () => p.B.dossier, captures: () => p.B.captures, rep: path.join(dir, `${p.B.slug}-periode`) },
      ];
      for (const c of cotes) {
        const graine = path.join(dir, `${c.cote.slug}.graine`);
        fs.writeFileSync(graine, Buffer.from(c.cote.cles[0].ed.graine).toString("hex"), { mode: 0o600 });
        const periode = path.join(c.rep, "periode-1");
        expect((await outil(["manifeste-essai", "--dossier", c.dossier(), "--key-id", `rec-${c.cote.slug}-1`, "--graine", `graine:${graine}`, "--sortie", periode])).result).to.equal("reussi");
        expect((await outil(["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", c.cote.cles[0].chaine.reference, "--dossier", c.dossier(), "--captures", c.captures()])).result).to.equal("reussi");
        const demande = path.join(c.rep, "demande-cloture.json");
        expect((await outil(["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", c.captures(), "--sortie", demande])).result).to.equal("reussi");
        for (const i of [1, 2]) expect((await O.outilReference(["signer", "--demande", demande, "--cle", `hardhat:${i}`, ...C()])).sortie.result).to.equal("reussi");
        expect((await outil(["clore", "--demande", demande, "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", c.cote.cles[0].chaine.reference, "--dossier", c.dossier(), "--captures", c.captures()])).result).to.equal("reussi");
      }
      const lire = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
      for (const c of cotes) expect(lire(c.dossier()).steps.every((e) => e.state === "capturee" || e.state === "faite"), c.cote.slug).to.equal(true);
      // Une transaction incluse à status 0x0 (setCuratorSet d'un compte qui n'administre pas le registre) tient lieu de l'envoi en échec.
      const annulee = await reseau.signataires[9].sendTransaction({ to: reseau.contrats.curator_set_registry, data: "0x" + SEL_JEU.setCuratorSet.slice(2) + "00".repeat(64), gasLimit: 300000, maxFeePerGas: 2, maxPriorityFeePerGas: 1 });
      const recuAnnule = await reseau.provider.request({ method: "eth_getTransactionReceipt", params: [annulee.hash] });
      expect(recuAnnule.status).to.equal("0x0");
      /** L'étape passe à echec, sous la transaction annulée, comme après un envoi qui a perdu la course (EX-7.13). */
      const mettreEnEchec = (fichier, step) => {
        const d = lire(fichier);
        const e = d.steps.find((x) => x.step === step);
        const avant = { ...e };
        Object.assign(e, { state: "echec", transaction_hash: annulee.hash.toLowerCase(), block_number: null, block_hash: null, capture: null, error: { code: "transaction_annulee", message: "reçu à status 0x0 (essai d'EX-7.29)" } });
        if (step === "jeu_approbateurs") e.contract = null;
        fs.writeFileSync(fichier, `${JSON.stringify(d, null, 2)}\n`);
        return avant;
      };
      const ROLES = { jeu_approbateurs: "jeu_approbateurs", assignation: "assignation", premiere_ancre: "ancre", premiere_cloture: "cloture" };
      for (const [step, role] of Object.entries(ROLES)) {
        const avantA = mettreEnEchec(cotes[0].dossier(), step);
        const avantB = mettreEnEchec(cotes[1].dossier(), step);
        expect(lire(cotes[0].dossier()).steps.find((x) => x.step === step).state).to.equal("echec");
        // La transaction de la même étape d'une autre organisation (B pour A) ne l'accomplit pas : l'étape reste echec.
        if (step !== "jeu_approbateurs") {
          const t0 = await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: avantB.transaction_hash } });
          expect(t0.sortie.result, `${step} : ${JSON.stringify(t0.sortie.error)}`).to.equal("reussi");
          expect(t0.sortie.outputs.dossier, step).to.equal(null);
          expect(lire(cotes[0].dossier()).steps.find((x) => x.step === step).state, `${step} : autre organisation`).to.equal("echec");
        }
        const envois = pont.envoisRecus.length;
        const t = await agent({ commande: "capturer", slug: p.A.slug, parametres: { transaction: avantA.transaction_hash } });
        const sb = await outil(["capturer", "--transaction", avantB.transaction_hash, "--role", role, "--dossier", cotes[1].dossier(), "--captures", cotes[1].captures()]);
        memeForme(t.sortie, sb);
        expect(t.sortie.result, `${step} : ${JSON.stringify(t.sortie.error)}`).to.equal("reussi");
        expect(sb.result, `${step} (outil) : ${JSON.stringify(sb.error)}`).to.equal("reussi");
        expect(t.sortie.checks.map((x) => `${x.id}:${x.status}`), step).to.deep.equal(sb.checks.map((x) => `${x.id}:${x.status}`));
        expect(t.sortie.outputs.dossier, step).to.deep.equal({ step, subject: avantA.subject, state: "capturee" });
        const eA = lire(cotes[0].dossier()).steps.find((x) => x.step === step);
        const eB = lire(cotes[1].dossier()).steps.find((x) => x.step === step);
        for (const [e, av, cote] of [[eA, avantA, "agent"], [eB, avantB, "outil"]]) {
          expect(e, `${step}, ${cote}`).to.deep.include({ state: "capturee", transaction_hash: av.transaction_hash, block_number: av.block_number, block_hash: av.block_hash, error: null });
          expect(e.capture, `${step}, ${cote}`).to.be.a("string");
          if (step === "jeu_approbateurs") expect(e.contract, `${step}, ${cote} : contrat créé repris`).to.equal(av.contract);
        }
        expect(pont.envoisRecus.length, `${step} : aucun envoi`).to.equal(envois);
      }
      // Les deux dossiers sont de nouveau finis.
      for (const c of cotes) expect(lire(c.dossier()).steps.every((e) => e.state === "capturee" || e.state === "faite"), c.cote.slug).to.equal(true);
    });
  });

  describe("OP-1, OP-2, OP-3 : refus avant tout envoi, comme l'outil", function () {
    it("OP-2 noeud_suiveur et noeud_injoignable, OP-1 jeu_validateurs_different", async function () {
      const p = paire("op12");
      pont.suiveur = true;
      this.retablir = () => {
        pont.suiveur = false;
      };
      let r = await preparer(p);
      pont.suiveur = false;
      memeForme(r.sa, r.sb);
      expect(r.sa.error.code).to.equal("noeud_suiveur");
      // Manifeste d'une autre instance : jeu de validateurs du réseau de développement au lieu du jeu d'essai.
      const autre = path.join(dir, "autre-instance");
      const jeuDev = JSON.parse(fs.readFileSync(path.join(E.RACINE, "test", "fixtures", "certificat-commit", "validators.json"), "utf8"));
      const m2 = E.ecrireManifesteEssai(autre, reseau, { jeu: { validators: jeuDev.validators } });
      const b = await O.demarrerAgentEssai({ manifeste: m2, rpc: pont.url, delai_s: 3 });
      const b2 = await O.demarrerAgentEssai({ manifeste, rpc: "http://127.0.0.1:9", delai_s: 3 });
      try {
        const tr = { commande: "inscrire-client-preparer", slug: "op1-a", parametres: { org: "op1-a", journaux: [JOURNAL], approbateurs: APP(), seuil: 2, admin_jeu: ADMIN(), cles_enregistreur: [p.A.cles[0].doc] } };
        const t = await b.executer(X, tr);
        const sb = (await O.outilReference(["inscrire-client", "--preparer", "--org", "op1-b", "--journal", JOURNAL, "--seuil", "2", "--approbateurs", APP().join(","), "--admin-jeu", ADMIN(), "--cle-enregistreur", p.B.docs[0], "--exploitant", "hardhat:0", "--sortie", path.join(dir, "op1-b.json"), "--instance", m2, "--rpc", pont.url])).sortie;
        memeForme(garder(t.sortie), sb);
        expect(t.sortie.error.code).to.equal("jeu_validateurs_different");
        const t2 = await b2.executer(X, { ...tr, slug: "op2-a", parametres: { ...tr.parametres, org: "op2-a" } });
        const sb2 = (await O.outilReference(["inscrire-client", "--preparer", "--org", "op2-b", "--journal", JOURNAL, "--seuil", "2", "--approbateurs", APP().join(","), "--admin-jeu", ADMIN(), "--cle-enregistreur", p.B.docs[0], "--exploitant", "hardhat:0", "--sortie", path.join(dir, "op2-b.json"), "--instance", manifeste, "--rpc", "http://127.0.0.1:9"])).sortie;
        memeForme(garder(t2.sortie), sb2);
        expect(t2.sortie.error.code).to.equal("noeud_injoignable");
      } finally {
        await b.arreter();
        await b2.arreter();
      }
    });

    it("OP-3 transaction_en_attente : un envoi sans issue de la même clé arrête l'inscription de la clé, comme l'outil", async function () {
      const p = paire("op3");
      await preparer(p);
      await inscrireClient(p);
      const c = await condense(p);
      pont.retenir = true;
      this.retablir = async () => {
        pont.retenir = false;
        await pont.relacher();
      };
      const premier = await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
      memeForme(premier.sa, premier.sb);
      expect(premier.sa.error.code).to.equal("recu_absent");
      const envois = pont.envoisRecus.length;
      const second = await inscrireCle(p, O.signerDemande(c.demA, [1, 2]), O.signerDemande(c.demB, [1, 2]));
      memeForme(second.sa, second.sb);
      expect(second.sa.error).to.deep.include({ code: "transaction_en_attente", check: "OP-3" });
      expect(pont.envoisRecus.length).to.equal(envois);
      pont.retenir = false;
      await pont.relacher();
    });
  });

  describe("prise locale et compte du pair (EX-7.28)", function () {
    it("connexion admise qui n'envoie aucune ligne : fermée par l'agent en moins de 11 s (relecture R6)", async function () {
      const debut = Date.now();
      const s = net.createConnection(a.prise);
      s.on("error", () => {});
      const fin = await new Promise((ok) => {
        const garde = setTimeout(() => ok("encore ouverte"), 13000);
        s.on("close", () => {
          clearTimeout(garde);
          ok("fermee");
        });
      });
      s.destroy();
      expect(fin).to.equal("fermee");
      expect(Date.now() - debut).to.be.below(11000);
      // Une ligne à moitié écrite ne garde pas non plus la connexion.
      const s2 = net.createConnection(a.prise);
      s2.on("error", () => {});
      s2.write('{"version":0,');
      const fin2 = await new Promise((ok) => {
        const garde = setTimeout(() => ok("encore ouverte"), 13000);
        s2.on("close", () => {
          clearTimeout(garde);
          ok("fermee");
        });
      });
      s2.destroy();
      expect(fin2).to.equal("fermee");
    });

    it("connexions simultanées : au plus quatre auxiliaires python3 à la fois, chaque connexion servie (relecture R6)", async function () {
      const outils = O.repertoireTemporaire("noortrace-inscription-python-");
      const journal = path.join(outils, "auxiliaires.log");
      const reel = ["/usr/bin/python3", "/usr/local/bin/python3", "/bin/python3"].find((x) => fs.existsSync(x));
      if (!reel) return enAttente(this, "python3 introuvable");
      // Auxiliaire témoin : consigne son entrée et sa sortie, retient 300 ms, puis lance le vrai python3 (descripteur 3 hérité).
      fs.writeFileSync(path.join(outils, "python3"), `#!/bin/sh\necho "+" >> "${journal}"\nsleep 0.3\n"${reel}" "$@"\nc=$?\necho "-" >> "${journal}"\nexit $c\n`, { mode: 0o755 });
      const b = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, env: { PATH: `${outils}:${process.env.PATH}` } });
      try {
        const reponses = await Promise.all(Array.from({ length: 16 }, () => b.remettre({ version: 0, kind: "inconnu" })));
        for (const r of reponses) expect(r).to.deep.include({ accepte: false, code: "requete_invalide" });
        let n = 0;
        let max = 0;
        for (const l of fs.readFileSync(journal, "utf8").split("\n").filter(Boolean)) {
          n += l === "+" ? 1 : -1;
          max = Math.max(max, n);
        }
        expect(max, "auxiliaires simultanés").to.be.at.most(4);
        expect(fs.readFileSync(journal, "utf8").split("\n").filter((l) => l === "+").length).to.equal(16);
      } finally {
        await b.arreter();
        fs.rmSync(b.base, { recursive: true, force: true });
        fs.rmSync(outils, { recursive: true, force: true });
      }
    });

    it("requête de plus de 65 536 octets : refusée (requete_invalide), consignée, rien n'est exécuté", async function () {
      const travauxAvant = fs.readdirSync(path.join(a.donnees, "travaux")).length;
      const grand = { version: 0, kind: "travail", exploitant: X, travail: { commande: "inscrire-client", slug: "pas-a", parametres: { bourrage: "x".repeat(70000) } } };
      const r = await a.remettre(grand);
      expect(r).to.deep.include({ accepte: false, code: "requete_invalide" });
      expect(r.message).to.match(/65536/);
      expect(fs.readdirSync(path.join(a.donnees, "travaux")).length).to.equal(travauxAvant);
      expect(a.journal().some((l) => l.evenement === "requete_refusee" && l.motif === "taille")).to.equal(true);
    });

    it("requêtes hors forme : JSON non strict, kind inconnu, membre inconnu, identité hors forme", async function () {
      const brut = (texte) => new Promise((resolve) => {
        const s = net.createConnection(a.prise, () => s.write(texte));
        let t = "";
        s.on("data", (d) => (t += d));
        s.on("close", () => resolve(t));
      });
      expect(JSON.parse(await brut('{"version":0,"version":0,"kind":"travail"}\n'))).to.deep.include({ accepte: false, code: "requete_invalide" });
      expect(await a.remettre({ version: 0, kind: "etat" })).to.deep.include({ accepte: false, code: "requete_invalide" });
      expect(await a.remettre({ version: 0, kind: "travail", exploitant: X, travail: { commande: "inscrire-client", slug: "pas-a", parametres: {} }, cle: "x" })).to.deep.include({ accepte: false, code: "requete_invalide" });
      expect(await a.remettre({ version: 0, kind: "travail", exploitant: "operateur", travail: { commande: "inscrire-client", slug: "pas-a", parametres: {} } })).to.deep.include({ accepte: false, code: "requete_invalide" });
      expect(await a.remettre({ version: 0, kind: "travail", exploitant: X, travail: { commande: "inscrire-client", slug: "client-absent", parametres: {} } })).to.deep.include({ accepte: false, code: "client_inconnu" });
    });

    it("pair d'un autre compte que celui de l'interface : connexion fermée avant toute lecture, refus consigné, rien n'est exécuté (second compte)", async function () {
      if (process.getuid() !== 0) return enAttente(this, "l'essai sous un second compte exige le superutilisateur");
      // Un compte système non privilégié qui est le seul membre de son groupe principal (EX-7.28 : le groupe de la
      // prise n'a pour membre que le compte de l'interface).
      const groupes = new Map();
      for (const l of fs.readFileSync("/etc/group", "utf8").split("\n")) {
        const q = l.split(":");
        if (q.length >= 4) groupes.set(Number(q[2]), new Set(q[3].split(",").filter(Boolean)));
      }
      const comptes = fs.readFileSync("/etc/passwd", "utf8").split("\n").map((l) => l.split(":")).filter((q) => q.length >= 4).map((q) => ({ nom: q[0], uid: Number(q[2]), gid: Number(q[3]) }));
      for (const c of comptes) if (groupes.has(c.gid)) groupes.get(c.gid).add(c.nom);
      const second = comptes.find((c) => c.uid !== 0 && c.gid !== 0 && groupes.get(c.gid)?.size === 1 && groupes.get(c.gid).has(c.nom));
      if (!second) return enAttente(this, "aucun compte système seul membre de son groupe principal sur ce poste");
      const nobody = second.uid;
      const groupeInterface = second.gid;
      // Agent sous le compte de l'essai (superutilisateur), interface déclarée : le second compte, seul membre de son groupe.
      const base = O.repertoireTemporaire();
      const prises = path.join(base, "prise");
      const donnees = path.join(base, "donnees");
      fs.mkdirSync(prises);
      fs.chmodSync(prises, 0o750);
      fs.chownSync(prises, 0, groupeInterface);
      fs.mkdirSync(donnees);
      fs.chmodSync(donnees, 0o750);
      fs.chmodSync(base, 0o755);
      const config = { version: 0, prise: path.join(prises, "agent.sock"), interface_uid: nobody, donnees, nature: "developpement", instance: manifeste, rpc: [pont.url], jeton: null, comptes: { exploitant: "hardhat:0" }, delai_s: 3 };
      const chemin = path.join(base, "agent.json");
      fs.writeFileSync(chemin, JSON.stringify(config));
      const lance = await O.lancerAgent(chemin);
      expect(lance.pret, typeof lance.stderr === "function" ? lance.stderr() : lance.stderr).to.be.an("object");
      try {
        expect(fs.statSync(config.prise).gid).to.equal(groupeInterface);
        // 1. Le superutilisateur (compte 0) n'est pas le compte de l'interface : fermé, consigné.
        const requete = JSON.stringify({ version: 0, kind: "confirmation", exploitant: X, confirmation: {} }) + "\n";
        const reponse = await new Promise((resolve) => {
          const s = net.createConnection(config.prise, () => s.write(requete));
          let t = "";
          s.on("data", (d) => (t += d));
          s.on("error", () => {});
          s.on("close", () => resolve(t));
        });
        expect(reponse).to.equal("");
        await new Promise((ok) => setTimeout(ok, 200));
        const journal = fs.readFileSync(path.join(donnees, "journal-agent.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
        const refus = journal.filter((l) => l.evenement === "pair_refuse");
        expect(refus).to.have.length(1);
        expect(refus[0]).to.include({ uid: 0, octets_lus: 0 });
        expect(refus[0].instant).to.match(/^\d{4}-\d{2}-\d{2}T/);
        expect(fs.existsSync(path.join(donnees, "confirmations.ndjson"))).to.equal(false);
        // 2. Le compte de l'interface est admis et reçoit une réponse.
        const script = `const s=require("net").createConnection(${JSON.stringify(config.prise)},()=>s.write(${JSON.stringify(JSON.stringify({ version: 0, kind: "etat" }) + "\n")}));let t="";s.on("data",d=>t+=d);s.on("close",()=>process.stdout.write(t));`;
        const sortie = await new Promise((resolve) => {
          const c = spawn(process.execPath, ["-e", script], { uid: nobody, gid: groupeInterface, stdio: ["ignore", "pipe", "pipe"] });
          let t = "";
          c.stdout.on("data", (d) => (t += d));
          c.on("close", () => resolve(t));
        });
        expect(JSON.parse(sortie)).to.deep.include({ accepte: false, code: "requete_invalide" });
      } finally {
        lance.processus.kill("SIGTERM");
        await new Promise((ok) => lance.processus.once("exit", ok));
        fs.rmSync(base, { recursive: true, force: true });
      }
    });

    it("démarrage refusé : répertoire de la prise hors de 0750, groupe avec un autre membre, prise d'un autre type (EX-7.28)", async function () {
      const base = O.repertoireTemporaire();
      try {
        const prises = path.join(base, "prise");
        const donnees = path.join(base, "donnees");
        fs.mkdirSync(prises);
        fs.mkdirSync(donnees);
        fs.chmodSync(donnees, 0o750);
        const config = { version: 0, prise: path.join(prises, "agent.sock"), interface_uid: process.getuid(), donnees, nature: "developpement", instance: manifeste, rpc: [pont.url], jeton: null, comptes: {}, delai_s: 3 };
        const chemin = path.join(base, "agent.json");
        fs.chmodSync(prises, 0o770);
        fs.writeFileSync(chemin, JSON.stringify(config));
        let r = await O.lancerAgent(chemin);
        expect(r.code).to.equal(2);
        expect(r.stderr).to.match(/0750/);
        fs.chmodSync(prises, 0o750);
        fs.writeFileSync(config.prise, "pas une prise");
        r = await O.lancerAgent(chemin);
        expect(r.code).to.equal(2);
        expect(r.stderr).to.match(/n'est pas une prise/);
      } finally {
        fs.rmSync(base, { recursive: true, force: true });
      }
    });
  });

  describe("références de clés (EX-7.3, EX-7.25)", function () {
    it("une valeur nue dans un champ de référence est refusée sans être gardée ni consignée", async function () {
      const p = paire("nue");
      await preparer(p);
      const secret = crypto.randomBytes(32).toString("hex");
      const valeurs = [secret, `0x${secret}`, "test test test test test test test test test test test junk", `fichier:${secret}`];
      for (const v of valeurs) {
        const r = await a.travail(X, { commande: "inscrire-cle", slug: p.A.slug, parametres: { demande: {}, cle_chaine: v } });
        expect(r, v.slice(0, 12)).to.deep.include({ accepte: false, code: "reference_refusee" });
        expect(r.message).to.not.contain(secret);
        const t = await a.travail(X, { commande: "inscrire-client-preparer", slug: "nue-x", parametres: { org: "nue-x", journaux: [JOURNAL], approbateurs: APP(), seuil: 2, admin_jeu: ADMIN(), cles_enregistreur: [], tresorerie: v } });
        expect(t.accepte).to.equal(false);
      }
      const journal = fs.readFileSync(path.join(a.donnees, "journal-agent.ndjson"), "utf8");
      expect(journal).to.not.contain(secret);
      expect(journal).to.not.contain("junk");
      for (const f of fs.readdirSync(path.join(a.donnees, "travaux"))) expect(fs.readFileSync(path.join(a.donnees, "travaux", f), "utf8")).to.not.contain(secret);
    });

    it("références de test refusées en production : l'agent ne démarre pas, un travail qui en porte une est refusé (EX-7.3, EX-7.24)", async function () {
      const production = path.join(E.RACINE, "spec", "vecteurs", "ct-4", "manifestes", "valides", "production", "instance-r1.json");
      const refuse = await (async () => {
        const base = O.repertoireTemporaire();
        try {
          const prises = path.join(base, "prise");
          const donnees = path.join(base, "donnees");
          fs.mkdirSync(prises);
          fs.chmodSync(prises, 0o750);
          fs.mkdirSync(donnees);
          fs.chmodSync(donnees, 0o750);
          const chemin = path.join(base, "agent.json");
          fs.writeFileSync(chemin, JSON.stringify({ version: 0, prise: path.join(prises, "agent.sock"), interface_uid: process.getuid(), donnees, nature: "production", instance: production, rpc: ["https://rpc.noortrace.example"], jeton: null, comptes: { tresorerie: "hardhat:0" }, delai_s: 3 }));
          return await O.lancerAgent(chemin);
        } finally {
          fs.rmSync(base, { recursive: true, force: true });
        }
      })();
      expect(refuse.code).to.equal(2);
      expect(refuse.stderr).to.match(/EX-7\.3/);
      const b = await O.demarrerAgentEssai({ manifeste: production, rpc: "https://rpc.noortrace.example", nature: "production", comptes: {} });
      try {
        const doc = O.documentCle({ keyId: "rec-prod-1", journalId: JID, chainKey: O.compteHardhat(5).adresse, publique: O.cleEd25519("prod").publique });
        const slug = `o-${"ab".repeat(16)}`;
        let r = await b.travail(X, { commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], seuil: 2, approbateurs: APP(), admin_jeu: ADMIN(), cles_enregistreur: [doc], tresorerie: "hardhat:0" } });
        expect(r).to.deep.include({ accepte: false, code: "reference_refusee" });
        r = await b.travail(X, { commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], seuil: 2, cles_essai: "/nulle/part/cles-essai.json" } });
        expect(r).to.deep.include({ accepte: false, code: "reference_refusee" });
        r = await b.travail(X, { commande: "inscrire-client-preparer", slug: "lisible", parametres: { org: "lisible", journaux: [JOURNAL], seuil: 2, approbateurs: APP(), admin_jeu: ADMIN(), cles_enregistreur: [doc] } });
        expect(r).to.deep.include({ accepte: false, code: "requete_invalide" });
      } finally {
        await b.arreter();
      }
    });
  });

  describe("sorties de l'agent", function () {
    it("chaque sortie produite est conforme à operations-registre-v0#/$defs/sortie, enregistrée dans sorties/<id>.json et rattachée à son travail", function () {
      expect(sorties.length).to.be.greaterThan(30);
      for (const s of sorties) {
        const v = REGISTRE_SCHEMAS.valider(SORTIE, s);
        expect(v.valide, JSON.stringify(v.erreurs)).to.equal(true);
      }
      let n = 0;
      for (const slug of fs.readdirSync(path.join(a.donnees, "clients"))) {
        const d = path.join(a.donnees, "clients", slug, "sorties");
        if (!fs.existsSync(d)) continue;
        for (const f of fs.readdirSync(d)) {
          const id = f.replace(/\.json$/, "");
          const t = JSON.parse(fs.readFileSync(path.join(a.donnees, "travaux", `${id}.json`), "utf8"));
          expect(t).to.include({ id, slug, etat: "fini", exploitant: X });
          expect(t.sortie).to.deep.equal(JSON.parse(fs.readFileSync(path.join(d, f), "utf8")));
          n++;
        }
      }
      expect(n).to.be.greaterThan(30);
      const journal = a.journal();
      expect(journal.filter((l) => l.evenement === "travail_recu").every((l) => l.exploitant === X)).to.equal(true);
    });
  });
});

describe("inscription : transport JSON-RPC de l'agent, réponse lue par morceaux et bornée (CT-4 EX-7.1)", function () {
  this.timeout(120000);
  const MIO = 1024 * 1024;

  /** Point JSON-RPC hostile : 200, puis `total` octets envoyés au rythme de la prise, sans jamais finir le corps. */
  const pointHostile = ({ total = 64 * MIO, longueur = null } = {}) => new Promise((ok) => {
    const etat = { ecrits: 0, ferme: false };
    const serveur = http.createServer((req, res) => {
      req.resume();
      res.writeHead(200, { "content-type": "application/json", ...(longueur === null ? {} : { "content-length": String(longueur) }) });
      const bloc = Buffer.alloc(64 * 1024, 0x20);
      const pousser = () => {
        while (!etat.ferme && etat.ecrits < total) {
          etat.ecrits += bloc.length;
          if (!res.write(bloc)) return res.once("drain", pousser);
        }
        return undefined;
      };
      res.on("close", () => {
        etat.ferme = true;
      });
      pousser();
    });
    serveur.listen(0, "127.0.0.1", () => ok({ url: `http://127.0.0.1:${serveur.address().port}`, etat, fermer: () => new Promise((f) => { serveur.closeAllConnections(); serveur.close(() => f()); }) }));
  });

  it("corps sans fin au-delà de la borne : refus noeud_injoignable dès la borne franchie, avant le délai, sans tout lire (relecture R2)", async function () {
    const { transportAvecJeton } = await import("../paquets/inscription/src/agent/reseau.mjs");
    const { ErreurRpc } = await import("@noortrace/ancrage/registre");
    const p = await pointHostile();
    try {
      const envoyer = transportAvecJeton(null);
      let pic = process.memoryUsage().arrayBuffers;
      const base = pic;
      const sonde = setInterval(() => {
        pic = Math.max(pic, process.memoryUsage().arrayBuffers);
      }, 5);
      const debut = Date.now();
      let erreur = null;
      try {
        await envoyer({ url: p.url, octets: Buffer.from('{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'), delaiMs: 20000, tailleMax: MIO });
      } catch (e) {
        erreur = e;
      }
      clearInterval(sonde);
      const duree = Date.now() - debut;
      expect(erreur, "refus attendu").to.be.instanceOf(ErreurRpc);
      expect(erreur.code).to.equal("noeud_injoignable");
      expect(erreur.message).to.match(/au-delà de 1048576 octets/);
      expect(duree, "refus dès la borne, bien avant le délai de 20 s").to.be.below(5000);
      await new Promise((ok) => setTimeout(ok, 200));
      expect(p.etat.ferme, "la connexion est fermée par l'agent").to.equal(true);
      expect(p.etat.ecrits, "octets envoyés par le point avant la fermeture").to.be.below(24 * MIO);
      expect(pic - base, "pic des tampons de l'agent").to.be.below(16 * MIO);
    } finally {
      await p.fermer();
    }
  });

  it("Content-Length annoncé au-delà de la borne : refus avant toute lecture du corps", async function () {
    const { transportAvecJeton } = await import("../paquets/inscription/src/agent/reseau.mjs");
    const p = await pointHostile({ total: 2 * MIO, longueur: 64 * MIO });
    try {
      const debut = Date.now();
      const e = await transportAvecJeton(null)({ url: p.url, octets: Buffer.from("{}"), delaiMs: 20000, tailleMax: MIO }).then(() => null, (x) => x);
      expect(e?.code).to.equal("noeud_injoignable");
      expect(Date.now() - debut).to.be.below(5000);
    } finally {
      await p.fermer();
    }
  });

  it("réponse dans la borne : octets rendus tels quels", async function () {
    const { transportAvecJeton } = await import("../paquets/inscription/src/agent/reseau.mjs");
    const corps = Buffer.from('{"jsonrpc":"2.0","id":1,"result":"0x84c"}');
    const serveur = http.createServer((req, res) => {
      req.resume();
      res.writeHead(200, { "content-type": "application/json" });
      res.end(corps);
    });
    await new Promise((ok) => serveur.listen(0, "127.0.0.1", ok));
    try {
      const r = await transportAvecJeton("jeton-essai")({ url: `http://127.0.0.1:${serveur.address().port}`, octets: Buffer.from("{}"), delaiMs: 5000, tailleMax: MIO });
      expect(r.status).to.equal(200);
      expect(Buffer.from(r.octets).equals(corps)).to.equal(true);
    } finally {
      serveur.close();
    }
  });
});
