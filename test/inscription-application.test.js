// Inscription des clients, étape 6 : l'application d'exploitant (TE-22 ;
// CT-4 §7.14, EX-7.23, EX-7.25 à EX-7.28 ; paquets/inscription/INTERFACES.md
// 1 et 2). L'interface Next.js est construite par l'essai (`next build`, sans
// réseau extérieur) puis servie par son binaire, l'agent réel derrière elle,
// sur le réseau Hardhat 31337 et le pont noorcore de l'essai. L'essai joue le
// navigateur par des requêtes HTTP : aucun champ de page ni de route ne reçoit
// une clé, une graine, une mnémonique, un jeton ou un mot de passe de clé ;
// aucune page ni aucun script servi ne contient le chemin de la prise ;
// aucun condensé n'est signé par l'application ; les confirmations sont
// consignées ; en-têtes (politique de sécurité du contenu bloquante à nonce,
// aucun Access-Control-Allow-*, Origin exigé hors GET).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import * as E from "./fixtures/inscription/reseau-essai.mjs";
import * as O from "./fixtures/inscription/outils.mjs";

const WEB = path.join(E.RACINE, "paquets", "inscription", "src", "web");
const BIN_WEB = path.join(E.RACINE, "paquets", "inscription", "bin", "noortrace-inscription-web");
const NEXT = path.join(E.RACINE, "node_modules", "next", "dist", "bin", "next");
const JOURNAL = "journal-principal";
const JID = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
const NOM = "operateur-1";
const MOT_DE_PASSE = "mot de passe du compte d'essai";
/**
 * Liste close des types de champ d'EX-7.25 (révision 0.7) : adresse, hachage, clé publique Ed25519, slug, nom de
 * journal, seuil, montant, référence de clé, texte, entier, origine HTTPS, identité de session, document JSON contrôlé,
 * chemin relatif sous le répertoire du client, et les listes de valeurs d'un de ces types ; aucun autre.
 */
const TYPES = new Set(["adresse", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "seuil", "montant", "reference_cle", "texte", "entier", "origine", "identite", "document", "chemin", "liste_adresses", "liste_noms_journal", "liste_identites", "liste_documents"]);

const portLibre = () => new Promise((ok) => {
  const s = net.createServer();
  s.listen(0, "127.0.0.1", () => {
    const p = s.address().port;
    s.close(() => ok(p));
  });
});

describe("inscription : application d'exploitant, interface Next.js et agent réel (TE-22, EX-7.23 à EX-7.28)", function () {
  this.timeout(1200000);
  let reseau;
  let pont;
  let dir;
  let manifeste;
  let a;
  let web;
  let url;
  let origine;
  let cookie;
  let journalWeb = "";
  let cleChaine;
  const slug = "application-essai";

  const req = async (chemin, { methode = "GET", corps, entetes = {}, avecOrigine = true, avecSession = true } = {}) => {
    const h = { ...entetes };
    if (avecSession && cookie) h.cookie = cookie;
    if (methode !== "GET" && avecOrigine) h.origin = origine;
    if (corps !== undefined) h["content-type"] = "application/json";
    const r = await fetch(`${url}${chemin}`, { method: methode, headers: h, body: corps === undefined ? undefined : typeof corps === "string" ? corps : JSON.stringify(corps), redirect: "manual" });
    const octets = Buffer.from(await r.arrayBuffer());
    let json = null;
    try {
      json = JSON.parse(octets.toString("utf8"));
    } catch {
      json = null;
    }
    return { statut: r.status, entetes: r.headers, texte: octets.toString("utf8"), octets, json };
  };
  const travail = async (t) => {
    const r = await req("/api/travaux", { methode: "POST", corps: t });
    expect(r.statut, r.texte).to.equal(200);
    for (;;) {
      const s = await req(`/api/travaux/${r.json.id}`);
      if (["fini", "refuse", "abandonne"].includes(s.json.etat)) return s.json;
      await new Promise((ok) => setTimeout(ok, 200));
    }
  };

  before(async function () {
    dir = O.repertoireTemporaire();
    reseau = await E.demarrerReseau();
    pont = await E.ouvrirPont(reseau.provider, { noorcore: true });
    manifeste = E.ecrireManifesteEssai(path.join(dir, "instance"), reseau);
    a = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, delai_s: 5 });
    // Construction de l'interface par l'essai, sans réseau extérieur (télémétrie coupée, aucune police distante).
    const b = spawnSync(process.execPath, [NEXT, "build", WEB], { cwd: E.RACINE, env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" }, encoding: "utf8", timeout: 600000 });
    expect(b.status, `${b.stdout}\n${b.stderr}`).to.equal(0);
    // Fichier des comptes : scrypt(mot de passe, sel, N = 131 072, r = 8, p = 1, 32 octets).
    const sel = crypto.randomBytes(16);
    const cle = crypto.scryptSync(Buffer.from(MOT_DE_PASSE, "utf8"), sel, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const comptes = path.join(dir, "comptes.json");
    fs.writeFileSync(comptes, JSON.stringify({ version: 0, accounts: [{ name: NOM, salt: sel.toString("hex"), key: cle.toString("hex") }] }));
    const port = await portLibre();
    origine = `http://127.0.0.1:${port}`;
    const config = path.join(dir, "interface.json");
    fs.writeFileSync(config, JSON.stringify({ version: 0, ecoute: { hote: "127.0.0.1", port }, origine, prise: a.prise, donnees: a.donnees, comptes: `fichier:${comptes}`, nature: "developpement" }));
    web = spawn(process.execPath, [BIN_WEB, "--config", config], { cwd: E.RACINE, env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    const pret = await new Promise((ok, ko) => {
      let t = "";
      web.stdout.on("data", (d) => {
        journalWeb += d;
        t += d;
        const ligne = t.split("\n").find((l) => l.startsWith('{"pret"'));
        if (ligne) ok(JSON.parse(ligne));
      });
      web.stderr.on("data", (d) => (journalWeb += d));
      web.on("exit", (c) => ko(new Error(`interface arrêtée (${c}) : ${journalWeb}`)));
    });
    url = pret.url;
    const k = crypto.createHash("sha256").update("noortrace/essai/inscription/application/chaine").digest();
    const f = path.join(dir, "chaine.cle");
    fs.writeFileSync(f, k.toString("hex"), { mode: 0o600 });
    cleChaine = { reference: `fichier:${f}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse(), octets: k };
  });

  after(async function () {
    if (web && web.exitCode === null) {
      web.kill("SIGTERM");
      await new Promise((ok) => web.once("exit", ok));
    }
    await a?.arreter();
    await pont?.fermer();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (a?.base) fs.rmSync(a.base, { recursive: true, force: true });
  });

  describe("en-têtes et périmètre public", function () {
    it("sans session : /connexion servie, toute autre page renvoyée à /connexion, toute route 401", async function () {
      const c = await req("/connexion", { avecSession: false });
      expect(c.statut).to.equal(200);
      expect(c.texte).to.contain("<form");
      for (const p of ["/", "/clients", "/clients/nouveau", `/clients/${slug}`, `/clients/${slug}/paquet`]) {
        const r = await req(p, { avecSession: false });
        expect(r.statut, p).to.equal(303);
        expect(new URL(r.entetes.get("location"), url).pathname, p).to.equal("/connexion");
      }
      for (const p of ["/api/clients", `/api/clients/${slug}`, "/api/travaux/trv-" + "0".repeat(32), `/api/clients/${slug}/paquet`]) {
        expect((await req(p, { avecSession: false })).statut, p).to.equal(401);
      }
      expect((await req("/api/travaux", { methode: "POST", corps: {}, avecSession: false })).statut).to.equal(401);
      expect((await req("/api/deconnexion", { methode: "POST", corps: {}, avecSession: false })).statut).to.equal(401);
    });

    it("politique de sécurité du contenu bloquante, à nonce tiré à chaque réponse, appliquée à chaque script ; aucun en-tête Access-Control-Allow-*", async function () {
      const r1 = await req("/connexion", { avecSession: false });
      const r2 = await req("/connexion", { avecSession: false });
      const csp = r1.entetes.get("content-security-policy");
      expect(r1.entetes.get("content-security-policy-report-only")).to.equal(null);
      expect(csp).to.match(/^default-src 'none'; script-src 'nonce-([A-Za-z0-9+/=]{24})' 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'$/);
      const n1 = /'nonce-([^']+)'/.exec(csp)[1];
      const n2 = /'nonce-([^']+)'/.exec(r2.entetes.get("content-security-policy"))[1];
      expect(n1).to.not.equal(n2);
      expect(Buffer.from(n1, "base64").length).to.be.at.least(16);
      const scripts = [...r1.texte.matchAll(/<script\b([^>]*)>/g)].map((m) => m[1]);
      expect(scripts.length).to.be.greaterThan(0);
      for (const s of scripts) expect(s, s).to.contain(`nonce="${n1}"`);
      for (const r of [r1, r2]) for (const [k] of r.entetes) expect(k.toLowerCase()).to.not.match(/^access-control-allow-/);
      expect(r1.entetes.get("x-powered-by")).to.equal(null);
      // La route d'optimisation des images n'est pas servie (images.unoptimized).
      const img = await req("/_next/image?url=%2Ffavicon.ico&w=64&q=75", { avecSession: false });
      expect(img.statut).to.not.equal(200);
    });

    it("hors GET, l'en-tête Origin est exigé et doit être l'origine de l'interface", async function () {
      const sans = await req("/api/connexion", { methode: "POST", corps: { name: NOM, password: MOT_DE_PASSE }, avecOrigine: false, avecSession: false });
      expect(sans.statut).to.equal(403);
      const autre = await req("/api/connexion", { methode: "POST", corps: { name: NOM, password: MOT_DE_PASSE }, avecOrigine: false, avecSession: false, entetes: { origin: "https://autre.example" } });
      expect(autre.statut).to.equal(403);
      expect(sans.entetes.get("set-cookie")).to.equal(null);
    });
  });

  describe("comptes et session (INTERFACES.md 1)", function () {
    it("échecs : 401 pour un nom inconnu comme pour un mauvais mot de passe ; verrou progressif après cinq échecs (429, retry_after_s)", async function () {
      const faux = await req("/api/connexion", { methode: "POST", corps: { name: NOM, password: "autre" }, avecSession: false });
      expect(faux.statut).to.equal(401);
      expect(faux.json.error.code).to.equal("identifiants_refuses");
      for (let k = 0; k < 5; k++) {
        const r = await req("/api/connexion", { methode: "POST", corps: { name: "intrus", password: `essai-${k}` }, avecSession: false });
        expect(r.statut, `échec ${k + 1}`).to.equal(401);
      }
      const bloque = await req("/api/connexion", { methode: "POST", corps: { name: "intrus", password: "essai-6" }, avecSession: false });
      expect(bloque.statut).to.equal(429);
      expect(bloque.json.error).to.deep.include({ code: "essai_trop_tot" });
      expect(bloque.json.error.data.retry_after_s).to.equal(1);
    });

    it("succès : 204 et cookie __Host-noortrace-inscription (Secure, HttpOnly, SameSite=Strict, Path=/, 8 h)", async function () {
      const r = await req("/api/connexion", { methode: "POST", corps: { name: NOM, password: MOT_DE_PASSE }, avecSession: false });
      expect(r.statut).to.equal(204);
      const sc = r.entetes.get("set-cookie");
      expect(sc).to.match(/^__Host-noortrace-inscription=[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}; Secure; HttpOnly; SameSite=Strict; Path=\/; Max-Age=28800$/);
      cookie = sc.split(";")[0];
      const l = await req("/api/clients");
      expect(l.statut).to.equal(200);
      expect(l.json).to.deep.equal({ clients: [] });
      // Un cookie au MAC altéré n'ouvre rien.
      const altere = cookie.slice(0, -2) + (cookie.endsWith("A") ? "BB" : "AA");
      expect((await req("/api/clients", { entetes: { cookie: altere }, avecSession: false })).statut).to.equal(401);
    });
  });

  describe("aucune clé par formulaire, aucune signature par l'application (EX-7.25, EX-7.27, EX-7.28)", function () {
    it("parcours du client par l'interface : préparation, confirmation consignée, pas 2 à 5, demande non signée, relais de la demande signée hors de l'application", async function () {
      const ed = O.cleEd25519("application");
      const doc = O.documentCle({ keyId: "rec-application-01", journalId: JID, chainKey: cleChaine.adresse, publique: ed.publique });
      const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
      let t = await travail({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
      expect(t.sortie.result).to.equal("reussi");
      expect(t.exploitant).to.equal(`exploitant ${NOM}`);
      // Sans confirmation : refus, affiché « confirmation hors bande absente », rien d'envoyé.
      const envois = pont.envoisRecus.length;
      const r = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug, parametres: {} } });
      expect(r.statut).to.equal(400);
      expect(r.json.error.code).to.equal("confirmation_absente");
      expect(r.json.error.message).to.match(/^confirmation hors bande absente/);
      expect(pont.envoisRecus.length).to.equal(envois);
      // Confirmation consignée avec l'identité de la session (EX-7.26).
      const dossier = (await req(`/api/clients/${slug}`)).json.dossier;
      const conf = { operation: "approvisionnement", objet: { org_id: dossier.organisation.org_id, cle_chaine: cleChaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel au numéro du contrat", instant: "2026-11-11T09:00:00.000Z", piece_sha256: "0x" + "77".repeat(32) };
      const c = await req(`/api/clients/${slug}/confirmations`, { methode: "POST", corps: conf });
      expect(c.statut, c.texte).to.equal(200);
      expect(c.json.id).to.match(/^cnf-[0-9a-f]{32}$/);
      const registre = (await req(`/api/clients/${slug}/confirmations`)).json.confirmations;
      expect(registre).to.have.length(1);
      expect(registre[0]).to.include({ id: c.json.id, exploitant: `exploitant ${NOM}`, personne_client: conf.personne_client, canal: conf.canal, instant: conf.instant, piece_sha256: conf.piece_sha256, operation: "approvisionnement" });
      expect(registre[0].objet).to.deep.equal(conf.objet);
      t = await travail({ commande: "inscrire-client", slug, parametres: {} });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      // Pas 6 : l'application prépare la demande, ne la signe pas (EX-7.27).
      t = await travail({ commande: "condense-inscription", slug, parametres: { key_id: "rec-application-01" } });
      expect(t.sortie.result).to.equal("reussi");
      const vue = (await req(`/api/clients/${slug}`)).json;
      const demande = vue.demandes.find((x) => x.nom.startsWith("demande-inscription-rec-application-01"))?.document;
      expect(demande.signatures).to.deep.equal([]);
      const signee = O.signerDemande(demande, [2, 3]);
      t = await travail({ commande: "inscrire-cle", slug, parametres: { demande: signee, cle_chaine: cleChaine.reference } });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      // Aucune signature de l'application n'apparaît ailleurs que dans la demande signée hors d'elle.
      for (const x of vue.demandes) expect(x.document.signatures, x.nom).to.deep.equal([]);
    });

    it("chaque champ des pages a un type de la liste close d'EX-7.25 (révision 0.7) ; aucun ne reçoit une clé, une graine, une mnémonique, un jeton ni un mot de passe de clé", async function () {
      const { TYPES_DECLARES } = await import("../paquets/inscription/src/commun/champs.mjs");
      expect([...TYPES_DECLARES].sort(), "liste du module égale à celle du texte").to.deep.equal([...TYPES].sort());
      const pages = ["/connexion", "/clients", "/clients/nouveau", `/clients/${slug}`, `/clients/${slug}/confirmations`, `/clients/${slug}/paquet`];
      let n = 0;
      for (const p of pages) {
        const r = await req(p);
        expect(r.statut, p).to.equal(200);
        for (const m of r.texte.matchAll(/<(input|textarea|select)\b([^>]*)>/g)) {
          n++;
          const attributs = m[2];
          const type = /data-type="([^"]+)"/.exec(attributs)?.[1];
          const nom = /name="([^"]+)"/.exec(attributs)?.[1] ?? "";
          if (p === "/connexion" && nom === "password") {
            expect(type).to.equal("mot_de_passe_compte");
            continue;
          }
          expect(TYPES.has(type), `${p} : ${nom} de type ${type}`).to.equal(true);
          expect(nom, p).to.not.match(/cle_privee|private|graine|seed|mnemoni|jeton|token|password|mot_de_passe|secret/i);
          expect(attributs, `${p} : ${nom}`).to.not.match(/type="password"/);
        }
      }
      expect(n).to.be.greaterThan(20);
    });

    it("une valeur nue dans un champ de référence ou de texte est refusée (400), jamais recopiée ni consignée", async function () {
      const secret = crypto.randomBytes(32).toString("hex");
      const essais = [
        { commande: "inscrire-cle", slug, parametres: { demande: {}, cle_chaine: secret } },
        { commande: "inscrire-cle", slug, parametres: { demande: {}, cle_chaine: `0x${secret}` } },
        { commande: "inscrire-client-preparer", slug: "autre-client", parametres: { org: "autre-client", journaux: [JOURNAL], seuil: 1, approbateurs: [O.compteHardhat(1).adresse], admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [], tresorerie: "test test test test test test test test test test test junk" } },
        { commande: "paquet", slug, parametres: { prepared_by: `clé ${secret}`, console_origin: null, administrators: null } },
      ];
      for (const e of essais) {
        const r = await req("/api/travaux", { methode: "POST", corps: e });
        expect(r.statut, JSON.stringify(e.parametres).slice(0, 60)).to.equal(400);
        expect(["reference_refusee", "requete_invalide"]).to.include(r.json.error.code);
        expect(r.texte).to.not.contain(secret);
        expect(r.texte).to.not.contain("junk");
      }
      const conf = await req(`/api/clients/${slug}/confirmations`, { methode: "POST", corps: { operation: "approvisionner", objet: { org_id: "0x" + "00".repeat(32), cle_chaine: cleChaine.adresse }, personne_client: secret, canal: "x", instant: "2026-11-11T09:00:00.000Z", piece_sha256: "0x" + "77".repeat(32) } });
      expect(conf.statut).to.equal(400);
      expect(conf.texte).to.not.contain(secret);
      expect(fs.readFileSync(path.join(a.donnees, "journal-agent.ndjson"), "utf8")).to.not.contain(secret);
      expect(journalWeb).to.not.contain(secret);
    });

    it("aucune page ni aucun script servi ne contient le chemin de la prise ; aucun script ne demande une signature à un portefeuille", async function () {
      const pages = ["/connexion", "/clients", "/clients/nouveau", `/clients/${slug}`, `/clients/${slug}/confirmations`, `/clients/${slug}/paquet`];
      const scripts = new Set();
      // Le chemin de la prise, son nom et son répertoire (les sorties des travaux nomment, comme l'outil, des fichiers
      // des données de l'agent, qui ne sont pas la prise).
      const marques = [a.prise, path.basename(a.prise), path.dirname(a.prise)];
      for (const p of pages) {
        const r = await req(p);
        for (const m of marques) expect(r.texte, `${p} contient ${m}`).to.not.contain(m);
        for (const s of r.texte.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) scripts.add(s[1]);
        for (const s of r.texte.matchAll(/<link\b[^>]*\bhref="([^"]+\.(?:js|css))"/g)) scripts.add(s[1]);
      }
      // Morceaux chargés à la demande : tous les fichiers statiques de la construction.
      const statiques = path.join(WEB, ".next", "static");
      const fichiers = [];
      const parcourir = (d) => {
        for (const n of fs.readdirSync(d)) {
          const f = path.join(d, n);
          if (fs.statSync(f).isDirectory()) parcourir(f);
          else fichiers.push(f);
        }
      };
      parcourir(statiques);
      expect(scripts.size).to.be.greaterThan(0);
      for (const s of scripts) {
        const r = await req(s);
        expect(r.statut, s).to.equal(200);
        for (const m of marques) expect(r.texte, `${s} contient ${m}`).to.not.contain(m);
      }
      for (const f of fichiers) {
        const t = fs.readFileSync(f, "utf8");
        for (const m of marques) expect(t, `${f} contient ${m}`).to.not.contain(m);
        expect(t, f).to.not.match(/personal_sign|eth_sign|signTypedData|eth_requestAccounts|window\.ethereum/);
      }
      // Les réponses de l'API ne portent que des sorties de travaux et des fichiers de l'agent, sans la prise.
      for (const p of ["/api/clients", `/api/clients/${slug}`, `/api/clients/${slug}/confirmations`]) {
        const r = await req(p);
        expect(r.texte, p).to.not.contain(a.prise);
      }
    });
  });

  describe("paquet client par l'interface (INTERFACES.md 4.2)", function () {
    it("paquet absent : 404 ; paquet produit : archive tar ustar du répertoire contrôlé, sans le registre des confirmations", async function () {
      expect((await req(`/api/clients/${slug}/paquet`)).statut).to.equal(404);
      // Pas 7 à 9 : l'outil de référence tient lieu d'enregistreur, sur le dossier et les captures de l'agent.
      const cl = a.client(slug);
      const graine = path.join(dir, "rec.graine");
      fs.writeFileSync(graine, Buffer.from(O.cleEd25519("application").graine).toString("hex"), { mode: 0o600 });
      const C = ["--instance", manifeste, "--rpc", pont.url];
      const periode = path.join(cl.dir, "periode-1");
      const etapes = [
        ["manifeste-essai", "--dossier", cl.dossier, "--key-id", "rec-application-01", "--graine", `graine:${graine}`, "--sortie", periode],
        ["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
        ["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", cl.captures, "--sortie", path.join(dir, "cloture.json")],
        ["signer", "--demande", path.join(dir, "cloture.json"), "--cle", "hardhat:1"],
        ["signer", "--demande", path.join(dir, "cloture.json"), "--cle", "hardhat:3"],
        ["clore", "--demande", path.join(dir, "cloture.json"), "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", cleChaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
      ];
      for (const e of etapes) {
        const r = await O.outilReference([...e, ...C]);
        expect(r.sortie?.result, `${e[0]} : ${r.err}`).to.equal("reussi");
      }
      const t = await travail({ commande: "paquet", slug, parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: null } });
      expect(t.sortie?.command).to.equal("paquet-client");
      expect(t.sortie?.result, JSON.stringify(t.sortie)).to.equal("reussi");
      const r = await req(`/api/clients/${slug}/paquet`);
      expect(r.statut).to.equal(200);
      expect(r.entetes.get("content-type")).to.equal("application/x-tar");
      expect(r.octets.subarray(257, 263).toString("latin1")).to.equal("ustar\0");
      const archive = path.join(dir, "paquet.tar");
      fs.writeFileSync(archive, r.octets);
      const extrait = path.join(dir, "extrait");
      fs.mkdirSync(extrait);
      const x = spawnSync("tar", ["-xf", archive, "-C", extrait], { encoding: "utf8" });
      expect(x.status, x.stderr).to.equal(0);
      const { controlerPaquet } = await import("../paquets/inscription/src/commun/paquet.mjs");
      expect(controlerPaquet(path.join(extrait, `paquet-client-${slug}`))).to.deep.equal({ valide: true, ecarts: [] });
      expect(spawnSync("tar", ["-tf", archive], { encoding: "utf8" }).stdout).to.not.contain("confirmations");
      // Deux archives du même paquet sont identiques.
      expect((await req(`/api/clients/${slug}/paquet`)).octets.equals(r.octets)).to.equal(true);
    });
  });

  describe("bornes des corps de requête (relecture de l'étape 6)", function () {
    /** Requête HTTP brute : écrit les en-têtes puis `envoyer(socket)`, sans finir le corps ; rend le statut et le corps de la réponse, ou null passé `attente` ms. */
    const brute = (entetes, envoyer, attente = 5000) => new Promise((ok) => {
      const u = new URL(url);
      const so = net.connect(Number(u.port), u.hostname);
      let recu = "";
      let fini = false;
      const finir = () => {
        if (fini) return;
        fini = true;
        so.destroy();
        const m = /^HTTP\/1\.1 (\d+)[^]*?\r\n\r\n([^]*)$/.exec(recu);
        ok(m ? { statut: Number(m[1]), corps: m[2] } : null);
      };
      so.on("data", (d) => {
        recu += d;
        if (/\r\n\r\n[^]*\}$/.test(recu)) finir();
      });
      // Le serveur ferme la connexion après un refus : l'erreur d'écriture éventuelle n'empêche pas de lire la réponse reçue.
      so.on("error", () => {});
      so.on("close", finir);
      setTimeout(finir, attente);
      so.on("connect", () => {
        so.write(`POST /api/connexion HTTP/1.1\r\nHost: ${u.host}\r\nOrigin: ${origine}\r\nContent-Type: application/json\r\n${entetes}\r\n`);
        envoyer(so);
      });
    });

    it("Content-Length au-delà de 256 Kio : 413 aussitôt, sans attendre ni lire le corps (le corps n'est pas fini)", async function () {
      const t0 = Date.now();
      const r = await brute(`Content-Length: ${256 * 1024 + 1}\r\n`, (so) => so.write(" ".repeat(1024)));
      expect(r, "réponse avant la fin du corps").to.not.equal(null);
      expect(r.statut).to.equal(413);
      expect(JSON.parse(r.corps).error.code).to.equal("corps_trop_grand");
      expect(Date.now() - t0).to.be.below(3000);
    });

    it("corps sans longueur annoncée (Transfer-Encoding: chunked) : 411 aussitôt, avant que Next le retienne", async function () {
      const r = await brute("Transfer-Encoding: chunked\r\n", (so) => so.write(`400\r\n${" ".repeat(1024)}\r\n`));
      expect(r, "réponse avant la fin du corps").to.not.equal(null);
      expect(r.statut).to.equal(411);
      expect(JSON.parse(r.corps).error.code).to.equal("longueur_exigee");
    });

    it("corps de 256 Kio exactement : la borne n'est pas franchie (400 requete_invalide pour un JSON qui n'est pas { name, password })", async function () {
      const r = await req("/api/connexion", { methode: "POST", corps: " ".repeat(256 * 1024 - 2) + "{}", avecSession: false });
      expect(r.statut, r.texte).to.equal(400);
      expect(r.json.error.code).to.equal("requete_invalide");
    });

    it("lireCorpsBorne (routes) : un flux sans fin est coupé dès la borne franchie (null), sans attendre sa fin ; dans la borne, les octets tels quels", async function () {
      const { lireCorpsBorne, CORPS_MAX } = await import("../paquets/inscription/src/web/lib/routes.mjs");
      let annule = false;
      const sansFin = new ReadableStream({
        pull(c) {
          c.enqueue(new Uint8Array(64 * 1024).fill(0x20));
        },
        cancel() {
          annule = true;
        },
      });
      const r = await lireCorpsBorne(new Request("http://127.0.0.1/", { method: "POST", body: sansFin, duplex: "half" }));
      expect(r).to.equal(null);
      expect(annule, "flux annulé").to.equal(true);
      expect(await lireCorpsBorne(new Request("http://127.0.0.1/", { method: "POST", body: "x".repeat(CORPS_MAX + 1), headers: { "content-length": String(CORPS_MAX + 1) } }))).to.equal(null);
      expect(Buffer.from(await lireCorpsBorne(new Request("http://127.0.0.1/", { method: "POST", body: '{"a":1}' }))).toString()).to.equal('{"a":1}');
    });
  });

  describe("fin de session", function () {
    it("déconnexion : 204, puis la session est fermée", async function () {
      const r = await req("/api/deconnexion", { methode: "POST", corps: {} });
      expect(r.statut).to.equal(204);
      expect(r.entetes.get("set-cookie")).to.match(/^__Host-noortrace-inscription=; Secure; HttpOnly; SameSite=Strict; Path=\/; Max-Age=0$/);
      expect((await req("/api/clients")).statut).to.equal(401);
    });
  });
});
