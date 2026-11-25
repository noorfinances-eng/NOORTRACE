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
const TYPES = new Set(["adresse", "hachage", "cle_publique_ed25519", "slug", "nom_journal", "seuil", "montant", "reference_cle", "texte", "entier", "origine", "identite", "document", "chemin", "liste_adresses", "liste_noms_journal", "liste_identites", "liste_documents", "liste_textes"]);

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
    a = await O.demarrerAgentEssai({ manifeste, rpc: pont.url, delai_s: 5, clesRepertoire: dir });
    // Construction de l'interface par l'essai, sans réseau extérieur (télémétrie coupée, aucune police distante).
    const b = spawnSync(process.execPath, [NEXT, "build", WEB], { cwd: E.RACINE, env: { ...process.env, NEXT_TELEMETRY_DISABLED: "1" }, encoding: "utf8", timeout: 600000 });
    expect(b.status, `${b.stdout}\n${b.stderr}`).to.equal(0);
    // Fichier des comptes : scrypt(mot de passe, sel, N = 131 072, r = 8, p = 1, 32 octets).
    const sel = crypto.randomBytes(16);
    const cle = crypto.scryptSync(Buffer.from(MOT_DE_PASSE, "utf8"), sel, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
    const comptes = path.join(dir, "comptes.json");
    // Lisible de son seul propriétaire, comme le serveur l'exige (revue de l'étape 8, CT-7 CLE-37).
    fs.writeFileSync(comptes, JSON.stringify({ version: 0, accounts: [{ name: NOM, salt: sel.toString("hex"), key: cle.toString("hex") }] }), { mode: 0o600 });
    fs.chmodSync(comptes, 0o600);
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
      for (const p of ["/", "/clients", "/clients/nouveau", `/clients/${slug}`, `/clients/${slug}/paquet`, `/clients/${slug}/fiche-controle`]) {
        const r = await req(p, { avecSession: false });
        expect(r.statut, p).to.equal(303);
        expect(new URL(r.entetes.get("location"), url).pathname, p).to.equal("/connexion");
      }
      for (const p of ["/api/clients", `/api/clients/${slug}`, "/api/travaux/trv-" + "0".repeat(32), `/api/clients/${slug}/paquet`, `/api/clients/${slug}/fiche-controle`]) {
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
    it("parcours du client par l'interface : préparation, fiche de contrôle des adresses renvoyée et confirmation du versement consignées, pas 2 à 5, demande non signée, relais de la demande signée hors de l'application", async function () {
      const ed = O.cleEd25519("application");
      const doc = O.documentCle({ keyId: "rec-application-01", journalId: JID, chainKey: cleChaine.adresse, publique: ed.publique });
      const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
      let t = await travail({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
      expect(t.sortie.result).to.equal("reussi");
      expect(t.exploitant).to.equal(`exploitant ${NOM}`);
      // Sans confirmation : refus, affiché « confirmation hors bande absente », rien d'envoyé. Décisions du 2026-11-25
      // (CT-4 EX-7.8) : la première confirmation qui manque est celle de la fiche de contrôle des adresses des approbateurs.
      const envois = pont.envoisRecus.length;
      const r = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug, parametres: {} } });
      expect(r.statut).to.equal(400);
      expect(r.json.error.code).to.equal("confirmation_absente");
      expect(r.json.error.message).to.match(/^confirmation hors bande absente : confirmation hors bande absente pour le jeu d'approbateurs/);
      expect(pont.envoisRecus.length).to.equal(envois);
      // La fiche de contrôle, servie en fichier texte par la route de lecture ; renvoyée telle quelle, la pièce est la fiche.
      const dossier = (await req(`/api/clients/${slug}`)).json.dossier;
      const fiche = await req(`/api/clients/${slug}/fiche-controle`);
      expect(fiche.statut).to.equal(200);
      const ficheSha256 = "0x" + crypto.createHash("sha256").update(fiche.octets).digest("hex");
      const confFiche = { operation: "jeu_approbateurs", objet: { org_id: dossier.organisation.org_id, fiche_sha256: ficheSha256 }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T09:00:00.000Z", piece_sha256: ficheSha256 };
      const cf = await req(`/api/clients/${slug}/confirmations`, { methode: "POST", corps: confFiche });
      expect(cf.statut, cf.texte).to.equal(200);
      // La fiche confirmée, il manque encore la confirmation du versement : même refus, rien d'envoyé.
      const r2 = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug, parametres: {} } });
      expect([r2.statut, r2.json.error.code]).to.deep.equal([400, "confirmation_absente"]);
      expect(r2.json.error.message).to.match(/^confirmation hors bande absente : confirmation hors bande absente pour l'approvisionnement/);
      expect(pont.envoisRecus.length).to.equal(envois);
      // Confirmation consignée avec l'identité de la session (EX-7.26).
      const conf = { operation: "approvisionnement", objet: { org_id: dossier.organisation.org_id, cle_chaine: cleChaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel au numéro du contrat", instant: "2026-11-11T09:00:00.000Z", piece_sha256: "0x" + "77".repeat(32) };
      const c = await req(`/api/clients/${slug}/confirmations`, { methode: "POST", corps: conf });
      expect(c.statut, c.texte).to.equal(200);
      expect(c.json.id).to.match(/^cnf-[0-9a-f]{32}$/);
      const registre = (await req(`/api/clients/${slug}/confirmations`)).json.confirmations;
      expect(registre).to.have.length(2);
      expect(registre[0]).to.include({ id: cf.json.id, operation: "jeu_approbateurs", piece_sha256: ficheSha256, consommee_par: null, perimee: false });
      expect(registre[0].objet).to.deep.equal(confFiche.objet);
      expect(registre[1]).to.include({ id: c.json.id, exploitant: `exploitant ${NOM}`, personne_client: conf.personne_client, canal: conf.canal, instant: conf.instant, piece_sha256: conf.piece_sha256, operation: "approvisionnement" });
      expect(registre[1].objet).to.deep.equal(conf.objet);
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
      const horsChamps = [];
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
          // Complément du 2026-11-18 d'EX-7.25, sixième lecture : deux éléments de page qui ne sont pas des champs, sans
          // nom de champ, envoyés à aucune route et qui ne remplissent aucun champ : la case de relecture des adresses du
          // pas 1 et la recherche de la liste des clients ; aucun autre.
          const horsChamp = /data-adresses-relues=""/.test(attributs) ? "/clients/nouveau" : /data-recherche-clients=""/.test(attributs) ? "/clients" : null;
          if (horsChamp !== null) {
            expect([p, nom, type ?? null, /type="(checkbox|search)"/.exec(attributs)?.[1]], `${p} : élément hors champ`).to.deep.equal([horsChamp, "", null, horsChamp === "/clients" ? "search" : "checkbox"]);
            expect(attributs, "jamais cochée d'avance").to.not.match(/\bchecked\b/);
            horsChamps.push(horsChamp);
            continue;
          }
          expect(TYPES.has(type), `${p} : ${nom} de type ${type}`).to.equal(true);
          expect(nom, p).to.not.match(/cle_privee|private|graine|seed|mnemoni|jeton|token|password|mot_de_passe|secret/i);
          expect(attributs, `${p} : ${nom}`).to.not.match(/type="password"/);
        }
      }
      expect(n).to.be.greaterThan(20);
      expect(horsChamps.sort(), "les deux éléments hors champ, chacun une fois").to.deep.equal(["/clients", "/clients/nouveau"]);
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

  describe("présentation des écrans sur le dossier conduit par l'agent (complément du 2026-11-17 ; INTERFACES.md 2.4)", function () {
    it("fiche, liste, confirmations et paquet du client inscrit : étapes en mots, prochaine action, valeurs exactes du dossier dans les blocs repliés seulement ; la pièce de la confirmation et le manifeste du paquet restent à lire sans rien ouvrir ; aucun attribut style", async function () {
      const vue = (await req(`/api/clients/${slug}`)).json;
      const fiche = await req(`/clients/${slug}`);
      expect(fiche.statut).to.equal(200);
      /** Le HTML rendu sans ses blocs repliés : ce qui se lit sans rien ouvrir (les scripts de Next, qui portent l'arbre des composants pour l'hydratation, ne sont pas du texte affiché). */
      const sansDetails = (html) => html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "").replace(/<details\b[^>]*>[\s\S]*?<\/details>/g, "");
      const ouvert = sansDetails(fiche.texte);
      expect(fiche.texte).to.not.match(/<details\b[^>]*\sopen\b/);
      // Les étapes, dans l'ordre : la préparation puis celles du dossier, chacune avec son code et son état en attributs.
      const etapes = [...fiche.texte.matchAll(/<li class="nt-etape nt-etape-([a-z-]+)" data-etape="([a-z_]+)" data-etat="([a-z_]+)"/g)].map((m) => [m[2], m[3], m[1]]);
      expect(etapes).to.deep.equal([["preparation", "faite", "faite"], ...vue.dossier.steps.map((e) => [e.step, e.state, "faite"])]);
      // Complément du 2026-11-18 (langage des écrans) : le nom courant de chaque étape se lit sans rien ouvrir ; une étape
      // faite tient en une ligne, et la phrase de son état est dans son détail replié.
      for (const mot of ["Préparer le dossier", "Enregistrer les approbateurs", "Rattacher les approbateurs au client", "Contrôler les approbateurs", "Alimenter le compte technique", "Inscrire l&#x27;enregistreur", "Déposer la première preuve de date", "Clore la première période"]) expect(ouvert, mot).to.contain(mot);
      expect(fiche.texte).to.contain("Étape faite sans rien écrire sur le registre public.");
      expect(ouvert, "phrase d'état d'une étape faite hors de son détail").to.not.contain("Étape faite sans rien écrire sur le registre public.");
      expect([...ouvert.matchAll(/data-developpee="(oui|non)"/g)].map((m) => m[1]), "aucune étape à développer sur un client inscrit").to.deep.equal(Array(vue.dossier.steps.length + 1).fill("non"));
      expect(ouvert).to.contain('data-etat-client="inscrit"');
      expect(ouvert).to.contain('data-prochaine-action="remettre_paquet"');
      // Demandes de signature : la demande préparée dont la copie signée a été relayée n'est plus dite « à faire signer ».
      expect([...ouvert.matchAll(/data-demande="([^"]+)"/g)].map((m) => m[1]).sort()).to.deep.equal(vue.demandes.map((x) => x.nom).sort());
      expect(ouvert).to.contain("Remplacé par sa version signée");
      expect(ouvert).to.contain("Signé et envoyé<");
      expect(ouvert).to.not.contain("À faire signer par le client");
      // Valeurs exactes : dans la page, et seulement dans un bloc replié.
      let n = 0;
      for (const e of vue.dossier.steps) {
        for (const v of [e.transaction_hash, e.block_hash, e.capture]) {
          if (v === null) continue;
          n++;
          expect(fiche.texte, `${e.step} : ${v}`).to.contain(v);
          expect(ouvert, `${e.step} : ${v} hors d'un bloc replié`).to.not.contain(v);
        }
      }
      expect(n).to.be.at.least(15);
      expect(fiche.texte).to.contain(vue.dossier.organisation.org_id);
      expect(ouvert).to.not.contain(vue.dossier.organisation.org_id);
      expect(ouvert, "code d'étape ou d'état hors d'un bloc replié").to.not.match(/>(jeu_approbateurs|lecture_jeu|premiere_ancre|premiere_cloture|capturee|a_faire)</);
      // Liste : la carte du client, son avancement et sa prochaine action.
      const liste = await req("/clients");
      expect(liste.texte).to.match(new RegExp(`<article class="nt-carte" data-client="${slug}">`));
      expect(sansDetails(liste.texte)).to.contain(`${vue.dossier.steps.length + 1} étapes sur ${vue.dossier.steps.length + 1}`);
      expect(sansDetails(liste.texte)).to.contain("Remettez le paquet au client");
      expect(sansDetails(liste.texte)).to.contain("Inscription terminée");
      // Confirmations : ce qui engage se lit sans rien ouvrir (INTERFACES.md 2.4) ; à la quatrième lecture des écrans,
      // la personne qui l'a notée se lit aussi par le nom de son compte, et l'action qui l'a utilisée par son nom.
      const conf = sansDetails((await req(`/clients/${slug}/confirmations`)).texte);
      const registre = (await req(`/api/clients/${slug}/confirmations`)).json.confirmations;
      // Décisions du 2026-11-25 : deux confirmations, celle de la fiche de contrôle et celle du versement, toutes deux utilisées.
      expect(registre.map((x) => [x.operation, x.consommee_par !== null])).to.deep.equal([["jeu_approbateurs", true], ["approvisionnement", true]]);
      const versement = registre.find((x) => x.operation === "approvisionnement");
      for (const v of [versement.piece_sha256, versement.instant, versement.canal, versement.exploitant, versement.objet.cle_chaine, versement.consommee_par, registre[0].objet.fiche_sha256]) expect(conf, v).to.contain(v);
      for (const v of [versement.exploitant.replace(/^exploitant /, ""), "Faire les étapes 2 à 5"]) expect(conf, v).to.contain(v);
      expect(conf).to.contain("Déjà utilisée");
      // Paquet : le SHA-256 du manifeste, en entier, sans rien ouvrir.
      const paquet = sansDetails((await req(`/clients/${slug}/paquet`)).texte);
      const manifeste = vue.travaux.find((t) => t.commande === "paquet").sortie.outputs.manifest_sha256;
      expect(manifeste).to.match(/^0x[0-9a-f]{64}$/);
      expect(paquet).to.contain(`data-manifeste-paquet="true">${manifeste}<`);
      expect(paquet).to.contain(`href="/api/clients/${slug}/paquet"`);
      // Politique style-src 'self' : aucun attribut style dans les pages servies.
      for (const p of ["/connexion", "/clients", "/clients/nouveau", `/clients/${slug}`, `/clients/${slug}/confirmations`, `/clients/${slug}/paquet`]) {
        const r = await req(p);
        expect(r.texte, p).to.not.match(/<[a-z][^>]*\sstyle="/);
      }
    });
  });

  describe("nom interne et remise du paquet (complément du 2026-11-19, décision du porteur sur le suivi interne des clients ; CT-4 EX-7.23)", function () {
    it("décisions du 2026-11-19 : le nom interne, donné avant les pas 2 à 10, ne sort jamais de l'outil (requêtes au nœud, données de l'agent hors des notes, journal, parties, paquet et son archive) ; la remise du paquet se note, se refuse en double et se corrige sans s'effacer", async function () {
      const slug2 = "essai-nom-interne";
      const NOM_INTERNE = "Assurances du Léman NI7Q4";
      const NOM_CHANGE = "Mutuelle des Alpes NI8R5";
      const MOTIF = "Remise notée par erreur : motif interne MX3K9";
      const NOM_APPROBATEUR = "Camille Durand-Vexin AP6W2";
      const k = crypto.createHash("sha256").update("noortrace/essai/inscription/application/nom-interne/chaine").digest();
      const fk = path.join(dir, "chaine-nom-interne.cle");
      fs.writeFileSync(fk, k.toString("hex"), { mode: 0o600 });
      const chaine = { reference: `fichier:${fk}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse() };
      const ed = O.cleEd25519("application-nom-interne");
      const keyId = "rec-nom-interne-01";
      const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
      const debutRequetes = pont.requetesRecues.length;
      let t = await travail({ commande: "inscrire-client-preparer", slug: slug2, parametres: { org: slug2, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [O.documentCle({ keyId, journalId: JID, chainKey: chaine.adresse, publique: ed.publique })] } });
      expect(t.sortie.result).to.equal("reussi");
      const note = (corps, s = slug2) => req(`/api/clients/${s}/notes`, { methode: "POST", corps });
      // Le nom interne, avant tout envoi au registre public.
      let r = await note({ sorte: "nom_interne", nom: NOM_INTERNE });
      expect(r.statut, r.texte).to.equal(200);
      expect(r.json.id).to.match(/^not-[0-9a-f]{32}$/);
      // Décisions du 2026-11-25 : le nom d'un approbateur, donné par le client pour la fiche de contrôle, de même.
      r = await note({ sorte: "noms_approbateurs", noms: [{ adresse: app[0], nom: NOM_APPROBATEUR }] });
      expect(r.statut, r.texte).to.equal(200);
      // Refus de forme et de l'agent : 400, valeur jamais recopiée ; client inconnu : 404 ; hors session : 401 ; sans Origin : 403.
      const secret = crypto.randomBytes(32).toString("hex");
      for (const corps of [{ sorte: "nom_interne", nom: secret }, { sorte: "nom_interne", nom: "x", org_id: "0x" + "00".repeat(32) }, { sorte: "remise_paquet", manifest_sha256: "0x12" }, { sorte: "autre" }, { sorte: "noms_approbateurs", noms: [{ adresse: app[0], nom: secret }] }, { sorte: "noms_approbateurs", noms: [{ adresse: O.compteHardhat(7).adresse, nom: "x" }] }]) {
        const x = await note(corps);
        expect(x.statut, JSON.stringify(corps)).to.equal(400);
        expect(x.json.error.code).to.equal("requete_invalide");
        expect(x.texte).to.not.contain(secret);
      }
      r = await note({ sorte: "remise_paquet", manifest_sha256: "0x" + "ab".repeat(32) });
      expect([r.statut, r.json.error.code], "aucun paquet produit").to.deep.equal([400, "paquet_inconnu"]);
      r = await note({ sorte: "correction_remise", remise: `not-${"0".repeat(32)}`, motif: "x" });
      expect([r.statut, r.json.error.code]).to.deep.equal([400, "remise_inconnue"]);
      expect((await note({ sorte: "nom_interne", nom: "x" }, "client-absent")).statut).to.equal(404);
      expect((await req(`/api/clients/${slug2}/notes`, { methode: "POST", corps: { sorte: "nom_interne", nom: "x" }, avecSession: false })).statut).to.equal(401);
      expect((await req(`/api/clients/${slug2}/notes`, { methode: "POST", corps: { sorte: "nom_interne", nom: "x" }, avecOrigine: false })).statut).to.equal(403);
      // Pas 2 à 6 par l'outil. Décisions du 2026-11-25 : la fiche de contrôle des adresses, renvoyée telle quelle, d'abord ;
      // le nom interne n'y est pas (elle nomme le client par son nom court).
      const org = (await req(`/api/clients/${slug2}`)).json.dossier.organisation.org_id;
      const ficheTexte = await req(`/api/clients/${slug2}/fiche-controle`);
      expect(ficheTexte.statut).to.equal(200);
      expect(ficheTexte.texte.toLowerCase()).to.not.contain(NOM_INTERNE.toLowerCase());
      expect(ficheTexte.texte, "le nom de l'approbateur, lui, est sur la fiche").to.match(new RegExp(`^Approbateur [1-3] : ${app[0].toLowerCase()} — nom : ${NOM_APPROBATEUR}$`, "m"));
      const ficheSha256 = "0x" + crypto.createHash("sha256").update(ficheTexte.octets).digest("hex");
      expect((await req(`/api/clients/${slug2}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: org, fiche_sha256: ficheSha256 }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T09:00:00.000Z", piece_sha256: ficheSha256 } })).statut).to.equal(200);
      expect((await req(`/api/clients/${slug2}/confirmations`, { methode: "POST", corps: { operation: "approvisionnement", objet: { org_id: org, cle_chaine: chaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel au numéro du contrat", instant: "2026-11-19T09:00:00.000Z", piece_sha256: "0x" + "78".repeat(32) } })).statut).to.equal(200);
      t = await travail({ commande: "inscrire-client", slug: slug2, parametres: {} });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      t = await travail({ commande: "condense-inscription", slug: slug2, parametres: { key_id: keyId } });
      expect(t.sortie.result).to.equal("reussi");
      const demande = (await req(`/api/clients/${slug2}`)).json.demandes.find((x) => x.nom.startsWith(`demande-inscription-${keyId}`)).document;
      t = await travail({ commande: "inscrire-cle", slug: slug2, parametres: { demande: O.signerDemande(demande, [2, 3]), cle_chaine: chaine.reference } });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      // Pas 7 à 9 chez le client (l'outil de référence tient lieu d'enregistreur), puis pas 10 et le paquet par l'outil.
      const cl = a.client(slug2);
      const graine = path.join(dir, "rec-nom-interne.graine");
      fs.writeFileSync(graine, Buffer.from(ed.graine).toString("hex"), { mode: 0o600 });
      const C = ["--instance", manifeste, "--rpc", pont.url];
      const periode = path.join(cl.dir, "periode-1");
      const cloture = path.join(dir, "cloture-nom-interne.json");
      for (const e of [
        ["manifeste-essai", "--dossier", cl.dossier, "--key-id", keyId, "--graine", `graine:${graine}`, "--sortie", periode],
        ["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", chaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
        ["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", cl.captures, "--sortie", cloture],
        ["signer", "--demande", cloture, "--cle", "hardhat:1"],
        ["signer", "--demande", cloture, "--cle", "hardhat:3"],
        ["clore", "--demande", cloture, "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", chaine.reference, "--dossier", cl.dossier, "--captures", cl.captures],
      ]) {
        const x = await O.outilReference([...e, ...C]);
        expect(x.sortie?.result, `${e[0]} : ${x.err}`).to.equal("reussi");
      }
      t = await travail({ commande: "exporter", slug: slug2, parametres: { manifeste: "periode-1/manifeste.json" } });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      t = await travail({ commande: "verifier", slug: slug2, parametres: { parties: "parties/1", manifeste: "periode-1/manifeste.json" } });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      t = await travail({ commande: "paquet", slug: slug2, parametres: { prepared_by: "exploitant de l'essai", console_origin: null, administrators: null } });
      expect(t.sortie.result, JSON.stringify(t.sortie)).to.equal("reussi");
      const manifesteSha = t.sortie.outputs.manifest_sha256;
      // Remise : notée une fois ; en double, refusée ; d'un autre paquet, refusée ; corrigée sans s'effacer ; notée de nouveau.
      r = await note({ sorte: "remise_paquet", manifest_sha256: manifesteSha });
      expect(r.statut, r.texte).to.equal(200);
      const remise1 = r.json.id;
      r = await note({ sorte: "remise_paquet", manifest_sha256: manifesteSha });
      expect([r.statut, r.json.error.code]).to.deep.equal([400, "remise_deja_notee"]);
      r = await note({ sorte: "remise_paquet", manifest_sha256: "0x" + "ab".repeat(32) });
      expect([r.statut, r.json.error.code]).to.deep.equal([400, "paquet_inconnu"]);
      expect((await req(`/clients/${slug2}`)).texte).to.contain('data-prochaine-action="paquet_remis"');
      r = await note({ sorte: "correction_remise", remise: remise1, motif: MOTIF });
      expect(r.statut, r.texte).to.equal(200);
      r = await note({ sorte: "correction_remise", remise: remise1, motif: "seconde correction" });
      expect([r.statut, r.json.error.code], "une remise ne se corrige qu'une fois").to.deep.equal([400, "remise_inconnue"]);
      expect((await req(`/clients/${slug2}`)).texte).to.contain('data-prochaine-action="remettre_paquet"');
      r = await note({ sorte: "remise_paquet", manifest_sha256: manifesteSha });
      expect(r.statut, r.texte).to.equal(200);
      r = await note({ sorte: "nom_interne", nom: NOM_CHANGE });
      expect(r.statut).to.equal(200);
      // Le registre des notes, en ajout seul : chaque note, avec l'exploitant et l'instant ; la remise corrigée y reste.
      const lignes = fs.readFileSync(path.join(a.donnees, "notes-internes.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      expect(lignes.map((l) => [l.sorte, l.org_id === org, l.exploitant])).to.deep.equal([["nom_interne", true, `exploitant ${NOM}`], ["noms_approbateurs", true, `exploitant ${NOM}`], ["remise_paquet", true, `exploitant ${NOM}`], ["correction_remise", true, `exploitant ${NOM}`], ["remise_paquet", true, `exploitant ${NOM}`], ["nom_interne", true, `exploitant ${NOM}`]]);
      expect(lignes[0]).to.include({ nom: NOM_INTERNE });
      expect(lignes[3]).to.include({ remise: remise1, motif: MOTIF });
      expect(lignes[1].noms).to.deep.equal([{ adresse: app[0].toLowerCase(), nom: NOM_APPROBATEUR }]);
      for (const l of lignes) expect(l.recu_a).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{12}Z$/);
      // Les pages, servies sous session, montrent le nom et la remise.
      expect((await req("/clients")).texte).to.contain(NOM_CHANGE);
      expect((await req(`/clients/${slug2}`)).texte).to.contain(NOM_CHANGE);
      expect((await req(`/clients/${slug2}/paquet`)).texte).to.contain(`Paquet remis le `);
      // Ce qui sort de l'outil : rien ne porte le nom interne, ni le motif de la correction.
      const archive = (await req(`/api/clients/${slug2}/paquet`)).octets;
      expect(archive.length).to.be.greaterThan(1024);
      const formes = (texte) => [texte, JSON.stringify(texte).slice(1, -1).replace(/[\u0080-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`), Buffer.from(texte, "utf8").toString("hex"), Buffer.from(texte, "utf8").toString("base64").slice(0, 16), texte.split(" ").pop(), Buffer.from(texte.split(" ").pop()).toString("hex")].map((x) => x.toLowerCase());
      const cherches = [...formes(NOM_INTERNE), ...formes(NOM_CHANGE), ...formes(MOTIF), ...formes(NOM_APPROBATEUR)];
      const contient = (octets) => {
        const bas = Buffer.from(octets).toString("latin1").toLowerCase();
        const utf = Buffer.from(octets).toString("utf8").toLowerCase();
        return cherches.find((x) => bas.includes(x) || utf.includes(x)) ?? null;
      };
      const fichiers = [];
      const parcourir = (d) => {
        for (const n of fs.readdirSync(d)) {
          const f = path.join(d, n);
          const st = fs.lstatSync(f);
          if (st.isDirectory()) parcourir(f);
          else if (st.isFile()) fichiers.push(f);
        }
      };
      parcourir(a.donnees);
      const notesFichier = path.join(a.donnees, "notes-internes.ndjson");
      expect(contient(fs.readFileSync(notesFichier)), "la recherche trouve le nom là où il est gardé").to.not.equal(null);
      expect(contient(Buffer.from(NOM_APPROBATEUR)), "la recherche trouve aussi le nom de l'approbateur").to.not.equal(null);
      const verifies = fichiers.filter((f) => f !== notesFichier);
      for (const n of ["journal-agent.ndjson", `clients/${slug2}/dossier.json`, `clients/${slug2}/parties/1`, `clients/${slug2}/paquets/1/paquet-client-${slug2}/paquet-client.json`, `clients/${slug2}/captures`]) {
        expect(verifies.some((f) => f.startsWith(path.join(a.donnees, n))), `${n} parcouru`).to.equal(true);
      }
      for (const f of verifies) expect(contient(fs.readFileSync(f)), f).to.equal(null);
      expect(contient(archive), "archive du paquet").to.equal(null);
      const requetes = pont.requetesRecues.slice(debutRequetes);
      expect(requetes.filter((x) => x.includes('"eth_sendRawTransaction"')).length, "les pas 2 à 9 ont écrit sur le registre").to.be.at.least(6);
      for (const x of requetes) expect(contient(Buffer.from(x)), "requête au nœud").to.equal(null);
      expect(contient(Buffer.from(journalWeb)), "journal du serveur de l'interface").to.equal(null);
      // Le journal de l'agent garde chaque note sans son contenu.
      const journal = fs.readFileSync(path.join(a.donnees, "journal-agent.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      const recues = journal.filter((l) => l.evenement === "note_recue");
      expect(recues.map((l) => Object.keys(l).sort().join(","))).to.deep.equal(Array(6).fill("evenement,exploitant,id,instant,org_id,sorte"));
      expect(journal.filter((l) => l.evenement === "note_refusee").map((l) => l.code)).to.include.members(["paquet_inconnu", "remise_inconnue", "remise_deja_notee"]);
    });
  });

  describe("fiche de contrôle des adresses des approbateurs et durée d'un versement (décisions du porteur du 2026-11-25 ; CT-4 EX-7.8, EX-7.9, EX-7.23, EX-7.26)", function () {
    it("décisions du 2026-11-25 : la fiche est un fichier texte canonique dont l'empreinte est citée par la confirmation ; sans cette confirmation, les pas 2 à 5 sont refusés sans rien envoyer ; le dossier changé, la confirmation ne vaut plus et l'étape reste bloquée ; le déploiement du jeu consomme la confirmation ; l'agent écrit les frais de l'instance, que l'interface rend avec le dossier", async function () {
      const { texteFiche, empreinteFiche, lignesFiche } = await import("../paquets/inscription/src/commun/fiche-controle.mjs");
      const slug3 = "application-fiche";
      const k = crypto.createHash("sha256").update("noortrace/essai/inscription/application/fiche/chaine").digest();
      const fk = path.join(dir, "chaine-fiche.cle");
      fs.writeFileSync(fk, k.toString("hex"), { mode: 0o600 });
      const chaine = { reference: `fichier:${fk}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse() };
      const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
      let t = await travail({ commande: "inscrire-client-preparer", slug: slug3, parametres: { org: slug3, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [O.documentCle({ keyId: "rec-fiche-01", journalId: JID, chainKey: chaine.adresse, publique: O.cleEd25519("application-fiche").publique })] } });
      expect(t.sortie.result).to.equal("reussi");
      const vue = (await req(`/api/clients/${slug3}`)).json;
      const dossier = vue.dossier;
      // 1. Les frais de l'instance : écrits par l'agent dans ses données, rendus par l'interface avec le dossier (EX-7.23, EX-7.9).
      const frais = JSON.parse(fs.readFileSync(path.join(a.donnees, "frais-instance.json"), "utf8"));
      expect(frais).to.deep.equal({ version: 0, provision_days: 30, refill_below_days: 7, gas_limit: 3000000, max_daily_budget_gas: null, manifest_sha256: frais.manifest_sha256 });
      expect(frais.manifest_sha256).to.match(/^0x[0-9a-f]{64}$/);
      expect(vue.frais).to.deep.equal({ provision_days: 30, refill_below_days: 7, gas_limit: 3000000, max_daily_budget_gas: null, manifest_sha256: frais.manifest_sha256 });
      expect(BigInt(dossier.funding.amount_wei), "le montant du dossier est bien provision_days × b + gas_limit").to.equal(30n * BigInt(dossier.funding.daily_budget_gas) + 3000000n);
      // 2. La fiche : le fichier texte, canonique (deux lectures, les mêmes octets), son empreinte, rendue avec le dossier ;
      // la page imprimable porte les mêmes lignes et l'empreinte, sans rien ouvrir.
      const f1 = await req(`/api/clients/${slug3}/fiche-controle`);
      const f2 = await req(`/api/clients/${slug3}/fiche-controle`);
      expect(f1.statut).to.equal(200);
      expect(f1.entetes.get("content-type")).to.equal("text/plain; charset=utf-8");
      expect(f1.entetes.get("content-disposition")).to.equal(`attachment; filename="fiche-controle-${slug3}.txt"`);
      expect(f1.octets.equals(f2.octets)).to.equal(true);
      expect(f1.texte).to.equal(texteFiche(dossier));
      const ficheSha256 = "0x" + crypto.createHash("sha256").update(f1.octets).digest("hex");
      expect(ficheSha256).to.equal(empreinteFiche(dossier));
      expect(vue.fiche).to.deep.equal({ sha256: ficheSha256, noms: {}, versions: [{ version: 1, fiche_sha256: ficheSha256, produite_a: vue.fiche.versions[0].produite_a, courante: true }] });
      expect(vue.fiche.versions[0].produite_a).to.match(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]{12}Z$/);
      const lignes = f1.texte.split("\n");
      expect(lignes[0]).to.equal("Fiche de contrôle des adresses des approbateurs");
      expect(lignes[1]).to.equal(`Organisation (nom court) : ${slug3}`);
      expect(lignes[2]).to.equal("Nombre d'approbations requises : 2, sur 3 approbateurs");
      for (const [i, adresse] of dossier.approvers.members.entries()) expect(lignes[3 + i]).to.equal(`Approbateur ${i + 1} : ${adresse} — nom : — (le client complète le nom)`);
      expect(lignes[6]).to.equal(`Responsable des approbateurs : ${dossier.approvers.set_admin}`);
      expect(lignes[7]).to.match(/^Consigne : Chaque approbateur compare sa ligne/);
      expect(lignes[8], "terminée par un saut de ligne").to.equal("");
      const page = (await req(`/clients/${slug3}/fiche-controle`)).texte;
      const sansDetails = page.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "").replace(/<details\b[^>]*>[\s\S]*?<\/details>/g, "").replace(/&#x27;/g, "'").replace(/&quot;/g, '"');
      for (const x of lignesFiche(dossier)) if (x.valeur) expect(sansDetails, x.cle).to.contain(x.valeur.length > 60 ? x.valeur.slice(0, 60) : x.valeur);
      expect(sansDetails).to.contain(`data-fiche-sha256="">${ficheSha256}<`);
      expect(sansDetails).to.contain('data-fiche-controle="fiche_a_confirmer"');
      // 3. Sûreté : avec la seule confirmation du versement, les pas 2 à 5 sont refusés à la remise : aucun travail créé,
      // aucune sortie, rien n'est envoyé au nœud ; l'interface dit la mention fixée.
      expect((await req(`/api/clients/${slug3}/confirmations`, { methode: "POST", corps: { operation: "approvisionnement", objet: { org_id: dossier.organisation.org_id, cle_chaine: chaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel au numéro du contrat", instant: "2026-11-25T09:00:00.000Z", piece_sha256: "0x" + "66".repeat(32) } })).statut).to.equal(200);
      const travauxAvant = fs.readdirSync(path.join(a.donnees, "travaux")).length;
      const sortiesAvant = fs.readdirSync(path.join(a.client(slug3).dir, "sorties")).length;
      const envois = pont.envoisRecus.length;
      const refus = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug: slug3, parametres: {} } });
      expect([refus.statut, refus.json.error.code]).to.deep.equal([400, "confirmation_absente"]);
      expect(refus.json.error.message).to.equal(`confirmation hors bande absente : confirmation hors bande absente pour le jeu d'approbateurs de ${dossier.organisation.org_id} (fiche de contrôle ${ficheSha256}) (EX-7.26)`);
      expect(fs.readdirSync(path.join(a.donnees, "travaux")).length, "aucun travail créé").to.equal(travauxAvant);
      expect(fs.readdirSync(path.join(a.client(slug3).dir, "sorties")).length, "aucune sortie").to.equal(sortiesAvant);
      expect(pont.envoisRecus.length, "rien n'est envoyé").to.equal(envois);
      // Une confirmation de la fiche qui cite une autre empreinte (une version d'avant) ne vaut pas.
      const autre = "0x" + "ab".repeat(32);
      expect((await req(`/api/clients/${slug3}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: dossier.organisation.org_id, fiche_sha256: autre }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T09:05:00.000Z", piece_sha256: autre } })).statut).to.equal(200);
      const refus2 = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug: slug3, parametres: {} } });
      expect([refus2.statut, refus2.json.error.code]).to.deep.equal([400, "confirmation_absente"]);
      expect((await req(`/api/clients/${slug3}/confirmations`)).json.confirmations.find((x) => x.objet.fiche_sha256 === autre).perimee, "dite « ne vaut plus »").to.equal(true);
      // Un objet mal formé pour cette opération est refusé par la route, sans recopie.
      expect((await req(`/api/clients/${slug3}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: dossier.organisation.org_id, cle_chaine: chaine.adresse }, personne_client: "x", canal: "y", instant: "2026-11-25T09:05:00.000Z", piece_sha256: autre } })).statut).to.equal(400);
      // 4. La fiche renvoyée telle quelle, confirmée : la pièce est la fiche. Puis le dossier change (un approbateur de
      // plus) : la fiche et son empreinte changent, la confirmation ne vaut plus, l'étape reste bloquée.
      const cf = await req(`/api/clients/${slug3}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: dossier.organisation.org_id, fiche_sha256: ficheSha256 }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T09:10:00.000Z", piece_sha256: ficheSha256 } });
      expect(cf.statut, cf.texte).to.equal(200);
      const fichierDossier = a.client(slug3).dossier;
      const original = fs.readFileSync(fichierDossier, "utf8");
      const change = JSON.parse(original);
      change.approvers.members = [...change.approvers.members, O.compteHardhat(5).adresse].sort();
      fs.writeFileSync(fichierDossier, JSON.stringify(change, null, 2) + "\n");
      try {
        const nouvelle = "0x" + crypto.createHash("sha256").update((await req(`/api/clients/${slug3}/fiche-controle`)).octets).digest("hex");
        expect(nouvelle).to.not.equal(ficheSha256);
        expect(nouvelle).to.equal(empreinteFiche(change));
        const refus3 = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug: slug3, parametres: {} } });
        expect([refus3.statut, refus3.json.error.code]).to.deep.equal([400, "confirmation_absente"]);
        expect(refus3.json.error.message).to.contain(`(fiche de contrôle ${nouvelle})`);
        expect(pont.envoisRecus.length, "rien n'est envoyé").to.equal(envois);
        const pageChangee = (await req(`/clients/${slug3}/fiche-controle`)).texte;
        expect(pageChangee).to.contain('data-confirmations-perimees="2"');
        expect(pageChangee).to.contain('data-fiche-controle="fiche_a_confirmer"');
        expect((await req(`/api/clients/${slug3}/confirmations`)).json.confirmations.filter((x) => x.perimee).map((x) => x.id)).to.include(cf.json.id);
      } finally {
        fs.writeFileSync(fichierDossier, original);
      }
      // 5. Le dossier rétabli, la confirmation vaut de nouveau : pas 2 à 5 faits ; le déploiement du jeu a consommé la
      // confirmation de la fiche, le versement la sienne ; la sortie du travail est celle de l'outil (aucun membre de plus).
      t = await travail({ commande: "inscrire-client", slug: slug3, parametres: {} });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      expect(Object.keys(t.sortie.outputs).sort()).to.deep.equal(["assignment", "curator_set", "funded", "set_deployment", "set_read"]);
      const registre = (await req(`/api/clients/${slug3}/confirmations`)).json.confirmations;
      const fiche = registre.find((x) => x.id === cf.json.id);
      expect(fiche.consommee_par).to.equal(t.id);
      expect(fiche.perimee).to.equal(false);
      expect(registre.find((x) => x.operation === "approvisionnement").consommee_par).to.equal(t.id);
      const lignesRegistre = fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
      expect(lignesRegistre.find((l) => l.consommation === cf.json.id)).to.include({ travail: t.id, org_id: dossier.organisation.org_id, fiche_sha256: ficheSha256 });
      const pageFaite = (await req(`/clients/${slug3}/fiche-controle`)).texte;
      expect(pageFaite).to.contain('data-fiche-controle="fiche_adresses_enregistrees"');
      // Le nom interne n'entre pas dans la fiche : la fiche d'un client nommé ne porte que son nom court.
      expect((await req(`/api/clients/${slug3}/notes`, { methode: "POST", corps: { sorte: "nom_interne", nom: "Coopérative Fictive FC9X2" } })).statut).to.equal(200);
      expect((await req(`/api/clients/${slug3}/fiche-controle`)).texte).to.not.match(/Coopérative|FC9X2/);
      expect((await req(`/clients/${slug3}/fiche-controle`)).texte.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "")).to.not.match(/Coopérative|FC9X2/);
    });

    it("décisions du 2026-11-25 (noms et versions) : l'agent enregistre chaque version de la fiche (la version 1 à la préparation, une de plus à chaque note de noms qui change la fiche, jamais deux fois la même empreinte) ; la note des noms refuse une adresse hors du dossier et, l'étape 2 faite, est refusée (fiche_figee) ; la confirmation d'une version d'avant est notée, dite « ne vaut plus », et ne débloque rien, sans rien envoyer ; celle de la version courante débloque et se consomme ; les noms n'entrent pas dans le dossier", async function () {
      const { texteFiche, empreinteFiche } = await import("../paquets/inscription/src/commun/fiche-controle.mjs");
      const slug4 = "application-noms";
      const k = crypto.createHash("sha256").update("noortrace/essai/inscription/application/noms/chaine").digest();
      const fk = path.join(dir, "chaine-noms.cle");
      fs.writeFileSync(fk, k.toString("hex"), { mode: 0o600 });
      const chaine = { reference: `fichier:${fk}`, adresse: new SignataireChaineFichier(new Uint8Array(k)).adresse() };
      const app = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
      let t = await travail({ commande: "inscrire-client-preparer", slug: slug4, parametres: { org: slug4, journaux: [JOURNAL], approbateurs: app, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [O.documentCle({ keyId: "rec-noms-01", journalId: JID, chainKey: chaine.adresse, publique: O.cleEd25519("application-noms").publique })] } });
      expect(t.sortie.result).to.equal("reussi");
      let vue = (await req(`/api/clients/${slug4}`)).json;
      const dossier = vue.dossier;
      const org = dossier.organisation.org_id;
      const [m1] = dossier.approvers.members;
      const v1 = empreinteFiche(dossier);
      const v2 = empreinteFiche(dossier, { [m1]: "Camille Durand" });
      expect(v2).to.not.equal(v1);
      const versionsEnregistrees = () => fs.readFileSync(path.join(a.donnees, "fiches-controle.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((l) => l.org_id === org).map((l) => [l.version, l.fiche_sha256]);
      const versionsVues = async () => ((await req(`/api/clients/${slug4}`)).json.fiche.versions.map((x) => [x.version, x.fiche_sha256, x.courante]));
      // 1. La version 1, enregistrée à la préparation ; rendue avec le dossier.
      expect(versionsEnregistrees()).to.deep.equal([[1, v1]]);
      expect(await versionsVues()).to.deep.equal([[1, v1, true]]);
      // 2. La note des noms : une adresse hors du dossier est refusée ; un nom accepté fait la version 2 ; le même nom
      // de nouveau n'ajoute rien ; le nom retiré ramène la fiche à la version 1, déjà enregistrée.
      const note = (corps) => req(`/api/clients/${slug4}/notes`, { methode: "POST", corps });
      let r = await note({ sorte: "noms_approbateurs", noms: [{ adresse: O.compteHardhat(8).adresse, nom: "Personne Inconnue" }] });
      expect([r.statut, r.json.error.code]).to.deep.equal([400, "requete_invalide"]);
      expect(r.json.error.message).to.contain("hors des approbateurs du dossier");
      expect(r.texte).to.not.contain("Personne Inconnue");
      r = await note({ sorte: "noms_approbateurs", noms: [{ adresse: m1, nom: "Camille Durand" }] });
      expect(r.statut, r.texte).to.equal(200);
      expect((await req(`/api/clients/${slug4}/fiche-controle`)).texte).to.equal(texteFiche(dossier, { [m1]: "Camille Durand" }));
      vue = (await req(`/api/clients/${slug4}`)).json;
      expect(vue.fiche.sha256).to.equal(v2);
      expect(vue.fiche.noms).to.deep.equal({ [m1]: "Camille Durand" });
      expect(versionsEnregistrees()).to.deep.equal([[1, v1], [2, v2]]);
      expect(await versionsVues()).to.deep.equal([[2, v2, true], [1, v1, false]]);
      expect((await note({ sorte: "noms_approbateurs", noms: [{ adresse: m1, nom: "Camille Durand" }] })).statut).to.equal(200);
      expect(versionsEnregistrees(), "la même empreinte n'est pas enregistrée deux fois").to.deep.equal([[1, v1], [2, v2]]);
      expect((await note({ sorte: "noms_approbateurs", noms: [{ adresse: m1, nom: null }] })).statut).to.equal(200);
      expect(await versionsVues(), "le nom retiré : la version 1 redevient la courante").to.deep.equal([[2, v2, false], [1, v1, true]]);
      expect(versionsEnregistrees()).to.deep.equal([[1, v1], [2, v2]]);
      expect((await note({ sorte: "noms_approbateurs", noms: [{ adresse: m1, nom: "Camille Durand" }] })).statut).to.equal(200);
      expect(await versionsVues()).to.deep.equal([[2, v2, true], [1, v1, false]]);
      const journal = () => fs.readFileSync(path.join(a.donnees, "journal-agent.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((l) => l.evenement === "fiche_controle_version" && l.org_id === org);
      expect(journal().map((l) => [l.version, l.fiche_sha256])).to.deep.equal([[1, v1], [2, v2]]);
      expect(fs.readFileSync(a.client(slug4).dossier, "utf8"), "le dossier ne porte pas les noms").to.not.contain("Camille");
      // 3. La confirmation de la version 1, celle d'avant : notée, dite « ne vaut plus », l'étape 2 reste bloquée, rien n'est envoyé.
      expect((await req(`/api/clients/${slug4}/confirmations`, { methode: "POST", corps: { operation: "approvisionnement", objet: { org_id: org, cle_chaine: chaine.adresse }, personne_client: "Responsable de l'essai", canal: "appel au numéro du contrat", instant: "2026-11-25T10:00:00.000Z", piece_sha256: "0x" + "67".repeat(32) } })).statut).to.equal(200);
      const cf1 = await req(`/api/clients/${slug4}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: org, fiche_sha256: v1 }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T10:05:00.000Z", piece_sha256: v1 } });
      expect(cf1.statut, cf1.texte).to.equal(200);
      const envois = pont.envoisRecus.length;
      const refus = await req("/api/travaux", { methode: "POST", corps: { commande: "inscrire-client", slug: slug4, parametres: {} } });
      expect([refus.statut, refus.json.error.code]).to.deep.equal([400, "confirmation_absente"]);
      expect(refus.json.error.message).to.contain(`(fiche de contrôle ${v2})`);
      expect(pont.envoisRecus.length, "rien n'est envoyé").to.equal(envois);
      expect((await req(`/api/clients/${slug4}/confirmations`)).json.confirmations.find((x) => x.id === cf1.json.id).perimee).to.equal(true);
      // 4. La version courante confirmée : l'étape 2 se fait et consomme cette confirmation, pas celle d'avant.
      const cf2 = await req(`/api/clients/${slug4}/confirmations`, { methode: "POST", corps: { operation: "jeu_approbateurs", objet: { org_id: org, fiche_sha256: v2 }, personne_client: "Responsable de l'essai", canal: "fiche renvoyée signée, par courrier", instant: "2026-11-25T10:10:00.000Z", piece_sha256: v2 } });
      expect(cf2.statut, cf2.texte).to.equal(200);
      t = await travail({ commande: "inscrire-client", slug: slug4, parametres: {} });
      expect(t.sortie.result, JSON.stringify(t.sortie.error)).to.equal("reussi");
      const registre = (await req(`/api/clients/${slug4}/confirmations`)).json.confirmations;
      expect(registre.find((x) => x.id === cf2.json.id)).to.include({ consommee_par: t.id, perimee: false });
      expect(registre.find((x) => x.id === cf1.json.id)).to.include({ consommee_par: null, perimee: true });
      expect(fs.readFileSync(path.join(a.donnees, "confirmations.ndjson"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).find((l) => l.consommation === cf2.json.id)).to.include({ travail: t.id, fiche_sha256: v2 });
      // 5. L'étape 2 faite : les noms ne changent plus ; la fiche reste celle confirmée ; aucune version de plus.
      r = await note({ sorte: "noms_approbateurs", noms: [{ adresse: m1, nom: "Autre Nom" }] });
      expect([r.statut, r.json.error.code]).to.deep.equal([400, "fiche_figee"]);
      expect((await req(`/api/clients/${slug4}/fiche-controle`)).texte).to.equal(texteFiche(dossier, { [m1]: "Camille Durand" }));
      expect(versionsEnregistrees()).to.deep.equal([[1, v1], [2, v2]]);
      expect((await req(`/clients/${slug4}/fiche-controle`)).texte).to.not.contain("data-noms-approbateurs-action");
      expect((await req(`/clients/${slug4}`)).texte, "la fiche du client ne porte pas la saisie des noms").to.not.contain("data-noms-approbateurs-action");
      expect(fs.readFileSync(a.client(slug4).dossier, "utf8")).to.not.contain("Camille");
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
