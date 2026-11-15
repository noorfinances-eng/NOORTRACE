// Inscription des clients, revue de sécurité interne de l'étape 8
// (paquets/inscription) : un essai par constat corrigé, qui échoue sur le code
// d'avant la correction et passe après, et, pour chaque règle nouvelle, un
// mutant (copie du paquet sous NOORTRACE_TMP où la règle est retirée par un
// remplacement textuel exact et unique) que l'oracle de l'essai tue ; les
// copies sont détruites à la fin.
//
// Constats : CT-4 EX-7.28 (comptes de l'agent et de l'interface, EX-7.23),
// EX-7.3 (clé de chaîne en clair en production), (jeton
// vers un point http:// en production, EX-7.1), EX-7.25 (références d'un
// travail : répertoire de clés, alias, message unique), CT-7 CLE-37,
// (interface d'exploitant : fichier des comptes, écoute,
// HSTS, verrou par nom et adresse, sessions, hôte), 
// (plafond nul, budget_jour), (instance relue), (journal,
// refus comptés, bornes du paquet).
//
// Le paquet éprouvé est paquets/inscription du dépôt ; NOORTRACE_INSCRIPTION_PAQUET
// désigne une autre racine du paquet (rejeu rouge/vert de la revue sur une
// copie d'avant la correction). Les agents sont lancés en processus séparés
// (lanceur d'essai de test/fixtures/inscription, qui admet un seul compte).

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { registerHooks } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as R from "@noortrace/ancrage/registre";
import * as O from "./fixtures/inscription/outils.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PAQUET = process.env.NOORTRACE_INSCRIPTION_PAQUET ? path.resolve(process.env.NOORTRACE_INSCRIPTION_PAQUET) : path.join(RACINE, "paquets", "inscription");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const VECTEURS = path.join(RACINE, "spec", "vecteurs", "ct-4", "manifestes", "valides");
const X = "exploitant operateur-1";
const ETAT_INTERFACE = Symbol.for("noortrace.inscription.interface");

const importer = (racine, rel) => import(pathToFileURL(path.join(racine, "src", rel)).href);

/**
 * Le mandataire de l'interface (src/web/proxy.mjs) importe « next/server », comme Next le prescrit : son bâti
 * (`next build`, Turbopack) résout ce chemin, mais Node seul ne le résout pas, le paquet next n'ayant pas de table
 * « exports » (son module de ce chemin est next/server.js, celui que l'essai importe pour NextRequest). L'essai charge
 * donc le mandataire avec cette seule résolution ajoutée, pour les imports de proxy.mjs et le temps de l'import, quel
 * que soit le lanceur (mocha seul, ou Hardhat et son chargeur tsx, qui la fait déjà).
 */
async function importerMandataire(racine) {
  const crochet = registerHooks({
    resolve: (specifier, contexte, suivant) => suivant(specifier === "next/server" && contexte.parentURL?.endsWith("/src/web/proxy.mjs") ? "next/server.js" : specifier, contexte),
  });
  try {
    return await importer(racine, "web/proxy.mjs");
  } finally {
    crochet.deregister();
  }
}
const livre = (rel) => importer(PAQUET, rel);
const temporaire = (prefixe) => {
  fs.mkdirSync(TMP, { recursive: true });
  return fs.mkdtempSync(path.join(TMP, prefixe));
};
const TEMPORAIRES = [];
const tmp = (prefixe = "noortrace-revue-inscription-") => {
  const d = temporaire(prefixe);
  TEMPORAIRES.push(d);
  return d;
};

// ---------------------------------------------------------------------------
// Fabrique de mutants : copie de src/, schemas/, bin/ et package.json du
// paquet (sans la sortie de « next build », src/web/.next, que ni les essais ni
// les mutants ne chargent), node_modules du dépôt lié, puis chaque remplacement
// { fichier, ancien, nouveau }, `ancien` devant apparaître exactement une fois.
// ---------------------------------------------------------------------------
const horsConstruction = (source) => !source.split(path.sep).includes(".next");
function mutant(nom, remplacements) {
  const racine = tmp(`noortrace-revue-inscription-mutant-${nom}-`);
  for (const d of ["src", "schemas", "bin"]) fs.cpSync(path.join(PAQUET, d), path.join(racine, d), { recursive: true, filter: horsConstruction });
  fs.copyFileSync(path.join(PAQUET, "package.json"), path.join(racine, "package.json"));
  fs.symlinkSync(path.join(RACINE, "node_modules"), path.join(racine, "node_modules"));
  for (const r of remplacements) {
    const f = path.join(racine, "src", r.fichier);
    const texte = fs.readFileSync(f, "utf8");
    const n = texte.split(r.ancien).length - 1;
    if (n !== 1) throw new Error(`mutant ${nom} : « ${r.ancien} » trouvé ${n} fois dans ${r.fichier}`);
    fs.writeFileSync(f, texte.replace(r.ancien, () => r.nouveau));
  }
  return { racine, importer: (rel) => importer(racine, rel) };
}

/** Copie d'un vecteur de manifeste (`developpement` ou `production`) ; rend le chemin de son `instance-r1.json`. */
function copierVecteur(nom, dans = tmp("noortrace-revue-instance-")) {
  const d = path.join(dans, "instance");
  fs.cpSync(path.join(VECTEURS, nom), d, { recursive: true });
  return path.join(d, "instance-r1.json");
}

/** Répertoires d'une configuration d'agent (prise 0750, données 0750) ; rend `{ base, config }` (à compléter). */
function configurationAgent({ nature = "developpement", instance, rpc = ["http://127.0.0.1:9"], interfaceUid = process.getuid(), comptes = {}, cles = null, jeton = null } = {}) {
  const base = tmp();
  const prises = path.join(base, "prise");
  const donnees = path.join(base, "donnees");
  fs.mkdirSync(prises, { mode: 0o750 });
  fs.chmodSync(prises, 0o750);
  fs.mkdirSync(donnees, { mode: 0o750 });
  fs.chmodSync(donnees, 0o750);
  const config = { version: 0, prise: path.join(prises, "agent.sock"), interface_uid: interfaceUid, donnees, nature, instance, rpc, jeton, comptes, delai_s: 3 };
  if (cles) config.cles = cles;
  return { base, config, chemin: (() => {
    const c = path.join(base, "agent.json");
    fs.writeFileSync(c, JSON.stringify(config));
    return c;
  })() };
}

/** Lance le binaire d'une racine du paquet ; rend `{ code, stderr, pret, processus }`. */
function lancerBinaire(racine, cheminConfig, env = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(racine, "bin", "noortrace-inscription-agent"), "--config", cheminConfig], { cwd: RACINE, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreurs = "";
    p.stdout.on("data", (d) => {
      sortie += d;
      if (sortie.includes("\n")) resolve({ processus: p, pret: JSON.parse(sortie.split("\n")[0]), stderr: erreurs });
    });
    p.stderr.on("data", (d) => (erreurs += d));
    p.on("exit", (code) => resolve({ code, stderr: erreurs }));
  });
}

const fichier64hex = (dir, nom, mode = 0o600, contenu = "11".repeat(32)) => {
  const f = path.join(dir, nom);
  fs.writeFileSync(f, contenu + "\n", { mode });
  fs.chmodSync(f, mode);
  return f;
};

after(function () {
  for (const d of TEMPORAIRES) fs.rmSync(d, { recursive: true, force: true });
});

describe("inscription : corrections de la revue de l'étape 8 (paquets/inscription)", function () {
  this.timeout(600000);

  // -------------------------------------------------------------------------
  describe("agent : comptes et références (CT-4 EX-7.28, CT-4 EX-7.3, CT-4 EX-7.1, CT-4 EX-7.25)", function () {
    it("CT-4 EX-7.28 : l'agent refuse de démarrer quand interface_uid est son propre compte ou le compte 0, ou sous le compte 0 (EX-7.23) ; le binaire rend 2 ; l'option memeCompteAdmis de l'API programmatique le lève (essais) ; mutant sans controlerComptes : démarrage admis (tué)", async function () {
      const C = await livre("agent/configuration.mjs");
      const config0 = { interface_uid: 1000 };
      expect(() => C.controlerComptes(config0, { uid: 1000 })).to.throw(C.ErreurConfiguration, /EX-7\.23/);
      expect(() => C.controlerComptes({ interface_uid: 0 }, { uid: 1000 })).to.throw(C.ErreurConfiguration, /compte 0/);
      expect(() => C.controlerComptes({ interface_uid: 1001 }, { uid: 0 })).to.throw(C.ErreurConfiguration, /compte 0/);
      expect(() => C.controlerComptes({ interface_uid: 1001 }, { uid: 1000 })).to.not.throw();
      // Démarrage entier : le compte de l'essai désigné comme interface est refusé avant tout autre contrôle.
      const A = await livre("agent/index.mjs");
      const instance = copierVecteur("production");
      // Un jeton du nœud par variable : sa résolution fait partie du démarrage éprouvé.
      const env = { NOORTRACE_REVUE_JETON: "jeton-essai-sans-valeur" };
      const { chemin, config } = configurationAgent({ nature: "production", instance, rpc: ["https://rpc.noortrace.example"], jeton: "env:NOORTRACE_REVUE_JETON" });
      expect(() => A.preparerDemarrage(config, { racine: RACINE, controlerPrise: false })).to.throw(C.ErreurConfiguration, /EX-7\.23/);
      // Le binaire ne passe aucune option : code 2, message sur la sortie d'erreur.
      const r = await lancerBinaire(PAQUET, chemin, env);
      if (r.processus) r.processus.kill("SIGKILL");
      expect(r.code, r.stderr).to.equal(2);
      expect(r.stderr).to.match(/EX-7\.23/);
      // Le lanceur d'essai (API programmatique, memeCompteAdmis) démarre le même agent ; tous les autres contrôles s'appliquent.
      const arreter = async (lance) => {
        if (!lance.processus) return;
        lance.processus.kill("SIGTERM");
        await new Promise((ok) => lance.processus.once("exit", ok));
      };
      const essai = await O.lancerAgent(chemin, { env });
      await arreter(essai);
      expect(essai.pret, typeof essai.stderr === "function" ? essai.stderr() : essai.stderr).to.deep.include({ pret: true, prise: config.prise });
      // Mutant : la séparation des comptes retirée des deux points d'entrée ; le binaire mutant démarre sous un seul compte.
      const m = mutant("meme-compte", [
        { fichier: "agent/index.mjs", ancien: "if (memeCompteAdmis !== true) controlerComptes(config);", nouveau: "if (false) controlerComptes(config);" },
        { fichier: "agent/configuration.mjs", ancien: "if (options.memeCompteAdmis !== true) controlerComptes(config, { uid });", nouveau: "if (false) controlerComptes(config, { uid });" },
      ]);
      const MC = await m.importer("agent/configuration.mjs");
      expect(() => MC.controlerRepertoires(config), "mutant : controlerRepertoires n'applique plus EX-7.23").to.not.throw(/EX-7\.23/);
      const mute = await lancerBinaire(m.racine, chemin, env);
      await arreter(mute);
      expect(mute.pret, `mutant : la réponse retirée, le binaire démarre sous le compte de l'interface (${mute.stderr})`).to.deep.include({ pret: true });
    });

    it("CT-4 EX-7.3 : en production, fichier: et env: sont refusées pour la clé de chaîne comme pour tout rôle (reference_refusee), aucune clé n'est chargée ; en développement elles restent admises ; mutant qui admet cle_chaine : admise (tué)", async function () {
      const Ref = await livre("commun/references.mjs");
      const K = await livre("agent/cles.mjs");
      const prod = (role) => ({ role, nature: "production", evmChainId: 5124 });
      for (const forme of ["fichier", "env"]) {
        expect(Ref.motifRefusReference({ forme }, prod("cle_chaine")), `${forme}: cle_chaine`).to.equal("reference_refusee");
        expect(Ref.motifRefusReference({ forme }, prod("tresorerie")), `${forme}: tresorerie`).to.equal("reference_refusee");
        expect(Ref.motifRefusReference({ forme }, { role: "cle_chaine", nature: "developpement", evmChainId: 31337 }), `${forme}: développement`).to.equal(null);
      }
      const dir = tmp();
      const f = fichier64hex(dir, "chaine.cle");
      let erreur = null;
      try {
        K.signataire(`fichier:${f}`, prod("cle_chaine"));
      } catch (e) {
        erreur = e;
      }
      expect(erreur, "signataire en production").to.be.an.instanceOf(K.ErreurReference);
      expect(erreur.code).to.equal("reference_refusee");
      expect(erreur.message).to.not.contain("11".repeat(32));
      // Mutant : la clé de chaîne de nouveau admise en production.
      const m = mutant("reference-production", [{ fichier: "commun/references.mjs", ancien: 'if (nature === "production") return "reference_refusee";', nouveau: 'if (nature === "production" && role !== "cle_chaine") return "reference_refusee";' }]);
      const MR = await m.importer("commun/references.mjs");
      const MK = await m.importer("agent/cles.mjs");
      expect(MR.motifRefusReference({ forme: "fichier" }, prod("cle_chaine")), "mutant : la réponse retirée, la forme est admise").to.equal(null);
      expect(MK.signataire(`fichier:${f}`, prod("cle_chaine")).adresse(), "mutant : la clé est chargée en mémoire de l'agent").to.match(/^0x[0-9a-f]{40}$/);
    });

    it("en production, un point http:// hors de la boucle locale est refusé au démarrage (EX-7.1) et OP-2 contrôle tous les points avant le premier appel : aucune requête, le jeton ne part pas ; mutants (démarrage admis ; contrôle point par point) : jeton envoyé au second point (tués)", async function () {
      const C = await livre("agent/configuration.mjs");
      const P1 = "https://validateur-1.noortrace.example";
      const P2 = "http://198.51.100.7:8545";
      const JETON = "jeton-d-essai-sans-valeur";
      const base = { version: 0, prise: "/run/a/agent.sock", interface_uid: 991, donnees: "/var/lib/a", instance: "/etc/a/instance-r1.json", jeton: "env:JETON", comptes: {}, delai_s: 3 };
      expect(() => C.lireConfiguration({ ...base, nature: "production", rpc: [P1, P2] })).to.throw(C.ErreurConfiguration, /EX-7\.1/);
      expect(C.lireConfiguration({ ...base, nature: "production", rpc: [P1, "http://127.0.0.1:8645", "http://[::1]:8645", "http://localhost:8645"] }).rpc).to.have.length(4);
      expect(C.lireConfiguration({ ...base, nature: "developpement", rpc: [P1, P2] }).rpc).to.have.length(2);
      // OP-2 avec un faux transport : le premier point rend un index de suiveur puis se tait, le second répond à tout.
      const scenario = async (racine) => {
        const Rs = await importer(racine, "agent/reseau.mjs");
        const B = await importer(racine, "agent/commandes/base.mjs");
        const S = await importer(racine, "agent/sortie.mjs");
        const recus = [];
        const faux = async (url, init) => {
          const corps = JSON.parse(Buffer.from(init.body).toString("utf8"));
          recus.push({ url, methode: corps.method, jeton: init.headers.authorization === `Bearer ${JETON}` });
          const rendre = (result) => new Response(JSON.stringify({ jsonrpc: "2.0", id: corps.id, result }), { status: 200, headers: { "content-type": "application/json" } });
          if (url === P1) {
            if (corps.method === "eth_blockNumber") return rendre("0x10");
            if (corps.method === "noor_txindexStatus") return rendre({ last_indexed_height: 0 });
            throw new TypeError("connexion coupée");
          }
          return rendre("0x1d2d3c");
        };
        const rpc = new R.ClientRpc({ points: [P1, P2], transport: Rs.transportAvecJeton(JETON, { fetch: faux }), delaiMs: 2000 });
        const ctx = { rpc, instance: { nature: "production", manifeste: {}, evmChainId: 1912124, bftChainId: "x", validatorSetHash: "0x", contrats: {}, attestationDeploiement: null }, attendre: async () => {} };
        const sortie = new S.Sortie("capturer", ctx);
        let fin = null;
        try {
          await B.prealables(ctx, sortie);
        } catch (e) {
          if (e.name !== "FinCommande") throw e;
          fin = e;
        }
        return { fin, recus, fuite: recus.filter((r) => r.url === P2 && r.jeton).length };
      };
      const s = await scenario(PAQUET);
      expect(s.fin, "OP-2 arrête la commande").to.not.equal(null);
      expect(s.fin.code).to.equal("noeud_injoignable");
      expect(s.recus, "aucune requête avant le contrôle de tous les points").to.deep.equal([]);
      expect(s.fuite).to.equal(0);
      // Mutant 1 : le démarrage n'applique plus EX-7.1.
      const m1 = mutant("points-demarrage", [{ fichier: "agent/configuration.mjs", ancien: 'if (c.nature === "production") {\n    const refuses = pointsRefusesEnProduction(c.rpc);', nouveau: "if (false) {\n    const refuses = pointsRefusesEnProduction(c.rpc);" }]);
      const M1 = await m1.importer("agent/configuration.mjs");
      expect(M1.lireConfiguration({ ...base, nature: "production", rpc: [P1, P2] }).rpc, "mutant : la réponse retirée, la configuration est admise").to.deep.equal([P1, P2]);
      // Mutant 2 : OP-2 ne contrôle plus les points avant d'appeler : le jeton part vers le second point.
      const m2 = mutant("points-reseau", [{ fichier: "agent/reseau.mjs", ancien: 'if (nature === "production") {\n    const refuses = pointsRefusesEnProduction(rpc.points());', nouveau: "if (false) {\n    const refuses = pointsRefusesEnProduction(rpc.points());" }]);
      const s2 = await scenario(m2.racine);
      expect(s2.fuite, "mutant : la réponse retirée, le jeton part en clair vers le point http:// non local").to.be.greaterThan(0);
    });

    it("CT-4 EX-7.25 : une référence de travail ne désigne qu'un fichier du répertoire de clés de l'agent ou un alias de sa configuration, env: y est refusée ; toute référence qui ne se résout pas rend à l'interface le même message, le détail va au journal ; mutants (répertoire non contrôlé ; message détaillé) : tués", async function () {
      const T = await livre("commun/travaux.mjs");
      const K = await livre("agent/cles.mjs");
      const B = await livre("agent/commandes/base.mjs");
      const S = await livre("agent/sortie.mjs");
      const dir = tmp();
      const cles = { repertoire: dir, alias: { "chaine-1": `fichier:${path.join(dir, "alias.cle")}`, "compte-essai": "hardhat:3" } };
      const slug = `o-${"ab".repeat(16)}`;
      // Formes d'un travail : env: refusée, alias: admise.
      expect(() => T.lireTravail({ commande: "inscrire-cle", slug, parametres: { demande: {}, cle_chaine: "env:CLE_CHAINE" } })).to.throw(/env: non admise/);
      expect(T.lireTravail({ commande: "inscrire-cle", slug, parametres: { demande: {}, cle_chaine: "alias:chaine-1" } }).parametres.cle_chaine).to.equal("alias:chaine-1");
      // Référence effective : sous le répertoire de clés seulement, directement ; alias connu seulement.
      const M = K.MESSAGE_REFERENCE_NON_RESOLUE;
      const refus = (reference, c = cles) => {
        try {
          K.referenceDeTravail("cle_chaine", reference, c);
        } catch (e) {
          expect(e).to.be.an.instanceOf(K.ErreurReference);
          return e;
        }
        return null;
      };
      expect(refus("fichier:/etc/shadow")?.message).to.equal(M);
      expect(refus(`fichier:${path.join(dir, "sous", "x.cle")}`)?.message).to.equal(M);
      expect(refus(`fichier:${path.join(dir, ".cachee.cle")}`)?.message).to.equal(M);
      expect(refus("alias:inconnu")?.message).to.equal(M);
      expect(refus(`fichier:${path.join(dir, "x.cle")}`, { repertoire: null, alias: {} })?.message, "sans répertoire de clés, aucun fichier").to.equal(M);
      expect(refus("fichier:/etc/shadow").detail).to.match(/hors du répertoire de clés/);
      expect(K.referenceDeTravail("cle_chaine", `fichier:${path.join(dir, "x.cle")}`, cles)).to.deep.equal({ reference: `fichier:${path.join(dir, "x.cle")}`, forme: "fichier", alias: null });
      expect(K.referenceDeTravail("cle_chaine", "alias:chaine-1", cles)).to.deep.equal({ reference: cles.alias["chaine-1"], forme: "fichier", alias: "chaine-1" });
      expect(K.referenceDeTravail("tresorerie", "alias:compte-essai", cles)).to.deep.equal({ reference: "hardhat:3", forme: "hardhat", alias: "compte-essai" });
      // Message unique à la résolution (cleRole), détail au journal, pour quatre fichiers et deux formes.
      const texte = fichier64hex(dir, "texte.cle", 0o600, "un jeton quelconque");
      const ouvert = fichier64hex(dir, "ouvert.cle", 0o644);
      const bon = fichier64hex(dir, "bon.cle");
      fs.mkdirSync(path.join(dir, "repertoire.cle"));
      const cas = [`fichier:${path.join(dir, "absent.cle")}`, `fichier:${path.join(dir, "repertoire.cle")}`, `fichier:${ouvert}`, `fichier:${texte}`, "alias:inconnu", "fichier:/etc/shadow"];
      const resoudre = async (racine, reference) => {
        const Bx = racine === PAQUET ? B : await importer(racine, "agent/commandes/base.mjs");
        const Sx = racine === PAQUET ? S : await importer(racine, "agent/sortie.mjs");
        const journal = [];
        const ctx = { config: { comptes: {}, cles }, instance: { nature: "developpement", evmChainId: 31337 }, consigner: (evenement, champs) => journal.push({ evenement, ...champs }), travailId: "trv-essai", slug: "essai" };
        const sortie = new Sx.Sortie("inscrire-cle", ctx);
        try {
          const s = Bx.cleRole(ctx, sortie, "cle_chaine", reference);
          return { adresse: s.adresse(), journal };
        } catch (e) {
          if (e.name !== "FinCommande") throw e;
          return { message: e.message, code: e.code, journal };
        }
      };
      const resultats = [];
      for (const c of cas) resultats.push(await resoudre(PAQUET, c));
      for (const r of resultats) {
        expect(r.message, JSON.stringify(r)).to.equal(M);
        expect(r.code).to.equal("usage");
        expect(r.journal.filter((l) => l.evenement === "reference_non_resolue")).to.have.length(1);
      }
      const details = new Set(resultats.map((r) => r.journal[0].detail));
      expect(details.size, "le détail, au journal seulement, distingue les cas").to.be.at.least(4);
      for (const r of resultats) for (const l of r.journal) expect(JSON.stringify(l)).to.not.contain("11".repeat(32));
      const ok = await resoudre(PAQUET, `fichier:${bon}`);
      expect(ok.adresse).to.match(/^0x[0-9a-f]{40}$/);
      expect(ok.journal.find((l) => l.evenement === "reference_employee")).to.include({ reference: `fichier:${bon}`, alias: null });
      // Mutant 1 : le répertoire de clés n'est plus contrôlé : /etc/shadow est désigné.
      const m1 = mutant("cles-repertoire", [{ fichier: "agent/cles.mjs", ancien: 'if (path.dirname(chemin) !== base || path.basename(chemin).startsWith(".")) refuser("fichier hors du répertoire de clés de l\'agent");', nouveau: 'if (false) refuser("fichier hors du répertoire de clés de l\'agent");' }]);
      const MK = await m1.importer("agent/cles.mjs");
      expect(MK.referenceDeTravail("cle_chaine", "fichier:/etc/shadow", cles).reference, "mutant : la réponse retirée, tout chemin est désigné").to.equal("fichier:/etc/shadow");
      // Mutant 2 : le message détaillé repart vers l'interface.
      const m2 = mutant("cles-message", [{ fichier: "agent/commandes/base.mjs", ancien: 'sortie.arreter("inutilisable", "usage", null, MESSAGE_REFERENCE_NON_RESOLUE);', nouveau: 'sortie.arreter("inutilisable", "usage", null, String(e.detail ?? e.message));' }]);
      const mutes = [];
      for (const c of cas) mutes.push((await resoudre(m2.racine, c)).message);
      expect(new Set(mutes).size, "mutant : la réponse retirée, les messages renseignent l'interface").to.be.greaterThan(1);
    });
  });

  // -------------------------------------------------------------------------
  describe("interface d'exploitant (CT-7 CLE-37)", function () {
    const reinitialiser = () => {
      delete globalThis[ETAT_INTERFACE];
    };
    const comptesAvec = (dir, { mode = 0o600, nom = "alice", motDePasse = "mot de passe de l'essai" } = {}) => {
      const sel = crypto.randomBytes(16);
      const cle = crypto.scryptSync(Buffer.from(motDePasse, "utf8"), sel, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 });
      const f = path.join(dir, `comptes-${(mode).toString(8)}.json`);
      fs.writeFileSync(f, JSON.stringify({ version: 0, accounts: [{ name: nom, salt: sel.toString("hex"), key: cle.toString("hex") }] }), { mode });
      fs.chmodSync(f, mode);
      return { chemin: f, nom, motDePasse };
    };
    const configurationInterface = (dir, membres) => {
      const f = path.join(dir, `interface-${crypto.randomBytes(4).toString("hex")}.json`);
      fs.writeFileSync(f, JSON.stringify({ version: 0, ecoute: { hote: "127.0.0.1", port: 8443 }, origine: "https://inscription.noortrace.example", prise: "/run/x/agent.sock", donnees: "/var/lib/x", nature: "developpement", ...membres }));
      return f;
    };
    afterEach(reinitialiser);

    it("CT-7 CLE-37 : le fichier des comptes lisible par d'autres que son propriétaire est refusé ; en production, ecoute.hote hors de la boucle locale est refusée et chaque réponse porte Strict-Transport-Security ; mutants : tués", async function () {
      const Sv = await livre("web/lib/serveur.mjs");
      const dir = tmp();
      const ouvert = comptesAvec(dir, { mode: 0o644 });
      const ferme = comptesAvec(dir, { mode: 0o600 });
      expect(() => Sv.lireComptes(ouvert.chemin)).to.throw(Sv.ErreurConfigurationInterface, /lisible par d'autres/);
      expect(Sv.lireComptes(ferme.chemin).size).to.equal(1);
      const prod = (hote) => configurationInterface(dir, { nature: "production", ecoute: { hote, port: 8443 }, comptes: `fichier:${ferme.chemin}` });
      expect(() => Sv.lireConfigurationInterface(prod("0.0.0.0"))).to.throw(Sv.ErreurConfigurationInterface, /ecoute\.hote/);
      expect(() => Sv.lireConfigurationInterface(prod("192.0.2.5"))).to.throw(Sv.ErreurConfigurationInterface, /ecoute\.hote/);
      expect(Sv.lireConfigurationInterface(prod("127.0.0.1")).ecoute.hote).to.equal("127.0.0.1");
      expect(Sv.lireConfigurationInterface(configurationInterface(dir, { ecoute: { hote: "0.0.0.0", port: 8443 }, comptes: `fichier:${ferme.chemin}` })).ecoute.hote, "hors production : libre").to.equal("0.0.0.0");
      // HSTS : mandataire de Next appelé avec une requête de production.
      const { NextRequest } = await import("next/server.js");
      const hsts = async (racine, nature) => {
        reinitialiser();
        process.env.NOORTRACE_INSCRIPTION_CONFIG = configurationInterface(dir, { nature, origine: nature === "production" ? "https://inscription.noortrace.example" : "http://127.0.0.1:8443", comptes: `fichier:${ferme.chemin}` });
        const Px = await importerMandataire(racine);
        const hote = nature === "production" ? "inscription.noortrace.example" : "127.0.0.1:8443";
        const reponse = Px.proxy(new NextRequest(`https://${hote}/connexion`, { headers: { host: hote } }));
        return reponse.headers.get("strict-transport-security");
      };
      expect(await hsts(PAQUET, "production")).to.equal("max-age=63072000; includeSubDomains");
      expect(await hsts(PAQUET, "developpement")).to.equal(null);
      // Mutants.
      const m1 = mutant("interface-comptes", [{ fichier: "web/lib/serveur.mjs", ancien: "if ((st.mode & 0o077) !== 0) throw new ErreurConfigurationInterface(", nouveau: "if (false) throw new ErreurConfigurationInterface(" }]);
      expect((await m1.importer("web/lib/serveur.mjs")).lireComptes(ouvert.chemin).size, "mutant : la réponse retirée, le fichier en 0644 est lu").to.equal(1);
      const m2 = mutant("interface-ecoute", [{ fichier: "web/lib/serveur.mjs", ancien: 'if (c.nature === "production" && !HOTES_PRODUCTION.includes(c.ecoute.hote)) throw refus(', nouveau: "if (false) throw refus(" }]);
      expect((await m2.importer("web/lib/serveur.mjs")).lireConfigurationInterface(prod("0.0.0.0")).ecoute.hote, "mutant : la réponse retirée, l'écoute sur toute adresse est admise en production").to.equal("0.0.0.0");
      const m3 = mutant("interface-hsts", [{ fichier: "web/proxy.mjs", ancien: 'if (config.nature === "production") securite["strict-transport-security"] = HSTS;', nouveau: 'if (false) securite["strict-transport-security"] = HSTS;' }]);
      expect(await hsts(m3.racine, "production"), "mutant : la réponse retirée, aucun HSTS").to.equal(null);
    });

    it("CT-7 CLE-37 : le verrou de connexion vaut par couple (adresse cliente, nom) : cinq échecs d'un tiers verrouillent son adresse, non le compte de l'exploitant depuis une autre adresse ; mutant à verrou par nom seul : l'exploitant reçoit 429 (tué)", async function () {
      const dir = tmp();
      const c = comptesAvec(dir);
      const scenario = async (racine) => {
        reinitialiser();
        process.env.NOORTRACE_INSCRIPTION_CONFIG = configurationInterface(dir, { comptes: `fichier:${c.chemin}` });
        const Sx = await importer(racine, "web/lib/serveur.mjs");
        const t = Date.now();
        const tiers = [];
        for (let i = 1; i <= 5; i++) tiers.push((await Sx.connecter(c.nom, `essai du tiers ${i}`, t, { adresse: "203.0.113.9" })).statut);
        const tiersEncore = await Sx.connecter(c.nom, "essai du tiers 6", t, { adresse: "203.0.113.9" });
        const exploitant = await Sx.connecter(c.nom, c.motDePasse, t, { adresse: "198.51.100.5" });
        return { tiers, tiersEncore, exploitant };
      };
      const s = await scenario(PAQUET);
      expect(s.tiers).to.deep.equal([401, 401, 401, 401, 401]);
      expect(s.tiersEncore.statut, "même adresse : verrouillé").to.equal(429);
      expect(s.exploitant.statut, "autre adresse, bon mot de passe : session ouverte").to.equal(204);
      expect(s.exploitant.session).to.be.a("string");
      const m = mutant("verrou-adresse", [{ fichier: "web/lib/serveur.mjs", ancien: "const cle = `${adresse}\\n${nom}`;", nouveau: "const cle = nom;" }]);
      const sm = await scenario(m.racine);
      expect(sm.exploitant.statut, "mutant : la réponse retirée, le tiers ferme le compte de l'exploitant").to.equal(429);
    });

    it("au plus 10 000 sessions, les sessions échues purgées à chaque ouverture ; un en-tête Host étranger à l'origine reçoit 421 ; mutants (plafond, purge, hôte) : tués", async function () {
      const dir = tmp();
      const c = comptesAvec(dir);
      const ouvrir = async (racine) => {
        reinitialiser();
        process.env.NOORTRACE_INSCRIPTION_CONFIG = configurationInterface(dir, { comptes: `fichier:${c.chemin}` });
        const Sx = await importer(racine, "web/lib/serveur.mjs");
        const e = Sx.etat();
        for (let i = 0; i < Sx.SESSIONS_MAX + 1; i++) Sx.ouvrirSession("alice");
        const taille = e.sessions.size;
        const echue = Sx.ouvrirSession("bob");
        const id = Buffer.from(echue.split(".")[0], "base64url").toString("hex");
        e.sessions.get(id).expire = Date.now() - 1;
        Sx.ouvrirSession("carol");
        return { taille, echueGardee: e.sessions.has(id) };
      };
      const r = await ouvrir(PAQUET);
      expect(r.taille).to.equal(10000);
      expect(r.echueGardee, "session échue purgée à l'ouverture suivante").to.equal(false);
      const m1 = mutant("sessions-plafond", [{ fichier: "web/lib/serveur.mjs", ancien: "while (e.sessions.size >= SESSIONS_MAX) e.sessions.delete(e.sessions.keys().next().value);", nouveau: "while (false) e.sessions.delete(e.sessions.keys().next().value);" }]);
      expect((await ouvrir(m1.racine)).taille, "mutant : la réponse retirée, aucun plafond").to.equal(10001);
      const m2 = mutant("sessions-purge", [{ fichier: "web/lib/serveur.mjs", ancien: "  purgerSessions();\n  while (e.sessions.size >= SESSIONS_MAX)", nouveau: "  while (e.sessions.size >= SESSIONS_MAX)" }]);
      expect((await ouvrir(m2.racine)).echueGardee, "mutant : la réponse retirée, la session échue reste").to.equal(true);
      // Garde d'hôte.
      const { NextRequest } = await import("next/server.js");
      const statut = async (racine, hote) => {
        reinitialiser();
        process.env.NOORTRACE_INSCRIPTION_CONFIG = configurationInterface(dir, { origine: "http://127.0.0.1:8443", comptes: `fichier:${c.chemin}` });
        const Px = await importerMandataire(racine);
        return Px.proxy(new NextRequest("http://127.0.0.1:8443/connexion", { headers: { host: hote } })).status;
      };
      expect(await statut(PAQUET, "autre.example")).to.equal(421);
      expect(await statut(PAQUET, "127.0.0.1:8443")).to.equal(200);
      const m3 = mutant("hote-admis", [{ fichier: "web/proxy.mjs", ancien: 'if (!hoteAdmis(requete.headers.get("host"), config.origine)) return refus(421,', nouveau: "if (false) return refus(421," }]);
      expect(await statut(m3.racine, "autre.example"), "mutant : la réponse retirée, l'hôte étranger est servi").to.equal(200);
    });
  });

  // -------------------------------------------------------------------------
  describe("agent : plafond, instance relue, bornes", function () {
    it("fees.max_daily_budget_gas nul dans le manifeste vaut « aucun plafond » (plus d'erreur interne d'approvisionner) ; budget_jour d'un travail borné à 2^53 − 1 dans les deux commandes ; mutants : tués", async function () {
      const I = await livre("agent/instance.mjs");
      const T = await livre("commun/travaux.mjs");
      expect(I.normaliserFees({ max_daily_budget_gas: null, gas_limit: 5 })).to.not.have.property("max_daily_budget_gas");
      expect(I.normaliserFees({ max_daily_budget_gas: null, gas_limit: 5 }).gas_limit).to.equal(5);
      expect(I.normaliserFees({ max_daily_budget_gas: 7 }).max_daily_budget_gas).to.equal(7);
      // Manifeste de production du vecteur avec le plafond nul : il passe son schéma et se charge sans plafond.
      const instance = copierVecteur("production");
      const m = JSON.parse(fs.readFileSync(instance, "utf8"));
      m.fees.max_daily_budget_gas = null;
      expect(R.verifierManifesteSchema(m).valide).to.equal(true);
      fs.writeFileSync(instance, JSON.stringify(m, null, 2) + "\n");
      const i = I.chargerInstance(instance, { racine: RACINE });
      expect(i.fees).to.not.have.property("max_daily_budget_gas");
      // Expression d'approvisionner sur ces fees : aucune exception.
      const budget = 10800000n;
      expect(() => i.fees.max_daily_budget_gas !== undefined && i.fees.max_daily_budget_gas !== null && budget > BigInt(i.fees.max_daily_budget_gas)).to.not.throw();
      // budget_jour borné.
      const base = { org: "abc", journaux: ["journal-principal"], seuil: 1, approbateurs: ["0x" + "11".repeat(20)], admin_jeu: "0x" + "22".repeat(20), cles_enregistreur: [] };
      const preparer = (b) => T.lireTravail({ commande: "inscrire-client-preparer", slug: "abc", parametres: { ...base, budget_jour: b } });
      const approvisionner = (b) => T.lireTravail({ commande: "approvisionner", slug: "abc", parametres: { cle_chaine: "0x" + "11".repeat(20), budget_jour: b } });
      expect(preparer("9007199254740991").parametres.budget_jour).to.equal("9007199254740991");
      expect(approvisionner(9007199254740991).parametres.budget_jour).to.equal("9007199254740991");
      for (const b of ["9007199254740992", "1" + "0".repeat(77)]) {
        expect(() => preparer(b), `préparation, ${b.length} chiffres`).to.throw(/2 à 9007199254740991|de 1 à 9007199254740991/);
        expect(() => approvisionner(b), `approvisionner, ${b.length} chiffres`).to.throw(/de 1 à 9007199254740991/);
      }
      const m1 = mutant("fees-plafond", [{ fichier: "agent/instance.mjs", ancien: "fees: normaliserFees(manifeste.fees),", nouveau: "fees: { ...FEES_DEFAUT, ...manifeste.fees }," }]);
      expect((await m1.importer("agent/instance.mjs")).chargerInstance(instance, { racine: RACINE }).fees, "mutant : la réponse retirée, le plafond nul reste et BigInt(null) lève").to.have.property("max_daily_budget_gas", null);
      const m2 = mutant("fees-budget", [{ fichier: "commun/champs.mjs", ancien: "export const budgetJour = (champ, v) => montant(champ, v, { min: 1n, max: BUDGET_JOUR_MAX });", nouveau: "export const budgetJour = (champ, v) => montant(champ, v, { min: 1n });" }]);
      const MT = await m2.importer("commun/travaux.mjs");
      expect(MT.lireTravail({ commande: "approvisionner", slug: "abc", parametres: { cle_chaine: "0x" + "11".repeat(20), budget_jour: "1" + "0".repeat(77) } }).parametres.budget_jour.length, "mutant : la réponse retirée, 78 chiffres admis").to.equal(78);
    });

    it("l'instance relue à chaque travail doit garder la nature de la configuration et les identifiants du démarrage : un manifeste révisé vers une autre instance refuse le travail (instance_illisible) ; mutant sans comparaison : travail admis (tué)", async function () {
      const scenario = async (racinePaquet) => {
        const dirInstance = tmp("noortrace-revue-instance-");
        const manifeste = copierVecteur("developpement", dirInstance);
        const a = await O.demarrerAgentEssai({ manifeste, rpc: "http://127.0.0.1:9", comptes: {}, delai_s: 1, racinePaquet });
        try {
          const travail = (slug) => ({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: ["journal-principal"], seuil: 1, approbateurs: ["0x" + "11".repeat(20)], admin_jeu: "0x" + "22".repeat(20), cles_enregistreur: [] } });
          const avant = await a.travail(X, travail("avant-revision"));
          expect(avant.accepte, JSON.stringify(avant)).to.equal(true);
          await a.attendre(avant.id);
          // Révision du manifeste sur place : l'instance de production du vecteur remplace celle de développement.
          for (const f of fs.readdirSync(path.join(VECTEURS, "production"))) fs.cpSync(path.join(VECTEURS, "production", f), path.join(path.dirname(manifeste), f), { recursive: true });
          return await a.travail(X, travail(`o-${"ab".repeat(16)}`));
        } finally {
          await a.arreter();
          fs.rmSync(a.base, { recursive: true, force: true });
        }
      };
      const apres = await scenario(PAQUET);
      expect(apres).to.deep.include({ accepte: false, code: "instance_illisible" });
      expect(apres.message).to.match(/nature production/);
      const m = mutant("nature-instance", [
        { fichier: "agent/index.mjs", ancien: "if (instance.nature !== config.nature) throw new ErreurInstance(`nature ${instance.nature}", nouveau: "if (false) throw new ErreurInstance(`nature ${instance.nature}" },
        { fichier: "agent/index.mjs", ancien: "if (instance.evmChainId !== instanceDemarrage.evmChainId || instance.bftChainId !== instanceDemarrage.bftChainId) {", nouveau: "if (false) {" },
      ]);
      const mute = await scenario(m.racine);
      expect(mute.accepte, `mutant : la réponse retirée, le travail est admis sur l'autre instance (${JSON.stringify(mute)})`).to.equal(true);
    });

    it("le journal de l'agent est tourné à sa borne (une génération gardée) ; les refus sont consignés huit par minute puis comptés (refus_cumules) ; le contrôle du paquet ne lit ni un fichier au-delà de 64 Mio ni plus de 4 096 entrées ; mutants : tués", async function () {
      const D = await livre("agent/donnees.mjs");
      const dir = tmp();
      // Journal borné.
      const tourner = async (racine) => {
        const Dx = racine === PAQUET ? D : await importer(racine, "agent/donnees.mjs");
        const j = path.join(dir, `journal-${path.basename(racine)}.ndjson`);
        for (let i = 0; i < 50; i++) Dx.ajouterLigne(j, { i, texte: "x".repeat(40) }, { tailleMax: 500 });
        return { taille: fs.statSync(j).size, precedent: fs.existsSync(`${j}.1`) ? fs.statSync(`${j}.1`).size : null, lignes: Dx.lireLignes(j).length };
      };
      const t = await tourner(PAQUET);
      expect(t.taille).to.be.at.most(500);
      expect(t.precedent).to.be.a("number").and.at.most(500);
      expect(t.lignes).to.be.greaterThan(0);
      const m1 = mutant("donnees-journal", [{ fichier: "agent/donnees.mjs", ancien: "if (taille > 0 && taille + ligne.length > tailleMax) {", nouveau: "if (false) {" }]);
      const tm = await tourner(m1.racine);
      expect(tm.precedent, "mutant : la réponse retirée, aucune rotation").to.equal(null);
      expect(tm.taille).to.be.greaterThan(500);
      // Refus comptés : vingt travaux hors forme, huit lignes travail_refuse, puis une ligne refus_cumules à l'arrêt.
      const refuser = async (racinePaquet) => {
        const manifeste = copierVecteur("developpement");
        const a = await O.demarrerAgentEssai({ manifeste, rpc: "http://127.0.0.1:9", comptes: {}, delai_s: 1, racinePaquet });
        for (let i = 0; i < 20; i++) expect(await a.travail(X, { commande: "inexistante", slug: "x", parametres: {} })).to.deep.include({ accepte: false, code: "requete_invalide" });
        await a.arreter();
        const journal = a.journal();
        fs.rmSync(a.base, { recursive: true, force: true });
        return { refus: journal.filter((l) => l.evenement === "travail_refuse").length, cumules: journal.filter((l) => l.evenement === "refus_cumules") };
      };
      const r = await refuser(PAQUET);
      expect(r.refus).to.equal(8);
      expect(r.cumules).to.have.length(1);
      expect(r.cumules[0]).to.include({ refus: "travail_refuse", nombre: 12 });
      const m2 = mutant("donnees-refus", [{ fichier: "agent/index.mjs", ancien: "if (!EVENEMENTS_REFUS.includes(evenement)) return ecrireLigne(evenement, champs);", nouveau: "return ecrireLigne(evenement, champs);" }]);
      expect((await refuser(m2.racine)).refus, "mutant : la réponse retirée, une ligne par refus").to.equal(20);
      // Contrôle du paquet : fichier trop grand (creux, non lu), trop d'entrées.
      const Sch = await livre("commun/schemas.mjs");
      const P = await livre("commun/paquet.mjs");
      const { keccak256, octetsVersHex, utf8 } = await import("@noortrace/noyau");
      const org = "client-borne";
      // Les trois fichiers obligatoires sont déclarés (schéma : au moins trois entrées) et absents : écarts du point 2, sans effet sur les bornes.
      const declares = [["inscription-client.json", "dossier"], ["jeu-approbateurs.json", "jeu_approbateurs"], ["gabarit-service-approbation.json", "gabarit_service"]].map(([p, role]) => ({ path: p, role, sha256: "0x" + "00".repeat(32), length: 2 }));
      const manifestePaquet = { version: 0, org, org_id: octetsVersHex(keccak256(utf8(org))), instance: { evm_chain_id: 2124, bft_chain_id: "noortrace-2124-dev", manifest_sha256: null }, files: declares, prepared_by: "essai", prepared_at: "2026-11-13T00:00:00.000Z", source: "essai de la revue" };
      expect(Sch.valider(Sch.IDS.paquet, manifestePaquet).valide, "manifeste du paquet d'essai conforme").to.equal(true);
      const paquet = path.join(tmp(), P.nomPaquet(org));
      fs.mkdirSync(path.join(paquet, "captures"), { recursive: true });
      fs.writeFileSync(path.join(paquet, P.MANIFESTE_PAQUET), P.serialiserDocument(manifestePaquet));
      const gros = path.join(paquet, "a-gros.bin");
      fs.writeFileSync(gros, "");
      fs.truncateSync(gros, P.FICHIER_PAQUET_MAX_OCTETS + 1);
      for (let i = 0; i < P.ENTREES_PAQUET_MAX + 2; i++) fs.writeFileSync(path.join(paquet, "captures", `f-${String(i).padStart(5, "0")}.json`), "{}");
      const codes = (Px) => Px.controlerPaquet(paquet).ecarts.filter((e) => e.point === 2).map((e) => e.code);
      const c = codes(P);
      expect(c).to.include("fichier_trop_grand");
      expect(c).to.include("trop_de_fichiers");
      const m3 = mutant("paquet-taille", [{ fichier: "commun/paquet.mjs", ancien: 'else if (st.size > FICHIER_PAQUET_MAX_OCTETS) anomalies.push({ fichier: relatif, code: "fichier_trop_grand" });', nouveau: 'else if (false) anomalies.push({ fichier: relatif, code: "fichier_trop_grand" });' }]);
      expect(codes(await m3.importer("commun/paquet.mjs")), "mutant : la réponse retirée, le fichier est lu en entier").to.not.include("fichier_trop_grand");
      const m4 = mutant("paquet-entrees", [{ fichier: "commun/paquet.mjs", ancien: "if (entrees >= ENTREES_PAQUET_MAX) {", nouveau: "if (false) {" }]);
      expect(codes(await m4.importer("commun/paquet.mjs")), "mutant : la réponse retirée, aucune borne du nombre d'entrées").to.not.include("trop_de_fichiers");
    });
  });
});
