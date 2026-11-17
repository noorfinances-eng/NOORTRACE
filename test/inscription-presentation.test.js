// Inscription des clients : présentation de l'interface d'exploitant (complément du 2026-11-17, décision du porteur
// sur la présentation des écrans ; CT-4 §7.14, EX-7.16, EX-7.26 ; paquets/inscription/INTERFACES.md 2.2). Essais
// sans navigateur ni construction : la feuille de style (bloc de jetons commun entre ses deux repères, règles
// propres après lui), les mots du parcours (`src/web/lib/parcours.mjs` : libellé en clair de chaque étape et de
// chaque état du schéma, numérotation, prochaine action, détail technique aux valeurs exactes du dossier, libellés
// des travaux et des erreurs) et la bascule de thème (`src/web/lib/theme.mjs`). Les mutants sont des copies du
// module, modifiées et importées depuis un répertoire temporaire.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as O from "./fixtures/inscription/outils.mjs";
import { RACINE } from "./fixtures/inscription/reseau-essai.mjs";
import { CODES_ETAPES, dossierFictif, travailFictif } from "./fixtures/inscription/donnees-fictives.mjs";

const WEB = path.join(RACINE, "paquets", "inscription", "src", "web");
const FEUILLE = path.join(WEB, "app", "globals.css");
const MODULE = path.join(WEB, "lib", "parcours.mjs");
const SCHEMAS = path.join(RACINE, "paquets", "inscription", "schemas");
const schema = (nom) => JSON.parse(fs.readFileSync(path.join(SCHEMAS, nom), "utf8"));
const DEBUT = "/* noor-theme:debut */";
const FIN = "/* noor-theme:fin */";

/** Fichiers source de l'interface (hors de la sortie de « next build »). */
function sources(dir = WEB) {
  const l = [];
  for (const n of fs.readdirSync(dir)) {
    if (n === ".next" || n === "node_modules") continue;
    const f = path.join(dir, n);
    if (fs.statSync(f).isDirectory()) l.push(...sources(f));
    else if (/\.(js|mjs|css)$/.test(n)) l.push(f);
  }
  return l;
}

describe("inscription : présentation de l'interface d'exploitant (complément du 2026-11-17)", function () {
  this.timeout(60000);
  let P;
  let dir;
  /** Copie modifiée du module du parcours : `ancien` doit y figurer exactement une fois. */
  const mutant = async (nom, ancien, nouveau) => {
    const texte = fs.readFileSync(MODULE, "utf8");
    const n = texte.split(ancien).length - 1;
    if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
    const f = path.join(dir, `parcours-${nom}.mjs`);
    fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
    return import(pathToFileURL(f).href);
  };

  before(async function () {
    dir = O.repertoireTemporaire("noortrace-inscription-presentation-");
    P = await import(pathToFileURL(MODULE).href);
  });

  describe("feuille de style et sources", function () {
    it("le bloc de jetons commun est en tête de globals.css, une seule fois, entre ses deux repères ; les règles propres de l'outil viennent après lui, sans redéfinir un jeton --nt-, sans classe nt-, sans adresse ni import, sans prefers-color-scheme", function () {
      const css = fs.readFileSync(FEUILLE, "utf8");
      expect(css.split(DEBUT).length - 1, "repère de début").to.equal(1);
      expect(css.split(FIN).length - 1, "repère de fin").to.equal(1);
      expect(css.startsWith(DEBUT), "le bloc ouvre la feuille").to.equal(true);
      const bloc = css.slice(0, css.indexOf(FIN) + FIN.length);
      const propres = css.slice(bloc.length);
      // Le bloc : les deux états (sombre sans attribut, clair par data-theme), l'impression en clair, aucune adresse.
      expect(bloc).to.match(/html\[data-theme="clair"\]/);
      expect(bloc).to.match(/@media print/);
      expect(bloc, "aucune adresse dans le bloc").to.not.match(/url\(|@import/);
      expect((bloc.match(/\.nt-[a-z0-9-]+/g) ?? []).length, "classes du bloc").to.be.greaterThan(100);
      // Les règles propres : après le repère de fin, préfixe ins-, jetons lus et jamais redéfinis.
      expect(propres.trim().length, "règles propres présentes").to.be.greaterThan(0);
      expect(propres, "jeton redéfini hors du bloc").to.not.match(/--nt-[a-z0-9-]+\s*:/);
      expect(propres, "classe nt- écrite hors du bloc").to.not.match(/\.nt-[a-z0-9-]+[^{},]*[{,]/);
      expect(propres, "adresse hors du bloc").to.not.match(/url\(|@import/);
      expect(propres, "prefers-color-scheme hors du bloc").to.not.match(/prefers-color-scheme|color-scheme\s*:/);
      expect(propres, "!important hors du bloc").to.not.match(/!important/);
      for (const c of propres.match(/\.[a-z][a-z0-9-]*/g) ?? []) expect(c, "classe propre sans le préfixe ins-").to.match(/^\.ins-/);
    });

    it("aucune source de l'interface ne pose un style en ligne (style-src 'self'), n'écrit de HTML brut hors de l'amorce du thème, ni ne charge une ressource d'une autre origine", function () {
      const fichiers = sources();
      expect(fichiers.length).to.be.greaterThan(15);
      let amorces = 0;
      for (const f of fichiers) {
        const t = fs.readFileSync(f, "utf8");
        const rel = path.relative(WEB, f);
        if (f.endsWith(".css")) continue;
        expect(t, `${rel} : attribut style`).to.not.match(/\bstyle=\{|\bstyle="/);
        expect(t, `${rel} : adresse d'une autre origine`).to.not.match(/https?:\/\/(?!127\.0\.0\.1|[a-z0-9.-]+\.example\b)[a-z0-9]/);
        amorces += t.split("dangerouslySetInnerHTML").length - 1;
        expect(t, `${rel} : innerHTML`).to.not.match(/\.innerHTML\s*=/);
      }
      // Une seule écriture de HTML brut : l'amorce du thème, script à nonce du gabarit.
      expect(amorces, "dangerouslySetInnerHTML").to.equal(1);
      expect(fs.readFileSync(path.join(WEB, "app", "layout.js"), "utf8")).to.match(/nonce=\{/);
    });
  });

  describe("mots du parcours (src/web/lib/parcours.mjs)", function () {
    it("chaque étape et chaque état du schéma inscription-client-v0 a un libellé en clair, distinct de son code, et une phrase qui dit ce qu'elle fait ; un code inconnu reste affiché tel quel ; mutants (état « envoyee » dit « Fait » ; étape sans phrase) : tués", async function () {
      const s = schema("inscription-client-v0.schema.json").$defs.etape.properties;
      expect(s.step.enum).to.deep.equal(CODES_ETAPES);
      const verifier = (M) => {
        for (const code of s.step.enum) {
          const e = M.ETAPES[code];
          expect(e, code).to.be.an("object");
          expect(e.titre, code).to.be.a("string").and.not.match(/_|^$/);
          expect(e.titre, code).to.not.equal(code);
          expect(e.phrase, code).to.match(/^[A-ZÀ-Ý].{20,}\.$/);
        }
        for (const code of s.state.enum) {
          const e = M.ETATS_ETAPE[code];
          expect(e, code).to.be.an("object");
          expect(e.libelle, code).to.be.a("string").and.not.match(/_|^$/);
          expect(e.explication, code).to.match(/\.$/);
          expect(["faite", "en-cours", "a-faire", "echec"], code).to.include(e.rang);
        }
        // Seuls « capturee » et « faite » se disent « Fait » ; l'échec se dit « Échec ».
        const faits = s.state.enum.filter((c) => M.ETATS_ETAPE[c].rang === "faite");
        expect(faits.sort()).to.deep.equal(["capturee", "faite"]);
        expect(M.ETATS_ETAPE.echec.rang).to.equal("echec");
        expect(M.ETATS_ETAPE.envoyee.libelle).to.equal("Envoyée");
        expect(M.ETATS_ETAPE.incluse.libelle).to.equal("Incluse");
        expect(M.ETATS_ETAPE.a_faire.libelle).to.equal("À faire");
        expect(M.ETATS_ETAPE.echec.libelle).to.equal("Échec");
      };
      verifier(P);
      // Un code que cette version ne connaît pas n'est ni caché ni travesti.
      const d = dossierFictif("client-x", ["capturee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      d.steps[1].state = "etat_futur";
      d.steps[2].step = "etape_future";
      const l = P.etapesDuParcours(d);
      expect(l[2].libelle).to.contain("etat_futur");
      expect(l[2].rang).to.equal("a-faire");
      expect(l[3].titre).to.contain("etape_future");
      expect(P.avancement(d).faites, "un état inconnu ne compte pas comme fait").to.equal(2);
      let tue = 0;
      const m1 = await mutant("envoyee-faite", 'envoyee: { libelle: "Envoyée"', 'envoyee: { libelle: "Fait"');
      try { verifier(m1); } catch { tue++; }
      const m2 = await mutant("sans-phrase", "phrase: \"Rattache ce jeu à l'organisation dans le registre.\"", 'phrase: ""');
      try { verifier(m2); } catch { tue++; }
      expect(tue, "mutants tués").to.equal(2);
    });

    it("le parcours affiche la préparation du dossier en étape 1 puis les étapes du dossier dans leur ordre, numérotées ; l'avancement compte les étapes faites ; mutant (l'échec compté comme fait) : tué", async function () {
      const d = dossierFictif("client-en-cours", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
      const verifier = (M) => {
        const l = M.etapesDuParcours(d);
        expect(l.map((e) => e.numero)).to.deep.equal([1, 2, 3, 4, 5, 6, 7, 8]);
        expect(l[0].code).to.equal("preparation");
        expect(l[0].rang).to.equal("faite");
        expect(l[0].titre).to.equal("Préparer le dossier");
        expect(l.slice(1).map((e) => e.code)).to.deep.equal(CODES_ETAPES);
        expect(l.map((e) => e.rang)).to.deep.equal(["faite", "faite", "faite", "faite", "faite", "a-faire", "a-faire", "a-faire"]);
        expect(l[1].titre).to.equal("Créer le jeu d'approbateurs");
        expect(l[4].titre).to.equal("Approvisionner la clé de chaîne");
        // L'objet se dit en clair : la clé de chaîne par l'identifiant de sa clé d'enregistreur.
        expect(l[4].objet).to.contain(d.recorders[0].key_id);
        expect(l[1].resultat).to.match(/bloc 100/);
        const a = M.avancement(d);
        expect(a).to.include({ faites: 5, total: 8, echecs: 0 });
        expect(a.phrase).to.equal("5 étapes sur 8");
        expect(a.etat).to.equal("en_cours");
        const e = dossierFictif("client-en-echec", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        expect(M.avancement(e)).to.include({ faites: 2, total: 8, echecs: 1, etat: "a_reprendre" });
        expect(M.avancement(dossierFictif("z", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"])).phrase).to.equal("1 étape sur 8");
        const fini = M.avancement(dossierFictif("client-inscrit", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]));
        expect(fini).to.include({ faites: 8, total: 8, etat: "inscrit" });
      };
      verifier(P);
      const m = await mutant("echec-fait", 'echec: { libelle: "Échec", explication: "La transaction a été refusée par le contrat, ou la relecture la contredit.", rang: "echec"', 'echec: { libelle: "Échec", explication: "La transaction a été refusée par le contrat, ou la relecture la contredit.", rang: "faite"');
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
    });

    it("le détail technique d'une étape garde, sans les abréger ni en changer la casse, le code de l'étape et de l'état, l'objet, la transaction, le bloc, la capture, le contrat, l'erreur et l'instant exact du dossier ; mutant (hachage abrégé) : tué", async function () {
      const d = dossierFictif("client-en-echec", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      const verifier = (M) => {
        const l = M.etapesDuParcours(d);
        expect(l[0].technique.map((x) => x.valeur)).to.include.members([d.prepared_at, d.prepared_by]);
        for (let k = 0; k < d.steps.length; k++) {
          const e = d.steps[k];
          const valeurs = l[k + 1].technique.map((x) => x.valeur);
          for (const v of [e.step, e.state, e.subject, e.transaction_hash, e.block_hash, e.capture, e.contract, e.updated_at, e.error?.code, e.error?.message]) {
            if (v !== null && v !== undefined) expect(valeurs, `${e.step} : ${v}`).to.include(v);
          }
          if (e.block_number !== null) expect(valeurs, `${e.step} : bloc`).to.include(String(e.block_number));
          for (const x of l[k + 1].technique) expect(x.libelle, e.step).to.be.a("string").and.not.equal("");
        }
        // L'échec se dit en clair, avec quoi faire ; son code reste au détail.
        expect(l[2].erreur.quoiFaire).to.match(/relit|relire|relisent/);
        expect(l[2].erreur.code).to.equal("transaction_annulee");
      };
      verifier(P);
      const m = await mutant("hachage-abrege", "valeur: e.transaction_hash }", "valeur: e.transaction_hash.slice(0, 10) + \"…\" }");
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
    });

    it("la prochaine action suit l'état du dossier : confirmation hors bande à consigner avant tout approvisionnement (EX-7.26), étapes 2 à 5, demande à préparer, demande à faire signer hors de l'application puis à relayer (EX-7.27), première période, export, vérification, paquet, remise ; mutant (confirmation consommée comptée) : tué", async function () {
      const neuf = dossierFictif("client-neuf", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      const cle = neuf.recorders[0].chain_key;
      const conf = (consommee) => ({ id: "cnf-1", operation: "approvisionnement", objet: { org_id: neuf.organisation.org_id, cle_chaine: cle }, consommee_par: consommee });
      const vue = (dossier, plus = {}) => ({ slug: dossier.organisation.slug, dossier, confirmations: [], demandes: [], periodes: [], parties: [], travaux: [], paquet: { present: false, dernier: null }, ...plus });
      const verifier = (M) => {
        // Sans confirmation : la consigner d'abord ; l'action nomme la clé visée et mène au registre des confirmations.
        let a = M.prochaineAction(vue(neuf));
        expect(a.code).to.equal("consigner_confirmation");
        expect(a.lien).to.equal("/clients/client-neuf/confirmations");
        expect(a.cles).to.deep.equal([cle]);
        expect(a.titre).to.match(/confirmation hors bande/);
        // Une confirmation d'une autre opération, ou déjà consommée, ne compte pas.
        expect(M.prochaineAction(vue(neuf, { confirmations: [{ ...conf(null), operation: "approvisionner" }] })).code).to.equal("consigner_confirmation");
        expect(M.prochaineAction(vue(neuf, { confirmations: [conf("trv-1")] })).code).to.equal("consigner_confirmation");
        a = M.prochaineAction(vue(neuf, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", commande: "inscrire-client", titre: "Conduire les étapes 2 à 5" });
        // Étape en échec : la reprise relit la chaîne ; la confirmation en réserve suffit.
        const echec = dossierFictif("client-neuf", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(echec, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", titre: "Reprendre les étapes 2 à 5" });
        // Envoi sans reçu : reprise, jamais un nouvel envoi (EX-7.16) ; aucune confirmation n'est exigée tant que l'approvisionnement n'est pas à faire.
        const envoye = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "envoyee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(envoye));
        expect(a.code).to.equal("conduire_etapes");
        expect(a.phrase).to.match(/jamais un nouvel envoi/);
        // Étapes 2 à 5 faites : demande à préparer, puis à faire signer hors de l'application et à relayer.
        const cours = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(cours));
        expect(a).to.include({ code: "preparer_demande", commande: "condense-inscription", keyId: cours.recorders[0].key_id });
        a = M.prochaineAction(vue(cours, { demandes: [{ nom: `demande-inscription-${cours.recorders[0].key_id}-trv-1.json`, document: { signatures: [] } }] }));
        expect(a).to.include({ code: "relayer_demande", commande: "inscrire-cle" });
        expect(a.phrase).to.match(/hors de (cette |l')application/);
        // Clé inscrite : la première période se fait hors de l'outil.
        const inscrite = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "capturee", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(inscrite));
        expect(a.code).to.equal("attendre_premiere_periode");
        expect(a.commande).to.equal(undefined);
        // Dossier fini : export, vérification, paquet, remise.
        const fini = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]);
        expect(M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"] }))).to.include({ code: "exporter", commande: "exporter" });
        expect(M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"], parties: ["parties/1"] }))).to.include({ code: "verifier", commande: "verifier" });
        const verifie = [travailFictif(9, { slug: "client-neuf", commande: "verifier", recu_a: "2026-11-13T09:00:00.000Z" })];
        a = M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"], parties: ["parties/1"], travaux: verifie }));
        expect(a).to.include({ code: "produire_paquet", lien: "/clients/client-neuf/paquet" });
        expect(M.prochaineAction(vue(fini)).code, "sans période dans les données de l'agent").to.equal("produire_paquet");
        a = M.prochaineAction(vue(fini, { paquet: { present: true, dernier: null } }));
        expect(a).to.include({ code: "remettre_paquet", lien: "/clients/client-neuf/paquet" });
        for (const x of [M.prochaineAction(vue(neuf)), M.prochaineAction(vue(cours)), M.prochaineAction(vue(inscrite)), M.prochaineAction(vue(fini))]) {
          expect(x.titre, x.code).to.match(/^[A-ZÀ-Ý]/);
          expect(x.phrase, x.code).to.match(/\.$/);
          expect(`${x.titre} ${x.phrase}`, x.code).to.not.match(/[a-z]_[a-z]/);
        }
      };
      verifier(P);
      const m = await mutant("confirmation-consommee", "&& !c.consommee_par", "");
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
    });

    it("chaque commande de travail, chaque état de travail et chaque résultat de sortie a un libellé en clair ; « confirmation hors bande absente » reste mot pour mot (EX-7.26) ; chaque code d'erreur du schéma des sorties reçoit une explication et une conduite à tenir", async function () {
      const { COMMANDES } = await import("../paquets/inscription/src/commun/travaux.mjs");
      for (const c of COMMANDES) expect(P.COMMANDES[c], c).to.be.a("string").and.match(/^[A-ZÀ-Ý][^_]+$/);
      expect(Object.keys(P.COMMANDES).sort()).to.deep.equal([...COMMANDES].sort());
      const resultats = schema("operations-registre-v0.schema.json").$defs.sortie.properties.result.enum;
      const vus = new Set();
      for (const r of resultats) {
        const e = P.etatTravail({ etat: "fini", sortie: { result: r } });
        expect(e.libelle, r).to.be.a("string").and.not.match(/_/);
        expect(e.libelle, r).to.not.equal(r);
        vus.add(e.libelle);
      }
      expect(vus.size, "un libellé par résultat").to.equal(resultats.length);
      expect(P.etatTravail({ etat: "fini", sortie: { result: "reussi" } })).to.include({ libelle: "Réussi", ton: "succes" });
      expect(P.etatTravail({ etat: "fini", sortie: { result: "refuse" } }).libelle).to.equal("Refusé avant envoi");
      for (const etat of ["en_attente", "en_cours", "refuse", "abandonne"]) expect(P.etatTravail({ etat }).libelle, etat).to.be.a("string").and.not.match(/_/);
      expect(P.etatTravail({ etat: "en_cours" })).to.include({ libelle: "En cours", ton: "info" });
      // Refus pour confirmation absente : la phrase du texte, mot pour mot, sans capitale ajoutée.
      const refus = P.etatTravail({ etat: "refuse", motif: { code: "confirmation_absente", message: "x" } });
      expect(refus.ton).to.equal("refus");
      expect(P.explicationErreur("confirmation_absente").phrase).to.contain("confirmation hors bande absente");
      expect(P.explicationErreur("confirmation_absente").quoiFaire).to.match(/[Cc]onsignez/);
      const codes = schema("operations-registre-v0.schema.json").$defs.sortie.properties.error.oneOf[1].properties.code.enum;
      expect(codes.length).to.be.greaterThan(40);
      for (const c of codes) {
        const x = P.explicationErreur(c);
        expect(x.phrase, c).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(x.quoiFaire, c).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(x.connu, c).to.equal(true);
      }
      // Un code inconnu : phrase générale, le code n'est pas caché par l'appelant (il l'affiche à côté).
      expect(P.explicationErreur("code_futur").connu).to.equal(false);
    });

    it("les instants se lisent en français et en UTC (« 12 novembre 2026 à 08:05 UTC ») ; un instant illisible est rendu tel quel", function () {
      expect(P.dateLisible("2026-11-12T08:05:07.250Z")).to.equal("12 novembre 2026 à 08:05 UTC");
      expect(P.dateLisible("2026-01-01T00:00:00.000Z")).to.equal("1er janvier 2026 à 00:00 UTC");
      expect(P.dateLisible("hier")).to.equal("hier");
      expect(P.dateLisible(null)).to.equal("");
    });
  });

  describe("bascule de thème (src/web/lib/theme.mjs)", function () {
    it("deux états seulement : toute valeur autre que « clair » retombe sur le sombre ; clé « noor.theme » ; l'amorce ne pose que data-theme=\"clair\" et ne lit que cette clé", async function () {
      const T = await import(pathToFileURL(path.join(WEB, "lib", "theme.mjs")).href);
      expect(T.CLE_THEME).to.equal("noor.theme");
      for (const v of [undefined, null, "", "sombre", "bleu", "CLAIR", 1]) expect(T.normaliseTheme(v), String(v)).to.equal("sombre");
      expect(T.normaliseTheme("clair")).to.equal("clair");
      expect(T.prochainTheme("clair")).to.equal("sombre");
      expect(T.prochainTheme("n'importe quoi")).to.equal("clair");
      expect(T.COULEUR_BARRE).to.deep.equal({ sombre: "#060B16", clair: "#F3F7FF" });
      expect(T.libelleBascule("sombre")).to.equal("Passer au thème clair");
      expect(T.libelleBascule("clair")).to.equal("Passer au thème sombre");
      // L'amorce, jouée dans un document factice : clair mémorisé, autre valeur, stockage refusé.
      const jouer = (valeur, { leve = false } = {}) => {
        const attributs = {};
        const document = { documentElement: { setAttribute: (n, v) => { attributs[n] = v; } } };
        const localStorage = { getItem: (k) => { if (leve) throw new Error("refusé"); return k === "noor.theme" ? valeur : "clair"; } };
        new Function("document", "localStorage", T.AMORCE_THEME)(document, localStorage);
        return attributs;
      };
      expect(jouer("clair")).to.deep.equal({ "data-theme": "clair" });
      expect(jouer("sombre")).to.deep.equal({});
      expect(jouer(null)).to.deep.equal({});
      expect(jouer("clair", { leve: true })).to.deep.equal({});
      expect(T.AMORCE_THEME).to.not.match(/cookie|sessionStorage|fetch|<|>/);
    });
  });
});
