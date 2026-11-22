// Inscription des clients : présentation de l'interface d'exploitant (complément du 2026-11-17, décision du porteur
// sur la présentation des écrans ; CT-4 §7.14, EX-7.16, EX-7.26 ; paquets/inscription/INTERFACES.md 2.2). Essais
// sans navigateur ni construction : la feuille de style (bloc de jetons commun entre ses deux repères, règles
// propres après lui), les mots du parcours (`src/web/lib/parcours.mjs` : libellé en clair de chaque étape et de
// chaque état du schéma, numérotation, prochaine action, détail technique aux valeurs exactes du dossier, libellés
// des travaux et des erreurs) et la bascule de thème (`src/web/lib/theme.mjs`). Les mutants sont des copies du
// module, modifiées et importées depuis un répertoire temporaire.
//
// Complément du 2026-11-18, décision du porteur (langage des écrans ; INTERFACES.md 2.5) : les libellés attendus
// sont ceux du langage courant (nom en verbe de chaque étape, un mot et une phrase par état, prochaine action
// écrite comme une consigne, erreurs qui disent ce qui s'est passé, ce qui a été envoyé ou dépensé, et quoi
// faire) ; aucun texte du module ne porte un mot de la liste publiée (test/fixtures/inscription/langage.mjs).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as O from "./fixtures/inscription/outils.mjs";
import { RACINE } from "./fixtures/inscription/reseau-essai.mjs";
import { CODES_ETAPES, dossierFictif, travailFictif } from "./fixtures/inscription/donnees-fictives.mjs";
import { MOTS_TECHNIQUES, motsTechniquesDans } from "./fixtures/inscription/langage.mjs";

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
        expect(M.ETATS_ETAPE.incluse.libelle).to.equal("Inscrite");
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
      const m2 = await mutant("sans-phrase", "phrase: \"Relit la liste sur le registre public, comme le service d'approbation du client la lira. Rien n'est écrit ni dépensé.\"", 'phrase: ""');
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
        // Le nom courant de chaque étape, en verbe (complément du 2026-11-18).
        expect(l.map((e) => e.titre)).to.deep.equal(["Préparer le dossier", "Enregistrer les approbateurs", "Rattacher les approbateurs au client", "Contrôler les approbateurs", "Alimenter le compte technique", "Inscrire l'enregistreur", "Déposer la première preuve de date", "Clore la première période"]);
        for (const e of l) expect(e.titre, e.code).to.match(/^[A-ZÉ][a-zéèêôîû]+(?:er|ir|re) /);
        // L'objet se dit en clair : le compte technique par le nom de son enregistreur, valeur du dossier à part du texte.
        expect(l[4].objet).to.deep.equal({ texte: "Compte technique de l'enregistreur", valeur: d.recorders[0].key_id });
        expect(l[5].objet).to.deep.equal({ texte: "Enregistreur", valeur: d.recorders[0].key_id });
        expect(l[1].explication).to.equal("L'opération est inscrite sur le registre public et sa preuve est rangée dans le dossier.");
        expect(l[3].explication).to.equal("Étape faite sans rien écrire sur le registre public.");
        // Seule l'étape où l'on en est se développe ; les autres tiennent en une ligne.
        expect(l.map((e) => e.developpee)).to.deep.equal([false, false, false, false, false, true, false, false]);
        const a = M.avancement(d);
        expect(a).to.include({ faites: 5, total: 8, echecs: 0 });
        expect(a.phrase).to.equal("5 étapes sur 8");
        expect(a.phraseFaites).to.equal("5 étapes sur 8 faites");
        expect(a.etat).to.equal("en_cours");
        const e = dossierFictif("client-en-echec", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        expect(M.avancement(e)).to.include({ faites: 2, total: 8, echecs: 1, etat: "a_reprendre", libelle: "À reprendre" });
        // Une étape en échec se développe elle aussi ; l'étape suivante n'est pas « celle où l'on en est ».
        expect(M.etapesDuParcours(e).map((x) => x.developpee)).to.deep.equal([false, false, true, false, false, false, false, false]);
        const neuf = M.avancement(dossierFictif("z", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]));
        expect(neuf.phrase).to.equal("1 étape sur 8");
        expect(neuf.phraseFaites, "accord au singulier").to.equal("1 étape sur 8 faite");
        // Une étiquette, un sens (seconde lecture des écrans). Un envoi parti d'ici et resté sans réponse : une
        // action attend la personne, « Réponse à aller chercher ». Une étape envoyée par le client : rien à faire,
        // « En attente du registre ». La suite chez le client : rien à faire, « En attente chez le client ».
        const ETAPES_2_A_5 = ["capturee", "capturee", "faite", "capturee"];
        expect(M.avancement(dossierFictif("z", ["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]))).to.include({ etat: "en_cours", attente: "reponse_a_chercher", libelle: "Réponse à aller chercher", resume: "Un envoi est resté sans réponse : une action vous attend." });
        expect(M.avancement(dossierFictif("z", [...ETAPES_2_A_5, "incluse", "a_faire", "a_faire"]))).to.include({ attente: "reponse_a_chercher", libelle: "Réponse à aller chercher" });
        for (const fin of [["capturee", "envoyee", "a_faire"], ["capturee", "incluse", "a_faire"], ["capturee", "capturee", "envoyee"]]) expect(M.avancement(dossierFictif("z", [...ETAPES_2_A_5, ...fin])), fin.join(",")).to.include({ etat: "en_cours", attente: "registre", libelle: "En attente du registre", resume: "Une étape envoyée par le client attend la réponse du registre public : vous n'avez rien à faire." });
        for (const fin of [["capturee", "a_faire", "a_faire"], ["capturee", "capturee", "a_faire"]]) expect(M.avancement(dossierFictif("z", [...ETAPES_2_A_5, ...fin])), fin.join(",")).to.include({ etat: "en_cours", attente: "client", libelle: "En attente chez le client", resume: "La suite se fait chez le client : vous n'avez rien à faire." });
        expect(M.avancement(d), "étape 6 à faire : c'est à la personne, pas au client").to.include({ attente: null, libelle: "En cours" });
        // L'étiquette et la consigne disent la même chose : agir seulement sous « Réponse à aller chercher ».
        const vueNue = (x) => ({ slug: "z", dossier: x, confirmations: [], demandes: [], periodes: [], parties: [], travaux: [], paquet: { present: false, dernier: null } });
        for (const etats of [["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], [...ETAPES_2_A_5, "envoyee", "a_faire", "a_faire"], [...ETAPES_2_A_5, "capturee", "envoyee", "a_faire"], [...ETAPES_2_A_5, "capturee", "capturee", "incluse"], [...ETAPES_2_A_5, "capturee", "a_faire", "a_faire"], [...ETAPES_2_A_5, "capturee", "capturee", "a_faire"]]) {
          const x = dossierFictif("z", etats);
          expect({ reponse_a_chercher: "reprendre_envoi", registre: "attendre_envoi", client: "attendre_premiere_periode" }[M.avancement(x).attente], etats.join(",")).to.equal(M.prochaineAction(vueNue(x)).code);
        }
        // Une étape que le client fait lui-même ne se dit pas « À faire » comme celles de la personne.
        expect(l.map((e) => e.libelle)).to.deep.equal(["Fait", "Fait", "Fait", "Fait", "Fait", "À faire", "À faire par le client", "À faire par le client"]);
        expect(l[6].explication).to.equal("Rien n'a encore été envoyé pour cette étape : c'est le client qui la fait, avec ses propres outils.");
        expect(l[5].explication).to.equal("Rien n'a encore été envoyé pour cette étape.");
        expect(M.etapesDuParcours(dossierFictif("z", [...ETAPES_2_A_5, "capturee", "envoyee", "a_faire"])).slice(6).map((e) => e.libelle), "envoyée par le client : l'état reste celui du dossier").to.deep.equal(["Envoyée", "À faire par le client"]);
        const fini = M.avancement(dossierFictif("client-inscrit", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]));
        expect(fini).to.include({ faites: 8, total: 8, etat: "inscrit" });
      };
      verifier(P);
      const m = await mutant("echec-fait", 'echec: { libelle: "Échec", explication: "Le registre public a refusé l\'opération, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.", rang: "echec"', 'echec: { libelle: "Échec", explication: "Le registre public a refusé l\'opération, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.", rang: "faite"');
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
      // Mutants de la seconde lecture : une même étiquette pour « agissez » et pour « ne faites rien » ; les étapes
      // du client dites « À faire » comme celles de la personne.
      for (const [nom, ancien, nouveau] of [
        ["etiquette-double", 'attente: "reponse_a_chercher", libelle: "Réponse à aller chercher"', 'attente: "reponse_a_chercher", libelle: "En attente du registre"'],
        ["etapes-du-client", 'const ETAPES_DU_CLIENT = Object.freeze(["premiere_ancre", "premiere_cloture"]);', "const ETAPES_DU_CLIENT = Object.freeze([]);"],
      ]) {
        const x = await mutant(nom, ancien, nouveau);
        let mort = false;
        try { verifier(x); } catch { mort = true; }
        expect(mort, `mutant ${nom} tué`).to.equal(true);
      }
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
        // L'échec se dit en clair : ce qui s'est passé, ce qui a été dépensé, quoi faire ; son code reste au détail.
        // Quatrième lecture : la cause se dit d'après la vérification qui l'a rendue ; l'étape sans capture vient d'un reçu refusé (OP-11).
        expect(l[2].erreur.phrase).to.equal("Le registre public a reçu l'opération, mais elle n'a pas eu l'effet attendu.");
        expect(l[2].erreur.effet).to.equal("Cet envoi a coûté des crédits d'écriture. L'outil vérifiera ce qui est réellement inscrit avant de refaire quoi que ce soit.");
        expect(l[2].erreur.quoiFaire).to.equal("Relancez l'action une fois. Si elle échoue de nouveau, n'insistez pas : prévenez l'équipe technique en lui donnant le détail de l'étape.");
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
        // Sans confirmation : la noter d'abord ; l'action nomme le compte visé et mène à l'écran des confirmations.
        let a = M.prochaineAction(vue(neuf));
        expect(a.code).to.equal("consigner_confirmation");
        expect(a.lien).to.equal("/clients/client-neuf/confirmations");
        expect(a.cles).to.deep.equal([cle]);
        expect(a.titre).to.equal("Notez la confirmation du client");
        // Le bouton de la fiche mène à l'écran des confirmations : il ne porte pas le nom du bouton qui note.
        expect(a.bouton).to.equal("Aller noter la confirmation");
        // Ce que la personne fait confirmer, elle sait l'expliquer : ce que sont les crédits (CT-4 EX-4.16, EX-4.19),
        // et comment faire confirmer l'adresse, en entier et par écrit (EX-7.26, EX-8.21).
        expect(a.credits).to.equal("Les crédits d'écriture ne sont pas de l'argent : ils servent seulement à payer les écritures sur le registre public, et chaque écriture en consomme. Ils ne s'achètent pas, ne se vendent pas et ne s'échangent pas : c'est notre société qui les fournit, et le client ne les paie pas.");
        expect(a.versement).to.equal("Ceux que nous versons sur le compte technique de l'enregistreur du client lui servent à payer ses propres écritures : ses preuves de date et ses clôtures de période.");
        expect(a.adresse).to.equal("Ne la dictez pas : 42 caractères ne se lisent pas à voix haute sans erreur. Envoyez-la au client par écrit, par un autre moyen que cet outil, et demandez-lui de vous répondre par écrit qu'elle est bien, en entier, celle du compte technique de son enregistreur. Gardez sa réponse avec la pièce de la confirmation.");
        expect(a.adresse, "jamais une comparaison partielle").to.not.match(/premiers|derniers|début|fin de/);
        expect(motsTechniquesDans(`${a.credits}\n${a.adresse}`)).to.deep.equal([]);
        // Une confirmation d'une autre opération, ou déjà consommée, ne compte pas.
        expect(M.prochaineAction(vue(neuf, { confirmations: [{ ...conf(null), operation: "approvisionner" }] })).code).to.equal("consigner_confirmation");
        expect(M.prochaineAction(vue(neuf, { confirmations: [conf("trv-1")] })).code).to.equal("consigner_confirmation");
        // Rien n'a encore été tenté : on commence, on ne « reprend » pas.
        a = M.prochaineAction(vue(neuf, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", commande: "inscrire-client", variante: "commencer", titre: "Lancez l'inscription sur le registre public", bouton: "Commencer les étapes 2 à 5" });
        // Étape en échec : la reprise part de l'étape arrêtée et relit le registre ; la confirmation en réserve suffit.
        const echec = dossierFictif("client-neuf", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(echec, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", variante: "reprendre_echec", titre: "Reprenez à l'étape 3", bouton: "Reprendre à l'étape 3" });
        expect(a.phrase).to.equal("Vous n'avez rien à corriger d'ici : l'outil vérifie d'abord ce qui est réellement inscrit sur le registre public, puis refait les étapes 3 à 5. Les étapes déjà faites ne sont pas refaites.");
        // Arrêt sur un refus préalable, sans échec : on continue à l'étape qui reste.
        const arrete = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(arrete, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", variante: "continuer", titre: "Continuez l'inscription à l'étape 5", bouton: "Continuer à l'étape 5" });
        // Envoi sans reçu : reprise de la transaction connue, jamais un nouvel envoi (EX-7.13, EX-7.16). Complément du
        // 2026-11-18 : la consigne est la capture de cet envoi (`capturer --envoi`), qui ne demande aucune confirmation.
        const envoye = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "envoyee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(envoye));
        // Troisième lecture : le travail `capturer` ne fait que lire le registre ; une seule formule pour ce geste.
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 5, parametre: "envoi", valeur: envoye.steps[3].transaction_hash, titre: "Allez chercher la réponse du registre public pour l'étape 5", bouton: "Chercher la réponse", sousBouton: "Rien n'est renvoyé, rien n'est dépensé." });
        expect(a.phrase).to.equal("Une opération est partie vers le registre public, mais sa réponse n'est pas rangée dans le dossier. L'outil va chercher cette réponse et range la preuve de l'opération. Il ne renvoie jamais une opération déjà partie.");
        // Envoi sans réponse et confirmation non notée : la consigne est la reprise de l'envoi, et elle seule ; la
        // confirmation ne redevient la consigne qu'une fois l'envoi rangé.
        const parti = dossierFictif("client-neuf", ["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(parti));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 2, parametre: "envoi", valeur: parti.steps[0].transaction_hash });
        // L'attente a sa durée ordinaire, celle que règle le service d'inscription (120 secondes par défaut), et une
        // conduite sans chiffre inventé : si la fiche ne change pas, prévenir, sans relancer.
        expect(a.apres).to.equal("Après le clic : l'outil va chercher la réponse du registre public et l'attend, quelques minutes d'ordinaire. S'il l'obtient, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Sinon, la fiche ne change pas : prévenez alors l'équipe technique, sans rien lancer d'autre.");
        expect(a.cles, "aucune confirmation demandée tant que l'envoi n'est pas repris").to.equal(undefined);
        expect(M.prochaineAction(vue(dossierFictif("client-neuf", ["capturee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]))).code, "l'envoi rangé, la confirmation redevient la consigne").to.equal("consigner_confirmation");
        // Opération inscrite dont la preuve manque : même consigne, par la transaction (`capturer --transaction`).
        const inscriteSansPreuve = dossierFictif("client-neuf", ["capturee", "incluse", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(inscriteSansPreuve, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 3, parametre: "transaction", valeur: inscriteSansPreuve.steps[1].transaction_hash });
        expect(a.apres).to.equal("Après le clic : l'outil range la preuve, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Si la fiche ne change pas, prévenez l'équipe technique, sans rien lancer d'autre.");
        expect(a).to.include({ titre: "Allez chercher la réponse du registre public pour l'étape 3", bouton: "Chercher la réponse", sousBouton: "Rien n'est renvoyé, rien n'est dépensé." });
        // L'envoi de l'étape 6 (inscription de l'enregistreur) part aussi du service d'inscription : même reprise.
        const sixEnvoyee = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "envoyee", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(sixEnvoyee));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 6, parametre: "envoi", valeur: sixEnvoyee.steps[4].transaction_hash });
        // Les deux dernières étapes se font chez le client, avec ses propres outils : leur envoi n'est pas dans les
        // données du service d'inscription. La reprise n'y est pas proposée ; la consigne est neutre, sans commande.
        const neutres = [];
        for (const etats of [
          ["capturee", "capturee", "faite", "capturee", "capturee", "envoyee", "a_faire"],
          ["capturee", "capturee", "faite", "capturee", "capturee", "incluse", "a_faire"],
          ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "envoyee"],
          ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "incluse"],
        ]) {
          const chezLeClient = dossierFictif("client-neuf", etats);
          a = M.prochaineAction(vue(chezLeClient));
          const n = etats.findIndex((x) => x === "envoyee" || x === "incluse") + 2;
          const envoyee = etats.includes("envoyee");
          expect(a, etats.join(",")).to.include({ code: "attendre_envoi", etape: n, titre: envoyee ? `Attendez la réponse du registre public pour l'étape ${n}` : `Attendez que la preuve de l'étape ${n} soit rangée dans le dossier`, bouton: "Actualiser la fiche", lien: "/clients/client-neuf" });
          expect(a.commande, "aucune action proposée").to.equal(undefined);
          // D'abord à qui est l'étape, puis où elle en est et depuis quand, puis à partir de quand s'inquiéter : sans durée inventée.
          // Heures des données fictives, dans l'ordre des étapes : la première preuve de date à 10:00, la clôture à 11:00.
          const depuis = `depuis le 12 novembre 2026 à ${n === 7 ? "10:00" : "11:00"} UTC`;
          expect(a.phrase).to.equal(`Cette étape se fait chez le client, avec ses propres outils : vous n'avez rien à lancer d'ici. ${envoyee ? `Elle est notée « Envoyée » ${depuis} et attend la réponse du registre public` : `Le registre public l'a inscrite ${depuis}, mais sa preuve n'est pas encore rangée dans le dossier`}. Le client a fait sa part : si la fiche n'a pas changé à votre prochaine visite, prévenez l'équipe technique.`);
          expect(a.apres).to.equal("Le bouton relit seulement la fiche : rien n'est envoyé, rien n'est dépensé. Cet outil ne sait pas combien de temps le registre public mettra à répondre.");
          neutres.push(vue(chezLeClient));
        }
        // Étapes 2 à 5 faites : demande à préparer, puis à faire signer hors de l'application et à relayer.
        const cours = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(cours));
        expect(a).to.include({ code: "preparer_demande", commande: "condense-inscription", keyId: cours.recorders[0].key_id, titre: "Préparez le document d'inscription de l'enregistreur" });
        a = M.prochaineAction(vue(cours, { demandes: [{ nom: `demande-inscription-${cours.recorders[0].key_id}-trv-1.json`, document: { signatures: [] } }] }));
        // Troisième lecture : le bouton dit lui-même qui envoie, et la phrase dessous dit que c'est le cas habituel.
        expect(a).to.include({ code: "relayer_demande", commande: "inscrire-cle", titre: "Faites signer le document par les approbateurs du client, puis envoyez-le", bouton: "Envoyer par notre compte d'envoi", sousBouton: "C'est le cas habituel : notre société envoie le document signé au registre public et paie cet envoi. L'autre cas, l'envoi par un compte que désigne l'équipe technique, ne sert qu'à ses essais ; il est rangé dans « Actions rarement utiles »." });
        expect(a.phrase).to.equal("Le document d'inscription de l'enregistreur est prêt. Remettez-le aux approbateurs du client : ils le contrôlent et le signent avec leur propre outil, jamais dans celui-ci. Quand le client vous rend le document signé, envoyez-le ici.");
        // Enregistreur inscrit : la première période se fait hors de l'outil.
        const inscrite = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "capturee", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(inscrite));
        expect(a.code).to.equal("attendre_premiere_periode");
        expect(a.commande).to.equal(undefined);
        expect(a.titre).to.equal("Attendez la première preuve de date du client");
        expect(a.apres).to.equal("Cette fiche se met à jour quand ces deux étapes sont enregistrées dans le dossier. Cet outil ne sait pas quand le client les fera : si la fiche n'a pas changé à votre prochaine visite, demandez au client où il en est.");
        // Aucune attente ne porte une durée que rien ne fonde : seule la reprise d'un envoi en a une.
        for (const x of [a, ...neutres.map((v) => M.prochaineAction(v))]) expect(`${x.phrase} ${x.apres}`, x.code).to.not.match(/[0-9]+ (?:minutes?|heures?|jours?)|quelques (?:minutes|heures|jours)|une heure|deux minutes/);
        // Dossier fini : export, vérification, paquet, remise.
        const fini = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]);
        expect(M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"] }))).to.include({ code: "exporter", commande: "exporter" });
        expect(M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"], parties: ["parties/1"] }))).to.include({ code: "verifier", commande: "verifier" });
        const verifie = [travailFictif(9, { slug: "client-neuf", commande: "verifier", recu_a: "2026-11-13T09:00:00.000Z" })];
        a = M.prochaineAction(vue(fini, { periodes: ["periode-1/manifeste.json"], parties: ["parties/1"], travaux: verifie }));
        expect(a).to.include({ code: "produire_paquet", lien: "/clients/client-neuf/paquet" });
        expect(M.prochaineAction(vue(fini)).code, "sans période dans les données de l'agent").to.equal("produire_paquet");
        a = M.prochaineAction(vue(fini, { paquet: { present: true, dernier: null } }));
        // Inscription finie et paquet produit : ce n'est plus une « prochaine action » parmi d'autres.
        expect(a).to.include({ code: "remettre_paquet", lien: "/clients/client-neuf/paquet", surTitre: "Inscription terminée", titre: "Remettez le paquet au client" });
        // Chaque action est une consigne : quoi faire (verbe à l'impératif), pourquoi, quoi avoir sous la main, ce qui se passe après.
        const toutes = [vue(neuf), vue(neuf, { confirmations: [conf(null)] }), vue(echec, { confirmations: [conf(null)] }), vue(arrete, { confirmations: [conf(null)] }), vue(envoye), vue(parti), vue(inscriteSansPreuve, { confirmations: [conf(null)] }), vue(cours), vue(cours, { demandes: [{ nom: `demande-inscription-${cours.recorders[0].key_id}-trv-1.json`, document: { signatures: [] } }] }), vue(inscrite), vue(fini, { periodes: ["periode-1/manifeste.json"] }), vue(fini, { periodes: ["periode-1/manifeste.json"], parties: ["parties/1"] }), vue(fini), vue(fini, { paquet: { present: true, dernier: null } }), vue(sixEnvoyee), ...neutres].map((v) => M.prochaineAction(v));
        expect(new Set(toutes.map((x) => x.code)).size, "états couverts").to.equal(11);
        for (const x of toutes) {
          expect(x.titre, x.code).to.match(/^[A-ZÀ-Ý][a-zéèêçôîû]+(?:ez|tes) /);
          expect(x.phrase, x.code).to.match(/^[A-ZÀ-Ý].{40,}\.$/);
          expect(x.aPreparer, x.code).to.match(/^(Ayez sous la main : .+|Vous n'avez rien à rassembler avant de cliquer.*)\.$/);
          expect(x.apres, x.code).to.match(/^[A-ZÀ-Ý].{30,}\.$/);
          expect(x.bouton, x.code).to.match(/^[A-ZÀ-Ý][a-zéèêçôîû]+(?:er|ir|re) /);
          expect(x.surTitre, x.code).to.be.oneOf(["Prochaine action", "Inscription terminée"]);
          expect(motsTechniquesDans([x.surTitre, x.titre, x.phrase, x.aPreparer, x.apres, x.bouton].join("\n")), x.code).to.deep.equal([]);
        }
        // « Reprendre » ne se dit que si quelque chose a été envoyé ou a échoué.
        for (const x of toutes) if (/[Rr]epren/.test(`${x.titre} ${x.bouton}`)) expect(x.code === "reprendre_envoi" || x.variante === "reprendre_echec", x.titre).to.equal(true);
      };
      verifier(P);
      const m = await mutant("confirmation-consommee", "&& !c.consommee_par", "");
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
      // Mutant : « Reprendre » offert à un client où rien n'a été tenté.
      const m2 = await mutant("reprendre-sans-tentative", "bouton: `Commencer les étapes 2 à ${dernier}`", "bouton: `Reprendre les étapes 2 à ${dernier}`");
      tue = false;
      try { verifier(m2); } catch { tue = true; }
      expect(tue, "mutant « Reprendre » sans tentative tué").to.equal(true);
      // Mutant : l'envoi resté sans réponse ne passe plus avant la confirmation (deux consignes contraires sur l'écran).
      const m3 = await mutant("envoi-apres-confirmation", "const partie = etapes.find((e) => (e.state === \"envoyee\" || e.state === \"incluse\") && e.transaction_hash);", "const partie = null;");
      tue = false;
      try { verifier(m3); } catch { tue = true; }
      expect(tue, "mutant « envoi après confirmation » tué").to.equal(true);
    });

    it("chaque commande de travail, chaque état de travail et chaque résultat de sortie a un libellé en clair ; « confirmation hors bande absente » reste mot pour mot (EX-7.26) ; chaque code d'erreur du schéma des sorties reçoit une explication et une conduite à tenir", async function () {
      const { COMMANDES } = await import("../paquets/inscription/src/commun/travaux.mjs");
      for (const c of COMMANDES) expect(P.COMMANDES[c], c).to.be.a("string").and.match(/^[A-ZÀ-Ý][^_]+$/);
      expect(Object.keys(P.COMMANDES).sort()).to.deep.equal([...COMMANDES].sort());
      // Le nom d'une action est un verbe, sans mot de technicien.
      for (const c of COMMANDES) {
        expect(P.COMMANDES[c], c).to.match(/^[A-ZÉ][a-zéèêôîû]+(?:er|ir|re) /);
        expect(motsTechniquesDans(P.COMMANDES[c]), c).to.deep.equal([]);
      }
      const resultats = schema("operations-registre-v0.schema.json").$defs.sortie.properties.result.enum;
      const vus = new Set();
      for (const r of resultats) {
        const e = P.etatTravail({ etat: "fini", sortie: { result: r } });
        expect(e.libelle, r).to.be.a("string").and.not.match(/_/);
        expect(e.libelle, r).to.not.equal(r);
        expect(e.explication, r).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(motsTechniquesDans(`${e.libelle}\n${e.explication}`), r).to.deep.equal([]);
        vus.add(e.libelle);
      }
      expect(vus.size, "un libellé par résultat").to.equal(resultats.length);
      expect(P.etatTravail({ etat: "fini", sortie: { result: "reussi" } })).to.include({ libelle: "Réussi", ton: "succes" });
      expect(P.etatTravail({ etat: "fini", sortie: { result: "refuse" } }).libelle).to.equal("Refusé avant envoi");
      expect(P.etatTravail({ etat: "fini", sortie: { result: "incertain" } }).libelle).to.equal("Résultat pas encore connu");
      for (const etat of ["en_attente", "en_cours", "refuse", "abandonne"]) {
        const e = P.etatTravail({ etat });
        expect(e.libelle, etat).to.be.a("string").and.not.match(/_/);
        expect(e.explication, etat).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(motsTechniquesDans(`${e.libelle}\n${e.explication}`), etat).to.deep.equal([]);
      }
      expect(P.etatTravail({ etat: "en_cours" })).to.include({ libelle: "En cours", ton: "info" });
      // Un travail déjà en cours : le suivant attend son tour, et l'écran le dit.
      expect(P.etatTravail({ etat: "en_attente" })).to.include({ libelle: "En attente de son tour", termine: false });
      // Refus pour confirmation absente : une phrase courante, et la mention du texte, mot pour mot, à part.
      const refus = P.etatTravail({ etat: "refuse", motif: { code: "confirmation_absente", message: "x" } });
      expect(refus.ton).to.equal("refus");
      const absente = P.explicationErreur("confirmation_absente");
      expect(absente.fixe).to.equal("confirmation hors bande absente");
      expect(absente.phrase).to.equal("Rien n'a été envoyé : il manque la confirmation du client pour cette opération.");
      expect(absente.quoiFaire).to.equal("Notez la confirmation du client sur l'écran « Confirmations du client », puis relancez l'action.");
      const codes = schema("operations-registre-v0.schema.json").$defs.sortie.properties.error.oneOf[1].properties.code.enum;
      expect(codes.length).to.be.greaterThan(40);
      // Les refus de l'interface et de l'agent hors du schéma des sorties, et les deux pannes que la page constate elle-même.
      const interface_ = ["confirmation_absente", "reference_refusee", "requete_invalide", "agent_injoignable", "session_absente", "client_inconnu", "file_pleine", "travail_inconnu", "paquet_absent", "corps_trop_grand", "longueur_exigee", "origine_refusee", "hote_refuse", "configuration", "outil_injoignable", "suivi_interrompu"];
      for (const c of [...codes, ...interface_]) {
        const x = P.explicationErreur(c);
        expect(x.phrase, c).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(x.effet, c).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(x.quoiFaire, c).to.match(/^[A-ZÀ-Ý].+\.$/);
        expect(x.connu, c).to.equal(true);
        // Aucun mot de technicien : le code et le message exacts sont affichés à part, dans le détail.
        expect(motsTechniquesDans([x.phrase, x.effet, x.quoiFaire].join("\n")), c).to.deep.equal([]);
        if (c !== "confirmation_absente") expect(x.fixe, c).to.equal(null);
      }
      // Ce qui a été envoyé ou dépensé se dit : rien pour un refus préalable, un coût pour un envoi qui a échoué.
      expect(P.explicationErreur("solde_insuffisant").effet).to.equal("Rien n'a été envoyé au registre public et rien n'a été dépensé.");
      expect(P.explicationErreur("transaction_annulee").effet).to.match(/a coûté des crédits d'écriture/);
      expect(P.explicationErreur("recu_absent").effet).to.match(/est partie vers le registre public/);
      // Un code inconnu : explication générale, le code n'est pas caché par l'appelant (il l'affiche à côté).
      const inconnu = P.explicationErreur("code_futur");
      expect(inconnu.connu).to.equal(false);
      expect(inconnu.quoiFaire).to.match(/prévenez l'équipe technique/);
    });

    it("un travail d'ensemble « réussi » dont une étape est en échec dans le dossier se dit « Terminé, avec une étape en échec », jamais « Réussi » ; seul le dernier travail de sa commande est confronté au dossier ; mutant (confrontation retirée) : tué", async function () {
      const echec = dossierFictif("client-en-echec", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      const sain = dossierFictif("client-sain", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
      const recent = travailFictif(2, { slug: "client-en-echec", commande: "inscrire-client", recu_a: "2026-11-12T08:20:00.000Z" });
      const ancien = travailFictif(1, { slug: "client-en-echec", commande: "inscrire-client", recu_a: "2026-11-12T08:00:00.000Z" });
      const autre = travailFictif(3, { slug: "client-en-echec", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" });
      const verifier = (M) => {
        const l = M.etatsTravaux([recent, ancien, autre], echec);
        expect(l[0]).to.include({ libelle: "Terminé, avec une étape en échec", ton: "refus", termine: true });
        expect(l[0].explication).to.match(/c'est l'étape qui fait foi/);
        expect(l[1].libelle, "un travail plus ancien de la même commande garde son résultat").to.equal("Réussi");
        expect(l[2].libelle, "une commande qui ne conduit pas l'étape en échec").to.equal("Réussi");
        expect(M.etatsTravaux([recent], sain)[0].libelle, "sans étape en échec").to.equal("Réussi");
        // L'étape « Inscrire l'enregistreur » en échec contredit le dernier envoi de la demande signée, pas les étapes 2 à 5.
        const cle = dossierFictif("client-cle", ["capturee", "capturee", "faite", "capturee", "echec", "a_faire", "a_faire"]);
        const envoi = travailFictif(4, { slug: "client-cle", commande: "inscrire-cle", recu_a: "2026-11-12T09:00:00.000Z" });
        const etapes = travailFictif(5, { slug: "client-cle", commande: "inscrire-client", recu_a: "2026-11-12T08:30:00.000Z" });
        expect(M.etatsTravaux([envoi, etapes], cle).map((x) => x.libelle)).to.deep.equal(["Terminé, avec une étape en échec", "Réussi"]);
      };
      verifier(P);
      const m = await mutant("sans-confrontation", "if (reussi && dernier && dossier &&", "if (false && reussi && dernier && dossier &&");
      let tue = false;
      try { verifier(m); } catch { tue = true; }
      expect(tue, "mutant tué").to.equal(true);
    });

    it("aucun mot de technicien dans les textes du parcours : étapes, états, saisies refusées, opérations, lexique ; chaque saisie refusée dit quoi corriger ; le lexique reprend les mots du glossaire commun ; mutants (« clé de chaîne » dans une étape, « hors bande » dans une erreur) : tués", async function () {
      const verifier = (M) => {
        const textes = [];
        for (const e of [M.ETAPE_PREPARATION, ...Object.values(M.ETAPES)]) textes.push(e.titre, e.phrase);
        for (const e of Object.values(M.ETATS_ETAPE)) textes.push(e.libelle, e.explication);
        for (const d of [dossierFictif("a", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]), dossierFictif("b", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]), dossierFictif("c", ["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]), dossierFictif("d", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"])]) {
          const a = M.avancement(d);
          textes.push(a.libelle, a.phrase, a.phraseFaites, a.resume);
          for (const e of M.etapesDuParcours(d)) textes.push(e.libelle, e.explication, e.objet?.texte ?? "");
        }
        for (const t of Object.values(M.OPERATIONS_JEU)) textes.push(t);
        for (const t of Object.values(M.OPERATIONS_CONFIRMATION)) textes.push(t);
        for (const x of M.LEXIQUE) textes.push(x.terme, x.explication);
        const types = ["slug", "nom_journal", "liste_noms_journal", "adresse", "liste_adresses", "hachage", "cle_publique_ed25519", "seuil", "entier", "montant", "reference_cle", "texte", "chemin", "document", "liste_documents", "horodatage", "type_futur"];
        for (const t of types) {
          const s = M.explicationSaisie(t);
          expect(s, t).to.match(/^[A-ZÀ-Ý].+\.$/);
          textes.push(s);
        }
        expect(textes.length).to.be.greaterThan(90);
        for (const t of textes) expect(motsTechniquesDans(t), t).to.deep.equal([]);
        // Une saisie refusée dit quoi corriger, pas seulement ce qui est faux.
        for (const t of ["slug", "adresse", "liste_adresses", "hachage", "document", "liste_documents", "horodatage", "reference_cle"]) expect(M.explicationSaisie(t), t).to.match(/Corrigez|Copiez|Collez|Servez-vous|laissez/);
      };
      verifier(P);
      expect(MOTS_TECHNIQUES.length, "liste publiée").to.be.greaterThan(40);
      // Le lexique : les mots du glossaire commun aux trois écrans, avec leur explication.
      const lexique = Object.fromEntries(P.LEXIQUE.map((x) => [x.terme, x.explication]));
      expect(lexique["registre public"]).to.equal("un registre que personne ne peut modifier après coup");
      expect(lexique.empreinte).to.equal("une suite de caractères qui identifie un document sans erreur possible : si un seul caractère du document change, l'empreinte change");
      expect(lexique.journal).to.equal("la suite des actions enregistrées, dans l'ordre");
      for (const terme of ["enregistreur", "preuve de date", "signature", "adresse de signature", "compte technique", "crédits d'écriture", "service d'inscription", "paquet du client", "approbateur"]) expect(lexique[terme], terme).to.be.a("string").and.match(/.{20,}/);
      let tues = 0;
      const m1 = await mutant("cle-de-chaine", "Verse des crédits d'écriture sur le compte technique de l'enregistreur du client", "Verse à la clé de chaîne");
      try { verifier(m1); } catch { tues++; }
      const m2 = await mutant("hors-bande", 'E("Rien n\'a été envoyé : il manque la confirmation du client pour cette opération."', 'E("Rien n\'a été envoyé : confirmation hors bande absente."');
      let vu = false;
      try { expect(motsTechniquesDans(m2.explicationErreur("confirmation_absente").phrase)).to.deep.equal([]); } catch { vu = true; }
      if (vu) tues++;
      expect(tues, "mutants tués").to.equal(2);
    });

    it("les instants se lisent en français et en UTC (« 12 novembre 2026 à 08:05 UTC ») ; un instant illisible est rendu tel quel", function () {
      expect(P.dateLisible("2026-11-12T08:05:07.250Z")).to.equal("12 novembre 2026 à 08:05 UTC");
      expect(P.dateLisible("2026-01-01T00:00:00.000Z")).to.equal("1er janvier 2026 à 00:00 UTC");
      expect(P.dateLisible("hier")).to.equal("hier");
      expect(P.dateLisible(null)).to.equal("");
      // Le jour seul, pour la ligne d'une étape faite ; un nombre lisible garde tous ses chiffres.
      expect(P.jourLisible("2026-11-12T08:05:07.250Z")).to.equal("12 novembre 2026");
      expect(P.jourLisible("hier")).to.equal("hier");
      expect(P.nombreLisible("327000000")).to.equal("327\u00a0000\u00a0000");
      expect(P.nombreLisible("327000000").replace(/\u00a0/g, "")).to.equal("327000000");
      expect(P.nombreLisible("12 wei")).to.equal("12 wei");
    });

    it("troisième lecture des écrans : une seule formule pour la reprise d'un envoi, qui ne fait que lire le registre (« Allez chercher la réponse du registre public », « Chercher la réponse ») ; le bouton de l'envoi d'un document signé dit qui envoie ; une confirmation n'est attendue que pour un versement à faire ou un changement des approbateurs préparé ; les fiches d'enregistreur se lisent une par zone et donnent la liste de la saisie à la main ; les heures des données fictives suivent l'ordre des étapes ; mutants tués", async function () {
      const neuf = dossierFictif("client-neuf", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      const vue = (dossier, plus = {}) => ({ slug: dossier.organisation.slug, dossier, confirmations: [], demandes: [], periodes: [], parties: [], travaux: [], paquet: { present: false, dernier: null }, ...plus });
      // 1. Une formule pour la reprise : la consigne, le nom de l'action, les erreurs qui y renvoient, le résultat pas encore connu.
      const formule = (M) => {
        const textes = [M.libelleCommande("capturer"), M.etatTravail({ etat: "fini", sortie: { result: "incertain" } }).explication];
        for (const code of ["recu_absent", "transaction_en_attente", "certificat_indisponible", "certificat_elague", "certificat_invalide", "capture_incomplete"]) {
          const x = M.explicationErreur(code);
          textes.push(x.phrase, x.effet, x.quoiFaire);
          expect(x.quoiFaire, code).to.contain("Actualisez la fiche du client : elle vous propose d'aller chercher la réponse du registre public.");
        }
        for (const etats of [["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], ["capturee", "incluse", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"], ["capturee", "capturee", "faite", "capturee", "envoyee", "a_faire", "a_faire"]]) {
          const a = M.prochaineAction(vue(dossierFictif("client-neuf", etats)));
          expect(a.code).to.equal("reprendre_envoi");
          expect(a.titre).to.match(/^Allez chercher la réponse du registre public pour l'étape [2-6]$/);
          expect([a.bouton, a.sousBouton]).to.deep.equal(["Chercher la réponse", "Rien n'est renvoyé, rien n'est dépensé."]);
          textes.push(a.titre, a.phrase, a.aPreparer, a.apres, a.bouton, a.sousBouton);
        }
        expect(M.libelleCommande("capturer")).to.equal("Aller chercher la réponse du registre public");
        expect(M.etatTravail({ etat: "fini", sortie: { result: "incertain" } }).explication).to.equal("L'opération est partie, mais la réponse du registre public n'est pas arrivée. Ne relancez pas l'action : allez chercher la réponse du registre public, depuis la fiche du client.");
        // Rien ne dit « reprendre » un envoi : le mot fait croire qu'on renvoie.
        for (const t of textes) expect(t, t).to.not.match(/repren[a-z]* (?:cet |l'|un |votre )?envoi|reprise de l'envoi/i);
        expect(motsTechniquesDans(textes.join("\n"))).to.deep.equal([]);
      };
      formule(P);
      let tue = false;
      try { formule(await mutant("reprendre-cet-envoi", "  bouton: \"Chercher la réponse\",", "  bouton: \"Reprendre cet envoi\",")); } catch { tue = true; }
      expect(tue, "mutant « Reprendre cet envoi » tué").to.equal(true);
      // 2. L'envoi d'un document signé : le bouton nomme notre compte d'envoi ; la phrase dessous dit le cas habituel.
      expect(P.PAR_NOTRE_COMPTE).to.deep.equal({ bouton: "Envoyer par notre compte d'envoi", sousBouton: "C'est le cas habituel : notre société envoie le document signé au registre public et paie cet envoi. L'autre cas, l'envoi par un compte que désigne l'équipe technique, ne sert qu'à ses essais ; il est rangé dans « Actions rarement utiles »." });
      // 3. Confirmation attendue : la même règle que la consigne pour le versement, et un changement des approbateurs préparé.
      const attendues = (M) => {
        const cle = neuf.recorders[0].chain_key;
        const conf = (plus) => ({ id: "cnf-1", operation: "approvisionnement", objet: { org_id: neuf.organisation.org_id, cle_chaine: cle }, consommee_par: null, ...plus });
        expect(M.confirmationsAttendues({ dossier: neuf })).to.deep.equal([{ operation: "approvisionnement", cle_chaine: cle }]);
        expect(M.confirmationsAttendues({ dossier: neuf, confirmations: [conf()] }), "une confirmation prête à servir attend déjà").to.deep.equal([]);
        expect(M.confirmationsAttendues({ dossier: neuf, confirmations: [conf({ consommee_par: "trv-1" })] }), "une confirmation déjà utilisée ne compte pas").to.have.length(1);
        const verse = dossierFictif("client-verse", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
        expect(M.confirmationsAttendues({ dossier: verse }), "versement fait").to.deep.equal([]);
        const echec = dossierFictif("client-echec", ["capturee", "capturee", "faite", "echec", "a_faire", "a_faire", "a_faire"]);
        expect(M.confirmationsAttendues({ dossier: echec }).map((x) => x.operation), "versement en échec, à refaire").to.deep.equal(["approvisionnement"]);
        const digest = `0x${"ab".repeat(32)}`;
        const prepare = { nom: "demande-administration-trv-7.json", document: { operation: "administration_jeu", digest } };
        expect(M.confirmationsAttendues({ dossier: verse, demandes: [prepare] })).to.deep.equal([{ operation: "administrer-jeu", digest }]);
        expect(M.confirmationsAttendues({ dossier: verse, demandes: [prepare], confirmations: [{ id: "cnf-2", operation: "administrer-jeu", objet: { org_id: verse.organisation.org_id, digest }, consommee_par: null }] })).to.deep.equal([]);
        expect(M.confirmationsAttendues({ dossier: verse, demandes: [prepare, { nom: "demande-administration-relayee-trv-8.json", document: { digest } }] }), "changement envoyé").to.deep.equal([]);
        // La consigne de la fiche et l'écran des confirmations disent la même chose.
        for (const v of [vue(neuf), vue(neuf, { confirmations: [conf()] }), vue(verse), vue(echec)]) expect(M.prochaineAction(v).code === "consigner_confirmation", v.dossier.organisation.slug).to.equal(M.confirmationsAttendues(v).length > 0);
      };
      attendues(P);
      tue = false;
      try { attendues(await mutant("toujours-attendue", "const l = versementsSansConfirmation(dossier, confirmations).map(", "const l = [{ operation: \"approvisionnement\" }, ...versementsSansConfirmation(dossier, confirmations)].map(")); } catch { tue = true; }
      expect(tue, "mutant « confirmation toujours attendue » tué").to.equal(true);
      // 4. Les fiches d'enregistreur : une par zone ; la liste assemblée est celle de la saisie à la main « [ fiche, fiche ] ».
      const C = await import(pathToFileURL(path.join(WEB, "composants", "champs-page.js")).href);
      expect([...C.MEMBRES_FICHE].sort(), "membres exigés par le schéma").to.deep.equal([...schema("inscription-client-v0.schema.json").$defs.cle_enregistreur.required].sort());
      const champ = { nom: "cles_enregistreur", type: "liste_documents" };
      const fiche = (n) => ({ ...dossierFictif(`fiche-${n}`, ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]).recorders[0], created_at: "2026-11-10T09:00:00.000Z" });
      const [t1, t2] = [JSON.stringify(fiche(1), null, 2), `\n  ${JSON.stringify(fiche(2))}  \n`];
      expect(C.lireFiches(champ, [t1])).to.deep.equal({ valeur: [fiche(1)] });
      expect(C.lireFiches(champ, [t1, t2])).to.deep.equal({ valeur: [fiche(1), fiche(2)] });
      // Le corps envoyé est celui que produisait la saisie à la main dans une seule zone, au caractère près.
      expect(JSON.stringify(C.lireFiches(champ, [t1, t2]).valeur)).to.equal(JSON.stringify(C.lireChamp(champ, `[${t1},${t2}]`).valeur));
      for (const [textes, attendu] of [
        [[""], { zone: 0, regle: "fiche_vide" }], [[t1, "   "], { zone: 1, regle: "fiche_vide" }], [["[]"], { zone: 0, regle: "fiche_liste" }], [[`[${t1}]`], { zone: 0, regle: "fiche_liste" }],
        [[t1.slice(0, -1)], { zone: 0, regle: "fiche_illisible" }], [["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"], { zone: 0, regle: "fiche_illisible" }], [['"texte"'], { zone: 0, regle: "fiche_illisible" }],
        [[t1, JSON.stringify({ key_id: "rec-1" })], { zone: 1, regle: "fiche_illisible" }],
      ]) {
        const r = C.lireFiches(champ, textes);
        expect(r, textes.join("|").slice(0, 40)).to.include(attendu);
        expect(r.valeur).to.equal(undefined);
        expect(r.erreur, "la valeur refusée n'est pas recopiée").to.not.contain("0x7099");
      }
      for (const regle of ["fiche_vide", "fiche_liste", "fiche_illisible"]) {
        for (const retirable of [false, true]) {
          const t = P.explicationFiche(regle, retirable);
          expect(t, regle).to.match(/^[A-ZÀ-Ý].+\.$/);
          expect(t, regle).to.match(/[Cc]ollez/);
          expect(motsTechniquesDans(t), regle).to.deep.equal([]);
        }
      }
      expect(P.explicationFiche("fiche_vide", true)).to.match(/« Retirer cette zone »\.$/);
      // La première zone ne reste pas vide, et la phrase dit pourquoi (une liste vide, que la route admet, est
      // refusée dans la page) : cet outil n'inscrit que les enregistreurs du dossier, qui ne se prépare qu'une fois.
      expect(P.explicationFiche("fiche_vide", false)).to.equal("Cette zone est vide. Collez-y tout le contenu du fichier que le client vous a envoyé pour son enregistreur, sans rien y changer. Il faut au moins une fiche : l'outil n'inscrit au registre public que les enregistreurs dont la fiche est donnée ici, et il ne pourra plus en ajouter une fois le dossier préparé.");
      for (const regle of ["fiche_liste", "fiche_illisible"]) for (const retirable of [false, true]) expect(P.explicationFiche(regle, retirable), regle).to.not.contain("au moins une fiche");
      expect(P.explicationFiche("fiche_vide", true), "une zone ajoutée peut se retirer").to.not.contain("au moins une fiche");
      expect(P.explicationSaisie("liste_documents"), "plus de crochets à taper").to.not.match(/crochet/);
      // 5. Heures des données fictives : dans l'ordre des étapes et des travaux (un même échec n'a qu'une heure).
      const { ecrireDonneesFictives, ajouterClientFictif } = await import("./fixtures/inscription/donnees-fictives.mjs");
      const d = path.join(dir, "donnees-heures");
      fs.mkdirSync(d);
      const F = ecrireDonneesFictives(d);
      ajouterClientFictif(d, "client-etape-7-envoyee", ["capturee", "capturee", "faite", "capturee", "capturee", "envoyee", "a_faire"], { histoire: true });
      ajouterClientFictif(d, "client-premiere-periode", ["capturee", "capturee", "faite", "capturee", "capturee", "a_faire", "a_faire"], { histoire: true });
      const travaux = fs.readdirSync(path.join(d, "travaux")).map((n) => JSON.parse(fs.readFileSync(path.join(d, "travaux", n), "utf8")));
      const lignes = fs.readFileSync(path.join(d, "confirmations.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
      let vus = 0;
      for (const slug of fs.readdirSync(path.join(d, "clients"))) {
        const dossier = JSON.parse(fs.readFileSync(path.join(d, "clients", slug, "dossier.json"), "utf8"));
        const siens = travaux.filter((t) => t.slug === slug);
        const instants = dossier.steps.filter((e) => e.updated_at).map((e) => e.updated_at);
        expect(instants, `${slug} : étapes dans l'ordre`).to.deep.equal([...instants].sort());
        for (const e of dossier.steps.filter((x) => x.updated_at)) {
          expect(e.updated_at > dossier.prepared_at, `${slug} ${e.step} après la préparation`).to.equal(true);
          const commande = { jeu_approbateurs: "inscrire-client", assignation: "inscrire-client", lecture_jeu: "inscrire-client", approvisionnement: "inscrire-client", inscription: "inscrire-cle" }[e.step];
          const t = siens.filter((x) => x.commande === commande).sort((a, b) => (a.recu_a < b.recu_a ? 1 : -1))[0];
          if (!commande || !t) continue;
          vus++;
          // L'étape est écrite par le travail qui la conduit : après sa réception, à la même minute affichée.
          expect(e.updated_at > t.recu_a, `${slug} ${e.step} après son travail`).to.equal(true);
          expect(P.dateLisible(e.updated_at), `${slug} ${e.step} : même heure que son travail`).to.equal(P.dateLisible(t.recu_a));
        }
        // La confirmation est notée avant le travail qui la consomme, et consommée avant le versement.
        for (const l of lignes.filter((x) => x.consommation && x.org_id === dossier.organisation.org_id)) {
          const c = lignes.find((x) => x.id === l.consommation);
          const verse = dossier.steps.find((e) => e.step === "approvisionnement");
          const t = travaux.find((x) => x.id === l.travail);
          expect([c.instant < c.recu_a, c.recu_a <= t.recu_a, t.recu_a < l.instant, l.instant < verse.updated_at], slug).to.deep.equal([true, true, true, true]);
        }
      }
      expect(vus, "étapes confrontées à leur travail").to.be.greaterThan(12);
      // Les deux incohérences relevées par la lecture : l'échec de « client-en-echec » et les étapes 6 et 7.
      const echoue = F.travaux.find((t) => t.slug === "client-en-echec" && t.commande === "inscrire-client");
      expect(P.dateLisible(F.clients["client-en-echec"].dossier.steps[1].updated_at)).to.equal(P.dateLisible(echoue.recu_a));
      const sept = JSON.parse(fs.readFileSync(path.join(d, "clients", "client-etape-7-envoyee", "dossier.json"), "utf8")).steps;
      expect(sept[5].updated_at > sept[4].updated_at, "étape 7 envoyée après l'étape 6").to.equal(true);
    });

    it("quatrième lecture des écrans : ce que sont les crédits d'écriture se dit en une explication exacte (pas de l'argent, à quoi ils servent, qui les fournit, le client ne les paie pas), sans durée ; aucun texte ne parle de « compte de paiement » ni de « budget » ; la cause d'une étape en échec se dit d'après la vérification qui l'a rendue ; « Rien à réunir » ne contredit jamais une consigne « Préparez » ; mutants : tués", async function () {
      const verifier = (M) => {
        // L'explication, mot pour mot, et chacune de ses affirmations (CT-4 4.5, EX-4.15, EX-4.16, EX-4.19).
        expect(M.CREDITS_EN_CLAIR).to.equal("Les crédits d'écriture ne sont pas de l'argent : ils servent seulement à payer les écritures sur le registre public, et chaque écriture en consomme. Ils ne s'achètent pas, ne se vendent pas et ne s'échangent pas : c'est notre société qui les fournit, et le client ne les paie pas.");
        for (const motif of [/ne sont pas de l'argent/, /seulement à payer les écritures/, /ne s'achètent pas, ne se vendent pas et ne s'échangent pas/, /notre société qui les fournit/, /le client ne les paie pas/]) expect(M.CREDITS_EN_CLAIR).to.match(motif);
        // Aucune durée : elle ne se calcule pas à partir de ce que l'écran affiche.
        for (const t of [M.CREDITS_EN_CLAIR, M.VERSEMENT_EN_CLAIR, M.montantEnClair(10800000)]) expect(t).to.not.match(/[0-9]+ ?jours?|semaines?|mois\b|environ/);
        expect(M.montantEnClair(10800000).replace(/\s/g, " "), "milliers séparés par une espace insécable").to.equal("Le montant est calculé à partir de la consommation prévue pour son enregistreur, réglée à 10 800 000 crédits par jour ; si le compte en a déjà, l'outil ne verse que la différence.");
        expect(M.nommeLesCredits("Cet envoi coûte des crédits d'écriture.")).to.equal(true);
        expect(M.nommeLesCredits("Rien n'est dépensé.")).to.equal(false);
        // Aucun mot qui contredit l'explication, dans aucun texte du module.
        const lexique = M.LEXIQUE.map((x) => `${x.terme} ${x.explication}`);
        const codes = schema("operations-registre-v0.schema.json").$defs.sortie.properties.error.oneOf[1].properties.code.enum;
        const erreurs = codes.flatMap((c) => { const x = M.explicationErreur(c); return [x.phrase, x.effet, x.quoiFaire]; });
        const etapes = Object.values(M.ETAPES).map((x) => `${x.titre} ${x.phrase}`);
        const neuf = dossierFictif("client-neuf", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        const consigne = M.prochaineAction({ slug: "client-neuf", dossier: neuf });
        const tout = [...lexique, ...erreurs, ...etapes, M.CREDITS_EN_CLAIR, M.VERSEMENT_EN_CLAIR, M.montantEnClair(1), M.PAR_NOTRE_COMPTE.sousBouton, consigne.phrase, consigne.credits, consigne.versement].join("\n");
        expect(tout).to.not.match(/compte de paiement|budget/i);
        expect(lexique.find((x) => x.startsWith("crédits d'écriture"))).to.equal("crédits d'écriture ce qui paie chaque écriture sur le registre public ; ce n'est pas de l'argent : notre société les fournit, ils ne s'achètent ni ne se vendent, et le client ne les paie pas");
        // Ce qui a échoué : d'après la vérification (OP-11 : reçu ; OP-12 : relecture) ; sans elle, la phrase générale.
        expect(M.explicationErreur("transaction_annulee", { verification: "OP-11" }).phrase).to.equal("Le registre public a reçu l'opération, mais elle n'a pas eu l'effet attendu.");
        expect(M.explicationErreur("transaction_annulee", { verification: "OP-12" }).phrase).to.equal("Le registre public a inscrit l'opération, mais le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.");
        expect(M.explicationErreur("transaction_annulee").phrase).to.equal("L'opération a été envoyée, mais le registre public l'a refusée, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.");
        expect(M.explicationErreur("recu_absent", { verification: "OP-11" }), "les autres codes ne changent pas").to.deep.equal(M.explicationErreur("recu_absent"));
        const echec = dossierFictif("client-en-echec", ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        expect(echec.steps[1].capture, "reçu refusé : pas de capture").to.equal(null);
        expect(M.etapesDuParcours(echec)[2].erreur.phrase).to.equal("Le registre public a reçu l'opération, mais elle n'a pas eu l'effet attendu.");
        const relu = structuredClone(echec);
        Object.assign(relu.steps[1], { capture: "capture-101-0-assignation.json", block_number: 101, block_hash: `0x${"cd".repeat(32)}` });
        expect(M.etapesDuParcours(relu)[2].erreur.phrase).to.equal("Le registre public a inscrit l'opération, mais le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.");
        expect(M.etapesDuParcours(relu)[2].erreur.code, "le code reste au détail, inchangé").to.equal("transaction_annulee");
        const reprise = M.prochaineAction({ slug: "client-en-echec", dossier: echec, confirmations: [{ id: "c", operation: "approvisionnement", objet: { cle_chaine: echec.recorders[0].chain_key }, consommee_par: null }] });
        expect(reprise.phrase).to.equal("Vous n'avez rien à corriger d'ici : l'outil vérifie d'abord ce qui est réellement inscrit sur le registre public, puis refait les étapes 3 à 5. Les étapes déjà faites ne sont pas refaites.");
        // « Vous n'avez rien à rassembler avant de cliquer » (cinquième lecture ; avant : « Rien à réunir »), jamais
        // « Rien à préparer » (qui contredisait « Préparez le document »).
        const prep = dossierFictif("client-prep", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
        const document = M.prochaineAction({ slug: "client-prep", dossier: prep });
        expect(document.titre).to.equal("Préparez le document d'inscription de l'enregistreur");
        expect(document.aPreparer).to.equal("Vous n'avez rien à rassembler avant de cliquer : l'enregistreur concerné est déjà choisi ci-dessous.");
        expect(fs.readFileSync(MODULE, "utf8")).to.not.contain("Rien à préparer");
      };
      verifier(P);
      let tues = 0;
      for (const [nom, ancien, nouveau] of [
        ["credits-compte-de-paiement", "c'est notre société qui les fournit, et le client ne les paie pas.", "c'est notre société qui les verse, depuis son compte de paiement."],
        ["cause-sans-verification", "e.capture ? \"OP-12\" : \"OP-11\"", "null"],
        ["rien-a-preparer", "aPreparer: `${RIEN_A_RASSEMBLER.slice(0, -1)} : l'enregistreur concerné", "aPreparer: `Rien à préparer : l'enregistreur concerné"],
      ]) {
        const m = await mutant(nom, ancien, nouveau);
        try { verifier(m); } catch { tues++; }
      }
      expect(tues, "trois mutants, trois tués").to.equal(3);
    });

    it("cinquième lecture des écrans : la confirmation porte sur le versement de l'étape 5, et la consigne dit pourquoi elle vient avant l'étape 2 ; le repère d'un montant de crédits est un minimum vrai, sans durée ; « Vous n'avez rien à rassembler avant de cliquer » ; l'autre cas de l'envoi est dit ; l'empreinte du paquet est expliquée là où la fiche en parle ; une saisie refusée l'est en entier (chaque zone de fiche fautive) ; mutants : tués", async function () {
      const neuf = dossierFictif("client-neuf", ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
      const echec5 = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "echec", "a_faire", "a_faire", "a_faire"]);
      const vue = (dossier, plus = {}) => ({ slug: dossier.organisation.slug, dossier, confirmations: [], demandes: [], periodes: [], parties: [], travaux: [], paquet: { present: false, dernier: null }, ...plus });
      const verifier = (M) => {
        // 1. Ce que la confirmation autorise, et l'ordre réel (CT-4 EX-7.26 ; admission du travail inscrire-client).
        let a = M.prochaineAction(vue(neuf));
        expect(a.code).to.equal("consigner_confirmation");
        expect(a.phrase).to.equal("L'étape 5 verse des crédits d'écriture sur le compte technique de l'enregistreur du client. Le client doit d'abord confirmer ce versement par un autre moyen que cet outil : un appel au numéro de son contrat, un courrier signé. L'outil fait les étapes 2 à 5 en une seule action : tant que cette confirmation n'est pas notée ici, il ne la commence pas, même pour les étapes qui ne versent rien.");
        a = M.prochaineAction(vue(echec5));
        expect(a.code).to.equal("consigner_confirmation");
        expect(a.phrase, "versement en échec : l'action repart de l'étape 5").to.match(/^L'étape 5 verse .* L'outil fait l'étape 5 en une seule action : /);
        a = M.prochaineAction(vue(neuf, { confirmations: [{ id: "c", operation: "approvisionnement", objet: { cle_chaine: neuf.recorders[0].chain_key }, consommee_par: null }] }));
        expect(a.phrase).to.equal("La confirmation du client est notée : elle porte sur le versement de l'étape 5. L'outil peut maintenant enregistrer les approbateurs, les rattacher au client, contrôler le résultat, puis alimenter le compte technique.");
        // 2. Repère : ce que consomment une preuve de date et une clôture (gaz de référence d'EX-4.19), et combien de ces
        // paires la consommation prévue paie au moins chaque jour (⌊b / 450 000⌋). Le montant d'un versement ne donne
        // aucun nombre : une part du solde (la limite de gaz d'un envoi, EX-4.18, que l'écran n'affiche pas) ne paie
        // aucune écriture ; avec les réglages par défaut, 327 000 000 crédits en paient 720 paires au moins, non 726.
        expect(M.repereEnClair("327000000", "10800000").replace(/\s/g, " ")).to.equal("Repère : d'ordinaire, une preuve de date consomme au plus 100 000 crédits et une clôture de période au plus 350 000. La consommation prévue, 10 800 000 crédits par jour, paie chaque jour au moins 24 preuves de date suivies chacune de leur clôture.");
        expect(M.repereEnClair("327000000").replace(/\s/g, " ")).to.equal("Repère : d'ordinaire, une preuve de date consomme au plus 100 000 crédits et une clôture de période au plus 350 000.");
        for (const m of ["450000", "327000000", "4719000000"]) expect(M.repereEnClair(m, "10800000"), "aucun nombre d'écritures tiré du montant").to.not.match(/paient|Ces [0-9 ]+ crédits/);
        for (const m of ["450000", "899999", "327000000", "157200000", "4719000000"]) {
          const n = M.paires(m);
          expect(n * 450000n <= BigInt(m) && (n + 1n) * 450000n > BigInt(m), m).to.equal(true);
        }
        expect(M.repereEnClair("449999")).to.equal(null);
        expect(M.repereEnClair("abc")).to.equal(null);
        expect(M.repereEnClair("327000000"), "aucune durée").to.not.match(/[0-9]+ ?jours?|semaines?|mois\b|environ/);
        // 3. Rien à rassembler ; l'autre cas de l'envoi ; l'empreinte du paquet expliquée.
        expect(M.RIEN_A_RASSEMBLER).to.equal("Vous n'avez rien à rassembler avant de cliquer.");
        expect(M.PAR_NOTRE_COMPTE.sousBouton).to.match(/L'autre cas, .* « Actions rarement utiles »\.$/);
        const fini = dossierFictif("client-fini", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]);
        a = M.prochaineAction(vue(fini, { periodes: ["p"], parties: ["x"], paquet: { present: true } }));
        expect(a.code).to.equal("remettre_paquet");
        // Complément du 2026-11-19 : l'outil sait si la remise est notée ; la consigne ne dit plus « si ce n'est pas déjà fait ».
        expect(a.phrase).to.equal("L'inscription est faite et le paquet est produit. Téléchargez le paquet et remettez-le au client, avec son empreinte : une suite de 66 caractères, donnée sur l'écran du paquet, qui permet au client de vérifier qu'il a reçu exactement ce paquet. Puis notez la remise sur ce même écran.");
        // 4. Un champ requis vide a sa phrase ; le nom court refusé renvoie d'abord au tirage.
        expect(M.CHAMP_VIDE).to.equal("Ce champ est vide. Remplissez-le en suivant l'aide écrite dessous.");
        expect(M.explicationSaisie("slug")).to.match(/^Le nom court n'a pas la bonne forme\. Servez-vous du bouton « Tirer un nom au hasard »/);
        for (const t of [M.CHAMP_VIDE, M.RIEN_A_RASSEMBLER, M.PAR_NOTRE_COMPTE.sousBouton, M.repereEnClair("327000000", "10800000"), M.explicationSaisie("slug")]) expect(motsTechniquesDans(t), t).to.deep.equal([]);
      };
      verifier(P);
      expect(fs.readFileSync(MODULE, "utf8")).to.not.contain("Rien à réunir");
      let tues = 0;
      for (const [nom, ancien, nouveau] of [
        ["repere-sans-ancre", "export const CREDITS_PAR_PAIRE = 450000n;", "export const CREDITS_PAR_PAIRE = 350000n;"],
        ["confirmation-sans-ordre", "L'outil fait ${jusqua} en une seule action : tant que cette confirmation n'est pas notée ici, il ne la commence pas, même pour les étapes qui ne versent rien.", "Sans cette confirmation notée ici, l'outil ne verse rien."],
        ["autre-cas-tu", " L'autre cas, l'envoi par un compte que désigne l'équipe technique, ne sert qu'à ses essais ; il est rangé dans « Actions rarement utiles ».", ""],
      ]) {
        const m = await mutant(nom, ancien, nouveau);
        try { verifier(m); } catch { tues++; }
      }
      expect(tues, "trois mutants du module, trois tués").to.equal(3);
      // 5. Les fiches d'enregistreur : chaque zone fautive est rendue, pas seulement la première.
      const CHAMPS = path.join(WEB, "composants", "champs-page.js");
      const C = await import(pathToFileURL(CHAMPS).href);
      const champ = { nom: "cles_enregistreur", type: "liste_documents" };
      const fiche = JSON.stringify({ ...neuf.recorders[0], created_at: "2026-11-10T09:00:00.000Z" });
      const lire = (Cx) => {
        const r = Cx.lireFiches(champ, ["", fiche, "[]", "{ illisible"]);
        expect(r.valeur).to.equal(undefined);
        expect(r).to.include({ zone: 0, regle: "fiche_vide" });
        expect(r.erreurs.map((x) => [x.zone, x.regle])).to.deep.equal([[0, "fiche_vide"], [2, "fiche_liste"], [3, "fiche_illisible"]]);
        expect(Cx.lireFiches(champ, [fiche]).valeur.length).to.equal(1);
      };
      lire(C);
      // Mutant : la lecture s'arrête de nouveau à la première zone fautive (copie du module, imports rendus absolus).
      const texte = fs.readFileSync(CHAMPS, "utf8").replace(/from "\.\.\/\.\.\/commun\//g, `from "${pathToFileURL(path.join(RACINE, "paquets", "inscription", "src", "commun")).href}/`);
      const ancien = 'if (texte === "") { refus("fiche_vide"); continue; }';
      expect(texte.split(ancien).length - 1).to.equal(1);
      const f = path.join(dir, "champs-page-premiere-seulement.mjs");
      fs.writeFileSync(f, texte.replace(ancien, () => 'if (texte === "") { refus("fiche_vide"); break; }'));
      let tue = false;
      try { lire(await import(pathToFileURL(f).href)); } catch { tue = true; }
      expect(tue, "mutant « première zone seulement » tué").to.equal(true);
    });
  });

  describe("suivi interne des clients (complément du 2026-11-19 ; src/commun/notes.mjs)", function () {
    it("décisions du 2026-11-19 : nom interne et remise du paquet ; formes exactes des corps de note, refus sans la valeur, nom en vigueur, remise corrigée sans effacement, consigne « paquet remis » ; mutants : tués", async function () {
      const N = await import(pathToFileURL(path.join(RACINE, "paquets", "inscription", "src", "commun", "notes.mjs")).href);
      const org = `0x${"ab".repeat(32)}`;
      const autre = `0x${"cd".repeat(32)}`;
      const manifeste = `0x${"12".repeat(32)}`;
      // Corps de la route : trois formes exactes, rien d'autre.
      expect(N.lireCorpsNote({ sorte: "nom_interne", nom: "Assurances du Léman" })).to.deep.equal({ sorte: "nom_interne", nom: "Assurances du Léman" });
      expect(N.lireCorpsNote({ sorte: "nom_interne", nom: null })).to.deep.equal({ sorte: "nom_interne", nom: null });
      expect(N.lireCorpsNote({ sorte: "remise_paquet", manifest_sha256: manifeste.toUpperCase().replace("0X", "0x") })).to.deep.equal({ sorte: "remise_paquet", manifest_sha256: manifeste });
      expect(N.lireCorpsNote({ sorte: "correction_remise", remise: `not-${"0".repeat(32)}`, motif: "cliqué par erreur" })).to.deep.equal({ sorte: "correction_remise", remise: `not-${"0".repeat(32)}`, motif: "cliqué par erreur" });
      expect(N.lireNote({ sorte: "nom_interne", org_id: org, nom: "Assurances du Léman" })).to.deep.equal({ sorte: "nom_interne", org_id: org, nom: "Assurances du Léman" });
      const secret = "f".repeat(64);
      const refus = [
        {}, { sorte: "autre" }, { sorte: "nom_interne" }, { sorte: "nom_interne", nom: "" }, { sorte: "nom_interne", nom: " espace" }, { sorte: "nom_interne", nom: "x".repeat(81) },
        { sorte: "nom_interne", nom: "a\nb" }, { sorte: "nom_interne", nom: secret }, { sorte: "nom_interne", nom: "x", org_id: org }, { sorte: "remise_paquet", manifest_sha256: "0x12" },
        { sorte: "remise_paquet", manifest_sha256: manifeste, nom: "x" }, { sorte: "correction_remise", remise: "trv-" + "0".repeat(32), motif: "x" }, { sorte: "correction_remise", remise: `not-${"0".repeat(32)}`, motif: " " },
      ];
      for (const r of refus) {
        let e = null;
        try { N.lireCorpsNote(r); } catch (x) { e = x; }
        expect(e?.code, JSON.stringify(r)).to.equal("requete_invalide");
        expect(e.message).to.not.contain(secret);
      }
      expect(() => N.lireNote({ sorte: "nom_interne", nom: "x" }), "note de l'agent sans organisation").to.throw(/org_id/);
      expect(N.lireCorpsNote({ sorte: "nom_interne", nom: "x".repeat(80) }).nom.length).to.equal(80);
      // Ce que le registre des notes dit d'un client.
      const l = (id, sorte, plus, quand = "2026-11-19T10:00:00.000Z", qui = "exploitant operateur-1") => ({ id: `not-${String(id).padStart(32, "0")}`, sorte, org_id: org, ...plus, exploitant: qui, recu_a: quand });
      const lignes = [
        l(1, "nom_interne", { nom: "Assurances du Léman" }),
        { ...l(2, "nom_interne", { nom: "Autre client" }), org_id: autre },
        l(3, "remise_paquet", { manifest_sha256: manifeste }, "2026-11-19T10:30:00.000Z"),
        l(4, "correction_remise", { remise: `not-${"0".repeat(31)}3`, motif: "cliqué par erreur" }, "2026-11-19T11:00:00.000Z", "exploitant operateur-2"),
        l(5, "correction_remise", { remise: `not-${"0".repeat(31)}3`, motif: "seconde correction, ignorée" }),
        l(6, "remise_paquet", { manifest_sha256: manifeste }, "2026-11-20T09:15:00.000Z"),
        l(7, "nom_interne", { nom: "Assurances du Léman SA" }, "2026-11-20T09:00:00.000Z"),
      ];
      const etat = (M) => {
        const e = M.etatNotes(lignes, org);
        expect(e.nom).to.include({ valeur: "Assurances du Léman SA", id: `not-${"0".repeat(31)}7` });
        expect(e.noms.map((x) => x.valeur), "historique des noms, celui d'un autre client exclu").to.deep.equal(["Assurances du Léman", "Assurances du Léman SA"]);
        expect(e.remises.map((r) => [r.id.slice(-1), r.correction ? r.correction.motif : null])).to.deep.equal([["3", "cliqué par erreur"], ["6", null]]);
        expect(e.remises[0].correction).to.include({ exploitant: "exploitant operateur-2", recu_a: "2026-11-19T11:00:00.000Z" });
        expect(M.remiseEnVigueur(e, manifeste)?.id).to.equal(`not-${"0".repeat(31)}6`);
        expect(M.remiseEnVigueur(M.etatNotes(lignes.slice(0, 4), org), manifeste), "remise corrigée : plus en vigueur").to.equal(null);
        expect(M.remiseEnVigueur(e, `0x${"99".repeat(32)}`), "autre paquet").to.equal(null);
        expect(M.etatNotes([...lignes, l(8, "nom_interne", { nom: null })], org).nom, "nom retiré").to.equal(null);
      };
      etat(N);
      // Consigne : remise en vigueur du paquet affiché → « Le paquet a été remis au client ».
      const fini = dossierFictif("client-fini", ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"]);
      const vue = { slug: "client-fini", dossier: fini, confirmations: [], demandes: [], periodes: [], parties: [], travaux: [travailFictif(1, { slug: "client-fini", commande: "paquet", recu_a: "2026-11-13T10:00:00.000Z", outputs: { manifest_sha256: manifeste } })], paquet: { present: true, dernier: null } };
      expect(P.manifesteDuPaquet(vue)).to.equal(manifeste);
      expect(P.manifesteDuPaquet({ ...vue, paquet: { present: false } })).to.equal(null);
      const remise = N.remiseEnVigueur(N.etatNotes(lignes, org), manifeste);
      const a = P.prochaineAction({ ...vue, remise });
      expect(a).to.include({ code: "paquet_remis", surTitre: "Inscription terminée", titre: "Le paquet a été remis au client", bouton: "Voir le paquet", lien: "/clients/client-fini/paquet" });
      expect(a.phrase).to.equal("Paquet remis le 20 novembre 2026 à 09:15 UTC par operateur-1. Vous n'avez plus rien à faire pour ce client.");
      expect(P.prochaineAction(vue).code, "sans remise").to.equal("remettre_paquet");
      expect(P.phraseRemise({ recu_a: "2026-11-19T10:30:00.000Z", exploitant: "exploitant operateur-1" })).to.equal("Paquet remis le 19 novembre 2026 à 10:30 UTC par operateur-1.");
      // Refus de l'agent en clair, sans mot de technicien ; le lexique dit ce qu'est le nom interne.
      for (const code of ["paquet_inconnu", "remise_deja_notee", "remise_inconnue"]) {
        const x = P.explicationErreur(code);
        expect(x.connu, code).to.equal(true);
        expect(x.effet).to.equal("Rien n'a été noté, et rien n'a été envoyé au registre public.");
        for (const t of [x.phrase, x.effet, x.quoiFaire]) expect(motsTechniquesDans(t), t).to.deep.equal([]);
      }
      const lex = P.LEXIQUE.find((x) => x.terme === "nom interne");
      expect(lex.explication).to.match(/seule notre équipe le voit : il ne part jamais vers le registre public ni dans le paquet du client$/);
      for (const t of [a.phrase, a.titre, a.apres, P.prochaineAction(vue).phrase, P.prochaineAction(vue).apres, lex.explication]) expect(motsTechniquesDans(t), t).to.deep.equal([]);
      // Mutants du module des notes (copie, imports rendus absolus) : la correction n'efface plus rien de visible / est ignorée ; le nom retiré reste.
      const NOTES = path.join(RACINE, "paquets", "inscription", "src", "commun", "notes.mjs");
      const texte = fs.readFileSync(NOTES, "utf8").replace(/from "\.\/champs\.mjs"/g, `from "${pathToFileURL(path.join(RACINE, "paquets", "inscription", "src", "commun", "champs.mjs")).href}"`);
      const mutants = [
        ["correction ignorée", "if (r) r.correction = { ...auteur, motif: l.motif };", "void r;"],
        ["correction qui efface la remise", "if (r) r.correction = { ...auteur, motif: l.motif };", "if (r) remises.splice(remises.indexOf(r), 1);"],
        ["nom retiré gardé", "return { nom: dernier && dernier.valeur !== null ? dernier : null, noms, remises };", "return { nom: noms.filter((x) => x.valeur !== null).pop() ?? null, noms, remises };"],
      ];
      for (const [nom, ancien, nouveau] of mutants) {
        expect(texte.split(ancien).length - 1, nom).to.equal(1);
        const f = path.join(dir, `notes-${nom.replace(/[^a-z]/g, "-")}.mjs`);
        fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
        let tue = false;
        try { etat(await import(pathToFileURL(f).href)); } catch { tue = true; }
        expect(tue, `mutant « ${nom} » tué`).to.equal(true);
      }
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
