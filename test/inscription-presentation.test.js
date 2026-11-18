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
        expect(l[2].erreur.phrase).to.equal("L'opération a été envoyée, mais le registre public l'a refusée, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.");
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
        expect(a.credits).to.equal("Les crédits d'écriture paient les écritures de l'enregistreur du client sur le registre public : chaque preuve de date, chaque clôture de période. Ils ne s'achètent pas et ne se vendent pas : c'est notre société qui les verse, depuis son compte de paiement.");
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
        expect(a.phrase).to.equal("L'outil vérifie d'abord ce qui est réellement inscrit sur le registre public, puis refait les étapes 3 à 5. Les étapes déjà faites ne sont pas refaites.");
        // Arrêt sur un refus préalable, sans échec : on continue à l'étape qui reste.
        const arrete = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(arrete, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "conduire_etapes", variante: "continuer", titre: "Continuez l'inscription à l'étape 5", bouton: "Continuer à l'étape 5" });
        // Envoi sans reçu : reprise de la transaction connue, jamais un nouvel envoi (EX-7.13, EX-7.16). Complément du
        // 2026-11-18 : la consigne est la capture de cet envoi (`capturer --envoi`), qui ne demande aucune confirmation.
        const envoye = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "envoyee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(envoye));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 5, parametre: "envoi", valeur: envoye.steps[3].transaction_hash, titre: "Reprenez l'envoi resté sans réponse à l'étape 5", bouton: "Reprendre cet envoi" });
        expect(a.phrase).to.equal("Une opération est partie vers le registre public, mais sa réponse n'est pas rangée dans le dossier. L'outil va chercher cette réponse et range la preuve de l'opération. Il ne renvoie jamais une opération déjà partie.");
        // Envoi sans réponse et confirmation non notée : la consigne est la reprise de l'envoi, et elle seule ; la
        // confirmation ne redevient la consigne qu'une fois l'envoi rangé.
        const parti = dossierFictif("client-neuf", ["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(parti));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 2, parametre: "envoi", valeur: parti.steps[0].transaction_hash });
        // L'attente a sa durée ordinaire, celle que règle le service d'inscription (120 secondes par défaut), et une
        // conduite sans chiffre inventé : si la fiche ne change pas, prévenir, sans relancer.
        expect(a.apres).to.equal("Après le clic : l'outil va chercher la réponse du registre public et l'attend, quelques minutes d'ordinaire. S'il l'obtient, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Sinon, la fiche ne change pas : prévenez alors l'équipe technique, sans rien lancer d'autre. Rien n'est renvoyé, rien n'est dépensé.");
        expect(a.cles, "aucune confirmation demandée tant que l'envoi n'est pas repris").to.equal(undefined);
        expect(M.prochaineAction(vue(dossierFictif("client-neuf", ["capturee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]))).code, "l'envoi rangé, la confirmation redevient la consigne").to.equal("consigner_confirmation");
        // Opération inscrite dont la preuve manque : même consigne, par la transaction (`capturer --transaction`).
        const inscriteSansPreuve = dossierFictif("client-neuf", ["capturee", "incluse", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(inscriteSansPreuve, { confirmations: [conf(null)] }));
        expect(a).to.include({ code: "reprendre_envoi", commande: "capturer", etape: 3, parametre: "transaction", valeur: inscriteSansPreuve.steps[1].transaction_hash });
        expect(a.apres).to.equal("Après le clic : l'outil range la preuve, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Si la fiche ne change pas, prévenez l'équipe technique, sans rien lancer d'autre. Rien n'est renvoyé, rien n'est dépensé.");
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
          const depuis = `depuis le 12 novembre 2026 à 08:0${n - 2} UTC`;
          expect(a.phrase).to.equal(`Cette étape se fait chez le client, avec ses propres outils : vous n'avez rien à lancer d'ici. ${envoyee ? `Elle est notée « Envoyée » ${depuis} et attend la réponse du registre public` : `Le registre public l'a inscrite ${depuis}, mais sa preuve n'est pas encore rangée dans le dossier`}. Le client a fait sa part : si la fiche n'a pas changé à votre prochaine visite, prévenez l'équipe technique.`);
          expect(a.apres).to.equal("Le bouton relit seulement la fiche : rien n'est envoyé, rien n'est dépensé. Cet outil ne sait pas combien de temps le registre public mettra à répondre.");
          neutres.push(vue(chezLeClient));
        }
        // Étapes 2 à 5 faites : demande à préparer, puis à faire signer hors de l'application et à relayer.
        const cours = dossierFictif("client-neuf", ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"]);
        a = M.prochaineAction(vue(cours));
        expect(a).to.include({ code: "preparer_demande", commande: "condense-inscription", keyId: cours.recorders[0].key_id, titre: "Préparez le document d'inscription de l'enregistreur" });
        a = M.prochaineAction(vue(cours, { demandes: [{ nom: `demande-inscription-${cours.recorders[0].key_id}-trv-1.json`, document: { signatures: [] } }] }));
        expect(a).to.include({ code: "relayer_demande", commande: "inscrire-cle", titre: "Faites signer le document par les approbateurs du client, puis envoyez-le", bouton: "Envoyer le document signé" });
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
          expect(x.aPreparer, x.code).to.match(/^(Ayez sous la main : .+|Rien à préparer.*)\.$/);
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
