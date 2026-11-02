// Tests de propriétés de la bibliothèque noyau : entrée TU-12 du plan de
// tests (CT-9). fast-check 4.10.2, graine constante écrite ci-dessous,
// 200 exécutions par propriété, générateur xorshift128plus, aucune limite de
// temps.
//
// Rejouer un échec : fast-check imprime le couple seed/path du contre-exemple ;
// le rejouer en passant { ...PARAMETRES, seed: <seed>, path: "<path>" } à
// l'appel fc.assert de la propriété concernée.

import { expect } from "chai";
import fc from "fast-check";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";

const GRAINE = 20261102;
const PARAMETRES = Object.freeze({ seed: GRAINE, numRuns: 200, randomType: "xorshift128plus" });

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const V = path.join(RACINE, "spec", "vecteurs", "ct-1");
const lire = (rel) => N.analyserJson(Uint8Array.from(fs.readFileSync(path.join(V, rel))));

// Clés et événements de test (vecteurs CT-1, clés publiques et jetables).
const CLES_TEST = lire("cles/cles-test.json");
const GRAINE_REC_01 = N.hexVersOctets(CLES_TEST.keys[0].seed, 32);
const CLES = lire("journal-valide/cles.json");
const MODELES = lire("journal-valide/evenements.json").filter((e) => e.recorder_key_id === "rec-test-01");

// Valeur JSON à entiers sûrs : null, booléens, entiers de l'intervalle sûr
// (et -0), chaînes de points de code quelconques (contrôles, U+2028, hors du
// plan multilingue de base), tableaux et objets imbriqués.
const { valeur: valeurJson } = fc.letrec((tie) => ({
  valeur: fc.oneof(
    { depthSize: "small", withCrossShrink: true },
    fc.constant(null),
    fc.boolean(),
    fc.maxSafeInteger(),
    fc.constant(-0),
    fc.string({ unit: "binary", maxLength: 12 }),
    fc.array(tie("valeur"), { maxLength: 5 }),
    fc.dictionary(fc.string({ unit: "binary", maxLength: 8 }), tie("valeur"), { maxKeys: 5 }),
  ),
}));
const objetJson = fc.dictionary(fc.string({ unit: "binary", maxLength: 8 }), valeurJson, { maxKeys: 8 });

// Événement scellé : un modèle de journal-valide dont l'intention et la
// délégation sont tirées au hasard, rescellé par rec-test-01.
const evenementScelle = fc
  .record({
    modele: fc.constantFrom(...MODELES),
    intention: fc.option(fc.string({ unit: "binary", maxLength: 64 }), { nil: null }),
    lancePar: fc.string({ unit: "binary", minLength: 1, maxLength: 32 }),
  })
  .map(({ modele, intention, lancePar }) => {
    const e = structuredClone(modele);
    if (typeof e.intent === "string") e.intent = intention ?? "";
    e.delegation.launched_by = lancePar;
    return N.scellerEvenement(e, GRAINE_REC_01);
  });

// Journal valide de 64 événements (appels d'outil autorisés), dont chaque
// préfixe est un journal valide.
const JOURNAL_64 = (() => {
  const modele = MODELES.find((e) => e.seq === 2);
  const depart = N.decoderHorodatage("2026-11-02T00:00:00.000Z");
  const evenements = [];
  let precedent = N.ZERO32;
  for (let s = 1; s <= 64; s++) {
    const e = N.scellerEvenement(
      { ...structuredClone(modele), seq: s, ts: N.ecrireHorodatage(depart + s * 1000), prev_hash: precedent },
      GRAINE_REC_01,
    );
    evenements.push(e);
    precedent = e.hash;
  }
  return evenements;
})();

const inverserBit = (hex, octet, bit) => {
  const o = N.hexVersOctets(hex);
  o[octet % o.length] ^= 1 << bit;
  return N.octetsVersHex(o);
};

describe("Noyau : propriétés (TU-12)", function () {
  it("Propriété 1 : pour tout objet JSON à entiers sûrs, jcs(parse(jcs(x))) = jcs(x)", function () {
    fc.assert(
      fc.property(objetJson, (x) => {
        const c = N.jcs(x);
        return N.jcs(N.analyserJson(c)) === c;
      }),
      { ...PARAMETRES },
    );
  });

  it("Propriété 2 : pour tout événement scellé et toute mutation d'un octet du corps, E-7 échoue ou la mutation est hors du corps", function () {
    // Nouvel octet : un caractère ASCII imprimable (le texte reste souvent
    // lisible) ou n'importe quel octet ; toujours différent de l'ancien.
    const nouvelOctet = fc.oneof(fc.integer({ min: 0x20, max: 0x7e }), fc.integer({ min: 0, max: 255 }));
    fc.assert(
      fc.property(evenementScelle, fc.nat(), nouvelOctet, (e, position, octet) => {
        expect(N.controlerEvenement(e, {}).controles["E-7"].statut).to.equal("reussi");
        // L'événement tel qu'il est stocké : son texte JSON en UTF-8.
        const octets = N.utf8(JSON.stringify(e));
        const k = position % octets.length;
        const mute = Uint8Array.from(octets);
        mute[k] = octet === mute[k] ? octet ^ 1 : octet;
        let lu;
        try {
          lu = N.analyserJson(mute);
        } catch (err) {
          // Texte devenu illisible : l'événement est refusé (E-1 ou E-2) avant
          // tout calcul de hash ; la mutation est détectée.
          if (!(err instanceof N.ErreurJson)) throw err;
          return true;
        }
        if (lu === null || typeof lu !== "object" || Array.isArray(lu)) return true;
        let corpsInchange;
        try {
          corpsInchange = N.formeCanoniqueEvenement(lu) === N.formeCanoniqueEvenement(e);
        } catch {
          corpsInchange = false;
        }
        const e7 = N.controlerEvenement(lu, {}).controles["E-7"].statut;
        // Hors du corps : la mutation a touché hash, sig, ou laissé le corps
        // E' inchangé (forme canonique identique).
        return corpsInchange || e7 === "echoue";
      }),
      { ...PARAMETRES },
    );
  });

  it("Propriété 3 : pour tout journal de n ≤ 64 événements et toute transposition, C-2 échoue", function () {
    expect(N.verifierJournal(JOURNAL_64, CLES).valide).to.equal(true);
    const transposition = fc
      .integer({ min: 2, max: 64 })
      .chain((n) => fc.tuple(fc.constant(n), fc.integer({ min: 0, max: n - 1 }), fc.integer({ min: 0, max: n - 1 })))
      .filter(([, i, j]) => i !== j);
    fc.assert(
      fc.property(transposition, ([n, i, j]) => {
        const journal = JOURNAL_64.slice(0, n);
        [journal[i], journal[j]] = [journal[j], journal[i]];
        const r = N.verifierJournal(journal, CLES);
        return r.valide === false && r.controles_en_echec.includes("C-2");
      }),
      { ...PARAMETRES },
    );
  });

  it("Propriété 4 : pour tout arbre de n ≤ 1024 feuilles et toute feuille, la preuve d'inclusion est acceptée et toute preuve altérée refusée ; pour tout m ≤ n ≤ 64, la preuve de cohérence est acceptée", function () {
    const feuilles = (n, sel) => Array.from({ length: n }, (_, i) => N.sha256Hex(N.utf8(`${sel}/${i}`)));
    const alterations = ["noeud", "feuille", "racine", "tronque", "allonge", "indice"];
    const inclusion = fc
      .record({ n: fc.integer({ min: 1, max: 1024 }), sel: fc.nat(), alteration: fc.constantFrom(...alterations), octet: fc.nat(), bit: fc.integer({ min: 0, max: 7 }), autre: fc.nat() })
      .chain((x) => fc.record({ m: fc.integer({ min: 0, max: x.n - 1 }) }).map(({ m }) => ({ ...x, m })));
    fc.assert(
      fc.property(inclusion, ({ n, sel, m, alteration, octet, bit, autre }) => {
        const D = feuilles(n, sel);
        const p = N.preuveInclusion(m, D);
        if (!N.verifierInclusion(p) || p.root !== N.racineMerkle(D)) return false;
        let altere;
        switch (alteration) {
          case "noeud":
            if (p.path.length === 0) return true;
            altere = { ...p, path: p.path.map((h, i) => (i === octet % p.path.length ? inverserBit(h, autre, bit) : h)) };
            break;
          case "feuille":
            altere = { ...p, leaf_hash: inverserBit(p.leaf_hash, octet, bit) };
            break;
          case "racine":
            altere = { ...p, root: inverserBit(p.root, octet, bit) };
            break;
          case "tronque":
            if (p.path.length === 0) return true;
            altere = { ...p, path: p.path.slice(0, -1) };
            break;
          case "allonge":
            altere = { ...p, path: [...p.path, N.sha256Hex(N.utf8(`noeud/${autre}`))] };
            break;
          default: {
            // indice : une autre feuille du même arbre (tree_size n'est pas
            // altéré : la taille est liée au manifeste par M-3, non par le chemin).
            if (n === 1) return true;
            altere = { ...p, leaf_index: (m + 1 + (autre % (n - 1))) % n };
          }
        }
        return N.verifierInclusion(altere) === false;
      }),
      { ...PARAMETRES },
    );
    const coherence = fc
      .integer({ min: 1, max: 64 })
      .chain((n) => fc.tuple(fc.constant(n), fc.integer({ min: 1, max: n }), fc.nat()));
    fc.assert(
      fc.property(coherence, ([n, m, sel]) => {
        const D = feuilles(n, sel);
        const preuve = {
          first_size: m,
          second_size: n,
          first_root: N.racineMerkle(D.slice(0, m)),
          second_root: N.racineMerkle(D),
          path: N.preuveCoherence(m, D),
        };
        return N.verifierCoherence(preuve).valide === true;
      }),
      { ...PARAMETRES },
    );
  });

  it("Propriété 5 : signature puis vérification Ed25519 sur des messages de 0 à 4096 octets", function () {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.uint8Array({ minLength: 0, maxLength: 4096 }), (graine, message) => {
        const publique = N.clePubliqueEd25519(graine);
        const sig = N.signerEd25519(graine, message);
        return sig.length === 64 && N.verifierEd25519(publique, message, sig) === true;
      }),
      { ...PARAMETRES },
    );
  });
});
