// Exécution, sous Node, de travailleur.js de la page de vérification tel
// qu'il est construit (prélude, wasm_exec.js, pilote), dans un contexte `vm`
// qui n'offre que ce qu'offre un travailleur dédié du navigateur et dont le
// pilote a besoin : self, postMessage, addEventListener, crypto,
// performance, TextEncoder, TextDecoder, setTimeout, clearTimeout, console.
// Ni require, ni process, ni fs, ni path : le prélude doit les fournir.
//
// Les messages sont recopiés dans le domaine du contexte, comme le clonage
// structuré d'un navigateur ; les ArrayBuffer transférés y sont recopiés.

import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { performance } from "node:perf_hooks";

/**
 * Charge le texte de travailleur.js et rend { envoyer(message), fermer() } ;
 * envoyer rend une promesse du message suivant du travailleur.
 */
export function chargerTravailleur(texte, { nom = "travailleur.js" } = {}) {
  const ecouteurs = { message: [], error: [], unhandledrejection: [] };
  const recus = [];
  const attentes = [];
  const contexte = {
    crypto: webcrypto,
    performance,
    TextEncoder,
    TextDecoder,
    // Un rappel de minuterie qui lève est rendu aux écouteurs « error ».
    setTimeout: (f, ms, ...args) => setTimeout(() => {
      try {
        f(...args);
      } catch (e) {
        surErreur(e);
      }
    }, ms),
    clearTimeout,
    console,
  };
  contexte.self = contexte;
  contexte.addEventListener = (type, f) => {
    if (!ecouteurs[type]) throw new Error(`événement non simulé : ${type}`);
    ecouteurs[type].push(f);
  };
  contexte.postMessage = (message) => {
    // Recopie vers le domaine de Node (clonage structuré de Node).
    const copie = structuredClone(message);
    const a = attentes.shift();
    if (a) a(copie);
    else recus.push(copie);
  };
  vm.createContext(contexte, { name: "travailleur", codeGeneration: { strings: false, wasm: true } });
  // Clonage structuré dans le domaine du contexte : objets, tableaux, chaînes,
  // nombres, booléens, null, ArrayBuffer et Uint8Array.
  const clonerDans = vm.runInContext(`(function cloner(v) {
    if (v === null || typeof v !== "object") return v;
    const t = Object.prototype.toString.call(v);
    if (t === "[object ArrayBuffer]") { const c = new ArrayBuffer(v.byteLength); new Uint8Array(c).set(new Uint8Array(v)); return c; }
    if (t === "[object Uint8Array]") { const c = new Uint8Array(v.length); c.set(v); return c; }
    if (Array.isArray(v)) return v.map(cloner);
    const o = {};
    for (const k of Object.keys(v)) o[k] = cloner(v[k]);
    return o;
  })`, contexte);
  // Les erreurs non rattrapées des rappels du moteur sont rendues aux écouteurs
  // « error » du travailleur, comme dans un navigateur.
  vm.runInContext(texte, contexte, { filename: nom });
  function surErreur(e) {
    const ev = { error: e, message: String(e?.message ?? e), defaut: false, preventDefault() { this.defaut = true; } };
    for (const f of ecouteurs.error) f(ev);
    if (!ev.defaut) throw e;
  }
  return {
    envoyer(message) {
      const copie = clonerDans(message);
      for (const f of ecouteurs.message) {
        try {
          f({ data: copie });
        } catch (e) {
          surErreur(e);
        }
      }
      return this.suivant();
    },
    suivant() {
      if (recus.length > 0) return Promise.resolve(recus.shift());
      return new Promise((r) => attentes.push(r));
    },
    contexte,
  };
}
