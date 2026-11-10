// Manifeste d'instance (CT-4 §4.8, §6.8, RG-16 à RG-20) : forme et révisions
// (RG-16), genèse et identifiants (RG-17), jeux de validateurs (RG-18),
// contrats et preuves de déploiement (RG-19), ancre `registry` du réviseur
// dérivée du manifeste (RG-20, CT-6 §12.2). Le composant d'ancrage lit le
// manifeste pour connaître l'instance (identifiants, contrats en service,
// frais, jeux par hauteur pour CP-4) ; ce module le contrôle avant usage et
// rejoue la famille `manifestes` des vecteurs de CT-4.
//
// Chaque vérification rend `reussi` ou `echoue` avec le premier motif de la
// table de CT-4 §6.9, dans l'ordre où la règle les énonce ; un manifeste
// hors de son schéma rend RG-16 `echoue` (`schema`) et RG-17 à RG-20
// `echoue` avec lui, sans ancre dérivée (EX-6.19).

import fs from "node:fs";
import { sha256Hex } from "@noortrace/noyau";
import { lireJeu, lireJeux } from "./certificat.mjs";
import { verifierCapture } from "./capture.mjs";
import { adresseCreation, lireTransaction } from "./transaction.mjs";
import { estHexOctets, octetsVersHex, utf8Texte } from "./octets.mjs";
import { NOMS_CONTRATS, verifierIndexCapture, verifierManifesteSchema } from "./schemas.mjs";

const REGLES_ATTENDUES = Object.freeze({
  possEnabled: false, possRewards: "0x0000000000000000000000000000000000000000", possCapWei: "0",
  possGenesisUnix: 0, possHalvingSec: 0, possSubperiodSec: 0, possEmissionModel: "noormint/v1",
});

/** Ligne de règles canonique d'un document de genèse (CT-4 EX-4.3). */
export function ligneRegles(genese) {
  const r = genese.rules;
  return `chainId=${r.chainId} evmChainId=${genese.chainId} possEnabled=${r.possEnabled} possRewards=${r.possRewards} possCapWei=${r.possCapWei} possGenesisUnix=${r.possGenesisUnix} possHalvingSec=${r.possHalvingSec} possSubperiodSec=${r.possSubperiodSec} possEmissionModel=${r.possEmissionModel}`;
}

/** Forme d'un document de genèse (CT-4 §4.2) : `genese_invalide` ou null. */
function defautGenese(genese) {
  if (!genese || typeof genese !== "object" || Array.isArray(genese)) return "genese_invalide";
  if (!Number.isSafeInteger(genese.chainId) || genese.chainId < 1) return "genese_invalide";
  if (!Array.isArray(genese.alloc) || genese.alloc.length === 0) return "genese_invalide";
  const adresses = new Set();
  for (const a of genese.alloc) {
    if (!a || typeof a !== "object" || typeof a.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(a.address)) return "genese_invalide";
    if (typeof a.balanceWei !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(a.balanceWei)) return "genese_invalide";
    const min = a.address.toLowerCase();
    if (adresses.has(min)) return "genese_invalide";
    adresses.add(min);
  }
  return null;
}

/** Section `rules` exacte d'EX-4.2 : `regles_invalides` ou null. */
function defautRegles(genese) {
  const r = genese.rules;
  if (!r || typeof r !== "object" || Array.isArray(r)) return "regles_invalides";
  if (typeof r.chainId !== "string" || r.chainId.length === 0) return "regles_invalides";
  for (const [k, v] of Object.entries(REGLES_ATTENDUES)) if (r[k] !== v) return "regles_invalides";
  const cles = Object.keys(r).sort();
  if (cles.join(",") !== ["chainId", ...Object.keys(REGLES_ATTENDUES)].sort().join(",")) return "regles_invalides";
  return null;
}

/** RG-17 : genèse et identifiants. `geneseOctets` : octets du document publié. */
export function verifierGenese(manifeste, geneseOctets) {
  const echec = (motif) => ({ statut: "echoue", motif });
  if (!(geneseOctets instanceof Uint8Array)) return echec("genese_differente");
  if (sha256Hex(geneseOctets) !== manifeste.genesis.sha256) return echec("genese_differente");
  const texte = utf8Texte(geneseOctets);
  let genese;
  try {
    genese = texte === null ? null : JSON.parse(texte);
  } catch {
    genese = null;
  }
  const d1 = defautGenese(genese);
  if (d1) return echec(d1);
  const d2 = defautRegles(genese);
  if (d2) return echec(d2);
  if (ligneRegles(genese) !== manifeste.genesis.rules_line) return echec("ligne_regles_differente");
  const m = /^noortrace-([1-9][0-9]{0,9})-[a-z0-9]{1,16}$/.exec(manifeste.bft_chain_id);
  if (genese.rules.chainId !== manifeste.bft_chain_id || genese.chainId !== manifeste.evm_chain_id || !m || Number(m[1]) !== manifeste.evm_chain_id) return echec("identifiants_incoherents");
  const total = genese.alloc.reduce((s, a) => s + BigInt(a.balanceWei), 0n);
  if (total.toString() !== manifeste.genesis.alloc_total_wei) return echec("offre_differente");
  return { statut: "reussi", motif: null, genese };
}

/** RG-18 : jeux de validateurs (EX-6.21). */
export function verifierJeuxValidateurs(manifeste) {
  const echec = (motif) => ({ statut: "echoue", motif });
  const jeux = manifeste.validator_sets;
  const f = (N) => Math.floor((N - 1) / 3);
  for (const j of jeux) {
    if (!Array.isArray(j.validators) || j.validators.length < 4) return echec("jeu_invalide");
    const lu = lireJeu(j.validators);
    if (!lu) return echec("jeu_invalide");
    const cles = new Set(lu.validateurs.map((v) => octetsVersHex(v.declaree)));
    if (cles.size !== lu.validateurs.length) return echec("jeu_invalide");
    if (octetsVersHex(lu.hash) !== j.valset_hash) return echec("valset_hash_different");
    const ids = lu.validateurs.map((v) => v.id);
    const nommes = j.operators.map((o) => o.validator);
    if (nommes.length !== ids.length || new Set(nommes).size !== nommes.length || !nommes.every((n) => ids.includes(n))) return echec("operateurs_incoherents");
  }
  const tries = jeux.map((j) => ({ de: j.from_height, a: j.to_height })).sort((x, y) => x.de - y.de);
  if (tries[0].de !== 1) return echec("intervalles_incoherents");
  for (let k = 0; k < tries.length; k++) {
    const t = tries[k];
    if (t.a !== null && t.a < t.de) return echec("intervalles_incoherents");
    if (k > 0) {
      const p = tries[k - 1];
      if (p.a === null || p.a >= t.de) return echec("intervalles_incoherents");
    }
  }
  if (manifeste.nature === "production") {
    for (const j of jeux) {
      const N = j.validators.length;
      const parOperateur = new Map();
      const parSite = new Map();
      for (const o of j.operators) {
        parOperateur.set(o.operator, (parOperateur.get(o.operator) ?? 0) + 1);
        parSite.set(o.site, (parSite.get(o.site) ?? 0) + 1);
      }
      if ([...parOperateur.values(), ...parSite.values()].some((n) => n > f(N))) return echec("domaine_de_panne");
    }
  }
  return { statut: "reussi", motif: null };
}

/** Contrats en service (`to_height` nul) : exactement un par nom ; rend la table nom → contrat, ou null. */
export function contratsEnService(manifeste) {
  const table = {};
  for (const nom of NOMS_CONTRATS) {
    const liste = manifeste.contracts.filter((c) => c.name === nom && c.to_height === null);
    if (liste.length !== 1) return null;
    table[nom] = liste[0];
  }
  return table;
}

/** Administrateur du registre déclaré à une hauteur (`accounts`), ou null. */
function administrateurA(manifeste, hauteur) {
  const c = manifeste.accounts.find((a) => a.role === "administrateur_registre" && a.from_height <= hauteur && (a.to_height === null || hauteur <= a.to_height));
  return c ? c.address : null;
}

/**
 * RG-19 : contrats (EX-6.22). `lecteur` lit les fichiers désignés par
 * `evidence.capture.file` (chemins relatifs au répertoire du manifeste).
 */
export function verifierContrats(manifeste, lecteur) {
  const echec = (motif, detail = "") => ({ statut: "echoue", motif, detail });
  const service = contratsEnService(manifeste);
  if (!service) return echec("contrats_en_service");
  for (const c of manifeste.contracts) {
    if (adresseCreation(c.deployer, c.nonce) !== c.address) return echec("adresse_creation", c.name);
  }
  const registre = service.CuratorSetRegistry.address;
  for (const c of manifeste.contracts) {
    const args = c.constructor_args;
    let attendu;
    if (c.name === "AttestationRegistry") attendu = [];
    else if (c.name === "CuratorSetRegistry") {
      const admin = administrateurA(manifeste, c.block_number);
      attendu = admin ? [admin] : null;
      if (attendu === null && args.length === 1 && estHexOctets(args[0], 20)) attendu = [args[0]];
    } else attendu = [registre];
    if (!attendu || JSON.stringify(args) !== JSON.stringify(attendu)) return echec("arguments_constructeur", c.name);
  }
  const jeux = lireJeux(manifeste);
  for (const c of manifeste.contracts) {
    if (c.evidence === null) {
      // EX-4.28 : en production, block_hash et evidence ne sont jamais nuls.
      if (manifeste.nature === "production") return echec("preuve_absente", c.name);
      continue;
    }
    const octets = lecteur.lire(c.evidence.capture.file);
    if (!octets) return echec("preuve_absente", c.name);
    if (sha256Hex(octets) !== c.evidence.capture.sha256) return echec("preuve_invalide", `${c.name} : SHA-256 de l'index`);
    const texte = utf8Texte(octets);
    let index;
    try {
      index = texte === null ? null : JSON.parse(texte);
    } catch {
      index = null;
    }
    if (!index || !verifierIndexCapture(index).valide) return echec("preuve_invalide", `${c.name} : index hors schéma`);
    if (index.role !== "deploiement" || index.contract !== c.address || index.transaction_hash !== c.transaction_hash || index.block_number !== c.block_number || (c.block_hash !== null && index.block_hash !== c.block_hash)) {
      return echec("preuve_invalide", `${c.name} : index d'une autre transaction ou d'un autre rôle`);
    }
    const repertoire = c.evidence.capture.file.includes("/") ? c.evidence.capture.file.slice(0, c.evidence.capture.file.lastIndexOf("/")) : "";
    const sousLecteur = { lire: (nom) => lecteur.lire(repertoire ? `${repertoire}/${nom}` : nom) };
    const v = verifierCapture({ fichiers: sousLecteur, index, jeux: jeux ?? [], bftChainId: manifeste.bft_chain_id });
    if (v.premierEchec) return echec("preuve_invalide", `${c.name} : ${v.premierEchec.check}`);
    const recu = v.recus[index.transaction_index];
    if (!recu || recu.status !== "0x1") return echec("preuve_invalide", `${c.name} : reçu de déploiement sans status 0x1`);
    const tx = v.certificat?.txsRaw?.[index.transaction_index];
    let lue;
    try {
      lue = tx ? lireTransaction(tx) : null;
    } catch {
      lue = null;
    }
    if (!lue || lue.to !== null || lue.from !== c.deployer || lue.nonce !== BigInt(c.nonce)) return echec("preuve_invalide", `${c.name} : transaction de déploiement`);
  }
  return { statut: "reussi", motif: null, detail: "" };
}

/** RG-20 : ancre `registry` dérivée du manifeste (EX-6.23), ou null si un nom n'a pas exactement un contrat en service. */
export function ancreReviseur(manifeste, { source = null } = {}) {
  const service = contratsEnService(manifeste);
  if (!service) return null;
  return {
    chain_id: manifeste.bft_chain_id,
    contracts: {
      period_registry: service.PeriodRegistry.address,
      attestation_registry: service.AttestationRegistry.address,
      recorder_registry: service.RecorderRegistry.address,
    },
    validator_sets: manifeste.validator_sets.map((j) => ({ from_height: j.from_height, to_height: j.to_height, validators: j.validators, source: j.source })),
    source: source ?? `dérivée du manifeste d'instance ${manifeste.bft_chain_id}, révision ${manifeste.revision} (RG-20)`,
  };
}

function sansSources(ancre) {
  return { chain_id: ancre.chain_id, contracts: ancre.contracts, validator_sets: ancre.validator_sets.map((j) => ({ from_height: j.from_height, to_height: j.to_height, validators: j.validators })) };
}

/**
 * RG-16 à RG-20 sur un manifeste. `manifesteOctets` : octets du fichier du
 * manifeste ; `precedentOctets` : octets de la révision précédente (ou
 * null) ; `geneseOctets` : octets du document de genèse ; `lecteur` : lit les
 * fichiers de preuve ; `ancre` : ancre `registry` fournie à comparer (RG-20).
 * Rend `{ verdicts, refusal, registry, manifeste }`.
 */
export function verifierManifeste({ manifesteOctets, precedentOctets = null, geneseOctets, lecteur, ancre = null }) {
  const verdicts = { "RG-16": "echoue", "RG-17": "echoue", "RG-18": "echoue", "RG-19": "echoue", "RG-20": "echoue" };
  const refus = [];
  const echec = (check, code) => { verdicts[check] = "echoue"; refus.push({ check, code }); };
  const texte = manifesteOctets instanceof Uint8Array ? utf8Texte(manifesteOctets) : null;
  let manifeste;
  try {
    manifeste = texte === null ? null : JSON.parse(texte);
  } catch {
    manifeste = null;
  }
  if (!manifeste || !verifierManifesteSchema(manifeste).valide) {
    echec("RG-16", "schema");
    return { verdicts, refusal: refus[0], registry: null, manifeste: null };
  }
  // RG-16 : révisions.
  if (manifeste.revision === 1) {
    if (manifeste.previous_sha256 !== null) echec("RG-16", "revision_mal_chainee");
    else verdicts["RG-16"] = "reussi";
  } else {
    let precedent = null;
    try {
      precedent = precedentOctets ? JSON.parse(utf8Texte(precedentOctets) ?? "") : null;
    } catch {
      precedent = null;
    }
    const ok = precedent && precedentOctets && manifeste.previous_sha256 === sha256Hex(precedentOctets) && manifeste.revision === precedent.revision + 1
      && Date.parse(manifeste.published_at) >= Date.parse(precedent.published_at);
    if (ok) verdicts["RG-16"] = "reussi";
    else echec("RG-16", "revision_mal_chainee");
  }
  // RG-17.
  const g = verifierGenese(manifeste, geneseOctets);
  if (g.statut === "reussi") verdicts["RG-17"] = "reussi";
  else echec("RG-17", g.motif);
  // RG-18.
  const j = verifierJeuxValidateurs(manifeste);
  if (j.statut === "reussi") verdicts["RG-18"] = "reussi";
  else echec("RG-18", j.motif);
  // RG-19.
  const c = verifierContrats(manifeste, lecteur);
  if (c.statut === "reussi") verdicts["RG-19"] = "reussi";
  else echec("RG-19", c.motif);
  // RG-20.
  const derivee = ancreReviseur(manifeste);
  if (!derivee) {
    echec("RG-20", "derivation_impossible");
    return { verdicts, refusal: refus[0] ?? null, registry: null, manifeste };
  }
  if (ancre && JSON.stringify(sansSources(ancre)) !== JSON.stringify(sansSources(derivee))) {
    echec("RG-20", "ancre_differente");
    return { verdicts, refusal: refus[0] ?? null, registry: null, manifeste };
  }
  verdicts["RG-20"] = "reussi";
  return { verdicts, refusal: refus[0] ?? null, registry: derivee, manifeste };
}

/**
 * Lit un manifeste et ses fichiers depuis un répertoire (chemins relatifs du
 * manifeste) et applique RG-16 à RG-20 ; `fichiers` : `{ manifest, previous,
 * genesis }` (noms relatifs au répertoire ; `genesis` peut être un chemin
 * relatif à la racine du dépôt quand il commence par `chain/`, résolu par
 * `racine`).
 */
export function verifierManifesteRepertoire({ repertoire, fichiers, racine = null, ancre = null }) {
  const lecteurBrut = {
    lire(nom) {
      if (typeof nom !== "string" || nom.includes("..") || nom.startsWith("/")) return null;
      const base = nom.startsWith("chain/") && racine ? racine : repertoire;
      try {
        return new Uint8Array(lireFichierBrut(`${base}/${nom}`));
      } catch {
        return null;
      }
    },
  };
  const manifesteOctets = lecteurBrut.lire(fichiers.manifest);
  const precedentOctets = fichiers.previous ? lecteurBrut.lire(fichiers.previous) : null;
  const geneseOctets = lecteurBrut.lire(fichiers.genesis);
  return verifierManifeste({ manifesteOctets, precedentOctets, geneseOctets, lecteur: lecteurBrut, ancre });
}

function lireFichierBrut(chemin) {
  const st = fs.lstatSync(chemin);
  if (!st.isFile() || st.size > 16 * 1024 * 1024) throw new Error("fichier non ordinaire ou trop grand");
  return fs.readFileSync(chemin);
}
