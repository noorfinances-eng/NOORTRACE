// Instance servie par l'agent (CT-4 §4.8, EX-7.1, EX-7.2) : le manifeste
// d'instance désigné par la configuration (`instance`), contrôlé par RG-16 à
// RG-20 (`verifierManifesteRepertoire` de `@noortrace/ancrage/registre`), ou,
// sans manifeste, les valeurs du réseau de développement d'EX-7.2, lues dans
// le répertoire de travail de l'agent (la racine du dépôt sur le poste du
// réseau de développement) : `deployments/noorcore.json`,
// `chain/config/alloc-dev.json`, `chain/runtime/validators.json`.

import fs from "node:fs";
import path from "node:path";
import { octetsVersHex, sha256Hex } from "@noortrace/noyau";
import * as R from "@noortrace/ancrage/registre";

/** Frais par défaut de CT-4 §4.8 (EX-7.2). */
export const FEES_DEFAUT = Object.freeze({ transaction_type: 2, max_fee_per_gas_wei: "1", max_priority_fee_per_gas_wei: "1", gas_limit: 3000000, gas_limit_max: 16777216, provision_days: 30, refill_below_days: 7 });

/** Identifiants du réseau de développement (EX-7.2). */
export const DEVELOPPEMENT = Object.freeze({ evmChainId: 2124, bftChainId: "noortrace-2124-dev" });

/** Erreur de chargement : `code` `instance_illisible`. */
export class ErreurInstance extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurInstance";
    this.code = "instance_illisible";
  }
}

const NOMS = { AttestationRegistry: "attestation_registry", CuratorSetRegistry: "curator_set_registry", PeriodRegistry: "period_registry", RecorderRegistry: "recorder_registry" };

/**
 * Charge l'instance. `chemin` : manifeste (`instance-registre-v0`) ou null ;
 * `racine` : répertoire des fichiers d'EX-7.2 (par défaut le répertoire de
 * travail). Rend `{ nature, evmChainId, bftChainId, manifeste, manifestSha256,
 * genesisSha256, contrats, deploiements, fees, jeux, validatorSetHash,
 * comptes (rôle → adresse à la tête), attestationDeploiement }`.
 */
export function chargerInstance(chemin, { racine = process.cwd() } = {}) {
  if (chemin) return depuisManifeste(chemin, racine);
  return developpement(racine);
}

function depuisManifeste(chemin, racine) {
  let octets;
  try {
    octets = fs.readFileSync(chemin);
  } catch {
    throw new ErreurInstance("manifeste d'instance illisible");
  }
  let manifeste;
  try {
    manifeste = JSON.parse(octets.toString("utf8"));
  } catch {
    throw new ErreurInstance("manifeste d'instance : JSON illisible");
  }
  const repertoire = path.dirname(chemin);
  const precedent = Number.isInteger(manifeste?.revision) && manifeste.revision > 1 ? `instance-r${manifeste.revision - 1}.json` : null;
  const v = R.verifierManifesteRepertoire({
    repertoire,
    fichiers: { manifest: path.basename(chemin), previous: precedent && fs.existsSync(path.join(repertoire, precedent)) ? precedent : null, genesis: manifeste?.genesis?.file ?? "" },
    racine,
  });
  if (v.refusal) throw new ErreurInstance(`manifeste d'instance refusé : ${v.refusal.check} ${v.refusal.code}`);
  const enService = R.contratsEnService(manifeste);
  const contrats = {};
  const deploiements = {};
  for (const [nom, c] of Object.entries(enService)) {
    contrats[NOMS[nom]] = c.address;
    deploiements[NOMS[nom]] = c;
  }
  const jeux = R.lireJeux(manifeste);
  const enVigueur = manifeste.validator_sets.find((s) => s.to_height === null) ?? manifeste.validator_sets[manifeste.validator_sets.length - 1];
  const comptes = {};
  for (const a of manifeste.accounts) if (a.to_height === null) comptes[a.role] = a.address;
  return {
    nature: manifeste.nature,
    evmChainId: manifeste.evm_chain_id,
    bftChainId: manifeste.bft_chain_id,
    manifeste,
    manifesteOctets: new Uint8Array(octets),
    manifestSha256: sha256Hex(octets),
    genesisSha256: manifeste.genesis.sha256,
    contrats,
    deploiements,
    fees: { ...FEES_DEFAUT, ...manifeste.fees },
    jeux: manifeste,
    jeuxLus: jeux,
    validatorSetHash: enVigueur.valset_hash,
    comptes,
    attestationDeploiement: deploiements.attestation_registry ?? null,
  };
}

function developpement(racine) {
  const lire = (relatif) => {
    try {
      return fs.readFileSync(path.join(racine, relatif));
    } catch {
      throw new ErreurInstance(`réseau de développement sans manifeste : ${relatif} illisible (EX-7.2)`);
    }
  };
  let deploiement;
  let validateurs;
  try {
    deploiement = JSON.parse(lire("deployments/noorcore.json").toString("utf8"));
    validateurs = JSON.parse(lire("chain/runtime/validators.json").toString("utf8"));
  } catch (e) {
    if (e instanceof ErreurInstance) throw e;
    throw new ErreurInstance("réseau de développement sans manifeste : fichier JSON illisible (EX-7.2)");
  }
  const genese = lire("chain/config/alloc-dev.json");
  const contrats = {};
  const deploiements = {};
  for (const [nom, cle] of Object.entries(NOMS)) {
    const c = deploiement?.contrats?.[nom];
    if (!c || typeof c.adresse !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(c.adresse)) throw new ErreurInstance(`deployments/noorcore.json : contrat ${nom} absent`);
    contrats[cle] = c.adresse.toLowerCase();
    deploiements[cle] = { name: nom, address: c.adresse.toLowerCase(), block_number: c.bloc ?? null, block_hash: null, transaction_hash: c.tx ?? null };
  }
  const jeuLu = R.lireJeu(validateurs);
  if (!jeuLu) throw new ErreurInstance("chain/runtime/validators.json : jeu de validateurs illisible");
  // Source du jeu d'EX-7.2, telle que l'outil de référence la nomme (énoncé du contrôle 8, EX-11.22).
  const source = "chain/runtime/validators.json du réseau de développement";
  const jeux = { validator_sets: [{ from_height: 1, to_height: null, validators: validateurs.validators, source }] };
  const deployeur = typeof deploiement.deployeur === "string" ? deploiement.deployeur.toLowerCase() : null;
  const comptes = deployeur ? { tresorerie: deployeur, deployeur, administrateur_registre: deployeur, relayeur: deployeur } : {};
  return {
    nature: "developpement",
    evmChainId: DEVELOPPEMENT.evmChainId,
    bftChainId: DEVELOPPEMENT.bftChainId,
    manifeste: null,
    manifesteOctets: null,
    manifestSha256: null,
    genesisSha256: sha256Hex(genese),
    contrats,
    deploiements,
    fees: { ...FEES_DEFAUT },
    jeux,
    jeuxLus: R.lireJeux(jeux),
    validatorSetHash: octetsVersHex(jeuLu.hash),
    comptes,
    attestationDeploiement: null,
  };
}
