// Configuration (CT-2 §15) : un seul document JSON, validé au démarrage
// contre `configuration-enregistreur-v0` (EX-15.1), dans l'ordre d'EX-15.4 :
// (1) JSON strict, (2) schéma (toutes les erreurs), (3) règles que le schéma
// n'exprime pas, (4) références de secrets. À la première étape en erreur, le
// démon s'arrête avec un rapport sur stderr (une ligne par erreur : pointeur
// JSON, règle, valeur fautive sauf pour les secrets) et le code de retour 2.
//
// Pas 3 : ce lot vérifie les règles qui touchent le cœur et celles qui se
// lisent sur le document seul (signataire, cadence, bail, rétention et WORM,
// alias, gabarits d'effets, mode observation, approbateurs de test, chemins
// des routes, jetons statiques). Les vérifications propres aux lots suivants
// (motifs de rédaction d'EX-10.6 et EX-10.23, politique d'approbation de CT-3
// EX-4.2 et EX-8.2, collisions de noms annoncés d'EX-4.11) leur reviennent ;
// INTERFACES.md dit où elles s'insèrent (`reglesSupplementaires`).

import os from "node:os";
import { ErreurJson, egaliteJson } from "@noortrace/noyau";
import { analyserJsonIntegral } from "./jcs-integral.mjs";
import { IDS, registreSchemas } from "./schema.mjs";
import { BACKENDS_PAR_CLASSE } from "./signataires.mjs";
import { cadenceAdmise } from "./points.mjs";
import { estPointeur } from "./effets.mjs";
import { resoudreSecret, ErreurSecret } from "./secrets.mjs";

/**
 * Adresses des clés de test publiées (copie de la liste des adresses de
 * `spec/vecteurs/ct-7/cles-de-test.json`, comptes Hardhat publics ; un test la
 * compare au fichier) : un jeu statique qui en contient une est une erreur en
 * production et un avertissement ailleurs (EX-15.8, `approbateurs_de_test`).
 */
export const ADRESSES_DE_TEST = Object.freeze([
  "0x14dc79964da2c08b23698b3d3cc7ca32193d9955", "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
  "0x19d8bddeed23cb80dca47e16b74dd29bc020c138", "0x23618e81e3f5cdf7f54c3d65f7fbc0abf5b21e8f",
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x3fe8b04d740f4830417565e9d6c0903620d36cbb",
  "0x436b0cee00aef664dd71949195231b609dbe1314", "0x510d7d0f5afbd9129abb1a899aff5f9246dd9c49",
  "0x51a74df21f83ca01def00b5defaae3ce87d8dd83", "0x526b68c91c74f6faa53d03d990fd97a79922d202",
  "0x5747a77dda82031f8dd96a06a75c52a672a0a4c3", "0x6058c0c9cdbf4e959aa25e45a68ddc1132d85c88",
  "0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x71a272a1cf45cea193b923450a7af09a9f1586a5",
  "0x90f79bf6eb2c4f870365e785982e1f101e93b906", "0x976ea74026e726554db657fa54763abd0c3a0aa9",
  "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc", "0x9a6c8146a5ab723fcfdba8a4523605ae5f8addbb",
  "0xa0ee7a142d267c1f36714e4a8f75612f20a79720", "0xa95a82cc265f0d72f40cb040dfd644e74873d383",
  "0xaa2a59656361352e96ef2eed355316ef8b29dab7", "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
  "0xdd2db1636768f86c546563f0368c5c8d5c777990", "0xe2bdcef6264103ab6c88fa3c1b5a2ceacd995b22",
  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "0xfa405776d8b12ba0de9ab211d1712bdca00291bb",
]);

/** Texte fixe de l'avertissement du mode observation (EX-15.8). */
export const AVERTISSEMENT_OBSERVATION =
  "mode observation : aucun appel ne sera bloque ni soumis a approbation ; une ecriture peut n'avoir qu'un evenement en attente, ou aucun au-dela des bornes de 14.5";

/** Valeurs par défaut des membres facultatifs. */
export const DEFAUTS = Object.freeze({ checkpoint_interval_s: 60 });

/** Répertoire des exports quand `exports_dir` est absent (EX-15.12, révision 0.8). */
export const REPERTOIRE_EXPORTS_DEFAUT = "/var/lib/noortrace-exports";

/**
 * Vrai si les deux chemins absolus sont égaux ou si l'un contient l'autre,
 * comparés composant par composant (EX-15.4 pas 3, EX-15.12).
 * @param {string} a
 * @param {string} b
 */
export function cheminsEmboites(a, b) {
  const ca = a.split("/").filter((x) => x !== "");
  const cb = b.split("/").filter((x) => x !== "");
  const n = Math.min(ca.length, cb.length);
  for (let i = 0; i < n; i++) if (ca[i] !== cb[i]) return false;
  return true;
}

function estObjet(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Parcourt les références de secrets d'un document (objets à une clé `env`,
 * `file` ou `vault`, plus `encoding`).
 * @param {unknown} v
 * @param {string} pointeur
 * @param {(ref: object, pointeur: string) => void} f
 */
export function parcourirSecrets(v, pointeur, f) {
  if (Array.isArray(v)) {
    v.forEach((x, k) => parcourirSecrets(x, `${pointeur}/${k}`, f));
    return;
  }
  if (!estObjet(v)) return;
  const cles = Object.keys(v);
  const emplacement = cles.filter((c) => c === "env" || c === "file" || c === "vault");
  if (emplacement.length === 1 && cles.every((c) => c === emplacement[0] || c === "encoding") && (typeof v[emplacement[0]] === "string" || estObjet(v.vault))) {
    f(v, pointeur);
    return;
  }
  for (const c of cles) parcourirSecrets(v[c], `${pointeur}/${c.replace(/~/g, "~0").replace(/\//g, "~1")}`, f);
}

/**
 * Pas 3 d'EX-15.4 : règles que le schéma n'exprime pas (part du cœur).
 * @param {object} c document validé contre le schéma
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
/** Utilisateur système qui exécute la validation (le démon), ou null. */
function utilisateurDuDemon() {
  try {
    return os.userInfo().username;
  } catch {
    return null;
  }
}

/** Hôte d'une URL sur la boucle locale (127.0.0.0/8, ::1, localhost). */
function adresseDeBouclage(url) {
  let h;
  try {
    h = new URL(url).hostname.replace(/^\[|\]$/g, "");
  } catch {
    return false;
  }
  return h === "localhost" || h === "::1" || /^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/.test(h);
}

export function reglesHorsSchema(c) {
  const erreurs = [];
  const avertissements = [];
  const err = (pointeur, regle, valeur) => erreurs.push({ pointeur, regle, valeur });
  const avert = (pointeur, regle) => avertissements.push({ pointeur, regle });
  const prod = c.recorder.environment === "production";

  // Signataire : cohérence classe / backend, classe D refusée en production (EX-11.8).
  const classe = c.signer.class;
  if (!BACKENDS_PAR_CLASSE[classe]?.includes(c.signer.backend.type)) {
    err("/signer/backend/type", `incohérent avec la classe ${classe} (EX-15.4 pas 3)`, c.signer.backend.type);
  }
  if (prod && classe === "D") err("/signer/class", "classe D refusée en production (EX-11.8)", classe);
  if (c.signer.verify_after_sign !== true) err("/signer/verify_after_sign", "non désactivable en version 0 (EX-11.6)", c.signer.verify_after_sign);
  if (prod && c.signer.backend.type === "pkcs11" && /libsofthsm2\.so$/.test(c.signer.backend.module)) {
    avert("/signer/backend/module", "module PKCS#11 logiciel (SoftHSM2) : vaut la classe D (11.2)");
  }
  if (c.signer.rotation.next_key_id !== null && c.signer.rotation.next_key_id === c.signer.key_id) {
    err("/signer/rotation/next_key_id", "identique à signer.key_id", c.signer.rotation.next_key_id);
  }

  // Alias de serveurs (EX-4.9, EX-4.10).
  const alias = Object.keys(c.policy.servers ?? {});
  if (alias.includes("noortrace")) err("/policy/servers/noortrace", "alias réservé (EX-4.9)", "noortrace");
  if (c.tools.prefix === false && alias.length > 1) err("/tools/prefix", "false seulement avec un seul serveur (EX-4.10)", false);

  // Cadence des points de contrôle (EX-12.24).
  if (c.checkpoint_interval_s !== undefined && !cadenceAdmise(c.checkpoint_interval_s)) {
    err("/checkpoint_interval_s", "diviseur de 3600 entre 10 et 3600 attendu (EX-12.24)", c.checkpoint_interval_s);
  }

  // Répertoire des exports (révision 0.8, EX-15.4 pas 3, EX-15.12) :
  // `exports_dir`, ou son défaut s'il est absent, n'est ni `storage.root`, ni
  // un répertoire qui le contient, ni un répertoire qu'il contient. La
  // validation seule : l'export (EX-15.13) n'est pas dans ce lot.
  const exportsDir = c.exports_dir ?? REPERTOIRE_EXPORTS_DEFAUT;
  if (typeof c.storage?.root === "string" && cheminsEmboites(exportsDir, c.storage.root)) {
    err("/exports_dir", "ni storage.root, ni un répertoire qui le contient ou qu'il contient (EX-15.12)", exportsDir);
  }

  // Bail (EX-13.3, EX-13.10).
  if (!(c.lease.renew_ms < c.lease.ttl_ms / 2)) err("/lease/renew_ms", "lease.renew_ms < lease.ttl_ms / 2 attendu", c.lease.renew_ms);
  if (prod && c.lease.store.type !== "file" && c.lease.fencing === null) {
    err("/lease/fencing", "obligatoire avec un magasin postgresql ou etcd en production (EX-13.10)", null);
  }

  // Rétention et WORM (EX-12.19, EX-12.30, EX-12.31).
  const worm = c.storage.seal.worm;
  if (worm) {
    const ans = c.storage.retention.events_years;
    if (worm.retain_days < 365 * ans) err("/storage/seal/worm/retain_days", `au moins 365 × events_years (${365 * ans}) attendu (EX-15.4)`, worm.retain_days);
    else if (worm.retain_days < 365 * (ans + 1)) avert("/storage/seal/worm/retain_days", "inférieur à 365 × (events_years + 1) : fin de l'exercice en cours non couverte (EX-12.19)");
    if (prod && worm.mode !== "compliance") err("/storage/seal/worm/mode", "compliance seul admis en production (EX-12.30)", worm.mode);
    if (prod && worm.type === "gcs-object-retention") err("/storage/seal/worm/type", "gcs-object-retention hors production en version 0 (EX-12.30)", worm.type);
    if (worm.legal_hold_on_write === true && worm.type !== "s3-object-lock") err("/storage/seal/worm/legal_hold_on_write", "seulement avec s3-object-lock (EX-12.31)", true);
    if (worm.legal_hold_on_write === true && prod) err("/storage/seal/worm/legal_hold_on_write", "refusé en production (EX-12.31)", true);
  }

  // Chaîne de clé du registre en production (EX-11.19).
  if (prod && c.anchoring?.registry?.chain_key?.class === "D") err("/anchoring/registry/chain_key/class", "classe D refusée en production (EX-11.19)", "D");

  // Serveurs stdio en production (EX-3.5, EX-15.4 pas 3) : « un serveur stdio
  // sans user, ou dont user est celui du démon » et « une commande qui n'est
  // pas épinglée » sont refusés. L'utilisateur du démon est celui qui exécute
  // la validation (le démon au démarrage et au rechargement).
  if (prod) {
    for (const [a, serveur] of Object.entries(c.policy.servers ?? {})) {
      const t = serveur.transport;
      if (t?.type !== "stdio") continue;
      const ici = `/policy/servers/${a}/transport`;
      if (t.user === null || t.user === undefined) err(`${ici}/user`, "utilisateur distinct de celui du démon obligatoire en production (EX-3.5)", null);
      else if (t.user === utilisateurDuDemon()) err(`${ici}/user`, "utilisateur du démon refusé (EX-3.5)", t.user);
      if (t.integrity === null || t.integrity === undefined) err(`${ici}/integrity`, "épinglage de la commande obligatoire en production (EX-3.5)", null);
      else if (typeof t.integrity.package === "string" && !(t.command ?? []).includes(t.integrity.package)) {
        err(`${ici}/command`, "la commande ne contient pas tel quel le paquet épinglé (EX-3.5)", t.integrity.package);
      }
    }
  }

  // Canal du service d'approbation (EX-18.8, CT-3 EX-12.2) : « Un token nul
  // n'est admis que sur une prise Unix dont le pair est vérifié » ; en HTTP,
  // mTLS (que la configuration v0 ne porte pas) ou jeton, et TLS hors de la
  // boucle locale. Le texte ne distingue pas l'environnement : erreur partout.
  const svc = c.policy.approval?.service;
  if (svc && (svc.url || svc.socket)) {
    const signaler = err;
    const sansJeton = svc.token === null || svc.token === undefined;
    if (svc.url && sansJeton) {
      signaler("/policy/approval/service/token", "jeton nul admis seulement sur une prise Unix dont le pair est vérifié ; aucun mTLS en version 0 (EX-18.8)", null);
    } else if (!svc.url && sansJeton && (svc.peer_user === null || svc.peer_user === undefined)) {
      signaler("/policy/approval/service/peer_user", "prise Unix sans peer_user : pair non vérifié, jeton nul refusé (EX-18.8)", null);
    }
    if (svc.url && /^http:\/\//i.test(svc.url) && !adresseDeBouclage(svc.url)) {
      signaler("/policy/approval/service/url", "TLS exigé hors de la boucle locale (CT-3 EX-12.2, EX-18.8)", svc.url);
    }
  }

  // Gabarits d'effets (EX-7.6, EX-15.4 pas 3).
  for (const [a, serveur] of Object.entries(c.policy.servers ?? {})) {
    for (const [nom, outil] of Object.entries(serveur.tools ?? {})) {
      const ici = `/policy/servers/${a}/tools/${nom.replace(/~/g, "~0").replace(/\//g, "~1")}`;
      if (outil.failure === "passant" && (outil.class ?? serveur.class_default) === "ecriture") {
        avert(`${ici}/failure`, "outil d'écriture passant : ses effets pourront n'avoir qu'un événement en attente (EX-14.2)");
      }
      (outil.effects ?? []).forEach((g, k) => {
        const p = `${ici}/effects/${k}`;
        for (const champ of ["object", "amount", "currency"]) {
          const v = g[champ];
          if (typeof v === "string" && v.startsWith("/") && !estPointeur(v)) err(`${p}/${champ}`, "pointeur hors de /arguments et /result (EX-7.6)", v);
        }
        if (typeof g.amount === "string" && !estPointeur(g.amount)) err(`${p}/amount`, "pointeur ou null attendu (EX-7.6)", g.amount);
        if (typeof g.currency === "string" && !estPointeur(g.currency) && !/^[A-Z]{3}$/.test(g.currency)) {
          err(`${p}/currency`, "pointeur ou trois lettres majuscules attendus (EX-7.6)", g.currency);
        }
        if (g.extract !== null && g.extract !== undefined) {
          try {
            new RegExp(g.extract, "u");
          } catch {
            err(`${p}/extract`, "expression régulière invalide (EX-7.6)", g.extract);
          }
        }
      });
    }
  }

  // Routes du frontal modèle : chemins distincts (EX-15.4 pas 3).
  const chemins = new Set();
  (c.policy.model?.routes ?? []).forEach((r, k) => {
    if (chemins.has(r.path)) err(`/policy/model/routes/${k}/path`, "chemin de route en double", r.path);
    chemins.add(r.path);
    if (r.credentials === "propre" && (r.secret === null || r.secret === undefined)) err(`/policy/model/routes/${k}/secret`, "secret non nul attendu avec credentials propre", null);
  });

  // Jetons statiques désignés (EX-15.4 pas 3, EX-7.3).
  const jetonsMcp = new Set((c.mcp.http?.static_tokens ?? []).map((t) => t.id));
  const jetonsModele = new Set([...(c.model.static_tokens ?? []).map((t) => t.id), ...jetonsMcp]);
  const verifierHotes = (liste, ou, admis) => {
    const vus = new Set();
    (liste ?? []).forEach((h, k) => {
      const id = h.match?.static_token;
      if (typeof id !== "string") return;
      if (!admis.has(id)) err(`${ou}/${k}/match/static_token`, "jeton statique inconnu", id);
      if (vus.has(id)) err(`${ou}/${k}/match/static_token`, "jeton référencé par deux connexions du même frontal", id);
      vus.add(id);
    });
  };
  verifierHotes(c.mcp.hosts, "/mcp/hosts", jetonsMcp);
  verifierHotes(c.model.hosts, "/model/hosts", jetonsModele);
  (c.mcp.hosts ?? []).concat(c.model.hosts ?? []).forEach((h) => {
    if ((h.allowed_on_behalf_of ?? []).length && h.accept_declared_delegation !== true) {
      err(`/mcp/hosts`, "allowed_on_behalf_of non vide seulement avec accept_declared_delegation", h.id ?? null);
    }
  });

  // OpenTelemetry (révision 0.5), forme minimale.
  if (c.otel?.enabled === true && !c.policy.otel) err("/policy/otel", "requis quand otel.enabled vaut true (EX-15.4 pas 3)", null);
  if (c.policy.otel && c.otel?.enabled !== true) avert("/policy/otel", "présent sans otel activé");

  // Mode d'attente et mode observation (EX-15.4, EX-15.8).
  const mode = c.policy.approval?.mode;
  if (mode === "retenir") avert("/policy/approval/mode", "retenir : hold_timeout_ms doit rester sous le délai de tous les hôtes raccordés (EX-4.50)");
  if (mode === "observation") {
    avert("/policy/approval/mode", AVERTISSEMENT_OBSERVATION);
    if (!c.policy.version.endsWith("-observation")) err("/policy/version", "version_observation_sans_suffixe (EX-15.8)", c.policy.version);
  } else if (c.policy.version.endsWith("-observation")) {
    err("/policy/version", "suffixe_observation_hors_mode (EX-15.8)", c.policy.version);
  }
  const jeu = c.policy.approval?.rules?.approver_set;
  if (mode !== "observation" && jeu?.source === "statique" && Array.isArray(jeu.members)) {
    const test = jeu.members.filter((m) => ADRESSES_DE_TEST.includes(m));
    if (test.length) {
      if (prod) err("/policy/approval/rules/approver_set/members", "approbateurs_de_test (EX-15.8)", test);
      else avert("/policy/approval/rules/approver_set/members", "approbateurs_de_test (EX-15.8)");
    }
  }
  return { erreurs, avertissements };
}

/**
 * Pas 1 à 3 d'EX-15.4 (commande `validate-config`, EX-15.7).
 * @param {Uint8Array|string} octets document tel que lu
 * @param {{reglesSupplementaires?: ((c: object) => {erreurs: object[], avertissements: object[]})[]}} [options]
 *   règles des lots suivants (rédaction, politique d'approbation, frontaux)
 * @returns {{config: object|null, erreurs: object[], avertissements: object[], pas: number}}
 *   `pas` : pas de la première erreur (1, 2 ou 3), 0 sans erreur
 */
export function validerConfiguration(octets, options = {}) {
  let c;
  try {
    c = analyserJsonIntegral(octets);
  } catch (e) {
    if (!(e instanceof ErreurJson)) throw e;
    return { config: null, erreurs: [{ pointeur: "", regle: `JSON strict : ${e.message}`, valeur: undefined }], avertissements: [], pas: 1 };
  }
  const schema = registreSchemas().valider(IDS.configuration, c);
  if (!schema.valide) {
    const secrets = new Set();
    parcourirSecrets(c, "", (_, p) => secrets.add(p));
    const erreurs = schema.erreurs.map((e) => ({ ...e, secret: [...secrets].some((p) => e.pointeur.startsWith(p)) }));
    return { config: null, erreurs, avertissements: [], pas: 2 };
  }
  const r = reglesHorsSchema(c);
  for (const f of options.reglesSupplementaires ?? []) {
    const x = f(c);
    r.erreurs.push(...x.erreurs);
    r.avertissements.push(...x.avertissements);
  }
  if (r.erreurs.length) return { config: null, erreurs: r.erreurs, avertissements: r.avertissements, pas: 3 };
  return { config: { ...DEFAUTS, ...c }, erreurs: [], avertissements: r.avertissements, pas: 0 };
}

/**
 * Pas 4 d'EX-15.4 : résout toutes les références de secrets ; la clé du MAC
 * de relais et la clé de pseudonymisation font au moins 32 octets.
 * @param {object} c
 * @param {{env?: NodeJS.ProcessEnv, uid?: number|null}} [contexte]
 * @returns {{secrets: Map<string, Uint8Array>, erreurs: object[]}} secrets par pointeur
 */
export function resoudreSecrets(c, contexte = {}) {
  const secrets = new Map();
  const erreurs = [];
  parcourirSecrets(c, "", (ref, pointeur) => {
    try {
      secrets.set(pointeur, resoudreSecret(ref, pointeur, contexte));
    } catch (e) {
      if (!(e instanceof ErreurSecret)) throw e;
      erreurs.push({ pointeur, regle: e.regle, secret: true });
    }
  });
  const mac = secrets.get("/storage/relay_mac_key");
  if (mac && mac.length < 32) erreurs.push({ pointeur: "/storage/relay_mac_key", regle: "au moins 32 octets après décodage (EX-7.22)", secret: true });
  const pseudo = secrets.get("/policy/redaction/pseudonym_key");
  if (pseudo && pseudo.length < 32) erreurs.push({ pointeur: "/policy/redaction/pseudonym_key", regle: "au moins 32 octets après décodage (EX-10.12)", secret: true });
  return { secrets, erreurs };
}

/**
 * Ligne de rapport sur stderr (EX-15.4) : pointeur JSON, règle, valeur
 * fautive sauf pour un secret.
 * @param {{pointeur: string, regle: string, valeur?: unknown, secret?: boolean}} e
 * @returns {string}
 */
export function ligneRapport(e) {
  const valeur = e.secret || e.valeur === undefined ? "" : ` ; valeur : ${JSON.stringify(e.valeur)}`;
  return `${e.pointeur === "" ? "/" : e.pointeur} : ${e.regle}${valeur}`;
}

/**
 * Pointeurs JSON qui diffèrent entre deux documents, hors `policy` (EX-15.5 :
 * « redémarrage requis »).
 * @param {object} a
 * @param {object} b
 * @returns {string[]}
 */
export function differencesHorsPolitique(a, b) {
  const cles = new Set([...Object.keys(a), ...Object.keys(b)]);
  cles.delete("policy");
  return [...cles].filter((k) => !egaliteJson(a[k], b[k])).map((k) => `/${k}`).sort();
}
