// Déploiement de référence (CT-8, sections 4, 6 et 9) : vérifications
// statiques CO-1 à CO-14 des fichiers Compose, évaluation et collecte du
// contrôle préalable (IP-1 à IP-13), calculateur de dimensionnement (DM-1 à
// DM-22), et validation des schémas conteneurs-v0, controle-prealable-v0 et
// dimensionnement-v0.
//
// Les fonctions d'évaluation (verifierConteneurs, evaluerControle,
// dimensionner) sont pures : ni réseau, ni horloge, ni fichier. Seule
// collecterObservations lit l'hôte (système, horloge, ports, résolution des
// noms, sortie réseau, droits, moteur de conteneurs) ; elle n'écrit rien.
//
// Lecture YAML par js-yaml 4.3.2 (dépendance de développement du dépôt) : une
// clé dupliquée lève une exception, ce qui fait échouer CO-1 (yaml_invalide).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

/** Racine du dépôt. */
export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Version des outils de déploiement (champ `tool` des observations). */
export const VERSION_OUTIL = "0.1.0";

export const ID_SCHEMA_CONTENEURS = "https://noortrace.example/schemas/v0/conteneurs.schema.json";
export const ID_SCHEMA_CONTROLE = "https://noortrace.example/schemas/v0/controle-prealable.schema.json";
export const ID_SCHEMA_DIMENSIONNEMENT = "https://noortrace.example/schemas/v0/dimensionnement.schema.json";

const GIO = 2 ** 30;
const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// ---------------------------------------------------------------------------
// Validation de schéma (JSON Schema 2020-12, sous-ensemble employé par CT-8)
// ---------------------------------------------------------------------------
//
// Le validateur de scripts/lib/journal.mjs (validerSchema) applique un
// sous-ensemble fermé de mots-clés et ignore les autres (motsClesHorsSousEnsemble).
// Les trois schémas de déploiement emploient en plus contains, maxContains,
// maxProperties et exclusiveMinimum (CT-8 A.16) : ce validateur les applique,
// avec les mots-clés de ce sous-ensemble, sans modifier journal.mjs.

/** Mots-clés appliqués par validerSchemaDeploiement. */
export const MOTS_CLES_DEPLOIEMENT = Object.freeze([
  "$ref", "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
  "required", "minProperties", "maxProperties", "propertyNames", "properties", "additionalProperties",
  "prefixItems", "items", "minItems", "maxItems", "uniqueItems", "contains", "minContains", "maxContains",
  "allOf", "anyOf", "oneOf", "not", "if", "then", "else",
]);
const ANNOTATIONS = new Set(["$id", "$schema", "$defs", "$comment", "title", "description", "examples", "default", "deprecated", "readOnly", "writeOnly"]);

function egal(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => egal(x, b[i]));
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return egal(ka, kb) && ka.every((k) => egal(a[k], b[k]));
}

function typeJSON(v, t) {
  switch (t) {
    case "null": return v === null;
    case "boolean": return typeof v === "boolean";
    case "string": return typeof v === "string";
    case "number": return typeof v === "number" && Number.isFinite(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "array": return Array.isArray(v);
    case "object": return estObjet(v);
    default: return false;
  }
}

function resoudre(ref, racine, registre) {
  const i = ref.indexOf("#");
  const base = i === -1 ? ref : ref.slice(0, i);
  const fragment = i === -1 ? "" : ref.slice(i + 1);
  const doc = base ? registre[base] : racine;
  if (!doc) throw new Error(`schéma référencé inconnu : ${base}`);
  let cible = doc;
  for (const seg of fragment ? fragment.split("/").slice(1) : []) {
    cible = cible?.[seg.replace(/~1/g, "/").replace(/~0/g, "~")];
    if (cible === undefined) throw new Error(`référence de schéma introuvable : ${ref}`);
  }
  return { schema: cible, racine: doc };
}

function valider(v, s, racine, chemin, erreurs, registre) {
  const ou = chemin || "/";
  if (s === true) return;
  if (s === false) {
    erreurs.push({ chemin: ou, message: "aucune valeur admise ici" });
    return;
  }
  const conforme = (val, sch) => {
    const e = [];
    valider(val, sch, racine, chemin, e, registre);
    return e.length === 0;
  };
  for (const k of Object.keys(s)) if (!ANNOTATIONS.has(k) && !MOTS_CLES_DEPLOIEMENT.includes(k)) throw new Error(`mot-clé de schéma non pris en charge : ${k} (${ou})`);
  if (typeof s.$ref === "string") {
    const r = resoudre(s.$ref, racine, registre);
    valider(v, r.schema, r.racine, chemin, erreurs, registre);
  }
  if (s.type !== undefined) {
    const types = Array.isArray(s.type) ? s.type : [s.type];
    if (!types.some((t) => typeJSON(v, t))) erreurs.push({ chemin: ou, message: `type ${types.join(" ou ")} attendu` });
  }
  if ("const" in s && !egal(v, s.const)) erreurs.push({ chemin: ou, message: `valeur constante ${JSON.stringify(s.const)} attendue` });
  if (Array.isArray(s.enum) && !s.enum.some((e) => egal(v, e))) erreurs.push({ chemin: ou, message: `valeur hors de l'énumération ${JSON.stringify(s.enum)}` });
  if (typeof v === "string") {
    if (typeof s.pattern === "string" && !new RegExp(s.pattern, "u").test(v)) erreurs.push({ chemin: ou, message: `ne respecte pas le motif ${s.pattern}` });
    const n = [...v].length;
    if (typeof s.minLength === "number" && n < s.minLength) erreurs.push({ chemin: ou, message: `chaîne de moins de ${s.minLength} caractère(s)` });
    if (typeof s.maxLength === "number" && n > s.maxLength) erreurs.push({ chemin: ou, message: `chaîne de plus de ${s.maxLength} caractères` });
  }
  if (typeof v === "number") {
    if (typeof s.minimum === "number" && v < s.minimum) erreurs.push({ chemin: ou, message: `inférieur au minimum ${s.minimum}` });
    if (typeof s.maximum === "number" && v > s.maximum) erreurs.push({ chemin: ou, message: `supérieur au maximum ${s.maximum}` });
    if (typeof s.exclusiveMinimum === "number" && !(v > s.exclusiveMinimum)) erreurs.push({ chemin: ou, message: `non strictement supérieur à ${s.exclusiveMinimum}` });
    if (typeof s.exclusiveMaximum === "number" && !(v < s.exclusiveMaximum)) erreurs.push({ chemin: ou, message: `non strictement inférieur à ${s.exclusiveMaximum}` });
    if (typeof s.multipleOf === "number" && !Number.isInteger(v / s.multipleOf)) erreurs.push({ chemin: ou, message: `n'est pas un multiple de ${s.multipleOf}` });
  }
  if (estObjet(v)) {
    const cles = Object.keys(v);
    if (Array.isArray(s.required)) for (const k of s.required) if (!Object.hasOwn(v, k)) erreurs.push({ chemin: ou, message: `membre obligatoire absent : ${k}` });
    if (typeof s.minProperties === "number" && cles.length < s.minProperties) erreurs.push({ chemin: ou, message: `moins de ${s.minProperties} membre(s)` });
    if (typeof s.maxProperties === "number" && cles.length > s.maxProperties) erreurs.push({ chemin: ou, message: `plus de ${s.maxProperties} membres` });
    if (s.propertyNames !== undefined) for (const k of cles) valider(k, s.propertyNames, racine, `${chemin}/${k}`, erreurs, registre);
    const props = estObjet(s.properties) ? s.properties : {};
    for (const k of cles) {
      if (Object.hasOwn(props, k)) valider(v[k], props[k], racine, `${chemin}/${k}`, erreurs, registre);
      else if (s.additionalProperties !== undefined) {
        if (s.additionalProperties === false) erreurs.push({ chemin: `${chemin}/${k}`, message: "membre non admis" });
        else valider(v[k], s.additionalProperties, racine, `${chemin}/${k}`, erreurs, registre);
      }
    }
  }
  if (Array.isArray(v)) {
    const pre = Array.isArray(s.prefixItems) ? s.prefixItems : [];
    pre.forEach((sch, i) => { if (i < v.length) valider(v[i], sch, racine, `${chemin}/${i}`, erreurs, registre); });
    if (s.items !== undefined) for (let i = pre.length; i < v.length; i++) valider(v[i], s.items, racine, `${chemin}/${i}`, erreurs, registre);
    if (typeof s.minItems === "number" && v.length < s.minItems) erreurs.push({ chemin: ou, message: `moins de ${s.minItems} élément(s)` });
    if (typeof s.maxItems === "number" && v.length > s.maxItems) erreurs.push({ chemin: ou, message: `plus de ${s.maxItems} éléments` });
    if (s.uniqueItems === true && v.some((x, i) => v.findIndex((y) => egal(x, y)) !== i)) erreurs.push({ chemin: ou, message: "éléments non uniques" });
    if (s.contains !== undefined) {
      const n = v.filter((x) => conforme(x, s.contains)).length;
      const min = typeof s.minContains === "number" ? s.minContains : 1;
      if (n < min) erreurs.push({ chemin: ou, message: `moins de ${min} élément(s) conforme(s) à contains` });
      if (typeof s.maxContains === "number" && n > s.maxContains) erreurs.push({ chemin: ou, message: `plus de ${s.maxContains} élément(s) conforme(s) à contains` });
    }
  }
  if (Array.isArray(s.allOf)) for (const sch of s.allOf) valider(v, sch, racine, chemin, erreurs, registre);
  if (Array.isArray(s.anyOf) && !s.anyOf.some((sch) => conforme(v, sch))) erreurs.push({ chemin: ou, message: "aucune branche de anyOf ne convient" });
  if (Array.isArray(s.oneOf)) {
    const n = s.oneOf.filter((sch) => conforme(v, sch)).length;
    if (n !== 1) erreurs.push({ chemin: ou, message: `${n} branche(s) de oneOf conviennent, une attendue` });
  }
  if (s.not !== undefined && conforme(v, s.not)) erreurs.push({ chemin: ou, message: "valeur conforme au schéma de not" });
  if (s.if !== undefined) {
    if (conforme(v, s.if)) { if (s.then !== undefined) valider(v, s.then, racine, chemin, erreurs, registre); }
    else if (s.else !== undefined) valider(v, s.else, racine, chemin, erreurs, registre);
  }
}

/**
 * Valide `valeur` contre `schema` (ou sa définition `fragment`, par exemple
 * "#/$defs/rapport") ; `registre` associe un $id à un schéma pour les $ref
 * absolus. Rend la liste des erreurs { chemin, message }, vide si la valeur
 * est conforme. Un mot-clé hors de MOTS_CLES_DEPLOIEMENT et des annotations
 * lève une exception (jamais ignoré sans bruit).
 */
export function validerSchemaDeploiement(valeur, schema, { fragment = "", registre = {} } = {}) {
  const r = fragment ? resoudre(fragment, schema, registre) : { schema, racine: schema };
  const erreurs = [];
  valider(valeur, r.schema, r.racine, "", erreurs, registre);
  return erreurs;
}

/** Charge spec/schemas/<nom>-v0.schema.json. */
export function chargerSchema(nom) {
  return JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "schemas", `${nom}-v0.schema.json`), "utf8"));
}

/** Texte JSON des fichiers du déploiement et des vecteurs : indentation de deux espaces, saut de ligne final. */
export const texteJSON = (v) => JSON.stringify(v, null, 2) + "\n";

// ---------------------------------------------------------------------------
// Vérifications statiques CO-1 à CO-14 (CT-8 §4.4)
// ---------------------------------------------------------------------------

/** Motif des noms de variable d'environnement tenus pour secrets (CO-9), en complément de la liste fermée de la description. */
export const RE_NOM_SECRET = /(KEY|TOKEN|SECRET|PASSWORD|PASS|PIN|DSN|CREDENTIAL|JETON|CLE|MOT_DE_PASSE|AUTH|BEARER|COOKIE)/i;
/** Sources de montage lié interdites, et leurs sous-chemins (CO-11). */
export const MONTAGES_INTERDITS = Object.freeze(["/", "/etc", "/proc", "/sys", "/dev", "/root", "/home", "/var/run/docker.sock", "/run/docker.sock", "/var/lib/docker"]);
/** Adresses de publication admises (CO-10). */
export const ADRESSES_PUBLICATION = Object.freeze(["127.0.0.1", "${NOORTRACE_IP_INTERNE:?adresse interne requise}"]);
/** Réseaux qui doivent être internes (CO-14). */
export const RESEAUX_INTERNES = Object.freeze(["outils", "console"]);
/** Clés de premier niveau admises (CO-1) : `include` et toute autre clé sont refusés. */
export const CLES_PREMIER_NIVEAU = Object.freeze(["name", "services", "networks", "volumes", "secrets"]);
/**
 * Liste fermée des clés de service (CO-8) : toute autre clé (privileged, pid,
 * ipc, devices, userns_mode, cgroup_parent, extends, volumes_from, uts,
 * sysctls, device_cgroup_rules, runtime, extra_hosts, …) échoue avec le code
 * cle_interdite_<clé>. `build` relève de CO-3 seul.
 */
export const CLES_SERVICE = Object.freeze(["image", "user", "group_add", "command", "read_only", "tmpfs", "environment", "cap_drop", "cap_add", "security_opt", "restart", "ports", "volumes", "secrets", "networks", "network_mode", "healthcheck", "depends_on", "profiles", "build"]);
/** Options de ligne de commande qui portent un secret (CO-9) : leur valeur doit être un chemin /run/secrets/. */
const RE_OPTION_SECRETE = /^--(jeton|cle|mot-de-passe|token|secret|password)(=(.*))?$/;
/** Entrées de security_opt qui retirent un confinement (CO-7). */
const RE_SANS_CONFINEMENT = /^(seccomp[:=]unconfined|apparmor[:=]unconfined|label[:=]disable)$/;

function analyserPort(p) {
  if (estObjet(p)) return { host_ip: p.host_ip ?? null, published: String(p.published ?? ""), target: Number(p.target) };
  const s = String(p);
  let m = /^(\$\{[^}]+\}|[0-9.]+):([0-9]+):([0-9]+)$/.exec(s);
  if (m) return { host_ip: m[1], published: m[2], target: Number(m[3]) };
  m = /^([0-9]+)(:([0-9]+))?$/.exec(s);
  if (m) return { host_ip: null, published: m[1], target: Number(m[3] ?? m[1]) };
  return { host_ip: null, published: s, target: NaN, invalide: true };
}

function analyserVolume(v) {
  if (estObjet(v)) return { type: v.type, source: v.source, target: v.target, ro: v.read_only === true, creation: v.bind ? v.bind.create_host_path : undefined };
  const [source, target, mode = "rw"] = String(v).split(":");
  return { type: /^[./~]/.test(source) ? "bind" : "volume", source, target, ro: mode.split(",").includes("ro"), creation: undefined };
}

const sousChemin = (src, base) => src === base || src.startsWith(base === "/" ? "/" : base + "/");
/** Un chemin dont un composant vaut « .. » (CO-11 : jamais admis dans la source d'un montage lié). */
const remonte = (src) => String(src).split("/").includes("..");

/** Arguments de command, entrypoint ou healthcheck.test, en liste de chaînes. */
const arguments_ = (v) => (Array.isArray(v) ? v.map(String) : typeof v === "string" ? v.split(/\s+/).filter(Boolean) : []);

/** Une option qui porte un secret en clair dans une liste d'arguments (CO-9). */
function secretEnLigne(args) {
  for (let i = 0; i < args.length; i++) {
    const m = RE_OPTION_SECRETE.exec(args[i]);
    if (!m) continue;
    const valeur = m[2] !== undefined ? m[3] : args[i + 1];
    if (valeur === undefined || !String(valeur).startsWith("/run/secrets/")) return true;
  }
  return false;
}

/**
 * Vérifications CO-1 à CO-14 d'un fichier Compose (texte) contre la
 * description des images (`images.json`, conteneurs-v0). `nom` est le nom
 * de base du fichier. Rend le rapport conteneurs-v0 `$defs/rapport` : les
 * constats de chaque vérification dans l'ordre des services du fichier, puis
 * des clés de premier niveau (secrets, volumes, réseaux). Quand CO-1 échoue
 * faute d'un document analysable (yaml_invalide, services_absents,
 * cle_premier_niveau_non_admise), CO-2 à CO-14 sont non_execute, raison
 * prerequis_en_echec, et all_images_by_digest vaut false.
 */
export function verifierConteneurs(texte, description, nom = "compose.yaml") {
  const constats = Object.fromEntries(Array.from({ length: 14 }, (_, i) => [`CO-${i + 1}`, []]));
  const ajouter = (id, service, code) => constats[id].push({ service, code });
  let doc = null;
  let analysable = true;
  try {
    doc = yaml.load(texte, { json: false });
  } catch {
    ajouter("CO-1", null, "yaml_invalide");
    analysable = false;
  }
  if (analysable && (!estObjet(doc) || !estObjet(doc.services) || Object.keys(doc.services).length === 0)) {
    ajouter("CO-1", null, "services_absents");
    analysable = false;
  }
  if (analysable && Object.keys(doc).some((k) => !CLES_PREMIER_NIVEAU.includes(k))) {
    ajouter("CO-1", null, "cle_premier_niveau_non_admise");
    analysable = false;
  }
  const services = analysable ? doc.services : {};
  const secretsHaut = analysable && estObjet(doc.secrets) ? doc.secrets : {};
  const recus = new Map(); // secret de premier niveau → comptes des services qui le reçoivent
  for (const [nomS, s0] of Object.entries(services)) {
    const s = estObjet(s0) ? s0 : {};
    const d = description.services[nomS];
    if (!d) {
      ajouter("CO-1", nomS, "service_non_decrit");
      continue;
    }
    // CO-2 : image épinglée sur le nom et l'étiquette de la description.
    const m = /^([a-z0-9][a-z0-9._/-]*)(?::([A-Za-z0-9._-]+))?(?:@sha256:([0-9a-f]{64}))?$/.exec(String(s.image ?? ""));
    if (!m || m[1] !== d.image || (!m[2] && !m[3]) || (m[2] && m[2] !== d.tag)) ajouter("CO-2", nomS, "image_non_epinglee");
    // CO-3 : aucune construction.
    if ("build" in s) ajouter("CO-3", nomS, "construction_presente");
    // CO-4 : compte numérique de la description ; 0 seulement pour attributs ; groupes supplémentaires de la description.
    if (String(s.user ?? "") !== d.user || (d.user.startsWith("0:") && nomS !== "attributs")) ajouter("CO-4", nomS, s.user === undefined ? "utilisateur_absent" : "utilisateur_non_conforme");
    else if (/^0:|:0$/.test(d.user) && d.cap_add.length === 0) ajouter("CO-4", nomS, "utilisateur_non_conforme");
    const groupes = (Array.isArray(s.group_add) ? s.group_add : s.group_add === undefined ? [] : [s.group_add]).map(String).sort();
    if (!egal(groupes, (d.group_add ?? []).slice().sort())) ajouter("CO-4", nomS, "groupe_non_conforme");
    // CO-5 : racine en lecture seule ; tmpfs bornés ; répertoire temporaire désigné par TMPDIR.
    if (s.read_only !== true) ajouter("CO-5", nomS, "racine_inscriptible");
    const tmpfs = (Array.isArray(s.tmpfs) ? s.tmpfs : s.tmpfs === undefined ? [] : [s.tmpfs]).map(String);
    const env = s.environment ?? {};
    const tmpdir = Array.isArray(env) ? env.includes("TMPDIR=" + d.tmpfs) : estObjet(env) && env.TMPDIR === d.tmpfs;
    if (tmpfs.some((t) => !/^[^:]+:(.*,)?size=[0-9]+/.test(t))) ajouter("CO-5", nomS, "tmp_non_borne");
    else if (d.tmpfs && (!tmpfs.some((t) => t.startsWith(d.tmpfs + ":")) || !tmpdir)) ajouter("CO-5", nomS, "tmp_non_borne");
    // CO-6 : toutes les capacités retirées ; ajouts égaux à la description.
    const retirees = Array.isArray(s.cap_drop) ? s.cap_drop : [];
    if (!(retirees.length === 1 && retirees[0] === "ALL")) ajouter("CO-6", nomS, "capacites_non_retirees");
    const ajoutees = (Array.isArray(s.cap_add) ? s.cap_add : []).slice().sort();
    if (!egal(ajoutees, d.cap_add.slice().sort())) ajouter("CO-6", nomS, "capacite_ajoutee");
    // CO-7 : pas de nouveaux privilèges ; aucun confinement retiré.
    const opts = (Array.isArray(s.security_opt) ? s.security_opt : []).map(String);
    if (!opts.includes("no-new-privileges:true")) ajouter("CO-7", nomS, "privileges_non_bloques");
    if (opts.some((o) => RE_SANS_CONFINEMENT.test(o))) ajouter("CO-7", nomS, "confinement_desactive");
    // CO-8 : liste fermée des clés de service ; jamais le réseau de l'hôte.
    for (const k of Object.keys(s)) if (!CLES_SERVICE.includes(k) && s[k] !== false) ajouter("CO-8", nomS, "cle_interdite_" + k.replace(/[^a-z_]/g, "_"));
    if (s.network_mode === "host") ajouter("CO-8", nomS, "reseau_hote");
    // CO-9 : secrets par fichier, jamais dans l'environnement ni sur la ligne de commande.
    if ("env_file" in s) ajouter("CO-9", nomS, "fichier_environnement");
    const nomsEnv = Array.isArray(env) ? env.map((x) => String(x).split("=")[0]) : estObjet(env) ? Object.keys(env) : [];
    if (nomsEnv.some((n) => !(d.environment ?? []).includes(n))) ajouter("CO-9", nomS, "variable_non_decrite");
    if (nomsEnv.some((n) => RE_NOM_SECRET.test(n))) ajouter("CO-9", nomS, "secret_en_environnement");
    if ([s.command, s.entrypoint, estObjet(s.healthcheck) ? s.healthcheck.test : undefined].some((v) => secretEnLigne(arguments_(v)))) ajouter("CO-9", nomS, "secret_en_ligne_de_commande");
    for (const sec of Array.isArray(s.secrets) ? s.secrets : []) {
      const n = typeof sec === "string" ? sec : String(sec?.source ?? "");
      const cible = typeof sec === "string" ? null : sec?.target ?? null;
      if (!d.secrets.some((re) => new RegExp(re).test(n))) ajouter("CO-9", nomS, "secret_non_decrit");
      if (!Object.hasOwn(secretsHaut, n)) ajouter("CO-9", nomS, "secret_non_declare");
      if (cible && !String(cible).startsWith("/run/secrets/") && String(cible).includes("/")) ajouter("CO-9", nomS, "secret_hors_run_secrets");
      const compte = String(s.user ?? d.user).split(":")[0];
      if (!recus.has(n)) recus.set(n, []);
      recus.get(n).push({ service: nomS, compte });
    }
    // CO-10 : ports publiés sur une adresse explicite admise.
    for (const p of Array.isArray(s.ports) ? s.ports : []) {
      const a = analyserPort(p);
      if (a.invalide || a.published.includes("-")) ajouter("CO-10", nomS, "port_invalide");
      else if (!ADRESSES_PUBLICATION.includes(a.host_ip)) ajouter("CO-10", nomS, "port_toutes_interfaces");
      else if (!d.ports.includes(a.target)) ajouter("CO-10", nomS, "port_non_decrit");
    }
    // CO-11 : volumes décrits, montages liés admis, jamais de remontée « .. ».
    for (const v of Array.isArray(s.volumes) ? s.volumes : []) {
      const a = analyserVolume(v);
      const src = String(a.source ?? "");
      if (a.type === "bind" && (remonte(src) || (MONTAGES_INTERDITS.some((x) => sousChemin(src, x)) && !d.bind_sources.some((x) => src.startsWith(x))))) {
        ajouter("CO-11", nomS, "montage_interdit");
        continue;
      }
      const dv = d.volumes.find((x) => x.target === a.target);
      if (!dv) {
        ajouter("CO-11", nomS, "volume_non_decrit");
        continue;
      }
      if (dv.access === "ro" && !a.ro) ajouter("CO-11", nomS, "volume_inscriptible");
      if (a.type === "bind") {
        if (!d.bind_sources.some((x) => src.startsWith(x))) ajouter("CO-11", nomS, "montage_non_decrit");
        if (a.creation !== false) ajouter("CO-11", nomS, "creation_chemin_hote");
      }
    }
    // CO-12 : sonde en forme exec, dépendances sur l'état sain.
    const hc = s.healthcheck;
    if (d.probe.type === "commande") {
      if (!estObjet(hc) || !Array.isArray(hc.test) || hc.test[0] !== "CMD") ajouter("CO-12", nomS, "sonde_non_conforme");
    } else if (!estObjet(hc) || hc.disable !== true) ajouter("CO-12", nomS, "sonde_non_desactivee");
    const dep = s.depends_on ?? {};
    if (Array.isArray(dep)) {
      if (dep.length) ajouter("CO-12", nomS, "dependance_sans_condition");
    } else if (estObjet(dep)) {
      for (const [cible, c] of Object.entries(dep)) {
        const dc = description.services[cible];
        const attendu = dc && dc.probe.type === "commande" ? "service_healthy" : "service_started";
        if (!estObjet(c) || c.condition !== attendu) ajouter("CO-12", nomS, "dependance_sans_condition");
      }
    }
    // CO-13 : redémarrage.
    const rs = String(s.restart ?? "");
    if (d.kind === "service" ? rs !== "unless-stopped" : rs !== "no") ajouter("CO-13", nomS, "redemarrage_non_conforme");
    // CO-14 : réseaux ; `service:<nom>` (révision 0.7 de CT-8) : l'espace réseau d'un service du même fichier, sans réseau ni port propres.
    if (d.network_mode === "none") {
      if (s.network_mode !== "none") ajouter("CO-14", nomS, "reseau_attendu_aucun");
    } else if (typeof d.network_mode === "string" && d.network_mode.startsWith("service:")) {
      const hote = d.network_mode.slice("service:".length);
      if (s.network_mode !== d.network_mode || !Object.hasOwn(services, hote) || hote === nomS || s.networks !== undefined || s.ports !== undefined) ajouter("CO-14", nomS, "espace_reseau_non_conforme");
    } else if (s.network_mode !== "none" && s.network_mode !== "host") {
      const reseaux = Array.isArray(s.networks) ? s.networks : estObjet(s.networks) ? Object.keys(s.networks) : [];
      if (!reseaux.length) ajouter("CO-14", nomS, "reseau_par_defaut");
      if (reseaux.some((n) => !d.networks.includes(n))) ajouter("CO-14", nomS, "reseau_non_decrit");
    }
  }
  // CO-9 : secrets de premier niveau ; un fichier n'a qu'un propriétaire, donc un seul compte qui le lit.
  for (const s of Object.values(secretsHaut)) {
    if (!(estObjet(s) && (s.external === true || (typeof s.file === "string" && /^\.\/secrets\/[a-z0-9][a-z0-9._-]*$/.test(s.file))))) ajouter("CO-9", null, "secret_hors_repertoire");
    if (estObjet(s) && "environment" in s) ajouter("CO-9", null, "secret_depuis_environnement");
  }
  for (const [, l] of recus) if (new Set(l.map((x) => x.compte)).size > 1) ajouter("CO-9", l[1].service, "secret_partage_entre_comptes");
  // CO-11 : volumes de premier niveau ; un pilote ou des options qui lient un chemin de l'hôte sont refusés.
  const volumesHaut = analysable && estObjet(doc.volumes) ? doc.volumes : {};
  for (const v of Object.values(volumesHaut)) {
    if (!estObjet(v)) continue;
    const o = estObjet(v.driver_opts) ? v.driver_opts : {};
    if ((v.driver !== undefined && v.driver !== "local") || Object.keys(o).length > 0) ajouter("CO-11", null, "volume_lie_hote");
  }
  // CO-14 : réseaux internes.
  const reseaux = analysable && estObjet(doc.networks) ? doc.networks : {};
  for (const [n, r] of Object.entries(reseaux)) if (RESEAUX_INTERNES.includes(n) && !(estObjet(r) && r.internal === true)) ajouter("CO-14", null, "reseau_non_interne");
  const checks = Object.entries(constats).map(([id, findings]) => {
    if (!analysable && id !== "CO-1") return { id, status: "non_execute", reason: "prerequis_en_echec", findings: [] };
    return { id, status: findings.length ? "echoue" : "reussi", reason: null, findings };
  });
  const listes = Object.values(services);
  const parCondense = listes.length > 0 && listes.every((s) => /@sha256:[0-9a-f]{64}$/.test(String(s?.image ?? "")));
  return {
    version: 0,
    file: nom,
    sha256: crypto.createHash("sha256").update(texte).digest("hex"),
    verdict: checks.some((c) => c.status !== "reussi") ? "non_conforme" : "conforme",
    all_images_by_digest: parCondense,
    checks,
  };
}

/** Ports publiés d'un fichier Compose : [{ service, host_ip, published, target }] dans l'ordre du fichier. */
export function portsPublies(texte) {
  const doc = yaml.load(texte, { json: false });
  const out = [];
  for (const [service, s] of Object.entries(doc?.services ?? {})) for (const p of s?.ports ?? []) out.push({ service, ...analyserPort(p) });
  return out;
}

// ---------------------------------------------------------------------------
// Contrôle préalable : évaluation (CT-8 §6.2, EX-6.3)
// ---------------------------------------------------------------------------

const SYSTEMES_ADMIS = Object.freeze(["ext4", "xfs", "btrfs"]);
const SYSTEMES_REFUSES = Object.freeze(["nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs"]);
const IDS_IP = Array.from({ length: 13 }, (_, i) => `IP-${i + 1}`);

/**
 * Exigences de chaque profil (table d'EX-6.2). Les seuils de ressources
 * sont des cibles (à mesurer, CT-9) ; `clock_max_error_ms` est
 * `clock.warn_skew_ms` de la configuration (1 000 dans l'exemple de CT-2
 * §15.3) ; `storage_free_min_bytes` de production vient de `totals.local_bytes`
 * d'un dimensionnement (null sans dimensionnement) ; `ports` de production
 * sont les ports publiés du fichier Compose (null : ceux des observations).
 */
export const EXIGENCES = Object.freeze({
  rapide: Object.freeze({
    profile: "rapide", architectures: ["x64"], cpus_min: 2, memory_min_bytes: 4 * GIO, storage_free_min_bytes: 10 * GIO,
    filesystems_ok: SYSTEMES_ADMIS, filesystems_refused: SYSTEMES_REFUSES, clock_max_error_ms: 1000,
    ports: [8300, 8400, 8500].map((port) => ({ address: "127.0.0.1", port })),
    images_by_digest: false, require_cache_declaration: false,
    blocking: { "IP-1": true, "IP-2": true, "IP-3": true, "IP-4": true, "IP-5": false, "IP-6": true, "IP-7": true, "IP-8": true, "IP-9": false, "IP-10": true, "IP-11": true, "IP-12": true, "IP-13": false },
  }),
  production: Object.freeze({
    profile: "production", architectures: ["x64"], cpus_min: 4, memory_min_bytes: 8 * GIO, storage_free_min_bytes: null,
    filesystems_ok: SYSTEMES_ADMIS, filesystems_refused: SYSTEMES_REFUSES, clock_max_error_ms: 1000, ports: null,
    images_by_digest: true, require_cache_declaration: true,
    blocking: Object.fromEntries(IDS_IP.map((id) => [id, true])),
  }),
});

/** Exigences d'un profil, avec les remplacements d'EX-6.1 (seuil d'espace, borne d'horloge, --seulement). */
export function exigencesProfil(profil, { storageFreeMinBytes, clockMaxErrorMs, only = null } = {}) {
  if (!Object.hasOwn(EXIGENCES, profil)) throw new Error(`profil inconnu : ${profil}`);
  const ex = structuredClone(EXIGENCES[profil]);
  if (profil === "production" && storageFreeMinBytes !== undefined) ex.storage_free_min_bytes = storageFreeMinBytes;
  if (clockMaxErrorMs !== undefined) ex.clock_max_error_ms = clockMaxErrorMs;
  ex.only = only;
  return ex;
}

const verif = (id, status, reason, measured, expected) => ({ id, status, reason, measured, expected });

/** Modes admis d'un fichier de secret (IP-10) : 0400, ou 0600 pour un secret que son service doit réécrire. */
export const MODES_SECRET = Object.freeze([0o400, 0o600]);
/** Adresses d'écoute sur toutes les interfaces, refusées pour NOORTRACE_IP_INTERNE (IP-6). */
export const ADRESSES_TOUTES_INTERFACES = Object.freeze(["0.0.0.0", "::", "[::]"]);

/**
 * Évaluation du contrôle préalable (EX-6.2, EX-6.3) : fonction pure des
 * observations (controle-prealable-v0 `$defs/observations`) et des
 * exigences d'un profil (exigencesProfil). Rend le rapport
 * controle-prealable-v0 (racine).
 */
export function evaluerControle(obs, ex) {
  const r = [];
  // IP-1 système
  if (obs.platform === null) r.push(verif("IP-1", "non_execute", "mesure_absente", null, { platform: "linux", architectures: ex.architectures }));
  else {
    const raison = obs.platform !== "linux" ? "systeme_non_pris_en_charge" : ex.architectures.includes(obs.arch) ? null : "architecture_non_prise_en_charge";
    r.push(verif("IP-1", raison ? "echoue" : "reussi", raison, { platform: obs.platform, arch: obs.arch }, { platform: "linux", architectures: ex.architectures }));
  }
  // IP-2 ressources
  {
    const ok = obs.cpus >= ex.cpus_min && obs.memory_bytes >= ex.memory_min_bytes;
    const raison = ok ? null : obs.cpus < ex.cpus_min ? "processeurs_insuffisants" : "memoire_insuffisante";
    r.push(verif("IP-2", ok ? "reussi" : "echoue", raison, { cpus: obs.cpus, memory_bytes: obs.memory_bytes }, { cpus_min: ex.cpus_min, memory_min_bytes: ex.memory_min_bytes }));
  }
  // IP-3 espace libre et IP-4 système de fichiers, sous storage.root
  const st = obs.storage;
  if (!st) {
    r.push(verif("IP-3", "non_execute", "mesure_absente", null, { free_min_bytes: ex.storage_free_min_bytes }));
    r.push(verif("IP-4", "non_execute", "mesure_absente", null, { accepted: ex.filesystems_ok }));
  } else {
    const min = ex.storage_free_min_bytes;
    if (min === null) r.push(verif("IP-3", "non_execute", "dimensionnement_absent", { free_bytes: st.free_bytes }, { free_min_bytes: null }));
    else r.push(verif("IP-3", st.free_bytes >= min ? "reussi" : "echoue", st.free_bytes >= min ? null : "espace_insuffisant", { free_bytes: st.free_bytes }, { free_min_bytes: min }));
    const statut = ex.filesystems_ok.includes(st.fstype) ? "reussi" : ex.filesystems_refused.includes(st.fstype) ? "echoue" : "avertissement";
    const raison = statut === "reussi" ? null : statut === "echoue" ? "systeme_de_fichiers_refuse" : "systeme_de_fichiers_non_eprouve";
    r.push(verif("IP-4", statut, raison, { fstype: st.fstype }, { accepted: ex.filesystems_ok }));
  }
  // IP-5 horloge
  {
    const c = obs.clock;
    const attendu = { synchronized: true, max_error_ms: ex.clock_max_error_ms };
    if (!c) r.push(verif("IP-5", "non_execute", "mesure_absente", null, attendu));
    else if (c.source === "aucune") r.push(verif("IP-5", "non_execute", "outil_absent", { source: c.source }, attendu));
    else if (!c.synchronized) r.push(verif("IP-5", "echoue", "horloge_non_synchronisee", { source: c.source, synchronized: false, error_bound_ms: c.error_bound_ms }, attendu));
    else if (c.error_bound_ms === null) r.push(verif("IP-5", "avertissement", "borne_inconnue", { source: c.source, synchronized: true, error_bound_ms: null }, attendu));
    else if (c.error_bound_ms > ex.clock_max_error_ms) r.push(verif("IP-5", "echoue", "ecart_trop_grand", { source: c.source, synchronized: true, error_bound_ms: c.error_bound_ms }, attendu));
    else r.push(verif("IP-5", "reussi", null, { source: c.source, synchronized: true, error_bound_ms: c.error_bound_ms }, attendu));
  }
  // IP-6 ports
  {
    const attendus = ex.ports === null ? obs.ports.map(({ address, port }) => ({ address, port })) : ex.ports;
    const occupes = attendus.filter((p) => {
      const o = obs.ports.find((q) => q.address === p.address && q.port === p.port);
      return !o || !o.free;
    });
    // Adresse interne de production (NOORTRACE_IP_INTERNE) : une adresse d'une interface de l'hôte, jamais toutes les interfaces.
    const ia = obs.internal_address ?? null;
    const raisonAdresse = ia === null ? null : ADRESSES_TOUTES_INTERFACES.includes(ia.address) ? "adresse_toutes_interfaces" : ia.on_host ? null : "adresse_hors_hote";
    const raison = raisonAdresse ?? (occupes.length ? "port_occupe" : null);
    r.push(verif("IP-6", raison ? "echoue" : "reussi", raison, { busy: occupes, internal_address: ia }, { free: attendus }));
  }
  // IP-7 résolution des noms
  {
    const ko = obs.dns.filter((d) => d.addresses.length === 0);
    r.push(verif("IP-7", ko.length ? "echoue" : "reussi", ko.length ? "nom_non_resolu" : null, { unresolved: ko.map((d) => d.name) }, { resolved: obs.dns.map((d) => d.name) }));
  }
  // IP-8 sortie réseau déclarée
  {
    const ko = obs.egress.filter((f) => f.result !== "ouvert");
    r.push(verif("IP-8", ko.length ? "echoue" : "reussi", ko.length ? ko[0].result : null, { failed: ko.map((f) => ({ flow: f.flow, host: f.host, port: f.port, result: f.result })) }, { open: obs.egress.map((f) => f.flow) }));
  }
  // IP-9 mandataire
  {
    const ok = obs.proxy.declared === obs.proxy.environment_set;
    r.push(verif("IP-9", ok ? "reussi" : "avertissement", ok ? null : "mandataire_incoherent", { environment_set: obs.proxy.environment_set }, { declared: obs.proxy.declared }));
  }
  // IP-10 droits
  {
    // Ordre fixé par EX-6.2 : répertoire des secrets, mode de chaque secret,
    // propriétaire de chaque secret, mode puis propriétaire de la configuration.
    const d = obs.rights;
    let raison = null;
    if (d.secrets_dir_mode !== null && (d.secrets_dir_mode & 0o077) !== 0) raison = "secrets_lisibles";
    else if (d.secret_files.some((f) => (f.mode & 0o077) !== 0)) raison = "secrets_lisibles";
    else if (d.secret_files.some((f) => !MODES_SECRET.includes(f.mode & 0o7777))) raison = "secret_mode_non_conforme";
    else if (d.secret_files.some((f) => f.expected_uid === null)) raison = "secret_partage_entre_comptes";
    else if (d.secret_files.some((f) => f.uid !== f.expected_uid)) raison = "secret_proprietaire_incorrect";
    else if (d.config_mode !== null && (d.config_mode & 0o077) !== 0) raison = "configuration_lisible_par_autrui";
    else if (d.config_mode !== null && d.config_uid !== d.config_expected_uid) raison = "configuration_proprietaire_incorrect";
    r.push(verif("IP-10", raison ? "echoue" : "reussi", raison, { uid_is_root: d.uid === 0, secrets_dir_mode: d.secrets_dir_mode, config_mode: d.config_mode, config_uid: d.config_uid, config_expected_uid: d.config_expected_uid }, { secret_modes: MODES_SECRET, secrets_mode_mask: 0o077, config_mode_mask: 0o077 }));
  }
  // IP-11 moteur et Compose
  {
    const m = obs.engine;
    const ok = m.engine_ok && m.compose_ok;
    r.push(verif("IP-11", ok ? "reussi" : "echoue", ok ? null : m.engine_ok ? "compose_absent" : "moteur_absent", { engine_ok: m.engine_ok, compose_ok: m.compose_ok }, { engine_ok: true, compose_ok: true }));
  }
  // IP-12 fichier Compose (CO-1 à CO-14)
  {
    const c = obs.compose;
    const attendu = { failed: [], images_by_digest: ex.images_by_digest };
    if (!c) r.push(verif("IP-12", "non_execute", "fichier_absent", null, attendu));
    else {
      const raison = c.failed.length ? "conteneurs_non_conformes" : ex.images_by_digest && !c.all_images_by_digest ? "condense_requis" : null;
      r.push(verif("IP-12", raison ? "echoue" : "reussi", raison, { failed: c.failed.slice(), all_images_by_digest: c.all_images_by_digest }, attendu));
    }
  }
  // IP-13 cache d'écriture protégé (déclaration de l'exploitant)
  if (obs.declarations.write_cache_protected === true) r.push(verif("IP-13", "reussi", null, { declared: true }, { declared: true }));
  else r.push(verif("IP-13", ex.require_cache_declaration ? "echoue" : "non_execute", "declaration_absente", { declared: false }, { declared: true }));
  const choisies = ex.only ?? null;
  for (const c of r) {
    c.blocking = ex.blocking[c.id];
    if (choisies && !choisies.includes(c.id)) Object.assign(c, { status: "non_execute", reason: "non_demandee", measured: null, blocking: false });
  }
  const bloque = r.some((c) => c.blocking && (c.status === "echoue" || c.status === "non_execute"));
  const avertit = r.some((c) => c.status !== "reussi");
  return {
    version: 0,
    profile: ex.profile,
    checked_at: obs.checked_at,
    tool: obs.tool,
    verdict: bloque ? "non_pret" : avertit ? "pret_avec_avertissements" : "pret",
    exit_code: bloque ? 1 : 0,
    checks: r,
  };
}

// ---------------------------------------------------------------------------
// Contrôle préalable : destinations (EX-6.5) et collecte sur l'hôte
// ---------------------------------------------------------------------------

/** Hôte et port d'une URL http(s) (443 par défaut pour https, 80 pour http), ou null. */
export function hotePort(url) {
  if (typeof url !== "string" || url === "") return null;
  let u;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  return { host: u.hostname, port: u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80 };
}

/** Un pont stdio du réseau interne `outils` (EX-3.7) : jamais essayé par IP-7 ni IP-8. */
const estPont = (host) => /^pont-[a-z0-9-]+$/.test(host);

function contientVault(v) {
  if (Array.isArray(v)) return v.some(contientVault);
  if (!estObjet(v)) return false;
  if (typeof v.vault === "string" || (estObjet(v.vault) && Object.keys(v.vault).length)) return true;
  return Object.values(v).some(contientVault);
}

/**
 * Destinations essayées par IP-7 et IP-8 (EX-6.5), tirées de la
 * configuration de l'enregistreur et du document ancrage-v0 (facultatif),
 * dans l'ordre des flux puis de la configuration, sans doublon :
 * [{ flow, host, port }]. `env` fournit VAULT_ADDR.
 */
export function destinations(config, ancrage = null, { env = {} } = {}) {
  const out = [];
  const ajouter = (flow, url) => {
    const hp = hotePort(url);
    if (!hp || (flow === "FL-7" && estPont(hp.host))) return;
    if (!out.some((d) => d.flow === flow && d.host === hp.host && d.port === hp.port)) out.push({ flow, ...hp });
  };
  const pol = config?.policy ?? {};
  for (const s of Object.values(pol.servers ?? {})) if (s?.transport?.type === "http") ajouter("FL-7", s.transport.url);
  for (const r of pol.model?.routes ?? []) ajouter("FL-8", r?.upstream);
  ajouter("FL-9", config?.signer?.backend?.url);
  ajouter("FL-11", config?.storage?.seal?.worm?.endpoint);
  ajouter("FL-12", pol.approval?.service?.url);
  ajouter("FL-17", config?.anchoring?.rfc3161?.url);
  for (const p of ancrage?.rfc3161?.providers ?? []) ajouter("FL-17", p?.url);
  for (const c of config?.anchoring?.opentimestamps?.calendars ?? []) ajouter("FL-18", c);
  for (const c of ancrage?.opentimestamps?.calendars ?? []) ajouter("FL-18", c);
  for (const c of ancrage?.opentimestamps?.upgrade?.whitelist ?? []) ajouter("FL-18", c);
  ajouter("FL-19", config?.anchoring?.registry?.rpc_url);
  if (contientVault(config) && env.VAULT_ADDR) ajouter("FL-23", env.VAULT_ADDR);
  const ordre = (f) => Number(f.slice(3));
  return out.map((d, i) => ({ d, i })).sort((a, b) => ordre(a.d.flow) - ordre(b.d.flow) || a.i - b.i).map((x) => x.d);
}

/** UID du compte d'une description de service (« 10001:10001 » → 10001). */
const uidService = (d) => Number(String(d?.user ?? "").split(":")[0]);

/**
 * UID attendu d'un fichier de secret : celui des services de la description
 * qui l'admettent quand ils ont tous le même compte ; null quand ils ont des
 * comptes différents (un fichier n'a qu'un propriétaire : IP-10 échoue,
 * secret_partage_entre_comptes) ; celui de l'enregistreur quand aucun ne
 * l'admet.
 */
export function uidAttenduSecret(nom, description) {
  const uids = new Set();
  for (const d of Object.values(description.services)) if ((d.secrets ?? []).some((re) => new RegExp(re).test(nom))) uids.add(uidService(d));
  if (uids.size === 0) return uidService(description.services.enregistreur);
  return uids.size === 1 ? [...uids][0] : null;
}

/** Type du système de fichiers qui porte `chemin`, d'après /proc/self/mountinfo (point de montage le plus long qui le contient). */
export function typeSystemeFichiers(chemin, mountinfo) {
  let meilleur = null;
  for (const ligne of mountinfo.split("\n")) {
    if (!ligne.trim()) continue;
    const [avant, apres] = ligne.split(" - ");
    if (!apres) continue;
    const point = avant.split(" ")[4].replace(/\\([0-7]{3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)));
    const type = apres.split(" ")[0];
    if (sousChemin(chemin, point) && (!meilleur || point.length >= meilleur.point.length)) meilleur = { point, type };
  }
  return meilleur ? meilleur.type : null;
}

/**
 * Borne d'erreur de l'horloge d'après `chronyc -c tracking` (R9-F41,
 * R9-F42) : |System time| + Root dispersion + Root delay / 2, en
 * millisecondes, avec le statut de saut. Champs CSV supposés dans l'ordre de
 * la sortie lisible (référence, nom, strate, instant de référence, System
 * time, Last offset, RMS offset, Frequency, Residual freq, Skew, Root delay,
 * Root dispersion, Update interval, Leap status) : ordre non vérifié sur
 * chrony 4.6 (CT-8 §6.2) ; une ligne de moins de 14 champs est
 * tenue pour illisible (null).
 */
export function lireChronyc(sortie) {
  const champs = String(sortie).trim().split("\n")[0].split(",");
  if (champs.length < 14) return null;
  const sys = Number(champs[4]);
  const delai = Number(champs[10]);
  const dispersion = Number(champs[11]);
  const saut = champs[13].trim();
  if (![sys, delai, dispersion].every(Number.isFinite)) return null;
  const synchronise = saut !== "Not synchronised";
  return { synchronized: synchronise, error_bound_ms: synchronise ? Math.round((Math.abs(sys) + dispersion + delai / 2) * 1e6) / 1e3 : null };
}

async function executer(commande, args, { timeoutMs = 10000 } = {}) {
  const { spawn } = await import("node:child_process");
  return new Promise((resolve) => {
    let sortie = "";
    let fini = false;
    let p;
    try {
      p = spawn(commande, args, { stdio: ["ignore", "pipe", "ignore"] });
    } catch {
      resolve({ code: null, sortie: "" });
      return;
    }
    const minuterie = setTimeout(() => { if (!fini) p.kill("SIGKILL"); }, timeoutMs);
    p.stdout.on("data", (d) => { sortie += d; });
    p.on("error", () => { fini = true; clearTimeout(minuterie); resolve({ code: null, sortie: "" }); });
    p.on("close", (code) => { if (fini) return; fini = true; clearTimeout(minuterie); resolve({ code, sortie }); });
  });
}

async function collecterHorloge() {
  const ch = await executer("chronyc", ["-c", "tracking"]);
  if (ch.code === 0) {
    const l = lireChronyc(ch.sortie);
    if (l) return { source: "chrony", ...l };
  }
  const td = await executer("timedatectl", ["show", "-p", "NTPSynchronized", "--value"]);
  if (td.code === 0 && /^(yes|no)$/.test(td.sortie.trim())) return { source: "timedatectl", synchronized: td.sortie.trim() === "yes", error_bound_ms: null };
  if (fs.existsSync("/run/systemd/timesync/synchronized")) return { source: "timesyncd", synchronized: true, error_bound_ms: null };
  return { source: "aucune", synchronized: null, error_bound_ms: null };
}

async function portLibre(address, port) {
  const net = await import("node:net");
  return new Promise((resolve) => {
    const srv = net.createServer();
    srv.once("error", () => resolve(false));
    srv.listen({ host: address, port, exclusive: true }, () => srv.close(() => resolve(true)));
  });
}

async function essaiSortie(host, port, { mandataire = false, delaiMs = 5000 } = {}) {
  const net = await import("node:net");
  const tls = await import("node:tls");
  const tcp = await new Promise((resolve) => {
    const s = net.connect({ host, port });
    const minuterie = setTimeout(() => { s.destroy(); resolve({ ok: false, result: "delai" }); }, delaiMs);
    s.once("connect", () => { clearTimeout(minuterie); resolve({ ok: true, socket: s }); });
    s.once("error", (e) => {
      clearTimeout(minuterie);
      resolve({ ok: false, result: e.code === "ENOTFOUND" || e.code === "EAI_AGAIN" ? "dns" : e.code === "ETIMEDOUT" ? "delai" : "refus" });
    });
  });
  if (!tcp.ok) return mandataire && (tcp.result === "refus" || tcp.result === "delai") ? "mandataire" : tcp.result;
  return new Promise((resolve) => {
    const t = tls.connect({ socket: tcp.socket, servername: host });
    const minuterie = setTimeout(() => { t.destroy(); resolve("delai"); }, delaiMs);
    t.once("secureConnect", () => { clearTimeout(minuterie); t.destroy(); resolve("ouvert"); });
    t.once("error", () => { clearTimeout(minuterie); t.destroy(); resolve("tls"); });
  });
}

const horodatageCourant = () => new Date().toISOString();

/** Une vérification demandée (--seulement absent : toutes). */
const demandee = (only, id) => !only || only.includes(id);

/**
 * Adresses des interfaces de l'hôte (os.networkInterfaces), pour dire si
 * NOORTRACE_IP_INTERNE en est une (IP-6).
 */
async function adressesHote() {
  const os = await import("node:os");
  return Object.values(os.networkInterfaces()).flat().filter(Boolean).map((i) => i.address);
}

/**
 * Collecte des observations sur l'hôte (EX-6.1, colonne « Mesure » d'EX-6.2).
 * Options : profil, configuration (objet ou null), cheminConfiguration
 * (fichier dont les droits sont relevés), ancrage (objet ou null),
 * texteCompose (ou null), nomCompose, description (images.json, ou null
 * quand ni IP-10 ni IP-12 ne sont demandées), secrets (répertoire ou null),
 * stockage (chemin ou null), mandataire (booléen), cacheProtege (booléen),
 * ipInterne (adresse qui remplace NOORTRACE_IP_INTERNE, ou null), only
 * (liste --seulement ou null), date (horodatage ou null), env (process.env).
 * Seules les mesures des vérifications demandées sont relevées : une
 * vérification non demandée ne lit rien et n'essaie aucune connexion. N'écrit
 * rien ; le rapport ne porte ni nom d'hôte ni contenu de fichier. Lève une
 * Error (usage invalide, code 2 de l'outil) si le répertoire des secrets est
 * illisible (relevé avant tout essai de réseau) ou si l'adresse interne
 * manque pour les ports de production ; un stockage illisible donne storage =
 * null (IP-3 et IP-4 non exécutées, mesure_absente). Le stockage est relevé
 * sur son chemin réel (liens symboliques résolus), et le système de fichiers
 * est celui qui porte ce chemin réel (IP-4).
 */
export async function collecterObservations({ profil, configuration = null, cheminConfiguration = null, ancrage = null, texteCompose = null, nomCompose = "compose.yaml", description = null, secrets = null, stockage = null, mandataire = false, cacheProtege = false, ipInterne = null, only = null, date = null, env = process.env }) {
  const os = await import("node:os");
  const dns = await import("node:dns");
  // Système et ressources.
  const obs = {
    version: 0,
    checked_at: date ?? horodatageCourant(),
    tool: VERSION_OUTIL,
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.availableParallelism(),
    memory_bytes: os.totalmem(),
  };
  // Droits, relevés avant tout essai de réseau : un répertoire des secrets illisible arrête la collecte.
  const mode = (st) => st.mode & 0o7777;
  const uidDemon = description ? uidService(description.services.enregistreur) : 10001;
  const droits = { uid: typeof process.getuid === "function" ? process.getuid() : 0, secrets_dir_mode: null, secret_files: [], config_mode: null, config_uid: null, config_expected_uid: uidDemon };
  if (demandee(only, "IP-10")) {
    let noms;
    try {
      const st = fs.statSync(secrets);
      if (!st.isDirectory()) throw new Error("pas un répertoire");
      droits.secrets_dir_mode = mode(st);
      noms = fs.readdirSync(secrets).sort();
    } catch (err) {
      throw new Error(`--secrets ${secrets} : répertoire illisible (${err.code ?? err.message})`);
    }
    for (const nom of noms) {
      const st = fs.lstatSync(path.join(secrets, nom));
      if (!st.isFile() || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(nom)) continue;
      droits.secret_files.push({ name: nom, mode: mode(st), uid: st.uid, expected_uid: uidAttenduSecret(nom, description) });
    }
    if (cheminConfiguration) {
      const st = fs.statSync(cheminConfiguration);
      droits.config_mode = mode(st);
      droits.config_uid = st.uid;
    }
  }
  // Stockage, sur son chemin réel.
  obs.storage = null;
  if (stockage !== null && (demandee(only, "IP-3") || demandee(only, "IP-4"))) {
    try {
      const chemin = fs.realpathSync(path.resolve(stockage));
      const st = fs.statfsSync(chemin);
      const mountinfo = fs.readFileSync("/proc/self/mountinfo", "utf8");
      obs.storage = { path: chemin, fstype: typeSystemeFichiers(chemin, mountinfo) ?? "inconnu", free_bytes: Number(BigInt(st.bavail) * BigInt(st.bsize)) };
    } catch {
      obs.storage = null;
    }
  }
  obs.clock = demandee(only, "IP-5") ? await collecterHorloge() : null;
  // Ports : rapide, ceux d'EX-6.2 ; production, les ports publiés du fichier Compose, sur l'adresse interne.
  let ports = [];
  obs.internal_address = null;
  if (demandee(only, "IP-6")) {
    if (profil === "rapide") ports = EXIGENCES.rapide.ports.map((p) => ({ ...p }));
    else {
      const interne = ipInterne ?? env.NOORTRACE_IP_INTERNE ?? null;
      const publies = texteCompose ? portsPublies(texteCompose) : [];
      if (publies.some((p) => p.host_ip && p.host_ip.startsWith("${NOORTRACE_IP_INTERNE"))) {
        if (!interne) throw new Error("l'adresse interne (--ip-interne ou NOORTRACE_IP_INTERNE) est requise pour relever les ports de production (CT-8 §4.3)");
        obs.internal_address = { address: interne, on_host: (await adressesHote()).includes(interne.replace(/^\[|\]$/g, "")) };
      }
      for (const p of publies) {
        let address = p.host_ip;
        if (address && address.startsWith("${NOORTRACE_IP_INTERNE")) address = interne;
        const port = Number(p.published);
        if (!ports.some((q) => q.address === address && q.port === port)) ports.push({ address, port });
      }
    }
  }
  obs.ports = [];
  for (const p of ports) obs.ports.push({ ...p, free: ADRESSES_TOUTES_INTERFACES.includes(p.address) ? false : await portLibre(p.address, p.port) });
  // Résolution des noms et sortie réseau (EX-6.5).
  const dests = demandee(only, "IP-7") || demandee(only, "IP-8") ? destinations(configuration, ancrage, { env }) : [];
  obs.dns = [];
  for (const d of dests) {
    if (obs.dns.some((x) => x.name === d.host)) continue;
    let adresses = [];
    try {
      adresses = (await dns.promises.lookup(d.host, { all: true })).map((a) => a.address);
    } catch {
      adresses = [];
    }
    obs.dns.push({ name: d.host, addresses: adresses });
  }
  const varsMandataire = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY"].some((k) => typeof env[k] === "string" && env[k] !== "");
  obs.egress = [];
  for (const d of demandee(only, "IP-8") ? dests : []) {
    const resolu = obs.dns.find((x) => x.name === d.host)?.addresses.length > 0;
    obs.egress.push({ flow: d.flow, host: d.host, port: d.port, result: resolu ? await essaiSortie(d.host, d.port, { mandataire: varsMandataire }) : "dns" });
  }
  obs.proxy = { declared: Boolean(mandataire), environment_set: varsMandataire };
  obs.rights = droits;
  // Moteur et Compose.
  obs.engine = demandee(only, "IP-11") ? { engine_ok: (await executer("docker", ["version"])).code === 0, compose_ok: (await executer("docker", ["compose", "version"])).code === 0 } : { engine_ok: false, compose_ok: false };
  if (texteCompose === null || description === null || !demandee(only, "IP-12")) obs.compose = null;
  else {
    const rap = verifierConteneurs(texteCompose, description, nomCompose);
    obs.compose = { file_sha256: rap.sha256, failed: rap.checks.filter((c) => c.status !== "reussi").map((c) => c.id), all_images_by_digest: rap.all_images_by_digest };
  }
  obs.declarations = { write_cache_protected: Boolean(cacheProtege) };
  return obs;
}

// ---------------------------------------------------------------------------
// Dimensionnement (CT-8 §9)
// ---------------------------------------------------------------------------

/**
 * Coefficients par défaut de la table de 9.2 (EX-9.1). `b_cap` (CT-8 0.2) :
 * capture d'une transaction d'un bloc plein de 64 transactions, telle que
 * CT-4 EX-9.2 l'écrit (en-tête, reçu de chaque transaction du bloc,
 * certificat, index), mesure TM-31 de CT-9 du 2026-11-02 : 109 479 octets de
 * fichiers JSON-RPC plus 14 282 octets d'index.
 */
export const COEFFICIENTS = Object.freeze({
  b_pt: 682,
  b_man: 916,
  b_tsq: 113,
  b_der: 3114,
  b_tsr_sup: 9,
  b_ots: 233,
  b_cap: 123761,
  gaz_ancre: 96977,
  gaz_cloture: 314256,
  tx_par_bloc: 64,
  blocs_par_s: 1.1,
  debit_cible: 500,
});

const r3 = (x) => Math.round(x * 1000) / 1000;
const r6 = (x) => Math.round(x * 1e6) / 1e6;
const c = Math.ceil;

/** Refus d'EX-9.3, journal par journal, dans l'ordre de la spécification. */
export function erreursDimensionnement(e) {
  const err = [];
  for (const j of e.journals) {
    const k = j.anchoring;
    if (3600 % k.checkpoint_interval_s !== 0) err.push({ journal: j.id, code: "checkpoint_interval_s_non_diviseur" });
    if (k.rfc3161_interval_s % k.checkpoint_interval_s !== 0 || 3600 % k.rfc3161_interval_s !== 0) err.push({ journal: j.id, code: "rfc3161_interval_s_invalide" });
    if (k.retention_years < 10) err.push({ journal: j.id, code: "retention_years_inferieure_a_10" });
    if (j.storage.worm && j.storage.worm.retain_days < 365 * j.storage.events_years) err.push({ journal: j.id, code: "retain_days_insuffisant" });
  }
  return err;
}

/**
 * Calculateur de dimensionnement (DM-1 à DM-22, EX-9.2, EX-9.3) : entrées
 * dimensionnement-v0 (racine, supposées valides contre le schéma), sortie
 * `$defs/sorties`. Double précision, chaque ligne de gauche à droite avec ses
 * parenthèses, arrondi unique en sortie.
 */
export function dimensionner(e) {
  const K = { ...COEFFICIENTS, ...(e.coefficients ?? {}) };
  const err = erreursDimensionnement(e);
  if (err.length) return { version: 0, valid: false, errors: err };
  const N_h = e.hours_per_year;
  const sorties = [];
  const tot = { journals: 0, local_bytes: 0, worm_bytes: 0, ops_archive_bytes: 0, tokens_qualified: 0, tokens_other: 0, registry_anchors: 0, registry_closures: 0, gas: 0, tx_per_hour: 0, peak_write_bytes_per_s: 0, peak_fsync_per_s: 0 };
  const Cap_h = K.tx_par_bloc * K.blocs_par_s * 3600; // DM-21
  for (const j of e.journals) {
    const a = j.activity;
    const s = j.storage;
    const k = j.anchoring;
    const m = j.memory;
    const E = a.agents * a.events_per_hour * a.active_hours; // DM-1
    const r_moy = (a.agents * a.events_per_hour) / 3600; // DM-2
    const r_pic = r_moy * a.peak_factor; // DM-3
    const V_e = E * a.event_bytes; // DM-4
    const V_p = E * a.piece_bytes_per_event; // DM-5
    const N_p = E * a.pieces_per_event;
    const n_T = 3600 / k.rfc3161_interval_s; // DM-6
    const d_q = k.provider_role === "principal" ? 1 : 0;
    const d_s = k.provider_role === "second_rang" || k.provider_role === "interne" ? 1 : 0;
    const d_r = k.registry_checkpoints === "aucun" ? 0 : 1;
    const N_q = N_h * (1 + d_q * (n_T - 1) * k.a);
    const N_s = N_h * d_s * (n_T - 1) * k.a;
    const N_a = N_h * (1 + d_r * (1 + 3600 / k.checkpoint_interval_s)); // DM-7
    const N_ots = N_h * (1 + (k.ots_checkpoint === "mi_periode" ? 1 : 0)); // DM-8
    const b_tok = K.b_tsq + K.b_der + (K.b_der + K.b_tsr_sup) + k.crl_per_token * k.crl_bytes + k.acquisition_bytes; // DM-9
    const V_anc = (N_q + N_s) * (1 + k.r) * b_tok + N_ots * K.b_ots;
    const V_pts = N_h * (3600 / k.checkpoint_interval_s + 1) * K.b_pt; // DM-10
    const V_man = N_h * K.b_man;
    const V_j = V_pts + V_man;
    const V_cap = (N_a + N_h) * K.b_cap; // DM-11
    const V_o = E * a.ops_log_bytes_per_event; // DM-12
    const W_pic = r_pic * (a.event_bytes + a.piece_bytes_per_event + a.ops_log_bytes_per_event); // DM-13
    const F_max = r_pic * (1 + a.write_share); // DM-14
    const F_min = r_pic / s.fsync.group_max_events + r_pic * a.write_share;
    const G = N_a * K.gaz_ancre + N_h * K.gaz_cloture; // DM-15
    const S_loc = (V_e + V_j) * (s.local_days / 365) + V_p * (s.pieces_days / 365) + (V_anc + V_cap) * k.retention_years
      + s.ops_log.keep_files * s.ops_log.rotate_max_bytes + s.pending_max_bytes + 2 * s.min_free_bytes; // DM-16
    const S_w = s.worm ? s.worm.copies * (V_e + V_j + V_anc + V_cap + (s.worm.pieces_in_worm ? 1 : 0) * V_p + (s.worm.ops_log_in_worm ? 1 : 0) * V_o) * (s.worm.retain_days / 365) : 0; // DM-17
    const A_o = V_o * (s.local_days / 365); // DM-18
    const M_tamp = m.max_concurrent * (m.request_max_bytes + m.response_max_bytes); // DM-19
    const T_j = (N_a + N_h) / N_h; // DM-20
    sorties.push({
      id: j.id,
      count: j.count,
      events_per_year: c(E),
      mean_events_per_s: r3(r_moy),
      peak_events_per_s: r3(r_pic),
      peak_over_target: r_pic > K.debit_cible,
      segment_bytes_per_year: c(V_e),
      piece_bytes_per_year: c(V_p),
      piece_files_per_year: c(N_p),
      checkpoint_bytes_per_year: c(V_pts),
      manifest_bytes_per_year: c(V_man),
      anchor_bytes_per_year: c(V_anc),
      capture_bytes_per_year: c(V_cap),
      ops_log_bytes_per_year: c(V_o),
      tokens_qualified_per_year: c(N_q),
      tokens_other_per_year: c(N_s),
      registry_anchors_per_year_max: c(N_a),
      registry_closures_per_year: c(N_h),
      ots_submissions_per_year: c(N_ots),
      registry_tx_per_hour_max: r3(T_j),
      registry_journals_max: Math.floor(Cap_h / T_j),
      gas_per_year_max: c(G),
      local_bytes: c(S_loc),
      worm_bytes: c(S_w),
      ops_archive_bytes: c(A_o),
      peak_write_bytes_per_s: c(W_pic),
      peak_fsync_per_s_max: r3(F_max),
      peak_fsync_per_s_min: r3(F_min),
      memory_buffers_max_bytes: c(M_tamp),
      memory_base_bytes: m.base_bytes === null ? null : m.base_bytes,
    });
    // DM-22 : sommes type par type, dans l'ordre des entrées.
    const J = j.count;
    tot.journals += J;
    tot.local_bytes += J * S_loc;
    tot.worm_bytes += J * S_w;
    tot.ops_archive_bytes += J * A_o;
    tot.tokens_qualified += J * N_q;
    tot.tokens_other += J * N_s;
    tot.registry_anchors += J * N_a;
    tot.registry_closures += J * N_h;
    tot.gas += J * G;
    tot.tx_per_hour += J * T_j;
    tot.peak_write_bytes_per_s += J * W_pic;
    tot.peak_fsync_per_s += J * F_max;
  }
  // EX-9.3 : une sortie entière qui dépasse 2^53 − 1 ne se représente pas exactement ; refus, jamais une sortie hors du schéma.
  const depasse = (o) => Object.values(o).some((v) => typeof v === "number" && (v > Number.MAX_SAFE_INTEGER || v * o.count > Number.MAX_SAFE_INTEGER));
  const totaux = [tot.local_bytes, tot.worm_bytes, tot.ops_archive_bytes, tot.tokens_qualified, tot.tokens_other, tot.registry_anchors, tot.registry_closures, tot.gas, tot.peak_write_bytes_per_s];
  const tropGrands = sorties.filter(depasse).map((j) => ({ journal: j.id, code: "depassement_capacite" }));
  if (!tropGrands.length && totaux.some((v) => c(v) > Number.MAX_SAFE_INTEGER)) tropGrands.push({ journal: sorties.at(-1).id, code: "depassement_capacite" });
  if (tropGrands.length) return { version: 0, valid: false, errors: tropGrands };
  return {
    version: 0,
    valid: true,
    journals: sorties,
    totals: {
      journals: tot.journals,
      local_bytes: c(tot.local_bytes),
      worm_bytes: c(tot.worm_bytes),
      ops_archive_bytes: c(tot.ops_archive_bytes),
      tokens_qualified_per_year: c(tot.tokens_qualified),
      tokens_other_per_year: c(tot.tokens_other),
      registry_anchors_per_year_max: c(tot.registry_anchors),
      registry_closures_per_year: c(tot.registry_closures),
      gas_per_year_max: c(tot.gas),
      registry_tx_per_hour_max: r3(tot.tx_per_hour),
      registry_capacity_tx_per_hour: r3(Cap_h),
      registry_capacity_share: r6(tot.tx_per_hour / Cap_h),
      peak_write_bytes_per_s: c(tot.peak_write_bytes_per_s),
      peak_fsync_per_s_max: r3(tot.peak_fsync_per_s),
    },
  };
}

/** Octets en Gio à trois décimales (résumés lisibles, tables de 9.5 et 9.6). */
export const gio = (octets) => (octets / GIO).toFixed(3);

/** Message français d'une erreur de node:util parseArgs (option inconnue, valeur manquante), sinon le message reçu. */
export function messageOptions(err) {
  const m = /'([^']+)'/.exec(err?.message ?? "");
  switch (err?.code) {
    case "ERR_PARSE_ARGS_UNKNOWN_OPTION":
      return `option inconnue : ${m ? m[1] : "?"}`;
    case "ERR_PARSE_ARGS_INVALID_OPTION_VALUE":
      return `valeur d'option invalide : ${err.message}`;
    case "ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL":
      return `argument inattendu : ${m ? m[1] : "?"}`;
    default:
      return err?.message ?? String(err);
  }
}

// ---------------------------------------------------------------------------
// Contenu de l'archive de déploiement (CT-8 EX-3.6)
// ---------------------------------------------------------------------------

/** Outils de scripts/deploiement/ que l'archive porte (renvois.mjs et extraire-runbooks.mjs sont des outils du dépôt, hors archive). */
export const OUTILS_ARCHIVE = Object.freeze(["archiver-journal-exploitation.mjs", "configurer-rapide.mjs", "consultations.mjs", "controle-prealable.mjs", "dimensionner.mjs", "proces-verbal.mjs", "rapport-observation.mjs", "sauvegarde.mjs", "verifier-conteneurs.mjs", "verifier-journal.mjs"]);

/** Bibliothèques de scripts/lib/ que ces outils importent, directement ou non. */
export const BIBLIOTHEQUES_ARCHIVE = Object.freeze(["approbation.mjs", "capture.mjs", "console.mjs", "deploiement.mjs", "exploitation.mjs", "journal.mjs", "noortrace.mjs", "ots.mjs", "sauvegarde.mjs", "securite.mjs"]);

/** package.json engendré pour la copie de la distribution ESM d'ethers (même forme que le paquet réviseur, CT-8 EX-13.21). */
function paquetEthersArchive(version) {
  return Buffer.from(JSON.stringify({ name: "ethers", version, type: "module", main: "./dist/ethers.js", exports: { ".": "./dist/ethers.js" }, license: "MIT", description: "Copie de dist/ethers.js de la distribution npm d'ethers, jointe à l'archive de déploiement (CT-8 EX-3.6)" }, null, 2) + "\n");
}

/** package.json engendré pour la copie de la distribution ESM de js-yaml. */
function paquetYamlArchive(version) {
  return Buffer.from(JSON.stringify({ name: "js-yaml", version, type: "module", main: "./dist/js-yaml.mjs", exports: { ".": "./dist/js-yaml.mjs" }, license: "MIT", description: "Copie de dist/js-yaml.mjs de la distribution npm de js-yaml, jointe à l'archive de déploiement (CT-8 EX-3.6)" }, null, 2) + "\n");
}

/**
 * Fichiers de l'archive de déploiement (EX-3.6) : chemin relatif à la racine
 * de l'archive -> octets, triés par chemin. deploiement/ entier (fichiers de
 * conteneur, description des images, configurations, LISEZMOI.md), les outils
 * d'OUTILS_ARCHIVE, les bibliothèques de BIBLIOTHEQUES_ARCHIVE, les schémas de
 * spec/schemas/, la liste des clés de test publiées (CT-7 CLE-28, pour la règle
 * approbateurs_de_test de CT-2 EX-15.8), LICENSE et NOTICE, et une copie figée
 * des deux seules dépendances (dist ESM d'ethers et de js-yaml, avec leur
 * licence). Elle s'exécute avec Node.js 22, sans npm et sans réseau.
 */
export function fichiersArchive(racine = RACINE) {
  const r = new Map();
  const ajouter = (rel, octets = fs.readFileSync(path.join(racine, rel))) => r.set(rel, octets);
  const parcourir = (rel) => {
    for (const e of fs.readdirSync(path.join(racine, rel), { withFileTypes: true })) {
      const p = `${rel}/${e.name}`;
      if (e.isDirectory()) parcourir(p);
      else if (e.isFile()) ajouter(p);
    }
  };
  parcourir("deploiement");
  for (const o of OUTILS_ARCHIVE) ajouter(`scripts/deploiement/${o}`);
  for (const b of BIBLIOTHEQUES_ARCHIVE) ajouter(`scripts/lib/${b}`);
  for (const s of fs.readdirSync(path.join(racine, "spec", "schemas")).filter((n) => n.endsWith(".schema.json"))) ajouter(`spec/schemas/${s}`);
  ajouter("spec/vecteurs/ct-7/cles-de-test.json");
  ajouter("LICENSE");
  ajouter("NOTICE");
  const nm = path.join(racine, "node_modules");
  const vEthers = JSON.parse(fs.readFileSync(path.join(nm, "ethers", "package.json"), "utf8")).version;
  r.set("node_modules/ethers/package.json", paquetEthersArchive(vEthers));
  ajouter("node_modules/ethers/dist/ethers.js");
  ajouter("node_modules/ethers/LICENSE.md");
  const vYaml = JSON.parse(fs.readFileSync(path.join(nm, "js-yaml", "package.json"), "utf8")).version;
  r.set("node_modules/js-yaml/package.json", paquetYamlArchive(vYaml));
  ajouter("node_modules/js-yaml/dist/js-yaml.mjs");
  ajouter("node_modules/js-yaml/LICENSE");
  return new Map([...r.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}
