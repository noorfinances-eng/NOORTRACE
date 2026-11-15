// Rapprochement des signatures (CT-7 EX-3.7 ; CT-9 TA-31, MN-31) : « compter
// les opérations de signature que le journal d'audit du backend attribue à
// l'identité d'usage de la clé sur un intervalle, et les comparer au nombre
// d'objets signés par cette clé dans le journal sur le même intervalle :
// événements, manifestes, points de contrôle et contresignatures de
// rotation […]. Un compte du backend supérieur est un incident de
// compromission (4.6). » « Cette version ne qualifie pas un compte
// inférieur ».
//
// Backend lu : journal d'audit `file` de Vault ou d'OpenBao (une ligne JSON
// par entrée ; réponses `type: "response"` de `update` sur
// `<mount>/sign/<nom>` sans `error`, datées par `time`) ; les autres
// backends (CloudTrail, Cloud Audit Logs) ne sont pas lus (LISEZMOI, lecture
// 195). Objets signés comptés : événements (`recorder_key_id`, `ts`),
// contresignatures de rotation (`new_key_id`, `ts` de la rotation),
// manifestes (`recorder_key_id` du fichier `.sig`, `generated_at`), points
// de contrôle (`key_id`, `checkpoint_ts`). Le démon signe aussi hors du
// journal : signatures de test (démarrage, sortie du mode « clé ») et
// tentatives dont la signature n'a pas servi ; il les consigne
// (`signer_test_signature`, `signer_unavailable.tentatives`) : elles sont
// comptées à part, d'après le journal d'exploitation, et justifient autant
// d'opérations du backend.
//
//   noortrace-ctl cle rapprocher --configuration <fichier> --audit <journal d'audit>
//                                [--cle <key_id>] [--de <horodatage>] [--a <horodatage>]
// Codes : 0 sans écart positif ; 3 écart positif, écart non fini ou lot
// indéterminé (incident, CT-7 4.6) ; 1 anomalie sans incident (ligne du
// journal d'exploitation hors des valeurs que le démon écrit, ligne d'audit
// sur la clé non classée) ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { annonceRotation, decoderHorodatage } from "@noortrace/noyau";
import { lireEvenements } from "../dossier.mjs";

const dans = (t, de, a) => t !== null && !Number.isNaN(t) && (de === null || t >= de) && (a === null || t < a);
const lignesJson = (texte) =>
  String(texte)
    .split("\n")
    .filter(Boolean)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
const instant = (x) => {
  if (typeof x !== "string") return null;
  const t = Date.parse(x);
  return Number.isNaN(t) ? null : t;
};

/** Valeur admise de `signer_unavailable.tentatives` : entier de 0 à 2 (le démon n'en écrit jamais plus, `signataires.mjs`). */
export const TENTATIVES_MAX = 2;

/**
 * Analyse du journal d'audit Vault/OpenBao pour une clé (étape 8, CT-7 EX-3.7) :
 *   - `operations` : réponses `update` sans erreur dont le chemin est
 *     `<mount>/sign/<nom>` ou commence par `<mount>/sign/<nom>/` (algorithme
 *     dans l'URL, barre finale) ; une requête par lot (`request.data.batch_input`
 *     en tableau, valeurs HMAC comprises) compte autant d'opérations que
 *     d'entrées ;
 *   - `lots_indetermines` : requêtes par lot dont le nombre d'entrées n'est pas
 *     lisible (lot présent mais non tableau) : chacune vaut un incident ;
 *   - `non_classees` : toute autre ligne sans erreur qui touche la clé sous
 *     `<mount>/` (`export/…/<nom>`, `keys/<nom>/config`, `keys/<nom>/rotate`,
 *     écriture ou suppression de `keys/<nom>`…), que l'outil ne sait pas
 *     classer : chacune est une anomalie (code de retour non nul) ; la lecture
 *     de `keys/<nom>` (clé publique, faite par le démon) est classée et comptée
 *     à part (`lectures_cle`).
 * @param {string} texte journal d'audit (lignes JSON)
 * @param {{mount: string, nom: string, de?: number|null, a?: number|null}} o
 * @returns {{operations: number, lots_indetermines: number, lectures_cle: number, non_classees: {time: string|null, path: string, operation: string|null}[]}}
 */
export function analyserAuditTransit(texte, o) {
  const mount = o.mount.replace(/^\/+|\/+$/g, "");
  const chemin = `${mount}/sign/${o.nom}`;
  const r = { operations: 0, lots_indetermines: 0, lectures_cle: 0, non_classees: [] };
  for (const e of lignesJson(texte)) {
    if (e.type !== "response" || e.error) continue;
    if (!dans(instant(e.time), o.de ?? null, o.a ?? null)) continue;
    const p = typeof e.request?.path === "string" ? e.request.path.replace(/^\/+/, "") : null;
    if (p === null || !p.startsWith(`${mount}/`)) continue;
    const segments = p.split("/").filter(Boolean);
    if (!segments.includes(o.nom)) continue;
    const operation = typeof e.request?.operation === "string" ? e.request.operation : null;
    if ((p === chemin || p.startsWith(`${chemin}/`)) && operation === "update") {
      const lot = e.request?.data?.batch_input;
      if (lot === undefined || lot === null) r.operations++;
      else if (Array.isArray(lot)) r.operations += lot.length;
      else r.lots_indetermines++;
      continue;
    }
    if (p === `${mount}/keys/${o.nom}` && operation === "read") {
      r.lectures_cle++;
      continue;
    }
    if (r.non_classees.length < 1000) r.non_classees.push({ time: typeof e.time === "string" ? e.time.slice(0, 64) : null, path: p.slice(0, 256), operation: operation?.slice(0, 32) ?? null });
  }
  return r;
}

/**
 * Compte des opérations de signature réussies d'un journal d'audit Vault/OpenBao
 * (voir `analyserAuditTransit`, membre `operations`).
 * @param {string} texte journal d'audit (lignes JSON)
 * @param {{mount: string, nom: string, de?: number|null, a?: number|null}} o
 */
export function compterAuditTransit(texte, o) {
  return analyserAuditTransit(texte, o).operations;
}

/**
 * Objets signés par `keyId` dans un répertoire de journal, et signatures hors
 * journal consignées au journal d'exploitation, sur [de, a).
 * @param {{repertoire: string, journalExploitation: string|null, keyId: string, de?: number|null, a?: number|null}} o
 */
export async function compterObjetsSignes(o) {
  const de = o.de ?? null;
  const a = o.a ?? null;
  const c = { evenements: 0, contresignatures: 0, manifestes: 0, points: 0, signatures_de_test: 0, tentatives_non_servies: 0, anomalies: [] };
  const evts = fs.existsSync(path.join(o.repertoire, "segments")) ? await lireEvenements(o.repertoire) : [];
  for (const e of evts) {
    const t = decoderHorodatage(e.ts);
    if (!dans(t, de, a)) continue;
    if (e.recorder_key_id === o.keyId) c.evenements++;
    if (e.execution?.tool === "noortrace.journal.rotation-cle" && annonceRotation(e)?.new_key_id === o.keyId) c.contresignatures++;
  }
  const dirM = path.join(o.repertoire, "manifestes");
  for (const f of fs.existsSync(dirM) ? fs.readdirSync(dirM).filter((x) => x.endsWith(".sig")) : []) {
    const s = JSON.parse(fs.readFileSync(path.join(dirM, f), "utf8"));
    if (s.recorder_key_id !== o.keyId) continue;
    const m = JSON.parse(fs.readFileSync(path.join(dirM, f.replace(/\.sig$/, ".json")), "utf8"));
    if (dans(instant(m.generated_at), de, a)) c.manifestes++;
  }
  const dirP = path.join(o.repertoire, "points");
  for (const f of fs.existsSync(dirP) ? fs.readdirSync(dirP) : []) {
    for (const p of lignesJson(fs.readFileSync(path.join(dirP, f), "utf8"))) {
      if (p.key_id === o.keyId && dans(typeof p.checkpoint_ts === "number" ? p.checkpoint_ts * 1000 : instant(p.checkpoint_ts), de, a)) c.points++;
    }
  }
  if (o.journalExploitation) {
    // Journal courant et fichiers tournés (<chemin>.1 … <chemin>.<keep_files>).
    const fichiers = [];
    for (let k = 0, f = o.journalExploitation; fs.existsSync(f); f = `${o.journalExploitation}.${++k}`) fichiers.push(f);
    for (const f of fichiers) {
      let numero = 0;
      for (const l of lignesJson(fs.readFileSync(f, "utf8"))) {
        numero++;
        if (!dans(instant(l.ts), de, a)) continue;
        if (l.event === "signer_test_signature" && l.data?.key_id === o.keyId) c.signatures_de_test++;
        if (l.event === "signer_unavailable" && l.data?.key_id === o.keyId) {
          // Le journal d'exploitation n'est pas signé (étape 8, CT-7 MN-96) : seule une
          // valeur que le démon peut écrire (entier de 0 à TENTATIVES_MAX) justifie
          // des opérations ; toute autre est une anomalie, qui ne justifie rien.
          const t = l.data && Object.hasOwn(l.data, "tentatives") ? l.data.tentatives : 0;
          if (Number.isSafeInteger(t) && t >= 0 && t <= TENTATIVES_MAX) c.tentatives_non_servies += t;
          else if (c.anomalies.length < 1000) c.anomalies.push({ fichier: f, ligne: numero, raison: `tentatives hors de 0 à ${TENTATIVES_MAX}`, valeur: typeof t === "number" ? t : typeof t });
        }
      }
    }
  }
  return c;
}

/**
 * Rapprochement d'une clé (EX-3.7) : écart = opérations du backend − objets
 * signés − signatures hors journal consignées. Un écart positif est un
 * incident ; un écart négatif n'est pas qualifié (« compte inférieur »).
 * Étape 8 (CT-7 MN-96) : un écart qui n'est pas un nombre fini et un
 * lot d'entrées indéterminé valent incident ; les lignes du journal
 * d'exploitation hors des valeurs que le démon écrit et les lignes d'audit non
 * classées sont des `anomalies` ; les objets sont comptés d'après leurs champs
 * (`signatures_verifiees: false`) ; `justifiees_par_journal_exploitation` isole
 * ce que seul le journal d'exploitation, non signé, justifie.
 * @param {{audit: string, mount: string, nom: string, repertoire: string, journalExploitation: string|null, keyId: string, de?: number|null, a?: number|null}} o
 */
export async function rapprocher(o) {
  const audit = analyserAuditTransit(o.audit, o);
  const backend = audit.operations;
  const objets = await compterObjetsSignes(o);
  const parJournalExploitation = objets.signatures_de_test + objets.tentatives_non_servies;
  const justifiees = objets.evenements + objets.contresignatures + objets.manifestes + objets.points + parJournalExploitation;
  const ecart = backend - justifiees;
  const anomalies = [
    ...objets.anomalies,
    ...audit.non_classees.map((x) => ({ raison: "ligne_audit_non_classee", ...x })),
  ];
  const { anomalies: _a, ...comptes } = objets;
  void _a;
  return {
    key_id: o.keyId,
    backend_operations: backend,
    lots_indetermines: audit.lots_indetermines,
    lectures_cle: audit.lectures_cle,
    objets: comptes,
    justifiees,
    justifiees_par_journal_exploitation: parJournalExploitation,
    signatures_verifiees: false,
    ecart,
    anomalies,
    incident: !Number.isFinite(ecart) || ecart > 0 || audit.lots_indetermines > 0,
  };
}

/**
 * `noortrace-ctl cle rapprocher` (voir l'en-tête).
 * @param {string[]} argv arguments après `cle rapprocher`
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream}} [io]
 * @returns {Promise<number>}
 */
export async function principalRapprochement(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const usage = "usage : noortrace-ctl cle rapprocher --configuration <fichier> --audit <journal d'audit> [--cle <key_id>] [--de <horodatage>] [--a <horodatage>]";
  const o = {};
  for (let k = 0; k < argv.length; k += 2) {
    const nom = argv[k];
    if (!["--configuration", "--audit", "--cle", "--de", "--a"].includes(nom) || k + 1 >= argv.length || nom.slice(2) in o) {
      stderr.write(`${usage}\n`);
      return 2;
    }
    o[nom.slice(2)] = argv[k + 1];
  }
  if (!o.configuration || !o.audit) {
    stderr.write(`${usage}\n`);
    return 2;
  }
  let config;
  let audit;
  try {
    config = JSON.parse(fs.readFileSync(o.configuration, "utf8"));
    audit = fs.readFileSync(o.audit, "utf8");
  } catch {
    stderr.write("noortrace-ctl cle rapprocher : configuration ou journal d'audit illisible\n");
    return 2;
  }
  const b = config.signer?.backend;
  if (!b || (b.type !== "vault-transit" && b.type !== "openbao-transit")) {
    stderr.write("noortrace-ctl cle rapprocher : seul un journal d'audit Vault/OpenBao est lu (classe B Transit)\n");
    return 2;
  }
  const keyId = o.cle ?? config.signer.key_id;
  const nom = keyId === config.signer.key_id ? b.key_name : keyId;
  const de = o.de ? instant(o.de) : null;
  const a = o.a ? instant(o.a) : null;
  if ((o.de && de === null) || (o.a && a === null)) {
    stderr.write("--de, --a : horodatage RFC 3339 attendu\n");
    return 2;
  }
  const repertoire = path.join(config.storage.root, config.recorder.org_id.replace(/^0x/, ""), config.recorder.journal_id.replace(/^0x/, ""));
  const r = await rapprocher({ audit, mount: b.mount, nom, repertoire, journalExploitation: config.supervision?.ops_log?.path ?? null, keyId, de, a });
  stdout.write(`${JSON.stringify(r)}\n`);
  // Codes : 3 incident ; 1 anomalie sans incident (ligne du journal d'exploitation hors valeurs admises, ligne d'audit non classée) ; 0 sinon.
  return r.incident ? 3 : r.anomalies.length ? 1 : 0;
}
