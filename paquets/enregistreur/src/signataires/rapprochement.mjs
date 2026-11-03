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
// Codes : 0 sans écart positif ; 3 écart positif (incident, CT-7 4.6) ; 2 usage.

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

/**
 * Compte des opérations de signature réussies d'un journal d'audit Vault/OpenBao.
 * @param {string} texte journal d'audit (lignes JSON)
 * @param {{mount: string, nom: string, de?: number|null, a?: number|null}} o
 */
export function compterAuditTransit(texte, o) {
  const chemin = `${o.mount.replace(/^\/+|\/+$/g, "")}/sign/${o.nom}`;
  let n = 0;
  for (const e of lignesJson(texte)) {
    if (e.type !== "response" || e.error) continue;
    if (e.request?.path !== chemin || e.request?.operation !== "update") continue;
    if (!dans(instant(e.time), o.de ?? null, o.a ?? null)) continue;
    n++;
  }
  return n;
}

/**
 * Objets signés par `keyId` dans un répertoire de journal, et signatures hors
 * journal consignées au journal d'exploitation, sur [de, a).
 * @param {{repertoire: string, journalExploitation: string|null, keyId: string, de?: number|null, a?: number|null}} o
 */
export async function compterObjetsSignes(o) {
  const de = o.de ?? null;
  const a = o.a ?? null;
  const c = { evenements: 0, contresignatures: 0, manifestes: 0, points: 0, signatures_de_test: 0, tentatives_non_servies: 0 };
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
      for (const l of lignesJson(fs.readFileSync(f, "utf8"))) {
        if (!dans(instant(l.ts), de, a)) continue;
        if (l.event === "signer_test_signature" && l.data?.key_id === o.keyId) c.signatures_de_test++;
        if (l.event === "signer_unavailable" && l.data?.key_id === o.keyId) c.tentatives_non_servies += Number(l.data?.tentatives ?? 0);
      }
    }
  }
  return c;
}

/**
 * Rapprochement d'une clé (EX-3.7) : écart = opérations du backend − objets
 * signés − signatures hors journal consignées. Un écart positif est un
 * incident ; un écart négatif n'est pas qualifié (« compte inférieur »).
 * @param {{audit: string, mount: string, nom: string, repertoire: string, journalExploitation: string|null, keyId: string, de?: number|null, a?: number|null}} o
 */
export async function rapprocher(o) {
  const backend = compterAuditTransit(o.audit, o);
  const objets = await compterObjetsSignes(o);
  const justifiees = objets.evenements + objets.contresignatures + objets.manifestes + objets.points + objets.signatures_de_test + objets.tentatives_non_servies;
  const ecart = backend - justifiees;
  return { key_id: o.keyId, backend_operations: backend, objets, justifiees, ecart, incident: ecart > 0 };
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
  return r.incident ? 3 : 0;
}
