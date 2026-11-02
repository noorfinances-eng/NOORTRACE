// Fil de calcul de la rédaction (CT-2 EX-3.6) : la rédaction des pièces,
// l'exécution des motifs sous la borne d'EX-10.23, l'analyse et la
// sérialisation des pièces s'exécutent ici, hors des fils d'entrée-sortie,
// de l'écrivain et du bail. Le fil reçoit la politique compilable (document
// et clé de pseudonymisation) et des travaux ; il rend les octets des pièces
// par transfert, sans copie.

import { parentPort, workerData } from "node:worker_threads";
import { PolitiqueCompilee, executerOperation } from "./redaction-moteur.mjs";

let politique = null;
let budgetMs = 1000;

function charger(d) {
  politique = new PolitiqueCompilee(d.doc, { cle: d.cle ? new Uint8Array(d.cle) : null });
  budgetMs = d.budgetMs;
}

/** Tampon transférable propre à une vue (copié s'il est partagé). */
function propre(octets, transfert) {
  let o = octets;
  if (o.byteOffset !== 0 || o.byteLength !== o.buffer.byteLength || transfert.includes(o.buffer)) o = o.slice();
  transfert.push(o.buffer);
  return o;
}

function exporter(r, transfert) {
  if (r && typeof r === "object" && r.piece) {
    const sortie = { ...r, piece: { octets: propre(r.piece.octets, transfert), reference: r.piece.reference } };
    if (r.original) sortie.original = propre(r.original, transfert);
    return sortie;
  }
  return r;
}

if (workerData) charger(workerData);

parentPort.on("message", (m) => {
  if (m.type === "politique") {
    charger(m);
    return;
  }
  if (m.type !== "travail") return;
  parentPort.postMessage({ id: m.id, debut: true });
  try {
    const r = executerOperation(politique, budgetMs, m.op, m.args, { longueur: (n) => parentPort.postMessage({ id: m.id, longueur: n }) });
    const transfert = [];
    const sortie = exporter(r, transfert);
    parentPort.postMessage({ id: m.id, ok: true, r: sortie }, transfert);
  } catch (e) {
    parentPort.postMessage({ id: m.id, ok: false, erreur: { name: e?.name ?? "Error", message: String(e?.message ?? e) } });
  }
});
