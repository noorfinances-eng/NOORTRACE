// Scénario TI-13 du SDK JavaScript `noortrace-sdk` (CT-2 6.5), le même que
// `scenario.py` pour le SDK Python : mêmes étapes, mêmes arguments, mêmes
// sorties normalisées (une entrée par étape), pour comparer les deux
// langages. Les noms d'exception sont ramenés à ceux du SDK Python par la
// table d'EX-6.12 (`ErreurNoortraceIndisponible` → `NoortraceIndisponible`…).

import { ClientNoortrace, AppelNonAutorise, ErreurNoortrace } from "noortrace-sdk";

/** Table d'EX-6.12 : classe TypeScript → classe Python. */
export const CLASSES_EX_6_12 = Object.freeze({
  ErreurNoortraceIndisponible: "NoortraceIndisponible",
  ErreurNoortraceDegrade: "NoortraceDegrade",
  ErreurNoortraceLimite: "NoortraceLimite",
  ErreurNoortraceNonDurable: "NoortraceNonDurable",
  ErreurNoortraceEntreeInvalide: "NoortraceEntreeInvalide",
  ErreurNoortrace: "NoortraceErreur",
  AppelNonAutorise: "AppelNonAutorise",
  ErreurNoortraceConfiguration: "NoortraceConfiguration",
});

const debut = (d) => ({ call: d.call !== null && d.call !== undefined, decision: d.decision, ticket: d.ticket !== null && d.ticket !== undefined, ticket_state: d.ticket_state ?? null });

function erreur(e) {
  const r = { classe: CLASSES_EX_6_12[e.constructor.name] ?? e.constructor.name };
  for (const k of ["envoyee", "raison", "decision", "ticket_state"]) if (k in e) r[k] = e[k];
  if ("ticket" in e) r.ticket = e.ticket !== null && e.ticket !== undefined;
  return r;
}

/** Étapes de l'interface publique, démon en marche. */
export async function interface_(prise, runId) {
  const sorties = [];
  const sortie = (etape, valeur) => sorties.push({ etape, valeur });
  const session = await new ClientNoortrace({ socket: prise, delaiMs: 10000 }).ouvrir({ runId });
  const ref = await session.declarerContexte({ kind: "autre", octets: '{"note":"contexte ti13"}', mediaType: "application/json" });
  sortie("declarer_contexte", { sha256: ref.sha256, length: ref.length, redacted: ref.redacted });
  const d1 = await session.debutAppel({ tool: "lire_fiche", arguments: { id: "F1" }, classe: "lecture", contexte: [ref.sha256] });
  sortie("debut_appel_lecture", debut(d1));
  const s1 = await session.finAppel(d1, { resultat: { fiche: "F1", etat: "ouverte" }, isError: false, durationMs: 5 });
  sortie("fin_appel", { seq: Number.isInteger(s1.seq), hash: typeof s1.hash === "string" && s1.hash.length === 66 });
  const executions = [];
  const ecrireNote = ({ id }) => {
    executions.push(id);
    return { ok: true, id };
  };
  const r2 = await session.appelOutil({ tool: "ecrire_note", arguments: { id: "F1", note: "relue" }, classe: "ecriture" }, ecrireNote);
  sortie("appel_outil_ecriture", { resultat: r2, executions: executions.length });
  sortie("debut_appel_a_approuver", debut(await session.debutAppel({ tool: "approuver_virement", arguments: { montant: "9000.00" }, classe: "ecriture" })));
  sortie("debut_appel_refuse", debut(await session.debutAppel({ tool: "refuser_virement", arguments: { montant: "1.00" }, classe: "ecriture" })));
  try {
    await session.appelOutil({ tool: "refuser_virement", arguments: { montant: "2.00" }, classe: "ecriture" }, ecrireNote);
    sortie("appel_outil_refuse", "aucune exception");
  } catch (e) {
    if (!(e instanceof AppelNonAutorise)) throw e;
    sortie("appel_outil_refuse", { ...erreur(e), texte: e.texte, executions: executions.length });
  }
  const e5 = await session.echangeModele({ format: "autre", providerLabel: "simule", request: { q: "statut" }, response: { r: "ouvert" }, status: 200, durationMs: 3, isError: false });
  sortie("echange_modele", { seq: Number.isInteger(e5.seq), hash: typeof e5.hash === "string" });
  sortie("fermer", await session.fermer());
  return sorties;
}

/** Démon arrêté après l'ouverture d'une session : `couper()` l'arrête. */
export async function arrete(prise, runId, couper) {
  const sorties = [];
  const sortie = (etape, valeur) => sorties.push({ etape, valeur });
  const session = await new ClientNoortrace({ socket: prise, delaiMs: 2000, reprises: 0 }).ouvrir({ runId });
  await couper();
  const executions = [];
  try {
    await session.appelOutil({ tool: "ecrire_note", arguments: { id: "F2", note: "x" }, classe: "ecriture" }, ({ id }) => executions.push(id));
    sortie("appel_outil_demon_arrete", "aucune exception");
  } catch (e) {
    if (!(e instanceof ErreurNoortrace)) throw e;
    sortie("appel_outil_demon_arrete", { ...erreur(e), executions: executions.length });
  }
  try {
    await new ClientNoortrace({ socket: prise, delaiMs: 2000, reprises: 0 }).ouvrir({ runId });
    sortie("ouvrir_demon_arrete", "aucune exception");
  } catch (e) {
    if (!(e instanceof ErreurNoortrace)) throw e;
    sortie("ouvrir_demon_arrete", erreur(e));
  }
  return sorties;
}

/** Prise d'un démon muet : `ouvrir` au-delà de `delai_s`. */
export async function muet(prise, runId) {
  try {
    await new ClientNoortrace({ socket: prise, delaiMs: 500, reprises: 0 }).ouvrir({ runId });
    return [{ etape: "ouvrir_demon_muet", valeur: "aucune exception" }];
  } catch (e) {
    if (!(e instanceof ErreurNoortrace)) throw e;
    return [{ etape: "ouvrir_demon_muet", valeur: erreur(e) }];
  }
}
