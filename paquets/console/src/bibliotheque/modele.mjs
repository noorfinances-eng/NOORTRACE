// Modèle d'affichage d'un ticket (CT-3 EX-9.4, EX-9.6, EX-9.15 à EX-9.19,
// EX-12.14 ; `$defs/modele_affichage` de console-approbation-v0) : les treize
// contrôles d'EX-9.15, dans l'ordre et avec leurs sauts, sur une vue reçue
// après le choix de la décision et de l'adresse ; vérification de l'événement
// `retenue` et de la pièce « arguments » (EX-9.6 a et b), champs liés (c),
// arguments feuille par feuille (d, EX-9.16, pointeurs d'EX-4.4), formation
// de `A` et contrôle croisé des condensés du service (EX-9.17), empreintes
// (EX-9.18), avertissements dans l'ordre d'EX-9.15 (`condense_utf8` d'EX-9.19,
// `separation_non_verifiable`, `membres_ajoutes`, `separation_incomplete`
// d'EX-13.18) ; et l'objet `session` du contexte tiré de l'annuaire (EX-9.15,
// contrôles 9 et 12).

import { condenses, hachageEvenement } from "./condenses.mjs";
import { sha256 } from "./hachage.mjs";
import { analyserJsonStrict, cloner, egaliteJson, jcs } from "./json.mjs";
import { decoderInstant, instantParametre } from "./instants.mjs";
import { decoderBase64, longueurPointsDeCode, utf8Strict, versHex } from "./octets.mjs";

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const aCle = (o, c) => estObjet(o) && Object.prototype.hasOwnProperty.call(o, c);

/** Membre d'un objet, ou `undefined` (aucun accès à travers une valeur qui n'est pas un objet). */
function membre(v, ...chemin) {
  let x = v;
  for (const c of chemin) {
    if (!aCle(x, c)) return undefined;
    x = x[c];
  }
  return x;
}

const echapper = (nom) => nom.replace(/~/g, "~0").replace(/\//g, "~1");

/**
 * Feuilles d'une valeur JSON (EX-9.16) : pointeur et valeur, membres d'un
 * objet dans l'ordre JCS des noms, éléments d'un tableau dans l'ordre.
 * @param {unknown} racine
 * @returns {{pointer: string, value: unknown}[]}
 */
export function feuilles(racine) {
  const sortie = [];
  const pile = [{ v: racine, p: "" }];
  while (pile.length) {
    const { v, p } = pile.pop();
    if (Array.isArray(v) && v.length > 0) {
      for (let k = v.length - 1; k >= 0; k--) pile.push({ v: v[k], p: `${p}/${k}` });
    } else if (estObjet(v) && Object.keys(v).length > 0) {
      const noms = Object.keys(v).sort();
      for (let k = noms.length - 1; k >= 0; k--) pile.push({ v: v[noms[k]], p: `${p}/${echapper(noms[k])}` });
    } else {
      sortie.push({ pointer: p, value: v });
    }
  }
  return sortie;
}

/**
 * Résolution d'un pointeur selon les pas 1 et 2 d'EX-4.4, appliqués à une
 * valeur : `{ resolu, valeur }`.
 * @param {unknown} racine
 * @param {string} pointeur
 */
export function resoudrePointeur(racine, pointeur) {
  if (pointeur === "") return { resolu: true, valeur: racine };
  const jetons = pointeur.slice(1).split("/").map((j) => j.replace(/~1/g, "/").replace(/~0/g, "~"));
  let x = racine;
  for (const j of jetons) {
    if (estObjet(x) && Object.prototype.hasOwnProperty.call(x, j)) x = x[j];
    else if (Array.isArray(x) && /^(0|[1-9][0-9]{0,8})$/.test(j) && Number(j) < x.length) x = x[Number(j)];
    else return { resolu: false, valeur: undefined };
  }
  return { resolu: true, valeur: x };
}

// Contrôle 2 (EX-9.6 a) : hachage recalculé de l'événement `retenue`, ou null.
function evenementVerifie(vue) {
  const e = vue.retained_event;
  if (!estObjet(e)) return null;
  if (membre(e, "execution", "status") !== "retenue") return null;
  if (membre(e, "policy", "decision") !== "a_approuver") return null;
  if (typeof vue.ticket !== "string" || membre(e, "policy", "ticket") !== vue.ticket) return null;
  // A se forme de ces membres (EX-9.17) : des chaînes, sans quoi l'événement n'est pas retenu.
  if (typeof e.org_id !== "string" || typeof e.journal_id !== "string") return null;
  let h;
  try {
    h = hachageEvenement(e);
  } catch {
    return null;
  }
  return h === e.hash && h === vue.request_hash ? h : null;
}

// Contrôle 3 (EX-9.6 b) : valeur de la pièce « arguments » vérifiée, ou
// `{ ok: false }`.
function pieceVerifiee(vue) {
  const ref = membre(vue, "retained_event", "execution", "arguments");
  if (!estObjet(ref) || typeof ref.sha256 !== "string" || !Number.isSafeInteger(ref.length)) return { ok: false };
  if (vue.arguments_piece !== null) {
    if (typeof vue.arguments_piece !== "string") return { ok: false };
    const octets = decoderBase64(vue.arguments_piece);
    if (octets === null || versHex(sha256(octets)) !== ref.sha256 || octets.length !== ref.length) return { ok: false };
    try {
      return { ok: true, valeur: analyserJsonStrict(octets) };
    } catch {
      return { ok: false };
    }
  }
  if (!aCle(ref, "value")) return { ok: false };
  let octets;
  try {
    octets = utf8Strict(jcs(ref.value));
  } catch {
    return { ok: false };
  }
  if (versHex(sha256(octets)) !== ref.sha256 || octets.length !== ref.length) return { ok: false };
  return { ok: true, valeur: ref.value };
}

// Contrôle 4 (EX-9.6 c) : champs liés égaux à l'événement.
function champsLies(vue) {
  const e = vue.retained_event;
  const r = vue.request;
  const egaux = (a, b) => a !== undefined && a === b;
  if (!egaux(membre(e, "execution", "tool"), membre(r, "tool_announced"))) return false;
  if (!egaux(membre(e, "policy", "rule"), membre(vue, "rule", "policy_rule"))) return false;
  if (!egaux(membre(e, "org_id"), vue.org_id) || !egaux(membre(e, "journal_id"), vue.journal_id)) return false;
  for (const k of ["launched_by", "on_behalf_of", "scope", "run_id"]) {
    if (!aCle(membre(e, "delegation"), k) || !aCle(membre(r, "delegation"), k) || e.delegation[k] !== r.delegation[k]) return false;
  }
  const intention = membre(e, "intent");
  if (typeof intention === "string" && intention !== membre(r, "intent")) return false;
  return true;
}

const ETATS_VOTE = Object.freeze(["ouvert", "seuil_atteint", "verification"]);
const JETONS = Object.freeze(["[REDIGE:", "[PSEUDO:"]);

/**
 * Modèle d'affichage d'EX-9.4 tiré de la vue du ticket et du contexte de
 * session (`$defs/modele_affichage`), `blocking` complet et ordonné selon
 * EX-9.15 et ses sauts.
 * @param {object} vue `$defs/vue_ticket`
 * @param {{session: {session_identity: string, entry: "absente"|"active"|"desactivee", addresses: string[], is_requester: boolean}, decision: string|null, approver: string|null, reason: string|null, now: string}} contexte
 * @returns {object}
 */
export function modeleAffichage(vue, contexte) {
  if (!estObjet(vue) || !estObjet(vue.request) || !estObjet(vue.separation)) throw new TypeError("modeleAffichage : vue du ticket attendue");
  if (!estObjet(contexte) || !estObjet(contexte.session) || !Array.isArray(contexte.session.addresses)) throw new TypeError("modeleAffichage : contexte attendu");
  const { session, decision, approver, reason } = contexte;
  if (decision !== null && decision !== "approuve" && decision !== "refuse") throw new TypeError("modeleAffichage : decision approuve, refuse ou null attendue");
  if (approver !== null && typeof approver !== "string") throw new TypeError("modeleAffichage : approver chaine ou null attendu");
  if (reason !== null && typeof reason !== "string") throw new TypeError("modeleAffichage : reason chaine ou null attendu");
  if (!["absente", "active", "desactivee"].includes(session.entry)) throw new TypeError("modeleAffichage : session.entry absente, active ou desactivee attendue");
  const maintenant = instantParametre(contexte.now, "modeleAffichage (now)");

  const blocking = [];
  // 1. État du ticket.
  if (!ETATS_VOTE.includes(vue.state)) blocking.push("ticket_clos_aux_votes");
  // 2. Événement retenue.
  const hachage = evenementVerifie(vue);
  const clair = feuilles(vue.request.arguments);
  let statuts = clair.map(() => "non_verifiable");
  let digests = null;
  if (hachage === null) {
    blocking.push("evenement_invalide");
  } else {
    // 3. Pièce « arguments ».
    const piece = pieceVerifiee(vue);
    if (!piece.ok) blocking.push("piece_invalide");
    // 4. Champs liés.
    if (!champsLies(vue)) blocking.push("champ_different");
    // 5. Arguments, feuille par feuille (seulement si la pièce est vérifiée).
    if (piece.ok) {
      statuts = clair.map((f) => {
        const r = resoudrePointeur(piece.valeur, f.pointer);
        if (!r.resolu) return "non_verifiable";
        if (typeof r.valeur === "string" && JETONS.some((j) => r.valeur.includes(j))) return "non_verifiable";
        return egaliteJson(r.valeur, f.value) ? "verifie" : "different";
      });
      if (statuts.includes("different")) blocking.push("argument_different");
      if (feuilles(piece.valeur).some((q) => !resoudrePointeur(vue.request.arguments, q.pointer).resolu)) blocking.push("argument_absent_de_l_affichage");
    }
    // 6. Condensés formés depuis l'événement vérifié, comparés à ceux du service.
    const e = vue.retained_event;
    const forme = (d) => condenses({ decision: d, journal_id: e.journal_id, org_id: e.org_id, request_hash: hachage, ticket: e.policy.ticket });
    digests = { approuve: forme("approuve"), refuse: forme("refuse") };
    if (membre(vue, "digests", "approuve") !== digests.approuve.d_a || membre(vue, "digests", "refuse") !== digests.refuse.d_a) {
      blocking.push("empreinte_divergente");
    }
  }
  // 7. Jeu figé.
  const fige = estObjet(vue.approver_set);
  if (!fige) blocking.push("jeu_non_fige");
  // 8. Décision choisie.
  if (decision === null) blocking.push("decision_absente");
  // 9. Adresse active attribuée à la session.
  let neuf = null;
  if (session.entry === "absente") neuf = "identite_inconnue";
  else if (session.entry === "desactivee") neuf = "identite_desactivee";
  else if (approver === null || !session.addresses.includes(approver)) neuf = "adresse_non_attribuee";
  if (neuf !== null) blocking.push(neuf);
  // 10 et 11, sautés après un échec de 7 ou de 9 ; 11 sauté après un échec de 10.
  const interdite = vue.separation.self_approval === "interdite";
  if (fige && neuf === null) {
    const membres = Array.isArray(vue.approver_set.members) ? vue.approver_set.members : [];
    if (!membres.includes(approver)) {
      blocking.push("hors_jeu");
    } else if (!(Array.isArray(vue.eligible) && vue.eligible.includes(approver))) {
      const demandeur = Array.isArray(vue.separation.requester_addresses) && vue.separation.requester_addresses.includes(approver);
      blocking.push(interdite && demandeur ? "auto_approbation" : "recuse");
    }
  }
  // 12. Session du demandeur.
  if (interdite && session.is_requester === true) blocking.push("session_du_demandeur");
  // 13. Motif.
  if (reason !== null && longueurPointsDeCode(reason) > 1024) blocking.push("motif_trop_long");

  // Avertissements, dans l'ordre d'EX-9.15.
  const warnings = [];
  if (digests !== null && decision !== null && digests[decision].utf8) warnings.push("condense_utf8");
  const banniere = interdite && vue.separation.requester_declared === false;
  if (banniere) warnings.push("separation_non_verifiable");
  if (Array.isArray(vue.added_members) && vue.added_members.length > 0) warnings.push("membres_ajoutes");
  const declarees = Array.isArray(vue.separation.requester_addresses) ? vue.separation.requester_addresses : [];
  const annuaire = Array.isArray(vue.separation.requester_directory_addresses) ? vue.separation.requester_directory_addresses : [];
  if (annuaire.some((a) => !declarees.includes(a))) warnings.push("separation_incomplete");

  const echeance = decoderInstant(vue.deadline);
  return {
    version: 0,
    ticket: vue.ticket,
    state: vue.state,
    org_id: vue.org_id,
    journal_id: vue.journal_id,
    tool: {
      announced: vue.request.tool_announced,
      original: vue.request.tool_original,
      server_alias: vue.request.server_alias,
      class: vue.request.class,
    },
    arguments: clair.map((f, k) => ({ pointer: f.pointer, value: cloner(f.value), status: statuts[k] })),
    effects: cloner(vue.effects),
    rule: cloner(vue.rule),
    opening: cloner(vue.opening),
    intent: vue.request.intent,
    intent_status: estObjet(membre(vue, "retained_event", "intent")) ? "reference_non_verifiable" : "en_clair",
    delegation: cloner(vue.request.delegation),
    separation_banner: banniere,
    request: { request_hash: vue.request_hash, seq: membre(vue, "retained_event", "seq"), ts: membre(vue, "retained_event", "ts") },
    digests,
    decision,
    approver,
    deadline: vue.deadline,
    remaining_ms: echeance === null ? null : echeance - maintenant,
    contest: cloner(vue.contest),
    approver_set: cloner(vue.approver_set),
    effective_required: vue.effective_required,
    votes: cloner(vue.votes),
    warnings,
    blocking,
    signable: blocking.length === 0,
  };
}

/**
 * L'objet `session` du contexte de `modeleAffichage`, tiré de l'annuaire
 * (EX-9.15, contrôles 9 et 12) : `entry` `absente`, `active` ou `desactivee`,
 * `addresses` l'adresse active de l'entrée (ou vide), `is_requester` vrai si le
 * `launched_by` du ticket est dans `requester_identities` de l'entrée.
 * @param {object} annuaire
 * @param {string} identite
 * @param {object} vue
 * @returns {{session_identity: string, entry: string, addresses: string[], is_requester: boolean}}
 */
export function sessionDuModele(annuaire, identite, vue) {
  if (!estObjet(annuaire) || !Array.isArray(annuaire.entries)) throw new TypeError("sessionDuModele : annuaire attendu");
  if (typeof identite !== "string") throw new TypeError("sessionDuModele : identite attendue");
  if (!estObjet(vue) || !estObjet(vue.request) || !estObjet(vue.request.delegation)) throw new TypeError("sessionDuModele : vue attendue");
  const e = annuaire.entries.find((x) => x.session_identity === identite);
  if (e === undefined) return { session_identity: identite, entry: "absente", addresses: [], is_requester: false };
  const active = e.active === true ? e.addresses.find((a) => a.state === "active") : undefined;
  const lb = vue.request.delegation.launched_by;
  return {
    session_identity: identite,
    entry: e.active === true ? "active" : "desactivee",
    addresses: active === undefined ? [] : [active.address],
    is_requester: typeof lb === "string" && e.requester_identities.includes(lb),
  };
}
