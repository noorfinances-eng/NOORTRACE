// Famille console/ des vecteurs de CT-3 (spec/CT-3-approbations.md, révision
// 0.3, annexe A.11, vérifications CS-1 à CS-9) et épreuve de lecture de la
// console (EX-A.17), appelées par scripts/vecteurs/generer-ct3.mjs.
//
// Les condensés (A, JCS(A), D_A, H) et les signatures attendus sont calculés
// par scripts/lib/journal.mjs et ethers ; les fichiers de clé par node:crypto
// et vérifiés par ethers (decryptKeystoreJsonSync) ; les raisons et l'ordre
// de blocking sont posés par conception. Tout est ensuite confronté à la
// bibliothèque de la console de référence scripts/lib/console.mjs : un écart
// arrête la génération.

import crypto from "node:crypto";
import { Signature, decryptKeystoreJsonSync, getBytes, hashMessage, keccak256, recoverAddress, toUtf8Bytes } from "ethers";
import * as J from "../../lib/journal.mjs";
import * as K from "../../lib/console.mjs";
import { IDENTITE_COMPTE } from "./annuaire.mjs";

const copie = (v) => JSON.parse(JSON.stringify(v));
const N_SECP = K.N_SECP256K1;
const sha = (etiquette) => J.sha256(Buffer.from(etiquette, "utf8"));
/** UUID de version 4 depuis les 16 premiers octets de SHA-256 d'une étiquette (bits de version et de variante posés). */
export function uuidEtiquette(etiquette) {
  const o = Buffer.from(sha(etiquette).slice(2, 34), "hex");
  o[6] = (o[6] & 0x0f) | 0x40;
  o[8] = (o[8] & 0x3f) | 0x80;
  const h = o.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
export const MOT_DE_PASSE = "noortrace/vecteurs/ct3/console/mot-de-passe";
export const ETIQUETTE_FICHIER_CLE = "noortrace/vecteurs/ct3/console/fichier-cle/<cas>/sel, …/iv, …/uuid";
export const ETIQUETTE_DECOUVERTE = "noortrace/vecteurs/ct3/console/decouverte/<nom>/uuid";
export const ETIQUETTE_ZERO = "noortrace/vecteurs/ct3/demande/console-zero";
export const ETIQUETTE_EN_LIGNE = "noortrace/vecteurs/ct3/console/en-ligne/precedent";
export const ICONE = "data:image/svg+xml;base64," + Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>').toString("base64");

export function familleConsole(ctx) {
  const { COMPTES, ADR, ORG_ID, JOURNAL_ID, REGISTRE, JEU, BLOC, DEMANDE, DEMANDEUR, V1, exiger, valider, EV_CT1, PIECES_CT1, MD } = ctx;
  const sigD = (compte, a) => J.signerApprobation(COMPTES[compte], J.objetApprobation(a));
  const sHaut = (sig) => sig.slice(0, 66) + (N_SECP - BigInt("0x" + sig.slice(66, 130))).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
  /** Condensés attendus par journal.mjs et ethers, puis confrontés à console.mjs. */
  const condensesAttendus = (a) => {
    const A = J.objetApprobation(a);
    const d = J.condenseApprobation(A);
    const h = J.condenseEIP191Approbation(A);
    const x = d.slice(2), y = h.slice(2);
    const attendu = { a: A, jcs: J.octetsJCS(A).toString("utf8"), d_a: d, fingerprint: `${x.slice(0, 8)}…${x.slice(56)}`, groups: x.match(/.{8}/g).join(" "), h, h_fingerprint: `${y.slice(0, 8)}…${y.slice(56)}`, utf8: (() => {
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(x, "hex"));
        return true;
      } catch {
        return false;
      }
    })() };
    exiger(J.egalJSON(K.condenses(A), attendu), `condenses(${A.ticket}, ${A.decision}) diffère de journal.mjs`);
    return attendu;
  };

  // -------------------------------------------------------------------------
  // modeles/ (CS-1 à CS-4)
  // -------------------------------------------------------------------------
  const ret = EV_CT1.find((e) => e.seq === 5);
  const piece = PIECES_CT1.find((p) => p.sha256 === ret.execution.arguments.sha256);
  exiger(ret && piece && ret.policy.ticket === "apr-2201", "événement seq 5 et pièce de CT-1");
  const base2201 = { journal_id: ret.journal_id, org_id: ret.org_id, request_hash: ret.hash, ticket: "apr-2201" };
  const D2201 = { approuve: condensesAttendus({ decision: "approuve", ...base2201 }), refuse: condensesAttendus({ decision: "refuse", ...base2201 }) };
  exiger(D2201.approuve.d_a === "0xa57cbdad280b5cb2e9f6ee87b85d8bc05e76a5966377e7d58046519464f7df7c" && D2201.refuse.d_a === "0xd2cace7b1eded2643785e99e2f5316ee6cb4fad6ea468426d30d76538ccab300", "D_A d'apr-2201 (EX-9.17)");
  const M123 = [ADR(1), ADR(2), ADR(3)].sort();
  const vue2201 = {
    version: 0,
    ticket: "apr-2201",
    state: "ouvert",
    org_id: ret.org_id,
    journal_id: ret.journal_id,
    request_hash: ret.hash,
    request: {
      tool_announced: "sap.payments.create",
      tool_original: "sap.payments.create",
      server_alias: "sap",
      class: "ecriture",
      arguments: { claim_id: "2026-81044", amount: "12500.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" },
      intent: ret.intent,
      delegation: copie(ret.delegation),
      policy_version: ret.code.policy_version,
    },
    retained_event: copie(ret),
    arguments_piece: Buffer.from(piece.texte, "utf8").toString("base64"),
    rule: { policy_rule: "paiement > 5000 CHF", name: "paiement > 5000 CHF", description: "Chaque paiement est approuvé au seuil du jeu d'approbateurs.", level: "revue", contest_ms: 0 },
    opening: null,
    effects: [{ system: "SAP", action: "ecriture", object: "2026-81044", amount: "12500.00", currency: "CHF", unresolved: [] }],
    deadline: J.horodatage(J.msHorodatage(ret.ts) + 3600000),
    contest: { window_end: null, objections: [], last_threshold_at: null },
    approver_set: { threshold: { required: 2, size: 3 }, members: M123, source: `CuratorSet c=2124 r=${REGISTRE} s=${JEU(1)} h=1200..1200 b=${BLOC(1200)}` },
    effective_required: 2,
    added_members: [],
    eligible: [ADR(1), ADR(2)].sort(),
    votes: [{ approver: ADR(2), decision: "approuve", reason: null, at: "2026-11-05T09:21:12.000Z" }],
    separation: { self_approval: "interdite", requester_declared: true, requester_addresses: [ADR(3)], requester_directory_addresses: [ADR(3)] },
    digests: { approuve: D2201.approuve.d_a, refuse: D2201.refuse.d_a },
  };
  const exempleVue = /<!-- schema: console-approbation\/vue_ticket -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(exempleVue && J.egalJSON(JSON.parse(exempleVue[1]), vue2201), "la vue d'apr-2201 diffère de l'exemple de CT-3 12.9");
  const NOW = "2026-11-05T09:25:00.000Z";
  const MOTIF = "Constat et facture concordants";
  const SESSION_1 = { session_identity: IDENTITE_COMPTE[1], entry: "active", addresses: [ADR(1)], is_requester: false };

  // Demande à référence en ligne : événement retenue de journal-approbations scellé par rec-test-01 (CT-1 §13).
  const graine = sha("noortrace/vecteurs/v0/cle-enregistreur/rec-test-01");
  const argsEnLigne = { amount: "7400.00", beneficiary_iban: "CH9300762011623852957", claim_id: "2026-90417", currency: "CHF" };
  const corpsEnLigne = {
    version: 0,
    seq: 9,
    ts: "2026-11-12T09:00:00.200Z",
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    recorder_key_id: "rec-test-01",
    prev_hash: sha(ETIQUETTE_EN_LIGNE),
    delegation: { launched_by: DEMANDEUR, on_behalf_of: "service-sinistres", scope: "sinistres:lecture,paiement", run_id: "run-2026-11-12-0009" },
    code: { model: "fournisseur/modele@2026-09", prompt_version: null, policy_version: V1, recorder: "0.1.0" },
    intent: "Régler le sinistre 2026-90417",
    policy: { rule: "paiement > 5000 CHF", decision: "a_approuver", ticket: "apr-0901", redaction: null },
    approval: null,
    execution: { tool: "sap.payments.create", arguments: J.referenceEnLigne(argsEnLigne), status: "retenue", result: null, duration_ms: null, is_error: null },
    effects: [],
    context: [],
  };
  const evEnLigne = J.scellerEvenement(corpsEnLigne, graine);
  exiger(valider(evEnLigne, "evenement", null).length === 0, `événement en ligne non conforme : ${JSON.stringify(valider(evEnLigne, "evenement", null).slice(0, 2))}`);
  exiger(J.verifierSignatureEvenement(evEnLigne, J.clePubliqueEd25519(graine)) && K.hachageEvenement(evEnLigne) === evEnLigne.hash, "événement en ligne");
  const base0901 = { journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: evEnLigne.hash, ticket: "apr-0901" };
  const D0901 = { approuve: condensesAttendus({ decision: "approuve", ...base0901 }), refuse: condensesAttendus({ decision: "refuse", ...base0901 }) };
  const vueEnLigne = {
    ...copie(vue2201),
    ticket: "apr-0901",
    org_id: ORG_ID,
    journal_id: JOURNAL_ID,
    request_hash: evEnLigne.hash,
    request: { tool_announced: "sap.payments.create", tool_original: "sap.payments.create", server_alias: "sap", class: "ecriture", arguments: { claim_id: "2026-90417", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" }, intent: corpsEnLigne.intent, delegation: copie(corpsEnLigne.delegation), policy_version: V1 },
    retained_event: evEnLigne,
    arguments_piece: null,
    effects: [{ system: "SAP", action: "ecriture", object: "2026-90417", amount: "7400.00", currency: "CHF", unresolved: [] }],
    deadline: "2026-11-12T10:00:00.200Z",
    votes: [],
    digests: { approuve: D0901.approuve.d_a, refuse: D0901.refuse.d_a },
  };

  // Intention portée par une référence (contrôle 4 d'EX-9.15) : la même demande que reference-en-ligne,
  // ticket apr-0902, dont l'événement retenue (seq 10, chaîné à seq 9) porte l'intention par une référence à sa pièce.
  const corpsIntentionRef = { ...copie(corpsEnLigne), seq: 10, ts: "2026-11-12T09:05:00.200Z", prev_hash: evEnLigne.hash, intent: J.reference(Buffer.from(corpsEnLigne.intent, "utf8")), policy: { ...corpsEnLigne.policy, ticket: "apr-0902" } };
  const evIntentionRef = J.scellerEvenement(corpsIntentionRef, graine);
  exiger(valider(evIntentionRef, "evenement", null).length === 0 && J.verifierSignatureEvenement(evIntentionRef, J.clePubliqueEd25519(graine)) && K.hachageEvenement(evIntentionRef) === evIntentionRef.hash, "événement à intention par référence");
  const base0902 = { journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: evIntentionRef.hash, ticket: "apr-0902" };
  const D0902 = { approuve: condensesAttendus({ decision: "approuve", ...base0902 }), refuse: condensesAttendus({ decision: "refuse", ...base0902 }) };
  const vueIntentionRef = { ...copie(vueEnLigne), ticket: "apr-0902", request_hash: evIntentionRef.hash, retained_event: evIntentionRef, deadline: "2026-11-12T10:05:00.200Z", digests: { approuve: D0902.approuve.d_a, refuse: D0902.refuse.d_a } };

  const vue = (f) => {
    const v = copie(vue2201);
    f(v);
    return v;
  };
  const pieceModifiee = Buffer.from(piece.texte.replace("12500.00", "12500.01"), "utf8").toString("base64");
  const casModeles = [
    // [id, description, checks, vue, session, decision, approver, reason, now, blocking attendu, warnings attendus, statut des arguments]
    ["apr-2201-approuve", "Vue du ticket apr-2201 (événement seq 5 et pièce de CT-1, journal-valide), compte 1, décision approuve : tout est vérifié, l'IBAN, rédigé dans la pièce, est non vérifiable ; signable.", ["CS-1", "CS-2", "CS-3", "CS-4"], vue2201, SESSION_1, "approuve", ADR(1), MOTIF, NOW, [], []],
    ["apr-2201-refuse", "Même vue, décision refuse : signable ; l'empreinte affichée est celle de D_refuse.", ["CS-1", "CS-2", "CS-3", "CS-4"], vue2201, SESSION_1, "refuse", ADR(1), null, NOW, [], []],
    ["reference-en-ligne", "Demande de journal-approbations dont la référence des arguments est en ligne (value), événement retenue scellé par la clé de test rec-test-01 de CT-1 : arguments vérifiés sans pièce séparée ; signable.", ["CS-1", "CS-2", "CS-3"], vueEnLigne, SESSION_1, "approuve", ADR(1), null, "2026-11-12T09:10:00.000Z", [], []],
    ["intention-par-reference", "Demande de reference-en-ligne, ticket apr-0902, dont l'événement retenue porte l'intention par une référence (objet) et non en chaîne : la console ne peut pas la vérifier et l'affiche « non vérifiable par la console » (intent_status reference_non_verifiable), sans bloquer ; signable.", ["CS-2"], vueIntentionRef, SESSION_1, "approuve", ADR(1), null, "2026-11-12T09:10:00.000Z", [], []],
    ["effet-connu-apres-execution", "Gabarit d'effets dont object pointe vers le résultat (/result/document_id) : la vue porte object null et unresolved [{ member object, pointer /result/document_id }] ; la console l'affiche « connu après exécution », sans bloquer ; signable.", ["CS-2"], vue((v) => (v.effects = [{ system: "SAP", action: "ecriture", object: null, amount: "12500.00", currency: "CHF", unresolved: [{ member: "object", pointer: "/result/document_id" }] }])), SESSION_1, "approuve", ADR(1), MOTIF, NOW, [], []],
    ["evenement-modifie", "L'événement retenue servi a son ts modifié d'un caractère : hachage recalculé différent, evenement_invalide ; contrôles 3 à 6 non faits, condensés nuls, arguments non vérifiables.", ["CS-1"], vue((v) => (v.retained_event.ts = "2026-11-05T09:12:09.905Z")), SESSION_1, "approuve", ADR(1), null, NOW, ["evenement_invalide"], []],
    ["request-hash-different", "request_hash de la vue différent du hash de l'événement : evenement_invalide.", ["CS-1"], vue((v) => (v.request_hash = DEMANDE("console-autre"))), SESSION_1, "approuve", ADR(1), null, NOW, ["evenement_invalide"], []],
    ["piece-modifiee", "Pièce « arguments » servie avec un montant modifié : sha256 différent, piece_invalide ; arguments non vérifiables.", ["CS-1"], vue((v) => (v.arguments_piece = pieceModifiee)), SESSION_1, "approuve", ADR(1), null, NOW, ["piece_invalide"], []],
    ["outil-different", "Outil annoncé de la requête différent d'execution.tool : champ_different.", ["CS-2"], vue((v) => (v.request.tool_announced = "sap.payments.update")), SESSION_1, "approuve", ADR(1), null, NOW, ["champ_different"], []],
    ["regle-differente", "Règle de la vue différente de policy.rule de l'événement : champ_different.", ["CS-2"], vue((v) => (v.rule.policy_rule = "paiement > 1000 CHF")), SESSION_1, "approuve", ADR(1), null, NOW, ["champ_different"], []],
    ["run-id-different", "run_id de la délégation de la requête différent de celui de l'événement : champ_different.", ["CS-2"], vue((v) => (v.request.delegation.run_id = "run-2026-11-05-0008")), SESSION_1, "approuve", ADR(1), null, NOW, ["champ_different"], []],
    ["intention-differente", "Intention de la requête différente de celle, en chaîne, de l'événement : champ_different.", ["CS-2"], vue((v) => (v.request.intent = "Régler le sinistre 2026-81044 : 21500.00 CHF au bénéficiaire du contrat")), SESSION_1, "approuve", ADR(1), null, NOW, ["champ_different"], []],
    ["argument-different", "amount vaut 21500.00 en clair et 12500.00 dans la pièce : feuille different, argument_different.", ["CS-2"], vue((v) => (v.request.arguments.amount = "21500.00")), SESSION_1, "approuve", ADR(1), null, NOW, ["argument_different"], []],
    ["argument-absent-de-la-piece", "Un argument en clair (note) absent de la pièce : non vérifiable, sans bloquer.", ["CS-2"], vue((v) => (v.request.arguments.note = "paiement urgent")), SESSION_1, "approuve", ADR(1), null, NOW, [], []],
    ["chemin-absent-de-l-affichage", "currency, présent dans la pièce, manque aux arguments en clair : argument_absent_de_l_affichage.", ["CS-2"], vue((v) => delete v.request.arguments.currency), SESSION_1, "approuve", ADR(1), null, NOW, ["argument_absent_de_l_affichage"], []],
    ["condense-service-faux-approuve", "Le D_A du service pour approuve diffère de celui de la console : empreinte_divergente.", ["CS-3"], vue((v) => (v.digests.approuve = "0x" + "11".repeat(32))), SESSION_1, "approuve", ADR(1), null, NOW, ["empreinte_divergente"], []],
    ["condense-service-faux-refuse", "Seul le D_A du service pour refuse est faux, l'approbateur choisit approuve : empreinte_divergente quand même.", ["CS-3"], vue((v) => (v.digests.refuse = "0x" + "22".repeat(32))), SESSION_1, "approuve", ADR(1), null, NOW, ["empreinte_divergente"], []],
    ["ticket-approuve", "Ticket déjà approuve : ticket_clos_aux_votes.", ["CS-4"], vue((v) => (v.state = "approuve")), SESSION_1, "approuve", ADR(1), null, NOW, ["ticket_clos_aux_votes"], []],
    ["jeu-non-fige", "Jeu non figé : jeu_non_fige ; membre et éligibilité ne sont pas contrôlés.", ["CS-4"], vue((v) => Object.assign(v, { approver_set: null, effective_required: null, eligible: [] })), SESSION_1, "approuve", ADR(1), null, NOW, ["jeu_non_fige"], []],
    ["decision-absente", "Aucune décision choisie : decision_absente.", ["CS-4"], vue2201, SESSION_1, null, ADR(1), null, NOW, ["decision_absente"], []],
    ["identite-sans-entree", "L'identité de session n'a pas d'entrée dans l'annuaire : identite_inconnue.", ["CS-4"], vue2201, { session_identity: "oidc https://idp.assureur-demo.example approbateur-9", entry: "absente", addresses: [], is_requester: false }, "approuve", ADR(1), null, NOW, ["identite_inconnue"], []],
    ["entree-desactivee", "L'entrée de la session est désactivée : identite_desactivee.", ["CS-4"], vue2201, { session_identity: IDENTITE_COMPTE[2], entry: "desactivee", addresses: [], is_requester: false }, "approuve", ADR(2), null, NOW, ["identite_desactivee"], []],
    ["adresse-non-attribuee", "Le compte 2 choisi par la session d'approbateur-1, dont l'adresse active est le compte 1 : adresse_non_attribuee.", ["CS-4"], vue2201, SESSION_1, "approuve", ADR(2), null, NOW, ["adresse_non_attribuee"], []],
    ["adresse-hors-jeu", "Compte 4, adresse active de sa session, hors du jeu figé : hors_jeu.", ["CS-4"], vue2201, { session_identity: IDENTITE_COMPTE[4], entry: "active", addresses: [ADR(4)], is_requester: false }, "approuve", ADR(4), null, NOW, ["hors_jeu"], []],
    ["adresse-du-demandeur", "Compte 3, adresse du demandeur sous interdite, par la session du demandeur : auto_approbation puis session_du_demandeur.", ["CS-4"], vue2201, { session_identity: IDENTITE_COMPTE[3], entry: "active", addresses: [ADR(3)], is_requester: true }, "approuve", ADR(3), null, NOW, ["auto_approbation", "session_du_demandeur"], []],
    ["membre-recuse", "Compte 2, membre du jeu qui s'est récusé (absent d'eligible) : recuse.", ["CS-4"], vue((v) => (v.eligible = [ADR(1)])), { session_identity: IDENTITE_COMPTE[2], entry: "active", addresses: [ADR(2)], is_requester: false }, "refuse", ADR(2), null, NOW, ["recuse"], []],
    ["motif-trop-long", "Motif de 1 025 caractères : motif_trop_long.", ["CS-4"], vue2201, SESSION_1, "approuve", ADR(1), "é".repeat(1025), NOW, ["motif_trop_long"], []],
    ["motif-1024", "Motif de 1 024 points de code, accentués : admis.", ["CS-4"], vue2201, SESSION_1, "approuve", ADR(1), "é".repeat(1024), NOW, [], []],
    ["separation-non-verifiable", "Demandeur sans entrée dans separation.identities sous interdite : bandeau et avertissement separation_non_verifiable, sans bloquer ; le compte 3 est alors éligible.", ["CS-4"], vue((v) => Object.assign(v, { eligible: M123, separation: { self_approval: "interdite", requester_declared: false, requester_addresses: [], requester_directory_addresses: [] } })), SESSION_1, "approuve", ADR(1), null, NOW, [], ["separation_non_verifiable"]],
    ["membres-ajoutes", "Le compte 4 a été ajouté au jeu par un nouveau gel : avertissement membres_ajoutes.", ["CS-4"], vue((v) => Object.assign(v, { approver_set: { ...v.approver_set, threshold: { required: 2, size: 4 }, members: [...M123, ADR(4)].sort() }, added_members: [ADR(4)], eligible: [ADR(1), ADR(2), ADR(4)].sort() })), SESSION_1, "approuve", ADR(1), null, NOW, [], ["membres_ajoutes"]],
    ["separation-incomplete", "La politique déclare le compte 4 pour le demandeur, l'annuaire lui attribue le compte 3 : avertissement separation_incomplete, sans bloquer.", ["CS-4"], vue((v) => Object.assign(v, { eligible: M123, separation: { self_approval: "interdite", requester_declared: true, requester_addresses: [ADR(4)], requester_directory_addresses: [ADR(3)] } })), SESSION_1, "approuve", ADR(1), null, NOW, [], ["separation_incomplete"]],
    [
      "plusieurs-defauts",
      "Ticket approuve, outil et montant différents, D_A du service faux pour refuse, jeu non figé, aucune décision, adresse non attribuée, session du demandeur, motif trop long : toutes les raisons, dans l'ordre des contrôles.",
      ["CS-2", "CS-3", "CS-4"],
      vue((v) => Object.assign(v, { state: "approuve", approver_set: null, effective_required: null, eligible: [], request: { ...v.request, tool_announced: "sap.payments.update", arguments: { ...v.request.arguments, amount: "21500.00" } }, digests: { ...v.digests, refuse: "0x" + "22".repeat(32) } })),
      { session_identity: IDENTITE_COMPTE[1], entry: "active", addresses: [ADR(1)], is_requester: true },
      null,
      ADR(2),
      "x".repeat(1025),
      NOW,
      ["ticket_clos_aux_votes", "champ_different", "argument_different", "empreinte_divergente", "jeu_non_fige", "decision_absente", "adresse_non_attribuee", "session_du_demandeur", "motif_trop_long"],
      [],
    ],
  ];
  const modeles = casModeles.map(([id, description, checks, v, session, decision, approver, reason, now, blocking, warnings]) => {
    const m = K.modeleAffichage(v, { session, decision, approver, reason, now });
    exiger(J.egalJSON(m.blocking, blocking), `modèle ${id} : blocking ${JSON.stringify(m.blocking)}, conception ${JSON.stringify(blocking)}`);
    exiger(J.egalJSON(m.warnings, warnings), `modèle ${id} : warnings ${JSON.stringify(m.warnings)}, conception ${JSON.stringify(warnings)}`);
    // Condensés : ceux de journal.mjs sur l'événement, ou nuls si l'événement ne se vérifie pas.
    const evOk = !blocking.includes("evenement_invalide");
    exiger(evOk ? J.hachageEvenement(v.retained_event) === v.retained_event.hash : m.digests === null, `modèle ${id} : événement`);
    if (evOk) {
      const b = { journal_id: v.retained_event.journal_id, org_id: v.retained_event.org_id, request_hash: v.retained_event.hash, ticket: v.retained_event.policy.ticket };
      exiger(J.egalJSON(m.digests, { approuve: condensesAttendus({ decision: "approuve", ...b }), refuse: condensesAttendus({ decision: "refuse", ...b }) }), `modèle ${id} : condensés`);
    }
    const cas = { version: 0, id, description, checks, input: { view: v, session, decision, approver, reason, now }, expected: m };
    const e = valider(cas, "console-approbation", "cas_modele");
    exiger(e.length === 0, `console/modeles/${id} non conforme : ${JSON.stringify(e.slice(0, 3))}`);
    return cas;
  });
  const m0 = modeles[0].expected;
  exiger(m0.remaining_ms === 2829904 && m0.digests.approuve.fingerprint === "a57cbdad…64f7df7c" && m0.digests.refuse.fingerprint === "d2cace7b…8ccab300", "valeurs de 12.9 et d'EX-9.18");
  exiger(J.egalJSON(m0.arguments.map((a) => [a.pointer, a.status]), [["/amount", "verifie"], ["/beneficiary_iban", "non_verifiable"], ["/claim_id", "verifie"], ["/currency", "verifie"]]), "feuilles d'EX-9.16");
  // Intention (contrôle 4 d'EX-9.15) et effets non résolus (EX-12.14), posés par conception.
  for (const c of modeles) {
    exiger(c.expected.intent_status === (c.id === "intention-par-reference" ? "reference_non_verifiable" : "en_clair"), `modèle ${c.id} : intent_status`);
    exiger(J.egalJSON(c.expected.effects, c.input.view.effects), `modèle ${c.id} : effets`);
  }
  exiger(modeles.some((c) => c.expected.effects.some((e) => e.unresolved.length > 0 && e.unresolved.every((u) => e[u.member] === null))), "EX-12.14 : effet non résolu sans cas");
  const codesModeles = new Set(modeles.flatMap((c) => c.expected.blocking));
  for (const code of ["evenement_invalide", "piece_invalide", "champ_different", "argument_different", "argument_absent_de_l_affichage", "empreinte_divergente", "ticket_clos_aux_votes", "jeu_non_fige", "decision_absente", "identite_inconnue", "identite_desactivee", "adresse_non_attribuee", "hors_jeu", "auto_approbation", "recuse", "session_du_demandeur", "motif_trop_long"]) exiger(codesModeles.has(code), `CS-4 : ${code} sans cas`);

  // -------------------------------------------------------------------------
  // requetes/ (CS-3, CS-5)
  // -------------------------------------------------------------------------
  const A0001 = { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: DEMANDE(1), ticket: "apr-0001" };
  // D_A à premier octet nul : plus petit k ≥ 1 du ticket apr-c0-<k>.
  const rhZero = sha(ETIQUETTE_ZERO);
  exiger(rhZero === "0xd3620aa8af23a0d83931eb2db11403b2947430cbd89c3387781bce95ab06823b", "request_hash de console-zero");
  let k = 1;
  while (J.condenseApprobation(J.objetApprobation({ decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: rhZero, ticket: `apr-c0-${k}` })).slice(2, 4) !== "00") k++;
  exiger(k === 542, `k du D_A à octet nul : ${k}, attendu 542`);
  const AZERO = { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: rhZero, ticket: `apr-c0-${k}` };
  const sigCt1 = Object.fromEntries(EV_CT1.find((e) => e.seq === 6).approval.approvers.map((a, i) => [a, EV_CT1.find((e) => e.seq === 6).approval.signatures[i]]));
  const casRequetes = [
    ["apr-2201-approuve-compte-1", "Compte 1 sur D_approuve du ticket apr-2201 : la signature RFC 6979 est celle de l'approval de l'événement seq 6 des vecteurs de CT-1.", { decision: "approuve", ...base2201 }, 1],
    ["apr-2201-approuve-compte-2", "Compte 2 sur D_approuve du ticket apr-2201 : signature de l'événement seq 6 de CT-1.", { decision: "approuve", ...base2201 }, 2],
    ["apr-2201-refuse-compte-1", "Compte 1 sur D_refuse du ticket apr-2201.", { decision: "refuse", ...base2201 }, 1],
    ["apr-0001-approuve-compte-1", "Compte 1 sur le ticket apr-0001 de decisions/valides/approbation-2-sur-3.json.", A0001, 1],
    [`apr-c0-${k}-approuve-compte-1`, `D_A dont le premier octet est nul (ticket apr-c0-${k}, plus petit k ≥ 1) : une conversion par entier ou par texte le perdrait (EX-9.22).`, AZERO, 1],
  ];
  const requetes = casRequetes.map(([id, description, a, compte]) => {
    const dig = condensesAttendus(a);
    const preimage = J.hex(Buffer.concat([Buffer.from([0x19]), Buffer.from("Ethereum Signed Message:\n32", "utf8"), getBytes(dig.d_a)]));
    exiger(keccak256(preimage) === dig.h && getBytes(preimage).length === 60, `requête ${id} : préimage`);
    const signature = sigD(compte, a);
    exiger(recoverAddress(dig.h, signature).toLowerCase() === ADR(compte), `requête ${id} : recouvrement`);
    exiger(K.signerHachage(getBytes(COMPTES[compte].privateKey), getBytes(dig.h)) === signature, `requête ${id} : RFC 6979 de console.mjs`);
    if (a.ticket === "apr-2201" && a.decision === "approuve") exiger(signature === sigCt1[ADR(compte)], `requête ${id} : signature de CT-1`);
    const request = { method: "personal_sign", params: [dig.d_a, ADR(compte)] };
    exiger(J.egalJSON(K.requetePersonalSign(dig.d_a, ADR(compte)), request), `requête ${id} : requetePersonalSign`);
    const cas = { version: 0, id, description, checks: ["CS-3", "CS-5"], input: { a: J.objetApprobation(a), approver: ADR(compte), account: compte }, expected: { digests: dig, preimage, request, signature } };
    exiger(valider(cas, "console-approbation", "cas_requete").length === 0, `console/requetes/${id} non conforme`);
    return cas;
  });
  exiger(requetes.find((c) => c.id === "apr-0001-approuve-compte-1").expected.digests.d_a === "0xce13c3f15c3eab4c81a4735828741b0acf205a46e59d6894ed2e7589b5777d0d", "D_A d'apr-0001 d'EX-A.15");
  exiger(requetes.at(-1).expected.digests.d_a === "0x00d9060ac22cf499a79777dfeb7fa339783ac23f12571712c02663d9acdca5c7", "D_A à octet nul d'EX-A.15");

  // -------------------------------------------------------------------------
  // reponses/ (CS-6, CS-7)
  // -------------------------------------------------------------------------
  const A2201 = { decision: "approuve", ...base2201 };
  const can = sigD(1, A2201);
  exiger(can.endsWith("1b"), "la signature canonique du compte 1 sur D_approuve a v = 27");
  const can28 = sigD(1, A0001);
  exiger(can28.endsWith("1c"), "la signature canonique du compte 1 sur apr-0001 a v = 28");
  const sigChaine = Signature.from(COMPTES[1].signingKey.sign(hashMessage(toUtf8Bytes(D2201.approuve.d_a)))).serialized;
  const SID1 = IDENTITE_COMPTE[1];
  const conceptionReponses = [
    // [id, description, A, réponse, verdict (null : acceptée), signature normalisée attendue, adresse recouvrée attendue (pour une acceptation : le compte 1)]
    ["canonique", "Forme canonique (s bas, v = 27) : acceptée telle quelle, vote construit.", A2201, { result: can }, null, can],
    ["v-0", "v = 0 : normalisé en v = 27, accepté.", A2201, { result: can.slice(0, 130) + "00" }, null, can],
    ["v-1", "v = 1 (signature du compte 1 sur apr-0001, de v = 28) : normalisé en v = 28, accepté.", A0001, { result: can28.slice(0, 130) + "01" }, null, can28],
    ["s-haut-normalisee", "Signature du compte 1 sur D_A (apr-2201, approuve) rendue avec s dans la moitié haute et v = 28 : la console la ramène à s bas et v = 27, recouvre le compte 1 et envoie la forme normalisée.", A2201, { result: sHaut(can) }, null, can],
    ["s-haut-v27", "s haut et v = 27 (signature du compte 1 sur apr-0001) : ramené à s bas et v = 28, accepté.", A0001, { result: sHaut(can28) }, null, can28],
    ["majuscules", "Chiffres hexadécimaux en majuscules : acceptée, écrite en minuscules.", A2201, { result: "0x" + can.slice(2).toUpperCase() }, null, can],
    ["v-29", "v = 29 (forme que Ledger rendrait si r dépassait l'ordre) : signature_invalide.", A2201, { result: can.slice(0, 130) + "1d" }, "signature_invalide"],
    ["v-37", "v = 37 (forme EIP-155) : signature_invalide, bien qu'ethers et eth-account l'acceptent.", A2201, { result: can.slice(0, 130) + "25" }, "signature_invalide"],
    ["v-38", "v = 38 (forme EIP-155) : signature_invalide.", A2201, { result: can.slice(0, 130) + "26" }, "signature_invalide"],
    ["longueur-64", "Signature compacte de 64 octets (EIP-2098) : signature_invalide, bien qu'ethers l'accepte.", A2201, { result: can.slice(0, 130) }, "signature_invalide"],
    ["longueur-66", "66 octets : signature_invalide.", A2201, { result: can + "00" }, "signature_invalide"],
    ["r-nul", "r = 0 : signature_invalide.", A2201, { result: "0x" + "0".repeat(64) + can.slice(66) }, "signature_invalide"],
    ["s-egal-n", "s = n : signature_invalide avant toute normalisation.", A2201, { result: can.slice(0, 66) + N_SECP.toString(16) + can.slice(130) }, "signature_invalide"],
    ["autre-adresse", "Signature valide du compte 2 : adresse_differente, l'adresse recouvrée est affichée, aucun vote.", A2201, { result: sigD(2, A2201) }, "adresse_differente", null, ADR(2)],
    ["signature-de-la-chaine", "Signature du compte 1 sur la chaîne « 0x… » de 66 caractères au lieu des 32 octets (EX-9.7) : elle recouvre une autre adresse, adresse_differente.", A2201, { result: sigChaine }, "adresse_differente", null, "0x58047c881cfdadf1b8d785b79b29c5cc784ede6e"],
    ["erreur-4001", "Promesse rompue par 4001 : refus_approbateur ; aucun vote n'est envoyé.", A2201, { error: { code: 4001, message: "User rejected the request." } }, "refus_approbateur"],
    ["erreur-4100", "Promesse rompue par 4100 : non_autorise.", A2201, { error: { code: 4100, message: "The requested account and/or method has not been authorized by the user." } }, "non_autorise"],
    ["erreur-4200", "Promesse rompue par 4200 : methode_non_prise_en_charge.", A2201, { error: { code: 4200, message: "The requested method is not supported by this Ethereum provider." } }, "methode_non_prise_en_charge"],
    ["erreur-4900", "Promesse rompue par 4900 : deconnecte.", A2201, { error: { code: 4900, message: "The provider is disconnected from all chains." } }, "deconnecte"],
    ["erreur-4901", "Promesse rompue par 4901 : chaine_deconnectee ; la console ne demande jamais de changer de réseau.", A2201, { error: { code: 4901, message: "The provider is disconnected from the specified chain." } }, "chaine_deconnectee"],
    ["erreur-autre-code", "Promesse rompue par un autre code (-32603) : erreur_portefeuille.", A2201, { error: { code: -32603, message: "Internal error" } }, "erreur_portefeuille"],
    ["erreur-sans-code", "Promesse rompue sans code numérique : erreur_portefeuille.", A2201, { error: { code: null, message: "<b>erreur</b> du portefeuille" } }, "erreur_portefeuille"],
    ["resultat-nul", "Promesse tenue avec null : reponse_invalide.", A2201, { result: null }, "reponse_invalide"],
    ["resultat-non-hexadecimal", "Promesse tenue avec une chaîne qui n'est pas hexadécimale : reponse_invalide.", A2201, { result: "signature" }, "reponse_invalide"],
  ];
  const reponses = conceptionReponses.map(([id, description, a, response, reason, normalisee = null, recouvree = null]) => {
    const A = J.objetApprobation(a);
    const dig = condensesAttendus(A);
    const session = SID1;
    const motif = A.ticket === "apr-2201" ? MOTIF : "Pièces vérifiées";
    const attendu = { outcome: reason === null ? "accepte" : "refuse", reason, signature: reason === null ? normalisee : null, recovered: reason === null ? ADR(1) : recouvree, vote: null };
    if (reason === null) {
      exiger(J.verifierSignatureApprobation(A, normalisee, ADR(1)).ok, `réponse ${id} : forme normalisée`);
      attendu.vote = { ticket: A.ticket, approver: ADR(1), decision: A.decision, signature: normalisee, reason: motif, session_identity: session };
    } else if (reason === "adresse_differente") exiger(recoverAddress(dig.h, response.result).toLowerCase() === recouvree, `réponse ${id} : adresse recouvrée par ethers`);
    const r = K.verifierReponse(response, dig.d_a, ADR(1));
    const vote = r.outcome === "accepte" ? K.requeteVoter({ ticket: A.ticket }, A.decision, r.signature, ADR(1), motif, session) : null;
    exiger(J.egalJSON({ ...r, vote }, attendu), `réponse ${id} : ${JSON.stringify({ ...r, vote })}, conception ${JSON.stringify(attendu)}`);
    const cas = { version: 0, id, description, checks: ["CS-6", "CS-7"], input: { a: A, approver: ADR(1), reason: motif, session_identity: session, response }, expected: attendu };
    exiger(valider(cas, "console-approbation", "cas_reponse").length === 0, `console/reponses/${id} non conforme : ${JSON.stringify(valider(cas, "console-approbation", "cas_reponse").slice(0, 2))}`);
    if (attendu.vote) exiger(valider(attendu.vote, "console-approbation", "requete_voter").length === 0, `réponse ${id} : vote non conforme`);
    return cas;
  });
  const exempleReponse = /<!-- schema: console-approbation\/cas_reponse -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(exempleReponse && J.egalJSON(JSON.parse(exempleReponse[1]), reponses.find((c) => c.id === "s-haut-normalisee")), "le cas s-haut-normalisee diffère de l'exemple d'EX-9.21");
  const exempleVote = /<!-- schema: console-approbation\/requete_voter -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(exempleVote && J.egalJSON(JSON.parse(exempleVote[1]), reponses.find((c) => c.id === "canonique").expected.vote), "le vote canonique diffère de l'exemple de 12.9");

  // -------------------------------------------------------------------------
  // decouverte/ (CS-8)
  // -------------------------------------------------------------------------
  const ann = (nom, provider, o = {}) => ({ info: { uuid: uuidEtiquette(`noortrace/vecteurs/ct3/console/decouverte/${nom}/uuid`), name: `Portefeuille ${nom}`, icon: ICONE, rdns: `com.exemple.portefeuille-${nom}`, ...o }, provider });
  const pf = (a) => ({ uuid: a.info.uuid, name: a.info.name, rdns: a.info.rdns, provider: a.provider });
  const pA = ann("a", "p1"), pB = ann("b", "p2");
  const conceptionDecouverte = [
    ["aucune-annonce", "Aucune annonce : liste vide ; la page dit qu'aucun portefeuille ne s'est annoncé et continue d'écouter.", [], [], []],
    ["une-annonce", "Une seule annonce : proposée, jamais présélectionnée.", [pA], [pf(pA)], []],
    ["deux-portefeuilles", "Deux portefeuilles : proposés dans l'ordre de leur première annonce.", [pA, pB], [pf(pA), pf(pB)], []],
    ["reannonce-meme-objet", "Un portefeuille se réannonce par le même objet à chaque eip6963:requestProvider : sans effet.", [pA, pB, pA], [pf(pA), pf(pB)], []],
    ["annonce-en-double", "Deux portefeuilles s'annoncent ; le premier se réannonce (même objet, sans effet), puis un troisième objet reprend son uuid : les deux annonces de cet uuid par des objets différents sont écartées et l'uuid est exclu.", [pA, pB, pA, { ...copie(pA), provider: "p3" }, pA], [pf(pB)], [{ index: 0, reason: "annonce_en_double" }, { index: 3, reason: "annonce_en_double" }, { index: 4, reason: "annonce_en_double" }]],
    ["uuid-non-v4", "uuid qui n'est pas de version 4 : annonce_invalide.", [ann("c", "p1", { uuid: uuidEtiquette("noortrace/vecteurs/ct3/console/decouverte/c/uuid").replace(/^(.{14})4/, (_, debut) => `${debut}1`) }), pB], [pf(pB)], [{ index: 0, reason: "annonce_invalide" }]],
    ["icone-non-data", "Icône qui n'est pas une URI data: : annonce_invalide.", [ann("d", "p1", { icon: "https://portefeuille.example/icone.svg" }), pB], [pf(pB)], [{ index: 0, reason: "annonce_invalide" }]],
    ["nom-vide", "Nom vide : annonce_invalide.", [ann("e", "p1", { name: "" }), pB], [pf(pB)], [{ index: 0, reason: "annonce_invalide" }]],
    ["nom-trop-long", "Nom de 65 caractères : annonce_invalide.", [ann("f", "p1", { name: "P".repeat(65) }), pB], [pf(pB)], [{ index: 0, reason: "annonce_invalide" }]],
    ["rdns-imite", "Deux portefeuilles qui déclarent le même rdns : tous deux proposés, rdns n'est pas une identité.", [pA, ann("g", "p2", { rdns: pA.info.rdns })], [pf(pA), pf(ann("g", "p2", { rdns: pA.info.rdns }))], []],
  ];
  const decouverte = conceptionDecouverte.map(([id, description, announcements, providers, rejected]) => {
    const r = K.decouvrir(announcements);
    exiger(J.egalJSON(r, { providers, rejected }), `découverte ${id} : ${JSON.stringify(r)}`);
    const cas = { version: 0, id, description, checks: ["CS-8"], input: { announcements }, expected: { providers, rejected } };
    exiger(valider(cas, "console-approbation", "cas_decouverte").length === 0, `console/decouverte/${id} non conforme`);
    return cas;
  });

  // -------------------------------------------------------------------------
  // fichiers-cle/ (CS-9)
  // -------------------------------------------------------------------------
  const lab = (cas, quoi) => Buffer.from(sha(`noortrace/vecteurs/ct3/console/fichier-cle/${cas}/${quoi}`).slice(2), "hex");
  /** Fichier Web3 Secret Storage v3 construit par node:crypto. */
  function fichierCle(cas, cleHex, kdf) {
    const sel = lab(cas, "sel");
    const iv = lab(cas, "iv").subarray(0, 16);
    const dk = kdf === "pbkdf2" ? crypto.pbkdf2Sync(Buffer.from(MOT_DE_PASSE, "utf8"), sel, 1024, 32, "sha256") : crypto.scryptSync(Buffer.from(MOT_DE_PASSE, "utf8"), sel, 32, { N: 1024, r: 8, p: 1 });
    const c = crypto.createCipheriv("aes-128-ctr", dk.subarray(0, 16), iv);
    const ct = Buffer.concat([c.update(Buffer.from(cleHex.slice(2), "hex")), c.final()]);
    const mac = keccak256(Buffer.concat([dk.subarray(16, 32), ct])).slice(2);
    const kdfparams = kdf === "pbkdf2" ? { c: 1024, dklen: 32, prf: "hmac-sha256", salt: sel.toString("hex") } : { dklen: 32, n: 1024, p: 1, r: 8, salt: sel.toString("hex") };
    return { crypto: { cipher: "aes-128-ctr", cipherparams: { iv: iv.toString("hex") }, ciphertext: ct.toString("hex"), kdf, kdfparams, mac }, id: uuidEtiquette(`noortrace/vecteurs/ct3/console/fichier-cle/${cas}/uuid`), version: 3 };
  }
  const fPbkdf2 = fichierCle("pbkdf2", COMPTES[1].privateKey, "pbkdf2");
  const fScrypt = fichierCle("scrypt", COMPTES[1].privateKey, "scrypt");
  const exempleFichier = /<!-- schema: console-approbation\/fichier_cle -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(exempleFichier && J.egalJSON(JSON.parse(exempleFichier[1]), fPbkdf2), "le fichier pbkdf2 diffère de l'exemple d'EX-13.28");
  const varie = (f, g) => {
    const d = copie(f);
    g(d);
    return d;
  };
  const conceptionFichiers = [
    ["pbkdf2-valide", "Fichier de clé v3, PBKDF2-HMAC-SHA-256 à 1 024 itérations, AES-128-CTR, clé du compte 1 : déchiffré, adresse du compte 1, dérivation signalée faible.", fPbkdf2, MOT_DE_PASSE, 1, null, ["derivation_faible"], ADR(1)],
    ["scrypt-valide", "Fichier de clé v3, scrypt n = 1 024, r = 8, p = 1, clé du compte 1 : déchiffré, dérivation signalée faible.", fScrypt, MOT_DE_PASSE, 1, null, ["derivation_faible"], ADR(1)],
    ["mauvais-mot-de-passe", "Mauvais mot de passe : le MAC ne concorde pas, mot_de_passe_ou_mac, rien n'est déchiffré.", fPbkdf2, MOT_DE_PASSE + "!", 1, "mot_de_passe_ou_mac", ["derivation_faible"]],
    ["mac-modifie", "MAC modifié d'un chiffre : mot_de_passe_ou_mac.", varie(fPbkdf2, (d) => (d.crypto.mac = (d.crypto.mac[0] === "0" ? "1" : "0") + d.crypto.mac.slice(1))), MOT_DE_PASSE, 1, "mot_de_passe_ou_mac", ["derivation_faible"]],
    ["aes-128-cbc", "cipher aes-128-cbc : fichier_cle_non_pris_en_charge.", varie(fPbkdf2, (d) => (d.crypto.cipher = "aes-128-cbc")), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["kdf-inconnu", "kdf argon2id : fichier_cle_non_pris_en_charge.", varie(fPbkdf2, (d) => (d.crypto.kdf = "argon2id")), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["prf-hmac-sha512", "prf hmac-sha512, qu'ethers accepte : fichier_cle_non_pris_en_charge.", varie(fPbkdf2, (d) => (d.crypto.kdfparams.prf = "hmac-sha512")), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["dklen-16", "dklen 16 : fichier_cle_non_pris_en_charge.", varie(fPbkdf2, (d) => (d.crypto.kdfparams.dklen = 16)), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["n-non-puissance-de-2", "scrypt n = 1 000, qui n'est pas une puissance de 2 : fichier_cle_non_pris_en_charge.", varie(fScrypt, (d) => (d.crypto.kdfparams.n = 1000)), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["n-2-puissance-19", "scrypt n = 2^19, au-delà de la borne 2^18 : fichier_cle_non_pris_en_charge, sans dériver.", varie(fScrypt, (d) => (d.crypto.kdfparams.n = 524288)), MOT_DE_PASSE, 1, "fichier_cle_non_pris_en_charge", []],
    ["version-1", "version 1 : fichier_cle_invalide.", varie(fPbkdf2, (d) => (d.version = 1)), MOT_DE_PASSE, 1, "fichier_cle_invalide", []],
    ["iv-court", "iv de 15 octets : fichier_cle_invalide.", varie(fPbkdf2, (d) => (d.crypto.cipherparams.iv = d.crypto.cipherparams.iv.slice(2))), MOT_DE_PASSE, 1, "fichier_cle_invalide", []],
    ["cle-nulle", "Fichier qui chiffre la clé nulle, hors de [1, n − 1] : cle_invalide.", fichierCle("cle-nulle", "0x" + "00".repeat(32), "pbkdf2"), MOT_DE_PASSE, 1, "cle_invalide", ["derivation_faible"]],
    ["cle-compte-2", "Fichier de la clé du compte 2 présenté pour l'adresse du compte 1 : adresse_differente, avant toute signature.", fichierCle("cle-compte-2", COMPTES[2].privateKey, "pbkdf2"), MOT_DE_PASSE, 1, "adresse_differente", ["derivation_faible"], ADR(2)],
  ];
  const fichiersCle = conceptionFichiers.map(([id, description, keystore, password, compte, reason, warnings, address = null]) => {
    if (reason === null || reason === "adresse_differente") {
      const w = decryptKeystoreJsonSync(JSON.stringify(keystore), password);
      exiger(w.address.toLowerCase() === address, `fichier ${id} : ethers déchiffre ${w.address}`);
    }
    const r = K.lireFichierCle(keystore, password, ADR(compte));
    const attendu = { outcome: reason === null ? "accepte" : "refuse", reason, address, warnings };
    exiger(J.egalJSON({ outcome: r.outcome, reason: r.reason, address: r.address, warnings: r.warnings }, attendu), `fichier ${id} : ${JSON.stringify({ ...r, cle: undefined })}, conception ${JSON.stringify(attendu)}`);
    if (r.cle) {
      exiger(J.hex(Buffer.from(r.cle)) === COMPTES[1].privateKey, `fichier ${id} : clé déchiffrée`);
      // La page signe H par RFC 6979 : même signature qu'ethers, puis la clé est effacée (EX-13.28, pas 7 et 8).
      const s = K.signerCondense(r.cle, D2201.approuve.d_a);
      exiger(s === can && r.cle.every((x) => x === 0), `fichier ${id} : signerCondense`);
    }
    const cas = { version: 0, id, description, checks: ["CS-9"], input: { keystore, password, approver: ADR(compte) }, expected: attendu };
    exiger(valider(cas, "console-approbation", "cas_fichier_cle").length === 0, `console/fichiers-cle/${id} non conforme`);
    if (["pbkdf2-valide", "scrypt-valide"].includes(id)) exiger(valider(keystore, "console-approbation", "fichier_cle").length === 0, `fichier ${id} : $defs/fichier_cle`);
    return cas;
  });

  return { modeles, requetes, reponses, decouverte, fichiersCle, kZero: k, vue2201 };
}

// ---------------------------------------------------------------------------
// Épreuve de lecture de la console (EX-A.17)
// ---------------------------------------------------------------------------

export const CONSIGNE_CONSOLE = `# Épreuve de lecture de la console d'approbation (CT-3, annexe A.11, EX-A.17)

Vous recevez, selon votre rôle, des sections de la spécification CT-3
(\`spec/CT-3-approbations.md\`, révision 0.3) et rien d'autre. Répondez seul,
sans aide et par écrit, aux questions de votre rôle, dans le gabarit
\`gabarit-reponse.md\`. Citez les règles (EX-…) sur lesquelles vous vous
appuyez quand vous le pouvez. Un troisième relecteur, qui ne vous a pas aidé,
marque ensuite chaque élément attendu présent ou absent ; la grille n'est pas
dans ce répertoire.

## Rôle « approbateur » : sections 9 et 13

Vous êtes une personne nommée de l'organisation, membre du jeu d'approbateurs,
et vous détenez votre clé dans votre portefeuille.

1. Comment vous inscrivez-vous ?
2. Comment signez-vous depuis la console avec votre portefeuille ?
3. Que vérifiez-vous avant de signer ?
4. Que faites-vous si l'empreinte diffère ?

## Rôle « développeur intégrateur » : sections 7.4, 9, 12 et 13

Vous intégrez la console au système d'identité du client et au service
d'approbation.

1. Quels messages la page, le portefeuille et le service échangent-ils, dans
   quel ordre, et avec quel contenu exact ?
2. Que refuse la console, et à quel moment ?
`;

export const GABARIT_CONSOLE = `# Réponse à l'épreuve de lecture de la console

- Rôle : (approbateur ou integrateur)
- Lecteur : (nom)
- Sections reçues : (9 et 13 ; ou 7.4, 9, 12 et 13)

## Question 1

(réponse)

## Question 2

(réponse)

## Question 3 (approbateur seulement)

(réponse)

## Question 4 (approbateur seulement)

(réponse)
`;

const el = (element, ...rules) => ({ element, rules });
export const ATTENDU_ACCEPTATION_CONSOLE = {
  version: 0,
  roles: [
    {
      role: "approbateur",
      sections: ["9", "13"],
      questions: [
        {
          id: "q1",
          question: "Comment vous inscrivez-vous ?",
          elements: [
            el("Se connecter à la console par le système d'identité de l'organisation, en se réauthentifiant si la console le demande.", "EX-13.2", "EX-13.8"),
            el("Choisir explicitement son portefeuille dans la liste des portefeuilles annoncés, puis le compte à inscrire, sans présélection.", "EX-13.22", "EX-13.23"),
            el("Lire le message d'inscription affiché ligne par ligne : origine égale à celle de la console ouverte, organisation, sa propre identité, l'adresse du compte choisi, l'expiration, et la mention « Ce message n'est pas un vote ».", "EX-13.12", "EX-13.13", "EX-13.14"),
            el("Signer le message dans le portefeuille (personal_sign sur le texte), qui montre le même texte, et refuser dans le portefeuille si une ligne diffère.", "EX-13.12", "EX-13.15"),
            el("L'adresse reste en attente jusqu'à sa validation par un administrateur autre que soi.", "EX-13.17"),
          ],
        },
        {
          id: "q2",
          question: "Comment signez-vous depuis la console avec votre portefeuille ?",
          elements: [
            el("Lire la demande sur un même écran, puis choisir sa décision, approuve ou refuse, sans choix présélectionné.", "EX-9.4", "EX-9.5"),
            el("Choisir explicitement son portefeuille (jamais un portefeuille choisi d'office) et son adresse active.", "EX-13.22", "EX-13.23"),
            el("La console redemande la vue après le choix, refait ses contrôles et n'offre la signature que si tout concorde.", "EX-9.15"),
            el("Le portefeuille reçoit une requête personal_sign sur les 32 octets de D_A et montre 64 chiffres hexadécimaux.", "EX-13.24", "EX-9.20"),
            el("Comparer l'empreinte affichée par la console à l'écran du portefeuille, ou de l'appareil pour un portefeuille matériel, avant de confirmer.", "EX-9.20", "EX-13.26"),
          ],
        },
        {
          id: "q3",
          question: "Que vérifiez-vous avant de signer ?",
          elements: [
            el("Les arguments et leur marque, « vérifié » ou « non vérifiable par la console ».", "EX-9.4", "EX-9.16"),
            el("La règle déclenchée et la délégation ; l'intention marquée « déclarée par l'agent, non vérifiée ».", "EX-9.4"),
            el("Les 8 premiers et les 8 derniers chiffres du message montré par le portefeuille, égaux à l'empreinte de la console ; les huit groupes pour une objection ou un montant élevé.", "EX-9.18", "EX-9.20"),
            el("Sur un appareil qui montre « Message hash », comparer cette valeur à l'empreinte de H et non à celle de D_A.", "EX-9.18", "EX-9.20"),
            el("Le portefeuille montre un message en hexadécimal, et non une transaction ni des données typées.", "EX-9.20"),
          ],
        },
        {
          id: "q4",
          question: "Que faites-vous si l'empreinte diffère ?",
          elements: [
            el("Refuser la requête dans le portefeuille et ne pas réessayer depuis cette page.", "EX-9.20"),
            el("Prévenir l'administrateur de l'organisation par un autre canal que la console.", "EX-9.20"),
            el("Refuser dans le portefeuille n'est pas voter refuse : aucun vote n'est envoyé ; pour s'opposer, signer refuse depuis une console saine.", "EX-9.20", "EX-13.29"),
            el("Si la console affiche elle-même empreinte_divergente, il n'y a rien à signer ; prévenir l'administrateur.", "EX-9.17", "EX-9.20"),
          ],
        },
      ],
    },
    {
      role: "integrateur",
      sections: ["7.4", "9", "12", "13"],
      questions: [
        {
          id: "q1",
          question: "Quels messages la page, le portefeuille et le service échangent-ils, dans quel ordre, et avec quel contenu exact ?",
          elements: [
            el("consulter { ticket, session_identity } vers le service, qui rend la vue du ticket ; la console applique EX-9.15 et affiche le modèle.", "EX-12.14", "EX-9.15"),
            el("Découverte EIP-6963 (eip6963:requestProvider, annonces eip6963:announceProvider), choix explicite, puis eth_requestAccounts.", "EX-13.22", "EX-13.23"),
            el("personal_sign avec params [\"0x\" et les 64 chiffres minuscules de D_A, adresse en minuscules] : la donnée d'abord, l'adresse ensuite ; 66 puis 42 caractères.", "EX-13.24", "EX-9.7"),
            el("Le portefeuille signe la préimage EIP-191 de 60 octets et rend r ‖ s ‖ v de 65 octets, ou une erreur EIP-1193.", "EX-13.24", "EX-9.21"),
            el("La console vérifie la réponse (forme, normalisation, recouvrement, adresse) avant tout envoi.", "EX-9.21"),
            el("voter { ticket, approver, decision, signature normalisée, reason, session_identity } ; réponse { ticket, state } ou l'erreur de 12.8.", "EX-12.16", "EX-9.21"),
            el("Les neuf pas dans cet ordre, et l'inscription : preparer_inscription, reconstruction du texte, personal_sign sur ses octets, inscrire.", "EX-13.13", "EX-13.15"),
          ],
        },
        {
          id: "q2",
          question: "Que refuse la console, et à quel moment ?",
          elements: [
            el("Avant toute signature, les treize contrôles d'EX-9.15, dans l'ordre, sur une vue redemandée après le choix : état, événement, pièce, champs liés, arguments, condensés, jeu, décision, annuaire, membre, éligibilité, session du demandeur, motif.", "EX-9.15"),
            el("Un D_A différent de digests du service : aucune signature, jamais la valeur du service.", "EX-9.17"),
            el("Les contrôles d'annuaire d'EX-13.18 : jeu non figé, identité inconnue ou désactivée, adresse non attribuée, hors du jeu, session du demandeur.", "EX-13.18"),
            el("Après le portefeuille, toute réponse de forme refusée (longueur, r, s, v hors de {0, 1, 27, 28}) ou qui ne recouvre pas l'adresse choisie.", "EX-9.21", "EX-9.22"),
            el("Les pannes et codes EIP-1193 de 13.14 (4001, 4100, 4200, 4900, 4901, autre code, réponse invalide, délai), sans jamais transmettre une panne comme un vote.", "EX-13.29", "EX-13.30"),
            el("Jamais window.ethereum sans choix explicite, jamais eth_sign ni eth_signTypedData, jamais la signature du D_A du service.", "EX-13.20", "EX-13.22", "EX-9.17"),
          ],
        },
      ],
    },
  ],
};
