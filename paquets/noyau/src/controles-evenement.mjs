// Contrôles d'un événement pour lui-même, E-1 à E-11 (CT-1 §11.4), communs à
// la vérification d'un journal (§7.2) et à celle d'un dossier (§11).

import { ZERO32, chaineNonVide, decoderHorodatage, estEntierSur, estHex, hexVersOctets } from "./conventions.mjs";
import { PROFONDEUR_V0, depasseProfondeur, egaliteJson, formeCanoniqueAbsente, jcs, jcsOctets } from "./json-strict.mjs";
import { recouvrerAdresseEip191, sha256Hex } from "./hachage.mjs";
import {
  condenseApprobation,
  hacherEvenement,
  objetApprobation,
  referencesEvenement,
  sorteEvenement,
  verifierSignatureEvenement,
} from "./evenement.mjs";
import { annonceRotation, ecartsRotation } from "./rotation.mjs";
import { dansValidite } from "./cles.mjs";
import { validerSchema } from "./schemas.mjs";

/** Identifiants des contrôles d'un événement, dans l'ordre de CT-1 §11.4. */
export const CONTROLES_EVENEMENT = Object.freeze(["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"]);

/** Statuts d'un contrôle (CT-6 EX-6.1). */
export const STATUTS = Object.freeze({ REUSSI: "reussi", ECHOUE: "echoue", NON_EXECUTE: "non_execute" });

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// Résultat d'un contrôle : statut, raison de non-exécution, détails lisibles.
function resultat(statut, details = [], raison = null) {
  return { statut, raison, details };
}

const reussi = (details = []) => resultat(STATUTS.REUSSI, details);
const echoue = (details) => resultat(STATUTS.ECHOUE, details);
const nonExecute = (raison, details = []) => resultat(STATUTS.NON_EXECUTE, details, raison);
const selon = (ecarts) => (ecarts.length ? echoue(ecarts) : reussi());

/** Identité de l'enregistreur dans `delegation.launched_by` d'un événement du journal sur lui-même (CT-1 §5.3). */
export const LANCEUR_ENREGISTREUR = "noortrace-enregistreur";

const vide = (v) => Array.isArray(v) && v.length === 0;

/**
 * Écarts d'un événement à la cohérence de sa sorte : règle exacte de E-3 de
 * CT-1 §5.3 (révision 0.5). Une valeur absente, ou d'un autre type que celui
 * que la règle nomme, ne la tient pas.
 * @param {object} e
 * @returns {string[]}
 */
export function ecartsSorte(e) {
  const ecarts = [];
  const sorte = sorteEvenement(e);
  if (sorte === null) return ["execution.tool illisible"];
  if (sorte === "reserve_inconnu") return [`execution.tool ${e.execution.tool} : nom de l'espace noortrace. qui n'est pas l'un des quatre noms réservés`];
  const pd = e.policy?.decision;
  const approbation = e.approval;
  const x = e.execution ?? {};
  const executeAvecPieces = sorte === "echange" || (sorte === "appel_outil" && x.status === "executee");

  if (sorte === "appel_outil") {
    // Règle 1 : appel d'outil.
    if (!["autorise", "a_approuver", "refuse"].includes(pd)) ecarts.push(`policy.decision ${pd} pour un appel d'outil (autorise, a_approuver ou refuse attendu)`);
    if (approbation !== null && pd !== "a_approuver") ecarts.push("approval non nul sur un appel d'outil dont policy.decision n'est pas a_approuver");
    if (x.status === "retenue" && (pd !== "a_approuver" || approbation !== null)) {
      ecarts.push("appel retenu : policy.decision a_approuver et approval nul attendus");
    }
    if (x.status === "refusee" && !(pd === "refuse" || (pd === "a_approuver" && ["refuse", "expire"].includes(approbation?.decision)))) {
      ecarts.push("appel refusé : politique refuse, ou approbation refuse ou expire, attendue");
    }
    if (x.status === "executee" && !(pd === "autorise" || (pd === "a_approuver" && approbation?.decision === "approuve"))) {
      ecarts.push("appel exécuté : politique autorise, ou approbation approuve, attendue");
    }
    if ((x.status === "retenue" || x.status === "refusee") && !vide(e.effects)) {
      ecarts.push("appel non relayé (retenu ou refusé) : effects doit être un tableau vide");
    }
  } else {
    // Règles 2 et 3 : échange, décision, rotation, changement de politique.
    if (pd !== "sans_objet") ecarts.push(`policy.decision ${pd} pour un événement ${sorte} (sans_objet attendu)`);
    if (x.status !== "executee") ecarts.push(`execution.status ${x.status} pour un événement ${sorte} (executee attendu)`);
    if (sorte === "decision") {
      if (!estObjet(approbation)) ecarts.push("décision d'approbation sans approval");
    } else if (approbation !== null) {
      ecarts.push(`approval non nul pour un événement ${sorte}`);
    }
    if (sorte !== "echange" && e.intent !== null) ecarts.push(`intent non nul pour un événement ${sorte}`);
  }

  if (executeAvecPieces) {
    if (!estObjet(x.result)) ecarts.push("execution.result : référence attendue");
    if (!(estEntierSur(x.duration_ms) && x.duration_ms >= 0)) ecarts.push("execution.duration_ms : entier ≥ 0 attendu");
    if (typeof x.is_error !== "boolean") ecarts.push("execution.is_error : booléen attendu");
  } else {
    if (x.result !== null) ecarts.push("execution.result : null attendu");
    if (x.duration_ms !== null) ecarts.push("execution.duration_ms : null attendu");
    if (x.is_error !== null) ecarts.push("execution.is_error : null attendu");
  }

  const args = x.arguments;
  const enLigne = estObjet(args) && "value" in args;
  if (sorte === "decision") {
    if (!enLigne) ecarts.push("décision d'approbation : référence en ligne attendue (value = A)");
    else if (estObjet(approbation)) {
      try {
        if (jcs(args.value, SANS_BORNE) !== jcs(objetApprobation(e), SANS_BORNE)) ecarts.push("décision d'approbation : arguments.value n'a pas la forme canonique de l'objet signé A");
      } catch {
        ecarts.push("décision d'approbation : forme canonique de arguments.value ou de l'objet signé A incalculable");
      }
    }
    // Les effets de l'appel approuvé sont déclarés par l'appel relayé, non par la décision.
    if (!vide(e.effects)) ecarts.push("décision d'approbation : effects doit être un tableau vide");
  } else if (sorte === "rotation") {
    if (!enLigne) ecarts.push("rotation de clé : référence en ligne attendue (annonce de rotation)");
    if (e.delegation?.launched_by !== LANCEUR_ENREGISTREUR) ecarts.push(`rotation de clé : delegation.launched_by ${JSON.stringify(e.delegation?.launched_by)}, ${LANCEUR_ENREGISTREUR} attendu`);
    // new_key_id est lu dans execution.arguments.value (§8, règle 4) ; le
    // reste de l'annonce relève de E-10.
    const nouvelle = enLigne && estObjet(args.value) ? args.value.new_key_id : undefined;
    if (typeof nouvelle !== "string") ecarts.push("rotation de clé : new_key_id illisible dans execution.arguments.value, effects invérifiables");
    else {
      const attendu = [{ system: "noortrace", action: "ecriture", object: `cle:${nouvelle}`, amount: null, currency: null }];
      if (!egaliteJson(e.effects, attendu)) ecarts.push(`rotation de clé : effects doit être ${jcs(attendu)}`);
    }
  } else if (sorte === "politique") {
    if (e.delegation?.launched_by !== LANCEUR_ENREGISTREUR) ecarts.push(`changement de politique : delegation.launched_by ${JSON.stringify(e.delegation?.launched_by)}, ${LANCEUR_ENREGISTREUR} attendu`);
    const v = enLigne ? args.value : undefined;
    const longueur = typeof v?.policy_version === "string" ? [...v.policy_version].length : 0;
    const forme =
      estObjet(v) &&
      Object.keys(v).length === 2 &&
      typeof v.policy_version === "string" &&
      longueur >= 1 &&
      longueur <= 128 &&
      estHex(v.policy_sha256, 32);
    if (!forme) ecarts.push("changement de politique : référence en ligne { policy_version (1 à 128 caractères), policy_sha256 } attendue");
  }
  return ecarts;
}

const SANS_BORNE = Object.freeze({ profondeurMax: Infinity });

/**
 * Applique E-1 à E-11 à un événement.
 *
 * Une relation dont un terme est absent, n'a pas le type JSON que le schéma
 * lui donne ou ne se calcule pas (un horodatage qui n'est pas une date
 * existante) n'est pas tenue, et le contrôle qui l'évalue échoue (CT-1 §11.4,
 * révision 0.5). Un événement qui n'est pas un objet, ou plus profond que la
 * borne (CT-1 §4, règle 7 : 128, comptée depuis l'objet de l'événement),
 * échoue à E-1, et E-2 à E-11 ne s'y exécutent pas.
 * @param {unknown} e l'événement
 * @param {{indexCles?: {exploitable: boolean, cles: Map<string, object>}|null, profondeurMax?: number}} [contexte]
 *   indexCles : cles.json lu par indexerCles ; null, absent ou inexploitable : E-8 non exécuté (ou en
 *   échec si inexploitable), E-11 non exécuté, E-10 non exécuté sauf échec de ses règles hors cles.json ;
 *   profondeurMax : borne d'imbrication (PROFONDEUR_V0 par défaut, Infinity : aucune)
 * @returns {{controles: Record<string, {statut: string, raison: string|null, details: string[]}>, hash: string|null}}
 *   les onze résultats et le hash recalculé (null s'il est incalculable)
 */
export function controlerEvenement(e, contexte = {}) {
  const r = {};
  const inexploitable = (motif) => {
    r["E-1"] = echoue([motif]);
    for (const id of CONTROLES_EVENEMENT.slice(1)) r[id] = nonExecute("prerequis_en_echec");
    return { controles: r, hash: null };
  };
  if (!estObjet(e)) return inexploitable("l'événement n'est pas un objet JSON");
  const borne = contexte.profondeurMax ?? PROFONDEUR_V0;
  if (depasseProfondeur(e, borne)) return inexploitable(`événement plus profond que ${borne} niveaux (CT-1 §4, règle 7)`);
  // Sans forme canonique (texte lu par lireJournal, ou valeur en mémoire) :
  // E-2 échoue, et aucune autre règle ne s'exécute (CT-1 §11.4, cas (d)).
  let motifForme = formeCanoniqueAbsente(e);
  if (motifForme === null) {
    try {
      jcs(e, SANS_BORNE);
    } catch (err) {
      motifForme = err.message;
    }
  }
  if (motifForme !== null) {
    for (const id of CONTROLES_EVENEMENT) r[id] = nonExecute("prerequis_en_echec");
    r["E-2"] = echoue([`forme canonique incalculable : ${motifForme}`]);
    return { controles: r, hash: null };
  }
  const index = contexte.indexCles ?? null;

  // E-1 : schéma, dates existantes, identifiants non nuls.
  const ecarts1 = [];
  const schema = validerSchema("evenement", e);
  if (!schema.valide) ecarts1.push(...schema.erreurs.map((x) => `schéma : ${x}`));
  if (decoderHorodatage(e.ts) === null) ecarts1.push(`ts ${JSON.stringify(e.ts)} : horodatage qui ne se décode pas`);
  if (estObjet(e.approval) && typeof e.approval.at === "string" && decoderHorodatage(e.approval.at) === null) {
    ecarts1.push(`approval.at ${e.approval.at} : horodatage qui ne se décode pas`);
  }
  if (e.org_id === ZERO32) ecarts1.push("org_id nul");
  if (e.journal_id === ZERO32) ecarts1.push("journal_id nul");
  r["E-1"] = selon(ecarts1);

  // E-2 : forme canonique calculable (vérifiée ci-dessus ; la profondeur relève de E-1).
  const canonique = true;
  r["E-2"] = reussi();

  r["E-3"] = selon(ecartsSorte(e));

  // E-4 : toute référence rédigée exige un policy.redaction qui est une chaîne
  // non vide au sens de CT-1 §3 (révision 0.5 : "" et une chaîne de blancs ne
  // suffisent pas).
  const refs = referencesEvenement(e);
  const redigees = refs.filter((x) => x.reference.redacted === true);
  r["E-4"] =
    redigees.length && !chaineNonVide(e.policy?.redaction)
      ? echoue(redigees.map((x) => `${x.chemin} rédigée alors que policy.redaction (${JSON.stringify(e.policy?.redaction)}) n'est pas une chaîne non vide`))
      : reussi();

  // E-5 : approvers et signatures de même longueur ; approval.ticket = policy.ticket.
  if (e.approval !== null) {
    const a = estObjet(e.approval) ? e.approval : {};
    const ecarts5 = [];
    if (!Array.isArray(a.approvers) || !Array.isArray(a.signatures) || a.approvers.length !== a.signatures.length) {
      ecarts5.push(`approvers (${a.approvers?.length}) et signatures (${a.signatures?.length}) de longueurs différentes`);
    }
    if (typeof a.ticket !== "string" || a.ticket !== e.policy?.ticket) ecarts5.push(`approval.ticket ${a.ticket} différent de policy.ticket ${e.policy?.ticket}`);
    r["E-5"] = selon(ecarts5);
  } else {
    r["E-5"] = reussi();
  }

  // E-6 : références en ligne.
  const ecarts6 = [];
  for (const { chemin, reference } of refs) {
    if (!("value" in reference)) continue;
    try {
      const octets = jcsOctets(reference.value, SANS_BORNE);
      const empreinte = sha256Hex(octets);
      if (reference.sha256 !== empreinte) ecarts6.push(`${chemin} : sha256 ${reference.sha256} différent de SHA-256(JCS(value)) ${empreinte}`);
      if (reference.length !== octets.length) ecarts6.push(`${chemin} : length ${reference.length} différente de ${octets.length} octets de JCS(value)`);
    } catch (err) {
      ecarts6.push(`${chemin} : JCS(value) incalculable (${err.message})`);
    }
  }
  r["E-6"] = selon(ecarts6);

  // E-7 : hash recalculé.
  let hashCalcule = null;
  if (canonique) {
    hashCalcule = hacherEvenement(e);
    r["E-7"] =
      hashCalcule === e.hash ? reussi() : echoue([`hash recalculé ${hashCalcule} différent de hash ${e.hash}`]);
  } else {
    r["E-7"] = nonExecute("prerequis_en_echec");
  }

  // E-8 : signature sous la clé recorder_key_id de cles.json.
  const cle = index?.exploitable && typeof e.recorder_key_id === "string" ? index.cles.get(e.recorder_key_id) : undefined;
  if (!index) r["E-8"] = nonExecute("cles_absent");
  else if (!index.exploitable) r["E-8"] = echoue(["cles.json inexploitable"]);
  else if (!cle) r["E-8"] = echoue([`clé ${e.recorder_key_id} absente de cles.json`]);
  else if (!cle.admise) r["E-8"] = echoue([`clé publique de ${e.recorder_key_id} refusée (non canonique ou de petit ordre)`]);
  else if (!canonique) r["E-8"] = nonExecute("prerequis_en_echec");
  else r["E-8"] = verifierSignatureEvenement(e, cle.octets) ? reussi() : echoue([`signature invalide sous la clé ${e.recorder_key_id}`]);

  // E-9 : adresses recouvrées des signatures d'approbation. approvers ou
  // signatures qui n'est pas un tableau met E-9 en échec (CT-6 EX-5.19).
  if (estObjet(e.approval) && Array.isArray(e.approval.signatures) && Array.isArray(e.approval.approvers)) {
    const ecarts9 = [];
    let DA;
    try {
      DA = condenseApprobation(objetApprobation(e));
    } catch (err) {
      ecarts9.push(`objet signé A incalculable (${err.message})`);
    }
    if (DA) {
      // « Pour chaque i, l'adresse recouvrée de signatures[i] = approvers[i] » :
      // i parcourt les signatures ; une signature sans approvers[i] échoue
      // (E-9, en plus de E-5) ; un approbateur sans signature relève de E-5.
      for (let i = 0; i < e.approval.signatures.length; i++) {
        const sig = e.approval.signatures[i];
        if (!estHex(sig, 65)) {
          ecarts9.push(`signatures[${i}] : 65 octets en hexadécimal minuscule attendus`);
          continue;
        }
        const { adresse, canonique: canon, raison } = recouvrerAdresseEip191(DA, hexVersOctets(sig));
        if (!canon) ecarts9.push(`signatures[${i}] non canonique : ${raison}`);
        else if (i >= e.approval.approvers.length) ecarts9.push(`signatures[${i}] recouvre ${adresse}, sans approvers[${i}]`);
        else if (adresse !== e.approval.approvers[i]) ecarts9.push(`signatures[${i}] recouvre ${adresse}, approvers[${i}] vaut ${e.approval.approvers[i]}`);
      }
    }
    r["E-9"] = selon(ecarts9);
  } else if (e.approval !== null) {
    r["E-9"] = echoue(["approval.approvers ou approval.signatures illisible"]);
  } else {
    r["E-9"] = reussi();
  }

  // E-10 : rotation. Ses comparaisons à cles.json exigent un cles.json
  // exploitable ; sans lui, E-10 n'est pas exécuté, sauf échec de ses autres
  // règles (CT-1 §11.4, révision 0.5 : l'échec l'emporte).
  if (sorteEvenement(e) !== "rotation") r["E-10"] = reussi();
  else if (index?.exploitable) r["E-10"] = selon(ecartsRotation(e, index));
  else {
    const ecarts10 = ecartsRotation(e, null);
    r["E-10"] = ecarts10.length ? echoue(ecarts10) : nonExecute("prerequis_en_echec", ["cles.json inexploitable : comparaisons à cles.json non faites"]);
  }

  // E-11 : ts dans la validité de la clé qui signe ; clé absente : non
  // exécuté (E-8) ; ts qui n'est pas une date existante : relation non tenue.
  const instant = decoderHorodatage(e.ts);
  if (!index || !index.exploitable || !cle) r["E-11"] = nonExecute("prerequis_en_echec");
  else if (instant === null) r["E-11"] = echoue([`ts ${JSON.stringify(e.ts)} : date inexistante, validité de la clé ${e.recorder_key_id} invérifiable`]);
  else r["E-11"] = dansValidite(cle, instant) ? reussi() : echoue([`ts ${e.ts} hors de la validité annoncée de la clé ${e.recorder_key_id}`]);

  return { controles: r, hash: hashCalcule };
}

/**
 * Hash recalculé d'un événement, ou null s'il n'est pas calculable (pas un
 * objet, ou sans forme canonique).
 * @param {unknown} e
 * @returns {string|null}
 */
export function hashRecalcule(e) {
  if (!estObjet(e) || formeCanoniqueAbsente(e) !== null) return null;
  try {
    return hacherEvenement(e);
  } catch {
    return null;
  }
}

/**
 * Dit si un événement est une rotation et rend son new_key_id, sinon null.
 * @param {unknown} e
 * @returns {string|null}
 */
export function nouvelleCle(e) {
  if (!estObjet(e) || sorteEvenement(e) !== "rotation") return null;
  return annonceRotation(e)?.new_key_id ?? null;
}
