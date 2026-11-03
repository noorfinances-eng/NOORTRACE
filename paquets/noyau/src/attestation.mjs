// Attestation de périmètre (CT-7 §7, qui fait foi ; CT-1 révision 0.4,
// §11.2 et §11.4) : condensé D_P, signatures EIP-191 des signataires, et
// vérifications AT-1 à AT-7 de la partie attestation-perimetre.json d'un
// dossier. Ces vérifications sont signalées sans jamais rendre un dossier
// invalide (CT-6 EX-5.11).

import { concatener, decoderBase64Canonique, decoderHorodatage, hexVersOctets, octetsVersHex } from "./conventions.mjs";
import { ErreurJson, PROFONDEUR_V0, analyserJson, decoderUtf8, egaliteJson, jcsOctets } from "./json-strict.mjs";
import { PREFIXES, keccak256, recouvrerAdresseEip191, sha256Hex, signerEip191 } from "./hachage.mjs";
import { controlerEvenement, hashRecalcule } from "./controles-evenement.mjs";
import { NOMS_RESERVES } from "./evenement.mjs";
import { validerSchema } from "./schemas.mjs";

// Le hachage et la signature portent sur l'objet en mémoire : la borne de
// profondeur de CT-1 §4 (règle 7) s'applique à la lecture et à E-1, non ici.
const SANS_BORNE = Object.freeze({ profondeurMax: Infinity });

/** Taille maximale de la partie attestation-perimetre.json : 4 Mio (CT-6 EX-4.15). */
export const TAILLE_MAX_PARTIE = 4 * 1024 * 1024;

/** Taille maximale du document de politique embarqué, octets décodés. */
export const TAILLE_MAX_DOCUMENT = 2097152;

/** Durée maximale de validité d'une attestation : 366 jours, en millisecondes. */
export const VALIDITE_MAX_MS = 366 * 86400000;

/** Identifiants des vérifications de la partie, dans l'ordre. */
export const VERIFICATIONS_PERIMETRE = Object.freeze(["AT-1", "AT-2", "AT-3", "AT-4", "AT-5", "AT-6", "AT-7"]);

/**
 * Condensé D_P = keccak256(P_P || JCS(P)) d'une attestation (CT-7 EX-7.6).
 * @param {object} attestation l'objet P
 * @returns {Uint8Array} 32 octets
 */
export function condenseAttestation(attestation) {
  return keccak256(concatener(PREFIXES.P_P, jcsOctets(attestation, SANS_BORNE)));
}

/**
 * Signature EIP-191 d'un signataire sur D_P.
 * @param {Uint8Array} clePrivee clé secp256k1 de 32 octets
 * @param {object} attestation
 * @returns {string} 65 octets en hexadécimal préfixé
 */
export function signerAttestation(clePrivee, attestation) {
  return octetsVersHex(signerEip191(clePrivee, condenseAttestation(attestation)));
}

/**
 * Écarts d'une attestation aux relations qu'AT-1 ajoute au schéma (CT-7
 * EX-7.2) : dates existantes, validity.from ≤ validity.until, au plus 366
 * jours, journal_id distincts, journal_id de chaque agent présent, agent_id
 * distincts, adresses des signataires distinctes. Le schéma est supposé
 * satisfait.
 * @param {object} P
 * @returns {string[]}
 */
export function ecartsAttestation(P) {
  const ecarts = [];
  const de = decoderHorodatage(P.validity.from);
  const a = decoderHorodatage(P.validity.until);
  if (de === null) ecarts.push(`validity.from ${P.validity.from} : date inexistante`);
  if (a === null) ecarts.push(`validity.until ${P.validity.until} : date inexistante`);
  if (decoderHorodatage(P.issued_at) === null) ecarts.push(`issued_at ${P.issued_at} : date inexistante`);
  if (de !== null && a !== null) {
    if (de > a) ecarts.push("validity.from postérieur à validity.until");
    else if (a - de > VALIDITE_MAX_MS) ecarts.push("validité de plus de 366 jours");
  }
  const journaux = P.journals.map((j) => j.journal_id);
  if (new Set(journaux).size !== journaux.length) ecarts.push("journal_id en double dans journals");
  for (const ag of P.agents) {
    if (!journaux.includes(ag.journal_id)) ecarts.push(`agent ${ag.agent_id} : journal_id absent de journals`);
  }
  const agents = P.agents.map((x) => x.agent_id);
  if (new Set(agents).size !== agents.length) ecarts.push("agent_id en double");
  const adresses = P.signatories.map((x) => x.address);
  if (new Set(adresses).size !== adresses.length) ecarts.push("adresse en double dans signatories");
  return ecarts;
}

const statut = (id, status, reason = null, details = []) => ({ id, status, reason, details });

/**
 * Applique AT-2, AT-3 et AT-4 à une attestation signée dont AT-1 a réussi.
 * @param {object} signee attestation signée
 * @param {object} jeu approver_set
 * @returns {{digest: string, recovered: (string|null)[], at2: object, at3: object, at4: object}}
 */
function verifierSignatures(signee, jeu) {
  const DP = condenseAttestation(signee.attestation);
  const digest = octetsVersHex(DP);
  const at2 = signee.digest === digest ? statut("AT-2", "reussi", null, [digest]) : statut("AT-2", "echoue", null, [`digest ${signee.digest} différent de D_P recalculé ${digest}`]);
  const recovered = [];
  const ecarts3 = [];
  signee.signatures.forEach((s, i) => {
    const r = recouvrerAdresseEip191(DP, hexVersOctets(s.signature));
    recovered.push(r.adresse);
    if (!r.canonique) ecarts3.push(`signatures[${i}] non canonique : ${r.raison}`);
    else if (r.adresse !== s.address) ecarts3.push(`signatures[${i}] recouvre ${r.adresse}, déclarée pour ${s.address}`);
  });
  const at3 = ecarts3.length ? statut("AT-3", "echoue", null, ecarts3) : statut("AT-3", "reussi", null, recovered);
  let at4;
  if (at3.status !== "reussi") {
    at4 = statut("AT-4", "non_execute", "prerequis_en_echec");
  } else {
    const ecarts4 = [];
    const adresses = signee.signatures.map((s) => s.address);
    if (new Set(adresses).size !== adresses.length) ecarts4.push("adresse en double dans signatures");
    const signataires = new Set(signee.attestation.signatories.map((x) => x.address));
    const membres = new Set(jeu.members);
    for (const a of new Set(adresses)) {
      if (!signataires.has(a)) ecarts4.push(`${a} absente de signatories`);
      if (!membres.has(a)) ecarts4.push(`${a} absente du jeu d'approbateurs`);
    }
    const valides = [...new Set(adresses)].filter((a) => signataires.has(a) && membres.has(a)).length;
    if (valides < jeu.threshold.required) ecarts4.push(`${valides} signataire(s) membre(s), seuil ${jeu.threshold.required}`);
    if (jeu.threshold.required > jeu.threshold.size) ecarts4.push("required supérieur à size");
    if (jeu.threshold.size !== jeu.members.length) ecarts4.push(`size ${jeu.threshold.size} différent du nombre de membres ${jeu.members.length}`);
    at4 = ecarts4.length ? statut("AT-4", "echoue", null, ecarts4) : statut("AT-4", "reussi", null, [`${valides} signataire(s), seuil ${jeu.threshold.required} sur ${jeu.threshold.size}`]);
  }
  return { digest, recovered, at2, at3, at4 };
}

/**
 * Vérifie une attestation signée hors de tout dossier (CT-7 EX-7.16) : AT-1
 * à AT-4 seules ; retenue si elles réussissent.
 * @param {unknown} signee attestation signée
 * @param {unknown} jeu jeu d'approbateurs déclaré
 * @returns {{digest: string|null, recovered: (string|null)[]|null, checks: {id: string, status: string, reason: string|null}[], retained: boolean}}
 */
export function verifierAttestationSignee(signee, jeu) {
  const ecarts = [];
  const s1 = validerSchema("attestation-signee", signee);
  const s2 = validerSchema("jeu-approbateurs", jeu);
  if (!s1.valide) ecarts.push(...s1.erreurs);
  if (!s2.valide) ecarts.push(...s2.erreurs);
  if (s1.valide) ecarts.push(...ecartsAttestation(signee.attestation));
  const court = (x) => ({ id: x.id, status: x.status, reason: x.reason });
  if (ecarts.length) {
    return {
      digest: null,
      recovered: null,
      checks: [statut("AT-1", "echoue"), ...["AT-2", "AT-3", "AT-4"].map((id) => statut(id, "non_execute", "prerequis_en_echec"))].map(court),
      retained: false,
    };
  }
  const v = verifierSignatures(signee, jeu);
  const checks = [statut("AT-1", "reussi"), v.at2, v.at3, v.at4].map(court);
  return { digest: v.digest, recovered: v.recovered, checks, retained: checks.every((c) => c.status === "reussi") };
}

/**
 * @typedef {object} ContexteAttestation
 * @property {object|null} evenement l'événement prouvé, s'il est exploitable (E-1 et E-2 réussies sur evenement.json)
 * @property {{exploitable: boolean, cles: Map<string, object>}|null} indexCles cles.json lu
 * @property {object|null} approbations approbations.json exploitable, ou null
 * @property {number} [profondeurMax] borne d'imbrication des JSON lus, la partie et le document de politique :
 *   128 par défaut (CT-1 §4, règle 7, révision 0.5 : même borne et même comptage pour le document)
 */

/**
 * Vérifications AT-1 à AT-7 de la partie attestation-perimetre.json d'un
 * dossier, avec leurs prérequis et raisons de non-exécution (CT-1 §11.4,
 * CT-6 EX-5.12), l'attestation retenue (CT-6 EX-6.19) et les avertissements
 * AV-AT- (CT-6 §5.5, dans l'ordre d'EX-6.15).
 * @param {Uint8Array} octets le fichier de la partie
 * @param {ContexteAttestation} contexte
 * @returns {{verifications: {id: string, status: string, reason: string|null, details: string[]}[],
 *   retenue: boolean, avertissements: string[], digest: string|null}}
 */
export function verifierPartieAttestation(octets, contexte) {
  const { evenement, indexCles, approbations } = contexte;
  const res = new Map();
  const poser = (x) => res.set(x.id, x);

  // AT-1 : la partie, son schéma, les relations d'EX-7.2, le document embarqué.
  let partie = null;
  const ecarts1 = [];
  if (octets.length > TAILLE_MAX_PARTIE) {
    ecarts1.push(`partie de ${octets.length} octets, au-delà de 4 Mio`);
  } else {
    try {
      partie = analyserJson(octets, { profondeurMax: contexte.profondeurMax });
    } catch (e) {
      if (!(e instanceof ErreurJson)) throw e;
      ecarts1.push(`partie illisible : ${e.message}`);
    }
    if (ecarts1.length === 0) {
      if (partie === null || typeof partie !== "object" || Array.isArray(partie)) {
        ecarts1.push("la partie n'est pas un objet JSON");
      } else {
        const s = validerSchema("attestation_perimetre", partie);
        if (!s.valide) ecarts1.push(...s.erreurs.map((e) => `schéma : ${e}`));
        else {
          ecarts1.push(...ecartsAttestation(partie.signed.attestation));
          if (partie.inscription !== null) {
            const ins = partie.inscription.event;
            if (decoderHorodatage(ins.ts) === null) ecarts1.push("inscription : ts qui ne se décode pas");
            if (ins.approval !== null && decoderHorodatage(ins.approval.at) === null) ecarts1.push("inscription : approval.at qui ne se décode pas");
            if (decoderBase64Canonique(partie.inscription.policy_document, TAILLE_MAX_DOCUMENT) === null) {
              ecarts1.push("inscription.policy_document : base64 non canonique ou de plus de 2 097 152 octets décodés");
            }
          }
        }
      }
    }
  }
  if (ecarts1.length) {
    poser(statut("AT-1", "echoue", null, ecarts1));
    for (const id of VERIFICATIONS_PERIMETRE.slice(1)) poser(statut(id, "non_execute", "prerequis_en_echec"));
    return conclure(res, null, contexte, null);
  }
  poser(statut("AT-1", "reussi"));
  const signee = partie.signed;
  const P = signee.attestation;

  // AT-2 à AT-4.
  const v = verifierSignatures(signee, partie.approver_set);
  poser(v.at2);
  poser(v.at3);
  poser(v.at4);

  // AT-5 : liaison à l'événement prouvé.
  if (!evenement) {
    poser(statut("AT-5", "non_execute", "prerequis_en_echec", ["evenement.json inexploitable"]));
  } else {
    const ecarts5 = [];
    if (P.org.org_id !== evenement.org_id) ecarts5.push(`org.org_id ${P.org.org_id} différent de celui de l'événement ${evenement.org_id}`);
    if (!P.journals.some((j) => j.journal_id === evenement.journal_id)) ecarts5.push(`journal ${evenement.journal_id} absent de journals`);
    const ts = decoderHorodatage(evenement.ts);
    if (ts === null || ts < decoderHorodatage(P.validity.from) || ts > decoderHorodatage(P.validity.until)) {
      ecarts5.push(`ts ${evenement.ts} hors de la validité ${P.validity.from} – ${P.validity.until}`);
    }
    poser(ecarts5.length ? statut("AT-5", "echoue", null, ecarts5) : statut("AT-5", "reussi"));
  }

  // AT-6 : inscription.
  if (partie.inscription === null) {
    poser(statut("AT-6", "non_execute", "partie_absente"));
  } else if (v.at2.status !== "reussi" || !evenement || !indexCles?.exploitable) {
    poser(statut("AT-6", "non_execute", "prerequis_en_echec"));
  } else {
    poser(verifierInscription(partie.inscription, evenement, indexCles, v.digest, contexte.profondeurMax));
  }

  // AT-7 : version de politique.
  const at6 = res.get("AT-6");
  if (at6.status === "non_execute" && at6.reason === "partie_absente") {
    poser(statut("AT-7", "non_execute", "partie_absente"));
  } else if (at6.status !== "reussi") {
    poser(statut("AT-7", "non_execute", "prerequis_en_echec"));
  } else {
    const ve = evenement.code.policy_version;
    const vi = partie.inscription.event.execution.arguments.value.policy_version;
    poser(ve === vi ? statut("AT-7", "reussi", null, [ve]) : statut("AT-7", "non_execute", "piece_hors_dossier", [`version de politique de l'événement (${ve}) différente de celle de l'inscription (${vi})`]));
  }
  return conclure(res, partie, contexte, v.digest);
}

function verifierInscription(inscription, evenement, indexCles, digest, profondeurMax) {
  const ins = inscription.event;
  const ecarts = [];
  const { controles, hash } = controlerEvenement(ins, { indexCles });
  // E-1 à E-7, E-11, et la signature sous la clé recorder_key_id de cles.json
  // (partie signature de E-8 : clé absente d'un cles.json exploitable, échec).
  for (const id of ["E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-11", "E-8"]) {
    const r = controles[id];
    if (r.statut !== "reussi") ecarts.push(`${id} ${r.statut === "echoue" ? "en échec" : "non exécuté"}${r.details.length ? " : " + r.details.join(" ; ") : ""}`);
  }
  if (ins.execution?.tool !== NOMS_RESERVES.POLITIQUE) ecarts.push(`execution.tool ${ins.execution?.tool}, ${NOMS_RESERVES.POLITIQUE} attendu`);
  if (ins.org_id !== evenement.org_id || ins.journal_id !== evenement.journal_id) ecarts.push("org_id ou journal_id différent de celui de l'événement prouvé");
  const valeur = ins.execution?.arguments?.value;
  const document = decoderBase64Canonique(inscription.policy_document, TAILLE_MAX_DOCUMENT);
  if (!document) {
    ecarts.push("policy_document illisible");
  } else {
    if (!valeur || sha256Hex(document) !== valeur.policy_sha256) ecarts.push("SHA-256 du document de politique différent de policy_sha256");
    let doc = null;
    try {
      // Même borne et même comptage que les textes du format v0 (CT-1 §4,
      // règle 7, révision 0.5), nombres libres.
      doc = analyserJson(decoderUtf8(document), { nombres: "libres", substituts: "admis", profondeurMax: profondeurMax ?? PROFONDEUR_V0 });
    } catch (e) {
      if (!(e instanceof ErreurJson)) throw e;
      ecarts.push(`document de politique : ${e.message}`);
    }
    if (doc !== null) {
      const perimetre = doc && typeof doc === "object" && !Array.isArray(doc) ? doc.perimeter : undefined;
      const condense = perimetre && typeof perimetre === "object" && !Array.isArray(perimetre) ? perimetre.attestation_digest : undefined;
      if (typeof condense !== "string" || condense !== digest) ecarts.push("perimeter.attestation_digest du document différent de D_P recalculé");
    }
  }
  const seqI = ins.seq;
  if (!(seqI <= evenement.seq)) ecarts.push(`inscription seq ${seqI} postérieure à l'événement prouvé (seq ${evenement.seq})`);
  else if (seqI === evenement.seq) {
    if (hash === null || hash !== hashRecalcule(evenement)) ecarts.push("inscription de même seq que l'événement prouvé mais de hash différent");
  }
  const tsI = decoderHorodatage(ins.ts);
  const tsE = decoderHorodatage(evenement.ts);
  if (tsI === null || tsE === null || tsI > tsE) ecarts.push(`inscription ts ${ins.ts} postérieur à celui de l'événement prouvé ${evenement.ts}`);
  if (ecarts.length) return statut("AT-6", "echoue", null, ecarts);
  if (ins.recorder_key_id !== evenement.recorder_key_id) {
    return statut("AT-6", "non_execute", "ancre_absente", [`inscription signée par ${ins.recorder_key_id}, événement prouvé par ${evenement.recorder_key_id}`]);
  }
  return statut("AT-6", "reussi", null, [`seq ${seqI}, clé ${ins.recorder_key_id}`]);
}

function conclure(res, partie, contexte, digest) {
  const verifications = VERIFICATIONS_PERIMETRE.map((id) => res.get(id));
  const st = (id) => res.get(id);
  const retenue =
    ["AT-1", "AT-2", "AT-3", "AT-4", "AT-5"].every((id) => st(id).status === "reussi") &&
    (st("AT-6").status === "reussi" || (st("AT-6").status === "non_execute" && ["partie_absente", "ancre_absente"].includes(st("AT-6").reason)));
  // Avertissements : (vérification qui le lève, identifiant), triés par l'ordre
  // du rapport de la vérification puis par identifiant (CT-6 EX-6.15).
  const leves = [];
  if (!retenue) {
    let ids = verifications.filter((x) => x.status === "echoue").map((x) => x.id);
    if (ids.length === 0) {
      ids = verifications.filter((x) => x.id !== "AT-7" && x.status === "non_execute" && x.reason === "prerequis_en_echec").map((x) => x.id);
    }
    if (ids.length) leves.push({ check: ids[0], id: "AV-AT-1" });
  }
  if (st("AT-4").status === "reussi" && contexte.approbations && partie) {
    const a = contexte.approbations.approver_set;
    const b = partie.approver_set;
    const memes = new Set(a.members).size === new Set(b.members).size && b.members.every((m) => a.members.includes(m));
    if (!memes || !egaliteJson(a.threshold, b.threshold)) leves.push({ check: "AT-4", id: "AV-AT-2" });
  }
  if (st("AT-7").status === "non_execute" && st("AT-7").reason === "piece_hors_dossier") leves.push({ check: "AT-7", id: "AV-AT-3" });
  leves.sort((x, y) => VERIFICATIONS_PERIMETRE.indexOf(x.check) - VERIFICATIONS_PERIMETRE.indexOf(y.check) || (x.id < y.id ? -1 : x.id > y.id ? 1 : 0));
  return { verifications, retenue, avertissements: leves.map((x) => x.id), digest };
}
