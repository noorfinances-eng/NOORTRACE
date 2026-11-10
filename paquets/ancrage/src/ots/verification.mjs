// Vérifications O-1 à O-5 et O-7 de CT-6 §10.4 (EX-10.5 à EX-10.9, EX-10.11),
// exécutées par le composant d'ancrage à la création d'une preuve, à sa mise
// à niveau (CT-5 EX-6.6) et contre ses propres en-têtes (EX-6.9). O-6
// (profondeur) n'est jamais exécutée ici : le composant ne tient compte
// d'aucun nombre de confirmations (EX-6.7), c'est le réviseur qui l'exige.
//
// Deux modes pour O-5 :
// - sans `ancre` (le défaut, EX-6.9 : « EX-10.9 sans point de contrôle de
//   réviseur ») : le premier en-tête du fichier joue le rôle du point de
//   contrôle (c = s) ; chaînage, preuve de travail, difficulté et médiane des
//   heures sont contrôlés au-dessus de lui ; aucun hachage attendu ;
// - avec `ancre` (l'ancre `bitcoin` d'un fichier d'ancres de CT-6 §12.2, ou
//   `null`) : EX-10.9 telle qu'elle est écrite, règles 1 à 6, ce qui permet
//   de rejouer les vecteurs de CT-6 ; `ancre` nul rend O-5 `non_execute`
//   (`ancre_absente`).

import { octetsVersHex, hexVersOctets } from "@noortrace/noyau";
import { lireOts, ErreurOts, PROFIL_V0, appliquerOperation, BORNES } from "./format.mjs";
import { lireFichierEntetes, premierDefautDeChainage, setCompact, getCompact, hachageEnEntier, RESEAUX, BORNES_ENTETES, ErreurEntetes } from "./entetes.mjs";

/** Statuts d'une vérification (CT-6 §6.1). */
export const STATUT = Object.freeze({ REUSSI: "reussi", ECHOUE: "echoue", NON_EXECUTE: "non_execute" });
/** Raisons de non-exécution (CT-6 §6.2). */
export const RAISON = Object.freeze({
  PARTIE_ABSENTE: "partie_absente",
  ANCRE_ABSENTE: "ancre_absente",
  HORS_PERIMETRE_VERSION: "hors_perimetre_version",
  PREREQUIS_EN_ECHEC: "prerequis_en_echec",
});
/** Vérifications rendues par `verifierOts`. */
export const VERIFICATIONS = Object.freeze(["O-1", "O-2", "O-3", "O-4", "O-5", "O-7"]);

/**
 * Exécute les opérations du profil depuis l'empreinte (O-3, EX-10.7) et
 * collecte les attestations avec le message de leur nœud.
 * @param {import("./format.mjs").Noeud} arbre
 * @param {Uint8Array} empreinte
 * @returns {{attestations: object[], defauts: string[]}}
 */
export function executerArbre(arbre, empreinte) {
  const attestations = [];
  const defauts = [];
  const parcourir = (noeud, message, chemin, profondeur) => {
    for (const a of noeud.attestations) {
      attestations.push({
        genre: a.genre,
        hauteur: a.hauteur,
        uri: a.uri,
        etiquette: octetsVersHex(a.etiquette),
        chemin,
        resultat: chemin === "profil" ? message : null,
        operations: profondeur,
      });
    }
    for (const o of noeud.operations) {
      if (chemin !== "profil") {
        parcourir(o.noeud, null, chemin, profondeur + 1);
        continue;
      }
      if (!PROFIL_V0.has(o.code)) {
        parcourir(o.noeud, null, "hors_profil", profondeur + 1);
        continue;
      }
      const suivant = appliquerOperation(o.code, o.argument, message);
      if (suivant === null) {
        defauts.push(`opération 0x${o.code.toString(16)} : message ou résultat hors de [1, ${BORNES.MESSAGE_MAX}] octets`);
        parcourir(o.noeud, null, "echec", profondeur + 1);
        continue;
      }
      parcourir(o.noeud, suivant, "profil", profondeur + 1);
    }
  };
  parcourir(arbre, empreinte, "profil", 0);
  return { attestations, defauts };
}

/** Plus petite et plus grande hauteur Bitcoin attestées (toutes branches), ou null. */
export function hauteursAttestees(arbre) {
  let min = null;
  let max = null;
  const parcourir = (noeud) => {
    for (const a of noeud.attestations) {
      if (a.genre !== "bitcoin") continue;
      if (min === null || a.hauteur < min) min = a.hauteur;
      if (max === null || a.hauteur > max) max = a.hauteur;
    }
    for (const o of noeud.operations) parcourir(o.noeud);
  };
  parcourir(arbre);
  return min === null ? null : { min, max };
}

/**
 * État d'une preuve (CT-5 EX-6.7) : `complete` si elle porte au moins une
 * attestation Bitcoin, `en_attente` sinon. Lève `ErreurOts` si illisible.
 * @param {Uint8Array} octets
 */
export function etatPreuve(octets) {
  const { arbre } = lireOts(octets);
  return hauteursAttestees(arbre) === null ? "en_attente" : "complete";
}

/**
 * O-5 (EX-10.9) sur un fichier d'en-têtes lu.
 * @param {ReturnType<typeof lireFichierEntetes>} entetes
 * @param {{ancre?: object|null, reseau?: string|null}} options
 * @returns {{statut: string, raison: string|null, detail: string, c: number|null}}
 */
export function verifierChaineEntetes(entetes, { ancre, reseau = null } = {}) {
  const { enTetes, network } = entetes;
  const s = entetes.start_height;
  const t = entetes.end_height;
  const echecs = [];
  const nonApplicables = [];
  const modeReviseur = ancre !== undefined;
  let c;

  // Règle 1 : réseau.
  if (modeReviseur) {
    if (ancre.network !== network) echecs.push(`règle 1 : réseau du fichier ${network}, réseau de l'ancre ${ancre.network}`);
  } else if (reseau !== null && reseau !== network) {
    echecs.push(`règle 1 : réseau du fichier ${network}, réseau configuré ${reseau}`);
  }
  const parametres = RESEAUX[network];

  // Règle 2 : chaînage sur toute la suite.
  const defaut = premierDefautDeChainage(enTetes);
  if (defaut !== null) echecs.push(`règle 2 : en-tête ${s + defaut} non chaîné à ${s + defaut - 1}`);

  // Règle 3 : point de contrôle.
  if (modeReviseur) {
    c = ancre.checkpoint.height;
    if (c < s || c > t) nonApplicables.push(`règle 3 : point de contrôle ${c} hors du fichier [${s}, ${t}]`);
    else if (enTetes[c - s].hashAffiche !== ancre.checkpoint.hash) echecs.push(`règle 3 : hachage de l'en-tête ${c} différent du point de contrôle`);
  } else {
    c = s;
  }

  if (c >= s && c <= t) {
    for (let i = c + 1; i <= t; i += 1) {
      const H = enTetes[i - s];
      // Règle 4 : preuve de travail.
      const { cible, negatif, debordement } = setCompact(H.nBits);
      if (negatif || debordement || cible === 0n || cible > parametres.powLimit) {
        echecs.push(`règle 4 : cible de l'en-tête ${i} négative, nulle, en débordement ou au-dessus de powLimit`);
      } else if (hachageEnEntier(H.hash) > cible) {
        echecs.push(`règle 4 : l'en-tête ${i} ne satisfait pas sa cible`);
      }
      // Règle 5 : difficulté.
      if (parametres.nBitsFixe !== null) {
        if (H.nBits !== parametres.nBitsFixe) echecs.push(`règle 5 : nBits de l'en-tête ${i} différent de la constante regtest`);
      } else if (i % BORNES_ENTETES.INTERVALLE_RETARGET !== 0) {
        if (H.nBits !== enTetes[i - 1 - s].nBits) echecs.push(`règle 5 : nBits de l'en-tête ${i} différent du précédent hors réajustement`);
      } else if (i - BORNES_ENTETES.INTERVALLE_RETARGET < s) {
        nonApplicables.push(`règle 5 : réajustement à ${i} sans l'en-tête ${i - BORNES_ENTETES.INTERVALLE_RETARGET}`);
      } else {
        const precedent = enTetes[i - 1 - s];
        const ancien = enTetes[i - BORNES_ENTETES.INTERVALLE_RETARGET - s];
        let delta = precedent.nTime - ancien.nTime;
        if (delta < 302400) delta = 302400;
        if (delta > 4838400) delta = 4838400;
        let nouvelle = (setCompact(precedent.nBits).cible * BigInt(delta)) / 1209600n;
        if (nouvelle > parametres.powLimit) nouvelle = parametres.powLimit;
        if (H.nBits !== getCompact(nouvelle)) echecs.push(`règle 5 : nBits de l'en-tête ${i} différent du réajustement attendu`);
      }
      // Règle 6 : médiane des onze heures précédentes.
      if (i - 11 >= s) {
        const heures = [];
        for (let k = i - 11; k <= i - 1; k += 1) heures.push(enTetes[k - s].nTime);
        heures.sort((a, b) => a - b);
        if (!(H.nTime > heures[5])) echecs.push(`règle 6 : nTime de l'en-tête ${i} inférieur ou égal à la médiane des onze précédents`);
      }
    }
  }

  if (echecs.length > 0) return { statut: STATUT.ECHOUE, raison: null, detail: [...echecs, ...nonApplicables].join(" ; "), c };
  if (nonApplicables.length > 0) return { statut: STATUT.NON_EXECUTE, raison: RAISON.ANCRE_ABSENTE, detail: nonApplicables.join(" ; "), c };
  return { statut: STATUT.REUSSI, raison: null, detail: `en-têtes ${s} à ${t} chaînés, travail et difficulté contrôlés au-dessus de ${c}`, c };
}

/**
 * Vérifie une preuve `.ots` : O-1, O-2, O-3, O-7, et O-4, O-5 quand des
 * en-têtes sont fournis.
 * @param {{octets: Uint8Array, empreinteAttendue: string|Uint8Array, entetes?: Uint8Array|object|null, ancre?: object|null, reseau?: string|null}} p
 * @returns {{checks: object, raisons: object, details: object, attestations: object[], etat: string|null, empreinte: string|null, retenue: object|null, avertissements: string[]}}
 */
export function verifierOts({ octets, empreinteAttendue, entetes = null, ancre, reseau = null }) {
  const checks = {};
  const raisons = {};
  const details = {};
  const avertissements = new Set();
  for (const id of VERIFICATIONS) {
    checks[id] = STATUT.NON_EXECUTE;
    raisons[id] = RAISON.PREREQUIS_EN_ECHEC;
    details[id] = "";
  }
  const poser = (id, statut, raison = null, detail = "") => {
    checks[id] = statut;
    raisons[id] = statut === STATUT.NON_EXECUTE ? raison : null;
    details[id] = detail;
  };
  const resultat = { checks, raisons, details, attestations: [], etat: null, empreinte: null, retenue: null, avertissements: [] };

  // O-1 : format.
  let lu;
  try {
    lu = lireOts(octets);
  } catch (e) {
    if (!(e instanceof ErreurOts)) throw e;
    poser("O-1", STATUT.ECHOUE, null, `${e.code} : ${e.message}`);
    for (const id of VERIFICATIONS.slice(1)) details[id] = "O-1 en échec";
    return resultat;
  }
  poser("O-1", STATUT.REUSSI, null, `${lu.taille} octets, empreinte ${lu.empreinteHex}`);
  resultat.empreinte = lu.empreinteHex;
  const hauteurs = hauteursAttestees(lu.arbre);
  resultat.etat = hauteurs === null ? "en_attente" : "complete";

  // O-2 : empreinte.
  let attendue = null;
  try {
    attendue = typeof empreinteAttendue === "string" ? hexVersOctets(empreinteAttendue, 32) : empreinteAttendue;
  } catch {
    attendue = null;
  }
  if (!(attendue instanceof Uint8Array) || attendue.length !== 32) {
    poser("O-2", STATUT.NON_EXECUTE, RAISON.PREREQUIS_EN_ECHEC, "empreinte attendue absente ou mal formée");
  } else if (octetsVersHex(attendue) === lu.empreinteHex) {
    poser("O-2", STATUT.REUSSI, null, "empreinte du fichier égale à l'empreinte attendue");
  } else {
    poser("O-2", STATUT.ECHOUE, null, `empreinte du fichier ${lu.empreinteHex}, attendue ${octetsVersHex(attendue)}`);
  }

  // O-3 : opérations.
  const execution = executerArbre(lu.arbre, lu.empreinte);
  const attestations = execution.attestations.map((a) => ({ ...a, resultat: a.resultat === null ? null : octetsVersHex(a.resultat), statut: STATUT.NON_EXECUTE, raison: null }));
  resultat.attestations = attestations;
  if (execution.defauts.length > 0) poser("O-3", STATUT.ECHOUE, null, execution.defauts.join(" ; "));
  else poser("O-3", STATUT.REUSSI, null, `${attestations.length} attestation(s) atteinte(s)`);
  for (const a of attestations) {
    // AV-O-2 : attestation en attente, inconnue ou hors profil, non exploitée.
    if (a.genre !== "bitcoin" || a.chemin === "hors_profil") avertissements.add("AV-O-2");
    if (a.chemin === "hors_profil") a.raison = RAISON.HORS_PERIMETRE_VERSION;
    else if (a.chemin === "echec") a.raison = RAISON.PREREQUIS_EN_ECHEC;
    else if (a.genre !== "bitcoin") a.raison = RAISON.PARTIE_ABSENTE;
  }

  // O-7 : attestation Bitcoin présente.
  if (hauteurs !== null) poser("O-7", STATUT.REUSSI, null, `attestation(s) Bitcoin aux hauteurs ${hauteurs.min} à ${hauteurs.max}`);
  else poser("O-7", STATUT.NON_EXECUTE, RAISON.PARTIE_ABSENTE, `aucune attestation Bitcoin : ${attestations.length} attestation(s) en attente ou inconnue(s)`);

  // O-5 : chaîne d'en-têtes.
  let entetesLus = null;
  if (checks["O-7"] !== STATUT.REUSSI) {
    poser("O-5", STATUT.NON_EXECUTE, RAISON.PARTIE_ABSENTE, "aucune attestation Bitcoin");
  } else if (entetes === null || entetes === undefined) {
    poser("O-5", STATUT.NON_EXECUTE, RAISON.PARTIE_ABSENTE, "fichier d'en-têtes non fourni");
  } else if (ancre === null) {
    poser("O-5", STATUT.NON_EXECUTE, RAISON.ANCRE_ABSENTE, "ancre bitcoin non fournie");
  } else {
    try {
      entetesLus = lireFichierEntetes(entetes);
    } catch (e) {
      if (!(e instanceof ErreurEntetes)) throw e;
      poser("O-5", STATUT.NON_EXECUTE, RAISON.PREREQUIS_EN_ECHEC, `fichier d'en-têtes inexploitable : ${e.message}`);
    }
    if (entetesLus !== null) {
      const o5 = verifierChaineEntetes(entetesLus, { ancre, reseau });
      poser("O-5", o5.statut, o5.raison, o5.detail);
      // AV-O-3 : O-5 exécutée (réussie ou en échec) sur le réseau regtest.
      if (o5.statut !== STATUT.NON_EXECUTE && entetesLus.network === "regtest") avertissements.add("AV-O-3");
    }
  }

  // O-4 : attestation Bitcoin contre l'en-tête.
  if (checks["O-3"] !== STATUT.REUSSI || checks["O-5"] !== STATUT.REUSSI) {
    const raison =
      checks["O-3"] === STATUT.ECHOUE || checks["O-5"] === STATUT.ECHOUE || raisons["O-3"] === RAISON.PREREQUIS_EN_ECHEC || raisons["O-5"] === RAISON.PREREQUIS_EN_ECHEC
        ? RAISON.PREREQUIS_EN_ECHEC
        : raisons["O-5"];
    poser("O-4", STATUT.NON_EXECUTE, raison, "O-3 ou O-5 non réussie");
    for (const a of attestations) if (a.genre === "bitcoin" && a.chemin === "profil") a.raison = raison;
  } else {
    let concordantes = 0;
    let comparees = 0;
    const s = entetesLus.start_height;
    const t = entetesLus.end_height;
    for (const a of attestations) {
      if (a.genre !== "bitcoin" || a.chemin !== "profil") continue;
      if (a.hauteur < s || a.hauteur > t) {
        a.statut = STATUT.NON_EXECUTE;
        a.raison = RAISON.ANCRE_ABSENTE;
        continue;
      }
      comparees += 1;
      const racine = octetsVersHex(entetesLus.enTetes[a.hauteur - s].racine);
      if (a.resultat !== null && a.resultat.length === 66 && a.resultat === racine) {
        a.statut = STATUT.REUSSI;
        concordantes += 1;
        if (resultat.retenue === null || a.hauteur < resultat.retenue.hauteur) {
          resultat.retenue = { hauteur: a.hauteur, hash: entetesLus.enTetes[a.hauteur - s].hashAffiche };
        }
      } else {
        a.statut = STATUT.ECHOUE;
      }
    }
    if (concordantes > 0) {
      poser("O-4", STATUT.REUSSI, null, `${concordantes} attestation(s) concordante(s) sur ${comparees} comparée(s)`);
      if (comparees > concordantes) avertissements.add("AV-O-1");
    } else if (comparees > 0) {
      poser("O-4", STATUT.ECHOUE, null, `${comparees} attestation(s) comparée(s), aucune ne concorde avec la racine de son en-tête`);
    } else if (attestations.some((a) => a.genre === "bitcoin" && a.chemin === "hors_profil") && !attestations.some((a) => a.genre === "bitcoin" && a.chemin === "profil")) {
      // Toutes les attestations Bitcoin sont sous une opération hors profil (EX-10.7, EX-10.12) : aucune date n'est établie.
      poser("O-4", STATUT.NON_EXECUTE, RAISON.HORS_PERIMETRE_VERSION, "attestation sous une opération hors du profil de la version 0 : non vérifiée ; aucune date n'est établie");
    } else {
      poser("O-4", STATUT.NON_EXECUTE, RAISON.ANCRE_ABSENTE, "aucune hauteur attestée dans le fichier d'en-têtes");
    }
  }

  resultat.avertissements = [...avertissements].sort();
  return resultat;
}

/**
 * Condition d'écriture d'une preuve fusionnée (CT-5 EX-6.6) : O-1 et O-3
 * réussies ; O-4 et O-5 non en échec quand des en-têtes sont fournis.
 * @param {ReturnType<typeof verifierOts>} v
 * @returns {{admise: boolean, motifs: string[]}}
 */
export function admissionApresFusion(v) {
  const motifs = [];
  if (v.checks["O-1"] !== STATUT.REUSSI) motifs.push("O-1");
  if (v.checks["O-3"] !== STATUT.REUSSI) motifs.push("O-3");
  if (v.checks["O-4"] === STATUT.ECHOUE) motifs.push("O-4");
  if (v.checks["O-5"] === STATUT.ECHOUE) motifs.push("O-5");
  return { admise: motifs.length === 0, motifs };
}
