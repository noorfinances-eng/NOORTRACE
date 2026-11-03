// Côté démon de l'interface noyau ↔ service d'approbation (CT-2 §7.5,
// CT-3 §12) : validation de la réponse d'`evaluer` (EX-7.16), vérification
// des remises SG-1 à SG-7 (EX-7.5), vérifications de relais RL-1 à RL-4
// (EX-7.21), MAC de relais (EX-7.22), fichiers des approbations
// (EX-12.23), expiration par le noyau seul (EX-9.4), et interface du service
// (`charger`, `evaluer`, `ouvrir`, `decisions`, `acquitter`, `consommer`,
// `expiration`). Le service d'approbation lui-même (CT-3) est un lot
// suivant ; `service-approbation-factice.mjs` en tient lieu dans les tests.

import path from "node:path";
import fs from "node:fs/promises";
import { createHmac } from "node:crypto";
import {
  condenseApprobation, decoderHorodatage, egaliteJson, objetApprobation, octetsVersHex, verifierEip191, utf8,
  concatener, ErreurJson,
} from "@noortrace/noyau";
import { jcsIntegralOctets, analyserJsonIntegral } from "./jcs-integral.mjs";
import { FichierAjout, decouperLignes, tronquer } from "./fichiers.mjs";
import { ligneIntention } from "./intentions.mjs";
import { IDS, registreSchemas } from "./schema.mjs";
import { ErreurEnregistreur } from "./erreurs.mjs";

/**
 * Borne de `expire_after_ms` (CT-3 7.6 : « E ≤ 86 400 000 ms », schéma de
 * CT-2). Quand la politique de la version d'une `retenue` est introuvable (pièce
 * de politique absente ou illisible au redémarrage), E n'est pas connu : le
 * noyau ne peut pas établir l'échéance `request_ts + E` (EX-9.4) et attend la
 * borne, `request_ts + E_MAX + timeout_ms`, qui n'est jamais antérieure à
 * l'échéance réelle (LISEZMOI, Lectures).
 */
export const E_MAX_MS = 86400000;

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

// ------------------------------------------------------------ MAC de relais

const ETIQUETTE_MAC = utf8("noortrace/relais/v0");

/**
 * MAC de relais (EX-7.22) : HMAC-SHA-256(K_relais, UTF-8("noortrace/relais/v0")
 * ‖ 0x00 ‖ JCS_integral(arguments)), en hexadécimal préfixé.
 * @param {Uint8Array} cle au moins 32 octets
 * @param {unknown} argumentsEnClair
 * @returns {string}
 */
export function macRelais(cle, argumentsEnClair) {
  if (!(cle instanceof Uint8Array) || cle.length < 32) throw new TypeError("clé du MAC de relais : 32 octets au moins");
  const h = createHmac("sha256", cle);
  h.update(concatener(ETIQUETTE_MAC, Uint8Array.of(0), jcsIntegralOctets(argumentsEnClair)));
  return octetsVersHex(new Uint8Array(h.digest()));
}

/** Ligne de contrôle d'un fichier `mac-*` : M calculé sur la chaîne JSON "controle". */
export function ligneControleMac(cle) {
  return { kind: "controle", mac: macRelais(cle, "controle") };
}

// ------------------------------------------------------------ jeux d'approbateurs

const MOTIF_ADRESSE = /^0x[0-9a-f]{40}$/;
const MOTIF_SOURCE = /^(CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?|jeu statique de la politique .{1,128})$/u;

/**
 * Jeu « exploitable » (EX-7.16) : forme de `$defs/approver_set`, `source` de
 * CT-3 EX-8.8, membres distincts, `size` égal au nombre de membres,
 * `required` au plus `size`.
 * @param {unknown} jeu
 */
export function jeuExploitable(jeu) {
  if (!registreSchemas().valider(`${IDS.ticket}#/$defs/approver_set`, jeu).valide) return false;
  if (!MOTIF_SOURCE.test(jeu.source)) return false;
  if (!jeu.members.every((m) => MOTIF_ADRESSE.test(m)) || new Set(jeu.members).size !== jeu.members.length) return false;
  return jeu.threshold.size === jeu.members.length && jeu.threshold.required <= jeu.threshold.size;
}

// ------------------------------------------------------------ réponse d'evaluer

/** Erreur rendue par le service (CT-3 §12.8) ou panne du canal. */
export class ErreurServiceApprobation extends Error {
  /** @param {string} code raison de CT-3 §12.8, ou `indisponible` @param {object} [data] */
  constructor(code, data = {}) {
    super(`service d'approbation : ${code}`);
    this.name = "ErreurServiceApprobation";
    this.code = code;
    this.data = data;
  }
}

const COMBINAISONS = [
  ["autorise", null, false],
  ["refuse", null, false],
  ["a_approuver", "nouveau", false],
  ["a_approuver", "en_attente", false],
  ["autorise", "approuve", true],
  ["refuse", "refuse", true],
  ["refuse", "expire", true],
];

const MEMBRES_EVALUER = ["approval", "approver_set", "decision", "rule", "ticket", "ticket_state"];

/**
 * Validation de la réponse d'`evaluer` (EX-7.16, EX-7.23).
 * @param {unknown} r
 * @param {{decisionScellee: (ticket: string) => object|null, observation?: boolean}} ctx
 *   `decisionScellee` : l'événement de décision scellé par le noyau pour ce ticket, ou null
 * @returns {{valide: true, combinaison: string}|{valide: false, raison: string}}
 */
export function validerReponseEvaluer(r, ctx) {
  const non = (raison) => ({ valide: false, raison });
  if (r === null || typeof r !== "object" || Array.isArray(r)) return non("pas un objet");
  const cles = Object.keys(r).sort();
  if (cles.length !== 6 || !cles.every((c, k) => c === MEMBRES_EVALUER[k])) return non("membres de CT-3 §12.3 attendus");
  const schema = registreSchemas().valider(`${IDS.ticket}#/$defs/reponse_evaluer`, r);
  if (!schema.valide) return non(`forme : ${schema.erreurs[0].pointeur} ${schema.erreurs[0].regle}`);
  if (ctx.observation) {
    // EX-7.23 : seule la réponse sans ticket est admise, rule bornée et sans forme réservée.
    if (r.ticket !== null || r.ticket_state !== null || r.approval !== null || r.approver_set !== null) return non("ticket en mode observation");
    if (r.rule === null || r.rule.length > 998 || /^evaluation impossible( \[|$)/.test(r.rule) || r.rule.includes("[observation")) {
      return non("règle réservée ou trop longue en mode observation");
    }
    return { valide: true, combinaison: "observation" };
  }
  if (r.decision === "a_approuver" && r.rule === null) return non("rule nulle pour a_approuver");
  if ((r.ticket === null) !== (r.ticket_state === null)) return non("ticket et ticket_state incohérents");
  const c = COMBINAISONS.find(([d, t]) => d === r.decision && t === r.ticket_state);
  if (!c) return non("combinaison hors de la table d'EX-7.16");
  const [, etat, scellee] = c;
  if ((r.approval !== null) !== scellee) return non("approval incohérent avec ticket_state");
  if ((r.approver_set !== null) !== (etat === "nouveau")) return non("approver_set incohérent avec ticket_state");
  if (etat === "nouveau" && !jeuExploitable(r.approver_set)) return non("approver_set non exploitable");
  if (scellee) {
    if (r.approval.ticket !== r.ticket || r.approval.decision !== r.ticket_state) return non("approval d'un autre ticket ou d'une autre décision");
    const d = ctx.decisionScellee(r.ticket);
    if (!d) return non("aucune décision scellée par le noyau pour ce ticket (RL-1)");
    if (!egaliteJson(d.approval, r.approval)) return non("approval différent de la décision scellée (RL-1)");
  }
  return { valide: true, combinaison: `${r.decision}/${r.ticket_state ?? "null"}` };
}

// ------------------------------------------------------------ remises (SG-)

/**
 * Vérifications SG-1 à SG-7 d'une remise (EX-7.5), dans l'ordre.
 * @param {unknown} remise
 * @param {{index: import("./index-chaine.mjs").IndexChaine, org_id: string, journal_id: string, instant: number,
 *   politique: (version: string) => object|null}} ctx
 *   `instant` : instant d'écriture prévu de la décision (SG-4, revérifié à `ts`) ;
 *   `politique` : document d'ensemble de politique d'une version
 * @returns {{ok: true, retenue: object}|{ok: false, verification: string, raison: string, decision?: object}}
 */
export function verifierRemise(remise, ctx) {
  const non = (verification, raison, extra = {}) => ({ ok: false, verification, raison, ...extra });
  // SG-1
  const forme = registreSchemas().valider(`${IDS.ticket}#/$defs/remise`, remise);
  if (!forme.valide) return non("SG-1", "remise_mal_formee");
  const a = remise.approval;
  const m = /^(.+)\/([1-9][0-9]{0,9})$/.exec(remise.remise_id);
  if (a.ticket !== remise.ticket || !m || m[1] !== remise.ticket || !MOTIF_SOURCE.test(remise.approver_set.source)) {
    return non("SG-1", "remise_mal_formee");
  }
  // SG-2
  const retenues = ctx.index.retenues.get(remise.ticket) ?? [];
  if (!retenues.length) return non("SG-2", "ticket_inconnu");
  const retenue = retenues.find((e) => e.hash === a.request_hash);
  if (!retenue) return non("SG-2", "request_hash_different");
  // SG-3
  const deja = ctx.index.decisions.get(remise.ticket);
  if (deja) return non("SG-3", "ticket_deja_decide", { decision: deja });
  // SG-4 : la politique de la version de la `retenue` donne E ; introuvable, l'échéance
  // ne peut pas être établie et la vérification échoue (jamais sautée).
  const politique = ctx.politique(retenue.code.policy_version);
  if (a.decision === "approuve" || a.decision === "refuse") {
    const E = delaiExpiration(politique);
    if (E === null || !(ctx.instant < decoderHorodatage(retenue.ts) + E)) return non("SG-4", "echeance_depassee");
  }
  // SG-5 (E-5, E-9)
  if (a.approvers.length !== a.signatures.length) return non("SG-5", "signature_invalide");
  const A = objetApprobation({ approval: a, org_id: ctx.org_id, journal_id: ctx.journal_id });
  const D = condenseApprobation(A);
  for (let k = 0; k < a.signatures.length; k++) {
    if (!verifierEip191(D, a.signatures[k], a.approvers[k])) return non("SG-5", "signature_invalide");
  }
  // SG-6 (A-3)
  const jeu = remise.approver_set;
  if (new Set(a.approvers).size !== a.approvers.length) return non("SG-6", "approbateur_double");
  if (!a.approvers.every((x) => jeu.members.includes(x))) return non("SG-6", "approbateur_hors_jeu");
  if (
    a.threshold.required !== jeu.threshold.required ||
    a.threshold.size !== jeu.threshold.size ||
    jeu.threshold.required > jeu.threshold.size ||
    jeu.threshold.size !== jeu.members.length
  ) {
    return non("SG-6", "seuil_different_du_jeu");
  }
  if (a.decision === "expire" && a.approvers.length > 0) return non("SG-6", "expire_avec_signatures");
  if ((a.decision === "approuve" || a.decision === "refuse") && a.approvers.length < a.threshold.required) return non("SG-6", "seuil_non_atteint");
  // SG-7 : sans approbateur, rien à vérifier ; sinon la politique de la version de la
  // `retenue` est requise : introuvable, la vérification échoue (jamais sautée). Une
  // politique présente sans `separation.self_approval: "interdite"` ne l'exige pas.
  if (a.approvers.length > 0) {
    if (!estObjet(politique)) return non("SG-7", "auto_approbation");
    const sep = politique.approval?.rules?.separation;
    if (sep?.self_approval === "interdite") {
      const id = (sep.identities ?? []).find((x) => x.launched_by === retenue.delegation.launched_by);
      if (id && a.approvers.some((x) => id.addresses.includes(x))) return non("SG-7", "auto_approbation");
    }
  }
  return { ok: true, retenue };
}

/**
 * `expire_after_ms` d'une version de politique (CT-3 EX-7.10), ou null.
 * @param {object|null} politique
 * @returns {number|null}
 */
export function delaiExpiration(politique) {
  const E = politique?.approval?.expire_after_ms;
  return Number.isSafeInteger(E) ? E : null;
}

// ------------------------------------------------------------ relais (RL-)

/**
 * Vérifications de relais RL-1 à RL-4 (EX-7.21), dans l'ordre.
 * @param {{ticket: string, tool: string, delegation: object, arguments: object, mac: string,
 *   approvalReponse: object|null, instant: number, timeoutOutil: number}} appel
 * @param {{index: object, macs: Map<string, string>, intentionsOuvertes: Set<string>, relaisEnCours: Set<string>,
 *   politique: (version: string) => object|null}} ctx
 *   `macs` : request_hash → MAC inscrit pour la retenue ; `intentionsOuvertes`, `relaisEnCours` : tickets
 * @returns {{ok: true, retenue: object, decision: object}|{ok: false, verification: string}}
 */
export function verifierRelais(appel, ctx) {
  const non = (verification) => ({ ok: false, verification });
  const decision = ctx.index.decisions.get(appel.ticket);
  // RL-1
  if (!decision || decision.approval.decision !== "approuve") return non("RL-1");
  if (appel.approvalReponse !== null && !egaliteJson(appel.approvalReponse, decision.approval)) return non("RL-1");
  // RL-2
  const retenue = ctx.index.retenuesParHash.get(decision.approval.request_hash);
  if (!retenue) return non("RL-2");
  const d = appel.delegation;
  const r = retenue.delegation;
  const refR = retenue.execution.arguments;
  const refA = appel.arguments;
  if (
    retenue.execution.tool !== appel.tool ||
    r.launched_by !== d.launched_by ||
    r.on_behalf_of !== d.on_behalf_of ||
    r.scope !== d.scope ||
    refR.sha256 !== refA.sha256 ||
    refR.length !== refA.length ||
    refR.redacted !== refA.redacted
  ) {
    return non("RL-2");
  }
  const macInscrit = ctx.macs.get(retenue.hash);
  if (!macInscrit || macInscrit !== appel.mac) return non("RL-2");
  // RL-3
  if (ctx.index.premiersExecutes.has(appel.ticket) || ctx.intentionsOuvertes.has(appel.ticket) || ctx.relaisEnCours.has(appel.ticket)) {
    return non("RL-3");
  }
  // RL-4 : E de la version de la `retenue` ; politique introuvable : échec (jamais sautée).
  const E = delaiExpiration(ctx.politique(retenue.code.policy_version));
  if (E === null || !(appel.instant + appel.timeoutOutil < decoderHorodatage(decision.approval.at) + E)) return non("RL-4");
  return { ok: true, retenue, decision };
}

// ------------------------------------------------------------ expiration par le noyau seul

/** Raison fixe d'une expiration par le noyau seul (EX-9.4). */
export const RAISON_EXPIRATION_NOYAU = "expire par l'enregistreur, service d'approbation sans reponse";

/**
 * `approval` (sans `at`) d'une expiration par le noyau seul (EX-9.4) et le
 * jeu retenu : dernière remise au jeu exploitable, à défaut celui de la
 * réponse `nouveau` (ligne `retenue`).
 * @param {string} ticket
 * @param {object} retenue événement `retenue`
 * @param {{retenues: Map<string, object[]>, remises: Map<string, object[]>}} fichiers état relu des fichiers des approbations
 * @returns {{approval: object, approver_set: object}|null}
 */
export function approvalExpiration(ticket, retenue, fichiers) {
  const remises = (fichiers.remises.get(ticket) ?? []).filter((l) => jeuExploitable(l.approver_set));
  let jeu = remises.length ? remises[remises.length - 1].approver_set : null;
  if (!jeu) {
    const lr = (fichiers.retenues.get(ticket) ?? []).find((l) => l.request_hash === retenue.hash) ?? (fichiers.retenues.get(ticket) ?? [])[0];
    jeu = lr?.approver_set ?? null;
  }
  if (!jeu) return null;
  return {
    approval: {
      decision: "expire",
      ticket,
      request_hash: retenue.hash,
      threshold: { required: jeu.threshold.required, size: jeu.threshold.size },
      approvers: [],
      signatures: [],
      reason: RAISON_EXPIRATION_NOYAU,
    },
    approver_set: jeu,
  };
}

// ------------------------------------------------------------ fichiers des approbations

/**
 * Ligne `remise` d'EX-12.23 (`{ kind, ticket, remise_id, decision,
 * approver_set }`) d'un message reçu de `decisions`, ou null quand le message
 * n'a pas les membres qui la forment (objet, `ticket` et `remise_id` chaînes,
 * `approval` objet de `decision` chaîne, `approver_set` objet) : un tel message
 * n'est pas une remise (`$defs/remise`), SG-1 le refuse, et son jeu ne serait de
 * toute façon jamais exploitable (EX-9.4, EX-7.16).
 * @param {unknown} remise
 * @returns {object|null}
 */
export function ligneRemise(remise) {
  if (!estObjet(remise) || typeof remise.ticket !== "string" || typeof remise.remise_id !== "string") return null;
  if (!estObjet(remise.approval) || typeof remise.approval.decision !== "string" || !estObjet(remise.approver_set)) return null;
  return { kind: "remise", ticket: remise.ticket, remise_id: remise.remise_id, decision: remise.approval.decision, approver_set: remise.approver_set };
}

/**
 * Fichiers des approbations d'une époque (EX-12.23) :
 * `approbations/approbations-<epoch>.ndjson` et `approbations/mac-<epoch>.ndjson`
 * (ligne de contrôle en tête), en ajout seul, lignes JCS intégral, fdatasync.
 */
export class FichiersApprobations {
  /**
   * @param {string} repertoireJournal
   * @param {number} epoque
   * @param {Uint8Array} cleMac
   */
  constructor(repertoireJournal, epoque, cleMac) {
    this.dir = path.join(repertoireJournal, "approbations");
    this.epoque = epoque;
    this.cleMac = cleMac;
    /** État relu et tenu à jour. */
    this.retenues = new Map();
    this.remises = new Map();
    this.decisions = new Map();
    this.macs = new Map();
    this.continuations = new Map();
    this.controle = null;
    /** Vrai après un échec d'écriture : réouverture avant toute nouvelle ligne. */
    this.enPanne = false;
  }

  /** Relit tous les fichiers (ordre des époques), puis ouvre ceux de l'époque. */
  async ouvrir() {
    await fs.mkdir(this.dir, { recursive: true, mode: 0o700 });
    await this.relire();
    const suffixe = `${String(this.epoque).padStart(20, "0")}.ndjson`;
    this.fA = await FichierAjout.ouvrir(path.join(this.dir, `approbations-${suffixe}`), { creer: true, existantAdmis: true });
    this.fM = await FichierAjout.ouvrir(path.join(this.dir, `mac-${suffixe}`), { creer: true, existantAdmis: true });
    if (this.fM.taille === 0) {
      await this.fM.ajouter(ligneIntention(ligneControleMac(this.cleMac)));
      await this.fM.synchroniser();
    }
  }

  async relire() {
    const noms = (await fs.readdir(this.dir)).filter((n) => /^(approbations|mac)-[0-9]{20}\.ndjson$/.test(n));
    noms.sort((x, y) => x.slice(-27).localeCompare(y.slice(-27)) || x.localeCompare(y));
    let dernierControle = null;
    for (const nom of noms) {
      const chemin = path.join(this.dir, nom);
      const lignes = decouperLignes(new Uint8Array(await fs.readFile(chemin)));
      for (let k = 0; k < lignes.length; k++) {
        let o = null;
        try {
          if (lignes[k].complete) o = analyserJsonIntegral(lignes[k].octets);
        } catch (e) {
          if (!(e instanceof ErreurJson)) throw e;
        }
        if (o === null || typeof o !== "object") {
          if (k === lignes.length - 1) {
            await tronquer(chemin, lignes[k].debut);
            break;
          }
          throw new Error(`fichier des approbations corrompu : ${nom}, ligne ${k + 1}`);
        }
        this.appliquer(o, nom.startsWith("mac-"));
        if (o.kind === "controle") dernierControle = o.mac;
      }
    }
    this.controle = dernierControle;
  }

  appliquer(o, mac) {
    const ajouter = (m, t, v) => {
      if (!m.has(t)) m.set(t, []);
      m.get(t).push(v);
    };
    if (mac) {
      if (o.kind !== "controle" && o.request_hash) this.macs.set(o.request_hash, o.mac);
      return;
    }
    if (o.kind === "retenue") ajouter(this.retenues, o.ticket, o);
    else if (o.kind === "remise") ajouter(this.remises, o.ticket, o);
    else if (o.kind === "decision") this.decisions.set(o.ticket, o);
    else if (o.kind === "continuation" || o.kind === "continuation_consommee") ajouter(this.continuations, o.ticket, o);
  }

  /**
   * Ligne de contrôle du dernier fichier `mac-*` relu, comparée à la clé
   * courante (EX-7.22) : `null` si aucun fichier, sinon égalité.
   * @returns {boolean|null}
   */
  controleConcorde() {
    return this.controle === null ? null : this.controle === ligneControleMac(this.cleMac).mac;
  }

  async _ecrire(f, objet) {
    await f.ajouter(ligneIntention(objet));
  }

  /**
   * Écriture d'une ou plusieurs lignes et de leurs fdatasync. Un échec de
   * `write` ou de `fdatasync` (erreur d'entrée-sortie) est, comme pour un
   * segment (EX-12.8), fatal pour les descripteurs ouverts : le fichier est
   * marqué en panne et l'erreur rendue comme panne de stockage
   * (ErreurEnregistreur `stockage`, EX-7.19 pas 2) ; la ligne suivante n'est
   * écrite qu'après la réouverture, qui relit les fichiers et coupe une
   * dernière ligne incomplète (EX-12.23) : aucune ligne n'est ajoutée derrière
   * une ligne tronquée.
   * @param {() => Promise<void>} f
   */
  async _io(f) {
    if (this.enPanne) await this.rouvrir();
    try {
      await f();
    } catch (e) {
      this.enPanne = true;
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible (fichiers des approbations)", { cause: e });
    }
  }

  /** Réouverture après une panne : état relu des fichiers, descripteurs neufs. */
  async rouvrir() {
    await this.fermer();
    this.retenues = new Map();
    this.remises = new Map();
    this.decisions = new Map();
    this.macs = new Map();
    this.continuations = new Map();
    try {
      await this.ouvrir();
    } catch (e) {
      throw new ErreurEnregistreur("stockage", "noortrace: stockage indisponible (fichiers des approbations)", { cause: e });
    }
    this.enPanne = false;
  }

  /**
   * Lignes `retenue` et MAC, écrites après la signature de l'événement
   * `retenue` et avant son ajout au segment, sous un même fdatasync (EX-12.23).
   */
  async inscrireRetenue(p) {
    const ligne = { kind: "retenue", ticket: p.ticket, request_seq: p.request_seq, request_hash: p.request_hash, approver_set: p.approver_set };
    await this._io(async () => {
      await this._ecrire(this.fA, ligne);
      await this._ecrire(this.fM, { ticket: p.ticket, request_hash: p.request_hash, mac: p.mac });
      await this.fA.synchroniser();
      await this.fM.synchroniser();
    });
    this.appliquer(ligne, false);
    this.macs.set(p.request_hash, p.mac);
  }

  /**
   * Ligne `remise`, fdatasync avant sa vérification (EX-7.19 pas 2). Le
   * message doit permettre de former la ligne (`ligneRemise`) : sinon il n'y a
   * pas de remise à inscrire et SG-1 le refuse.
   */
  async inscrireRemise(remise) {
    const ligne = ligneRemise(remise);
    if (!ligne) throw new TypeError("remise sans les membres de sa ligne (SG-1)");
    await this._io(async () => {
      await this._ecrire(this.fA, ligne);
      await this.fA.synchroniser();
    });
    this.appliquer(ligne, false);
  }

  /** Ligne `decision`, après signature et avant ajout au segment (EX-12.23). */
  async inscrireDecision(p) {
    const ligne = { kind: "decision", ticket: p.ticket, seq: p.seq, hash: p.hash, approver_set: p.approver_set };
    await this._io(async () => {
      await this._ecrire(this.fA, ligne);
      await this.fA.synchroniser();
    });
    this.appliquer(ligne, false);
  }

  /**
   * Jeu d'approbateurs d'une décision pour l'exportateur (EX-12.23) : ligne
   * `decision`, à défaut dernière remise exploitable de même décision, à
   * défaut (expire) la règle d'EX-9.4.
   * @param {object} evenementDecision
   * @returns {object|null}
   */
  jeuDecision(evenementDecision) {
    const t = evenementDecision.approval.ticket;
    const l = this.decisions.get(t);
    if (l && l.hash === evenementDecision.hash) return l.approver_set;
    const remises = (this.remises.get(t) ?? []).filter((r) => jeuExploitable(r.approver_set));
    const meme = remises.filter((r) => r.decision === evenementDecision.approval.decision);
    if (meme.length) return meme[meme.length - 1].approver_set;
    if (evenementDecision.approval.decision === "expire") {
      if (remises.length) return remises[remises.length - 1].approver_set;
      return (this.retenues.get(t) ?? [])[0]?.approver_set ?? null;
    }
    return null;
  }

  async fermer() {
    await this.fA?.fermer();
    await this.fM?.fermer();
  }
}

// ------------------------------------------------------------ interface du service

/**
 * Interface du service d'approbation vue du noyau (CT-3 §12, EX-7.14).
 * Chaque méthode rend l'objet de réponse ou lève ErreurServiceApprobation.
 * @abstract
 */
export class ServiceApprobation {
  async charger(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async evaluer(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async ouvrir(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async decisions(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async acquitter(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async consommer(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
  async expiration(requete) {
    void requete;
    throw new ErreurServiceApprobation("indisponible");
  }
}
