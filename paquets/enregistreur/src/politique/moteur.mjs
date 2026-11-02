// Moteur de politique du démon `noortrace` (CT-2 §3.1, 7.2, 7.5, 14.2, 14.6 ;
// CT-3 §11 et §12) : point d'appel de CT-3 côté démon. Il soumet la demande
// au service d'approbation par `coeur.evaluer` (EX-7.4, EX-7.16), applique à
// la réponse la matrice de 14.2 (service indisponible : bloquant pour une
// écriture et pour tout outil susceptible d'approbation, passant pour une
// autre lecture si la configuration le dit) et le mode d'attente
// (`erreur`, `retenir`, `observation`), et rend au frontal ce qu'il doit
// faire. Il ne scelle rien : retenue, refus, relais et décisions passent par
// le cœur (INTERFACES.md, sections a et d).
//
// Mode observation (révision 0.6, EX-4.51, EX-7.23, EX-14.13 à EX-14.17) :
// l'évaluation est faite sans être appliquée ; l'appel est relayé avec
// `policy.decision: "autorise"`, sans ticket, et la marque
// ` [observation <x>]` dans `policy.rule` (CT-3 EX-6.8) ; ce qu'un mode
// bloquant aurait bloqué, retenu ou refusé est consigné
// (`observation_would_block`) et compté ; un événement perdu au-delà des
// bornes de 14.5 l'est aussi (`event_lost`).
//
// Le moteur tient aussi la boucle `decisions` du noyau (EX-7.19 : une
// requête toujours ouverte, relancée dès qu'elle répond) quand le cœur a ses
// minuteurs, consigne les expirations différées par un mode dégradé (EX-9.4)
// et refuse d'entrer en mode observation avec des tickets ouverts (EX-15.8).

import { ErreurEnregistreur } from "../erreurs.mjs";
import { delaiExpiration } from "../approbations.mjs";
import { echeanceExpiration } from "../lui-meme.mjs";

/** Nom fixe qui précède la marque `inconnu` (CT-3 EX-6.8) ; il ne désigne aucune règle. */
export const REGLE_EVALUATION_IMPOSSIBLE = "evaluation impossible";

/** Réponse appliquée à une lecture passante quand le service est indisponible (14.2). */
export const REPONSE_DEFAUT_LECTURE = Object.freeze({ rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });

/** Raisons d'`observation_would_block` et de `noortrace_events_lost_total` (17.2, révision 0.6). */
export const RAISONS_OBSERVATION = Object.freeze(["approbation", "politique", "redaction", "quota", "stockage", "cle", "bail", "horloge", "attente"]);

/** Longueur maximale de `intent` dans la requête `evaluer` (`$defs/requete_evaluer` de ticket-v0). */
export const INTENTION_MAX = 4096;

/** Attente de la requête `decisions` (EX-7.19 : au plus 25 000). */
export const ATTENTE_DECISIONS_MS = 25000;

/**
 * `policy.rule` d'un appel relayé en mode observation (EX-14.14, CT-3
 * EX-6.8) : la chaîne rendue par le service suivie de ` [observation <x>]`,
 * ou `evaluation impossible [observation inconnu]` sans réponse valide.
 * @param {string|null} rule
 * @param {"autorise"|"a_approuver"|"refuse"|"inconnu"} would
 * @returns {string}
 */
export function regleObservation(rule, would) {
  if (would === "inconnu") return `${REGLE_EVALUATION_IMPOSSIBLE} [observation inconnu]`;
  return `${rule} [observation ${would}]`;
}

/**
 * Réponse soumise à approbation : `a_approuver`, ou ticket approuvé, ou tout
 * ticket (EX-14.1 : traitée comme une écriture pour la section 14).
 * @param {object} reponse
 */
export function soumiseAApprobation(reponse) {
  return reponse.decision === "a_approuver" || reponse.ticket_state === "approuve" || (reponse.ticket !== null && reponse.ticket !== undefined);
}

const dormir = (ms) =>
  new Promise((r) => {
    const t = setTimeout(r, ms);
    t.unref?.();
  });

export class MoteurPolitique {
  /**
   * @param {import("../coeur.mjs").Coeur} coeur
   */
  constructor(coeur) {
    this.coeur = coeur;
    /** Tickets dont l'expiration différée est déjà consignée (EX-9.4). */
    this.expirationsDifferees = new Set();
    this.boucle = null;
    this.actualiser();
  }

  get config() {
    return this.coeur.config;
  }

  /** Mode d'attente de la version en vigueur (`erreur`, `retenir`, `observation`). */
  get mode() {
    return this.config.policy.approval?.mode ?? "erreur";
  }

  /** La version en vigueur est en mode observation (14.6). */
  get observation() {
    return this.mode === "observation";
  }

  /** Jauge `noortrace_observation_mode` (EX-17.8), au démarrage et au rechargement. */
  actualiser() {
    this.coeur.metriques?.jauge("noortrace_observation_mode", {}, this.observation ? 1 : 0);
  }

  /**
   * Ligne « service d'approbation indisponible » de 14.2 : bloquant pour une
   * écriture et pour tout outil susceptible d'approbation (liste du dernier
   * `charger` réussi, EX-7.4 ; tout outil tant qu'elle manque), passant pour
   * une autre lecture si `policy.failure.approval_service.lecture` vaut
   * `passant`.
   * @param {string} nom nom annoncé
   * @param {"lecture"|"ecriture"} classe
   */
  bloquantSansService(nom, classe) {
    if (classe === "ecriture") return true;
    if (this.coeur.susceptible(nom)) return true;
    return this.config.policy.failure?.approval_service?.lecture !== "passant";
  }

  /**
   * Pas 3 de 4.4 : `evaluer` (EX-7.4), validation (EX-7.16, EX-7.23) et
   * matrice de 14.2.
   *
   * Hors observation : rend la réponse validée ; pour une indisponibilité
   * du service (sans réponse dans `timeout_ms`, erreur, réponse invalide),
   * rend la réponse par défaut d'une lecture passante (`decision:
   * "autorise"`, `rule: null`, défaut consigné) ou lève
   * ErreurEnregistreur(`approbation`).
   *
   * En observation : ne lève jamais pour le service ; rend la réponse à
   * appliquer (`autorise`, sans ticket, règle marquée) et `observation: {
   * would, bloquerait }` (`bloquerait` : raison d'`observation_would_block`
   * ou null).
   * @param {object} requete l'objet d'EX-7.4 (arguments en clair)
   * @param {{nom: string, classe: "lecture"|"ecriture", host?: string|null, request_id?: string|null, alias?: string|null}} o
   * @returns {Promise<{reponse: object, evaluee: object|null, defaut: boolean,
   *   observation: null|{would: string, bloquerait: string|null}}>}
   */
  async evaluerAppel(requete, o) {
    let evaluee = null;
    let erreur = null;
    const contexteIntention = { host: o.host ?? null, request_id: o.request_id ?? null };
    try {
      evaluee = await this.coeur.evaluer({ ...requete, intent: await this.intentionEvaluer(requete.intent, contexteIntention) });
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur)) throw e;
      erreur = e;
    }
    const contexte = { host: o.host ?? null, request_id: o.request_id ?? null };
    if (this.observation) {
      const would = evaluee ? evaluee.decision : "inconnu";
      const rule = regleObservation(evaluee?.rule ?? null, would);
      let bloquerait = null;
      if (would === "refuse") bloquerait = "politique";
      else if (would === "a_approuver") bloquerait = "approbation";
      else if (would === "inconnu" && this.bloquantSansService(o.nom, o.classe)) bloquerait = "approbation";
      return {
        reponse: { rule, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
        evaluee,
        defaut: false,
        observation: { would, bloquerait },
      };
    }
    if (erreur) {
      if (this.bloquantSansService(o.nom, o.classe)) throw erreur;
      this.coeur.journal.consigner("warning", "politique", "approval_default_applied", { server: o.alias ?? null, tool_announced: o.nom }, contexte);
      return { reponse: { ...REPONSE_DEFAUT_LECTURE }, evaluee: null, defaut: true, observation: null };
    }
    return { reponse: evaluee, evaluee, defaut: false, observation: null };
  }

  /**
   * Membre `intent` de la requête `evaluer` (EX-7.4) : `$defs/requete_evaluer`
   * n'admet qu'une chaîne d'au plus 4 096 caractères ou `null`, alors que
   * l'intention corrélée (5.6) peut être une référence de pièce `text/plain`
   * (EX-5.21 : texte rédigé, ou plus long que 4 096). Lecture (LISEZMOI) :
   * pour une référence, le texte de la pièce, déjà rédigé, s'il tient dans la
   * borne (c'est ce que montre la requête du cas CT-3
   * `console/modeles/intention-par-reference`) ; sinon `null`, consigné
   * (`intent_not_sent`, sans la valeur). Une chaîne passe telle quelle.
   * @param {unknown} intent chaîne, référence ou null
   * @param {{host?: string|null, request_id?: string|null}} [contexte]
   * @returns {Promise<string|null>}
   */
  async intentionEvaluer(intent, contexte = {}) {
    if (intent === null || intent === undefined) return null;
    if (typeof intent === "string") return intent;
    const omise = (raison) => {
      this.coeur.journal.consigner("info", "politique", "intent_not_sent", { reason: raison, sha256: intent?.sha256 ?? null, length: intent?.length ?? null }, contexte);
      return null;
    };
    if (typeof intent !== "object" || typeof intent.sha256 !== "string") return omise("forme");
    if (intent.media_type !== undefined && intent.media_type !== "text/plain") return omise("media_type");
    let octets = null;
    try {
      octets = await this.coeur.pieces.lire(intent.sha256);
    } catch {
      octets = null;
    }
    if (!octets) return omise("piece_absente");
    let texte;
    try {
      texte = new TextDecoder("utf-8", { fatal: true }).decode(octets);
    } catch {
      return omise("utf8");
    }
    if ([...texte].length > INTENTION_MAX) return omise("longueur");
    return texte;
  }

  /**
   * Classe d'un appel pour la section 14 (EX-14.1) : un appel soumis à
   * approbation est une écriture ; en observation, aucun appel ne l'est
   * (EX-14.14 : l'intention suit la classe de l'outil).
   * @param {object} reponse réponse appliquée
   * @param {"lecture"|"ecriture"} classe
   */
  classeEffective(reponse, classe) {
    if (classe === "ecriture") return "ecriture";
    return !this.observation && soumiseAApprobation(reponse) ? "ecriture" : "lecture";
  }

  /**
   * `observation_would_block` (EX-14.16, EX-17.8) : composant `politique`,
   * jamais les arguments ; compte `noortrace_observation_would_block_total`.
   * @param {{would: string, raison: string, alias?: string|null, nom?: string|null, classe?: string|null,
   *   seq?: number|null, host?: string|null, request_id?: string|null}} x
   */
  consignerBlocageEvite(x) {
    this.coeur.metriques.compter("noortrace_observation_would_block_total", { reason: x.raison });
    this.coeur.journal.consigner(
      "warning",
      "politique",
      "observation_would_block",
      { would: x.would, reason: x.raison, server: x.alias ?? null, tool_announced: x.nom ?? null, class: x.classe ?? null, seq: x.seq ?? null },
      { seq: x.seq ?? null, host: x.host ?? null, request_id: x.request_id ?? null },
    );
  }

  /**
   * Événement perdu au-delà des bornes de 14.5 en mode observation
   * (EX-14.16) : `event_lost` (composant `noyau`) et
   * `noortrace_events_lost_total{reason}`.
   * @param {string} raison
   * @param {number} [nombre]
   * @param {{host?: string|null, request_id?: string|null}} [contexte]
   */
  consignerPerte(raison, nombre = 1, contexte = {}) {
    this.coeur.metriques.compter("noortrace_events_lost_total", { reason: raison }, nombre);
    this.coeur.journal.consigner("error", "noyau", "event_lost", { reason: raison, count: nombre }, contexte);
  }

  /** `noortrace_observation_marks_total{would}` (17.2) pour un appel relayé avec une marque. */
  compterMarque(would) {
    this.coeur.metriques.compter("noortrace_observation_marks_total", { would });
  }

  /**
   * Instant de capture d'un événement mis en attente (EX-14.10) ; pendant un
   * mode dégradé « horloge », l'instant mural du dernier événement scellé
   * augmenté de l'avance de l'horloge monotone depuis ce scellement
   * (EX-14.16) : aucun `ts` n'est posé dans le futur.
   * @returns {number} ms
   */
  instantCapture() {
    const c = this.coeur;
    const murale = c.horlogeBrute.murale();
    if (!c.degrade.actif("horloge")) return murale;
    const dernier = c.ecrivain?.lastTs ?? null;
    const mono = c.horloge?.dernierMonotone ?? null;
    if (dernier === null || mono === null) return dernier ?? murale;
    return dernier + Math.max(0, c.horlogeBrute.monotone() - mono);
  }

  // ------------------------------------------------------------ EX-15.8

  /**
   * Tickets ouverts : `retenue` des fichiers des approbations (EX-12.23)
   * dont l'événement est dans la chaîne et qui n'ont pas de décision scellée.
   * @returns {string[]}
   */
  ticketsOuverts() {
    const c = this.coeur;
    if (!c.index || !c.approbations) return [];
    const ouverts = [];
    for (const [ticket, lignes] of c.approbations.retenues) {
      if (c.index.decisions.has(ticket)) continue;
      if (lignes.some((l) => c.index.retenuesParHash?.has(l.request_hash))) ouverts.push(ticket);
    }
    return ouverts.sort();
  }

  /**
   * Refus d'entrer en mode observation tant qu'un ticket est ouvert (EX-15.8,
   * CT-3 EX-11.15) : rend la raison `tickets_ouverts`, ou null.
   * @param {object} politique ensemble de politique qui entrerait en vigueur
   * @param {{depuisMode?: string|null}} [o] mode de la version en vigueur (rechargement)
   * @returns {string|null}
   */
  refusEntreeObservation(politique, o = {}) {
    if (politique?.approval?.mode !== "observation") return null;
    if (o.depuisMode === "observation") return null;
    const ouverts = this.ticketsOuverts();
    if (!ouverts.length) return null;
    this.coeur.journal.consigner("error", "config", "observation_refused", { reason: "tickets_ouverts", tickets: ouverts.length });
    return "tickets_ouverts";
  }

  // ------------------------------------------------------------ EX-9.4, EX-7.19

  /**
   * Expirations atteintes pendant un mode dégradé (EX-9.4, 14.2) : elles
   * seront scellées à la sortie du mode, après les événements de reprise et
   * en attente ; le retard est dit par le journal d'exploitation
   * (`approval_expired_deferred`), une ligne par ticket.
   */
  noterExpirationsDifferees() {
    const c = this.coeur;
    if (!c.index) return;
    const maintenant = c.horlogeBrute.murale();
    for (const [ticket] of c.index.retenues) {
      if (this.expirationsDifferees.has(ticket)) continue;
      const retenue = c.index.retenueSansDecision(ticket);
      if (!retenue) continue;
      const E = delaiExpiration(c.politiquesParVersion.get(retenue.code.policy_version) ?? null);
      const echeance = echeanceExpiration(retenue, E, this.config.policy.approval.timeout_ms);
      if (echeance === null || maintenant < echeance) continue;
      this.expirationsDifferees.add(ticket);
      c.journal.consigner("warning", "politique", "approval_expired_deferred", { reasons: c.degrade.raisons() }, { seq: retenue.seq });
    }
  }

  /**
   * Boucle `decisions` (EX-7.19, CT-3 EX-12.8) : une requête toujours
   * ouverte, relancée dès qu'elle répond ; sans réponse au terme de `wait_ms
   * + timeout_ms`, le service est indisponible (consigné une fois) et la
   * requête est réessayée avec un délai croissant borné. Une réponse vide
   * rendue bien avant `wait_ms` (service qui ne tient pas l'attente longue)
   * est relancée après 100 ms, pour ne pas tourner à vide.
   * @param {{wait_ms?: number}} [o]
   */
  demarrerBoucle(o = {}) {
    if (!this.coeur.service || this.boucle) return;
    const etat = { arret: false };
    this.boucle = etat;
    const wait_ms = o.wait_ms ?? ATTENTE_DECISIONS_MS;
    const delai = wait_ms + (this.config.policy.approval?.timeout_ms ?? 2000);
    const tourner = async () => {
      let pause = 0;
      let indisponible = false;
      while (!etat.arret && !this.coeur.arrete) {
        const t0 = Date.now();
        let minuteur;
        try {
          const acq = await Promise.race([
            this.coeur.traiterRemises({ wait_ms }),
            new Promise((_, rej) => {
              minuteur = setTimeout(() => rej(new Error("decisions : delai")), delai);
              minuteur.unref?.();
            }),
          ]);
          if (indisponible) this.coeur.journal.consigner("info", "politique", "approval_service_available", { message: "decisions" });
          indisponible = false;
          pause = 0;
          if (!acq.length && Date.now() - t0 < Math.min(100, wait_ms)) await dormir(100);
        } catch (e) {
          if (!indisponible) this.coeur.journal.consigner("warning", "politique", "approval_service_unavailable", { message: "decisions", code: e?.code ?? "indisponible" });
          indisponible = true;
          pause = Math.min(Math.max(pause * 2, 200), 5000);
          await dormir(pause);
        } finally {
          clearTimeout(minuteur);
        }
      }
    };
    etat.promesse = tourner();
  }

  /** Arrête la boucle `decisions` (arrêt du démon). */
  arreter() {
    if (this.boucle) this.boucle.arret = true;
    this.boucle = null;
  }
}
