// Notifications livrées par le service (CT-3 13.19, EX-13.39 à EX-13.42) :
// document `$defs/notification` de `configuration-approbation-v0`, boîte
// d'envoi `notifications.ndjson` tournée au-delà de 64 Mio (8 fichiers tournés
// au plus), livraison signée au webhook de l'exploitant du client, reprises,
// file bornée et lignes du journal du service.
//
// Le document est formé par le service APRÈS la persistance de ce qui le
// cause ; ce module ne fait qu'inscrire et livrer, hors de la file des
// entrées : rien de ce qu'il fait ne retarde une réponse ni une transition.
// Le corps envoyé est le JCS du document (CT-1 §4), identique à chaque
// tentative ; c'est aussi la ligne de la boîte, écrite avant la première
// tentative. Signature : `NOORTRACE-Signature: sha256=<HMAC-SHA256(K,
// "noortrace/notification/v0\n" ‖ corps)>` (EX-13.41). Livraison (EX-13.42) :
// sans redirection, certificat vérifié par `notifications.ca` ou, à défaut,
// par le magasin d'autorités du système (`tls.getCACertificates("system")`,
// et non la liste intégrée de Node), délai `timeout_ms` du début de la
// résolution du nom à la ligne de statut ; le corps de la réponse, ignoré,
// est lu au plus jusqu'à 65 536 octets et jusqu'à ce même délai, puis la
// prise est toujours détruite (un webhook qui ne finit jamais son corps ne
// garde aucune prise ouverte) ; reprise sur erreur de réseau ou de TLS, délai écoulé, 408, 429
// ou 5xx, 10 s, 60 s, 300 s puis 1 800 s après la fin de la tentative
// précédente ; abandon sur tout autre statut ; file de 10 000 au plus,
// éviction `file_pleine` qui épargne `vote_inscrit` et `operation_annuaire`.
// Les reprises ne survivent pas à un redémarrage (EX-13.42).
//
// L'horloge des reprises est celle du service (injectable) : `traiter()`
// lance les tentatives échues à son instant ; un minuteur réel le rappelle
// au prochain instant échu.

import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { createHmac, randomBytes } from "node:crypto";
import { ecrireHorodatage } from "@noortrace/noyau";
import { jcsIntegral } from "./json.mjs";

/** Préfixe du MAC (EX-13.41). */
export const PREFIXE_SIGNATURE = "noortrace/notification/v0\n";
/** Délais des reprises, en millisecondes, après la fin de la tentative précédente (EX-13.42). */
export const REPRISES_MS = Object.freeze([10000, 60000, 300000, 1800000]);
/** Taille au-delà de laquelle la boîte est tournée (EX-13.39). */
export const TAILLE_BOITE = 64 * 1024 * 1024;
/** Nombre de fichiers tournés gardés (EX-13.39). */
export const FICHIERS_TOURNES = 8;
/** Notifications en attente de livraison au plus (EX-13.42). */
export const FILE_MAX = 10000;
/** Octets lus au plus du corps d'une réponse du webhook (EX-13.42). */
export const LECTURE_MAX = 65536;
/** `kind` épargnés par l'éviction tant qu'une autre notification attend (EX-13.42). */
export const KINDS_EPARGNES = Object.freeze(["vote_inscrit", "operation_annuaire"]);
/** Période d'une notification `plafond_atteint` par `launched_by` (EX-13.40). */
export const PERIODE_PLAFOND_MS = 15 * 60 * 1000;

/**
 * Signature d'un corps (EX-13.41) : les 64 chiffres hexadécimaux du HMAC.
 * @param {string} cle `notifications.key`, déjà débarrassée de ses espaces
 * @param {Buffer|Uint8Array} corps
 */
export function signerNotification(cle, corps) {
  return createHmac("sha256", Buffer.from(cle, "latin1")).update(PREFIXE_SIGNATURE, "utf8").update(corps).digest("hex");
}

/** Identifiant d'une notification : `ntf-` et 128 bits tirés au hasard. */
export function identifiantNotification() {
  return `ntf-${randomBytes(16).toString("hex")}`;
}

const CODES_TLS = /CERT|TLS|SSL|EPROTO|SIGNATURE|ISSUER|HANDSHAKE/i;

let magasinSysteme = null;

/**
 * Autorités de vérification du webhook (EX-13.42) : `notifications.ca` si
 * elle est déclarée, sinon le magasin d'autorités du système (lu une fois).
 * @param {string|null} ca PEM de `notifications.ca`
 * @returns {string|string[]}
 */
export function autoritesWebhook(ca) {
  if (ca) return ca;
  magasinSysteme ??= tls.getCACertificates("system");
  return magasinSysteme;
}

/** Options de la requête d'une tentative (en-têtes, autorités) ; essais et `envoyerNotification`. */
export function optionsTentative(u, { corps, signature, ca }) {
  const options = {
    method: "POST",
    agent: false,
    headers: { "Content-Type": "application/json", "Content-Length": corps.length, "NOORTRACE-Signature": `sha256=${signature}` },
  };
  if (u.protocol === "https:") options.ca = autoritesWebhook(ca);
  return options;
}

/**
 * Une tentative de livraison.
 * @returns {Promise<{status: number}|{cause: "reseau"|"tls"|"delai"}>}
 */
export function envoyerNotification({ url, corps, signature, ca, timeout_ms }) {
  return new Promise((resoudre) => {
    let fini = false;
    // le résultat est rendu à la ligne de statut ; le minuteur, lui, court
    // jusqu'à la fin du corps et détruit la prise à l'échéance (EX-13.39)
    const finir = (r) => {
      if (fini) return;
      fini = true;
      resoudre(r);
    };
    const fermer = () => {
      clearTimeout(minuteur);
      req?.destroy();
    };
    let u;
    try {
      u = new URL(url);
    } catch {
      finir({ cause: "reseau" });
      return;
    }
    const module_ = u.protocol === "https:" ? https : http;
    let options;
    try {
      options = optionsTentative(u, { corps, signature, ca });
    } catch {
      finir({ cause: "tls" });
      return;
    }
    let req;
    // le délai court dès avant la résolution du nom (EX-13.42)
    const minuteur = setTimeout(() => {
      finir({ cause: "delai" });
      req?.destroy();
    }, timeout_ms);
    minuteur.unref?.();
    try {
      req = module_.request(u, options, (res) => {
        finir({ status: res.statusCode });
        let lus = 0;
        res.on("data", (x) => {
          lus += x.length;
          if (lus >= LECTURE_MAX) fermer();
        });
        res.on("end", fermer);
        res.on("close", fermer);
        res.on("error", () => {});
      });
    } catch {
      clearTimeout(minuteur);
      finir({ cause: "reseau" });
      return;
    }
    req.on("error", (e) => {
      clearTimeout(minuteur);
      finir({ cause: CODES_TLS.test(`${e?.code ?? ""} ${e?.reason ?? ""} ${e?.library ?? ""}`) ? "tls" : "reseau" });
    });
    req.end(corps);
  });
}

/** Inscription et livraison des notifications. */
export class Notificateur {
  /**
   * @param {{boite: string, console_origin: string, horloge?: () => number,
   *   journal: (type: string, detail: object) => void,
   *   webhook?: {url: string, cle: string, ca: string|null, timeout_ms: number}|null,
   *   tailleBoite?: number, envoyer?: typeof envoyerNotification, minuterie?: boolean}} p
   *   `tailleBoite` et `envoyer` : essais seulement ; `minuterie: false` : aucune tentative
   *   sans appel explicite de `traiter()` (horloge injectée des essais)
   */
  constructor(p) {
    this.boite = p.boite;
    this.console_origin = p.console_origin;
    this.horloge = p.horloge ?? Date.now;
    this.journal = p.journal;
    this.webhook = p.webhook ?? null;
    this.tailleBoite = p.tailleBoite ?? TAILLE_BOITE;
    this.envoyer = p.envoyer ?? envoyerNotification;
    this.minuterie = p.minuterie !== false;
    /** @type {Map<string, {doc: object, corps: Buffer, tentatives: number, prochaine: number|null, enCours: boolean}>} */
    this.file = new Map();
    this.ecritures = Promise.resolve();
    this.enVol = new Set();
    this.minuteur = null;
    this.arrete = false;
    fs.mkdirSync(path.dirname(this.boite), { recursive: true, mode: 0o700 });
  }

  /** Lien de l'écran d'un ticket, ou de l'écran d'inscription (EX-13.43). */
  lien(ticket) {
    return ticket === null ? `${this.console_origin}/inscription` : `${this.console_origin}/tickets/${ticket}`;
  }

  /**
   * Forme, inscrit et met en livraison une notification (EX-13.40). Sans
   * destinataire, rien n'est formé : ligne `notification_sans_destinataire`.
   * @param {{kind: string, entries: string[], roles: string[], ticket: string|null, tool: string|null,
   *   deadline: string|null, link: string|null, details: object|null}} n
   * @returns {object|null} le document formé
   */
  notifier(n) {
    const entries = [...new Set(n.entries)].sort();
    const roles = [...new Set(n.roles)].sort();
    if (entries.length === 0 && roles.length === 0) {
      this.journal("notification_sans_destinataire", { kind: n.kind, ticket: n.ticket });
      return null;
    }
    const doc = {
      version: 0,
      id: identifiantNotification(),
      kind: n.kind,
      created_at: ecrireHorodatage(this.horloge()),
      recipients: { entries, roles },
      ticket: n.ticket,
      tool: n.tool,
      deadline: n.deadline,
      link: n.link,
      details: n.details,
    };
    const corps = Buffer.from(jcsIntegral(doc), "utf8");
    const item = { doc, corps, tentatives: 0, prochaine: null, enCours: false };
    // la ligne de la boîte est écrite avant la première tentative (EX-13.39)
    const ecrite = this.#ecrireBoite(doc, corps);
    if (this.webhook && !this.arrete) {
      this.file.set(doc.id, item);
      this.#evincer();
      ecrite.then(() => {
        if (!this.file.has(doc.id)) return;
        item.prochaine = this.horloge();
        if (this.minuterie) this.traiter();
      });
    }
    return doc;
  }

  #ecrireBoite(doc, corps) {
    this.ecritures = this.ecritures.then(async () => {
      try {
        await fsp.appendFile(this.boite, Buffer.concat([corps, Buffer.from("\n")]), { mode: 0o600 });
        const st = await fsp.stat(this.boite);
        if (st.size > this.tailleBoite) await this.#tourner();
      } catch (e) {
        void e;
        this.journal("notification_boite_en_echec", { id: doc.id, kind: doc.kind });
      }
    });
    return this.ecritures;
  }

  /** Rotation (EX-13.39) : le fichier courant devient `.1`, les précédents le numéro suivant, 8 au plus. */
  async #tourner() {
    await fsp.rm(`${this.boite}.${FICHIERS_TOURNES}`, { force: true });
    for (let k = FICHIERS_TOURNES - 1; k >= 1; k--) {
      try {
        await fsp.rename(`${this.boite}.${k}`, `${this.boite}.${k + 1}`);
      } catch (e) {
        if (e.code !== "ENOENT") throw e;
      }
    }
    await fsp.rename(this.boite, `${this.boite}.1`);
  }

  /** File pleine (EX-13.42) : abandonne la plus ancienne qui attend, en épargnant vote_inscrit et operation_annuaire. */
  #evincer() {
    while (this.file.size > FILE_MAX) {
      const attente = [...this.file.values()].filter((x) => !x.enCours);
      const victime = attente.find((x) => !KINDS_EPARGNES.includes(x.doc.kind)) ?? attente[0];
      if (!victime) return;
      this.file.delete(victime.doc.id);
      this.journal("notification_abandonnee", { id: victime.doc.id, kind: victime.doc.kind, attempts: victime.tentatives, cause: "file_pleine" });
    }
  }

  /** Instant de la prochaine tentative échue ou à venir, ou null. */
  prochaineEcheance() {
    let min = null;
    for (const x of this.file.values()) if (!x.enCours && x.prochaine !== null && (min === null || x.prochaine < min)) min = x.prochaine;
    return min;
  }

  /** Lance chaque tentative échue à l'instant de l'horloge ; replanifie le minuteur. */
  traiter() {
    if (this.arrete) return;
    const t = this.horloge();
    for (const x of [...this.file.values()]) {
      if (x.enCours || x.prochaine === null || x.prochaine > t) continue;
      const v = this.#tenter(x).finally(() => this.enVol.delete(v));
      this.enVol.add(v);
    }
    this.#planifier();
  }

  #planifier() {
    clearTimeout(this.minuteur);
    if (this.arrete || !this.minuterie) return;
    const p = this.prochaineEcheance();
    if (p === null) return;
    this.minuteur = setTimeout(() => this.traiter(), Math.max(0, Math.min(p - this.horloge(), 2 ** 31 - 1)));
    this.minuteur.unref?.();
  }

  async #tenter(x) {
    x.enCours = true;
    x.tentatives += 1;
    const attempt = x.tentatives;
    const { id, kind } = x.doc;
    const r = await this.envoyer({
      url: this.webhook.url, corps: x.corps, signature: signerNotification(this.webhook.cle, x.corps), ca: this.webhook.ca, timeout_ms: this.webhook.timeout_ms,
    });
    x.enCours = false;
    if (!this.file.has(id)) return;
    if (r.status !== undefined && r.status >= 200 && r.status < 300) {
      this.file.delete(id);
      this.journal("notification_livree", { id, kind, attempt, status: r.status });
      return;
    }
    const status = r.status ?? null;
    this.journal("notification_echec", { id, kind, attempt, status, cause: status === null ? r.cause : "statut" });
    const reprise = status === null || status === 408 || status === 429 || (status >= 500 && status <= 599);
    if (!reprise) {
      this.file.delete(id);
      this.journal("notification_abandonnee", { id, kind, attempts: attempt, cause: "statut_definitif" });
    } else if (attempt > REPRISES_MS.length) {
      this.file.delete(id);
      this.journal("notification_abandonnee", { id, kind, attempts: attempt, cause: "reprises_epuisees" });
    } else {
      x.prochaine = this.horloge() + REPRISES_MS[attempt - 1];
    }
    if (this.minuterie) this.#planifier();
  }

  /** Attend la fin des écritures de la boîte et des tentatives en cours. */
  async attendre() {
    await this.ecritures;
    while (this.enVol.size) await Promise.allSettled([...this.enVol]);
  }

  /** Arrête : plus aucune tentative ; les notifications en attente restent dans la boîte seulement (EX-13.42). */
  async arreter() {
    this.arrete = true;
    clearTimeout(this.minuteur);
    await this.attendre();
  }
}

/**
 * Suivi des refus `plafond_atteint` (EX-13.40) : une notification au premier
 * refus d'un `launched_by` dans une période de 15 minutes ; les refus suivants
 * de la période sont comptés et le journal en reçoit le nombre à sa fin
 * (`plafond_refus_non_notifies`).
 */
export class SuiviPlafond {
  /**
   * @param {{horloge: () => number, journal: (type: string, detail: object) => void, minuterie?: boolean}} p
   *   `minuterie: false` : périodes closes par `cloturer()` seulement (horloge injectée)
   */
  constructor(p) {
    this.horloge = p.horloge;
    this.journal = p.journal;
    this.minuterie = p.minuterie !== false;
    /** @type {Map<string, {debut: number, non_notifies: number}>} */
    this.periodes = new Map();
    this.minuteurs = new Set();
  }

  /** Arrête les minuteurs de fin de période. */
  arreter() {
    for (const m of this.minuteurs) clearTimeout(m);
    this.minuteurs.clear();
  }

  /** Clôt les périodes finies à l'instant de l'horloge. */
  cloturer() {
    const t = this.horloge();
    for (const [lb, p] of this.periodes) {
      if (t < p.debut + PERIODE_PLAFOND_MS) continue;
      this.periodes.delete(lb);
      if (p.non_notifies > 0) {
        this.journal("plafond_refus_non_notifies", { launched_by: lb, count: p.non_notifies, period_start: ecrireHorodatage(p.debut) });
      }
    }
  }

  /**
   * Un refus `plafond_atteint` de `launched_by` : vrai s'il faut notifier.
   * @param {string} launched_by
   */
  refus(launched_by) {
    this.cloturer();
    const p = this.periodes.get(launched_by);
    if (p) {
      p.non_notifies += 1;
      return false;
    }
    this.periodes.set(launched_by, { debut: this.horloge(), non_notifies: 0 });
    if (this.minuterie) {
      const m = setTimeout(() => {
        this.minuteurs.delete(m);
        this.cloturer();
      }, PERIODE_PLAFOND_MS + 1);
      m.unref?.();
      this.minuteurs.add(m);
    }
    return true;
  }
}
