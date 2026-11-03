// Magasin de bail partagé entre hôtes (CT-2 §13.2, §13.3) : socle commun des
// magasins `postgresql` et `etcd`. Durées de `lease` (EX-13.3) : `ttl_ms`,
// `renew_ms`, `acquire_wait_ms` ; les délais se mesurent sur l'horloge
// MONOTONE du démon : le bail est tenu pour valide jusqu'à
// `t_renew + ttl_ms − marge`, `marge = renew_ms`, où `t_renew` est l'instant
// monotone d'ENVOI de la dernière demande d'acquisition ou de renouvellement
// réussie (borne prudente : le magasin a compté son TTL après cet envoi ; un
// renouvellement n'est tenu pour réussi qu'à la réception de la réponse).
// Les horloges murales des hôtes ne participent pas au raisonnement.
//
// Le renouvellement tourne dans son propre minuteur (« un fil pour le bail »,
// 3.4) ; un renouvellement refusé par le magasin (bail repris par un autre)
// ou un bail échu faute de renouvellement est une perte : la ligne
// `lease_lost` est consignée, la métrique `noortrace_lease_epoch` passe à 0,
// et le cœur entre en mode dégradé « bail » (EX-13.6) ; il ne reprend
// qu'après une nouvelle acquisition, après relecture du journal.

import { MagasinBail } from "../bail.mjs";
import { ErreurEnregistreur } from "../erreurs.mjs";

const dormir = (ms) => new Promise((r) => setTimeout(r, ms).unref?.());

/** Erreur d'accès au magasin (injoignable, refus, réponse illisible). */
export class ErreurMagasin extends Error {
  constructor(message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ErreurMagasin";
  }
}

/**
 * Socle d'un magasin de bail réseau.
 * @abstract
 */
export class MagasinBailReseau extends MagasinBail {
  /**
   * @param {object} o
   * @param {string} o.instance `recorder.instance_id` (détenteur)
   * @param {string} o.org_id
   * @param {string} o.journal_id
   * @param {number} o.ttl_ms
   * @param {number} o.renew_ms
   * @param {number} o.acquire_wait_ms
   * @param {() => number} [o.monotone] horloge monotone, ms
   */
  constructor(o) {
    super();
    this.instance = o.instance;
    this.org_id = o.org_id;
    this.journal_id = o.journal_id;
    this.ttl = o.ttl_ms;
    this.renouvellement = o.renew_ms;
    this.attenteAcquisition = o.acquire_wait_ms;
    this.monotone = o.monotone ?? (() => performance.now());
    this.epoque = 0;
    this.detenu = false;
    this.tRenouv = null;
    this.minuteur = null;
    this.perdu = false;
  }

  /**
   * Lie le magasin au cœur : horloge monotone, journal d'exploitation,
   * métriques, mode dégradé (crochet facultatif lu par le cœur).
   * @param {import("../coeur.mjs").Coeur} coeur
   */
  lier(coeur) {
    this.coeur = coeur;
    this.monotone = () => coeur.horlogeBrute.monotone();
  }

  /** Nom du journal dans le magasin : `<org_id>/<journal_id>` (13.2). */
  get nomJournal() {
    return `${this.org_id}/${this.journal_id}`;
  }

  // Méthodes du magasin, à fournir : rendent l'époque ou null (détenu par un
  // autre), un booléen (renouvellement, vérification), ou lèvent ErreurMagasin.
  async _acquerir() { throw new Error("à implémenter"); }
  async _renouveler() { throw new Error("à implémenter"); }
  async _verifier() { throw new Error("à implémenter"); }
  async _liberer() {}
  _fermer() {}

  /**
   * Acquiert le bail (EX-13.4) : rend l'époque. Un magasin injoignable est
   * réessayé pendant `acquire_wait_ms` (EX-13.3), puis l'acquisition est
   * abandonnée (raison `bail`) ; un bail détenu par une autre instance lève
   * la raison `bail_non_detenu` (le cœur passe en attente, `lease_standby`).
   * @returns {Promise<number>}
   */
  async acquerir() {
    const limite = this.monotone() + this.attenteAcquisition;
    let derniere = null;
    for (;;) {
      const t0 = this.monotone();
      try {
        const e = await this._acquerir();
        if (e === null) throw new ErreurEnregistreur("bail_non_detenu", "noortrace: bail non detenu", { donnees: { event: "lease_standby" } });
        if (!Number.isSafeInteger(e) || e < 1) throw new ErreurEnregistreur("bail", "noortrace: epoque du bail invalide");
        if (e <= this.epoque) throw new ErreurEnregistreur("bail", "noortrace: epoque du bail non croissante (EX-13.4)");
        this.epoque = e;
        this.tRenouv = t0;
        this.detenu = true;
        this.perdu = false;
        this._armer();
        return e;
      } catch (err) {
        if (err instanceof ErreurEnregistreur) throw err;
        derniere = err;
        this.coeur?.metriques?.compter("noortrace_lease_renew_failures_total", { store: this.type });
        if (this.monotone() >= limite) break;
        await dormir(Math.min(this.renouvellement, Math.max(10, limite - this.monotone())));
      }
    }
    throw new ErreurEnregistreur("bail", "noortrace: magasin de bail injoignable", { cause: derniere });
  }

  /** Valide jusqu'à `t_renew + ttl − marge`, sur l'horloge monotone (EX-13.3). */
  valide() {
    return this.detenu && this.tRenouv !== null && this.monotone() < this.tRenouv + this.ttl - this.renouvellement;
  }

  _armer() {
    clearTimeout(this.minuteur);
    const tour = async () => {
      if (!this.detenu) return;
      const t0 = this.monotone();
      let ok = null;
      try {
        ok = await this._renouveler();
      } catch {
        ok = null;
        this.coeur?.metriques?.compter("noortrace_lease_renew_failures_total", { store: this.type });
      }
      if (!this.detenu) return;
      if (ok === true) this.tRenouv = t0;
      else if (ok === false) {
        this._perte("renouvellement_refuse");
        return;
      }
      if (!this.valide()) {
        this._perte("bail_echu");
        return;
      }
      this.minuteur = setTimeout(tour, this.renouvellement);
      this.minuteur.unref?.();
    };
    this.minuteur = setTimeout(tour, this.renouvellement);
    this.minuteur.unref?.();
  }

  /** Perte constatée par le fil du bail : consignée une fois, mode dégradé « bail ». */
  _perte(cause) {
    if (this.perdu) return;
    this.perdu = true;
    this.detenu = false;
    clearTimeout(this.minuteur);
    const c = this.coeur;
    if (!c) return;
    c.journal.consigner("error", "bail", "lease_lost", { epoch: this.epoque, store: this.type, cause });
    c.metriques.jauge("noortrace_lease_epoch", {}, 0);
    c.degrade.entrer("bail");
  }

  /**
   * Revérifie l'époque auprès du magasin après un fdatasync et avant de
   * répondre (EX-13.10 (2)) ; un magasin injoignable ne prouve rien : la
   * vérification échoue.
   * @returns {Promise<boolean>}
   */
  async verifierApresEcriture() {
    if (!this.valide()) return false;
    try {
      return (await this._verifier()) === true;
    } catch {
      return false;
    }
  }

  /** Arrêt propre : le renouvellement cesse, le bail est rendu s'il est encore détenu. */
  async liberer() {
    clearTimeout(this.minuteur);
    const detenu = this.detenu;
    this.detenu = false;
    if (detenu) {
      try {
        await this._liberer();
      } catch {
        // le bail échoira de lui-même
      }
    }
    this._fermer();
  }

  /** Perte simulée (tests du mode dégradé « bail »). */
  perdre() {
    this.detenu = false;
    clearTimeout(this.minuteur);
  }
}
