// Magasin de bail `postgresql` (CT-2 §13.2) : une table
// `lease(name text primary key, holder text, epoch bigint, expires_at timestamptz)`
// (nom de table : `lease.store.table`), une ligne par journal
// (`name = "<org_id>/<journal_id>"`). Acquisition par l'`UPDATE` conditionnel
// de 13.2, renouvellement par l'`UPDATE` qui exige le même détenteur et la même
// époque (zéro ligne = bail perdu), vérification après écriture par lecture
// de la ligne (EX-13.10 (2)). C'est l'horloge du serveur de base de données
// (`clock_timestamp()`, jamais `now()`, figé au début de la transaction) qui
// tranche l'expiration. Les verrous consultatifs ne produisent pas de jeton
// et ne sont pas employés.

import { MagasinBailReseau, ErreurMagasin } from "./bail-reseau.mjs";
import { ConnexionPg, analyserDsn } from "./pg-protocole.mjs";

const identifiant = (t) => `"${t.replace(/"/g, '""')}"`;

/** Requêtes SQL exactes de 13.2 pour une table donnée. */
export function requetesBailPg(table) {
  const t = identifiant(table);
  return {
    creer: `CREATE TABLE IF NOT EXISTS ${t} (name text PRIMARY KEY, holder text, epoch bigint NOT NULL DEFAULT 0, expires_at timestamptz)`,
    ligne: `INSERT INTO ${t} (name, holder, epoch, expires_at) VALUES ($1, NULL, 0, NULL) ON CONFLICT (name) DO NOTHING`,
    acquerir: `UPDATE ${t} SET holder = $1, epoch = epoch + 1, expires_at = clock_timestamp() + $2 * interval '1 millisecond' WHERE name = $3 AND (holder IS NULL OR expires_at < clock_timestamp()) RETURNING epoch`,
    renouveler: `UPDATE ${t} SET expires_at = clock_timestamp() + $1 * interval '1 millisecond' WHERE name = $2 AND holder = $3 AND epoch = $4`,
    lire: `SELECT holder, epoch FROM ${t} WHERE name = $1`,
    liberer: `UPDATE ${t} SET holder = NULL, expires_at = NULL WHERE name = $1 AND holder = $2 AND epoch = $3`,
  };
}

export class MagasinBailPostgresql extends MagasinBailReseau {
  /**
   * @param {object} o options de MagasinBailReseau, et :
   * @param {string} o.dsn DSN résolu (`lease.store.dsn`)
   * @param {string} o.table `lease.store.table`
   */
  constructor(o) {
    super(o);
    this.dsn = analyserDsn(o.dsn);
    this.sql = requetesBailPg(o.table);
    this.connexion = null;
    this.preparee = false;
    this.file = Promise.resolve();
  }

  get type() {
    return "postgresql";
  }

  /** Une requête à la fois sur une connexion ; reconnexion après une panne. */
  _requete(sql, params) {
    const p = this.file.then(async () => {
      if (!this.connexion || this.connexion.ferme) {
        this.connexion = new ConnexionPg(this.dsn, { delaiMs: Math.max(1000, Math.min(this.ttl, 10000)) });
        try {
          await this.connexion.ouvrir();
        } catch (e) {
          this.connexion.detruire();
          this.connexion = null;
          throw new ErreurMagasin(`postgresql injoignable : ${e.message}`, e);
        }
      }
      try {
        return await this.connexion.requete(sql, params);
      } catch (e) {
        if (this.connexion?.ferme) this.connexion = null;
        throw new ErreurMagasin(`postgresql : ${e.message}`, e);
      }
    });
    this.file = p.catch(() => {});
    return p;
  }

  async _preparer() {
    if (this.preparee) return;
    await this._requete(this.sql.creer, []);
    await this._requete(this.sql.ligne, [this.nomJournal]);
    this.preparee = true;
  }

  async _acquerir() {
    await this._preparer();
    const r = await this._requete(this.sql.acquerir, [this.instance, String(this.ttl), this.nomJournal]);
    if (r.lignes.length === 0) return null;
    const e = Number(r.lignes[0][0]);
    if (!Number.isSafeInteger(e)) throw new ErreurMagasin("époque hors des entiers sûrs");
    return e;
  }

  async _renouveler() {
    const r = await this._requete(this.sql.renouveler, [String(this.ttl), this.nomJournal, this.instance, String(this.epoque)]);
    return r.commande === "UPDATE 1";
  }

  async _verifier() {
    const r = await this._requete(this.sql.lire, [this.nomJournal]);
    return r.lignes.length === 1 && r.lignes[0][0] === this.instance && Number(r.lignes[0][1]) === this.epoque;
  }

  async _liberer() {
    await this._requete(this.sql.liberer, [this.nomJournal, this.instance, String(this.epoque)]);
  }

  _fermer() {
    this.connexion?.fermer();
    this.connexion = null;
  }
}
