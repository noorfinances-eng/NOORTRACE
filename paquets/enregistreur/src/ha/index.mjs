// Haute disponibilité à écrivain unique avec bail (CT-2 §13) : magasins de
// bail `postgresql` et `etcd` (13.2), socle commun (validité sur l'horloge
// monotone, renouvellement, perte, EX-13.3, EX-13.6), jeton de clôture côté
// stockage et surveillance de la fourche (EX-13.5, EX-13.10), contrôle de la
// clé du MAC de relais avant l'acquisition (13.4 pas 1).

import { MagasinBailFichier } from "../bail.mjs";
import { ErreurEnregistreur } from "../erreurs.mjs";
import { MagasinBailPostgresql } from "./postgresql.mjs";
import { MagasinBailEtcd } from "./etcd.mjs";

export { MagasinBailReseau, ErreurMagasin } from "./bail-reseau.mjs";
export { MagasinBailPostgresql, requetesBailPg } from "./postgresql.mjs";
export { MagasinBailEtcd, ClientEtcd } from "./etcd.mjs";
export { ConnexionPg, ErreurPg, analyserDsn } from "./pg-protocole.mjs";
export {
  FICHIERS_A_EPOQUE, epoqueMaxNoms, epoqueMaxJournal, verifierEpoqueOuverture, GardeEpoque, controleCleMac, taillesAnterieures, SurveillanceFourche,
} from "./cloture.mjs";

/**
 * Magasin de bail de `lease.store` (13.2).
 * @param {object} config document validé
 * @param {Map<string, Uint8Array>} secrets secrets résolus (`/lease/store/dsn`)
 * @param {{monotone?: () => number}} [o]
 * @returns {import("../bail.mjs").MagasinBail}
 */
export function magasinBailDepuisConfiguration(config, secrets, o = {}) {
  const l = config.lease;
  const s = l.store;
  if (s.type === "file") return new MagasinBailFichier(s.path);
  const commun = {
    instance: config.recorder.instance_id,
    org_id: config.recorder.org_id,
    journal_id: config.recorder.journal_id,
    ttl_ms: l.ttl_ms,
    renew_ms: l.renew_ms,
    acquire_wait_ms: l.acquire_wait_ms,
    monotone: o.monotone,
  };
  if (s.type === "postgresql") {
    const dsn = secrets.get("/lease/store/dsn");
    if (!dsn) throw new ErreurEnregistreur("bail", "DSN du magasin de bail non résolu");
    return new MagasinBailPostgresql({ ...commun, dsn: Buffer.from(dsn).toString("utf8"), table: s.table });
  }
  if (s.type === "etcd") return new MagasinBailEtcd({ ...commun, endpoints: s.endpoints, prefix: s.prefix, tls: s.tls });
  throw new ErreurEnregistreur("bail", `magasin de bail ${s.type} inconnu`);
}
