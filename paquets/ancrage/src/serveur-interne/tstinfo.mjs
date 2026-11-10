// `TSTInfo` (RFC 3161 §2.4.2) émis par le serveur interne : `version 1`,
// `policy`, `messageImprint` recopié octet pour octet depuis la requête,
// `serialNumber` strictement croissant (AN-26), `genTime` GeneralizedTime à
// la seconde, `accuracy` `seconds` ≤ 1 (AN-24), `ordering` absent (valeur
// DEFAULT, jamais encodée : CT-6 EX-9.21), `nonce` recopié à l'identique
// (AN-25), `tsa` en `directoryName` du sujet de l'unité (CT-6 T-9 règle 3)
// ou absent, aucune extension.

import { sequence, entier, oid, tempsGeneralise, explicite, tlv, ETIQUETTE } from "./der-ecriture.mjs";

/**
 * @param {object} o
 * @param {string} o.politique OID
 * @param {Uint8Array} o.messageImprint `MessageImprint` complet, tel que reçu
 * @param {bigint} o.serie numéro de série
 * @param {number} o.genTimeMs instant UTC en ms (tronqué à la seconde)
 * @param {number} o.precisionS 0 ou 1
 * @param {Uint8Array|null} o.nonce contenu de l'INTEGER nonce tel que reçu, ou null
 * @param {Uint8Array|null} o.tsa `Name` DER du sujet de l'unité, ou null
 * @returns {Uint8Array} DER de `TSTInfo`
 */
export function construireTstInfo(o) {
  if (typeof o.serie !== "bigint" || o.serie <= 0n) throw new RangeError("TSTInfo : numéro de série positif attendu");
  if (!(o.messageImprint instanceof Uint8Array) || o.messageImprint[0] !== ETIQUETTE.SEQUENCE) throw new RangeError("TSTInfo : messageImprint (SEQUENCE) attendu");
  if (!Number.isInteger(o.precisionS) || o.precisionS < 0 || o.precisionS > 1) throw new RangeError("TSTInfo : précision 0 ou 1 s attendue (AN-24)");
  const parties = [
    entier(1),
    oid(o.politique),
    o.messageImprint,
    entier(o.serie),
    tempsGeneralise(o.genTimeMs),
    sequence(entier(o.precisionS)),
  ];
  if (o.nonce instanceof Uint8Array) {
    if (o.nonce.length === 0) throw new RangeError("TSTInfo : nonce vide");
    parties.push(tlv(ETIQUETTE.INTEGER, o.nonce));
  }
  if (o.tsa instanceof Uint8Array) parties.push(explicite(0, explicite(4, o.tsa)));
  return sequence(...parties);
}
