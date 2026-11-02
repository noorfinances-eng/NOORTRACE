// Références de secrets (CT-2 §15.2) : `{ "env" }`, `{ "file" }` ou
// `{ "vault" }`, avec `encoding` (`hex`, `base64`, `utf8`) quand la valeur doit
// devenir des octets. Les valeurs résolues vivent en mémoire du démon, ne sont
// jamais écrites ni consignées, et sont effacées à l'arrêt.

import fs from "node:fs";
import { decoderBase64Canonique } from "@noortrace/noyau";

/** Erreur de résolution d'une référence (jamais la valeur). */
export class ErreurSecret extends Error {
  /** @param {string} pointeur @param {string} regle */
  constructor(pointeur, regle) {
    super(`${pointeur} : ${regle}`);
    this.name = "ErreurSecret";
    this.pointeur = pointeur;
    this.regle = regle;
  }
}

/**
 * Décode une valeur selon `encoding` (15.2).
 * @param {Uint8Array} brut
 * @param {"hex"|"base64"|"utf8"|undefined} encodage
 * @returns {Uint8Array|null}
 */
export function decoderSecret(brut, encodage) {
  if (encodage === undefined || encodage === "utf8") return brut;
  const texte = Buffer.from(brut).toString("utf8");
  if (encodage === "hex") {
    const h = texte.startsWith("0x") ? texte.slice(2) : texte;
    if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) return null;
    return new Uint8Array(Buffer.from(h, "hex"));
  }
  if (encodage === "base64") return decoderBase64Canonique(texte);
  return null;
}

/**
 * Résout une référence de secret (EX-15.4 pas 4).
 * @param {object} ref
 * @param {string} pointeur pointeur JSON de la référence, pour le rapport
 * @param {{env?: NodeJS.ProcessEnv, uid?: number|null}} [contexte]
 * @returns {Uint8Array}
 * @throws {ErreurSecret}
 */
export function resoudreSecret(ref, pointeur, contexte = {}) {
  const env = contexte.env ?? process.env;
  let brut;
  if (typeof ref?.env === "string") {
    const v = env[ref.env];
    if (v === undefined) throw new ErreurSecret(pointeur, `variable d'environnement ${ref.env} absente`);
    brut = new Uint8Array(Buffer.from(v, "utf8"));
  } else if (typeof ref?.file === "string") {
    let st;
    try {
      st = fs.statSync(ref.file);
    } catch {
      throw new ErreurSecret(pointeur, `fichier de secret ${ref.file} illisible`);
    }
    const uid = contexte.uid === undefined ? (process.getuid?.() ?? null) : contexte.uid;
    if ((st.mode & 0o077) !== 0) throw new ErreurSecret(pointeur, `fichier de secret ${ref.file} lisible par d'autres que son propriétaire (0400 ou 0600 attendu)`);
    if (uid !== null && st.uid !== uid) throw new ErreurSecret(pointeur, `fichier de secret ${ref.file} d'un autre propriétaire que l'utilisateur du démon`);
    brut = new Uint8Array(fs.readFileSync(ref.file));
  } else if (ref?.vault) {
    throw new ErreurSecret(pointeur, "référence vault non prise en charge par ce lot du démon");
  } else {
    throw new ErreurSecret(pointeur, "référence de secret mal formée");
  }
  const octets = decoderSecret(brut, ref.encoding);
  if (octets === null) throw new ErreurSecret(pointeur, `valeur non décodable selon encoding ${ref.encoding}`);
  return octets;
}
