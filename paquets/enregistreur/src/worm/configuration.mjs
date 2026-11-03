// Règles de configuration du support WORM que le cœur ne vérifie pas encore
// (EX-15.4 pas 3) et fabrique du service de copies du démon.

import { jcsIntegralOctets } from "../jcs-integral.mjs";
import { parcourirSecrets } from "../configuration.mjs";
import { operationsSupport } from "./support.mjs";
import { ServiceCopiesWorm } from "./copies.mjs";

/**
 * Emplacement désigné par une référence de secret (15.2), sans son
 * `encoding` : `{ "file": "/run/secrets/x", "encoding": "hex" }` et
 * `{ "file": "/run/secrets/x" }` désignent le même secret (les mêmes octets
 * lus, décodés autrement) ; c'est la « même référence » d'EX-15.4.
 */
const emplacement = (v) => {
  if (v && typeof v === "object" && !Array.isArray(v)) {
    const { encoding, ...reste } = v;
    void encoding;
    return Buffer.from(jcsIntegralOctets(reste)).toString("utf8");
  }
  return Buffer.from(jcsIntegralOctets(v)).toString("utf8");
};

/**
 * Règle supplémentaire du pas 3 d'EX-15.4 : avertissement si
 * `storage.seal.worm.credentials` est la même référence qu'un autre secret de
 * la configuration (même fichier, même variable ou même chemin de coffre,
 * quel que soit `encoding`).
 * @param {object} c document
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controleWorm(c) {
  const avertissements = [];
  const worm = c.storage?.seal?.worm;
  if (worm?.credentials) {
    const cible = emplacement(worm.credentials);
    parcourirSecrets(c, "", (ref, pointeur) => {
      if (pointeur !== "/storage/seal/worm/credentials" && emplacement(ref) === cible) {
        avertissements.push({ pointeur: "/storage/seal/worm/credentials", regle: `même référence que ${pointeur} (EX-15.4)` });
      }
    });
  }
  return { erreurs: [], avertissements };
}

/**
 * Service de copies de l'écrivain pour `storage.seal.worm`, ou null sans
 * support ; identifiants de l'écrivain résolus (`/storage/seal/worm/credentials`).
 * @param {object} config
 * @param {Map<string, Uint8Array>} secrets
 * @param {{tls?: object, delais?: number[]}} [o]
 * @returns {ServiceCopiesWorm|null}
 */
export function supportWormDepuisConfiguration(config, secrets, o = {}) {
  const worm = config.storage.seal.worm;
  if (!worm) return null;
  const id = secrets.get("/storage/seal/worm/credentials");
  if (!id) throw new Error("identifiants du support WORM non résolus");
  return new ServiceCopiesWorm({ worm, operations: operationsSupport(worm, id, o) });
}
