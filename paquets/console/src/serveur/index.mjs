// Serveur de console NOORTRACE (CT-3 13.20, 13.21 ; contrat 2.2) :
// `demarrerServeur`, `validerConfiguration`, `sonder`, `principal`.
// Node seulement, sans cadriciel (`node:http`, `node:https`, `node:crypto`) ;
// de `@noortrace/approbation`, seulement `RegistreSchemas` et
// `lireJsonStrict` ; de la bibliothèque de la console, `estIdentiteCanonique`,
// `METHODES_CANAL` et `METHODES_REAUTHENTIFICATION`.

import path from "node:path";
import { erreursDocument, completer, refusDemarrage, resoudreReferences, validerConfiguration } from "./configuration.mjs";
import { chargerPages, PAGES_DEFAUT } from "./pages.mjs";
import { ecouter } from "./serveur.mjs";
import { ErreurDemarrage, creerJournal } from "./outils.mjs";
import { sonder } from "./sonde.mjs";
import { principal } from "./cli.mjs";

export { validerConfiguration, sonder, principal };

/**
 * Démarre le serveur de console. Lève `ErreurDemarrage` (code de sortie 1)
 * pour une configuration refusée, un `walletconnect` non nul
 * (`parcours_non_offert`), une référence illisible ou mal formée
 * (`reference_illisible`), une écoute impossible (`ecoute_impossible`) :
 * l'erreur porte alors `rapport`, la ligne d'EX-10.14 ; ou pour un manifeste
 * des pages en écart (texte seul).
 * @param {{config: object, base: string, horloge?: () => number, agentHttps?: import("node:https").Agent, pages?: string}} o
 * @returns {Promise<{adresse: {host: string, port: number}, arreter: () => Promise<void>}>}
 */
export async function demarrerServeur({ config, base, horloge = Date.now, agentHttps, pages }) {
  const errors = erreursDocument(config);
  if (errors.length) throw new ErreurDemarrage("configuration refusée", { rapport: { valide: false, errors } });
  const c = completer(config);
  if (c.walletconnect !== null) throw refusDemarrage("parcours_non_offert", "/walletconnect", "parcours c non offert par cette console");
  const secrets = resoudreReferences(c, path.resolve(base));
  const bibliotheque = await import("@noortrace/console");
  if (c.identity.kind === "local") {
    // Révision 0.6 : chaque nom forme avec `identity.domain` une identité
    // canonique d'EX-13.7, de 256 caractères au plus (`reference_illisible`).
    for (const nom of secrets.identity.comptes.keys()) {
      if (!bibliotheque.estIdentiteCanonique(`utilisateur ${c.identity.domain} ${nom}`)) {
        throw refusDemarrage("reference_illisible", "/identity/accounts", "référence mal formée : /identity/accounts");
      }
    }
  }
  const fichiers = chargerPages(pages ?? PAGES_DEFAUT);
  const journal = creerJournal(horloge);
  const e = await ecouter({ config: c, secrets, horloge, agentHttps, pages: fichiers, journal, bibliotheque });
  const a = e.serveur.address();
  const adresse = { host: a.address, port: a.port };
  journal("serveur_pret", { ecoute: adresse });
  let arrete = false;
  return {
    adresse,
    async arreter() {
      if (arrete) return;
      arrete = true;
      await e.fermer();
      journal("serveur_arrete", {});
    },
  };
}
