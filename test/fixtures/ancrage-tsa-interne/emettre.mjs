// Processus émetteur des essais d'AN-26 (lot E) : ouvre le compteur durable
// d'un répertoire, répond à une requête des vecteurs CT-5 avec l'autorité de
// test de CT-6, écrit la réponse et imprime le numéro de série émis.
// Arguments : <répertoire du compteur> <requête .tsq> <réponse .tsr>
// [--tenir <ms>] (garde le verrou ouvert pendant ce délai avant de répondre,
// pour éprouver l'exclusion d'un second émetteur).
// Code de retour : 0 réussi ; 3 verrou refusé (ErreurCompteur) ; 1 autre erreur.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Autorite, Compteur, ErreurCompteur, repondre } from "@noortrace/ancrage/serveur-interne";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CLES = path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles");

/** Corps du processus émetteur ; lancé seulement comme programme (le chargeur des essais importe aussi ce fichier). */
async function principal() {
  const [repertoire, requete, reponse, ...reste] = process.argv.slice(2);
  const tenir = reste[0] === "--tenir" ? Number(reste[1]) : 0;
  const horloge = { murale: () => Date.parse("2026-11-03T13:53:02Z"), monotone: () => 0, ecartMs: 0 };

  let compteur;
  try {
    compteur = Compteur.ouvrir({ repertoire });
  } catch (e) {
    if (e instanceof ErreurCompteur) {
      process.stdout.write(`verrou refuse: ${e.message}\n`);
      process.exit(3);
    }
    throw e;
  }
  if (tenir > 0) {
    process.stdout.write("verrou pris\n");
    await new Promise((r) => setTimeout(r, tenir));
  }
  const autorite = new Autorite({
    clePrivee: fs.readFileSync(path.join(CLES, "tsa-test.cle.pem")),
    certificat: fs.readFileSync(path.join(CLES, "tsa-test.pem")),
    politique: "1.3.6.1.4.1.99999.1.1",
    compteur,
  });
  const r = repondre({ requete: new Uint8Array(fs.readFileSync(requete)), autorite, horloge });
  fs.writeFileSync(reponse, r.octets);
  process.stdout.write(`${r.statut} ${r.serial ?? ""}\n`);
  autorite.fermer();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await principal();
