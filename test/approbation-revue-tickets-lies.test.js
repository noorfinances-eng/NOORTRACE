// Contrôle de session du canal de la console (`controleCanal`, bibliothèque
// d'annuaire du paquet console, réexportée par le service d'approbation) :
// `tickets` avec `related_to` (CT-3 révision 0.8, EX-13.32, table, et
// EX-12.21) — « ticket est nul pour un ticket inconnu dans l'organisation, et
// pour tickets sans related_to ; avec related_to, c'est le ticket désigné,
// auquel s'applique l'ordre de consulter ». Revue de sécurité de l'étape 8 : les cas
// `tickets-related-*` des vecteurs régénérés (CT-3 EX-13.32) le jugent ; ici,
// chaque cas `consulter` publié est rejoué comme une requête `tickets` qui
// désigne le même ticket. La bibliothèque éprouvée est celle du paquet, ou le
// fichier que nomme NOORTRACE_REVUE_ANNUAIRE (copie ou mutant).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ANNUAIRE = process.env.NOORTRACE_REVUE_ANNUAIRE ? pathToFileURL(path.resolve(process.env.NOORTRACE_REVUE_ANNUAIRE)).href : "@noortrace/console/annuaire";
const { controleCanal } = await import(ANNUAIRE);
const lire = (rel) => JSON.parse(fs.readFileSync(path.join(RACINE, "spec", "vecteurs", "ct-3", "annuaire", rel), "utf8"));

describe("approbation, revue de sécurité de l'étape 8 : tickets avec related_to suit l'ordre de consulter (CT-3 EX-13.32, EX-12.21, révision 0.8)", function () {
  const c = lire("controles-canal.json");
  const annuaire = lire(c.annuaire);
  const consulter = c.cases.filter((x) => x.method === "consulter");

  it("chaque cas consulter publié, rejoué comme tickets { session_identity, related_to: ticket }, rend la raison de consulter (null, identite_invalide, session_non_autorisee ou ticket_inconnu)", function () {
    expect(consulter.length).to.be.at.least(10);
    for (const x of consulter) {
      const requete = { session_identity: x.request.session_identity, related_to: x.request.ticket };
      expect(controleCanal(annuaire, "tickets", requete, x.ticket), x.id).to.equal(x.expected.reason);
    }
  });

  it("sans related_to, tickets ne lit aucun ticket : la session de l'organisation passe, une session hors organisation est refusée (cas tickets publiés)", function () {
    for (const x of c.cases.filter((y) => y.method === "tickets" && y.request.related_to === undefined)) {
      expect(controleCanal(annuaire, "tickets", x.request, null), x.id).to.equal(x.expected.reason);
    }
  });
});
