// Processus enfant des tests de reprise du cœur : démarre un cœur sur une
// configuration de développement, écrit, puis attend d'être tué (SIGKILL).
//   node enfant.mjs <configuration.json> intention   intention durable, relais en vol
//   node enfant.mjs <configuration.json> boucle      échanges scellés sans fin
// Importé sans être lancé (par exemple par le chargeur des tests, qui lit
// tous les fichiers .mjs de test/), il ne fait rien.
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { Coeur, pieceJson } from "@noortrace/enregistreur";
import { secretsDev } from "./outils.mjs";

async function principal() {
  const [chemin, mode] = process.argv.slice(2);
  const config = JSON.parse(fs.readFileSync(chemin, "utf8"));
  const coeur = await Coeur.demarrer({ config, secrets: secretsDev() });
  const delegation = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement", run_id: null };

  async function echange(n) {
    const req = pieceJson({ n, messages: [{ role: "user", content: `requete ${n}` }] });
    const rep = pieceJson({ n, content: [{ type: "text", text: `reponse ${n}` }] });
    await coeur.ecrirePiece(req);
    await coeur.ecrirePiece(rep);
    return coeur.scellerEchange({
      delegation,
      code: { model: "fournisseur/modele-test", prompt_version: null },
      intent: null,
      requete: req.reference,
      reponse: rep.reference,
      duration_ms: 10,
      is_error: false,
    });
  }

  if (mode === "intention") {
    await echange(1);
    const args = pieceJson({ claim_id: "2026-81044", amount: "7400.00", currency: "CHF" });
    await coeur.ecrirePiece(args);
    const appel = {
      host: { id: "agent-sinistres-stdio" },
      delegation,
      tool_announced: "sap__payments.create",
      tool_original: "payments.create",
      server_alias: "sap",
      class: "ecriture",
      arguments: args.reference,
      context: [],
      intent: null,
      code: { model: null, prompt_version: null },
    };
    const relais = await coeur.preparerRelais(appel, {
      reponse: { rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null },
      argumentsEnClair: { claim_id: "2026-81044", amount: "7400.00", currency: "CHF" },
      upstream_id: "e-000000000007",
    });
    process.stdout.write(`INTENTION ${relais.intention.intent_id} ${relais.intention.intention_sha256}\n`);
  } else {
    let n = 0;
    for (;;) {
      await echange(++n);
      if (n === 5) process.stdout.write("PRET\n");
    }
  }
  setInterval(() => {}, 1000);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await principal();
