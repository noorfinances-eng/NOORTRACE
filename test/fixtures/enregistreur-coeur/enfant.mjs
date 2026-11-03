// Processus enfant des tests de reprise du cœur : démarre un cœur sur une
// configuration de développement, écrit, puis attend d'être tué (SIGKILL).
//   node enfant.mjs <configuration.json> intention        intention durable, relais en vol
//   node enfant.mjs <configuration.json> boucle           échanges scellés sans fin
//   node enfant.mjs <configuration.json> cloture-sig      se tue juste avant le renommage de la
//                                                          signature du manifeste (clôture)
//   node enfant.mjs <configuration.json> reprise-attente  redémarre, se tue juste avant la
//                                                          suppression du fichier d'attente repris
// Importé sans être lancé (par exemple par le chargeur des tests, qui lit
// tous les fichiers .mjs de test/), il ne fait rien.
import fs from "node:fs";
import fsp from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { Coeur, HorlogeReglable, pieceJson } from "@noortrace/enregistreur";
import { decoderHorodatage } from "@noortrace/noyau";
import { secretsDev } from "./outils.mjs";

/** Arrêt brutal du processus quand `rename` vise `motif` (avant) ou `rm` vise `motifRm`. */
function armerArretBrutal({ motif = null, motifRm = null }) {
  const renommer = fsp.rename;
  fsp.rename = async function (a, b) {
    if (motif && motif.test(String(b))) {
      fs.writeSync(1, `KILL rename ${b}\n`);
      process.kill(process.pid, "SIGKILL");
    }
    return renommer.call(this, a, b);
  };
  const supprimer = fsp.rm;
  fsp.rm = async function (p, ...reste) {
    if (motifRm && motifRm.test(String(p))) {
      fs.writeSync(1, `KILL rm ${p}\n`);
      process.kill(process.pid, "SIGKILL");
    }
    return supprimer.call(this, p, ...reste);
  };
}

async function principal() {
  const [chemin, mode] = process.argv.slice(2);
  const config = JSON.parse(fs.readFileSync(chemin, "utf8"));
  if (mode === "reprise-attente") {
    armerArretBrutal({ motifRm: /attente\/attente-/ });
    await Coeur.demarrer({ config, secrets: secretsDev(), horloge: new HorlogeReglable(decoderHorodatage("2026-11-10T10:20:00.000Z")) });
    process.stdout.write("FINI\n");
    process.exit(0);
  }
  const horloge = mode === "cloture-sig" ? new HorlogeReglable(decoderHorodatage("2026-11-10T10:14:02.100Z")) : undefined;
  const coeur = await Coeur.demarrer({ config, secrets: secretsDev(), horloge });
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
  } else if (mode === "cloture-sig") {
    // Trois échanges dans la période 10:00-11:00, puis la clôture, interrompue
    // entre l'écriture du manifeste et celle de sa signature (R-A-1).
    for (let k = 1; k <= 3; k++) {
      horloge.avancer(1000);
      await echange(k);
    }
    horloge.aller(decoderHorodatage("2026-11-10T11:00:00.250Z"));
    armerArretBrutal({ motif: /manifestes\/periode-[0-9]{10}\.sig$/ });
    await coeur.tic();
    process.stdout.write("FINI\n");
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
