// Processus enfant des essais du composant d'ancrage branché dans
// l'enregistreur (lot F2) : le démon réel assemblé par `principal` de
// `src/cli.mjs` (configuration, secrets, composant d'ancrage, cœur, frontaux,
// signaux), avec l'horloge hybride des essais du composant (le temps mural
// avance avec le temps réel et saute sur commande, les minuteries du
// composant suivent). Il lit des commandes JSON sur son entrée standard, une
// par ligne, et répond une ligne JSON par commande sur sa sortie standard
// (la sortie du démon va sur la sortie d'erreur) :
//   { "cmd": "avancer", "ms": n }                       saute de n ms (murale et monotone ensemble)
//   { "cmd": "evenement", "n": k }                      scelle un échange de modèle factice (événement durable), rend seq
//   { "cmd": "exporter", "seq": s, "destination": d }   exporte le dossier de l'événement s
//   { "cmd": "reexports" }                              dossiers à réexporter (EX-10.5)
//   { "cmd": "etat" }                                   état du composant d'ancrage
//   { "cmd": "journal", "event": e }                    lignes du journal d'exploitation en mémoire d'un événement
//   { "cmd": "decaler-murale", "ms": n }                déplace la seule horloge murale de n ms (recul si n < 0 ; TE-14, JS-8)
//   { "cmd": "rotation", "cle": k }                     rotation de la clé de l'enregistreur vers k (TE-14, JS-4)
//   { "cmd": "controles" }                              un tour des contrôles périodiques du cœur (EX-17.5)
//   { "cmd": "worm", "action": a }                      balayer | quotidien | horaire | vider sur le support WORM branché
//   { "cmd": "metriques" }                              exposition texte des métriques (cœur et ancrage)
//   { "cmd": "demarrage" }                              instant du démarrage du cœur et horloge murale (CT-2 EX-15.10, demandes périmées)
//   { "cmd": "point-arret", "repertoire": r }           point d'arrêt de l'export d'une demande `dossier` (CT-2 EX-15.13) avant la
//                                                       seconde vérification du parent : écrit <r>/atteint-<request_id> (chemin du
//                                                       répertoire temporaire) et attend <r>/reprendre-<request_id> ; r null : retiré
//   { "cmd": "arreter" }                                arrêt propre, code 0
//   node demon.mjs noortrace --config <configuration.json>
// (le mot `noortrace` avant `--config` fait reconnaître le processus par
// `noortrace-ctl`, qui cherche `noortrace --config <fichier>` dans la ligne
// de commande). L'instant de départ de l'horloge vient de la variable
// NOORTRACE_TEST_HORLOGE_BASE_MS. Importé sans être lancé, il ne fait rien.

import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";
import { principal, superviserProcessus, pieceJson } from "@noortrace/enregistreur";
import { HorlogeHybride } from "../ancrage-composant/outils.mjs";

const DELEGATION = { launched_by: "agent-sinistres", on_behalf_of: null, scope: "sinistres:lecture,paiement", run_id: null };

async function principalEnfant() {
  const argv = process.argv.slice(2);
  const k = argv.indexOf("--config");
  const base = Number(process.env.NOORTRACE_TEST_HORLOGE_BASE_MS);
  const horloge = new HorlogeHybride(Number.isFinite(base) ? base : Date.now());
  const repondre = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
  const r = await principal(["--config", argv[k + 1]], { horloge, stdout: process.stderr, stderr: process.stderr });
  if (typeof r === "number") {
    repondre({ started: false, code: r });
    process.exit(r);
  }
  const { coeur } = r;
  superviserProcessus(r, { argv: ["node", "noortrace", "--config", argv[k + 1]] });
  repondre({ started: true, port: coeur.serveur?.address()?.port ?? null, epoque: coeur.ecrivain?.epoque ?? null, pid: process.pid, murale: horloge.murale() });

  async function echange(n) {
    const req = pieceJson({ n, messages: [{ role: "user", content: `requete ${n}` }] });
    const rep = pieceJson({ n, content: [{ type: "text", text: `reponse ${n}` }] });
    await coeur.ecrirePiece(req);
    await coeur.ecrirePiece(rep);
    return coeur.scellerEchange({ delegation: DELEGATION, code: { model: "fournisseur/modele-test", prompt_version: null }, intent: null, requete: req.reference, reponse: rep.reference, duration_ms: 10, is_error: false });
  }

  const lecteur = readline.createInterface({ input: process.stdin });
  for await (const ligne of lecteur) {
    if (!ligne.trim()) continue;
    let c;
    try {
      c = JSON.parse(ligne);
    } catch {
      repondre({ ok: false, erreur: "commande illisible" });
      continue;
    }
    try {
      switch (c.cmd) {
        case "avancer":
          await horloge.avancer(Number(c.ms));
          repondre({ ok: true, id: c.id, murale: horloge.murale() });
          break;
        case "evenement": {
          const e = await echange(Number(c.n ?? 1));
          repondre({ ok: true, id: c.id, seq: e.seq, ts: e.ts, hash: e.hash });
          break;
        }
        case "exporter": {
          const d = await coeur.exporterDossier(Number(c.seq), String(c.destination));
          repondre({ ok: true, id: c.id, parts: d.parts.map((p) => ({ name: p.name, present: p.present, reason: p.reason_if_absent })) });
          break;
        }
        case "reexports":
          repondre({ ok: true, id: c.id, dus: await coeur.reexportsDus() });
          break;
        case "etat":
          repondre({ ok: true, id: c.id, etat: coeur.o.ancrage ? coeur.o.ancrage.etat() : null, murale: horloge.murale() });
          break;
        case "journal":
          repondre({ ok: true, id: c.id, lignes: coeur.journal.trouver(String(c.event)) });
          break;
        case "decaler-murale":
          // CT-2 EX-7.9, EX-7.13 (TE-14, JS-8) : la seule horloge murale recule ou saute, la monotone suit le temps réel.
          horloge.decalerMurale(Number(c.ms));
          repondre({ ok: true, id: c.id, murale: horloge.murale() });
          break;
        case "rotation": {
          // CT-2 EX-11.15 (TE-14, JS-4) : rotation de la clé de l'enregistreur vers une clé que le signataire détient.
          const e = await coeur.tournerCle(String(c.cle));
          repondre({ ok: true, id: c.id, seq: e.seq, hash: e.hash });
          break;
        }
        case "controles":
          // CT-2 EX-17.5 (TE-14, JS-10) : un tour des contrôles périodiques du cœur, à l'instant de l'horloge injectée.
          await coeur.controles.tic();
          repondre({ ok: true, id: c.id });
          break;
        case "worm": {
          // CT-2 EX-17.5 à EX-17.7 (TE-14, JS-9, JS-10) : balayage des copies, contrôles de la supervision WORM.
          const w = coeur.o.worm ?? null;
          if (!w) {
            repondre({ ok: false, id: c.id, erreur: "aucun support WORM" });
            break;
          }
          let resultat = null;
          if (c.action === "balayer") resultat = await w.balayer();
          else if (c.action === "quotidien") await w.supervision?.quotidien(horloge.murale());
          else if (c.action === "horaire") await w.supervision?.horaire(horloge.murale());
          else if (c.action === "vider") await w.vider();
          repondre({ ok: true, id: c.id, resultat });
          break;
        }
        case "metriques":
          repondre({ ok: true, id: c.id, texte: coeur.metriques.exposer() + (typeof coeur.o.ancrage?.metriques === "function" ? coeur.o.ancrage.metriques() : "") });
          break;
        case "demarrage":
          repondre({ ok: true, id: c.id, demarrage: coeur.instantDemarrage, murale: horloge.murale(), pid: process.pid });
          break;
        case "point-arret": {
          // CT-2 EX-15.13 point 2 (TE-18) : lien posé pendant l'écriture, arrêt brutal avant le renommage.
          const rep = c.repertoire ? String(c.repertoire) : null;
          coeur.o.pointArretExport = rep === null ? undefined : async ({ request_id, temporaire }) => {
            fs.writeFileSync(path.join(rep, `atteint-${request_id}`), temporaire);
            const limite = Date.now() + 120000;
            while (!fs.existsSync(path.join(rep, `reprendre-${request_id}`)) && Date.now() < limite) await new Promise((r) => setTimeout(r, 20));
          };
          repondre({ ok: true, id: c.id });
          break;
        }
        case "panne-export":
          // CT-2 EX-15.15 (révision 0.9) : erreur imprévue pendant l'écriture d'un export (avant le renommage).
          coeur.o.pointArretExport = c.actif === false ? undefined : async () => {
            throw new TypeError("panne d'essai de l'export");
          };
          repondre({ ok: true, id: c.id });
          break;
        case "panne-synchronisation":
          // CT-2 EX-15.13 point 2 (révision 0.9) : synchronisation du parent en échec après le renommage.
          coeur.o.essaiSynchronisationParent = c.actif === false ? undefined : () => {
            throw Object.assign(new Error("synchronisation d'essai"), { code: "EIO" });
          };
          repondre({ ok: true, id: c.id });
          break;
        case "panne-ancrage": {
          // CT-2 EX-15.15 (révision 0.9) : erreur imprévue d'une demande ancrage, hors des refus prévus.
          if (c.actif === false) delete coeur.commandeAncrage;
          else coeur.commandeAncrage = async () => {
            throw new TypeError("panne d'essai de l'ancrage");
          };
          repondre({ ok: true, id: c.id });
          break;
        }
        case "arreter":
          process.kill(process.pid, "SIGTERM");
          repondre({ ok: true, id: c.id });
          break;
        default:
          repondre({ ok: false, id: c.id, erreur: `commande inconnue : ${String(c.cmd)}` });
      }
    } catch (e) {
      repondre({ ok: false, id: c.id, erreur: String(e?.message ?? e).slice(0, 500) });
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await principalEnfant();
