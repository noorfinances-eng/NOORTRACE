// Fil d'exécution (worker_threads) de l'essai d'identité d'EX-18.10 : pour
// chaque dossier qu'il reçoit et chaque configuration, il fait vérifier le
// dossier par travailleur.js (prélude et pilote tels quels, sous Node) et par
// le binaire natif dans une racine /entrees, puis compare, octet pour octet,
// sortie standard, sortie d'erreur et code des deux exécutions (lisible,
// --json).

import fs from "node:fs";
import path from "node:path";
import { isMainThread, parentPort, workerData } from "node:worker_threads";
import { chargerTravailleur } from "./travailleur-node.mjs";
import { ANCRES, CHAINE, RacineNatif, argumentsVerification, fichiersDe } from "./outils.mjs";

const tampon = (b) => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);

function premiereDifference(a, b) {
  const n = Math.min(a.length, b.length);
  let i = 0;
  while (i < n && a[i] === b[i]) i++;
  const extrait = (x) => Buffer.from(x.subarray(Math.max(0, i - 40), i + 40)).toString("utf8");
  return `octet ${i} (longueurs ${a.length} et ${b.length}) : page « ${extrait(a)} » ; binaire « ${extrait(b)} »`;
}

/** Corps du fil : ne s'exécute que dans un fil lancé par l'essai, jamais quand le module est seulement chargé (npm test charge chaque fichier de test/). */
async function executerFil({ travailleur, wasm, natif, racine, dossiers, configurations }) {
  const t = chargerTravailleur(fs.readFileSync(travailleur, "utf8"));
  const octetsWasm = fs.readFileSync(wasm);
  const pret = await t.envoyer({ type: "artefact", octets: tampon(octetsWasm) });
  if (pret.type !== "artefact_pret") throw new Error(`artefact non prêt : ${JSON.stringify(pret)}`);

  const r = new RacineNatif(racine, natif);
  const ancres = fs.readFileSync(ANCRES);
  const chaine = fs.readFileSync(CHAINE);
  const discordances = [];
  const codes = {};
  let executions = 0;
  let versionJson = null;

  for (const d of dossiers) {
    const contenu = fichiersDe(d.chemin);
    for (const c of configurations) {
      const nomConfiguration = `${d.nom} ${argumentsVerification(c).join(" ")}`;
      const fichiers = contenu.map((f) => ({ chemin: `dossier/${f.chemin}`, octets: tampon(f.octets) }));
      if (c.ancres) fichiers.push({ chemin: "ancres.json", octets: tampon(ancres) });
      if (c.entetes) fichiers.push({ chemin: "entetes-bitcoin.json", octets: tampon(chaine) });
      const reponse = await t.envoyer({ type: "verifier", fichiers, repertoires: [], options: { ...c, exiger: c.exiger ?? null, detail: c.detail === true } });
      if (reponse.type !== "resultat") {
        discordances.push(`${nomConfiguration} : la page rend ${JSON.stringify(reponse)}`);
        continue;
      }
      r.installer(d.chemin, c);
      const args = argumentsVerification(c);
      const attendues = [r.executer(args), r.executer([...args, "--json"])];
      const page = reponse.executions;
      if (page[0].code !== page[1].code) discordances.push(`${nomConfiguration} : codes des deux exécutions de la page différents (${page[0].code}, ${page[1].code})`);
      for (let i = 0; i < 2; i++) {
        const p = page[i];
        const n = attendues[i];
        const quoi = `${nomConfiguration}${i === 1 ? " --json" : ""}`;
        executions++;
        const argv = ["noortrace-verifier", ...args, ...(i === 1 ? ["--json"] : [])];
        if (JSON.stringify(p.arguments) !== JSON.stringify(argv)) discordances.push(`${quoi} : arguments ${JSON.stringify(p.arguments)}`);
        if (p.code !== n.code) discordances.push(`${quoi} : code ${p.code} au lieu de ${n.code}`);
        if (Buffer.compare(Buffer.from(p.sortie), n.sortie) !== 0) discordances.push(`${quoi} : sortie standard, ${premiereDifference(Buffer.from(p.sortie), n.sortie)}`);
        if (Buffer.compare(Buffer.from(p.erreur), n.erreur) !== 0) discordances.push(`${quoi} : sortie d'erreur, ${premiereDifference(Buffer.from(p.erreur), n.erreur)}`);
        codes[n.code] = (codes[n.code] ?? 0) + 1;
        if (i === 1 && versionJson === null && n.code !== 2) versionJson = JSON.parse(n.sortie.toString("utf8")).verifier.version;
      }
    }
    parentPort.postMessage({ type: "progression", dossier: d.nom });
  }
  fs.rmSync(racine, { recursive: true, force: true });
  parentPort.postMessage({ type: "fin", discordances, codes, executions, version: pret.version, empreinte: pret.empreinte, versionJson });
}

if (!isMainThread && workerData) await executerFil(workerData);
