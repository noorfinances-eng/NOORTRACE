// Démon d'essai des décors de l'ancrage (test/fixtures/enregistreur-ancrage/demon.mjs) :
// la relance qui suit la perte du bail (CT-2 EX-13.6 ; 13.4, pas 8) emploie
// l'horloge injectée du décor, comme le premier démarrage. Sans cela,
// l'instance relancée lit l'horloge du système : ses lignes du journal
// d'exploitation sont datées de l'heure de la machine, et la durée de sa
// relance et de son arrêt en dépend.
//
// L'essai monte le démon réel sur une horloge injectée éloignée de l'heure de
// la machine, fait perdre le bail (auxiliaire flock terminé, comme TE-14 JS-3),
// attend la relance, puis constate que l'instance relancée date son démarrage
// et ses lignes sur l'horloge injectée, et qu'un arrêt demandé ensuite sort
// par le code 0.

import { expect } from "chai";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { monterDemon, Demon, repertoireTemporaire, enAttente } from "./fixtures/enregistreur-ancrage/outils.mjs";

const BASE = Date.UTC(2026, 10, 6, 9, 0, 2); // 2026-11-06T09:00:02Z, période [09:00, 10:00)
const UNE_HEURE = 3600000;

describe("démon d'essai de l'ancrage : la relance après perte du bail emploie l'horloge injectée (CT-2 EX-13.6)", function () {
  this.timeout(300000);
  let dir;
  let m;
  let demon;

  before(async function () {
    dir = repertoireTemporaire("noortrace-relance-horloge-");
    m = await monterDemon({ dir, baseMs: BASE, registre: false, surchargesAncrage: { registry: { checkpoints: "aucun" } } });
    if (m.condition) return;
    demon = new Demon(m);
    await demon.demarrer();
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await m?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("l'instance relancée date son démarrage et ses lignes sur l'horloge injectée, jamais sur celle de la machine ; les commandes s'adressent à elle ; l'arrêt demandé ensuite sort par le code 0", async function () {
    if (!m || m.condition) return enAttente(this, m?.condition ?? "contexte non préparé");
    // L'horloge injectée est à plus d'une heure de celle de la machine : les deux se distinguent sans ambiguïté.
    expect(Math.abs(Date.now() - BASE)).to.be.above(24 * UNE_HEURE);
    const injectee = (ms) => Math.abs(ms - BASE) < UNE_HEURE;
    const avant = await demon.commande({ cmd: "demarrage" });
    expect(injectee(avant.demarrage), `premier démarrage à ${avant.demarrage}`).to.equal(true);
    expect((await demon.evenement(1)).seq).to.be.a("number");
    // Perte du bail : le verrou est rendu par le noyau quand l'auxiliaire flock se termine.
    const enfants = spawnSync("pgrep", ["-P", String(demon.pid), "-x", "flock"], { encoding: "utf8" });
    const pids = enfants.stdout.trim().split("\n").filter(Boolean);
    expect(pids.length, "auxiliaire flock du bail").to.be.at.least(1);
    for (const p of pids) process.kill(Number(p), "SIGKILL");
    await new Promise((r) => setTimeout(r, 300));
    await demon.evenement(2).catch(() => {});
    const limite = Date.now() + 30000;
    while (!/bail perdu, relance en instance passive/.test(demon.sortie) && Date.now() < limite) await new Promise((r) => setTimeout(r, 20));
    expect(demon.sortie, "relance après perte du bail").to.match(/bail perdu, relance en instance passive/);
    const avantRelance = demon.lignes().length;
    // L'instance relancée remplace la première : son instant de démarrage est postérieur, et lu sur l'horloge injectée.
    let apres = null;
    while (Date.now() < limite) {
      const r = await demon.commande({ cmd: "demarrage" });
      if (r.demarrage !== avant.demarrage) {
        apres = r;
        break;
      }
      await new Promise((r2) => setTimeout(r2, 50));
    }
    expect(apres, "instance relancée en place").to.not.equal(null);
    expect(apres.pid).to.equal(avant.pid);
    expect(apres.demarrage).to.be.above(avant.demarrage);
    expect(injectee(apres.demarrage), `relance à ${apres.demarrage}, horloge de la machine ${Date.now()}`).to.equal(true);
    expect(Math.abs(apres.demarrage - apres.murale)).to.be.below(60000);
    // Les lignes du journal d'exploitation écrites depuis la relance sont datées sur l'horloge injectée.
    const fin = await demon.arreter();
    expect(fin.code, JSON.stringify(fin)).to.equal(0);
    const lignes = demon.lignes();
    const depuis = lignes.slice(avantRelance);
    expect(depuis.length, "lignes écrites depuis la relance").to.be.at.least(1);
    for (const l of lignes) expect(injectee(N.decoderHorodatage(l.ts)), `${l.event} ${l.ts}`).to.equal(true);
    expect(lignes.at(-1).event).to.equal("shutdown");
  });
});
