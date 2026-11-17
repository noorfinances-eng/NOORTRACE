// Application d'exploitant : longueur du chemin de la prise de l'agent
// (`prise` de l'agent et de l'interface ; CT-4 EX-7.28 ; CT-2 EX-6.10 ;
// complément du 2026-11-16) et lignes de commande de
// `noortrace-inscription-agent` et `noortrace-inscription-web`.
//
// L'agent bornait sa prise à 107 octets, taille de `sun_path` sous Linux ;
// sous macOS, la borne est de 103, et un chemin plus long y est tronqué sans
// erreur : l'agent écouterait, et l'interface joindrait, une autre prise que
// celle du répertoire d'EX-7.28. L'interface ne bornait rien. Le chemin fait
// désormais au plus 103 octets UTF-8, borne du SDK, du démon et du service
// d'approbation : l'agent et l'interface le refusent au démarrage (code 2,
// `chemin_prise_trop_long`), le client de la prise avant toute connexion.
//
// Une option inconnue, en double ou sans sa valeur, ou un argument en trop,
// rend l'usage et le code 2.

import { expect } from "chai";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { lireConfiguration, ErreurConfiguration } from "../paquets/inscription/src/agent/configuration.mjs";
import { lireConfigurationInterface, ErreurConfigurationInterface } from "../paquets/inscription/src/web/lib/serveur.mjs";
import * as Client from "../paquets/inscription/src/agent/client.mjs";

const { remettre, ErreurAgent } = Client;
import { creerRepertoireTemporaire } from "./aides/temporaires.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_AGENT = path.join(RACINE, "paquets", "inscription", "bin", "noortrace-inscription-agent");
const BIN_WEB = path.join(RACINE, "paquets", "inscription", "bin", "noortrace-inscription-web");

/** Chemin de `n` octets exactement : `<dir>/p…p.sock`. */
function cheminDe(dir, n) {
  const reste = n - Buffer.byteLength(dir) - "/".length - ".sock".length;
  if (reste < 1) throw new Error(`répertoire trop long pour un chemin de ${n} octets : ${dir}`);
  const c = `${dir}/${"p".repeat(reste)}.sock`;
  expect(Buffer.byteLength(c)).to.equal(n);
  return c;
}

const configurationAgent = (prise) => ({
  version: 0, prise, interface_uid: 4242, donnees: "/var/lib/noortrace-inscription", nature: "developpement", instance: null,
  rpc: ["http://127.0.0.1:8545"], jeton: null, comptes: {}, cles: null,
});
const configurationInterface = (prise, dir) => ({
  version: 0, ecoute: { hote: "127.0.0.1", port: 3999 }, origine: "http://127.0.0.1:3999", prise, donnees: "/var/lib/noortrace-inscription",
  comptes: `fichier:${dir}/comptes-absents.json`, nature: "developpement",
});

function commande(bin, args) {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", timeout: 60000 });
  return { code: r.status, sortie: r.stdout, erreur: r.stderr };
}

describe("inscription : longueur du chemin de la prise de l'agent (CT-4 EX-7.28 ; CT-2 EX-6.10 ; complément du 2026-11-16)", function () {
  this.timeout(120000);
  let dir;
  before(function () {
    dir = creerRepertoireTemporaire("noortrace-prises-in-");
  });

  it("la borne est celle du SDK, du démon et du service : 103 octets", function () {
    expect(Client.CHEMIN_PRISE_MAX_OCTETS).to.equal(103);
  });

  it("configuration de l'agent : prise refusée à 104 octets (chemin_prise_trop_long), admise à 103 ; borne en octets UTF-8", function () {
    expect(() => lireConfiguration(configurationAgent(cheminDe("/run/noortrace", 104)))).to.throw(ErreurConfiguration, /chemin_prise_trop_long : 104 octets, au plus 103/);
    expect(lireConfiguration(configurationAgent(cheminDe("/run/noortrace", 103))).prise).to.equal(cheminDe("/run/noortrace", 103));
    expect(() => lireConfiguration(configurationAgent(`/run/${"é".repeat(49)}/sock`))).to.throw(ErreurConfiguration, /chemin_prise_trop_long : 108 octets/);
  });

  it("configuration de l'interface : prise refusée à 104 octets (chemin_prise_trop_long), admise à 103", function () {
    const f = path.join(dir, "interface.json");
    fs.writeFileSync(f, JSON.stringify(configurationInterface(cheminDe("/run/noortrace", 104), dir)));
    expect(() => lireConfigurationInterface(f)).to.throw(ErreurConfigurationInterface, /chemin_prise_trop_long : 104 octets, au plus 103/);
    fs.writeFileSync(f, JSON.stringify(configurationInterface(cheminDe("/run/noortrace", 103), dir)));
    expect(lireConfigurationInterface(f).prise).to.equal(cheminDe("/run/noortrace", 103));
  });

  it("démarrage de l'agent et de l'interface refusé à 104 octets : code 2, chemin_prise_trop_long sur la sortie d'erreur, aucune prise", function () {
    const prise = cheminDe(dir, 104);
    const fa = path.join(dir, "agent.json");
    fs.writeFileSync(fa, JSON.stringify(configurationAgent(prise)));
    const a = commande(BIN_AGENT, ["--config", fa]);
    expect(a.code, a.erreur).to.equal(2);
    expect(a.sortie).to.equal("");
    expect(a.erreur).to.match(/chemin_prise_trop_long : 104 octets, au plus 103/);
    const fw = path.join(dir, "interface-104.json");
    fs.writeFileSync(fw, JSON.stringify(configurationInterface(prise, dir)));
    const w = commande(BIN_WEB, ["--config", fw]);
    expect(w.code, w.erreur).to.equal(2);
    expect(w.sortie).to.equal("");
    expect(w.erreur).to.match(/chemin_prise_trop_long : 104 octets, au plus 103/);
    expect(fs.existsSync(prise)).to.equal(false);
  });

  it("client de la prise (remettre) : un chemin de plus de 103 octets est refusé avant toute connexion", async function () {
    const prise = cheminDe(dir, 104);
    let connexions = 0;
    const ouvertes = new Set();
    const serveur = net.createServer((s) => {
      connexions += 1;
      ouvertes.add(s);
      s.end(JSON.stringify({ accepte: true, id: "t-1" }) + "\n");
    });
    await new Promise((ok) => serveur.listen(prise, ok));
    let r;
    try {
      r = await remettre(prise, { version: 0, kind: "travail" }, { delaiMs: 2000 }).then((v) => ({ v }), (e) => ({ e }));
    } finally {
      for (const s of ouvertes) s.destroy();
      await new Promise((ok) => serveur.close(ok));
    }
    expect(connexions).to.equal(0);
    expect(r.e, JSON.stringify(r.v)).to.be.instanceOf(ErreurAgent);
    expect(r.e.message).to.match(/chemin_prise_trop_long : 104 octets, au plus 103/);
  });
});

describe("inscription : lignes de commande strictes (complément du 2026-11-16)", function () {
  this.timeout(60000);
  for (const [nom, bin] of [["noortrace-inscription-agent", BIN_AGENT], ["noortrace-inscription-web", BIN_WEB]]) {
    const usage = (r, quoi) => {
      expect(r.code, `${nom} ${quoi} : ${r.sortie}${r.erreur}`).to.equal(2);
      expect(r.erreur, quoi).to.match(/^usage : /);
      expect(r.sortie, quoi).to.equal("");
    };

    it(`${nom} : --config sans valeur (option à la place du fichier) : usage, code 2`, function () {
      usage(commande(bin, ["--config", "--inconnue"]), "--config --inconnue");
    });

    it(`${nom} : déjà refusés : option inconnue, en double, argument en trop, aucun argument (usage, code 2)`, function () {
      usage(commande(bin, ["--config", "/x.json", "--inconnue"]), "option inconnue");
      usage(commande(bin, ["--inconnue", "/x.json"]), "option inconnue seule");
      usage(commande(bin, ["--config", "/x.json", "--config", "/x.json"]), "--config en double");
      usage(commande(bin, ["--config"]), "--config seul");
      usage(commande(bin, ["--config", "/x.json", "/y.json"]), "argument en trop");
      usage(commande(bin, []), "aucun argument");
    });
  }
});
