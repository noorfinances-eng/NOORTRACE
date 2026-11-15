// Composant d'ancrage (paquets/ancrage), CT-5 EX-4.9 règle 4 bis et EX-5.10
// étape 10, arbitrage du 14 novembre : en production, `crl_hosts` absent ou
// nul ne lève pas la règle des adresses : seules les adresses publiques sont
// admises, les adresses locales et privées (RFC 1918, 3927, 4193, 6598) sont
// refusées sans requête ; avec une liste, l'hôte doit en faire partie ; hors
// production, la boucle locale reste admise (serveur de CRL d'essai).
//
// Le composant appliquait déjà cette lecture : l'essai la fixe, et son
// mutant (refus des adresses locales retiré en production) est tué par
// l'oracle. Racine du composant éprouvé : le paquet du dépôt, ou le répertoire
// `src` que nomme NOORTRACE_REVUE_ANCRAGE (copie d'avant ou mutant).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const SRC = process.env.NOORTRACE_REVUE_ANCRAGE ? path.resolve(process.env.NOORTRACE_REVUE_ANCRAGE) : path.join(PROJECT_ROOT, "paquets", "ancrage", "src");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});
const importer = (src) => import(pathToFileURL(path.join(src, "rfc3161", "index.mjs")).href + `?t=${Date.now()}-${Math.random()}`);

/** Copie de paquets/ancrage/src sous NOORTRACE_TMP, `ancien` remplacé par `nouveau` dans `fichier` (chemin relatif à src). */
function mutant(nom, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-crl-hotes-${nom}-`));
  COPIES.push(racine);
  const src = path.join(racine, "src");
  fs.cpSync(SRC, src, { recursive: true });
  fs.symlinkSync(path.join(PROJECT_ROOT, "node_modules"), path.join(racine, "node_modules"));
  const f = path.join(src, fichier);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return src;
}

const PUBLIQUES = ["http://crl.qtsa.example/ca.crl", "https://pki.qtsa.example/inter.crl", "http://198.51.100.7/ca.crl"];
const LOCALES = ["http://127.0.0.1/ca.crl", "http://localhost:8080/ca.crl", "http://[::1]/ca.crl", "http://crl.localhost/ca.crl"];
const PRIVEES = ["http://10.1.2.3/ca.crl", "http://172.16.0.9/ca.crl", "http://192.168.1.1/ca.crl", "http://169.254.0.5/ca.crl", "http://100.64.1.1/ca.crl", "http://[fd00::1]/ca.crl"];

/** Motif du refus (ou null) de chaque adresse, sous la politique du composant pour ce prestataire et ce profil. */
function juger(RFC, prestataire, production, urls) {
  const politique = RFC.politiqueCaptureCrl({ production, prestataire });
  return urls.map((u) => RFC.controlerUrlCrl(u, politique));
}
const oracle = (RFC) => [{ id: "qtsa", crl_hosts: null }, { id: "qtsa" }].every((p) => juger(RFC, p, true, PUBLIQUES).every((m) => m === null) && juger(RFC, p, true, [...LOCALES, ...PRIVEES]).every((m) => typeof m === "string"));

describe("Composant d'ancrage, CT-5 EX-4.9 règle 4 bis (arbitrage du 14 novembre) : crl_hosts absent ou nul en production → adresses publiques seules", function () {
  it("production, crl_hosts nul ou absent : adresses publiques admises ; locales (127/8, localhost, ::1, *.localhost) et privées (RFC 1918, 3927, 4193, 6598) refusées ; avec une liste, un hôte public hors de la liste refusé ; hors production, la boucle locale admise", async function () {
    const RFC = await importer(SRC);
    for (const p of [{ id: "qtsa", crl_hosts: null }, { id: "qtsa" }]) {
      expect(RFC.politiqueCaptureCrl({ production: true, prestataire: p })).to.deep.equal({ production: true, hotesAdmis: null });
      expect(juger(RFC, p, true, PUBLIQUES), JSON.stringify(p)).to.deep.equal(PUBLIQUES.map(() => null));
      for (const [u, m] of [...LOCALES, ...PRIVEES].map((x, i) => [x, juger(RFC, p, true, [...LOCALES, ...PRIVEES])[i]])) expect(m, `${u} (${JSON.stringify(p)})`).to.be.a("string");
    }
    const liste = { id: "qtsa", crl_hosts: ["crl.qtsa.example"] };
    expect(juger(RFC, liste, true, PUBLIQUES)).to.deep.equal([null, "hôte pki.qtsa.example hors de la liste des hôtes de CRL admis", "hôte 198.51.100.7 hors de la liste des hôtes de CRL admis"]);
    expect(juger(RFC, { id: "qtsa", crl_hosts: null }, false, LOCALES)).to.deep.equal(LOCALES.map(() => null));
    expect(oracle(RFC)).to.equal(true);
  });

  it("mutant : refus des adresses locales en production retiré (tué par l'oracle)", async function () {
    const RFC = await importer(mutant("locales", path.join("rfc3161", "transport.mjs"), '  if (classe === "locale" && production) return', '  if (false) return'));
    expect(oracle(RFC)).to.equal(false);
  });

  it("mutant : refus des adresses privées retiré (tué par l'oracle)", async function () {
    const RFC = await importer(mutant("privees", path.join("rfc3161", "transport.mjs"), '  if (classe === "privee") return', '  if (false) return'));
    expect(oracle(RFC)).to.equal(false);
  });
});
