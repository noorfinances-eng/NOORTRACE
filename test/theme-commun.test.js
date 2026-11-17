// Thème commun des écrans NOORTRACE (complément du 2026-11-17, décision du
// porteur : présentation des écrans) : le bloc de jetons et de composants
// placé entre les repères « noor-theme:debut » et « noor-theme:fin » est
// identique à l'octet dans les trois feuilles de style du dépôt : la console
// d'approbation, la page de vérification et l'outil d'inscription. Hors du
// bloc, aucune feuille ne redéfinit un jeton du thème. Le bloc tient sous les
// politiques de contenu des trois paquets : aucune adresse, aucune police
// téléchargée, aucun `!important` hors de l'impression.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DEBUT = "/* noor-theme:debut */";
const FIN = "/* noor-theme:fin */";

/** Les trois feuilles de style qui portent le thème. */
const FEUILLES = Object.freeze({
  "console d'approbation": "paquets/console/src/pages/statique/console.css",
  "page de vérification": "paquets/verification-web/src/page/page.css",
  "outil d'inscription": "paquets/inscription/src/web/app/globals.css",
});

const sha256 = (o) => createHash("sha256").update(o).digest("hex");

/** Les octets du bloc d'une feuille, repères compris ; lève une erreur lisible si un repère manque ou se répète. */
function bloc(fichier) {
  const octets = fs.readFileSync(path.join(RACINE, fichier));
  const texte = octets.toString("latin1");
  const debuts = texte.split(DEBUT).length - 1;
  const fins = texte.split(FIN).length - 1;
  if (debuts !== 1 || fins !== 1) throw new Error(`${fichier} : ${debuts} repère(s) de début et ${fins} repère(s) de fin, un de chaque attendu`);
  const a = texte.indexOf(DEBUT);
  const b = texte.indexOf(FIN) + FIN.length;
  if (b <= a) throw new Error(`${fichier} : le repère de fin précède le repère de début`);
  return { bloc: octets.subarray(a, b), avant: octets.subarray(0, a).toString("utf8"), apres: octets.subarray(b).toString("utf8") };
}

describe("thème commun des écrans : un même bloc, à l'octet, dans les trois feuilles de style", () => {
  it("chaque feuille porte une fois chaque repère, dans l'ordre, et un bloc non vide", () => {
    for (const [nom, fichier] of Object.entries(FEUILLES)) {
      expect(fs.existsSync(path.join(RACINE, fichier)), `${nom} : ${fichier}`).to.equal(true);
      const b = bloc(fichier);
      expect(b.bloc.length, nom).to.be.greaterThan(10000);
    }
  });

  it("le bloc est identique à l'octet dans les trois feuilles", () => {
    const empreintes = Object.fromEntries(Object.entries(FEUILLES).map(([nom, fichier]) => [nom, sha256(bloc(fichier).bloc)]));
    const reference = empreintes["console d'approbation"];
    for (const [nom, e] of Object.entries(empreintes)) expect(e, `${nom} : bloc différent de celui de la console d'approbation`).to.equal(reference);
    const octets = Object.values(FEUILLES).map((f) => bloc(f).bloc);
    for (const o of octets) expect(o.equals(octets[0])).to.equal(true);
  });

  it("hors du bloc, aucune feuille ne redéfinit un jeton du thème ni ne porte un troisième état", () => {
    for (const [nom, fichier] of Object.entries(FEUILLES)) {
      const b = bloc(fichier);
      const dehors = (b.avant + b.apres).replace(/\/\*[\s\S]*?\*\//g, "");
      expect(dehors.match(/--nt-[a-z0-9-]+\s*:/g) ?? [], `${nom} : jeton redéfini hors du bloc`).to.deep.equal([]);
      const etats = [...new Set([...dehors.matchAll(/data-theme=["']?([A-Za-z0-9_-]+)/g)].map((x) => x[1]))];
      expect(etats.filter((e) => e !== "clair"), `${nom} : état de thème autre que « clair » hors du bloc`).to.deep.equal([]);
    }
  });

  it("le bloc tient sous les politiques de contenu : aucune adresse, aucune police téléchargée, aucun !important hors de l'impression ; deux états et l'impression en clair", () => {
    const texte = bloc(FEUILLES["console d'approbation"]).bloc.toString("utf8");
    expect(texte).to.not.match(/url\(|@import|@font-face|https?:|expression\(/i);
    const impression = texte.indexOf("@media print");
    expect(impression).to.be.greaterThan(0);
    expect(texte.slice(0, impression)).to.not.contain("!important");
    // Deux états : le sombre sans attribut, le clair par data-theme="clair" ; aucun autre.
    expect(texte).to.match(/:root\s*\{\s*color-scheme: dark;/);
    expect(texte).to.match(/html\[data-theme="clair"\]\s*\{\s*color-scheme: light;/);
    expect([...new Set([...texte.matchAll(/data-theme="([a-z]+)"/g)].map((x) => x[1]))]).to.deep.equal(["clair"]);
    expect(texte.slice(impression)).to.match(/color-scheme: light;/);
    // Toute classe du bloc commence par « nt- ».
    const classes = [...texte.replace(/\/\*[\s\S]*?\*\//g, "").matchAll(/\.([a-zA-Z_][a-zA-Z0-9_-]*)/g)].map((x) => x[1]).filter((c) => !/^\d/.test(c));
    expect(classes.length).to.be.greaterThan(100);
    expect([...new Set(classes.filter((c) => !c.startsWith("nt-")))]).to.deep.equal([]);
  });
});
