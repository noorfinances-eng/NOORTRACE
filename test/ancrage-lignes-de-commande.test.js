// Lignes de commande de `noortrace-ancrage` et de `noortrace-tsa-interne`
// (CT-5 EX-8.13, §7 ; complément du 2026-11-16).
//
// Les deux programmes lisaient leurs options sans les connaître : une option
// mal écrite était ignorée (`servir --prot 2020` écoutait sur un port tiré au
// hasard, `serie --cle cles.json` admettait les points sans vérifier leur
// signature), une option donnée deux fois prenait la dernière valeur, une
// option à valeur laissée sans valeur prenait une valeur par défaut
// (`--hote` seul : 127.0.0.1 ; `--checkpoint-interval` seul : 1 s). Chaque
// commande n'admet désormais que ses options, chacune au plus une fois, avec
// sa valeur quand elle en prend une, et ses arguments ; sinon l'usage et le
// code 2, sans rien écrire ni écouter. Aucun des deux programmes n'ouvre ni
// ne joint de prise Unix (TCP seulement) : la borne de longueur des chemins
// de prise n'a pas d'objet ici.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { RACINE, CT1, CT5 } from "./fixtures/ancrage-composant/outils.mjs";
import { creerRepertoireTemporaire } from "./aides/temporaires.mjs";

const BIN = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage");
const BIN_TSA = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-tsa-interne");

/** Lance un programme ; un programme qui écoute encore au délai est arrêté (code null ou 0, jamais 2). */
function lancer(bin, args, delaiMs = 8000) {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: "utf8", timeout: delaiMs, killSignal: "SIGKILL" });
  return { code: r.status, sortie: r.stdout ?? "", erreur: r.stderr ?? "" };
}

/** Bloc ```json qui suit un marqueur. */
function blocApres(texte, marqueur) {
  const lignes = texte.split("\n");
  let i = lignes.findIndex((l) => l.includes(marqueur));
  while (!lignes[i].startsWith("```")) i++;
  let fin = i + 1;
  while (lignes[fin] !== "```") fin++;
  return lignes.slice(i + 1, fin).join("\n");
}

const usage = (r, quoi) => {
  expect(r.code, `${quoi} : ${r.sortie}${r.erreur}`).to.equal(2);
  expect(r.erreur, quoi).to.match(/^usage : /);
};

describe("noortrace-ancrage : ligne de commande stricte (CT-5 EX-8.13 ; complément du 2026-11-16)", function () {
  this.timeout(120000);
  let dir;
  let exemple;
  let trace;
  let completude;
  let acquisitions;
  before(function () {
    dir = creerRepertoireTemporaire("noortrace-ancrage-lignes-");
    exemple = path.join(dir, "ancrage-v0.json");
    fs.writeFileSync(exemple, blocApres(fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8"), "<!-- schema: ancrage -->"));
    trace = path.join(CT5, "planification", "heure-nominale-reference.json");
    completude = path.join(CT5, "completude", "completude.json");
    acquisitions = path.join(dir, "acquisitions.ndjson");
    fs.writeFileSync(acquisitions, "");
  });

  it("formes admises inchangées (code 0), drapeau suivi d'un argument compris", function () {
    for (const args of [
      ["configuration", exemple, "--profil", "developpement"],
      ["configuration", exemple, "--json", "--profil", "production", "--checkpoint-interval", "60"],
      ["trace", trace, "--json"],
      ["trace", "--json", trace],
      ["cout", "--role", "interne", "--activite", "1", "--countersign-idle", "--json"],
      ["completude", completude, "--json"],
      ["acquisitions", acquisitions],
      ["aide"],
      ["--aide"],
    ]) {
      const r = lancer(BIN, args);
      expect(r.code, `${args.join(" ")} : ${r.erreur}`).to.equal(0);
    }
  });

  it("option inconnue : usage, code 2, pour chaque commande", function () {
    usage(lancer(BIN, ["configuration", exemple, "--profil", "developpement", "--inconnue"]), "configuration --inconnue");
    usage(lancer(BIN, ["trace", trace, "--jsn"]), "trace --jsn");
    usage(lancer(BIN, ["cout", "--rol", "interne"]), "cout --rol");
    usage(lancer(BIN, ["completude", completude, "--profil", "developpement"]), "completude --profil");
    usage(lancer(BIN, ["acquisitions", acquisitions, "--sortie", path.join(dir, "x")]), "acquisitions --sortie");
    usage(lancer(BIN, ["serie", "--configuration", exemple, "--periode", "1793869200", "--points", path.join(CT1, "points-de-controle", "periode-1.json"), "--cle", path.join(CT1, "cles", "cles.json")]), "serie --cle (pour --cles)");
    usage(lancer(BIN, ["fiche", "--configuration", exemple, "--ident", "tsa-interne"]), "fiche --ident");
  });

  it("option en double, option sans sa valeur, argument en trop : usage, code 2, rien n'est écrit", function () {
    usage(lancer(BIN, ["configuration", exemple, "--profil", "developpement", "--profil", "production"]), "--profil en double");
    usage(lancer(BIN, ["completude", completude, "--json", "--json"]), "--json en double");
    usage(lancer(BIN, ["configuration", exemple, "--profil", "developpement", "--checkpoint-interval"]), "--checkpoint-interval sans valeur");
    usage(lancer(BIN, ["cout", "--role", "interne", "--activite"]), "--activite sans valeur");
    usage(lancer(BIN, ["cout", "--activite", "--json"]), "--activite suivie d'une option");
    const sortie = path.join(dir, "fiche.json");
    usage(lancer(BIN, ["fiche", "--configuration", exemple, "--id", "tsa-interne", "--sortie"]), "--sortie sans valeur");
    expect(fs.existsSync(sortie)).to.equal(false);
    usage(lancer(BIN, ["configuration", exemple, exemple, "--profil", "developpement"]), "configuration f f");
    usage(lancer(BIN, ["acquisitions", acquisitions, acquisitions]), "acquisitions f f");
    usage(lancer(BIN, ["cout", "en-trop"]), "cout en-trop");
    usage(lancer(BIN, ["trace", trace, "--json", "oui"]), "drapeau avec une valeur");
  });

  it("fiche : --prestataire avec --configuration ou --id (l'une des deux formes ignorée) : usage, code 2", function () {
    usage(lancer(BIN, ["fiche", "--prestataire", path.join(dir, "prestataire-absent.json"), "--configuration", exemple, "--id", "tsa-interne"]), "deux formes");
    usage(lancer(BIN, ["fiche", "--prestataire", path.join(dir, "prestataire-absent.json"), "--id", "tsa-interne"]), "--prestataire --id");
  });

  it("déjà refusés : --profil sans valeur, commande inconnue, aucune commande (usage, code 2)", function () {
    usage(lancer(BIN, ["configuration", exemple, "--profil"]), "--profil sans valeur");
    usage(lancer(BIN, ["inconnue"]), "commande inconnue");
    expect(lancer(BIN, []).code).to.equal(2);
  });
});

describe("noortrace-tsa-interne : ligne de commande stricte (CT-5 §7 ; complément du 2026-11-16)", function () {
  this.timeout(180000);
  let dir;
  before(function () {
    dir = path.join(creerRepertoireTemporaire("noortrace-tsa-lignes-"), "ac");
    const r = lancer(BIN_TSA, ["init", "--repertoire", dir, "--algorithme", "p-256", "--politique", "1.3.6.1.4.1.99999.3.1", "--crl-url", "http://127.0.0.1:8080/crl.pem"], 60000);
    expect(r.code, r.erreur).to.equal(0);
  });

  it("servir : option mal écrite (--prot), en double (--port), sans valeur (--hote) : usage, code 2, sans écouter", function () {
    for (const [quoi, args] of [
      ["--prot", ["servir", "--repertoire", dir, "--prot", "2020"]],
      ["--port en double", ["servir", "--repertoire", dir, "--port", "0", "--port", "0"]],
      ["--hote sans valeur", ["servir", "--repertoire", dir, "--port", "0", "--hote"]],
      ["--tls-ac-client (pour --tls-ac-clients)", ["servir", "--repertoire", dir, "--port", "0", "--tls-ac-client", path.join(dir, "ac.pem")]],
      ["argument en trop", ["servir", "--repertoire", dir, "--port", "0", "en-trop"]],
    ]) {
      const r = lancer(BIN_TSA, args);
      usage(r, quoi);
      expect(r.sortie, quoi).to.not.match(/^http/m);
    }
  });

  it("servir : les deux formes mêlées (--repertoire avec --cle, --inclure-ac avec --cle) : usage, code 2, sans écouter", function () {
    for (const [quoi, args] of [
      ["--repertoire --cle", ["servir", "--repertoire", dir, "--port", "0", "--cle", path.join(dir, "unite.cle.pem")]],
      ["--repertoire --chaine", ["servir", "--repertoire", dir, "--port", "0", "--chaine", path.join(dir, "ac.pem")]],
      ["--cle --inclure-ac", ["servir", "--cle", path.join(dir, "unite.cle.pem"), "--certificat", path.join(dir, "unite.pem"), "--politique", "1.3.6.1.4.1.99999.3.1", "--compteur", path.join(path.dirname(dir), "compteur"), "--port", "0", "--inclure-ac"]],
    ]) {
      const r = lancer(BIN_TSA, args);
      usage(r, quoi);
      expect(r.sortie, quoi).to.not.match(/^http/m);
    }
  });

  it("init, crl, ac, sonde : option inconnue, en double ou sans valeur : usage, code 2, rien n'est écrit", function () {
    const neuf = path.join(path.dirname(dir), "neuf");
    usage(lancer(BIN_TSA, ["init", "--repertoire", neuf, "--politique", "1.2.3", "--crl-url", "http://127.0.0.1/crl", "--algo", "p-256"]), "init --algo");
    expect(fs.existsSync(neuf)).to.equal(false);
    const crl = fs.readFileSync(path.join(dir, "crl.pem"));
    usage(lancer(BIN_TSA, ["crl", "--repertoire", dir, "--validite-crl-jour", "3"]), "crl --validite-crl-jour");
    usage(lancer(BIN_TSA, ["crl", "--repertoire", dir, "--validite-crl-jours"]), "crl --validite-crl-jours sans valeur");
    expect(fs.readFileSync(path.join(dir, "crl.pem")).equals(crl)).to.equal(true);
    usage(lancer(BIN_TSA, ["ac", "--repertoire", dir, "--crl", "--crl"]), "ac --crl en double");
    usage(lancer(BIN_TSA, ["ac", "--repertoire", dir, "--cle"]), "ac --cle");
    usage(lancer(BIN_TSA, ["sonde", "--url", "http://127.0.0.1:1/sante", "--delai", "1"]), "sonde --delai");
  });

  it("formes admises inchangées : ac, ac --crl, aide (code 0) ; déjà refusés : init sans --politique, aucune commande (code 2)", function () {
    expect(lancer(BIN_TSA, ["ac", "--repertoire", dir]).sortie).to.match(/^-----BEGIN CERTIFICATE-----/);
    expect(lancer(BIN_TSA, ["ac", "--repertoire", dir, "--crl"]).sortie).to.match(/^-----BEGIN X509 CRL-----/);
    expect(lancer(BIN_TSA, ["aide"]).code).to.equal(0);
    usage(lancer(BIN_TSA, ["init", "--repertoire", path.join(dir, "x")]), "init sans --politique");
    expect(lancer(BIN_TSA, []).code).to.equal(2);
  });
});
