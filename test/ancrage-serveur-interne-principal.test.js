// Serveur RFC 3161 interne comme prestataire principal hors production
// (CT-5 révision 0.9, EX-4.9 règle 4, EX-5.5, EX-7.1) : AN-1 l'admet en
// profil de développement et de test (`qualified: null`, `http://` vers une
// adresse locale sans authentification, ou `https://` avec authentification),
// le refuse en production avec sa raison ; le transport ne l'admet en
// `http://` que sur désignation du composant ; un jeton réel est obtenu du
// serveur interne de `paquets/ancrage` et vérifié à l'acquisition (T-1 à T-9
// contre l'AC du serveur, EX-5.10). Aucun réseau public : le serveur écoute
// sur 127.0.0.1, port choisi par le système.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { validerConfiguration, commeServeurInterne } from "@noortrace/ancrage/planificateur";
import { acquerir, controlerUrl, transportHttps, ErreurTransport } from "@noortrace/ancrage/rfc3161";
import { initialiserAutorite, chargerAutorite, demarrerServeur, FICHIERS_AUTORITE } from "@noortrace/ancrage/serveur-interne";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BIN_ANCRAGE = path.join(RACINE, "paquets", "ancrage", "bin", "noortrace-ancrage");
const POLITIQUE = "1.3.6.1.4.1.99999.1.1";
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();

/** Document ancrage-v0 de l'installation rapide (deploiement/config/rapide/ancrage.json), seul prestataire : le serveur interne en principal. */
const documentRapide = () => JSON.parse(fs.readFileSync(path.join(RACINE, "deploiement", "config", "rapide", "ancrage.json"), "utf8"));
const regles = (r) => [...new Set(r.erreurs.map((e) => e.regle))].sort();

describe("ancrage : serveur RFC 3161 interne comme prestataire principal hors production (CT-5 révision 0.9, EX-4.9 règle 4)", function () {
  this.timeout(60000);
  let dir;
  before(() => {
    dir = fs.mkdtempSync(path.join(TMP, "noortrace-principal-interne-"));
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("AN-1 hors production : le principal non qualifié en http:// local sans authentification (serveur interne) est admis en développement et en test, par le module et par noortrace-ancrage configuration (code 0) ; en https:// avec authentification aussi", function () {
    const d = documentRapide();
    const p = d.rfc3161.providers[0];
    expect(p).to.include({ role: "principal", url: "http://127.0.0.1:2020/", qualified: null });
    expect(p.auth).to.deep.equal({ method: "aucune", secret: null });
    expect(commeServeurInterne(p, false)).to.equal(true);
    expect(commeServeurInterne(p, true)).to.equal(false);
    for (const profil of ["developpement", "test"]) {
      const v = validerConfiguration(d, { profil, checkpointIntervalEnregistreur: 60 });
      expect(v.valide, `${profil} : ${JSON.stringify(v.erreurs)}`).to.equal(true);
    }
    const fichier = path.join(dir, "ancrage-rapide.json");
    fs.writeFileSync(fichier, JSON.stringify(d));
    const r = spawnSync(process.execPath, [BIN_ANCRAGE, "configuration", fichier, "--profil", "developpement", "--checkpoint-interval", "60"], { encoding: "utf8" });
    expect(r.status, r.stdout + r.stderr).to.equal(0);
    expect(r.stdout).to.match(/^configuration valide \(AN-1, profil developpement\) : 1 prestataire\(s\)/);
    const tls = structuredClone(d);
    tls.rfc3161.providers[0].url = "https://horodatage-interne.example/tsa";
    tls.rfc3161.providers[0].auth = { method: "certificat_client", secret: { file: "/run/secrets/tsa-interne" } };
    expect(validerConfiguration(tls, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).valide).to.equal(true);
  });

  it("AN-1 refuse le serveur interne comme principal en production, avec sa raison (règle 4 : principal non qualifié, http:// et auth aucune admis hors production seulement), par le module et par l'outil (code 1) ; hors production, un http:// non local, un principal qualifié en http:// local ou un second_rang en http:// local restent refusés", function () {
    const d = documentRapide();
    const prod = validerConfiguration(d, { profil: "production", checkpointIntervalEnregistreur: 60 });
    expect(prod.valide).to.equal(false);
    expect(regles(prod)).to.deep.equal(["4"]);
    const messages = prod.erreurs.map((e) => e.message);
    expect(messages).to.include("principal tsa-interne sans qualified : refusé en production");
    expect(messages.filter((m) => /n'est admis comme principal que hors production \(EX-4\.9, règle 4\)/.test(m))).to.have.lengthOf(2);
    const fichier = path.join(dir, "ancrage-production.json");
    fs.writeFileSync(fichier, JSON.stringify(d));
    const r = spawnSync(process.execPath, [BIN_ANCRAGE, "configuration", fichier, "--profil", "production", "--checkpoint-interval", "60"], { encoding: "utf8" });
    expect(r.status).to.equal(1);
    expect(r.stdout + r.stderr).to.include("n'est admis comme principal que hors production");
    const nonLocal = structuredClone(d);
    nonLocal.rfc3161.providers[0].url = "http://192.0.2.10:2020/";
    expect(validerConfiguration(nonLocal, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).erreurs.map((e) => e.message).join(" ")).to.match(/adresse locale.*EX-5\.5/);
    const qualifie = structuredClone(d);
    const exemple = JSON.parse(/<!-- schema: ancrage -->\n```json\n([\s\S]*?)\n```/.exec(fs.readFileSync(path.join(RACINE, "spec", "CT-5-ancrage.md"), "utf8"))[1]);
    qualifie.rfc3161.providers[0].qualified = exemple.rfc3161.providers[0].qualified;
    expect(regles(validerConfiguration(qualifie, { profil: "developpement", checkpointIntervalEnregistreur: 60 }))).to.deep.equal(["4"]);
    const secondRang = structuredClone(d);
    secondRang.rfc3161.providers.push({ ...structuredClone(d.rfc3161.providers[0]), id: "second", role: "second_rang", url: "http://127.0.0.1:2021/" });
    expect(regles(validerConfiguration(secondRang, { profil: "developpement", checkpointIntervalEnregistreur: 60 }))).to.deep.equal(["4"]);
  });

  it("nominal : jeton réel du serveur interne de paquets/ancrage (init p-256, servir sur 127.0.0.1), obtenu par le principal désigné serveur interne et vérifié à l'acquisition contre l'AC (EX-5.10, outcome obtenue, qualified null) ; sans la désignation, le transport refuse l'url http:// du principal", async function () {
    const rep = path.join(dir, "tsa");
    const horloge = { murale: () => Date.now(), monotone: () => performance.now() };
    const aleatoire = (n) => new Uint8Array(crypto.randomBytes(n));
    initialiserAutorite({ repertoire: rep, algorithme: "p-256", politique: POLITIQUE, crlUrl: "http://127.0.0.1:2020/crl.pem", horloge, aleatoire });
    const autorite = chargerAutorite({ repertoire: rep });
    const serveur = await demarrerServeur({ autorite, ecoute: { hote: "127.0.0.1", port: 0 }, horloge });
    try {
      const p = documentRapide().rfc3161.providers[0];
      p.url = serveur.adresse.url;
      p.anchor_certificates = [fs.readFileSync(path.join(rep, FICHIERS_AUTORITE.ac), "utf8")];
      expect(() => controlerUrl(p.url, "principal")).to.throw(ErreurTransport).with.property("code", "url");
      const imprint = `0x${crypto.randomBytes(32).toString("hex")}`;
      let refus = null;
      try {
        await acquerir({ prestataire: p, imprint, objet: "manifeste", attempt: 1, horloge, aleatoire, transport: transportHttps() });
      } catch (e) {
        refus = e;
      }
      expect(refus).to.be.instanceOf(ErreurTransport);
      const r = await acquerir({ prestataire: { ...p, serveur_interne: true }, imprint, objet: "manifeste", attempt: 1, horloge, aleatoire, transport: transportHttps() });
      expect(r.enregistrement, JSON.stringify(r.enregistrement)).to.include({ outcome: "obtenue", provider_role: "principal", qualified: null, pki_status: 0, policy: POLITIQUE, error_code: null });
      expect(r.enregistrement.token_size).to.be.above(300);
      expect(r.enregistrement.serial_number).to.be.a("string");
    } finally {
      await serveur.fermer();
      autorite.fermer();
    }
  });
});
