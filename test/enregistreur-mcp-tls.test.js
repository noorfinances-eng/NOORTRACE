// Frontal MCP : prise TCP des connecteurs (`mcp.connector_tcp`) en TLS et en
// mTLS (CT-2 EX-4.39, table de 15.1 ligne `mcp` : « prise TCP des connecteurs
// (`connector_tcp`, jeton ou mTLS) » ; LISEZMOI, lectures 134 et 135). Banc :
// cœur réel, frontal réel, serveur d'outils stdio réel lancé par le frontal,
// connecteur réel `bin/noortrace-connecteur` lancé comme par un hôte, qui
// joint la prise TCP ; autorité et certificats générés à l'exécution par
// `openssl` (aucune clé dans le dépôt). Écrit d'après le seul texte de CT-2.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";
import * as N from "@noortrace/noyau";
import {
  Coeur, FrontalMcp, ServeurConnecteurs, validerConfiguration, controleConnecteurTcp, lireEvenements,
} from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { RACINE, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationMcp, hoteDemo, serveurStdio, RedacteurTest } from "./fixtures/enregistreur-mcp/outils.mjs";
import { ClientHote, metaModerne } from "./fixtures/enregistreur-mcp/client-hote.mjs";
import { autoriteDeTest } from "./fixtures/enregistreur-sdk/outils.mjs";

const SERVEUR = path.join(RACINE, "test", "fixtures", "enregistreur-mcp", "serveur-outils.mjs");
const octets = (c) => new TextEncoder().encode(JSON.stringify(c));

describe("enregistreur, frontal MCP : prise TCP des connecteurs en TLS et en mTLS (EX-4.39, lectures 134 et 135)", function () {
  this.timeout(120000);
  let dir;
  let pki;
  let config;
  let coeur;
  let frontal;
  const serveurs = [];
  const clients = [];

  /** Connecteur réel, prise TCP, environnement TLS donné. */
  const connecteur = (port, env) => {
    const c = new ClientHote(["--tcp", `127.0.0.1:${port}`], { ...process.env, ...env });
    clients.push(c);
    return c;
  };
  const tlsEnv = (certificat) => ({ NOORTRACE_CONNECTEUR_TLS_CA: pki.ca, NOORTRACE_CONNECTEUR_TLS_CERT: certificat.cert, NOORTRACE_CONNECTEUR_TLS_KEY: certificat.key });
  const refus = () => coeur.journal.trouver("auth_failed").map((l) => l.data.reason);
  const attendreRefus = async (n) => {
    for (let k = 0; k < 200 && refus().length < n; k++) await new Promise((r) => setTimeout(r, 10));
  };
  const ecouter = async (tcp, jetons = new Map()) => {
    const s = new ServeurConnecteurs({ frontal, tcp, jetons });
    await s.ecouter();
    serveurs.push(s);
    return s.adresseTcp().port;
  };

  before(async function () {
    dir = repertoireTemporaire("noortrace-mcp-tls-");
    pki = autoriteDeTest(path.join(dir, "pki"));
    const hotes = [
      { ...hoteDemo({ id: "agent-a", match: { peer_user: "agent-a" }, launched_by: "${peer_user}" }), host_group: "groupe-a" },
      { ...hoteDemo({ id: "agent-b", match: { peer_user: "agent-b" }, launched_by: "${peer_user}" }), host_group: "groupe-b" },
      { ...hoteDemo({ id: "poste", match: { static_token: "poste" }, launched_by: "poste-tls" }), host_group: "poste" },
    ];
    const r = configurationMcp(dir, {
      servers: { demo: serveurStdio([process.execPath, SERVEUR], { protocol: "auto" }) },
      hosts: hotes,
      socket: path.join(dir, "prise", "mcp.sock"),
      http: { listen: "127.0.0.1:0", path: "/mcp", allowed_origins: [], tls: null, oauth: null, static_tokens: [{ id: "poste", token: { env: "NOORTRACE_TEST_JETON_POSTE" } }] },
      journal_id: N.octetsVersHex(N.keccak256(N.utf8("journal-mcp-tls"))),
    });
    config = r.config;
    config.model.hosts = [];
    config.mcp.connector_tcp = { listen: "127.0.0.1:0", client_auth: "mtls", tls: { cert_file: pki.serveur.cert_file, key_file: pki.serveur.key_file } };
    const v = validerConfiguration(octets(config), { reglesSupplementaires: [controleConnecteurTcp] });
    expect(v.erreurs, JSON.stringify(v.erreurs)).to.deep.equal([]);
    Object.assign(process.env, r.env);
    coeur = await Coeur.demarrer({ config: v.config, secrets: secretsDev(), service: new ServiceApprobationFactice({ org_id: v.config.recorder.org_id, journal_id: v.config.recorder.journal_id }) });
    frontal = new FrontalMcp({ coeur, redacteur: new RedacteurTest() });
    await frontal.demarrer();
  });

  after(async function () {
    for (const c of clients) c.p.kill("SIGKILL");
    for (const s of serveurs) await s.fermer();
    await frontal?.arreter();
    await coeur?.arreter();
  });

  it("mTLS : le connecteur réel présente son certificat, rattaché à la connexion d'hôte de son nom commun ; un appel d'outil traverse et produit un événement", async function () {
    const port = await ecouter(config.mcp.connector_tcp);
    const a = connecteur(port, tlsEnv(pki.client("agent-b")));
    const liste = await a.requete("tools/list", { _meta: metaModerne() });
    expect(liste.result.tools.map((t) => t.name)).to.include("demo__claims.get");
    const r = await a.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "2026-81044" }, _meta: metaModerne() });
    expect(r.result.isError).to.equal(false);
    expect(await a.fermer()).to.equal(0);
    const e = (await lireEvenements(coeur.repertoire)).at(-1);
    expect(e.execution.tool).to.equal("demo__claims.get");
    expect(e.execution.status).to.equal("executee");
    // Rattaché à agent-b (launched_by = ${peer_user} = CN), pas à agent-a.
    expect(e.delegation.launched_by).to.equal("agent-b");
    expect(coeur.journal.trouver("host_connected").map((l) => l.host)).to.deep.equal(["agent-b"]);
  });

  it("mTLS : autorité étrangère, certificat expiré, sans certificat, certificat sans entrée de mcp.hosts : refusés (auth_failed), aucune connexion d'hôte", async function () {
    const port = await ecouter(config.mcp.connector_tcp);
    const avant = refus().length;
    const connectes = coeur.journal.trouver("host_connected").length;
    const codes = [];
    for (const env of [tlsEnv(pki.etranger("agent-a")), tlsEnv(pki.expire("agent-a")), tlsEnv(pki.client("agent-inconnu"))]) {
      const c = connecteur(port, env);
      codes.push(await c.fin);
    }
    // Sans certificat : le connecteur réel en TLS avec un jeton, sur une prise mTLS.
    const sans = connecteur(port, { NOORTRACE_CONNECTEUR_TLS_CA: pki.ca, NOORTRACE_CONNECTEUR_JETON: "sans-objet" });
    codes.push(await sans.fin);
    expect(codes).to.deep.equal([1, 1, 1, 1]);
    await attendreRefus(avant + 4);
    expect(refus().slice(avant)).to.have.members(["certificat:UNABLE_TO_VERIFY_LEAF_SIGNATURE", "certificat:CERT_HAS_EXPIRED", "hote_inconnu", "certificat:absent"]);
    expect(coeur.journal.trouver("auth_failed").slice(avant).every((l) => l.data.tls === true && l.data.transport === "stdio")).to.equal(true);
    expect(coeur.journal.trouver("host_connected").length).to.equal(connectes);
    // Une poignée de main sans certificat, client brut : aucune identité acceptée.
    const recu = await new Promise((r) => {
      const c = tls.connect({ host: "127.0.0.1", port, ca: fs.readFileSync(pki.ca) });
      let x = "";
      c.on("data", (d) => (x += d));
      c.on("error", () => {});
      c.on("close", () => r(x));
    });
    expect(recu).to.not.contain("acceptee");
  });

  it("jeton sur TLS (client_auth jeton, tls posé) : le connecteur réel vérifie le démon et envoie son jeton ; jeton faux refusé", async function () {
    const port = await ecouter({ listen: "127.0.0.1:0", client_auth: "jeton", tls: { cert_file: pki.serveur.cert_file, key_file: pki.serveur.key_file } }, new Map([["poste", N.utf8("jeton-poste-tls")]]));
    const a = connecteur(port, { NOORTRACE_CONNECTEUR_TLS_CA: pki.ca, NOORTRACE_CONNECTEUR_JETON: "jeton-poste-tls" });
    const r = await a.requete("tools/call", { name: "demo__claims.get", arguments: { claim_id: "2026-81045" }, _meta: metaModerne() });
    expect(r.result.isError).to.equal(false);
    expect(await a.fermer()).to.equal(0);
    expect((await lireEvenements(coeur.repertoire)).at(-1).delegation.launched_by).to.equal("poste-tls");
    const avant = refus().length;
    const faux = connecteur(port, { NOORTRACE_CONNECTEUR_TLS_CA: pki.ca, NOORTRACE_CONNECTEUR_JETON: "faux" });
    expect(await faux.fin).to.equal(1);
    await attendreRefus(avant + 1);
    expect(refus().slice(avant)).to.deep.equal(["jeton"]);
    expect(JSON.stringify(coeur.journal.lignes)).to.not.contain("jeton-poste-tls");
  });

  it("configuration : client_auth mtls sans tls refusé par la validation (pas 3 d'EX-15.4) et au démarrage de la prise ; chaîne sans autorité refusée au démarrage", async function () {
    const c = structuredClone(config);
    c.mcp.connector_tcp.tls = null;
    expect(validerConfiguration(octets(c), { reglesSupplementaires: [controleConnecteurTcp] }).erreurs.map((e) => e.pointeur)).to.deep.equal(["/mcp/connector_tcp/tls"]);
    for (const [tcp, attendu] of [
      [c.mcp.connector_tcp, "client_auth mtls exige mcp.connector_tcp.tls"],
      [{ ...config.mcp.connector_tcp, tls: { cert_file: pki.serveur.seul, key_file: pki.serveur.key_file } }, "autorité des certificats clients"],
    ]) {
      let erreur = null;
      try {
        await new ServeurConnecteurs({ frontal, tcp }).ecouter();
      } catch (e) {
        erreur = e;
      }
      expect(String(erreur?.message)).to.contain(attendu);
    }
  });

  it("connecteur : certificat sans clé, ou prise TCP sans jeton ni certificat, refusés à la ligne de commande (code 2)", async function () {
    const p = pki.client("agent-a", "client-seul");
    const sansCle = connecteur(1, { NOORTRACE_CONNECTEUR_TLS_CA: pki.ca, NOORTRACE_CONNECTEUR_TLS_CERT: p.cert });
    expect(await sansCle.fin).to.equal(2);
    expect(sansCle.stderr).to.contain("mTLS exige");
    const env = { ...process.env };
    delete env.NOORTRACE_CONNECTEUR_JETON;
    const rien = new ClientHote(["--tcp", "127.0.0.1:1"], env);
    clients.push(rien);
    expect(await rien.fin).to.equal(2);
    expect(rien.stderr).to.contain("jeton ou mTLS");
  });
});
