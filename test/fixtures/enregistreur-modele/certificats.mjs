// Certificats générés à l'exécution pour les tests TLS du frontal modèle
// (passerelle `model.tls`, ICAPS `model.icap.tls_listen` et `client_ca`) :
// une autorité de test, un certificat serveur pour 127.0.0.1, un certificat
// client signé par l'autorité, et une seconde autorité étrangère avec son
// propre certificat client. Clés jetables, sans valeur ; `openssl` requis.

import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

/** `openssl` est-il disponible ? */
export function opensslDisponible() {
  return spawnSync("openssl", ["version"], { encoding: "utf8" }).status === 0;
}

function ossl(args, cwd) {
  execFileSync("openssl", args, { cwd, stdio: "pipe" });
}

function autorite(dir, nom) {
  ossl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `${nom}.key`, "-out", `${nom}.pem`, "-days", "2", "-subj", `/CN=${nom}`], dir);
}

function signe(dir, nom, ca, extensions) {
  fs.writeFileSync(path.join(dir, `${nom}.ext`), extensions);
  ossl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", `${nom}.key`, "-out", `${nom}.csr`, "-subj", `/CN=${nom}`], dir);
  ossl(["x509", "-req", "-in", `${nom}.csr`, "-CA", `${ca}.pem`, "-CAkey", `${ca}.key`, "-CAcreateserial", "-out", `${nom}.pem`, "-days", "2", "-extfile", `${nom}.ext`], dir);
}

/**
 * Génère le jeu de certificats sous `dir`.
 * @param {string} dir
 * @returns {{ca: string, serveurCert: string, serveurCle: string, autreServeurCert: string, autreServeurCle: string,
 *   clientCert: string, clientCle: string, etrangerCert: string, etrangerCle: string, etrangeCa: string}}
 */
export function genererCertificats(dir) {
  fs.mkdirSync(dir, { recursive: true });
  autorite(dir, "ca-test");
  autorite(dir, "ca-etrangere");
  signe(dir, "serveur", "ca-test", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n");
  signe(dir, "serveur-autre-nom", "ca-test", "subjectAltName=DNS:ailleurs.example\nextendedKeyUsage=serverAuth\n");
  signe(dir, "client", "ca-test", "extendedKeyUsage=clientAuth\n");
  signe(dir, "client-etranger", "ca-etrangere", "extendedKeyUsage=clientAuth\n");
  const p = (n) => path.join(dir, n);
  return {
    ca: p("ca-test.pem"),
    serveurCert: p("serveur.pem"),
    serveurCle: p("serveur.key"),
    autreServeurCert: p("serveur-autre-nom.pem"),
    autreServeurCle: p("serveur-autre-nom.key"),
    clientCert: p("client.pem"),
    clientCle: p("client.key"),
    etrangerCert: p("client-etranger.pem"),
    etrangerCle: p("client-etranger.key"),
    etrangeCa: p("ca-etrangere.pem"),
  };
}
