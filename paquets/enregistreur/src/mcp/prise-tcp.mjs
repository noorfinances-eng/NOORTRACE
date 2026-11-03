// Prise TCP locale authentifiée, commune à la prise des connecteurs stdio
// (`mcp.connector_tcp`, frontal MCP) et à celle du point d'entrée SDK
// (`sdk.tcp_listen`) : `$defs/tcp_listen` du schéma de configuration, CT-2
// EX-4.39 (« Une prise TCP n'a pas d'identité de pair : elle exige un jeton
// ou mTLS »), EX-6.1, EX-6.10.
//
//   - `client_auth: "jeton"` : première ligne `{"noortrace_token": …}`, sur
//     TCP nu, ou sur TLS si `tls` est posé ;
//   - `client_auth: "mtls"` : TLS obligatoire (`tls.cert_file`,
//     `tls.key_file`), certificat client exigé, vérifié contre l'autorité qui
//     suit le certificat du démon dans `tls.cert_file` et rattaché à l'entrée
//     d'hôte dont `match.peer_user` est le nom commun (CN) de son sujet ; pas
//     de ligne de jeton (LISEZMOI, lectures 113 et 134 : le schéma n'a ni
//     autorité cliente pour ces prises ni forme de `match` pour un
//     certificat).
// Plancher TLS 1.2, comme la passerelle et ICAPS (lecture 74).

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import { X509Certificate } from "node:crypto";

/**
 * Sépare le certificat du démon et les certificats qui le suivent dans
 * `tls.cert_file` (chaîne PEM) : ces derniers sont l'autorité admise pour
 * les certificats clients en mTLS (lecture 113).
 * @param {Buffer} pem
 * @param {string} [nom] nom de la prise, pour les messages
 * @returns {{cert: string, autorites: string[]}}
 */
export function chaineServeur(pem, nom = "prise TCP") {
  const blocs = pem.toString("utf8").match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? [];
  if (!blocs.length) throw new Error(`${nom} : tls.cert_file sans certificat PEM`);
  for (const b of blocs) new X509Certificate(b);
  return { cert: blocs.join("\n") + "\n", autorites: blocs.slice(1) };
}

/**
 * Crée et met en écoute le serveur d'une prise `$defs/tcp_listen`.
 * @param {{listen: string, client_auth: "jeton"|"mtls", tls: {cert_file: string, key_file: string}|null}} tcp
 * @param {{nom: string, pointeur: string, connexions: Set<object>,
 *   surJeton: (c: net.Socket) => void, surMtls: (c: tls.TLSSocket) => void,
 *   surEchecTls: (raison: string) => void}} o
 *   `nom` et `pointeur` (p. ex. « prise TCP du SDK », `sdk.tcp_listen`) pour
 *   les messages ; `connexions` reçoit toute prise acceptée, poignée de main
 *   comprise, pour la fermer à l'arrêt
 * @returns {Promise<net.Server>}
 */
export async function ecouterPriseTcp(tcp, o) {
  const [hote, port] = tcp.listen.split(/:(?=[0-9]+$)/);
  const mtls = tcp.client_auth === "mtls";
  let s;
  if (tcp.tls) {
    const { cert, autorites } = chaineServeur(fs.readFileSync(tcp.tls.cert_file), o.nom);
    const opts = { cert, key: fs.readFileSync(tcp.tls.key_file), minVersion: "TLSv1.2" };
    if (mtls) {
      if (!autorites.length) throw new Error(`${o.nom} : client_auth mtls exige l'autorité des certificats clients à la suite du certificat du démon dans ${o.pointeur}.tls.cert_file (lecture 113)`);
      // Certificat exigé ; sa vérification (autorité, validité) est relue
      // après la poignée de main pour consigner la raison du refus, et la
      // prise est détruite avant toute lecture (`identiteCertificat`).
      Object.assign(opts, { ca: autorites, requestCert: true, rejectUnauthorized: false });
    }
    s = tls.createServer(opts, (c) => (mtls ? o.surMtls(c) : o.surJeton(c)));
    // Poignée de main échouée (version, suite, message TLS invalide).
    s.on("tlsClientError", (e) => o.surEchecTls(e?.code ?? "tls"));
  } else {
    if (mtls) throw new Error(`${o.nom} : client_auth mtls exige ${o.pointeur}.tls`);
    s = net.createServer((c) => o.surJeton(c));
  }
  s.on("connection", (x) => {
    o.connexions.add(x);
    x.on("close", () => o.connexions.delete(x));
    x.on("error", () => {});
  });
  await new Promise((res, rej) => {
    s.once("error", rej);
    s.listen(Number(port), hote.replace(/^\[|\]$/g, ""), res);
  });
  return s;
}

/**
 * Identité d'une connexion mTLS : nom commun du certificat client vérifié,
 * ou la raison du refus (`certificat:absent`, `certificat:<code OpenSSL>`,
 * `certificat:sans_nom_commun`).
 * @param {tls.TLSSocket} c
 * @returns {{cn: string, empreinte: string}|{refus: string}}
 */
export function identiteCertificat(c) {
  const pc = c.getPeerCertificate();
  if (!pc?.raw) return { refus: "certificat:absent" };
  if (c.authorized !== true) return { refus: `certificat:${c.authorizationError ?? "refuse"}` };
  const cn = pc.subject?.CN;
  if (typeof cn !== "string" || cn.length === 0) return { refus: "certificat:sans_nom_commun" };
  return { cn, empreinte: pc.fingerprint256 };
}

/**
 * Règle du pas 3 d'EX-15.4 pour une prise `$defs/tcp_listen` :
 * `client_auth: "mtls"` exige `tls` (certificat du démon suivi de l'autorité
 * des certificats clients, lecture 113).
 * @param {object|null|undefined} tcp
 * @param {string} pointeur pointeur JSON de la prise, p. ex. `/mcp/connector_tcp`
 * @returns {{pointeur: string, regle: string, valeur: null}[]}
 */
export function erreursPriseTcp(tcp, pointeur) {
  if (tcp?.client_auth === "mtls" && !tcp.tls) return [{ pointeur: `${pointeur}/tls`, regle: "client_auth mtls exige tls (certificat du démon suivi de l'autorité des certificats clients, lecture 113)", valeur: null }];
  return [];
}

/**
 * Règles du pas 3 d'EX-15.4 pour la prise TCP des connecteurs
 * (`mcp.connector_tcp`, lecture 134).
 * @param {object} c configuration validée contre le schéma
 */
export function controleConnecteurTcp(c) {
  return { erreurs: erreursPriseTcp(c.mcp?.connector_tcp, "/mcp/connector_tcp"), avertissements: [] };
}
