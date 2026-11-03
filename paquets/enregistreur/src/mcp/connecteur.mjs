// Connecteur stdio `noortrace-connecteur` (CT-2 §2, §3.4, EX-3.3, §4.7.1) :
// programme mince lancé par l'hôte comme serveur MCP stdio. Il relaie les
// lignes JSON-RPC entre son entrée et sa sortie standard et la prise locale du
// démon, sans clé, sans stockage, sans politique. Il rejette lui-même une
// ligne qui contient un CR (-32700, EX-4.43) et un cadrage `Content-Length`
// (EX-4.31), écrit son journal sur sa sortie d'erreur, et se termine à la
// fermeture de son entrée standard ou de la prise.
//
// Identité (EX-4.39) : sur une prise Unix, il répond au défi du démon par un
// fichier créé en exclusion dans le répertoire de la prise ; sur une prise
// TCP, sa première ligne porte le jeton statique, lu dans une variable
// d'environnement (jamais sur la ligne de commande), sur TCP nu ou sur TLS ;
// en mTLS, il présente son certificat client et n'envoie pas de jeton. CT-2
// ne décrit pas la configuration TLS du connecteur : elle vient de
// l'environnement, sous les noms du SDK (EX-6.10) préfixés du connecteur,
// chemins de fichiers et non valeurs (LISEZMOI, lecture 135).

import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import path from "node:path";
import { DecoupeurLignes, PREFIXE_DEFI } from "./hote-stdio.mjs";

const ERREUR_CR = '{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error","data":{"reason":"cr_dans_la_ligne"}}}';

/**
 * Exécute le connecteur.
 * `tls` : sur une prise TCP, connexion TLS vérifiée contre `ca` (à défaut,
 * les autorités du système) ; avec `cert` et `key`, mTLS sans ligne de jeton.
 * @param {{socket?: string, tcp?: {hote: string, port: number}, jeton?: string|null,
 *   tls?: {ca?: Buffer, cert?: Buffer, key?: Buffer}|null,
 *   entree?: NodeJS.ReadableStream, sortie?: NodeJS.WritableStream, erreur?: NodeJS.WritableStream,
 *   ligneMax?: number}} o
 * @returns {Promise<number>} code de retour
 */
export function executerConnecteur(o) {
  const entree = o.entree ?? process.stdin;
  const sortie = o.sortie ?? process.stdout;
  const erreur = o.erreur ?? process.stderr;
  const ligneMax = o.ligneMax ?? 16842752;
  return new Promise((resoudre) => {
    const avecTls = !o.socket && o.tls;
    const mtls = Boolean(avecTls && o.tls.cert && o.tls.key);
    const c = o.socket
      ? net.createConnection(o.socket)
      : avecTls
        ? tls.connect({ host: o.tcp.hote, port: o.tcp.port, ca: o.tls.ca, cert: o.tls.cert, key: o.tls.key, minVersion: "TLSv1.2", servername: net.isIP(o.tcp.hote) ? undefined : o.tcp.hote })
        : net.createConnection(o.tcp.port, o.tcp.hote);
    let identifie = false;
    let fin = false;
    const terminer = (code) => {
      if (fin) return;
      fin = true;
      resoudre(code);
    };
    c.on("error", (e) => {
      erreur.write(`noortrace-connecteur: prise injoignable (${e.code ?? "erreur"})\n`);
      terminer(1);
    });
    c.on("close", () => terminer(identifie ? 0 : 1));
    const relayerEntree = () => {
      const d = new DecoupeurLignes(
        ligneMax,
        (l) => {
          if (l.includes(13)) {
            sortie.write(ERREUR_CR + "\n");
            return;
          }
          if (/^Content-Length:/i.test(l.subarray(0, 32).toString("latin1"))) {
            erreur.write("noortrace-connecteur: cadrage Content-Length refuse\n");
            return;
          }
          c.write(Buffer.concat([l, Buffer.from("\n")]));
        },
        () => sortie.write('{"jsonrpc":"2.0","id":null,"error":{"code":-31013,"message":"noortrace: taille maximale depassee","data":{"limit_bytes":' + ligneMax + ',"direction":"requete"}}}\n'),
      );
      entree.on("data", (x) => d.pousser(Buffer.isBuffer(x) ? x : Buffer.from(x)));
      entree.on("end", () => c.end());
    };
    const d = new DecoupeurLignes(Number.MAX_SAFE_INTEGER, (l) => {
      if (!identifie) {
        let m = null;
        try {
          m = JSON.parse(l.toString("utf8"));
        } catch {
          m = null;
        }
        if (m && typeof m.noortrace_defi === "string" && /^[0-9a-f]{32}$/.test(m.noortrace_defi) && o.socket) {
          const f = path.join(path.dirname(o.socket), PREFIXE_DEFI + m.noortrace_defi);
          try {
            fs.closeSync(fs.openSync(f, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600));
          } catch (e) {
            erreur.write(`noortrace-connecteur: preuve d'identite impossible (${e.code ?? "erreur"})\n`);
            c.destroy();
            return;
          }
          c.write(JSON.stringify({ noortrace_preuve: m.noortrace_defi }) + "\n");
          return;
        }
        if (m && m.noortrace_identite === "acceptee") {
          identifie = true;
          relayerEntree();
          return;
        }
        erreur.write("noortrace-connecteur: reponse inattendue du demon\n");
        c.destroy();
        return;
      }
      sortie.write(Buffer.concat([l, Buffer.from("\n")]));
    }, () => {});
    c.on("data", (x) => d.pousser(x));
    // Prise TCP : première ligne {"noortrace_token": …}, sauf en mTLS (EX-4.39, lecture 135).
    c.on(avecTls ? "secureConnect" : "connect", () => {
      if (o.tcp && !mtls) c.write(JSON.stringify({ noortrace_token: o.jeton ?? "" }) + "\n");
    });
  });
}

/**
 * Ligne de commande : `noortrace-connecteur --socket <chemin>` ou
 * `noortrace-connecteur --tcp <hôte:port>` (jeton dans NOORTRACE_CONNECTEUR_JETON ;
 * TLS par NOORTRACE_CONNECTEUR_TLS_CA, et mTLS par NOORTRACE_CONNECTEUR_TLS_CERT
 * et NOORTRACE_CONNECTEUR_TLS_KEY, chemins de fichiers PEM).
 * @param {string[]} argv
 * @param {NodeJS.ProcessEnv} [env]
 */
export async function principalConnecteur(argv, env = process.env) {
  const k = argv.indexOf("--socket");
  const t = argv.indexOf("--tcp");
  if (k >= 0 && argv[k + 1]) return executerConnecteur({ socket: argv[k + 1] });
  if (t >= 0 && argv[t + 1]) {
    const [hote, port] = argv[t + 1].split(/:(?=[0-9]+$)/);
    const { NOORTRACE_CONNECTEUR_TLS_CA: ca, NOORTRACE_CONNECTEUR_TLS_CERT: cert, NOORTRACE_CONNECTEUR_TLS_KEY: key } = env;
    let options = null;
    if (ca || cert || key) {
      if (Boolean(cert) !== Boolean(key)) {
        process.stderr.write("noortrace-connecteur: mTLS exige NOORTRACE_CONNECTEUR_TLS_CERT et NOORTRACE_CONNECTEUR_TLS_KEY\n");
        return 2;
      }
      try {
        options = { ca: ca ? fs.readFileSync(ca) : undefined, cert: cert ? fs.readFileSync(cert) : undefined, key: key ? fs.readFileSync(key) : undefined };
      } catch (e) {
        process.stderr.write(`noortrace-connecteur: fichier TLS illisible (${e.code ?? "erreur"})\n`);
        return 2;
      }
    }
    if (!(options?.cert) && !env.NOORTRACE_CONNECTEUR_JETON) {
      process.stderr.write("noortrace-connecteur: une prise TCP exige un jeton ou mTLS (EX-4.39)\n");
      return 2;
    }
    return executerConnecteur({ tcp: { hote, port: Number(port) }, jeton: options?.cert ? null : (env.NOORTRACE_CONNECTEUR_JETON ?? null), tls: options });
  }
  process.stderr.write("usage : noortrace-connecteur --socket <chemin> | --tcp <hote:port>\n");
  return 2;
}
