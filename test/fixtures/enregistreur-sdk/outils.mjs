// Outils des tests du point d'entrée SDK et du SDK JavaScript
// (test/enregistreur-sdk-*.test.js) : entrée de `sdk.hosts` de l'utilisateur
// courant (prise Unix, identité du pair), démon en processus (cœur, rédacteur
// pii-v1 de l'exemple de 15.3, service d'approbation factice, point d'entrée
// SDK), client `noortrace-sdk`, lecture des événements et du journal
// d'exploitation. Répertoires sous os.tmpdir().

import os from "node:os";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { Coeur, Redacteur, demarrerSdk, lireEvenements, HorlogeReglable } from "@noortrace/enregistreur";
import { ServiceApprobationFactice } from "@noortrace/enregistreur/factice";
import { ClientNoortrace } from "noortrace-sdk";
import { configurationDev, repertoireTemporaire, secretsDev } from "../enregistreur-coeur/outils.mjs";

export const QUOTA_LARGE = Object.freeze({ max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 });

/** Entrée de `sdk.hosts` identifiée par l'utilisateur du processus courant. */
export function hoteSdk(o = {}) {
  return {
    id: o.id ?? "agent-local",
    match: o.match ?? { peer_user: os.userInfo().username },
    launched_by: o.launched_by ?? "${peer_user}",
    scope: o.scope ?? "sinistres:lecture,paiement",
    on_behalf_of: o.on_behalf_of ?? null,
    accept_declared_delegation: o.accept_declared_delegation ?? true,
    tool_name_template: "{tool_announced}",
    tool_name_sanitize: false,
    prompt_version_name: o.prompt_version_name ?? null,
    host_group: o.host_group ?? "agent-sinistres",
    allowed_on_behalf_of: o.allowed_on_behalf_of ?? ["service-sinistres"],
    quota: { ...QUOTA_LARGE, ...(o.quota ?? {}) },
    alias: o.alias ?? "agent-local",
  };
}

/**
 * Démon en processus : cœur, rédacteur, service factice, point d'entrée SDK.
 * @param {{hotes?: object[], decider?: Function, modifier?: (c: object) => void, horloge?: object, service?: object|null, redaction?: boolean}} [o]
 */
export async function demarrerDemonSdk(o = {}) {
  const dir = repertoireTemporaire("noortrace-sdk-");
  const hotes = o.hotes ?? [hoteSdk()];
  const { config, env } = configurationDev(dir, { sdk: { hosts: hotes } });
  config.sdk.socket = path.join(dir, "p", "sdk.sock");
  o.modifier?.(config);
  Object.assign(process.env, env);
  const secrets = secretsDev();
  const redaction = o.redaction === false ? null : Redacteur.depuisConfiguration(config, secrets, { fils: 0 });
  const service = o.service === null ? null : (o.service ?? new ServiceApprobationFactice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id, decider: o.decider }));
  const coeur = await Coeur.demarrer({ config, secrets, redaction: redaction ?? undefined, service, horloge: o.horloge });
  const sdk = await demarrerSdk(coeur, secrets, { correlateur: o.correlateur ?? null });
  const d = {
    dir,
    config,
    coeur,
    sdk,
    service,
    redaction,
    client: (x = {}) => new ClientNoortrace({ socket: config.sdk.socket, ...x }),
    evenements: () => lireEvenements(coeur.repertoire),
    lignes: (evenement) => coeur.journal.lignes.filter((l) => l.event === evenement),
    // `d.sdk` peut être remplacé par un essai (point d'entrée redémarré) : c'est lui qui est arrêté.
    async arreter() {
      await d.sdk.arreter();
      await coeur.arreter();
      await redaction?.fermer();
    },
  };
  return d;
}

/**
 * Client brut de la prise (entrées hostiles) : preuve d'identité, puis lignes.
 * @param {string} socket
 */
export async function priseBrute(socket) {
  const c = net.createConnection(socket);
  const lignes = [];
  let tampon = "";
  let attente = null;
  c.on("data", (x) => {
    tampon += x.toString("utf8");
    let k;
    while ((k = tampon.indexOf("\n")) >= 0) {
      const l = tampon.slice(0, k);
      tampon = tampon.slice(k + 1);
      let m;
      try {
        m = JSON.parse(l);
      } catch {
        m = l;
      }
      if (m && typeof m === "object" && typeof m.noortrace_defi === "string") {
        const f = path.join(path.dirname(socket), ".noortrace-defi-" + m.noortrace_defi);
        fs.closeSync(fs.openSync(f, "wx", 0o600));
        c.write(JSON.stringify({ noortrace_preuve: m.noortrace_defi }) + "\n");
        continue;
      }
      lignes.push(m);
      if (attente) {
        const a = attente;
        attente = null;
        a();
      }
    }
  });
  await new Promise((r) => c.once("connect", r));
  const suivante = async () => {
    while (!lignes.length) await new Promise((r) => (attente = r));
    return lignes.shift();
  };
  const identite = await suivante();
  return {
    identite,
    c,
    envoyer: (texte) => c.write(texte + "\n"),
    suivante,
    async appel(methode, params, id = 1) {
      c.write(JSON.stringify({ jsonrpc: "2.0", id, method: `noortrace/sdk/${methode}`, params }) + "\n");
      return suivante();
    },
    fermer: () => c.destroy(),
  };
}

/**
 * Autorité de test pour le mTLS de la prise TCP du SDK, générée à l'exécution
 * par `openssl` (aucune clé dans le dépôt) : certificat du démon pour
 * 127.0.0.1 suivi de l'autorité dans le même fichier (lecture 113),
 * certificats clients valides, expiré, ou d'une autre autorité.
 * @param {string} dir
 */
export function autoriteDeTest(dir) {
  fs.mkdirSync(dir, { recursive: true });
  const f = (n) => path.join(dir, n);
  const ossl = (args) => {
    const r = spawnSync("openssl", args, { cwd: dir, encoding: "utf8" });
    if (r.status !== 0) throw new Error(`openssl ${args[0]} : ${r.stderr}`);
  };
  const cleEc = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  const racine = (nom) => {
    ossl(["req", "-x509", ...cleEc, "-days", "2", "-subj", `/CN=${nom}`, "-keyout", f(`${nom}.key`), "-out", f(`${nom}.pem`)]);
    const db = f(`${nom}-db`);
    fs.mkdirSync(db, { recursive: true });
    fs.writeFileSync(path.join(db, "index.txt"), "");
    fs.writeFileSync(path.join(db, "serial"), "01\n");
    fs.writeFileSync(
      f(`${nom}.cnf`),
      `[ca]\ndefault_ca=x\n[x]\ndatabase=${db}/index.txt\nserial=${db}/serial\nnew_certs_dir=${db}\ndefault_md=sha256\npolicy=p\nunique_subject=no\ncopy_extensions=copy\n[p]\ncommonName=supplied\n`,
    );
    return nom;
  };
  const emettre = (autorite, cn, fichier, o = {}) => {
    ossl(["req", ...cleEc, "-subj", `/CN=${cn}`, ...(o.san ? ["-addext", `subjectAltName=${o.san}`] : []), "-keyout", f(`${fichier}.key`), "-out", f(`${fichier}.csr`)]);
    const duree = o.expire ? ["-startdate", "20200101000000Z", "-enddate", "20200102000000Z"] : ["-days", "2"];
    ossl(["ca", "-batch", "-notext", "-config", f(`${autorite}.cnf`), "-cert", f(`${autorite}.pem`), "-keyfile", f(`${autorite}.key`), "-in", f(`${fichier}.csr`), "-out", f(`${fichier}.pem`), ...duree]);
    return { cert: f(`${fichier}.pem`), key: f(`${fichier}.key`) };
  };
  const ca = racine("autorite");
  racine("autre-autorite");
  const serveur = emettre(ca, "noortrace-sdk", "serveur", { san: "IP:127.0.0.1" });
  // Certificat du démon suivi de l'autorité des certificats clients.
  fs.writeFileSync(f("serveur-chaine.pem"), fs.readFileSync(serveur.cert, "utf8") + fs.readFileSync(f(`${ca}.pem`), "utf8"));
  return {
    ca: f(`${ca}.pem`),
    serveur: { cert_file: f("serveur-chaine.pem"), key_file: serveur.key, seul: serveur.cert },
    client: (cn, fichier = `client-${cn}`) => emettre(ca, cn, fichier),
    expire: (cn) => emettre(ca, cn, `expire-${cn}`, { expire: true }),
    etranger: (cn) => emettre("autre-autorite", cn, `etranger-${cn}`),
  };
}

export { HorlogeReglable, ServiceApprobationFactice, ClientNoortrace };
