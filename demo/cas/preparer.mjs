#!/usr/bin/env node
// Préparation d'un passage d'un cas de démonstration (CT-9 TE-1, TE-2) : les
// gestes de l'exploitant que les pas IR-2 et IR-3 de CT-8 §7.2 font à la main,
// et le fichier d'ancres du réviseur d'IR-8, écrits dans un répertoire de
// travail propre au passage que la surcharge demo/cas/compose.cas.yaml monte
// (variable NOORTRACE_CAS_TRAVAIL).
//
//   node demo/cas/preparer.mjs preparer --cas <assurance|administration> --travail <répertoire absolu>
//        --projet <nom du projet Compose> --origine-console <https://…> --issuer <https://…>
//        [--port-sante <port>]
//     1. crée l'autorité du serveur RFC 3161 interne dans le volume horodatage
//        du projet (`horodatage-init init`, politique de test de CT-5 EX-7.4,
//        unité P-256), puis lit son certificat (`ac`) : rien ne quitte le volume
//        que le certificat ;
//     2. écrit <travail>/ancrage-cas.json : le document ancrage-v0 de la
//        démonstration de référence (demo/ancrage-demo.json), dont le
//        prestataire principal est ce serveur interne (http://127.0.0.1:2020/,
//        espace réseau de l'enregistreur), avec ce certificat ;
//     3. écrit <travail>/approbation-cas.json : la configuration du service
//        d'approbation de la démonstration (demo/approbation-demo.json) pour
//        l'organisation et le journal du cas, l'origine de la console réelle
//        et l'identité de son administrateur (`oidc <issuer> admin-1`).
//
//   node demo/cas/preparer.mjs ancres --cas <cas> --travail <répertoire> --projet <nom>
//     Après la clôture : republie la CRL de l'autorité (`horodatage-init crl`,
//     T-10 de CT-6 n'admet qu'une CRL postérieure à genTime), la lit (`ac
//     --crl`) et écrit <travail>/ancres-cas.json : le fichier d'ancres du
//     réviseur (CT-6 §12) de la démonstration (demo/ancres-demo.json) avec
//     l'autorité interne, sa CRL et la clé de l'enregistreur du journal du cas.
//
// Chaque commande imprime une ligne JSON. Codes : 0 ; 1 échec ; 2 usage.
// Aucune connexion réseau : les commandes Compose tournent des conteneurs
// sans réseau (horodatage-init).

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const ICI = path.dirname(fileURLToPath(import.meta.url));
export const DEMO = path.resolve(ICI, "..");
export const CAS = Object.freeze(["assurance", "administration"]);
export const POLITIQUE_TEST = "1.3.6.1.4.1.99999.1.1";

/** Variables de `demo/cas/<cas>/cas.env` (forme `NOM=valeur`, commentaires `#`). */
export function lireEnv(cas) {
  const env = {};
  for (const l of fs.readFileSync(path.join(ICI, cas, "cas.env"), "utf8").split("\n")) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(l);
    if (m) env[m[1]] = m[2];
  }
  return env;
}

/** Arguments communs de `docker compose` pour un passage. */
export function argumentsCompose({ cas, projet, travail, portSante = null }) {
  return {
    args: ["compose", "-p", projet, "--project-directory", DEMO, "--env-file", path.join(ICI, cas, "cas.env"), "-f", path.join(DEMO, "compose.yaml"), "-f", path.join(ICI, "compose.cas.yaml")],
    env: { ...process.env, NOORTRACE_CAS_TRAVAIL: travail, ...(portSante ? { NOORTRACE_DEMO_PORT_SANTE: String(portSante) } : {}) },
  };
}

function compose(o, args, { entree = undefined } = {}) {
  const { args: base, env } = argumentsCompose(o);
  const r = spawnSync("docker", [...base, ...args], { encoding: "utf8", env, input: entree, maxBuffer: 64 * 1024 * 1024, timeout: 300000 });
  if (r.status !== 0) throw new Error(`docker compose ${args.slice(0, 3).join(" ")} : code ${r.status}\n${r.stderr.split("\n").slice(-12).join("\n")}`);
  return r.stdout;
}

/** `horodatage-init <commande…>` dans le projet (profil outils, conteneur sans réseau). */
const horodatageInit = (o, args) => compose(o, ["--profile", "outils", "run", "--rm", "-T", "--no-deps", "horodatage-init", ...args]);

/** Un seul certificat PEM, tel quel. */
function unPem(texte, quoi) {
  const m = texte.match(/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----\n?/g);
  if (!m || m.length !== 1) throw new Error(`${quoi} : un seul bloc PEM attendu, ${m ? m.length : 0} lu(s)`);
  return m[0].endsWith("\n") ? m[0] : `${m[0]}\n`;
}

export function preparer(o) {
  if (!CAS.includes(o.cas)) throw new Error(`cas inconnu : ${o.cas}`);
  if (!path.isAbsolute(o.travail)) throw new Error("--travail : chemin absolu requis");
  for (const [nom, v] of [["--origine-console", o.origineConsole], ["--issuer", o.issuer]]) if (!/^https:\/\/[^\s/]+(:[0-9]+)?$/.test(v ?? "")) throw new Error(`${nom} : origine https sans chemin requise`);
  const env = lireEnv(o.cas);
  fs.mkdirSync(o.travail, { recursive: true, mode: 0o700 });
  // 1. Autorité du serveur interne (IR-2) ; `init` refuse d'écraser une autorité existante : un volume déjà peuplé est réemployé.
  let creation = "creee";
  try {
    horodatageInit(o, ["init", "--repertoire", "/var/lib/noortrace-tsa", "--politique", POLITIQUE_TEST, "--crl-url", "http://127.0.0.1:2020/crl.pem", "--algorithme", "p-256"]);
  } catch (e) {
    if (!/existe|exist/i.test(e.message)) throw e;
    creation = "existante";
  }
  const acPem = unPem(horodatageInit(o, ["ac", "--repertoire", "/var/lib/noortrace-tsa"]), "certificat de l'AC");
  fs.writeFileSync(path.join(o.travail, "ac-horodatage.pem"), acPem);
  // 2. Document d'ancrage (IR-3) : celui de la démonstration de référence, prestataire principal = serveur interne servi.
  const ancrage = JSON.parse(fs.readFileSync(path.join(DEMO, "ancrage-demo.json"), "utf8"));
  if (ancrage.rfc3161.providers.length !== 1) throw new Error("ancrage-demo.json : un seul prestataire attendu");
  ancrage.rfc3161.providers[0] = {
    ...ancrage.rfc3161.providers[0],
    id: "tsa-interne", role: "principal", url: "http://127.0.0.1:2020/", auth: { method: "aucune", secret: null }, policy_oid: POLITIQUE_TEST, accepted_policies: [POLITIQUE_TEST],
    anchor_certificates: [acPem], qualified: null, request_timeout_ms: 5000,
    source: `cas de démonstration « ${o.cas} » (CT-9 TE-1, TE-2) : serveur RFC 3161 interne non qualifié (CT-5 §7) du service horodatage de demo/cas/compose.cas.yaml, joint sur la boucle locale de l'espace réseau de l'enregistreur ; principal admis hors production seulement (CT-5 EX-4.9, règle 4) ; anchor_certificates : l'AC créée dans le volume horodatage au début du passage, sans valeur hors de la démonstration`,
  };
  fs.writeFileSync(path.join(o.travail, "ancrage-cas.json"), `${JSON.stringify(ancrage, null, 2)}\n`);
  // 3. Configuration du service d'approbation : organisation, journal, console réelle et son administrateur.
  const approbation = JSON.parse(fs.readFileSync(path.join(DEMO, "approbation-demo.json"), "utf8"));
  approbation.org = env.NOORTRACE_CAS_ORG;
  approbation.org_id = env.NOORTRACE_CAS_ORG_ID;
  approbation.journal_id = env.NOORTRACE_CAS_JOURNAL_ID;
  approbation.console_origin = o.origineConsole;
  approbation.administrators = [`oidc ${o.issuer} admin-1`];
  fs.writeFileSync(path.join(o.travail, "approbation-cas.json"), `${JSON.stringify(approbation, null, 2)}\n`);
  return { cas: o.cas, travail: o.travail, projet: o.projet, autorite: creation, org_id: approbation.org_id, journal_id: approbation.journal_id, console_origin: o.origineConsole, administrators: approbation.administrators, fichiers: ["ac-horodatage.pem", "ancrage-cas.json", "approbation-cas.json"] };
}

export function ancres(o) {
  if (!CAS.includes(o.cas)) throw new Error(`cas inconnu : ${o.cas}`);
  const env = lireEnv(o.cas);
  const acPem = fs.readFileSync(path.join(o.travail, "ac-horodatage.pem"), "utf8");
  horodatageInit(o, ["crl", "--repertoire", "/var/lib/noortrace-tsa"]);
  const crlPem = unPem(horodatageInit(o, ["ac", "--crl", "--repertoire", "/var/lib/noortrace-tsa"]), "CRL");
  fs.writeFileSync(path.join(o.travail, "crl-horodatage.pem"), crlPem);
  const a = JSON.parse(fs.readFileSync(path.join(DEMO, "ancres-demo.json"), "utf8"));
  a.label = `Ancres du cas de démonstration « ${o.cas} »`;
  a.prepared_by = `réviseur du cas de démonstration « ${o.cas} » (CT-9 TE-1, TE-2)`;
  a.prepared_at = new Date().toISOString();
  a.tsa_authorities = [{ name: "AC du serveur RFC 3161 interne de la démonstration (interne, non qualifié)", certificate: acPem, intermediates: [], accepted_policies: [POLITIQUE_TEST], qualified: null, source: "autorité créée dans le volume horodatage au début du passage (horodatage-init), sans valeur hors de la démonstration" }];
  a.revocation = { crls: [crlPem], statements: [] };
  a.recorders = a.recorders.map((r) => ({ ...r, org_id: env.NOORTRACE_CAS_ORG_ID, journal_id: env.NOORTRACE_CAS_JOURNAL_ID, source: `${r.source} ; journal ${env.NOORTRACE_CAS_JOURNAL} de ${env.NOORTRACE_CAS_ORG}` }));
  const chemin = path.join(o.travail, "ancres-cas.json");
  fs.writeFileSync(chemin, `${JSON.stringify(a, null, 2)}\n`);
  return { cas: o.cas, ancres: chemin, tsa_authorities: 1, crls: 1, recorders: a.recorders.map((r) => r.key_id) };
}

function principal(argv) {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: { cas: { type: "string" }, travail: { type: "string" }, projet: { type: "string" }, "origine-console": { type: "string" }, issuer: { type: "string" }, "port-sante": { type: "string" } } });
  const o = { cas: values.cas, travail: values.travail, projet: values.projet, origineConsole: values["origine-console"], issuer: values.issuer, portSante: values["port-sante"] ?? null };
  if (!o.cas || !o.travail || !o.projet) throw Object.assign(new Error("usage : preparer.mjs preparer|ancres --cas <cas> --travail <répertoire absolu> --projet <nom> [--origine-console <url> --issuer <url>] [--port-sante <port>]"), { usage: true });
  if (positionals[0] === "preparer") return preparer(o);
  if (positionals[0] === "ancres") return ancres(o);
  throw Object.assign(new Error("commande attendue : preparer | ancres"), { usage: true });
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(`${JSON.stringify(principal(process.argv.slice(2)))}\n`);
  } catch (e) {
    process.stderr.write(`preparer : ${e.message}\n`);
    process.exit(e.usage ? 2 : 1);
  }
}
