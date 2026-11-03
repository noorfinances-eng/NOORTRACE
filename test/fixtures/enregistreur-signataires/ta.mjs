// Scénarios des TA- du lot des signataires sur le démon réel (CT-9 §10 ;
// joués par test/adversarial.test.js, référence puis mutant du paquet) :
//
// - TA-33 (MN-33) : signataire de classe B (Vault Transit réel) arrêté sans
//   reprise, sur la configuration de l'installation rapide (CT-8 §7.3)
//   modifiée comme le disent les préconditions de TA-33 ;
// - TA-31 (MN-31) : rapprochement des signatures (CT-7 EX-3.7) entre le
//   journal d'audit `file` de Vault et le journal du démon : écart 0, puis 1
//   après une signature faite hors de l'écrivain avec l'identité d'usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import * as N from "@noortrace/noyau";
import { validerConfiguration, lireEvenements } from "@noortrace/enregistreur";
import { RACINE } from "../enregistreur-coeur/outils.mjs";
import { SERVEUR_OUTILS, configurationDemon, demarrer, arreter, appelerOutil, portLibre } from "../enregistreur-adversarial/demon.mjs";
import { demarrerTransit, arreterConteneur } from "./outils.mjs";

/** Lignes d'événements des segments d'un journal. */
export const nbEvenements = async (rep) => (fs.existsSync(path.join(rep, "segments")) ? (await lireEvenements(rep)).length : 0);


/**
 * Configuration de l'installation rapide (deploiement/config/rapide, CT-8
 * §7.3) modifiée comme le demandent les préconditions de TA-33 :
 * `policy.approval.mode` = `erreur`, `policy.version` sans `-observation`,
 * signataire de classe B (`vault-transit`) au lieu de la classe D ; et
 * adaptée à l'hôte de test : chemins et secrets sous le répertoire du test,
 * adresses d'écoute sur la boucle locale, serveur d'outils stdio de test à
 * la place du serveur HTTP de l'exemple, service d'approbation simulé joint
 * en HTTP, seuil d'espace libre abaissé.
 * @param {string} d
 * @param {{url: string, jeton: string, service: object, serveurService: object, tls: {ca: string}}} o
 */
export async function configurationRapide(d, o) {
  const config = JSON.parse(fs.readFileSync(path.join(RACINE, "deploiement", "config", "rapide", "configuration.json"), "utf8"));
  if (config.policy.approval.mode !== "observation") throw new Error("configuration rapide : mode observation attendu");
  config.policy.approval.mode = "erreur";
  config.policy.version = config.policy.version.replace(/-observation$/, "");
  config.signer = {
    ...config.signer,
    class: "B",
    backend: { type: "vault-transit", url: o.url, mount: "transit", key_name: config.signer.key_id, token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null },
    rotation: { ...config.signer.rotation, next_key_id: null },
  };
  const secrets = path.join(d, "secrets");
  fs.mkdirSync(secrets, { recursive: true });
  const valeurs = {};
  (function remplacer(v) {
    if (Array.isArray(v)) return v.forEach(remplacer);
    if (v === null || typeof v !== "object") return;
    for (const x of Object.values(v)) {
      if (x && typeof x === "object" && typeof x.file === "string" && x.file.startsWith("/run/secrets/")) {
        const nom = path.basename(x.file);
        valeurs[nom] = x.encoding === "hex" ? N.octetsVersHex(N.sha256(N.utf8(`ta33/${nom}`))).slice(2) : `jeton-de-test-${nom}`;
        x.file = path.join(secrets, nom);
        fs.writeFileSync(x.file, valeurs[nom], { mode: 0o600 });
      } else {
        remplacer(x);
      }
    }
  })(config);
  const portHttp = await portLibre();
  const portSante = await portLibre();
  const prises = fs.mkdtempSync(path.join(os.tmpdir(), "ntta33-"));
  config.mcp.socket = path.join(prises, "mcp.sock");
  config.mcp.http.listen = `127.0.0.1:${portHttp}`;
  config.model.listen = `127.0.0.1:${await portLibre()}`;
  config.supervision.health_listen = `127.0.0.1:${portSante}`;
  config.supervision.ops_log.path = path.join(d, "exploitation.ndjson");
  config.storage.root = path.join(d, "stockage");
  config.storage.min_free_bytes = 1048576;
  config.lease.store.path = path.join(d, "bail", "verrou");
  config.policy.servers = {
    demo: {
      transport: { type: "stdio", command: [process.execPath, SERVEUR_OUTILS], cwd: null, env: {}, sandbox: null, user: null, integrity: null },
      protocol: "legacy", class_default: "ecriture", timeout_ms: 60000,
      tools: { lire: { class: "lecture", timeout_ms: null, effects: null, failure: null }, ecrire: { class: "ecriture", timeout_ms: null, effects: null, failure: null } },
      uri_prefixes: [], relay: null,
    },
  };
  config.policy.approval.service = { url: `http://127.0.0.1:${o.serveurService.address().port}`, socket: null, token: { env: "NOORTRACE_TEST_JETON_APPROBATION" }, peer_user: null };
  const v = validerConfiguration(new TextEncoder().encode(JSON.stringify(config)));
  if (v.erreurs.length) throw new Error(JSON.stringify(v.erreurs));
  const { service, serveurService, tls } = o;
  service.org_id = config.recorder.org_id;
  service.journal_id = config.recorder.journal_id;
  return {
    config, dir: d, portHttp, portSante, ports: [portHttp], jeton: valeurs["jeton-hote"],
    journal: path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2)),
    env: { NOORTRACE_TEST_JETON_TRANSIT: o.jeton, NOORTRACE_TEST_JETON_APPROBATION: "jeton-approbation-de-test", NODE_EXTRA_CA_CERTS: tls.ca },
    prises,
  };
}

/** Valeur de la jauge `noortrace_degraded{reason="cle"}` lue sur `GET /metrics`, ou null. */
export async function jaugeCle(port) {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/metrics`);
    const m = /^noortrace_degraded\{reason="cle"\} (\S+)$/m.exec(await r.text());
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

/**
 * TA-33 : arrête le backend pendant la capture ; appelle un outil ; lit la
 * réponse de l'hôte, la jauge, le journal d'exploitation et le segment.
 * @param {object} paquet REFERENCE ou mutant
 * @param {{base: string, nom: string, tls: object, service: object, serveurService: object, attenteMaxMs: number}} o
 */
export async function scenarioTa33(paquet, o) {
  const d = path.join(o.base, `ta33-${o.nom}`);
  fs.mkdirSync(d, { recursive: true });
  const srv = await demarrerTransit("vault-transit", `noortrace-test-ta33-${o.nom}-${process.pid}`, o.tls);
  let c;
  try {
    await srv.creerCle("rec-rapide-01");
    c = await configurationRapide(d, { url: srv.origine, jeton: await srv.jetonUsage(["rec-rapide-01"]), service: o.service, serveurService: o.serveurService, tls: o.tls });
    const p = await demarrer(paquet, c, path.join(d, "configuration.json"));
    const obs = {};
    try {
      obs.avantPanne = await appelerOutil(c.portHttp, c.jeton, "demo__ecrire", { id: "T0", montant: "1" });
      // Le backend est arrêté : il ne répond plus et ne reviendra pas.
      await srv.prox.fermer();
      arreterConteneur(srv.nom);
      obs.evenementsArret = await nbEvenements(c.journal);
      // Jauge à 1 pendant plus de 60 s (condition de CT-2 §17.4), relevée toutes les 5 s.
      obs.jauge = [];
      const debut = Date.now();
      let premiere = null;
      while (Date.now() - debut < o.attenteMaxMs) {
        const g = await jaugeCle(c.portSante);
        obs.jauge.push(g);
        if (g === 1 && premiere === null) premiere = Date.now();
        if (premiere !== null && Date.now() - premiere > 61000) break;
        await new Promise((r) => setTimeout(r, premiere === null ? 500 : 5000));
      }
      obs.jaugeDepuisMs = premiere === null ? 0 : Date.now() - premiere;
      obs.jaugeTenue = premiere !== null && obs.jauge.slice(obs.jauge.indexOf(1)).every((g) => g === 1);
      obs.appel = await appelerOutil(c.portHttp, c.jeton, "demo__ecrire", { id: "T1", montant: "2" });
      await new Promise((r) => setTimeout(r, 1000));
      obs.evenementsFin = await nbEvenements(c.journal);
      obs.lignes = p.lignes();
    } finally {
      await arreter(p);
    }
    return obs;
  } finally {
    await srv.arreter();
    if (c) fs.rmSync(c.prises, { recursive: true, force: true });
  }
}

/** Oracle de TA-33 (CT-9) sur une observation. */
export const oracleTa33 = (o) => ({
  capturePrealable: o.avantPanne.statut === 200 && o.evenementsArret > 0,
  cle31010: o.appel.corps?.error?.code === -31010 && o.appel.corps?.error?.data?.reason === "cle",
  jaugePlusDe60s: o.jaugeTenue && o.jaugeDepuisMs > 60000,
  aucunNouvelEvenement: o.evenementsFin === o.evenementsArret,
});

/** `bin/noortrace-ctl` d'un paquet, en processus réel. */
export function ctl(paquet, args, env = {}) {
  return new Promise((res) => {
    const p = spawn(process.execPath, [paquet.bin("noortrace-ctl"), ...args], { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreur = "";
    p.stdout.on("data", (x) => (sortie += x));
    p.stderr.on("data", (x) => (erreur += x));
    p.on("exit", (code) => res({ code, sortie, erreur }));
  });
}

/**
 * TA-31 : backend de signature de test à journal d'audit (Vault Transit réel,
 * audit `file`) ; le démon réel produit n objets signés ; le rapprochement
 * (`noortrace-ctl cle rapprocher` du paquet) est exécuté sur l'intervalle,
 * puis de nouveau après une signature faite hors de l'écrivain par le même
 * backend avec l'identité d'usage.
 * @param {object} paquet REFERENCE ou mutant
 * @param {{base: string, nom: string, tls: object, approbation: number, service?: object}} o
 */
export async function scenarioTa31(paquet, o) {
  const d = path.join(o.base, `ta31-${o.nom}`);
  fs.mkdirSync(d, { recursive: true });
  const srv = await demarrerTransit("vault-transit", `noortrace-test-ta31-${o.nom}-${process.pid}`, o.tls);
  try {
    await srv.creerCle("rec-ta31-01");
    await srv.activerAudit();
    const jeton = await srv.jetonUsage(["rec-ta31-01"]);
    const c = await configurationDemon(d, {
      approbation: o.approbation,
      modifier: (config, env) => {
        config.signer = { ...config.signer, class: "B", key_id: "rec-ta31-01", backend: { type: "vault-transit", url: srv.origine, mount: "transit", key_name: "rec-ta31-01", token: { env: "NOORTRACE_TEST_JETON_TRANSIT" }, namespace: null }, rotation: { planned_every_days: null, next_key_id: null } };
        Object.assign(env, { NOORTRACE_TEST_JETON_TRANSIT: jeton, NODE_EXTRA_CA_CERTS: o.tls.ca });
      },
    });
    if (o.service) {
      o.service.org_id = c.config.recorder.org_id;
      o.service.journal_id = c.config.recorder.journal_id;
    }
    const fichier = path.join(d, "configuration.json");
    const p = await demarrer(paquet, c, fichier);
    const obs = { reponses: [] };
    try {
      for (const k of [1, 2, 3]) obs.reponses.push(await appelerOutil(c.portHttp, c.env.NOORTRACE_TEST_JETON_HOTE, "demo__ecrire", { id: `R${k}`, montant: String(k) }));
    } finally {
      await arreter(p);
    }
    obs.evenements = await nbEvenements(c.journal);
    const audit = path.join(d, "audit.log");
    fs.writeFileSync(audit, srv.lireAudit());
    obs.sansExterne = await ctl(paquet, ["cle", "rapprocher", "--configuration", fichier, "--audit", audit]);
    // Un objet signé hors de l'écrivain, par le même backend et la même identité d'usage.
    const r = await fetch(`${srv.direct}/v1/transit/sign/rec-ta31-01`, { method: "POST", headers: { "x-vault-token": jeton }, body: JSON.stringify({ input: Buffer.from("objet hors ecrivain").toString("base64") }) });
    obs.signatureExterne = r.status;
    fs.writeFileSync(audit, srv.lireAudit());
    obs.avecExterne = await ctl(paquet, ["cle", "rapprocher", "--configuration", fichier, "--audit", audit]);
    return obs;
  } finally {
    await srv.arreter();
  }
}

