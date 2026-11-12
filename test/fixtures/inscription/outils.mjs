// Outils des essais de l'inscription (étape 6) : clés d'essai dérivées au
// moment de l'essai du mnémonique public (`m/44'/60'/0'/0/i`) et de graines
// publiques, documents de clé d'enregistreur, signature des demandes hors de
// l'application (comme le ferait l'outil d'un approbateur, EX-7.27), agent
// démarré dans un répertoire temporaire, outil de référence lancé en boîte
// noire (ses sorties seules sont lues), comparaison de la forme de deux
// sorties (épreuve d'EX-7.24).

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { HDNodeWallet } from "ethers";
import { clePubliqueEd25519, ecrireHorodatage, octetsVersHex, sha256, signerEip191, utf8, hexVersOctets } from "@noortrace/noyau";
import { remettre } from "../../../paquets/inscription/src/agent/client.mjs";
import { RACINE, MNEMONIQUE } from "./reseau-essai.mjs";

/** Répertoire temporaire des essais (`NOORTRACE_TMP` ou `os.tmpdir()`), jamais dans le dépôt. */
export function repertoireTemporaire(prefixe = "noortrace-inscription-") {
  const base = process.env.NOORTRACE_TMP ?? os.tmpdir();
  fs.mkdirSync(base, { recursive: true });
  return fs.mkdtempSync(path.join(base, prefixe));
}

/** Compte Hardhat `i` du mnémonique public : `{ adresse, cle }` (clé de test sans valeur, dérivée à l'essai). */
export function compteHardhat(i) {
  const w = HDNodeWallet.fromPhrase(MNEMONIQUE, undefined, `m/44'/60'/0'/0/${i}`);
  return { adresse: w.address.toLowerCase(), cle: hexVersOctets(w.privateKey) };
}

/** Graine Ed25519 d'essai : SHA-256(UTF-8(« noortrace/essai/inscription/<nom> »)) ; rend `{ graine, publique }`. */
export function cleEd25519(nom) {
  const graine = sha256(utf8(`noortrace/essai/inscription/${nom}`));
  return { graine, publique: octetsVersHex(clePubliqueEd25519(graine)) };
}

/** Document `cle_enregistreur` (CT-2 EX-11.13) d'une clé d'essai, classe D. */
export function documentCle({ keyId, journalId, chainKey, publique, classe = "D" }) {
  return {
    key_id: keyId, journal_id: journalId, algorithm: "ed25519", public_key: publique, custody_class: classe, backend_type: "fichier",
    created_at: ecrireHorodatage(Date.now()), chain_key: chainKey, chain_key_class: classe, origin_proof: null,
  };
}

/** Signe une demande `demande_signature` par des comptes Hardhat (hors de l'application), signatures rangées par adresse. */
export function signerDemande(demande, indices) {
  const d = JSON.parse(JSON.stringify(demande));
  for (const i of indices) {
    const c = compteHardhat(i);
    const sig = signerEip191(c.cle, hexVersOctets(d.digest));
    d.signatures.push({ signer: c.adresse, v: sig[64], r: octetsVersHex(sig.subarray(0, 32)), s: octetsVersHex(sig.subarray(32, 64)) });
  }
  d.signatures.sort((a, b) => (a.signer < b.signer ? -1 : a.signer > b.signer ? 1 : 0));
  return d;
}

/**
 * Lance l'outil de référence en boîte noire, sans bloquer la boucle
 * d'événements (le pont JSON-RPC de l'essai sert dans ce même processus) ;
 * rend `{ sortie, code, err }`. `env` complète l'environnement (une
 * référence `env:` de l'outil).
 */
export function outilReference(args, { delaiMs = 300000, env = {} } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [path.join(RACINE, "scripts", "registre", "noortrace-registre.mjs"), ...args], { cwd: RACINE, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    const minuterie = setTimeout(() => p.kill("SIGKILL"), delaiMs);
    p.on("close", (code) => {
      clearTimeout(minuterie);
      let sortie = null;
      try {
        sortie = JSON.parse(out);
      } catch {
        sortie = null;
      }
      resolve({ sortie, code, err });
    });
  });
}

/** Clés d'un objet, récursivement (forme des `outputs`) ; un tableau rend la forme de son premier élément. */
export function formeObjet(v) {
  if (Array.isArray(v)) return v.length ? [formeObjet(v[0])] : [];
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).map((k) => [k, formeObjet(v[k])]));
  return v === null ? null : typeof v;
}

/** Forme d'une sortie comparée par l'épreuve d'EX-7.24 : commande, résultat, code, vérifications et leurs statuts, membres des `outputs`. */
export function formeSortie(s, { valeursOutputs = false } = {}) {
  if (!s) return s;
  return {
    command: s.command,
    result: s.result,
    exit_code: s.exit_code,
    error: s.error ? { code: s.error.code, check: s.error.check } : null,
    checks: s.checks.map((c) => `${c.id}:${c.status}`),
    outputs: valeursOutputs ? s.outputs : formeObjet(s.outputs),
  };
}

/** Binaire de l'agent. */
export const BIN_AGENT = path.join(RACINE, "paquets", "inscription", "bin", "noortrace-inscription-agent");

/**
 * Lance le binaire de l'agent (processus séparé, répertoire de travail : la
 * racine du dépôt) ; rend `{ processus, pret }` quand la ligne de
 * disponibilité est écrite, ou `{ code, stderr }` s'il s'arrête avant.
 */
export function lancerAgent(cheminConfig, { env = {} } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN_AGENT, "--config", cheminConfig], { cwd: RACINE, env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let sortie = "";
    let erreurs = "";
    p.stdout.on("data", (d) => {
      sortie += d;
      const ligne = sortie.split("\n")[0];
      if (sortie.includes("\n")) {
        try {
          resolve({ processus: p, pret: JSON.parse(ligne), stderr: () => erreurs });
        } catch {
          resolve({ processus: p, pret: null, stderr: () => erreurs });
        }
      }
    });
    p.stderr.on("data", (d) => {
      erreurs += d;
    });
    p.on("exit", (code) => resolve({ code, stderr: erreurs }));
  });
}

/**
 * Démarre un agent (binaire, processus séparé) dans des répertoires
 * temporaires (prise dans un répertoire 0750, données 0750). `comptes` :
 * références par rôle ; `interfaceUid` : compte admis (par défaut celui de
 * l'essai).
 */
export async function demarrerAgentEssai({ manifeste, rpc, comptes = { exploitant: "hardhat:0" }, delai_s = 10, nature = "developpement", interfaceUid = process.getuid(), jeton = null, env = {} }) {
  const base = repertoireTemporaire();
  const prises = path.join(base, "prise");
  const donnees = path.join(base, "donnees");
  fs.mkdirSync(prises, { mode: 0o750 });
  fs.chmodSync(prises, 0o750);
  fs.mkdirSync(donnees, { mode: 0o750 });
  fs.chmodSync(donnees, 0o750);
  const config = { version: 0, prise: path.join(prises, "agent.sock"), interface_uid: interfaceUid, donnees, nature, instance: manifeste, rpc: [rpc], jeton, comptes, delai_s };
  const cheminConfig = path.join(base, "agent.json");
  fs.writeFileSync(cheminConfig, JSON.stringify(config, null, 2));
  const lance = await lancerAgent(cheminConfig, { env });
  if (!lance.pret) throw new Error(`l'agent n'a pas démarré : ${lance.stderr?.() ?? lance.stderr}`);
  const agent = lance.processus;
  return {
    base, config, cheminConfig, agent, pret: lance.pret, donnees, prise: config.prise, stderr: lance.stderr,
    client: (slug) => ({
      dir: path.join(donnees, "clients", slug),
      dossier: path.join(donnees, "clients", slug, "dossier.json"),
      captures: path.join(donnees, "clients", slug, "captures"),
    }),
    remettre: (requete) => remettre(config.prise, requete),
    travail: (exploitant, travail) => remettre(config.prise, { version: 0, kind: "travail", exploitant, travail }),
    confirmation: (exploitant, confirmation) => remettre(config.prise, { version: 0, kind: "confirmation", exploitant, confirmation }),
    async attendre(id, delaiMs = 120000) {
      const debut = Date.now();
      for (;;) {
        try {
          const t = JSON.parse(fs.readFileSync(path.join(donnees, "travaux", `${id}.json`), "utf8"));
          if (["fini", "refuse", "abandonne"].includes(t.etat)) return t;
        } catch {
          // en cours d'écriture
        }
        if (Date.now() - debut > delaiMs) throw new Error(`travail ${id} non terminé`);
        await new Promise((ok) => setTimeout(ok, 50));
      }
    },
    /** Remet un travail et attend sa fin ; rend l'enregistrement du travail. */
    async executer(exploitant, travail) {
      const r = await remettre(config.prise, { version: 0, kind: "travail", exploitant, travail });
      if (!r.accepte) return { refus: r };
      return this.attendre(r.id);
    },
    journal: () => fs.readFileSync(path.join(donnees, "journal-agent.ndjson"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)),
    /** Arrête le processus de l'agent courant (`this.agent`, qu'un essai peut avoir relancé). */
    async arreter() {
      const p = this.agent;
      if (p.exitCode !== null || p.signalCode !== null) return p.exitCode;
      const fin = new Promise((ok) => p.once("exit", (code) => ok(code)));
      p.kill("SIGTERM");
      return fin;
    },
  };
}
