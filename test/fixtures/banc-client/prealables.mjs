// Préalables d'EX-8.2 du banc « client fictif » (CT-8 §8.2), réunis avant le
// jour de l'installation et non chronométrés par CT-8 : dossier d'inscription
// de l'organisation au registre accepté, jeu d'approbateurs déployé, assigné
// et lu, paquet client remis (CT-4 §7, §7.13), par l'agent d'inscription de
// l'application d'exploitant (`paquets/inscription`) sur le réseau de
// développement 2124 ; puis, au pas IC-13, l'inscription de la clé du journal
// de production (CT-4 §8.7) par l'outil de référence du registre, en boîte
// noire. Même enchaînement que le banc de l'étape 6
// (test/fixtures/exploitation-console/parcours/inscription.mjs), pour
// l'organisation du banc et son journal.
//
// Clés d'essai : comptes du mnémonique public (`m/44'/60'/0'/0/i`) ; la clé
// d'enregistreur du journal d'essai de l'inscription et sa clé de chaîne de
// classe D sont tirées par SHA-256 d'un texte public propre à l'organisation.
// Rien n'est écrit hors du répertoire de travail.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import * as N from "@noortrace/noyau";
import { SignataireChaineFichier } from "@noortrace/ancrage";
import { remettre } from "@noortrace/inscription/client";
import { controlerPaquet } from "@noortrace/inscription/paquet";
import { compte, signerDemande, POINTS, BIN_AGENT, OUTIL_REFERENCE } from "../exploitation-console/parcours/inscription.mjs";
import { RACINE } from "../exploitation-console/serveur/outils.mjs";

export { compte, signerDemande, POINTS, RACINE };

const EXPLOITANT = "exploitant operateur-1";
const deriver = (texte) => N.sha256(N.utf8(`noortrace/essai/banc-client/${texte}`));

/** Lance un programme Node en boîte noire ; rend `{ code, sortie, err }`. */
export function lancerNode(args, { delaiMs = 300000, cwd = RACINE } = {}) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
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
      resolve({ code, sortie, out, err });
    });
  });
}

/** Outil de référence du registre en boîte noire, relancé sur le seul refus passager `noeud_suiveur`. */
export async function outilRegistre(args) {
  let r;
  for (let i = 0; i < 20; i += 1) {
    r = await lancerNode([OUTIL_REFERENCE, ...args, "--rpc", POINTS.join(",")]);
    if (r.sortie?.error?.code !== "noeud_suiveur") return r;
    await new Promise((ok) => setTimeout(ok, 500));
  }
  return r;
}

async function demarrerAgent(base) {
  const prises = path.join(base, "prise");
  const donnees = path.join(base, "donnees");
  for (const d of [prises, donnees]) {
    fs.mkdirSync(d, { mode: 0o750 });
    fs.chmodSync(d, 0o750);
  }
  const config = { version: 0, prise: path.join(prises, "agent.sock"), interface_uid: process.getuid(), donnees, nature: "developpement", instance: null, rpc: [...POINTS], jeton: null, comptes: { exploitant: "hardhat:0" }, delai_s: 120 };
  const chemin = path.join(base, "agent.json");
  fs.writeFileSync(chemin, JSON.stringify(config, null, 2));
  const p = spawn(process.execPath, [BIN_AGENT, "--config", chemin], { cwd: RACINE, stdio: ["ignore", "pipe", "pipe"] });
  let sortie = "";
  let erreurs = "";
  p.stderr.on("data", (d) => (erreurs += d));
  await new Promise((resolve, reject) => {
    p.stdout.on("data", (d) => {
      sortie += d;
      if (sortie.includes("\n")) resolve();
    });
    p.on("exit", (code) => reject(new Error(`l'agent d'inscription s'est arrêté (code ${code}) : ${erreurs.slice(-500)}`)));
  });
  p.removeAllListeners("exit");
  return {
    donnees,
    client: (slug) => ({ dir: path.join(donnees, "clients", slug), dossier: path.join(donnees, "clients", slug, "dossier.json"), captures: path.join(donnees, "clients", slug, "captures") }),
    async executer(travail) {
      let t;
      for (let i = 0; i < 20; i += 1) {
        const r = await remettre(config.prise, { version: 0, kind: "travail", exploitant: EXPLOITANT, travail });
        if (!r.accepte) throw new Error(`travail ${travail.commande} refusé par l'agent : ${JSON.stringify(r)}`);
        const limite = Date.now() + 300000;
        for (;;) {
          try {
            t = JSON.parse(fs.readFileSync(path.join(donnees, "travaux", `${r.id}.json`), "utf8"));
            if (["fini", "refuse", "abandonne"].includes(t.etat)) break;
          } catch {
            // en cours d'écriture
          }
          if (Date.now() > limite) throw new Error(`travail ${travail.commande} non terminé`);
          await new Promise((ok) => setTimeout(ok, 100));
        }
        if (t.sortie?.error?.code !== "noeud_suiveur") return t;
        await new Promise((ok) => setTimeout(ok, 500));
      }
      return t;
    },
    confirmation: (c) => remettre(config.prise, { version: 0, kind: "confirmation", exploitant: EXPLOITANT, confirmation: c }),
    async arreter() {
      if (p.exitCode !== null || p.signalCode !== null) return;
      const fin = new Promise((ok) => p.once("exit", ok));
      p.kill("SIGTERM");
      await fin;
    },
  };
}

const attendu = (t, quoi) => {
  if (t.etat !== "fini" || t.sortie?.result !== "reussi") throw new Error(`${quoi} : ${JSON.stringify({ etat: t.etat, motif: t.motif ?? null, error: t.sortie?.error ?? null })}`);
  return t.sortie;
};

/**
 * Préalables du registre (EX-8.2) : organisation `slug` inscrite par l'agent
 * (jeu de trois approbateurs, comptes 1 à 3, seuil 2, administrateur du jeu
 * compte 4), journal d'essai et première période (CT-4 §7.8), paquet client
 * produit et contrôlé (EX-7.22).
 * @param {{travail: string, slug: string, consoleOrigin: string, administrateurs: string[], journal?: (t: string) => void}} o
 */
export async function inscrireOrganisation({ travail, slug, consoleOrigin, administrateurs, journal = () => {} }) {
  const base = path.join(travail, "inscription");
  fs.mkdirSync(base, { recursive: true, mode: 0o700 });
  const cles = path.join(base, "cles");
  fs.mkdirSync(cles, { mode: 0o700 });
  const nomJournalEssai = "journal-essai";
  const graine = deriver(`${slug}/rec-essai-01/ed25519`);
  const chaineOctets = deriver(`${slug}/rec-essai-01/chaine`);
  const chaine = SignataireChaineFichier.depuisOctets(chaineOctets);
  const fichierGraine = path.join(cles, "rec-essai-01.graine");
  const fichierChaine = path.join(cles, "cle-chaine-rec-essai-01.cle");
  fs.writeFileSync(fichierGraine, N.octetsVersHex(graine).slice(2), { mode: 0o600 });
  fs.writeFileSync(fichierChaine, N.octetsVersHex(chaineOctets).slice(2), { mode: 0o600 });
  const essai = { keyId: "rec-essai-01", journalId: N.octetsVersHex(N.keccak256(N.utf8(nomJournalEssai))), publique: N.octetsVersHex(N.clePubliqueEd25519(graine)) };
  const baseAgent = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "nt-agent-"));
  const agent = await demarrerAgent(baseAgent);
  try {
    const cl = agent.client(slug);
    const membres = [1, 2, 3].map((i) => compte(i).adresse);
    let t = await agent.executer({
      commande: "inscrire-client-preparer", slug,
      parametres: {
        org: slug, journaux: [nomJournalEssai], approbateurs: membres, seuil: 2, admin_jeu: compte(4).adresse,
        cles_enregistreur: [{
          key_id: essai.keyId, journal_id: essai.journalId, algorithm: "ed25519", public_key: essai.publique, custody_class: "D", backend_type: "fichier",
          created_at: N.ecrireHorodatage(Date.now()), chain_key: chaine.adresse(), chain_key_class: "D", origin_proof: null,
        }],
      },
    });
    const orgId = attendu(t, "inscrire-client --preparer").outputs.org_id;
    journal(`dossier préparé, org_id ${orgId}`);
    const c = await agent.confirmation({
      operation: "approvisionnement", objet: { org_id: orgId, cle_chaine: chaine.adresse() }, personne_client: "Responsable du client fictif (banc)",
      canal: "appel au numéro du contrat", instant: N.ecrireHorodatage(Date.now()), piece_sha256: N.sha256Hex(N.utf8(`piece ${slug} ${essai.keyId}`)),
    });
    if (!c.accepte) throw new Error(`confirmation refusée : ${JSON.stringify(c)}`);
    attendu(await agent.executer({ commande: "inscrire-client", slug, parametres: {} }), "inscrire-client (jeu, assignation, lecture, approvisionnement)");
    journal("jeu d'approbateurs déployé, assigné et lu ; clé de chaîne d'essai approvisionnée");
    t = await agent.executer({ commande: "condense-inscription", slug, parametres: { key_id: essai.keyId } });
    const signee = signerDemande(JSON.parse(fs.readFileSync(attendu(t, "condense inscription").outputs.demande, "utf8")), [1, 2]);
    attendu(await agent.executer({ commande: "inscrire-cle", slug, parametres: { demande: signee, cle_chaine: `fichier:${fichierChaine}` } }), "inscrire-cle (journal d'essai)");
    const periode = path.join(cl.dir, "periode-1");
    const cloture = path.join(base, "demande-cloture-1.json");
    for (const e of [
      ["manifeste-essai", "--dossier", cl.dossier, "--key-id", essai.keyId, "--graine", `graine:${fichierGraine}`, "--sortie", periode],
      ["ancrer", "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", `fichier:${fichierChaine}`, "--dossier", cl.dossier, "--captures", cl.captures],
      ["condense", "cloture", "--manifeste", path.join(periode, "manifeste.json"), "--captures", cl.captures, "--sortie", cloture],
      ["signer", "--demande", cloture, "--cle", "hardhat:1"],
      ["signer", "--demande", cloture, "--cle", "hardhat:3"],
      ["clore", "--demande", cloture, "--manifeste", path.join(periode, "manifeste.json"), "--cle-chaine", `fichier:${fichierChaine}`, "--dossier", cl.dossier, "--captures", cl.captures],
    ]) {
      const r = await outilRegistre(e);
      if (r.sortie?.result !== "reussi") throw new Error(`première période (${e[0]}) : ${JSON.stringify(r.sortie?.error ?? null)} ${r.err.slice(-300)}`);
    }
    journal("première période du journal d'essai ancrée et close (CT-4 §7.8)");
    t = await agent.executer({ commande: "paquet", slug, parametres: { prepared_by: "exploitant NOORTRACE du banc client fictif", console_origin: consoleOrigin, administrators: administrateurs } });
    const repertoirePaquet = attendu(t, "paquet client").outputs.directory;
    const controle = controlerPaquet(repertoirePaquet);
    if (!controle.valide) throw new Error(`paquet client refusé au contrôle d'EX-7.22 : ${JSON.stringify(controle.ecarts)}`);
    const paquet = path.join(travail, "paquet-client");
    fs.cpSync(repertoirePaquet, paquet, { recursive: true });
    const lire = (n) => JSON.parse(fs.readFileSync(path.join(paquet, n), "utf8"));
    journal(`paquet client produit et contrôlé (${path.basename(repertoirePaquet)})`);
    const deploiement = JSON.parse(fs.readFileSync(path.join(RACINE, "deployments", "noorcore.json"), "utf8"));
    return {
      slug, orgId, membres, seuil: 2,
      approbateurs: [1, 2, 3].map((i) => SignataireChaineFichier.depuisOctets(compte(i).cle)),
      contrats: {
        attestation_registry: deploiement.contrats.AttestationRegistry.adresse.toLowerCase(),
        period_registry: deploiement.contrats.PeriodRegistry.adresse.toLowerCase(),
        recorder_registry: deploiement.contrats.RecorderRegistry.adresse.toLowerCase(),
      },
      validators: JSON.parse(fs.readFileSync(path.join(RACINE, "chain", "runtime", "validators.json"), "utf8")).validators,
      paquet: { repertoire: paquet, controle, jeu: lire("jeu-approbateurs.json"), gabarit: lire("gabarit-service-approbation.json"), manifeste: lire("paquet-client.json") },
      dossier: cl.dossier,
      inscriptionEssai: signee,
      baseAgent,
    };
  } finally {
    await agent.arreter();
  }
}

/**
 * IC-13 (CT-4 §8.7) : inscription de la clé d'enregistreur du journal de
 * production et de sa clé de chaîne sous l'organisation, par l'outil de
 * référence en boîte noire ; la demande est signée hors de l'outil par les
 * comptes 1 et 2 du jeu (approbateurs). La clé de chaîne est donnée en
 * `fichier:` le temps de l'envoi (réseau de développement, CT-4 EX-7.3).
 * Rend les commandes et leurs sorties.
 */
export async function inscrireCleJournal({ rep, orgId, journalId, adresseChaine, fichierScalaire, clePubliqueEd25519 }) {
  fs.mkdirSync(rep, { recursive: true, mode: 0o700 });
  const demande = path.join(rep, "demande-inscription.json");
  const captures = path.join(rep, "captures");
  const sorties = [];
  let r = await outilRegistre(["condense", "inscription", "--org-id", orgId, "--journal-id", journalId, "--cle-chaine-adresse", adresseChaine, "--cle-ed25519", clePubliqueEd25519, "--sortie", demande]);
  sorties.push({ commande: "noortrace-registre condense inscription", code: r.code, result: r.sortie?.result ?? null });
  if (r.sortie?.result !== "reussi") throw new Error(`condense inscription : ${JSON.stringify(r.sortie?.error ?? null)} ${r.err.slice(-300)}`);
  const signee = signerDemande(JSON.parse(fs.readFileSync(demande, "utf8")), [1, 2]);
  fs.writeFileSync(demande, JSON.stringify(signee, null, 2));
  sorties.push({ commande: "signatures des approbateurs 1 et 2 (hors de l'outil)", code: 0, result: "reussi" });
  for (const e of [
    ["approvisionner", "--vers", adresseChaine, "--demande", demande, "--tresorerie", "hardhat:0", "--captures", captures],
    ["inscrire-cle", "--demande", demande, "--cle-chaine", `fichier:${fichierScalaire}`, "--captures", captures],
  ]) {
    r = await outilRegistre(e);
    sorties.push({ commande: `noortrace-registre ${e[0]}`, code: r.code, result: r.sortie?.result ?? null });
    if (r.sortie?.result !== "reussi") throw new Error(`${e[0]} : ${JSON.stringify(r.sortie?.error ?? null)} ${r.err.slice(-300)}`);
  }
  return { demande: signee, sorties };
}
