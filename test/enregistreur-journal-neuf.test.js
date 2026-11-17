// CT-8 §11.4, chemin C (TE-9) : reprise dans un journal neuf quand la clé
// courante est inutilisable (CT-2 EX-11.16). L'ancien journal (période close,
// période ouverte) est produit par le cœur réel, puis sa clé est perdue ; un
// nouveau journal (`journal_id` distinct, nouvelle clé, `seq = 1`) est ouvert
// par un second cœur. La demande d'inscription du nouveau journal (CT-4 §7.7,
// §8.4) est préparée hors ligne et signée au seuil par l'outil de référence
// du registre (`signer`, sans réseau) ; son relais au registre (pas 5) se
// joue sur le réseau 2124 (test/enregistreur-journal-neuf-registre.test.js). `noortrace-ctl journal
// successeur` écrit le lien (note d'exploitant à côté de la demande, ligne
// `journal_successor` du journal d'exploitation de l'ancien démon) ;
// `noortrace-ctl journal verifier-successeur` le retrouve et le contrôle
// contre la fin réelle de l'ancien journal, que l'outil de référence de CT-8
// EX-11.7 (`verifier-journal.mjs`) établit de son côté ; des mutants (fin
// faussée dans la note ou dans la ligne, demande d'un autre journal) sont
// refusés.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import { lireEvenements } from "@noortrace/enregistreur";
import { condenseInscription } from "../scripts/lib/conventions-registre.mjs";
import { RACINE, configurationDev, graine } from "./fixtures/enregistreur-coeur/outils.mjs";
import { construireJournal, ctl, repertoireTemporaire } from "./fixtures/enregistreur-export/outils.mjs";
import { valider, demarrerCoeur } from "./fixtures/enregistreur-modele/outils.mjs";
import { outilReference } from "./fixtures/inscription/outils.mjs";

const lireJSON = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const NOUVEAU_JOURNAL = N.octetsVersHex(N.sha256(N.utf8("noortrace/essais/te-9/journal-neuf")));

/** Fichier de clés (cles.json de CT-1) d'une clé d'essai des outils du cœur. */
function clesEssai(chemin, org, journal, keyId) {
  const cles = { version: 0, org_id: org, journal_id: journal, keys: [{ key_id: keyId, algorithm: "ed25519", public_key: N.octetsVersHex(N.clePubliqueEd25519(graine(keyId))), valid_from: "2026-01-01T00:00:00.000Z", valid_to: null, source: `clé d'essai ${keyId} des outils du cœur, sans valeur hors des tests` }] };
  fs.writeFileSync(chemin, JSON.stringify(cles, null, 2) + "\n");
  return chemin;
}

function verifierJournalReference(rep, cles) {
  const r = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "verifier-journal.mjs"), rep, "--cles", cles, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status, rapport: JSON.parse(r.stdout) };
}

/**
 * Demande `demande_signature` d'inscription du nouveau journal (CT-4 §7.7),
 * préparée hors ligne : condensé RG-7 recalculé par la référence ; contrat,
 * clé de chaîne et jeu d'approbateurs synthétiques, comme l'exemple de CT-4
 * §7.7 ; aucune signature.
 */
function demandeInscription(org, journal, keyId) {
  const base = {
    chain_id: 2124,
    contract: "0xbec49fa140acaa83533fb00a2bb19bddd0290f25",
    org_id: org,
    journal_id: journal,
    chain_key: "0xaf1056f6fd93594a0a71c87d3b18723232c61714",
    ed25519_public_key: N.octetsVersHex(N.clePubliqueEd25519(graine(keyId))),
  };
  const c = condenseInscription(base);
  return {
    version: 0,
    operation: "inscription",
    evm_chain_id: base.chain_id,
    contract: base.contract,
    fields: { org_id: base.org_id, journal_id: base.journal_id, chain_key: base.chain_key, ed25519_public_key: base.ed25519_public_key },
    digest: c.digest,
    eip191_digest: c.eip191_digest,
    signer_set: { curator_set: "0xa1a165880c7af8f1150efa652507ebe9561b73bd", threshold: 2, height: 20009, block_hash: "0x9d677845e821a226f80370d906f8f6a3b915fa0d4893623dba9c8de6804169b3" },
    signatures: [],
    prepared_at: "2026-11-16T08:00:00.000Z",
  };
}

describe("CT-8 §11.4 chemin C (TE-9) : reprise dans un journal neuf, lien consigné au registre et au journal d'exploitation, contrôlé contre la fin réelle de l'ancien journal (CT-2 EX-11.16)", function () {
  this.timeout(300000);
  let dir;
  let ancien;
  let demande;
  let cles;

  before(async function () {
    dir = repertoireTemporaire("noortrace-journal-neuf-");
    const dirA = path.join(dir, "ancien");
    fs.mkdirSync(dirA);
    ancien = await construireJournal(dirA);
    cles = clesEssai(path.join(dir, "cles-ancien.json"), ancien.config.recorder.org_id, ancien.config.recorder.journal_id, "rec-test-01");
  });

  after(async function () {
    await ancien?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("ancien journal clos puis clé perdue ; nouveau journal (journal_id distinct, nouvelle clé, seq = 1) ; demande d'inscription signée au seuil hors ligne ; lien écrit (note d'exploitant, ligne journal_successor) puis retrouvé et contrôlé : last_seq et last_hash égaux à la fin réelle", async function () {
    // Ancien journal : période P close (manifeste), période ouverte ; puis la clé est perdue.
    expect(fs.existsSync(path.join(ancien.repertoire, "manifestes", `periode-${String(ancien.P).padStart(10, "0")}.json`))).to.equal(true);
    fs.rmSync(ancien.config.signer.backend.path);
    const fin = (await lireEvenements(ancien.repertoire)).at(-1);
    const ref = verifierJournalReference(ancien.repertoire, cles);
    expect(ref.code).to.equal(0);
    expect([ref.rapport.last_seq, ref.rapport.last_hash]).to.deep.equal([fin.seq, fin.hash]);

    // Nouveau journal : nouvelle clé rec-test-02, journal_id distinct, premier événement seq 1.
    const dirN = path.join(dir, "nouveau");
    fs.mkdirSync(dirN);
    const { config: brut, env } = configurationDev(dirN, { journal_id: NOUVEAU_JOURNAL });
    brut.signer.key_id = "rec-test-02";
    brut.signer.backend.path = path.join(dirN, "cles", "rec-test-02.pem");
    brut.signer.rotation.next_key_id = null;
    const v = valider(brut, env);
    const { coeur } = await demarrerCoeur(v.config, v.secrets);
    const repN = coeur.repertoire;
    await coeur.arreter();
    const premiers = await lireEvenements(repN);
    expect(premiers[0]).to.deep.include({ seq: 1, journal_id: NOUVEAU_JOURNAL, recorder_key_id: "rec-test-02", prev_hash: N.ZERO32 });
    expect(verifierJournalReference(repN, clesEssai(path.join(dir, "cles-nouveau.json"), v.config.recorder.org_id, NOUVEAU_JOURNAL, "rec-test-02")).code).to.equal(0);

    // Demande d'inscription du nouveau journal, signée au seuil (2) par l'outil de référence, hors ligne.
    demande = path.join(dir, "registre", `demande-inscription-0xaf1056f6fd93594a0a71c87d3b18723232c61714.json`);
    fs.mkdirSync(path.dirname(demande));
    fs.writeFileSync(demande, `${JSON.stringify(demandeInscription(ancien.config.recorder.org_id, NOUVEAU_JOURNAL, "rec-test-02"), null, 2)}\n`);
    for (const i of [1, 2]) {
      const s = await outilReference(["signer", "--demande", demande, "--cle", `hardhat:${i}`]);
      expect(s.sortie?.result, s.err).to.equal("reussi");
    }
    expect(lireJSON(demande).signatures).to.have.lengthOf(2);

    // Lien écrit par l'exploitant.
    const r = await ctl(["journal", "successeur", "--configuration", ancien.cheminConfig, "--demande", demande]);
    expect(r.code, r.stderr).to.equal(0);
    expect(r.ligne).to.deep.include({ command: "journal successeur", result: "fait" });
    const lien = { old_journal_id: ancien.config.recorder.journal_id, last_seq: fin.seq, last_hash: fin.hash, new_journal_id: NOUVEAU_JOURNAL };
    expect(r.ligne.link).to.deep.equal(lien);
    const note = lireJSON(demande.replace(/\.json$/, ".note-exploitant.json"));
    expect(note).to.deep.include({ version: 0, kind: "journal_successor", org_id: ancien.config.recorder.org_id, ...lien, registration_digest: lireJSON(demande).digest });
    const lignes = fs.readFileSync(ancien.journal, "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((l) => l.event === "journal_successor");
    expect(lignes).to.have.lengthOf(1);
    expect(lignes[0]).to.deep.include({ level: "info", component: "noyau", org_id: ancien.config.recorder.org_id, journal_id: ancien.config.recorder.journal_id, seq: null });
    expect(lignes[0].data).to.deep.equal(lien);
    // La demande reste conforme pour l'outil de référence : le lien n'en change ni la forme ni le condensé.
    const s3 = await outilReference(["signer", "--demande", demande, "--cle", "hardhat:3"]);
    expect(s3.sortie?.result, s3.err).to.equal("reussi");

    // Rejouée, la commande n'écrit rien de plus.
    const r2 = await ctl(["journal", "successeur", "--configuration", ancien.cheminConfig, "--demande", demande]);
    expect(r2.code, r2.stderr).to.equal(0);
    expect(r2.ligne.result).to.equal("deja_fait");
    expect(fs.readFileSync(ancien.journal, "utf8").split("\n").filter((l) => l.includes('"journal_successor"'))).to.have.lengthOf(1);

    // Contrôle du lien, par la configuration ou par les seuls fichiers.
    for (const args of [["--configuration", ancien.cheminConfig], ["--journal", ancien.repertoire, "--journal-exploitation", ancien.journal]]) {
      const x = await ctl(["journal", "verifier-successeur", ...args, "--demande", demande]);
      expect(x.code, x.stdout + x.stderr).to.equal(0);
      expect(x.ligne).to.deep.include({ result: "lien_valide", link: lien });
      expect(x.ligne.checks.map((c) => [c.id, c.status])).to.deep.equal([["fin_ancien_journal", "reussi"], ["demande", "reussi"], ["note_exploitant", "reussi"], ["ligne_journal_exploitation", "reussi"]]);
    }
  });

  it("mutants refusés : last_hash faussé dans la note ou dans la ligne journal_successor, last_seq faussé, demande d'un autre journal ; lien différent déjà écrit ; ancien démon en marche", async function () {
    expect(demande, "lien écrit par l'essai précédent").to.be.a("string");
    const fichiers = ["--journal", ancien.repertoire, "--journal-exploitation", ancien.journal, "--demande", demande];
    const faux = `0x${"ab".repeat(32)}`;
    const noteVraie = lireJSON(demande.replace(/\.json$/, ".note-exploitant.json"));

    // Note dont last_hash est faussé.
    const noteFausse = path.join(dir, "note-fausse.json");
    fs.writeFileSync(noteFausse, JSON.stringify({ ...noteVraie, last_hash: faux }));
    let x = await ctl(["journal", "verifier-successeur", ...fichiers, "--note", noteFausse]);
    expect(x.code).to.equal(1);
    expect(x.ligne.result).to.equal("lien_invalide");
    expect(x.ligne.checks.find((c) => c.id === "note_exploitant")).to.deep.include({ status: "echec" });
    expect(x.ligne.checks.find((c) => c.id === "note_exploitant").detail).to.match(/last_hash/);

    // Note dont last_seq est faussé.
    fs.writeFileSync(noteFausse, JSON.stringify({ ...noteVraie, last_seq: noteVraie.last_seq - 1 }));
    x = await ctl(["journal", "verifier-successeur", ...fichiers, "--note", noteFausse]);
    expect(x.code).to.equal(1);
    expect(x.ligne.checks.find((c) => c.id === "note_exploitant").detail).to.match(/last_seq/);

    // Ligne journal_successor dont last_hash est faussé, à côté de la vraie : contradiction refusée.
    const opsMutant = path.join(dir, "exploitation-mutant.ndjson");
    const ligneVraie = fs.readFileSync(ancien.journal, "utf8").split("\n").find((l) => l.includes('"journal_successor"'));
    const ligneFausse = JSON.parse(ligneVraie);
    ligneFausse.data.last_hash = faux;
    fs.writeFileSync(opsMutant, `${ligneVraie}\n${JSON.stringify(ligneFausse)}\n`);
    x = await ctl(["journal", "verifier-successeur", "--journal", ancien.repertoire, "--journal-exploitation", opsMutant, "--demande", demande]);
    expect(x.code).to.equal(1);
    expect(x.ligne.checks.find((c) => c.id === "ligne_journal_exploitation")).to.deep.include({ status: "echec" });
    // Seule la ligne faussée : refusée de même.
    fs.writeFileSync(opsMutant, `${JSON.stringify(ligneFausse)}\n`);
    x = await ctl(["journal", "verifier-successeur", "--journal", ancien.repertoire, "--journal-exploitation", opsMutant, "--demande", demande]);
    expect(x.code).to.equal(1);
    expect(x.ligne.checks.find((c) => c.id === "ligne_journal_exploitation").status).to.equal("echec");

    // Demande d'inscription dont le journal_id est celui de l'ancien journal : refusée à l'écriture du lien.
    const autre = path.join(dir, "registre", "demande-meme-journal.json");
    fs.writeFileSync(autre, JSON.stringify(demandeInscription(ancien.config.recorder.org_id, ancien.config.recorder.journal_id, "rec-test-02")));
    x = await ctl(["journal", "successeur", "--configuration", ancien.cheminConfig, "--demande", autre]);
    expect(x.code).to.equal(1);
    expect(x.ligne.error.code).to.equal("demande_invalide");
    expect(fs.existsSync(autre.replace(/\.json$/, ".note-exploitant.json"))).to.equal(false);

    // Une autre demande (autre nouveau journal) quand un lien différent est déjà écrit : refusée, rien de remplacé.
    const autreNouveau = path.join(dir, "registre", "demande-autre-journal.json");
    fs.writeFileSync(autreNouveau, JSON.stringify(demandeInscription(ancien.config.recorder.org_id, N.octetsVersHex(N.sha256(N.utf8("autre journal"))), "rec-test-02")));
    x = await ctl(["journal", "successeur", "--configuration", ancien.cheminConfig, "--demande", autreNouveau]);
    expect(x.code).to.equal(1);
    expect(x.ligne.error.code).to.equal("successeur_existant");

    // Ancien démon encore en marche (processus `noortrace --config <ancienne configuration>`) : refusé.
    const proc = path.join(dir, "proc");
    fs.mkdirSync(path.join(proc, "424242"), { recursive: true });
    fs.writeFileSync(path.join(proc, "424242", "cmdline"), ["node", "/opt/noortrace/bin/noortrace", "--config", ancien.cheminConfig, ""].join("\0"));
    fs.symlinkSync(RACINE, path.join(proc, "424242", "cwd"));
    const { principalCtlJournal } = await import("@noortrace/enregistreur");
    const sortie = [];
    const io = { stdout: { write: (t) => sortie.push(String(t)) }, stderr: { write: () => {} }, racineProc: proc };
    expect(typeof principalCtlJournal).to.equal("function");
    expect(await principalCtlJournal(["successeur", "--configuration", ancien.cheminConfig, "--demande", demande], io)).to.equal(1);
    expect(JSON.parse(sortie.join("")).error.code).to.equal("demon_en_marche");
  });
});
