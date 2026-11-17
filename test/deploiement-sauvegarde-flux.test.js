// Sauvegarde d'un journal écrite en flux (CT-8 §11.2, EX-11.1 à EX-11.4 ;
// décision du porteur du 2026-11-16 : l'archive est écrite en flux, la
// mémoire de `sauvegarde.mjs creer` ne croît plus avec la taille du journal).
//
// - Mêmes octets qu'avant : sur chaque journal des vecteurs de CT-8 que
//   `creer` accepte, l'archive est celle de la bibliothèque appliquée au
//   journal entier (`inventaire` puis `ecrireArchive`, le chemin de l'outil
//   avant l'écriture en flux), octet pour octet, et le procès-verbal porte
//   les mêmes longueurs et SHA-256 ; un segment en cours d'écriture est
//   gardé jusqu'à sa dernière fin de ligne, comme avant.
// - Mémoire bornée : `creer` est joué dans un processus à part sur un journal
//   de 96 Mio (vingt-quatre pièces de 4 Mio) ; son pic de mémoire résidente
//   (`maxRSS`, ce processus seul, les outils qu'il lance exclus) dépasse de
//   moins de 32 Mio celui de la sauvegarde du journal des vecteurs, plus
//   petit que la borne. Avant l'écriture en flux, il le dépassait de plus de
//   trois fois la taille du journal.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import * as S from "../scripts/lib/sauvegarde.mjs";
import { RACINE } from "../scripts/lib/deploiement.mjs";

const OUTIL = path.join(RACINE, "scripts", "deploiement", "sauvegarde.mjs");
const JOURNAUX = path.join(RACINE, "spec", "vecteurs", "ct-8", "journaux");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const DATE = "2026-11-12T01:30:00.000Z";
const MTIME = Date.parse(DATE) / 1000;
const BORNE = 32 * 1024 * 1024;

const sha = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");

function copieJournal(nom, vers) {
  fs.cpSync(path.join(JOURNAUX, nom), vers, { recursive: true });
  for (const f of ["attendu.json", "cles.json"]) fs.rmSync(path.join(vers, f), { force: true });
  return vers;
}

/** `creer` dans un processus à part ; rend le code, la sortie d'erreur et le pic de mémoire résidente (octets) de ce processus. */
function creerMesure(journal, cles, archive, pv) {
  const script = [
    `const { principal } = await import(${JSON.stringify(pathToFileURL(OUTIL).href)});`,
    "let err = '';",
    `const code = principal(${JSON.stringify(["creer", "--journal", journal, "--cles", cles, "--archive", archive, "--pv", pv, "--id", "pv-2026-11-12-001", "--executant", "tache-sauvegarde", "--motif", "sauvegarde en flux", "--source", "volume d'essai", "--destination", "archive d'essai", "--date", DATE])}, { stdout: { write() {} }, stderr: { write: (t) => { err += t; } } });`,
    "process.stdout.write(JSON.stringify({ code, err, maxRSS: process.resourceUsage().maxRSS * 1024 }));",
  ].join("\n");
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8", cwd: RACINE, maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`processus de mesure : code ${r.status} ${r.stderr}`);
  return JSON.parse(r.stdout);
}

let TRAVAIL;
before(function () {
  TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-sauvegarde-flux-"));
});
after(function () {
  if (TRAVAIL) fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

describe("CT-8 §11.2, EX-11.1 : sauvegarde.mjs creer écrit l'archive en flux (décision du porteur du 2026-11-16)", function () {
  this.timeout(300000);

  it("EX-11.2, EX-13.13, EX-13.14 : sur chaque journal des vecteurs de CT-8 que creer accepte, l'archive est octet pour octet celle d'inventaire puis ecrireArchive (le chemin d'avant), et le procès-verbal porte leurs longueurs et SHA-256 ; un segment en cours d'écriture est gardé jusqu'à sa dernière fin de ligne", function () {
    const acceptes = [];
    for (const nom of fs.readdirSync(JOURNAUX).sort()) {
      const rep = path.join(TRAVAIL, `identite-${nom}`);
      fs.mkdirSync(rep);
      const journal = copieJournal(nom, path.join(rep, "journal"));
      const partiel = nom === "valide-deux-segments";
      if (partiel) {
        const seg = fs.readdirSync(path.join(journal, "segments")).sort().at(-1);
        fs.appendFileSync(path.join(journal, "segments", seg), '{"seq":99,"partiel');
      }
      const r = creerMesure(journal, path.join(JOURNAUX, nom, "cles.json"), path.join(rep, "a.tar"), path.join(rep, "pv.json"));
      if (r.code !== 0) {
        expect(fs.existsSync(path.join(rep, "a.tar")), `${nom} : archive laissée après un refus`).to.equal(false);
        continue;
      }
      acceptes.push(nom);
      const { fichiers, tronques } = S.inventaire(journal);
      const attendue = S.ecrireArchive(fichiers, MTIME);
      const obtenue = fs.readFileSync(path.join(rep, "a.tar"));
      expect(obtenue.equals(attendue), `${nom} : archive différente de celle d'avant`).to.equal(true);
      const pv = JSON.parse(fs.readFileSync(path.join(rep, "pv.json"), "utf8"));
      expect(pv.files, nom).to.deep.equal(fichiers.map((f) => ({ path: f.path, length: f.octets.length, sha256_source: sha(f.octets), sha256_destination: sha(f.octets) })));
      expect(pv.totals, nom).to.deep.equal({ files: fichiers.length, bytes: fichiers.reduce((s, f) => s + f.octets.length, 0) });
      if (partiel) expect(tronques.length).to.equal(1);
      expect(pv.observations, nom).to.equal(tronques.length ? `fichiers en cours d'écriture, gardés jusqu'à leur dernière fin de ligne : ${tronques.map((t) => `${t.path} (${t.retenu} octets sur ${t.length})`).join(", ")}` : null);
    }
    expect(acceptes).to.include.members(["valide", "valide-deux-segments", "valide-manifeste"]);
  });

  it("EX-11.1 : la mémoire de creer ne croît pas avec le journal : sur un journal de 96 Mio (vingt-quatre pièces de 4 Mio), le pic de mémoire résidente dépasse de moins de 32 Mio celui du journal des vecteurs, et l'archive reste celle d'avant", function () {
    const petit = path.join(TRAVAIL, "memoire-petit");
    fs.mkdirSync(petit);
    const cles = path.join(JOURNAUX, "valide-manifeste", "cles.json");
    const base = creerMesure(copieJournal("valide-manifeste", path.join(petit, "journal")), cles, path.join(petit, "a.tar"), path.join(petit, "pv.json"));
    expect(base.code, base.err).to.equal(0);
    const grand = path.join(TRAVAIL, "memoire-grand");
    fs.mkdirSync(grand);
    const journal = copieJournal("valide-manifeste", path.join(grand, "journal"));
    const pieces = path.join(journal, "ancres", "periode-1793865600", "rfc3161");
    fs.mkdirSync(pieces, { recursive: true });
    for (let i = 1; i <= 24; i++) fs.writeFileSync(path.join(pieces, `piece-${String(i).padStart(2, "0")}.der`), crypto.randomBytes(4 * 1024 * 1024));
    const r = creerMesure(journal, cles, path.join(grand, "a.tar"), path.join(grand, "pv.json"));
    expect(r.code, r.err).to.equal(0);
    const pv = JSON.parse(fs.readFileSync(path.join(grand, "pv.json"), "utf8"));
    expect(pv.totals.bytes).to.be.above(96 * 1024 * 1024);
    const ecart = r.maxRSS - base.maxRSS;
    expect(ecart, `pic de mémoire : ${Math.round(r.maxRSS / 1048576)} Mio contre ${Math.round(base.maxRSS / 1048576)} Mio pour le journal des vecteurs`).to.be.below(BORNE);
    const attendue = S.ecrireArchive(S.inventaire(journal).fichiers, MTIME);
    expect(fs.readFileSync(path.join(grand, "a.tar")).equals(attendue)).to.equal(true);
  });
});
