// File d'attente durable (CT-5 EX-8.5, lot C) : `file-<epoch>.ndjson` en
// ajout seul, JCS intégral d'une $defs/demande par ligne, `fdatasync` avant
// de rendre la main (règle 1, AN-32), une demande par id (règle 2), dernière
// ligne fait foi et ligne tronquée ignorée et signalée (règle 3), compaction
// optionnelle jamais sur le fichier courant (règle 5), fusion des époques
// (règle 6). Répertoires sous os.tmpdir() ; aucun essai n'exige le réseau.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { FileDurable, lireFiles, decoderFile, trierDemandes, fichiersDeFile, controlerDemande, nomFichierFile, estFinale, ETATS_FINAUX, TAILLE_MAX_LIGNE } from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPRISE = path.join(RACINE, "spec", "vecteurs", "ct-5", "reprise");
const lignes = (nom) => fs.readFileSync(path.join(REPRISE, nom), "utf8").split("\n").filter(Boolean);
const demandes = (nom) => lignes(nom).map((l) => JSON.parse(l));

describe("ancrage, planificateur : file d'attente durable (EX-8.5)", function () {
  let dir;
  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-planificateur-file-"));
  });
  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("règle 1 : ecrire ajoute la forme canonique JCS intégral suivie d'un saut de ligne et synchronise avant de rendre la main", function () {
    const file = FileDurable.ouvrir({ repertoire: path.join(dir, "file"), epoque: 7 });
    expect(path.basename(file.chemin)).to.equal("file-7.ndjson");
    const d = demandes("redemarrage-reprise.avant.ndjson");
    const r1 = file.ecrire(d[0]);
    const r2 = file.ecrire({ ...d[0], state: "envoyee" });
    file.fermer();
    const contenu = fs.readFileSync(file.chemin, "utf8");
    expect(contenu).to.equal(N.jcs(d[0]) + "\n" + N.jcs({ ...d[0], state: "envoyee" }) + "\n");
    expect(r1.octets + r2.octets).to.equal(Buffer.byteLength(contenu));
    expect(fs.statSync(path.join(dir, "file")).mode & 0o777).to.equal(0o700);
    expect(() => file.ecrire(d[0])).to.throw(/fermée/);
  });

  it("règle 1 : une demande hors de $defs/demande n'est jamais écrite (clé en trop, état hors énumération, id mal formé)", function () {
    const file = FileDurable.ouvrir({ repertoire: dir, epoque: 1 });
    const d = demandes("redemarrage-reprise.avant.ndjson")[0];
    expect(() => file.ecrire({ ...d, secret: "x" })).to.throw(TypeError);
    expect(() => file.ecrire({ ...d, state: "perdue" })).to.throw(TypeError);
    expect(() => file.ecrire({ ...d, id: "jeton_point:abc" })).to.throw(TypeError);
    expect(() => file.ecrire({ ...d, deadlines: [1, 1] })).to.throw(TypeError);
    expect(() => file.ecrire({ ...d, created_at: "2026-11-03T14:00:00Z" })).to.throw(TypeError);
    expect(() => controlerDemande(null)).to.throw(TypeError);
    file.fermer();
    expect(fs.readFileSync(file.chemin, "utf8")).to.equal("");
  });

  it("règle 3 : la dernière ligne d'un id fait foi et l'ordre rendu est celui de la première apparition", function () {
    fs.copyFileSync(path.join(REPRISE, "bascule-epoque.epoque-1.ndjson"), path.join(dir, "file-1.ndjson"));
    const r = lireFiles(dir);
    expect(r.tronquees).to.deep.equal([]);
    expect(r.demandes).to.have.lengthOf(6);
    expect(r.demandes.map((d) => d.state)).to.deep.equal(["obtenue", "obtenue", "obtenue", "envoyee", "attente_registre", "en_attente"]);
    const parId = new Map(demandes("bascule-epoque.epoque-1.ndjson").map((d) => [d.id, d]));
    expect(r.demandes.map((d) => N.jcs(d))).to.deep.equal([...parId.values()].map((d) => N.jcs(d)));
  });

  it("règle 3 : une ligne tronquée en fin de fichier est ignorée et signalée, jamais réparée ; les lignes précédentes restent lues", function () {
    const texte = lignes("registre-indisponible.avant.ndjson");
    fs.writeFileSync(path.join(dir, "file-1.ndjson"), texte.join("\n") + "\n" + texte[0].slice(0, 120));
    const r = lireFiles(dir);
    expect(r.demandes).to.have.lengthOf(2);
    expect(r.tronquees).to.deep.equal([{ fichier: "file-1.ndjson", ligne: 3, raison: "ligne_tronquee" }]);
    expect(fs.readFileSync(path.join(dir, "file-1.ndjson"), "utf8").endsWith(texte[0].slice(0, 120))).to.equal(true);
  });

  it("lignes hostiles : vide, non canonique, non conforme, JSON invalide, trop longue, profondeur excessive ; chacune signalée par fichier et numéro", function () {
    const bonne = lignes("registre-indisponible.avant.ndjson")[0];
    const objet = JSON.parse(bonne);
    const nonCanonique = JSON.stringify(objet, null, 1).replace(/\n\s*/g, " ");
    const nonConforme = N.jcs({ ...objet, state: "inconnu" });
    const invalide = "{\"id\":";
    const longue = N.jcs({ ...objet, attempts: [{ ...objet.attempts[0], detail: "x".repeat(TAILLE_MAX_LIGNE) }] });
    let profonde = "[";
    for (let i = 0; i < 200; i++) profonde += "[";
    profonde += "]".repeat(201);
    fs.writeFileSync(path.join(dir, "file-3.ndjson"), [bonne, "", nonCanonique, nonConforme, invalide, longue, profonde, bonne].join("\n") + "\n");
    const r = lireFiles(dir);
    expect(r.demandes).to.have.lengthOf(1);
    expect(r.tronquees.map((t) => [t.ligne, t.raison])).to.deep.equal([
      [2, "ligne_vide"],
      [3, "forme_non_canonique"],
      [4, "demande_non_conforme"],
      [5, "json_syntaxe"],
      [6, "ligne_trop_longue"],
      [7, "json_profondeur"],
    ]);
  });

  it("une ligne en UTF-8 mal formé ou avec une clé en double est illisible et signalée", function () {
    const bonne = lignes("registre-indisponible.avant.ndjson")[0];
    fs.writeFileSync(path.join(dir, "file-1.ndjson"), Buffer.concat([Buffer.from(bonne.replace("transaction envoyee", "transaction é"), "utf8").subarray(0, -3), Buffer.from([0xff, 0x22, 0x7d, 0x5d, 0x7d, 0x0a])]));
    fs.appendFileSync(path.join(dir, "file-1.ndjson"), "{\"version\":0,\"version\":0}\n");
    const r = lireFiles(dir);
    expect(r.demandes).to.deep.equal([]);
    expect(r.tronquees).to.have.lengthOf(2);
    for (const t of r.tronquees) expect(t.raison).to.match(/^json_/);
  });

  it("règle 6 : tous les fichiers file-*.ndjson sont relus dans l'ordre des époques, les compactions après leur original, les autres noms ignorés", function () {
    fs.copyFileSync(path.join(REPRISE, "bascule-epoque.epoque-2.ndjson"), path.join(dir, "file-2.ndjson"));
    fs.copyFileSync(path.join(REPRISE, "bascule-epoque.epoque-1.ndjson"), path.join(dir, "file-1.ndjson"));
    fs.writeFileSync(path.join(dir, "file-10.ndjson"), "");
    fs.writeFileSync(path.join(dir, "autre.ndjson"), lignes("file-pleine.avant.ndjson")[0] + "\n");
    fs.writeFileSync(path.join(dir, "file-1.1.compact.ndjson"), "");
    fs.writeFileSync(path.join(dir, "file-abc.ndjson"), "x\n");
    const r = lireFiles(dir);
    expect(fichiersDeFile(dir).map((f) => f.nom)).to.deep.equal(["file-1.ndjson", "file-1.1.compact.ndjson", "file-2.ndjson", "file-10.ndjson"]);
    expect(r.demandes.map((d) => N.jcs(d))).to.deep.equal(lignes("bascule-epoque.avant.ndjson"));
    expect(lireFiles(path.join(dir, "absent")).demandes).to.deep.equal([]);
  });

  it("règle 5 : la compaction d'une époque antérieure ne garde que la dernière ligne de chaque id, refuse le fichier courant et une demande active", function () {
    fs.copyFileSync(path.join(REPRISE, "bascule-epoque.epoque-2.ndjson"), path.join(dir, "file-2.ndjson"));
    expect(() => FileDurable.compacter(dir, 2, { courante: 2 })).to.throw(/fichier courant/);
    const r = FileDurable.compacter(dir, 2, { courante: 3 });
    expect(path.basename(r.chemin)).to.equal("file-2.1.compact.ndjson");
    expect(r.demandes).to.equal(2);
    expect(fs.readFileSync(r.chemin, "utf8").split("\n").filter(Boolean)).to.have.lengthOf(2);
    expect(fs.existsSync(path.join(dir, "file-2.ndjson"))).to.equal(true);
    expect(lireFiles(dir).demandes).to.have.lengthOf(2);
    expect(() => FileDurable.compacter(dir, 2, { courante: 3 })).to.throw(/EEXIST|exists/);
    fs.copyFileSync(path.join(REPRISE, "bascule-epoque.epoque-1.ndjson"), path.join(dir, "file-1.ndjson"));
    expect(() => FileDurable.compacter(dir, 1, { courante: 3 })).to.throw(/n'est pas finale/);
  });

  it("outils : tri par created_at puis id, états finaux, nom de fichier, décodage d'octets", function () {
    const d = demandes("heure-nominale-reference.apres.ndjson".replace("heure-nominale-reference", "registre-indisponible"));
    const melange = [...d].reverse();
    expect(trierDemandes(melange).map((x) => x.id)).to.deep.equal(d.map((x) => x.id));
    expect(ETATS_FINAUX).to.deep.equal(["obtenue", "complete", "sans_objet", "refusee", "remplacee"]);
    expect(estFinale({ state: "a_reprendre" })).to.equal(false);
    expect(nomFichierFile(12n)).to.equal("file-12.ndjson");
    expect(() => nomFichierFile(-1)).to.throw(RangeError);
    expect(() => nomFichierFile("1")).to.throw(RangeError);
    const dec = decoderFile(Buffer.from(lignes("file-pleine.avant.ndjson").join("\n") + "\n"));
    expect(dec.lignes).to.have.lengthOf(100);
    expect(dec.tronquees).to.deep.equal([]);
  });

  it("le répertoire est créé s'il manque et le fichier ouvert en ajout seul (une seconde ouverture n'écrase rien)", function () {
    const rep = path.join(dir, "a", "b");
    const f1 = FileDurable.ouvrir({ repertoire: rep, epoque: 1 });
    const d = demandes("registre-indisponible.avant.ndjson");
    f1.ecrire(d[0]);
    f1.fermer();
    const f2 = FileDurable.ouvrir({ repertoire: rep, epoque: 1, fdatasync: false });
    f2.ecrire(d[1]);
    f2.fermer();
    expect(f2.lire().demandes.map((x) => x.id)).to.deep.equal([d[0].id, d[1].id]);
    expect(() => FileDurable.ouvrir({ repertoire: "", epoque: 1 })).to.throw(TypeError);
  });
});
