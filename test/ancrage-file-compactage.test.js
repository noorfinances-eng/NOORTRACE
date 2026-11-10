// File d'attente durable, révision 0.6 de CT-5 : lecture des lignes d'avant
// la révision et fenêtre de 32 tentatives vérifiée à l'écriture (EX-8.5,
// règle 7), compactage du fichier courant (EX-8.5, règle 5 : déclencheurs,
// procédé, échec, borne), relecture d'une file compactée et `.compactage`
// résiduel supprimé à l'ouverture (EX-8.12), aucun autre fichier supprimé
// (EX-8.14, EX-5.15). Horloge monotone injectée ; répertoires sous
// `os.tmpdir()`, supprimés après chaque essai ; aucun réseau.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as N from "@noortrace/noyau";
import { FileDurable, lireFiles, decoderFile, dernieresLignes, controlerDemande, validerLigneDemande, totalTentatives, FENETRE_TENTATIVES, COMPACT_BYTES_DEFAUT } from "@noortrace/ancrage/planificateur";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPRISE = path.join(RACINE, "spec", "vecteurs", "ct-5", "reprise");
const lignesVecteur = (nom) => fs.readFileSync(path.join(REPRISE, nom), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
/** Ligne `jeton_periode` à 32 tentatives (9 à 40) et `attempts_total` 40 de la trace file-fenetre-32-redemarrage. */
const MODELE = lignesVecteur("file-fenetre-32-redemarrage.avant.ndjson").find((d) => d.kind === "jeton_periode");

const hex32 = (i) => "0x" + N.octetsVersHex(N.sha256(N.utf8(`demande-${i}`))).slice(2);

/** Demande d'essai conforme, d'empreinte propre à `i`, portant les tentatives de `attempts` (rangs donnés). */
function demande(i, { state = "a_reprendre", rangs = null, total = undefined, kind = "jeton_periode" } = {}) {
  const d = structuredClone(MODELE);
  const hash = hex32(i);
  d.kind = kind;
  d.subject.hash = hash;
  d.id = `${kind}:${hash}`;
  d.state = state;
  if (rangs !== null) {
    const base = MODELE.attempts[0];
    d.attempts = rangs.map((n) => ({ ...structuredClone(base), n, correlation_id: `${kind}:${hash.slice(2, 18)}:${n}`, outcome: "echec_transitoire" }));
  }
  if (total === null) delete d.attempts_total;
  else d.attempts_total = total ?? Math.max(0, ...d.attempts.map((a) => a.n));
  return d;
}
const rangs = (de, a) => Array.from({ length: a - de + 1 }, (_, k) => de + k);

/** Horloge monotone réglable. */
function monotoneReglable() {
  let t = 0;
  const f = () => t;
  f.avancer = (ms) => {
    t += ms;
  };
  return f;
}

/** Journal en mémoire de la couche de fichier. */
function journalFile() {
  const lignes = [];
  const j = (niveau, evenement, champs) => lignes.push({ niveau, evenement, champs });
  j.lignes = lignes;
  j.de = (e) => lignes.filter((l) => l.evenement === e);
  return j;
}

/** État de la file : dernière ligne de chaque id, en JCS (règle 3). */
const etat = (repertoire) => {
  const r = lireFiles(repertoire);
  return Object.fromEntries([...r.parId.entries()].map(([id, d]) => [id, N.jcs(d)]));
};
const noms = (repertoire) => fs.readdirSync(repertoire).sort();

describe("ancrage, file durable : révision 0.6 de CT-5 (EX-8.5 règles 5 et 7, EX-8.12, EX-8.14)", function () {
  let dir;
  beforeEach(function () {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "ancrage-file-compactage-"));
  });
  afterEach(function () {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  describe("EX-8.5, règle 7 : lignes d'avant la révision et fenêtre de 32 tentatives", function () {
    it("une ligne sans attempts_total (avant 0.6) de 40 tentatives est lue telle quelle, attempts_total valant 40 ; avec attempts_total, plus de 32 tentatives est refusé à la lecture comme à l'écriture", function () {
      const ancienne = demande(1, { rangs: rangs(1, 40), total: null });
      expect(validerLigneDemande(ancienne).valide).to.equal(true);
      const dec = decoderFile(Buffer.from(N.jcs(ancienne) + "\n"));
      expect(dec.tronquees).to.deep.equal([]);
      expect(dec.lignes[0].attempts.map((a) => a.n)).to.deep.equal(rangs(1, 40));
      expect(totalTentatives(dec.lignes[0])).to.equal(40);
      const fautive = demande(2, { rangs: rangs(1, 33), total: 33 });
      expect(validerLigneDemande(fautive).valide).to.equal(false);
      expect(decoderFile(Buffer.from(N.jcs(fautive) + "\n")).tronquees.map((t) => t.raison)).to.deep.equal(["demande_non_conforme"]);
      expect(() => controlerDemande(ancienne), "une ligne écrite porte au plus 32 tentatives").to.throw(/attempts/);
      expect(() => controlerDemande(demande(3, { rangs: rangs(9, 40), total: 40 }))).to.not.throw();
      expect(FENETRE_TENTATIVES).to.equal(32);
      const tentativeFausse = demande(4, { rangs: rangs(1, 40), total: null });
      tentativeFausse.attempts[35].outcome = "inconnue";
      expect(validerLigneDemande(tentativeFausse).erreurs[0]).to.match(/^\/attempts\/35/);
    });
  });

  describe("EX-8.5, règle 5 : compactage du fichier courant", function () {
    it("procédé : dernière ligne de chaque id, octets recopiés tels quels, dans l'ordre où ces dernières lignes figurent ; ligne tronquée finale non recopiée ; état inchangé ; ligne anchor_queue_compacted", function () {
      const journal = journalFile();
      const f = FileDurable.ouvrir({ repertoire: dir, epoque: 7, journal, compactBytes: COMPACT_BYTES_DEFAUT });
      const a1 = demande(1, { state: "a_envoyer", rangs: [] });
      const b1 = demande(2, { state: "a_envoyer", rangs: [] });
      const a2 = demande(1, { state: "envoyee", rangs: [1] });
      const c1 = demande(3, { state: "refusee", rangs: [1] });
      const b2 = demande(2, { state: "a_reprendre", rangs: [1, 2] });
      for (const d of [a1, b1, a2, c1, b2]) f.ecrire(d);
      fs.appendFileSync(f.chemin, '{"tronquee":');
      const avant = etat(dir);
      const tailleAvant = fs.statSync(f.chemin).size;
      const r = f.compacter();
      expect(r).to.deep.include({ fait: true, declencheur: "cloture", requests: 3, bytes_before: tailleAvant });
      const contenu = fs.readFileSync(f.chemin, "utf8");
      expect(contenu).to.equal([a2, c1, b2].map((d) => N.jcs(d) + "\n").join(""));
      expect(r.bytes_after).to.equal(Buffer.byteLength(contenu));
      expect(etat(dir)).to.deep.equal(avant);
      expect(journal.de("anchor_queue_compacted").map((l) => [l.niveau, l.champs])).to.deep.equal([["info", { bytes_before: tailleAvant, bytes_after: Buffer.byteLength(contenu), requests: 3 }]]);
      expect(noms(dir)).to.deep.equal(["file-7.ndjson"]);
      // Le descripteur d'ajout est rouvert sur le fichier renommé : la ligne suivante s'y ajoute.
      const c2 = demande(3, { state: "refusee", rangs: [1, 2] });
      f.ecrire(c2);
      expect(fs.readFileSync(f.chemin, "utf8")).to.equal(contenu + N.jcs(c2) + "\n");
      expect(f.mesures()).to.include({ s0: Buffer.byteLength(contenu), compactages: 1, echecs: 0 });
      f.fermer();
      // Les demandes finales sont gardées (sans quoi la reconstruction d'EX-8.12 les recréerait).
      expect(lireFiles(dir).demandes.map((d) => d.state)).to.include("refusee");
    });

    it("dernieresLignes rend les octets exacts des dernières lignes, sans les lignes illisibles", function () {
      const x = N.jcs(demande(1, { state: "a_envoyer", rangs: [] })) + "\n";
      const y = N.jcs(demande(2, { state: "a_envoyer", rangs: [] })) + "\n";
      const x2 = N.jcs(demande(1, { state: "envoyee", rangs: [1] })) + "\n";
      const r = dernieresLignes(Buffer.from(x + "pas du json\n" + y + x2 + '{"a":'));
      expect(r.lignes.map((l) => l.toString("utf8"))).to.deep.equal([y, x2]);
      expect(r.demandes).to.equal(2);
      expect(r.octets).to.equal(Buffer.byteLength(y + x2));
      expect(r.tronquees).to.have.lengthOf(2);
      expect(r.tronquees[0].raison).to.match(/^json_/);
      expect(r.tronquees[1].raison).to.equal("ligne_tronquee");
    });

    it("déclencheur de taille : au-delà de compact_bytes et de 2 × S_0 seulement ; jamais deux compactages de suite sans croissance au-delà de 2 × S_0 ; taille ≤ max(compact_bytes, 2 × S_0) + une ligne", function () {
      const journal = journalFile();
      const compactBytes = 64 * 1024;
      const f = FileDurable.ouvrir({ repertoire: dir, epoque: 1, journal, compactBytes, fdatasync: false });
      let ligneMax = 0;
      // 40 demandes actives, réécrites chacune à chaque tentative (fenêtre de 32 : la ligne cesse de croître).
      for (let n = 1; n <= 60; n++) {
        for (let i = 0; i < 40; i++) {
          const premier = Math.max(1, n - FENETRE_TENTATIVES + 1);
          const r = f.ecrire(demande(i, { state: "a_reprendre", rangs: rangs(premier, n), total: n }));
          ligneMax = Math.max(ligneMax, r.octets);
        }
      }
      const compactages = journal.de("anchor_queue_compacted");
      expect(compactages.length).to.be.at.least(5);
      for (const c of compactages) {
        expect(c.champs.requests).to.equal(40);
        expect(c.champs.bytes_before).to.be.above(compactBytes);
      }
      // Entre deux compactages, la taille a dépassé max(compact_bytes, 2 × S_0) du précédent, d'au plus une ligne : c'est
      // la plus grande taille atteinte (borne de la règle 5).
      for (let k = 0; k < compactages.length; k++) {
        const seuil = Math.max(compactBytes, 2 * (k === 0 ? 0 : compactages[k - 1].champs.bytes_after));
        expect(compactages[k].champs.bytes_before, `compactage ${k + 1}`).to.be.above(seuil);
        expect(compactages[k].champs.bytes_before, `compactage ${k + 1}`).to.be.at.most(seuil + ligneMax);
      }
      const final = f.mesures();
      expect(final.taille_max).to.equal(Math.max(...compactages.map((c) => c.champs.bytes_before)));
      expect(final.taille).to.be.at.most(Math.max(compactBytes, 2 * final.s0) + ligneMax);
      expect(Object.keys(etat(dir))).to.have.lengthOf(40);
      for (const d of lireFiles(dir).demandes) {
        expect(d.attempts).to.have.lengthOf(FENETRE_TENTATIVES);
        expect(d.attempts_total).to.equal(60);
        expect(d.attempts.map((a) => a.n)).to.deep.equal(rangs(29, 60));
      }
      f.fermer();
    });

    it("échec (ENOSPC simulé à l'écriture du fichier neuf) : ancienne file en place et valide, fichier neuf supprimé, ligne anchor_queue_compaction_failed, ajout continu sur l'ancien descripteur ; au plus une tentative par minute monotone sur dépassement de taille, la clôture tente toujours", function () {
      const journal = journalFile();
      const monotone = monotoneReglable();
      let panne = true;
      const crochet = (pas) => {
        if (panne && pas === "ecriture") throw Object.assign(new Error("plus de place (essai)"), { code: "ENOSPC" });
      };
      const f = FileDurable.ouvrir({ repertoire: dir, epoque: 2, journal, monotone, crochet, compactBytes: 4096, fdatasync: false });
      for (let i = 0; i < 4; i++) f.ecrire(demande(i, { state: "a_envoyer", rangs: [] }));
      const avant = fs.readFileSync(f.chemin);
      // Première ligne au-delà de 4096 octets : compactage tenté, en échec.
      f.ecrire(demande(10, { state: "a_reprendre", rangs: rangs(1, 3), total: 3 }));
      const echecs = journal.de("anchor_queue_compaction_failed");
      expect(echecs).to.have.lengthOf(1);
      expect(echecs[0].niveau).to.equal("error");
      expect(echecs[0].champs).to.deep.equal({ step: "ecriture", errno: "ENOSPC", bytes: fs.statSync(f.chemin).size });
      expect(noms(dir)).to.deep.equal(["file-2.ndjson"]);
      expect(fs.readFileSync(f.chemin).subarray(0, avant.length).equals(avant)).to.equal(true);
      // Rien n'est bloqué : les écritures suivantes réussissent aussitôt, sur l'ancien fichier, sans nouvelle tentative avant une minute.
      for (let i = 11; i < 15; i++) expect(f.ecrire(demande(i, { state: "a_envoyer", rangs: [] })).octets).to.be.above(0);
      expect(journal.de("anchor_queue_compaction_failed")).to.have.lengthOf(1);
      monotone.avancer(59999);
      f.ecrire(demande(15, { state: "a_envoyer", rangs: [] }));
      expect(journal.de("anchor_queue_compaction_failed")).to.have.lengthOf(1);
      // La clôture n'est pas limitée par la minute.
      expect(f.compacter({ declencheur: "cloture" })).to.include({ fait: false, step: "ecriture" });
      expect(journal.de("anchor_queue_compaction_failed")).to.have.lengthOf(2);
      monotone.avancer(60000);
      panne = false;
      f.ecrire(demande(16, { state: "a_envoyer", rangs: [] }));
      expect(journal.de("anchor_queue_compacted")).to.have.lengthOf(1);
      expect(Object.keys(etat(dir))).to.have.lengthOf(11);
      f.fermer();
    });

    it("échec à chacun des pas relecture, fdatasync et renommage : ancien fichier intact, aucun .compactage ; pas repertoire (après le renommage) : le fichier courant est le neuf, valide, et l'ajout s'y poursuit sans perte", function () {
      for (const pas of ["relecture", "fdatasync", "renommage", "repertoire"]) {
        const rep = path.join(dir, pas);
        const journal = journalFile();
        const f = FileDurable.ouvrir({ repertoire: rep, epoque: 3, journal, crochet: (p) => {
          if (p === pas) throw Object.assign(new Error(`panne ${p} (essai)`), { code: "EIO" });
        } });
        for (let i = 0; i < 3; i++) f.ecrire(demande(i, { state: "a_envoyer", rangs: [] }));
        f.ecrire(demande(0, { state: "envoyee", rangs: [1] }));
        const octetsAvant = fs.readFileSync(f.chemin);
        const etatAvant = etat(rep);
        const r = f.compacter();
        expect(r, pas).to.include({ fait: false, step: pas, errno: "EIO" });
        expect(journal.de("anchor_queue_compaction_failed")[0].champs, pas).to.deep.equal({ step: pas, errno: "EIO", bytes: octetsAvant.length });
        expect(noms(rep), pas).to.deep.equal(["file-3.ndjson"]);
        if (pas === "repertoire") expect(fs.readFileSync(f.chemin).length, pas).to.be.below(octetsAvant.length);
        else expect(fs.readFileSync(f.chemin).equals(octetsAvant), pas).to.equal(true);
        expect(etat(rep), pas).to.deep.equal(etatAvant);
        const suivante = demande(1, { state: "envoyee", rangs: [1] });
        f.ecrire(suivante);
        expect(etat(rep)[suivante.id], pas).to.equal(N.jcs(suivante));
        f.fermer();
      }
    });

    it("arrêt injecté avant chaque pas (a) à (f) : au redémarrage, l'ancien ou le nouveau fichier est sous le nom courant, l'état relu est le même, le .compactage est supprimé à l'ouverture", function () {
      const instantanes = [];
      const copier = (pas) => {
        const cible = path.join(dir, `arret-${instantanes.length}-${pas}`);
        fs.mkdirSync(cible);
        for (const n of fs.readdirSync(path.join(dir, "file"))) fs.copyFileSync(path.join(dir, "file", n), path.join(cible, n));
        instantanes.push({ pas, cible });
      };
      const f = FileDurable.ouvrir({ repertoire: path.join(dir, "file"), epoque: 4, crochet: (pas) => copier(pas) });
      for (let n = 1; n <= 3; n++) for (let i = 0; i < 3; i++) f.ecrire(demande(i, { state: "a_reprendre", rangs: rangs(1, n), total: n }));
      const etatAvant = etat(path.join(dir, "file"));
      expect(f.compacter().fait).to.equal(true);
      f.fermer();
      expect(instantanes.map((x) => x.pas)).to.deep.equal(["relecture", "ecriture", "fdatasync", "renommage", "repertoire", "reouverture"]);
      for (const { pas, cible } of instantanes) {
        expect(etat(cible), pas).to.deep.equal(etatAvant);
        const g = FileDurable.ouvrir({ repertoire: cible, epoque: 4 });
        expect(noms(cible), pas).to.deep.equal(["file-4.ndjson"]);
        expect(g.residus, pas).to.deep.equal(["fdatasync", "renommage"].includes(pas) ? ["file-4.ndjson.compactage"] : []);
        expect(etat(cible), pas).to.deep.equal(etatAvant);
        g.fermer();
      }
    });

    it("concurrence : une ligne demandée pendant le compactage est servie juste après et figure dans le fichier final ; aucune ligne écrite avant n'est perdue", function () {
      let f;
      const pendant = demande(9, { state: "a_envoyer", rangs: [] });
      let reponse = null;
      f = FileDurable.ouvrir({ repertoire: dir, epoque: 5, crochet: (pas) => {
        if (pas === "renommage" && reponse === null) reponse = f.ecrire(pendant);
      } });
      for (let i = 0; i < 4; i++) f.ecrire(demande(i, { state: "a_envoyer", rangs: [] }));
      const etatAvant = etat(dir);
      expect(f.compacter().fait).to.equal(true);
      expect(reponse.differee).to.equal(true);
      const lignes = fs.readFileSync(f.chemin, "utf8").split("\n").filter(Boolean);
      expect(lignes.at(-1)).to.equal(N.jcs(pendant));
      expect(etat(dir)).to.deep.equal({ ...etatAvant, [pendant.id]: N.jcs(pendant) });
      f.fermer();
    });
  });

  describe("EX-8.12 et EX-8.14 : relecture d'une file compactée, .compactage résiduel, aucun autre fichier supprimé", function () {
    it("un file-<epoch>.ndjson.compactage resté d'un arrêt est ignoré par lireFiles puis supprimé à l'ouverture ; l'état est celui du fichier courant ; les fichiers des autres époques et les compactions antérieures restent", function () {
      const f = FileDurable.ouvrir({ repertoire: dir, epoque: 6 });
      for (let i = 0; i < 3; i++) f.ecrire(demande(i, { state: "a_envoyer", rangs: [] }));
      f.compacter();
      f.fermer();
      fs.writeFileSync(path.join(dir, "file-6.ndjson.compactage"), N.jcs(demande(99, { state: "a_envoyer", rangs: [] })) + "\n" + '{"x":');
      fs.writeFileSync(path.join(dir, "file-5.ndjson"), N.jcs(demande(50, { state: "refusee", rangs: [1] })) + "\n");
      fs.writeFileSync(path.join(dir, "file-5.1.compact.ndjson"), N.jcs(demande(50, { state: "refusee", rangs: [1] })) + "\n");
      fs.writeFileSync(path.join(dir, "autre.txt"), "x");
      const etatFichiers = etat(dir);
      expect(Object.keys(etatFichiers)).to.not.include(demande(99).id);
      const g = FileDurable.ouvrir({ repertoire: dir, epoque: 6 });
      expect(g.residus).to.deep.equal(["file-6.ndjson.compactage"]);
      expect(noms(dir)).to.deep.equal(["autre.txt", "file-5.1.compact.ndjson", "file-5.ndjson", "file-6.ndjson"]);
      expect(etat(dir)).to.deep.equal(etatFichiers);
      g.fermer();
    });
  });
});
