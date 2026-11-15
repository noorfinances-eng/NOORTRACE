// Revue de sécurité interne de l'étape 8 : compteur de numéros de série
// du serveur RFC 3161 interne (CT-5 AN-26 ; RFC 3161 §2.4.2). Une
// restauration ou une perte du fichier du compteur ne rejoue aucun numéro
// (plancher d'époque) ; deux processus de conteneurs différents sur
// le même volume n'émettent jamais le même numéro (réservation exclusive par
// le système de fichiers).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Compteur, EPOQUE_PAS, RESERVATIONS_GARDEES } from "@noortrace/ancrage/serveur-interne";

const T = Date.UTC(2026, 10, 13, 12, 0, 0);

describe("ancrage, revue de sécurité de l'étape 8 : compteur du serveur interne, numéros jamais rejoués (CT-5 AN-26)", function () {
  const dirs = [];
  const dir = () => {
    const d = fs.mkdtempSync(path.join(process.env.NOORTRACE_TMP ?? os.tmpdir(), "ancrage-revue-compteur-"));
    dirs.push(d);
    return d;
  };
  after(function () {
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  it("CT-5 AN-26 : avec epoque, le compteur ne descend jamais sous secondes × 2^20 ; après une restauration du fichier serie (ou sa perte) et un redémarrage, aucun numéro émis n'est rejoué ; sans epoque, un compteur neuf émet 1, 2, 3", function () {
    const sans = Compteur.ouvrir({ repertoire: dir(), vivant: () => false });
    expect([sans.suivant(), sans.suivant(), sans.suivant()]).to.deep.equal([1n, 2n, 3n]);
    sans.fermer();

    const rep = dir();
    let maintenant = T;
    const horloge = { murale: () => maintenant };
    const plancher = BigInt(Math.floor(T / 1000)) * EPOQUE_PAS;
    const c1 = Compteur.ouvrir({ repertoire: rep, epoque: true, horloge, vivant: () => false });
    const emis = [c1.suivant(), c1.suivant(), c1.suivant()];
    expect(emis[0]).to.equal(plancher);
    expect(emis).to.deep.equal([plancher, plancher + 1n, plancher + 2n]);
    const sauvegarde = fs.readFileSync(path.join(rep, "serie"));
    emis.push(c1.suivant(), c1.suivant());
    c1.fermer();
    // Restauration du compteur depuis la sauvegarde prise après le troisième numéro, puis redémarrage une seconde plus tard.
    fs.writeFileSync(path.join(rep, "serie"), sauvegarde);
    maintenant = T + 1000;
    const c2 = Compteur.ouvrir({ repertoire: rep, epoque: true, horloge, vivant: () => false });
    const apres = c2.suivant();
    expect(emis.includes(apres), "aucun numéro déjà émis n'est rejoué").to.equal(false);
    expect(apres).to.be.above(emis[4]);
    c2.fermer();
    // Perte du fichier : même garantie.
    fs.rmSync(path.join(rep, "serie"));
    maintenant = T + 2000;
    const c3 = Compteur.ouvrir({ repertoire: rep, epoque: true, horloge, vivant: () => false });
    expect(c3.suivant()).to.be.above(apres);
    c3.fermer();
  });

  it("CT-5 AN-26 : un numéro déjà réservé par un autre processus (fichier serie-<n>) n'est jamais émis : le compteur le saute ; les réservations anciennes sont élaguées", function () {
    const rep = dir();
    const a = Compteur.ouvrir({ repertoire: rep, vivant: () => false, pid: 4242 });
    expect([a.suivant(), a.suivant()]).to.deep.equal([1n, 2n]);
    expect(fs.existsSync(path.join(rep, "serie-1"))).to.equal(true);
    expect(fs.existsSync(path.join(rep, "serie-2"))).to.equal(true);
    // Un second processus (autre conteneur, autre espace de pid : le verrou par pid ne le voit pas) a réservé 3 et 4 et
    // a avancé le fichier serie : le premier processus, dont la mémoire dit 2, ne doit émettre ni 3 ni 4.
    fs.closeSync(fs.openSync(path.join(rep, "serie-3"), "wx", 0o600));
    fs.closeSync(fs.openSync(path.join(rep, "serie-4"), "wx", 0o600));
    fs.writeFileSync(path.join(rep, "serie"), "4\n");
    expect(a.suivant()).to.equal(5n);
    for (let k = 0; k < RESERVATIONS_GARDEES + 10; k++) a.suivant();
    const reservations = fs.readdirSync(rep).filter((n) => /^serie-[0-9]+$/.test(n));
    expect(reservations.length).to.be.at.most(RESERVATIONS_GARDEES + 1);
    expect(reservations).to.not.include("serie-1");
    expect(reservations).to.include(`serie-${a.courant}`);
    a.fermer();
  });
});
