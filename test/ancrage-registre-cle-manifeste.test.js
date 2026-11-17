// CT-4 OP-9, CT-5 EX-9.3 (complément du 2026-11-16) : avant d'ancrer, le
// composant d'ancrage vérifie, pour l'ancre d'une période comme pour celle
// d'un point, que la clé Ed25519 qui a signé le document (le manifeste de la
// période, le point) est inscrite sous la clé de chaîne qui envoie :
// `recorderByPubKey(orgId, clé).chainKey` égale cette adresse. Sinon l'ancre
// est refusée par l'envoyeur (`cle_chaine_non_inscrite`), aucune transaction
// ne part, et l'envoyeur écrit pour la période la ligne du point
// (`registry_send_failed`). Complément du 2026-11-16 (CT-5 EX-8.10, table des
// codes) : ce refus est définitif ; le planificateur le reçoit sous la forme
// `refus_cle_chaine_non_inscrite`, reprend l'ancre de la période au pas
// `retry.max_ms` (`anchor_retry`) et rend `refusee` celle d'un point
// (`anchor_refused`).
//
// Cas éprouvé : un démon configuré par erreur avec la clé de chaîne d'un autre
// journal de l'organisation (clé de chaîne A inscrite pour une autre clé
// Ed25519 ; la clé qui signe les points et le manifeste inscrite sous B).
// Avant la correction, l'ancre de la période partait sous A (même nonce que
// le démon de A ; R-10 fausse au dossier). Monté sur le composant réel :
// serveurs RFC 3161, calendriers et nœud du registre factices de
// test/fixtures/ancrage-composant. Le mutant (clé publique passée pour le
// point seulement) est une copie de paquets/ancrage/src sous NOORTRACE_TMP
// (défaut os.tmpdir()), détruite à la fin. Sous NOORTRACE_REVUE_RACINE, le
// composant est lu dans cette racine (code d'avant : essai rouge).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import * as N from "@noortrace/noyau";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import { ORG, JOURNAL, attenteCalme, monterComposant, remisePoint, remiseCloture, repertoireTemporaire, enAttente } from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000; // 2026-11-05T07:00:00Z
const T0 = PERIODE * 1000;
const EVENEMENTS = { 1: 1, 20: 1, 40: 1 };
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COMPOSANT = "paquets/ancrage/src/composant.mjs";
const COPIES = [];
const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;

/** Ligne du composant corrigée (CT-4 OP-9) et sa forme d'avant : la clé publique du seul point. */
const LIGNE_OP9 = 'const keyId = req.subject.kind === "point" ? this.points.get(req.subject.hash)?.key_id : this.clotures.get(req.subject.hash)?.manifeste?.recorder_key_id;';
const LIGNE_MUTANT = 'const keyId = req.subject.kind === "point" ? this.points.get(req.subject.hash)?.key_id : null;';

/**
 * Copie de paquets/ancrage/src (node_modules du dépôt et du paquet liés) où la ligne d'OP-9 ne passe plus la clé du
 * manifeste ; le module copié est chargé une fois ici, avant que l'essai ne démarre ses serveurs.
 */
async function copieMutant() {
  const racine = fs.mkdtempSync(path.join(TMP, "noortrace-op9-mutant-"));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, "paquets", "ancrage"), { recursive: true });
  fs.cpSync(path.join(RACINE, "paquets", "ancrage", "src"), path.join(racine, "paquets", "ancrage", "src"), { recursive: true });
  fs.symlinkSync(path.join(PROJECT_ROOT, "node_modules"), path.join(racine, "node_modules"));
  fs.symlinkSync(path.join(PROJECT_ROOT, "paquets", "ancrage", "node_modules"), path.join(racine, "paquets", "ancrage", "node_modules"));
  const f = path.join(racine, COMPOSANT);
  const texte = fs.readFileSync(f, "utf8");
  expect(texte.split(LIGNE_OP9).length - 1, "ligne d'OP-9 du composant").to.equal(1);
  fs.writeFileSync(f, texte.replace(LIGNE_OP9, () => LIGNE_MUTANT));
  expect(typeof (await import(pathToFileURL(f).href)).creerComposantAncrage).to.equal("function");
  return racine;
}

/**
 * Rejoue la période (points de la série, point de clôture, clôture), puis avance de dix minutes. `cleAilleurs` : la
 * clé de chaîne configurée est inscrite pour une autre clé Ed25519, et la clé de la série sous une autre clé de chaîne
 * de la même organisation (même journal). Rend l'état utile à l'essai.
 */
async function parcours({ cleAilleurs, racineComposant = RACINE === PROJECT_ROOT ? null : RACINE }) {
  const dir = repertoireTemporaire("noortrace-ancrage-op9-");
  const autre = N.sha256(N.utf8("noortrace/essai/op9/autre-cle-ed25519"));
  const m = await monterComposant({ dir, periodStart: PERIODE, evenements: EVENEMENTS, racineComposant, ...(cleAilleurs ? { registreOptions: { clePublique: autre } } : {}) });
  if (m.condition) {
    fs.rmSync(dir, { recursive: true, force: true });
    return { condition: m.condition };
  }
  let composant = null;
  try {
    const cleB = new SignataireChaineFichier(N.sha256(N.utf8("noortrace/essai/op9/cle-chaine-b")));
    if (cleAilleurs) m.registre.noeud.inscrire({ orgId: ORG, chainKey: cleB.adresse(), ed25519PubKey: N.octetsVersHex(m.serie.clePublique), journalId: JOURNAL });
    composant = m.creer();
    const calme = attenteCalme(composant);
    await composant.demarrer();
    for (const point of m.serie.points) {
      await m.horloge.aller(N.decoderHorodatage(point.checkpoint_ts), calme);
      m.remis.push(point);
      expect((await composant.remettrePoint(remisePoint(point))).admis, point.checkpoint_ts).to.equal(true);
      await calme();
    }
    expect((await composant.remettreCloture(remiseCloture(m.serie))).admis).to.equal(true);
    await calme();
    await m.horloge.avancer(600000, calme);
    const periodHash = N.hacherManifeste(m.serie.manifeste);
    const fingerprint = N.empreinteAncre(ORG, JOURNAL, periodHash);
    const etat = {
      adresseA: m.registre.cleChaine.adresse(),
      adresseB: cleB.adresse(),
      ancre: composant.demandes().find((d) => d.kind === "ancre_registre_periode"),
      ancresPoints: composant.demandes().filter((d) => d.kind === "ancre_registre_point"),
      ancreAuRegistre: m.registre.noeud.ancres.get(fingerprint) ?? null,
      ancresDesPoints: composant.demandes().filter((d) => d.kind === "ancre_registre_point").map((d) => m.registre.noeud.ancres.get(N.empreinteAncre(ORG, JOURNAL, d.subject.hash)) ?? null),
      refus: m.journal.de("registry_send_failed").map((l) => l.data),
      reprises: m.journal.de("anchor_retry").map((l) => l.data),
      refusees: m.journal.de("anchor_refused").map((l) => l.data),
    };
    await composant.arreter({ attendre: false });
    return etat;
  } finally {
    if (composant?.etat().demarre) await composant.arreter({ attendre: false });
    await m.fermer();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

describe("CT-4 OP-9 : l'ancre d'une période vérifie, comme celle d'un point, que la clé du manifeste est inscrite sous la clé de chaîne qui envoie (complément du 2026-11-16)", function () {
  this.timeout(300000);

  it("clé du manifeste inscrite sous une autre clé de chaîne de l'organisation : l'ancre de la période est refusée (cle_chaine_non_inscrite, classé refus définitif par CT-5 EX-8.10 : refus_cle_chaine_non_inscrite) et n'est pas envoyée ; mêmes lignes de l'Envoyeur que pour un point", async function () {
    const e = await parcours({ cleAilleurs: true });
    if (e.condition) return enAttente(this, e.condition);
    // Aucune ancre au registre, ni de la période ni des points, sous la clé configurée.
    expect(e.ancreAuRegistre, "ancre de la période envoyée sous la clé de chaîne d'un autre journal").to.equal(null);
    expect(e.ancresDesPoints.filter(Boolean)).to.deep.equal([]);
    expect(e.ancre.state).to.equal("a_reprendre");
    // CT-5 EX-8.10 (complément du 2026-11-16, table des codes) : cle_chaine_non_inscrite est un refus définitif ; le
    // composant le passe au planificateur sous la forme refus_cle_chaine_non_inscrite.
    expect(e.ancre.attempts.map((a) => a.error_code)).to.include("refus_cle_chaine_non_inscrite");
    expect(e.ancre.attempts.every((a) => a.outcome !== "obtenue")).to.equal(true);
    // Même code, mêmes lignes (registry_send_failed avec la clé de chaîne inscrite ; anchor_retry) pour le point et la période.
    const refusDe = (sorte) => e.refus.filter((l) => l.request_id.startsWith(`${sorte}:`));
    for (const sorte of ["ancre_registre_point", "ancre_registre_periode"]) {
      expect(refusDe(sorte).length, sorte).to.be.at.least(1);
      for (const l of refusDe(sorte)) expect([l.code, l.registered_chain_key], sorte).to.deep.equal(["cle_chaine_non_inscrite", e.adresseB]);
    }
    // Puis le planificateur (CT-5 EX-8.10) : l'ancre de la période reprise au pas retry.max_ms (anchor_retry), celles des
    // points refusees (anchor_refused).
    expect(e.reprises.filter((l) => l.kind === "ancre_registre_periode" && l.error_code === "refus_cle_chaine_non_inscrite").length).to.be.at.least(1);
    expect(e.refusees.filter((l) => l.request_id.startsWith("ancre_registre_point:") && l.error_code === "refus_cle_chaine_non_inscrite").length).to.be.at.least(1);
    expect(e.ancresPoints.every((d) => d.state === "refusee")).to.equal(true);
  });

  it("cas valide : clé du manifeste inscrite sous la clé de chaîne configurée : l'ancre de la période part sous cette clé et est obtenue", async function () {
    const e = await parcours({ cleAilleurs: false });
    if (e.condition) return enAttente(this, e.condition);
    expect(e.ancre.state).to.equal("obtenue");
    expect(e.ancreAuRegistre?.issuer?.toLowerCase()).to.equal(e.adresseA.toLowerCase());
    expect(e.refus.filter((l) => l.code === "cle_chaine_non_inscrite")).to.deep.equal([]);
  });

  it("mutant (composant : clé publique passée à l'envoyeur pour le point seulement, comme avant la correction) : l'ancre de la période part sous la clé de chaîne d'un autre journal (tué)", async function () {
    const e = await parcours({ cleAilleurs: true, racineComposant: await copieMutant() });
    if (e.condition) return enAttente(this, e.condition);
    expect(e.ancreAuRegistre, "le mutant n'envoie pas l'ancre de la période").to.not.equal(null);
    expect(e.ancreAuRegistre.issuer.toLowerCase()).to.equal(e.adresseA.toLowerCase());
    expect(e.ancre.state).to.equal("obtenue");
  });
});
