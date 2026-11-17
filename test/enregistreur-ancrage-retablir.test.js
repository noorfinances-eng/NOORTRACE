// Levée du retrait de `qualified` par l'exploitant (CT-5 EX-5.9 ; CT-2 §15.10,
// demande `ancrage` ; CT-7 RA-90 ; décision du porteur du 2026-11-16) :
// `noortrace-ctl ancrage retablir-qualification <id>` dépose la demande, le
// démon agit (`commandeAncrage` du cœur, `retablirQualification` du composant
// d'ancrage) et la réponse est consignée au journal d'exploitation
// (`provider_qualification_restored`, refus `anchoring_ctl_refused`).
//
// - Le composant d'ancrage réel : retrait, puis la commande, puis le
//   prestataire est de nouveau `qualified` (fiche, état, fichier
//   `qualifications-retirees.json` relu au redémarrage) ; refus si le
//   prestataire n'est pas retiré, ou si l'identifiant manque.
// - `noortrace-ctl` reconnaît la commande : identifiant exigé (code 2), et,
//   sans démon, code 4 (la commande est admise, aucun démon ne répond).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { ErreurTransport } from "@noortrace/ancrage/rfc3161";
import { Coeur, principalCtlDemon } from "@noortrace/enregistreur";
import { monterComposant, repertoireTemporaire, enAttente, journalMemoire } from "./fixtures/ancrage-composant/outils.mjs";

const PERIODE = 1793862000;

/** La commande `ancrage` du cœur (demande déposée par noortrace-ctl), jouée sur un composant et un journal donnés. */
function commande(composant, journal, demande) {
  return Coeur.prototype.commandeAncrage.call({ o: { ancrage: composant }, journal }, demande);
}

describe("noortrace-ctl ancrage retablir-qualification : levée du retrait de qualified par l'exploitant (CT-5 EX-5.9 ; CT-7 RA-90)", function () {
  this.timeout(600000);

  it("retrait de qualified, puis la commande : le prestataire est de nouveau qualified (état, fiche, redémarrage), provider_qualification_restored consigné ; une seconde commande, ou une commande sur un prestataire jamais retiré, est refusée (anchoring_ctl_refused, retrait_absent) ; sans identifiant : identifiant_absent", async function () {
    const dir = repertoireTemporaire("noortrace-ancrage-retablir-");
    const m = await monterComposant({ dir, periodStart: PERIODE, evenements: { 1: 1 }, ErreurTransport });
    if (m.condition) return enAttente(this, m.condition);
    try {
      const principal = m.principal.prestataire.id;
      const secours = m.secours.prestataire.id;
      const journalCoeur = journalMemoire();
      const c1 = m.creer();
      await c1.demarrer();
      // Refus avant tout retrait : rien à lever.
      const refus = await commande(c1, journalCoeur, { commande: "retablir-qualification", id: secours });
      expect(refus).to.deep.equal({ accepte: false, raison: "retrait_absent" });
      expect(journalCoeur.de("anchoring_ctl_refused").at(-1).data).to.deep.equal({ command: "retablir-qualification", raison: "retrait_absent" });
      expect(await commande(c1, journalCoeur, { commande: "retablir-qualification", id: null })).to.deep.equal({ accepte: false, raison: "identifiant_absent" });
      // Retrait (acte de l'exploitant, ou automatique sur PKIStatus 4 ou 5), puis levée par la commande.
      expect(await commande(c1, journalCoeur, { commande: "retirer-qualification", id: principal })).to.deep.equal({ accepte: true });
      expect(c1.etat().qualifications_retirees).to.deep.equal([principal]);
      expect((await c1.fiche(principal)).fiche.qualified).to.equal(null);
      const r = await commande(c1, journalCoeur, { commande: "retablir-qualification", id: principal });
      expect(r).to.deep.equal({ accepte: true });
      expect(c1.etat().qualifications_retirees).to.deep.equal([]);
      expect((await c1.fiche(principal)).fiche.qualified).to.not.equal(null);
      const consigne = m.journal.de("provider_qualification_restored");
      expect(consigne).to.have.length(1);
      expect(consigne[0].data).to.deep.equal({ provider: principal });
      // Une seconde levée n'a plus d'objet.
      expect(await commande(c1, journalCoeur, { commande: "retablir-qualification", id: principal })).to.deep.equal({ accepte: false, raison: "retrait_absent" });
      await c1.arreter({ attendre: false });
      // Durable : le redémarrage relit l'absence de retrait.
      const c2 = m.creer({ epoque: 2 });
      await c2.demarrer();
      expect(c2.etat().qualifications_retirees).to.deep.equal([]);
      await c2.arreter({ attendre: false });
    } finally {
      await m.fermer();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("noortrace-ctl ancrage retablir-qualification : l'identifiant du prestataire est exigé (code 2) ; avec lui, la commande est admise et, sans démon en marche, rend 4 (aucun démon)", async function () {
    const dir = repertoireTemporaire("noortrace-ancrage-retablir-ctl-");
    try {
      const proc = path.join(dir, "proc");
      fs.mkdirSync(proc);
      const sortie = () => ({ texte: "", write(t) { this.texte += t; } });
      const err1 = sortie();
      expect(await principalCtlDemon(["ancrage", "retablir-qualification"], { stdout: sortie(), stderr: err1, racineProc: proc })).to.equal(2);
      expect(err1.texte).to.equal("noortrace-ctl ancrage retablir-qualification : identifiant de prestataire attendu\n");
      const err2 = sortie();
      expect(await principalCtlDemon(["ancrage", "retablir-qualification", "qtsa-principal"], { stdout: sortie(), stderr: err2, racineProc: proc })).to.equal(4);
      expect(err2.texte).to.not.include("usage");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
