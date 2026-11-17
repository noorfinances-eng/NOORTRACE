// Annuaire des approbateurs : expiration des entrées jamais validées et
// défis consommés hors des bornes (CT-3 EX-13.10, EX-13.13, EX-13.15,
// EX-13.17, EX-13.19, EX-13.32, EX-13.40 ; décision du porteur du
// 2026-11-16). Chaque règle est jouée sur la bibliothèque de référence
// (`scripts/lib/console.mjs`), sur le module d'annuaire qu'exécute le service
// (`@noortrace/console/annuaire`) et sur le service réel (horloge réglable) :
//   - une entrée dont aucune adresse n'a jamais été validée expire
//     `registration_entry_ttl_ms` après sa création, pas avant (opération
//     `expirer`, consignée, notifiée, persistée) ; une entrée validée n'expire
//     jamais ; l'identifiant n'est jamais réattribué ;
//   - le rejeu d'un annuaire exporté (AN-9) rejoue `expirer` et refuse une
//     expiration avant la borne basse, d'une entrée validée, ou un identifiant
//     réattribué ;
//   - 10 000 entrées en attente bloquent l'inscription nouvelle
//     (`limite_annuaire`) ; une expiration la rouvre ;
//   - un défi présenté est retiré : il ne compte plus dans les 4 défis par
//     identité ni dans les 1 024 au total, et son nonce présenté de nouveau
//     est inconnu.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as A from "@noortrace/approbation";
import * as B from "@noortrace/console/annuaire";
import * as K from "../scripts/lib/console.mjs";
import { SESSIONS, VECTEURS_CT3, attendre } from "./fixtures/approbation-service/outils.mjs";
import { adresseDe, boite, horlogeReglable, journalService, serviceEtape6, signerTexte } from "./fixtures/approbation-service/etape6.mjs";

const JOUR = 86400000;
const TTL = 30 * JOUR;
const T0 = "2026-11-10T08:00:00.000Z";
const iso = (ms) => new Date(ms).toISOString();
const plus = (ts, d) => iso(Date.parse(ts) + d);
const VIDE = JSON.parse(fs.readFileSync(path.join(VECTEURS_CT3, "annuaire", "annuaires", "vide.json"), "utf8"));
const ADMIN = SESSIONS.admin;
const nonce = (k) => k.toString(16).padStart(32, "0");
const conforme = (d) => A.annuaireConforme(d);
/** Adresse sans compte de test (préparation seule, jamais signée). */
const autre = (k) => "0x" + "ab".repeat(18) + k.toString(16).padStart(4, "0");

const BIBLIOTHEQUES = [
  ["bibliothèque de référence (scripts/lib/console.mjs)", K],
  ["module d'annuaire du service (@noortrace/console/annuaire)", B],
];

for (const [nom, L] of BIBLIOTHEQUES) {
  describe(`annuaire, ${nom} : expiration et défis consommés (décision du porteur du 2026-11-16)`, function () {
    this.timeout(120000);

    /** Applique une méthode et garde l'état ; rend le résultat. */
    function etat(depart = VIDE) {
      const e = { annuaire: depart, defis: [] };
      e.op = (methode, requete, at, o = {}) => {
        const r = L.appliquerOperation(e.annuaire, methode, requete, at, { defis: e.defis, identifiant: "compteur", ...o });
        e.annuaire = r.annuaire;
        e.defis = r.defis;
        return r;
      };
      /** Défi puis inscription de l'adresse du compte i, signée par le compte `signataire`. */
      e.inscrire = (session, i, at, k, signataire = i) => {
        const p = e.op("preparer_inscription", { session_identity: session, address: adresseDe(i) }, at, { nonce: nonce(k) });
        expect(p.accepted, p.reason).to.equal(true);
        return e.op("inscrire", { session_identity: session, address: adresseDe(i), message: p.response.message, signature: signerTexte(signataire, p.response.message) }, plus(at, 30000));
      };
      return e;
    }

    it("EX-13.10, EX-13.17 : une entrée jamais validée expire à created_at + registration_entry_ttl_ms, pas avant ; opération expirer consignée ; l'adresse est libérée, l'identifiant jamais réattribué", function () {
      const e = etat();
      expect(e.inscrire(SESSIONS[1], 1, T0, 1).accepted).to.equal(true);
      const cree = e.annuaire.entries[0].created_at;
      expect(cree).to.equal(plus(T0, 30000));
      const avant = e.annuaire;
      // pas avant l'échéance
      const tot = L.appliquerOperation(avant, "expirer", { entry: "apb-0001" }, plus(cree, TTL - 1), { ttlEntree: TTL });
      expect([tot.accepted, tot.reason]).to.deep.equal([false, "etat_incompatible"]);
      expect(tot.annuaire).to.deep.equal(avant);
      expect(L.expirerEntrees(avant, plus(cree, TTL - 1), TTL)).to.deep.equal({ annuaire: avant, expirees: [] });
      // entrée inconnue, forme
      expect(L.appliquerOperation(avant, "expirer", { entry: "apb-0009" }, plus(cree, TTL), { ttlEntree: TTL }).reason).to.equal("entree_inconnue");
      expect(L.appliquerOperation(avant, "expirer", { entry: "apb-0001", session_identity: ADMIN }, plus(cree, TTL), { ttlEntree: TTL }).reason).to.equal("requete_invalide");
      // à l'échéance exactement
      const r = L.appliquerOperation(avant, "expirer", { entry: "apb-0001" }, plus(cree, TTL), { ttlEntree: TTL });
      expect([r.accepted, r.reason, r.response]).to.deep.equal([true, null, null]);
      expect(r.annuaire.entries).to.deep.equal([]);
      expect(r.annuaire.revision).to.equal(2);
      expect(r.annuaire.updated_at).to.equal(plus(cree, TTL));
      expect(r.annuaire.operations.at(-1)).to.deep.equal({ seq: 2, at: plus(cree, TTL), op: "expirer", by: "service", entry: "apb-0001", address: null, launched_by: null, reason: null, administrators: null });
      expect(conforme(r.annuaire)).to.equal(true);
      // même effet par expirerEntrees ; défaut de 30 jours
      const x = L.expirerEntrees(avant, plus(cree, TTL), TTL);
      expect(x.expirees).to.deep.equal(["apb-0001"]);
      expect(x.annuaire).to.deep.equal(r.annuaire);
      expect(L.appliquerOperation(avant, "expirer", { entry: "apb-0001" }, plus(cree, TTL)).annuaire).to.deep.equal(r.annuaire);
      // l'adresse, jamais validée, est libérée ; la nouvelle entrée a un identifiant neuf
      e.annuaire = r.annuaire;
      const r2 = e.inscrire(SESSIONS[2], 1, plus(cree, TTL + 1000), 2);
      expect([r2.accepted, r2.response.entry]).to.deep.equal([true, "apb-0002"]);
      // la même identité se réinscrit : entrée nouvelle, identifiant neuf
      const r3 = e.inscrire(SESSIONS[1], 2, plus(cree, TTL + 2000), 3);
      expect([r3.accepted, r3.response.entry]).to.deep.equal([true, "apb-0003"]);
      expect(conforme(e.annuaire)).to.equal(true);
      expect(L.verifierAnnuaireExporte(e.annuaire, { conforme })).to.deep.equal([]);
    });

    it("EX-13.10 : une entrée dont une adresse a été validée n'expire jamais, même révoquée ensuite ; une entrée désactivée jamais validée expire", function () {
      const e = etat();
      e.inscrire(SESSIONS[1], 1, T0, 1);
      expect(e.op("valider", { session_identity: ADMIN, entry: "apb-0001", address: adresseDe(1) }, plus(T0, 60000)).accepted).to.equal(true);
      const loin = plus(T0, 365 * JOUR);
      expect(L.appliquerOperation(e.annuaire, "expirer", { entry: "apb-0001" }, loin, { ttlEntree: TTL }).reason).to.equal("etat_incompatible");
      expect(L.expirerEntrees(e.annuaire, loin, TTL).expirees).to.deep.equal([]);
      expect(e.op("revoquer", { session_identity: ADMIN, entry: "apb-0001", address: adresseDe(1), reason: null }, plus(T0, 120000)).accepted).to.equal(true);
      expect(L.expirerEntrees(e.annuaire, loin, TTL).expirees).to.deep.equal([]);
      // entrée jamais validée, désactivée : expire comme les autres
      e.inscrire(SESSIONS[2], 2, plus(T0, 180000), 2);
      expect(e.op("desactiver", { session_identity: ADMIN, entry: "apb-0002", reason: null }, plus(T0, 240000)).accepted).to.equal(true);
      const x = L.expirerEntrees(e.annuaire, plus(T0, 210000 + TTL), TTL);
      expect(x.expirees).to.deep.equal(["apb-0002"]);
      expect(x.annuaire.entries.map((y) => y.id)).to.deep.equal(["apb-0001"]);
      expect(L.verifierAnnuaireExporte(x.annuaire, { conforme })).to.deep.equal([]);
    });

    it("AN-9 (EX-13.19, point 6) : expirer rejoué ; expiration avant created_at + 86 400 000, d'une entrée validée, ou identifiant réattribué : operations_incoherentes", function () {
      const e = etat();
      e.inscrire(SESSIONS[1], 1, T0, 1);
      e.inscrire(SESSIONS[2], 2, plus(T0, 60000), 2);
      e.op("valider", { session_identity: ADMIN, entry: "apb-0002", address: adresseDe(2) }, plus(T0, 120000));
      const x = L.expirerEntrees(e.annuaire, plus(T0, 30000 + TTL), TTL);
      expect(x.expirees).to.deep.equal(["apb-0001"]);
      e.annuaire = x.annuaire;
      e.inscrire(SESSIONS[3], 1, plus(T0, TTL + 60000), 3);
      const doc = e.annuaire;
      expect(doc.operations.map((o) => o.op)).to.deep.equal(["inscrire", "inscrire", "valider", "expirer", "inscrire"]);
      expect(L.verifierAnnuaireExporte(doc, { conforme })).to.deep.equal([]);
      const copie = () => JSON.parse(JSON.stringify(doc));
      // avant la borne basse du réglage (un jour après la création)
      const tot = copie();
      tot.operations[3].at = plus(T0, 30000 + JOUR - 1);
      expect(L.verifierAnnuaireExporte(tot, { conforme })).to.deep.equal([{ code: "operations_incoherentes", pointer: "/operations/3" }]);
      const borne = copie();
      borne.operations[3].at = plus(T0, 30000 + JOUR);
      expect(L.verifierAnnuaireExporte(borne, { conforme })).to.deep.equal([]);
      // expiration d'une entrée validée
      const validee = copie();
      const tard = plus(T0, 2 * TTL);
      validee.entries = validee.entries.filter((x) => x.id !== "apb-0002");
      validee.operations.push({ seq: 6, at: tard, op: "expirer", by: "service", entry: "apb-0002", address: null, launched_by: null, reason: null, administrators: null });
      Object.assign(validee, { revision: 6, updated_at: tard });
      expect(L.verifierAnnuaireExporte(validee, { conforme })).to.deep.equal([{ code: "operations_incoherentes", pointer: "/operations/5" }]);
      // identifiant de l'entrée expirée réattribué
      const reattribue = copie();
      reattribue.entries[1].id = "apb-0001";
      reattribue.operations[4].entry = "apb-0001";
      expect(L.verifierAnnuaireExporte(reattribue, { conforme })).to.deep.equal([{ code: "operations_incoherentes", pointer: "/operations/4" }]);
      // expirer porte by « service » et rien d'autre (schéma)
      const parSession = copie();
      parSession.operations[3].by = ADMIN;
      expect(conforme(parSession)).to.equal(false);
      const avecAdresse = copie();
      avecAdresse.operations[3].address = adresseDe(1);
      expect(conforme(avecAdresse)).to.equal(false);
    });

    it("EX-13.17 : 10 000 entrées en attente, l'inscription nouvelle est refusée (limite_annuaire) ; une expiration la rouvre, sans réattribuer d'identifiant", function () {
      const plein = JSON.parse(JSON.stringify(VIDE));
      for (let k = 1; k <= 10000; k++) {
        const adresse = "0x" + k.toString(16).padStart(40, "0");
        plein.entries.push({
          id: `apb-${String(k).padStart(4, "0")}`, session_identity: `oidc https://idp.assureur-demo.example employe-${k}`, external_id: null, display_name: null, active: true,
          requester_identities: [], created_at: k === 1 ? T0 : plus(T0, JOUR),
          addresses: [{ address: adresse, state: "en_attente", proof: { message: "x", signature: "0x", nonce: nonce(k), issued_at: T0, expires_at: T0, received_at: T0 }, validated_at: null, validated_by: null, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null, replaced_by: null }],
        });
      }
      const e = etat(plein);
      const refus = e.inscrire(SESSIONS[1], 1, plus(T0, TTL - 60000), 1);
      expect([refus.accepted, refus.reason]).to.deep.equal([false, "limite_annuaire"]);
      expect(e.annuaire.entries).to.have.length(10000);
      const x = L.expirerEntrees(e.annuaire, plus(T0, TTL), TTL);
      expect(x.expirees).to.deep.equal(["apb-0001"]);
      e.annuaire = x.annuaire;
      const r = e.inscrire(SESSIONS[1], 1, plus(T0, TTL), 2);
      expect([r.accepted, r.response.entry]).to.deep.equal([true, "apb-10001"]);
      expect(e.annuaire.entries).to.have.length(10000);
      // Les 9 999 autres échoient ensemble : une opération expirer par entrée, dans l'ordre de entries, en une passe.
      const debut = Date.now();
      const tout = L.expirerEntrees(e.annuaire, plus(T0, JOUR + TTL), TTL);
      expect(Date.now() - debut, "durée de l'expiration de 9 999 entrées (ms)").to.be.below(10000);
      expect(tout.expirees).to.have.length(9999);
      expect(tout.annuaire.entries.map((x) => x.id)).to.deep.equal(["apb-10001"]);
      const ops = tout.annuaire.operations.slice(-9999);
      expect(ops.map((o) => o.entry)).to.deep.equal(tout.expirees);
      expect(ops.every((o, k) => o.op === "expirer" && o.by === "service" && o.at === plus(T0, JOUR + TTL) && o.seq === e.annuaire.revision + k + 1)).to.equal(true);
      expect(tout.annuaire.revision).to.equal(e.annuaire.revision + 9999);
    });

    it("EX-13.13 : un défi présenté est retiré, accepté ou refusé ; il ne compte plus dans les 4 défis de l'identité ; son nonce présenté de nouveau est inconnu", function () {
      const e = etat();
      const at = (s) => plus(T0, s * 1000);
      const messages = {};
      for (let i = 1; i <= 4; i++) {
        const p = e.op("preparer_inscription", { session_identity: SESSIONS[1], address: adresseDe(i) }, at(i), { nonce: nonce(i) });
        expect(p.accepted, `défi ${i}`).to.equal(true);
        messages[i] = p.response.message;
      }
      // cinquième défi, quatre défis non présentés : refusé
      expect(e.op("preparer_inscription", { session_identity: SESSIONS[1], address: autre(5) }, at(5), { nonce: nonce(5) }).reason).to.equal("limite_annuaire");
      // défi présenté, accepté : retiré
      const req1 = { session_identity: SESSIONS[1], address: adresseDe(1), message: messages[1], signature: signerTexte(1, messages[1]) };
      expect(e.op("inscrire", req1, at(6)).accepted).to.equal(true);
      expect(e.defis.map((d) => d.fields.nonce)).to.deep.equal([nonce(2), nonce(3), nonce(4)]);
      expect(e.op("preparer_inscription", { session_identity: SESSIONS[1], address: autre(5) }, at(7), { nonce: nonce(6) }).accepted).to.equal(true);
      // défi présenté, refusé (signature d'un autre compte) : retiré aussi
      const req2 = { session_identity: SESSIONS[1], address: adresseDe(2), message: messages[2], signature: signerTexte(3, messages[2]) };
      expect(e.op("inscrire", req2, at(8)).reason).to.equal("signature_invalide");
      expect(e.defis.some((d) => d.fields.nonce === nonce(2))).to.equal(false);
      expect(e.op("preparer_inscription", { session_identity: SESSIONS[1], address: autre(6) }, at(9), { nonce: nonce(7) }).accepted).to.equal(true);
      // quatre défis non présentés de nouveau : le suivant est refusé
      expect(e.defis.filter((d) => d.fields.identity === SESSIONS[1])).to.have.length(4);
      expect(e.op("preparer_inscription", { session_identity: SESSIONS[1], address: autre(7) }, at(10), { nonce: nonce(8) }).reason).to.equal("limite_annuaire");
      // les deux nonces présentés sont inconnus
      expect(e.op("inscrire", req1, at(11)).reason).to.equal("nonce_inconnu");
      expect(e.op("inscrire", { ...req2, signature: signerTexte(2, messages[2]) }, at(12)).reason).to.equal("nonce_inconnu");
      // verifierInscription garde son contrat : le défi y est marqué présenté
      const v = L.verifierInscription(e.annuaire, e.defis, { session_identity: SESSIONS[1], address: adresseDe(3), message: messages[3], signature: signerTexte(3, messages[3]) }, at(13), { identifiant: "compteur" });
      expect(v.accepted).to.equal(true);
      expect(v.defis.find((d) => d.fields.nonce === nonce(3)).used).to.equal(true);
    });
  });
}

describe("service d'approbation : expiration des entrées jamais validées et défis consommés (décision du porteur du 2026-11-16)", function () {
  this.timeout(180000);

  /** Défi puis inscription de l'adresse du compte i par le canal ; rend la réponse d'inscrire. */
  async function inscrire(s, session, i) {
    const p = await s.appel("preparer_inscription", { session_identity: session, address: adresseDe(i) });
    expect(p.statut, JSON.stringify(p.corps)).to.equal(200);
    return s.appel("inscrire", { session_identity: session, address: adresseDe(i), message: p.corps.message, signature: signerTexte(i, p.corps.message) });
  }
  const lireAnnuaire = async (s) => (await s.appel("annuaire", { session_identity: ADMIN })).corps;

  it("expiration à l'échéance et pas avant, avant de servir la méthode ; opération consignée, notifiée (operation_annuaire), persistée ; une entrée validée n'expire jamais", async function () {
    const h = horlogeReglable(T0);
    const s = await serviceEtape6({ horloge: h });
    let s2 = null;
    try {
      const r1 = await inscrire(s, SESSIONS[1], 1);
      expect(r1.statut, JSON.stringify(r1.corps)).to.equal(200);
      const id1 = r1.corps.entry;
      const r2 = await inscrire(s, SESSIONS[2], 2);
      const id2 = r2.corps.entry;
      expect((await s.appel("valider", { session_identity: ADMIN, entry: id2, address: adresseDe(2) })).statut).to.equal(200);
      // juste avant l'échéance : rien n'expire
      h.regler(plus(T0, TTL - 1));
      let a = await lireAnnuaire(s);
      expect([a.revision, a.entries.map((e) => e.id)]).to.deep.equal([3, [id1, id2]]);
      // à l'échéance : l'entrée jamais validée expire avant que la méthode soit servie
      h.regler(plus(T0, TTL));
      a = await lireAnnuaire(s);
      expect(a.entries.map((e) => e.id)).to.deep.equal([id2]);
      expect(a.revision).to.equal(4);
      expect(a.operations.at(-1)).to.deep.equal({ seq: 4, at: plus(T0, TTL), op: "expirer", by: "service", entry: id1, address: null, launched_by: null, reason: null, administrators: null });
      expect(A.verifierAnnuaireExporte(a, { conforme: A.annuaireConforme })).to.deep.equal([]);
      await attendre(() => boite(s.cfg.doc.state_dir).some((l) => l.includes('"expirer"')));
      const n = boite(s.cfg.doc.state_dir).map((l) => JSON.parse(l)).find((x) => x.kind === "operation_annuaire" && x.details.op === "expirer");
      expect(n).to.deep.include({ recipients: { entries: [id1], roles: [] }, ticket: null, tool: null, deadline: null });
      expect(n.details).to.deep.equal({ op: "expirer", entry: id1, address: null, revision: 4, at: plus(T0, TTL), by_self: false });
      await s.service.supervision.vider();
      expect(journalService(s.cfg.doc.state_dir).filter((l) => l.type === "operation_annuaire" && l.methode === "expirer").map((l) => [l.entry, l.revision])).to.deep.equal([[id1, 4]]);
      // l'entrée validée n'expire jamais
      h.regler(plus(T0, 400 * JOUR));
      a = await lireAnnuaire(s);
      expect([a.revision, a.entries.map((e) => e.id)]).to.deep.equal([4, [id2]]);
      // l'expiration est durable : relue au redémarrage
      await s.arreter();
      s2 = await serviceEtape6({ dir: s.dir, garder: s.cfg, horloge: h });
      a = await lireAnnuaire(s2);
      expect([a.revision, a.operations.at(-1).op, a.entries.map((e) => e.id)]).to.deep.equal([4, "expirer", [id2]]);
    } finally {
      await s.arreter().catch(() => {});
      await s2?.arreter();
    }
  });

  it("réglage registration_entry_ttl_ms : défaut 30 jours, de 86 400 000 à 31 536 000 000 ; la valeur de la configuration fait l'échéance", async function () {
    const base = { version: 0, environment: "developpement", org: "assureur-demo", org_id: VIDE.org_id, journal_id: "0x" + "11".repeat(32), state_dir: "/var/lib/x", storage_key: { env: "X" }, noyau: { socket: "/run/x.sock" }, administrators: [ADMIN], console_origin: VIDE.console_origin };
    expect(A.completer(base).registration_entry_ttl_ms).to.equal(TTL);
    for (const [v, ok] of [[JOUR - 1, false], [JOUR, true], [365 * JOUR, true], [365 * JOUR + 1, false], [1.5, false]]) {
      expect(A.validerConfiguration({ ...base, registration_entry_ttl_ms: v }).valide, String(v)).to.equal(ok);
    }
    const h = horlogeReglable(T0);
    const s = await serviceEtape6({ horloge: h, registration_entry_ttl_ms: JOUR });
    try {
      const id = (await inscrire(s, SESSIONS[1], 1)).corps.entry;
      h.regler(plus(T0, JOUR - 1));
      expect((await lireAnnuaire(s)).entries.map((e) => e.id)).to.deep.equal([id]);
      h.regler(plus(T0, JOUR));
      expect((await lireAnnuaire(s)).entries).to.deep.equal([]);
    } finally {
      await s.arreter();
    }
  });

  it("10 000 entrées en attente : inscription nouvelle refusée (limite_annuaire, 409) ; à l'échéance de la plus ancienne, la préparation l'expire d'abord et l'inscription passe", async function () {
    const h = horlogeReglable(plus(T0, TTL - 60000));
    const s = await serviceEtape6({ horloge: h });
    try {
      const plein = JSON.parse(JSON.stringify(VIDE));
      for (let k = 1; k <= 10000; k++) {
        plein.entries.push({
          id: `apb-${k.toString(16).padStart(16, "0")}`, session_identity: `oidc https://idp.assureur-demo.example employe-${k}`, external_id: null, display_name: null, active: true,
          requester_identities: [], created_at: k === 1 ? T0 : plus(T0, JOUR),
          addresses: [{ address: "0x" + k.toString(16).padStart(40, "0"), state: "en_attente", proof: { message: "x", signature: "0x", nonce: nonce(k), issued_at: T0, expires_at: T0, received_at: T0 }, validated_at: null, validated_by: null, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null, replaced_by: null }],
        });
      }
      s.service.annuaire.adopter({ annuaire: plein, defis: [], persiste: true });
      const refus = await inscrire(s, SESSIONS[1], 1);
      expect([refus.statut, refus.corps.error?.code]).to.deep.equal([409, "limite_annuaire"]);
      h.regler(plus(T0, TTL));
      const ok = await inscrire(s, SESSIONS[1], 1);
      expect(ok.statut, JSON.stringify(ok.corps)).to.equal(200);
      const a = await lireAnnuaire(s);
      expect(a.entries).to.have.length(10000);
      expect(a.entries.some((e) => e.id === plein.entries[0].id)).to.equal(false);
      expect(a.operations.map((o) => o.op)).to.deep.equal(["expirer", "inscrire"]);
      expect(ok.corps.entry).to.not.equal(plein.entries[0].id);
    } finally {
      await s.arreter();
    }
  });

  it("EX-13.13 : défi consommé (inscription acceptée) puis nouveau défi accepté au-delà de quatre ; nonce présenté de nouveau : nonce_inconnu", async function () {
    const h = horlogeReglable(T0);
    const s = await serviceEtape6({ horloge: h });
    try {
      const prep = [];
      for (let i = 1; i <= 4; i++) {
        const p = await s.appel("preparer_inscription", { session_identity: SESSIONS[1], address: adresseDe(i) });
        expect(p.statut).to.equal(200);
        prep.push(p.corps.message);
      }
      expect((await s.appel("preparer_inscription", { session_identity: SESSIONS[1], address: autre(5) })).corps.error.code).to.equal("limite_annuaire");
      const req = { session_identity: SESSIONS[1], address: adresseDe(1), message: prep[0], signature: signerTexte(1, prep[0]) };
      expect((await s.appel("inscrire", req)).statut).to.equal(200);
      expect(s.service.annuaire.defis).to.have.length(3);
      expect((await s.appel("preparer_inscription", { session_identity: SESSIONS[1], address: autre(5) })).statut).to.equal(200);
      expect((await s.appel("preparer_inscription", { session_identity: SESSIONS[1], address: autre(6) })).corps.error.code).to.equal("limite_annuaire");
      const rejeu = await s.appel("inscrire", req);
      expect([rejeu.statut, rejeu.corps.error.code]).to.deep.equal([404, "nonce_inconnu"]);
    } finally {
      await s.arreter();
    }
  });
});
