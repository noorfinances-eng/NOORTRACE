// Persistance du service d'approbation de la révision 0.5 (CT-3 EX-7.30,
// EX-13.37, EX-13.38 ; CT-9 TE-19) : annuaire et défis d'inscription dans les
// enregistrements chiffrés de l'état, relus égaux après un arrêt brutal ;
// préséance au démarrage (état persisté, amorce, annuaire vide) ; amorce
// non conforme, avec écart ou d'une autre organisation : refus de démarrer ;
// `registration_ttl_ms` recopié sans opération ; recopie d'`administrators`
// (`changer_administrateurs`, `by` `configuration`). Oracle du chiffrement
// par `node:crypto` seul : AES-256-GCM, données associées d'EX-7.30,
// recopie sous une autre nature ou un autre numéro indéchiffrable,
// instantané altéré refusé, modes 0700 et 0600.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { createDecipheriv } from "node:crypto";
import * as A from "@noortrace/approbation";
import { ClientServiceApprobation } from "@noortrace/enregistreur";
import {
  ANNUAIRE_REFERENCE, OUTIL_PAIEMENT, SESSIONS, VECTEURS_CT3, lancerService, messageCharger, politiqueParcours, repertoireTemporaire, requeteEvaluer, retenue,
} from "./fixtures/approbation-service/outils.mjs";
import {
  adresseDe, appelHttp, configurationEtape6, horlogeReglable, journalService, serviceEtape6, signerTexte, boite,
} from "./fixtures/approbation-service/etape6.mjs";
import * as N from "@noortrace/noyau";

const ID9 = "oidc https://idp.assureur-demo.example approbateur-9";
const ID8 = "oidc https://idp.assureur-demo.example approbateur-8";
const VIDE = path.join(VECTEURS_CT3, "annuaire", "annuaires", "vide.json");
const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

// ---------------------------------------------------------------- oracle du chiffrement (node:crypto seul)

/** Déchiffre un enregistrement `<n> <base64>` d'EX-7.30 ; lève si l'étiquette ne vérifie pas. */
function dechiffrerEnregistrement(cle, nature, n, b64) {
  const o = Buffer.from(b64, "base64");
  expect(o.toString("base64"), "base64 de RFC 4648 §4, avec remplissage").to.equal(b64);
  const d = createDecipheriv("aes-256-gcm", cle, o.subarray(0, 12), { authTagLength: 16 });
  d.setAAD(Buffer.from(`noortrace/approbation/etat/v0\n${nature}\n${n}`, "utf8"));
  d.setAuthTag(o.subarray(o.length - 16));
  return JSON.parse(Buffer.concat([d.update(o.subarray(12, o.length - 16)), d.final()]).toString("utf8"));
}

/** Lit et déchiffre tout l'état sous `state_dir/etat/`. */
function etatDechiffre(stateDir, cle) {
  const dir = path.join(stateDir, "etat");
  const decouper = (l) => {
    const k = l.indexOf(" ");
    return { n: l.slice(0, k), b64: l.slice(k + 1) };
  };
  const lignes = [];
  const j = path.join(dir, "journal.ndjson");
  if (fs.existsSync(j)) {
    const texte = fs.readFileSync(j, "utf8");
    if (texte.length) expect(texte.endsWith("\n")).to.equal(true);
    for (const l of texte.split("\n").filter(Boolean)) {
      const { n, b64 } = decouper(l);
      expect(n).to.match(/^[1-9][0-9]*$/);
      lignes.push({ n: Number(n), clair: dechiffrerEnregistrement(cle, "ligne", n, b64) });
    }
  }
  let instantane = null;
  const i = path.join(dir, "instantane.chiffre");
  if (fs.existsSync(i)) {
    const t = fs.readFileSync(i, "utf8");
    expect(t.endsWith("\n") && t.split("\n").length === 2).to.equal(true);
    const { n, b64 } = decouper(t.trim());
    instantane = { n: Number(n), clair: dechiffrerEnregistrement(cle, "instantane", n, b64) };
  }
  const args = [];
  for (const nom of fs.existsSync(path.join(dir, "arguments")) ? fs.readdirSync(path.join(dir, "arguments")) : []) {
    const { n, b64 } = decouper(fs.readFileSync(path.join(dir, "arguments", nom), "utf8").trim());
    expect(n).to.equal("0");
    const clair = dechiffrerEnregistrement(cle, "arguments", "0", b64);
    expect(clair.nom).to.equal(nom);
    args.push({ nom, clair });
  }
  return { lignes, instantane, args };
}

/** Dernier `annuaire` et derniers `defis` de l'état (instantané puis lignes), ou null. */
function annuaireDeLEtat(e) {
  let annuaire = e.instantane?.clair.annuaire ?? null;
  let defis = e.instantane?.clair.defis ?? null;
  for (const l of e.lignes) {
    if (l.n <= (e.instantane?.n ?? 0)) continue;
    if (l.clair.annuaire) annuaire = l.clair.annuaire;
    if (l.clair.defis) defis = l.clair.defis;
  }
  return { annuaire, defis };
}

const cleDe = (dir) => fs.readFileSync(path.join(dir, "cle-stockage"));

/** Inscrit l'adresse du compte i pour l'identité `id` (défi puis inscription) ; rend la réponse d'inscrire. */
async function inscrire(appel, h, id, i) {
  const p = await appel("preparer_inscription", { session_identity: id, address: adresseDe(i) });
  expect(p.statut, JSON.stringify(p.corps)).to.equal(200);
  h?.avancer(1000);
  const r = await appel("inscrire", { session_identity: id, address: adresseDe(i), message: p.corps.message, signature: signerTexte(i, p.corps.message) });
  expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
  return r.corps;
}

async function refusDemarrer(o) {
  try {
    const s = await serviceEtape6(o);
    await s.arreter();
  } catch (e) {
    return e;
  }
  throw new Error("démarrage accepté");
}

describe("service d'approbation : état chiffré et annuaire persisté (EX-7.30, EX-13.37, EX-13.38)", function () {
  this.timeout(120000);

  describe("TE-19 : chiffrement de l'état (EX-7.30)", function () {
    let dir;
    let cle;
    let s;
    before(async function () {
      const h = horlogeReglable("2026-11-10T11:00:00.000Z");
      s = await serviceEtape6({ horloge: h, essais: { compacterApres: 10 } });
      dir = s.dir;
      cle = cleDe(dir);
      await s.client.charger(messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() }));
      for (let k = 0; k < 4; k++) {
        const requete = requeteEvaluer(OUTIL_PAIEMENT.tool_announced, { claim_id: `2026-9000${k}`, amount: "7400.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" });
        const r = await s.client.evaluer(requete);
        h.avancer(10);
        await s.client.ouvrir(retenue({ requete, rule: r.rule, ticket: r.ticket, seq: 5 + 2 * k, ts: N.ecrireHorodatage(s.h.t) }).ouvrir);
      }
      const e = await inscrire(s.appel, h, ID9, 1);
      expect((await s.appel("valider", { session_identity: SESSIONS.admin, entry: e.entry, address: adresseDe(1) })).statut).to.equal(200);
      expect((await s.appel("preparer_inscription", { session_identity: ID8, address: adresseDe(2) })).statut).to.equal(200);
      await s.arreter();
    });

    it("chaque enregistrement est le base64 de nonce ‖ chiffré ‖ étiquette que node:crypto déchiffre avec les données associées d'EX-7.30", function () {
      const e = etatDechiffre(s.cfg.doc.state_dir, cle);
      expect(e.instantane, "un compactage a eu lieu").to.not.equal(null);
      expect(e.lignes.length).to.be.above(0);
      expect(e.args.length).to.equal(4);
      for (const a of e.args) expect(a.clair.secret).to.contain("CH9300762011623852957");
      // aucun argument en clair hors des fichiers d'arguments
      expect(JSON.stringify(e.instantane.clair)).to.not.contain("CH9300762011623852957");
      for (const l of e.lignes) expect(JSON.stringify(l.clair)).to.not.contain("CH9300762011623852957");
      const { annuaire, defis } = annuaireDeLEtat(e);
      expect(annuaire.revision).to.equal(2);
      expect(defis.map((d) => [d.fields.identity, d.used])).to.deep.equal([[ID9, true], [ID8, false]]);
      // nonces de 12 octets distincts
      const nonces = new Set();
      for (const f of ["journal.ndjson", "instantane.chiffre"]) {
        for (const l of fs.readFileSync(path.join(s.cfg.doc.state_dir, "etat", f), "utf8").split("\n").filter(Boolean)) {
          nonces.add(Buffer.from(l.slice(l.indexOf(" ") + 1), "base64").subarray(0, 12).toString("hex"));
        }
      }
      expect(nonces.size).to.equal(e.lignes.length + 1);
    });

    it("répertoires en 0700, fichiers en 0600 sous state_dir/etat/", function () {
      const etat = path.join(s.cfg.doc.state_dir, "etat");
      for (const d of [s.cfg.doc.state_dir, etat, path.join(etat, "arguments")]) expect((fs.statSync(d).mode & 0o777).toString(8), d).to.equal("700");
      const fichiers = [path.join(etat, "journal.ndjson"), path.join(etat, "instantane.chiffre"), ...fs.readdirSync(path.join(etat, "arguments")).map((f) => path.join(etat, "arguments", f))];
      for (const f of fichiers) expect((fs.statSync(f).mode & 0o777).toString(8), f).to.equal("600");
    });

    it("un enregistrement recopié sous une autre nature ou un autre numéro ne se déchiffre pas", function () {
      const e = path.join(s.cfg.doc.state_dir, "etat");
      const [l1] = fs.readFileSync(path.join(e, "journal.ndjson"), "utf8").split("\n").filter(Boolean);
      const n = l1.slice(0, l1.indexOf(" "));
      const b64 = l1.slice(l1.indexOf(" ") + 1);
      expect(() => dechiffrerEnregistrement(cle, "ligne", n, b64)).to.not.throw();
      expect(() => dechiffrerEnregistrement(cle, "instantane", n, b64)).to.throw();
      expect(() => dechiffrerEnregistrement(cle, "arguments", n, b64)).to.throw();
      expect(() => dechiffrerEnregistrement(cle, "ligne", String(Number(n) + 1), b64)).to.throw();
      const i = fs.readFileSync(path.join(e, "instantane.chiffre"), "utf8").trim();
      expect(() => dechiffrerEnregistrement(cle, "ligne", i.slice(0, i.indexOf(" ")), i.slice(i.indexOf(" ") + 1))).to.throw();
    });

    it("le service refuse de démarrer sur un instantané altéré, sur une ligne autre que la dernière recopiée sous un autre numéro ; une dernière ligne indéchiffrable est tronquée et consignée", async function () {
      const etat = path.join(s.cfg.doc.state_dir, "etat");
      const copie = (nom) => {
        const d = repertoireTemporaire("noortrace-etat-");
        fs.cpSync(dir, d, { recursive: true });
        const doc = { ...s.cfg.doc, state_dir: path.join(d, "service") };
        fs.writeFileSync(path.join(d, "approbation.json"), JSON.stringify(doc));
        void nom;
        return { d, cfg: { ...s.cfg, chemin: path.join(d, "approbation.json"), doc } };
      };
      // instantané altéré : un octet du chiffré
      const a = copie();
      const fi = path.join(a.cfg.doc.state_dir, "etat", "instantane.chiffre");
      const t = fs.readFileSync(fi, "utf8").trim();
      const o = Buffer.from(t.slice(t.indexOf(" ") + 1), "base64");
      o[20] ^= 1;
      fs.writeFileSync(fi, `${t.slice(0, t.indexOf(" "))} ${o.toString("base64")}\n`);
      expect((await refusDemarrer({ dir: a.d, garder: a.cfg })).message).to.match(/auth|unable|Unsupported state/i);
      // une ligne du journal recopiée sous le numéro de la suivante, puis une ligne valide : refus
      const lignes = fs.readFileSync(path.join(etat, "journal.ndjson"), "utf8").split("\n").filter(Boolean);
      expect(lignes.length).to.be.at.least(2);
      const b = copie();
      const n0 = Number(lignes[0].slice(0, lignes[0].indexOf(" ")));
      const fausse = `${n0 + 1} ${lignes[0].slice(lignes[0].indexOf(" ") + 1)}`;
      fs.writeFileSync(path.join(b.cfg.doc.state_dir, "etat", "journal.ndjson"), [lignes[0], fausse, ...lignes.slice(2), ""].join("\n"));
      expect((await refusDemarrer({ dir: b.d, garder: b.cfg })).message).to.match(/journal d'état corrompu/);
      // la même recopie en dernière ligne : tronquée, consignée, démarrage
      const c = copie();
      fs.writeFileSync(path.join(c.cfg.doc.state_dir, "etat", "journal.ndjson"), [...lignes, `${n0 + lignes.length} ${lignes[0].slice(lignes[0].indexOf(" ") + 1)}`, ""].join("\n"));
      const sc = await serviceEtape6({ dir: c.d, garder: c.cfg });
      await sc.arreter();
      expect(journalService(c.cfg.doc.state_dir).some((l) => l.type === "reprise" && l.kind === "derniere_ligne_tronquee")).to.equal(true);
      expect(fs.readFileSync(path.join(c.cfg.doc.state_dir, "etat", "journal.ndjson"), "utf8").split("\n").filter(Boolean)).to.deep.equal(lignes);
    });
  });

  it("reprise après arrêt brutal (SIGKILL) : annuaire et défis non expirés relus égaux ; le défi en attente sert après la reprise", async function () {
    const dir = repertoireTemporaire("noortrace-reprise-annuaire-");
    const cfg = configurationEtape6(dir);
    let svc = await lancerService(cfg.chemin);
    try {
      const appel = (m, c) => appelHttp(svc.console, m, c, cfg.jetonConsole);
      const e = await inscrire(appel, null, ID9, 1);
      expect((await appel("valider", { session_identity: SESSIONS.admin, entry: e.entry, address: adresseDe(1) })).statut).to.equal(200);
      const p = await appel("preparer_inscription", { session_identity: ID8, address: adresseDe(2) });
      expect(p.statut).to.equal(200);
      const avant = (await appel("annuaire", { session_identity: SESSIONS.admin })).corps;
      const etatAvant = annuaireDeLEtat(etatDechiffre(cfg.doc.state_dir, cleDe(dir)));
      await svc.tuer();
      svc = await lancerService(cfg.chemin);
      const appel2 = (m, c) => appelHttp(svc.console, m, c, cfg.jetonConsole);
      expect((await appel2("annuaire", { session_identity: SESSIONS.admin })).corps).to.deep.equal(avant);
      expect(annuaireDeLEtat(etatDechiffre(cfg.doc.state_dir, cleDe(dir)))).to.deep.equal(etatAvant);
      expect(etatAvant.annuaire).to.deep.equal(avant);
      // le défi tiré avant l'arrêt est connu après la reprise
      const r = await appel2("inscrire", { session_identity: ID8, address: adresseDe(2), message: p.corps.message, signature: signerTexte(2, p.corps.message) });
      expect(r.statut, JSON.stringify(r.corps)).to.equal(200);
      expect(r.corps).to.include({ address: adresseDe(2), state: "en_attente", revision: 3 });
      expect(r.corps.entry).to.match(/^apb-[0-9a-f]{16}$/);
    } finally {
      await svc.arreter();
    }
  });

  it("révision 0.6 (EX-7.24, EX-7.30, EX-12.14) : l'intention d'evaluer est gardée avec les arguments, relue après un arrêt brutal (SIGKILL), rendue telle quelle quand l'événement la porte par référence", async function () {
    const dir = repertoireTemporaire("noortrace-reprise-intention-");
    const cfg = configurationEtape6(dir, { annuaire: ANNUAIRE_REFERENCE });
    let svc = await lancerService(cfg.chemin);
    const INTENTION = "Régler le sinistre 2026-90417 ; intention portée par référence dans l'événement";
    try {
      let client = new ClientServiceApprobation({ url: `http://127.0.0.1:${svc.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
      await client.charger(messageCharger({ policy_version: "parcours-1", rules: politiqueParcours() }));
      const requete = { ...requeteEvaluer(OUTIL_PAIEMENT.tool_announced, { claim_id: "2026-90417", amount: "7400.00", currency: "CHF", beneficiary_iban: "CH9300762011623852957" }), intent: INTENTION };
      const r = await client.evaluer(requete);
      expect(r.ticket_state).to.equal("nouveau");
      const ret = retenue({ requete, rule: r.rule, ticket: r.ticket, seq: 5, ts: N.ecrireHorodatage(Date.now() - 100), intentParReference: true });
      expect(ret.evenement.intent).to.not.be.a("string");
      await client.ouvrir(ret.ouvrir);
      const vue = async () => (await appelHttp(svc.console, "consulter", { ticket: r.ticket, session_identity: SESSIONS.admin }, cfg.jetonConsole)).corps;
      const avant = await vue();
      expect(avant.request.intent).to.equal(INTENTION);
      // l'intention est dans le fichier d'arguments chiffré du ticket, jamais dans une ligne
      const e = etatDechiffre(cfg.doc.state_dir, cleDe(dir));
      const fichier = e.args.find((a) => a.nom === `t-${r.ticket}`);
      expect(JSON.parse(fichier.clair.secret).intent).to.equal(INTENTION);
      for (const l of e.lignes) expect(JSON.stringify(l.clair)).to.not.contain(INTENTION);
      await svc.tuer();
      svc = await lancerService(cfg.chemin);
      client = new ClientServiceApprobation({ url: `http://127.0.0.1:${svc.noyau.port}`, jeton: cfg.jetonNoyau, timeout_ms: 5000 });
      expect(await vue()).to.deep.equal(avant);
      void client;
    } finally {
      await svc.arreter();
    }
  });

  describe("préséance au démarrage (EX-13.38)", function () {
    it("sans amorce : l'annuaire vide de la configuration (vide.json), persisté seulement avec la première opération acceptée", async function () {
      const h = horlogeReglable("2026-11-10T08:00:00.000Z");
      const s = await serviceEtape6({ horloge: h });
      try {
        expect((await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps).to.deep.equal(lireJson(VIDE));
        expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire).to.equal(null);
        // une opération refusée ne persiste pas l'annuaire
        expect((await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0001", launched_by: "x" })).corps.error.code).to.equal("entree_inconnue");
        expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire).to.equal(null);
        await inscrire(s.appel, h, ID9, 1);
        expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire.revision).to.equal(1);
      } finally {
        await s.arreter();
      }
    });

    it("amorce conforme : retenue sans être persistée ; après la première opération, seul l'état fait foi (annuaire_amorce_ignoree)", async function () {
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, horloge: horlogeReglable("2026-11-10T11:00:00.000Z") });
      expect((await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps).to.deep.equal(lireJson(ANNUAIRE_REFERENCE));
      expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire).to.equal(null);
      expect((await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0001", launched_by: "agent-essai" })).statut).to.equal(200);
      const apres = (await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps;
      expect(apres.revision).to.equal(10);
      await s.arreter();
      // amorce changée en annuaire vide : ignorée, consignée
      const doc = { ...s.cfg.doc, console: { ...s.cfg.doc.console, annuaire: VIDE } };
      fs.writeFileSync(s.cfg.chemin, JSON.stringify(doc));
      const s2 = await serviceEtape6({ dir: s.dir, garder: { ...s.cfg, doc }, horloge: horlogeReglable("2026-11-10T12:00:00.000Z") });
      try {
        expect((await s2.appel("annuaire", { session_identity: SESSIONS.admin })).corps).to.deep.equal(apres);
        await s2.service.supervision.vider();
        expect(journalService(s.cfg.doc.state_dir).filter((l) => l.type === "annuaire_amorce_ignoree")).to.have.length(1);
      } finally {
        await s2.arreter();
      }
    });

    it("amorce non conforme, avec écart d'EX-13.19, ou d'une autre organisation ou origine : refus de démarrer", async function () {
      const d = repertoireTemporaire("noortrace-amorce-");
      const ecrire = (nom, doc) => {
        const f = path.join(d, nom);
        fs.writeFileSync(f, JSON.stringify(doc));
        return f;
      };
      const ref = lireJson(ANNUAIRE_REFERENCE);
      const cas = [
        [ecrire("schema.json", { ...ref, inconnu: 1 }), /EX-13.38, point 3.*schema/],
        [path.join(VECTEURS_CT3, "annuaire", "exports", "revision-faux.json"), /revision_incoherente/],
        [path.join(VECTEURS_CT3, "annuaire", "exports", "auto-validation.json"), /auto_validation/],
        [ecrire("autre-org.json", { ...lireJson(VIDE), org_id: "0x" + "11".repeat(32) }), /org_id/],
        [ecrire("autre-nom.json", { ...lireJson(VIDE), org: "autre-organisation" }), /un autre org /],
        [ecrire("autre-origine.json", { ...lireJson(VIDE), console_origin: "https://console.autre.example" }), /console_origin/],
        [path.join(d, "absent.json"), /illisible/],
      ];
      for (const [amorce, motif] of cas) {
        const e = await refusDemarrer({ annuaire: amorce });
        expect(e.message, amorce).to.match(motif);
      }
    });

    it("annuaire persisté d'une autre origine que la configuration : refus de démarrer (EX-13.38, point 4)", async function () {
      const h = horlogeReglable("2026-11-10T08:00:00.000Z");
      const s = await serviceEtape6({ horloge: h });
      await inscrire(s.appel, h, ID9, 1);
      await s.arreter();
      const doc = { ...s.cfg.doc, console_origin: "https://console.autre.example" };
      fs.writeFileSync(s.cfg.chemin, JSON.stringify(doc));
      expect((await refusDemarrer({ dir: s.dir, garder: { ...s.cfg, doc } })).message).to.match(/console_origin/);
    });

    it("registration_ttl_ms recopié de la configuration sans opération (annuaire_ttl_recopie), revision et updated_at inchangés ; il vaut pour les défis qui suivent", async function () {
      const ref = lireJson(ANNUAIRE_REFERENCE);
      const h = horlogeReglable("2026-11-10T11:00:00.000Z");
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, registration_ttl_ms: 900000, horloge: h });
      let a = (await s.appel("annuaire", { session_identity: SESSIONS.admin })).corps;
      expect(a).to.deep.equal({ ...ref, registration_ttl_ms: 900000 });
      await s.service.supervision.vider();
      expect(journalService(s.cfg.doc.state_dir).filter((l) => l.type === "annuaire_ttl_recopie").map((l) => [l.avant, l.apres])).to.deep.equal([[600000, 900000]]);
      expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire).to.equal(null);
      expect((await s.appel("lier_demandeur", { session_identity: SESSIONS.admin, entry: "apb-0001", launched_by: "agent-essai" })).statut).to.equal(200);
      await s.arreter();
      // annuaire persisté, nouvelle valeur : recopiée et persistée, sans opération
      const doc = { ...s.cfg.doc, registration_ttl_ms: 120000 };
      fs.writeFileSync(s.cfg.chemin, JSON.stringify(doc));
      const s2 = await serviceEtape6({ dir: s.dir, garder: { ...s.cfg, doc }, horloge: h });
      try {
        a = (await s2.appel("annuaire", { session_identity: SESSIONS.admin })).corps;
        expect(a.registration_ttl_ms).to.equal(120000);
        expect(a.revision).to.equal(10);
        expect(a.operations).to.have.length(10);
        expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire.registration_ttl_ms).to.equal(120000);
        const p = await s2.appel("preparer_inscription", { session_identity: ID9, address: "0x" + "ab".repeat(20) });
        expect(Date.parse(p.corps.fields.expires_at) - Date.parse(p.corps.fields.issued_at)).to.equal(120000);
      } finally {
        await s2.arreter();
      }
      expect(journalService(s.cfg.doc.state_dir).filter((l) => l.type === "annuaire_ttl_recopie")).to.have.length(2);
    });

    it("défis expirés non relus à la reprise ; défis non expirés relus", async function () {
      const h = horlogeReglable("2026-11-10T08:00:00.000Z");
      const s = await serviceEtape6({ horloge: h, registration_ttl_ms: 60000 });
      const p1 = await s.appel("preparer_inscription", { session_identity: ID9, address: adresseDe(1) });
      h.avancer(30000);
      const p2 = await s.appel("preparer_inscription", { session_identity: ID8, address: adresseDe(2) });
      await s.arreter();
      h.avancer(30000); // le premier défi expire à cet instant exactement
      const s2 = await serviceEtape6({ dir: s.dir, garder: s.cfg, horloge: h });
      try {
        const r1 = await s2.appel("inscrire", { session_identity: ID9, address: adresseDe(1), message: p1.corps.message, signature: signerTexte(1, p1.corps.message) });
        expect(r1.corps.error.code).to.equal("nonce_inconnu");
        const r2 = await s2.appel("inscrire", { session_identity: ID8, address: adresseDe(2), message: p2.corps.message, signature: signerTexte(2, p2.corps.message) });
        expect(r2.statut, JSON.stringify(r2.corps)).to.equal(200);
      } finally {
        await s2.arreter();
      }
    });
  });

  describe("recopie d'administrators (EX-13.37)", function () {
    const A1 = SESSIONS.admin;
    const A2 = "oidc https://idp.assureur-demo.example admin-2";

    it("liste différente de la copie : opération changer_administrateurs (by configuration, before, after), persistée avant toute méthode, non notifiée ; liste égale : rien", async function () {
      const h = horlogeReglable("2026-11-10T11:00:00.000Z");
      const s = await serviceEtape6({ annuaire: ANNUAIRE_REFERENCE, administrators: [A1, A2], horloge: h });
      let a;
      try {
        a = (await s.appel("annuaire", { session_identity: A2 })).corps;
        expect(a.revision).to.equal(10);
        expect(a.updated_at).to.equal("2026-11-10T11:00:00.000Z");
        expect(a.administrators).to.deep.equal([A1, A2]);
        expect(a.operations.at(-1)).to.deep.equal({
          seq: 10, at: "2026-11-10T11:00:00.000Z", op: "changer_administrateurs", by: "configuration", entry: null, address: null,
          launched_by: null, reason: null, administrators: { before: [A1], after: [A1, A2] },
        });
        // persistée dès le démarrage
        expect(annuaireDeLEtat(etatDechiffre(s.cfg.doc.state_dir, cleDe(s.dir))).annuaire).to.deep.equal(a);
        // le nouvel administrateur a les droits de la copie en vigueur
        expect((await s.appel("lier_demandeur", { session_identity: A2, entry: "apb-0002", launched_by: "agent-2" })).statut).to.equal(200);
        await s.service.notifications.attendre();
        expect(boite(s.cfg.doc.state_dir).map((l) => JSON.parse(l).details?.op)).to.deep.equal(["lier_demandeur"]);
        // l'opération de la recopie rejouée par un réviseur : sans écart (EX-13.19, point 6)
        const complet = (await s.appel("annuaire", { session_identity: A1 })).corps;
        expect(A.verifierAnnuaireExporte(complet, { conforme: A.annuaireConforme })).to.deep.equal([]);
      } finally {
        await s.arreter();
      }
      // même liste : aucune opération ; ordre changé : une opération (comparée comme liste)
      const s2 = await serviceEtape6({ dir: s.dir, garder: s.cfg, horloge: h });
      expect((await s2.appel("annuaire", { session_identity: A1 })).corps.revision).to.equal(11);
      await s2.arreter();
      const doc = { ...s.cfg.doc, administrators: [A2, A1] };
      fs.writeFileSync(s.cfg.chemin, JSON.stringify(doc));
      const s3 = await serviceEtape6({ dir: s.dir, garder: { ...s.cfg, doc }, horloge: h });
      try {
        const op = (await s3.appel("annuaire", { session_identity: A1 })).corps.operations.at(-1);
        expect(op).to.deep.include({ seq: 12, op: "changer_administrateurs", by: "configuration", administrators: { before: [A1, A2], after: [A2, A1] } });
      } finally {
        await s3.arreter();
      }
    });

    it("une valeur hors de la forme d'EX-13.9 n'est pas recopiée : refus de démarrer", async function () {
      const dir = repertoireTemporaire("noortrace-admins-");
      const cfg = configurationEtape6(dir);
      const charge = A.chargerConfiguration(cfg.chemin);
      for (const l of [[], [A1, A1], ["pas une identite"]]) {
        const e = await A.demarrerService({ config: { ...charge.config, administrators: l }, secrets: charge.secrets, base: dir }).then((i) => i.arreter().then(() => null), (x) => x);
        expect(e?.message, JSON.stringify(l)).to.match(/administrators|identite_invalide/);
      }
    });
  });
});
