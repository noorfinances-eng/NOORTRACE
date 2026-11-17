// CT-5 : passages que le texte ne tranchait pas, écrits par le complément du
// 2026-11-16 selon la lecture la plus sûre, et appliqués par la référence
// (scripts/lib/ancrage.mjs) et le composant d'ancrage (paquets/ancrage) :
//
// - EX-8.12 : une demande de jeton recréée `obtenue` s'applique comme à sa
//   promotion (EX-4.4) et clôt `remplacee` la demande de point relue qui sert
//   des échéances antérieures (trace `redemarrage-jeton-recree-couvrant`) ;
// - EX-8.10, EX-8.12, EX-4.13 : une ancre au registre passe `a_reprendre`
//   après un échec signalé par le registre ; elle et une soumission
//   OpenTimestamps `a_reprendre` gardent leur `due_at` au démarrage (trace
//   `redemarrage-ancres-a-reprendre`) ; une reprise échue pendant l'arrêt part
//   au démarrage, jamais avant ;
// - EX-8.4, règle 2 : le repli de clôture se lit à la lettre, ancre de la
//   période incluse et jeton retenu par `min_interval_ms` compris (trace
//   `repli-ancre-incluse-jeton-retenu`) ;
// - EX-8.3, AN-33, AN-34 : hors de la table, trois écritures du démarrage et
//   elles seules ;
// - EX-4.9 : règle 4 (rôle `interne` lui-même), règle 8 (lecteur de CT-6
//   §9.3), règle 9 (127 octets, étiquette et longueur comprises) : cas de la
//   famille `configuration`.
//
// Chaque règle retirée de la référence ou du composant (copie sous
// NOORTRACE_TMP, défaut os.tmpdir(), détruite à la fin) fait diverger le rejeu
// ou un cas (mutant tué). Les vecteurs sont lus dans le dépôt ; le code est lu
// dans le dépôt, ou sous NOORTRACE_REVUE_RACINE (code d'avant : essai rouge).

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const CT5 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-5");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const COPIES = [];
const unique = () => `?t=${Date.now()}-${Math.random()}`;
const trace = (id) => JSON.parse(fs.readFileSync(path.join(CT5, "planification", `${id}.json`), "utf8"));
const CONFIGURATION = JSON.parse(fs.readFileSync(path.join(CT5, "configuration", "configuration.json"), "utf8"));

/** Copie d'un sous-arbre de RACINE sous TMP (node_modules, spec et package.json liés), un fichier modifié par un remplacement unique. */
function copie(nom, sousArbre, fichier, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-lectures-tranchees-${nom}-`));
  COPIES.push(racine);
  fs.mkdirSync(path.join(racine, path.dirname(sousArbre)), { recursive: true });
  fs.cpSync(path.join(RACINE, sousArbre), path.join(racine, sousArbre), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, fichier);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`copie ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
const reference = (racine) => import(pathToFileURL(path.join(racine, "scripts", "lib", "ancrage.mjs")).href + unique());
const composant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "traces.mjs")).href + unique());
const configurationComposant = (racine) => import(pathToFileURL(path.join(racine, "paquets", "ancrage", "src", "planificateur", "configuration.mjs")).href + unique());
const PLANIFICATEUR = "paquets/ancrage/src/planificateur/planificateur.mjs";
const CONF = "paquets/ancrage/src/planificateur/configuration.mjs";
const mutantReference = (nom, ancien, nouveau) => reference(copie(nom, "scripts/lib", "scripts/lib/ancrage.mjs", ancien, nouveau));
const mutantComposant = (nom, ancien, nouveau, fichier = PLANIFICATEUR) => copie(nom, "paquets/ancrage/src", fichier, ancien, nouveau);

after(function () {
  for (const r of COPIES) fs.rmSync(r, { recursive: true, force: true });
});

/** Écarts de la référence (verifierTrace) et du composant (rejouerTrace) sur une trace publiée. */
async function ecarts(id, { R = null, C = null } = {}) {
  const t = trace(id);
  const ref = R ?? (await reference(RACINE));
  const comp = C ?? (await composant(RACINE));
  return { reference: ref.verifierTrace(t).length, composant: comp.rejouerTrace(t).ecarts.length };
}

const tri = (liste) => [...new Set(liste.map(String))].sort();
/** Cas de configuration dont le verdict ou les règles diffèrent de l'attendu, pour la référence (A) et le composant (C). */
function ecartsConfiguration(A, C, ids) {
  const ref = [];
  const comp = [];
  for (const c of CONFIGURATION.cases.filter((x) => ids.includes(x.id))) {
    const r = A.verifierConfiguration(c.input.document, { profil: c.input.profil, checkpoint_interval_s: c.input.checkpoint_interval_s });
    if (JSON.stringify(tri(r.violations.map((v) => v.rule))) !== JSON.stringify(c.expected.regles) || r.valide !== c.expected.valide) ref.push(c.id);
    const k = C.validerConfiguration(c.input.document, { profil: c.input.profil, checkpointIntervalEnregistreur: c.input.checkpoint_interval_s });
    if (JSON.stringify(tri(k.erreurs.map((e) => e.regle))) !== JSON.stringify(c.expected.regles) || k.valide !== c.expected.valide) comp.push(c.id);
  }
  return { reference: ref, composant: comp };
}
const CAS_NOUVEAUX = ["oid-der-127-octets", "oid-der-128-octets", "interne-https-sans-authentification", "interne-http-local-basic", "interne-https-basic", "certificat-tronque"];

describe("CT-5 : passages tranchés par le complément du 2026-11-16 (EX-8.12, EX-8.10, EX-4.13, EX-8.4, EX-8.3, EX-4.9)", function () {
  this.timeout(300000);

  it("EX-8.12, EX-4.4 : redemarrage-jeton-recree-couvrant est rejouée sans écart ; le jeton recréé obtenu de K3 clôt remplacee la demande relue de K1 (D_1 à D_8), checkpoint_anchor_late", async function () {
    expect(await ecarts("redemarrage-jeton-recree-couvrant")).to.deep.equal({ reference: 0, composant: 0 });
    const t = trace("redemarrage-jeton-recree-couvrant");
    const k1 = t.queue_after.find((d) => d.id.startsWith("jeton_point:") && d.deadlines.includes(1));
    const k3 = t.queue_after.find((d) => d.id.startsWith("jeton_point:") && d.deadlines.includes(9));
    expect([k1.state, k1.replaced_by, k3.state, k3.attempts_total]).to.deep.equal(["remplacee", k3.id, "obtenue", 0]);
    expect(t.expected.filter((a) => a.action === "journaliser" && a.detail.event === "checkpoint_anchor_late").map((a) => a.request_id)).to.deep.equal([k1.id]);
  });

  it("mutants CT-5 EX-8.12 (référence et composant) : sans EX-4.4 pour la demande recréée obtenue, la demande de K1 reste active (tués)", async function () {
    const R = await mutantReference("recree-couvrant-ref", "    this.clorePointsAnterieurs(d, t, p, ms(r.bound), d.kind === \"jeton_point\" ? Math.max(...d.deadlines) : this.nT);", "");
    expect((await ecarts("redemarrage-jeton-recree-couvrant", { R })).reference).to.be.above(0);
    const C = await composant(mutantComposant("recree-couvrant-comp", "    this.remplacerAnterieures(p, req, ms(r.bound), req.kind === \"jeton_point\" ? Math.min(...req.deadlines) : Infinity);\n  }", "  }"));
    expect((await ecarts("redemarrage-jeton-recree-couvrant", { C })).composant).to.be.above(0);
  });

  it("mutant CT-5 EX-8.12 (composant) : une reprise échue pendant l'arrêt datée de son due_at passé, avant le démarrage (tué)", async function () {
    const C = await composant(mutantComposant("reprise-echue-comp", "l'instant de celui-ci (trace redemarrage-jeton-recree-couvrant).\n          const at = Math.max(d.due_at ? ms(d.due_at) : this.now, this.now);", "l'instant de celui-ci (trace redemarrage-jeton-recree-couvrant).\n          const at = d.due_at ? ms(d.due_at) : this.now;"));
    expect((await ecarts("redemarrage-jeton-recree-couvrant", { C })).composant).to.be.above(0);
  });

  it("EX-8.10, EX-8.12, EX-4.13 : redemarrage-ancres-a-reprendre est rejouée sans écart ; l'ancre a_reprendre après noeud_injoignable (anchor_retry de mode reprise) et la soumission OpenTimestamps a_reprendre gardent leur due_at au démarrage", async function () {
    expect(await ecarts("redemarrage-ancres-a-reprendre")).to.deep.equal({ reference: 0, composant: 0 });
    const t = trace("redemarrage-ancres-a-reprendre");
    const ancre = t.queue_before.find((d) => d.kind === "ancre_registre_periode");
    const ots = t.queue_before.find((d) => d.kind === "ots_periode");
    expect([ancre.state, ancre.due_at, ancre.attempts[0].error_code, ots.state, ots.due_at]).to.deep.equal(["a_reprendre", "2026-11-03T14:00:06.000Z", "noeud_injoignable", "a_reprendre", "2026-11-03T14:00:07.000Z"]);
    const envois = t.expected.filter((a) => ["envoyer_registre", "soumettre_ots"].includes(a.action)).map((a) => [a.t, a.action]);
    expect(envois).to.deep.equal([["2026-11-03T14:00:06.000Z", "envoyer_registre"], ["2026-11-03T14:00:07.000Z", "soumettre_ots"]]);
  });

  it("EX-8.10 (référence) : un échec transitoire du registre rend l'ancre a_reprendre au pas d'EX-8.9 (ligne anchor_retry de mode reprise) ; un refus définitif refuse l'ancre d'un point (son jeton part) et reprend celle d'une période au pas retry.max_ms", async function () {
    const A = await reference(RACINE);
    const t = trace("heure-nominale-reference");
    const k1 = t.inputs.find((e) => e.type === "point_produit");
    const cloture = t.inputs.find((e) => e.type === "periode_close");
    const ancre = `ancre_registre_point:${k1.data.checkpoint_hash}`;
    const periode = `ancre_registre_periode:${cloture.data.period_hash}`;
    const r = A.rejouerTrace({ ...t, jitter_ms: [0, 0], queue_before: [], inputs: [
      { t: "2026-11-03T13:40:00.000Z", type: "demarrage", data: {} },
      { t: k1.t, type: "point_produit", data: k1.data },
      { t: "2026-11-03T13:42:01.000Z", type: "echec_registre", data: { request_id: ancre, code: "noeud_injoignable" } },
      { t: "2026-11-03T13:42:10.000Z", type: "tic", data: {} },
      { t: "2026-11-03T13:42:11.000Z", type: "echec_registre", data: { request_id: ancre, code: "refus_emetteur_inconnu" } },
      { t: cloture.t, type: "periode_close", data: cloture.data },
      { t: "2026-11-03T14:00:01.000Z", type: "echec_registre", data: { request_id: periode, code: "refus_fonds_insuffisants" } },
      { t: "2026-11-03T14:00:02.000Z", type: "arret", data: {} },
    ] });
    const a = r.file.find((d) => d.id === ancre);
    expect(a.state).to.equal("refusee");
    expect(a.attempts.map((x) => [x.outcome, x.error_code])).to.deep.equal([["echec_transitoire", "noeud_injoignable"], ["echec_permanente", "refus_emetteur_inconnu"]]);
    expect(r.actions.filter((x) => x.action === "envoyer_registre" && x.request_id === ancre).map((x) => x.t)).to.deep.equal([k1.t, "2026-11-03T13:42:06.000Z"]);
    expect(r.actions.find((x) => x.action === "journaliser" && x.detail.event === "anchor_retry")?.detail).to.deep.include({ mode: "reprise", error_code: "noeud_injoignable", attempt: 1 });
    expect(r.actions.some((x) => x.action === "envoyer_rfc3161" && x.request_id === `jeton_point:${k1.data.checkpoint_hash}`)).to.equal(true);
    const p = r.file.find((d) => d.id === periode);
    expect([p.state, p.due_at]).to.deep.equal(["a_reprendre", "2026-11-03T14:05:01.000Z"]);
  });

  it("mutants CT-5 EX-8.12 : sans la reprise d'une ancre a_reprendre au démarrage (référence), sans le due_at gardé d'une soumission OpenTimestamps (composant), la trace diverge (tués)", async function () {
    const R = await mutantReference("ancre-a-reprendre-ref", "        } else if (d.state === \"a_reprendre\") {\n          // EX-8.12 (a_reprendre garde due_at) et EX-4.13", "        } else if (false) {\n          // EX-8.12 (a_reprendre garde due_at) et EX-4.13");
    expect((await ecarts("redemarrage-ancres-a-reprendre", { R })).reference).to.be.above(0);
    const C = await composant(mutantComposant("ots-a-reprendre-comp", "if (!this.bornerReprise(d, \"reprise_ots\")) this.timers.push({ at: Math.max(d.due_at ? ms(d.due_at) : this.now, this.now),", "if (!this.bornerReprise(d, \"reprise_ots\")) this.timers.push({ at: this.now,"));
    expect((await ecarts("redemarrage-ancres-a-reprendre", { C })).composant).to.be.above(0);
  });

  it("EX-8.4, règle 2 : repli-ancre-incluse-jeton-retenu est rejouée sans écart ; repli à 14:00:05.250 malgré l'ancre de la période incluse, clos remplacee par le jeton de clôture sans être envoyé", async function () {
    expect(await ecarts("repli-ancre-incluse-jeton-retenu")).to.deep.equal({ reference: 0, composant: 0 });
    const t = trace("repli-ancre-incluse-jeton-retenu");
    const repli = t.expected.filter((a) => a.action === "journaliser" && a.detail.event === "checkpoint_closing_fallback");
    expect(repli.map((a) => a.t)).to.deep.equal(["2026-11-03T14:00:05.250Z"]);
    expect(t.queue_after.find((d) => d.id === repli[0].request_id).state).to.equal("remplacee");
    expect(t.expected.some((a) => a.action === "envoyer_rfc3161" && a.request_id === repli[0].request_id)).to.equal(false);
  });

  it("mutants CT-5 EX-8.4, règle 2 : le repli écarté quand l'ancre de la période est incluse, dans la référence ou dans le composant (tués)", async function () {
    const R = await mutantReference("repli-ref", "        if (!ancre) return;\n        this.repliCloture(d, t);", "        if (!ancre || ancre.state === \"obtenue\") return;\n        this.repliCloture(d, t);");
    expect((await ecarts("repli-ancre-incluse-jeton-retenu", { R })).reference).to.be.above(0);
    const C = await composant(mutantComposant("repli-comp", "    if (jetonPeriode.state !== \"attente_registre\") return;", "    if (jetonPeriode.state !== \"attente_registre\" || this.demandes.get(`ancre_registre_periode:${jetonPeriode.subject.hash}`)?.state === \"obtenue\") return;"));
    expect((await ecarts("repli-ancre-incluse-jeton-retenu", { C })).composant).to.be.above(0);
  });

  it("EX-8.3, AN-33, AN-34 : sur les soixante-deux traces, les seules transitions hors de la table sont les quatre écritures du démarrage (première ligne obtenue d'une demande de jeton recréée, a_reprendre → a_reprendre après programmer backoff, a_reprendre → a_reprendre d'une soumission OpenTimestamps qui portait une tentative en cours, obtenue → a_reprendre de la réouverture)", function () {
    const TABLE = {
      a_envoyer: ["envoyee", "remplacee"],
      attente_registre: ["envoyee", "remplacee"],
      envoyee: ["obtenue", "en_attente", "a_reprendre", "envoyee", "a_envoyer", "refusee", "remplacee"],
      a_reprendre: ["envoyee", "remplacee"],
      en_attente: ["complete", "en_attente"],
      obtenue: ["a_reprendre"],
      complete: [], sans_objet: [], refusee: [], remplacee: [],
    };
    const hors = [];
    const fichiers = fs.readdirSync(path.join(CT5, "planification")).filter((f) => f.endsWith(".json"));
    // CT-5 A.3 (complément du 2026-11-16, ordre du démarrage ; puis clé de chaîne du verrou d'EX-9.4 ; puis minuteries de deux journaux, EX-8.16 ; puis refus de l'ancre d'une période et ordre des ancres de points, EX-8.10 et EX-9.4 : deux de plus ; puis l'ancre de la période après celle de son point de clôture et l'âge d'abandon OpenTimestamps, EX-9.4 et EX-8.11 : deux de plus, dont une à file ; puis la clé retenue par l'ancre d'une période, la soumission OpenTimestamps tardive et l'alerte du refus après un redémarrage, EX-9.4, EX-8.11 et EX-8.10 : trois de plus, dont deux à file ; puis l'ancre d'un point en reprise quand le point suivant de sa période est admis, EX-9.5 et EX-9.4 : une de plus, sans file) : soixante-deux traces.
    expect(fichiers).to.have.lengthOf(62);
    for (const f of fichiers) {
      const t = JSON.parse(fs.readFileSync(path.join(CT5, "planification", f), "utf8"));
      const etats = new Map(t.queue_before.map((d) => [d.id, d.state]));
      t.expected.forEach((a, i) => {
        if (a.action !== "ecrire_file") return;
        const avant = etats.get(a.request_id);
        const apres = a.detail.state;
        etats.set(a.request_id, apres);
        if (avant === undefined ? ["a_envoyer", "attente_registre"].includes(apres) : TABLE[avant].includes(apres)) return;
        const stockage = t.inputs.find((e) => e.t === a.t && e.type === "stockage_relu");
        const demarrage = t.inputs.find((e) => e.t === a.t && e.type === "demarrage");
        const precedente = t.expected[i - 1];
        if (avant === undefined && apres === "obtenue" && Array.isArray(stockage?.data.acquisitions)) return;
        if (avant === "a_reprendre" && apres === "a_reprendre" && demarrage && precedente?.action === "programmer" && precedente.detail.reason === "backoff" && precedente.request_id === a.request_id) return;
        // CT-5 EX-8.12 (complément du 2026-11-16) : une ligne a_reprendre qui porte encore une soumission en cours est
        // réécrite a_reprendre au démarrage, sa tentative close redemarrage, puis programmée immediat.
        const suivante = t.expected[i + 1];
        if (avant === "a_reprendre" && apres === "a_reprendre" && demarrage && a.request_id.startsWith("ots_") && t.queue_before.find((d) => d.id === a.request_id)?.attempts.some((x) => x.outcome === "en_cours") && suivante?.action === "programmer" && suivante.detail.reason === "immediat") return;
        hors.push(`${f} : ${avant ?? "(première ligne)"} → ${apres} (${a.request_id.split(":")[0]} à ${a.t})`);
      });
    }
    expect(hors).to.deep.equal([]);
    // obtenue → a_reprendre, admise par la table pour la révocation, est aussi celle de la réouverture d'EX-5.8 au démarrage.
    const reouverte = trace("redemarrage-jeton-sans-acquisition");
    expect(reouverte.expected[1]).to.deep.include({ action: "ecrire_file", detail: { state: "a_reprendre" } });
    expect(reouverte.queue_before.find((d) => d.id === reouverte.expected[1].request_id).state).to.equal("obtenue");
  });

  it("EX-4.9, règles 4, 8 et 9 : la référence et le composant rendent l'attendu des six cas nouveaux (rôle interne en https:// sans authentification et en http:// local avec basic refusés, en https:// avec basic admis ; certificat tronqué ; DER de 127 octets admis et de 128 octets refusé)", async function () {
    expect(CONFIGURATION.cases.map((c) => c.id)).to.include.members(CAS_NOUVEAUX);
    expect(ecartsConfiguration(await reference(RACINE), await configurationComposant(RACINE), CAS_NOUVEAUX)).to.deep.equal({ reference: [], composant: [] });
    const oid = (id) => CONFIGURATION.cases.find((c) => c.id === id).input.document.rfc3161.providers.find((p) => p.role === "interne").policy_oid;
    const A = await reference(RACINE);
    expect([A.encoderOIDDER(oid("oid-der-127-octets")).length, A.encoderOIDDER(oid("oid-der-128-octets")).length]).to.deep.equal([127, 128]);
  });

  it("mutants CT-5 EX-4.9 : règle 9 comptée sur le seul contenu (référence, composant), règle 4 du rôle interne retirée (composant) (tués)", async function () {
    const C = await configurationComposant(RACINE);
    const A = await reference(RACINE);
    const R9 = await mutantReference("regle-9-contenu-ref", "if (der.length > OID_DER_MAX) v(9,", "if (der.length - 2 > OID_DER_MAX) v(9,");
    expect(ecartsConfiguration(R9, C, CAS_NOUVEAUX).reference).to.deep.equal(["oid-der-128-octets"]);
    const C9 = await configurationComposant(mutantComposant("regle-9-contenu-comp", "  if (der.length > OID_DER_MAX) return", "  if (der.length - 2 > OID_DER_MAX) return", CONF));
    expect(ecartsConfiguration(A, C9, CAS_NOUVEAUX).composant).to.deep.equal(["oid-der-128-octets"]);
    const racine4 = mutantComposant("regle-4-interne-comp", "    if (interne && u.protocole === \"http:\" && p.auth.method !== \"aucune\") violer(", "    if (false) violer(", CONF);
    const f = path.join(racine4, CONF);
    fs.writeFileSync(f, fs.readFileSync(f, "utf8").replace("    if (interne && u.protocole === \"https:\" && p.auth.method === \"aucune\") violer(", "    if (false) violer("));
    expect(ecartsConfiguration(A, await configurationComposant(racine4), CAS_NOUVEAUX).composant).to.deep.equal(["interne-https-sans-authentification", "interne-http-local-basic"]);
  });

  it("EX-4.9, règle 8 : un certificat dont la version v1 est encodée (EX-9.21 de CT-6) est refusé par la référence et par le composant, qui lisent le TBSCertificate par le lecteur de CT-6 §9.3 ; le squelette seul l'admettait (mutant tué)", async function () {
    const base = CONFIGURATION.cases.find((c) => c.id === "exemple-developpement").input.document;
    const pem = base.rfc3161.providers.find((p) => p.role === "interne").anchor_certificates[0];
    const der = Buffer.from(pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, ""), "base64");
    const i = der.indexOf(Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]));
    expect(i).to.be.within(4, 12);
    const v1 = Buffer.from(der);
    v1[i + 4] = 0x00;
    const pemV1 = `-----BEGIN CERTIFICATE-----\n${v1.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;
    const doc = JSON.parse(JSON.stringify(base));
    doc.rfc3161.providers.find((p) => p.role === "interne").anchor_certificates = [pemV1];
    const A = await reference(RACINE);
    const C = await configurationComposant(RACINE);
    expect(tri(A.verifierConfiguration(doc, { profil: "developpement", checkpoint_interval_s: 60 }).violations.map((v) => v.rule))).to.deep.equal(["8"]);
    expect(tri(C.validerConfiguration(doc, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).erreurs.map((e) => e.regle))).to.deep.equal(["8"]);
    expect(C.validerConfiguration(base, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).valide).to.equal(true);
    const M = await configurationComposant(mutantComposant("regle-8-squelette-comp", "    lireCertificat(new Uint8Array(der));", "    void der;", CONF));
    expect(M.validerConfiguration(doc, { profil: "developpement", checkpointIntervalEnregistreur: 60 }).valide).to.equal(true);
  });

  it("INDEX.md et CT-5 (A.3, A.4, note de révision) nomment les trois traces et les six cas", function () {
    const index = fs.readFileSync(path.join(CT5, "INDEX.md"), "utf8");
    const ct5 = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-5-ancrage.md"), "utf8").replace(/[ \n]+/g, " ");
    const a3 = ct5.slice(ct5.indexOf("### A.3 Disposition"), ct5.indexOf("### A.4 Familles"));
    for (const id of ["redemarrage-jeton-recree-couvrant", "redemarrage-ancres-a-reprendre", "repli-ancre-incluse-jeton-retenu"]) {
      expect(index).to.include(`| \`${id}.json\` |`);
      expect(a3).to.include(`${id}.json`);
      expect(ct5).to.include(`trace \`${id}\``);
    }
    for (const id of CAS_NOUVEAUX) expect(index).to.include(`| \`${id}\` |`);
    expect(a3).to.include("trente-huit traces");
  });
});
