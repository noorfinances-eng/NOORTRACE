// Essais du harnais de mesure de CT-2 EX-16.2 et des outils de campagne de
// CT-9 §11 (scripts/mesures/) : percentiles au plus proche rang (EX-11.4),
// règles de `met` et d'`excluded_reason` (EX-11.2, EX-11.14), émission à
// cadence fixe et omission coordonnée (EX-11.9), serveur d'outils nul et
// fournisseur simulé (EX-16.2, pas 2), latence par octet d'un flux SSE
// (pas 5), configuration de mesure (pas 1), harnais entier sur l'enregistreur
// réel avec un petit effectif, rapports acceptés par l'outil publié de CT-9 ;
// campagne TM-30 sur des calendriers locaux (aucun réseau public : EX-3.11,
// décision du porteur), refus de partir sans `--reseau-public`.
//
// Aucune valeur mesurée ici n'est une mesure publiée : les effectifs sont
// petits et la machine n'est pas le système de référence (EX-11.1).

import { expect } from "chai";
import { network } from "hardhat";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { plusProcheRang, agreger, effectifMinimal, ligne, comptePourLesCibles, rapportMesure, validerRapport, ecrireRapportValide, systeme, typeDisque, lireJson, sha256Hex, CATALOGUE, UNITES } from "../scripts/mesures/commun.mjs";
import { creerServeur, preparerReponse, remplissage } from "../scripts/mesures/serveur-nul.mjs";
import { creerFournisseur, preparerMessage, evenementsFlux } from "../scripts/mesures/fournisseur-simule.mjs";
import { Connexion, aCadenceFixe, enSerie, fabriqueAppelOutil, fabriqueEchangeModele, reponseOutilReussie } from "../scripts/mesures/hote.mjs";
import { latencesOctets, executer as executerHarnais, CAMPAGNES, differenceHistogramme } from "../scripts/mesures/ct-2-perf.mjs";
import { lireConfigurationPubliee, CONFIGURATION_PUBLIEE, MEMBRES_REMPLACES } from "../scripts/mesures/montage.mjs";
import { soumettreCampagne, mettreANiveauCampagne, rapportCampagne, relireCampagne, executer as executerTm30, ErreurCampagne } from "../scripts/mesures/tm-30-calendriers-publics.mjs";
import { calendriersFactices } from "./fixtures/ancrage-composant/outils.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_CONFIGURATION = path.join(RACINE, "test", "fixtures", "mesures", "configuration-mesure.json");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const tmp = (p) => fs.mkdtempSync(path.join(TMP, p));
const catalogue = lireJson(CATALOGUE);
const ecoute = (serveur) => new Promise((r) => serveur.listen(0, "127.0.0.1", () => r(serveur.address().port)));
const fermer = (serveur) => new Promise((r) => {
  serveur.closeAllConnections?.();
  serveur.close(() => r());
});
const getJson = (port, chemin) => new Promise((res, rej) => {
  http.get({ host: "127.0.0.1", port, path: chemin, agent: false }, (x) => {
    let t = "";
    x.on("data", (k) => (t += k));
    x.on("end", () => res(JSON.parse(t)));
  }).on("error", rej);
});

describe("Mesures (CT-9 §11) : outils communs des campagnes (scripts/mesures/commun.mjs)", () => {
  it("plusProcheRang : valeur de rang ceil(p/100 × N) de la série triée (EX-11.4) ; p99 d'une série de 100 est le maximum, d'une série de 101 l'avant-dernière", () => {
    const serie = Array.from({ length: 100 }, (_, i) => 100 - i);
    expect(plusProcheRang(serie, 50)).to.equal(50);
    expect(plusProcheRang(serie, 95)).to.equal(95);
    expect(plusProcheRang(serie, 99)).to.equal(99);
    expect(plusProcheRang(serie, 100)).to.equal(100);
    expect(plusProcheRang([7], 99)).to.equal(7);
    expect(plusProcheRang([3, 1, 2], 50)).to.equal(2);
    expect(plusProcheRang([...serie, 1000], 99)).to.equal(100);
    expect(() => plusProcheRang([], 50)).to.throw(RangeError);
    expect(() => plusProcheRang([1], 0)).to.throw(RangeError);
    expect(effectifMinimal(99)).to.equal(100);
    expect(effectifMinimal(95)).to.equal(20);
    const a = agreger([1.0004, 2, 3]);
    expect(a).to.deep.equal({ n: 3, p50: 2, p95: 3, p99: 3, min: 1, max: 3, mean: 2 });
  });

  it("comptePourLesCibles (EX-11.2) : disque en mémoire, fdatasync désactivé ou machine hors référence ne comptent pas, dans cet ordre de raison ; le système de référence avec fdatasync compte", () => {
    const base = { reference: true, disk: { type: "nvme", fsync: true } };
    expect(comptePourLesCibles(base)).to.deep.equal({ compte: true, raison: null });
    expect(comptePourLesCibles({ ...base, disk: { type: "memoire", fsync: true } })).to.deep.equal({ compte: false, raison: "disque_memoire" });
    expect(comptePourLesCibles({ ...base, disk: { type: "ssd", fsync: false } })).to.deep.equal({ compte: false, raison: "fsync_desactive" });
    expect(comptePourLesCibles({ ...base, reference: false })).to.deep.equal({ compte: false, raison: "hors_systeme_de_reference" });
    expect(comptePourLesCibles({ reference: false, disk: { type: "memoire", fsync: false } }).raison).to.equal("disque_memoire");
  });

  it("ligne : met null et excluded_reason hors référence ; sur le système de référence, met vrai ou faux selon la cible du catalogue (p50_et_p99_au_plus, au_moins, p99_au_plus, au_plus sur max), aucune_cible sans met, p99 absent sous 100 échantillons", () => {
    const hors = { compte: false, raison: "hors_systeme_de_reference" };
    const ref = { compte: true, raison: null };
    const serie100 = Array.from({ length: 100 }, (_, i) => 1 + i / 100);
    const l = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: serie100, connections: 1, compte: hors, catalogue });
    expect(l.met).to.equal(null);
    expect(l.excluded_reason).to.equal("hors_systeme_de_reference");
    expect(l.target).to.deep.equal({ p50: 5, p99: 50 });
    expect(l.samples).to.have.length(100);
    expect(l.n).to.equal(100);
    const ok = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: serie100, connections: 1, compte: ref, catalogue });
    expect(ok.met).to.equal(true);
    expect(ok.excluded_reason).to.equal(null);
    const ko = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: serie100.map((x) => x * 10), connections: 1, compte: ref, catalogue });
    expect(ko.met).to.equal(false);
    // p50 ≤ 5 mais p99 > 50 : faux (sur 100 échantillons, le p99 est le 99e : deux valeurs au-dessus de 50 le font dépasser ; une seule ne suffit pas).
    const mixte = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: [...Array(98).fill(1), 51, 52], connections: 1, compte: ref, catalogue });
    expect(mixte.met).to.equal(false);
    expect(mixte.p99).to.equal(51);
    expect(ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: [...Array(99).fill(1), 51], connections: 1, compte: ref, catalogue }).met).to.equal(true);
    expect(ligne({ name: "debit", test_id: "TM-3", unit: "evenements_par_s", value: 500, n: 20000, connections: 16, compte: ref, catalogue }).met).to.equal(true);
    expect(ligne({ name: "debit", test_id: "TM-3", unit: "evenements_par_s", value: 499.9, n: 20000, connections: 16, compte: ref, catalogue }).met).to.equal(false);
    expect(ligne({ name: "reprise", test_id: "TM-8", unit: "ms", serie: Array(100).fill(2000), compte: ref, catalogue }).met).to.equal(true);
    expect(ligne({ name: "latence_premier_octet_sse", test_id: "TM-2", unit: "ms", serie: [1, 2, 10.001], compte: ref, catalogue }).met).to.equal(false);
    const sans = ligne({ name: "signature", test_id: "TM-5", unit: "ms", serie: [0.3, 0.4], compte: ref, catalogue });
    expect(sans.met).to.equal(null);
    expect(sans.excluded_reason).to.equal("aucune_cible");
    // Moins de 100 échantillons : p99 absent, donc met null et échantillon insuffisant (EX-11.3).
    const court = ligne({ name: "reprise", test_id: "TM-8", unit: "ms", serie: Array(10).fill(100), compte: ref, catalogue });
    expect(court.p99).to.equal(null);
    expect(court.met).to.equal(null);
    expect(court.excluded_reason).to.equal("echantillon_insuffisant");
    // Ligne supplémentaire : ni cible ni met (EX-11.11).
    const sup = ligne({ name: "reprise_processus", test_id: "TM-8", unit: "ms", serie: serie100, principale: false, compte: ref, catalogue });
    expect(sup.target).to.equal(null);
    expect(sup.met).to.equal(null);
    // Au-delà de 512 échantillons, publiés à part (samples_sha256).
    const grande = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: Array(513).fill(1), compte: hors, catalogue });
    expect(grande.samples).to.equal(null);
    expect(grande.samples_sha256).to.match(/^[0-9a-f]{64}$/);
    // Avec un fichier désigné, la série est écrite à part et son SHA-256 est celui du fichier (EX-11.4).
    const d = tmp("noortrace-mesure-echantillons-");
    const f = path.join(d, "echantillons.json");
    const aPart = ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: Array.from({ length: 600 }, (_, i) => i / 10), compte: hors, catalogue, fichierEchantillons: f });
    expect(JSON.parse(fs.readFileSync(f, "utf8"))).to.have.length(600);
    expect(aPart.samples_sha256).to.equal(sha256Hex(fs.readFileSync(f)));
    fs.rmSync(d, { recursive: true, force: true });
    expect(() => ligne({ name: "x", test_id: "TM-1", unit: "secondes", serie: [1], compte: hors, catalogue })).to.throw(/EX-11\.6/);
    expect(() => ligne({ name: "x", test_id: "TU-1", unit: "ms", serie: [1], compte: hors, catalogue })).to.throw(/TM-/);
    expect(UNITES).to.include.members(["ms", "s", "octets", "evenements_par_s", "nombre"]);
  });

  it("rapportMesure + validerRapport : un rapport hors référence est accepté par scripts/tests/mesures.mjs (boîte noire) ; un rapport dont une ligne porte met vrai sans compter, ou dont une entrée n'a pas sa ligne principale, est refusé ; ecrireRapportValide ne laisse rien derrière un refus", function () {
    this.timeout(60000);
    const sys = systeme({ repertoire: TMP });
    expect(sys.reference).to.equal(false);
    const compte = comptePourLesCibles(sys);
    const d = tmp("noortrace-mesure-rapport-");
    const results = [ligne({ name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: [1, 2, 3], connections: 1, compte, catalogue })];
    const r = rapportMesure({ sys, compte, methode: { warmup: 0, repetitions: 3, clock: "monotone" }, results, notes: ["essai"] });
    expect(r.spec_version).to.equal(catalogue.spec_version);
    expect(r.counts_for_targets).to.equal(false);
    const f = path.join(d, "rapport-2026-11-13-essai.json");
    ecrireRapportValide(f, r);
    expect(fs.existsSync(f)).to.equal(true);
    const faux = structuredClone(r);
    faux.results[0].met = true;
    fs.writeFileSync(path.join(d, "faux.json"), JSON.stringify(faux));
    expect(validerRapport(path.join(d, "faux.json"), "rapport-2026-11-13-faux.json").code).to.equal(1);
    const sansPrincipale = structuredClone(r);
    sansPrincipale.results[0].name = "latence_appel_relaye_journal";
    expect(() => ecrireRapportValide(path.join(d, "rapport-2026-11-13-sans.json"), sansPrincipale)).to.throw(/MES-6/);
    expect(fs.existsSync(path.join(d, "rapport-2026-11-13-sans.json"))).to.equal(false);
    expect(fs.existsSync(path.join(d, "rapport-2026-11-13-sans.json.provisoire"))).to.equal(false);
    expect(() => validerRapport(f, "autre-nom.json")).to.throw(/EX-11\.11/);
    expect(typeDisque(TMP)).to.be.oneOf(["nvme", "ssd", "hdd", "virtuel", "memoire", "inconnu"]);
    fs.rmSync(d, { recursive: true, force: true });
  });
});

describe("Mesures : serveur d'outils nul, fournisseur simulé et hôte de test (CT-2 EX-16.2, pas 2 et 3 ; CT-9 EX-11.9)", () => {
  it("serveur nul : server/discover, tools/list, et un tools/call rendu par un corps JSON-RPC de la taille demandée, exacte pour un id et un numéro d'un chiffre ; instants reçu et répondu relevés par appel", async () => {
    const { serveur, mesures } = creerServeur({ resultatOctets: 2048 });
    const port = await ecoute(serveur);
    try {
      const poster = (corps) => new Promise((res, rej) => {
        const req = http.request({ host: "127.0.0.1", port, path: "/mcp", method: "POST", agent: false, headers: { "content-type": "application/json" } }, (x) => {
          const m = [];
          x.on("data", (k) => m.push(k));
          x.on("end", () => res({ statut: x.statusCode, corps: Buffer.concat(m) }));
        });
        req.on("error", rej);
        req.end(JSON.stringify(corps));
      });
      const d = await poster({ jsonrpc: "2.0", id: 1, method: "server/discover", params: {} });
      expect(JSON.parse(d.corps).result.supportedVersions).to.deep.equal(["2026-07-28"]);
      const l = await poster({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
      expect(JSON.parse(l.corps).result.tools.map((t) => t.name)).to.deep.equal(["appeler"]);
      const c = await poster({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "appeler", arguments: { n: 7 } } });
      expect(c.statut).to.equal(200);
      expect(c.corps.length).to.equal(2048);
      const json = JSON.parse(c.corps);
      expect(json.id).to.equal(3);
      expect(json.result.isError).to.equal(false);
      expect(json.result.content[0].text.startsWith("appel 7 ")).to.equal(true);
      expect(preparerReponse(600)(1, 1).length).to.equal(600);
      expect(preparerReponse(600)("m-1", 1).length).to.equal(600 + 4);
      expect(remplissage(10)).to.have.length(10);
      expect(remplissage(1000)).to.not.match(/[0-9@]/);
      const m = await getJson(port, "/mesures");
      expect(m.appels).to.equal(1);
      expect(m.n).to.deep.equal([7]);
      expect(BigInt(m.repondu_ns[0]) >= BigInt(m.recu_ns[0])).to.equal(true);
      expect(mesures.n).to.deep.equal([7]);
    } finally {
      await fermer(serveur);
    }
  });

  it("fournisseur simulé : hors flux, un message de la taille demandée ; en flux, 6 événements SSE écrits un par un à l'intervalle demandé, chaque écriture horodatée avec son décalage dans le corps ; le numéro de l'échange vient de metadata.user_id", async () => {
    const { serveur } = creerFournisseur({ reponseOctets: 1024, intervalleMs: 20, evenements: 6 });
    const port = await ecoute(serveur);
    try {
      const cx = new Connexion(port);
      const requete = fabriqueEchangeModele({ jeton: null, requeteOctets: 512 });
      expect(requete(5, false).corps.length).to.equal(512);
      const r = await cx.poster(requete(5, false).chemin, requete(5, false).entetes, requete(5, false).corps);
      expect(r.statut).to.equal(200);
      expect(r.corps.length).to.equal(1024);
      expect(JSON.parse(r.corps).id).to.equal("msg_mesure_5");
      expect(preparerMessage(300)(2).length).to.equal(300);
      const f = await cx.poster(requete(6, true).chemin, requete(6, true).entetes, requete(6, true).corps, { parMorceaux: true });
      expect(f.type.startsWith("text/event-stream")).to.equal(true);
      const attendu = evenementsFlux(6, 6);
      expect(attendu).to.have.length(6);
      expect(f.octets).to.equal(attendu.reduce((a, b) => a + b.length, 0));
      cx.fermer();
      const m = await getJson(port, "/mesures");
      const horsFlux = m.echanges.find((x) => !x.flux);
      const flux = m.echanges.find((x) => x.flux);
      expect(horsFlux.n).to.equal(5);
      expect(flux.n).to.equal(6);
      expect(flux.ecritures).to.have.length(6);
      expect(flux.ecritures.map((w) => w.decalage)).to.deep.equal(attendu.reduce((acc, b, i) => [...acc, i === 0 ? 0 : acc[i - 1] + attendu[i - 1].length], []));
      for (let i = 1; i < 6; i++) expect(Number(BigInt(flux.ecritures[i].emis_ns) - BigInt(flux.ecritures[i - 1].emis_ns)) / 1e6).to.be.at.least(15);
      // Latence par octet : réception − émission à chaque frontière des deux découpages.
      const v = latencesOctets(flux.ecritures, f.morceaux);
      expect(v.length).to.be.at.least(6);
      for (const x of v) expect(x).to.be.at.least(0);
    } finally {
      await fermer(serveur);
    }
  });

  it("latencesOctets : avec un seul morceau reçu pour deux écritures, la latence du premier octet de chaque écriture est réception − son émission (le premier octet attend la fin du second) ; morceaux redécoupés par l'intermédiaire pris en compte", () => {
    const ecritures = [{ decalage: 0, octets: 10, emis_ns: "1000000" }, { decalage: 10, octets: 5, emis_ns: "51000000" }];
    const unMorceau = [{ decalage: 0, octets: 15, recu_ns: "52000000" }];
    expect(latencesOctets(ecritures, unMorceau)).to.deep.equal([51, 1]);
    const redecoupe = [{ decalage: 0, octets: 4, recu_ns: "2000000" }, { decalage: 4, octets: 6, recu_ns: "3000000" }, { decalage: 10, octets: 5, recu_ns: "53000000" }];
    expect(latencesOctets(ecritures, redecoupe)).to.deep.equal([1, 2, 2]);
  });

  it("aCadenceFixe (EX-11.9), cas forcé sans charge : les matchers chai de Hardhat, installés à la première connexion au réseau en mémoire et actifs ensuite pour toute la suite, sont actifs ici ; leur closeTo n'admet que des entiers (un écart toléré de 0.01 est refusé), d'où des instants prévus comparés en nanosecondes entières", async function () {
    // Dans la suite entière, un essai de contrat précédent s'est déjà connecté : l'essai suivant tourne alors sous ces
    // matchers, seul ou non (rouge d'origine : « InvalidParameterError: 0.01 is not an integer » après une connexion).
    await network.connect();
    expect(() => expect(0).to.be.closeTo(0, 0.01)).to.throw(/0\.01 is not an integer/);
    expect(() => expect(20_000_000).to.be.closeTo(20_000_000, 10_000)).to.not.throw();
  });

  it("aCadenceFixe (EX-11.9) : l'appel i est prévu à t0 + i / cadence quelle que soit la lenteur des réponses, sa latence se compte depuis l'instant prévu (omission coordonnée) ; un serveur qui met 100 ms par appel à 50 appels/s sur 2 connexions accumule une attente croissante que l'envoi effectif ne cache pas", async function () {
    this.timeout(30000);
    await network.connect(); // matchers chai de Hardhat actifs, comme dans la suite entière (cas forcé ci-dessus)
    const serveur = http.createServer((req, rep) => {
      req.on("data", () => {});
      req.on("end", () => setTimeout(() => rep.writeHead(200, { "content-type": "application/json" }).end('{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'), 100));
    });
    const port = await ecoute(serveur);
    try {
      const connexions = [new Connexion(port), new Connexion(port)];
      const requete = fabriqueAppelOutil({ jeton: null, argumentsOctets: 64 });
      const r = await aCadenceFixe({ connexions, requete, valide: reponseOutilReussie, appels: 20, echauffement: 2, premier: 1, cadenceParS: 50 });
      connexions.forEach((c) => c.fermer());
      expect(r.mesures).to.have.length(20);
      // Instants prévus en nanosecondes entières (pas de 20 ms, tolérance de 10 µs) : le closeTo des matchers de Hardhat
      // n'admet que des entiers.
      const prevusNs = r.mesures.map((m) => Number(m.prevu_ns - r.debut_ns));
      for (let i = 0; i < 20; i++) expect(prevusNs[i]).to.be.closeTo(i * 20_000_000, 10_000);
      const depuisPrevu = r.mesures.map((m) => Number(m.reponse_ns - m.prevu_ns) / 1e6);
      const depuisEnvoi = r.mesures.map((m) => Number(m.reponse_ns - m.envoi_ns) / 1e6);
      // Deux connexions à 100 ms par appel servent 20 appels/s ; à 50 appels/s la file croît : la latence depuis l'instant prévu du dernier appel dépasse largement celle depuis son envoi.
      expect(depuisPrevu[19]).to.be.greaterThan(depuisEnvoi[19] + 300);
      expect(Math.max(...depuisEnvoi)).to.be.lessThan(depuisPrevu[19]);
      expect(r.fin_ns > r.debut_ns).to.equal(true);
      expect(() => aCadenceFixe({ connexions, requete, valide: () => true, appels: 1, cadenceParS: 0 })).to.throw(RangeError);
    } finally {
      await fermer(serveur);
    }
  });

  it("enSerie : échauffement exclu des mesures, numéros consécutifs depuis `premier`, réponse inattendue signalée avec son numéro ; fabriqueAppelOutil : arguments de la taille demandée, en-têtes de l'ère 2026-07-28", async () => {
    const { serveur } = creerServeur({ resultatOctets: 300 });
    const port = await ecoute(serveur);
    try {
      const cx = new Connexion(port);
      const requete = fabriqueAppelOutil({ jeton: null, outil: "appeler", argumentsOctets: 4096 });
      const q = requete(3);
      expect(q.entetes["mcp-protocol-version"]).to.equal("2026-07-28");
      expect(q.entetes["mcp-name"]).to.equal("appeler");
      expect(q.entetes.authorization).to.equal(undefined);
      expect(Buffer.byteLength(JSON.stringify(JSON.parse(q.corps.toString()).params.arguments))).to.equal(4096);
      const m = await enSerie({ connexion: cx, requete, valide: reponseOutilReussie, appels: 3, echauffement: 2, premier: 10 });
      expect(m.map((x) => x.n)).to.deep.equal([12, 13, 14]);
      for (const x of m) expect(x.reponse_ns > x.envoi_ns).to.equal(true);
      // Le serveur nul répond à tout tools/call (il ne regarde pas le nom) ; une méthode inconnue rend une erreur JSON-RPC, que l'hôte signale avec le numéro de l'appel.
      const mauvais = (n) => ({ chemin: "/mcp", entetes: { "content-type": "application/json" }, corps: Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: `m-${n}`, method: "inconnue", params: {} })) });
      let erreur = null;
      await enSerie({ connexion: cx, requete: mauvais, valide: reponseOutilReussie, appels: 1, premier: 42 }).catch((e) => (erreur = e));
      expect(erreur?.message).to.match(/appel 42/);
      cx.fermer();
      expect((await getJson(port, "/mesures")).n).to.deep.equal([10, 11, 12, 13, 14]);
    } finally {
      await fermer(serveur);
    }
  });

  it("differenceHistogramme : différence de deux lectures d'un histogramme Prometheus, moyenne et bornes supérieures des seaux du p50 et du p99 ; null sans observation", () => {
    const avant = { sum: 10, count: 10, seaux: [["1", 5], ["2", 8], ["5", 10], ["+Inf", 10]] };
    const apres = { sum: 40, count: 20, seaux: [["1", 5], ["2", 10], ["5", 19], ["+Inf", 20]] };
    const d = differenceHistogramme(apres, avant);
    expect(d.n).to.equal(10);
    expect(d.mean).to.equal(3);
    expect(d.majorant_p50).to.equal(5);
    expect(d.majorant_p99).to.equal(null);
    expect(differenceHistogramme(avant, avant)).to.equal(null);
    expect(differenceHistogramme(undefined, avant)).to.equal(null);
  });
});

describe("Mesures : configuration de mesure de CT-2 EX-16.2 (pas 1) et harnais entier sur l'enregistreur réel", function () {
  this.timeout(600000);

  it("la configuration de mesure du dépôt (fixture) est valide pour noortrace validate-config : classe D, bail file, politique pii-v1, validation groupée 64 / 5 ms, mode erreur, outil nul de classe ecriture autorisé, passerelle de modèle ; la copie publiée sous spec/vecteurs/ct-2/mesures/, quand elle existe, lui est identique octet pour octet", () => {
    const { config, sha256 } = lireConfigurationPubliee(FIXTURE_CONFIGURATION);
    expect(config.signer.class).to.equal("D");
    expect(config.lease.store.type).to.equal("file");
    expect(config.policy.redaction.name).to.equal("pii-v1");
    expect(config.storage.fsync).to.deep.equal({ group_max_events: 64, group_max_wait_ms: 5 });
    expect(config.policy.approval.mode).to.equal("erreur");
    expect(config.policy.servers.nul.tools.appeler.class).to.equal("ecriture");
    expect(config.policy.approval.rules.rules[0].tools).to.deep.equal(["nul__appeler"]);
    expect(config.model.mode).to.equal("passerelle");
    expect(config.policy.model.routes[0].format).to.equal("anthropic-messages");
    expect(config.anchoring.ancrage).to.equal(null);
    for (const p of MEMBRES_REMPLACES) {
      const v = p.split("/").slice(1).reduce((o, k) => o?.[k], config);
      expect(v, p).to.be.a("string");
    }
    const env = { NOORTRACE_MESURE_JETON_HOTE: "j".repeat(32), NOORTRACE_MESURE_JETON_PASSERELLE: "p".repeat(32), NOORTRACE_MESURE_CLE_MAC_RELAIS: "11".repeat(32), NOORTRACE_MESURE_JETON_APPROBATION: "a".repeat(32), NOORTRACE_MESURE_CLE_MODELE: "m".repeat(32) };
    const r = spawnSync(process.execPath, [path.join(RACINE, "paquets", "enregistreur", "bin", "noortrace"), "validate-config", FIXTURE_CONFIGURATION], { encoding: "utf8", env: { ...process.env, ...env } });
    expect(r.status, r.stderr).to.equal(0);
    expect(r.stderr).to.not.match(/^erreur/m);
    if (fs.existsSync(CONFIGURATION_PUBLIEE)) expect(lireConfigurationPubliee(CONFIGURATION_PUBLIEE).sha256).to.equal(sha256);
    expect(() => lireConfigurationPubliee(path.join(TMP, "absente.json"))).to.throw(/EX-16\.2/);
  });

  it("ct-2-perf.mjs : les six campagnes avec un petit effectif (n 30, échauffement 3, segment de reprise 1 Mio) produisent un rapport par campagne, chacun accepté par scripts/tests/mesures.mjs, hors référence (counts_for_targets faux, met null, excluded_reason hors_systeme_de_reference), avec la ligne principale de chaque entrée et le SHA-256 de la configuration ; code 0", async () => {
    const d = tmp("noortrace-mesure-harnais-");
    try {
      // Le harnais classe le disque du répertoire de mesure (CT-2 EX-16.3, CT-9 EX-11.2) : sur tmpfs ou ramfs, le motif
      // d'exclusion est disque_memoire, pas hors_systeme_de_reference. Cet essai exige donc un répertoire sur un disque réel.
      expect(typeDisque(d), `répertoire de mesure ${d} sur un disque en mémoire : cet essai exige un disque réel (NOORTRACE_TMP ou TMPDIR hors tmpfs)`).to.not.equal("memoire");
      const sortie = path.join(d, "rapports");
      const journal = [];
      const code = await executerHarnais(["--sortie", sortie, "--repertoire", d, "--configuration", FIXTURE_CONFIGURATION, "--n", "30", "--echauffement", "3", "--cadence", "100", "--connexions-sse", "3", "--segment-reprise", "1048576", "--etiquette", "essai"], { log: (t) => journal.push(t) });
      expect(code, journal.join("\n")).to.equal(0);
      const attendu = { latence: ["latence_appel_relaye", "latence_appel_relaye_journal", "signature", "signature_classe_d_isolee"], sse: ["latence_premier_octet_sse"], debit: ["debit", "octets_pieces_par_appel", "octets_par_evenement_en_charge", "memoire_charge", "memoire_vide"], modele: ["latence_echange_modele"], reprise: ["reprise", "reprise_processus"], observation: ["observation_latence", "observation_latence_paire", "observation_latence_paire_sans", "observation_ecriture"] };
      const { sha256 } = lireConfigurationPubliee(FIXTURE_CONFIGURATION);
      for (const c of CAMPAGNES) {
        const f = fs.readdirSync(sortie).find((x) => x.endsWith(`-essai-${c}.json`));
        expect(f, c).to.be.a("string");
        const r = JSON.parse(fs.readFileSync(path.join(sortie, f), "utf8"));
        expect(r.kind).to.equal("rapport-mesure");
        expect(r.counts_for_targets).to.equal(false);
        expect(r.system.reference).to.equal(false);
        expect(r.configuration_sha256).to.equal(sha256);
        expect(r.method.percentile_method).to.equal("plus_proche_rang");
        expect(r.results.map((l) => l.name)).to.deep.equal(attendu[c]);
        for (const l of r.results) {
          expect(l.met).to.equal(null);
          expect(l.excluded_reason).to.equal("hors_systeme_de_reference");
          expect(l.unit).to.equal(catalogue.tests.find((t) => t.id === l.test_id).measure.unit);
        }
        expect(validerRapport(path.join(sortie, f)).code).to.equal(0);
      }
      const latence = JSON.parse(fs.readFileSync(path.join(sortie, fs.readdirSync(sortie).find((x) => x.endsWith("-essai-latence.json"))), "utf8"));
      const l1 = latence.results[0];
      expect(l1.n).to.equal(30);
      expect(l1.connections).to.equal(1);
      expect(l1.samples).to.have.length(30);
      expect(l1.p99).to.equal(null);
      expect(latence.method).to.include({ warmup: 3, repetitions: 30, clock: "monotone", pair_with_without: false });
      const debit = JSON.parse(fs.readFileSync(path.join(sortie, fs.readdirSync(sortie).find((x) => x.endsWith("-essai-debit.json"))), "utf8"));
      expect(debit.results[0].value).to.be.greaterThan(0);
      expect(debit.results[0].connections).to.equal(16);
      expect(debit.results[1].value).to.be.greaterThan(16384);
      expect(debit.results.find((l) => l.name === "memoire_vide").value).to.be.greaterThan(10000000);
      const reprise = JSON.parse(fs.readFileSync(path.join(sortie, fs.readdirSync(sortie).find((x) => x.endsWith("-essai-reprise.json"))), "utf8"));
      expect(reprise.method).to.include({ warmup: 3, repetitions: 10, clock: "murale" });
      expect(reprise.results[0].n).to.equal(10);
      expect(reprise.results[0].conditions.join(" ")).to.match(/segment de [0-9]{7,} octets/);
      const observation = JSON.parse(fs.readFileSync(path.join(sortie, fs.readdirSync(sortie).find((x) => x.endsWith("-essai-observation.json"))), "utf8"));
      expect(observation.method.pair_with_without).to.equal(true);
      expect(observation.results[1].samples).to.have.length(30);
      expect(observation.results[2].samples).to.have.length(30);
      const resume = JSON.parse(fs.readFileSync(path.join(sortie, "resume.json"), "utf8"));
      expect(resume.rapports.map((x) => x.campagne)).to.deep.equal([...CAMPAGNES]);
      expect(fs.existsSync(path.join(sortie, "echantillons-essai-debit-latences-cadence-fixe.json"))).to.equal(true);
      // Le répertoire de mesure est détruit sans --conserver.
      expect(fs.readdirSync(d)).to.deep.equal(["rapports"]);
    } finally {
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  it("ct-2-perf.mjs : usage (code 2) sans --sortie, pour une campagne inconnue, un type de disque inconnu ; code 1 quand la configuration manque", async () => {
    const d = tmp("noortrace-mesure-usage-");
    const muet = { log: () => {} };
    expect(await executerHarnais([], muet)).to.equal(2);
    expect(await executerHarnais(["--sortie", d, "--campagnes", "inconnue"], muet)).to.equal(2);
    expect(await executerHarnais(["--sortie", d, "--disque", "disquette"], muet)).to.equal(2);
    expect(await executerHarnais(["--sortie", d, "--configuration", path.join(d, "absente.json"), "--campagnes", "latence"], muet)).to.equal(1);
    fs.rmSync(d, { recursive: true, force: true });
  });
});

describe("Mesures : campagne TM-30 vers des calendriers (scripts/mesures/tm-30-calendriers-publics.mjs), ici sur des calendriers factices locaux", function () {
  this.timeout(60000);

  it("soumettre : refuse de partir sans --reseau-public (code 2, aucun état écrit) ; la campagne ne joint jamais le réseau public dans un essai", async () => {
    const d = tmp("noortrace-tm30-refus-");
    const erreurs = [];
    const ecrire = process.stderr.write.bind(process.stderr);
    process.stderr.write = (t) => (erreurs.push(String(t)), true);
    let code;
    try {
      code = await executerTm30(["soumettre", "--etat", path.join(d, "etat")], { log: () => {} });
    } finally {
      process.stderr.write = ecrire;
    }
    expect(code).to.equal(2);
    expect(erreurs.join("")).to.match(/--reseau-public/);
    expect(fs.existsSync(path.join(d, "etat"))).to.equal(false);
    fs.rmSync(d, { recursive: true, force: true });
  });

  it("soumission à deux calendriers, passes de mise à niveau (404 en attente puis 200), cadence d'au moins 60 s entre deux passes, preuves complètes relues O-1 à O-3 et O-7, rapport b_ots_mis_a_niveau et b_ots_en_attente_public accepté par l'outil de CT-9 ; rapport refusé tant qu'aucune preuve n'est complète ; une seconde soumission sur le même état est refusée", async () => {
    const d = tmp("noortrace-tm30-");
    const calendriers = await calendriersFactices({ fichierEntetes: path.join(d, "entetes.json") });
    try {
      let t = Date.parse("2026-11-13T07:31:29Z");
      const horloge = { murale: () => t, monotone: () => performance.now() };
      const etatDir = path.join(d, "etat");
      const e = await soumettreCampagne({ repertoire: etatDir, calendriers: calendriers.uris, n: 3, transport: calendriers.transport, horloge });
      expect(e.preuves.map((p) => p.etat)).to.deep.equal(["en_attente", "en_attente", "en_attente"]);
      expect(e.preuves.every((p) => p.en_attente.length === 2)).to.equal(true);
      expect(fs.readdirSync(etatDir).filter((f) => f.endsWith(".ots"))).to.have.length(6);
      let erreur = null;
      await soumettreCampagne({ repertoire: etatDir, calendriers: calendriers.uris, n: 3, transport: calendriers.transport, horloge }).catch((x) => (erreur = x));
      expect(erreur).to.be.instanceOf(ErreurCampagne).with.property("code", "etat_existant");
      erreur = null;
      try {
        rapportCampagne({ repertoire: etatDir, sortieRapport: path.join(d, "rapport-2026-11-13-tm-30.json") });
      } catch (x) {
        erreur = x;
      }
      expect(erreur).to.be.instanceOf(ErreurCampagne).with.property("code", "campagne_inachevee");
      const p1 = await mettreANiveauCampagne({ repertoire: etatDir, listeBlanche: calendriers.uris, transport: calendriers.transport, horloge });
      expect(p1.reste).to.equal(3);
      expect(p1.passe.fusions).to.equal(0);
      t += 30000;
      erreur = null;
      await mettreANiveauCampagne({ repertoire: etatDir, listeBlanche: calendriers.uris, transport: calendriers.transport, horloge }).catch((x) => (erreur = x));
      expect(erreur).to.be.instanceOf(ErreurCampagne).with.property("code", "cadence");
      calendriers.completer(1010);
      t += 31000;
      const p2 = await mettreANiveauCampagne({ repertoire: etatDir, listeBlanche: calendriers.uris, transport: calendriers.transport, horloge });
      expect(p2.reste).to.equal(0);
      expect(p2.passe.fusions).to.equal(6);
      const relues = relireCampagne(etatDir);
      expect(relues.map((r) => r.etat)).to.deep.equal(["mise_a_niveau_par_tous", "mise_a_niveau_par_tous", "mise_a_niveau_par_tous"]);
      for (const r of relues) {
        expect(r.checks["O-1"]).to.equal("reussi");
        expect(r.checks["O-3"]).to.equal("reussi");
        expect(r.checks["O-7"]).to.equal("reussi");
        expect(r.accord).to.equal(true);
        expect(r.hauteurs_bitcoin).to.have.length(2);
      }
      // La version en attente d'origine est conservée à côté de la version mise à niveau.
      expect(fs.statSync(path.join(etatDir, "preuve-01.en-attente.ots")).size).to.be.lessThan(fs.statSync(path.join(etatDir, "preuve-01.ots")).size);
      const f = path.join(d, "rapport-2026-11-13-tm-30.json");
      const r = rapportCampagne({ repertoire: etatDir, sortieRapport: f, maintenant: new Date("2026-11-13T12:00:00Z") });
      expect(r.results.map((l) => l.name)).to.deep.equal(["b_ots_mis_a_niveau", "b_ots_en_attente_public"]);
      expect(r.results[0].n).to.equal(3);
      expect(r.results[0].max).to.equal(relues[0].octets);
      expect(r.results[0].met).to.equal(null);
      expect(r.results[0].p50).to.equal(null);
      expect(r.results[1].max).to.equal(e.preuves[0].octets_en_attente);
      expect(r.method).to.include({ warmup: 0, repetitions: 3, clock: "sans_objet" });
      expect(validerRapport(f).code).to.equal(0);
      const code = await executerTm30(["etat", "--etat", etatDir], { log: () => {} });
      expect(code).to.equal(0);
    } finally {
      await calendriers.fermer();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});
