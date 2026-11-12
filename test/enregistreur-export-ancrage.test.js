// TE-18 (CT-9, étape 6), composant d'ancrage branché : `noortrace-ctl dossier
// exporter` sur le démon réel à horloge réglable avec `anchoring.ancrage`
// (CT-2 EX-15.13 points 1, 2 et 4 ; EX-15.14 ; CT-5 §10, EX-10.5). Le dossier
// est produit par l'exportateur du composant dans le répertoire temporaire
// (ligne `dossier_exported` de `component` `ancrage`, `defects`, rang du point
// couvrant), `entetes-bitcoin.json` est écrit à côté quand la période en a un
// (non déclaré par l'index, compté dans `files`), et le démon écrit
// `dossier_reexport_due` quand une ancre arrivée rend à réexporter un dossier
// exporté depuis son démarrage, avec la destination demandée (jamais le
// répertoire temporaire) ; le nouveau dossier, dans une destination neuve,
// n'est plus dû. Décor hors réseau public de test/fixtures/enregistreur-ancrage
// (autorités RFC 3161 de test, calendriers OpenTimestamps factices, registre
// factice) ; en attente sans openssl.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import { monterDemon, Demon, repertoireTemporaire, enAttente, verifierJs, binaireGo, verifierGo, statuts } from "./fixtures/enregistreur-ancrage/outils.mjs";
import { ctl } from "./fixtures/enregistreur-export/outils.mjs";

const BASE = Date.UTC(2026, 10, 5, 7, 0, 2);
const PERIODE = Math.floor(BASE / 3600000) * 3600;

describe("TE-18 avec le composant d'ancrage branché : dossier produit par l'exportateur de CT-5 dans le répertoire temporaire, entetes-bitcoin.json, dossier_reexport_due (CT-2 EX-15.13, EX-15.14 ; CT-5 EX-10.5)", function () {
  this.timeout(900000);
  let dir;
  let m;
  let demon;
  let exportsDir;
  let seq;
  const lignes = (event) => demon.de(event);

  before(async function () {
    dir = repertoireTemporaire("noortrace-export-ancrage-");
    exportsDir = path.join(dir, "exports");
    fs.mkdirSync(exportsDir);
    m = await monterDemon({ dir, baseMs: BASE, surchargesConfig: (c) => { c.exports_dir = exportsDir; } });
    if (m.condition) return;
    demon = new Demon(m);
    await demon.demarrer();
  });

  after(async function () {
    if (demon?.p) await demon.arreter().catch(() => {});
    await m?.fermer?.();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  function pret() {
    if (!m || m.condition) {
      enAttente(this, m?.condition ?? "contexte non préparé");
      return false;
    }
    return true;
  }

  const exporter = (n) => ctl(["dossier", "exporter", "--seq", String(seq), "--vers", path.join(exportsDir, n), "--configuration", m.cheminConfig]);

  it("période close et ancrée, export par la commande : component ancrage, point couvrant ancré (rang 1), defects (parties du registre écartées), aucune entête Bitcoin avant la preuve complète ; le résumé de réexport nomme la destination ; aucun dossier_reexport_due tant qu'aucune ancre n'arrive", async function () {
    if (!pret.call(this)) return;
    seq = (await demon.evenement(1)).seq;
    await demon.avancer(Date.UTC(2026, 10, 5, 8, 0, 1) - m.horloge.murale());
    await demon.attendre((l) => l.some((x) => x.event === "period_closed"), 60000, "period_closed");
    await demon.attendre((l) => l.some((x) => x.event === "period_timestamped") && l.filter((x) => x.event === "ots_submitted").length >= 2, 120000, "ancres de la période");
    const r = await exporter("avant");
    expect(r.code, r.stderr).to.equal(0);
    const destination = path.join(exportsDir, "avant");
    const l = lignes("dossier_exported").find((x) => x.data.destination === destination);
    expect(l).to.include({ level: "info", component: "ancrage", seq });
    expect(l.request_id).to.match(/^[0-9a-f]{32}$/);
    expect(l.data).to.deep.equal(r.ligne.data);
    expect(l.data).to.include({ selection: "seq", seq, period_start: PERIODE, bitcoin_headers: false });
    expect(l.data.checkpoint_rank).to.equal(1);
    const index = JSON.parse(fs.readFileSync(path.join(destination, "dossier.json"), "utf8"));
    // La clôture n'est pas relayée au registre ici (aucune demande signée déposée) : les parties du registre sont écartées
    // par l'exportateur, un défaut (CT-5 §10), que `defects` compte (EX-15.14).
    const registre = index.parts.find((p) => p.name === "registre");
    expect(registre.present).to.equal(false);
    expect(registre.reason_if_absent).to.match(/capture_incomplete/);
    expect(l.data.defects).to.equal(1);
    const fichiers = fs.readdirSync(destination).sort();
    expect(fichiers).to.deep.equal([...index.parts.filter((p) => p.present).map((p) => p.file), "dossier.json"].sort());
    expect(l.data.files).to.equal(fichiers.length);
    expect(l.data.parts_present).to.equal(index.parts.filter((p) => p.present).length);
    expect(l.data.dossier_sha256).to.equal(N.sha256Hex(new Uint8Array(fs.readFileSync(path.join(destination, "dossier.json")))));
    expect(fs.statSync(destination).mode & 0o7777).to.equal(0o750);
    for (const f of fichiers) expect(fs.statSync(path.join(destination, f)).mode & 0o7777, f).to.equal(0o640);
    expect(lignes("dossier_reexport_due")).to.deep.equal([]);
    expect((await demon.commande({ cmd: "reexports" })).dus).to.deep.equal([]);
    const js = verifierJs(destination);
    expect(js.code, js.stderr).to.equal(0);
  });

  it("mise à niveau OpenTimestamps : dossier_reexport_due (component ancrage, request_id null) nomme la destination demandée et les raisons ; un nouvel export vers une destination neuve porte entetes-bitcoin.json (bitcoin_headers, files compté) et n'est plus dû ; le dossier antérieur est inchangé", async function () {
    if (!pret.call(this) || seq === undefined) return;
    const destinationAvant = path.join(exportsDir, "avant");
    const avant = fs.readFileSync(path.join(destinationAvant, "dossier.json"));
    m.calendriers.completer(1010);
    await demon.avancer(61000);
    await demon.attendre((l) => l.filter((x) => x.event === "ots_complete").length >= 2 && l.some((x) => x.event === "bitcoin_headers_written"), 120000, "ots_complete et entetes-bitcoin.json");
    await demon.attendre((l) => l.some((x) => x.event === "dossier_reexport_due" && x.data.reasons.includes("entetes_bitcoin")), 30000, "dossier_reexport_due");
    const dus = lignes("dossier_reexport_due");
    for (const d of dus) {
      expect(d).to.include({ level: "info", component: "ancrage", seq, request_id: null, host: null });
      expect(Object.keys(d.data)).to.deep.equal(["seq", "hash", "period_start", "destination", "generated_at", "reasons"]);
      expect(d.data).to.include({ seq, period_start: PERIODE, destination: destinationAvant });
      expect(d.data.destination).to.not.include(".noortrace-partiel-");
      expect(new Set(d.data.reasons).size).to.equal(d.data.reasons.length);
    }
    const derniere = dus.at(-1);
    expect(derniere.data.reasons).to.include.members(["ots_periode", "entetes_bitcoin"]);
    expect(derniere.data.generated_at).to.equal(JSON.parse(avant.toString("utf8")).generated_at);
    // Une ligne par ancre arrivée : deux lignes successives d'un même dossier ne portent jamais les mêmes raisons et le même constat
    // (une ligne du composant sans ancre nouvelle n'en écrit pas d'autre) ; une ancre de plus en a donné une de plus.
    const nDus = dus.length;
    await demon.avancer(61000);
    await new Promise((r) => setTimeout(r, 1500));
    expect(lignes("dossier_reexport_due").length).to.equal(nDus);
    // Réexport : destination neuve ; entetes-bitcoin.json à côté, compté dans files.
    const r = await exporter("apres");
    expect(r.code, r.stderr).to.equal(0);
    const destination = path.join(exportsDir, "apres");
    expect(r.ligne.data.bitcoin_headers).to.equal(true);
    expect(fs.existsSync(path.join(destination, "entetes-bitcoin.json"))).to.equal(true);
    const index = JSON.parse(fs.readFileSync(path.join(destination, "dossier.json"), "utf8"));
    expect(index.parts.some((p) => p.file === "entetes-bitcoin.json")).to.equal(false);
    expect(r.ligne.data.files).to.equal(fs.readdirSync(destination).length);
    expect(r.ligne.data.files).to.equal(index.parts.filter((p) => p.present).length + 2);
    expect(fs.statSync(path.join(destination, "entetes-bitcoin.json")).mode & 0o7777).to.equal(0o640);
    expect((await demon.commande({ cmd: "reexports" })).dus).to.deep.equal([]);
    expect(Buffer.compare(fs.readFileSync(path.join(destinationAvant, "dossier.json")), avant)).to.equal(0);
    // Une ancre de plus ne rend pas le nouveau dossier dû : aucune ligne nouvelle.
    const n = lignes("dossier_reexport_due").length;
    await demon.avancer(61000);
    await new Promise((x) => setTimeout(x, 1500));
    expect(lignes("dossier_reexport_due").length).to.equal(n);
    const js = verifierJs(destination, { entetes: path.join(destination, "entetes-bitcoin.json") });
    expect(js.code, js.stderr).to.equal(0);
    const bin = binaireGo();
    if (!bin) return enAttente(this, "vérificateur Go de CT-6 : vérification JavaScript faite, vérification Go non faite");
    const go = verifierGo(destination, { entetes: path.join(destination, "entetes-bitcoin.json"), bin });
    expect(go.code, go.stderr).to.equal(0);
    expect(statuts(go.rapport)).to.deep.equal(statuts(js.rapport));
  });
});
