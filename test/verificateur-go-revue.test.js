import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// REVUE DE SÉCURITÉ INTERNE (étape 8) DU BINAIRE GO DE CT-6 : chaque
// essai rejoue, sur le binaire construit (NOORTRACE_VERIFIER_BIN,
// NOORTRACE_GO_BIN ou verificateur/dist/noortrace-verifier-linux-amd64), un
// dossier hostile de la revue, fabriqué ici sous NOORTRACE_TMP depuis les
// vecteurs publiés, et vérifie le code de retour et le rapport : CT-6 EX-15.1
// (parties de petites valeurs : rapport sous un plafond de mémoire), EX-4.6
// (pièces hors de --pieces), (uniqueItems en temps linéaire), EX-8.6
// et (rapport lisible neutralisé), (A-3 sans panique),
// (résumé par fichier), CT-6 EX-15.3 (corpus de graines), EX-15.1
// (rapport borné), EX-9.6 (CRL au numéro de série non minimal), R-1
// (ligne de certificat de 4 Mio en octets). Chaque essai échoue sur le
// binaire relu (étape 5, SHA-256 6fef2fa5…) et passe sur le binaire corrigé.
// Sans binaire, les essais sont en attente nommée.

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CT1 = path.join(RACINE, "spec", "vecteurs", "ct-1", "dossiers");
const CT6 = path.join(RACINE, "spec", "vecteurs", "ct-6");
const SEQ7 = path.join(CT1, "valide-seq-7");
const COMPLET = path.join(CT6, "dossiers", "valide-seq-7-complet");
const ANCRES = path.join(CT6, "ancres", "ancres-test.json");
const CHAINE = path.join(CT6, "ots", "entetes", "chaine.json");
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();

function binaireGo() {
  for (const c of [process.env.NOORTRACE_VERIFIER_BIN, process.env.NOORTRACE_GO_BIN, path.join(RACINE, "verificateur", "dist", "noortrace-verifier-linux-amd64")]) {
    if (c && fs.existsSync(c)) return c;
  }
  return null;
}
function enAttente(ctx, condition) {
  (ctx.currentTest ?? ctx.test).title += ` — en attente : ${condition}`;
  ctx.skip();
}
const sha256 = (b) => "0x" + crypto.createHash("sha256").update(b).digest("hex");
/** Copie un dossier publié sous un répertoire temporaire propre. */
function copier(src) {
  const d = fs.mkdtempSync(path.join(TMP, "verif-go-revue-"));
  for (const f of fs.readdirSync(src)) fs.copyFileSync(path.join(src, f), path.join(d, f));
  return d;
}
/** Réécrit une partie et reporte son SHA-256 dans l'index. */
function remplacer(d, fichier, contenu) {
  const ancien = fs.readFileSync(path.join(d, fichier));
  fs.writeFileSync(path.join(d, fichier), contenu);
  const idx = fs.readFileSync(path.join(d, "dossier.json"), "utf8").replace(sha256(ancien), sha256(Buffer.from(contenu)));
  fs.writeFileSync(path.join(d, "dossier.json"), idx);
}
function modifierJSON(d, fichier, f) {
  const v = JSON.parse(fs.readFileSync(path.join(d, fichier), "utf8"));
  f(v);
  remplacer(d, fichier, JSON.stringify(v));
}
/** Lance le binaire ; avec `mesurerRSS`, par python3 quand il existe, qui rend la mémoire résidente maximale (Mio) sur la sortie d'erreur. */
function lancer(bin, args, { mesurerRSS = false, json = true } = {}) {
  const a = json ? [...args, "--json"] : args;
  let cmd = bin, argv = a, rssMio = null;
  const python = ["/usr/bin/python3", "/usr/local/bin/python3"].find((p) => fs.existsSync(p));
  if (mesurerRSS && python) {
    cmd = python;
    argv = ["-I", "-c", "import sys,subprocess,resource\np=subprocess.run(sys.argv[1:])\nsys.stderr.write('RSS_MAX_KIO=%d\\n'%resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)\nsys.exit(p.returncode)", bin, ...a];
  }
  const r = spawnSync(cmd, argv, { encoding: json ? "utf8" : "buffer", maxBuffer: 256 * 1024 * 1024 });
  let stderr = String(r.stderr);
  const m = stderr.match(/RSS_MAX_KIO=(\d+)\n/);
  if (m) { rssMio = Number(m[1]) / 1024; stderr = stderr.replace(m[0], ""); }
  let doc = null;
  if (json) { try { doc = JSON.parse(r.stdout); } catch { doc = null; } }
  return { code: r.status, stdout: r.stdout, stderr, doc, rssMio };
}
/** La mémoire résidente mesurée reste sous le plafond (quand python3 permet de la mesurer). */
function sousPlafond(r, plafondMio) {
  if (r.rssMio === null) return;
  expect(r.rssMio, `mémoire résidente ${Math.round(r.rssMio)} Mio`).to.be.lessThan(plafondMio);
}
const check = (doc, id) => doc.checks.find((c) => c.id === id);
const zeros = (n) => "[" + "0,".repeat(n - 1) + "0]";
const nettoyer = [];
after(() => { for (const d of nettoyer) fs.rmSync(d, { recursive: true, force: true }); });
const tmp = (src) => { const d = copier(src); nettoyer.push(d); return d; };

// ---------------------------------------------------------------- DER minimal (CRL)
/** Lecture d'un élément TLV DER : { tag, longueur de l'en-tête, contenu, fin }. */
function tlv(buf, i) {
  const tag = buf[i];
  let l = buf[i + 1], j = i + 2;
  if (l & 0x80) { const n = l & 0x7f; l = 0; for (let k = 0; k < n; k++) l = l * 256 + buf[j++]; }
  return { tag, debut: j, fin: j + l, contenu: buf.subarray(j, j + l) };
}
function longueur(n) {
  if (n < 128) return Buffer.from([n]);
  const b = []; let x = n; while (x > 0) { b.unshift(x & 0xff); x >>= 8; }
  return Buffer.from([0x80 | b.length, ...b]);
}
const enc = (tag, ...parties) => { const c = Buffer.concat(parties); return Buffer.concat([Buffer.from([tag]), longueur(c.length), c]); };
function enfants(buf) { const out = []; for (let i = 0; i < buf.length;) { const e = tlv(buf, i); out.push(Buffer.from(buf.subarray(i, e.fin))); i = e.fin; } return out; }
/** CRL de crl-tsa-revoquee.pem dont le numéro de série de l'entrée est encodé sous forme non minimale, resignée par l'AC de test. */
function crlNumeroNonMinimal() {
  const pem = fs.readFileSync(path.join(CT6, "rfc3161", "crl", "crl-tsa-revoquee.pem"), "utf8");
  const der = Buffer.from(pem.replace(/-----[^-]+-----|\s/g, ""), "base64");
  const [tbs, sigAlg] = enfants(tlv(der, 0).contenu);
  const champs = enfants(tlv(tbs, 0).contenu);
  // version, signature, issuer, thisUpdate, nextUpdate, revokedCertificates, [0] extensions
  const iRev = champs.findIndex((c, k) => k >= 5 && c[0] === 0x30);
  const entrees = enfants(tlv(champs[iRev], 0).contenu).map((e) => {
    const [serie, ...reste] = enfants(tlv(e, 0).contenu);
    const valeur = tlv(serie, 0).contenu;
    expect(valeur.length).to.equal(1);
    return enc(0x30, enc(0x02, Buffer.from([0x00, ...valeur])), ...reste);
  });
  champs[iRev] = enc(0x30, ...entrees);
  const tbs2 = enc(0x30, ...champs);
  const cle = crypto.createPrivateKey(fs.readFileSync(path.join(CT6, "rfc3161", "cles", "ac-test.cle.pem")));
  const sig = crypto.sign("sha256", tbs2, cle);
  const crl = enc(0x30, tbs2, sigAlg, enc(0x03, Buffer.from([0]), sig));
  const b64 = crl.toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN X509 CRL-----\n${b64}\n-----END X509 CRL-----\n`;
}

// ---------------------------------------------------------------- essais
describe("Vérificateur Go — revue de sécurité interne de l'étape 8", function () {
  this.timeout(300_000);
  let bin;
  before(function () { bin = binaireGo(); });
  beforeEach(function () { if (!bin) enAttente(this, "binaire du vérificateur Go de CT-6 absent (NOORTRACE_VERIFIER_BIN)"); });

  it("CT-6 EX-15.1 : registre.json de 16 Mio de petites valeurs est jugé sous 1 Gio de mémoire résidente, avec un rapport JSON (code 1, R-1 en échec sur le nombre de valeurs)", function () {
    const d = tmp(COMPLET);
    remplacer(d, "registre.json", zeros(8 * 1024 * 1024));
    const r = lancer(bin, [d, "--ancres", ANCRES, "--entetes-bitcoin", CHAINE], { mesurerRSS: true });
    expect(r.code, r.stderr.slice(0, 300)).to.equal(1);
    sousPlafond(r, 1024);
    expect(r.doc, "rapport JSON attendu").to.not.equal(null);
    expect(r.doc.exit_code).to.equal(1);
    const r1 = check(r.doc, "R-1");
    expect(r1.status).to.equal("echoue");
    expect(r1.detail).to.match(/nombre de valeurs/);
  });

  it("CT-6 EX-15.1 (extension) : fichier d'en-têtes de 16 Mio de petites valeurs : code 2, entree_illisible, N-2, sous 1 Gio de mémoire résidente", function () {
    const d = tmp(COMPLET);
    const f = path.join(d, "entetes-hostiles.json");
    fs.writeFileSync(f, zeros(8 * 1024 * 1024));
    const r = lancer(bin, [COMPLET, "--ancres", ANCRES, "--entetes-bitcoin", f], { mesurerRSS: true });
    expect(r.code, r.stderr.slice(0, 300)).to.equal(2);
    sousPlafond(r, 1024);
    expect(r.doc, "rapport d'erreur JSON attendu (EX-8.5)").to.not.equal(null);
    expect(r.doc.error.kind).to.equal("entree_illisible");
    expect(r.doc.error.check).to.equal("N-2");
    expect(r.doc.error.message).to.match(/nombre de valeurs/);
  });

  it("CT-6 EX-15.1 : approbations.json de 1 Mio dont events est fait de zéros : rapport de moins de 1 Mio, code 1, sous 512 Mio de mémoire résidente", function () {
    const d = tmp(SEQ7);
    const ap = JSON.parse(fs.readFileSync(path.join(SEQ7, "approbations.json"), "utf8"));
    const texte = JSON.stringify(ap).replace(/"events":\[.*\]\}$/, `"events":${zeros(512 * 1024)}}`);
    expect(texte.length).to.be.greaterThan(1024 * 1024);
    remplacer(d, "approbations.json", texte);
    const r = lancer(bin, [d], { mesurerRSS: true });
    expect(r.code, r.stderr.slice(0, 300)).to.equal(1);
    sousPlafond(r, 512);
    expect(r.stdout.length).to.be.lessThan(1024 * 1024);
    expect(check(r.doc, "A-1").status).to.equal("echoue");
    expect(check(r.doc, "A-2").detail).to.match(/au-delà des 1024/);
  });

  it("CT-6 EX-4.6 : une référence dont sha256 n'est pas hexadécimal n'ouvre aucun fichier hors de --pieces", function () {
    const base = fs.mkdtempSync(path.join(TMP, "verif-go-revue-pieces-"));
    nettoyer.push(base);
    const pieces = path.join(base, "pieces");
    fs.mkdirSync(pieces);
    const secret = Buffer.from("contenu du poste du réviseur\n");
    fs.writeFileSync(path.join(base, "secret.txt"), secret);
    const hors = "0x.." + "/".repeat(52) + "secret.txt";
    expect(hors.length).to.equal(66);
    const d = tmp(SEQ7);
    modifierJSON(d, "evenement.json", (v) => { v.execution.arguments.sha256 = hors; });
    const r = lancer(bin, [d, "--pieces", pieces]);
    expect(r.code).to.equal(1);
    expect(r.doc.inputs.pieces.files).to.equal(0);
    const e6 = check(r.doc, "E-6");
    expect(e6.detail ?? "").to.not.include(sha256(secret).slice(2));
    expect(e6.detail ?? "").to.not.include("secret");
  });

  it("CT-6 EX-4.6 : un répertoire de --pieces nommé par le sha256 n'est pas ouvert : code 2, entree_illisible, EX-4.17", function () {
    const piece = Buffer.from("pièce fournie à part");
    const nom = sha256(piece).slice(2);
    const pieces = fs.mkdtempSync(path.join(TMP, "verif-go-revue-pieces-"));
    nettoyer.push(pieces);
    fs.mkdirSync(path.join(pieces, nom));
    const d = tmp(SEQ7);
    modifierJSON(d, "evenement.json", (v) => { v.execution.arguments.sha256 = "0x" + nom; v.execution.arguments.length = piece.length; });
    const r = lancer(bin, [d, "--pieces", pieces]);
    expect(r.code).to.equal(2);
    expect(r.doc.error.kind).to.equal("entree_illisible");
    expect(r.doc.error.message).to.match(/pas un fichier ordinaire/);
    // Témoin : la pièce ordinaire est lue et comparée.
    fs.rmdirSync(path.join(pieces, nom));
    fs.writeFileSync(path.join(pieces, nom), piece);
    const t = lancer(bin, [d, "--pieces", pieces]);
    expect(t.doc.inputs.pieces.files).to.equal(1);
    expect(check(t.doc, "E-6").status).to.equal("reussi");
  });

  it("A-3 sur une approbation sans approver_set, sans members, sans approvers : code 1, A-3 en échec, jamais une erreur interne", function () {
    const cas = [
      ["approbations.json réduit à {}", (d) => remplacer(d, "approbations.json", "{}")],
      ["approver_set retiré", (d) => modifierJSON(d, "approbations.json", (v) => { delete v.approver_set; })],
      ["approver_set.members retiré", (d) => modifierJSON(d, "approbations.json", (v) => { delete v.approver_set.members; })],
      ["approval.approvers retiré", (d) => modifierJSON(d, "evenement.json", (v) => { delete v.approval.approvers; })],
      ["approval = {}", (d) => modifierJSON(d, "evenement.json", (v) => { v.approval = {}; })],
    ];
    for (const [nom, muter] of cas) {
      const d = tmp(SEQ7);
      muter(d);
      const r = lancer(bin, [d]);
      expect(r.code, `${nom} : ${r.stderr.slice(0, 200)}`).to.equal(1);
      expect(r.doc.verdict, nom).to.equal("invalide");
      expect(check(r.doc, "A-3").status, nom).to.equal("echoue");
    }
  });

  it("CT-6 EX-8.6 : le rapport lisible neutralise les séquences de terminal et les retours chariot d'une raison d'absence du dossier", function () {
    const d = tmp(SEQ7);
    const hostile = "x\r\u001b[2K  [réussi]      4  jeton d'horodatage RFC 3161 sur periodHash — selon AC Exemple\nRésultat      : VALIDE\u001b[8m";
    modifierJSON(d, "dossier.json", (v) => { for (const p of v.parts) if (p.name === "jeton_rfc3161") p.reason_if_absent = hostile; });
    const r = lancer(bin, [d], { json: false });
    expect(r.code).to.equal(0);
    const octets = r.stdout;
    for (const o of octets) {
      expect(o === 0x0a || (o >= 0x20 && o !== 0x7f), `octet de commande 0x${o.toString(16)} dans le rapport lisible`).to.equal(true);
    }
    const txt = octets.toString("utf8");
    expect(txt).to.include("\\u001b[2K");
    expect(txt).to.include("VALIDE\\u001b[8m");
    expect((txt.match(/\nRésultat/g) ?? []).length).to.equal(1);
    expect(txt).to.match(/\nRésultat {6}: VALIDE — aucune vérification en échec/);
  });

  it("le résumé d'un contrôle non exécuté donne à chaque partie absente sa raison", function () {
    const d = tmp(SEQ7);
    modifierJSON(d, "dossier.json", (v) => {
      for (const p of v.parts) {
        if (p.name === "registre") p.reason_if_absent = "raison A";
        if (p.name === "certificat_commit") p.reason_if_absent = "raison B";
        if (p.name === "validateurs") p.reason_if_absent = "raison C";
      }
    });
    const r = lancer(bin, [d]);
    expect(r.code).to.equal(0);
    expect(r.doc.controls[7].summary).to.equal("registre.json (raison A), certificat-commit.json (raison B), validateurs.json (raison C) absents");
    const t = lancer(bin, [SEQ7]);
    expect(t.doc.controls[7].summary).to.equal("registre.json, certificat-commit.json, validateurs.json absents (hors périmètre CT-1)");
  });

  it("un jeu de 65 535 approbateurs distincts est jugé en moins de dix secondes (uniqueItems linéaire)", function () {
    const d = tmp(SEQ7);
    modifierJSON(d, "approbations.json", (v) => {
      v.approver_set.members = Array.from({ length: 65535 }, (_, i) => "0x" + (i + 1).toString(16).padStart(40, "0"));
      v.approver_set.threshold = { required: 2, size: 65535 };
    });
    const debut = Date.now();
    const r = lancer(bin, [d]);
    const duree = Date.now() - debut;
    expect(r.code).to.equal(1);
    expect(duree, `durée ${duree} ms`).to.be.lessThan(10_000);
  });

  it("une CRL du fichier d'ancres au numéro de série non minimal est lue (EX-9.6) : T-10 échoue, code 1, et non code 2", function () {
    const ancres = JSON.parse(fs.readFileSync(ANCRES, "utf8"));
    ancres.revocation.crls = [crlNumeroNonMinimal()];
    const d = tmp(COMPLET);
    const f = path.join(d, "ancres-crl-non-minimale.json");
    fs.writeFileSync(f, JSON.stringify(ancres));
    const r = lancer(bin, [COMPLET, "--ancres", f, "--entetes-bitcoin", CHAINE]);
    expect(r.code, r.stderr.slice(0, 300)).to.equal(1);
    expect(check(r.doc, "T-10").status).to.equal("echoue");
    expect(r.doc.failed_checks).to.deep.equal(["T-10"]);
  });

  it("une ligne de certificat de 2,2 millions de « é » (4,4 Mio) fait échouer R-1 (borne en octets, §15.1) ; 4 190 000 « a » passent", function () {
    const muter = (d, zz) => modifierJSON(d, "certificat-commit.json", (v) => {
      const ligne = JSON.parse(v.certificates[0].precommits[0].line);
      ligne.zz = zz;
      v.certificates[0].precommits[0].line = JSON.stringify(ligne);
    });
    const octets = tmp(COMPLET);
    muter(octets, "é".repeat(2_200_000));
    const r = lancer(bin, [octets, "--ancres", ANCRES, "--entetes-bitcoin", CHAINE]);
    expect(r.code).to.equal(1);
    expect(check(r.doc, "R-1").status).to.equal("echoue");
    expect(check(r.doc, "R-1").detail).to.match(/ligne de plus de 4 Mio/);
    const ascii = tmp(COMPLET);
    muter(ascii, "a".repeat(4_190_000));
    const t = lancer(bin, [ascii, "--ancres", ANCRES, "--entetes-bitcoin", CHAINE]);
    expect(check(t.doc, "R-1").status).to.equal("reussi");
    expect(t.code).to.equal(0);
  });

  it("chaque cible de fuzzing a son corpus de graines sous testdata/fuzz (EX-15.3)", function () {
    const cibles = [["jsonv", "FuzzAnalyser"], ["jcs", "FuzzCanonique"], ["ancres", "FuzzAncres"], ["ancres", "FuzzEntetes"], ["ots", "FuzzAnalyser"],
      ["registre", "FuzzRegistre"], ["registre", "FuzzLigne"], ["horodatage", "FuzzJeton"], ["horodatage", "FuzzCertificat"], ["horodatage", "FuzzCRL"]];
    for (const [paquet, cible] of cibles) {
      const dir = path.join(RACINE, "verificateur", paquet, "testdata", "fuzz", cible);
      expect(fs.existsSync(dir), dir).to.equal(true);
      const graines = fs.readdirSync(dir);
      expect(graines.length, dir).to.be.greaterThan(0);
      for (const g of graines) expect(fs.readFileSync(path.join(dir, g), "utf8").startsWith("go test fuzz v1\n"), g).to.equal(true);
    }
  });
});
