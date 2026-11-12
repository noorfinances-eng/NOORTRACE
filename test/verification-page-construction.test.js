// Page de vérification (CT-6 §18, révision 0.6) : construction de l'artefact
// WebAssembly et des fichiers de la page (EX-18.3, EX-18.4, EX-18.6, table
// de 18.3, EX-18.12).
//
// - Deux constructions de l'artefact, depuis deux copies des sources à deux
//   chemins, avec deux caches vides, donnent les mêmes octets ; puis les
//   fichiers de la page aussi, et deux exécutions de construire.mjs sur les
//   mêmes entrées.
// - verificateur-wasm.js, travailleur.js, SHA256SUMS, en-tetes.json et
//   index.html ont exactement la forme du contrat.
// - GOOS=js GOARCH=wasm go list -deps ./cmd/noortrace-verifier ne nomme ni
//   net/http, ni crypto/tls, ni os/exec.
//
// Sans go1.27.3 (NOORTRACE_GO_BIN, à défaut le PATH), en attente.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { RACINE, VERSION, construireArtefact, construirePage, enAttente, environnementGo, repertoireTemporaire, sha256 } from "./fixtures/verification-page/outils.mjs";

const MODULE = path.join(RACINE, "verificateur");
const SOURCES = path.join(RACINE, "paquets", "verification-web", "src");
const FICHIERS = ["SHA256SUMS", "en-tetes.json", "index.html", "noortrace-verifier.wasm", "page.css", "page.js", "travailleur.js", "verificateur-wasm.js"];

/** Les en-têtes d'EX-18.12, recopiés de la table de CT-6. */
function enTetesAttendus() {
  const communs = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000",
  };
  const js = "text/javascript; charset=utf-8";
  return {
    "index.html": {
      "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; worker-src 'self'; connect-src 'none'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types noortrace-travailleur",
      "Integrity-Policy": "blocked-destinations=(script style)",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
      "Content-Type": "text/html; charset=utf-8",
      ...communs,
    },
    "noortrace-verifier.wasm": { "Content-Type": "application/wasm", ...communs, "Content-Disposition": "attachment" },
    "page.css": { "Content-Type": "text/css; charset=utf-8", ...communs },
    "page.js": { "Content-Type": js, ...communs },
    "travailleur.js": { "Content-Security-Policy": "default-src 'none'; script-src 'wasm-unsafe-eval'", "Content-Type": js, ...communs },
    "verificateur-wasm.js": { "Content-Type": js, ...communs },
  };
}

function copier(source, cible, filtre = () => true) {
  fs.cpSync(source, cible, { recursive: true, filter: (s) => filtre(s) });
}

function octetsDe(rep) {
  return Object.fromEntries(fs.readdirSync(rep).sort().map((n) => [n, fs.readFileSync(path.join(rep, n))]));
}

describe("page de vérification : construction reproductible et fichiers produits (CT-6 EX-18.3, EX-18.4, EX-18.6)", function () {
  this.timeout(20 * 60 * 1000);
  let env = null;
  let dir;
  let page;
  let wasm;

  before(function () {
    env = environnementGo();
    if (env === null) return;
    dir = repertoireTemporaire("noortrace-page-construction");
  });

  after(function () {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  it("deux constructions depuis deux copies des sources, à deux chemins, avec deux caches vides : mêmes octets pour l'artefact et pour chaque fichier de la page (EX-18.4)", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const sorties = [];
    for (const [i, sous] of [["a", "copie-a"], ["b", path.join("autre", "chemin", "plus", "long")]].entries()) {
      const base = path.join(dir, sous[0] === "a" ? "a" : "b", sous[1]);
      const module = path.join(base, "verificateur");
      copier(MODULE, module, (s) => !s.includes(`${path.sep}dist`));
      const sources = path.join(base, "verification-web", "src");
      copier(SOURCES, sources);
      const envCopie = {
        ...env,
        GOCACHE: path.join(dir, `cache-${i}`),
        GOPATH: path.join(dir, `gopath-${i}`),
        GOMODCACHE: path.join(dir, `gopath-${i}`, "pkg", "mod"),
        HOME: path.join(dir, `maison-${i}`),
      };
      fs.mkdirSync(envCopie.HOME, { recursive: true });
      const w = path.join(dir, `wasm-${i}`);
      const imprime = construireArtefact(w, envCopie, module);
      expect(imprime).to.match(/^[0-9a-f]{64} {2}noortrace-verifier\.wasm\n[0-9a-f]{64} {2}wasm_exec\.js\n$/);
      const p = path.join(dir, `page-${i}`);
      construirePage(w, p, path.join(sources, "construire.mjs"));
      sorties.push({ wasm: octetsDe(w), page: octetsDe(p), w, p });
    }
    expect(Object.keys(sorties[0].wasm)).to.deep.equal(["noortrace-verifier.wasm", "wasm_exec.js"]);
    for (const n of Object.keys(sorties[0].wasm)) expect(sha256(sorties[1].wasm[n]), n).to.equal(sha256(sorties[0].wasm[n]));
    expect(Object.keys(sorties[0].page)).to.deep.equal(FICHIERS);
    for (const n of FICHIERS) expect(sha256(sorties[1].page[n]), n).to.equal(sha256(sorties[0].page[n]));
    // Aucun chemin de la machine dans les fichiers produits.
    for (const n of FICHIERS) {
      const t = sorties[0].page[n].toString("latin1");
      for (const c of [dir, RACINE, env.HOME ?? "/nulle-part"]) expect(t.includes(c), `${n} contient ${c}`).to.equal(false);
    }
    wasm = sorties[0].w;
    page = sorties[0].p;
  });

  it("deux exécutions de construire.mjs sur les mêmes entrées : mêmes octets ; sortie non vide refusée", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const autre = path.join(dir, "page-bis");
    const imprime = construirePage(wasm, autre);
    const a = octetsDe(page);
    const b = octetsDe(autre);
    for (const n of FICHIERS) expect(sha256(b[n]), n).to.equal(sha256(a[n]));
    expect(imprime).to.equal(a.SHA256SUMS.toString("utf8"));
    const r = spawnSync(process.execPath, [path.join(SOURCES, "construire.mjs"), "--wasm", wasm, "--version", VERSION, "--sortie", autre], { encoding: "utf8" });
    expect(r.status).to.equal(1);
    expect(r.stderr).to.include("absent ou vide");
    const u = spawnSync(process.execPath, [path.join(SOURCES, "construire.mjs"), "--wasm", wasm, "--version", VERSION], { encoding: "utf8" });
    expect(u.status).to.equal(2);
  });

  it("artefact et fichier de soutien : recette d'EX-18.3, wasm_exec.js de go1.27.3 sans changement", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const goroot = execFileSync("go", ["env", "GOROOT"], { env, encoding: "utf8" }).trim();
    const soutien = fs.readFileSync(path.join(goroot, "lib", "wasm", "wasm_exec.js"));
    expect(Buffer.compare(fs.readFileSync(path.join(wasm, "wasm_exec.js")), soutien)).to.equal(0);
    // L'artefact est celui de la recette, appliquée à la main depuis le dépôt.
    const main = path.join(dir, "recette.wasm");
    execFileSync("go", ["build", "-trimpath", "-buildvcs=false", `-ldflags=-buildid= -X main.version=${VERSION}`, "-o", main, "./cmd/noortrace-verifier"], {
      cwd: MODULE,
      env: { ...env, GOTOOLCHAIN: "local", GOENV: "off", GOFLAGS: "-mod=vendor", GOPROXY: "off", GOSUMDB: "off", CGO_ENABLED: "0", GOOS: "js", GOARCH: "wasm" },
      stdio: "pipe",
    });
    expect(sha256(fs.readFileSync(main))).to.equal(sha256(fs.readFileSync(path.join(wasm, "noortrace-verifier.wasm"))));
    const octets = fs.readFileSync(main);
    expect(octets.subarray(0, 4).toString("latin1")).to.equal("\0asm");
  });

  it("verificateur-wasm.js exactement de la forme de 18.3 ; noortrace-verifier.wasm publié tel quel", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const a = fs.readFileSync(path.join(page, "noortrace-verifier.wasm"));
    expect(Buffer.compare(a, fs.readFileSync(path.join(wasm, "noortrace-verifier.wasm")))).to.equal(0);
    const t = fs.readFileSync(path.join(page, "verificateur-wasm.js"), "latin1");
    const attendu = `globalThis.NOORTRACE_VERIFICATEUR_WASM = "${a.toString("base64")}";\n`;
    expect(t === attendu).to.equal(true);
    const b64 = t.slice('globalThis.NOORTRACE_VERIFICATEUR_WASM = "'.length, -3);
    expect(/^[A-Za-z0-9+/]*={0,2}$/.test(b64) && b64.length % 4 === 0).to.equal(true);
    expect(Buffer.compare(Buffer.from(b64, "base64"), a)).to.equal(0);
  });

  it("travailleur.js = prélude ‖ wasm_exec.js inchangé ‖ pilote ; EMPREINTE_WASM = SHA-256 de l'artefact", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const t = fs.readFileSync(path.join(page, "travailleur.js"));
    const prelude = fs.readFileSync(path.join(SOURCES, "travailleur", "prelude.js"));
    const soutien = fs.readFileSync(path.join(wasm, "wasm_exec.js"));
    const empreinte = `0x${sha256(fs.readFileSync(path.join(page, "noortrace-verifier.wasm")))}`;
    const pilote = Buffer.from(fs.readFileSync(path.join(SOURCES, "travailleur", "pilote.js"), "utf8").replace("@@EMPREINTE_WASM@@", empreinte).replace("@@VERSION@@", VERSION), "utf8");
    expect(Buffer.compare(t, Buffer.concat([prelude, soutien, pilote]))).to.equal(0);
    expect(t.toString("utf8")).to.include(`const EMPREINTE_WASM = "${empreinte}";`);
    expect(t.toString("utf8").startsWith('"use strict";\n')).to.equal(true);
  });

  it("SHA256SUMS : les six fichiers de la page, triés, au format de sha256sum ; en-tetes.json : la table d'EX-18.12", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const six = ["index.html", "noortrace-verifier.wasm", "page.css", "page.js", "travailleur.js", "verificateur-wasm.js"];
    const attendu = six.map((n) => `${sha256(fs.readFileSync(path.join(page, n)))}  ${n}\n`).join("");
    expect(fs.readFileSync(path.join(page, "SHA256SUMS"), "utf8")).to.equal(attendu);
    const v = spawnSync("sha256sum", ["--strict", "-c", "SHA256SUMS"], { cwd: page, encoding: "utf8" });
    if (v.error === undefined) expect(v.status, v.stdout + v.stderr).to.equal(0);
    const entetes = JSON.parse(fs.readFileSync(path.join(page, "en-tetes.json"), "utf8"));
    expect(entetes).to.deep.equal(enTetesAttendus());
    for (const h of Object.values(entetes)) {
      for (const [k, val] of Object.entries(h)) {
        expect(k.toLowerCase()).to.not.be.oneOf(["set-cookie", "access-control-allow-origin"]);
        expect(val).to.not.include("'unsafe-eval'");
        expect(val).to.not.include("'unsafe-inline'");
      }
    }
  });

  it("index.html : aucun script ni style en ligne, aucun gestionnaire, aucune ressource d'une autre origine, trois sous-ressources dans l'ordre avec leurs intégrités justes, lang=\"fr\"", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const html = fs.readFileSync(path.join(page, "index.html"), "utf8");
    expect(html).to.match(/^<!DOCTYPE html>\n<html lang="fr">/);
    expect(html).to.not.match(/<style/i);
    expect(html).to.not.match(/\sstyle\s*=/i);
    expect(html).to.not.match(/\son[a-z]+\s*=/i);
    expect(html).to.not.match(/(?:src|href|action)\s*=\s*"(?:[a-z]+:|\/\/)/i);
    const scripts = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scripts.map((s) => s[2])).to.deep.equal(["", ""]);
    const ressources = [...html.matchAll(/<(link|script)\b([^>]*)>/gi)].map((m) => m[0]);
    const sri = (n) => `sha384-${crypto.createHash("sha384").update(fs.readFileSync(path.join(page, n))).digest("base64")}`;
    expect(ressources).to.deep.equal([
      `<link rel="stylesheet" href="page.css" integrity="${sri("page.css")}" crossorigin="anonymous">`,
      `<script src="verificateur-wasm.js" integrity="${sri("verificateur-wasm.js")}" crossorigin="anonymous">`,
      `<script src="page.js" integrity="${sri("page.js")}" crossorigin="anonymous">`,
    ]);
    // Phrase fixe d'EX-18.2, en français, avec la version.
    expect(html).to.include(`le vérificateur noortrace-verifier ${VERSION}, compilé en WebAssembly ; aucun fichier ne quitte votre poste.`);
  });

  it("page.js et le pilote : un script classique, sans importation, sans requête, sans stockage, sans insertion de HTML ni évaluation", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const pageJs = fs.readFileSync(path.join(page, "page.js"), "utf8");
    const travailleur = fs.readFileSync(path.join(page, "travailleur.js"), "utf8");
    const soutien = fs.readFileSync(path.join(wasm, "wasm_exec.js"), "utf8");
    const propres = [pageJs, travailleur.replace(soutien, "")];
    const interdits = [/\bimport\s*[({"'*]/, /\bimport\s+\w/, /\bexport\s/, /importScripts/, /\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /EventSource/, /sendBeacon/, /localStorage/, /sessionStorage/, /indexedDB/, /\bcaches\b/, /document\.cookie/, /serviceWorker/, /innerHTML/, /outerHTML/, /insertAdjacentHTML/, /document\.write/, /\beval\s*\(/, /new Function/, /Math\.random/, /\bDate\b/];
    for (const t of propres) for (const m of interdits) expect(m.test(t), String(m)).to.equal(false);
    expect(pageJs.startsWith('"use strict";\n')).to.equal(true);
    expect(pageJs).to.include(`const VERSION_VERIFICATEUR = "${VERSION}";`);
    // Le travailleur n'est créé que depuis la chaîne constante travailleur.js.
    expect(pageJs.match(/new Worker\(/g)).to.have.length(2);
    expect(pageJs).to.include('new Worker(politique.createScriptURL("travailleur.js"))');
    expect(pageJs).to.include('new Worker("travailleur.js")');
    expect(pageJs).to.include('createPolicy("noortrace-travailleur"');
  });

  it("GOOS=js GOARCH=wasm : go list -deps sans net/http, crypto/tls ni os/exec ; aucun paquet du module n'importe syscall/js ; seul entree change avec la cible", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const go = (args, cible) => execFileSync("go", args, { cwd: MODULE, env: { ...env, GOFLAGS: "-mod=vendor", ...cible }, encoding: "utf8" });
    const js = { GOOS: "js", GOARCH: "wasm" };
    const deps = go(["list", "-deps", "./cmd/noortrace-verifier"], js).trim().split("\n");
    for (const p of ["net/http", "crypto/tls", "os/exec"]) expect(deps).to.not.include(p);
    expect(deps).to.include("syscall/js");
    const importateurs = go(["list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", "./cmd/noortrace-verifier"], js)
      .trim().split("\n").map((l) => l.split(" ")).filter((x) => x.slice(1).includes("syscall/js")).map((x) => x[0]).sort();
    // Constat de go1.27.3 : syscall et time (zoneinfo_js.go) ; aucun paquet du module ni de vendor/.
    expect(importateurs).to.deep.equal(["syscall", "time"]);
    // Aucune contrainte de construction ne nomme js ni wasm ; seul entree change de fichiers avec la cible.
    const fichiersJs = go(["list", "-f", "{{.ImportPath}} {{.GoFiles}}", "./..."], js);
    const fichiersLinux = go(["list", "-f", "{{.ImportPath}} {{.GoFiles}}", "./..."], { GOOS: "linux", GOARCH: "amd64" });
    const differents = fichiersJs.split("\n").filter((l, i) => l !== fichiersLinux.split("\n")[i]);
    expect(differents).to.deep.equal(["github.com/noorfinances-eng/noortrace/verificateur/entree [entree.go ouvrir_autre.go]"]);
    const g = spawnSync("grep", ["-rlE", "--include=*.go", "--exclude-dir=vendor", "(//go:build.*\\b(js|wasm)\\b|\"syscall/js\")", "."], { cwd: MODULE, encoding: "utf8" });
    expect([g.status, g.stdout]).to.deep.equal([1, ""]);
  });

  it("construire-wasm.sh refuse une autre chaîne que go1.27.3, et GOWASM, GOEXPERIMENT ou GOFIPS140 posées", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const faux = path.join(dir, "faux-go");
    fs.mkdirSync(faux, { recursive: true });
    fs.writeFileSync(path.join(faux, "go"), "#!/bin/sh\necho go1.24.7\n", { mode: 0o755 });
    const script = path.join(MODULE, "scripts", "construire-wasm.sh");
    const r = spawnSync(script, ["-o", path.join(dir, "jamais")], { env: { ...env, PATH: `${faux}${path.delimiter}${env.PATH}` }, encoding: "utf8" });
    expect(r.status).to.equal(1);
    expect(r.stderr).to.include("go1.27.3 exigé");
    expect(fs.existsSync(path.join(dir, "jamais"))).to.equal(false);
    for (const v of ["GOWASM=satconv", "GOEXPERIMENT=nocoverageredesign", "GOFIPS140=latest"]) {
      const [k, val] = v.split("=");
      const x = spawnSync(script, ["-o", path.join(dir, "jamais")], { env: { ...env, [k]: val }, encoding: "utf8" });
      expect(x.status, v).to.equal(1);
      expect(x.stderr).to.include(k);
    }
    const u = spawnSync(script, [], { env, encoding: "utf8" });
    expect(u.status).to.equal(2);
  });

  it("construire.sh (EX-14.6, révision 0.7 de CT-6) : GOEXPERIMENT et GOFIPS140 vidées par la recette, refusées si posées ; binaire égal, octet pour octet, à celui de la recette sans ces variables", function () {
    if (env === null) return enAttente(this, "go1.27.3 absent (NOORTRACE_GO_BIN ou PATH)");
    const script = path.join(MODULE, "scripts", "construire.sh");
    const texte = fs.readFileSync(script, "utf8");
    expect(texte).to.include("  GOEXPERIMENT= GOFIPS140= \\\n  GOOS=\"$goos\" GOARCH=\"$goarch\" GOAMD64=v1 \\\n");
    for (const v of ["GOEXPERIMENT=nocoverageredesign", "GOFIPS140=latest"]) {
      const [k, val] = v.split("=");
      const x = spawnSync(script, ["-v", VERSION, "-o", path.join(dir, "natif-jamais")], { env: { ...env, [k]: val }, cwd: MODULE, encoding: "utf8" });
      expect(x.status, v).to.equal(1);
      expect(x.stderr).to.include(k);
      expect(fs.existsSync(path.join(dir, "natif-jamais"))).to.equal(false);
    }
    // Mêmes octets qu'avant la révision : la recette d'EX-14.6 sans les deux variables.
    const a = path.join(dir, "natif-script");
    execFileSync(script, ["-v", VERSION, "-o", a], { env, cwd: MODULE, stdio: "pipe" });
    const b = path.join(dir, "natif-recette-0.6");
    const recette = { ...env, GOENV: "off", GOFLAGS: "-mod=vendor", GOPROXY: "off", GOSUMDB: "off", CGO_ENABLED: "0", GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1" };
    delete recette.GOEXPERIMENT;
    delete recette.GOFIPS140;
    execFileSync("go", ["build", "-trimpath", "-buildvcs=false", `-ldflags=-buildid= -X main.version=${VERSION}`, "-o", b, "./cmd/noortrace-verifier"], { env: recette, cwd: MODULE, stdio: "pipe" });
    expect(sha256(fs.readFileSync(a))).to.equal(sha256(fs.readFileSync(b)));
  });
});
