#!/usr/bin/env node
// Publication préparée d'une version, sans rien publier (CT-6 EX-14.6 à
// EX-14.10, CT-8 EX-3.6, EX-3.13, EX-3.14).
//
//   node scripts/publication/preparer-version.mjs --version <x.y.z> --commit <40 hex>
//        --date <secondes depuis 1970> --sortie <répertoire à créer>
//        [--binaires <répertoire>] [--temoin <répertoire>] [--condenses <fichier JSON>]
//        [--image-construction <image@sha256:…>] [--depot-url <https://…>] [--ref <ref git>]
//        [--execution <identifiant>] [--exiger-arbre-propre]
//
// Écrit sous --sortie, qui ne doit pas exister :
//   noortrace-verifier-linux-amd64, noortrace-verifier-linux-arm64
//     binaires de la recette d'EX-14.6 (verificateur/scripts/construire.sh),
//     construits ici, ou repris de --binaires (constructeur de la CI) ;
//   noortrace-verifier-linux-<arch>.go-version-m.txt
//     sortie de `go version -m` (EX-14.9) ;
//   noortrace-deploiement-<version>.tar
//     archive de déploiement : les fichiers de
//     scripts/deploiement/construire-archive.mjs, en ustar déterministe
//     (CT-8 EX-13.14 : entrées triées, fichiers seuls, mode 0644,
//     propriétaires nuls, date = --date) ;
//   LICENSE, NOTICE, LICENCES-TIERCES (EX-14.10) ;
//   SHA256SUMS : une ligne « <sha256>  <nom> » par fichier ci-dessus, triée ;
//   provenance.intoto.json : déclaration in-toto (SLSA provenance v1)
//     préparée, non signée, dont les sujets sont les fichiers de SHA256SUMS
//     et SHA256SUMS lui-même ;
//   NOTE-DE-VERSION.md : le gabarit note-de-version.gabarit.md rempli.
//
// --date est SOURCE_DATE_EPOCH, la date du commit (EX-3.13, EX-14.8) : mêmes
// entrées, mêmes octets. --temoin désigne les binaires d'un second
// constructeur ; une différence d'un seul octet fait refuser la préparation
// (EX-3.13, EX-14.8).
//
// Le script ne signe rien (aucune clé n'existe à la préparation : la
// signature minisign de SHA256SUMS est posée hors de la CI par le détenteur
// de la clé), ne pousse rien, n'ouvre aucune connexion réseau : la recette
// porte GOPROXY=off et GOTOOLCHAIN=local, et l'archive est faite des
// fichiers du dépôt.
//
// Codes : 0 préparée ; 1 refus (go1.27.3 absent, construction en échec,
// binaires différents du témoin, arbre modifié avec --exiger-arbre-propre) ;
// 2 usage ou sortie existante. En cas de refus, --sortie est supprimé.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

export const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const PLATEFORMES = ["linux/amd64", "linux/arm64"];
export const GO_EXIGE = "go1.27.3";
const GABARIT = path.join(RACINE, "scripts", "publication", "note-de-version.gabarit.md");

const USAGE = `Usage : node scripts/publication/preparer-version.mjs --version <x.y.z> --commit <40 hex> --date <secondes> --sortie <répertoire à créer>
       [--binaires <répertoire>] [--temoin <répertoire>] [--condenses <fichier JSON>]
       [--image-construction <image@sha256:…>] [--depot-url <https://…>] [--ref <ref git>]
       [--execution <identifiant>] [--exiger-arbre-propre]`;

export class Usage extends Error {}
export class Refus extends Error {}

export const nomBinaire = (plateforme) => `noortrace-verifier-${plateforme.replace("/", "-")}`;
export const nomArchive = (version) => `noortrace-deploiement-${version}.tar`;
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const compareOctets = (a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

// ---------------------------------------------------------------------------
// Archive ustar déterministe (CT-8 EX-13.14, recette GNU tar d'EX-13.15).

function champOctal(h, debut, largeur, valeur) {
  const t = valeur.toString(8).padStart(largeur - 1, "0");
  if (t.length !== largeur - 1) throw new Refus(`valeur ${valeur} hors du champ ustar de ${largeur} octets`);
  h.write(t, debut, "latin1");
  h[debut + largeur - 1] = 0;
}

/** Découpe nom / préfixe de ustar (règle de GNU tar, split_long_name). */
export function decouperNom(nom) {
  const n = Buffer.from(nom, "utf8");
  if (n.length <= 100) return { name: n, prefix: Buffer.alloc(0) };
  for (let i = Math.min(155, n.length - 1); i >= 1; i--) {
    if (n[i] !== 0x2f) continue;
    const reste = n.length - i - 1;
    if (reste === 0 || reste > 100) break;
    return { name: n.subarray(i + 1), prefix: n.subarray(0, i) };
  }
  throw new Refus(`${nom} : nom non représentable en ustar`);
}

/** Archive ustar des fichiers [{ nom, octets }], dans l'ordre des octets des noms. */
export function ecrireUstar(fichiers, mtime) {
  if (!Number.isInteger(mtime) || mtime < 0 || mtime > 8 ** 11 - 1) throw new Refus(`date ${mtime} hors du champ mtime de ustar`);
  const tries = [...fichiers].sort((a, b) => compareOctets(a.nom, b.nom));
  const morceaux = [];
  for (const { nom, octets } of tries) {
    const { name, prefix } = decouperNom(nom);
    const h = Buffer.alloc(512);
    name.copy(h, 0);
    h.write("0000644\0", 100, "latin1");
    h.write("0000000\0", 108, "latin1");
    h.write("0000000\0", 116, "latin1");
    champOctal(h, 124, 12, octets.length);
    champOctal(h, 136, 12, mtime);
    h.fill(0x20, 148, 156);
    h.write("0", 156, "latin1");
    h.write("ustar\0", 257, "latin1");
    h.write("00", 263, "latin1");
    prefix.copy(h, 345);
    let somme = 0;
    for (const o of h) somme += o;
    h.write(somme.toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
    morceaux.push(h, octets, Buffer.alloc((512 - (octets.length % 512)) % 512));
  }
  morceaux.push(Buffer.alloc(1024));
  const total = morceaux.reduce((s, b) => s + b.length, 0);
  morceaux.push(Buffer.alloc((10240 - (total % 10240)) % 10240));
  return Buffer.concat(morceaux);
}

/** Fichiers ordinaires d'un répertoire, chemins relatifs en « / ». */
function lireArbre(racine) {
  const r = [];
  const parcourir = (rel) => {
    for (const e of fs.readdirSync(path.join(racine, rel), { withFileTypes: true })) {
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) parcourir(p);
      else if (e.isFile()) r.push({ nom: p, octets: fs.readFileSync(path.join(racine, ...p.split("/"))) });
      else throw new Refus(`${p} : ni fichier ordinaire ni répertoire`);
    }
  };
  parcourir("");
  return r;
}

// ---------------------------------------------------------------------------

function lireOptions(argv) {
  let o;
  try {
    o = parseArgs({
      args: argv, strict: true, allowPositionals: false,
      options: {
        version: { type: "string" }, commit: { type: "string" }, date: { type: "string" }, sortie: { type: "string" },
        binaires: { type: "string" }, temoin: { type: "string" }, condenses: { type: "string" },
        "image-construction": { type: "string" }, "depot-url": { type: "string" }, ref: { type: "string" },
        execution: { type: "string" }, "exiger-arbre-propre": { type: "boolean", default: false },
        aide: { type: "boolean", default: false },
      },
    }).values;
  } catch (err) {
    throw new Usage(err.message);
  }
  if (o.aide) return o;
  for (const k of ["version", "commit", "date", "sortie"]) if (o[k] === undefined) throw new Usage(`option --${k} requise`);
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?$/.test(o.version)) throw new Usage(`--version ${o.version} : x.y.z attendu`);
  if (!/^[0-9a-f]{40}$/.test(o.commit)) throw new Usage(`--commit ${o.commit} : 40 chiffres hexadécimaux minuscules attendus`);
  if (!/^(0|[1-9]\d*)$/.test(o.date) || Number(o.date) > 8 ** 11 - 1) throw new Usage(`--date ${o.date} : secondes depuis 1970 attendues`);
  o.date = Number(o.date);
  if (o.temoin !== undefined && o.binaires === undefined) throw new Usage("--temoin demande --binaires");
  if (o["image-construction"] !== undefined && !/^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$/.test(o["image-construction"])) throw new Usage("--image-construction : <image>:<étiquette>@sha256:<64 hex> attendu");
  o.depotUrl = o["depot-url"] ?? "https://depot.invalid/noortrace";
  if (!/^https:\/\/[^\s@]+$/.test(o.depotUrl)) throw new Usage("--depot-url : adresse https attendue");
  o.ref ??= `refs/tags/v${o.version}`;
  o.execution ??= "essai-a-blanc";
  return o;
}

function environnementGo() {
  const env = { ...process.env, GOTOOLCHAIN: "local" };
  delete env.GOFLAGS;
  return env;
}

function verifierGo(env) {
  const r = spawnSync("go", ["env", "GOVERSION"], { env: { ...env, GOENV: "off" }, encoding: "utf8" });
  const v = r.status === 0 ? r.stdout.trim() : `absent (${r.error?.code ?? r.stderr.trim()})`;
  if (v !== GO_EXIGE) throw new Refus(`Go ${GO_EXIGE} exigé (CT-6 EX-14.3), ${v} trouvé`);
}

function verifierArbre(commit, exiger) {
  const tete = spawnSync("git", ["rev-parse", "HEAD"], { cwd: RACINE, encoding: "utf8" });
  const etat = spawnSync("git", ["status", "--porcelain", "--untracked-files=no"], { cwd: RACINE, encoding: "utf8" });
  const ecarts = [];
  if (tete.status !== 0) ecarts.push("dépôt git illisible");
  else if (tete.stdout.trim() !== commit) ecarts.push(`HEAD ${tete.stdout.trim()} ≠ --commit ${commit}`);
  if (etat.status === 0 && etat.stdout.trim() !== "") ecarts.push("arbre de travail modifié");
  if (ecarts.length === 0) return;
  const message = `${ecarts.join(" ; ")} : les fichiers préparés ne sont pas ceux du commit`;
  if (exiger) throw new Refus(message);
  process.stderr.write(`Avertissement : ${message} (essai à blanc)\n`);
}

function lireCondenses(fichier) {
  if (fichier === undefined) return {};
  let c;
  try {
    c = JSON.parse(fs.readFileSync(fichier, "utf8"));
  } catch (err) {
    throw new Usage(`--condenses ${fichier} : ${err.message}`);
  }
  if (c === null || typeof c !== "object" || Array.isArray(c)) throw new Usage("--condenses : objet { image: condensé } attendu");
  for (const [k, v] of Object.entries(c)) {
    if (!/^noortrace\/[a-z0-9-]+$/.test(k) || typeof v !== "string" || !/^sha256:[0-9a-f]{64}$/.test(v)) throw new Usage(`--condenses : ${k} → ${v} : noortrace/<nom> → sha256:<64 hex> attendu`);
  }
  return c;
}

function imagesNoortrace() {
  const d = JSON.parse(fs.readFileSync(path.join(RACINE, "deploiement", "images", "images.json"), "utf8"));
  const vues = new Map();
  for (const s of Object.values(d.services)) if (s.image.startsWith("noortrace/") && !vues.has(s.image)) vues.set(s.image, s.tag);
  return [...vues].sort((a, b) => compareOctets(a[0], b[0]));
}

function remplir(gabarit, valeurs) {
  const texte = gabarit.replace(/\{\{([a-z0-9_]+)\}\}/g, (_, k) => {
    if (!(k in valeurs)) throw new Refus(`gabarit : valeur ${k} inconnue`);
    return valeurs[k];
  });
  if (/\{\{|\}\}/.test(texte)) throw new Refus("gabarit : marque non remplie");
  return texte;
}

/** Prépare la version ; rend la liste SHA256SUMS. */
export function preparer(o) {
  const env = environnementGo();
  verifierGo(env);
  verifierArbre(o.commit, o["exiger-arbre-propre"]);
  const condenses = lireCondenses(o.condenses);
  const base = process.env.NOORTRACE_TMP ?? os.tmpdir();
  const travail = fs.mkdtempSync(path.join(base, "noortrace-preparer-"));
  const sortie = path.resolve(o.sortie);
  fs.mkdirSync(sortie, { recursive: false });
  try {
    const fichiers = new Map(); // nom → mode
    // 1. Binaires (EX-14.6), puis comparaison au témoin (EX-14.8).
    for (const p of PLATEFORMES) {
      const nom = nomBinaire(p);
      const cible = path.join(sortie, nom);
      if (o.binaires !== undefined) {
        const source = path.join(o.binaires, nom);
        if (!fs.statSync(source, { throwIfNoEntry: false })?.isFile()) throw new Refus(`${source} : binaire absent`);
        fs.copyFileSync(source, cible);
      } else {
        const r = spawnSync(path.join(RACINE, "verificateur", "scripts", "construire.sh"), ["-v", o.version, "-p", p, "-o", cible], { env, encoding: "utf8" });
        if (r.status !== 0) throw new Refus(`construction ${p} en échec : ${r.stderr.trim()}`);
      }
      if (o.temoin !== undefined) {
        const temoin = path.join(o.temoin, nom);
        if (!fs.statSync(temoin, { throwIfNoEntry: false })?.isFile()) throw new Refus(`${temoin} : binaire témoin absent`);
        const a = fs.readFileSync(cible);
        const b = fs.readFileSync(temoin);
        if (!a.equals(b)) throw new Refus(`${nom} : constructeurs en désaccord (${sha256(a)} ≠ ${sha256(b)}, CT-8 EX-3.13, CT-6 EX-14.8)`);
      }
      fs.chmodSync(cible, 0o755);
      fichiers.set(nom, 0o755);
      // 2. go version -m, lancé dans --sortie sur le nom seul.
      const m = spawnSync("go", ["version", "-m", nom], { cwd: sortie, env: { ...env, GOENV: "off" }, encoding: "utf8" });
      if (m.status !== 0) throw new Refus(`go version -m ${nom} : ${m.stderr.trim()}`);
      fs.writeFileSync(path.join(sortie, `${nom}.go-version-m.txt`), m.stdout);
      fichiers.set(`${nom}.go-version-m.txt`, 0o644);
    }
    // 3. Archive de déploiement (EX-3.6), ustar déterministe.
    const arbre = path.join(travail, "archive");
    const a = spawnSync(process.execPath, [path.join(RACINE, "scripts", "deploiement", "construire-archive.mjs"), "--sortie", arbre], { cwd: RACINE, encoding: "utf8" });
    if (a.status !== 0) throw new Refus(`construire-archive.mjs : ${a.stderr.trim()}`);
    const entrees = lireArbre(arbre);
    const tar = ecrireUstar(entrees, o.date);
    fs.writeFileSync(path.join(sortie, nomArchive(o.version)), tar);
    fichiers.set(nomArchive(o.version), 0o644);
    // 4. Licences (EX-14.10).
    for (const [nom, source] of [["LICENSE", "LICENSE"], ["NOTICE", "NOTICE"], ["LICENCES-TIERCES", "verificateur/LICENCES-TIERCES"]]) {
      fs.copyFileSync(path.join(RACINE, ...source.split("/")), path.join(sortie, nom));
      fichiers.set(nom, 0o644);
    }
    for (const [nom, mode] of fichiers) fs.chmodSync(path.join(sortie, nom), mode);
    // 5. SHA256SUMS.
    const noms = [...fichiers.keys()].sort(compareOctets);
    const empreintes = new Map(noms.map((n) => [n, sha256(fs.readFileSync(path.join(sortie, n)))]));
    const sums = noms.map((n) => `${empreintes.get(n)}  ${n}\n`).join("");
    fs.writeFileSync(path.join(sortie, "SHA256SUMS"), sums, { mode: 0o644 });
    // 6. Provenance préparée, non signée.
    const dateIso = new Date(o.date * 1000).toISOString();
    const image = o["image-construction"] ?? null;
    const declaration = {
      _type: "https://in-toto.io/Statement/v1",
      subject: [...noms, "SHA256SUMS"].map((n) => ({ name: n, digest: { sha256: n === "SHA256SUMS" ? sha256(sums) : empreintes.get(n) } })),
      predicateType: "https://slsa.dev/provenance/v1",
      predicate: {
        buildDefinition: {
          buildType: "https://actions.github.io/buildtypes/workflow/v1",
          externalParameters: { workflow: { ref: o.ref, repository: o.depotUrl, path: ".github/workflows/version.yml" } },
          internalParameters: {
            noortrace: {
              version: o.version,
              source_date_epoch: o.date,
              go: GO_EXIGE,
              recette: "CT-6 EX-14.6 (verificateur/scripts/construire.sh)",
              image_construction: image,
              archive: "CT-8 EX-13.14 (ustar, entrées triées, mode 0644, propriétaires nuls)",
            },
          },
          resolvedDependencies: [{ uri: `git+${o.depotUrl}@${o.ref}`, digest: { gitCommit: o.commit } }],
        },
        runDetails: {
          builder: { id: `${o.depotUrl}/.github/workflows/version.yml@${o.ref}` },
          metadata: { invocationId: o.execution },
        },
      },
    };
    fs.writeFileSync(path.join(sortie, "provenance.intoto.json"), JSON.stringify(declaration, null, 2) + "\n", { mode: 0o644 });
    // 7. Note de version.
    const lire = (n) => fs.readFileSync(path.join(sortie, n), "utf8").trimEnd();
    const valeurs = {
      version: o.version,
      commit: o.commit,
      epoch: String(o.date),
      date: dateIso,
      table_fichiers: noms.map((n) => `| \`${n}\` | ${fs.statSync(path.join(sortie, n)).size} | \`${empreintes.get(n)}\` |`).join("\n"),
      commentaire_confiance: `noortrace ${o.version} ${dateIso.slice(0, 10)}`,
      etat_signature: "À la préparation, `SHA256SUMS` n'est pas signé : aucune clé n'est employée par la CI. Le détenteur de la clé signe hors de la CI, par `minisign -S -s <clé secrète> -m SHA256SUMS -t '<commentaire de confiance ci-dessus>'`, vérifie la signature par la commande ci-dessus, puis publie `SHA256SUMS.minisig` avec les fichiers.",
      sha_amd64: empreintes.get(nomBinaire("linux/amd64")),
      sha_arm64: empreintes.get(nomBinaire("linux/arm64")),
      image_construction: image === null ? "aucune (essai à blanc : go1.27.3 de l'hôte, même recette)." : `\`${image}\`.`,
      go_version_m_amd64: lire(`${nomBinaire("linux/amd64")}.go-version-m.txt`),
      go_version_m_arm64: lire(`${nomBinaire("linux/arm64")}.go-version-m.txt`),
      nom_archive: nomArchive(o.version),
      sha_archive: empreintes.get(nomArchive(o.version)),
      taille_archive: String(tar.length),
      entrees_archive: String(entrees.length),
      table_images: imagesNoortrace().map(([img, tag]) => `| \`${img}\` | \`${tag}\` | ${condenses[img] ? `\`${condenses[img]}\`` : "non publiée à cette version"} |`).join("\n"),
      etat_provenance: "`provenance.intoto.json` : déclaration in-toto (SLSA provenance v1) préparée et non signée ; ses sujets sont les fichiers de `SHA256SUMS` et `SHA256SUMS` lui-même. L'attestation signée de la CI (CT-2 EX-18.6, CT-6 EX-14.9) n'est produite qu'après validation de la publication, avec les droits `id-token: write` et `attestations: write`, que le travail de préparation n'a pas.",
    };
    const note = remplir(fs.readFileSync(GABARIT, "utf8"), valeurs);
    fs.writeFileSync(path.join(sortie, "NOTE-DE-VERSION.md"), note, { mode: 0o644 });
    return sums;
  } catch (err) {
    fs.rmSync(sortie, { recursive: true, force: true });
    throw err;
  } finally {
    fs.rmSync(travail, { recursive: true, force: true });
  }
}

export function principal(argv) {
  let o;
  try {
    o = lireOptions(argv);
    if (o.aide) {
      process.stdout.write(`${USAGE}\n`);
      return 0;
    }
    if (fs.existsSync(o.sortie)) throw new Usage(`${o.sortie} existe déjà`);
  } catch (err) {
    process.stderr.write(`Erreur : ${err.message}\n${USAGE}\n`);
    return 2;
  }
  try {
    const sums = preparer(o);
    process.stdout.write(`${sums}Version ${o.version} préparée sous ${o.sortie} ; rien n'est signé ni publié.\n`);
    return 0;
  } catch (err) {
    if (!(err instanceof Refus) && !(err instanceof Usage)) throw err;
    process.stderr.write(`Refus : ${err.message}\n`);
    return err instanceof Usage ? 2 : 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) process.exitCode = principal(process.argv.slice(2));
