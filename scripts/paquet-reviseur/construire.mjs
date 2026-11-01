#!/usr/bin/env node
// Outil de construction d'un paquet réviseur (CT-8 §13.5).
//
//   node scripts/paquet-reviseur/construire.mjs --description <description.json> --sortie <paquet.tar>
//   node scripts/paquet-reviseur/construire.mjs --aide
//   npm run paquet:construire -- --description <description.json> --sortie <paquet.tar>
//
// Lit une description (paquet-reviseur-v0#/$defs/description_source), dont
// les chemins relatifs se résolvent contre le répertoire du fichier de
// description (EX-13.17) ; copie dossier.json et les parties présentes de
// chaque dossier, les fichiers d'ancres et d'en-têtes, l'attestation, les
// pièces, les instructions de 13.11 et, si demandé, le vérificateur (13.6) ;
// écrit le manifeste (13.3) et l'archive canonique (13.4). Ne juge pas les
// dossiers (EX-13.19). N'ouvre aucune connexion réseau. Codes : 0 archive
// écrite ; 2 refus (usage, description, entrée illisible, sortie existante),
// et rien n'est écrit (EX-13.18).

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "../lib/journal.mjs";
import * as P from "../lib/paquet.mjs";

const ICI = path.dirname(fileURLToPath(import.meta.url));

export class Refus extends Error {}

export function construire(description, base) {
  const schema = P.chargerSchema();
  const erreurs = J.validerSchema(description, schema, { fragment: "#/$defs/description_source" });
  if (erreurs.length) throw new Refus(`description non conforme : ${erreurs.map(P.texteErreur).join(" ; ")}`);
  // Date unique des entrées (EX-13.14) : une date réelle, entre 1970 et la
  // borne du champ mtime (11 chiffres octaux), relue à l'identique.
  const t = Date.parse(description.created_at);
  if (!Number.isFinite(t) || new Date(t).toISOString() !== description.created_at) throw new Refus(`created_at ${description.created_at} : date impossible`);
  const mtime = t / 1000;
  if (mtime < 0 || mtime > 8 ** 11 - 1) throw new Refus(`created_at ${description.created_at} : hors de 1970-01-01T00:00:00.000Z à 2242-03-16T12:56:31.000Z (champ mtime de ustar)`);
  const fichiers = new Map(); // chemin dans le paquet -> { octets, role }
  const minuscules = new Map(); // chemin en minuscules -> chemin (PR-5, EX-13.32)
  const ajouter = (chemin, octets, role) => {
    const deja = fichiers.get(chemin);
    if (deja && !deja.octets.equals(octets)) throw new Refus(`${chemin} : deux sources différentes pour le même chemin du paquet`);
    const bas = chemin.toLowerCase();
    if (minuscules.has(bas) && minuscules.get(bas) !== chemin) throw new Refus(`${minuscules.get(bas)} et ${chemin} : chemins égaux à la casse près, que PR-5 refuserait`);
    minuscules.set(bas, chemin);
    fichiers.set(chemin, { octets, role });
  };
  const lire = (p) => {
    try {
      return fs.readFileSync(path.resolve(base, p));
    } catch (err) {
      throw new Refus(`${p} : illisible (${err.code ?? err.message})`);
    }
  };
  const dossiers = [];
  for (const d of description.dossiers) {
    const source = path.resolve(base, d.source);
    const nom = path.basename(source);
    const chemin = `dossiers/${nom}`;
    if (dossiers.some((x) => x.path === chemin)) throw new Refus(`${chemin} : deux dossiers de même nom`);
    const octetsIndex = lire(path.join(source, "dossier.json"));
    let index;
    try {
      index = J.analyserJSONStrict(octetsIndex);
    } catch (err) {
      throw new Refus(`${d.source}/dossier.json : ${err.message}`);
    }
    ajouter(`${chemin}/dossier.json`, octetsIndex, "dossier");
    for (const partie of index.parts ?? []) {
      if (!partie.present) continue;
      if (typeof partie.file !== "string" || !/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(partie.file)) throw new Refus(`${d.source} : nom de partie refusé (${partie.file})`);
      ajouter(`${chemin}/${partie.file}`, lire(path.join(source, partie.file)), "dossier");
    }
    const ancres = d.anchors === null ? null : `ancres/${path.basename(d.anchors)}`;
    if (ancres) ajouter(ancres, lire(d.anchors), "ancres");
    const entetes = d.bitcoin_headers === null ? null : `entetes/${path.basename(d.bitcoin_headers)}`;
    if (entetes) ajouter(entetes, lire(d.bitcoin_headers), "entetes");
    dossiers.push({ path: chemin, anchors: ancres, bitcoin_headers: entetes });
  }
  let attestation = null;
  if (description.attestation) {
    attestation = { signed: "attestation/attestation-signee.json", approver_set: "attestation/jeu-approbateurs.json" };
    ajouter(attestation.signed, lire(description.attestation.signed), "attestation");
    ajouter(attestation.approver_set, lire(description.attestation.approver_set), "attestation");
  }
  for (const p of description.pieces) ajouter(`pieces/${path.basename(p)}`, lire(p), "pieces");
  ajouter("LISEZMOI.md", fs.readFileSync(path.join(ICI, "instructions", "LISEZMOI.md")), "instructions");
  ajouter("README.md", fs.readFileSync(path.join(ICI, "instructions", "README.md")), "instructions");
  let verifier = null;
  if (description.include_verifier) {
    for (const [chemin, octets] of P.fichiersVerificateur()) ajouter(chemin, octets, "verificateur");
    verifier = { tool: "verificateur/scripts/paquet-reviseur/verifier.mjs", dossier_verifier: "verificateur/scripts/verify/dossier.mjs", version: "0.1.0", runtime: "Node.js 22 ou ultérieur" };
  }
  for (const [chemin, f] of fichiers) if (f.octets.length > P.LIMITE_FICHIER) throw new Refus(`${chemin} : ${f.octets.length} octets, au-delà de ${P.LIMITE_FICHIER}`);
  const files = [...fichiers.entries()]
    .sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)))
    .map(([chemin, f]) => ({ path: chemin, size: f.octets.length, sha256: P.sha256(f.octets), role: f.role }));
  const manifeste = { format: P.FORMAT, version: 0, label: description.label, created_at: description.created_at, prepared_by: description.prepared_by, dossiers, attestation, verifier, instructions: { fr: "LISEZMOI.md", en: "README.md" }, files };
  const err = J.validerSchema(manifeste, schema);
  if (err.length) throw new Refus(`manifeste produit non conforme : ${err.map(P.texteErreur).join(" ; ")}`);
  const octetsManifeste = Buffer.from(JSON.stringify(manifeste, null, 2) + "\n");
  const entrees = [...fichiers.entries()].map(([chemin, f]) => ({ nom: `${P.RACINE}/${chemin}`, octets: f.octets }));
  entrees.push({ nom: P.MANIFESTE, octets: octetsManifeste });
  // Noms des entrées : la règle de PR-5 (EX-13.32), appliquée avant d'écrire.
  const noms = P.verifierNoms(entrees.map((e, i) => {
    const { prefix, name } = (() => {
      try {
        return P.decouper(e.nom);
      } catch {
        throw new Refus(`${e.nom} : nom non représentable en ustar (EX-13.14)`);
      }
    })();
    const champ = (x) => ({ texte: x, octets: Buffer.from(x, "latin1"), bourrageNul: true });
    return { n: i + 1, nom: e.nom, champs: { prefix: champ(prefix), name: champ(name) } };
  }));
  if (noms) throw new Refus(`nom d'entrée refusé : ${noms.fr}`);
  const archive = P.ecrireArchive(entrees, mtime);
  if (archive.length > P.LIMITE_ARCHIVE) throw new Refus(`archive de ${archive.length} octets, au-delà de ${P.LIMITE_ARCHIVE}`);
  return { archive, manifeste, octetsManifeste };
}

const AIDE = `Construction d'un paquet réviseur NOORTRACE (CT-8 §13.5)

usage :
  node scripts/paquet-reviseur/construire.mjs --description <description.json> --sortie <paquet.tar>
  node scripts/paquet-reviseur/construire.mjs --aide

  --description   document JSON conforme à paquet-reviseur-v0#/$defs/description_source ;
                  ses chemins relatifs se résolvent contre son propre répertoire
  --sortie        archive à écrire ; elle ne doit pas exister
  --aide          cette aide

Codes de retour : 0 archive écrite ; 2 refus (rien n'est écrit).
Vérifiez le paquet par scripts/paquet-reviseur/verifier.mjs avant de le
remettre, et transmettez son SHA-256 au réviseur par un autre canal que
l'archive (EX-13.37).
`;

/** Vrai si le chemin existe, lien symbolique pendant compris. */
function existe(chemin) {
  try {
    fs.lstatSync(chemin);
    return true;
  } catch (err) {
    return err.code !== "ENOENT";
  }
}

/** Analyse stricte des options : inconnue, répétée ou sans valeur : refus (code 2). */
export function lireOptions(argv) {
  const o = {};
  const AVEC_VALEUR = new Set(["description", "sortie"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) throw new Refus(`argument inattendu : ${a}`);
    let [nom, v] = a.slice(2).split(/=(.*)/s);
    if (Object.hasOwn(o, nom)) throw new Refus(`option répétée : --${nom}`);
    if (AVEC_VALEUR.has(nom)) {
      if (v === undefined) v = argv[++i];
      if (v === undefined || v === "") throw new Refus(`--${nom} sans valeur`);
      o[nom] = v;
    } else if (nom === "aide" || nom === "help") {
      if (v !== undefined) throw new Refus(`--${nom} ne prend pas de valeur`);
      o.aide = true;
    } else throw new Refus(`option inconnue : --${nom}`);
  }
  if (o.aide) {
    if (Object.keys(o).length > 1) throw new Refus("--aide ne se combine avec aucune autre option");
    return o;
  }
  if (!o.description || !o.sortie) throw new Refus("--description et --sortie sont obligatoires (--aide pour l'usage)");
  return o;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  try {
    const opt = lireOptions(process.argv.slice(2));
    if (opt.aide) {
      process.stdout.write(AIDE);
      process.exit(0);
    }
    // Refus d'une sortie existante avant tout travail (EX-13.18, pas 10).
    if (existe(opt.sortie)) throw new Refus(`${opt.sortie} existe déjà : l'outil ne remplace jamais un fichier`);
    let octets;
    try {
      octets = fs.readFileSync(opt.description);
    } catch (err) {
      throw new Refus(`${opt.description} : illisible (${err.code ?? err.message})`);
    }
    let description;
    try {
      description = J.analyserJSONStrict(octets);
    } catch (err) {
      throw new Refus(`${opt.description} : ${err.message}`);
    }
    const { archive, manifeste, octetsManifeste } = construire(description, path.dirname(path.resolve(opt.description)));
    try {
      fs.writeFileSync(opt.sortie, archive, { flag: "wx" });
    } catch (err) {
      throw new Refus(`${opt.sortie} : écriture impossible (${err.code ?? err.message})`);
    }
    console.log(`Paquet        : ${opt.sortie}, ${archive.length} octets, SHA-256 ${P.sha256(archive)}`);
    console.log(`Manifeste     : ${manifeste.files.length} fichiers, ${manifeste.dossiers.length} dossier(s), SHA-256 ${P.sha256(octetsManifeste)}`);
    console.log("Remise        : transmettez le SHA-256 du paquet au réviseur par un autre canal que l'archive (CT-8 EX-13.37)");
  } catch (err) {
    console.error(`Erreur : ${err instanceof Refus ? err.message : `erreur interne : ${err.message}`}`);
    process.exit(2);
  }
}
