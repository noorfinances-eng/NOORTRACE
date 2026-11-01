// Famille `paquets` des vecteurs de CT-8 (spec/CT-8-deploiement-et-exploitation.md,
// §13 et annexe A.10) : spec/vecteurs/ct-8/paquets/.
//
// Construit valide.tar par l'outil de construction de référence avec la
// description de 13.5, en dérive onze archives qui ne diffèrent de lui que
// d'une chose (EX-A.12), construit observation.tar (dossiers du journal
// d'exemple de 12.4, EX-A.15), rejoue l'outil de vérification de référence
// sur les dix-sept cas de la table d'EX-A.13 et écrit cas.json (EX-A.14). Entrées lues,
// jamais modifiées : dossiers et ancres de ct-6, attestation de ct-7,
// manifeste d'instance de ct-4 (EX-A.11). Les rapports de l'outil ne sont pas
// écrits : ils portent des chemins absolus.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as J from "../../lib/journal.mjs";
import * as P from "../../lib/paquet.mjs";
import { construire } from "../../paquet-reviseur/construire.mjs";
import { journalExemple } from "./exploitation.mjs";

const RACINE_PROJET = fileURLToPath(new URL("../../../", import.meta.url));
/** Répertoire de référence de la famille : les chemins de description.json lui sont relatifs. */
export const REPERTOIRE_PAQUETS = path.join(RACINE_PROJET, "spec", "vecteurs", "ct-8", "paquets");
export const OUTIL_VERIFICATION = path.join(RACINE_PROJET, "scripts", "paquet-reviseur", "verifier.mjs");

const json = (v) => JSON.stringify(v, null, 2) + "\n";

const CT6 = "../../ct-6";
/** Description de valide.tar (CT-8 §13.5), chemins relatifs à spec/vecteurs/ct-8/paquets/. */
export const DESCRIPTION = {
  version: 0,
  label: "Paquet de démonstration des vecteurs CT-8 : journal sinistres, période du 2026-11-05 de 09:00 à 10:00",
  created_at: "2026-10-27T00:00:00.000Z",
  prepared_by: "exploitant de l'instance de démonstration (vecteurs CT-8)",
  dossiers: [
    { source: `${CT6}/dossiers/valide-seq-7-complet`, anchors: `${CT6}/ancres/ancres-test.json`, bitcoin_headers: `${CT6}/ots/entetes/chaine.json` },
    { source: `${CT6}/dossiers/valide-seq-7-complet-attestation`, anchors: `${CT6}/ancres/ancres-test.json`, bitcoin_headers: `${CT6}/ots/entetes/chaine.json` },
    { source: `${CT6}/dossiers/valide-point-de-controle-complet`, anchors: `${CT6}/ancres/ancres-test.json`, bitcoin_headers: `${CT6}/ots/entetes/chaine-points.json` },
  ],
  attestation: { signed: "../../ct-7/attestations/exemple/attestation-signee.json", approver_set: "../../ct-7/attestations/exemple/jeu.json" },
  pieces: ["../../ct-4/manifestes/valides/developpement/instance-r1.json"],
  include_verifier: false,
};

/**
 * Description d'observation.tar (EX-A.15) : les dossiers de seq 1 (annonce de
 * l'ensemble 2026-11-05-observation, policy.rule nulle) et de seq 3 (appel
 * marqué « [observation a_approuver] ») du journal d'exemple de 12.4, écrits
 * par la famille observation, et la pièce de l'ensemble en vigueur ; sans
 * ancres (les dossiers n'ont ni jeton, ni preuve, ni inscription).
 */
export function descriptionObservation() {
  const hex = journalExemple().empObs.policy_sha256.slice(2);
  return {
    version: 0,
    label: "Paquet de démonstration du mode observation (vecteurs CT-8, journal d'exemple de 12.4)",
    created_at: "2026-10-27T00:00:00.000Z",
    prepared_by: "exploitant de l'instance de démonstration (vecteurs CT-8)",
    dossiers: [
      { source: "../observation/dossiers/seq-1", anchors: null, bitcoin_headers: null },
      { source: "../observation/dossiers/seq-3", anchors: null, bitcoin_headers: null },
    ],
    attestation: null,
    pieces: [`../observation/politiques/${hex}.json`],
    include_verifier: false,
  };
}

/** Les dix-sept cas d'EX-A.13, dans l'ordre : nom, archive, empreinte attendue (nom d'archive dont prendre le SHA-256), ancres de la ligne de commande, description. */
const CAS = [
  ["valide", "valide.tar", null, null, "Paquet construit par l'outil de référence : trois dossiers valides de ct-6, le fichier d'ancres de test, deux fichiers d'en-têtes, l'attestation de ct-7 ; sans vérificateur joint."],
  ["valide-empreinte", "valide.tar", "valide.tar", null, "Le même paquet, vérifié avec l'empreinte attendue reçue à part : PR-2 réussit."],
  ["empreinte-fausse", "valide.tar", "fichier-altere.tar", null, "Le même paquet, vérifié avec l'empreinte d'un autre paquet : PR-2 échoue, rien d'autre n'est lu."],
  ["fichier-altere", "fichier-altere.tar", null, null, "Un octet de dossiers/valide-seq-7-complet/evenement.json changé (seq 7 devenu 9), manifeste inchangé : PR-8."],
  ["fichier-manquant", "fichier-manquant.tar", null, null, "dossiers/valide-seq-7-complet/voisins.json retiré de l'archive, toujours déclaré : PR-8."],
  ["fichier-en-trop", "fichier-en-trop.tar", null, null, "dossiers/valide-seq-7-complet/note.txt ajouté à sa place dans l'ordre, absent du manifeste : PR-8."],
  ["manifeste-altere", "manifeste-altere.tar", null, null, "Le manifeste déclare pour evenement.json le SHA-256 d'une autre version ; le fichier est intact : PR-8."],
  ["contrefacon-coherente", "contrefacon-coherente.tar", null, null, "evenement.json changé et le manifeste recalculé : le paquet est intact (PR-1 à PR-10), et le vérificateur de CT-6 rend le dossier invalide (D-2) : code 1."],
  ["chemin-hors-archive", "chemin-hors-archive.tar", null, null, "Entrée paquet-reviseur/../../evasion.txt, qui sortirait du répertoire d'extraction : PR-5."],
  ["chemin-absolu", "chemin-absolu.tar", null, null, "Entrée /paquet-reviseur/evasion.txt, nom absolu : PR-5."],
  ["lien-symbolique", "lien-symbolique.tar", null, null, "Entrée paquet-reviseur/ancres/raccourci, lien symbolique vers ../../../evasion, hors du répertoire d'extraction : PR-4."],
  ["lien-physique", "lien-physique.tar", null, null, "Entrée paquet-reviseur/ancres/double, lien physique vers un fichier de l'archive : PR-4, plus strict que GNU tar et que le filtre data de Python."],
  ["nom-en-double", "nom-en-double.tar", null, null, "Seconde entrée paquet-reviseur/LISEZMOI.md, d'un autre contenu : PR-5."],
  ["metadonnees-non-fixees", "metadonnees-non-fixees.tar", null, null, "paquet-reviseur/README.md au mode 0600 : PR-6."],
  ["ancres-du-reviseur-discordantes", "valide.tar", null, "spec/vecteurs/ct-6/ancres/ancres-cle-enregistreur-autre.json", "Le paquet valide, vérifié avec un fichier d'ancres du réviseur qui attribue à rec-test-01 la clé de rec-test-02 : paquet intact, N-3 échoue dans chaque dossier, code 1."],
  ["ancres-non-conformes", "valide.tar", null, "spec/vecteurs/ct-6/ots/entetes/chaine.json", "Le paquet valide, vérifié avec --ancres désignant un fichier qui n'est pas un fichier d'ancres : chaque dossier rend le code 2 (N-1), code 2."],
  ["observation", "observation.tar", null, null, "Paquet des dossiers de seq 1 (annonce de l'ensemble, policy.rule nulle) et de seq 3 (appel marqué) du journal d'exemple de 12.4, avec la pièce de l'ensemble : les deux dossiers sont déclarés en mode observation (policy_version en -observation), seq 3 avec la marque a_approuver (EX-12.9, EX-A.15)."],
];

/**
 * Archive « brute » : entrées dans l'ordre donné, avec leurs champs (type,
 * mode, lien, date), fin d'archive et bourrage d'EX-13.14. Sert aux variantes,
 * qui ne s'écartent de la forme canonique que d'une chose (EX-A.12).
 */
export function archiveBrute(entrees, mtime) {
  const m = [];
  for (const e of entrees) {
    m.push(P.enTete({ nom: e.nom, taille: e.octets.length, mtime: e.mtime ?? mtime, type: e.type ?? "0", mode: e.mode ?? P.MODE, lien: e.lien ?? "" }));
    m.push(e.octets);
    const r = e.octets.length % P.BLOC;
    if (r) m.push(Buffer.alloc(P.BLOC - r, 0));
  }
  m.push(Buffer.alloc(2 * P.BLOC, 0));
  const total = m.reduce((s, x) => s + x.length, 0);
  const pad = (P.ENREGISTREMENT - (total % P.ENREGISTREMENT)) % P.ENREGISTREMENT;
  if (pad) m.push(Buffer.alloc(pad, 0));
  return Buffer.concat(m);
}

/** Les treize archives : valide.tar, ses onze variantes et observation.tar (nom -> octets). */
export function archives() {
  const { archive: valide } = construire(DESCRIPTION, REPERTOIRE_PAQUETS);
  const mtime = Date.parse(DESCRIPTION.created_at) / 1000;
  const R = P.RACINE;
  const base = P.lireArchive(valide).entrees.map((e) => ({ nom: e.nom, octets: Buffer.from(e.donnees) }));
  const octetsDe = (nom) => base.find((e) => e.nom === nom).octets;
  const manifeste = J.analyserJSONStrict(octetsDe(P.MANIFESTE));
  const brute = (entrees) => archiveBrute(entrees, mtime);
  const trier = (entrees) => [...entrees].sort((a, b) => Buffer.compare(Buffer.from(a.nom), Buffer.from(b.nom)));
  const remplacer = (nom, octets) => base.map((e) => (e.nom === nom ? { nom, octets } : e));
  const manifesteOctets = (m) => Buffer.from(json(m));
  const EV = `${R}/dossiers/valide-seq-7-complet/evenement.json`;
  const evAltere = Buffer.from(octetsDe(EV).toString("utf8").replace('"seq": 7', '"seq": 9'));
  if (evAltere.equals(octetsDe(EV)) || evAltere.length !== octetsDe(EV).length) throw new Error("paquets : l'altération d'evenement.json doit changer un seul octet");
  const avecEmpreinte = (taille) => {
    const m = structuredClone(manifeste);
    const f = m.files.find((x) => x.path === "dossiers/valide-seq-7-complet/evenement.json");
    f.sha256 = P.sha256(evAltere);
    if (taille) f.size = evAltere.length;
    return manifesteOctets(m);
  };
  return {
    "valide.tar": valide,
    "fichier-altere.tar": brute(remplacer(EV, evAltere)),
    "fichier-manquant.tar": brute(base.filter((e) => e.nom !== `${R}/dossiers/valide-seq-7-complet/voisins.json`)),
    "fichier-en-trop.tar": brute(trier([...base, { nom: `${R}/dossiers/valide-seq-7-complet/note.txt`, octets: Buffer.from("fichier ajouté après la construction du paquet\n") }])),
    "manifeste-altere.tar": brute(remplacer(P.MANIFESTE, avecEmpreinte(false))),
    "contrefacon-coherente.tar": brute(remplacer(P.MANIFESTE, avecEmpreinte(true)).map((e) => (e.nom === EV ? { nom: EV, octets: evAltere } : e))),
    "chemin-hors-archive.tar": brute(trier([...base, { nom: `${R}/../../evasion.txt`, octets: Buffer.from("écrit hors du répertoire d'extraction\n") }])),
    "chemin-absolu.tar": brute([{ nom: `/${R}/evasion.txt`, octets: Buffer.from("nom absolu\n") }, ...base]),
    "lien-symbolique.tar": brute(trier([...base, { nom: `${R}/ancres/raccourci`, octets: Buffer.alloc(0), type: "2", lien: "../../../evasion" }])),
    "lien-physique.tar": brute(trier([...base, { nom: `${R}/ancres/double`, octets: Buffer.alloc(0), type: "1", lien: `${R}/ancres/ancres-test.json` }])),
    "nom-en-double.tar": brute(trier([...base, { nom: `${R}/LISEZMOI.md`, octets: Buffer.from("Seconde version des instructions, glissée après la construction.\n") }])),
    "metadonnees-non-fixees.tar": brute(base.map((e) => (e.nom === `${R}/README.md` ? { ...e, mode: 0o600 } : e))),
    "observation.tar": construire(descriptionObservation(), REPERTOIRE_PAQUETS).archive,
  };
}

/** Exécute l'outil de vérification de référence (--json) ; rend { status, rapport }. */
export function executerOutil(archive, { empreinte = null, ancres = null, env = {} } = {}) {
  const args = [OUTIL_VERIFICATION, archive, "--json"];
  if (empreinte) args.push("--empreinte", empreinte);
  if (ancres) args.push("--ancres", ancres);
  const r = spawnSync(process.execPath, args, { encoding: "utf8", env, maxBuffer: 64 * 1024 * 1024 });
  let rapport;
  try {
    rapport = JSON.parse(r.stdout);
  } catch {
    throw new Error(`${path.basename(archive)} : rapport illisible (code ${r.status}) ${r.stderr}`);
  }
  return { status: r.status, rapport };
}

/**
 * Écrit la famille sous `repertoire` (effacé puis recréé) ; rend les cas, pour
 * la section « paquets » d'INDEX.md.
 */
export function genererPaquets(repertoire) {
  fs.rmSync(repertoire, { recursive: true, force: true });
  fs.mkdirSync(repertoire, { recursive: true });
  fs.writeFileSync(path.join(repertoire, "description.json"), json(DESCRIPTION));
  fs.writeFileSync(path.join(repertoire, "description-observation.json"), json(descriptionObservation()));
  const tars = archives();
  for (const [nom, octets] of Object.entries(tars)) fs.writeFileSync(path.join(repertoire, nom), octets);
  const H = (nom) => P.sha256(tars[nom]);
  const env = process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {};
  const fichier = { version: 0, family: "paquets", description: "Paquets réviseurs de CT-8 §13 : un paquet valide et ses variantes, chacune avec ses options et le résultat attendu de l'outil de vérification.", cases: [] };
  for (const [name, archive, empreinteDe, ancres, description] of CAS) {
    const empreinte = empreinteDe ? H(empreinteDe) : null;
    const { status, rapport } = executerOutil(path.join(repertoire, archive), { empreinte, ancres: ancres ? path.join(RACINE_PROJET, ancres) : null, env });
    if (rapport.exit_code !== status) throw new Error(`paquets/${name} : code de sortie ${status} différent de exit_code ${rapport.exit_code} (EX-A.14)`);
    if (rapport.error) throw new Error(`paquets/${name} : erreur ${rapport.error.type} : ${rapport.error.message}`);
    fichier.cases.push({
      name,
      archive,
      archive_sha256: H(archive),
      options: { expected_sha256: empreinte, anchors: ancres },
      expected: {
        exit_code: rapport.exit_code,
        package_status: rapport.package_status,
        checks: rapport.checks.map((c) => ({ id: c.id, status: c.status, reason: c.reason })),
        warnings: rapport.warnings.map((w) => w.id),
        dossiers: rapport.dossiers.map((d) => ({ path: d.path, exit_code: d.exit_code, observation_mode: d.observation_mode, observation: d.observation })),
        observation: rapport.summary.observation,
      },
      description,
    });
  }
  const erreurs = J.validerSchema(fichier, P.chargerSchema(), { fragment: "#/$defs/fichier_cas" });
  if (erreurs.length) throw new Error(`paquets/cas.json non conforme à $defs/fichier_cas : ${erreurs.map(P.texteErreur).join(" ; ")}`);
  fs.writeFileSync(path.join(repertoire, "cas.json"), json(fichier));
  return { cas: fichier.cases, tailles: Object.fromEntries(Object.entries(tars).map(([n, o]) => [n, o.length])), shaCas: P.sha256(Buffer.from(json(fichier))) };
}

const groupe = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " ");

/** Section « paquets » d'INDEX.md (EX-A.3, EX-A.14). */
export function sectionIndex({ cas, tailles, shaCas }) {
  const total = Object.values(tailles).reduce((s, t) => s + t, 0);
  const L = [];
  L.push("## paquets");
  L.push("");
  L.push("Paquets réviseurs de CT-8 §13, annexe A.10. `description.json` est la");
  L.push("description de `valide.tar` (13.5), chemins relatifs à `paquets/` ;");
  L.push("`valide.tar` est construit par `scripts/paquet-reviseur/construire.mjs`");
  L.push("(paquet allégé, sans vérificateur joint) ; chaque archive de variante n'en");
  L.push("diffère que d'une chose. `observation.tar` est construit de même depuis");
  L.push("`description-observation.json` (dossiers de `observation/dossiers/`, EX-A.15).");
  L.push("`cas.json` (schéma `paquet-reviseur-v0#/$defs/fichier_cas`)");
  L.push("donne, pour chaque cas, ses options et le résultat attendu de l'outil de");
  L.push("vérification, que le générateur a obtenu en l'exécutant (EX-A.14).");
  L.push("");
  L.push(`${Object.keys(tailles).length} archives, ${groupe(total)} octets en tout ; SHA-256 de \`cas.json\` :`);
  L.push(`\`${shaCas}\`.`);
  L.push("");
  L.push("| Cas | Archive | SHA-256 | Options | Code | Paquet | PR- en échec | Avertissements | Codes des dossiers | Ce qui change |");
  L.push("|---|---|---|---|---|---|---|---|---|---|");
  for (const c of cas) {
    const opts = [c.options.expected_sha256 ? `\`--empreinte ${c.options.expected_sha256}\`` : null, c.options.anchors ? `\`--ancres ${c.options.anchors}\`` : null].filter(Boolean).join(" ") || "—";
    const echecs = c.expected.checks.filter((x) => x.status === "echoue").map((x) => x.id).join(", ") || "—";
    const av = c.expected.warnings.join(", ") || "—";
    const codes = c.expected.dossiers.map((d) => d.exit_code).join(", ") || "—";
    L.push(`| \`${c.name}\` | \`${c.archive}\` (${tailles[c.archive]} octets) | \`${c.archive_sha256}\` | ${opts} | ${c.expected.exit_code} | \`${c.expected.package_status}\` | ${echecs} | ${av} | ${codes} | ${c.description} |`);
  }
  L.push("");
  L.push("Commande de chaque cas, depuis la racine du dépôt (code de sortie attendu en");
  L.push("commentaire) :");
  L.push("");
  L.push("```bash");
  for (const c of cas) {
    const args = [`spec/vecteurs/ct-8/paquets/${c.archive}`];
    if (c.options.expected_sha256) args.push(`--empreinte ${c.options.expected_sha256}`);
    if (c.options.anchors) args.push(`--ancres ${c.options.anchors}`);
    L.push(`# ${c.name} : code ${c.expected.exit_code}`);
    L.push(`node scripts/paquet-reviseur/verifier.mjs ${args.join(" ")}`);
  }
  L.push("```");
  L.push("");
  L.push("Reconstruction de `valide.tar` depuis sa description (l'archive écrite est");
  L.push("identique, octet pour octet) :");
  L.push("");
  L.push("```bash");
  L.push("node scripts/paquet-reviseur/construire.mjs --description spec/vecteurs/ct-8/paquets/description.json --sortie <nouveau fichier>.tar");
  L.push("```");
  return L.join("\n");
}
