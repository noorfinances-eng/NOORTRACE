// Bibliothèques de référence du déploiement (scripts/lib/deploiement.mjs,
// scripts/lib/sauvegarde.mjs ; CT-8 §4.4, EX-6.2, §11.2) : corrections de la
// revue de sécurité interne de l'étape 8 (CO-14, CO-1, CO-7 et CO-11 à
// listes fermées ; EX-6.2 : IP-10 suit les liens ; EX-11.1 : course entre la liste et la lecture de
// l'inventaire, archive écrite en flux).
//
// Chaque essai éprouve ensuite un mutant de la règle (copie de scripts/lib sous
// NOORTRACE_TMP, règle retirée, oracle en échec, copie détruite). Racine des
// scripts éprouvés : le dépôt, ou NOORTRACE_REVUE_RACINE.

import { expect } from "chai";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";

const RACINE = process.env.NOORTRACE_REVUE_RACINE ? path.resolve(process.env.NOORTRACE_REVUE_RACINE) : PROJECT_ROOT;
const TMP = process.env.NOORTRACE_TMP ?? os.tmpdir();
const MUTANTS = [];
const TRAVAIL = fs.mkdtempSync(path.join(TMP, "noortrace-revue-deploiement-"));
const READDIR_ORIGINE = fs.readdirSync;

const importer = (racine, lib) => import(pathToFileURL(path.join(racine, "scripts", "lib", lib)).href + `?t=${Date.now()}-${Math.random()}`);
function mutant(nom, lib, ancien, nouveau) {
  const racine = fs.mkdtempSync(path.join(TMP, `noortrace-revue-deploiement-${nom}-`));
  MUTANTS.push(racine);
  fs.mkdirSync(path.join(racine, "scripts"));
  fs.cpSync(path.join(RACINE, "scripts", "lib"), path.join(racine, "scripts", "lib"), { recursive: true });
  for (const l of ["spec", "node_modules", "package.json", "deploiement"]) fs.symlinkSync(path.join(PROJECT_ROOT, l), path.join(racine, l));
  const f = path.join(racine, "scripts", "lib", lib);
  const texte = fs.readFileSync(f, "utf8");
  const n = texte.split(ancien).length - 1;
  if (n !== 1) throw new Error(`mutant ${nom} : « ${ancien} » trouvé ${n} fois`);
  fs.writeFileSync(f, texte.replace(ancien, () => nouveau));
  return racine;
}
after(function () {
  fs.readdirSync = READDIR_ORIGINE;
  for (const r of MUTANTS) fs.rmSync(r, { recursive: true, force: true });
  fs.rmSync(TRAVAIL, { recursive: true, force: true });
});

const DESCRIPTION = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "deploiement", "images", "images.json"), "utf8"));
const PRODUCTION = fs.readFileSync(path.join(PROJECT_ROOT, "deploiement", "compose", "production.yaml"), "utf8");
const RAPIDE = fs.readFileSync(path.join(PROJECT_ROOT, "deploiement", "compose", "rapide.yaml"), "utf8");
const remplacer = (t, de, par) => {
  if (t.split(de).length !== 2) throw new Error(`motif absent ou non unique : ${de}`);
  return t.replace(de, par);
};
const codes = (r) => r.checks.filter((c) => c.status !== "reussi").map((c) => `${c.id}:${c.findings.map((f) => f.code).join("+")}`);

/** Les huit écritures du relecteur (CT-8 CO-7) et la vérification qui doit les refuser. */
const CAS = [
  ["sortie-externe-host", remplacer(PRODUCTION, "  sortie: {}\n", "  sortie:\n    external: true\n    name: host\n"), "CO-14:reseau_non_conforme"],
  ["sortie-macvlan", remplacer(PRODUCTION, "  sortie: {}\n", "  sortie:\n    driver: macvlan\n    driver_opts:\n      parent: eth0\n"), "CO-14:reseau_non_conforme"],
  ["security-opt-supplementaires", remplacer(PRODUCTION, '    security_opt:\n      - no-new-privileges:true\n    restart: unless-stopped\n    ports:\n      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:8300:8300"', '    security_opt:\n      - no-new-privileges:true\n      - no-new-privileges:false\n      - systempaths=unconfined\n      - seccomp=./config/permissif.json\n      - apparmor=profil-du-client\n    restart: unless-stopped\n    ports:\n      - "${NOORTRACE_IP_INTERNE:?adresse interne requise}:8300:8300"'), "CO-7:security_opt_non_conforme"],
  ["montage-interpole", remplacer(PRODUCTION, "        source: /srv/noortrace-outils/fichiers\n", "        source: /srv/noortrace-outils/${NOORTRACE_SOUS_REPERTOIRE}\n"), "CO-1:interpolation_non_admise"],
  ["journal-tmpfs", remplacer(PRODUCTION, "      - type: volume\n        source: journal\n        target: /var/lib/noortrace\n      - type: volume\n        source: exploitation", "      - type: tmpfs\n        target: /var/lib/noortrace\n      - type: volume\n        source: exploitation"), "CO-11:type_montage_non_admis"],
  ["volume-externe", remplacer(PRODUCTION, "  journal: {}\n  exploitation: {}\n", "  journal:\n    external: true\n    name: autre_projet_donnees\n  exploitation: {}\n"), "CO-11:volume_non_conforme"],
  ["propagation-rshared", remplacer(PRODUCTION, "        source: /srv/noortrace-outils/fichiers\n        target: /srv/pieces\n        bind:\n          create_host_path: false\n", "        source: /srv/noortrace-outils/fichiers\n        target: /srv/pieces\n        bind:\n          create_host_path: false\n          propagation: rshared\n"), "CO-11:option_montage_non_admise"],
  ["dollar-litteral", remplacer(PRODUCTION, "name: noortrace\n", "name: noortrace$$x\n"), "CO-1:interpolation_non_admise"],
];

describe("CT-8, référence : vérifications CO- à listes fermées (CO-1, CO-7, CO-11, CO-14)", function () {
  let D;
  before(async function () {
    D = await importer(RACINE, "deploiement.mjs");
  });
  const oracle = (M) => CAS.every(([, texte, attendu]) => {
    const r = M.verifierConteneurs(texte, DESCRIPTION, "production.yaml");
    return r.verdict === "non_conforme" && JSON.stringify(codes(r)) === JSON.stringify([attendu]);
  });

  it("CT-8 CO-14, CT-8 CO-7 : un réseau macvlan ou externe, une interpolation hors liste (montage ou dollar littéral), une entrée de security_opt hors no-new-privileges:true, un montage tmpfs, une option bind hors create_host_path et un volume externe rendent non_conforme avec la seule vérification attendue ; les deux fichiers de référence restent conformes", function () {
    for (const [nom, texte, attendu] of CAS) {
      const r = D.verifierConteneurs(texte, DESCRIPTION, "production.yaml");
      expect(r.verdict, nom).to.equal("non_conforme");
      expect(codes(r), nom).to.deep.equal([attendu]);
    }
    expect(oracle(D)).to.equal(true);
    for (const [nom, texte] of [["production.yaml", PRODUCTION], ["rapide.yaml", RAPIDE]]) {
      const r = D.verifierConteneurs(texte, DESCRIPTION, nom);
      expect(r.verdict, nom).to.equal("conforme");
    }
    expect(D.INTERPOLATIONS_ADMISES.ports).to.deep.equal(["${NOORTRACE_IP_INTERNE:?adresse interne requise}"]);
    expect(D.INTERPOLATIONS_ADMISES.command).to.have.length(3);
  });

  it("mutant (CO-14) : sans la liste fermée des clés d'un réseau, le macvlan passe conforme (tué par l'oracle)", async function () {
    const M = await importer(mutant("co14", "deploiement.mjs", 'else if (!(r === null || r === undefined || (estObjet(r) && Object.keys(r).every((k) => CLES_RESEAU.includes(k)) && (r.internal === undefined || r.internal === true)))) ajouter("CO-14", null, "reseau_non_conforme");\n', ""), "deploiement.mjs");
    expect(oracle(M)).to.equal(false);
  });
  it("mutant CT-8 CO-14 (CO-1) : sans le refus des interpolations hors liste, la source /srv/noortrace-outils/${…} passe conforme (tué par l'oracle)", async function () {
    const M = await importer(mutant("co1", "deploiement.mjs", 'if (analysable) for (const { service } of interpolationsNonAdmises(doc)) ajouter("CO-1", service, "interpolation_non_admise");\n', ""), "deploiement.mjs");
    expect(oracle(M)).to.equal(false);
  });
  it("mutant (CO-7) : sans la liste fermée de security_opt, systempaths=unconfined passe conforme (tué par l'oracle)", async function () {
    const M = await importer(mutant("co7", "deploiement.mjs", '    else if (opts.some((o) => !SECURITY_OPT.includes(o))) ajouter("CO-7", nomS, "security_opt_non_conforme");\n', ""), "deploiement.mjs");
    expect(oracle(M)).to.equal(false);
  });
  it("mutant CT-8 CO-7 (CO-11) : sans la liste fermée des types et options de montage, tmpfs et propagation passent conformes (tué par l'oracle)", async function () {
    const M = await importer(mutant("co11", "deploiement.mjs", '      if (!TYPES_MONTAGE.includes(a.type)) ajouter("CO-11", nomS, "type_montage_non_admis");\n      else if (a.clesHorsType.length || a.clesBind.some((k) => !CLES_BIND.includes(k))) ajouter("CO-11", nomS, "option_montage_non_admise");\n', ""), "deploiement.mjs");
    expect(oracle(M)).to.equal(false);
  });
});

describe("CT-8, référence : IP-10 suit les liens d'un secret (EX-6.2)", function () {
  let D;
  before(async function () {
    D = await importer(RACINE, "deploiement.mjs");
  });
  /** Un répertoire de secrets dont cle-chaine est un lien vers un fichier lisible par tous. */
  async function observer(M) {
    const d = fs.mkdtempSync(path.join(TRAVAIL, "ip10-"));
    const sec = path.join(d, "secrets");
    fs.mkdirSync(sec, { mode: 0o700 });
    fs.writeFileSync(path.join(d, "cle-chaine-ailleurs"), "valeur d'essai\n", { mode: 0o644 });
    fs.chmodSync(path.join(d, "cle-chaine-ailleurs"), 0o644);
    fs.symlinkSync(path.join(d, "cle-chaine-ailleurs"), path.join(sec, "cle-chaine"));
    fs.writeFileSync(path.join(sec, "cle-mac-relais"), "00", { mode: 0o400 });
    fs.chmodSync(path.join(sec, "cle-mac-relais"), 0o400);
    const cfg = path.join(d, "configuration.json");
    fs.writeFileSync(cfg, "{}", { mode: 0o600 });
    const obs = await M.collecterObservations({ profil: "production", description: DESCRIPTION, secrets: sec, cheminConfiguration: cfg, only: ["IP-10"], date: "2026-11-13T00:00:00.000Z", env: {} });
    // Les propriétaires attendus sont ramenés aux réels : l'essai ne tourne pas sous les comptes des services.
    for (const f of obs.rights.secret_files) f.expected_uid = f.uid;
    obs.rights.config_expected_uid = obs.rights.config_uid;
    return { obs, rapport: M.evaluerControle(obs, M.exigencesProfil("production", { only: ["IP-10"] })) };
  }
  const oracle = async (M) => {
    const { obs, rapport } = await observer(M);
    const ip10 = rapport.checks.find((c) => c.id === "IP-10");
    return obs.rights.secret_files.map((f) => f.name).includes("cle-chaine") && ip10.status === "echoue" && ip10.reason === "secrets_lisibles";
  };
  it("CT-8 EX-6.2 : un secret posé en lien symbolique vers un fichier en 0644 est relevé (statSync, liens suivis) et IP-10 échoue secrets_lisibles", async function () {
    expect(await oracle(D)).to.equal(true);
  });
  it("mutant CT-8 EX-6.2 : avec lstatSync, le lien est écarté sans constat et IP-10 réussit (tué par l'oracle)", async function () {
    const M = await importer(mutant("ip10", "deploiement.mjs", "const st = fs.statSync(path.join(secrets, nom));\n      if (!st.isFile() || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(nom)) continue;", "const st = fs.lstatSync(path.join(secrets, nom));\n      if (!st.isFile() || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(nom)) continue;"), "deploiement.mjs");
    expect(await oracle(M)).to.equal(false);
  });
});

describe("CT-8, référence : inventaire de la sauvegarde sans course, archive en flux (§11.2, EX-11.1)", function () {
  let S;
  before(async function () {
    S = await importer(RACINE, "sauvegarde.mjs");
  });
  /** Un journal de deux fichiers ; entre la liste du répertoire et la lecture, journal.json est remplacé par un lien vers un fichier de l'hôte. */
  const course = (M) => {
    const j = fs.mkdtempSync(path.join(TRAVAIL, "journal-"));
    fs.writeFileSync(path.join(j, "journal.json"), '{"version":0}\n');
    fs.mkdirSync(path.join(j, "segments"));
    fs.writeFileSync(path.join(j, "segments", "seg-0000000000000001-00000000000000000001.ndjson"), '{"seq":1}\n');
    const hote = path.join(TRAVAIL, `hote-${path.basename(j)}.txt`);
    fs.writeFileSync(hote, "fichier de l'hote\n");
    fs.readdirSync = (p, o) => {
      const r = READDIR_ORIGINE(p, o);
      if (typeof p === "string" && path.resolve(p) === path.resolve(j) && fs.lstatSync(path.join(j, "journal.json")).isFile()) {
        fs.rmSync(path.join(j, "journal.json"));
        fs.symlinkSync(hote, path.join(j, "journal.json"));
      }
      return r;
    };
    try {
      const inv = M.inventaire(j);
      return { contenu: inv.fichiers.find((f) => f.path === "journal.json")?.octets.toString() ?? null, erreur: null };
    } catch (e) {
      return { contenu: null, erreur: e.message };
    } finally {
      fs.readdirSync = READDIR_ORIGINE;
    }
  };
  const oracle = (M) => {
    const r = course(M);
    return r.contenu === null && r.erreur !== null && /lien refusé/.test(r.erreur);
  };
  it("CT-8 EX-11.1 : un fichier remplacé par un lien entre la liste et la lecture est refusé (O_NOFOLLOW, même inode que la liste) : le contenu du fichier de l'hôte n'entre pas dans l'inventaire ; un lien présent dès la liste est refusé ; un répertoire ordinaire s'inventorie comme avant", function () {
    expect(oracle(S)).to.equal(true);
    const j = fs.mkdtempSync(path.join(TRAVAIL, "journal-"));
    fs.writeFileSync(path.join(j, "journal.json"), '{"version":0}\n');
    fs.symlinkSync(path.join(TRAVAIL, "ailleurs"), path.join(j, "lien.ndjson"));
    expect(() => S.inventaire(j)).to.throw(S.ErreurSauvegarde, /lien refusé/);
    fs.rmSync(path.join(j, "lien.ndjson"));
    fs.mkdirSync(path.join(j, "segments"));
    fs.writeFileSync(path.join(j, "segments", "seg-0000000000000001-00000000000000000001.ndjson"), '{"seq":1}\n{"seq":2}');
    const inv = S.inventaire(j);
    expect(inv.fichiers.map((f) => f.path)).to.deep.equal(["journal.json", "segments/seg-0000000000000001-00000000000000000001.ndjson"]);
    expect(inv.tronques).to.deep.equal([{ path: "segments/seg-0000000000000001-00000000000000000001.ndjson", length: 19, retenu: 10 }]);
    expect(inv.fichiers[1].octets.toString()).to.equal('{"seq":1}\n');
  });
  it("CT-8 EX-11.1 : ouvrirSansSuivre refuse un fichier dont l'inode n'est pas celui attendu, un lien et un répertoire", function () {
    const j = fs.mkdtempSync(path.join(TRAVAIL, "ouvrir-"));
    fs.writeFileSync(path.join(j, "a"), "a");
    fs.symlinkSync(path.join(j, "a"), path.join(j, "l"));
    fs.mkdirSync(path.join(j, "d"));
    expect(() => S.ouvrirSansSuivre(path.join(j, "l"), "l")).to.throw(S.ErreurSauvegarde, /lien refusé/);
    expect(() => S.ouvrirSansSuivre(path.join(j, "d"), "d")).to.throw(S.ErreurSauvegarde, /fichier spécial/);
    expect(() => S.ouvrirSansSuivre(path.join(j, "a"), "a", { ino: -1, dev: -1 })).to.throw(S.ErreurSauvegarde, /remplacé entre la liste et la lecture/);
    const { fd, st } = S.ouvrirSansSuivre(path.join(j, "a"), "a", fs.lstatSync(path.join(j, "a")));
    expect(st.size).to.equal(1);
    fs.closeSync(fd);
  });
  it("mutant CT-8 EX-11.1 : avec readFileSync (liens suivis) après la liste, le contenu du fichier de l'hôte entre dans l'inventaire (tué par l'oracle)", async function () {
    const M = await importer(mutant("course", "sauvegarde.mjs", "const { fd, st } = ouvrirSansSuivre(path.join(abs, e.name), r, liste);", "const fd = fs.openSync(path.join(abs, e.name), fs.constants.O_RDONLY); const st = fs.fstatSync(fd); void liste;"), "sauvegarde.mjs");
    expect(oracle(M)).to.equal(false);
  });
  it("CT-8 EX-11.1 : ecrireArchiveFlux rend les mêmes octets qu'ecrireArchive, morceau par morceau, avec le SHA-256 calculé au fil de l'eau, et lit les fichiers à l'écriture (lire()) sans les tenir tous en mémoire", function () {
    const fichiers = [{ path: "segments/seg-0000000000000001-00000000000000000001.ndjson", octets: Buffer.from('{"seq":1}\n') }, { path: "journal.json", octets: Buffer.from('{"version":0}\n') }];
    const attendu = S.ecrireArchive(fichiers, 1700000000);
    const morceaux = [];
    const r = S.ecrireArchiveFlux(fichiers.map((f) => ({ path: f.path, length: f.octets.length, lire: () => f.octets })), 1700000000, (b) => morceaux.push(Buffer.from(b)));
    const obtenu = Buffer.concat(morceaux);
    expect(obtenu.equals(attendu)).to.equal(true);
    expect(r).to.deep.equal({ sha256: S.sha256(attendu), length: attendu.length });
    expect(morceaux.length).to.be.greaterThan(2);
    expect(S.lireArchive(obtenu).erreurs).to.deep.equal([]);
    expect(() => S.ecrireArchiveFlux([{ path: "journal.json", length: 3, lire: () => Buffer.from("ab") }], 1700000000, () => {})).to.throw(/2 octets lus, 3 annoncés/);
  });
});
