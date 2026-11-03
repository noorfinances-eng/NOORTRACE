// Ligne de commande `noortrace-ctl` : actions du lot WORM.
//
//   noortrace-ctl worm gel poser            --configuration <fichier> --identifiants <référence> --identite <nom> --de <period_start> --a <period_start> --motif <texte> [--reference <texte>] [--registre-copies <répertoire>] [--journal-exploitation <chemin>]
//   noortrace-ctl worm gel demander-levee   --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> --motif <texte> [--journal-exploitation <chemin>]
//   noortrace-ctl worm gel lever            --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> --demande <sha256> [--journal-exploitation <chemin>]
//   noortrace-ctl worm gel reprendre        --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> [--journal-exploitation <chemin>]
//   noortrace-ctl worm gel etat             --configuration <fichier> --identifiants <référence> --gel <gel_id>
//   noortrace-ctl worm releve               --configuration <fichier> [--journal-exploitation <chemin>]
//   noortrace-ctl worm reconstruire         --configuration <fichier> --vers <répertoire> [--registre-copies <répertoire>] [--identifiants <référence>] [--cles <cles.json>] [--journal-exploitation <chemin>]
//   noortrace-ctl worm restaurer <clé>      --version <id> --configuration <fichier> --vers <répertoire> [--registre-copies <répertoire>] [--identifiants <référence>]
//
// Les actions `worm gel` (CT-2 EX-12.36) s'exécutent hors du démon, sous
// l'identité de l'exploitant, avec SES identifiants (`--identifiants`, une
// référence de secret de 15.2 écrite en JSON) : la commande refuse (code 2)
// des identifiants égaux à la référence `storage.seal.worm.credentials` ;
// elle ne résout pas les identifiants de l'écrivain, n'ouvre ni
// `storage.root`, ni le bail, ni le signataire. `worm releve` (EX-17.6, « à
// la demande ») est une commande locale sous l'utilisateur du démon
// (EX-18.1) : elle emploie les identifiants de l'écrivain, dont elle n'use
// que les droits de lecture, et le registre des copies du journal.
// `worm reconstruire` et `worm restaurer` (CT-2 EX-12.17 ; CT-8 §11.4 chemin
// B et EX-10.14) relisent les copies avec les mêmes droits de lecture (ou ceux
// du rôle Lecteur, `--identifiants`) et n'écrivent que dans un répertoire neuf.

import fs from "node:fs";
import path from "node:path";
import { ecrireHorodatage } from "@noortrace/noyau";
import { validerConfiguration, ligneRapport } from "../configuration.mjs";
import { resoudreSecret, ErreurSecret } from "../secrets.mjs";
import { jcsIntegralOctets } from "../jcs-integral.mjs";
import { operationsSupport } from "./support.mjs";
import { OutilGel, ArretOutil, CODES } from "./gel.mjs";
import { lireRegistres } from "./registre.mjs";
import { lireRegistreGels, releverVerrouillage } from "./controles.mjs";
import { epoqueMaxNoms } from "../ha/cloture.mjs";
import {
  reconstruireJournal, restaurerVersion, registreParCle, ErreurRestauration, clePubliqueDepuisConfiguration, clePubliqueDepuisCles,
} from "./restauration.mjs";

export const USAGE_CTL = [
  "usage : noortrace-ctl worm gel poser --configuration <fichier> --identifiants <référence> --identite <nom> --de <period_start> --a <period_start> --motif <texte> [--reference <texte>] [--registre-copies <répertoire>] [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm gel demander-levee --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> --motif <texte> [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm gel lever --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> --demande <sha256> [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm gel reprendre --configuration <fichier> --identifiants <référence> --identite <nom> --gel <gel_id> [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm gel etat --configuration <fichier> --identifiants <référence> --gel <gel_id>",
  "        noortrace-ctl worm releve --configuration <fichier> [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm reconstruire --configuration <fichier> --vers <répertoire> [--registre-copies <répertoire>] [--identifiants <référence>] [--cles <cles.json>] [--journal-exploitation <chemin>]",
  "        noortrace-ctl worm restaurer <clé> --version <id> --configuration <fichier> --vers <répertoire> [--registre-copies <répertoire>] [--identifiants <référence>]",
].join("\n");

const OPTIONS = {
  poser: { requises: ["configuration", "identifiants", "identite", "de", "a", "motif"], facultatives: ["reference", "registre-copies", "journal-exploitation"] },
  "demander-levee": { requises: ["configuration", "identifiants", "identite", "gel", "motif"], facultatives: ["journal-exploitation"] },
  lever: { requises: ["configuration", "identifiants", "identite", "gel", "demande"], facultatives: ["journal-exploitation"] },
  reprendre: { requises: ["configuration", "identifiants", "identite", "gel"], facultatives: ["journal-exploitation"] },
  etat: { requises: ["configuration", "identifiants", "gel"], facultatives: [] },
  releve: { requises: ["configuration"], facultatives: ["journal-exploitation"] },
  reconstruire: { requises: ["configuration", "vers"], facultatives: ["registre-copies", "identifiants", "cles", "journal-exploitation"] },
  restaurer: { requises: ["configuration", "vers", "version"], facultatives: ["registre-copies", "identifiants", "journal-exploitation"] },
};

/** Lignes du journal d'exploitation de l'outil (EX-9.5, composant `worm`), dans un fichier ou sur la sortie d'erreur. */
export class JournalOutil {
  /**
   * @param {{chemin: string|null, stderr: NodeJS.WritableStream, org_id: string|null, journal_id: string|null, murale: () => number}} o
   */
  constructor(o) {
    Object.assign(this, o);
    this.lignes = [];
  }

  consigner(niveau, composantOuEvenement, evenementOuData, data) {
    // Deux formes : (niveau, evenement, data) pour l'outil ; (niveau, composant, evenement, data) comme JournalExploitation.
    const [composant, evenement, d] = data === undefined ? ["worm", composantOuEvenement, evenementOuData] : [composantOuEvenement, evenementOuData, data];
    const ligne = {
      ts: ecrireHorodatage(this.murale()), level: niveau, component: composant, event: evenement,
      org_id: this.org_id, journal_id: this.journal_id, seq: null, host: null, request_id: null, data: d ?? {},
    };
    this.lignes.push(ligne);
    const texte = `${JSON.stringify(ligne)}\n`;
    if (this.chemin) {
      try {
        fs.mkdirSync(path.dirname(this.chemin), { recursive: true });
        fs.appendFileSync(this.chemin, texte, { mode: 0o600 });
        return;
      } catch {
        // à défaut, sur la sortie d'erreur
      }
    }
    this.stderr.write(texte);
  }
}

function analyserOptions(args, action) {
  const spec = OPTIONS[action];
  const o = {};
  for (let k = 0; k < args.length; k += 2) {
    const nom = args[k];
    if (!nom.startsWith("--") || k + 1 >= args.length) return { erreur: `option mal formée : ${nom}` };
    const n = nom.slice(2);
    if (![...spec.requises, ...spec.facultatives].includes(n)) return { erreur: `option inconnue : ${nom}` };
    if (n in o) return { erreur: `option répétée : ${nom}` };
    o[n] = args[k + 1];
  }
  for (const n of spec.requises) if (!(n in o)) return { erreur: `option requise : --${n}` };
  return { o };
}

const egalJson = (a, b) => {
  try {
    return Buffer.from(jcsIntegralOctets(a)).equals(Buffer.from(jcsIntegralOctets(b)));
  } catch {
    return false;
  }
};

/**
 * Exécute `noortrace-ctl` ; rend le code de sortie.
 * @param {string[]} argv arguments après le nom du programme
 * @param {{stdout?: NodeJS.WritableStream, stderr?: NodeJS.WritableStream, env?: NodeJS.ProcessEnv, murale?: () => number,
 *   aleatoire?: (n: number) => Uint8Array, delais?: number[], tls?: object}} [io]
 * @returns {Promise<number>}
 */
export async function principalCtl(argv, io = {}) {
  const stdout = io.stdout ?? process.stdout;
  const stderr = io.stderr ?? process.stderr;
  const env = io.env ?? process.env;
  const murale = io.murale ?? (() => Date.now());
  let action;
  let reste;
  if (argv[0] === "worm" && argv[1] === "gel" && argv[2] && argv[2] !== "releve") {
    action = argv[2];
    reste = argv.slice(3);
  } else if (argv[0] === "worm" && (argv[1] === "releve" || argv[1] === "reconstruire")) {
    action = argv[1];
    reste = argv.slice(2);
  } else if (argv[0] === "worm" && argv[1] === "restaurer" && argv[2] && !argv[2].startsWith("--")) {
    action = "restaurer";
    reste = argv.slice(3);
  }
  if (!action || !OPTIONS[action]) {
    stderr.write(`${USAGE_CTL}\n`);
    return CODES.USAGE;
  }
  const { o, erreur } = analyserOptions(reste, action);
  const journalSansConfig = new JournalOutil({ chemin: o?.["journal-exploitation"] ?? null, stderr, org_id: null, journal_id: null, murale });
  if (erreur) {
    stderr.write(`${erreur}\n${USAGE_CTL}\n`);
    return CODES.USAGE;
  }
  // Pas 1 : configuration en JSON strict, validée contre le schéma.
  let config;
  try {
    const v = validerConfiguration(new Uint8Array(fs.readFileSync(o.configuration)));
    if (v.erreurs.length) {
      for (const e of v.erreurs) stderr.write(`config_invalid : ${ligneRapport(e)}\n`);
      journalSansConfig.consigner("error", "worm_legal_hold_failed", { raison: "configuration" });
      return CODES.USAGE;
    }
    config = v.config;
  } catch {
    stderr.write("/ : fichier de configuration illisible\n");
    journalSansConfig.consigner("error", "worm_legal_hold_failed", { raison: "configuration" });
    return CODES.USAGE;
  }
  const worm = config.storage.seal.worm;
  const journal = new JournalOutil({
    chemin: o["journal-exploitation"] ?? (action === "releve" ? config.supervision.ops_log.path : null),
    stderr,
    org_id: config.recorder.org_id,
    journal_id: config.recorder.journal_id,
    murale,
  });
  if (!worm) {
    stderr.write("/storage/seal/worm : support WORM non configuré\n");
    journal.consigner("error", "worm_legal_hold_failed", { raison: "configuration" });
    return CODES.USAGE;
  }
  if (action === "releve") return releveCtl({ config, worm, env, journal, stdout, stderr, murale, io });
  if (action === "reconstruire" || action === "restaurer") return restaurationCtl({ action, cle: argv[2], o, config, worm, env, journal, stdout, stderr, murale, io });

  // Pas 2 : identifiants de l'exploitant, jamais ceux de l'écrivain.
  let ref;
  try {
    ref = JSON.parse(o.identifiants);
  } catch {
    ref = null;
  }
  if (!ref || typeof ref !== "object" || Array.isArray(ref) || egalJson(ref, worm.credentials)) {
    stderr.write("--identifiants : référence de secret absente, illisible, ou égale à celle de l'écrivain (EX-12.36)\n");
    journal.consigner("error", "worm_legal_hold_failed", { raison: "identifiants" });
    return CODES.USAGE;
  }
  let operations;
  try {
    const octets = resoudreSecret(ref, "--identifiants", { env });
    operations = operationsSupport(worm, octets, { delais: io.delais, tls: io.tls, murale });
  } catch (e) {
    stderr.write(`--identifiants : ${e instanceof ErreurSecret ? e.regle : e.message}\n`);
    journal.consigner("error", "worm_legal_hold_failed", { raison: "identifiants" });
    return CODES.USAGE;
  }
  // Validation des valeurs (EX-12.35, EX-12.36).
  const invalide = (m) => {
    stderr.write(`${m}\n`);
    return CODES.USAGE;
  };
  if ("identite" in o && (o.identite.length < 1 || o.identite.length > 256)) return invalide("--identite : 1 à 256 caractères");
  if ("gel" in o && !/^gel-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/.test(o.gel)) return invalide("--gel : identifiant gel-<AAAAMMJJ>T<hhmmss>Z-<8 hex> attendu");
  if ("demande" in o && !/^0x[0-9a-f]{64}$/.test(o.demande)) return invalide("--demande : empreinte 0x et 64 chiffres hexadécimaux attendue");
  if ("motif" in o && o.motif.length < 1) return invalide("--motif : texte non vide attendu");
  let de;
  let a;
  if (action === "poser") {
    de = /^[0-9]{1,12}$/.test(o.de) ? Number(o.de) : NaN;
    a = /^[0-9]{1,12}$/.test(o.a) ? Number(o.a) : NaN;
    if (!Number.isSafeInteger(de) || !Number.isSafeInteger(a) || de % 3600 !== 0 || a % 3600 !== 0 || de > a) {
      return invalide("--de, --a : deux period_start multiples de 3 600, --de ≤ --a");
    }
  }
  let registreCopies = null;
  if (o["registre-copies"]) {
    registreCopies = (await lireRegistres(o["registre-copies"])).map((x) => ({ key: x.ligne.key, version_id: x.ligne.version_id }));
  }
  const outil = new OutilGel({
    config,
    operations,
    journal,
    sortie: (t) => stdout.write(t),
    murale,
    aleatoire: io.aleatoire,
    registreCopies,
  });
  try {
    switch (action) {
      case "poser":
        return await outil.poser({ identite: o.identite, de, a, motif: o.motif, reference: o.reference ?? null });
      case "demander-levee":
        return await outil.demanderLevee({ identite: o.identite, gel: o.gel, motif: o.motif });
      case "lever":
        return await outil.lever({ identite: o.identite, gel: o.gel, demande: o.demande });
      case "reprendre":
        return await outil.reprendre({ identite: o.identite, gel: o.gel });
      case "etat":
        return await outil.etat({ gel: o.gel });
      default:
        return CODES.USAGE;
    }
  } catch (e) {
    if (e instanceof ArretOutil) {
      if (e.code !== CODES.GARDE) journal.consigner("error", "worm_legal_hold_failed", { raison: e.raison, ...e.data });
      stderr.write(`noortrace-ctl : ${e.raison}\n`);
      return e.code;
    }
    journal.consigner("error", "worm_legal_hold_failed", { raison: "erreur", message: String(e?.message ?? e) });
    stderr.write(`noortrace-ctl : ${e?.message ?? e}\n`);
    return CODES.PARTIEL;
  }
}

/** `noortrace-ctl worm releve` : relevé à la demande (EX-17.6), consigné. */
async function releveCtl({ config, worm, env, journal, stdout, stderr, murale, io }) {
  let operations;
  try {
    const octets = resoudreSecret(worm.credentials, "/storage/seal/worm/credentials", { env });
    operations = operationsSupport(worm, octets, { delais: io.delais, tls: io.tls, murale });
  } catch (e) {
    stderr.write(`/storage/seal/worm/credentials : ${e instanceof ErreurSecret ? e.regle : e.message}\n`);
    return CODES.USAGE;
  }
  const repertoire = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
  const epoque = await epoqueMaxNoms(path.join(repertoire, "worm"), /^copies-([0-9]{20})\.ndjson$/);
  const ctx = { operations, worm, repertoire, epoque, journal, metriques: null, murale, vus: new Set() };
  journal.consigner("info", "supervision", "integrity_check", { check: "releve_demande", ok: true });
  let gels;
  try {
    gels = await lireRegistreGels(ctx);
    if (!gels.ok) journal.consigner("error", "supervision", "integrity_check", { check: "registre_gels", ok: false });
  } catch {
    gels = { ok: false, gels: [] };
  }
  try {
    const r = await releverVerrouillage({ ...ctx, gels: gels.gels });
    stdout.write(`${JSON.stringify(r)}\n`);
    return r.non_conformes || r.inattendues || !gels.ok ? CODES.PARTIEL : CODES.FAIT;
  } catch (e) {
    stderr.write(`noortrace-ctl : relevé impossible : ${e.message}\n`);
    return CODES.SUPPORT;
  }
}

/**
 * `worm reconstruire` et `worm restaurer` (CT-2 EX-12.17, CT-8 §11.4 et
 * EX-10.14). Codes : 0 fait ; 1 incident (copie absente, altérée, version non
 * inscrite, versions multiples, chaîne rompue) : rien n'est écrit ; 2 usage ;
 * 4 support injoignable.
 */
async function restaurationCtl({ action, cle, o, config, worm, env, journal, stdout, stderr, murale, io }) {
  let operations;
  try {
    let octets;
    if (o.identifiants) {
      const ref = JSON.parse(o.identifiants);
      octets = resoudreSecret(ref, "--identifiants", { env });
    } else {
      octets = resoudreSecret(worm.credentials, "/storage/seal/worm/credentials", { env });
    }
    operations = operationsSupport(worm, octets, { delais: io.delais, tls: io.tls, murale });
  } catch (e) {
    stderr.write(`identifiants : ${e instanceof ErreurSecret ? e.regle : e.message}\n`);
    return CODES.USAGE;
  }
  const original = path.join(config.storage.root, config.recorder.org_id.slice(2), config.recorder.journal_id.slice(2));
  const dirRegistre = o["registre-copies"] ?? (action === "restaurer" ? path.join(original, "worm") : null);
  const consigner = (niveau, composant, evenement, data) => journal.consigner(niveau, composant, evenement, data);
  try {
    if (action === "reconstruire") {
      const registre = dirRegistre ? await registreParCle(dirRegistre) : null;
      // Clé initiale du journal pour vérifier les signatures (CT-8 §11.4 pas 5 :
      // `--cles <fichier>`) ; à défaut, le signataire de classe D de la configuration.
      let clePublique = clePubliqueDepuisConfiguration(config, { env });
      if (o.cles) {
        try {
          clePublique = clePubliqueDepuisCles(JSON.parse(fs.readFileSync(o.cles, "utf8")));
        } catch {
          stderr.write("--cles : fichier cles.json illisible\n");
          return CODES.USAGE;
        }
      }
      const { synthese } = await reconstruireJournal({ config, operations, destination: o.vers, registre, murale, consigner, clePublique });
      stdout.write(`${JSON.stringify(synthese)}\n`);
      return CODES.FAIT;
    }
    const r = await restaurerVersion({ config, operations, cle, version_id: o.version, destination: o.vers, registre: (await registreParCle(dirRegistre)) ?? new Map(), original });
    journal.consigner("info", "worm", "worm_restored", { key: r.key, version_id: r.version_id, sha256: r.sha256, length: r.length });
    stdout.write(`${JSON.stringify(r)}\n`);
    return CODES.FAIT;
  } catch (e) {
    if (e instanceof ErreurRestauration) {
      journal.consigner("error", "worm", "worm_restore_refused", { incidents: e.incidents });
      stderr.write(`noortrace-ctl : ${e.message}\n`);
      return e.code;
    }
    if (e?.name === "ErreurTransport") {
      journal.consigner("error", "worm", "worm_restore_refused", { incidents: [{ kind: "injoignable" }] });
      return CODES.SUPPORT;
    }
    throw e;
  }
}
