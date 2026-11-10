// Ligne de commande de `bin/noortrace-ancrage` (CT-5 EX-8.13 : outil
// `serie`, `cout`, `trace` ; EX-10.6 : fiche de prestataire ; EX-10.7 :
// complétude au registre ; AN-1 : configuration ; `acquisitions` : résumé
// d'un fichier d'enregistrements d'EX-5.13). Codes de retour : 0 réussite,
// 1 défaut constaté ou erreur, 2 usage. Messages en français ; aucune valeur
// de secret n'est jamais affichée (les fiches sont privées d'`auth`,
// AN-54). L'horloge, l'aléa et les flux sont fournis par le binaire : rien
// ici ne lit l'horloge de la machine (règle 2 d'INTERFACES.md).

import fs from "node:fs";
import { analyserJson, hacherPoint, jcs, decoderHorodatage } from "@noortrace/noyau";
import {
  validerConfiguration, admettrePoint, admettreManifeste, tableEcheances, constaterCadence, cout, verifierCompletudeRegistre, rejouerTrace, PROFILS,
} from "./planificateur/index.mjs";
import { construireFiche, verifierFiche, epreuveAcceptation, transportHttps } from "./rfc3161/index.mjs";

export const USAGE = `noortrace-ancrage — composant d'ancrage NOORTRACE (CT-5)

Commandes :
  configuration <ancrage-v0.json> [--profil developpement|test|production] [--checkpoint-interval <s>] [--json]
        AN-1 : schéma ancrage-v0 puis les huit règles d'EX-4.9 ; code 1 si une règle est violée.
  serie --configuration <ancrage-v0.json> --periode <period_start> --points <serie.ndjson|json>
        [--cles <cles.json>] [--evenements <hashes.json>] [--manifeste <m.json> --signature <m.sig>]
        [--acquisitions <acquisitions.ndjson>] [--json]
        AN-3 sur chaque point (et le manifeste), AN-2 : table des échéances, délais d_jeton et d_point,
        écarts de cadence, alertes ; code 1 sur un refus d'admission ou une alerte.
  cout  [--entrees <cas.json>] [--journaux J] [--heures N] [--c-k s] [--c-t s] [--activite a]
        [--role principal|second_rang|interne|aucun] [--countersign-idle] [--registre nouveaux_evenements|tous|aucun]
        [--prix-qualifie p] [--prix-second-rang p] [--forfait F] [--quota Q|null] [--reprises r] [--json]
        EX-12.1, EX-12.2 : nombres et coût en unités symboliques (aucun prix par défaut : p = 1, 0.2, 0).
  trace <trace.json> [--json]
        Rejoue une trace de CT-5 §8.10 et compare expected et queue_after (AN-42) ; code 1 sur un écart.
  fiche (--prestataire <prestataire.json> | --configuration <ancrage-v0.json> --id <id>) [--epreuve] [--sortie <fichier>] [--json]
        EX-10.6, AN-54 : construit et vérifie la fiche ; --epreuve joue l'épreuve d'acceptation d'EX-11.4 (réseau).
  acquisitions <acquisitions.ndjson> [--json]
        Résume les tentatives par objet et nomme le jeton promu (EX-5.8, EX-5.13) ; code 1 sur une ligne illisible
        ou deux jetons promus non révoqués pour un même objet.
  completude <entrees.json> [--json]
        EX-10.7, AN-61 : complete, orphans, out_of_order, attached ; code 1 si la série n'est pas complète.
  aide

Codes de retour : 0 réussite ; 1 défaut constaté ou erreur ; 2 usage.
`;

export class ErreurUsage extends Error {
  constructor(message) {
    super(message);
    this.name = "ErreurUsage";
  }
}

/** Analyse `--option valeur` et `--drapeau`. */
export function analyserArguments(argv) {
  const options = {};
  const positionnels = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const nom = a.slice(2);
      const suivant = argv[i + 1];
      if (suivant !== undefined && !suivant.startsWith("--")) {
        options[nom] = suivant;
        i++;
      } else options[nom] = true;
    } else positionnels.push(a);
  }
  return { options, positionnels };
}

const exiger = (options, nom) => {
  const v = options[nom];
  if (v === undefined || v === true) throw new ErreurUsage(`--${nom} requis`);
  return v;
};
const nombre = (options, nom, defaut) => {
  const v = options[nom];
  if (v === undefined) return defaut;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new ErreurUsage(`--${nom} : nombre attendu`);
  return n;
};
const lireJson = (chemin) => {
  try {
    return analyserJson(new Uint8Array(fs.readFileSync(chemin)));
  } catch (e) {
    throw new Error(`${chemin} : ${e.message}`);
  }
};
const lireNdjsonOuJson = (chemin) => {
  const texte = fs.readFileSync(chemin, "utf8");
  if (texte.trimStart().startsWith("[")) return lireJson(chemin);
  return texte.split("\n").filter((l) => l.trim().length).map((l, i) => {
    try {
      return analyserJson(new TextEncoder().encode(l));
    } catch (e) {
      throw new Error(`${chemin}, ligne ${i + 1} : ${e.message}`);
    }
  });
};
const ecrireJson = (sortie, objet) => sortie.write(`${JSON.stringify(objet, null, 2)}\n`);

/**
 * Point d'entrée.
 * @param {{argv: string[], horloge: {murale: () => number, monotone: () => number}, aleatoire: (n: number) => Uint8Array,
 *   sortie: {write: (s: string) => void}, erreur: {write: (s: string) => void}, env?: Record<string, string|undefined>}} contexte
 * @returns {Promise<number>} code de retour
 */
export async function lancer(contexte) {
  const { argv, sortie, erreur } = contexte;
  const { options, positionnels } = analyserArguments(argv);
  const commande = positionnels[0];
  try {
    if (commande === undefined || commande === "aide" || options.aide) {
      sortie.write(USAGE);
      return commande === undefined && !options.aide ? 2 : 0;
    }
    switch (commande) {
      case "configuration": return commandeConfiguration(positionnels, options, sortie);
      case "serie": return commandeSerie(options, sortie);
      case "cout": return commandeCout(options, sortie);
      case "trace": return commandeTrace(positionnels, options, sortie);
      case "fiche": return await commandeFiche(options, sortie, contexte);
      case "acquisitions": return commandeAcquisitions(positionnels, options, sortie);
      case "completude": return commandeCompletude(positionnels, options, sortie);
      default: throw new ErreurUsage(`commande inconnue : ${commande}`);
    }
  } catch (e) {
    if (e instanceof ErreurUsage) {
      erreur.write(`usage : ${e.message}\n${USAGE}`);
      return 2;
    }
    erreur.write(`erreur : ${e.message}\n`);
    return 1;
  }
}

function commandeConfiguration(positionnels, options, sortie) {
  const chemin = positionnels[1];
  if (!chemin) throw new ErreurUsage("chemin du document ancrage-v0 attendu");
  const profil = options.profil ?? "developpement";
  if (!PROFILS.includes(profil)) throw new ErreurUsage(`--profil : ${PROFILS.join(", ")}`);
  const cK = options["checkpoint-interval"] === undefined ? null : nombre(options, "checkpoint-interval");
  const v = validerConfiguration(lireJson(chemin), { profil, checkpointIntervalEnregistreur: cK });
  if (options.json) ecrireJson(sortie, { valide: v.valide, profil, erreurs: v.erreurs });
  else if (v.valide) sortie.write(`configuration valide (AN-1, profil ${profil}) : ${v.projection.rfc3161.providers.length} prestataire(s), c_K ${v.projection.checkpoint_interval_s} s, c_T ${v.projection.rfc3161.checkpoints.interval_s} s\n`);
  else {
    sortie.write(`configuration refusée (AN-1, profil ${profil}) : ${v.erreurs.length} règle(s) violée(s)\n`);
    for (const e of v.erreurs) sortie.write(`  [${e.regle}] ${e.message}\n`);
  }
  return v.valide ? 0 : 1;
}

function commandeSerie(options, sortie) {
  const configuration = lireJson(exiger(options, "configuration"));
  const periodStart = nombre(options, "periode");
  if (!Number.isSafeInteger(periodStart) || periodStart % 3600 !== 0) throw new ErreurUsage("--periode : heure UTC pleine en secondes attendue");
  const points = lireNdjsonOuJson(exiger(options, "points"));
  const cles = options.cles ? lireJson(options.cles) : null;
  const hashes = options.evenements ? lireJson(options.evenements) : null;
  const rapport = { period_start: periodStart, points: points.length, admission: [], echeances: null, cadence: null, alertes: [], manifeste: null };
  // AN-3 : admission de chaque point à sa place dans la série.
  const serie = [];
  let refus = 0;
  for (const p of points) {
    let a;
    if (cles) {
      try {
        a = admettrePoint({ point: p, serie, cles, hashesPeriode: Array.isArray(hashes) ? hashes : null, periodStart });
      } catch (e) {
        a = { admis: false, empreinte: null, regle: "format", detail: e.message };
      }
    } else a = { admis: null, empreinte: hacherPoint(p), regle: null, detail: "cles.json absent : signature non vérifiée" };
    if (a.admis === false) refus += 1;
    else serie.push(p);
    rapport.admission.push({ checkpoint_ts: p.checkpoint_ts, tree_size: p.tree_size, checkpoint_hash: a.empreinte ?? hacherPoint(p), admis: a.admis, regle: a.regle, detail: a.detail });
  }
  if (options.manifeste) {
    const manifeste = lireJson(options.manifeste);
    const signature = options.signature ? lireJson(options.signature) : null;
    rapport.manifeste = cles && signature ? admettreManifeste({ manifeste, signature, cles }) : { admis: null, empreinte: null, regle: null, detail: "signature ou cles.json absent" };
    if (rapport.manifeste.admis === false) refus += 1;
  }
  // AN-2 : échéances et délais d'après les jetons promus d'acquisitions.ndjson.
  const ancres = [];
  let cloture = null;
  if (options.acquisitions) {
    const lignes = lireNdjsonOuJson(options.acquisitions);
    const dernieres = new Map();
    for (const e of lignes) dernieres.set(e.attempt_id, e);
    for (const e of dernieres.values()) {
      if (e.outcome !== "obtenue" || e.promoted !== true || e.revoked === true || !e.gen_time) continue;
      const jeton = { gen_time: e.gen_time, accuracy_s: e.upper_bound && e.gen_time ? Math.max(0, Math.ceil((decoderHorodatage(e.upper_bound) - decoderHorodatage(e.gen_time.endsWith("Z") && e.gen_time.length === 20 ? `${e.gen_time.slice(0, 19)}.000Z` : e.gen_time)) / 1000)) : 0, provider: e.provider_id };
      if (e.object === "manifeste") cloture = { jeton, generated_at: null };
      else ancres.push({ checkpoint_hash: e.imprint, jeton });
    }
  }
  const pointsTable = serie.map((p) => ({ checkpoint_hash: hacherPoint(p), tree_size: p.tree_size, checkpoint_ts: p.checkpoint_ts }));
  if (pointsTable.length) {
    rapport.echeances = tableEcheances({ periodStart, configuration, points: pointsTable, ancres, cloture });
    rapport.cadence = rapport.echeances.cadence;
    rapport.alertes = rapport.echeances.alertes;
  } else rapport.cadence = constaterCadence({ periodStart, checkpointIntervalS: configuration.checkpoint_interval_s, points: [] });
  const defaut = refus > 0 || rapport.alertes.length > 0;
  if (options.json) ecrireJson(sortie, { ...rapport, conforme: !defaut });
  else {
    sortie.write(`série de la période ${periodStart} : ${points.length} point(s), ${refus} refus d'admission (AN-3)\n`);
    for (const a of rapport.admission.filter((x) => x.admis === false)) sortie.write(`  refusé ${a.checkpoint_ts} (tree_size ${a.tree_size}) : ${a.regle} — ${a.detail}\n`);
    if (rapport.manifeste) sortie.write(`manifeste : ${rapport.manifeste.admis === false ? `refusé (${rapport.manifeste.regle})` : rapport.manifeste.admis ? "admis" : rapport.manifeste.detail}\n`);
    if (rapport.echeances) {
      sortie.write("échéance  instant                   point(tree_size)  état         d_point_s  d_jeton_s\n");
      for (const e of rapport.echeances.echeances) sortie.write(`  D_${String(e.k).padEnd(5)} ${e.at}  ${String(e.tree_size ?? "-").padEnd(16)} ${e.state.padEnd(12)} ${String(e.d_point_s ?? "-").padStart(9)}  ${String(e.d_jeton_s ?? "-").padStart(9)}\n`);
      const c = rapport.echeances.cloture;
      sortie.write(`  D_${String(c.k).padEnd(5)} ${c.at}  ${"clôture".padEnd(16)} ${c.state.padEnd(12)} ${"-".padStart(9)}  ${String(c.d_jeton_s ?? "-").padStart(9)}\n`);
      sortie.write(`cadence : ${rapport.cadence.conforme ? "conforme" : `${rapport.cadence.ecarts.length} écart(s) au-delà de ${rapport.cadence.tolerance_s} s`}\n`);
      for (const e of rapport.cadence.ecarts) sortie.write(`  écart ${e.gap_s} s entre ${e.de ?? "le début de la période"} et ${e.a}\n`);
      sortie.write(`alertes : ${rapport.alertes.length ? rapport.alertes.map((a) => a.code).join(", ") : "aucune"}\n`);
      if (rapport.echeances.fenetres.W_date_max_s !== null) sortie.write(`fenêtre de date observée : W_date ≤ ${rapport.echeances.fenetres.W_date_max_s} s (c_T ${rapport.echeances.fenetres.c_T} s)\n`);
    }
  }
  return defaut ? 1 : 0;
}

function commandeCout(options, sortie) {
  let entrees;
  if (options.entrees) {
    // Les entrées de coût portent des nombres décimaux (prix symboliques, part d'activité) : lecture JSON ordinaire.
    const d = JSON.parse(fs.readFileSync(options.entrees, "utf8"));
    entrees = d.input ?? d;
  } else {
    const quota = options.quota === undefined || options.quota === "null" ? null : nombre(options, "quota");
    entrees = {
      journals: nombre(options, "journaux", 1),
      hours_per_year: nombre(options, "heures", 8760),
      checkpoint_interval_s: nombre(options, "c-k", 60),
      rfc3161_checkpoint_interval_s: nombre(options, "c-t", 300),
      activity_ratio: nombre(options, "activite", 1),
      checkpoints_provider_role: options.role ?? "principal",
      countersign_idle: options["countersign-idle"] === true,
      registry_checkpoints: options.registre ?? "nouveaux_evenements",
      unit_price_qualified: nombre(options, "prix-qualifie", 1),
      unit_price_second_rank: nombre(options, "prix-second-rang", 0.2),
      subscription_fee: nombre(options, "forfait", 0),
      subscription_quota: quota,
      billable_retry_ratio: nombre(options, "reprises", 0),
    };
  }
  const r = cout(entrees);
  if (options.json) ecrireJson(sortie, { input: entrees, expected: r, unites: "symboliques (AN-60) : jamais un prix" });
  else {
    sortie.write(`coût par journal et par an (EX-12.1, EX-12.2), unités symboliques p (jamais un prix, AN-60)\n`);
    sortie.write(`  jetons qualifiés N_q      : ${r.qualified_tokens_per_journal}\n  jetons de second rang N_s : ${r.second_rank_tokens_per_journal}\n`);
    sortie.write(`  ancres au registre N_a    : ${r.registry_anchors_per_journal}\n  gaz au plus G             : ${r.gas_upper_bound_per_journal} wei\n`);
    sortie.write(`  coût par journal C_j      : ${r.cost_per_journal} p\n  coût total C              : ${r.cost_total} p (${entrees.journals} journal/journaux)\n`);
  }
  return 0;
}

function commandeTrace(positionnels, options, sortie) {
  const chemin = positionnels[1];
  if (!chemin) throw new ErreurUsage("chemin de la trace attendu");
  const trace = lireJson(chemin);
  const r = rejouerTrace(trace);
  if (options.json) ecrireJson(sortie, { id: trace.id, conforme: r.conforme, actions: r.actions.length, demandes: r.file.length, ecarts: r.ecarts.slice(0, 20) });
  else {
    sortie.write(`trace ${trace.id} : ${r.actions.length} action(s), ${r.file.length} demande(s) ; ${r.conforme ? "conforme à expected et queue_after (AN-42)" : `${r.ecarts.length} écart(s)`}\n`);
    for (const e of r.ecarts.slice(0, 10)) sortie.write(`  ${e.ou}[${e.indice}] attendu ${e.attendu ? jcs(e.attendu).slice(0, 160) : "rien"} ; obtenu ${e.obtenu ? jcs(e.obtenu).slice(0, 160) : "rien"}\n`);
  }
  return r.conforme ? 0 : 1;
}

/** Résout le secret d'un prestataire pour l'épreuve (CT-2 §15.2 : env ou file) ; la valeur n'est jamais affichée. */
function resoudreSecret(prestataire, env) {
  const s = prestataire.auth?.secret;
  if (!s || prestataire.auth.method === "aucune") return { ...prestataire, auth: { method: prestataire.auth?.method ?? "aucune", secret: null } };
  if (s instanceof Uint8Array) return prestataire;
  if (typeof s.env === "string") {
    const v = env?.[s.env];
    if (!v) throw new Error(`secret du prestataire ${prestataire.id} : variable ${s.env} absente`);
    return { ...prestataire, auth: { method: prestataire.auth.method, secret: new TextEncoder().encode(v) } };
  }
  if (typeof s.file === "string") return { ...prestataire, auth: { method: prestataire.auth.method, secret: new Uint8Array(fs.readFileSync(s.file)) } };
  throw new Error(`secret du prestataire ${prestataire.id} : emplacement vault non résolu par cet outil`);
}

async function commandeFiche(options, sortie, contexte) {
  let prestataire;
  if (options.prestataire) prestataire = lireJson(options.prestataire);
  else {
    const configuration = lireJson(exiger(options, "configuration"));
    const id = exiger(options, "id");
    prestataire = configuration.rfc3161?.providers?.find((p) => p.id === id);
    if (!prestataire) throw new Error(`prestataire ${id} absent de la configuration`);
  }
  let epreuve = null;
  if (options.epreuve) {
    const resolu = resoudreSecret(prestataire, contexte.env ?? {});
    epreuve = await epreuveAcceptation({ prestataire: resolu, transport: contexte.transport ?? transportHttps(), horloge: contexte.horloge, aleatoire: contexte.aleatoire });
  }
  const fiche = construireFiche(prestataire, { epreuve });
  const v = verifierFiche(fiche);
  if (options.sortie) fs.writeFileSync(options.sortie, `${JSON.stringify(fiche, null, 2)}\n`);
  if (options.json) ecrireJson(sortie, { fiche, verification: v });
  else {
    sortie.write(`fiche prestataire-${fiche.id}.json : ${v.conforme ? "conforme (AN-54)" : `${v.ecarts.length} écart(s) : ${v.ecarts.join(" ; ")}`}\n`);
    sortie.write(`  rôle ${fiche.role}, ${fiche.anchor_certificates.length} certificat(s) d'ancre, qualified ${fiche.qualified ? "renseigné" : "null"}${fiche.qualified_notice ? ` (${fiche.qualified_notice})` : ""}\n`);
    if (epreuve) sortie.write(`  épreuve d'acceptation (EX-11.4) à ${epreuve.tested_at} : ${epreuve.outcome}${epreuve.error_code ? ` (${epreuve.error_code})` : ""} ; T-1 à T-9 : ${epreuve.checks_passed.length}/9 ; gen_time ${epreuve.gen_time ?? "-"} ; unité ${epreuve.tsu_subject_cn ?? "-"}\n`);
    if (options.sortie) sortie.write(`  écrite dans ${options.sortie}\n`);
  }
  return v.conforme && (!epreuve || epreuve.outcome === "obtenue") ? 0 : 1;
}

function commandeAcquisitions(positionnels, options, sortie) {
  const chemin = positionnels[1];
  if (!chemin) throw new ErreurUsage("chemin d'acquisitions.ndjson attendu");
  const texte = fs.readFileSync(chemin, "utf8");
  const lignes = texte.split("\n");
  const tronquee = lignes[lignes.length - 1] !== "";
  const enregistrements = [];
  const illisibles = [];
  lignes.slice(0, -1).forEach((l, i) => {
    if (l === "") return;
    try {
      const e = analyserJson(new TextEncoder().encode(l));
      if (jcs(e) !== l) illisibles.push({ ligne: i + 1, raison: "forme_non_canonique" });
      enregistrements.push(e);
    } catch (err) {
      illisibles.push({ ligne: i + 1, raison: err.message.slice(0, 120) });
    }
  });
  const dernieres = new Map();
  for (const e of enregistrements) dernieres.set(e.attempt_id ?? Symbol("id"), e);
  const objets = new Map();
  for (const e of dernieres.values()) {
    const nom = e.object_name ?? "inconnu";
    const o = objets.get(nom) ?? { object: e.object, object_name: nom, imprint: e.imprint, tentatives: 0, issues: {}, prestataires: new Set(), promus: [], revoques: 0 };
    o.tentatives += 1;
    o.issues[e.outcome] = (o.issues[e.outcome] ?? 0) + 1;
    o.prestataires.add(e.provider_id);
    if (e.revoked === true) o.revoques += 1;
    if (e.promoted === true && e.revoked !== true) o.promus.push({ attempt_id: e.attempt_id, provider_id: e.provider_id, qualified: e.qualified !== null, gen_time: e.gen_time, upper_bound: e.upper_bound, token_sha256: e.token_sha256, token: e.files?.token ?? null, t10: e.checks?.["T-10"] ?? null });
    objets.set(nom, o);
  }
  const resume = [...objets.values()].map((o) => ({ ...o, prestataires: [...o.prestataires], promu: o.promus[0] ?? null, doublon: o.promus.length > 1 }));
  const defaut = tronquee || illisibles.length > 0 || resume.some((o) => o.doublon);
  if (options.json) ecrireJson(sortie, { lignes: enregistrements.length, tronquee, illisibles, objets: resume, conforme: !defaut });
  else {
    sortie.write(`${chemin} : ${enregistrements.length} ligne(s)${tronquee ? ", dernière ligne tronquée" : ""}${illisibles.length ? `, ${illisibles.length} illisible(s)` : ""}\n`);
    for (const o of resume) {
      sortie.write(`  ${o.object_name} : ${o.tentatives} tentative(s) [${Object.entries(o.issues).map(([k, v]) => `${k} ${v}`).join(", ")}], prestataires ${o.prestataires.join(", ")}${o.revoques ? `, ${o.revoques} révoqué(s)` : ""}\n`);
      if (o.promu) sortie.write(`    promu : ${o.promu.token ?? "-"} (${o.promu.attempt_id}, ${o.promu.provider_id}${o.promu.qualified ? ", qualifié" : ""}, gen_time ${o.promu.gen_time}, au plus tard ${o.promu.upper_bound}, T-10 ${o.promu.t10})\n`);
      else sortie.write("    aucun jeton promu\n");
      if (o.doublon) sortie.write(`    défaut : ${o.promus.length} jetons promus non révoqués (EX-5.8 : un seul)\n`);
    }
  }
  return defaut ? 1 : 0;
}

function commandeCompletude(positionnels, options, sortie) {
  const chemin = positionnels[1];
  if (!chemin) throw new ErreurUsage("chemin des entrées de complétude attendu");
  const d = lireJson(chemin);
  // Un cas seul (`input` ou les entrées nues), ou une famille de cas (`cases`, forme des vecteurs).
  const cas = Array.isArray(d.cases) ? d.cases.map((c) => ({ id: c.id, input: c.input, expected: c.expected ?? null })) : [{ id: d.id ?? null, input: d.input ?? d, expected: d.expected ?? null }];
  const resultats = cas.map((c) => {
    const r = verifierCompletudeRegistre(c.input);
    const attendu = c.expected ? jcs(c.expected) === jcs(r) : null;
    return { id: c.id, resultat: r, attendu_reproduit: attendu };
  });
  if (options.json) ecrireJson(sortie, resultats.length === 1 && cas[0].id === null ? resultats[0].resultat : resultats);
  else {
    for (const x of resultats) {
      const r = x.resultat;
      sortie.write(`${x.id ? `${x.id} : ` : ""}complétude au registre (EX-10.7) : ${r.complete ? "complete" : "incomplete"} ; ${r.attached} ancre(s) rattachée(s), ${r.orphans.length} orpheline(s), ${r.out_of_order.length} hors ordre${x.attendu_reproduit === null ? "" : x.attendu_reproduit ? " ; attendu reproduit" : " ; DIFFÉRENT de l'attendu"}\n`);
      for (const o of r.orphans) sortie.write(`  orpheline ${o}\n`);
      for (const o of r.out_of_order) sortie.write(`  hors ordre ${o}\n`);
    }
  }
  if (resultats.some((x) => x.attendu_reproduit === false)) return 1;
  return resultats.every((x) => x.resultat.complete || x.attendu_reproduit === true) ? 0 : 1;
}
