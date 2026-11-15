#!/usr/bin/env node
// Harnais de mesure de CT-2 EX-16.2 (`npm run mesures:ct2`) : les objectifs de
// CT-2 §16.1 mesurés sur l'enregistreur réel, et les entrées de CT-9 §11.5 qui
// en dépendent : TM-1 (latence ajoutée par appel relayé), TM-2 (latence ajoutée
// à chaque octet d'un flux SSE), TM-3 (débit), TM-4 (latence ajoutée par échange
// de modèle hors flux), TM-5 (durée d'un appel `sign`), TM-7 (octets par
// événement et par appel en charge), TM-8 (reprise au démarrage), TM-9 (mémoire
// résidente), TM-38 (mode observation, paire avec et sans).
//
//   node scripts/mesures/ct-2-perf.mjs --sortie <répertoire> [--repertoire <répertoire du disque local>]
//        [--configuration spec/vecteurs/ct-2/mesures/configuration-mesure.json]
//        [--campagnes latence,sse,debit,modele,reprise,observation]
//        [--n 20000] [--echauffement 2000] [--cadence 1000] [--connexions-sse 16]
//        [--segment-reprise 268435456] [--systeme-de-reference] [--disque nvme|ssd|hdd|virtuel|memoire|inconnu]
//        [--etiquette ct2] [--conserver]
//
// Chaque campagne monte l'enregistreur avec la configuration de mesure publiée
// (pas 1 : classe D, bail `file`, politique `pii-v1`, stockage sous
// `--repertoire`, qui doit être sur le disque à mesurer), le serveur d'outils
// nul et le fournisseur de modèle simulé (pas 2), et le service d'approbation
// de CT-3 que tout appel d'outil traverse ; l'hôte de test (pas 3) est dans ce
// processus. Tous sur la même machine (EX-16.1). Les instants sont lus sur
// l'horloge monotone du système (CLOCK_MONOTONIC, `process.hrtime.bigint()`,
// la même pour tous les processus de la machine : CT-9 EX-11.5).
//
// Ce que le pas 4 d'EX-16.2 demande et que le journal d'exploitation ne porte
// pas : `t_recu`, `t_envoi`, `t_reponse` et l'instant du `fdatasync` par appel
// (la ligne `tool_call_relayed` ne porte que `duration_ms`, entier,
// CT-2 §9.2 ; E8-23). La soustraction de 16.1 est donc faite avec les instants
// du serveur d'outils nul (requête reçue en entier, réponse remise au
// système, même horloge) : `(t_reponse_hote − t_envoi_hote) − (t_repondu_serveur
// − t_recu_serveur)`. Elle comprend en plus les deux trajets sur la boucle
// locale entre l'enregistreur et le serveur d'outils, que 16.1 exclut : la
// valeur publiée majore la latence ajoutée. Une ligne supplémentaire
// (`latence_appel_relaye_journal`) donne la même soustraction avec
// `duration_ms` du journal, à la milliseconde. Le débit (pas 6) prend la
// dernière réponse reçue par l'hôte pour le dernier `fdatasync` (la réponse
// d'un appel de classe `ecriture` n'est rendue qu'après la durabilité,
// EX-12.6) : il minore `N / (t_dernier_fdatasync − t_premier_recu)`.
//
// Rapports (CT-9 EX-11.11, `$defs/rapport_mesure`) : un fichier par campagne,
// `<sortie>/rapport-<AAAA-MM-JJ>-<etiquette>-<campagne>.json`, chacun validé
// par `scripts/tests/mesures.mjs` avant d'être écrit, plus `<sortie>/resume.json`.
// Le rapport ne compte pour les cibles que sur le système de référence
// (`--systeme-de-reference`, déclaration de l'opérateur, CT-9 EX-11.1), jamais
// avec un disque en mémoire ; `met` est null ailleurs. Code de retour : 0 que
// les cibles soient tenues ou non (pas 7) ; 1 quand une mesure n'a pas pu être
// faite ; 2 usage.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { SignataireFichier, SignataireVerifie } from "@noortrace/enregistreur";
import { monter, requeteJson, lireConfigurationPubliee, CONFIGURATION_PUBLIEE, MEMBRES_REMPLACES, MEMBRES_D_OPTION } from "./montage.mjs";
import { Connexion, fabriqueAppelOutil, fabriqueEchangeModele, reponseOutilReussie, enSerie, aCadenceFixe, auPlusVite } from "./hote.mjs";
import { systeme, comptePourLesCibles, ligne, rapportMesure, ecrireRapportValide, publierEchantillons, chargeTexte, arbreModifie, agreger, lireJson, CATALOGUE, TYPES_DISQUE, arrondi3 } from "./commun.mjs";

export const CAMPAGNES = Object.freeze(["latence", "sse", "debit", "modele", "reprise", "observation"]);
const USAGE = "usage : node scripts/mesures/ct-2-perf.mjs --sortie <répertoire> [--repertoire <répertoire>] [--configuration <fichier>] [--campagnes a,b] [--n 20000] [--echauffement 2000] [--cadence 1000] [--connexions-sse 16] [--segment-reprise 268435456] [--systeme-de-reference] [--disque <type>] [--etiquette ct2] [--conserver]";
const ms = (ns) => Number(ns) / 1e6;

class ErreurMesure extends Error {}

// ------------------------------------------------------------------ relevés

/** `VmRSS` d'un processus, en octets, ou null. */
export function vmRss(pid) {
  try {
    const m = /^VmRSS:\s+([0-9]+) kB/m.exec(fs.readFileSync(`/proc/${pid}/status`, "utf8"));
    return m ? Number(m[1]) * 1024 : null;
  } catch {
    return null;
  }
}

/** Octets et nombre de fichiers sous un répertoire (0 s'il manque). */
export function tailleRepertoire(d) {
  let octets = 0;
  let fichiers = 0;
  if (!fs.existsSync(d)) return { octets, fichiers };
  for (const f of fs.readdirSync(d, { recursive: true, withFileTypes: true })) {
    if (!f.isFile()) continue;
    octets += fs.statSync(path.join(f.parentPath ?? f.path, f.name)).size;
    fichiers += 1;
  }
  return { octets, fichiers };
}

/** Lit `/metrics` de l'enregistreur et rend les histogrammes { nom{etiquettes}: { sum, count, seaux: [[le, n]] } }. */
export async function lireHistogrammes(portSante) {
  const r = await new Promise((res, rej) => {
    import("node:http").then((http) => {
      http.get({ host: "127.0.0.1", port: portSante, path: "/metrics", agent: false }, (x) => {
        let t = "";
        x.on("data", (k) => (t += k));
        x.on("end", () => res(t));
      }).on("error", rej);
    });
  });
  const h = {};
  for (const l of r.split("\n")) {
    const m = /^([a-z_]+)_(bucket|sum|count)(?:\{([^}]*)\})? ([0-9.e+-]+|\+Inf)$/.exec(l);
    if (!m) continue;
    const etiquettes = (m[3] ?? "").split(",").filter((x) => x && !x.startsWith("le=")).sort().join(",");
    const cle = `${m[1]}{${etiquettes}}`;
    h[cle] ??= { sum: 0, count: 0, seaux: [] };
    if (m[2] === "sum") h[cle].sum = Number(m[4]);
    else if (m[2] === "count") h[cle].count = Number(m[4]);
    else h[cle].seaux.push([/le="([^"]+)"/.exec(m[3])?.[1] ?? "+Inf", Number(m[4])]);
  }
  return h;
}

/** Différence de deux lectures d'un histogramme ; rend { n, mean, seaux: [[le, n]], majorant_p50, majorant_p99 } (bornes supérieures des seaux). */
export function differenceHistogramme(apres, avant) {
  if (!apres) return null;
  const n = apres.count - (avant?.count ?? 0);
  const somme = apres.sum - (avant?.sum ?? 0);
  const seaux = apres.seaux.map(([le, c], i) => [le, c - (avant?.seaux?.[i]?.[1] ?? 0)]);
  const majorant = (p) => {
    const rang = Math.ceil((p / 100) * n);
    const s = seaux.find(([, c]) => c >= rang);
    return s ? (s[0] === "+Inf" ? null : Number(s[0])) : null;
  };
  return n > 0 ? { n, mean: arrondi3(somme / n), seaux, majorant_p50: majorant(50), majorant_p99: majorant(99) } : null;
}

/** Échantillonne `VmRSS` d'un processus toutes les `pasMs` ms ; rend { arreter() → { max, releves } }. */
export function suivreMemoire(pid, pasMs = 200) {
  const releves = [];
  const t = setInterval(() => {
    const v = vmRss(pid);
    if (v !== null) releves.push(v);
  }, pasMs);
  return {
    arreter() {
      clearInterval(t);
      const v = vmRss(pid);
      if (v !== null) releves.push(v);
      return { max: releves.length ? Math.max(...releves) : null, releves };
    },
  };
}

// ------------------------------------------------------------------ campagnes

function conditionsCommunes(ctx, m) {
  const c = m.config;
  return [
    `configuration de mesure publiée : ${path.relative(ctx.racine, ctx.cheminConfiguration)} (SHA-256 ${ctx.publiee.sha256}) ; membres remplacés à l'exécution : ${MEMBRES_REMPLACES.join(", ")}${m.options.observation || m.options.segmentOctets ? ` ; membres d'option : ${MEMBRES_D_OPTION.join(", ")}` : ""}`,
    `signataire de classe ${c.signer.class} (${c.signer.backend.type}), bail ${c.lease.store.type}, politique de rédaction ${c.policy.redaction.name}, validation groupée ${c.storage.fsync.group_max_events} / ${c.storage.fsync.group_max_wait_ms} ms, mode d'approbation ${c.policy.approval.mode}`,
    `fdatasync actif (jamais désactivé par le harnais) sur ${ctx.sys.disk.type === "virtuel" ? "un disque virtuel dont l'honneur du fdatasync n'est pas établi" : `un disque de type ${ctx.sys.disk.type}`} ; répertoire de mesure ${ctx.repertoire}`,
    "hôte de test, serveur d'outils nul, fournisseur simulé, service d'approbation et enregistreur sur la même machine (EX-16.1), horloge monotone du système (EX-11.5)",
    `${chargeTexte()} au début de la campagne ; autres processus de la machine non maîtrisés par le harnais`,
  ];
}

/** Une ligne du rapport ; au-delà de 512 échantillons, la série est publiée à part (EX-11.4) : echantillons-<etiquette>-<campagne>-<ligne>.json à côté du rapport. */
const nouvelleLigne = (ctx, p) => {
  const fichier = path.join(ctx.repertoireRapports, `echantillons-${ctx.etiquette}-${ctx.campagneCourante}-${p.name}.json`);
  const l = ligne({ ...p, compte: ctx.compte, catalogue: ctx.catalogue, fichierEchantillons: fichier });
  if (l.samples_sha256) l.conditions = [...l.conditions, `échantillons publiés à part : ${path.basename(fichier)} (SHA-256 ${l.samples_sha256}, tableau JSON des valeurs dans l'ordre de collecte)`];
  return l;
};

/** Latence ajoutée par appel relayé (TM-1), signature (TM-5), mémoire à vide (TM-9) ; en mode observation : TM-38. */
async function campagneLatence(ctx, { observation = false } = {}) {
  const nom = observation ? "observation" : "latence";
  const m = await monter({ repertoire: path.join(ctx.repertoire, nom), configuration: ctx.cheminConfiguration, options: { observation, resultatOctets: 16384 } });
  try {
    const e = await m.demarrerEnregistreur();
    await new Promise((r) => setTimeout(r, 500));
    const memoireVide = vmRss(e.pid);
    const C = conditionsCommunes(ctx, m);
    const hAvant = await lireHistogrammes(e.ports.sante);
    const decalageJournal = fs.existsSync(m.journalExploitation) ? fs.statSync(m.journalExploitation).size : 0;
    const requete = fabriqueAppelOutil({ jeton: m.jetonHote, argumentsOctets: 4096 });
    const cx = new Connexion(e.ports.mcp);
    ctx.log(`${nom} : ${ctx.echauffement} appels d'échauffement puis ${ctx.n} appels, une connexion`);
    const mesures = await enSerie({ connexion: cx, requete, valide: reponseOutilReussie, appels: ctx.n, echauffement: ctx.echauffement, progres: ctx.progres(nom) });
    cx.fermer();
    const hApres = await lireHistogrammes(e.ports.sante);
    // Instants du serveur d'outils nul, par numéro d'appel.
    const srv = (await requeteJson({ port: m.portOutils, chemin: "/mesures", delaiMs: 60000 })).corps;
    const serveur = new Map(srv.n.map((n, i) => [n, { recu: BigInt(srv.recu_ns[i]), repondu: BigInt(srv.repondu_ns[i]) }]));
    const total = [];
    const ajoutee = [];
    const auServeur = [];
    for (const x of mesures) {
      const s = serveur.get(x.n);
      if (!s) throw new ErreurMesure(`appel ${x.n} : aucun instant au serveur d'outils nul`);
      total.push(ms(x.reponse_ns - x.envoi_ns));
      auServeur.push(ms(s.repondu - s.recu));
      ajoutee.push(ms(x.reponse_ns - x.envoi_ns) - ms(s.repondu - s.recu));
    }
    // Journal d'exploitation : duration_ms par appel (corrélation par l'id JSON-RPC, EX-16.2 pas 4).
    await new Promise((r) => setTimeout(r, 300));
    const relayes = new Map(m.lignesExploitation(decalageJournal).filter((l) => l.event === "tool_call_relayed").map((l) => [l.request_id, l.data.duration_ms]));
    const ajouteeJournal = mesures.map((x) => relayes.has(JSON.stringify(`m-${x.n}`)) ? ms(x.reponse_ns - x.envoi_ns) - relayes.get(JSON.stringify(`m-${x.n}`)) : null).filter((v) => v !== null);
    const sign = differenceHistogramme(hApres[`noortrace_sign_duration_ms{backend="${m.config.signer.backend.type}"}`], hAvant[`noortrace_sign_duration_ms{backend="${m.config.signer.backend.type}"}`]);
    const fsync = differenceHistogramme(hApres["noortrace_fsync_duration_ms{}"], hAvant["noortrace_fsync_duration_ms{}"]);
    const relais = differenceHistogramme(hApres['noortrace_relay_latency_ms{class="ecriture",path="mcp"}'], hAvant['noortrace_relay_latency_ms{class="ecriture",path="mcp"}']);
    const Cl = [...C, "arguments de 4 096 octets (valeur JSON), résultat de 16 384 octets (corps JSON-RPC du serveur nul), outil de classe ecriture autorisé par une règle automatique", "une connexion d'hôte, appels en série", `soustraction : (t_reponse_hote − t_envoi_hote) − (t_repondu_serveur − t_recu_serveur), instants du serveur d'outils nul et non du journal d'exploitation (E8-23) : la valeur comprend les deux trajets sur la boucle locale vers le serveur d'outils`, `temps total vu par l'hôte : ${JSON.stringify(agreger(total))} ms ; temps au serveur d'outils nul : ${JSON.stringify(agreger(auServeur))} ms`, `histogramme noortrace_relay_latency_ms de l'enregistreur (sa propre définition de 16.1, entier) : ${relais ? `n ${relais.n}, moyenne ${relais.mean} ms, p50 ≤ ${relais.majorant_p50} ms, p99 ≤ ${relais.majorant_p99} ms (bornes de seaux)` : "absent"}`];
    const results = [];
    const rep = ctx.repertoireRapports;
    const echantillons = (nomFichier, serie) => publierEchantillons(path.join(rep, nomFichier), serie);
    if (!observation) {
      results.push(nouvelleLigne(ctx, { name: "latence_appel_relaye", test_id: "TM-1", unit: "ms", serie: ajoutee, connections: 1, conditions: Cl }));
      results.push(nouvelleLigne(ctx, { name: "latence_appel_relaye_journal", test_id: "TM-1", unit: "ms", serie: ajouteeJournal, connections: 1, principale: false, conditions: [...C, `soustraction avec duration_ms de la ligne tool_call_relayed du journal d'exploitation (entier, milliseconde tronquée) corrélée par l'id JSON-RPC : ${ajouteeJournal.length} appels corrélés sur ${mesures.length}`] }));
      const ligneSignature = nouvelleLigne(ctx, { name: "signature", test_id: "TM-5", unit: "ms", n: sign?.n ?? null, value: null, text_value: sign ? `classe D (${m.config.signer.backend.type}) : ${sign.n} appels sign pendant TM-1, moyenne ${sign.mean} ms, p50 ≤ ${sign.majorant_p50} ms et p99 ≤ ${sign.majorant_p99} ms (bornes de seaux de l'histogramme noortrace_sign_duration_ms : ${sign.seaux.map(([le, c]) => `≤${le}:${c}`).join(" ")})` : "histogramme noortrace_sign_duration_ms absent", conditions: [...C, `backend : ${m.config.signer.backend.type}, classe D`, "durée par appel non publiée par l'enregistreur (ni journal ni métrique par appel) : moyenne et bornes de seaux de l'histogramme de 17.2 ; mesure isolée du même backend dans la ligne signature_classe_d_isolee", "classes A, B et C : aucun backend disponible en test (lacune nommée)"] });
      ligneSignature.mean = sign?.mean ?? null;
      results.push(ligneSignature);
      results.push(nouvelleLigne(ctx, { name: "signature_classe_d_isolee", test_id: "TM-5", unit: "ms", serie: await signatureIsolee(ctx), principale: false, conditions: [...C, `SignataireFichier (classe D) sous SignataireVerifie (signature vérifiée après chaque sign, EX-11.6), message de 200 octets, ${ctx.echauffement} échauffements puis ${ctx.n} appels dans le processus de l'hôte`] }));
      ctx.resume.memoire_vide_latence = memoireVide;
    } else {
      // TM-38 : paire avec et sans (EX-11.8) : même séquence de requêtes vers le serveur d'outils nul, sans l'enregistreur sur le chemin.
      ctx.log("observation : la même séquence sans l'enregistreur (paire avec et sans)");
      const sans = new Connexion(m.portOutils);
      const requeteSans = fabriqueAppelOutil({ jeton: null, outil: "appeler", argumentsOctets: 4096 });
      const mesuresSans = await enSerie({ connexion: sans, requete: requeteSans, valide: reponseOutilReussie, appels: ctx.n, echauffement: ctx.echauffement, premier: 1000000, progres: ctx.progres("observation (sans)") });
      sans.fermer();
      const avec = total;
      const sansSerie = mesuresSans.map((x) => ms(x.reponse_ns - x.envoi_ns));
      const aAvec = agreger(avec);
      const aSans = agreger(sansSerie);
      const difference = { p50: arrondi3(aAvec.p50 - aSans.p50), p95: arrondi3(aAvec.p95 - aSans.p95), p99: arrondi3(aAvec.p99 - aSans.p99), max: arrondi3(aAvec.max - aSans.max) };
      const Cp = [...C, "paire avec et sans (CT-9 EX-11.8, composition de pratiques publiées, non normée) : deux montages identiques sauf l'enregistreur sur le chemin, même machine, même séquence de requêtes, même ordre, l'un après l'autre", `avec l'enregistreur (mode observation) : ${JSON.stringify(aAvec)} ms ; sans (hôte → serveur d'outils nul) : ${JSON.stringify(aSans)} ms ; différence des percentiles : ${JSON.stringify(difference)} ms`];
      results.push(nouvelleLigne(ctx, { name: "observation_latence", test_id: "TM-38", unit: "ms", serie: ajoutee, connections: 1, conditions: [...Cl, "mode observation (policy.approval.mode observation, policy.version suffixée -observation, CT-2 EX-15.8)"] }));
      results.push(nouvelleLigne(ctx, { name: "observation_latence_paire", test_id: "TM-38", unit: "ms", serie: avec, connections: 1, principale: false, conditions: [...Cp, "cette ligne : la série AVEC l'enregistreur (temps total vu par l'hôte) ; la série SANS est la ligne observation_latence_paire_sans"] }));
      results.push(nouvelleLigne(ctx, { name: "observation_latence_paire_sans", test_id: "TM-38", unit: "ms", serie: sansSerie, connections: 1, principale: false, conditions: [...Cp, "cette ligne : la série SANS l'enregistreur"] }));
      results.push(nouvelleLigne(ctx, { name: "observation_ecriture", test_id: "TM-38", unit: "ms", n: fsync?.n ?? null, text_value: fsync ? `${fsync.n} fdatasync pendant la campagne, moyenne ${fsync.mean} ms, p50 ≤ ${fsync.majorant_p50} ms, p99 ≤ ${fsync.majorant_p99} ms (bornes de seaux de noortrace_fsync_duration_ms)` : "histogramme noortrace_fsync_duration_ms absent", principale: false, conditions: [...C, "durée d'écriture par appel (intention et événement) non publiée par l'enregistreur : histogramme des fdatasync de 17.2 (intentions et événements confondus)"] }));
      ctx.resume.observation = { avec: aAvec, sans: aSans, difference };
    }
    const notes = [`${nom} : ${mesures.length} appels mesurés après ${ctx.echauffement} d'échauffement ; latence ajoutée (soustraction par le serveur nul) ${JSON.stringify(agreger(ajoutee))} ms ; ${chargeTexte()} à la fin.`];
    if (sign) notes.push(`sign (classe D) : ${sign.n} appels, moyenne ${sign.mean} ms.`);
    return { nom, results, notes, methode: { warmup: ctx.echauffement, repetitions: ctx.n, clock: "monotone", pair_with_without: observation }, echantillons };
  } finally {
    await m.fermer();
  }
}

/** Durée d'un appel sign de la classe D, mesurée dans le processus de l'hôte (ligne supplémentaire de TM-5). */
async function signatureIsolee(ctx) {
  const d = fs.mkdtempSync(path.join(ctx.repertoire, "signature-"));
  try {
    const chemin = path.join(d, "cle.pem");
    fs.writeFileSync(chemin, generateKeyPairSync("ed25519").privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    const backend = SignataireFichier.charger({ environment: "developpement", keyId: "rec-mesure-01", chemin });
    const s = new SignataireVerifie(backend, { timeout_ms: 5000 });
    const message = new Uint8Array(200).fill(0x41);
    const serie = [];
    for (let i = 0; i < ctx.echauffement + ctx.n; i++) {
      const t = process.hrtime.bigint();
      await s.signer("rec-mesure-01", message);
      if (i >= ctx.echauffement) serie.push(ms(process.hrtime.bigint() - t));
    }
    return serie;
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
}

/** Débit (TM-3), octets par événement et par appel (TM-7), mémoire sous charge (TM-9). */
async function campagneDebit(ctx) {
  const m = await monter({ repertoire: path.join(ctx.repertoire, "debit"), configuration: ctx.cheminConfiguration, options: { resultatOctets: 16384 } });
  try {
    const e = await m.demarrerEnregistreur();
    await new Promise((r) => setTimeout(r, 500));
    const memoireVide = vmRss(e.pid);
    ctx.resume.m_0 = memoireVide;
    const C = conditionsCommunes(ctx, m);
    const sous = (x) => path.join(m.repertoireJournal, x);
    const requete = fabriqueAppelOutil({ jeton: m.jetonHote, argumentsOctets: 4096 });
    const connexions = Array.from({ length: 16 }, () => new Connexion(e.ports.mcp));
    const nbEvenements = () => m.lignesExploitation().filter((l) => l.event === "tool_call_relayed").length;
    // Échauffement à part : les tailles et la mémoire sont relevées autour des N appels comptés.
    ctx.log(`debit : ${ctx.echauffement} appels d'échauffement à ${ctx.cadence}/s sur 16 connexions`);
    await aCadenceFixe({ connexions, requete, valide: reponseOutilReussie, appels: ctx.echauffement, echauffement: 0, cadenceParS: ctx.cadence });
    await new Promise((r) => setTimeout(r, 1000));
    const avant = { segments: tailleRepertoire(sous("segments")), pieces: tailleRepertoire(sous("pieces")), intentions: tailleRepertoire(sous("intentions")), evenements: nbEvenements() };
    const memoire = suivreMemoire(e.pid);
    ctx.log(`debit : ${ctx.n} appels à cadence fixe ${ctx.cadence}/s, 16 connexions (omission coordonnée, EX-11.9)`);
    const r = await aCadenceFixe({ connexions, requete, valide: reponseOutilReussie, appels: ctx.n, echauffement: 0, premier: ctx.echauffement + 1, cadenceParS: ctx.cadence });
    const mem = memoire.arreter();
    await new Promise((r2) => setTimeout(r2, 1000));
    const apres = { segments: tailleRepertoire(sous("segments")), pieces: tailleRepertoire(sous("pieces")), intentions: tailleRepertoire(sous("intentions")), evenements: nbEvenements() };
    connexions.forEach((c) => c.fermer());
    const dureeS = Number(r.fin_ns - r.debut_ns) / 1e9;
    const debit = ctx.n / dureeS;
    const latences = r.mesures.map((x) => ms(x.reponse_ns - x.prevu_ns));
    const attentes = r.mesures.map((x) => ms(x.envoi_ns - x.prevu_ns));
    const evenements = apres.evenements - avant.evenements;
    const octetsParEvenement = evenements > 0 ? (apres.segments.octets - avant.segments.octets) / evenements : null;
    const octetsPiecesParAppel = (apres.pieces.octets - avant.pieces.octets) / ctx.n;
    // Les latences à cadence fixe (ms) ne peuvent pas être une ligne de TM-3 (unité evenements_par_s, MES-3) : publiées à part avec leur SHA-256, résumées dans conditions.
    const shaLatences = publierEchantillons(path.join(ctx.repertoireRapports, `echantillons-${ctx.etiquette}-debit-latences-cadence-fixe.json`), latences);
    const Cd = [...C, `16 connexions d'hôte ; ${ctx.n} appels émis à cadence fixe de ${ctx.cadence} par seconde (instant prévu t0 + i / cadence), répartis à tour de rôle sur les connexions ; latence comptée depuis l'instant prévu (EX-11.9)`, "mêmes tailles que TM-1 (arguments 4 096 octets, résultat 16 384 octets)", `débit = N / (dernière réponse reçue par l'hôte − instant prévu du premier appel compté) = ${ctx.n} / ${arrondi3(dureeS)} s ; l'instant du dernier fdatasync n'est pas dans le journal (E8-23) : la dernière réponse le suit, le débit publié le minore`, `latence depuis l'instant prévu : ${JSON.stringify(agreger(latences))} ms (série publiée à part : echantillons-${ctx.etiquette}-debit-latences-cadence-fixe.json, SHA-256 ${shaLatences}) ; attente en file avant l'envoi effectif : ${JSON.stringify(agreger(attentes))} ms`];
    const results = [
      nouvelleLigne(ctx, { name: "debit", test_id: "TM-3", unit: "evenements_par_s", value: debit, n: ctx.n, connections: 16, conditions: Cd }),
      nouvelleLigne(ctx, { name: "octets_pieces_par_appel", test_id: "TM-7", unit: "octets", value: octetsPiecesParAppel, n: ctx.n, connections: 16, conditions: [...Cd, `croissance de pieces/ pendant les N appels comptés : ${apres.pieces.octets - avant.pieces.octets} octets, ${apres.pieces.fichiers - avant.pieces.fichiers} fichiers (arguments et résultat distincts par appel), divisée par N`] }),
      nouvelleLigne(ctx, { name: "octets_par_evenement_en_charge", test_id: "TM-7", unit: "octets", value: octetsParEvenement, n: evenements || null, connections: 16, principale: false, conditions: [...Cd, `croissance de segments/ pendant les N appels comptés : ${apres.segments.octets - avant.segments.octets} octets pour ${evenements} événements tool_call_relayed consignés (saut de ligne compris) ; nom propre (EX-11.11) : octets_par_evenement est le result_name de TM-6`, `intentions/ : ${apres.intentions.octets - avant.intentions.octets} octets`] }),
      nouvelleLigne(ctx, { name: "memoire_charge", test_id: "TM-9", unit: "octets", serie: mem.releves, percentiles: false, connections: 16, conditions: [...Cd, `VmRSS de /proc/<pid>/status du démon relevé toutes les 200 ms pendant les N appels comptés ; m_0 (memoire_vide) = ${memoireVide} octets ; memoire_charge − memoire_vide = ${mem.max === null || memoireVide === null ? "inconnu" : mem.max - memoireVide} octets`, "M_tamp du calculateur (scripts/deploiement/dimensionner.mjs, memory_buffers_max_bytes) non confronté par le harnais : m_0 est à reporter dans ses entrées (membre coefficients)"] }),
      nouvelleLigne(ctx, { name: "memoire_vide", test_id: "TM-9", unit: "octets", value: memoireVide, n: 1, principale: false, conditions: [...C, "VmRSS de /proc/<pid>/status du démon 500 ms après sa santé ok, avant tout appel (m_0)"] }),
    ];
    const notes = [`debit : ${arrondi3(debit)} événements/s sur ${arrondi3(dureeS)} s à cadence ${ctx.cadence}/s ; octets par événement ${arrondi3(octetsParEvenement)}, octets de pièces par appel ${arrondi3(octetsPiecesParAppel)} ; VmRSS max ${mem.max} octets ; ${chargeTexte()} à la fin.`];
    if (octetsParEvenement !== null && (octetsParEvenement > 2 * 1588.11 || octetsParEvenement < 1588.11 / 2)) notes.push(`octets par événement en charge à plus d'un facteur 2 de la moyenne de TM-6 (1 588,11 octets sur les vecteurs) : arguments et résultat de mesure plus grands que ceux de la démonstration.`);
    ctx.resume.debit = { debit: arrondi3(debit), duree_s: arrondi3(dureeS), vmrss_max: mem.max };
    return { nom: "debit", results, notes, methode: { warmup: ctx.echauffement, repetitions: ctx.n, clock: "monotone", pair_with_without: false } };
  } finally {
    await m.fermer();
  }
}

/** Latence ajoutée par échange de modèle hors flux (TM-4). */
async function campagneModele(ctx) {
  const m = await monter({ repertoire: path.join(ctx.repertoire, "modele"), configuration: ctx.cheminConfiguration, options: { reponseOctets: 16384 } });
  try {
    const e = await m.demarrerEnregistreur();
    const C = conditionsCommunes(ctx, m);
    const requete = fabriqueEchangeModele({ jeton: m.jetonPasserelle, requeteOctets: 32768 });
    const cx = new Connexion(e.ports.modele);
    ctx.log(`modele : ${ctx.echauffement} échanges d'échauffement puis ${ctx.n} échanges hors flux, une connexion`);
    const mesures = await enSerie({ connexion: cx, requete: (n) => requete(n, false), valide: (r) => r.statut === 200, appels: ctx.n, echauffement: ctx.echauffement, progres: ctx.progres("modele") });
    cx.fermer();
    const four = (await requeteJson({ port: m.portFournisseur, chemin: "/mesures", delaiMs: 60000 })).corps.echanges;
    const parN = new Map(four.filter((x) => !x.flux).map((x) => [x.n, x]));
    const total = [];
    const ajoutee = [];
    for (const x of mesures) {
      const f = parN.get(x.n);
      if (!f) throw new ErreurMesure(`échange ${x.n} : aucun instant au fournisseur simulé`);
      total.push(ms(x.reponse_ns - x.envoi_ns));
      ajoutee.push(ms(x.reponse_ns - x.envoi_ns) - ms(BigInt(f.repondu_ns) - BigInt(f.recu_ns)));
    }
    const results = [nouvelleLigne(ctx, { name: "latence_echange_modele", test_id: "TM-4", unit: "ms", serie: ajoutee, connections: 1, conditions: [...C, "POST /v1/messages sans stream, corps de requête de 32 768 octets, réponse de 16 384 octets, fournisseur simulé de l'API Messages", "soustraction : (t_reponse_hote − t_envoi_hote) − (t_repondu_fournisseur − t_recu_fournisseur), instants du fournisseur simulé (le journal ne porte pas t_recu, t_envoi, t_reponse : E8-23) ; comprend les deux trajets sur la boucle locale vers le fournisseur", `temps total vu par l'hôte : ${JSON.stringify(agreger(total))} ms`] })];
    return { nom: "modele", results, notes: [`modele : ${mesures.length} échanges mesurés ; latence ajoutée ${JSON.stringify(agreger(ajoutee))} ms ; ${chargeTexte()} à la fin.`], methode: { warmup: ctx.echauffement, repetitions: ctx.n, clock: "monotone", pair_with_without: false } };
  } finally {
    await m.fermer();
  }
}

/**
 * Latence ajoutée à chaque octet d'un flux SSE (TM-2) : pour chaque octet du
 * corps, instant d'émission (écriture du fournisseur qui le contient) et
 * instant de réception (morceau de l'hôte qui le contient) ; latence de
 * l'octet = réception − émission ; `max` sur tous les octets de tous les flux.
 */
export function latencesOctets(ecritures, morceaux) {
  // Les deux découpages du même corps : la latence est constante entre deux frontières ; elle est évaluée à chaque frontière.
  const frontieres = new Set([...ecritures.map((w) => w.decalage), ...morceaux.map((c) => c.decalage)]);
  const emis = (o) => ecritures.find((w) => o >= w.decalage && o < w.decalage + w.octets);
  const recu = (o) => morceaux.find((c) => o >= c.decalage && o < c.decalage + c.octets);
  const valeurs = [];
  for (const o of frontieres) {
    const w = emis(o);
    const c = recu(o);
    if (!w || !c) continue;
    valeurs.push(ms(BigInt(c.recu_ns) - BigInt(w.emis_ns)));
  }
  return valeurs;
}

async function campagneSse(ctx) {
  const m = await monter({ repertoire: path.join(ctx.repertoire, "sse"), configuration: ctx.cheminConfiguration, options: { intervalleMs: 50, evenementsFlux: 6 } });
  try {
    const e = await m.demarrerEnregistreur();
    const C = conditionsCommunes(ctx, m);
    const requete = fabriqueEchangeModele({ jeton: m.jetonPasserelle, requeteOctets: 4096 });
    const k = ctx.connexionsSse;
    const connexions = Array.from({ length: k }, () => new Connexion(e.ports.modele));
    const part = (total, i) => Math.floor(total / k) + (i < total % k ? 1 : 0);
    ctx.log(`sse : ${ctx.echauffement} flux d'échauffement puis ${ctx.n} flux, ${k} connexions en parallèle, un événement toutes les 50 ms`);
    const parConnexion = await Promise.all(connexions.map((cx, i) => enSerie({ connexion: cx, requete: (n) => requete(n, true), valide: (r) => r.statut === 200, appels: part(ctx.n, i), echauffement: part(ctx.echauffement, i), premier: 1 + i * 1000000, options: { parMorceaux: true } })));
    connexions.forEach((c) => c.fermer());
    const mesures = parConnexion.flat();
    const four = (await requeteJson({ port: m.portFournisseur, chemin: "/mesures", delaiMs: 120000 })).corps.echanges;
    const parN = new Map(four.filter((x) => x.flux).map((x) => [x.n, x]));
    const maxParFlux = [];
    let maxOctet = -Infinity;
    let octets = 0;
    let premierOctet = [];
    for (const x of mesures) {
      const f = parN.get(x.n);
      if (!f) throw new ErreurMesure(`flux ${x.n} : aucun instant au fournisseur simulé`);
      if (f.ecritures.reduce((a, w) => a + w.octets, 0) !== x.octets) throw new ErreurMesure(`flux ${x.n} : ${x.octets} octets reçus pour ${f.ecritures.reduce((a, w) => a + w.octets, 0)} émis`);
      const v = latencesOctets(f.ecritures, x.morceaux);
      const mx = Math.max(...v);
      maxParFlux.push(mx);
      if (mx > maxOctet) maxOctet = mx;
      octets += x.octets;
      premierOctet.push(ms(BigInt(x.morceaux[0].recu_ns) - BigInt(f.ecritures[0].emis_ns)));
    }
    const results = [
      nouvelleLigne(ctx, { name: "latence_premier_octet_sse", test_id: "TM-2", unit: "ms", serie: maxParFlux, connections: k, conditions: [...C, "fournisseur simulé de l'API Messages en flux SSE, 6 événements par flux, un toutes les 50 ms (cadence tenue depuis le début du flux), même machine, même horloge", `${k} connexions d'hôte en parallèle, flux en série sur chacune ; ${mesures.length} flux, ${octets} octets en tout`, "latence d'un octet = instant de réception du morceau de l'hôte qui le contient − instant de l'écriture du fournisseur qui le contient ; max de la ligne = max sur tous les octets de tous les flux ; samples = max par flux (n = flux), percentiles sur ces maxima", `premier octet seul : ${JSON.stringify(agreger(premierOctet))} ms`] }),
    ];
    return { nom: "sse", results, notes: [`sse : ${mesures.length} flux, max sur tous les octets ${arrondi3(maxOctet)} ms, max par flux ${JSON.stringify(agreger(maxParFlux))} ms ; ${chargeTexte()} à la fin.`], methode: { warmup: ctx.echauffement, repetitions: ctx.n, clock: "monotone", pair_with_without: false } };
  } finally {
    await m.fermer();
  }
}

/** Reprise au démarrage pour un segment de 256 MiB (TM-8). */
async function campagneReprise(ctx) {
  const cible = ctx.segmentReprise;
  // Le segment courant doit atteindre la taille cible sans tourner : plafond de rotation au double.
  const m = await monter({ repertoire: path.join(ctx.repertoire, "reprise"), configuration: ctx.cheminConfiguration, options: { resultatOctets: 256, segmentOctets: Math.min(2 * cible, 1099511627776) } });
  try {
    let e = await m.demarrerEnregistreur();
    const C = conditionsCommunes(ctx, m);
    const segments = path.join(m.repertoireJournal, "segments");
    const dernier = () => {
      const l = fs.readdirSync(segments).filter((f) => f.endsWith(".ndjson")).sort();
      return l.length ? path.join(segments, l.at(-1)) : null;
    };
    const taille = () => (dernier() ? fs.statSync(dernier()).size : 0);
    // Remplissage : arguments constants (une seule pièce d'arguments), résultat de 256 octets qui varie (une pièce par appel), au plus vite sur 16 connexions.
    const requete = fabriqueAppelOutil({ jeton: m.jetonHote, argumentsOctets: 4096, varier: false });
    const connexions = Array.from({ length: 16 }, () => new Connexion(e.ports.mcp));
    ctx.log(`reprise : remplissage du segment courant jusqu'à ${cible} octets`);
    const t0 = Date.now();
    const appels = await auPlusVite({ connexions, requete, valide: reponseOutilReussie, continuer: () => taille() < cible });
    connexions.forEach((c) => c.fermer());
    await new Promise((r) => setTimeout(r, 500));
    const segmentOctets = taille();
    ctx.log(`reprise : ${appels} appels en ${Math.round((Date.now() - t0) / 1000)} s, segment de ${segmentOctets} octets ; ${3} échauffements puis ${10} redémarrages`);
    const journalSerie = [];
    const processusSerie = [];
    for (let i = 0; i < 13; i++) {
      await m.arreterEnregistreur();
      const decalage = fs.statSync(m.journalExploitation).size;
      e = await m.demarrerEnregistreur();
      const lignes = m.lignesExploitation(decalage);
      const bail = lignes.find((l) => l.event === "lease_acquired");
      const startup = lignes.find((l) => l.event === "startup");
      if (!bail || !startup) throw new ErreurMesure(`redémarrage ${i + 1} : lignes lease_acquired ou startup absentes du journal`);
      if (lignes.some((l) => l.event === "segment_truncated" || l.event === "segment_corrupted")) throw new ErreurMesure(`redémarrage ${i + 1} : segment tronqué ou corrompu à la relecture`);
      if (i >= 3) {
        journalSerie.push(Date.parse(startup.ts) - Date.parse(bail.ts));
        processusSerie.push(ms(process.hrtime.bigint() - e.lance_ns));
      }
    }
    const results = [
      nouvelleLigne(ctx, { name: "reprise", test_id: "TM-8", unit: "ms", serie: journalSerie, conditions: [...C, `segment de ${segmentOctets} octets (cible ${cible}), ${appels} appels de remplissage, storage.segment_max_bytes porté à ${m.config.storage.segment_max_bytes} pour que le segment ne tourne pas`, "durée = ts de la ligne startup − ts de la ligne lease_acquired du journal d'exploitation (horloge murale de l'enregistreur, milliseconde ; la relecture d'EX-12.10 commence après l'acquisition du bail et aucune ligne du journal ne marque son début propre) ; 3 échauffements puis 10 redémarrages par SIGTERM puis relance", "disque local : voir le type de disque de la machine"] }),
      nouvelleLigne(ctx, { name: "reprise_processus", test_id: "TM-8", unit: "ms", serie: processusSerie, principale: false, conditions: [...C, "durée du lancement du processus (spawn) à la santé ok puis aux deux frontaux à l'écoute, horloge monotone de l'hôte : relecture comprise, démarrage de Node.js et du cœur compris"] }),
    ];
    return { nom: "reprise", results, notes: [`reprise : segment de ${segmentOctets} octets ; journal ${JSON.stringify(agreger(journalSerie))} ms ; processus ${JSON.stringify(agreger(processusSerie))} ms ; ${chargeTexte()} à la fin.`], methode: { warmup: 3, repetitions: 10, clock: "murale", pair_with_without: false } };
  } finally {
    await m.fermer();
  }
}

// ------------------------------------------------------------------ exécution

export async function executer(argv, { log = (t) => process.stderr.write(`${t}\n`) } = {}) {
  let a;
  try {
    a = parseArgs({ args: argv, allowPositionals: false, options: { sortie: { type: "string" }, repertoire: { type: "string" }, configuration: { type: "string" }, campagnes: { type: "string" }, n: { type: "string" }, echauffement: { type: "string" }, cadence: { type: "string" }, "connexions-sse": { type: "string" }, "segment-reprise": { type: "string" }, "systeme-de-reference": { type: "boolean", default: false }, disque: { type: "string" }, etiquette: { type: "string" }, conserver: { type: "boolean", default: false }, help: { type: "boolean", short: "h", default: false } } }).values;
  } catch (e) {
    process.stderr.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  if (a.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (!a.sortie) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const entier = (v, defaut, min) => {
    if (v === undefined) return defaut;
    const x = Number(v);
    if (!Number.isInteger(x) || x < min) throw new RangeError(`entier ≥ ${min} attendu : ${v}`);
    return x;
  };
  let ctx;
  try {
    const campagnes = (a.campagnes ?? CAMPAGNES.join(",")).split(",").map((s) => s.trim()).filter(Boolean);
    for (const c of campagnes) if (!CAMPAGNES.includes(c)) throw new RangeError(`campagne inconnue : ${c} (${CAMPAGNES.join(", ")})`);
    if (a.disque !== undefined && !TYPES_DISQUE.includes(a.disque)) throw new RangeError(`--disque : ${TYPES_DISQUE.join(", ")}`);
    if (a.etiquette !== undefined && !/^[a-z0-9][a-z0-9-]*$/.test(a.etiquette)) throw new RangeError("--etiquette : lettres minuscules, chiffres, tirets");
    const cheminConfiguration = path.resolve(a.configuration ?? CONFIGURATION_PUBLIEE);
    const publiee = lireConfigurationPubliee(cheminConfiguration);
    const repertoireRapports = path.resolve(a.sortie);
    fs.mkdirSync(repertoireRapports, { recursive: true });
    const repertoire = fs.mkdtempSync(path.join(a.repertoire ? path.resolve(a.repertoire) : os.tmpdir(), "noortrace-mesure-ct2-"));
    const sys = systeme({ reference: a["systeme-de-reference"], repertoire, disque: a.disque ?? null, fsync: true });
    const compte = comptePourLesCibles(sys);
    ctx = {
      racine: fileURLToPath(new URL("../../", import.meta.url)), cheminConfiguration, publiee, repertoire, repertoireRapports, sys, compte, catalogue: lireJson(CATALOGUE), log,
      n: entier(a.n, 20000, 1), echauffement: entier(a.echauffement, 2000, 0), cadence: entier(a.cadence, 1000, 1), connexionsSse: entier(a["connexions-sse"], 16, 1), segmentReprise: entier(a["segment-reprise"], 268435456, 1048576),
      etiquette: a.etiquette ?? "ct2", conserver: a.conserver, resume: { rapports: [] },
      progres: (nom) => (i, total) => log(`${nom} : ${i} / ${total} appels, ${chargeTexte()}`),
    };
    log(`machine : ${sys.cpu}, ${sys.cores} processeurs, disque ${sys.disk.type}, référence ${sys.reference} → ${compte.compte ? "compte pour les cibles" : `ne compte pas (${compte.raison})`} ; ${chargeTexte()}`);
    const date = new Date().toISOString().slice(0, 10);
    const joueurs = { latence: () => campagneLatence(ctx), sse: () => campagneSse(ctx), debit: () => campagneDebit(ctx), modele: () => campagneModele(ctx), reprise: () => campagneReprise(ctx), observation: () => campagneLatence(ctx, { observation: true }) };
    for (const c of campagnes) {
      const debut = Date.now();
      ctx.campagneCourante = c;
      const r = await joueurs[c]();
      const notes = [...r.notes, `Commit éprouvé : ${arbreModifie(ctx.racine) ? "arbre de travail modifié par rapport au commit cité" : "arbre de travail propre"}.`];
      const rapport = rapportMesure({ sys: { ...ctx.sys, load_avg_1m: systeme({ reference: sys.reference, repertoire, disque: sys.disk.type }).load_avg_1m }, compte, methode: r.methode, configurationSha256: publiee.sha256, results: r.results, notes, racine: ctx.racine, catalogue: ctx.catalogue });
      const chemin = path.join(repertoireRapports, `rapport-${date}-${ctx.etiquette}-${r.nom}.json`);
      ecrireRapportValide(chemin, rapport);
      ctx.resume.rapports.push({ campagne: r.nom, fichier: chemin, duree_s: Math.round((Date.now() - debut) / 1000), lignes: r.results.map((l) => ({ name: l.name, test_id: l.test_id, value: l.value, p50: l.p50, p99: l.p99, max: l.max, mean: l.mean, met: l.met })) });
      log(`${r.nom} : rapport écrit et validé par scripts/tests/mesures.mjs : ${chemin} (${Math.round((Date.now() - debut) / 1000)} s)`);
      if (!ctx.conserver) fs.rmSync(path.join(repertoire, r.nom), { recursive: true, force: true });
    }
    ctx.resume.system = sys;
    ctx.resume.counts_for_targets = compte.compte;
    fs.writeFileSync(path.join(repertoireRapports, "resume.json"), JSON.stringify(ctx.resume, null, 2) + "\n");
    return 0;
  } catch (e) {
    if (e instanceof RangeError) {
      process.stderr.write(`${e.message}\n${USAGE}\n`);
      return 2;
    }
    process.stderr.write(`mesure impossible : ${e.message}\n`);
    return 1;
  } finally {
    if (ctx && !ctx.conserver) fs.rmSync(ctx.repertoire, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  process.exitCode = await executer(process.argv.slice(2));
}
