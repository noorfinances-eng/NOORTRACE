#!/usr/bin/env node
// Campagne de TM-30 (CT-9 §11.5 ; CT-8 EX-9.1, coefficient `b_ots`) : taille
// d'une preuve OpenTimestamps mise à niveau par deux calendriers réels après
// inclusion dans Bitcoin. Complément dû à l'étape 8 : la campagne de l'étape 5
// (scripts/e2e/mesure-ancrage.mjs) mesure la mise à niveau sur des calendriers
// factices à chaîne regtest et, avec le réseau public, des preuves en attente
// seulement.
//
// La campagne joint le réseau public. Elle n'est jamais lancée par un essai :
// `soumettre` et `mettre-a-niveau` refusent de partir sans `--reseau-public`,
// et les essais de cet outil lui injectent des calendriers locaux.
//
//   node scripts/mesures/tm-30-calendriers-publics.mjs soumettre --etat <rép> --reseau-public
//        [--preuves 10] [--calendrier <url> --calendrier <url>] [--delai-ms 15000]
//   node scripts/mesures/tm-30-calendriers-publics.mjs mettre-a-niveau --etat <rép> --reseau-public
//        [--liste-blanche <url> …] [--delai-ms 15000]
//   node scripts/mesures/tm-30-calendriers-publics.mjs etat --etat <rép>
//   node scripts/mesures/tm-30-calendriers-publics.mjs rapport --etat <rép> --sortie-rapport <fichier>
//        [--python-ots <python>]
//
// `soumettre` (une fois) : pour chaque preuve, une empreinte de 32 octets
// tirée au hasard, un nonce de 16 octets, l'engagement d'EX-6.2 de CT-5
// envoyé aux deux calendriers ; le fichier `.ots` en attente est écrit quand
// les deux ont répondu (`min_responses` = 2). Les calendriers ne voient que
// l'engagement : aucune donnée du dépôt ni de la machine ne leur est envoyée.
// `mettre-a-niveau` (à rejouer jusqu'à la fin, au plus une fois par minute,
// CT-5 EX-6.6) : `GET <calendrier>/timestamp/<engagement>` pour chaque
// attestation encore en attente ; un chemin reçu est fusionné et la preuve
// relue (O-1, O-3 de CT-6 §10) avant d'être écrite ; une preuve est dite mise
// à niveau par les deux calendriers quand elle ne porte plus d'attestation en
// attente. `etat` et `rapport` ne joignent aucun réseau.
//
// Défaut du composant d'ancrage constaté sur les calendriers publics (campagne
// du 2026-11-13) : `fusionnerOts` (paquets/ancrage/src/ots/format.mjs) exige
// un engagement de 32 octets, alors que l'engagement du nœud qui porte
// l'attestation en attente d'un calendrier réel est le message après les
// opérations d'agrégation du calendrier (44 octets observés : `prepend` de
// 4 octets, `sha256`, `append` de 8 octets), et `mettreANiveau` laisse
// échapper l'exception au lieu de rendre un refus. Tant qu'il n'est pas
// corrigé, `mettreANiveauCampagne` emploie d'abord le composant et, sur cette
// seule erreur (`ErreurOts` de code `engagement`), rejoue la mise à niveau par
// `mettreANiveauLocale` ci-dessous, qui suit EX-6.6 avec les primitives du
// composant (lecture, fusion de nœud, vérification O-1 et O-3) sans la borne
// fautive ; le rapport le dit dans `conditions`. Un essai qui reproduit le
// défaut est rendu avec la campagne.
//
// Ce que la campagne ne fait pas : elle ne lit aucun en-tête Bitcoin (O-4 et
// O-5 de CT-6 §10 restent `non_execute` : la source d'en-têtes n'est pas dans
// le périmètre de la campagne) ; la hauteur attestée est donc celle que les
// calendriers déclarent, non rapprochée de la chaîne.
//
// L'état de la campagne vit sous `--etat`, hors du dépôt : `etat.json`,
// `preuve-<kk>.en-attente.ots`, `preuve-<kk>.ots` (dernière version),
// `journal.ndjson` (une ligne par requête). Codes : 0 fait ; 1 refus ou
// campagne inachevée pour `rapport` ; 2 usage.

import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { soumettre, mettreANiveau, transportHttps, lireOts, ecrireOts, lireTimestamp, attestationsEnAttente, hauteursAttestees, verifierOts, admissionApresFusion, relireReponseCalendrier, ACCEPT_OTS, ErreurOts, STATUT } from "@noortrace/ancrage/ots";
import { systeme, comptePourLesCibles, ligne, rapportMesure, ecrireRapportValide, chargeTexte, arbreModifie, sha256Hex } from "./commun.mjs";

/** Les deux premiers agrégateurs publics par défaut de CT-5 EX-6.2 (R1-F56). */
export const CALENDRIERS = Object.freeze(["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]);
/** Liste blanche de mise à niveau par défaut de CT-5 §4 (`opentimestamps.upgrade.whitelist`). */
export const LISTE_BLANCHE = Object.freeze(["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org", "https://finney.calendar.eternitywall.com", "https://ots.btc.catallaxy.com"]);
const USAGE = "usage : node scripts/mesures/tm-30-calendriers-publics.mjs <soumettre|mettre-a-niveau|etat|rapport> --etat <répertoire> [--reseau-public] [--preuves <n>] [--calendrier <url>]… [--liste-blanche <url>]… [--delai-ms <ms>] [--sortie-rapport <fichier>] [--python-ots <python>]";
const horlogeReelle = { murale: () => Date.now(), monotone: () => performance.now() };
const hex = (o) => Buffer.from(o).toString("hex");
const nomPreuve = (k) => `preuve-${String(k).padStart(2, "0")}`;
const iso = (ms) => new Date(ms).toISOString();

export class ErreurCampagne extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ErreurCampagne";
    this.code = code;
  }
}

const cheminEtat = (rep) => path.join(rep, "etat.json");
export const lireEtat = (rep) => JSON.parse(fs.readFileSync(cheminEtat(rep), "utf8"));
function ecrireEtat(rep, etat) {
  const tmp = `${cheminEtat(rep)}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(etat, null, 2) + "\n");
  fs.renameSync(tmp, cheminEtat(rep));
}
const journaliser = (rep, o) => fs.appendFileSync(path.join(rep, "journal.ndjson"), JSON.stringify(o) + "\n");

/** Attestations d'une preuve : URI encore en attente et hauteurs Bitcoin attestées. */
export function decrirePreuve(octets) {
  const lu = lireOts(octets);
  const attentes = attestationsEnAttente(lu.arbre, lu.empreinte).map((a) => a.attestation.uri);
  const hauteurs = [];
  const parcourir = (noeud) => {
    for (const a of noeud.attestations) if (a.genre === "bitcoin") hauteurs.push(a.hauteur);
    for (const o of noeud.operations) parcourir(o.noeud);
  };
  parcourir(lu.arbre);
  return { octets: octets.length, en_attente: attentes.sort(), hauteurs_bitcoin: hauteurs.sort((a, b) => a - b), etat: hauteursAttestees(lu.arbre) === null ? "en_attente" : attentes.length === 0 ? "mise_a_niveau_par_tous" : "mise_a_niveau_partielle" };
}

/**
 * Soumission de la campagne : `n` engagements aux deux calendriers. Refuse
 * de repartir sur un état existant (les engagements d'une campagne ne se
 * retirent pas). `aleatoire` et `horloge` sont injectables pour les essais.
 */
export async function soumettreCampagne({ repertoire, calendriers = CALENDRIERS, n = 10, delaiMs = 15000, transport, horloge = horlogeReelle, aleatoire = (k) => new Uint8Array(randomBytes(k)), log = () => {} }) {
  if (!Array.isArray(calendriers) || calendriers.length !== 2 || calendriers[0] === calendriers[1]) throw new ErreurCampagne("calendriers", "deux calendriers distincts attendus (TM-30 : preuve mise à niveau par deux calendriers)");
  if (!Number.isInteger(n) || n < 1 || n > 100) throw new ErreurCampagne("preuves", "nombre de preuves hors de [1, 100]");
  fs.mkdirSync(repertoire, { recursive: true });
  if (fs.existsSync(cheminEtat(repertoire))) throw new ErreurCampagne("etat_existant", `une campagne existe déjà sous ${repertoire} : la soumission ne se rejoue pas, employer mettre-a-niveau`);
  const etat = { version: 0, kind: "campagne-tm-30", calendriers: [...calendriers], soumission_debut: iso(horloge.murale()), soumission_fin: null, charge_soumission: chargeTexte(), preuves: [], mises_a_niveau: [] };
  for (let k = 1; k <= n; k++) {
    const empreinte = aleatoire(32);
    const nonce = aleatoire(16);
    const r = await soumettre({ empreinte, nonce, calendriers, minReponses: 2, delaiMs, transport, horloge });
    for (const x of r.reponses) journaliser(repertoire, { instant: iso(horloge.murale()), action: "soumettre", preuve: k, calendrier: x.calendrier, status: x.status, erreur: x.erreur, octets: x.octets ? x.octets.length : null, duree_ms: Math.round(x.dureeMs) });
    const p = { k, empreinte: hex(empreinte), nonce: hex(nonce), engagement: r.engagement, soumis_a: iso(r.instant), ecrite: r.ecrire, reponses: r.reponses.map((x) => ({ calendrier: x.calendrier, status: x.status, erreur: x.erreur, attestations: x.attestations })), octets_en_attente: null, en_attente: [], octets: null, etat: "non_soumise", hauteurs_bitcoin: [], premiere_attestation_a: null, complete_a: null };
    if (r.ecrire) {
      fs.writeFileSync(path.join(repertoire, `${nomPreuve(k)}.en-attente.ots`), r.octets, { flag: "wx" });
      fs.writeFileSync(path.join(repertoire, `${nomPreuve(k)}.ots`), r.octets, { flag: "wx" });
      const d = decrirePreuve(r.octets);
      Object.assign(p, { octets_en_attente: d.octets, octets: d.octets, en_attente: d.en_attente, etat: d.etat });
    }
    etat.preuves.push(p);
    ecrireEtat(repertoire, etat);
    log(`preuve ${k} : ${r.ecrire ? `${p.octets_en_attente} octets en attente auprès de ${p.en_attente.join(", ")}` : `non écrite (${r.reponses.map((x) => `${x.calendrier} : ${x.erreur ?? x.status}`).join(" ; ")})`}`);
  }
  etat.soumission_fin = iso(horloge.murale());
  ecrireEtat(repertoire, etat);
  return etat;
}

/**
 * Mise à niveau d'EX-6.6 écrite avec les primitives du composant, sans la
 * borne de 32 octets de `fusionnerOts` (voir l'en-tête) : pour chaque
 * attestation en attente dont l'URI est dans la liste blanche,
 * `GET <uri>/timestamp/<engagement du nœud>` ; 200 relu par
 * `relireReponseCalendrier`, fusionné au nœud, puis la preuve est vérifiée
 * (O-1, O-3 ; O-4 et O-5 non exécutées sans en-têtes) avant d'être rendue.
 * Même forme de résultat que `mettreANiveau`.
 */
export async function mettreANiveauLocale({ preuve, listeBlanche, transport, horloge, delaiMs }) {
  const blanche = new Set(listeBlanche.map((u) => u.replace(/\/+$/, "")));
  const lu = lireOts(preuve);
  const instant = horloge.murale();
  const etatAvant = hauteursAttestees(lu.arbre) === null ? "en_attente" : "complete";
  const copie = lu.arbre.copier();
  const attentes = attestationsEnAttente(copie, lu.empreinte);
  const refus = [];
  const reponses = [];
  let fusions = 0;
  for (const { noeud, message, attestation } of attentes) {
    const uri = attestation.uri.replace(/\/+$/, "");
    if (!blanche.has(uri)) {
      refus.push({ uri: attestation.uri, motif: "hors_liste_blanche", detail: "attestation conservée telle quelle" });
      continue;
    }
    const eHex = Buffer.from(message).toString("hex");
    const depart = horloge.monotone();
    const ligne = { uri: attestation.uri, engagement: `0x${eHex}`, status: null, resultat: null, dureeMs: 0 };
    try {
      const r = await transport.get(`${uri}/timestamp/${eHex}`, { Accept: ACCEPT_OTS }, delaiMs);
      ligne.dureeMs = horloge.monotone() - depart;
      ligne.status = r.status;
      if (r.status === 200) {
        const relue = relireReponseCalendrier(r.corps, message);
        if (relue.erreur !== null) {
          ligne.resultat = relue.erreur;
          refus.push({ uri: attestation.uri, motif: relue.erreur, detail: "chemin reçu refusé par le lecteur" });
        } else {
          noeud.retirerAttestations((a) => a.genre === "en_attente" && a.uri === attestation.uri);
          noeud.fusionner(lireTimestamp(r.corps));
          ligne.resultat = "fusionne";
          fusions += 1;
        }
      } else if (r.status === 404) {
        const texte = new TextDecoder("utf-8", { fatal: false }).decode((r.corps ?? new Uint8Array(0)).subarray(0, 512));
        ligne.resultat = texte.includes("Pending confirmation") || texte.includes("Timestamped by transaction") ? "en_attente" : texte.includes("Not found") ? "non_trouve" : "http_404";
      } else ligne.resultat = `http_${r.status}`;
    } catch (err) {
      ligne.dureeMs = horloge.monotone() - depart;
      ligne.resultat = `transport_${err?.code ?? "erreur"}`;
    }
    reponses.push(ligne);
  }
  if (fusions === 0) return { nouvelle: null, etat: etatAvant, refus, reponses, hauteurs: null, verification: null, instant, locale: true };
  const courante = ecrireOts({ empreinte: lu.empreinte, arbre: copie });
  const verification = verifierOts({ octets: courante, empreinteAttendue: lu.empreinte, entetes: null, reseau: null });
  const admission = admissionApresFusion(verification);
  if (!admission.admise) {
    refus.push({ uri: null, motif: `verification_${admission.motifs.join("_")}`, detail: admission.motifs.map((m) => verification.details[m]).join(" ; ") });
    return { nouvelle: null, etat: etatAvant, refus, reponses, hauteurs: null, verification, instant, locale: true };
  }
  const h = hauteursAttestees(copie);
  return { nouvelle: courante, etat: verification.etat, refus, reponses, hauteurs: h === null ? null : [h.min, h.max], verification, instant, locale: true };
}

/**
 * Une passe de mise à niveau sur toutes les preuves encore en attente. La
 * cadence est tenue ici : une passe à moins de 60 s de la précédente est
 * refusée (CT-5 EX-6.6 : jamais moins de 60 s).
 */
export async function mettreANiveauCampagne({ repertoire, listeBlanche = LISTE_BLANCHE, delaiMs = 15000, transport, horloge = horlogeReelle, log = () => {} }) {
  const etat = lireEtat(repertoire);
  const maintenant = horloge.murale();
  const derniere = etat.mises_a_niveau.at(-1);
  if (derniere && maintenant - Date.parse(derniere.instant) < 60000) throw new ErreurCampagne("cadence", "passe précédente à moins de 60 s (CT-5 EX-6.6)");
  const passe = { instant: iso(maintenant), charge: chargeTexte(), requetes: 0, fusions: 0, fusions_locales: 0, refus: [] };
  for (const p of etat.preuves) {
    if (!p.ecrite || p.etat === "mise_a_niveau_par_tous") continue;
    const fichier = path.join(repertoire, `${nomPreuve(p.k)}.ots`);
    const preuve = new Uint8Array(fs.readFileSync(fichier));
    let m;
    try {
      m = await mettreANiveau({ preuve, listeBlanche, transport, horloge, delaiMs, entetes: null, reseau: null });
    } catch (e) {
      if (!(e instanceof ErreurOts) || e.code !== "engagement") throw e;
      // Défaut de fusionnerOts (en-tête) : la mise à niveau est rejouée localement ; la ou les requêtes déjà faites par le composant sont consignées comme perdues.
      journaliser(repertoire, { instant: iso(horloge.murale()), action: "mettre-a-niveau", preuve: p.k, calendrier: null, status: null, resultat: "composant_erreur_engagement", detail: e.message });
      m = await mettreANiveauLocale({ preuve, listeBlanche, transport, horloge, delaiMs });
      if (m.nouvelle) passe.fusions_locales += m.reponses.filter((x) => x.resultat === "fusionne").length;
    }
    passe.requetes += m.reponses.length;
    for (const x of m.reponses) journaliser(repertoire, { instant: iso(horloge.murale()), action: "mettre-a-niveau", preuve: p.k, calendrier: x.uri, status: x.status, resultat: x.resultat, duree_ms: Math.round(x.dureeMs), fusion: m.locale ? "locale" : "composant" });
    for (const x of m.refus) passe.refus.push({ preuve: p.k, ...x });
    if (m.nouvelle) {
      // Une version n'est jamais réécrite en place : la nouvelle est posée à côté puis renommée ; la version en attente d'origine reste.
      fs.writeFileSync(`${fichier}.tmp`, m.nouvelle);
      fs.renameSync(`${fichier}.tmp`, fichier);
      const d = decrirePreuve(m.nouvelle);
      passe.fusions += m.reponses.filter((x) => x.resultat === "fusionne").length;
      if (p.premiere_attestation_a === null && d.hauteurs_bitcoin.length) p.premiere_attestation_a = iso(horloge.murale());
      if (d.etat === "mise_a_niveau_par_tous") p.complete_a = iso(horloge.murale());
      if (m.locale) p.fusion_locale = (p.fusion_locale ?? 0) + m.reponses.filter((x) => x.resultat === "fusionne").length;
      Object.assign(p, { octets: d.octets, en_attente: d.en_attente, etat: d.etat, hauteurs_bitcoin: d.hauteurs_bitcoin });
      log(`preuve ${p.k} : ${d.octets} octets, ${d.etat}, hauteurs ${d.hauteurs_bitcoin.join(", ")}`);
    } else {
      log(`preuve ${p.k} : inchangée (${m.reponses.map((x) => `${new URL(x.uri).host} ${x.resultat}`).join(" ; ") || m.refus.map((x) => x.motif).join(" ; ")})`);
    }
  }
  etat.mises_a_niveau.push(passe);
  ecrireEtat(repertoire, etat);
  return { etat, passe, reste: etat.preuves.filter((p) => p.ecrite && p.etat !== "mise_a_niveau_par_tous").length };
}

/** Relecture hors ligne de chaque preuve (O-1 à O-3 et O-7 de CT-6 §10, sans en-têtes) et accord de l'état avec les fichiers. */
export function relireCampagne(repertoire) {
  const etat = lireEtat(repertoire);
  return etat.preuves.filter((p) => p.ecrite).map((p) => {
    const octets = new Uint8Array(fs.readFileSync(path.join(repertoire, `${nomPreuve(p.k)}.ots`)));
    const v = verifierOts({ octets, empreinteAttendue: "0x" + p.empreinte, entetes: null, reseau: null });
    const d = decrirePreuve(octets);
    return { k: p.k, ...d, sha256: sha256Hex(octets), checks: v.checks, accord: d.octets === p.octets && d.etat === p.etat };
  });
}

/** Confrontation facultative : `python-opentimestamps` relit chaque preuve et la resérialise à l'identique (CT-5 EX-6.3). */
export function confronterPython(repertoire, python) {
  const programme = "import sys\nfrom opentimestamps.core.timestamp import DetachedTimestampFile\nfrom opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext\nfor f in sys.argv[1:]:\n    b = open(f, 'rb').read()\n    d = DetachedTimestampFile.deserialize(BytesDeserializationContext(b))\n    c = BytesSerializationContext()\n    d.serialize(c)\n    print(f.rsplit('/', 1)[-1], 'identique' if c.getbytes() == b else 'different')\n";
  const fichiers = lireEtat(repertoire).preuves.filter((p) => p.ecrite).map((p) => path.join(repertoire, `${nomPreuve(p.k)}.ots`));
  const r = spawnSync(python, ["-I", "-c", programme, ...fichiers], { encoding: "utf8" });
  if (r.status !== 0) return { joue: false, detail: (r.stderr || "").trim().split("\n").pop() ?? "échec" };
  const lignes = r.stdout.trim().split("\n");
  return { joue: true, identiques: lignes.filter((l) => l.endsWith(" identique")).length, total: fichiers.length };
}

/**
 * Rapport de mesure de la campagne (`$defs/rapport_mesure`). La ligne
 * principale `b_ots_mis_a_niveau` n'est écrite que sur des preuves mises à
 * niveau par les deux calendriers ; tant qu'aucune ne l'est, le rapport ne
 * peut pas être écrit (une ligne de TM-30 sans sa ligne principale est
 * refusée par l'outil de CT-9) et la fonction lève `campagne_inachevee`.
 */
export function rapportCampagne({ repertoire, sortieRapport, python = null, reference = false, maintenant = new Date(), log = () => {} }) {
  const etat = lireEtat(repertoire);
  const relues = relireCampagne(repertoire);
  const defauts = relues.filter((r) => !r.accord || r.checks["O-1"] !== "reussi" || r.checks["O-2"] !== "reussi" || r.checks["O-3"] !== "reussi");
  if (defauts.length) throw new ErreurCampagne("preuve_refusee", `preuve(s) ${defauts.map((r) => r.k).join(", ")} : fichier en désaccord avec l'état ou relecture O-1 à O-3 en échec`);
  const completes = relues.filter((r) => r.etat === "mise_a_niveau_par_tous");
  if (completes.length === 0) throw new ErreurCampagne("campagne_inachevee", `aucune des ${relues.length} preuves n'est mise à niveau par les deux calendriers : rejouer mettre-a-niveau plus tard`);
  const sys = systeme({ reference, repertoire, fsync: null });
  const compte = comptePourLesCibles(sys);
  const parK = new Map(etat.preuves.map((p) => [p.k, p]));
  const C = [
    `campagne publique nommée : ${etat.calendriers.join(" et ")} (soumission), mise à niveau auprès des calendriers que leurs réponses désignent ; sans compte ni dépense`,
    `soumission du ${etat.soumission_debut} au ${etat.soumission_fin} ; ${etat.mises_a_niveau.length} passe(s) de mise à niveau, la dernière le ${etat.mises_a_niveau.at(-1)?.instant ?? "-"}`,
    "aucun en-tête Bitcoin lu : O-4 et O-5 de CT-6 §10 non exécutées ; les hauteurs sont celles que les calendriers déclarent",
    "octets du fichier .ots entier (en-tête, empreinte, nonce, opérations et attestations)",
  ];
  const locales = etat.preuves.reduce((a, p) => a + (p.fusion_locale ?? 0), 0);
  if (locales > 0) C.push(`${locales} chemin(s) fusionné(s) par l'outil de campagne (mettreANiveauLocale) et non par mettreANiveau du composant, qui échoue sur un engagement de 44 octets (défaut de fusionnerOts signalé) ; même lecture, même fusion de nœud, même vérification O-1 et O-3`);
  const confrontation = python ? confronterPython(repertoire, python) : null;
  if (confrontation) C.push(confrontation.joue ? `python-opentimestamps relit et resérialise à l'identique ${confrontation.identiques} preuve(s) sur ${confrontation.total}` : `confrontation par python-opentimestamps non jouée (${confrontation.detail})`);
  const results = [
    ligne({ name: "b_ots_mis_a_niveau", test_id: "TM-30", unit: "octets", serie: completes.map((r) => r.octets), percentiles: false, compte, conditions: [...C, `${completes.length} preuve(s) sur ${relues.length} sans attestation en attente restante`, ...completes.map((r) => `preuve ${r.k} : ${r.octets} octets (${parK.get(r.k).octets_en_attente} en attente), hauteurs Bitcoin déclarées ${r.hauteurs_bitcoin.join(" et ")}, complète le ${parK.get(r.k).complete_a}, SHA-256 ${r.sha256}`)] }),
    ligne({ name: "b_ots_en_attente_public", test_id: "TM-30", unit: "octets", serie: relues.map((r) => parK.get(r.k).octets_en_attente), percentiles: false, principale: false, compte, conditions: [...C, "tailles des mêmes preuves à la soumission, deux attestations en attente"] }),
  ];
  const partielles = relues.filter((r) => r.etat === "mise_a_niveau_partielle");
  const notes = [
    `TM-30 : ${completes.length} preuve(s) mise(s) à niveau par les deux calendriers, ${partielles.length} par un seul, ${relues.length - completes.length - partielles.length} encore en attente, ${etat.preuves.length - relues.length} non écrite(s) à la soumission.`,
    `Hors du système de référence : la ligne n'a pas de cible et ne dépend pas de la machine ; ${chargeTexte()} à l'écriture du rapport.`,
  ];
  if (arbreModifie()) notes.push("L'arbre de travail différait du commit cité à l'écriture du rapport.");
  const r = rapportMesure({ sys, compte, methode: { warmup: 0, repetitions: completes.length, clock: "sans_objet", pair_with_without: false }, results, notes, maintenant });
  ecrireRapportValide(sortieRapport, r);
  log(`rapport écrit et validé : ${sortieRapport}`);
  return r;
}

export async function executer(argv, { transport = null, log = (m) => process.stdout.write(`${m}\n`) } = {}) {
  let a;
  try {
    a = parseArgs({ args: argv, allowPositionals: true, options: { etat: { type: "string" }, "reseau-public": { type: "boolean", default: false }, preuves: { type: "string" }, calendrier: { type: "string", multiple: true }, "liste-blanche": { type: "string", multiple: true }, "delai-ms": { type: "string" }, "sortie-rapport": { type: "string" }, "python-ots": { type: "string" }, help: { type: "boolean", short: "h", default: false } } });
  } catch (e) {
    process.stderr.write(`${e.message}\n${USAGE}\n`);
    return 2;
  }
  const o = a.values;
  const commande = a.positionals[0];
  if (o.help) {
    log(USAGE);
    return 0;
  }
  if (a.positionals.length !== 1 || !["soumettre", "mettre-a-niveau", "etat", "rapport"].includes(commande) || !o.etat) {
    process.stderr.write(`${USAGE}\n`);
    return 2;
  }
  const delaiMs = o["delai-ms"] === undefined ? 15000 : Number(o["delai-ms"]);
  if (!Number.isInteger(delaiMs) || delaiMs < 1) {
    process.stderr.write(`--delai-ms : entier positif attendu\n${USAGE}\n`);
    return 2;
  }
  const repertoire = path.resolve(o.etat);
  try {
    if (commande === "soumettre" || commande === "mettre-a-niveau") {
      if (!transport && !o["reseau-public"]) {
        process.stderr.write(`${commande} joint le réseau public : option --reseau-public exigée (campagne nommée, jamais dans un essai)\n`);
        return 2;
      }
      const t = transport ?? transportHttps();
      if (commande === "soumettre") {
        const n = o.preuves === undefined ? 10 : Number(o.preuves);
        const etat = await soumettreCampagne({ repertoire, calendriers: o.calendrier ?? [...CALENDRIERS], n, delaiMs, transport: t, log });
        const ecrites = etat.preuves.filter((p) => p.ecrite).length;
        log(`soumission du ${etat.soumission_debut} au ${etat.soumission_fin} : ${ecrites} preuve(s) écrite(s) sur ${etat.preuves.length}`);
        return ecrites === etat.preuves.length ? 0 : 1;
      }
      const r = await mettreANiveauCampagne({ repertoire, listeBlanche: o["liste-blanche"] ?? [...LISTE_BLANCHE], delaiMs, transport: t, log });
      log(`passe du ${r.passe.instant} : ${r.passe.requetes} requête(s), ${r.passe.fusions} chemin(s) fusionné(s), ${r.reste} preuve(s) encore à mettre à niveau`);
      return 0;
    }
    if (commande === "etat") {
      const etat = lireEtat(repertoire);
      for (const r of relireCampagne(repertoire)) log(`preuve ${r.k} : ${r.octets} octets, ${r.etat}, en attente [${r.en_attente.join(", ")}], hauteurs [${r.hauteurs_bitcoin.join(", ")}], O-1 ${r.checks["O-1"]}, O-2 ${r.checks["O-2"]}, O-3 ${r.checks["O-3"]}, O-7 ${r.checks["O-7"]}${r.accord ? "" : " ; DÉSACCORD avec etat.json"}`);
      log(`soumission du ${etat.soumission_debut} au ${etat.soumission_fin} ; ${etat.mises_a_niveau.length} passe(s) de mise à niveau`);
      return 0;
    }
    if (!o["sortie-rapport"]) {
      process.stderr.write(`rapport : --sortie-rapport exigé\n${USAGE}\n`);
      return 2;
    }
    rapportCampagne({ repertoire, sortieRapport: path.resolve(o["sortie-rapport"]), python: o["python-ots"] ?? null, log });
    return 0;
  } catch (e) {
    if (e instanceof ErreurCampagne) {
      process.stderr.write(`${e.code} : ${e.message}\n`);
      return 1;
    }
    throw e;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(path.resolve(process.argv[1]))) {
  process.exitCode = await executer(process.argv.slice(2));
}
