#!/usr/bin/env node
// Générateur des vecteurs de CT-7 (spec/CT-7-securite-et-conformite.md,
// annexe A) : spec/vecteurs/ct-7/.
//
//   node scripts/vecteurs/generer-ct7.mjs [--sortie <répertoire ct-7>]
//   npm run vecteurs:ct7
//
// Il écrit, depuis le texte de CT-7 et les vecteurs de CT-1, CT-3, CT-4 et
// CT-6 (lus, jamais réécrits) :
//
//   menaces.json              le modèle de menace (3.8), tiré des tables 3.2
//                             à 3.5 du texte (EX-A.4) ; refusé si RV-2, RV-3,
//                             RV-4, RV-6 ou RV-8 échoue (EX-A.5) ;
//   ceremonies/<cas>/         procès-verbaux valides et invalides et leur
//                             attendu.json (A.4) ; chaque cas est contrôlé :
//                             seules les vérifications attendues échouent ;
//   cles-de-test.json         clés publiques de test des vecteurs (EX-A.7) ;
//   attestations/             constantes, exemple de 7.1 et 7.2, cas hors
//                             dossier (attestations.json) et signatures
//                             croisées (croises.json) (A.6) ;
//   matrice-conformite.json   la matrice (section 8), depuis
//                             scripts/conformite/matrice-donnees.mjs ;
//                             refusée si une MX- échoue (A.8) ;
//   matrice/invalides/        la matrice altérée en un point, et attendu.json ;
//   acceptation-*/            consignes des trois épreuves à l'aveugle, et
//                             leurs grilles à part, hors du répertoire remis
//                             (section 9, A.15) ;
//   INDEX.md                  chaque cas et son attendu ; la consolidation.
//
// Les sous-répertoires confrontation/ et verificateur-independant/ ne sont
// jamais écrits ni effacés. Deux exécutions donnent des fichiers identiques
// octet pour octet (EX-A.2). Ce générateur ne touche aucun fichier de ct-1 à
// ct-6 (EX-A.3).

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import * as J from "../lib/journal.mjs";
import * as C from "../lib/console.mjs";
import * as S from "../lib/securite.mjs";
import * as R from "../conformite/verifier-renvois.mjs";
import { MATRICE } from "../conformite/matrice-donnees.mjs";
import * as A from "./ct7/attestation.mjs";
import * as K from "./ct7/ceremonies.mjs";

const RACINE_PROJET = fileURLToPath(new URL("../../", import.meta.url));
const SPEC = path.join(RACINE_PROJET, "spec");
const VECTEURS = path.join(SPEC, "vecteurs");
export const REPERTOIRE_CT7 = path.join(VECTEURS, "ct-7");
/** Entrées de ct-7 que ce générateur écrit (et efface avant d'écrire). */
const ENTREES_GENEREES = ["menaces.json", "cles-de-test.json", "matrice-conformite.json", "INDEX.md", "ceremonies", "attestations", "matrice", "acceptation-securite", "acceptation-securite-attendu.json", "acceptation-conformite", "acceptation-conformite-attendu.json", "acceptation-attestation", "acceptation-attestation-attendu.json"];
/** Vérifications du vérificateur de renvois qui interdisent d'écrire menaces.json (EX-A.5). */
const RV_BLOQUANTES = ["RV-2", "RV-3", "RV-4", "RV-6", "RV-8"];

class ErreurGeneration extends Error {}
const json = (v) => JSON.stringify(v, null, 2) + "\n";
/**
 * Plie un paragraphe à 80 colonnes (espaces seulement) ; `tete` précède la
 * première ligne (puce, numéro), `suite` les suivantes.
 */
function plier(texte, tete = "", suite = " ".repeat(tete.length)) {
  const lignes = [];
  let cur = tete;
  let vide = true;
  for (const mot of texte.split(" ")) {
    if (!vide && cur.length + 1 + mot.length > 80) {
      lignes.push(cur);
      cur = suite + mot;
    } else {
      cur += (vide ? "" : " ") + mot;
    }
    vide = false;
  }
  lignes.push(cur);
  return lignes.join("\n");
}
/** Plie à 80 colonnes les lignes de prose d'un texte Markdown (ni tables, ni titres, ni code). */
function plierMarkdown(lignes) {
  let code = false;
  return lignes
    .map((l) => {
      if (l.startsWith("```")) code = !code;
      if (code || l.startsWith("```") || l.startsWith("|") || l.startsWith("#") || l.length <= 80) return l;
      const puce = /^(- |[0-9]+\. |[A-Z][0-9]+\. )/.exec(l);
      return puce ? plier(l.slice(puce[1].length), puce[1]) : plier(l);
    })
    .join("\n");
}
const elements = (cellule) => cellule.split(" ; ").map((x) => x.trim()).filter(Boolean);

// ---------------------------------------------------------------------------
// Modèle de menace
// ---------------------------------------------------------------------------

function menaces(specs, readme, cles) {
  const doc = S.construireMenaces(S.lireTablesCt7(specs["CT-7"]), specs);
  const erreurs = R.verifierRV({ specs, readme, menaces: doc, cles, clesRecalculees: cles }).filter((e) => RV_BLOQUANTES.includes(e.id));
  if (erreurs.length) throw new ErreurGeneration(`menaces.json refusé (EX-A.5) :\n${erreurs.map((e) => `  ${e.id} : ${e.message}`).join("\n")}`);
  return doc;
}

// ---------------------------------------------------------------------------
// Procès-verbaux de cérémonie
// ---------------------------------------------------------------------------

function ceremonies(specs) {
  const schema = S.schemaCeremonie();
  const exemple = /<!-- schema: ceremonie-cles -->\n```json\n([\s\S]*?)\n```/.exec(specs["CT-7"]);
  const out = [];
  for (const c of K.casCeremonies()) {
    const r = S.verifierCeremonie(c.octets, { schema });
    if (JSON.stringify(r.failed) !== JSON.stringify(c.echecs)) throw new ErreurGeneration(`ceremonies/${c.nom} : en échec ${r.failed.join(", ") || "aucune"}, attendu ${c.echecs.join(", ") || "aucune"}`);
    const attendu = S.attenduCeremonie(r);
    const e = J.validerSchema(attendu, schema, { fragment: "#/$defs/attendu" });
    if (e.length) throw new ErreurGeneration(`ceremonies/${c.nom}/attendu.json : ${e[0].message}`);
    if (c.nom === "valide-creation-enregistreur" && (!exemple || c.octets !== exemple[1] + "\n")) throw new ErreurGeneration("valide-creation-enregistreur : différent de l'exemple annoté de CT-7 §5.10");
    out.push({ ...c, attendu });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Attestations hors dossier et signatures croisées
// ---------------------------------------------------------------------------

function attestations(cas) {
  const schemas = S.schemasAttestation();
  const P = A.attestationExemple();
  const D_P = S.condenseAttestation(P);
  const signee = A.signer(P);
  const constantes = {
    version: 0,
    prefix_hex: S.PREFIXE_ATTESTATION_HEX,
    prefix_utf8: S.PREFIXE_ATTESTATION,
    mnemonic: A.MNEMONIQUE_HARDHAT,
    accounts: [1, 2, 3, 4].map((i) => ({ index: i, derivation_path: A.CHEMIN_HARDHAT(i), address: A.adresse(i) })),
    org: { slug: A.ORG_SLUG, org_id: A.ORG_ID, derivation: "keccak256(UTF-8(slug))" },
    journals: [
      { name: "journal-principal", journal_id: A.JOURNAL_PRINCIPAL, derivation: "keccak256(UTF-8(name))" },
      { name: "journal-sinistres", journal_id: A.JOURNAL_SINISTRES, derivation: "keccak256(UTF-8(name))" },
    ],
    rules_sha256: { label: A.ETIQUETTE_REGLES_SORTIE, sha256: A.RULES_SHA256, derivation: "SHA-256(UTF-8(label))" },
    approver_set: A.jeuExemple(),
  };
  const exemple = {
    "attestation.json": json(P),
    "jcs.txt": J.canonicaliserJCS(P),
    "condense.json": json({ jcs_length: J.octetsJCS(P).length, digest: D_P, message: S.messageAttestation(D_P), signatures: signee.signatures }),
    "attestation-signee.json": json(signee),
    "jeu.json": json(A.jeuExemple()),
  };
  const fichier = {
    version: 0,
    family: "attestations",
    prefix_hex: S.PREFIXE_ATTESTATION_HEX,
    cases: A.casAttestations().map((c) => {
      const r = S.verifierAttestation(c.signed, c.approver_set, { schemas });
      return { name: c.name, description: c.description, input: { signed: c.signed, approver_set: c.approver_set }, expected: { digest: r.digest, recovered: r.recovered, checks: r.checks, retained: r.retained } };
    }),
  };
  const e = J.validerSchema(fichier, schemas[S.ID_SCHEMA_ATTESTATION_PERIMETRE], { registre: schemas, fragment: "#/$defs/fichier_vecteurs" });
  if (e.length) throw new ErreurGeneration(`attestations.json : ${e[0].chemin} ${e[0].message}`);
  const cr = croises(cas, P, D_P, signee, schemas);
  const ec = J.validerSchema(cr, schemas[S.ID_SCHEMA_ATTESTATION_PERIMETRE], { registre: schemas, fragment: "#/$defs/croises" });
  if (ec.length) throw new ErreurGeneration(`croises.json : ${ec[0].chemin} ${ec[0].message}`);
  for (const c of fichier.cases) if (c.name.startsWith("valide-") !== c.expected.retained) throw new ErreurGeneration(`attestations.json : ${c.name} ${c.expected.retained ? "retenue" : "non retenue"}`);
  return { constantes, exemple, fichier, croises: cr };
}

/** Signatures croisées du compte 1 (EX-A.9, EX-7.7). */
function croises(cas, P, D_P, signee, schemas) {
  const compte1 = A.COMPTES[1];
  const cle1 = C.depuisHex(compte1.privateKey);
  const signer32 = (d) => C.signerHachage(Uint8Array.from(cle1), C.condenseEIP191(C.depuisHex(d)));
  const recouvrer = (octets, sig) => C.verifierSignature(octets, sig, A.adresse(1)).recovered;
  // Le texte d'inscription de CT-3 §13.5 : le défi du cas cree-entree des vecteurs de CT-3, à l'adresse du compte 1.
  const inscriptions = J.analyserJSONStrict(fs.readFileSync(path.join(VECTEURS, "ct-3", "annuaire", "inscriptions.json")));
  const champs = { ...inscriptions.cases.find((x) => x.id === "cree-entree").challenges[0].fields, address: A.adresse(1) };
  const texte = C.messageInscription(champs);
  const sigTexte = C.signerHachage(Uint8Array.from(cle1), C.condenseEIP191(C.utf8(texte)));
  // Un procès-verbal des vecteurs (A.4), signé par le compte 1 (participant p1 de l'exemple).
  const pv = J.analyserJSONStrict(cas.find((c) => c.nom === "valide-creation-enregistreur").octets);
  const D_C = S.condenseCeremonie(pv);
  const sigPv = pv.signatures.find((s) => s.participant === "p1").signature;
  // periodDigest de la clôture de la période 1 des vecteurs de CT-4.
  const condenses = J.analyserJSONStrict(fs.readFileSync(path.join(VECTEURS, "ct-4", "condenses.json")));
  const periodDigest = condenses.cases.find((x) => x.id === "period-digest-periode-1").expected.digest;
  const D_A = K.D_A_APR_1192;
  const commeAttestation = (name, description, message, signature) => {
    const s = structuredClone(signee);
    s.signatures[0].signature = signature;
    const r = S.verifierAttestation(s, A.jeuExemple(), { schemas });
    return { name, description, message, signature, presented_as: "attestation", expected: { check: "CT-1 AT-3", status: r.checks[2].status, recovered: r.recovered[0] } };
  };
  const sigP = S.signerAttestation(compte1, P);
  const pvCroise = structuredClone(pv);
  pvCroise.signatures[0].signature = sigP;
  const rPv = S.verifierCeremonie(J.texteJSON(pvCroise));
  const cases = [
    commeAttestation("decision-comme-attestation", "Signature par le compte 1 du D_A de la décision apr-1192 de CT-1 §6.4, présentée comme signature de l'attestation de l'exemple.", { kind: "approbation", digest: D_A }, signer32(D_A)),
    commeAttestation("inscription-comme-attestation", "Signature par le compte 1 du texte d'inscription de CT-3 §13.5 (défi du cas cree-entree, adresse du compte 1), présentée comme signature de l'attestation.", { kind: "inscription", text: texte }, sigTexte),
    commeAttestation("ceremonie-comme-attestation", "Signature par le compte 1 (participant p1) du D_C du procès-verbal valide-creation-enregistreur, présentée comme signature de l'attestation.", { kind: "ceremonie", digest: D_C, case: "ceremonies/valide-creation-enregistreur" }, sigPv),
    commeAttestation("registre-comme-attestation", "Signature par le compte 1 du periodDigest de la clôture de la période 1 (ct-4/condenses.json, cas period-digest-periode-1), présentée comme signature de l'attestation.", { kind: "registre", digest: periodDigest, case: "ct-4/condenses.json period-digest-periode-1" }, signer32(periodDigest)),
    { name: "attestation-comme-decision", description: "Signature par le compte 1 du D_P de l'attestation de l'exemple, présentée comme signature du D_A de la décision apr-1192 : CT-1 E-9 la refuse.", message: { kind: "attestation", digest: D_P }, signature: sigP, presented_as: "approbation", target: { digest: D_A }, expected: { check: "CT-1 E-9", status: "echoue", recovered: recouvrer(C.depuisHex(D_A), sigP) } },
    { name: "attestation-comme-inscription", description: "Signature par le compte 1 du D_P, présentée comme signature du texte d'inscription : CT-3 AN-4 la refuse.", message: { kind: "attestation", digest: D_P }, signature: sigP, presented_as: "inscription", target: { text: texte }, expected: { check: "CT-3 AN-4", status: "echoue", recovered: recouvrer(C.utf8(texte), sigP) } },
    { name: "attestation-comme-ceremonie", description: "Signature par le compte 1 du D_P, présentée comme signature de p1 sur le procès-verbal valide-creation-enregistreur : CT-7 CR-11 la refuse.", message: { kind: "attestation", digest: D_P }, signature: sigP, presented_as: "ceremonie", target: { digest: D_C, case: "ceremonies/valide-creation-enregistreur" }, expected: { check: "CT-7 CR-11", status: rPv.failed.includes("CR-11") ? "echoue" : "reussi", recovered: recouvrer(C.depuisHex(D_C), sigP) } },
  ];
  for (const c of cases) if (c.expected.status !== "echoue" || c.expected.recovered === A.adresse(1)) throw new ErreurGeneration(`croises.json : ${c.name} n'est pas refusée`);
  return { version: 0, family: "croises", account: 1, address: A.adresse(1), attestation_digest: D_P, cases };
}

// ---------------------------------------------------------------------------
// Matrice de conformité et cas invalides
// ---------------------------------------------------------------------------

/** Les cas invalides de la matrice (EX-A.14) : [nom, altération, mutation, MX- attendues]. */
export function casMatrice() {
  const ligne = (m, id) => m.rows.find((r) => r.id === id);
  return [
    ["statut-force", "MC-57 passe de couvert à partiel", (m) => (ligne(m, "MC-57").status = "partiel"), ["MX-1", "MX-3"]],
    ["couvert-avec-contribution", "MC-1 passe à couvert", (m) => (ligne(m, "MC-1").status = "couvert"), ["MX-1", "MX-3"]],
    ["renvoi-inexistant", "une pièce de MC-17 devient CT-2 EX-12.999", (m) => (ligne(m, "MC-17").elements[0].pieces[0] = { kind: "exigence", spec: "CT-2", ref: "EX-12.999" }), ["MX-4"]],
    ["section-inexistante", "la pièce CT-2 §12.8 de MC-56 devient CT-2 §12.99", (m) => {
      const p = ligne(m, "MC-56").elements.flatMap((x) => x.pieces).find((x) => x.kind === "section" && x.spec === "CT-2" && x.ref === "§12.8");
      if (!p) throw new ErreurGeneration("matrice : pièce CT-2 §12.8 absente de MC-56");
      p.ref = "§12.99";
    }, ["MX-4"]],
    ["clause-orpheline", "la clause CL-5 n'est plus citée par aucune ligne, serves inchangé", (m) => {
      for (const r of m.rows) for (const x of r.elements) x.pieces = x.pieces.filter((p) => !(p.kind === "clause" && p.ref === "CL-5"));
    }, ["MX-5"]],
    ["lacune-ligne-inconnue", "L-1 nomme MC-99", (m) => (m.gaps.find((g) => g.id === "L-1").rows = ["MC-99"]), ["MX-6"]],
    ["mot-interdit", "le requirement de MC-57 se termine par « : le client est conforme »", (m) => (ligne(m, "MC-57").requirement += " : le client est conforme"), ["MX-7"]],
    ["ia-sans-date", "from de T-8 devient []", (m) => (m.texts.find((t) => t.id === "T-8").applicability.from = []), ["MX-1", "MX-9"]],
    ["texte-inconnu", "MC-42 porte text T-11", (m) => (ligne(m, "MC-42").text = "T-11"), ["MX-2"]],
    ["fait-hors-annexe", "MC-1 cite R6-F99", (m) => ligne(m, "MC-1").facts.push("R6-F99"), ["MX-9"]],
    ["lignes-permutees", "les lignes MC-25 et MC-26 échangent leur place", (m) => {
      const i = m.rows.findIndex((r) => r.id === "MC-25");
      [m.rows[i], m.rows[i + 1]] = [m.rows[i + 1], m.rows[i]];
    }, ["MX-2"]],
    ["ia-date-passee", "from de T-8 reçoit en tête une date passée, 2026-08-02", (m) => m.texts.find((t) => t.id === "T-8").applicability.from.unshift({ date: "2026-08-02", scope: "date passée ajoutée (cas invalide)" }), ["MX-9"]],
  ];
}

function matrice(specs) {
  const erreurs = R.verifierMatrice(MATRICE, { specs, publie: true });
  if (erreurs.length) throw new ErreurGeneration(`matrice-conformite.json refusé :\n${erreurs.map((e) => `  ${e.id} : ${e.message}`).join("\n")}`);
  const invalides = casMatrice().map(([nom, alteration, muter, attendu]) => {
    const m = structuredClone(MATRICE);
    muter(m);
    const echecs = [...new Set(R.verifierMatrice(m, { specs, publie: false }).map((e) => e.id))].sort((a, b) => Number(a.slice(3)) - Number(b.slice(3)));
    if (JSON.stringify(echecs) !== JSON.stringify(attendu)) throw new ErreurGeneration(`matrice/invalides/${nom} : en échec ${echecs.join(", ")}, attendu ${attendu.join(", ")}`);
    return { nom, alteration, contenu: m, failed: echecs };
  });
  const attendu = { version: 0, family: "matrice-invalides", note: "MX-8 ne s'exécute pas sur ces cas (CT-7 EX-A.14).", cases: invalides.map((c) => ({ name: c.nom, alteration: c.alteration, failed: c.failed })) };
  const e = J.validerSchema(attendu, R.sansContains(JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "matrice-conformite-v0.schema.json"), "utf8"))), { fragment: "#/$defs/cas_invalides_matrice" });
  if (e.length) throw new ErreurGeneration(`matrice/invalides/attendu.json : ${e[0].chemin} ${e[0].message}`);
  return { invalides, attendu };
}

// ---------------------------------------------------------------------------
// Épreuves à l'aveugle (section 9, A.15)
// ---------------------------------------------------------------------------

function tablesSection9(t7) {
  const t = S.tablesDe(S.texteSection(t7, "9") ?? "");
  if (t.length < 3) throw new ErreurGeneration("CT-7 section 9 : trois tables attendues");
  return { securite: t[0].lignes, conformite: t[1].lignes, attestation: t[2].lignes };
}

function epreuveSecurite(t9) {
  const scenarios = t9.securite.map((c, i) => ({ id: `S${i + 1}`, scenario: c[0], threat: c[1], expected: elements(c[2]) }));
  const consigne = [
    "# Épreuve à l'aveugle du responsable de la sécurité (CT-7, EX-9.1)",
    "",
    "Vous recevez la spécification CT-7 (`spec/CT-7-securite-et-conformite.md`,",
    "version 0.1) sans sa section 9 ni son annexe A.15, et rien d'autre. Répondez",
    "seul et par écrit. Pour chacun des six scénarios d'attaque ci-dessous,",
    "donnez :",
    "",
    "1. la menace de CT-7 qui le décrit (identifiant MN-) ;",
    "2. la réponse : au moins une exigence (EX-) citée par cette menace ;",
    "3. la détection : le contrôle du dossier ou la supervision qui la révèle ;",
    "4. le risque résiduel : l'identifiant du risque accepté (RA-), ou « aucun ».",
    "",
    "Un relecteur qui ne vous a pas aidé compare ensuite vos réponses à une grille",
    "qui n'est pas dans ce répertoire.",
    "",
    "## Scénarios",
    "",
    ...scenarios.map((s) => plier(`${s.scenario}.`, `${s.id}. `)),
    "",
  ].join("\n");
  return { consigne, grille: { version: 0, test: "acceptation-securite", rule: "CT-7 EX-9.1", success: "Chacune des six réponses contient la menace, une réponse, une détection et le risque résiduel de la grille.", scenarios } };
}

function epreuveConformite(t9) {
  const parId = new Map(MATRICE.rows.map((r) => [r.id, r]));
  const textes = new Map(MATRICE.texts.map((t) => [t.id, t]));
  const passages = t9.conformite.filter((c) => /^MC-/.test(c[1]));
  const sixieme = t9.conformite.find((c) => !/^MC-/.test(c[1]));
  const questions = passages.map((c, i) => {
    const r = parId.get(c[1]);
    if (!r) throw new ErreurGeneration(`épreuve de conformité : ligne ${c[1]} absente de la matrice`);
    const t = textes.get(r.text);
    const de = (rels) => r.elements.filter((x) => rels.includes(x.relation));
    return {
      id: `P${i + 1}`,
      passage: c[0],
      row: r.id,
      expected: {
        a_pieces: de(["repond_a", "contribue_a"]).map((x) => ({ relation: x.relation, element: x.element, condition: x.condition, pieces: x.pieces.map(R.ecrirePiece) })),
        b_not_covered: de(["ne_couvre_pas"]).map((x) => x.element),
        b_client: de(["releve_du_client"]).map((x) => x.element),
        c_status: r.status,
        c_applicability: r.applicability,
        c_from: t.applicability.from,
      },
      table_elements: elements(c[2]),
    };
  });
  const consigne = [
    "# Épreuve à l'aveugle du responsable de la conformité (CT-7, EX-9.2)",
    "",
    "Vous recevez la spécification CT-7 (`spec/CT-7-securite-et-conformite.md`,",
    "version 0.1) sans sa section 9 ni son annexe A.15, et rien d'autre. Répondez",
    "seul et par écrit. Pour chacun des cinq passages ci-dessous, répondez à trois",
    "questions :",
    "",
    "- (a) quelle pièce de NOORTRACE y répond ou y contribue ?",
    "- (b) qu'est-ce qui n'est pas couvert, ou relève de votre organisation ?",
    "- (c) quel est le statut de la ligne, et le texte s'applique-t-il aujourd'hui",
    "  (au 2026-10-26) ?",
    "",
    "## Passages",
    "",
    ...questions.map((q) => plier(`${q.passage}.`, `${q.id}. `)),
    "",
    "## Sixième question",
    "",
    "La matrice dit-elle que votre organisation est conforme ?",
    "",
    "Un relecteur qui ne vous a pas aidé compare ensuite vos réponses à une grille",
    "qui n'est pas dans ce répertoire.",
    "",
  ].join("\n");
  return {
    consigne,
    grille: {
      version: 0,
      test: "acceptation-conformite",
      rule: "CT-7 EX-9.2, EX-9.3",
      source: "spec/vecteurs/ct-7/matrice-conformite.json",
      success: "Chaque réponse contient tous ses éléments ; une réponse qui dit qu'une ligne couvert rend le client conforme, ou qui présente l'un des art. 12, 14, 19 ou 26 du règlement (UE) 2024/1689 comme applicable au 2026-10-26 (T-8), échoue quels que soient ses autres éléments.",
      questions,
      sixth_question: { question: "La matrice dit-elle que votre organisation est conforme ?", expected_answer: "non", expected: elements(sixieme ? sixieme[2] : "") },
    },
  };
}

function epreuveAttestation(t9, rapport) {
  const questions = t9.attestation.map((c) => {
    const m = /^(Q[0-9]+)\. (.*)$/.exec(c[0]);
    return { id: m ? m[1] : c[0], question: m ? m[2] : c[0], expected: elements(c[1]) };
  });
  const consigne = [
    "# Épreuve à l'aveugle de l'administrateur du client (CT-7, EX-9.4)",
    "",
    "Vous recevez la section 7 de la spécification CT-7",
    "(`spec/CT-7-securite-et-conformite.md`, version 0.1) et rien d'autre de la",
    "spécification. Vous disposez aussi de :",
    "",
    plier("l'attestation de l'exemple : `spec/vecteurs/ct-7/attestations/exemple/attestation.json` et sa forme signée `attestation-signee.json` ;", "- "),
    plier("un dossier de preuve qui la porte : `spec/vecteurs/ct-1/dossiers/valide-seq-12-attestation-inscrite/` ;", "- "),
    plier("le rapport de ce dossier, `rapport.txt` dans ce répertoire, tel que l'imprime `node scripts/verify/dossier.mjs` sur ce dossier (les deux lignes qui nomment la machine et le répertoire sont omises).", "- "),
    "",
    "Répondez seul et par écrit aux six questions. Un relecteur qui ne vous a pas",
    "aidé compare ensuite vos réponses à une grille qui n'est pas dans ce",
    "répertoire.",
    "",
    "## Questions",
    "",
    ...questions.map((q) => plier(q.question, `${q.id}. `)),
    "",
  ].join("\n");
  return {
    consigne,
    rapport,
    grille: { version: 0, test: "acceptation-attestation", rule: "CT-7 EX-9.4, EX-9.5", success: "Chaque réponse contient tous ses éléments ; une réponse qui dit l'attestation « preuve du périmètre » ou « preuve de conformité » échoue, quels que soient ses autres éléments.", questions },
  };
}

/** Rapport lisible du dossier ct-1 valide-seq-12-attestation-inscrite, sans les lignes qui nomment la machine et le répertoire. */
function rapportDossierAttestation() {
  const sortie = execFileSync(process.execPath, [path.join(RACINE_PROJET, "scripts", "verify", "dossier.mjs"), path.join(VECTEURS, "ct-1", "dossiers", "valide-seq-12-attestation-inscrite")], { encoding: "utf8" });
  return sortie.split("\n").filter((l) => !/^(Vérificateur|Répertoire)\s*:/.test(l)).join("\n");
}

// ---------------------------------------------------------------------------
// INDEX.md
// ---------------------------------------------------------------------------

const cellule = (s) => String(s).replace(/\|/g, "\\|");

function index({ doc, cas, cles, att, mat, tables }) {
  const l = [];
  l.push("# Vecteurs CT-7 — sécurité et conformité", "");
  l.push("Produit par `scripts/vecteurs/generer-ct7.mjs` (`npm run vecteurs:ct7`) ; ne pas l'éditer à la main. Spécification : [`spec/CT-7-securite-et-conformite.md`](../../CT-7-securite-et-conformite.md), annexe A.", "");
  l.push("Le générateur lit le texte de CT-7 et les vecteurs de CT-1, CT-3, CT-4 et CT-6, sans jamais les réécrire. Il n'écrit ni n'efface `confrontation/` ni `verificateur-independant/`. Deux exécutions donnent des fichiers identiques (EX-A.2).", "");
  l.push("```bash", "npm run vecteurs:ct7", "node scripts/conformite/verifier-renvois.mjs                                 # RV-1 à RV-9, MX-1 à MX-9 : code 0", "node scripts/verify/ceremonie.mjs spec/vecteurs/ct-7/ceremonies/valide-creation-enregistreur/proces-verbal.json   # code 0", "node scripts/conformite/attestation.mjs verifier spec/vecteurs/ct-7/attestations/exemple/attestation-signee.json --jeu spec/vecteurs/ct-7/attestations/exemple/jeu.json", "```", "");
  const parStatut = (k) => doc.threats.filter((t) => (k ? t.residual.accepted_risk : !t.residual.accepted_risk)).length;
  l.push("## menaces.json", "");
  l.push(`Le modèle de menace de CT-7 §3.8, tiré des tables 3.2 à 3.5 du texte (EX-A.4) : ${doc.components.length} composants, ${doc.threats.length} menaces (MN-1 à MN-${doc.threats.length}), dont ${parStatut(true)} avec un risque accepté et ${parStatut(false)} sans, ${doc.source_tables.length} tables sources de ${doc.source_tables.reduce((a, s) => a + s.rows, 0)} lignes. Schéma : \`spec/schemas/modele-menace-v0.schema.json\`.`, "");
  l.push("| Composant | Menaces |", "|---|---|");
  for (const c of doc.components) l.push(`| \`${c.id}\` (${cellule(c.name)}) | ${doc.threats.filter((t) => t.component === c.id).map((t) => t.id).join(", ")} |`);
  l.push("");
  l.push("### Consolidation des tables sources (CT-7 §3.3)", "");
  l.push("| Spécification | Section | Ligne de la table source | Menaces de CT-7 |", "|---|---|---|---|");
  for (const c of tables.rattachement) l.push(`| ${c[0]} | ${c[1]} | ${cellule(c[2])} | ${c[3]} |`);
  l.push("");
  l.push("## ceremonies/", "");
  l.push("Chaque cas : `proces-verbal.json` (le fichier vérifié, octets exacts) et `attendu.json` (`ceremonie-cles-v0#/$defs/attendu`). Un cas invalide est tiré d'un cas valide par une seule mutation, puis signé de nouveau par tous ses participants, sauf quand la mutation porte sur les signatures (EX-A.6). Comptes Hardhat 1 à 8 du mnémonique public de `spec/vecteurs/ct-3/constantes.json`.", "");
  l.push("| Cas | Mutation | Verdict | En échec | Non exécutées | D_C |", "|---|---|---|---|---|---|");
  for (const c of cas) l.push(`| \`${c.nom}\` | ${cellule(c.mutation)} | ${c.attendu.verdict} | ${c.attendu.failed.join(", ") || "—"} | ${c.attendu.not_executed.length ? "CR-2 à CR-12" : "—"} | ${c.attendu.digest ? `\`${c.attendu.digest.slice(0, 10)}…\`` : "—"} |`);
  l.push("");
  l.push("## cles-de-test.json", "");
  l.push(`Les clés publiques de test publiées par les vecteurs (EX-4.10, EX-A.7), recalculées depuis \`ct-1/cles/cles-test.json\`, \`ct-3/constantes.json\` (comptes Hardhat 0 à 9), \`ct-4/constantes.json\` et \`ct-6/rfc3161/cles/\` : ${cles.keys.length} clés (${["ct-1", "ct-3", "ct-4", "ct-6"].map((s) => `${s} : ${cles.keys.filter((k) => k.source === s).length}`).join(", ")}). Aucune ne sert en production ; RV-9 les recalcule.`, "");
  l.push("## attestations/", "");
  l.push("`constantes.json` : `P_P`, comptes, organisation, journaux, étiquette de `rules_sha256`, jeu. `exemple/` : l'attestation de CT-7 §7.1 (`attestation.json`), `JCS(P)` (`jcs.txt`), `D_P`, `M` et les signatures des comptes 1 et 2 (`condense.json`), `attestation-signee.json`, `jeu.json`. `attestations.json` : les cas d'EX-A.8 (schéma `attestation-perimetre-v0#/$defs/fichier_vecteurs`). `croises.json` : les signatures croisées d'EX-A.9.", "");
  l.push("| Cas | AT-1 | AT-2 | AT-3 | AT-4 | Retenue |", "|---|---|---|---|---|---|");
  for (const c of att.fichier.cases) l.push(`| \`${c.name}\` | ${c.expected.checks.map((x) => x.status).join(" | ")} | ${c.expected.retained ? "oui" : "non"} |`);
  l.push("");
  l.push("| Signature croisée (compte 1) | Présentée comme | Refusée par | Adresse recouvrée |", "|---|---|---|---|");
  for (const c of att.croises.cases) l.push(`| \`${c.name}\` | ${c.presented_as} | ${c.expected.check} | \`${c.expected.recovered}\` |`);
  l.push("");
  const comptes = ["couvert", "partiel", "hors_perimetre"].map((s) => `${MATRICE.rows.filter((r) => r.status === s).length} \`${s}\``).join(", ");
  l.push("## matrice-conformite.json et matrice/invalides/", "");
  l.push(`La matrice de CT-7 section 8, écrite depuis \`scripts/conformite/matrice-donnees.mjs\` : ${MATRICE.texts.length} textes, ${MATRICE.rows.length} lignes (${comptes}), ${MATRICE.clauses.length} clauses, ${MATRICE.gaps.length} lacunes. Schéma : \`spec/schemas/matrice-conformite-v0.schema.json\`. C'est une correspondance technique, pas un avis juridique (EX-8.1). Les cas invalides altèrent la matrice en un point ; \`attendu.json\` donne la liste exacte des MX- en échec (MX-8 ne s'exécute pas sur eux, EX-A.14).`, "");
  l.push("| Cas | Altération | MX- en échec |", "|---|---|---|");
  for (const c of mat.invalides) l.push(`| \`${c.nom}.json\` | ${cellule(c.alteration)} | ${c.failed.join(", ")} |`);
  l.push("");
  l.push("## Épreuves à l'aveugle (section 9)", "");
  l.push("| Épreuve | Remis à la personne | Grille, non remise |", "|---|---|---|");
  l.push("| Responsable de la sécurité (EX-9.1) | `acceptation-securite/consigne.md` | `acceptation-securite-attendu.json` |");
  l.push("| Responsable de la conformité (EX-9.2, EX-9.3) | `acceptation-conformite/consigne.md` | `acceptation-conformite-attendu.json` (dérivée de `matrice-conformite.json`) |");
  l.push("| Administrateur du client (EX-9.4, EX-9.5) | `acceptation-attestation/consigne.md`, `acceptation-attestation/rapport.txt` | `acceptation-attestation-attendu.json` |");
  l.push("");
  l.push("Les consignes d'EX-9.1 et d'EX-9.2 remettent CT-7 sans sa section 9 ni son annexe A.15, qui portent les grilles. `acceptation-attestation/rapport.txt` est la sortie lisible de `node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-12-attestation-inscrite`, sans les lignes « Vérificateur : » et « Répertoire : », qui dépendent de la machine (EX-A.29). Grilles : `modele-menace-v0#/$defs/grille_securite`, `matrice-conformite-v0#/$defs/grille_conformite`, `attestation-perimetre-v0#/$defs/grille_attestation`.", "");
  return plierMarkdown(l);
}

// ---------------------------------------------------------------------------
// Programme
// ---------------------------------------------------------------------------

/** Calcule tout le contenu de ct-7 : chemin relatif → contenu (chaîne ou octets). */
export function contenuCt7() {
  const specs = S.lireSpecifications(SPEC);
  const readme = fs.readFileSync(path.join(SPEC, "README.md"), "utf8");
  const cles = S.clesDeTest(VECTEURS);
  const doc = menaces(specs, readme, cles);
  const cas = ceremonies(specs);
  const att = attestations(cas);
  const mat = matrice(specs);
  const t9 = tablesSection9(specs["CT-7"]);
  const secu = epreuveSecurite(t9);
  const conf = epreuveConformite(t9);
  const attn = epreuveAttestation(t9, rapportDossierAttestation());
  // Formes des fichiers sans schéma propre (EX-A.7, EX-A.9, EX-A.14, A.15) : $defs des schémas de CT-7.
  const schema = (n) => R.sansContains(JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", `${n}-v0.schema.json`), "utf8")));
  const controler = (nom, valeur, n, fragment) => {
    const e = J.validerSchema(valeur, schema(n), { fragment });
    if (e.length) throw new ErreurGeneration(`${nom} : ${e[0].chemin} ${e[0].message}`);
  };
  controler("cles-de-test.json", cles, "ceremonie-cles", "#/$defs/cles_de_test");
  controler("acceptation-securite-attendu.json", secu.grille, "modele-menace", "#/$defs/grille_securite");
  controler("acceptation-conformite-attendu.json", conf.grille, "matrice-conformite", "#/$defs/grille_conformite");
  controler("acceptation-attestation-attendu.json", attn.grille, "attestation-perimetre", "#/$defs/grille_attestation");
  const f = new Map();
  f.set("menaces.json", json(doc));
  f.set("cles-de-test.json", json(cles));
  for (const c of cas) {
    f.set(`ceremonies/${c.nom}/proces-verbal.json`, c.octets);
    f.set(`ceremonies/${c.nom}/attendu.json`, json(c.attendu));
  }
  f.set("attestations/constantes.json", json(att.constantes));
  for (const [n, contenu] of Object.entries(att.exemple)) f.set(`attestations/exemple/${n}`, contenu);
  f.set("attestations/attestations.json", json(att.fichier));
  f.set("attestations/croises.json", json(att.croises));
  f.set("matrice-conformite.json", json(MATRICE));
  for (const c of mat.invalides) f.set(`matrice/invalides/${c.nom}.json`, json(c.contenu));
  f.set("matrice/invalides/attendu.json", json(mat.attendu));
  f.set("acceptation-securite/consigne.md", secu.consigne);
  f.set("acceptation-securite-attendu.json", json(secu.grille));
  f.set("acceptation-conformite/consigne.md", conf.consigne);
  f.set("acceptation-conformite-attendu.json", json(conf.grille));
  f.set("acceptation-attestation/consigne.md", attn.consigne);
  f.set("acceptation-attestation/rapport.txt", attn.rapport);
  f.set("acceptation-attestation-attendu.json", json(attn.grille));
  f.set("INDEX.md", index({ doc, cas, cles, att, mat, tables: S.lireTablesCt7(specs["CT-7"]) }));
  return f;
}

/** Écrit ct-7 dans `racine` : efface les entrées générées, puis les réécrit. Rend le nombre de fichiers écrits. */
export function genererCt7({ racine = REPERTOIRE_CT7 } = {}) {
  const f = contenuCt7();
  fs.mkdirSync(racine, { recursive: true });
  for (const e of ENTREES_GENEREES) fs.rmSync(path.join(racine, e), { recursive: true, force: true });
  for (const [rel, contenu] of f) {
    const cible = path.join(racine, rel);
    fs.mkdirSync(path.dirname(cible), { recursive: true });
    fs.writeFileSync(cible, contenu);
  }
  return f.size;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf("--sortie");
  if (i !== -1 && (!process.argv[i + 1] || process.argv[i + 1].startsWith("--"))) {
    console.error("usage : node scripts/vecteurs/generer-ct7.mjs [--sortie <répertoire>]");
    process.exit(2);
  }
  const racine = i !== -1 ? path.resolve(process.argv[i + 1]) : REPERTOIRE_CT7;
  try {
    const n = genererCt7({ racine });
    console.log(`${n} fichiers écrits dans ${path.relative(process.cwd(), racine) || "."}`);
  } catch (err) {
    if (err instanceof ErreurGeneration) {
      console.error(err.message);
      process.exit(1);
    }
    throw err;
  }
}
