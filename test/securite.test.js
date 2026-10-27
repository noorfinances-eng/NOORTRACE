import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import os from "node:os";
import { getBytes, verifyMessage, Wallet } from "ethers";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import * as C from "../scripts/lib/console.mjs";
import * as S from "../scripts/lib/securite.mjs";
import * as A from "../scripts/vecteurs/ct7/attestation.mjs";
import * as K from "../scripts/vecteurs/ct7/ceremonies.mjs";
import * as R from "../scripts/conformite/verifier-renvois.mjs";
import { contenuCt7 } from "../scripts/vecteurs/generer-ct7.mjs";

// L'IMPLÉMENTATION DE RÉFÉRENCE DE CT-7 (spec/CT-7-securite-et-conformite.md),
// partie « attestation de périmètre » (section 7) : condensé D_P, message
// EIP-191, signature, vérifications AT-1 à AT-4 hors dossier (annexe A.6).
// Les valeurs attendues sont lues dans le texte de CT-7 (§7.1, §7.2) ; les
// cas de la table d'EX-A.8 sont reconstruits ici depuis l'exemple, chacun
// avec la liste exacte des statuts de AT-1 à AT-4. La vérification de la
// partie dans un dossier (AT-1 à AT-7) est rejouée par test/journal.test.js
// (famille ct-1) et test/verificateur.test.js (famille ct-6, V-10).
//
// Partie cérémonie, modèle de menace et vecteurs (sections 3 à 5, annexe A) :
// exemple de §5.10 recalculé, cas de ceremonies/ rejoués par la bibliothèque
// et par la commande, menaces.json égal aux tables du texte, vérificateur de
// renvois sur le dépôt et sur des copies altérées, clés de test, vecteurs
// attestations/ et croises.json, outil de référence, et deux générations de
// spec/vecteurs/ct-7 identiques au contenu publié.

const SPEC = path.join(PROJECT_ROOT, "spec");
const CT7 = fs.readFileSync(path.join(SPEC, "CT-7-securite-et-conformite.md"), "utf8");
const SCHEMAS = S.schemasAttestation();
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/** Valeur nommée du bloc numérique de CT-7 §7.2 (« nom = valeur »). */
function valeur72(nom) {
  const bloc = CT7.split("Exemple numérique (attestation de 7.1")[1].split("```text\n")[1].split("```")[0];
  const m = new RegExp(`^${nom.replace(/[()]/g, "\\$&")}\\s*\\n?\\s*=\\s*(\\S+)`, "m").exec(bloc);
  return m ? m[1] : null;
}

describe("CT-7 : attestation de périmètre, condensé et signature (§7.1, §7.2)", function () {
  this.timeout(60_000);
  const P = A.attestationExemple();

  it("l'exemple annoté attestation-perimetre de §7.1 est l'attestation des vecteurs et il est conforme au schéma ; rules_sha256 dérive de son étiquette", function () {
    const exemple = J.analyserJSONStrict(/<!-- schema: attestation-perimetre -->\n```json\n([\s\S]*?)\n```/.exec(CT7)[1]);
    expect(exemple).to.deep.equal(P);
    expect(J.validerSchema(exemple, SCHEMAS[S.ID_SCHEMA_ATTESTATION_PERIMETRE], { registre: SCHEMAS })).to.deep.equal([]);
    expect(S.relationsAttestation(exemple)).to.deep.equal([]);
    expect(P.egress.rules_sha256).to.equal(J.sha256(Buffer.from("export fictif des règles de sortie du pare-feu, vecteurs CT-7", "utf8")));
  });

  it("P_P, JCS(P) de 3 201 octets, D_P, M et les signatures des comptes 1 et 2 sont ceux de §7.2 ; signerAttestation = signMessage(getBytes(D_P)) d'ethers", async function () {
    expect(S.PREFIXE_ATTESTATION_HEX).to.equal("6e6f6f7274726163652f6174746573746174696f6e2d706572696d657472652f76300a");
    expect(J.octetsJCS(P).length).to.equal(3201);
    const D_P = S.condenseAttestation(P);
    expect(D_P).to.equal(valeur72("D_P"));
    expect(S.messageAttestation(D_P)).to.equal(valeur72("M"));
    for (const i of [1, 2]) {
      const sig = S.signerAttestation(A.COMPTES[i], P);
      expect(sig, `compte ${i}`).to.equal(valeur72(`sig (${A.adresse(i)})`));
      expect(sig, `compte ${i}`).to.equal(await A.COMPTES[i].signMessage(getBytes(D_P)));
      expect(verifyMessage(getBytes(D_P), sig).toLowerCase()).to.equal(A.adresse(i));
    }
    // La signature du compte 3 sur le même M, citée en §7.2, recouvre l'adresse du compte 3.
    const sig3 = /La signature du compte 3 sur le même `M`,\n`(0x[0-9a-f]{130})`/.exec(CT7)[1];
    expect(S.signerAttestation(A.COMPTES[3], P)).to.equal(sig3);
    expect(S.examinerSignature(S.messageAttestation(D_P), sig3).adresse).to.equal("0x90f79bf6eb2c4f870365e785982e1f101e93b906");
  });

  it("séparation des domaines (EX-7.7) : P_P diffère de tous les préfixes de CT-1, de la ligne de titre de l'inscription de CT-3 et du préfixe de cérémonie, sans être préfixe de l'un d'eux ni l'inverse", function () {
    const autres = [J.PREFIXE_EVENEMENT, J.PREFIXE_SIGNATURE_EVENEMENT, J.PREFIXE_MANIFESTE, J.PREFIXE_SIGNATURE_MANIFESTE, J.PREFIXE_APPROBATION, J.PREFIXE_ROTATION, J.PREFIXE_POINT_DE_CONTROLE, J.PREFIXE_SIGNATURE_POINT_DE_CONTROLE, C.LIGNE_TITRE_INSCRIPTION + "\n", "noortrace/ceremonie-cles/v0\n"];
    for (const p of autres) expect(S.PREFIXE_ATTESTATION.startsWith(p) || p.startsWith(S.PREFIXE_ATTESTATION), JSON.stringify(p)).to.equal(false);
    // Une signature de D_A (ticket apr-2201 des vecteurs de CT-1) par le compte 1, présentée comme signature de l'attestation : AT-3 la refuse.
    const evs = J.analyserJSONStrict(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-1", "journal-valide", "evenements.json")));
    const sigA = evs.find((e) => e.seq === 6).approval.signatures[0];
    const signee = A.signer(P);
    signee.signatures[0].signature = sigA;
    const r = S.verifierAttestation(signee, A.jeuExemple());
    expect(r.checks.map((c) => c.status)).to.deep.equal(["reussi", "reussi", "echoue", "non_execute"]);
    expect(r.recovered[0]).to.not.equal(A.adresse(1));
  });
});

describe("CT-7 : vérifications AT-1 à AT-4 hors dossier (EX-7.16, cas de la table d'EX-A.8)", function () {
  this.timeout(120_000);
  const JEU = A.jeuExemple();
  const formeHaute = (sig) => {
    const s = BigInt("0x" + sig.slice(66, 130));
    return sig.slice(0, 66) + (N - s).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
  };
  const R = "reussi";
  const E = "echoue";
  const X = "non_execute";
  /** Les cas : [nom, signee (objet ou texte), jeu, statuts de AT-1 à AT-4]. */
  function cas() {
    const P = A.attestationExemple();
    const base = A.signer(P);
    const out = [];
    const avecP = (modif, comptes = [1, 2]) => {
      const p = A.attestationExemple();
      modif(p);
      return A.signer(p, comptes);
    };
    out.push(["valide-deux-signatures", base, JEU, [R, R, R, R]]);
    out.push(["valide-trois-signatures", avecP((p) => p.signatories.push({ name: "Approbateur 3", function: "directeur financier", address: A.adresse(3) }), [1, 2, 3]), JEU, [R, R, R, R]]);
    out.push(["valide-seuil-un", A.signer(P, [1]), { ...JEU, threshold: { required: 1, size: 3 } }, [R, R, R, R]]);
    out.push(["invalide-at1-membre-en-trop", { ...base, attestation: { ...P, extra: true } }, JEU, [E, X, X, X]]);
    out.push(["invalide-at1-validite-inversee", avecP((p) => (p.validity = { from: "2027-01-31T23:59:59.999Z", until: "2026-11-01T00:00:00.000Z" })), JEU, [E, X, X, X]]);
    out.push(["invalide-at1-date-inexistante", avecP((p) => (p.validity.until = "2027-02-30T00:00:00.000Z")), JEU, [E, X, X, X]]);
    out.push(["invalide-at1-agent-journal-inconnu", avecP((p) => (p.agents[0].journal_id = "0x" + "ab".repeat(32))), JEU, [E, X, X, X]]);
    out.push(["invalide-at1-signataires-en-double", avecP((p) => p.signatories.push({ ...p.signatories[0], name: "Approbateur 1 bis" })), JEU, [E, X, X, X]]);
    out.push(["invalide-at1-nombre-non-entier", J.texteJSON(base).replace('"version": 0,\n  "attestation"', '"version": 0.0,\n  "attestation"'), JEU, [E, X, X, X]]);
    out.push(["invalide-at2-condense-faux", { ...base, digest: avecP((p) => (p.issued_at = "2026-10-31T16:00:00.000Z")).digest }, JEU, [R, E, R, R]]);
    const sub = structuredClone(base);
    sub.signatures[1].signature = A.signature(P, 3).signature;
    out.push(["invalide-at3-signature-substituee", sub, JEU, [R, R, E, X]]);
    const haut = structuredClone(base);
    haut.signatures[1].signature = formeHaute(haut.signatures[1].signature);
    out.push(["invalide-at3-s-haut", haut, JEU, [R, R, E, X]]);
    const v0 = structuredClone(base);
    v0.signatures[1].signature = v0.signatures[1].signature.slice(0, 130) + "00";
    out.push(["invalide-at3-v-hors-domaine", v0, JEU, [R, R, E, X]]);
    out.push(["invalide-at4-seuil-non-atteint", A.signer(P, [1]), JEU, [R, R, R, E]]);
    out.push(["invalide-at4-non-membre", avecP((p) => p.signatories.push({ name: "Approbateur 4", function: "auditeur interne", address: A.adresse(4) }), [1, 4]), JEU, [R, R, R, E]]);
    out.push(["invalide-at4-hors-signataires", A.signer(P, [1, 3]), JEU, [R, R, R, E]]);
    const double = structuredClone(base);
    double.signatures[1] = { ...double.signatures[0] };
    out.push(["invalide-at4-adresse-en-double", double, JEU, [R, R, R, E]]);
    out.push(["invalide-at4-seuil-incoherent", base, { ...JEU, threshold: { required: 4, size: 3 } }, [R, R, R, E]]);
    return out;
  }

  it("chaque cas rend exactement les statuts attendus ; une AT- non exécutée porte prerequis_en_echec ; retained ssi les quatre réussissent ; digest nul si AT-1 échoue", function () {
    const liste = cas();
    expect(liste).to.have.length(18);
    for (const [nom, signee, jeu, statuts] of liste) {
      const r = S.verifierAttestation(signee, jeu, { schemas: SCHEMAS });
      expect(r.checks.map((c) => c.status), nom).to.deep.equal(statuts);
      for (const c of r.checks) expect(c.reason, `${nom} ${c.id}`).to.equal(c.status === "non_execute" ? "prerequis_en_echec" : null);
      expect(r.retained, nom).to.equal(statuts.every((s) => s === R));
      if (statuts[0] === E) expect([r.digest, r.recovered], nom).to.deep.equal([null, null]);
      else expect(r.digest, nom).to.match(/^0x[0-9a-f]{64}$/);
      // Les quatre premiers membres ont la forme de $defs/cas_attestation.expected du schéma.
      const expected = { digest: r.digest, recovered: r.recovered, checks: r.checks, retained: r.retained };
      const casSchema = { name: nom, description: "cas reconstruit par le test", input: { signed: typeof signee === "string" ? {} : signee, approver_set: jeu }, expected };
      expect(J.validerSchema(casSchema, SCHEMAS[S.ID_SCHEMA_ATTESTATION_PERIMETRE], { registre: SCHEMAS, fragment: "#/$defs/cas_attestation" }), nom).to.deep.equal([]);
    }
  });

  it("adresses recouvrées : celles des signataires pour un cas valide, l'adresse du compte 3 pour la signature substituée, null pour une signature non canonique ou de v hors domaine", function () {
    const parNom = Object.fromEntries(cas().map(([nom, signee, jeu]) => [nom, S.verifierAttestation(signee, jeu, { schemas: SCHEMAS })]));
    expect(parNom["valide-deux-signatures"].recovered).to.deep.equal([A.adresse(1), A.adresse(2)]);
    expect(parNom["invalide-at3-signature-substituee"].recovered).to.deep.equal([A.adresse(1), A.adresse(3)]);
    expect(parNom["invalide-at3-s-haut"].recovered).to.deep.equal([A.adresse(1), null]);
    expect(parNom["invalide-at3-v-hors-domaine"].recovered).to.deep.equal([A.adresse(1), null]);
    // La forme non canonique est refusée avant tout recouvrement, alors qu'ethers recouvre la même adresse.
    const haut = cas().find(([n]) => n === "invalide-at3-s-haut")[1].signatures[1].signature;
    expect(S.examinerSignature(S.messageAttestation(A.signer(A.attestationExemple()).digest), haut).motif.fr).to.match(/moitié haute/);
  });

  it("l'attestation signée de l'exemple et sa partie se construisent par construirePartieAttestation ; la partie sans inscription de valide-seq-7-attestation-sans-inscription est celle que construit la bibliothèque, membre pour membre", function () {
    const partie = S.construirePartieAttestation({ signee: A.signer(A.attestationExemple()), approver_set: A.jeuExemple() });
    const vecteur = J.analyserJSONStrict(fs.readFileSync(path.join(SPEC, "vecteurs", "ct-1", "dossiers", "valide-seq-7-attestation-sans-inscription", "attestation-perimetre.json")));
    expect(vecteur).to.deep.equal(partie);
    expect(J.validerSchema(partie, SCHEMAS[J.ID_SCHEMA_DOSSIER], { registre: SCHEMAS, fragment: "#/$defs/attestation_perimetre" })).to.deep.equal([]);
  });
});

// ---------------------------------------------------------------------------
// Cérémonie des clés (CT-7 section 5, annexe A.4, EX-A.19)
// ---------------------------------------------------------------------------


const CT7_VECTEURS = path.join(SPEC, "vecteurs", "ct-7");
const CEREMONIE_CLI = path.join(PROJECT_ROOT, "scripts", "verify", "ceremonie.mjs");
const ATTESTATION_CLI = path.join(PROJECT_ROOT, "scripts", "conformite", "attestation.mjs");
const RENVOIS_CLI = path.join(PROJECT_ROOT, "scripts", "conformite", "verifier-renvois.mjs");
const lireJ = (...p) => J.analyserJSONStrict(fs.readFileSync(path.join(...p)));
const SCHEMA_CEREMONIE = S.schemaCeremonie();
/** Bloc annoté `<!-- schema: nom -->` de CT-7. */
const annote = (nom) => J.analyserJSONStrict(new RegExp(`<!-- schema: ${nom.replace("/", "\\/")} -->\\n\`\`\`json\\n([\\s\\S]*?)\\n\`\`\``).exec(CT7)[1]);
/** Ligne « calcul | valeur » de la table de CT-7 §5.10. */
function valeur510(debut) {
  const section = S.texteSection(CT7, "5.10");
  const l = S.tablesDe(section)[0].lignes.find((c) => c[0].startsWith(debut));
  return l ? l[1].replace(/`/g, "") : null;
}

describe("CT-7 : procès-verbal de cérémonie, exemple de §5.10 (EX-5.7)", function () {
  this.timeout(60_000);
  const pv = annote("ceremonie-cles");

  it("l'exemple annoté est conforme à ceremonie-cles-v0 ; son attendu à #/$defs/attendu ; le modèle de menace annoté à modele-menace-v0", function () {
    expect(J.validerSchema(pv, SCHEMA_CEREMONIE)).to.deep.equal([]);
    expect(J.validerSchema(annote("ceremonie-cles/attendu"), SCHEMA_CEREMONIE, { fragment: "#/$defs/attendu" })).to.deep.equal([]);
    expect(J.validerSchema(annote("modele-menace"), JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "modele-menace-v0.schema.json"), "utf8")))).to.deep.equal([]);
  });

  it("P_C, JCS(V) de 4 748 octets, D_C, M, empreintes, adresse de chaîne et les trois signatures sont ceux du texte ; la forme JCS imprimée est JCS(V)", function () {
    expect(S.PREFIXE_CEREMONIE_HEX).to.equal("6e6f6f7274726163652f636572656d6f6e69652d636c65732f76300a");
    expect(Buffer.byteLength(S.PREFIXE_CEREMONIE)).to.equal(28);
    const { signatures, ...V } = pv;
    const jcs = J.octetsJCS(V);
    expect(jcs.length).to.equal(4771);
    const imprime = /Forme canonique `JCS\(V\)` \(4771 octets UTF-8, une ligne\) :\n\n```text\n(.*)\n```/.exec(CT7)[1];
    expect(jcs.toString("utf8")).to.equal(imprime);
    const D_C = S.condenseCeremonie(pv);
    expect(D_C).to.equal(valeur510("`D_C"));
    expect(D_C).to.equal("0x737c29754b0f9259cbb51db37fa76114ff723442eabaa77afbe70b7caecd9478");
    expect(S.messageCeremonie(D_C)).to.equal(valeur510("`M"));
    expect(pv.keys[0].fingerprint).to.equal(valeur510("SHA-256 de la clé publique Ed25519"));
    expect(J.sha256(C.depuisHex(pv.keys[1].public_key))).to.equal(valeur510("SHA-256 de la clé publique de chaîne"));
    expect(pv.keys[1].address).to.equal(valeur510("Adresse de chaîne"));
    expect(pv.keys[1].address).to.equal(K.COMPTES[3].adresse);
    for (const [p, compte] of [["p1", 1], ["p2", 2], ["p3", 4]]) {
      const sig = pv.signatures.find((s) => s.participant === p).signature;
      expect(sig, p).to.equal(valeur510(`Signature de \`${p}\``));
    }
  });

  it("signerCeremonie = signMessage(getBytes(D_C)) d'ethers ; verifyMessage recouvre chaque participant ; le procès-verbal recalculé est l'exemple, octet pour octet", async function () {
    const D_C = S.condenseCeremonie(pv);
    const signe = S.signerCeremonie(K.pvExemple(), { p1: K.COMPTES[1].cle, p2: K.COMPTES[2].cle, p3: K.COMPTES[4].cle });
    expect(J.texteJSON(signe)).to.equal(J.texteJSON(pv));
    for (const [p, compte] of [["p1", 1], ["p2", 2], ["p3", 4]]) {
      const sig = signe.signatures.find((s) => s.participant === p).signature;
      expect(sig).to.equal(await new Wallet(K.COMPTES[compte].cle).signMessage(getBytes(D_C)));
      expect(verifyMessage(getBytes(D_C), sig).toLowerCase()).to.equal(K.COMPTES[compte].adresse);
    }
  });

  it("séparation des domaines (EX-5.7) : P_C diffère de chaque préfixe de CT-1, de la ligne de titre de l'inscription de CT-3 et de P_P, sans être préfixe de l'un d'eux ni l'inverse", function () {
    const autres = [J.PREFIXE_EVENEMENT, J.PREFIXE_SIGNATURE_EVENEMENT, J.PREFIXE_MANIFESTE, J.PREFIXE_SIGNATURE_MANIFESTE, J.PREFIXE_APPROBATION, J.PREFIXE_ROTATION, J.PREFIXE_POINT_DE_CONTROLE, J.PREFIXE_SIGNATURE_POINT_DE_CONTROLE, C.LIGNE_TITRE_INSCRIPTION + "\n", S.PREFIXE_ATTESTATION];
    for (const p of autres) expect(S.PREFIXE_CEREMONIE.startsWith(p) || p.startsWith(S.PREFIXE_CEREMONIE), JSON.stringify(p)).to.equal(false);
    // Le préfixe de §5.7 est celui du texte.
    expect(/P_C = octets UTF-8 de "noortrace\/ceremonie-cles\/v0\\n"\n\s*= ([0-9a-f]+)/.exec(CT7)[1]).to.equal(S.PREFIXE_CEREMONIE_HEX);
  });

  it("tables de 4.3, 4.4 et CR-5 : algorithmes, classes admises en production, sauvegarde, lues dans le texte", function () {
    const t43 = S.tablesDe(S.texteSection(CT7, "4.3"))[0].lignes;
    for (const c of t43) {
      const usages = [...c[0].matchAll(/`([a-z_]+)`/g)].map((m) => m[1]);
      const classes = c[2].startsWith("`sans_objet`") ? ["sans_objet"] : c[2].split(",").map((x) => x.trim());
      for (const u of usages) expect(S.CLASSES_ADMISES_PRODUCTION[u], u).to.deep.equal(classes);
    }
    expect(Object.keys(S.CLASSES_ADMISES_PRODUCTION).sort()).to.deep.equal(t43.flatMap((c) => [...c[0].matchAll(/`([a-z_]+)`/g)].map((m) => m[1])).sort());
    const t44 = S.tablesDe(S.texteSection(CT7, "4.4"))[0].lignes;
    const regle = (texte) => (texte.startsWith("aucune ou") ? "libre" : texte.startsWith("aucune") || texte.startsWith("hors de") ? "aucune" : texte.includes("en production") ? "partage_en_production" : "partage");
    for (const c of t44) for (const m of c[0].matchAll(/`([a-z_]+)`/g)) expect(S.SAUVEGARDE_PAR_USAGE[m[1]], m[1]).to.equal(regle(c[1]));
    const cr5 = S.tablesDe(S.texteSection(CT7, "5.8"))[0].lignes.find((c) => c[0] === "CR-5")[1];
    for (const [u, algos] of Object.entries(S.ALGORITHME_PAR_USAGE)) for (const a of algos) expect(cr5, `${u} ${a}`).to.include(`\`${a}\``);
  });
});

describe("CT-7 : vecteurs ceremonies/ (annexe A.4, EX-A.6, EX-A.19)", function () {
  this.timeout(180_000);
  const cas = fs.readdirSync(path.join(CT7_VECTEURS, "ceremonies")).sort();

  it("les cas de la table d'EX-A.6 sont tous publiés, avec leur proces-verbal.json et leur attendu.json conforme à #/$defs/attendu", function () {
    const table = S.tablesDe(S.texteSection(CT7, "A.4"))[0].lignes.map((c) => c[0].replace(/`/g, ""));
    expect(cas).to.include.members(table);
    for (const c of cas) {
      expect(J.validerSchema(lireJ(CT7_VECTEURS, "ceremonies", c, "attendu.json"), SCHEMA_CEREMONIE, { fragment: "#/$defs/attendu" }), c).to.deep.equal([]);
      if (c.startsWith("valide-")) expect(J.validerSchema(lireJ(CT7_VECTEURS, "ceremonies", c, "proces-verbal.json"), SCHEMA_CEREMONIE), c).to.deep.equal([]);
    }
  });

  it("verifierCeremonie rend exactement attendu.json pour chaque cas ; chaque cas invalide échoue à la vérification que son nom annonce", function () {
    for (const c of cas) {
      const r = S.verifierCeremonie(fs.readFileSync(path.join(CT7_VECTEURS, "ceremonies", c, "proces-verbal.json")));
      expect(S.attenduCeremonie(r), c).to.deep.equal(lireJ(CT7_VECTEURS, "ceremonies", c, "attendu.json"));
      const vise = /^invalide-(cr[0-9]+)-/.exec(c);
      if (vise) expect(r.failed, c).to.include(vise[1].toUpperCase().replace("CR", "CR-"));
      else expect(r.failed, c).to.deep.equal([]);
      if (r.failed.includes("CR-1")) expect([r.digest, r.not_executed.length], c).to.deep.equal([null, 11]);
    }
  });

  it("la commande scripts/verify/ceremonie.mjs rend le même rapport (--json), le code 0 ou 1, et la phrase fixe de §5.8 pour un procès-verbal valide", function () {
    const phrase = /```text\n(Procès-verbal <ceremony_id> .*)\n```/.exec(CT7)[1];
    for (const c of cas) {
      const fichier = path.join(CT7_VECTEURS, "ceremonies", c, "proces-verbal.json");
      const attendu = lireJ(CT7_VECTEURS, "ceremonies", c, "attendu.json");
      const j = spawnSync(process.execPath, [CEREMONIE_CLI, fichier, "--json"], { encoding: "utf8" });
      expect(j.status, c).to.equal(attendu.verdict === "valide" ? 0 : 1);
      const rapport = JSON.parse(j.stdout);
      expect({ verdict: rapport.verdict, digest: rapport.digest, failed: rapport.failed, not_executed: rapport.not_executed, signers: rapport.signers }, c).to.deep.equal(attendu);
      expect(rapport.statuses.map((s) => s.id), c).to.deep.equal(S.IDS_CR);
      if (attendu.verdict === "valide") {
        const lisible = spawnSync(process.execPath, [CEREMONIE_CLI, fichier], { encoding: "utf8" });
        expect(lisible.status).to.equal(0);
        const pv = lireJ(fichier);
        expect(lisible.stdout).to.include(phrase.replace("<ceremony_id>", pv.ceremony_id).replace("<n>", String(pv.signatures.length)).replace("<D_C>", attendu.digest));
      }
    }
  });

  it("--condense imprime D_C seul, même sans signatures (EX-5.8) ; un fichier absent ou de plus de 1 Mio sort avec le code 2", function () {
    const ex = lireJ(CT7_VECTEURS, "ceremonies", "valide-creation-enregistreur", "proces-verbal.json");
    const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "ct7-ceremonie-"));
    try {
      const f = path.join(dossier, "pv.json");
      fs.writeFileSync(f, J.texteJSON({ ...ex, signatures: [] }));
      const r = spawnSync(process.execPath, [CEREMONIE_CLI, f, "--condense"], { encoding: "utf8" });
      expect([r.status, r.stdout.trim()]).to.deep.equal([0, "0x737c29754b0f9259cbb51db37fa76114ff723442eabaa77afbe70b7caecd9478"]);
      const gros = path.join(dossier, "gros.json");
      fs.writeFileSync(gros, J.texteJSON(ex).replace("{", "{" + " ".repeat(S.LIMITE_PROCES_VERBAL)));
      expect(spawnSync(process.execPath, [CEREMONIE_CLI, gros]).status).to.equal(2);
      expect(spawnSync(process.execPath, [CEREMONIE_CLI, path.join(dossier, "absent.json")]).status).to.equal(2);
      expect(S.verifierCeremonie(fs.readFileSync(gros)).failed).to.deep.equal(["CR-1"]);
    } finally {
      fs.rmSync(dossier, { recursive: true, force: true });
    }
  });

  it("CR-11 contrôle la forme canonique avant le recouvrement : la signature s haut, que ethers 6 refuse aussi, recouvrerait l'adresse du témoin si la forme n'était pas contrôlée, et reste refusée", function () {
    const pv = lireJ(CT7_VECTEURS, "ceremonies", "invalide-cr11-s-haut", "proces-verbal.json");
    const sig = pv.signatures[1].signature;
    expect(() => verifyMessage(getBytes(S.condenseCeremonie(pv)), sig)).to.throw(/non-canonical s/);
    const M = C.depuisHex(S.messageCeremonie(S.condenseCeremonie(pv)));
    expect(C.recouvrerAdresse(M, BigInt("0x" + sig.slice(2, 66)), BigInt("0x" + sig.slice(66, 130)), parseInt(sig.slice(130), 16) - 27)).to.equal(K.COMPTES[2].adresse);
    const r = S.verifierCeremonie(J.texteJSON(pv));
    expect(r.statuses.find((s) => s.id === "CR-11").detail).to.match(/moitié haute/);
    expect(r.signers).to.not.include(K.COMPTES[2].adresse);
  });

  it("EX-5.10 : la clé d'enregistreur et la clé de chaîne d'un procès-verbal vérifié sont celles de la ligne recorders du fichier d'ancres de test de ct-6 pour rec-test-01", function () {
    const pv = lireJ(CT7_VECTEURS, "ceremonies", "valide-creation-enregistreur", "proces-verbal.json");
    expect(S.verifierCeremonie(J.texteJSON(pv)).verdict).to.equal("valide");
    const cle = pv.keys.find((k) => k.usage === "enregistreur");
    const cles1 = lireJ(SPEC, "vecteurs", "ct-1", "cles", "cles.json").keys.find((k) => k.key_id === cle.key_id);
    expect(cle.public_key).to.equal(cles1.public_key);
  });
});

// ---------------------------------------------------------------------------
// Modèle de menace, renvois, traçabilité, clés de test (CT-7 3.8, A.3, A.10)
// ---------------------------------------------------------------------------

describe("CT-7 : modèle de menace et vérificateur de renvois (EX-3.1, EX-A.4, EX-A.18)", function () {
  this.timeout(120_000);
  const SPECS = S.lireSpecifications(SPEC);
  const README = fs.readFileSync(path.join(SPEC, "README.md"), "utf8");
  const MENACES = lireJ(CT7_VECTEURS, "menaces.json");
  const CLES = lireJ(CT7_VECTEURS, "cles-de-test.json");
  const entrees = (modif = {}) => ({ specs: SPECS, readme: README, menaces: MENACES, cles: CLES, clesRecalculees: S.clesDeTest(path.join(SPEC, "vecteurs")), ...modif });
  const ids = (erreurs) => [...new Set(erreurs.map((e) => e.id))];

  it("menaces.json est conforme à modele-menace-v0 et égal, octet pour octet, à ce que construireMenaces tire des tables 3.2 à 3.5 du texte (RV-5) : 98 menaces, 82 risques acceptés, 15 tables sources", function () {
    expect(J.validerSchema(MENACES, JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "modele-menace-v0.schema.json"), "utf8")))).to.deep.equal([]);
    expect(J.texteJSON(S.construireMenaces(S.lireTablesCt7(CT7), SPECS))).to.equal(fs.readFileSync(path.join(CT7_VECTEURS, "menaces.json"), "utf8"));
    expect(MENACES.threats).to.have.length(98);
    expect(MENACES.threats.filter((t) => t.residual.accepted_risk)).to.have.length(82);
    expect(MENACES.source_tables).to.have.length(15);
    // Chaque menace a une réponse écrite (EX-3.2) et porte au moins une catégorie STRIDE (EX-3.4).
    for (const t of MENACES.threats) {
      expect(t.response.refs.length > 0 || t.residual.accepted_risk !== null, t.id).to.equal(true);
      expect(t.stride.length, t.id).to.be.greaterThan(0);
    }
  });

  it("la table de 3.4 du texte, reconstruite depuis menaces.json cellule par cellule, est celle du texte (risque accepté et préfixe du test compris)", function () {
    const noms = new Map(MENACES.components.map((c) => [c.id, c.name]));
    const lignes = MENACES.threats.map((t) => [t.id, noms.get(t.component), t.stride.map((x) => `\`${x}\``).join(", "), t.actor, t.asset, t.effect, t.response.text, t.detection.text, t.residual.text + (t.residual.accepted_risk ? `${t.residual.text ? " " : ""}Risque accepté ${t.residual.accepted_risk.id}.` : ""), t.test.slice(S.PREFIXE_TEST_CT9.length)]);
    expect(lignes).to.deep.equal(S.lireTablesCt7(CT7).menaces);
  });

  it("verifier-renvois.mjs sort avec le code 0 sur le dépôt : RV-1 à RV-9 et MX-1 à MX-9, chaque renvoi EX- de menaces.json et de la table 0.2 existe", function () {
    const r = spawnSync(process.execPath, [RENVOIS_CLI], { encoding: "utf8" });
    expect(r.status, r.stdout).to.equal(0);
    expect(R.verifierDepot(PROJECT_ROOT)).to.deep.equal([]);
    // Chaque renvoi de menaces.json se résout dans la spécification citée (RV-3), CT-7 compris.
    const defs = Object.fromEntries(Object.entries(SPECS).map(([k, t]) => [k, R.definitions(t)]));
    const renvois = new Set(MENACES.threats.flatMap((t) => [...t.response.refs, ...t.detection.refs]));
    for (const x of renvois) expect(R.renvoiExiste(defs, x), x).to.equal(true);
  });

  it("copies altérées en mémoire : un EX inexistant (RV-3), une réponse vide sans risque accepté (RV-2), une ligne source détachée (RV-6), une ligne de traçabilité retirée (RV-7), un risque accepté renommé (RV-8), une clé de test changée (RV-9)", function () {
    const m1 = structuredClone(MENACES);
    m1.threats[0].response.refs.push("CT-2 EX-99.999");
    expect(ids(R.verifierRV(entrees({ menaces: m1 })))).to.include("RV-3");
    const m2 = structuredClone(MENACES);
    const sansRA = m2.threats.find((t) => !t.residual.accepted_risk);
    sansRA.response = { text: "Aucune.", refs: [] };
    expect(ids(R.verifierRV(entrees({ menaces: m2 })))).to.include("RV-2");
    const ligne = "| CT-3 | 14.4 | Le nœud RPC sert un état faux | MN-51 |\n";
    expect(CT7).to.include(ligne);
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": CT7.replace(ligne, "") } })))).to.include("RV-6");
    const tr = CT7.split("\n").find((l) => l.startsWith("| TR-100 |"));
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": CT7.replace(tr + "\n", "") } })))).to.include("RV-7");
    const ajout = SPECS["CT-2"] + "\n\nUne occurrence nouvelle de CT-7.\n";
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-2": ajout } })))).to.include("RV-7");
    const m3 = structuredClone(MENACES);
    m3.threats.find((t) => t.residual.accepted_risk).residual.accepted_risk.name += " (renommé)";
    expect(ids(R.verifierRV(entrees({ menaces: m3 })))).to.include.members(["RV-5", "RV-8"]);
    const c2 = structuredClone(CLES);
    c2.keys[0].public_key = "0x" + "00".repeat(32);
    expect(ids(R.verifierRV(entrees({ cles: c2 })))).to.deep.equal(["RV-9"]);
  });

  it("copies altérées de la table 0.2 : une réponse réduite à « — » ou vide échoue à RV-7, un EX- nu inexistant (EX-A.99 dans TR-15, EX-7.97 dans TR-19) échoue à RV-3 ; le dépôt passe", function () {
    const ligneTR = (id) => CT7.split("\n").find((l) => l.startsWith(`| ${id} |`));
    const remplacerReponse = (id, f) => {
      const l = ligneTR(id);
      const c = l.slice(2, -2).split(" | ");
      c[3] = f(c[3]);
      return CT7.replace(l, `| ${c.join(" | ")} |`);
    };
    expect(R.verifierRV(entrees())).to.deep.equal([]);
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": remplacerReponse("TR-1", () => "—") } })))).to.include("RV-7");
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": remplacerReponse("TR-1", () => "") } })))).to.include("RV-7");
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": remplacerReponse("TR-15", (x) => x + " Voir EX-A.99.") } })))).to.include("RV-3");
    expect(ids(R.verifierRV(entrees({ specs: { ...SPECS, "CT-7": remplacerReponse("TR-19", (x) => x + " Voir EX-7.97.") } })))).to.include("RV-3");
    // Le vérificateur de renvois refuse tout argument (code 2).
    expect(spawnSync(process.execPath, [RENVOIS_CLI, "--matrice", "x.json"]).status).to.equal(2);
  });

  it("table « menace → test existant » : chaque vecteur que la colonne « Test de CT-9 » nomme existe dans spec/vecteurs, et un dossier nommé valide- ou invalide- a cet attendu", function () {
    const dossiers = new Map();
    for (const f of ["ct-1/dossiers", "ct-6/dossiers", "ct-7/ceremonies"]) for (const d of fs.readdirSync(path.join(SPEC, "vecteurs", f))) dossiers.set(d, path.join(SPEC, "vecteurs", f, d));
    let relies = 0;
    for (const t of MENACES.threats) {
      for (const [, x] of t.test.matchAll(/`([^`]+)`/g)) {
        if (/^(valide|invalide)-[a-z0-9-]+$/.test(x)) {
          expect(dossiers.has(x), `${t.id} : ${x}`).to.equal(true);
          const a = lireJ(dossiers.get(x), "attendu.json");
          expect(a.valide ?? a.valid ?? a.verdict === "valide", `${t.id} : ${x}`).to.equal(x.startsWith("valide-"));
          relies++;
        } else if (/^ct-[1-7](\/|$)/.test(x)) {
          expect(fs.existsSync(path.join(SPEC, "vecteurs", x)), `${t.id} : ${x}`).to.equal(true);
          relies++;
        }
      }
    }
    expect(relies).to.be.greaterThan(40);
  });

  it("cles-de-test.json (EX-4.10, EX-A.7) : clés publiques et adresses recalculées depuis les fichiers des vecteurs ; ni la clé de l'enregistreur ni les comptes des cérémonies n'y manquent", function () {
    expect(CLES).to.deep.equal(S.clesDeTest(path.join(SPEC, "vecteurs")));
    const publiques = new Set(CLES.keys.map((k) => k.public_key));
    expect(publiques.has(K.PUB_REC_TEST_01)).to.equal(true);
    for (const i of [1, 2, 3, 4, 5, 6, 7, 8]) expect(CLES.keys.some((k) => k.address === K.COMPTES[i].adresse), `compte ${i}`).to.equal(true);
    for (const k of CLES.keys.filter((x) => x.algorithm === "secp256k1")) expect(k.address, k.label).to.equal("0x" + C.enHex(C.keccak256(C.depuisHex(k.public_key).slice(1))).slice(26));
  });

  it("RV-7 : chaque occurrence de « CT-7 » dans CT-1 à CT-6 et spec/README.md a sa ligne dans la table 0.2 (101 lignes), et chaque section citée existe", function () {
    const t = S.lireTablesCt7(CT7).tracabilite;
    expect(t).to.have.length(101);
    let n = 0;
    for (const [nom, f] of R.FICHIERS_TRACABILITE) n += R.occurrencesCT7(nom, nom === "spec/README.md" ? README : SPECS[nom]).length;
    expect(n).to.equal(101);
    expect(R.sectionsCitees("Section 7 ; jonction au dossier : CT-7 EX-7.13.")).to.deep.equal(["7"]);
    expect(R.sectionsCitees("7.5 ; vecteurs : annexe A.7.")).to.have.members(["A.7", "7.5"]);
  });
});

// ---------------------------------------------------------------------------
// Vecteurs ct-7/attestations (annexe A.6) et outil de référence (7.4)
// ---------------------------------------------------------------------------

describe("CT-7 : vecteurs attestations/ et outil de référence (EX-A.8, EX-A.9, EX-A.17)", function () {
  this.timeout(120_000);
  const REP = path.join(CT7_VECTEURS, "attestations");

  it("exemple/ : attestation.json est l'exemple de §7.1, jcs.txt fait 3 201 octets, condense.json donne D_P, M et les signatures de §7.2", function () {
    const P = A.attestationExemple();
    expect(lireJ(REP, "exemple", "attestation.json")).to.deep.equal(P);
    const jcs = fs.readFileSync(path.join(REP, "exemple", "jcs.txt"));
    expect(jcs.length).to.equal(3201);
    expect(jcs.equals(J.octetsJCS(P))).to.equal(true);
    const c = lireJ(REP, "exemple", "condense.json");
    expect([c.digest, c.message]).to.deep.equal([valeur72("D_P"), valeur72("M")]);
    expect(c.signatures.map((s) => s.signature)).to.deep.equal([valeur72(`sig (${A.adresse(1)})`), valeur72(`sig (${A.adresse(2)})`)]);
    const r = S.verifierAttestation(fs.readFileSync(path.join(REP, "exemple", "attestation-signee.json")), lireJ(REP, "exemple", "jeu.json"));
    expect(r.retained).to.equal(true);
    expect(lireJ(REP, "constantes.json").prefix_hex).to.equal(S.PREFIXE_ATTESTATION_HEX);
  });

  it("attestations.json est conforme à #/$defs/fichier_vecteurs, porte les 18 cas d'EX-A.8, et chaque cas est rejoué à l'identique par verifierAttestation", function () {
    const f = lireJ(REP, "attestations.json");
    expect(J.validerSchema(f, SCHEMAS[S.ID_SCHEMA_ATTESTATION_PERIMETRE], { registre: SCHEMAS, fragment: "#/$defs/fichier_vecteurs" })).to.deep.equal([]);
    const table = S.tablesDe(S.texteSection(CT7, "A.6"))[0].lignes;
    expect(f.cases.map((c) => c.name)).to.deep.equal(table.map((c) => c[0].replace(/`/g, "")));
    for (const c of f.cases) {
      const r = S.verifierAttestation(c.input.signed, c.input.approver_set, { schemas: SCHEMAS });
      expect({ digest: r.digest, recovered: r.recovered, checks: r.checks, retained: r.retained }, c.name).to.deep.equal(c.expected);
      const enEchec = table.find((x) => x[0] === `\`${c.name}\``)[2];
      expect(c.expected.checks.filter((x) => x.status === "echoue").map((x) => x.id).join(", ") || "aucun", c.name).to.equal(enEchec);
    }
  });

  it("croises.json (EX-7.7, EX-A.9) : chaque signature croisée du compte 1 est refusée, et l'adresse recouvrée sur le mauvais message est celle que le fichier donne", function () {
    const f = lireJ(REP, "croises.json");
    expect(f.cases).to.have.length(7);
    const signee = lireJ(REP, "exemple", "attestation-signee.json");
    for (const c of f.cases) {
      expect(c.expected.status, c.name).to.equal("echoue");
      expect(c.expected.recovered, c.name).to.not.equal(A.adresse(1));
      if (c.presented_as === "attestation") {
        const s = structuredClone(signee);
        s.signatures[0].signature = c.signature;
        const r = S.verifierAttestation(s, A.jeuExemple(), { schemas: SCHEMAS });
        expect([r.checks[2].status, r.recovered[0]], c.name).to.deep.equal(["echoue", c.expected.recovered]);
        // La signature est bien celle du compte 1 sur son propre message.
        const octets = c.message.text !== undefined ? C.utf8(c.message.text) : C.depuisHex(c.message.digest);
        expect(C.verifierSignature(octets, c.signature, A.adresse(1)).ok, c.name).to.equal(true);
      } else if (c.presented_as === "ceremonie") {
        const pv = lireJ(CT7_VECTEURS, "ceremonies", "valide-creation-enregistreur", "proces-verbal.json");
        pv.signatures[0].signature = c.signature;
        expect(S.verifierCeremonie(J.texteJSON(pv)).failed, c.name).to.deep.equal(["CR-11"]);
      } else {
        const octets = c.target.text !== undefined ? C.utf8(c.target.text) : C.depuisHex(c.target.digest);
        const v = C.verifierSignature(octets, c.signature, A.adresse(1));
        expect([v.ok, v.recovered], c.name).to.deep.equal([false, c.expected.recovered]);
      }
    }
    expect(verifyMessage(getBytes(f.attestation_digest), f.cases.find((c) => c.name === "attestation-comme-decision").signature).toLowerCase()).to.equal(A.adresse(1));
  });

  it("outil de référence : condenser donne D_P ; verifier --forme refuse une adresse IPv4 dans host (MN-87) et une sortie directe sans not_captured, et rappelle un not_captured vide ; verifier --jeu retient l'exemple", function () {
    const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "ct7-attestation-"));
    try {
      const ecrire = (nom, v) => {
        const f = path.join(dossier, nom);
        fs.writeFileSync(f, J.texteJSON(v));
        return f;
      };
      const P = A.attestationExemple();
      const fP = ecrire("p.json", P);
      const c = spawnSync(process.execPath, [ATTESTATION_CLI, "condenser", fP], { encoding: "utf8" });
      expect([c.status, c.stdout.trim()]).to.deep.equal([0, valeur72("D_P")]);
      // Second outil indépendant (EX-7.8, EX-A.21) : le mode condenser du vérificateur Go de ct-7 donne le même D_P, si go est présent.
      if (spawnSync("go", ["version"]).status === 0) {
        const go = spawnSync("go", ["run", ".", "condenser", fP], { cwd: path.join(CT7_VECTEURS, "verificateur-independant"), encoding: "utf8" });
        expect([go.status, go.stdout.split("\n")[0]]).to.deep.equal([0, valeur72("D_P")]);
      }
      expect(spawnSync(process.execPath, [ATTESTATION_CLI, "verifier", fP, "--forme"]).status).to.equal(0);
      const ip = A.attestationExemple();
      ip.agents[0].host = "192.0.2.10"; // adresse réservée à la documentation (RFC 5737)
      const rIp = spawnSync(process.execPath, [ATTESTATION_CLI, "verifier", ecrire("ip.json", ip), "--forme"], { encoding: "utf8" });
      expect(rIp.status).to.equal(1);
      expect(rIp.stdout).to.match(/\/agents\/0\/host : adresse IP refusée/);
      expect(S.controlerDeclaration(ip).erreurs).to.have.length(1);
      // condenser et signer refusent aussi l'attestation qui porte une adresse IP (EX-7.3, MN-87).
      const fIp = path.join(dossier, "ip.json");
      expect(spawnSync(process.execPath, [ATTESTATION_CLI, "condenser", fIp], { encoding: "utf8" }).status).to.equal(1);
      const cleIp = path.join(dossier, "cle-ip.hex");
      fs.writeFileSync(cleIp, A.COMPTES[1].privateKey + "\n");
      const sIp = spawnSync(process.execPath, [ATTESTATION_CLI, "signer", fIp, "--cle", `fichier:${cleIp}`, "--oui"], { encoding: "utf8" });
      expect(sIp.status).to.equal(1);
      expect(sIp.stdout).to.not.match(/"signature"/);
      const v6 = A.attestationExemple();
      v6.egress.summary += " Passerelle 2001:db8::1.";
      expect(S.controlerDeclaration(v6).erreurs).to.have.length(1);
      const direct = A.attestationExemple();
      direct.not_captured = [];
      const cd = S.controlerDeclaration(direct);
      expect(cd.erreurs.join(" ")).to.match(/sortie directe sans ligne not_captured/);
      expect(cd.rappels).to.have.length(1);
      const secret = A.attestationExemple();
      secret.gateway_credentials[0].secret_ref = { env: "sk-ab12cd34ef56gh78ij90kl12" };
      expect(S.controlerDeclaration(secret).avertissements).to.have.length(1);
      expect(S.controlerDeclaration(P)).to.deep.equal({ erreurs: [], avertissements: [], rappels: [] });
      const fS = path.join(REP, "exemple", "attestation-signee.json");
      const fJ = path.join(REP, "exemple", "jeu.json");
      const v = spawnSync(process.execPath, [ATTESTATION_CLI, "verifier", fS, "--jeu", fJ], { encoding: "utf8" });
      expect(v.status).to.equal(0);
      expect(v.stdout).to.match(/déclaré par ses signataires, non prouvé/);
      // signer --cle fichier: produit la signature de §7.2 ; assembler redonne l'attestation signée de l'exemple.
      const cle = path.join(dossier, "cle-1.hex");
      fs.writeFileSync(cle, A.COMPTES[1].privateKey + "\n");
      const s1 = spawnSync(process.execPath, [ATTESTATION_CLI, "signer", fP, "--cle", `fichier:${cle}`, "--oui"], { encoding: "utf8" });
      expect(s1.status).to.equal(0);
      const sig1 = JSON.parse(s1.stdout.slice(s1.stdout.lastIndexOf("{\n")));
      expect(sig1).to.deep.equal({ address: A.adresse(1), signature: valeur72(`sig (${A.adresse(1)})`) });
      const f1 = ecrire("sig1.json", sig1);
      const f2 = ecrire("sig2.json", A.signature(P, 2));
      const as = spawnSync(process.execPath, [ATTESTATION_CLI, "assembler", fP, f1, f2], { encoding: "utf8" });
      expect(JSON.parse(as.stdout)).to.deep.equal(lireJ(fS));
      // Aucune connexion réseau : sous un espace de noms réseau vide, la vérification donne la même sortie.
      const unshare = spawnSync("unshare", ["-n", "true"]);
      if (unshare.status === 0) {
        const isole = spawnSync("unshare", ["-n", process.execPath, ATTESTATION_CLI, "verifier", fS, "--jeu", fJ], { encoding: "utf8" });
        expect([isole.status, isole.stdout]).to.deep.equal([0, v.stdout]);
      }
    } finally {
      fs.rmSync(dossier, { recursive: true, force: true });
    }
  });
});

describe("CT-7 : partie attestation au-delà du plafond de lecture (CT-6 EX-4.15, MN-89)", function () {
  this.timeout(120000);
  it("une partie attestation-perimetre.json de 64 Mio plus un octet (fichier creux) rend l'entrée inutilisable : code 2, taille_depassee", function () {
    const dossier = fs.mkdtempSync(path.join(os.tmpdir(), "ct7-plafond-"));
    try {
      const source = path.join(SPEC, "vecteurs", "ct-1", "dossiers", "valide-at1-taille");
      fs.cpSync(source, dossier, { recursive: true });
      const f = path.join(dossier, "attestation-perimetre.json");
      fs.truncateSync(f, 64 * 1024 * 1024 + 1);
      const r = spawnSync(process.execPath, [path.join(PROJECT_ROOT, "scripts", "verify", "dossier.mjs"), dossier], { encoding: "utf8" });
      expect(r.status).to.equal(2);
      expect(r.stdout + r.stderr).to.match(/au-delà du plafond de lecture de 67108864 octets/);
    } finally {
      fs.rmSync(dossier, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// Génération : deux exécutions identiques, fichiers publiés égaux (EX-A.2)
// ---------------------------------------------------------------------------

describe("CT-7 : générateur scripts/vecteurs/generer-ct7.mjs (EX-A.1, EX-A.2, EX-A.3)", function () {
  this.timeout(180_000);

  it("deux générations en mémoire sont identiques et égales, fichier par fichier, à spec/vecteurs/ct-7 (hors confrontation/ et verificateur-independant/)", function () {
    const a = contenuCt7();
    const b = contenuCt7();
    expect([...a.keys()]).to.deep.equal([...b.keys()]);
    for (const [k, v] of a) expect(Buffer.from(b.get(k)).equals(Buffer.from(v)), k).to.equal(true);
    const publies = [];
    const parcourir = (rep, rel = "") => {
      for (const e of fs.readdirSync(rep, { withFileTypes: true })) {
        const r = rel ? `${rel}/${e.name}` : e.name;
        if (!rel && (e.name === "confrontation" || e.name === "verificateur-independant")) continue;
        if (e.isDirectory()) parcourir(path.join(rep, e.name), r);
        else publies.push(r);
      }
    };
    parcourir(CT7_VECTEURS);
    expect(publies.sort()).to.deep.equal([...a.keys()].sort());
    for (const [k, v] of a) expect(fs.readFileSync(path.join(CT7_VECTEURS, k)).equals(Buffer.from(v)), k).to.equal(true);
  });

  it("les grilles des épreuves sont à part des consignes ; la grille de sécurité reprend la table d'EX-9.1, celle de l'administrateur celle d'EX-9.4", function () {
    for (const e of ["securite", "conformite", "attestation"]) {
      expect(fs.existsSync(path.join(CT7_VECTEURS, `acceptation-${e}`, "consigne.md")), e).to.equal(true);
      expect(fs.existsSync(path.join(CT7_VECTEURS, `acceptation-${e}-attendu.json`)), e).to.equal(true);
      expect(fs.readdirSync(path.join(CT7_VECTEURS, `acceptation-${e}`)).some((f) => f.includes("attendu")), e).to.equal(false);
    }
    const t9 = S.tablesDe(S.texteSection(CT7, "9"));
    const secu = lireJ(CT7_VECTEURS, "acceptation-securite-attendu.json");
    expect(secu.scenarios.map((s) => [s.scenario, s.threat, s.expected.join(" ; ")])).to.deep.equal(t9[0].lignes);
    const consigne = fs.readFileSync(path.join(CT7_VECTEURS, "acceptation-securite", "consigne.md"), "utf8");
    for (const s of secu.scenarios) expect(consigne, s.id).to.not.include(s.threat);
    const attn = lireJ(CT7_VECTEURS, "acceptation-attestation-attendu.json");
    expect(attn.questions).to.have.length(6);
    expect(fs.readFileSync(path.join(CT7_VECTEURS, "acceptation-attestation", "rapport.txt"), "utf8")).to.match(/Périmètre\s+: déclaré, non prouvé/);
  });
});
