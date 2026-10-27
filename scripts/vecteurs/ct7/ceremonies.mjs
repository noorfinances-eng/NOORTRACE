// Procès-verbaux de cérémonie des vecteurs de CT-7 (annexe A.4) : l'exemple
// de CT-7 §5.10, quatre autres cas valides et les cas invalides, chacun tiré
// d'un cas valide par une seule mutation puis signé de nouveau par tous ses
// participants (sauf quand la mutation porte sur les signatures).
//
// Clés de test seulement (EX-A.1) : la clé Ed25519 rec-test-01 de CT-1 §13 ;
// les comptes Hardhat 1 à 8 du mnémonique public de
// spec/vecteurs/ct-3/constantes.json (chemin m/44'/60'/0'/0/i), lus et jamais
// réécrits. Les empreintes du script, de l'image du poste, des
// enregistrements et des preuves d'origine sont le SHA-256 d'étiquettes
// « noortrace/vecteurs/ct7/… ». Un procès-verbal réel ne porte jamais une clé
// de cles-de-test.json (EX-4.10).

import fs from "node:fs";
import path from "node:path";
import { HDNodeWallet, SigningKey } from "ethers";
import { PROJECT_ROOT } from "../../lib/noortrace.mjs";
import * as J from "../../lib/journal.mjs";
import * as C from "../../lib/console.mjs";
import * as S from "../../lib/securite.mjs";

const CT3 = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-3", "constantes.json"), "utf8"));
const CLES_CT1 = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-1", "cles", "cles-test.json"), "utf8"));

/** Comptes Hardhat 1 à 8 : { cle (hexadécimal 0x), adresse, publique (65 octets non compressés) }. */
export const COMPTES = Object.freeze(
  Object.fromEntries(
    [1, 2, 3, 4, 5, 6, 7, 8].map((i) => {
      const w = HDNodeWallet.fromPhrase(CT3.mnemonic, undefined, `m/44'/60'/0'/0/${i}`);
      return [i, Object.freeze({ cle: w.privateKey, adresse: w.address.toLowerCase(), publique: SigningKey.computePublicKey(w.privateKey, false).toLowerCase() })];
    }),
  ),
);

/** Clé publique Ed25519 de rec-test-01 (CT-1 §13). */
export const PUB_REC_TEST_01 = CLES_CT1.keys.find((k) => k.key_id === "rec-test-01").public_key;
/** D_A de la décision apr-1192 de CT-1 §6.4 (cas invalide-cr11-signature-d-une-decision). */
export const D_A_APR_1192 = "0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7";

/** SHA-256 de l'étiquette « noortrace/vecteurs/ct7/<suffixe> ». */
export const empreinte = (suffixe) => J.sha256(Buffer.from(`noortrace/vecteurs/ct7/${suffixe}`, "utf8"));
const sha = (hex) => J.sha256(C.depuisHex(hex));
const AUCUNE = Object.freeze({ scheme: "aucune", k: null, n: null, holders: [] });
const participant = (id, name, role, affiliation, compte) => ({ id, name, role, affiliation, address: COMPTES[compte].adresse });
const etape = (n, action, performed_by, witnessed_by, at, outcome = "fait") => ({ n, action, performed_by, witnessed_by, at, outcome });
const cleSecp = (key_id, usage, compte, custody_class, backup = AUCUNE) => ({ key_id, usage, algorithm: "secp256k1", generated_in: "module", custody_class, backend: "pkcs11", public_key: COMPTES[compte].publique, fingerprint: sha(COMPTES[compte].publique), address: COMPTES[compte].adresse, origin_proof_sha256: null, backup: structuredClone(backup) });
const cleApprobateur = (compte) => ({ key_id: `approbateur-compte-${compte}`, usage: "approbateur", algorithm: "secp256k1", generated_in: "detenteur", custody_class: "sans_objet", backend: "portefeuille du membre", public_key: null, fingerprint: null, address: COMPTES[compte].adresse, origin_proof_sha256: null, backup: structuredClone(AUCUNE) });

/** Le procès-verbal de l'exemple de CT-7 §5.10, sans signatures. */
export function pvExemple() {
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-02-sinistres-01",
    scope: "client",
    organization: { name: "assureur-demo", org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab" },
    purpose: "creation",
    purpose_details: null,
    environment: "production",
    place: "Salle de cérémonie, site principal (exemple)",
    started_at: "2026-11-02T08:00:00.000Z",
    ended_at: "2026-11-02T09:10:00.000Z",
    script: { title: "Création de la clé de l'enregistreur et de sa clé de chaîne", version: "1", sha256: empreinte("script/creation-enregistreur-v1") },
    workstation: { description: "Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées", offline: true, image_sha256: empreinte("image-poste/v1") },
    entropy: { source: "module", description: "Générateur aléatoire du module ; aucune valeur saisie" },
    participants: [participant("p1", "Officiant (compte de test 1)", "officiant", "assureur-demo, exploitation", 1), participant("p2", "Témoin (compte de test 2)", "temoin", "assureur-demo, sécurité", 2), participant("p3", "Auditeur (compte de test 4)", "auditeur", "cabinet d'audit (exemple)", 4)],
    steps: [
      etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2", "p3"], "2026-11-02T08:02:00.000Z"),
      etape(2, "Vérifier les scellés du module, démarrer le poste sur l'image dont le SHA-256 est inscrit, constater l'absence de réseau", "p1", ["p2"], "2026-11-02T08:10:00.000Z"),
      etape(3, "Générer dans le module la clé Ed25519 rec-test-01, non exportable", "p1", ["p2"], "2026-11-02T08:21:00.000Z"),
      etape(4, "Lire la clé publique Ed25519, calculer son SHA-256 et l'afficher à tous", "p1", ["p2", "p3"], "2026-11-02T08:24:00.000Z"),
      etape(5, "Générer dans le module la clé de chaîne secp256k1, signer un condensé d'essai et recouvrer l'adresse", "p1", ["p2"], "2026-11-02T08:35:00.000Z", "exception"),
      etape(6, "Remettre au démon la seule identité d'usage : ni export, ni suppression, ni changement de politique", "p1", ["p2"], "2026-11-02T08:48:00.000Z"),
      etape(7, "Exporter l'attestation du module (preuve d'origine) et calculer son SHA-256", "p1", ["p2", "p3"], "2026-11-02T08:55:00.000Z"),
      etape(8, "Arrêter l'enregistrement vidéo, calculer les SHA-256 des enregistrements et des journaux", "p1", ["p2", "p3"], "2026-11-02T09:05:00.000Z"),
    ],
    keys: [
      { key_id: "rec-test-01", usage: "enregistreur", algorithm: "ed25519", generated_in: "module", custody_class: "A", backend: "pkcs11", public_key: PUB_REC_TEST_01, fingerprint: sha(PUB_REC_TEST_01), address: null, origin_proof_sha256: empreinte("preuve-origine/rec-test-01"), backup: structuredClone(AUCUNE) },
      cleSecp("chaine-test-03", "chaine", 3, "A"),
    ],
    records: [
      { kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/camera-1") },
      { kind: "journal_module", name: "journal-module.txt", sha256: empreinte("enregistrement/journal-module") },
      { kind: "preuve_origine", name: "attestation-rec-test-01.der", sha256: empreinte("preuve-origine/rec-test-01") },
    ],
    findings: [{ n: 1, step: 5, kind: "ecart", text: "Le premier condensé d'essai a été signé avec la mauvaise étiquette de clé ; signature écartée, étape refaite sur l'étiquette prévue.", resolution: "Étape 5 refaite à 08:41 ; adresse recouvrée égale à l'adresse déclarée." }],
  };
}
/** Comptes des participants de l'exemple. */
const COMPTES_EXEMPLE = { p1: 1, p2: 2, p3: 4 };

function pvInscriptionMembres() {
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-03-membres-01",
    scope: "client",
    organization: { name: "assureur-demo", org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab" },
    purpose: "inscription_membres",
    purpose_details: null,
    environment: "production",
    place: "Salle de réunion, site principal (exemple)",
    started_at: "2026-11-03T14:00:00.000Z",
    ended_at: "2026-11-03T14:40:00.000Z",
    script: { title: "Inscription des membres du jeu d'approbateurs", version: "1", sha256: empreinte("script/inscription-membres-v1") },
    workstation: { description: "Aucune clé générée en cérémonie : chaque clé naît dans le portefeuille de son membre", offline: false, image_sha256: null },
    entropy: { source: "detenteur", description: "Chaque membre a généré sa clé dans son portefeuille, avant la cérémonie" },
    participants: [participant("p1", "Officiant (compte de test 1)", "officiant", "assureur-demo, exploitation", 1), participant("p2", "Témoin (compte de test 2)", "temoin", "assureur-demo, sécurité", 2), participant("p3", "Membre (compte de test 5)", "membre", "assureur-demo, sinistres", 5), participant("p4", "Membre (compte de test 6)", "membre", "assureur-demo, conformité", 6)],
    steps: [
      etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2"], "2026-11-03T14:02:00.000Z"),
      etape(2, "Le témoin constate l'identité du membre p3 sur une pièce d'identité ; le membre lit son adresse dans son portefeuille ; l'officiant l'inscrit", "p1", ["p2"], "2026-11-03T14:10:00.000Z"),
      etape(3, "Le témoin constate l'identité du membre p4 sur une pièce d'identité ; le membre lit son adresse dans son portefeuille ; l'officiant l'inscrit", "p1", ["p2"], "2026-11-03T14:18:00.000Z"),
      etape(4, "Écrire le procès-verbal ; chaque participant recalcule D_C sur son poste et signe", "p1", ["p2"], "2026-11-03T14:35:00.000Z"),
    ],
    keys: [cleApprobateur(5), cleApprobateur(6)],
    records: [{ kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/inscription-membres/camera-1") }],
    findings: [],
  };
}
const COMPTES_MEMBRES = { p1: 1, p2: 2, p3: 5, p4: 6 };

function pvSauvegardeAdministrateurRegistre() {
  const partage = { scheme: "partage_k_sur_n", k: 2, n: 3, holders: ["p3", "p4", "p5"] };
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-04-admin-registre-01",
    scope: "exploitant",
    organization: { name: "NOORTRACE, exploitant du registre (exemple)", org_id: null },
    purpose: "sauvegarde",
    purpose_details: null,
    environment: "production",
    place: "Salle forte de l'exploitant (exemple)",
    started_at: "2026-11-04T09:00:00.000Z",
    ended_at: "2026-11-04T10:30:00.000Z",
    script: { title: "Sauvegarde partagée de la clé de l'administrateur du registre", version: "1", sha256: empreinte("script/sauvegarde-administrateur-registre-v1") },
    workstation: { description: "Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées", offline: true, image_sha256: empreinte("image-poste/v1") },
    entropy: { source: "module", description: "Générateur aléatoire du module ; aucune valeur saisie" },
    participants: [participant("p1", "Officiant de l'exploitant (compte de test 8)", "officiant", "NOORTRACE, exploitation", 8), participant("p2", "Témoin (compte de test 1)", "temoin", "NOORTRACE, sécurité", 1), participant("p3", "Détenteur de part (compte de test 5)", "detenteur_part", "NOORTRACE, site principal", 5), participant("p4", "Détenteur de part (compte de test 6)", "detenteur_part", "NOORTRACE, site de secours", 6), participant("p5", "Détenteur de part (compte de test 7)", "detenteur_part", "NOORTRACE, direction", 7)],
    steps: [
      etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2"], "2026-11-04T09:03:00.000Z"),
      etape(2, "Vérifier les scellés du module, démarrer le poste sur l'image dont le SHA-256 est inscrit, constater l'absence de réseau", "p1", ["p2"], "2026-11-04T09:12:00.000Z"),
      etape(3, "Générer dans le module la clé d'enveloppe AES-256", "p1", ["p2"], "2026-11-04T09:25:00.000Z"),
      etape(4, "Chiffrer la clé de l'administrateur du registre sous la clé d'enveloppe", "p1", ["p2"], "2026-11-04T09:36:00.000Z"),
      etape(5, "Partager la clé d'enveloppe en trois parts, dont deux la reconstituent", "p1", ["p2"], "2026-11-04T09:50:00.000Z"),
      etape(6, "Remettre chaque part à son détenteur, sous sac à témoin d'effraction", "p1", ["p2"], "2026-11-04T10:05:00.000Z"),
      etape(7, "Arrêter l'enregistrement vidéo, calculer les SHA-256 des enregistrements et des journaux", "p1", ["p2"], "2026-11-04T10:20:00.000Z"),
    ],
    keys: [
      cleSecp("administrateur-registre-test-03", "administrateur_registre", 3, "A", partage),
      { key_id: "enveloppe-administrateur-registre-01", usage: "enveloppe", algorithm: "aes256", generated_in: "module", custody_class: "A", backend: "pkcs11", public_key: null, fingerprint: null, address: null, origin_proof_sha256: null, backup: structuredClone(partage) },
    ],
    records: [
      { kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/sauvegarde/camera-1") },
      { kind: "journal_module", name: "journal-module.txt", sha256: empreinte("enregistrement/sauvegarde/journal-module") },
    ],
    findings: [{ n: 1, step: 6, kind: "observation", text: "Parts remises sous les sacs à témoin d'effraction numéros 0001 (p3), 0002 (p4) et 0003 (p5) (exemple).", resolution: null }],
  };
}
const COMPTES_SAUVEGARDE = { p1: 8, p2: 1, p3: 5, p4: 6, p5: 7 };

function pvChangementAdministrateur() {
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-06-gouvernance-01",
    scope: "client",
    organization: { name: "assureur-demo", org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab" },
    purpose: "changement_administrateur",
    purpose_details: { approver_set_hash: empreinte("jeu-approbateurs/assureur-demo"), required: 2 },
    environment: "production",
    place: "Salle de cérémonie, site principal (exemple)",
    started_at: "2026-11-06T10:00:00.000Z",
    ended_at: "2026-11-06T11:00:00.000Z",
    script: { title: "Changement d'administrateur du jeu sur perte de la clé de gouvernance", version: "1", sha256: empreinte("script/changement-administrateur-v1") },
    workstation: { description: "Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées", offline: true, image_sha256: empreinte("image-poste/v1") },
    entropy: { source: "module", description: "Générateur aléatoire du module ; aucune valeur saisie" },
    participants: [participant("p1", "Officiant de l'exploitant (compte de test 8)", "officiant", "NOORTRACE, exploitation", 8), participant("p2", "Témoin (compte de test 4)", "temoin", "assureur-demo, sécurité", 4), participant("p3", "Membre présent (compte de test 1)", "membre", "assureur-demo, sinistres", 1), participant("p4", "Membre présent (compte de test 2)", "membre", "assureur-demo, conformité", 2)],
    steps: [
      etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2"], "2026-11-06T10:02:00.000Z"),
      etape(2, "Lire sur la chaîne le jeu en vigueur et constater que les membres présents en sont, au moins au seuil", "p1", ["p2"], "2026-11-06T10:12:00.000Z"),
      etape(3, "Générer dans le module la nouvelle clé de gouvernance et lire son adresse", "p1", ["p2"], "2026-11-06T10:25:00.000Z"),
      etape(4, "Écrire le procès-verbal ; chaque participant recalcule D_C sur son poste et signe", "p1", ["p2"], "2026-11-06T10:50:00.000Z"),
    ],
    keys: [cleApprobateur(1), cleApprobateur(2), cleSecp("gouvernance-test-07", "gouvernance", 7, "A")],
    records: [{ kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/gouvernance/camera-1") }],
    findings: [],
  };
}
const COMPTES_GOUVERNANCE = { p1: 8, p2: 4, p3: 1, p4: 2 };

function pvDeveloppement() {
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-01-developpement-01",
    scope: "client",
    organization: { name: "assureur-demo", org_id: "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab" },
    purpose: "creation",
    purpose_details: null,
    environment: "developpement",
    place: "Poste de développement (exemple)",
    started_at: "2026-11-01T07:00:00.000Z",
    ended_at: "2026-11-01T07:20:00.000Z",
    script: { title: "Création d'une clé d'enregistreur de développement", version: "0", sha256: null },
    workstation: { description: "Poste de développement, en ligne", offline: false, image_sha256: null },
    entropy: { source: "systeme_du_poste", description: "Générateur aléatoire du système du poste" },
    participants: [participant("p1", "Officiant (compte de test 1)", "officiant", "assureur-demo, développement", 1), participant("p2", "Témoin (compte de test 2)", "temoin", "assureur-demo, développement", 2)],
    steps: [
      etape(1, "Générer sur le poste la graine Ed25519 de la clé de développement", "p1", ["p2"], "2026-11-01T07:05:00.000Z"),
      etape(2, "Écrire la graine dans un fichier de mode 0600 (classe D)", "p1", ["p2"], "2026-11-01T07:08:00.000Z"),
      etape(3, "Lire la clé publique, calculer son SHA-256 et l'afficher", "p1", ["p2"], "2026-11-01T07:12:00.000Z"),
    ],
    keys: [{ key_id: "rec-test-01", usage: "enregistreur", algorithm: "ed25519", generated_in: "poste", custody_class: "D", backend: "fichier", public_key: PUB_REC_TEST_01, fingerprint: sha(PUB_REC_TEST_01), address: null, origin_proof_sha256: null, backup: structuredClone(AUCUNE) }],
    records: [],
    findings: [],
  };
}
const COMPTES_DEV = { p1: 1, p2: 2 };

/**
 * Restauration, en production, de la sauvegarde partagée de
 * valide-sauvegarde-administrateur-registre : deux détenteurs de part sur
 * trois, un officiant et un témoin (EX-5.5, CR-12). `D_C_sauvegarde` : le
 * condensé du procès-verbal de la sauvegarde restaurée.
 */
function pvRestauration(D_C_sauvegarde) {
  return {
    version: 0,
    kind: "ceremonie-cles",
    ceremony_id: "cer-2026-11-20-admin-registre-restauration-01",
    scope: "exploitant",
    organization: { name: "NOORTRACE, exploitant du registre (exemple)", org_id: null },
    purpose: "restauration",
    purpose_details: { backup_ceremony_digest: D_C_sauvegarde, k: 2, n: 3 },
    environment: "production",
    place: "Salle forte de l'exploitant (exemple)",
    started_at: "2026-11-20T09:00:00.000Z",
    ended_at: "2026-11-20T10:00:00.000Z",
    script: { title: "Restauration de la clé de l'administrateur du registre depuis sa sauvegarde partagée", version: "1", sha256: empreinte("script/restauration-administrateur-registre-v1") },
    workstation: { description: "Poste d'administration du module, démarré sur support en lecture seule, interfaces réseau désactivées ; support effacé à la fin de la cérémonie", offline: true, image_sha256: empreinte("image-poste/v1") },
    entropy: { source: "sans_objet", description: "Aucune clé générée : la clé est reconstituée depuis sa sauvegarde" },
    participants: [participant("p1", "Officiant de l'exploitant (compte de test 8)", "officiant", "NOORTRACE, exploitation", 8), participant("p2", "Témoin (compte de test 1)", "temoin", "NOORTRACE, sécurité", 1), participant("p3", "Détenteur de part (compte de test 5)", "detenteur_part", "NOORTRACE, site principal", 5), participant("p4", "Détenteur de part (compte de test 6)", "detenteur_part", "NOORTRACE, site de secours", 6)],
    steps: [
      etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2"], "2026-11-20T09:03:00.000Z"),
      etape(2, "Le témoin constate l'identité de chaque détenteur de part et l'intégrité de chaque sac à témoin d'effraction", "p1", ["p2"], "2026-11-20T09:12:00.000Z"),
      etape(3, "Reconstituer la clé d'enveloppe avec les parts de p3 et p4 dans le module", "p1", ["p2"], "2026-11-20T09:25:00.000Z"),
      etape(4, "Déchiffrer dans le module la clé de l'administrateur du registre et lire son adresse", "p1", ["p2"], "2026-11-20T09:36:00.000Z"),
      etape(5, "Remettre les parts sous sacs neufs ; effacer le support du poste", "p1", ["p2"], "2026-11-20T09:50:00.000Z"),
    ],
    keys: [],
    records: [{ kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/restauration/camera-1") }],
    findings: [{ n: 1, step: 5, kind: "observation", text: "Parts de p3 et p4 remises sous les sacs neufs numéros 0004 et 0005 ; adresse lue à l'étape 4 égale à celle de la sauvegarde (exemple).", resolution: null }],
  };
}
const COMPTES_RESTAURATION = { p1: 8, p2: 1, p3: 5, p4: 6 };

/** Rotation d'urgence de la clé de chaîne de l'exemple (exercice d'EX-3.12) : instants de la décision et de l'inclusion de la révocation. */
function pvRotationUrgence() {
  const pv = pvExemple();
  pv.ceremony_id = "cer-2026-11-12-sinistres-urgence-01";
  pv.purpose = "rotation_urgence";
  pv.purpose_details = { decided_at: "2026-11-12T07:40:00.000Z", revocation_included_at: "2026-11-12T07:52:00.000Z" };
  pv.started_at = "2026-11-12T08:00:00.000Z";
  pv.ended_at = "2026-11-12T08:40:00.000Z";
  pv.script = { title: "Rotation d'urgence de la clé de chaîne de l'enregistreur", version: "1", sha256: empreinte("script/rotation-urgence-v1") };
  pv.steps = [
    etape(1, "Lire le script à voix haute et comparer son SHA-256 à celui publié avant la cérémonie", "p1", ["p2"], "2026-11-12T08:02:00.000Z"),
    etape(2, "Générer dans le module la nouvelle clé de chaîne secp256k1, signer un condensé d'essai et recouvrer l'adresse", "p1", ["p2", "p3"], "2026-11-12T08:15:00.000Z"),
    etape(3, "Remettre au démon la seule identité d'usage de la nouvelle clé", "p1", ["p2"], "2026-11-12T08:30:00.000Z"),
  ];
  pv.keys = [cleSecp("chaine-test-07", "chaine", 7, "A")];
  pv.records = [{ kind: "video", name: "camera-1.mp4", sha256: empreinte("enregistrement/rotation-urgence/camera-1") }];
  pv.findings = [{ n: 1, step: null, kind: "observation", text: "Révocation de l'ancienne clé de chaîne incluse 12 minutes après la décision ; délai mesuré inscrit dans purpose_details (exemple).", resolution: null }];
  return pv;
}

/** Clés privées des participants d'un procès-verbal (identifiant → clé). */
const cles = (comptes) => Object.fromEntries(Object.entries(comptes).map(([p, i]) => [p, COMPTES[i].cle]));
const texte = (pv) => J.texteJSON(pv);

/** Signature de forme non canonique : s remplacé par n − s, v basculé. */
export function formeHaute(sig) {
  const s = BigInt("0x" + sig.slice(66, 130));
  return sig.slice(0, 66) + (C.N_SECP256K1 - s).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
}

/**
 * Les cas de ceremonies/ (CT-7 annexe A.4), dans l'ordre de la table :
 * [{ nom, mutation, octets (texte du procès-verbal publié), echecs (CR- en
 * échec attendues) }]. Le générateur contrôle que verifierCeremonie rend
 * exactement `echecs`.
 */
export function casCeremonies() {
  const out = [];
  const valide = (nom, mutation, pv, comptes) => out.push({ nom, mutation, octets: texte(S.signerCeremonie(pv, cles(comptes))), echecs: [] });
  /** Cas tiré de `base` par `modifier`, signé de nouveau par tous ses participants (comptes : identifiant → numéro de compte). */
  const mute = (nom, mutation, echecs, base, comptes, modifier) => {
    const pv = base();
    const c = { ...comptes };
    modifier(pv, c);
    out.push({ nom, mutation, octets: texte(S.signerCeremonie(pv, cles(c))), echecs });
  };
  /** Cas dont la mutation porte sur les signatures de l'exemple signé. */
  const signe = (nom, mutation, modifier) => {
    const pv = S.signerCeremonie(pvExemple(), cles(COMPTES_EXEMPLE));
    modifier(pv);
    out.push({ nom, mutation, octets: texte(pv), echecs: ["CR-11"] });
  };
  const exemple = texte(S.signerCeremonie(pvExemple(), cles(COMPTES_EXEMPLE)));

  out.push({ nom: "valide-creation-enregistreur", mutation: "exemple de CT-7 §5.10 : création, en production, de la clé de l'enregistreur rec-test-01 (classe A) et de sa clé de chaîne (compte 3) ; officiant, témoin, auditeur : comptes 1, 2, 4 ; écart consigné à l'étape 5", octets: exemple, echecs: [] });
  valide("valide-inscription-membres", "production ; officiant et témoin (comptes 1 et 2), membres (comptes 5 et 6), clés d'approbateur réduites à l'adresse, vidéo", pvInscriptionMembres(), COMPTES_MEMBRES);
  valide("valide-sauvegarde-administrateur-registre", "portée exploitant, org_id nul ; clé administrateur_registre de classe A (compte 3) et clé d'enveloppe, partage 2 sur 3 (détenteurs : comptes 5 à 7) ; officiant de l'exploitant (compte 8)", pvSauvegardeAdministrateurRegistre(), COMPTES_SAUVEGARDE);
  valide("valide-changement-administrateur", "membres présents du jeu (comptes 1 et 2), nouvelle clé de gouvernance de classe A (compte 7), officiant de l'exploitant (compte 8), témoin (compte 4)", pvChangementAdministrateur(), COMPTES_GOUVERNANCE);
  const D_C_sauvegarde = S.condenseCeremonie(pvSauvegardeAdministrateurRegistre());
  valide("valide-restauration-administrateur-registre", "restauration, en production, de la sauvegarde de valide-sauvegarde-administrateur-registre (purpose_details : son D_C, k = 2, n = 3) : officiant (compte 8), témoin (compte 1), deux détenteurs de part (comptes 5 et 6), aucune clé produite", pvRestauration(D_C_sauvegarde), COMPTES_RESTAURATION);
  valide("valide-rotation-urgence-chaine", "rotation d'urgence de la clé de chaîne de l'exemple, en production : purpose_details avec la décision (07:40) et l'inclusion de la révocation (07:52), nouvelle clé de chaîne (compte 7) ; officiant, témoin, auditeur : comptes 1, 2, 4", pvRotationUrgence(), COMPTES_EXEMPLE);
  valide("valide-developpement-classe-d", "développement, clé enregistreur de classe D générée sur le poste, script sans empreinte, sans vidéo ni auditeur", pvDeveloppement(), COMPTES_DEV);

  out.push({ nom: "invalide-cr1-cle-en-double", mutation: "texte JSON de l'exemple signé avec le membre version en double", octets: exemple.replace('{\n  "version": 0,', '{\n  "version": 0,\n  "version": 0,'), echecs: ["CR-1"] });
  out.push({ nom: "invalide-cr1-nombre-non-entier", mutation: "texte JSON de l'exemple signé où version vaut 0.0", octets: exemple.replace('{\n  "version": 0,', '{\n  "version": 0.0,'), echecs: ["CR-1"] });
  mute("invalide-cr1-schema", "membre place retiré", ["CR-1"], pvExemple, COMPTES_EXEMPLE, (pv) => delete pv.place);
  mute("invalide-cr2-un-seul-participant", "seul l'officiant ; les étapes restent témoignées par p2 et p3, qui ne sont plus participants : CR-4 échoue aussi, une seule personne ne pouvant témoigner d'aucune étape (table d'A.4)", ["CR-2", "CR-4"], pvExemple, COMPTES_EXEMPLE, (pv, c) => {
    pv.participants = pv.participants.slice(0, 1);
    delete c.p2;
    delete c.p3;
  });
  mute("invalide-cr2-deux-officiants", "le témoin p2 devient officiant ; un second témoin p4 (compte 5) le remplace dans chaque étape", ["CR-2"], pvExemple, COMPTES_EXEMPLE, (pv, c) => {
    pv.participants[1].role = "officiant";
    pv.participants.push(participant("p4", "Témoin (compte de test 5)", "temoin", "assureur-demo, sécurité", 5));
    for (const st of pv.steps) st.witnessed_by = st.witnessed_by.map((w) => (w === "p2" ? "p4" : w));
    c.p4 = 5;
  });
  mute("invalide-cr2-adresse-en-double", "l'auditeur p3 a l'adresse du témoin (et signe avec sa clé)", ["CR-2"], pvExemple, COMPTES_EXEMPLE, (pv, c) => {
    pv.participants[2].address = COMPTES[2].adresse;
    c.p3 = 2;
  });
  mute("invalide-cr2-auditeur-executant", "l'étape 2 est exécutée par l'auditeur p3", ["CR-2"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.steps[1].performed_by = "p3"));
  mute("invalide-cr3-etape-avant-le-debut", "at de la première étape avant started_at", ["CR-3"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.steps[0].at = "2026-11-02T07:59:00.000Z"));
  mute("invalide-cr3-numerotation", "les deux dernières étapes numérotées 7", ["CR-3"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.steps[7].n = 7));
  mute("invalide-cr4-temoin-de-lui-meme", "l'officiant p1 parmi les témoins de son étape 2", ["CR-4"], pvExemple, COMPTES_EXEMPLE, (pv) => pv.steps[1].witnessed_by.push("p1"));
  mute("invalide-cr4-temoin-auditeur-seul", "chaque étape est témoignée par le seul auditeur p3 : aucun témoin de rôle temoin", ["CR-4"], pvExemple, COMPTES_EXEMPLE, (pv) => {
    for (const st of pv.steps) st.witnessed_by = ["p3"];
  });
  mute("invalide-cr4-exception-sans-constat", "findings vide alors que l'étape 5 est en exception", ["CR-4"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.findings = []));
  mute("invalide-cr5-empreinte-fausse", "fingerprint de la clé Ed25519 remplacée par le SHA-256 d'une étiquette", ["CR-5"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.keys[0].fingerprint = empreinte("empreinte-fausse")));
  mute("invalide-cr5-adresse-de-chaine", "address de la clé de chaîne remplacée par celle du compte 1", ["CR-5"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.keys[1].address = COMPTES[1].adresse));
  mute("invalide-cr5-ed25519-33-octets", "clé publique Ed25519 de 33 octets (octet nul ajouté), empreinte recalculée", ["CR-5"], pvExemple, COMPTES_EXEMPLE, (pv) => {
    pv.keys[0].public_key += "00";
    pv.keys[0].fingerprint = sha(pv.keys[0].public_key);
  });
  mute("invalide-cr6-classe-d-en-production", "clé enregistreur en classe D, en production", ["CR-6"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.keys[0].custody_class = "D"));
  mute("invalide-cr6-administrateur-registre-classe-b", "clé administrateur_registre en classe B (cas valide-sauvegarde-administrateur-registre)", ["CR-6"], pvSauvegardeAdministrateurRegistre, COMPTES_SAUVEGARDE, (pv) => (pv.keys[0].custody_class = "B"));
  mute("invalide-cr7-sauvegarde-enregistreur", "partage 2 sur 2 de la clé enregistreur entre deux détenteurs de part ajoutés (comptes 5 et 6)", ["CR-7"], pvExemple, COMPTES_EXEMPLE, (pv, c) => {
    pv.participants.push(participant("p4", "Détenteur de part (compte de test 5)", "detenteur_part", "assureur-demo, site principal", 5), participant("p5", "Détenteur de part (compte de test 6)", "detenteur_part", "assureur-demo, site de secours", 6));
    pv.keys[0].backup = { scheme: "partage_k_sur_n", k: 2, n: 2, holders: ["p4", "p5"] };
    c.p4 = 5;
    c.p5 = 6;
  });
  mute("invalide-cr7-k-superieur-a-n", "partage de la clé d'enveloppe avec k = 3 et n = 2 (cas valide-sauvegarde-administrateur-registre)", ["CR-7"], pvSauvegardeAdministrateurRegistre, COMPTES_SAUVEGARDE, (pv) => (pv.keys[1].backup = { scheme: "partage_k_sur_n", k: 3, n: 2, holders: ["p3", "p4"] }));
  mute("invalide-cr8-membre-sans-cle", "un membre p5 (compte 7) sans clé approbateur (cas valide-inscription-membres)", ["CR-8"], pvInscriptionMembres, COMPTES_MEMBRES, (pv, c) => {
    pv.participants.push(participant("p5", "Membre (compte de test 7)", "membre", "assureur-demo, finances", 7));
    c.p5 = 7;
  });
  mute("invalide-cr9-sans-video-ni-auditeur", "production sans enregistrement vidéo ni auditeur (cas valide-inscription-membres, vidéo retirée)", ["CR-9"], pvInscriptionMembres, COMPTES_MEMBRES, (pv) => (pv.records = []));
  mute("invalide-cr9-poste-en-ligne", "clé enregistreur générée sur le poste (generated_in poste), poste en ligne (offline faux)", ["CR-9"], pvExemple, COMPTES_EXEMPLE, (pv) => {
    pv.keys[0].generated_in = "poste";
    pv.workstation.offline = false;
  });
  mute("invalide-cr10-incident-sans-resolution", "le constat 1 devient un incident sans résolution", ["CR-10"], pvExemple, COMPTES_EXEMPLE, (pv) => {
    pv.findings[0].kind = "incident";
    pv.findings[0].resolution = null;
  });
  mute("invalide-cr12-details-inattendus", "purpose_details d'une révocation (tx_hash) sur un procès-verbal de création", ["CR-12"], pvExemple, COMPTES_EXEMPLE, (pv) => (pv.purpose_details = { tx_hash: empreinte("transaction-fictive") }));
  mute("invalide-cr12-creation-sans-cle", "création sans aucune clé (keys vide)", ["CR-12"], pvDeveloppement, COMPTES_DEV, (pv) => (pv.keys = []));
  mute("invalide-cr12-restauration-sans-detenteur", "restauration avec le seul officiant et le seul témoin : les détenteurs p3 et p4 sont retirés (cas valide-restauration-administrateur-registre)", ["CR-12"], () => pvRestauration(D_C_sauvegarde), COMPTES_RESTAURATION, (pv, c) => {
    pv.participants = pv.participants.slice(0, 2);
    delete c.p3;
    delete c.p4;
  });
  mute("invalide-cr12-urgence-ordre", "decided_at postérieur à revocation_included_at (cas valide-rotation-urgence-chaine)", ["CR-12"], pvRotationUrgence, COMPTES_EXEMPLE, (pv) => (pv.purpose_details = { decided_at: "2026-11-12T07:55:00.000Z", revocation_included_at: "2026-11-12T07:52:00.000Z" }));
  mute("invalide-cr12-administrateur-sous-seuil", "jeu en vigueur au seuil de 3 avec deux membres présents (cas valide-changement-administrateur)", ["CR-12"], pvChangementAdministrateur, COMPTES_GOUVERNANCE, (pv) => (pv.purpose_details.required = 3));
  signe("invalide-cr11-signature-manquante", "signature de l'auditeur p3 retirée", (pv) => pv.signatures.splice(2, 1));
  signe("invalide-cr11-autre-proces-verbal", "action de l'étape 3 modifiée après signature", (pv) => (pv.steps[2].action += " (modifié après signature)"));
  signe("invalide-cr11-s-haut", "signature du témoin en forme s haut (n − s, v basculé)", (pv) => (pv.signatures[1].signature = formeHaute(pv.signatures[1].signature)));
  signe("invalide-cr11-signature-d-une-decision", "le témoin (compte 2) a signé le D_A de la décision apr-1192 de CT-1 §6.4 au lieu de D_C", (pv) => (pv.signatures[1].signature = C.signerHachage(C.depuisHex(COMPTES[2].cle), C.condenseEIP191(C.depuisHex(D_A_APR_1192)))));
  signe("invalide-cr11-signataire-substitue", "la signature du témoin est faite par le compte 3", (pv) => (pv.signatures[1].signature = C.signerHachage(C.depuisHex(COMPTES[3].cle), C.depuisHex(S.messageCeremonie(S.condenseCeremonie(pv))))));
  return out;
}
