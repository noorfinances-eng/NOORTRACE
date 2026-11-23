// Dossier de preuve construit au moment de l'essai avec des pièces tirées au hasard, pour éprouver le code 0 du
// vérificateur (CT-6 EX-6.26, complément du 2026-11-23 : aucun dossier publié des vecteurs ne le rend plus, chacun
// portant une clé de CT-1 §13, un compte Hardhat, une autorité de test ou le registre de développement).
//
//   import { dossierAleatoire } from "./fixtures/verificateur/dossier-aleatoire.mjs";
//   const d = dossierAleatoire();            // { fichiers, ancres, cles, variantes }
//   d.variantes.cleEnregistreurEssai()       // le même dossier, la clé d'enregistreur remplacée par rec-test-01
//   d.variantes.approbateurEssaiEnTrop()     // un troisième approbateur, compte Hardhat 1, au-dessus du seuil
//   d.variantes.autoriteEssai()              // le jeton et l'ancre d'horodatage de l'autorité de test de ct-6
//
// Les clés d'enregistreur (Ed25519), les comptes d'approbateur (secp256k1) et l'autorité d'horodatage (RSA 3072)
// viennent de crypto.randomBytes et de Wallet.createRandom : rien n'est dérivé d'une chaîne du dépôt, rien n'est écrit
// ailleurs que dans le répertoire temporaire de l'essai qui l'emploie. Le journal reprend les corps des événements 1 à 8
// du journal de référence de CT-1 (mêmes textes, mêmes pièces), re-chaînés et re-signés : l'approbation du ticket est
// signée par les comptes tirés au hasard, la période 1 est close par un manifeste de ces huit événements, et le dossier
// de l'événement 7 (l'appel approuvé) porte, en plus des sept parties de CT-1, un jeton RFC 3161 sur le periodHash,
// signé par l'autorité tirée au hasard ; le fichier d'ancres déclare cette autorité, une CRL vide et la clé
// d'enregistreur. Les cinq autres parties réservées restent absentes (hors périmètre CT-1) : contrôles 1, 2, 3, 4, 6
// et 7 réussis, 5 et 8 non exécutés pour une raison admise, aucun avertissement de pièce d'essai : code 0 attendu.
//
// Les variantes ne remplacent qu'une pièce par la pièce d'essai correspondante d'EX-6.23 : la clé de rec-test-01 est
// dérivée de sa graine publiée (spec/vecteurs/ct-1/cles/cles-test.json), le compte Hardhat 1 du mnémonique par défaut,
// l'autorité de test des clés publiées sous spec/vecteurs/ct-6/rfc3161/cles/ ; ce sont les pièces d'essai elles-mêmes.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HDNodeWallet, Wallet } from "ethers";
import * as J from "../../../scripts/lib/journal.mjs";
import * as H from "../../../scripts/lib/horodatage.mjs";
import * as R from "../../../scripts/vecteurs/ct6/rfc3161.mjs";

const RACINE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const CT1 = path.join(RACINE, "spec", "vecteurs", "ct-1");
const CLES_CT6 = path.join(RACINE, "spec", "vecteurs", "ct-6", "rfc3161", "cles");
const lireJSON = (...p) => J.analyserJSONStrict(fs.readFileSync(path.join(...p)));
const hex32 = () => "0x" + crypto.randomBytes(32).toString("hex");

/** Les sceaux (seq, hachages, signature…) retirés d'un événement du journal de référence : son corps seul. */
function sansSceau(e, keyId) {
  const o = { ...e, recorder_key_id: keyId };
  for (const k of ["version", "seq", "org_id", "journal_id", "prev_hash", "hash", "sig"]) delete o[k];
  return o;
}

/** Identifiant de clé du sujet d'un certificat : SHA-1 des octets de la clé publique (RFC 5280 §4.2.1.2, méthode 1). */
function ski(clePublique) {
  const spki = H.lireDER(clePublique.export({ type: "spki", format: "der" }));
  return crypto.createHash("sha1").update(spki.enfants[1].valeur().subarray(1)).digest();
}

/** genTime d'un jeton : cinq secondes après la fin de la période, en GeneralizedTime. */
const genTimeDe = (periodEnd) => new Date((periodEnd + 5) * 1000).toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";

/**
 * Une autorité d'horodatage et son unité, aux clés RSA 3072 tirées au hasard (la dérivation déterministe de
 * scripts/vecteurs/ct6/rfc3161.mjs reçoit une étiquette aléatoire : rien ne la rejoue). Rend les certificats DER, la
 * CRL vide et la clé de l'unité ; `sujets` nomme l'autorité et l'unité.
 */
function autoriteAleatoire() {
  const etiquette = `essai/${crypto.randomBytes(16).toString("hex")}`;
  const cleAc = R.cleRsaDepuisGraine(`${etiquette}/ac`, 3072);
  const cleTsa = R.cleRsaDepuisGraine(`${etiquette}/tsa`, 3072);
  return materiel({ cleAc, cleTsa, nomAc: "Autorité d'horodatage tirée au hasard", nomTsa: "Unité d'horodatage tirée au hasard" });
}

/**
 * Autorité et unité de test publiées de ct-6 : les certificats ac-test.pem et tsa-test.pem tels quels (EX-6.23 désigne
 * l'autorité par le SHA-256 de son DER publié), la CRL vide publiée et la clé de l'unité : la pièce d'essai elle-même.
 */
function autoriteEssai() {
  const der = (fichier) => Buffer.from(fs.readFileSync(fichier, "utf8").replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
  const cles = R.chargerCles(CLES_CT6);
  return { ac: der(path.join(CLES_CT6, "ac-test.pem")), tsa: der(path.join(CLES_CT6, "tsa-test.pem")), crl: der(path.join(CLES_CT6, "..", "crl", "crl-vide.pem")), cleTsa: cles["tsa-test"], sujetTsa: R.nom(R.SUJETS.tsa), nomAc: R.NOM_AUTORITE };
}

function materiel({ cleAc, cleTsa, nomAc, nomTsa }) {
  const pubAc = crypto.createPublicKey(cleAc);
  const pubTsa = crypto.createPublicKey(cleTsa);
  const sujetAc = R.nom({ C: "CH", O: "NOORTRACE essais", CN: nomAc });
  const sujetTsa = R.nom({ C: "CH", O: "NOORTRACE essais", CN: nomTsa });
  const skiAc = ski(pubAc);
  const OID = H.OID;
  const ac = R.construireCertificat({
    numero: 1,
    emetteur: sujetAc,
    sujet: sujetAc,
    debut: "2026-01-01T00:00:00Z",
    fin: "2036-01-01T00:00:00Z",
    clePublique: pubAc,
    cleEmetteur: cleAc,
    extensions: [
      { oid: OID.basicConstraints, critique: true, valeur: R.seq(R.bool(true)) },
      { oid: OID.keyUsage, critique: true, valeur: R.bits(Buffer.from([0x06]), 1) },
      { oid: OID.subjectKeyIdentifier, valeur: R.octets(skiAc) },
    ],
  });
  const tsa = R.construireCertificat({
    numero: 2,
    emetteur: sujetAc,
    sujet: sujetTsa,
    debut: "2026-06-01T00:00:00Z",
    fin: "2027-06-01T00:00:00Z",
    clePublique: pubTsa,
    cleEmetteur: cleAc,
    extensions: [
      { oid: OID.keyUsage, critique: true, valeur: R.bits(Buffer.from([0x80]), 7) },
      { oid: OID.extKeyUsage, critique: true, valeur: R.seq(R.oid(OID.idKpTimeStamping)) },
      { oid: OID.subjectKeyIdentifier, valeur: R.octets(ski(pubTsa)) },
      { oid: OID.authorityKeyIdentifier, valeur: R.seq(R.implicite(0, skiAc)) },
    ],
  });
  const crl = R.construireCRL({ emetteur: sujetAc, thisUpdate: R.CRL_THIS_UPDATE, nextUpdate: R.CRL_NEXT_UPDATE, numeroCrl: 1, skiEmetteur: skiAc, cleEmetteur: cleAc });
  return { ac, tsa, crl, cleTsa, sujetTsa, nomAc };
}

/** Jeton RFC 3161 sur `periodHash`, signé par l'unité de `mat`. */
function jeton(mat, manifeste, periodHash) {
  return R.construireJeton({
    empreinte: Buffer.from(periodHash.slice(2), "hex"),
    genTime: genTimeDe(manifeste.period_end),
    serie: 1,
    nonce: BigInt("0x" + crypto.randomBytes(8).toString("hex")),
    tsaNom: mat.sujetTsa,
    certificats: [mat.tsa],
    signataire: mat.tsa,
    cle: mat.cleTsa,
  });
}

/** Fichier d'ancres (ancres-confiance-v0) : l'autorité, sa CRL vide, la clé d'enregistreur ; ni Bitcoin ni registre. */
function ancres(mat, { org_id, journal_id, key_id, public_key }) {
  return {
    version: 0,
    label: "Ancres de l'essai : autorité d'horodatage et clé d'enregistreur tirées au hasard",
    prepared_by: "essai du vérificateur (test/fixtures/verificateur/dossier-aleatoire.mjs)",
    prepared_at: "2026-11-23T08:00:00.000Z",
    tsa_authorities: [{ name: mat.nomAc, certificate: H.encoderPEM(mat.ac, "CERTIFICATE"), intermediates: [], accepted_policies: [R.POLITIQUE], qualified: null, source: "autorité créée au moment de l'essai, jamais écrite" }],
    revocation: { crls: [H.encoderPEM(mat.crl, "X509 CRL")], statements: [] },
    bitcoin: null,
    registry: null,
    recorders: [{ org_id, journal_id, key_id, public_key, chain_key: null, source: "clé d'enregistreur créée au moment de l'essai, jamais écrite" }],
  };
}

/**
 * Construit le dossier. `options` : `cle` (clé Ed25519 de l'enregistreur, { clePrivee, clePublique } ; au hasard par
 * défaut), `approbateurs` (portefeuilles signataires ; deux au hasard par défaut), `membres` (adresses du jeu, trois au
 * hasard par défaut, les signataires compris), `autorite` (matériel d'horodatage ; au hasard par défaut).
 * Rend { fichiers (nom -> texte ou octets, dossier.json compris), ancres (objet), cles, approbateurs, variantes }.
 */
export function dossierAleatoire(options = {}) {
  const base = lireJSON(CT1, "journal-valide", "evenements.json").filter((e) => e.seq <= 8);
  const manifesteCT1 = lireJSON(CT1, "manifestes", "periode-1.json");
  const { org_id, journal_id } = base[0];
  // Identifiant de clé propre à ce dossier : le nom n'est pas un signe (EX-6.23), mais « rec-test-01 » ferait croire à une
  // pièce d'essai sur un écran « Valide ».
  const keyId = "rec-reel-01";
  const cle = options.cle ?? J.cleEd25519DepuisGraine(hex32());
  const signataires = options.approbateurs ?? [Wallet.createRandom(), Wallet.createRandom()];
  const membres = options.membres ?? [...signataires.map((w) => w.address.toLowerCase()), Wallet.createRandom().address.toLowerCase()];
  const mat = options.autorite ?? autoriteAleatoire();

  // Événements 1 à 5 (dont la demande retenue, seq 5), puis la décision (seq 6) et l'appel approuvé (seq 7) signés par
  // les approbateurs, puis seq 8 ; tous re-chaînés et re-signés par la clé de l'enregistreur.
  const premiers = J.chainer(base.filter((e) => e.seq <= 5).map((e) => sansSceau(e, keyId)), { org_id, journal_id, cles: { [keyId]: cle.clePrivee } });
  const demande = premiers[4];
  const decisionCT1 = base.find((e) => e.seq === 6);
  const A = { decision: "approuve", journal_id, org_id, request_hash: demande.hash, ticket: decisionCT1.approval.ticket };
  const approval = {
    ...decisionCT1.approval,
    request_hash: demande.hash,
    threshold: { required: 2, size: membres.length },
    approvers: signataires.map((w) => w.address.toLowerCase()),
    signatures: signataires.map((w) => J.signerApprobation(w, A)),
  };
  const suivants = base.filter((e) => e.seq >= 6).map((e) => {
    const corps = sansSceau(e, keyId);
    if (e.approval) corps.approval = approval;
    if (e.seq === 6) corps.execution = { ...corps.execution, arguments: J.referenceEnLigne(A) };
    return corps;
  });
  const tous = [...premiers, ...J.chainer(suivants, { org_id, journal_id, cles: { [keyId]: cle.clePrivee }, premierSeq: 6, prevHash: demande.hash })];
  const hashes = tous.map((e) => e.hash);
  const manifeste = J.construireManifeste({ org_id, journal_id, period_start: manifesteCT1.period_start, first_seq: 1, hashes, prev_period_hash: J.HASH_NUL, recorder_key_id: keyId, nonce: hex32(), generated_at: manifesteCT1.generated_at });
  const manifesteSig = J.signerManifeste(manifeste, cle.clePrivee);
  const cles = { version: 0, org_id, journal_id, keys: [{ key_id: keyId, algorithm: "ed25519", public_key: cle.clePublique, valid_from: "2026-11-01T00:00:00.000Z", valid_to: null, source: "clé créée au moment de l'essai, jamais écrite" }] };
  const ev = tous.find((e) => e.seq === 7);
  const { fichiers } = J.assemblerDossier({
    evenement: ev,
    previous: tous.find((e) => e.seq === 6),
    next: tous.find((e) => e.seq === 8),
    hashesPeriode: hashes,
    manifeste,
    manifesteSig,
    cles,
    approbations: { approver_set: { threshold: approval.threshold, members: membres, source: "comptes créés au moment de l'essai, jamais écrits" }, events: [tous.find((e) => e.seq === 6)] },
    generated_at: "2026-11-23T08:30:00.000Z",
  });
  // Le jeton d'horodatage sur le periodHash, et l'index recalculé avec cette huitième partie présente.
  const avecJeton = J.reindexerDossier({ ...fichiers, "jeton-rfc3161.der": jeton(mat, manifeste, manifesteSig.period_hash) }).fichiers;
  const variantes = {
    cleEnregistreurEssai: () => dossierAleatoire({ ...options, cle: J.cleEd25519DepuisGraine(lireJSON(CT1, "cles", "cles-test.json").keys.find((k) => k.key_id === "rec-test-01").seed), approbateurs: signataires, membres, autorite: mat }),
    approbateurEssaiEnTrop: () => {
      const hardhat = HDNodeWallet.fromPhrase("test test test test test test test test test test test junk", undefined, "m/44'/60'/0'/0/1");
      return dossierAleatoire({ ...options, cle, approbateurs: [...signataires, hardhat], membres: [...signataires.map((w) => w.address.toLowerCase()), hardhat.address.toLowerCase()], autorite: mat });
    },
    autoriteEssai: () => dossierAleatoire({ ...options, cle, approbateurs: signataires, membres, autorite: autoriteEssai() }),
  };
  return { fichiers: avecJeton, ancres: ancres(mat, { org_id, journal_id, key_id: keyId, public_key: cle.clePublique }), cles, approbateurs: signataires.map((w) => w.address.toLowerCase()), variantes };
}

/** Écrit le dossier et son fichier d'ancres sous `repertoire` (créé) ; rend { dossier, ancres } (chemins). */
export function ecrireDossier(d, repertoire) {
  const dossier = path.join(repertoire, "dossier");
  fs.mkdirSync(dossier, { recursive: true });
  for (const [f, contenu] of Object.entries(d.fichiers)) fs.writeFileSync(path.join(dossier, f), contenu);
  const ancresChemin = path.join(repertoire, "ancres.json");
  fs.writeFileSync(ancresChemin, JSON.stringify(d.ancres, null, 2) + "\n");
  return { dossier, ancres: ancresChemin };
}
