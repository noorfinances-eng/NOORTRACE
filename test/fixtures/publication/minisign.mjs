// Signature et vérification au format de minisign (CT-6 EX-14.9, CT-8
// EX-3.14), écrites avec le seul module crypto de Node.js (Ed25519 et
// BLAKE2b-512), sans dépendance : elles servent aux essais de la publication
// préparée, où aucune clé réelle n'existe et où minisign n'est pas installé.
//
// Format (documentation de minisign, signatures « préhachées », algorithme
// « ED », celui qu'écrit minisign par défaut) :
//
//   clé publique   untrusted comment: minisign public key <ID>
//                  base64("Ed" ‖ id (8 octets) ‖ clé Ed25519 (32 octets))
//   signature      untrusted comment: <texte>
//                  base64("ED" ‖ id (8 octets) ‖ Ed25519(BLAKE2b-512(fichier)))
//                  trusted comment: <texte de confiance>
//                  base64(Ed25519(signature (64 octets) ‖ texte de confiance))
//
// <ID> est l'identifiant de 8 octets lu comme un entier petit-boutiste,
// écrit en 16 chiffres hexadécimaux majuscules. Une signature « Ed » (sans
// préhachage, format ancien) est lue aussi, comme le fait minisign.
//
// La clé d'essai est éphémère : créée en mémoire par creerCleEssai, jamais
// écrite dans le dépôt ; l'appelant qui l'écrit sur disque le fait sous
// NOORTRACE_TMP ou os.tmpdir() et la détruit.

import crypto from "node:crypto";

const PREFIXE_SPKI_ED25519 = Buffer.from("302a300506032b6570032100", "hex");

/** Identifiant de clé tel que minisign l'imprime. */
export function texteIdentifiant(id) {
  return Buffer.from(id).reverse().toString("hex").toUpperCase();
}

/** Clé d'essai éphémère : { privee (KeyObject), publique (32 octets), id (8 octets) }. */
export function creerCleEssai() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  return { privee: privateKey, publique: spki.subarray(spki.length - 32), id: crypto.randomBytes(8) };
}

/** Fichier de clé publique minisign (deux lignes). */
export function textePublique(cle) {
  const octets = Buffer.concat([Buffer.from("Ed"), cle.id, cle.publique]);
  return `untrusted comment: minisign public key ${texteIdentifiant(cle.id)}\n${octets.toString("base64")}\n`;
}

/** Signature minisign préhachée (« ED ») de `donnees`, avec son commentaire de confiance. */
export function signer(cle, donnees, commentaireConfiance, commentaireNonFiable = "signature from minisign secret key") {
  if (/[\r\n]/.test(commentaireConfiance) || /[\r\n]/.test(commentaireNonFiable)) throw new Error("commentaire sur plusieurs lignes");
  const empreinte = crypto.createHash("blake2b512").update(donnees).digest();
  const sig = crypto.sign(null, empreinte, cle.privee);
  const globale = crypto.sign(null, Buffer.concat([sig, Buffer.from(commentaireConfiance, "utf8")]), cle.privee);
  return `untrusted comment: ${commentaireNonFiable}\n${Buffer.concat([Buffer.from("ED"), cle.id, sig]).toString("base64")}\ntrusted comment: ${commentaireConfiance}\n${globale.toString("base64")}\n`;
}

function base64Strict(ligne, longueur, quoi) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(ligne)) throw new Error(`${quoi} : base64 illisible`);
  const b = Buffer.from(ligne, "base64");
  if (b.length !== longueur || b.toString("base64") !== ligne) throw new Error(`${quoi} : longueur ${b.length}, ${longueur} attendus`);
  return b;
}

function clePublique(brute) {
  return crypto.createPublicKey({ key: Buffer.concat([PREFIXE_SPKI_ED25519, brute]), format: "der", type: "spki" });
}

/**
 * Vérifie `texteSignature` sur `donnees` avec `texteCle` (fichier de clé
 * publique, ou sa seule ligne base64). Rend { valide: true, commentaire }
 * ou { valide: false, raison }.
 */
export function verifier(texteCle, texteSignature, donnees) {
  try {
    const lignesCle = texteCle.split("\n").filter((l) => l !== "");
    const cle = base64Strict(lignesCle[lignesCle.length - 1], 42, "clé publique");
    if (cle.subarray(0, 2).toString("latin1") !== "Ed") return { valide: false, raison: "algorithme de clé inconnu" };
    const l = texteSignature.split("\n");
    if (l.length < 4 || !l[0].startsWith("untrusted comment: ") || !l[2].startsWith("trusted comment: ")) return { valide: false, raison: "fichier de signature mal formé" };
    if (l.slice(4).some((x) => x !== "")) return { valide: false, raison: "lignes en trop dans la signature" };
    const sig = base64Strict(l[1], 74, "signature");
    const globale = base64Strict(l[3], 64, "signature globale");
    const algo = sig.subarray(0, 2).toString("latin1");
    if (algo !== "ED" && algo !== "Ed") return { valide: false, raison: `algorithme de signature inconnu (${algo})` };
    if (!sig.subarray(2, 10).equals(cle.subarray(2, 10))) return { valide: false, raison: "signature d'une autre clé (identifiant différent)" };
    const publique = clePublique(cle.subarray(10));
    const message = algo === "ED" ? crypto.createHash("blake2b512").update(donnees).digest() : donnees;
    if (!crypto.verify(null, message, publique, sig.subarray(10))) return { valide: false, raison: "signature invalide" };
    const commentaire = l[2].slice("trusted comment: ".length);
    if (!crypto.verify(null, Buffer.concat([sig.subarray(10), Buffer.from(commentaire, "utf8")]), publique, globale)) return { valide: false, raison: "commentaire de confiance altéré" };
    return { valide: true, commentaire };
  } catch (err) {
    return { valide: false, raison: err.message };
  }
}
