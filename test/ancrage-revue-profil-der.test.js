// Composant d'ancrage (paquets/ancrage, client RFC 3161) : profil DER
// appliqué à tout le jeton (CT-6 EX-9.4, EX-9.7, révision 0.9 ;
// revue de sécurité de l'étape 8). Les
// jetons sont construits en mémoire par le générateur des vecteurs de CT-6
// (scripts/vecteurs/ct6/rfc3161.mjs : six formes refusées et leur témoin), ou
// dérivés d'eux par une réécriture DER (champs de fin du TBSCertificate,
// paramètres d'algorithme, profondeur) ; chacun est jugé par verifierJeton du
// composant : T-1 en échec pour les formes refusées, réussi pour les témoins.
// Racine du client éprouvé : le paquet du dépôt, ou le fichier que nomme
// NOORTRACE_REVUE_RFC3161 (copie ou mutant).

import { expect } from "chai";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as RFC from "../scripts/vecteurs/ct6/rfc3161.mjs";

const CT6 = path.join(PROJECT_ROOT, "spec", "vecteurs", "ct-6");
const CLIENT = process.env.NOORTRACE_REVUE_RFC3161 ? pathToFileURL(path.resolve(process.env.NOORTRACE_REVUE_RFC3161)).href : "@noortrace/ancrage/rfc3161";

// --- DER générique : lecture en arbre et réécriture à longueurs recalculées.
function lireNoeud(buf, pos = 0) {
  const tag = buf[pos];
  let l = buf[pos + 1];
  let p = pos + 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + buf[p++];
  }
  const contenu = buf.subarray(p, p + l);
  const noeud = { tag, fin: p + l };
  if (tag & 0x20) {
    noeud.enfants = [];
    let q = 0;
    while (q < contenu.length) {
      const e = lireNoeud(contenu, q);
      noeud.enfants.push(e);
      q = e.fin;
    }
  } else noeud.valeur = Buffer.from(contenu);
  return noeud;
}
function ecrireNoeud(n) {
  const corps = n.enfants ? Buffer.concat(n.enfants.map(ecrireNoeud)) : n.valeur;
  const L = corps.length;
  const lon = L < 0x80 ? Buffer.from([L]) : L < 0x100 ? Buffer.from([0x81, L]) : Buffer.from([0x82, L >> 8, L & 0xff]);
  return Buffer.concat([Buffer.from([n.tag]), lon, corps]);
}
/** Le certificat `der` dont les champs de fin du TBSCertificate sont récrits par `f(enfants)` (liste des éléments du TBS). */
function certificatModifie(der, f) {
  const cert = lireNoeud(der);
  f(cert.enfants[0].enfants);
  return ecrireNoeud(cert);
}

describe("ancrage, revue de sécurité de l'étape 8 : profil DER sur tout le jeton (CT-6 EX-9.4, EX-9.7, révision 0.9)", function () {
  this.timeout(120000);
  let verifierJeton;
  let lireCertificat;
  let materiel;
  let jetons;
  let base;
  before(async function () {
    ({ verifierJeton, lireCertificat } = await import(CLIENT));
    materiel = RFC.materielTest(RFC.chargerCles(path.join(CT6, "rfc3161", "cles")));
    jetons = RFC.jetonsTest(materiel, RFC.manifestesCT1());
    const periode1 = RFC.manifestesCT1()[0];
    base = (autres) => RFC.construireJeton({ empreinte: Buffer.from(periode1.periodHash.slice(2), "hex"), genTime: "20261105100005Z", serie: 1, nonce: 1n, tsaNom: materiel.nomTsa, certificats: [materiel.certs["tsa-test"]], signataire: materiel.certs["tsa-test"], cle: materiel.cles["tsa-test"], ...autres });
  });
  const t1 = (octets) => verifierJeton({ octets: new Uint8Array(octets), imprintAttendue: null, ancres: null, aGenTime: true }).checks["T-1"];
  const FORMES = ["t1-null-longueur", "t1-integer-vide", "t1-bit-string-vide", "t1-octet-string-construite", "t1-etiquette-0", "t1-unsigned-null-longueur", "t1-tstinfo-integer-vide"];

  it("les sept formes refusées des vecteurs de CT-6 (NULL de longueur 1, INTEGER vide, BIT STRING vide, OCTET STRING construite, étiquette universelle 0, dans crls ou unsignedAttrs, hors de la signature ; INTEGER vide dans le TSTInfo encapsulé) mettent T-1 en échec ; le témoin integer-non-minimal et periode-1 passent T-1", function () {
    for (const nom of FORMES) expect(t1(jetons[nom].octets), nom).to.equal("echoue");
    expect(t1(jetons["integer-non-minimal"].octets)).to.equal("reussi");
    expect(t1(jetons["periode-1"].octets)).to.equal("reussi");
  });

  it("TBSCertificate (EX-9.7, révision 0.9) : extensions [3] en double, ou issuerUniqueID [1] après extensions, rendent le certificat de l'unité illisible et T-1 en échec ; un uniqueID avant extensions, dans l'ordre, passe T-1", function () {
    const tsa = materiel.certs["tsa-test"];
    const deuxExt = certificatModifie(tsa, (e) => e.push(e[e.length - 1]));
    const uidApres = certificatModifie(tsa, (e) => e.push({ tag: 0x81, valeur: Buffer.from([0x00, 0xff]) }));
    const uidAvant = certificatModifie(tsa, (e) => e.splice(e.length - 1, 0, { tag: 0x81, valeur: Buffer.from([0x00, 0xff]) }));
    expect(t1(base({ certificats: [deuxExt] })), "extensions en double").to.equal("echoue");
    expect(t1(base({ certificats: [uidApres] })), "uniqueID après extensions").to.equal("echoue");
    expect(t1(base({ certificats: [uidAvant] })), "uniqueID avant extensions").to.equal("reussi");
  });

  it("paramètres d'algorithme et TSTInfo (EX-9.4, révision 0.9) : un BOOLEAN codé 01 dans les paramètres de l'algorithme d'empreinte, ou une imbrication de trente-trois niveaux dans une extension de TSTInfo, mettent T-1 en échec ; un NULL dans les paramètres passe", function () {
    const bool01 = RFC.seq(RFC.oid(RFC.ALG.sha256Nul.length ? "2.16.840.1.101.3.4.2.1" : "2.16.840.1.101.3.4.2.1"), RFC.tlv(0x01, Buffer.from([0x01])));
    expect(t1(base({ algImprint: bool01 })), "BOOLEAN 01 dans les paramètres").to.equal("echoue");
    let profond = RFC.nul();
    for (let i = 0; i < 33; i++) profond = RFC.seq(profond);
    expect(t1(base({ extensionsTstBrutes: [profond] })), "profondeur 33 dans TSTInfo").to.equal("echoue");
    // Certificat lu seul (ancre d'un prestataire, CT-6 §9.3) : un BOOLEAN codé 01 dans les paramètres des deux
    // AlgorithmIdentifier de signature (identiques, RFC 5280 §4.1.1.2) le rend illisible ; le certificat intact se lit.
    const bool = { tag: 0x01, valeur: Buffer.from([0x01]) };
    const cert = lireNoeud(materiel.certs["tsa-test"]);
    cert.enfants[1].enfants[1] = bool;
    cert.enfants[0].enfants[2].enfants[1] = bool;
    expect(() => lireCertificat(new Uint8Array(ecrireNoeud(cert))), "BOOLEAN 01 dans les paramètres de signature").to.throw(/BOOLEAN/);
    expect(() => lireCertificat(new Uint8Array(materiel.certs["tsa-test"]))).to.not.throw();
    expect(t1(base({ extensionsTst: [{ oid: "1.3.6.1.4.1.99999.4", critique: false, valeur: RFC.seq(RFC.nul()) }] })), "extension bien formée").to.equal("reussi");
  });
});
