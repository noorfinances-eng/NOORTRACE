// T-10, révocation (CT-6 EX-9.16), différée à l'acquisition (CT-5 EX-5.10
// étape 10 ; CT-6 EX-13.12, EX-13.17) : preuves de non-révocation des
// certificats du chemin retenu par T-7, CRL lues par le lecteur borné,
// `thisUpdate` postérieur ou égal à `genTime`.

import { ErreurDer, octetsEgaux } from "./der.mjs";
import { lireCertificat, lireCrl, entreeRevocation, pointsDistributionCrl, urisOcsp, crlVersPem } from "./x509.mjs";
import { verifierSignatureEmise } from "./signatures.mjs";
import { microsecondesVersRfc3339 } from "./verification.mjs";

/** Raisons de révocation qui laissent le jeton valide quand la révocation est postérieure à `genTime` (RFC 3161 §4). */
export const RAISONS_TOLEREES = Object.freeze([0, 3, 4, 5]);

function certificat(c, quoi) {
  if (c instanceof Uint8Array) return lireCertificat(c);
  if (c && c.octets instanceof Uint8Array && c.sujet) return c;
  throw new TypeError(`${quoi} : certificat lu ou DER attendu`);
}

/** Lit une liste de CRL (PEM, DER ou objets lus) ; les illisibles sont comptées. */
function lireCrls(liste, provenance) {
  const lues = [];
  let illisibles = 0;
  for (const c of liste ?? []) {
    try {
      if (c && c.revoques && c.emetteur) lues.push({ crl: c, provenance });
      else lues.push({ crl: lireCrl(c), provenance });
    } catch {
      illisibles++;
    }
  }
  return { lues, illisibles };
}

/**
 * T-10. `chemin` : les certificats `c₀…cₙ` retenus par T-7 (ancre exclue, sauf
 * identité) ; `autorite` : `{ nom, certificat, identite }` ou `null` ;
 * `crls` : CRL du fichier d'ancres (ou capturées par CT-5) ; `crlsJeton` :
 * CRL du champ `crls` du jeton ; `declarations` : `revocation.statements[]`
 * (`{ certificate_sha256, not_revoked_at }`) ; `aInstant` : `genTime` en ms.
 *
 * Rend `{ statut, raison, detail, preuves: [{ certificate_sha256, evidence, issued_at, crl_sha256 }],
 * avertissements, revocations: [{ certificate_sha256, date, raison, toleree }] }`.
 */
export function verifierRevocation({ chemin, autorite = null, crls = [], crlsJeton = [], declarations = [], aInstant }) {
  if (!Number.isFinite(aInstant)) return { statut: "non_execute", raison: "prerequis_en_echec", detail: "instant de validation inconnu", preuves: [], avertissements: [], revocations: [] };
  const certs = (chemin ?? []).map((c, i) => certificat(c, `chemin[${i}]`));
  const A = autorite ? { ...autorite, certificat: certificat(autorite.certificat, "autorite.certificat") } : null;
  const avertissements = [];
  const ancre = lireCrls(crls, "ancre");
  const jeton = lireCrls(crlsJeton, "jeton");
  if (jeton.illisibles > 0) avertissements.push({ id: "AV-T-3", detail: `${jeton.illisibles} CRL du jeton illisible(s)` });
  if (ancre.illisibles > 0) avertissements.push({ id: "AV-T-3", detail: `${ancre.illisibles} CRL d'ancre illisible(s)` });
  const toutes = [...ancre.lues, ...jeton.lues];
  const preuves = [];
  const revocations = [];
  let echec = null;
  let manquantes = 0;

  const aProuver = A && A.identite ? [] : certs;
  for (let i = 0; i < aProuver.length; i++) {
    const c = aProuver[i];
    const emetteur = i + 1 < certs.length ? certs[i + 1] : A ? A.certificat : null;
    let preuve = null;
    for (const { crl, provenance } of toutes) {
      if (!octetsEgaux(crl.emetteur.octets, c.emetteur.octets)) continue;
      const motifs = [];
      if (!crl.complete) motifs.push("delta ou partielle");
      if (!emetteur || !verifierSignatureEmise(crl, emetteur)) motifs.push("signature non vérifiée sous la clé de l'émetteur");
      if (crl.thisUpdate < aInstant) motifs.push("thisUpdate antérieur à genTime");
      if (motifs.length) {
        avertissements.push({ id: "AV-T-3", detail: `CRL ${crl.sha256} (${provenance}) écartée pour ${c.sha256} : ${motifs.join(", ")}` });
        continue;
      }
      const entree = entreeRevocation(crl, c);
      if (entree) {
        const toleree = entree.raison !== null && RAISONS_TOLEREES.includes(entree.raison) && entree.date > aInstant;
        revocations.push({ certificate_sha256: c.sha256, date: microsecondesVersRfc3339(entree.date * 1000), raison: entree.raison, toleree, crl_sha256: crl.sha256 });
        if (!toleree) {
          echec = echec ?? `certificat ${c.sha256} révoqué (raison ${entree.raison ?? "absente"}, le ${microsecondesVersRfc3339(entree.date * 1000)}) selon la CRL ${crl.sha256}`;
        }
      }
      preuve = { certificate_sha256: c.sha256, evidence: "crl", issued_at: microsecondesVersRfc3339(crl.thisUpdate * 1000), crl_sha256: crl.sha256 };
      break;
    }
    if (!preuve) {
      const d = (declarations ?? []).find((s) => s.certificate_sha256 === c.sha256 && Date.parse(s.not_revoked_at) >= aInstant);
      if (d) preuve = { certificate_sha256: c.sha256, evidence: "declaration", issued_at: d.not_revoked_at, crl_sha256: null };
    }
    if (preuve) preuves.push(preuve);
    else manquantes++;
  }

  // Certificat de l'autorité : jugé seulement par une CRL du fichier d'ancres, sans exiger sa signature.
  if (A) {
    for (const { crl } of ancre.lues) {
      if (!crl.complete || !octetsEgaux(crl.emetteur.octets, A.certificat.emetteur.octets)) continue;
      const entree = entreeRevocation(crl, A.certificat);
      if (!entree) continue;
      const toleree = entree.raison !== null && RAISONS_TOLEREES.includes(entree.raison) && entree.date > aInstant;
      revocations.push({ certificate_sha256: A.certificat.sha256, date: microsecondesVersRfc3339(entree.date * 1000), raison: entree.raison, toleree, crl_sha256: crl.sha256 });
      if (!toleree) echec = echec ?? `certificat de l'autorité ${A.nom ?? A.certificat.sha256} révoqué selon la CRL ${crl.sha256} du fichier d'ancres`;
    }
  }

  if (echec) return { statut: "echoue", raison: null, detail: echec, preuves, avertissements, revocations };
  if (manquantes > 0) return { statut: "non_execute", raison: "ancre_absente", detail: `${manquantes} certificat(s) du chemin sans preuve de non-révocation postérieure à genTime`, preuves, avertissements, revocations };
  return { statut: "reussi", raison: null, detail: null, preuves, avertissements, revocations };
}

/**
 * Capture les CRL des certificats d'un chemin par leurs points de
 * distribution (EX-5.10 étape 10 ; CT-6 EX-13.12) avec un `transport` injecté
 * (`{ obtenir(url, delaiMs) → { status, corps } }`). Rend, par certificat,
 * `{ certificate_sha256, sources, crl (octets)|null, pem|null, erreur|null, captured_at }`.
 * Une CRL qui ne se lit pas, ou dont `thisUpdate` précède `apresInstant`,
 * est rendue avec `erreur` : l'appelant rejoue (`crl_indisponible`).
 */
export async function capturerCrls({ chemin, transport, horloge, delaiMs = 10000, apresInstant = null }) {
  const resultats = [];
  for (const c0 of chemin ?? []) {
    const c = certificat(c0, "chemin");
    const sources = pointsDistributionCrl(c);
    const ocsp = urisOcsp(c);
    const r = { certificate_sha256: c.sha256, sources, ocsp, crl: null, pem: null, erreur: null, captured_at: microsecondesVersRfc3339(horloge.murale() * 1000) };
    if (sources.length === 0) {
      r.erreur = "aucun point de distribution de CRL";
      resultats.push(r);
      continue;
    }
    for (const url of sources) {
      try {
        const rep = await transport.obtenir(url, delaiMs);
        if (rep.status !== 200 || !(rep.corps instanceof Uint8Array)) {
          r.erreur = `http_${rep.status}`;
          continue;
        }
        const crl = lireCrl(rep.corps);
        if (apresInstant !== null && crl.thisUpdate < apresInstant) {
          r.erreur = "thisUpdate antérieur à genTime";
          continue;
        }
        r.crl = rep.corps;
        r.pem = rep.corps[0] === 0x2d ? Buffer.from(rep.corps).toString("latin1") : crlVersPem(rep.corps);
        r.erreur = null;
        break;
      } catch (err) {
        r.erreur = err instanceof ErreurDer ? `crl illisible : ${err.message}` : (err.code ?? err.message);
      }
    }
    resultats.push(r);
  }
  return resultats;
}
