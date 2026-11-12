// Demandes adressées au démon en marche par le fichier de demande et le
// signal SIGURG (CT-2 révision 0.8, EX-15.10 pas 3 et 5 ; table de §22,
// ligne `cli.mjs`). Le fichier `<supervision.ops_log.path>.rotation-urgence`
// porte un objet JSON dont le membre `demande` nomme l'action, et elle seule :
// `rotation-urgence` (EX-11.16), `ancrage` (CT-5 EX-5.9, EX-8.15) ou
// `dossier` (export du dossier, EX-15.11 à EX-15.13). Ce module lit la demande
// et rend l'action, ou le refus, sans rien exécuter, dans l'ordre d'EX-15.10
// pas 5 :
//
//   1. pas un objet JSON           → ctl_request_refused, demande_illisible
//   2. `demande` inconnue          → ctl_request_refused, demande_inconnue
//   3. `dossier` hors domaine      → dossier_export_refused, demande_invalide
//   4. demande périmée (600 s, ou  → dossier_export_refused ou
//      antérieure au démarrage)      ctl_request_refused, demande_perimee
//
// Les domaines d'EX-15.9 sont ici aussi : la commande `noortrace-ctl dossier
// exporter` (ctl-demon.mjs) les applique avant d'écrire la demande, le démon
// les applique de nouveau en la lisant.

import fs from "node:fs";
import path from "node:path";
import { decoderHorodatage, estHorodatage } from "@noortrace/noyau";
import { analyserJsonIntegral } from "./jcs-integral.mjs";

/** Valeurs de `demande` que le démon exécute (EX-15.10, pas 5). */
export const DEMANDES_CONNUES = Object.freeze(["rotation-urgence", "ancrage", "dossier"]);

/** Seuil de péremption d'une demande (EX-15.10, pas 5, refus 4) : 600 s. */
export const PEREMPTION_MS = 600000;

/** Membres d'une demande `dossier`, dans l'ordre du pas 3 d'EX-15.10. */
export const MEMBRES_DEMANDE_DOSSIER = Object.freeze(["demande", "selection", "seq", "ticket", "destination", "request_id", "pid", "at"]);

/** Désignations admises (EX-15.9). */
export const SELECTIONS = Object.freeze(["seq", "dernier", "ticket"]);

/**
 * Taille au-delà de laquelle un fichier de demande n'est pas lu (tenu pour
 * illisible) : une demande légitime fait quelques centaines d'octets ; la
 * borne protège la mémoire du démon d'un fichier démesuré.
 */
export const TAILLE_MAX_DEMANDE = 65536;

const MOTIF_TICKET = /^apr-[0-9a-z]+(-[0-9a-z]+)*$/;
const MOTIF_REQUEST_ID = /^[0-9a-f]{32}$/;
const MOTIF_ENTIER_DECIMAL = /^(0|[1-9][0-9]*)$/;
/** `pid` d'une demande : de 1 à 4 194 304 (EX-15.10, pas 5, refus 3). */
export const PID_MAX = 4194304;
/** Borne de `--delai-ms` (EX-15.9). */
export const DELAI_MAX_MS = 86400000;
/** Délai par défaut de `dossier exporter` (EX-15.9). */
export const DELAI_DOSSIER_DEFAUT_MS = 120000;

/** `--seq` et membre `seq` : entier de 1 à 2^53 − 1 (EX-15.9). */
export function seqValide(v) {
  return Number.isSafeInteger(v) && v >= 1;
}

/** Texte de `--seq` : entier décimal sans signe ni zéro de tête, de 1 à 2^53 − 1. */
export function texteSeqValide(s) {
  return typeof s === "string" && MOTIF_ENTIER_DECIMAL.test(s) && s !== "0" && seqValide(Number(s));
}

/** Texte de `--delai-ms` : entier décimal sans signe ni zéro de tête, de 0 à 86 400 000. */
export function texteDelaiValide(s) {
  return typeof s === "string" && MOTIF_ENTIER_DECIMAL.test(s) && Number(s) <= DELAI_MAX_MS;
}

/** Identifiant de ticket de CT-3 EX-7.1 : 5 à 128 caractères, motif `^apr-[0-9a-z]+(-[0-9a-z]+)*$`. */
export function ticketValide(v) {
  return typeof v === "string" && v.length >= 5 && v.length <= 128 && MOTIF_TICKET.test(v);
}

/** `request_id` : 32 chiffres hexadécimaux minuscules. */
export function requestIdValide(v) {
  return typeof v === "string" && MOTIF_REQUEST_ID.test(v);
}

/**
 * `request_id` d'une demande quand il est lisible (EX-15.15, révision 0.9) :
 * le fichier se lit comme un objet JSON dont le membre `request_id` est fait
 * de 32 chiffres hexadécimaux minuscules ; `null` sinon. `ctl_request_failed`
 * le reprend, pour que la commande qui a écrit la demande s'arrête aussitôt.
 * @param {unknown} objetOuOctets objet déjà lu, ou octets du fichier de demande
 * @returns {string|null}
 */
export function requestIdLisible(objetOuOctets) {
  let objet = objetOuOctets;
  if (objetOuOctets instanceof Uint8Array) {
    try {
      objet = analyserJsonIntegral(objetOuOctets, { profondeurMax: 32 });
    } catch {
      return null;
    }
  }
  return estObjetSimple(objet) && requestIdValide(objet.request_id) ? objet.request_id : null;
}

/** `pid` : entier de 1 à 4 194 304. */
export function pidValide(v) {
  return Number.isSafeInteger(v) && v >= 1 && v <= PID_MAX;
}

/** `at` : horodatage de CT-1 §3 (date existante, trois décimales, `Z`). */
export function atValide(v) {
  return typeof v === "string" && estHorodatage(v);
}

/**
 * Préfixe réservé des répertoires temporaires d'export (EX-15.13, point 2) :
 * un composant qui le porte n'est jamais une destination, puisque le démon
 * supprime à l'acquisition du bail tout répertoire de ce nom sous le
 * répertoire des exports (relecture de l'étape 6 ; question au texte de CT-2,
 * EX-15.9).
 */
export const PREFIXE_RESERVE = ".noortrace-partiel-";

/**
 * Chemin du domaine que `--vers` envoie (EX-15.9) : absolu, normalisé (aucun
 * composant `.` ni `..`, aucune barre oblique doublée ni finale), sans octet
 * nul, de 4 096 octets au plus, chaque composant de 1 à 255 octets. La racine
 * `/` seule n'a aucun composant : elle n'est pas du domaine. Étape 6 : aucun
 * composant ne commence par le préfixe réservé `.noortrace-partiel-` (un
 * dossier écrit sous ce nom serait effacé au démarrage suivant, contre
 * EX-15.13, point 4).
 * @param {unknown} s
 * @returns {boolean}
 */
export function destinationValide(s) {
  if (typeof s !== "string" || s.length < 2 || s[0] !== "/" || s.includes("\0")) return false;
  if (Buffer.byteLength(s, "utf8") > 4096) return false;
  for (const c of s.slice(1).split("/")) {
    if (c === "" || c === "." || c === "..") return false;
    if (Buffer.byteLength(c, "utf8") > 255) return false;
    if (c.startsWith(PREFIXE_RESERVE)) return false;
  }
  // Un substitut isolé ne s'écrit pas en UTF-8 : le chemin envoyé ne serait pas celui de la commande.
  return Buffer.from(s, "utf8").toString("utf8") === s;
}

/**
 * Forme envoyée de `--vers` (EX-15.9) : chemin non vide, sans octet nul,
 * dont le dernier composant donné n'est ni `.` ni `..` ; relatif, il est
 * résolu contre `cwd` ; le chemin absolu normalisé doit être du domaine de
 * `destinationValide`. Rend ce chemin, ou null (erreur d'usage).
 * @param {string} vers
 * @param {string} cwd
 * @returns {string|null}
 */
export function normaliserVers(vers, cwd) {
  if (typeof vers !== "string" || vers === "" || vers.includes("\0")) return null;
  const dernier = vers.replace(/\/+$/, "").split("/").pop();
  if (dernier === "." || dernier === "..") return null;
  const absolu = path.posix.resolve(cwd, vers);
  return destinationValide(absolu) ? absolu : null;
}

/** Tronque une valeur lue à 64 caractères (points de code), ou null si ce n'est pas une chaîne (EX-15.10, refus 2). */
export function tronquer64(v) {
  if (typeof v !== "string") return null;
  const points = Array.from(v);
  return points.length <= 64 ? v : points.slice(0, 64).join("");
}

function estObjetSimple(o) {
  return o !== null && typeof o === "object" && !Array.isArray(o);
}

function comparerOctets(a, b) {
  return Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

/**
 * Validité de chaque membre d'une demande `dossier` (EX-15.10, pas 5, refus
 * 3) : `seq` et `ticket` dépendent de `selection` (null hors de leur
 * désignation, et donc null quand `selection` n'est pas du domaine).
 * @param {object} o
 * @returns {Record<string, boolean>}
 */
export function validiteMembresDossier(o) {
  const a = (k) => Object.prototype.hasOwnProperty.call(o, k);
  return {
    demande: a("demande") && o.demande === "dossier",
    selection: a("selection") && SELECTIONS.includes(o.selection),
    seq: a("seq") && (o.selection === "seq" ? seqValide(o.seq) : o.seq === null),
    ticket: a("ticket") && (o.selection === "ticket" ? ticketValide(o.ticket) : o.ticket === null),
    destination: a("destination") && destinationValide(o.destination),
    request_id: a("request_id") && requestIdValide(o.request_id),
    pid: a("pid") && pidValide(o.pid),
    at: a("at") && atValide(o.at),
  };
}

/**
 * Premier membre fautif d'une demande `dossier`, ou null : les membres du pas
 * 3 dans leur ordre (absent ou hors domaine), puis les autres membres, par
 * ordre croissant de leurs octets (un membre de plus est fautif).
 * @param {object} o
 * @returns {string|null}
 */
export function membreFautif(o) {
  const v = validiteMembresDossier(o);
  for (const k of MEMBRES_DEMANDE_DOSSIER) if (!v[k]) return k;
  const autres = Object.keys(o).filter((k) => !MEMBRES_DEMANDE_DOSSIER.includes(k)).sort(comparerOctets);
  return autres[0] ?? null;
}

/**
 * `data` de `dossier_export_refused` (EX-15.14), dans l'ordre de la table :
 * `raison`, `selection`, `seq`, `ticket`, `destination`, `exports_dir`,
 * `period_start`, `decision`, `member`, `at`, `detail`. Chaque membre qui
 * reprend un membre de la demande vaut null quand ce membre manque ou sort de
 * son domaine.
 * @param {string} raison
 * @param {object|null} demande objet lu (éventuellement hors domaine)
 * @param {{exports_dir: string, seq?: number|null, period_start?: number|null, decision?: string|null,
 *   member?: string|null, at?: string|null, detail?: string|null}} x
 */
export function donneesRefusExport(raison, demande, x) {
  const v = estObjetSimple(demande) ? validiteMembresDossier(demande) : {};
  const lu = (k) => (v[k] ? demande[k] : null);
  return {
    raison,
    selection: lu("selection"),
    seq: x.seq !== undefined ? x.seq : lu("seq"),
    ticket: lu("ticket"),
    destination: lu("destination"),
    exports_dir: x.exports_dir,
    period_start: x.period_start ?? null,
    decision: x.decision ?? null,
    member: x.member ?? null,
    at: x.at ?? null,
    detail: x.detail ?? null,
  };
}

function refusCtl(raison, objet) {
  const demande = estObjetSimple(objet) ? tronquer64(objet.demande) : null;
  const at = estObjetSimple(objet) && atValide(objet.at) ? objet.at : null;
  return { refus: { event: "ctl_request_refused", component: "noyau", seq: null, request_id: null, data: { raison, demande, at } } };
}

/**
 * Lit une demande (EX-15.10, pas 5) : rend l'action à exécuter, ou le refus
 * et sa ligne, sans rien exécuter.
 * @param {Uint8Array|null} octets contenu du fichier de demande ; null : illisible
 * @param {{maintenant: number, demarrage: number, exports_dir: string}} o
 *   `maintenant` : instant de la lecture (ms, horloge murale du démon) ;
 *   `demarrage` : instant du démarrage du démon ; `exports_dir` : répertoire
 *   des exports tel que lu (repris dans `dossier_export_refused`)
 * @returns {{action: "rotation-urgence"|"ancrage"|"dossier", demande: object}
 *   | {refus: {event: string, component: string, seq: null, request_id: string|null, data: object}}}
 */
export function lireDemande(octets, o) {
  let objet;
  try {
    objet = octets === null ? undefined : analyserJsonIntegral(octets, { profondeurMax: 32 });
  } catch {
    objet = undefined;
  }
  // Refus 1 : pas un objet JSON.
  if (!estObjetSimple(objet)) return refusCtl("demande_illisible", null);
  // Refus 2 : `demande` inconnue (aucune demande n'est prise pour une autre action).
  if (!DEMANDES_CONNUES.includes(objet.demande) || !Object.prototype.hasOwnProperty.call(objet, "demande")) return refusCtl("demande_inconnue", objet);
  const dossier = objet.demande === "dossier";
  // Refus 3 : demande `dossier` hors de son domaine.
  if (dossier) {
    const member = membreFautif(objet);
    if (member !== null) {
      return {
        refus: {
          event: "dossier_export_refused",
          component: "noyau",
          seq: null,
          request_id: requestIdValide(objet.request_id) ? objet.request_id : null,
          data: donneesRefusExport("demande_invalide", objet, { exports_dir: o.exports_dir, member }),
        },
      };
    }
  }
  // Refus 4 : demande périmée, quelle que soit `demande` ; pour `rotation-urgence`
  // et `ancrage`, un `at` absent ou hors forme la rend périmée.
  const instant = atValide(objet.at) ? decoderHorodatage(objet.at) : null;
  if (instant === null || o.maintenant - instant > PEREMPTION_MS || instant < o.demarrage) {
    if (dossier) {
      return {
        refus: {
          event: "dossier_export_refused",
          component: "noyau",
          seq: null,
          request_id: objet.request_id,
          data: donneesRefusExport("demande_perimee", objet, { exports_dir: o.exports_dir, at: objet.at }),
        },
      };
    }
    return refusCtl("demande_perimee", objet);
  }
  return { action: objet.demande, demande: objet };
}

/**
 * Lit puis supprime le fichier de demande (EX-15.10, pas 5), sans suivre de
 * lien symbolique ni attendre sur un tube. Rend `{ absent: true }` sans
 * fichier ; `{ octets }` (null si le fichier n'est pas un fichier ordinaire
 * lisible de taille admise : la demande est alors illisible) ; et
 * `nonSupprime` (code d'erreur) si la suppression a échoué : une demande qui
 * reste en place n'est jamais exécutée, elle le serait à chaque signal.
 * @param {string} chemin
 * @returns {{absent: true} | {octets: Uint8Array|null, nonSupprime: string|null}}
 */
export function preleverFichierDemande(chemin) {
  let octets = null;
  let fd = null;
  try {
    fd = fs.openSync(chemin, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    const st = fs.fstatSync(fd);
    if (st.isFile() && st.size <= TAILLE_MAX_DEMANDE) {
      const tampon = Buffer.alloc(TAILLE_MAX_DEMANDE + 1);
      let n = 0;
      for (;;) {
        const k = fs.readSync(fd, tampon, n, tampon.length - n, null);
        if (k === 0) break;
        n += k;
        if (n > TAILLE_MAX_DEMANDE) break;
      }
      if (n <= TAILLE_MAX_DEMANDE) octets = new Uint8Array(tampon.subarray(0, n));
    }
  } catch (e) {
    if (e?.code === "ENOENT") return { absent: true };
    octets = null;
  } finally {
    if (fd !== null) fs.closeSync(fd);
  }
  let nonSupprime = null;
  try {
    fs.unlinkSync(chemin);
  } catch (e) {
    if (e?.code !== "ENOENT") nonSupprime = String(e?.code ?? "erreur");
  }
  return { octets, nonSupprime };
}
