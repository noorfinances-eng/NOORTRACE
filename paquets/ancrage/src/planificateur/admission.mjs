// Admission d'un objet à ancrer (CT-5 EX-3.1, EX-4.1, AN-3) par le noyau :
// signature du point (CT-1 §10.6) ou du manifeste (CT-1 §10.2) sous la clé
// en vigueur, place du point dans la série (chaînage par
// `prev_checkpoint_hash`, `tree_size` et `checkpoint_ts` non décroissants,
// `checkpoint_ts ≥ period_start`, CT-1 §10.5), `root`, `last_seq` et
// `last_hash` recalculés quand les événements de la période sont fournis,
// empreinte recalculée. Règles de refus : `format`, `period_start`,
// `signature`, `chainage`, `monotonie`, `racine`, `last_seq`, `last_hash`.

import {
  ZERO32,
  cleEnVigueur,
  dansValidite,
  decoderHorodatage,
  ecartsManifeste,
  estHex,
  hacherEvenement,
  hacherManifeste,
  hacherPoint,
  hexVersOctets,
  indexerCles,
  racineMerkle,
  validerSchema,
  verifierSeriePointsDeControle,
  verifierSignatureManifeste,
  verifierSignaturePoint,
} from "@noortrace/noyau";

/** Règles de refus d'`admettrePoint`, dans l'ordre d'évaluation. */
export const REGLES_ADMISSION = Object.freeze(["format", "period_start", "signature", "chainage", "monotonie", "racine", "last_seq", "last_hash"]);

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Index des clés de l'enregistreur : `cles.json` (CT-1 §11.2), un tableau de
 * ses `keys`, ou une `Map` déjà indexée.
 * @param {unknown} cles
 * @param {{org_id?: string, journal_id?: string}} attendus
 * @returns {{exploitable: boolean, cles: Map<string, object>, erreurs: string[]}}
 */
export function indexCles(cles, attendus = {}) {
  if (cles instanceof Map) return { exploitable: true, cles, erreurs: [] };
  if (Array.isArray(cles)) return indexerCles({ version: 0, org_id: attendus.org_id, journal_id: attendus.journal_id, keys: cles }, attendus);
  return indexerCles(cles, attendus);
}

/**
 * Hash des événements fournis (objets scellés ou hash hexadécimaux), par
 * `seq`, et liste ordonnée des hash de la période.
 * @param {unknown[]|null} evenements
 * @returns {{parSeq: Map<number, object>, hashes: string[]|null}}
 */
function lireEvenements(evenements, hashesPeriode) {
  const parSeq = new Map();
  let hashes = null;
  if (Array.isArray(hashesPeriode)) {
    hashes = hashesPeriode.map((h, i) => {
      if (!estHex(h, 32)) throw new TypeError(`hashesPeriode[${i}] : hash hexadécimal de 32 octets attendu`);
      return h;
    });
  }
  if (Array.isArray(evenements)) {
    const calcules = [];
    for (const e of evenements) {
      if (!estObjet(e) || !Number.isSafeInteger(e.seq)) throw new TypeError("événement : objet avec seq attendu");
      parSeq.set(e.seq, e);
      calcules.push({ seq: e.seq, hash: hacherEvenement(e) });
    }
    if (hashes === null && calcules.length) hashes = calcules.sort((a, b) => a.seq - b.seq).map((x) => x.hash);
  }
  return { parSeq, hashes };
}

/**
 * AN-3 : admission d'un point de contrôle signé.
 * @param {{point: object, serie?: object[], cles: unknown, hashesPeriode?: string[]|null, evenements?: object[]|null,
 *   periodStart: number, org_id?: string, journal_id?: string, firstSeq?: number|null, lastHashPrecedent?: string|null}} p
 *   `serie` : points déjà admis de la période, dans l'ordre ; `hashesPeriode` : hash des événements de la période
 *   dans l'ordre des seq (ou `evenements`, les événements scellés, dont les hash sont recalculés) ; `firstSeq` :
 *   `first_seq` de la période quand il est connu (manifeste, ou seq du premier événement fourni)
 * @returns {{admis: boolean, empreinte: string|null, regle: string|null, detail: string|null}}
 */
export function admettrePoint({ point, serie = [], cles, hashesPeriode = null, evenements = null, periodStart, org_id, journal_id, firstSeq = null, lastHashPrecedent = null }) {
  const refus = (regle, detail) => ({ admis: false, empreinte: null, regle, detail });
  if (!estObjet(point)) return refus("format", "le point n'est pas un objet");
  const schema = validerSchema("point-de-controle", point);
  if (!schema.valide) {
    // Une racine nulle pour tree_size ≥ 1 (ou non nulle pour 0) relève de la règle racine (CT-1 §10.5, révision 0.5).
    const racineSeule = Number.isSafeInteger(point.tree_size) && estHex(point.root, 32) &&
      validerSchema("point-de-controle", { ...point, root: point.tree_size === 0 ? ZERO32 : "0x" + "11".repeat(32) }).valide;
    if (!racineSeule) return refus("format", schema.erreurs[0]);
  }
  if (!Number.isSafeInteger(periodStart) || periodStart % 3600 !== 0) throw new RangeError("periodStart : heure UTC pleine en secondes attendue");
  if (point.period_start !== periodStart) return refus("period_start", `period_start ${point.period_start} différent de la période ${periodStart}`);
  if (org_id !== undefined && point.org_id !== org_id) return refus("period_start", "org_id différent du journal");
  if (journal_id !== undefined && point.journal_id !== journal_id) return refus("period_start", "journal_id différent du journal");
  const ts = decoderHorodatage(point.checkpoint_ts);
  if (ts === null) return refus("format", "checkpoint_ts : date inexistante");
  if (!Array.isArray(serie)) throw new TypeError("serie : tableau de points attendu");
  const empreinte = hacherPoint(point);

  // Signature sous la clé en vigueur (CT-1 §10.5 règle 5, §10.6).
  const index = indexCles(cles, { org_id: point.org_id, journal_id: point.journal_id });
  if (!index.exploitable) return refus("signature", `clés inexploitables : ${index.erreurs[0] ?? "cles.json non conforme"}`);
  const cle = index.cles.get(point.key_id);
  if (!cle) return refus("signature", `clé ${point.key_id} inconnue`);
  if (cle.admise === false) return refus("signature", `clé ${point.key_id} non admise (encodage ou petit ordre)`);
  const octetsCle = cle.octets ?? hexVersOctets(cle.public_key, 32);
  if (!verifierSignaturePoint(point, octetsCle)) return refus("signature", `signature invalide sous ${point.key_id}`);
  if (cle.debut !== undefined && !dansValidite(cle, ts)) return refus("signature", `checkpoint_ts hors de la validité de ${point.key_id}`);
  const { parSeq, hashes } = lireEvenements(evenements, hashesPeriode);
  const enVigueur = cleEnVigueur(parSeq, point.last_seq, { indexCles: index, instant: ts });
  if (enVigueur !== null && enVigueur !== point.key_id) return refus("signature", `clé en vigueur ${enVigueur}, point signé par ${point.key_id}`);

  // Place dans la série (règle 3).
  const precedent = serie.length ? serie[serie.length - 1] : null;
  const attendu = precedent ? hacherPoint(precedent) : ZERO32;
  if (point.prev_checkpoint_hash !== attendu) return refus("chainage", `prev_checkpoint_hash ${point.prev_checkpoint_hash} attendu ${attendu}`);
  if (ts < periodStart * 1000) return refus("monotonie", "checkpoint_ts antérieur à period_start");
  if (precedent) {
    if (point.tree_size < precedent.tree_size) return refus("monotonie", `tree_size ${point.tree_size} décroît (précédent ${precedent.tree_size})`);
    const tsPrecedent = decoderHorodatage(precedent.checkpoint_ts);
    if (tsPrecedent !== null && ts < tsPrecedent) return refus("monotonie", `checkpoint_ts ${point.checkpoint_ts} antérieur au précédent ${precedent.checkpoint_ts}`);
  }

  // Contenu (règle 2) : racine, last_seq, last_hash, selon ce qui est fourni.
  const n = point.tree_size;
  if (n === 0 && point.root !== ZERO32) return refus("racine", "root non nulle pour tree_size 0");
  if (n >= 1 && point.root === ZERO32) return refus("racine", `root nulle pour tree_size ${n}`);
  if (hashes !== null) {
    if (n > hashes.length) return refus("last_seq", `tree_size ${n} supérieur au nombre d'événements de la période (${hashes.length})`);
    if (n >= 1 && racineMerkle(hashes.slice(0, n)) !== point.root) return refus("racine", "root différente de la racine recalculée");
  }
  const premier = firstSeq ?? (parSeq.size ? Math.min(...parSeq.keys()) : null);
  if (premier !== null) {
    const lastSeqAttendu = n === 0 ? premier - 1 : premier + n - 1;
    if (point.last_seq !== lastSeqAttendu) return refus("last_seq", `last_seq ${point.last_seq} attendu ${lastSeqAttendu}`);
  }
  if (point.last_seq === 0 && point.last_hash !== ZERO32) return refus("last_hash", "last_hash non nul pour last_seq 0");
  if (n >= 1 && hashes !== null && point.last_hash !== hashes[n - 1]) return refus("last_hash", `last_hash différent du hash de l'événement ${point.last_seq}`);
  if (n === 0 && point.last_seq >= 1) {
    const e = parSeq.get(point.last_seq);
    if (e && hacherEvenement(e) !== point.last_hash) return refus("last_hash", `last_hash différent du hash de l'événement ${point.last_seq}`);
    if (!e && lastHashPrecedent !== null && point.last_hash !== lastHashPrecedent) return refus("last_hash", "last_hash différent de la tête héritée de la période précédente");
  }
  return { admis: true, empreinte, regle: null, detail: null };
}

/**
 * AN-3 : admission d'un manifeste signé (clôture).
 * @param {{manifeste: object, signature: object|string, cles: unknown}} p
 *   `signature` : contenu de `manifeste.sig` (objet `{sig}` ou hexadécimal)
 * @returns {{admis: boolean, empreinte: string|null, regle: string|null, detail: string|null}}
 */
export function admettreManifeste({ manifeste, signature, cles }) {
  const refus = (regle, detail) => ({ admis: false, empreinte: null, regle, detail });
  if (!estObjet(manifeste)) return refus("format", "le manifeste n'est pas un objet");
  const ecarts = ecartsManifeste(manifeste);
  if (ecarts.length) return refus("format", ecarts[0]);
  const sig = estObjet(signature) ? signature.sig : signature;
  if (!estHex(sig, 64)) return refus("signature", "signature : 64 octets hexadécimaux attendus");
  const index = indexCles(cles, { org_id: manifeste.org_id, journal_id: manifeste.journal_id });
  if (!index.exploitable) return refus("signature", `clés inexploitables : ${index.erreurs[0] ?? "cles.json non conforme"}`);
  const cle = index.cles.get(manifeste.recorder_key_id);
  if (!cle) return refus("signature", `clé ${manifeste.recorder_key_id} inconnue`);
  const octetsCle = cle.octets ?? hexVersOctets(cle.public_key, 32);
  if (!verifierSignatureManifeste(manifeste, sig, octetsCle)) return refus("signature", `signature invalide sous ${manifeste.recorder_key_id}`);
  const instant = decoderHorodatage(manifeste.generated_at);
  if (cle.debut !== undefined && instant !== null && !dansValidite(cle, instant)) return refus("signature", `generated_at hors de la validité de ${manifeste.recorder_key_id}`);
  return { admis: true, empreinte: hacherManifeste(manifeste), regle: null, detail: null };
}

/**
 * Vérification d'une série publiée contre son manifeste par le noyau
 * (CT-1 §10.5, `verifierSeriePointsDeControle`), telle que la remise au
 * réviseur de CT-5 §10.2 l'emploie.
 * @param {{points: object[], manifeste: object, evenements?: object[], cles?: unknown}} p
 */
export function verifierSerie({ points, manifeste, evenements = [], cles = null }) {
  return verifierSeriePointsDeControle(points, manifeste, evenements, cles);
}
