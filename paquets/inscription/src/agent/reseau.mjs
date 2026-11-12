// Accès JSON-RPC de l'agent aux validateurs (CT-4 EX-7.1) et vérifications
// OP-2 (nœud validateur) et OP-1 (instance, EX-4.9). Le jeton du nœud
// (`--jeton`, EX-10.3) est résolu par l'agent et envoyé en `Authorization:
// Bearer` à chaque point ; il n'est écrit nulle part (EX-7.1) : ni dans un
// envoi, ni dans un index (`node.rpc` est l'adresse du point), ni dans une
// sortie.

import * as R from "@noortrace/ancrage/registre";
import { octetsVersHex } from "@noortrace/noyau";

const MAX_U64 = (1n << 64n) - 1n;

/**
 * Transport HTTP avec jeton facultatif (même conduite que `transportHttp`
 * d'ancrage : délai et taille bornés). La réponse se lit par morceaux : un
 * `Content-Length` annoncé au-delà de `tailleMax` est refusé avant toute
 * lecture, et la lecture s'arrête (flux annulé, connexion fermée) dès que le
 * total dépasse `tailleMax`, sans jamais garder plus que la borne et un
 * morceau ; le délai `delaiMs` couvre la requête et la lecture du corps
 * (relecture de l'étape 6, R2). Toute panne est `noeud_injoignable`.
 */
export function transportAvecJeton(jeton = null, { fetch = globalThis.fetch } = {}) {
  return async function envoyer({ url, octets, delaiMs, tailleMax }) {
    const entetes = { "content-type": "application/json", accept: "application/json" };
    if (jeton) entetes.authorization = `Bearer ${jeton}`;
    const injoignable = (e) => new R.ErreurRpc("noeud_injoignable", `${url} : ${e?.name === "TimeoutError" ? "délai dépassé" : "injoignable"}`, url);
    const tropGrand = () => new R.ErreurRpc("noeud_injoignable", `${url} : réponse au-delà de ${tailleMax} octets`, url);
    const arret = new AbortController();
    const minuterie = setTimeout(() => arret.abort(new DOMException("délai dépassé", "TimeoutError")), delaiMs);
    try {
      let reponse;
      try {
        reponse = await fetch(url, { method: "POST", headers: entetes, body: octets, signal: arret.signal, redirect: "error" });
      } catch (e) {
        throw injoignable(arret.signal.aborted ? arret.signal.reason : e);
      }
      const annonce = reponse.headers.get("content-length");
      if (annonce !== null && /^[0-9]+$/.test(annonce) && Number(annonce) > tailleMax) {
        arret.abort();
        throw tropGrand();
      }
      const morceaux = [];
      let total = 0;
      if (reponse.body) {
        const lecteur = reponse.body.getReader();
        for (;;) {
          let r;
          try {
            r = await lecteur.read();
          } catch (e) {
            throw injoignable(arret.signal.aborted ? arret.signal.reason : e);
          }
          if (r.done) break;
          total += r.value.byteLength;
          if (total > tailleMax) {
            morceaux.length = 0;
            await lecteur.cancel().catch(() => {});
            arret.abort();
            throw tropGrand();
          }
          morceaux.push(r.value);
        }
      }
      const tampon = new Uint8Array(total);
      let k = 0;
      for (const m of morceaux) {
        tampon.set(m, k);
        k += m.byteLength;
      }
      return { status: reponse.status, octets: tampon };
    } finally {
      clearTimeout(minuterie);
    }
  };
}

/** Client JSON-RPC vers les points de la configuration. */
export function clientRpc(points, { jeton = null, transport = null, delaiMs = 10000 } = {}) {
  return new R.ClientRpc({ points, transport: transport ?? transportAvecJeton(jeton), delaiMs });
}

const estLocal = (url) => {
  try {
    const h = new URL(url).hostname;
    return h === "127.0.0.1" || h === "[::1]" || h === "::1" || h === "localhost";
  } catch {
    return false;
  }
};

/**
 * OP-2 (CT-4 §7.3) : chaque point répond, et `noor_txindexStatus` y rend
 * `last_indexed_height` non nul et au moins égal à la hauteur lue ; en
 * production, `http://` seulement vers la boucle locale (EX-7.1). Rend
 * `{ ok, code, detail, hauteur }`.
 */
export async function op2(rpc, { nature }) {
  let hauteur = null;
  for (const point of rpc.points()) {
    if (nature === "production" && point.startsWith("http://") && !estLocal(point)) {
      return { ok: false, code: "noeud_injoignable", detail: `${point} : http:// n'est admis en production que vers 127.0.0.1, ::1 ou localhost (EX-7.1)` };
    }
    let h;
    let s;
    try {
      const b = await rpc.appeler("eth_blockNumber", [], { point });
      h = b.erreur ? null : R.quantiteVersEntier(b.resultat, MAX_U64);
      if (h === null) return { ok: false, code: "noeud_injoignable", detail: `${point} : eth_blockNumber illisible` };
      s = await rpc.appeler("noor_txindexStatus", [], { point });
    } catch (e) {
      if (e instanceof R.ErreurRpc) return { ok: false, code: "noeud_injoignable", detail: `${point} : injoignable` };
      throw e;
    }
    const dernier = s.erreur ? null : s.resultat?.last_indexed_height;
    if (!Number.isSafeInteger(dernier) || dernier === 0 || BigInt(dernier) < h) {
      return { ok: false, code: "noeud_suiveur", detail: `${point} : noor_txindexStatus last_indexed_height ${dernier ?? "absent"} pour la hauteur ${h} (index d'un suiveur)` };
    }
    if (hauteur === null || h > hauteur) hauteur = h;
  }
  return { ok: true, code: null, detail: "", hauteur };
}

/** `noor_getCommitCertificate("latest")` réessayé selon CT-4 §9.3 ; rend `{ certificat }` ou `{ erreur }`. */
async function certificatTete(rpc, attendre) {
  let derniere = null;
  for (let essai = 0; essai < 100; essai++) {
    let r;
    try {
      r = await rpc.appelerPremier("noor_getCommitCertificate", ["latest"]);
    } catch (e) {
      if (e instanceof R.ErreurRpc) return { erreur: { code: "noeud_injoignable", message: e.message } };
      throw e;
    }
    if (!r.erreur) return { certificat: r.resultat };
    const c = R.classerErreurCertificat(r.erreur);
    derniere = { code: c.code, message: r.erreur.message };
    if (!c.reessayer) break;
    await attendre(50);
  }
  return { erreur: derniere };
}

/**
 * OP-1 (CT-4 §7.3, EX-4.9) : `eth_chainId` égale l'identifiant EVM ; le
 * certificat de la tête porte l'identifiant BFT et le hachage du jeu en
 * vigueur ; code non vide aux quatre adresses ; hachage du bloc de
 * déploiement d'`AttestationRegistry` quand le manifeste le donne. Rend
 * `{ ok, code, detail }`.
 */
export async function op1(rpc, instance, { attendre }) {
  try {
    const c = await rpc.appelerPremier("eth_chainId", []);
    const id = c.erreur ? null : R.quantiteVersEntier(c.resultat, MAX_U64);
    if (id === null || id !== BigInt(instance.evmChainId)) return { ok: false, code: "chaine_differente", detail: `eth_chainId ${c.resultat ?? "illisible"} différent de ${instance.evmChainId}` };
    const cert = await certificatTete(rpc, attendre);
    if (cert.erreur) {
      if (cert.erreur.code === "noeud_injoignable") return { ok: false, code: "noeud_injoignable", detail: cert.erreur.message };
      if (cert.erreur.code === "inutilisable") return { ok: false, code: "inutilisable", detail: `noor_getCommitCertificate : ${cert.erreur.message}` };
      return { ok: false, code: "jeu_validateurs_different", detail: `noor_getCommitCertificate("latest") : ${cert.erreur.message}` };
    }
    if (cert.certificat?.chainId !== instance.bftChainId) return { ok: false, code: "chaine_differente", detail: `certificat de la tête : chainId ${String(cert.certificat?.chainId).slice(0, 64)} différent de ${instance.bftChainId}` };
    if (String(cert.certificat?.valsetHash).toLowerCase() !== instance.validatorSetHash) return { ok: false, code: "jeu_validateurs_different", detail: `certificat de la tête : valsetHash différent de ${instance.validatorSetHash}` };
    for (const [nom, adresse] of Object.entries(instance.contrats)) {
      const g = await rpc.appelerPremier("eth_getCode", [adresse, "latest"]);
      if (g.erreur || typeof g.resultat !== "string" || g.resultat === "0x" || g.resultat === "") return { ok: false, code: "code_absent", detail: `aucun code à l'adresse de ${nom} ${adresse}` };
    }
    const d = instance.attestationDeploiement;
    if (d && d.block_hash) {
      const b = await rpc.appelerPremier("eth_getBlockByNumber", ["0x" + BigInt(d.block_number).toString(16), false]);
      if (b.erreur || b.resultat?.hash !== d.block_hash) return { ok: false, code: "chaine_differente", detail: `bloc ${d.block_number} de hachage différent de celui du déploiement d'AttestationRegistry` };
    }
    return { ok: true, code: null, detail: "" };
  } catch (e) {
    if (e instanceof R.ErreurRpc) return { ok: false, code: "noeud_injoignable", detail: e.message };
    throw e;
  }
}

/** Refus transitoire d'une lecture : l'état d'un bloc tout juste décidé n'est pas encore servi par le nœud. */
const TRANSITOIRE = /state unavailable|header not found|unknown block|missing trie node/i;

/**
 * Refait une lecture refusée de façon transitoire (au plus 40 fois, toutes les
 * 250 ms) : un nœud peut annoncer un bloc avant d'en servir l'état. Toute autre
 * erreur est levée telle quelle.
 */
export async function reessayer(fn, attendre = (ms) => new Promise((ok) => setTimeout(ok, ms))) {
  for (let essai = 1; ; essai++) {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof R.ErreurLecture) || e.code !== "appel_refuse" || !TRANSITOIRE.test(e.message) || essai >= 40) throw e;
      await attendre(250);
    }
  }
}

/** `eth_call` à une hauteur (`latest` par défaut) ; rend l'hexadécimal, ou lève `ErreurLecture`. */
export function lecture(rpc, contrat, donnees, hauteur = "latest") {
  return reessayer(() => R.appelLecture(rpc, contrat, typeof donnees === "string" ? Uint8Array.from(Buffer.from(donnees.slice(2), "hex")) : donnees, { hauteur }));
}

/** Solde (`eth_getBalance`, `latest`). */
export async function solde(rpc, adresse) {
  const r = await rpc.appelerPremier("eth_getBalance", [adresse, "latest"]);
  const n = r.erreur ? null : R.quantiteVersEntier(r.resultat, (1n << 256n) - 1n);
  if (n === null) throw new R.ErreurLecture("retour_illisible", "eth_getBalance illisible");
  return n;
}

/** Nonce d'EX-8.14 : le plus grand `eth_getTransactionCount(expéditeur, "latest")` des points qui répondent. */
export async function nonce(rpc, adresse) {
  const reponses = await rpc.appelerTous("eth_getTransactionCount", [adresse, "latest"]);
  let n = null;
  for (const r of reponses) {
    const v = r.panne || r.erreur ? null : R.quantiteVersEntier(r.resultat, MAX_U64);
    if (v !== null && (n === null || v > n)) n = v;
  }
  if (n === null) {
    const p = reponses.find((r) => r.panne);
    if (p) throw p.panne;
    throw new R.ErreurLecture("retour_illisible", "eth_getTransactionCount illisible");
  }
  return n;
}

/** Tête (`eth_blockNumber`) du premier point qui répond. */
export async function tete(rpc) {
  const r = await rpc.appelerPremier("eth_blockNumber", []);
  const h = r.erreur ? null : R.quantiteVersEntier(r.resultat, MAX_U64);
  if (h === null) throw new R.ErreurLecture("retour_illisible", "eth_blockNumber illisible");
  return h;
}

export { octetsVersHex };
