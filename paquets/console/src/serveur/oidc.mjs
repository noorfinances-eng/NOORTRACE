// OIDC du serveur de console (CT-3 EX-13.45, EX-13.46, contrat 2.8) :
// découverte et jeu de clés relus d'avance à la moitié de `cache_s`,
// relecture retentée toutes les 60 s, copie gardée jusqu'à `cache_s` ;
// demande par code avec PKCE `S256` ; transaction portée par le cookie
// chiffré ; échange par `client_secret_basic` ; vérification du jeton
// d'identité dans l'ordre des neuf points d'EX-13.46, tolérance de 60 s.
// Lectures et échanges : 10 000 ms, 1 048 576 octets, aucune redirection
// suivie, certificat vérifié contre le magasin du système (ou l'agent passé
// par les essais).

import crypto from "node:crypto";
import https from "node:https";
import { lireJsonStrict } from "@noortrace/approbation";
import { b64u, deB64u, egauxTempsConstant, magasinSysteme } from "./outils.mjs";

export const DELAI_FOURNISSEUR_MS = 10000;
export const TAILLE_MAX_FOURNISSEUR = 1048576;
export const TOLERANCE_S = 60;
export const RELECTURE_MS = 60000;

/** Le fournisseur n'a pas répondu (délai, réseau, TLS). */
export class FournisseurMuet extends Error {}
/** Le fournisseur a répondu au-delà de 1 048 576 octets. */
export class ReponseTropGrande extends Error {}

/**
 * Une requête HTTPS au fournisseur, sans suivre de redirection.
 * @param {string} url
 * @param {{methode?: string, entetes?: object, corps?: string|null, agent?: https.Agent|null}} o
 * @returns {Promise<{statut: number, corps: Buffer}>}
 */
export function requeteFournisseur(url, { methode = "GET", entetes = {}, corps = null, agent = null } = {}) {
  return new Promise((resoudre, rejeter) => {
    let fini = false;
    let req;
    const terminer = (erreur, valeur) => {
      if (fini) return;
      fini = true;
      clearTimeout(minuteur);
      if (erreur) {
        req?.destroy();
        rejeter(erreur);
      } else resoudre(valeur);
    };
    const minuteur = setTimeout(() => terminer(new FournisseurMuet("délai dépassé")), DELAI_FOURNISSEUR_MS);
    try {
      const options = { method: methode, headers: entetes, agent: agent ?? undefined };
      // Sans agent d'essai : le magasin du système, explicitement (EX-13.45).
      if (agent === null) options.ca = magasinSysteme();
      req = https.request(url, options, (rep) => {
        const morceaux = [];
        let taille = 0;
        rep.on("data", (d) => {
          taille += d.length;
          if (taille > TAILLE_MAX_FOURNISSEUR) terminer(new ReponseTropGrande("réponse trop grande"));
          else morceaux.push(d);
        });
        rep.on("end", () => terminer(null, { statut: rep.statusCode, corps: Buffer.concat(morceaux) }));
        rep.on("error", () => terminer(new FournisseurMuet("réponse interrompue")));
        rep.on("aborted", () => terminer(new FournisseurMuet("réponse interrompue")));
      });
    } catch {
      terminer(new FournisseurMuet("adresse inutilisable"));
      return;
    }
    req.on("error", () => terminer(new FournisseurMuet("fournisseur injoignable")));
    req.end(corps ?? undefined);
  });
}

/** Encodage `application/x-www-form-urlencoded` de HTML 4.01 (RFC 6749, annexe B). */
export function encoderFormulaire(texte) {
  let sortie = "";
  for (const o of Buffer.from(texte, "utf8")) {
    if ((o >= 0x30 && o <= 0x39) || (o >= 0x41 && o <= 0x5a) || (o >= 0x61 && o <= 0x7a)) sortie += String.fromCharCode(o);
    else if (o === 0x20) sortie += "+";
    else sortie += "%" + o.toString(16).toUpperCase().padStart(2, "0");
  }
  return sortie;
}

/** `Authorization` de `client_secret_basic` (EX-13.45, point 4 ; RFC 6749 §2.3.1). */
export const enteteBasic = (clientId, secret) =>
  "Basic " + Buffer.from(`${encoderFormulaire(clientId)}:${encoderFormulaire(secret)}`, "utf8").toString("base64");

/** `code_challenge` de PKCE `S256` : BASE64URL(SHA-256(ASCII(code_verifier))). */
export const defiPkce = (verificateur) => b64u(crypto.createHash("sha256").update(verificateur, "ascii").digest());

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

function urlHttps(v) {
  if (typeof v !== "string" || !v.startsWith("https://")) return false;
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Contrôle du document de découverte (EX-13.45, point 1) ; rend la cause
 * d'un refus, ou `null`.
 */
export function causeDecouverte(doc, issuer) {
  if (!estObjet(doc)) return "document non objet";
  if (doc.issuer !== issuer) return "issuer different";
  for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) if (!urlHttps(doc[k])) return `${k} non https`;
  return null;
}

/** Clés d'un jeu JWK importables par `node:crypto` ; les autres sont ignorées. */
export function clesDuJeu(jeu) {
  if (!estObjet(jeu) || !Array.isArray(jeu.keys)) return null;
  const cles = [];
  for (const jwk of jeu.keys) {
    if (!estObjet(jwk)) continue;
    try {
      const cle = crypto.createPublicKey({ key: jwk, format: "jwk" });
      cles.push({ jwk, cle });
    } catch {
      // clé illisible : ignorée
    }
  }
  return cles;
}

/** La clé convient à l'algorithme (EX-13.46, point 2). */
function compatible({ jwk, cle }, alg) {
  if (jwk.use !== undefined && jwk.use !== "sig") return false;
  if (jwk.alg !== undefined && jwk.alg !== alg) return false;
  const d = cle.asymmetricKeyDetails ?? {};
  if (alg === "RS256" || alg === "PS256") return jwk.kty === "RSA" && cle.asymmetricKeyType === "rsa" && d.modulusLength >= 2048;
  if (alg === "ES256") return jwk.kty === "EC" && jwk.crv === "P-256" && cle.asymmetricKeyType === "ec" && d.namedCurve === "prime256v1";
  return false;
}

function signatureValide(alg, cle, donnees, signature) {
  try {
    if (alg === "RS256") return crypto.verify("sha256", donnees, { key: cle, padding: crypto.constants.RSA_PKCS1_PADDING }, signature);
    if (alg === "PS256") return crypto.verify("sha256", donnees, { key: cle, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
    if (alg === "ES256") return signature.length === 64 && crypto.verify("sha256", donnees, { key: cle, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
  return false;
}

const LISTE_FERMEE = new Set(["RS256", "PS256", "ES256"]);
const nombre = (v) => typeof v === "number" && Number.isFinite(v);

/**
 * Vérifie un jeton d'identité dans l'ordre d'EX-13.46.
 * @param {string} jeton
 * @param {{
 *   cles: {jwk: object, cle: crypto.KeyObject}[], relireCles: () => Promise<{jwk: object, cle: crypto.KeyObject}[]|null>,
 *   algs: string[], issuer: string, clientId: string, nonce: string, reauthS: number,
 *   creeMs: number, maintenantMs: number, estIdentiteCanonique: (v: unknown) => boolean,
 * }} o
 * @returns {Promise<{ok: false, point: number, code: string} | {ok: true, identite: string, authTimeMs: number}>}
 */
export async function verifierJeton(jeton, o) {
  const echec = (point) => ({ ok: false, point, code: point === 9 ? "identite_invalide" : "jeton_invalide" });
  // 1. JWS compact de trois parties, en-tête JSON sans `crit`, `alg` admis
  const parties = typeof jeton === "string" ? jeton.split(".") : [];
  if (parties.length !== 3) return echec(1);
  const octetsEntete = deB64u(parties[0]);
  if (octetsEntete === null) return echec(1);
  let entete;
  try {
    entete = lireJsonStrict(octetsEntete);
  } catch {
    return echec(1);
  }
  if (!estObjet(entete) || Object.hasOwn(entete, "crit")) return echec(1);
  if (typeof entete.alg !== "string" || !LISTE_FERMEE.has(entete.alg) || !o.algs.includes(entete.alg)) return echec(1);
  const alg = entete.alg;
  // 2. clé du jeu en cache, signature
  const octetsCharge = deB64u(parties[1]);
  const signature = deB64u(parties[2]);
  if (octetsCharge === null || signature === null) return echec(2);
  const avecKid = Object.hasOwn(entete, "kid");
  if (avecKid && typeof entete.kid !== "string") return echec(2);
  const candidates = (cles) => cles.filter((k) => (!avecKid || k.jwk.kid === entete.kid) && compatible(k, alg));
  let cles = o.cles;
  if (avecKid && !cles.some((k) => k.jwk.kid === entete.kid)) {
    const relues = await o.relireCles();
    if (relues !== null) cles = relues;
  }
  const retenues = candidates(cles);
  if (retenues.length !== 1) return echec(2);
  if (!signatureValide(alg, retenues[0].cle, Buffer.from(`${parties[0]}.${parties[1]}`, "ascii"), signature)) return echec(2);
  let charge;
  try {
    charge = lireJsonStrict(octetsCharge);
  } catch {
    return echec(3);
  }
  if (!estObjet(charge)) return echec(3);
  // 3. émetteur
  if (charge.iss !== o.issuer) return echec(3);
  // 4. audience
  const aud = charge.aud;
  if (!(aud === o.clientId || (Array.isArray(aud) && aud.length === 1 && aud[0] === o.clientId))) return echec(4);
  if (Object.hasOwn(charge, "azp") && charge.azp !== o.clientId) return echec(4);
  // 5. instants
  const maintenantS = o.maintenantMs / 1000;
  if (!nombre(charge.exp) || !nombre(charge.iat)) return echec(5);
  if (!(maintenantS < charge.exp + TOLERANCE_S)) return echec(5);
  if (!(charge.iat >= maintenantS - 600 && charge.iat <= maintenantS + TOLERANCE_S)) return echec(5);
  if (Object.hasOwn(charge, "nbf") && !(nombre(charge.nbf) && charge.nbf <= maintenantS + TOLERANCE_S)) return echec(5);
  // 6. nonce
  if (typeof charge.nonce !== "string" || charge.nonce !== o.nonce) return echec(6);
  // 7. instant d'authentification
  const at = charge.auth_time;
  if (!nombre(at) || at > maintenantS + TOLERANCE_S) return echec(7);
  if (o.reauthS > 0 ? at < maintenantS - o.reauthS - TOLERANCE_S : at < o.creeMs / 1000 - TOLERANCE_S) return echec(7);
  // 8. sujet
  if (typeof charge.sub !== "string") return echec(8);
  // 9. identité canonique
  const identite = `oidc ${charge.iss} ${charge.sub}`;
  if (!o.estIdentiteCanonique(identite)) return echec(9);
  return { ok: true, identite, authTimeMs: Math.floor(at * 1000) };
}

/** Fournisseur OIDC du serveur : copie de la découverte et du jeu de clés, connexion, retour. */
export class FournisseurOidc {
  /**
   * @param {{identity: object, secret: string, origine: string, reauthS: number, horloge: () => number,
   *   agentHttps?: https.Agent, journal: Function, transactions: import("./sessions.mjs").Transactions,
   *   estIdentiteCanonique: (v: unknown) => boolean}} o
   */
  constructor(o) {
    this.identity = o.identity;
    this.secret = o.secret;
    this.origine = o.origine;
    this.reauthS = o.reauthS;
    this.horloge = o.horloge;
    this.agent = o.agentHttps ?? null;
    this.journal = o.journal;
    this.transactions = o.transactions;
    this.estIdentiteCanonique = o.estIdentiteCanonique;
    this.cacheMs = o.identity.cache_s * 1000;
    /** @type {{doc: object, cles: object[], luMs: number}|null} */
    this.copie = null;
    this.prochaineLectureMs = 0;
    this.derniereRelectureClesMs = -Infinity;
    this.lecture = null;
  }

  get urlDecouverte() {
    return this.identity.issuer.replace(/\/$/, "") + "/.well-known/openid-configuration";
  }

  async #lireJson(url) {
    const r = await requeteFournisseur(url, { agent: this.agent, entetes: { accept: "application/json" } });
    if (r.statut !== 200) throw new Error(`statut ${r.statut}`);
    return lireJsonStrict(r.corps);
  }

  /** Lit la découverte puis le jeu de clés ; garde la copie précédente en cas d'échec. */
  lire() {
    if (this.lecture) return this.lecture;
    this.lecture = (async () => {
      let cause = null;
      try {
        let doc;
        try {
          doc = await this.#lireJson(this.urlDecouverte);
        } catch (e) {
          throw new Error(e instanceof FournisseurMuet ? "decouverte injoignable" : "decouverte illisible");
        }
        const c = causeDecouverte(doc, this.identity.issuer);
        if (c !== null) throw new Error(c);
        let jeu;
        try {
          jeu = await this.#lireJson(doc.jwks_uri);
        } catch (e) {
          throw new Error(e instanceof FournisseurMuet ? "jeu de cles injoignable" : "jeu de cles illisible");
        }
        const cles = clesDuJeu(jeu);
        if (cles === null) throw new Error("jeu de cles illisible");
        const luMs = this.horloge();
        this.copie = { doc, cles, luMs };
        this.prochaineLectureMs = luMs + this.cacheMs / 2;
      } catch (e) {
        cause = e.message;
        this.prochaineLectureMs = this.horloge() + RELECTURE_MS;
      } finally {
        this.lecture = null;
      }
      this.journal("decouverte_oidc", { ok: cause === null, cause });
    })();
    return this.lecture;
  }

  /** Copie de la découverte et du jeu de clés lue depuis moins de `cache_s` (EX-13.44). */
  pret() {
    return this.copie !== null && this.horloge() - this.copie.luMs < this.cacheMs;
  }

  /**
   * `identity_ready` d'EX-13.44 (révision 0.6) : copie lue depuis moins de
   * `cache_s` et qui permet une connexion (PKCE `S256` et
   * `client_secret_basic` admis par le document, s'il les annonce).
   */
  identitePrete() {
    return this.refusConnexion() === null;
  }

  /** Relecture d'avance ou retentée, selon l'horloge (appelée chaque seconde). */
  async entretien() {
    if (this.lecture === null && this.horloge() >= this.prochaineLectureMs) await this.lire();
  }

  /** Raison de refuser une connexion avec la copie tenue, ou `null`. */
  refusConnexion() {
    if (!this.pret()) return "fournisseur_indisponible";
    const doc = this.copie.doc;
    const pkce = doc.code_challenge_methods_supported;
    if (pkce !== undefined && !(Array.isArray(pkce) && pkce.includes("S256"))) return "fournisseur_erreur";
    const auth = doc.token_endpoint_auth_methods_supported;
    if (auth !== undefined && !(Array.isArray(auth) && auth.includes("client_secret_basic"))) return "fournisseur_erreur";
    return null;
  }

  /**
   * `GET /connexion` (EX-13.45, point 2) : transaction et adresse de redirection.
   * @param {string|null} sid session que portait la requête
   * @param {string} retour chemin retenu
   * @returns {{code: string} | {cookie: string, location: string}}
   */
  debut(sid, retour) {
    const refus = this.refusConnexion();
    if (refus !== null) return { code: refus };
    const transaction = {
      tid: b64u(crypto.randomBytes(16)),
      state: b64u(crypto.randomBytes(16)),
      nonce: b64u(crypto.randomBytes(16)),
      code_verifier: b64u(crypto.randomBytes(32)),
      created_at: this.horloge(),
      retour,
      sid,
    };
    const u = new URL(this.copie.doc.authorization_endpoint);
    const p = u.searchParams;
    p.append("response_type", "code");
    p.append("client_id", this.identity.client_id);
    p.append("redirect_uri", `${this.origine}/connexion/retour`);
    p.append("scope", "openid");
    p.append("state", transaction.state);
    p.append("nonce", transaction.nonce);
    p.append("code_challenge", defiPkce(transaction.code_verifier));
    p.append("code_challenge_method", "S256");
    p.append("max_age", String(this.reauthS));
    if (this.reauthS === 0) p.append("prompt", "login");
    return { cookie: this.transactions.sceller(transaction), location: u.href };
  }

  /** Jeu de clés relu pour un `kid` inconnu, au plus une fois par période de 60 s. */
  async #relireCles() {
    const maintenant = this.horloge();
    if (maintenant - this.derniereRelectureClesMs < RELECTURE_MS || this.copie === null) return null;
    this.derniereRelectureClesMs = maintenant;
    try {
      const cles = clesDuJeu(await this.#lireJson(this.copie.doc.jwks_uri));
      if (cles === null) return null;
      this.copie = { ...this.copie, cles };
      return cles;
    } catch {
      return null;
    }
  }

  /**
   * `GET /connexion/retour` (EX-13.45, points 3 à 5, EX-13.46).
   * @param {URLSearchParams} params
   * @param {string|null} valeurCookie
   * @returns {Promise<{code: string, point?: number, erreurFournisseur?: string} | {identite: string, authTimeMs: number, sid: string|null, retour: string}>}
   */
  async retour(params, valeurCookie) {
    const t = this.transactions.consommer(valeurCookie);
    const state = params.get("state");
    if (t === null || state === null || !egauxTempsConstant(Buffer.from(state, "utf8"), Buffer.from(t.state, "utf8"))) return { code: "transaction_inconnue" };
    if (params.has("error")) return { code: "fournisseur_erreur", erreurFournisseur: params.get("error") };
    if (params.has("iss") && params.get("iss") !== this.identity.issuer) return { code: "fournisseur_erreur" };
    const code = params.get("code");
    if (code === null || code === "") return { code: "fournisseur_erreur" };
    const refus = this.refusConnexion();
    if (refus !== null) return { code: refus };
    const doc = this.copie.doc;
    const corps = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${this.origine}/connexion/retour`,
      code_verifier: t.code_verifier,
    }).toString();
    let r;
    try {
      r = await requeteFournisseur(doc.token_endpoint, {
        methode: "POST",
        agent: this.agent,
        corps,
        entetes: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(corps)),
          accept: "application/json",
          authorization: enteteBasic(this.identity.client_id, this.secret),
        },
      });
    } catch (e) {
      return { code: e instanceof ReponseTropGrande ? "fournisseur_erreur" : "fournisseur_indisponible" };
    }
    if (r.statut !== 200) return { code: "fournisseur_erreur" };
    let reponse;
    try {
      reponse = lireJsonStrict(r.corps);
    } catch {
      return { code: "fournisseur_erreur" };
    }
    if (!estObjet(reponse) || typeof reponse.id_token !== "string") return { code: "fournisseur_erreur" };
    const v = await verifierJeton(reponse.id_token, {
      cles: this.copie.cles,
      relireCles: () => this.#relireCles(),
      algs: this.identity.id_token_signing_alg_values,
      issuer: this.identity.issuer,
      clientId: this.identity.client_id,
      nonce: t.nonce,
      reauthS: this.reauthS,
      creeMs: t.created_at,
      maintenantMs: this.horloge(),
      estIdentiteCanonique: this.estIdentiteCanonique,
    });
    if (!v.ok) return { code: v.code, point: v.point };
    return { identite: v.identite, authTimeMs: v.authTimeMs, sid: t.sid, retour: t.retour };
  }
}
