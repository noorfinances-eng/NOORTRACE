// Serveur HTTPS de la console (CT-3 13.20, 13.21 ; contrat 2.4 à 2.13) :
// adresses d'EX-13.43, ordre de traitement de 2.5 (garde d'hôte, en-tête
// `Origin`, type de média, chemin et méthode, taille, forme du corps, route),
// en-têtes de 2.6 sur chaque réponse, sessions d'EX-13.48, OIDC
// d'EX-13.45 et EX-13.46 ou système local d'EX-13.47, relais vers le service
// avec `session_identity` imposée et réauthentification (EX-13.8, EX-13.49),
// santé d'EX-13.44, fichiers du manifeste des pages.

import https from "node:https";
import { lireJsonStrict } from "@noortrace/approbation";
import { conformeService, refusDemarrage } from "./configuration.mjs";
import { ClientService, ServiceIndisponible } from "./service.mjs";
import {
  Sessions,
  Transactions,
  COOKIE_SESSION,
  COOKIE_CONNEXION,
  lireCookie,
  cookieSession,
  cookieConnexion,
  effacerSession,
  effacerConnexion,
} from "./sessions.mjs";
import { FournisseurOidc } from "./oidc.mjs";
import { SystemeLocal } from "./local.mjs";
import { horodatage, estTicket, retourRetenu } from "./outils.mjs";

export const TAILLE_MAX_CORPS = 65536;
export const DELAI_SANTE_MS = 5000;
const DUREE_REAUTH_ZERO_MS = 600000;

const GET = Object.freeze(["GET", "HEAD"]);
const POST = Object.freeze(["POST"]);

/** Échappement HTML d'un texte. */
const echapperHtml = (t) => String(t).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

/** Messages ASCII des erreurs que le serveur rend lui-même. */
const MESSAGES = Object.freeze({
  hote_refuse: "hote refuse",
  origine_refusee: "origine refusee",
  session_absente: "session absente",
  service_indisponible: "service indisponible",
  identifiants_refuses: "identifiants refuses",
  essai_trop_tot: "essai trop tot",
  transaction_inconnue: "transaction inconnue",
  fournisseur_erreur: "erreur du fournisseur d'identite",
  fournisseur_indisponible: "fournisseur d'identite indisponible",
  jeton_invalide: "jeton d'identite invalide",
  identite_invalide: "identite de session invalide",
});

const STATUTS = Object.freeze({
  hote_refuse: 421,
  origine_refusee: 403,
  session_absente: 401,
  reauthentification_requise: 401,
  service_indisponible: 504,
  identifiants_refuses: 401,
  essai_trop_tot: 429,
  transaction_inconnue: 400,
  fournisseur_erreur: 400,
  fournisseur_indisponible: 502,
  jeton_invalide: 400,
  identite_invalide: 400,
});

/**
 * Corps relayé avec `session_identity` posée à l'identité de la session :
 * le membre est remplacé à sa place s'il existe, ajouté à la fin sinon ;
 * tous les autres octets du corps restent tels quels (13.18, contrat 2.10).
 * @param {string} texte objet JSON strict
 * @param {string} identite
 * @returns {string}
 */
export function imposerIdentite(texte, identite) {
  let i = 0;
  const blancs = () => {
    while (i < texte.length && " \t\n\r".includes(texte[i])) i++;
  };
  const chaine = () => {
    const debut = i;
    i++;
    while (texte[i] !== '"') i += texte[i] === "\\" ? 2 : 1;
    i++;
    return texte.slice(debut, i);
  };
  const valeur = () => {
    if (texte[i] === '"') return chaine();
    let profondeur = 0;
    while (i < texte.length) {
      const c = texte[i];
      if (c === '"') {
        chaine();
        continue;
      }
      if (c === "{" || c === "[") profondeur++;
      else if (c === "}" || c === "]") {
        if (profondeur === 0) break;
        profondeur--;
        if (profondeur === 0) {
          i++;
          break;
        }
      } else if (c === "," && profondeur === 0) break;
      else if (profondeur === 0 && " \t\n\r".includes(c)) break;
      i++;
    }
    return null;
  };
  const membres = [];
  blancs();
  i++; // {
  blancs();
  while (texte[i] !== "}") {
    const cle = JSON.parse(chaine());
    blancs();
    i++; // :
    blancs();
    const debut = i;
    valeur();
    membres.push({ cle, debut, fin: i });
    blancs();
    if (texte[i] === ",") {
      i++;
      blancs();
    }
  }
  const nouvelle = JSON.stringify(identite);
  const present = membres.find((m) => m.cle === "session_identity");
  if (present) return texte.slice(0, present.debut) + nouvelle + texte.slice(present.fin);
  const dernier = membres.at(-1);
  const insertion = dernier ? dernier.fin : texte.indexOf("{") + 1;
  return texte.slice(0, insertion) + (dernier ? "," : "") + `"session_identity":${nouvelle}` + texte.slice(insertion);
}

/**
 * Démarre l'écoute HTTPS ; la configuration est complétée et ses références
 * résolues.
 * @param {{config: object, secrets: object, horloge: () => number, agentHttps?: https.Agent, pages: object,
 *   journal: Function, bibliotheque: {estIdentiteCanonique: Function, METHODES_CANAL: string[], METHODES_REAUTHENTIFICATION: string[]}}} o
 */
export async function ecouter({ config, secrets, horloge, agentHttps, pages, journal, bibliotheque }) {
  const origine = config.console_origin;
  const autorite = origine.slice("https://".length);
  const local = config.identity.kind === "local";
  const reauthS = config.reauth_max_age_s;
  const METHODES = new Set(bibliotheque.METHODES_CANAL);
  const REAUTH = new Set(bibliotheque.METHODES_REAUTHENTIFICATION);
  const sessions = new Sessions({ horloge, dureeS: config.session_max_age_s, journal });
  const transactions = new Transactions({ horloge });
  const service = new ClientService({ service: config.service, secrets: secrets.service, agentHttps });
  let fournisseur = null;
  let systeme = null;
  if (local) {
    systeme = new SystemeLocal({ comptes: secrets.identity.comptes, domaine: config.identity.domain, horloge });
  } else {
    fournisseur = new FournisseurOidc({
      identity: config.identity,
      secret: secrets.identity.secret,
      origine,
      reauthS,
      horloge,
      agentHttps,
      journal,
      transactions,
      estIdentiteCanonique: bibliotheque.estIdentiteCanonique,
    });
    await fournisseur.lire();
  }

  // ---------------------------------------------------------------- santé
  let sante = null; // { joignable, instant } ou promesse en cours
  let santeEnCours = null;
  async function serviceJoignable() {
    if (sante !== null && horloge() - sante.instant < DELAI_SANTE_MS) return sante.joignable;
    if (santeEnCours === null) {
      santeEnCours = service.joignable((o) => lireJsonStrict(o)).then((joignable) => {
        sante = { joignable, instant: horloge() };
        santeEnCours = null;
        return joignable;
      });
    }
    return santeEnCours;
  }

  // ---------------------------------------------------------------- réponses
  const CSP =
    `default-src 'none'; script-src 'self' '${pages.carteSha256}'; style-src 'self'; img-src 'self' data:; connect-src 'self'; ` +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'";

  function envoyer(ctx, statut, { corps = null, type = null, entetes = {}, cookies = [] } = {}) {
    const res = ctx.res;
    if (res.headersSent) return;
    res.statusCode = statut;
    res.setHeader("Content-Security-Policy", CSP);
    res.setHeader("Integrity-Policy", "blocked-destinations=(script)");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Strict-Transport-Security", "max-age=31536000");
    res.setHeader("Cache-Control", ctx.chemin.startsWith("/statique/") ? "no-cache" : "no-store");
    for (const [k, v] of Object.entries(entetes)) res.setHeader(k, v);
    if (cookies.length) res.setHeader("Set-Cookie", cookies);
    if (ctx.fermer) res.setHeader("Connection", "close");
    if (corps !== null) {
      res.setHeader("Content-Type", type);
      res.setHeader("Content-Length", String(corps.length));
    } else if (statut !== 204) res.setHeader("Content-Length", "0");
    if (ctx.methode === "HEAD" || corps === null) res.end();
    else res.end(corps);
  }

  const json = (ctx, statut, valeur, options = {}) =>
    envoyer(ctx, statut, { ...options, corps: Buffer.from(JSON.stringify(valeur), "utf8"), type: "application/json; charset=utf-8" });

  function pageErreur(code, erreurFournisseur) {
    const feuille = pages.feuille ? `<link rel="stylesheet" href="${pages.feuille.chemin}" integrity="${pages.feuille.sha384}">` : "";
    const fournisseurHtml =
      erreurFournisseur !== undefined && erreurFournisseur !== null
        ? `<p>Réponse du fournisseur d'identité : <code>${echapperHtml(erreurFournisseur)}</code></p>`
        : "";
    return Buffer.from(
      '<!doctype html>\n<html lang="fr">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
        `<title>Connexion impossible</title>\n${feuille}\n</head>\n<body>\n<main>\n<h1>Connexion impossible</h1>\n` +
        `<p>Code : <code>${echapperHtml(code)}</code></p>\n${fournisseurHtml}\n<p><a href="/connexion">Se connecter de nouveau</a></p>\n</main>\n</body>\n</html>\n`,
      "utf8",
    );
  }

  /** Erreur rendue par le serveur : `$defs/erreur`, ou page HTML sur les navigations de connexion. */
  function erreur(ctx, statut, code, { message, data = {}, entetes = {}, cookies = [], erreurFournisseur } = {}) {
    if (ctx.html) {
      return envoyer(ctx, statut, { corps: pageErreur(code, erreurFournisseur), type: "text/html; charset=utf-8", entetes, cookies });
    }
    return json(ctx, statut, { error: { code, message: message ?? MESSAGES[code] ?? code.replace(/_/g, " "), data } }, { entetes, cookies });
  }

  const requeteInvalide = (ctx, statut, message, entetes) => erreur(ctx, statut, "requete_invalide", { message, entetes });

  // ---------------------------------------------------------------- routes
  /** Route d'un chemin (étape 4), ou `null` pour un chemin inconnu. */
  function route(chemin) {
    switch (chemin) {
      case "/":
        return { nom: "racine", methodes: GET };
      case "/tickets":
        return { nom: "ecran", ecran: "tickets", methodes: GET };
      case "/inscription":
        return { nom: "ecran", ecran: "inscription", methodes: GET };
      case "/annuaire":
        return { nom: "ecran", ecran: "annuaire", methodes: GET };
      case "/connexion":
        return { nom: "connexion", methodes: GET };
      case "/connexion/retour":
        return local ? null : { nom: "retour", methodes: GET };
      case "/connexion/locale":
        return local ? { nom: "locale", methodes: POST, corps: "connexion_locale" } : null;
      case "/deconnexion":
        return { nom: "deconnexion", methodes: POST, corps: "deconnexion" };
      case "/v0/session":
        return { nom: "session", methodes: POST, corps: "session" };
      case "/v0/sante":
        return { nom: "sante", methodes: GET };
      default:
        break;
    }
    if (chemin.startsWith("/tickets/") && estTicket(chemin.slice(9))) return { nom: "ecran", ecran: "ticket", methodes: GET };
    if (chemin.startsWith("/v0/") && METHODES.has(chemin.slice(4))) return { nom: "relais", methode: chemin.slice(4), methodes: POST, corps: "objet" };
    if (pages.statiques.has(chemin)) return { nom: "statique", methodes: GET };
    return null;
  }

  /** Lit au plus 65 537 octets du corps ; `null` au-delà de 65 536. */
  function lireCorps(req) {
    return new Promise((resoudre, rejeter) => {
      const morceaux = [];
      let taille = 0;
      let fini = false;
      req.on("data", (d) => {
        if (fini) return;
        taille += d.length;
        if (taille > TAILLE_MAX_CORPS) {
          fini = true;
          req.pause();
          resoudre(null);
        } else morceaux.push(d);
      });
      req.on("end", () => {
        if (!fini) {
          fini = true;
          resoudre(Buffer.concat(morceaux));
        }
      });
      req.on("error", (e) => {
        if (!fini) {
          fini = true;
          rejeter(e);
        }
      });
    });
  }

  /** Ouvre une session et relaie `annuaire` pour fixer le rôle (EX-13.48, points 1 et 4). */
  async function ouvrirSession({ identite, authTimeMs, precedente }) {
    if (precedente) sessions.detruire(precedente, "remplacee");
    const { session, cookie } = sessions.creer({ identite, authTimeMs, systeme: config.identity.kind });
    journal("session_ouverte", { session_identity: identite, auth_time: horodatage(authTimeMs), systeme: config.identity.kind });
    const corps = Buffer.from(JSON.stringify({ session_identity: identite }), "utf8");
    const r = await appelerService(session, "annuaire", corps);
    if (r !== null) majRole(session, r);
    return cookie;
  }

  function majRole(session, r) {
    if (r.statut !== 200) return;
    let doc = null;
    try {
      doc = lireJsonStrict(r.corps);
    } catch {
      doc = null;
    }
    session.administrator = doc !== null && typeof doc === "object" && Array.isArray(doc.administrators) && doc.administrators.includes(session.identite);
  }

  /** Relaie une méthode ; rend `{ statut, corps }` ou `null` (service indisponible). */
  async function appelerService(session, methode, corps) {
    const debut = horloge();
    let r = null;
    try {
      r = await service.relayer(methode, corps, config.service_timeout_ms);
    } catch (e) {
      if (!(e instanceof ServiceIndisponible)) throw e;
    }
    journal("relais", {
      methode,
      statut: r === null ? 504 : r.statut,
      duree_ms: horloge() - debut,
      session_identity: session.identite,
      auth_time: horodatage(session.authTimeMs),
    });
    return r;
  }

  // ---------------------------------------------------------------- traitement
  async function traiter(req, res) {
    const cible = req.url ?? "";
    const q = cible.indexOf("?");
    const chemin = q < 0 ? cible : cible.slice(0, q);
    const requete = q < 0 ? "" : cible.slice(q + 1);
    const methode = req.method;
    const ctx = {
      res,
      methode,
      chemin,
      html: (methode === "GET" || methode === "HEAD") && (chemin === "/connexion" || chemin === "/connexion/retour"),
      fermer: false,
    };
    const longueur = req.headers["content-length"];
    const annonce = (longueur !== undefined && Number(longueur) !== 0) || req.headers["transfer-encoding"] !== undefined;
    // le corps n'est pas lu avant l'étape 5 : la connexion est fermée après une réponse antérieure
    ctx.fermer = annonce;

    // 1. garde d'hôte
    if ((req.headers.host ?? "").toLowerCase() !== autorite) return erreur(ctx, 421, "hote_refuse");
    // 2. en-tête Origin
    if (methode !== "GET" && methode !== "HEAD" && req.headers.origin !== origine) return erreur(ctx, 403, "origine_refusee");
    // 3. type de média d'un corps annoncé
    if (annonce) {
      const type = (req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
      if (type !== "application/json") return requeteInvalide(ctx, 400, "type de media non application/json");
    }
    // 4. chemin et méthode
    const r = route(chemin);
    if (r === null) return requeteInvalide(ctx, 404, "chemin inconnu");
    if (!r.methodes.includes(methode)) return requeteInvalide(ctx, 405, "methode non admise", { Allow: r.methodes.join(", ") });
    // 5. taille
    let brut = Buffer.alloc(0);
    if (annonce) {
      if (longueur !== undefined && Number(longueur) > TAILLE_MAX_CORPS) return requeteInvalide(ctx, 413, "corps trop grand");
      try {
        brut = await lireCorps(req);
      } catch {
        res.destroy();
        return;
      }
      if (brut === null) return requeteInvalide(ctx, 413, "corps trop grand");
      ctx.fermer = false;
    }
    // 6. forme du corps
    let corps;
    if (brut.length > 0 || r.corps !== undefined) {
      try {
        corps = lireJsonStrict(brut);
      } catch {
        corps = undefined;
      }
      const estObjet = corps !== null && typeof corps === "object" && !Array.isArray(corps);
      const vide = brut.length === 0;
      let bon = corps !== undefined;
      if (r.corps === "connexion_locale") bon = bon && conformeService("requete_connexion_locale", corps);
      else if (r.corps === "session") bon = bon && conformeService("requete_session", corps);
      else if (r.corps === "objet") bon = bon && estObjet;
      else if (r.corps === "deconnexion") bon = vide || (estObjet && Object.keys(corps).length === 0);
      if (!bon) return requeteInvalide(ctx, 400, "corps non conforme");
    }
    // 7. route
    switch (r.nom) {
      case "racine":
        return envoyer(ctx, 303, { entetes: { Location: "/tickets" } });
      case "ecran":
        return envoyer(ctx, 200, { corps: pages.ecrans.get(r.ecran), type: "text/html; charset=utf-8" });
      case "statique": {
        const f = pages.statiques.get(chemin);
        return envoyer(ctx, 200, { corps: f.octets, type: f.type });
      }
      case "sante": {
        const joignable = await serviceJoignable();
        // révision 0.6 : faux aussi pour une copie qui fait refuser chaque connexion
        const pret = local ? true : fournisseur.identitePrete();
        return json(ctx, 200, { ready: joignable && pret, service_reachable: joignable, identity_ready: pret, checked_at: horodatage(horloge()) });
      }
      case "connexion":
        return connexion(ctx, req, requete);
      case "retour":
        return retourOidc(ctx, req, requete);
      case "locale":
        return connexionLocale(ctx, req, corps);
      case "deconnexion": {
        const s = sessions.lire(lireCookie(req.headers.cookie, COOKIE_SESSION));
        if (s) sessions.detruire(s.sid, "deconnexion");
        return envoyer(ctx, 204, { cookies: [effacerSession(), effacerConnexion()] });
      }
      case "session": {
        const s = sessions.lire(lireCookie(req.headers.cookie, COOKIE_SESSION));
        if (!s) return erreur(ctx, 401, "session_absente");
        return json(ctx, 200, {
          session_identity: s.identite,
          auth_time: horodatage(s.authTimeMs),
          administrator: s.administrator,
          reauth_max_age_s: reauthS,
          delai_signature_ms: config.delai_signature_ms,
        });
      }
      case "relais":
        return relais(ctx, req, r.methode, brut);
      default:
        throw new Error("route inconnue");
    }
  }

  function connexion(ctx, req, requete) {
    if (local) return envoyer(ctx, 200, { corps: pages.ecrans.get("connexion"), type: "text/html; charset=utf-8" });
    const retour = retourRetenu(new URLSearchParams(requete).get("retour"));
    const s = sessions.lire(lireCookie(req.headers.cookie, COOKIE_SESSION));
    const d = fournisseur.debut(s ? s.sid : null, retour);
    if (d.code) {
      journal("connexion_refusee", { code: d.code });
      return erreur(ctx, STATUTS[d.code], d.code);
    }
    return envoyer(ctx, 303, { entetes: { Location: d.location }, cookies: [cookieConnexion(d.cookie)] });
  }

  async function retourOidc(ctx, req, requete) {
    const r = await fournisseur.retour(new URLSearchParams(requete), lireCookie(req.headers.cookie, COOKIE_CONNEXION));
    if (r.code) {
      journal("connexion_refusee", { code: r.code });
      return erreur(ctx, STATUTS[r.code], r.code, { cookies: [effacerConnexion()], erreurFournisseur: r.erreurFournisseur });
    }
    const cookie = await ouvrirSession({ identite: r.identite, authTimeMs: r.authTimeMs, precedente: r.sid });
    return envoyer(ctx, 303, { entetes: { Location: r.retour }, cookies: [cookieSession(cookie), effacerConnexion()] });
  }

  async function connexionLocale(ctx, req, corps) {
    const v = await systeme.verifier(corps.name, corps.password);
    if (!v.ok) {
      journal("connexion_refusee", { code: v.code });
      if (v.code === "essai_trop_tot") {
        return erreur(ctx, 429, "essai_trop_tot", { data: { retry_after_s: v.retryAfterS }, entetes: { "Retry-After": String(v.retryAfterS) } });
      }
      return erreur(ctx, 401, v.code);
    }
    const precedente = sessions.lire(lireCookie(req.headers.cookie, COOKIE_SESSION));
    const cookie = await ouvrirSession({ identite: v.identite, authTimeMs: v.authTimeMs, precedente: precedente?.sid });
    return envoyer(ctx, 204, { cookies: [cookieSession(cookie)] });
  }

  async function relais(ctx, req, methode, brut) {
    const s = sessions.lire(lireCookie(req.headers.cookie, COOKIE_SESSION));
    if (!s) return erreur(ctx, 401, "session_absente");
    if (REAUTH.has(methode)) {
      const ecoule = horloge() - s.authTimeMs;
      // reauth_max_age_s = 0 (EX-13.48, point 5, révision 0.6) : une
      // authentification vaut pour la première méthode de la liste relayée
      // dans les 600 s ; quand c'est `preparer_inscription`, elle vaut aussi
      // pour la première `inscrire` qui suit, et pour elle seule. Une méthode
      // compte comme relayée dès son envoi : les drapeaux sont posés avant
      // l'appel, de sorte que deux requêtes simultanées ne passent pas.
      const inscriptionCouverte = reauthS === 0 && methode === "inscrire" && s.inscriptionCouverte === true;
      const admis = reauthS > 0 ? ecoule < reauthS * 1000 : (!s.reauthEmployee || inscriptionCouverte) && ecoule < DUREE_REAUTH_ZERO_MS;
      if (!admis) {
        journal("reauthentification_requise", { methode, auth_time: horodatage(s.authTimeMs) });
        const message = reauthS > 0 ? `authentification de plus de ${reauthS} s` : "authentification deja employee ou de plus de 600 s";
        return erreur(ctx, 401, "reauthentification_requise", { message, data: { reauth_max_age_s: reauthS } });
      }
      if (reauthS === 0) {
        s.inscriptionCouverte = !s.reauthEmployee && methode === "preparer_inscription";
        s.reauthEmployee = true;
      }
    }
    const corps = Buffer.from(imposerIdentite(brut.toString("utf8"), s.identite), "utf8");
    const r = await appelerService(s, methode, corps);
    if (r === null) return erreur(ctx, 504, "service_indisponible");
    if (methode === "annuaire") majRole(s, r);
    return envoyer(ctx, r.statut, { corps: r.corps, type: "application/json; charset=utf-8" });
  }

  // ---------------------------------------------------------------- écoute
  const serveur = https.createServer({ cert: secrets.tls.cert, key: secrets.tls.key }, (req, res) => {
    traiter(req, res).catch(() => {
      // erreur de programmation : 500 sans corps, sous les en-têtes de 2.6
      if (res.headersSent) res.destroy();
      else envoyer({ res, methode: req.method, chemin: (req.url ?? "").split("?")[0], html: false, fermer: true }, 500);
    });
  });
  // requête que l'analyseur HTTP de Node refuse avant le traitement : 400 requete_invalide, sous les en-têtes de 2.6
  serveur.on("clientError", (e, socket) => {
    if (e.code === "ECONNRESET" || e.code === "ERR_HTTP_REQUEST_TIMEOUT" || !socket.writable) return socket.destroy();
    const corps = JSON.stringify({ error: { code: "requete_invalide", message: "requete illisible", data: {} } });
    const lignes = [
      "HTTP/1.1 400 Bad Request",
      `Content-Security-Policy: ${CSP}`,
      "Integrity-Policy: blocked-destinations=(script)",
      "X-Content-Type-Options: nosniff",
      "Referrer-Policy: no-referrer",
      "Cross-Origin-Opener-Policy: same-origin",
      "Cross-Origin-Resource-Policy: same-origin",
      "Strict-Transport-Security: max-age=31536000",
      "Cache-Control: no-store",
      "Content-Type: application/json; charset=utf-8",
      `Content-Length: ${Buffer.byteLength(corps)}`,
      "Connection: close",
    ];
    socket.end(lignes.join("\r\n") + "\r\n\r\n" + corps);
  });
  await new Promise((resoudre, rejeter) => {
    const refus = (e) => rejeter(refusDemarrage("ecoute_impossible", "/listen", `écoute impossible (${e.code ?? "erreur"})`));
    serveur.once("error", refus);
    serveur.listen(config.listen.port, config.listen.host, () => {
      serveur.off("error", refus);
      resoudre();
    });
  });
  const entretien = setInterval(() => {
    sessions.purger();
    transactions.purger();
    if (fournisseur) fournisseur.entretien().catch(() => {});
  }, 1000);
  entretien.unref();
  return {
    serveur,
    async fermer() {
      clearInterval(entretien);
      await new Promise((resoudre) => {
        serveur.close(() => resoudre());
        serveur.closeAllConnections();
      });
    },
  };
}
