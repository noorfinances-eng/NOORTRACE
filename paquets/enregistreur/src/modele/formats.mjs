// Formats et fournisseurs du frontal modèle (CT-2 §5.1.1, §5.2, §5.3,
// §5.3.3, §5.5 pour le prompt système, §8.2 et EX-8.5) : normalisation du
// chemin et routes (EX-5.2, EX-5.28), chaîne de requête Gemini (EX-5.29),
// corps d'erreur de la passerelle au format de chaque fournisseur (EX-5.7,
// EX-5.24, EX-5.30, EX-5.33, 14.2), en-têtes en liste autorisée (5.3,
// EX-5.26), forme attendue d'une requête (EX-5.7 point 3), prompt système
// et son remplacement dans la pièce « requête » (5.5, EX-8.5), serveurs MCP
// et contenu en cache déclarés au fournisseur (EX-5.32), et règles de
// configuration du frontal (EX-15.4 pas 3).

import net from "node:net";

/** Formats de la version 0 (5.2). */
export const FORMATS = Object.freeze(["anthropic-messages", "openai-chat", "openai-responses", "gemini"]);

/** Motif d'un segment de modèle Gemini (EX-5.28). */
export const MOTIF_SEGMENT = /^[a-z0-9][a-z0-9.-]{0,127}$/;

/** Méthodes Gemini servies (EX-5.28). */
export const METHODES_GEMINI = Object.freeze(["generateContent", "streamGenerateContent"]);

/** Jeton de remplacement du prompt système dans la pièce « requête » (EX-8.5). */
export const JETON_PROMPT = "[REDIGE:prompt-systeme]";

const NON_RESERVES = /^[A-Za-z0-9\-._~]$/;

// ------------------------------------------------------------ chemin et routes (EX-5.2, EX-5.28)

/**
 * Normalise le chemin d'une requête (EX-5.2) : refus de `%2F`, d'un segment
 * `.` ou `..`, d'une barre oblique doublée, d'un octet hors de l'ASCII
 * imprimable ; décodage des seuls encodages pourcent de caractères non
 * réservés (RFC 3986 §6.2.2).
 * @param {string} cible cible reçue (chemin et chaîne de requête)
 * @returns {{ok: true, chemin: string, requete: string|null}|{ok: false, raison: string}}
 */
export function normaliserCible(cible) {
  if (typeof cible !== "string" || cible.length === 0 || cible[0] !== "/") return { ok: false, raison: "chemin" };
  for (let i = 0; i < cible.length; i++) {
    const c = cible.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return { ok: false, raison: "chemin" };
  }
  const k = cible.indexOf("?");
  const brut = k < 0 ? cible : cible.slice(0, k);
  const requete = k < 0 ? null : cible.slice(k + 1);
  if (/%2f/i.test(brut)) return { ok: false, raison: "chemin" };
  let chemin = "";
  for (let i = 0; i < brut.length; i++) {
    if (brut[i] === "%" && /^[0-9A-Fa-f]{2}$/.test(brut.slice(i + 1, i + 3))) {
      const c = String.fromCharCode(parseInt(brut.slice(i + 1, i + 3), 16));
      if (NON_RESERVES.test(c)) {
        chemin += c;
        i += 2;
        continue;
      }
    }
    chemin += brut[i];
  }
  if (chemin.includes("//")) return { ok: false, raison: "chemin" };
  const segments = chemin.split("/").slice(1);
  if (segments.some((s) => s === "." || s === "..")) return { ok: false, raison: "chemin" };
  return { ok: true, chemin, requete };
}

/**
 * Cherche la route d'une requête (EX-5.2, EX-5.28 ; 5.3.3 pas 2) : routes
 * `gemini` par préfixe, segment et méthode, puis égalité avec les routes
 * des autres formats, puis couples `passthrough`.
 * @param {object[]} routes `policy.model.routes`
 * @param {string} methode méthode HTTP
 * @param {string} chemin chemin normalisé
 * @returns {{genre: "echange", route: object, indice: number, segment?: string, methodeGemini?: string}
 *   |{genre: "passthrough", route: object, indice: number}|null}
 */
export function trouverRoute(routes, methode, chemin) {
  // Une route gemini nomme la collection : <path>/<modèle>:<méthode>.
  for (const [indice, route] of routes.entries()) {
    if (route.format !== "gemini" || methode !== "POST") continue;
    const prefixe = `${route.path}/`;
    if (!chemin.startsWith(prefixe)) continue;
    const reste = chemin.slice(prefixe.length);
    const k = reste.indexOf(":");
    if (k < 0) continue;
    const segment = reste.slice(0, k);
    const suffixe = reste.slice(k + 1);
    if (!MOTIF_SEGMENT.test(segment) || !METHODES_GEMINI.includes(suffixe)) continue;
    return { genre: "echange", route, indice, segment, methodeGemini: suffixe };
  }
  for (const [indice, route] of routes.entries()) {
    if (route.format !== "gemini" && methode === "POST" && route.path === chemin) return { genre: "echange", route, indice };
  }
  for (const [indice, route] of routes.entries()) {
    if ((route.passthrough ?? []).some((p) => p.method === methode && p.path === chemin)) return { genre: "passthrough", route, indice };
  }
  return null;
}

/**
 * Paramètres d'une chaîne de requête (EX-5.29) : coupée sur `&`, chaque
 * élément `nom=valeur` (ou `nom` seul), noms et valeurs décodés.
 * @param {string|null} requete
 * @returns {{nom: string, valeur: string}[]|null} null si un décodage échoue
 */
export function parametresRequete(requete) {
  if (requete === null || requete === "") return [];
  const sortie = [];
  for (const e of requete.split("&")) {
    const k = e.indexOf("=");
    const n = k < 0 ? e : e.slice(0, k);
    const v = k < 0 ? "" : e.slice(k + 1);
    try {
      sortie.push({ nom: decodeURIComponent(n.replace(/\+/g, "%20")), valeur: decodeURIComponent(v.replace(/\+/g, "%20")) });
    } catch {
      return null;
    }
  }
  return sortie;
}

/**
 * Chaîne de requête d'une route Gemini (EX-5.29).
 * @param {string} methodeGemini
 * @param {string|null} requete texte après le premier `?`, ou null
 * @returns {{ok: true, amont: string}|{ok: false, raison: "cle_dans_url"|"flux_sans_sse"|"parametre_non_admis", noms: string[]}}
 */
export function examinerRequeteGemini(methodeGemini, requete) {
  const params = parametresRequete(requete);
  const noms = (params ?? []).map((p) => (p.nom === "key" || p.nom === "alt" ? p.nom : `[autre:${Buffer.byteLength(p.nom, "utf8")}]`));
  if (params === null) return { ok: false, raison: "parametre_non_admis", noms };
  if (params.some((p) => p.nom === "key")) return { ok: false, raison: "cle_dans_url", noms };
  const alts = params.filter((p) => p.nom === "alt");
  if (methodeGemini === "streamGenerateContent" && !alts.some((p) => p.valeur === "sse")) return { ok: false, raison: "flux_sans_sse", noms };
  const autres = params.filter((p) => p.nom !== "alt");
  if (autres.length || alts.length > 1) return { ok: false, raison: "parametre_non_admis", noms };
  if (methodeGemini === "generateContent") {
    if (alts.length === 1 && alts[0].valeur !== "json") return { ok: false, raison: "parametre_non_admis", noms };
    return { ok: true, amont: "" };
  }
  return { ok: true, amont: "?alt=sse" };
}

/**
 * Une requête `streamGenerateContent` qui porte `alt=sse` reçoit ses refus en
 * `text/event-stream` (EX-5.30).
 * @param {string|undefined} methodeGemini
 * @param {string|null} requete
 */
export function refusEnFlux(methodeGemini, requete) {
  if (methodeGemini !== "streamGenerateContent") return false;
  return (parametresRequete(requete) ?? []).some((p) => p.nom === "alt" && p.valeur === "sse");
}

// ------------------------------------------------------------ corps d'erreur de la passerelle

/** Corps AIP-193 d'EX-5.30, par cas. */
const GEMINI = Object.freeze({
  corps_non_analysable: [400, "noortrace: corps de requete non analysable", "INVALID_ARGUMENT"],
  cle_dans_url: [400, "noortrace: cle d'API dans l'URL refusee", "INVALID_ARGUMENT"],
  flux_sans_sse: [400, "noortrace: streamGenerateContent exige alt=sse", "INVALID_ARGUMENT"],
  parametre_non_admis: [400, "noortrace: parametre de requete non admis", "INVALID_ARGUMENT"],
  serveurs_mcp_fournisseur: [400, "noortrace: serveurs MCP declares au fournisseur refuses", "INVALID_ARGUMENT"],
  cache_fournisseur: [400, "noortrace: contenu en cache du fournisseur refuse", "INVALID_ARGUMENT"],
  hote_inconnu: [401, "noortrace: hote non authentifie", "UNAUTHENTICATED"],
  taille: [413, "noortrace: corps de requete trop grand", "INVALID_ARGUMENT"],
  content_encoding: [415, "noortrace: requete comprimee refusee", "INVALID_ARGUMENT"],
  degrade: [503, "noortrace: echange bloque, enregistreur en mode degrade", "UNAVAILABLE"],
  delai: [504, "noortrace: delai du fournisseur depasse", "DEADLINE_EXCEEDED"],
});

/** Statut, message, type d'erreur et code des autres formats. */
const AUTRES = Object.freeze({
  corps_non_analysable: [400, "noortrace: corps de requete non analysable", "invalid_request_error", "noortrace_requete_invalide"],
  hote_inconnu: [401, "noortrace: hote non authentifie", "authentication_error", "noortrace_hote_inconnu"],
  taille: [413, "noortrace: corps de requete trop grand", "noortrace_taille", "noortrace_taille"],
  content_encoding: [415, "noortrace: requete comprimee refusee", "invalid_request_error", "noortrace_requete_comprimee"],
  degrade: [503, "noortrace: echange bloque, enregistreur en mode degrade", "noortrace_degrade", "noortrace_degrade"],
  delai: [504, "noortrace: delai du fournisseur depasse", "noortrace_timeout", "noortrace_timeout"],
});

/**
 * Réponse que la passerelle produit elle-même pour une route (EX-5.7,
 * EX-5.24, EX-5.30, EX-5.33, 14.2).
 * @param {string} format
 * @param {string} cas raison du refus
 * @param {{enFlux?: boolean}} [o] Gemini : refus d'un `streamGenerateContent?alt=sse`
 * @returns {{statut: number, contentType: string, corps: string}}
 */
export function reponseRefus(format, cas, o = {}) {
  if (format === "gemini") {
    const [code, message, status] = GEMINI[cas];
    return {
      statut: code,
      contentType: o.enFlux ? "text/event-stream" : "application/json; charset=UTF-8",
      corps: JSON.stringify({ error: { code, message, status } }),
    };
  }
  const [statut, message, type, code] = AUTRES[cas];
  // Délai (EX-5.24) : un corps unique hors Gemini ; Messages, ou Chat
  // Completions et Responses, sinon.
  if (format === "anthropic-messages" || cas === "delai") {
    const t = cas === "corps_non_analysable" || cas === "content_encoding" ? "invalid_request_error" : type;
    return { statut, contentType: "application/json", corps: JSON.stringify({ type: "error", error: { type: t, message } }) };
  }
  const t = cas === "taille" || cas === "hote_inconnu" ? "invalid_request_error" : type;
  return { statut, contentType: "application/json", corps: JSON.stringify({ error: { message, type: t, param: null, code } }) };
}

// ------------------------------------------------------------ en-têtes (5.3, EX-5.26)

/** En-têtes relayés vers le fournisseur et notés (5.3). */
const RELAYES_NOTES = new Set(["anthropic-version", "anthropic-beta", "openai-organization", "openai-project", "x-client-request-id", "user-agent", "x-goog-api-client"]);
/** En-têtes relayés vers le fournisseur. */
const RELAYES = new Set(["content-type", "accept"]);
/** Jamais relayés autrement que par la règle d'authentification (5.3). */
const JAMAIS = new Set(["authorization", "x-api-key", "api-key", "x-goog-api-key", "proxy-authorization", "cookie"]);
/** Champs saut par saut et cadrage (EX-5.26), posés par la passerelle. */
const SAUT_PAR_SAUT = new Set(["connection", "keep-alive", "te", "transfer-encoding", "upgrade", "proxy-connection", "host", "content-length", "accept-encoding", "content-encoding"]);
/** En-têtes de réponse relayés à l'hôte (5.3). */
const REPONSE_RELAYES = new Set(["content-type", "request-id", "x-request-id", "openai-version", "retry-after", "x-should-retry"]);

/** Nom de l'en-tête d'authentification d'une route (15.1). */
export function nomEnteteAuth(authHeader) {
  return authHeader === "authorization-bearer" ? "authorization" : authHeader;
}

function admisParListe(nom, liste) {
  return (liste ?? []).some((m) => (m.endsWith("*") ? nom.startsWith(m.slice(0, -1).toLowerCase()) : nom === m.toLowerCase()));
}

/**
 * En-têtes envoyés au fournisseur (5.3) : liste autorisée, plus
 * `model.forward_headers` ; `X-Noortrace-*`, en-têtes d'authentification,
 * `model.strip_headers` et champs saut par saut retirés.
 * @param {Object<string, string|string[]>} recus en-têtes de l'hôte (noms en minuscules)
 * @param {{forward: string[], strip: string[], nomsConnexion: Set<string>}} o
 * @returns {{envoyes: Object<string, string>, notes: Object<string, string>, retires: string[]}}
 */
export function entetesVersFournisseur(recus, o) {
  const envoyes = {};
  const notes = {};
  const retires = [];
  for (const [nom, valeur] of Object.entries(recus)) {
    const v = Array.isArray(valeur) ? valeur.join(", ") : valeur;
    const strip = admisParListe(nom, o.strip);
    if (nom.startsWith("x-noortrace-") || JAMAIS.has(nom) || SAUT_PAR_SAUT.has(nom) || o.nomsConnexion.has(nom) || strip) {
      if (!nom.startsWith("x-noortrace-") && !JAMAIS.has(nom) && !SAUT_PAR_SAUT.has(nom)) retires.push(nom);
      continue;
    }
    if (RELAYES_NOTES.has(nom) || nom.startsWith("x-claude-code-")) {
      envoyes[nom] = v;
      notes[nom] = v;
    } else if (RELAYES.has(nom) || admisParListe(nom, o.forward)) {
      envoyes[nom] = v;
    } else {
      retires.push(nom);
    }
  }
  return { envoyes, notes, retires };
}

/**
 * En-têtes de la réponse rendus à l'hôte (5.3) ; le cadrage est calculé par la
 * passerelle (EX-5.26). Le `Content-Encoding` d'une réponse comprimée malgré
 * `Accept-Encoding: identity` est rendu avec elle (EX-5.9).
 * @param {Object<string, string|string[]>} recus
 * @param {{forward: string[], strip: string[], nomsConnexion: Set<string>}} o
 * @returns {{rendus: Object<string, string|string[]>, notes: Object<string, string>}}
 */
export function entetesVersHote(recus, o) {
  const rendus = {};
  const notes = {};
  for (const [nom, valeur] of Object.entries(recus)) {
    if (SAUT_PAR_SAUT.has(nom) && nom !== "content-encoding") continue;
    if (o.nomsConnexion.has(nom) || admisParListe(nom, o.strip)) continue;
    if (REPONSE_RELAYES.has(nom) || nom.startsWith("anthropic-ratelimit-") || nom === "content-encoding" || admisParListe(nom, o.forward)) {
      rendus[nom] = valeur;
      if (nom === "request-id" || nom === "x-request-id") notes[nom] = Array.isArray(valeur) ? valeur.join(", ") : valeur;
    }
  }
  return { rendus, notes };
}

/**
 * Noms nommés par `Connection` (EX-5.26) : retirés dans les deux sens.
 * @param {string|string[]|undefined} v
 * @returns {Set<string>}
 */
export function nomsConnexion(v) {
  const s = new Set();
  for (const x of [].concat(v ?? [])) for (const n of String(x).split(",")) if (n.trim()) s.add(n.trim().toLowerCase());
  return s;
}

/**
 * Type de média d'un `Content-Type` (5.3.1 pas 5) : en minuscules, sans
 * paramètres.
 * @param {string|undefined|null} ct
 */
export function typeMedia(ct) {
  return typeof ct === "string" ? ct.split(";")[0].trim().toLowerCase() : "";
}

/** Type de média JSON (`application/json` ou suffixe `+json`). */
export function estTypeJson(t) {
  return t === "application/json" || /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+\+json$/.test(t);
}

// ------------------------------------------------------------ forme attendue, prompt système (5.5, EX-8.5)

const estObjet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/**
 * Forme attendue d'une requête (EX-5.7 point 3).
 * @param {string} format
 * @param {unknown} v corps analysé
 */
export function formeAttendue(format, v) {
  if (!estObjet(v)) return false;
  switch (format) {
    case "anthropic-messages":
    case "openai-chat":
      return "messages" in v;
    case "openai-responses":
      return "input" in v || "previous_response_id" in v;
    case "gemini":
      return Array.isArray(v.contents);
    default:
      return false;
  }
}

/**
 * Chaînes porteuses du prompt système d'une requête (5.5, EX-8.5), dans
 * l'ordre de la jointure : `{ lire, ecrire }` pour chacune, et le
 * remplacement de mode `reference`.
 * @param {string} format
 * @param {object} v corps (copie modifiable)
 * @returns {{porteuses: {texte: string, poser: (s: string) => void}[], remplacer: () => void}}
 */
export function porteusesPrompt(format, v) {
  const porteuses = [];
  const remplacements = [];
  const texteParties = (contenu, types, poserContenu) => {
    if (typeof contenu === "string") {
      porteuses.push({ texte: contenu, poser: (s) => poserContenu(s) });
      return true;
    }
    if (!Array.isArray(contenu)) return false;
    let n = 0;
    for (const p of contenu) {
      if (estObjet(p) && types.includes(p.type) && typeof p.text === "string") {
        porteuses.push({ texte: p.text, poser: (s) => (p.text = s) });
        n++;
      }
    }
    return n > 0;
  };
  switch (format) {
    case "anthropic-messages": {
      if (typeof v.system === "string" || Array.isArray(v.system)) {
        if (texteParties(v.system, ["text"], (s) => (v.system = s))) remplacements.push(() => (v.system = JETON_PROMPT));
      }
      break;
    }
    case "openai-chat": {
      if (!Array.isArray(v.messages)) break;
      for (const m of v.messages) {
        if (!estObjet(m) || (m.role !== "system" && m.role !== "developer")) continue;
        if (texteParties(m.content, ["text"], (s) => (m.content = s))) remplacements.push(() => (m.content = JETON_PROMPT));
      }
      break;
    }
    case "openai-responses": {
      if (typeof v.instructions === "string") {
        porteuses.push({ texte: v.instructions, poser: (s) => (v.instructions = s) });
        remplacements.push(() => (v.instructions = JETON_PROMPT));
      }
      if (!Array.isArray(v.input)) break;
      for (const m of v.input) {
        if (!estObjet(m) || (m.role !== "system" && m.role !== "developer")) continue;
        if (texteParties(m.content, ["input_text", "text"], (s) => (m.content = s))) remplacements.push(() => (m.content = JETON_PROMPT));
      }
      break;
    }
    case "gemini": {
      const si = v.systemInstruction;
      if (!estObjet(si) || !Array.isArray(si.parts)) break;
      for (const p of si.parts) if (estObjet(p) && typeof p.text === "string") porteuses.push({ texte: p.text, poser: (s) => (p.text = s) });
      remplacements.push(() => (si.parts = [{ text: JETON_PROMPT }]));
      break;
    }
    default:
      break;
  }
  return { porteuses, remplacer: () => remplacements.forEach((f) => f()) };
}

/**
 * Prompt système d'une requête (table de 5.5) : texte joint par `\n`, ou
 * null s'il n'y en a pas.
 * @param {string} format
 * @param {unknown} v
 * @returns {string|null}
 */
export function promptSysteme(format, v) {
  if (!formeAttendue(format, v)) return null;
  const { porteuses } = porteusesPrompt(format, structuredClone(v));
  if (format === "gemini") {
    const si = v.systemInstruction;
    if (!estObjet(si) || !Array.isArray(si.parts)) return null;
  } else if (!porteuses.length) return null;
  return porteuses.map((p) => p.texte).join("\n");
}

/**
 * Serveurs MCP et contenu en cache déclarés au fournisseur (EX-5.32), noms de
 * l'API et en snake_case.
 * @param {unknown} v
 * @returns {{mcp: number, cache: boolean}} nombre d'entrées `mcpServers`, référence de cache
 */
export function declarationsFournisseur(v) {
  let mcp = 0;
  if (estObjet(v) && Array.isArray(v.tools)) {
    for (const t of v.tools) {
      if (!estObjet(t)) continue;
      for (const k of ["mcpServers", "mcp_servers"]) {
        if (!(k in t)) continue;
        const x = t[k];
        if (x === null || (Array.isArray(x) && x.length === 0)) continue;
        mcp += Array.isArray(x) ? x.length : 1;
      }
    }
  }
  const cache = estObjet(v) && ["cachedContent", "cached_content"].some((k) => k in v && v[k] !== null);
  return { mcp, cache };
}

// ------------------------------------------------------------ adresses (EX-5.3, EX-5.8)

/**
 * Liste d'adresses de plages CIDR (IPv4 ou IPv6).
 * @param {string[]} cidrs
 * @returns {net.BlockList}
 */
export function listeAdresses(cidrs) {
  const b = new net.BlockList();
  for (const c of cidrs ?? []) {
    const [a, n] = c.split("/");
    const type = net.isIPv6(a) ? "ipv6" : "ipv4";
    try {
      b.addSubnet(a, Number(n), type);
    } catch {
      // plage invalide : refusée par la validation ; ignorée ici
    }
  }
  return b;
}

/**
 * Une adresse appartient-elle à une liste ? Une adresse IPv4 écrite en IPv6
 * (`::ffff:a.b.c.d`) est lue en IPv4 ; une valeur qui n'est pas une adresse
 * n'appartient à rien.
 * @param {net.BlockList} liste
 * @param {string|null|undefined} adresse
 */
export function adresseDans(liste, adresse) {
  if (typeof adresse !== "string") return false;
  const a = adresse.trim().replace(/^::ffff:(?=[0-9.]+$)/i, "");
  const t = net.isIP(a);
  if (!t) return false;
  return liste.check(a, t === 6 ? "ipv6" : "ipv4");
}

/**
 * Connexion d'hôte des modes `icap` et `miroir` (EX-5.8 point 3) : l'entrée
 * de `model.hosts` dont `match.source_addresses` contient l'adresse, à défaut
 * l'entrée d'`id` `"inconnu"`, sinon null.
 * @param {object} config
 * @param {string|null} adresse
 */
export function hotePourAdresse(config, adresse) {
  const hotes = config.model.hosts ?? [];
  for (const h of hotes) {
    if (Array.isArray(h.match?.source_addresses) && adresseDans(listeAdresses(h.match.source_addresses), adresse)) return h;
  }
  return hotes.find((h) => h.id === "inconnu") ?? null;
}

// ------------------------------------------------------------ configuration (EX-15.4 pas 3)

/**
 * Règles hors schéma du frontal modèle (EX-15.4 pas 3, EX-5.32, EX-7.3) :
 * couples `passthrough` uniques et distincts des routes, route `gemini` sur
 * une collection `/models`, `provider_mcp` et `provider_cache` à `relayer`
 * affichés, `passthrough` qui créerait un contenu en cache hors capture,
 * `listen`, `icap`, `mirror` selon le mode, connexions d'hôte.
 * @param {object} c document de configuration valide contre le schéma
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controleModele(c) {
  const erreurs = [];
  const avertissements = [];
  const err = (pointeur, regle, valeur) => erreurs.push({ pointeur, regle, valeur });
  const avert = (pointeur, regle) => avertissements.push({ pointeur, regle });
  const routes = c.policy?.model?.routes ?? [];
  const couples = new Set();
  const chemins = new Set(routes.filter((r) => r.format !== "gemini").map((r) => `POST ${r.path}`));
  routes.forEach((r, k) => {
    const ici = `/policy/model/routes/${k}`;
    (r.passthrough ?? []).forEach((p, j) => {
      const cle = `${p.method} ${p.path}`;
      if (couples.has(cle) || chemins.has(cle)) err(`${ici}/passthrough/${j}`, "couple passthrough en double ou égal à une route (EX-15.4)", cle);
      couples.add(cle);
      if (r.format === "gemini" && p.method === "POST" && (p.path.split("/").includes("cachedContents") || p.path.startsWith("/upload/"))) {
        err(`${ici}/passthrough/${j}/path`, "passthrough POST qui créerait un contenu hors capture (EX-5.32)", p.path);
      }
    });
    if (r.format === "gemini") {
      if (!r.path.endsWith("/models")) err(`${ici}/path`, "une route gemini nomme la collection des modèles (EX-5.28)", r.path);
      else if (r.path !== "/v1beta/models" && r.path !== "/v1/models") avert(`${ici}/path`, "collection gemini autre que /v1beta/models ou /v1/models (EX-5.28)");
      if (r.provider_mcp === "relayer") avert(`${ici}/provider_mcp`, "serveurs MCP déclarés au fournisseur relayés : contournement du frontal MCP accepté (EX-5.32)");
      if (r.provider_cache === "relayer") avert(`${ici}/provider_cache`, "contenu en cache du fournisseur relayé : non capturé (EX-5.32)");
    }
  });
  const m = c.model ?? {};
  if (m.mode === "passerelle" && !m.listen) err("/model/listen", "adresse d'écoute exigée en mode passerelle (EX-5.2)", m.listen ?? null);
  if (m.mode === "icap" && !m.icap) err("/model/icap", "membre icap exigé en mode icap (EX-5.3)", null);
  if (m.mode === "miroir" && !m.mirror) err("/model/mirror", "membre mirror exigé en mode miroir (EX-5.6)", null);
  if (m.mode && m.mode !== "desactive" && !(m.hosts ?? []).length) err("/model/hosts", "au moins une connexion d'hôte par frontal actif (EX-7.3)", null);
  (m.hosts ?? []).forEach((h, k) => {
    if (h.match?.source_addresses !== undefined && m.mode === "passerelle") err(`/model/hosts/${k}/match`, "source_addresses seulement en modes icap et miroir (EX-5.8)", null);
    // Jeton OAuth de la passerelle (EX-5.8 point 2) : vérifié par le serveur d'autorisation de mcp.http.oauth (lecture 72).
    if (typeof h.match?.oauth_subject === "string") {
      if (m.mode !== "passerelle") err(`/model/hosts/${k}/match`, "oauth_subject seulement en mode passerelle (EX-5.8)", null);
      else if (!c.mcp?.http?.oauth) err(`/model/hosts/${k}/match/oauth_subject`, "un jeton OAuth de la passerelle exige mcp.http.oauth (serveur d'autorisation, JWKS, portées ; EX-5.8)", null);
    }
  });
  const ic = m.icap;
  if (m.mode === "icap" && ic) {
    if (ic.tls_listen && !m.tls) err("/model/tls", "ICAPS (icap.tls_listen) exige le certificat de model.tls (EX-5.3)", null);
    if (ic.client_ca && !ic.tls_listen) err("/model/icap/client_ca", "client_ca exige icap.tls_listen : le certificat client est vérifié par ICAPS (EX-5.3)", ic.client_ca);
    if (c.recorder?.environment === "production" && !ic.client_ca && !(ic.allowed_sources ?? []).length) {
      err("/model/icap", "en production, ICAPS avec certificat client (client_ca) ou liste d'adresses (allowed_sources) exigé (EX-5.3)", null);
    }
  }
  return { erreurs, avertissements };
}
