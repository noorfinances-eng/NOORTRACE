// Mandataire de l'interface (Next.js 16, `proxy`) : à chaque réponse, une
// politique de sécurité du contenu bloquante à nonce tiré pour cette réponse
// (INTERFACES.md 2.3), transmise à Next pour ses scripts ; toute requête
// d'une autre méthode que GET ou HEAD exige l'en-tête `Origin` égal à
// l'origine de l'interface ; aucun en-tête `Access-Control-Allow-*` ; seules
// `/connexion` et `POST /api/connexion` (et les fichiers statiques de la
// construction, sans donnée) se servent sans session.

import { NextResponse } from "next/server";
import { configuration, cookieDe, session } from "./lib/serveur.mjs";

/** Politique de sécurité du contenu d'une réponse (INTERFACES.md 2.3 ; `connect-src 'self'` : LISEZMOI.md). */
export function politique(nonce) {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'self'`,
    "style-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'none'",
    "object-src 'none'",
  ].join("; ");
}

function nonce() {
  const o = new Uint8Array(16);
  crypto.getRandomValues(o);
  let s = "";
  for (const x of o) s += String.fromCharCode(x);
  return btoa(s);
}

const PUBLIQUES = new Set(["/connexion"]);

function refus(statut, code, message, entetes = {}) {
  return new NextResponse(JSON.stringify({ error: { code, message } }), { status: statut, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...entetes } });
}

export function proxy(requete) {
  const n = nonce();
  const csp = politique(n);
  const chemin = requete.nextUrl.pathname;
  const securite = { "content-security-policy": csp, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "x-frame-options": "DENY" };
  let config;
  try {
    config = configuration();
  } catch {
    return refus(500, "configuration", "interface mal configurée", securite);
  }
  // Méthodes autres que GET : Origin exigé, égal à l'origine de l'interface.
  if (requete.method !== "GET" && requete.method !== "HEAD") {
    const origine = requete.headers.get("origin");
    if (origine !== config.origine) return refus(403, "origine_refusee", "requête sans l'en-tête Origin de l'interface", securite);
  }
  const publique = PUBLIQUES.has(chemin) || (chemin === "/api/connexion" && requete.method === "POST");
  if (!publique && !session(cookieDe(requete.headers.get("cookie")))) {
    if (chemin.startsWith("/api/")) return refus(401, "session_absente", "session absente ou expirée", securite);
    const url = requete.nextUrl.clone();
    url.pathname = "/connexion";
    url.search = "";
    const r = NextResponse.redirect(url, 303);
    for (const [k, v] of Object.entries(securite)) r.headers.set(k, v);
    return r;
  }
  const entetes = new Headers(requete.headers);
  entetes.set("x-nonce", n);
  entetes.set("content-security-policy", csp);
  const reponse = NextResponse.next({ request: { headers: entetes } });
  for (const [k, v] of Object.entries(securite)) reponse.headers.set(k, v);
  if (chemin.startsWith("/api/")) reponse.headers.set("cache-control", "no-store");
  return reponse;
}

export const config = {
  matcher: ["/((?!_next/static).*)"],
};
