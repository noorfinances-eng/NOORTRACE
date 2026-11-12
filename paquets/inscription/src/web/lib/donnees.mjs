// Lecture, par l'interface, des fichiers de l'agent (INTERFACES.md 3.6) :
// lecture seule, par le groupe de l'interface ; l'état ne passe jamais par la
// prise. Rien de ce qui est lu ici ne contient de clé, de graine ni de jeton
// (l'agent n'en écrit jamais dans ses données).

import fs from "node:fs";
import path from "node:path";
import { MOTIF_SLUG } from "../../commun/champs.mjs";
import { dernierPaquet } from "../../commun/paquet.mjs";
import { configuration } from "./serveur.mjs";

const lireJson = (chemin) => {
  try {
    return JSON.parse(fs.readFileSync(chemin, "utf8"));
  } catch {
    return null;
  }
};

/** Répertoire des données de l'agent. */
const racine = () => configuration().donnees;

/** Répertoire d'un client, ou null si le slug n'a pas la forme de RG-1. */
export function repertoireClient(slug) {
  if (typeof slug !== "string" || !MOTIF_SLUG.test(slug)) return null;
  return path.join(racine(), "clients", slug);
}

/** Enregistrements des travaux (`travaux/<id>.json`), les plus récents d'abord. */
export function travaux({ slug = null } = {}) {
  const dir = path.join(racine(), "travaux");
  let noms = [];
  try {
    noms = fs.readdirSync(dir).filter((n) => /^trv-[0-9a-f]{32}\.json$/.test(n));
  } catch {
    return [];
  }
  return noms.map((n) => lireJson(path.join(dir, n))).filter((t) => t && (!slug || t.slug === slug)).sort((a, b) => (a.recu_a < b.recu_a ? 1 : a.recu_a > b.recu_a ? -1 : 0));
}

/** Un travail par son identifiant, ou null. */
export function travail(id) {
  if (typeof id !== "string" || !/^trv-[0-9a-f]{32}$/.test(id)) return null;
  return lireJson(path.join(racine(), "travaux", `${id}.json`));
}

/** Clients connus : slug, `org_id`, états des étapes, dernier travail. */
export function clients() {
  let noms = [];
  try {
    noms = fs.readdirSync(path.join(racine(), "clients")).filter((n) => MOTIF_SLUG.test(n)).sort();
  } catch {
    return [];
  }
  const tous = travaux();
  return noms.map((slug) => {
    const d = lireJson(path.join(racine(), "clients", slug, "dossier.json"));
    const dernier = tous.find((t) => t.slug === slug) ?? null;
    return {
      slug,
      org_id: d?.organisation?.org_id ?? null,
      steps: (d?.steps ?? []).map((s) => ({ step: s.step, subject: s.subject, state: s.state })),
      dernier_travail: dernier ? { id: dernier.id, commande: dernier.commande, etat: dernier.etat, recu_a: dernier.recu_a, result: dernier.sortie?.result ?? null } : null,
    };
  }).filter((c) => c.org_id !== null);
}

/** Dossier d'un client, ses travaux, leurs sorties et ses demandes de signature, ou null. */
export function client(slug) {
  const dir = repertoireClient(slug);
  if (!dir) return null;
  const dossier = lireJson(path.join(dir, "dossier.json"));
  if (!dossier) return null;
  const t = travaux({ slug });
  let demandes = [];
  try {
    demandes = fs.readdirSync(path.join(dir, "demandes")).filter((n) => /^demande-[A-Za-z0-9._-]+\.json$/.test(n)).sort().map((nom) => ({ nom, document: lireJson(path.join(dir, "demandes", nom)) }));
  } catch {
    demandes = [];
  }
  let periodes = [];
  try {
    periodes = fs.readdirSync(dir).filter((n) => /^periode-[0-9]+$/.test(n) && fs.existsSync(path.join(dir, n, "manifeste.json"))).sort().map((n) => `${n}/manifeste.json`);
  } catch {
    periodes = [];
  }
  let parties = [];
  try {
    parties = fs.readdirSync(path.join(dir, "parties")).filter((n) => /^[1-9][0-9]*$/.test(n)).sort((a, b) => Number(a) - Number(b)).map((n) => `parties/${n}`);
  } catch {
    parties = [];
  }
  return { slug, dossier, travaux: t, demandes, periodes, parties, paquet: etatPaquet(slug) };
}

/**
 * Confirmations hors bande inscrites pour un client (registre en ajout seul, EX-7.26), chacune avec
 * `consommee_par` : le travail dont le versement l'a consommée, ou null (une confirmation par approvisionnement).
 */
export function confirmations(slug) {
  const dir = repertoireClient(slug);
  const d = dir ? lireJson(path.join(dir, "dossier.json")) : null;
  if (!d) return [];
  let texte = "";
  try {
    texte = fs.readFileSync(path.join(racine(), "confirmations.ndjson"), "utf8");
  } catch {
    return [];
  }
  const lignes = texte.split("\n").filter(Boolean).map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter(Boolean);
  const consommees = new Map(lignes.filter((l) => typeof l.consommation === "string").map((l) => [l.consommation, l.travail ?? null]));
  return lignes.filter((c) => c.objet?.org_id === d.organisation.org_id).map((c) => ({ ...c, consommee_par: consommees.get(c.id) ?? null }));
}

/** Dernier paquet produit pour un client (`paquets/<n>/paquet-client-<slug>`, EX-7.30) et le dernier travail `paquet` (sa sortie `paquet-client`). */
export function etatPaquet(slug) {
  const dir = repertoireClient(slug);
  if (!dir) return null;
  const repertoire = dernierPaquet(dir, slug);
  const dernier = travaux({ slug }).find((t) => t.commande === "paquet") ?? null;
  return { present: repertoire !== null, repertoire, dernier: dernier ? { id: dernier.id, etat: dernier.etat, sortie: dernier.sortie ?? null } : null };
}
