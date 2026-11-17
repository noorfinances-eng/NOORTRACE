// Données fictives d'un agent d'inscription, écrites à la main pour les essais de présentation de l'interface
// (complément du 2026-11-17) : l'interface lit ces fichiers en lecture seule (INTERFACES.md 3.6), aucun agent
// n'est nécessaire. Cinq clients, à des états différents du parcours ; chaque valeur est dérivée d'un nom par
// SHA-256, aucune n'a de sens hors de l'essai. Les dossiers suivent les membres d'`inscription-client-v0`.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const h32 = (nom) => "0x" + crypto.createHash("sha256").update(`noortrace/essai/presentation/${nom}`).digest("hex");
const adr = (nom) => h32(nom).slice(0, 42);

/** Les sept étapes d'un dossier à une clé et un journal, dans l'ordre de CT-4 7.1. */
export const CODES_ETAPES = ["jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement", "inscription", "premiere_ancre", "premiere_cloture"];

/**
 * Dossier fictif. `etats` : état de chaque étape, dans l'ordre de `CODES_ETAPES` ; `erreur` : `{ code, message }`
 * porté par la première étape `echec`.
 */
export function dossierFictif(slug, etats, { erreur = { code: "transaction_annulee", message: "transaction incluse à status 0x0" } } = {}) {
  const cleChaine = adr(`${slug}/cle-chaine`);
  const keyId = `rec-${slug}-01`;
  const journal = `journal-${slug}`;
  const sujets = { jeu_approbateurs: slug, assignation: slug, lecture_jeu: slug, approvisionnement: cleChaine, inscription: keyId, premiere_ancre: journal, premiere_cloture: journal };
  const roles = { jeu_approbateurs: "jeu_approbateurs", assignation: "assignation", approvisionnement: "approvisionnement", inscription: "inscription", premiere_ancre: "ancre", premiere_cloture: "cloture" };
  const steps = CODES_ETAPES.map((step, k) => {
    const state = etats[k];
    const e = { step, subject: sujets[step], state, transaction_hash: null, block_number: null, block_hash: null, capture: null, error: null, updated_at: null };
    const bloc = 100 + k;
    if (state !== "a_faire") e.updated_at = `2026-11-12T08:0${k}:07.250Z`;
    if (["envoyee", "incluse", "capturee", "echec"].includes(state)) e.transaction_hash = h32(`${slug}/${step}/transaction`);
    if (["incluse", "capturee", "faite"].includes(state)) Object.assign(e, { block_number: bloc, block_hash: h32(`${slug}/${step}/bloc`) });
    if (state === "capturee") e.capture = `capture-${bloc}-0-${roles[step]}.json`;
    if (state === "echec") e.error = { ...erreur };
    if (step === "jeu_approbateurs" && ["incluse", "capturee"].includes(state)) e.contract = adr(`${slug}/jeu`);
    return e;
  });
  return {
    version: 0,
    instance: {
      evm_chain_id: 31337, bft_chain_id: "noortrace-31337-essai", genesis_sha256: h32("genese"),
      contracts: { curator_set_registry: adr("registre-jeux"), recorder_registry: adr("registre-cles"), period_registry: adr("registre-periodes"), attestation_registry: adr("registre-ancres") },
      manifest_sha256: h32("manifeste"), validator_set_hash: h32("validateurs"),
    },
    organisation: { slug, org_id: h32(`${slug}/org`) },
    approvers: { members: [adr("approbateur-1"), adr("approbateur-2"), adr("approbateur-3")].sort(), threshold: 2, set_admin: adr(`${slug}/gouvernance`) },
    journals: [{ name: journal, journal_id: h32(`${slug}/journal`) }],
    recorders: [{ key_id: keyId, journal_id: h32(`${slug}/journal`), algorithm: "ed25519", public_key: h32(`${slug}/ed25519`), custody_class: "D", backend_type: "fichier", created_at: "2026-11-10T09:00:00.000Z", chain_key: cleChaine, chain_key_class: "D", origin_proof: null }],
    funding: { funder: adr("tresorerie"), daily_budget_gas: 10800000, amount_wei: "327000000" },
    steps,
    result: null,
    prepared_by: "exploitant operateur-1",
    prepared_at: "2026-11-12T07:55:00.000Z",
    source: "dossier fictif d'un essai de présentation",
  };
}

/** Enregistrement de travail fictif (`$defs/travail` d'INTERFACES.md 3.3). */
export function travailFictif(n, { slug, commande, etat = "fini", result = "reussi", recu_a, outputs = {}, error = null, motif = null }) {
  const id = `trv-${String(n).padStart(32, "0")}`;
  const t = { id, commande, slug, exploitant: "exploitant operateur-1", recu_a, etat, debut: etat === "en_attente" ? null : recu_a, fin: etat === "fini" ? recu_a : null, sortie: null };
  if (etat === "fini") t.sortie = { version: 0, command: commande === "paquet" ? "paquet-client" : commande, result, exit_code: result === "reussi" || result === "deja_fait" ? 0 : 1, checks: [{ id: "OP-1", status: "reussi", detail: "" }], error, outputs };
  if (motif) t.motif = motif;
  return t;
}

/**
 * Écrit sous `donnees` cinq clients fictifs et rend ce que les essais comparent à l'affichage :
 * `{ clients: { <slug>: { dossier } }, confirmations, travaux, piece, manifestePaquet }`.
 */
export function ecrireDonneesFictives(donnees) {
  const etats = {
    "client-neuf": ["a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"],
    "client-en-cours": ["capturee", "capturee", "faite", "capturee", "a_faire", "a_faire", "a_faire"],
    "client-en-echec": ["capturee", "echec", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"],
    "client-envoye": ["envoyee", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire", "a_faire"],
    "client-inscrit": ["capturee", "capturee", "faite", "capturee", "capturee", "capturee", "capturee"],
  };
  const clients = {};
  for (const [slug, e] of Object.entries(etats)) {
    const dossier = dossierFictif(slug, e);
    const dir = path.join(donnees, "clients", slug);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "dossier.json"), JSON.stringify(dossier, null, 2) + "\n");
    clients[slug] = { dossier };
  }
  // Une demande d'inscription préparée, non signée, pour le client en cours.
  const enCours = clients["client-en-cours"].dossier;
  const demande = { version: 0, operation: "inscription", evm_chain_id: 31337, contract: enCours.instance.contracts.recorder_registry, fields: { org_id: enCours.organisation.org_id, journal_id: enCours.journals[0].journal_id, chain_key: enCours.recorders[0].chain_key, ed25519_public_key: enCours.recorders[0].public_key }, digest: h32("demande/condense"), eip191_digest: h32("demande/eip191"), signer_set: { curator_set: adr("client-en-cours/jeu"), threshold: 2, height: 103, block_hash: h32("demande/bloc") }, signatures: [], prepared_at: "2026-11-12T08:10:00.000Z" };
  fs.mkdirSync(path.join(donnees, "clients", "client-en-cours", "demandes"), { recursive: true });
  fs.writeFileSync(path.join(donnees, "clients", "client-en-cours", "demandes", `demande-inscription-${enCours.recorders[0].key_id}-trv-${"0".repeat(31)}3.json`), JSON.stringify(demande, null, 2) + "\n");
  // Un paquet produit pour le client inscrit (le manifeste suffit à l'interface pour le dire présent).
  const paquet = path.join(donnees, "clients", "client-inscrit", "paquets", "1", "paquet-client-client-inscrit");
  fs.mkdirSync(paquet, { recursive: true });
  fs.writeFileSync(path.join(paquet, "paquet-client.json"), "{}\n");
  const manifestePaquet = h32("paquet/manifeste");
  // Travaux : les plus récents d'abord à l'affichage.
  const travaux = [
    travailFictif(1, { slug: "client-en-cours", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" }),
    travailFictif(2, { slug: "client-en-cours", commande: "inscrire-client", recu_a: "2026-11-12T08:05:00.000Z", outputs: { curator_set: adr("client-en-cours/jeu") } }),
    travailFictif(3, { slug: "client-en-cours", commande: "condense-inscription", recu_a: "2026-11-12T08:10:00.000Z", outputs: { digest: demande.digest } }),
    travailFictif(4, { slug: "client-en-echec", commande: "inscrire-client", result: "echoue", recu_a: "2026-11-12T08:20:00.000Z", error: { code: "transaction_annulee", check: "OP-11", message: "transaction incluse à status 0x0" } }),
    travailFictif(5, { slug: "client-inscrit", commande: "paquet", recu_a: "2026-11-13T10:00:00.000Z", outputs: { directory: paquet, org: "client-inscrit", org_id: clients["client-inscrit"].dossier.organisation.org_id, files: 28, manifest_sha256: manifestePaquet, secrets_checked: { count: 0, references: [] } } }),
    travailFictif(6, { slug: "client-neuf", commande: "inscrire-client-preparer", recu_a: "2026-11-14T16:30:00.000Z" }),
  ];
  fs.mkdirSync(path.join(donnees, "travaux"), { recursive: true });
  for (const t of travaux) fs.writeFileSync(path.join(donnees, "travaux", `${t.id}.json`), JSON.stringify(t));
  // Confirmations hors bande : une consommée (client en cours), une en réserve (client en échec).
  const piece = h32("piece/confirmation");
  const confirmation = (n, slug, operation, pieceSha) => ({ id: `cnf-${String(n).padStart(32, "0")}`, operation, objet: { org_id: clients[slug].dossier.organisation.org_id, cle_chaine: clients[slug].dossier.recorders[0].chain_key }, personne_client: "Camille Durand (personne fictive)", canal: "appel au numéro du contrat", instant: "2026-11-12T07:58:00.000Z", piece_sha256: pieceSha, exploitant: "exploitant operateur-1", recu_a: "2026-11-12T08:00:00.000Z" });
  const confirmations = [confirmation(1, "client-en-cours", "approvisionnement", piece), confirmation(2, "client-en-echec", "approvisionnement", h32("piece/2"))];
  const lignes = [confirmations[0], { consommation: confirmations[0].id, travail: travaux[1].id, org_id: confirmations[0].objet.org_id, cle_chaine: confirmations[0].objet.cle_chaine, instant: "2026-11-12T08:05:02.000Z" }, confirmations[1]];
  fs.writeFileSync(path.join(donnees, "confirmations.ndjson"), lignes.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return { clients, confirmations, travaux, piece, manifestePaquet, demande };
}
