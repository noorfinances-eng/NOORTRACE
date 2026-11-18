// Données fictives d'un agent d'inscription, écrites à la main pour les essais de présentation de l'interface
// (complément du 2026-11-17) : l'interface lit ces fichiers en lecture seule (INTERFACES.md 3.6), aucun agent
// n'est nécessaire. Cinq clients, à des états différents du parcours ; chaque valeur est dérivée d'un nom par
// SHA-256, aucune n'a de sens hors de l'essai. Les dossiers suivent les membres d'`inscription-client-v0`.
//
// Cohérence (complément du 2026-11-18, seconde lecture des écrans) : les données disent ce qu'un agent aurait
// écrit. Chaque dossier a son travail de préparation, au même instant que `prepared_at` ; un versement fait a sa
// confirmation du client, notée puis consommée par le travail qui a versé (CT-4 EX-7.26) ; une étape envoyée ou en
// échec a le travail qui l'a envoyée, et la confirmation que l'agent exige avant de l'admettre. Un paquet produit
// porte la recherche de secrets d'EX-7.21 sur les références employées.
//
// Heures (troisième lecture des écrans) : elles suivent l'ordre des étapes et celui des travaux. Le dossier est
// préparé à 07:55 ; le client confirme à 07:58, la confirmation est notée à 08:00 ; le travail des étapes 2 à 5 est
// reçu à 08:05 et fait ses étapes de 08:05:10 à 08:05:40 (une étape en échec l'est à l'heure de ce travail ; la
// confirmation est consommée juste avant le versement, à 08:05:35) ; le document d'inscription est préparé à 08:10,
// envoyé signé à 09:30 (étape 6 à 09:30:10) ; chez le client, la première preuve de date est déposée à 10:00:07 et la
// première période close à 11:00:07 ; le paquet est produit le lendemain.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const h32 = (nom) => "0x" + crypto.createHash("sha256").update(`noortrace/essai/presentation/${nom}`).digest("hex");
const adr = (nom) => h32(nom).slice(0, 42);

/** Les sept étapes d'un dossier à une clé et un journal, dans l'ordre de CT-4 7.1. */
export const CODES_ETAPES = ["jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement", "inscription", "premiere_ancre", "premiere_cloture"];

/** Réception du travail qui conduit les étapes 2 à 5, et instant de la consommation de la confirmation (avant le versement). */
export const DEBUT_ETAPES = "2026-11-12T08:05:00.000Z";
export const CONSOMMATION = "2026-11-12T08:05:35.000Z";
/** Instant de la dernière écriture d'une étape (indice dans `CODES_ETAPES`), dans l'ordre du parcours. */
const INSTANTS_ETAPES = ["2026-11-12T08:05:10.250Z", "2026-11-12T08:05:20.250Z", "2026-11-12T08:05:30.250Z", "2026-11-12T08:05:40.250Z", "2026-11-12T09:30:10.250Z", "2026-11-12T10:00:07.250Z", "2026-11-12T11:00:07.250Z"];

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
    if (state !== "a_faire") e.updated_at = INSTANTS_ETAPES[k];
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
    travailFictif(2, { slug: "client-en-cours", commande: "inscrire-client", recu_a: DEBUT_ETAPES, outputs: { curator_set: adr("client-en-cours/jeu") } }),
    travailFictif(3, { slug: "client-en-cours", commande: "condense-inscription", recu_a: "2026-11-12T08:10:00.000Z", outputs: { digest: demande.digest } }),
    travailFictif(4, { slug: "client-en-echec", commande: "inscrire-client", result: "echoue", recu_a: DEBUT_ETAPES, error: { code: "transaction_annulee", check: "OP-11", message: "transaction incluse à status 0x0" } }),
    travailFictif(5, { slug: "client-inscrit", commande: "paquet", recu_a: "2026-11-13T10:00:00.000Z", outputs: { directory: paquet, org: "client-inscrit", org_id: clients["client-inscrit"].dossier.organisation.org_id, files: 28, manifest_sha256: manifestePaquet, secrets_checked: { count: 2, references: [{ option: "--relayeur", reference: "alias:relayeur" }, { option: "--tresorerie", reference: "alias:tresorerie" }] } } }),
    travailFictif(6, { slug: "client-neuf", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" }),
    // Ce qu'un agent aurait écrit pour les trois autres clients (cohérence, complément du 2026-11-18).
    travailFictif(7, { slug: "client-en-echec", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" }),
    travailFictif(8, { slug: "client-envoye", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" }),
    travailFictif(9, { slug: "client-envoye", commande: "inscrire-client", result: "incertain", recu_a: DEBUT_ETAPES, error: { code: "recu_absent", check: null, message: `aucun reçu pour ${clients["client-envoye"].dossier.steps[0].transaction_hash} en 120 s ; reprendre par le travail capturer` } }),
    travailFictif(10, { slug: "client-inscrit", commande: "inscrire-client-preparer", recu_a: "2026-11-12T07:55:00.000Z" }),
    travailFictif(11, { slug: "client-inscrit", commande: "inscrire-client", recu_a: DEBUT_ETAPES, outputs: { curator_set: adr("client-inscrit/jeu") } }),
    travailFictif(12, { slug: "client-inscrit", commande: "condense-inscription", recu_a: "2026-11-12T08:10:00.000Z", outputs: { digest: h32("client-inscrit/demande/condense") } }),
    travailFictif(13, { slug: "client-inscrit", commande: "inscrire-cle", recu_a: "2026-11-12T09:30:00.000Z", outputs: {} }),
  ];
  fs.mkdirSync(path.join(donnees, "travaux"), { recursive: true });
  for (const t of travaux) fs.writeFileSync(path.join(donnees, "travaux", `${t.id}.json`), JSON.stringify(t));
  // Confirmations hors bande.
  const piece = h32("piece/confirmation");
  const confirmation = (n, slug, operation, pieceSha) => ({ id: `cnf-${String(n).padStart(32, "0")}`, operation, objet: { org_id: clients[slug].dossier.organisation.org_id, cle_chaine: clients[slug].dossier.recorders[0].chain_key }, personne_client: "Camille Durand (personne fictive)", canal: "appel au numéro du contrat", instant: "2026-11-12T07:58:00.000Z", piece_sha256: pieceSha, exploitant: "exploitant operateur-1", recu_a: "2026-11-12T08:00:00.000Z" });
  // Une consommée (client en cours), une en réserve (client en échec : le versement n'est pas fait) ; puis, pour la
  // cohérence : une en réserve (client envoyé : l'agent l'exige avant d'admettre les étapes 2 à 5) et une consommée
  // (client inscrit).
  const confirmations = [confirmation(1, "client-en-cours", "approvisionnement", piece), confirmation(2, "client-en-echec", "approvisionnement", h32("piece/2")), confirmation(3, "client-envoye", "approvisionnement", h32("piece/3")), confirmation(4, "client-inscrit", "approvisionnement", h32("piece/4"))];
  const consommation = (c, t) => ({ consommation: c.id, travail: t.id, org_id: c.objet.org_id, cle_chaine: c.objet.cle_chaine, instant: CONSOMMATION });
  const lignes = [confirmations[0], consommation(confirmations[0], travaux[1]), confirmations[1], confirmations[2], confirmations[3], consommation(confirmations[3], travaux[10])];
  fs.writeFileSync(path.join(donnees, "confirmations.ndjson"), lignes.map((l) => JSON.stringify(l)).join("\n") + "\n");
  return { clients, confirmations, travaux, piece, manifestePaquet, demande };
}

/**
 * Ajoute sous `donnees` un client fictif de plus (complément du 2026-11-18, langage des écrans) : son dossier, à
 * l'état donné, et, si demandé, une confirmation du client prête à servir pour son compte technique et des
 * travaux. Rend `{ dossier, retirer() }` ; `retirer` efface le client, ses travaux et sa confirmation.
 *
 * `histoire` (seconde lecture des écrans) : écrit en outre ce qu'un agent aurait écrit pour arriver à cet état : le
 * travail de préparation, à l'instant de `prepared_at` ; dès qu'une des étapes 2 à 5 a été tentée, le travail qui
 * les conduit et la confirmation du client que l'agent exige avant de l'admettre, consommée si le versement est fait.
 */
export function ajouterClientFictif(donnees, slug, etats, { confirmation = false, travaux = [], erreur = undefined, histoire = false } = {}) {
  const dossier = dossierFictif(slug, etats, erreur ? { erreur } : undefined);
  const dir = path.join(donnees, "clients", slug);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "dossier.json"), JSON.stringify(dossier, null, 2) + "\n");
  const registre = path.join(donnees, "confirmations.ndjson");
  const avant = fs.existsSync(registre) ? fs.readFileSync(registre, "utf8") : null;
  const conduites = etats.slice(0, 4);
  const tentee = conduites.some((e) => e !== "a_faire");
  if (histoire) {
    const n = (k) => parseInt(crypto.createHash("sha256").update(`${slug}/travail/${k}`).digest("hex").slice(0, 12), 16);
    travaux = [...travaux, travailFictif(n(1), { slug, commande: "inscrire-client-preparer", recu_a: dossier.prepared_at })];
    if (tentee) {
      const echec = conduites.includes("echec");
      const enVol = conduites.includes("envoyee") || conduites.includes("incluse");
      const conduite = travailFictif(n(2), {
        slug, commande: "inscrire-client", recu_a: DEBUT_ETAPES,
        ...(echec ? { result: "echoue", error: { code: dossier.steps.find((e) => e.state === "echec").error.code, check: "OP-11", message: dossier.steps.find((e) => e.state === "echec").error.message } } : enVol ? { result: "incertain", error: { code: "recu_absent", check: null, message: "aucun reçu en 120 s ; reprendre par le travail capturer" } } : {}),
      });
      travaux.push(conduite);
      // L'enregistreur inscrit : le document préparé, puis envoyé signé.
      if (etats[4] === "capturee") travaux.push(travailFictif(n(3), { slug, commande: "condense-inscription", recu_a: "2026-11-12T08:10:00.000Z" }), travailFictif(n(4), { slug, commande: "inscrire-cle", recu_a: "2026-11-12T09:30:00.000Z" }));
      confirmation = true;
      histoire = { conduite, versee: etats[3] === "capturee" };
    }
  }
  if (confirmation) {
    const c = { id: `cnf-${crypto.createHash("sha256").update(slug).digest("hex").slice(0, 32)}`, operation: "approvisionnement", objet: { org_id: dossier.organisation.org_id, cle_chaine: dossier.recorders[0].chain_key }, personne_client: "Camille Durand (personne fictive)", canal: "appel au numéro du contrat", instant: "2026-11-12T07:58:00.000Z", piece_sha256: h32(`piece/${slug}`), exploitant: "exploitant operateur-1", recu_a: "2026-11-12T08:00:00.000Z" };
    fs.appendFileSync(registre, JSON.stringify(c) + "\n");
    if (histoire?.versee) fs.appendFileSync(registre, JSON.stringify({ consommation: c.id, travail: histoire.conduite.id, org_id: c.objet.org_id, cle_chaine: c.objet.cle_chaine, instant: CONSOMMATION }) + "\n");
  }
  fs.mkdirSync(path.join(donnees, "travaux"), { recursive: true });
  const fichiers = travaux.map((t) => {
    const f = path.join(donnees, "travaux", `${t.id}.json`);
    fs.writeFileSync(f, JSON.stringify(t));
    return f;
  });
  return {
    dossier,
    retirer() {
      fs.rmSync(dir, { recursive: true, force: true });
      for (const f of fichiers) fs.rmSync(f, { force: true });
      if (confirmation) {
        if (avant === null) fs.rmSync(registre, { force: true });
        else fs.writeFileSync(registre, avant);
      }
    },
  };
}
