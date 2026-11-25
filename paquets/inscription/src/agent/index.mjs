// Agent d'inscription (CT-4 EX-7.23, EX-7.28 ; INTERFACES.md 3) : processus
// séparé et privilégié, seul à résoudre les références de clés et le jeton,
// à signer et envoyer, à écrire les envois, les captures et le dossier. Il
// n'écoute qu'une prise `AF_UNIX` ; à chaque connexion, avant de lire aucun
// octet, il obtient du noyau le compte du pair (`SO_PEERCRED`, par un
// auxiliaire `python3 -I` à qui le descripteur est passé sans être lu) et
// ferme la connexion d'un autre compte que celui de l'interface, en
// consignant le refus. Une requête par connexion, un objet JSON strict sur
// une ligne d'au plus 65 536 octets ; seules la remise d'un travail, celle
// d'une confirmation et celle d'une note interne (nom interne d'un client,
// remise de son paquet : CT-4 EX-7.23, complément du 2026-11-19) passent :
// l'état se lit dans les fichiers (3.6), où l'agent écrit aussi les frais de
// l'instance qu'il applique (complément du 2026-11-25). Avant les pas 2 à 5,
// l'agent exige la confirmation de la fiche de contrôle des adresses des
// approbateurs (EX-7.8) comme celle du versement (EX-7.26). La file
// est unique et ordonnée, un travail à la fois ; l'agent refait chaque
// vérification avant d'écrire et ne croit pas l'interface.
//
// API programmatique (LISEZMOI.md) : `demarrerAgent(configuration, options)`
// rend `{ prise, pid, arreter(), file }` ; `options.horloge`,
// `options.attendre`, `options.racine`, `options.memeCompteAdmis` (agent et
// interface sous le même compte, essais seulement) servent aux essais ; le
// binaire `bin/noortrace-inscription-agent` ne passe aucune option.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { lireJsonStrict } from "@noortrace/approbation";
import { ecrireHorodatage, sha256Hex } from "@noortrace/noyau";
import { ErreurChamp } from "../commun/champs.mjs";
import { lireReference, motifRefusReference } from "../commun/references.mjs";
import { lireConfirmation, lireIdentite, lireTravail } from "../commun/travaux.mjs";
import { etatNotes, lireNote, remiseEnVigueur } from "../commun/notes.mjs";
import { MANIFESTE_PAQUET, nomPaquet } from "../commun/paquet.mjs";
import { controlerComptes, controlerReferences, controlerRepertoires, ErreurConfiguration, lireConfiguration, prisesIp } from "./configuration.mjs";
import { chargerInstance, ErreurInstance } from "./instance.mjs";
import { ajouterLigne, chemins, creerRepertoire, ecrireAtomique, JOURNAL_MAX_OCTETS, lireLignes, serialiser } from "./donnees.mjs";
import { clientRpc } from "./reseau.mjs";
import { lireDossier } from "./dossier.mjs";
import { FinCommande, Sortie } from "./sortie.mjs";
import { ErreurReference, referenceDeTravail } from "./cles.mjs";
import { ConfirmationAbsente, confirmationsPour, messageConfirmationAbsente } from "./commandes/base.mjs";
import { empreinteFiche, nouvelleVersion } from "../commun/fiche-controle.mjs";
import { fraisInstance } from "../commun/frais.mjs";
import { preparer } from "./commandes/preparer.mjs";
import { inscrireClient } from "./commandes/inscrire-client.mjs";
import { approvisionner } from "./commandes/approvisionner.mjs";
import { condenseInscription, inscrireCle } from "./commandes/inscription-cle.mjs";
import { capturer } from "./commandes/capturer.mjs";
import { exporter, verifier } from "./commandes/exporter-verifier.mjs";
import { produirePaquet } from "./commandes/paquet.mjs";
import { administrerJeu, condenseAdministration } from "./commandes/administrer-jeu.mjs";
import { COMMANDE_OUTIL } from "../commun/travaux.mjs";
import * as R from "@noortrace/ancrage/registre";

/** Taille maximale d'une requête (INTERFACES.md 3.2). */
export const TAILLE_REQUETE_MAX = 65536;
/** Travaux en attente au plus (`file_pleine` au-delà). */
export const FILE_MAX = 64;
/** Durée d'inactivité au-delà de laquelle une connexion à la prise est fermée, admise ou non (relecture de l'étape 6, R6). */
export const DELAI_CONNEXION_MS = 10000;
/** Auxiliaires `python3` du compte du pair lancés à la fois, au plus ; les autres connexions attendent leur tour. */
export const AUXILIAIRES_MAX = 4;
/** Connexions simultanées à la prise, au plus (au-delà, le noyau les refuse). */
export const CONNEXIONS_MAX = 64;
/** Refus consignés ligne à ligne par période et par événement ; au-delà, comptés dans une ligne `refus_cumules` (revue de l'étape 8). */
export const REFUS_PAR_PERIODE = 8;
/** Période du comptage des refus. */
export const PERIODE_REFUS_MS = 60000;
/** Événements du journal que le compte de l'interface peut provoquer sans limite : consignés avec borne. */
export const EVENEMENTS_REFUS = Object.freeze(["pair_refuse", "requete_refusee", "requete_erreur", "travail_refuse", "confirmation_refusee", "note_refusee"]);

/** Auxiliaire `python3 -I` : compte du pair par `SO_PEERCRED` sur le descripteur 3, sans le lire, puis `detach()`. */
export const AUXILIAIRE_PAIR = [
  "import socket,struct,sys",
  "s=socket.socket(fileno=3)",
  "c=s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i'))",
  "s.detach()",
  "pid,uid,gid=struct.unpack('3i',c)",
  "sys.stdout.write('%d %d %d'%(pid,uid,gid))",
].join("\n");

const COMMANDES = {
  "inscrire-client-preparer": preparer,
  "inscrire-client": inscrireClient,
  approvisionner,
  "condense-inscription": condenseInscription,
  "inscrire-cle": inscrireCle,
  capturer,
  exporter,
  verifier,
  paquet: produirePaquet,
  "condense-administration": condenseAdministration,
  "administrer-jeu": administrerJeu,
};

/** Compte du pair d'une connexion : `{ pid, uid, gid }` ou null (auxiliaire en échec). */
export function comptePair(socket, { python = "python3", delaiMs = 5000 } = {}) {
  return new Promise((resolve) => {
    let fini = false;
    const finir = (v) => {
      if (!fini) {
        fini = true;
        resolve(v);
      }
    };
    let enfant;
    try {
      enfant = spawn(python, ["-I", "-c", AUXILIAIRE_PAIR], { stdio: ["ignore", "pipe", "pipe", socket] });
    } catch {
      finir(null);
      return;
    }
    let sortie = "";
    enfant.stdout.on("data", (d) => {
      sortie += d;
      if (sortie.length > 64) enfant.kill("SIGKILL");
    });
    enfant.stderr.on("data", () => {});
    const minuterie = setTimeout(() => {
      enfant.kill("SIGKILL");
      finir(null);
    }, delaiMs);
    enfant.on("error", () => {
      clearTimeout(minuterie);
      finir(null);
    });
    enfant.on("close", (code) => {
      clearTimeout(minuterie);
      const m = /^(\d+) (\d+) (\d+)$/.exec(sortie);
      finir(code === 0 && m ? { pid: Number(m[1]), uid: Number(m[2]), gid: Number(m[3]) } : null);
    });
  });
}

/**
 * Lit la configuration et l'instance, contrôle le démarrage ; rend `{ config,
 * instance, gid }` ou lève `ErreurConfiguration`. `memeCompteAdmis` (essais de
 * l'API programmatique seulement) lève le contrôle des comptes d'EX-7.23.
 */
export function preparerDemarrage(source, { racine = process.cwd(), controlerPrise = true, memeCompteAdmis = false } = {}) {
  const config = lireConfiguration(source);
  if (memeCompteAdmis !== true) controlerComptes(config);
  let instance;
  try {
    instance = chargerInstance(config.instance, { racine });
  } catch (e) {
    if (e instanceof ErreurInstance) throw new ErreurConfiguration(e.message);
    throw e;
  }
  if (instance.nature !== config.nature) throw new ErreurConfiguration(`nature ${config.nature} différente de celle de l'instance (${instance.nature})`);
  controlerReferences(config, instance);
  const gid = controlerPrise ? controlerRepertoires(config, { memeCompteAdmis }) : null;
  if (prisesIp().length > 0) throw new ErreurConfiguration("l'agent a une prise d'écoute AF_INET ou AF_INET6 (EX-7.28)");
  return { config, instance, gid };
}

/** Résout le jeton du nœud (`env:` ou `fichier:` lisible de son seul propriétaire) ; texte ASCII imprimable sans espace. */
function resoudreJeton(reference) {
  if (!reference) return null;
  const ref = lireReference("jeton", reference, { formes: ["env", "fichier"] });
  let texte;
  if (ref.forme === "env") texte = process.env[ref.valeur];
  else {
    const st = fs.statSync(ref.valeur);
    if ((st.mode & 0o077) !== 0 || st.uid !== process.getuid()) throw new ErreurConfiguration("jeton : fichier lisible par d'autres que son propriétaire");
    texte = fs.readFileSync(ref.valeur, "utf8");
  }
  texte = typeof texte === "string" ? texte.trim() : "";
  if (!/^[\x21-\x7e]{1,4096}$/.test(texte)) throw new ErreurConfiguration("jeton : texte ASCII imprimable sans espace attendu");
  return texte;
}

/** Références de clés d'un travail (forme et rôle, jamais de valeur). */
function referencesDuTravail(t) {
  const r = [];
  if (t.parametres.tresorerie) r.push({ reference: t.parametres.tresorerie, role: "tresorerie" });
  if (t.parametres.cle_chaine && t.commande === "inscrire-cle") r.push({ reference: t.parametres.cle_chaine, role: "cle_chaine" });
  if (t.parametres.expediteur && t.commande === "administrer-jeu") r.push({ reference: t.parametres.expediteur, role: "expediteur" });
  return r;
}

/**
 * Démarre l'agent. `source` : chemin de la configuration ou objet. Rend `{
 * prise, pid, arreter(), file, attendreFile() }`.
 */
export async function demarrerAgent(source, options = {}) {
  const racine = options.racine ?? process.cwd();
  const { config, instance: instanceDemarrage } = preparerDemarrage(source, { racine, controlerPrise: options.controlerPrise ?? true, memeCompteAdmis: options.memeCompteAdmis === true });
  const jeton = resoudreJeton(config.jeton);
  const D = chemins(config.donnees);
  const horloge = options.horloge ?? { murale: () => Date.now(), monotone: () => Number(process.hrtime.bigint() / 1000000n) };
  const attendre = options.attendre ?? ((ms) => new Promise((ok) => setTimeout(ok, ms)));
  // Journal borné : ajout seul, tourné à JOURNAL_MAX_OCTETS (une génération gardée, `.1`) ; les refus que le
  // compte de l'interface peut provoquer sans limite sont consignés ligne à ligne jusqu'à REFUS_PAR_PERIODE par période et
  // par événement, puis comptés dans une ligne `refus_cumules` écrite à la période suivante ou à l'arrêt.
  const ecrireLigne = (evenement, champs = {}) => ajouterLigne(D.journal, { instant: ecrireHorodatage(horloge.murale()), evenement, ...champs }, { tailleMax: JOURNAL_MAX_OCTETS });
  const compteursRefus = new Map();
  const viderCompteur = (evenement, c) => {
    if (c.comptees > 0) ecrireLigne("refus_cumules", { refus: evenement, periode_debut: ecrireHorodatage(c.debut), nombre: c.comptees });
    c.comptees = 0;
  };
  const consigner = (evenement, champs = {}) => {
    if (!EVENEMENTS_REFUS.includes(evenement)) return ecrireLigne(evenement, champs);
    const t = horloge.murale();
    let c = compteursRefus.get(evenement);
    if (!c || t - c.debut >= PERIODE_REFUS_MS) {
      if (c) viderCompteur(evenement, c);
      c = { debut: t, ecrites: 0, comptees: 0 };
      compteursRefus.set(evenement, c);
    }
    if (c.ecrites < REFUS_PAR_PERIODE) {
      c.ecrites += 1;
      return ecrireLigne(evenement, champs);
    }
    c.comptees += 1;
    return undefined;
  };
  creerRepertoire(D.travaux);
  creerRepertoire(D.clients);

  /**
   * Frais de l'instance appliqués (CT-4 EX-7.23, complément du 2026-11-25) : écrits dans les données au démarrage et à
   * chaque relecture du manifeste qui les change, pour que l'interface dise la durée que couvre un versement (EX-7.9).
   */
  let fraisEcrits = null;
  const ecrireFrais = (instance) => {
    const octets = serialiser(fraisInstance(instance));
    if (fraisEcrits !== null && fraisEcrits.equals(octets)) return;
    ecrireAtomique(D.frais, octets);
    fraisEcrits = octets;
  };
  ecrireFrais(instanceDemarrage);

  /**
   * La fiche de contrôle des adresses des approbateurs d'un client (CT-4 EX-7.8, complément du 2026-11-25) : son
   * empreinte, calculée depuis le dossier tel qu'il est et les noms des approbateurs notés ; et sa version, enregistrée
   * au registre des versions si cette empreinte n'y est pas encore (préparation du dossier, note de noms, et chaque
   * recalcul à l'admission d'un travail ou à la réception d'une confirmation). Rend `{ sha256, orgId }` ou null.
   */
  const ficheDuClient = (slug, { enregistrer = true } = {}) => {
    const l = lireDossier(D.client(slug).dossier);
    if (l.erreur) return null;
    const orgId = l.dossier.organisation.org_id;
    const sha256 = empreinteFiche(l.dossier, etatNotes(lireLignes(D.notes), orgId).nomsApprobateurs);
    if (enregistrer) {
      const ligne = nouvelleVersion(lireLignes(D.fiches), orgId, sha256, ecrireHorodatage(horloge.murale()));
      if (ligne) {
        ajouterLigne(D.fiches, ligne);
        consigner("fiche_controle_version", { org_id: orgId, version: ligne.version, fiche_sha256: sha256 });
      }
    }
    return { sha256, orgId };
  };
  const slugDe = (orgId) => (fs.existsSync(D.clients) ? fs.readdirSync(D.clients) : []).find((s) => {
    const l = lireDossier(D.client(s).dossier);
    return !l.erreur && l.dossier.organisation.org_id === orgId;
  }) ?? null;

  /**
   * Instance relue à l'admission et à l'exécution de chaque travail (le manifeste peut avoir été révisé) : elle doit
   * garder la nature de la configuration et les identifiants de l'instance du démarrage, sinon
   * `instance_illisible`. Lève `ErreurInstance`.
   */
  const instanceCourante = () => {
    const instance = chargerInstance(config.instance, { racine });
    if (instance.nature !== config.nature) throw new ErreurInstance(`nature ${instance.nature} de l'instance différente de celle de la configuration (${config.nature})`);
    if (instance.evmChainId !== instanceDemarrage.evmChainId || instance.bftChainId !== instanceDemarrage.bftChainId) {
      throw new ErreurInstance(`identifiants de l'instance (${instance.evmChainId}, ${instance.bftChainId}) différents de ceux du démarrage (${instanceDemarrage.evmChainId}, ${instanceDemarrage.bftChainId})`);
    }
    ecrireFrais(instance);
    return instance;
  };

  // Travaux laissés en cours ou en attente par un arrêt : abandonnés (le dossier dit l'état réel, EX-7.13).
  for (const nom of fs.readdirSync(D.travaux)) {
    if (!/^trv-[0-9a-f]{32}\.json$/.test(nom)) continue;
    try {
      const t = JSON.parse(fs.readFileSync(path.join(D.travaux, nom), "utf8"));
      if (t.etat === "en_cours" || t.etat === "en_attente") {
        t.etat = "abandonne";
        t.fin = ecrireHorodatage(horloge.murale());
        ecrireAtomique(path.join(D.travaux, nom), serialiser(t));
        consigner("travail_abandonne", { id: t.id, slug: t.slug, commande: t.commande });
      }
    } catch {
      // enregistrement illisible : laissé tel quel
    }
  }

  const file = [];
  let enCours = null;
  let arret = false;
  let reveil = null;
  const ecrireTravail = (t) => ecrireAtomique(D.travail(t.id), serialiser(t));

  /** Confirmations exigées par un travail (EX-7.26) : null si toutes sont inscrites, sinon le message. */
  const confirmationManquante = (t, instance) => {
    const client = D.client(t.slug);
    if (t.commande === "approvisionner") {
      const l = lireDossier(client.dossier);
      if (l.erreur) return null;
      const n = confirmationsPour({ donnees: D }, { operations: ["approvisionner"], orgId: l.dossier.organisation.org_id, cleChaine: t.parametres.cle_chaine });
      return n.length === 0 ? `confirmation hors bande absente pour l'approvisionnement de ${t.parametres.cle_chaine} (EX-7.26)` : null;
    }
    if (t.commande === "administrer-jeu") {
      const l = lireDossier(client.dossier);
      if (l.erreur) return null;
      const digest = typeof t.parametres.demande?.digest === "string" ? t.parametres.demande.digest.toLowerCase() : null;
      const n = digest ? confirmationsPour({ donnees: D }, { operations: ["administrer-jeu"], orgId: l.dossier.organisation.org_id, digest }) : [];
      return n.length === 0 ? `confirmation hors bande absente pour la demande d'administration du jeu ${digest ?? ""} (EX-7.26)` : null;
    }
    if (t.commande === "inscrire-client") {
      const l = lireDossier(client.dossier);
      if (l.erreur) return null;
      const orgId = l.dossier.organisation.org_id;
      // Complément du 2026-11-25 (EX-7.8) : avant que les adresses des approbateurs partent (étape `jeu_approbateurs` à faire
      // ou en échec), la fiche de contrôle du dossier tel qu'il est doit avoir été renvoyée confirmée par le client.
      const eJeu = l.dossier.steps.find((e) => e.step === "jeu_approbateurs");
      if (eJeu && (eJeu.state === "a_faire" || eJeu.state === "echec")) {
        const fiche = ficheDuClient(t.slug).sha256;
        const n = confirmationsPour({ donnees: D }, { operations: ["jeu_approbateurs"], orgId, ficheSha256: fiche });
        if (n.length === 0) return messageConfirmationAbsente({ orgId, ficheSha256: fiche });
      }
      for (const e of l.dossier.steps) {
        if (e.step !== "approvisionnement" || (e.state !== "a_faire" && e.state !== "echec")) continue;
        const n = confirmationsPour({ donnees: D }, { operations: ["approvisionnement"], orgId: l.dossier.organisation.org_id, cleChaine: e.subject });
        if (n.length === 0) return `confirmation hors bande absente pour l'approvisionnement de ${e.subject} (EX-7.26)`;
      }
    }
    void instance;
    return null;
  };

  /** Contrôles d'admission d'un travail : rend `{ travail }` ou `{ code, message }`. */
  const admettreTravail = (requete) => {
    let instance;
    try {
      instance = instanceCourante();
    } catch (e) {
      if (e instanceof ErreurInstance) return { code: "instance_illisible", message: e.message };
      throw e;
    }
    let t;
    try {
      lireIdentite(requete.exploitant);
      t = lireTravail(requete.travail, { production: instance.nature === "production" });
    } catch (e) {
      if (e instanceof ErreurChamp) return { code: e.code, message: e.message };
      throw e;
    }
    for (const r of referencesDuTravail(t)) {
      // CT-4 EX-7.25 : référence effective (fichier du répertoire de clés, alias de la configuration), message unique
      // vers l'interface, détail au journal ; puis EX-7.3 sur la forme effective.
      let effective;
      try {
        effective = referenceDeTravail(r.role, r.reference, config.cles);
      } catch (e) {
        if (!(e instanceof ErreurReference)) throw e;
        consigner("reference_non_resolue", { id: null, slug: t.slug, role: r.role, forme: String(r.reference).split(":")[0], detail: String(e.detail ?? e.message).slice(0, 300) });
        return { code: "reference_refusee", message: e.message };
      }
      const motif = motifRefusReference({ forme: effective.forme }, { role: r.role, nature: instance.nature, evmChainId: instance.evmChainId });
      if (motif) return { code: "reference_refusee", message: `${r.role} : référence ${effective.forme}: refusée pour une instance de nature ${instance.nature} d'identifiant EVM ${instance.evmChainId} (EX-7.3)` };
    }
    if (t.parametres.cles_essai && !(instance.nature === "developpement" && [2124, 31337].includes(instance.evmChainId))) {
      return { code: "reference_refusee", message: "clés d'essai refusées hors des réseaux 2124 et 31337 (EX-7.3)" };
    }
    if (t.commande !== "inscrire-client-preparer" && !fs.existsSync(D.client(t.slug).dossier)) return { code: "client_inconnu", message: `aucun dossier pour le client ${t.slug}` };
    const manque = confirmationManquante(t, instance);
    if (manque) return { code: "confirmation_absente", message: manque };
    if (file.length >= FILE_MAX) return { code: "file_pleine", message: `plus de ${FILE_MAX} travaux en attente` };
    return { travail: t, references: referencesDuTravail(t) };
  };

  /**
   * Contrôles d'une note interne (CT-4 EX-7.23, complément du 2026-11-19) : rend null (admise) ou `{ code, message }`.
   * Le client est celui de l'organisation de la note ; une remise nomme un paquet que l'agent a produit pour lui et
   * qu'aucune remise en vigueur ne nomme déjà ; une correction vise une remise de ce client, non encore corrigée.
   */
  const admettreNote = (n) => {
    const slug = slugDe(n.org_id);
    if (!slug) return { code: "client_inconnu", message: `aucun client d'org_id ${n.org_id}` };
    if (n.sorte === "nom_interne") return null;
    if (n.sorte === "noms_approbateurs") {
      // Décisions du 2026-11-25 (CT-4 EX-7.8) : une adresse du dossier, tant que les approbateurs ne sont pas enregistrés.
      const l = lireDossier(D.client(slug).dossier);
      if (l.erreur) return { code: "client_inconnu", message: `dossier illisible pour le client ${slug}` };
      const eJeu = l.dossier.steps.find((e) => e.step === "jeu_approbateurs");
      if (eJeu && eJeu.state !== "a_faire" && eJeu.state !== "echec") return { code: "fiche_figee", message: "les approbateurs sont enregistrés sur le registre public : leurs noms sur la fiche de contrôle ne changent plus" };
      for (const x of n.noms) if (!l.dossier.approvers.members.includes(x.adresse)) return { code: "requete_invalide", message: "adresse hors des approbateurs du dossier" };
      return null;
    }
    const etat = etatNotes(lireLignes(D.notes), n.org_id);
    if (n.sorte === "remise_paquet") {
      const base = D.client(slug).paquets;
      const produits = (fs.existsSync(base) ? fs.readdirSync(base) : []).filter((x) => /^[1-9][0-9]*$/.test(x)).map((x) => {
        try {
          return sha256Hex(fs.readFileSync(path.join(base, x, nomPaquet(slug), MANIFESTE_PAQUET)));
        } catch {
          return null;
        }
      });
      if (!produits.includes(n.manifest_sha256)) return { code: "paquet_inconnu", message: `aucun paquet de manifeste ${n.manifest_sha256} produit pour le client ${slug}` };
      const r = remiseEnVigueur(etat, n.manifest_sha256);
      if (r) return { code: "remise_deja_notee", message: `remise de ce paquet déjà notée (${r.id}) ; une erreur se corrige par une note de correction` };
      return null;
    }
    if (!etat.remises.some((r) => r.id === n.remise && r.correction === null)) return { code: "remise_inconnue", message: `aucune remise ${n.remise} non corrigée pour ce client` };
    return null;
  };

  /** Exécute un travail de la file : `element` = `{ enreg, travail }` ; l'enregistrement ne porte jamais les paramètres. */
  const executer = async ({ enreg: t, travail: commande }) => {
    t.etat = "en_cours";
    t.debut = ecrireHorodatage(horloge.murale());
    ecrireTravail(t);
    consigner("travail_debut", { id: t.id, commande: t.commande, slug: t.slug, exploitant: t.exploitant });
    let instance;
    try {
      instance = instanceCourante();
    } catch (e) {
      if (!(e instanceof ErreurInstance)) throw e;
      instance = null;
      t.sortie = COMMANDE_OUTIL[t.commande] ? new Sortie(COMMANDE_OUTIL[t.commande]).rendre("inutilisable", { error: { code: "instance_illisible", check: null, message: String(e.message).slice(0, 2048) } }) : null;
    }
    if (instance) {
      const manque = confirmationManquante(commande, instance);
      if (manque) {
        t.etat = "refuse";
        t.motif = { code: "confirmation_absente", message: manque };
        t.fin = ecrireHorodatage(horloge.murale());
        ecrireTravail(t);
        consigner("travail_refuse", { id: t.id, code: "confirmation_absente" });
        return;
      }
      const ctx = {
        config, instance, jeton, horloge, attendre, racine, consigner,
        rpc: clientRpc(config.rpc, { jeton, transport: options.transport ?? null }),
        delaiMs: config.delai_s * 1000,
        donnees: D, slug: commande.slug, client: D.client(commande.slug), captures: D.client(commande.slug).captures,
        exploitant: t.exploitant, travailId: t.id,
      };
      try {
        t.sortie = await COMMANDES[commande.commande](ctx, commande);
      } catch (e) {
        if (e instanceof ConfirmationAbsente) {
          // Aucune sortie, rien n'est envoyé (EX-7.26) ; un versement précédent du même travail a pu partir.
          t.etat = "refuse";
          t.motif = { code: "confirmation_absente", message: e.message };
          t.sortie = null;
          t.fin = ecrireHorodatage(horloge.murale());
          ecrireTravail(t);
          consigner("travail_refuse", { id: t.id, code: "confirmation_absente" });
          return;
        }
        const s = ctx.sortieCourante ?? new Sortie(COMMANDE_OUTIL[commande.commande] ?? "etat");
        if (e instanceof FinCommande) t.sortie = e.sortie ?? s.depuisFin(e);
        else if (e instanceof R.ErreurRpc || e instanceof R.ErreurLecture) {
          consigner("travail_erreur_noeud", { id: t.id, code: e.code ?? null, message: String(e.message).slice(0, 300), pile: String(e.stack ?? "").split("\n").slice(1, 6).map((l) => l.trim()) });
          t.sortie = s.rendre("inutilisable", { error: { code: "noeud_injoignable", check: null, message: String(e.message).slice(0, 2048) } });
        }
        else {
          consigner("travail_erreur_interne", { id: t.id, message: String(e?.message ?? e).slice(0, 512) });
          t.sortie = s.rendre("inutilisable", { error: { code: "usage", check: null, message: `erreur interne de l'agent : ${String(e?.message ?? e).slice(0, 1024)}` } });
        }
      }
    }
    t.etat = "fini";
    t.fin = ecrireHorodatage(horloge.murale());
    if (t.sortie) ecrireAtomique(path.join(D.client(commande.slug).sorties, `${t.id}.json`), serialiser(t.sortie));
    // Le dossier préparé : la première version de sa fiche de contrôle est enregistrée (complément du 2026-11-25).
    if (commande.commande === "inscrire-client-preparer" && t.sortie?.result === "reussi") ficheDuClient(commande.slug);
    ecrireTravail(t);
    consigner("travail_fin", { id: t.id, commande: t.commande, slug: t.slug, result: t.sortie?.result ?? null, exit_code: t.sortie?.exit_code ?? null });
  };

  const boucle = async () => {
    for (;;) {
      if (arret) return;
      const element = file.shift();
      if (!element) {
        await new Promise((ok) => {
          reveil = ok;
        });
        reveil = null;
        continue;
      }
      enCours = element;
      try {
        await executer(element);
      } finally {
        enCours = null;
      }
    }
  };

  const repondre = (socket, objet) => {
    socket.end(JSON.stringify(objet) + "\n");
  };

  const traiter = (socket, ligne) => {
    let requete;
    try {
      requete = lireJsonStrict(Buffer.from(ligne, "utf8"));
    } catch {
      return repondre(socket, { accepte: false, code: "requete_invalide", message: "JSON strict attendu" });
    }
    if (!requete || typeof requete !== "object" || Array.isArray(requete) || requete.version !== 0) return repondre(socket, { accepte: false, code: "requete_invalide", message: "version 0 attendue" });
    if (requete.kind === "travail") {
      const cles = Object.keys(requete);
      if (cles.some((k) => !["version", "kind", "exploitant", "travail"].includes(k))) return repondre(socket, { accepte: false, code: "requete_invalide", message: "membre inconnu" });
      const a = admettreTravail(requete);
      if (!a.travail) {
        consigner("travail_refuse", { exploitant: typeof requete.exploitant === "string" ? requete.exploitant.slice(0, 300) : null, code: a.code });
        return repondre(socket, { accepte: false, code: a.code, message: a.message });
      }
      const id = `trv-${crypto.randomBytes(16).toString("hex")}`;
      const enreg = { id, commande: a.travail.commande, slug: a.travail.slug, exploitant: requete.exploitant, recu_a: ecrireHorodatage(horloge.murale()), etat: "en_attente", debut: null, fin: null, sortie: null };
      ecrireTravail(enreg);
      consigner("travail_recu", { id, commande: enreg.commande, slug: enreg.slug, exploitant: enreg.exploitant, references: a.references });
      file.push({ enreg, travail: a.travail });
      if (reveil) reveil();
      return repondre(socket, { accepte: true, id });
    }
    if (requete.kind === "confirmation") {
      const cles = Object.keys(requete);
      if (cles.some((k) => !["version", "kind", "exploitant", "confirmation"].includes(k))) return repondre(socket, { accepte: false, code: "requete_invalide", message: "membre inconnu" });
      let c;
      try {
        lireIdentite(requete.exploitant);
        c = lireConfirmation(requete.confirmation);
      } catch (e) {
        if (e instanceof ErreurChamp) return repondre(socket, { accepte: false, code: e.code, message: e.message });
        throw e;
      }
      const clients = fs.existsSync(D.clients) ? fs.readdirSync(D.clients) : [];
      const connu = clients.some((slug) => {
        const l = lireDossier(D.client(slug).dossier);
        return !l.erreur && l.dossier.organisation.org_id === c.objet.org_id;
      });
      if (!connu) {
        consigner("confirmation_refusee", { exploitant: requete.exploitant, code: "client_inconnu" });
        return repondre(socket, { accepte: false, code: "client_inconnu", message: `aucun client d'org_id ${c.objet.org_id}` });
      }
      // La confirmation de la fiche cite une version ; la fiche courante est recalculée et enregistrée si elle est nouvelle.
      if (c.operation === "jeu_approbateurs") ficheDuClient(slugDe(c.objet.org_id));
      const id = `cnf-${crypto.randomBytes(16).toString("hex")}`;
      ajouterLigne(D.confirmations, { id, ...c, exploitant: requete.exploitant, recu_a: ecrireHorodatage(horloge.murale()) });
      consigner("confirmation_recue", { id, operation: c.operation, org_id: c.objet.org_id, cle_chaine: c.objet.cle_chaine, fiche_sha256: c.objet.fiche_sha256, exploitant: requete.exploitant });
      return repondre(socket, { accepte: true, id });
    }
    if (requete.kind === "note") {
      const cles = Object.keys(requete);
      if (cles.some((k) => !["version", "kind", "exploitant", "note"].includes(k))) return repondre(socket, { accepte: false, code: "requete_invalide", message: "membre inconnu" });
      let n;
      try {
        lireIdentite(requete.exploitant);
        n = lireNote(requete.note);
      } catch (e) {
        if (e instanceof ErreurChamp) return repondre(socket, { accepte: false, code: e.code, message: e.message });
        throw e;
      }
      const a = admettreNote(n);
      if (a) {
        consigner("note_refusee", { exploitant: requete.exploitant, sorte: n.sorte, code: a.code });
        return repondre(socket, { accepte: false, code: a.code, message: a.message });
      }
      const id = `not-${crypto.randomBytes(16).toString("hex")}`;
      ajouterLigne(D.notes, { id, ...n, exploitant: requete.exploitant, recu_a: ecrireHorodatage(horloge.murale()) });
      // Le journal ne garde ni le nom interne ni le motif d'une correction (CT-4 EX-7.23, complément du 2026-11-19).
      consigner("note_recue", { id, sorte: n.sorte, org_id: n.org_id, exploitant: requete.exploitant });
      // Des noms changés : une fiche de contrôle nouvelle, enregistrée au registre des versions (complément du 2026-11-25).
      if (n.sorte === "noms_approbateurs") ficheDuClient(slugDe(n.org_id));
      return repondre(socket, { accepte: true, id });
    }
    return repondre(socket, { accepte: false, code: "requete_invalide", message: "kind travail, confirmation ou note attendu" });
  };

  // Auxiliaires du compte du pair : au plus AUXILIAIRES_MAX à la fois, les connexions suivantes attendent leur tour.
  let auxiliaires = 0;
  const enAttenteAuxiliaire = [];
  const prendreAuxiliaire = () => new Promise((ok) => {
    if (auxiliaires < AUXILIAIRES_MAX) {
      auxiliaires += 1;
      ok();
    } else enAttenteAuxiliaire.push(ok);
  });
  const rendreAuxiliaire = () => {
    const suivant = enAttenteAuxiliaire.shift();
    if (suivant) suivant();
    else auxiliaires -= 1;
  };

  const serveur = net.createServer({ pauseOnConnect: true }, async (socket) => {
    socket.on("error", () => {});
    // Délai sur toute connexion, dès l'acceptation (aucun octet lu) : une connexion muette ou une ligne jamais finie
    // ne garde ni descripteur ni attente de l'agent (relecture de l'étape 6, R6).
    socket.setTimeout(DELAI_CONNEXION_MS, () => socket.destroy());
    await prendreAuxiliaire();
    let pair;
    try {
      if (socket.destroyed) return;
      pair = await comptePair(socket, { python: options.python ?? "python3" });
    } finally {
      rendreAuxiliaire();
    }
    if (socket.destroyed) return;
    if (!pair || pair.uid !== config.interface_uid) {
      consigner("pair_refuse", { uid: pair?.uid ?? null, pid: pair?.pid ?? null, octets_lus: socket.bytesRead });
      socket.destroy();
      return;
    }
    socket.resume();
    let tampon = Buffer.alloc(0);
    socket.on("data", (d) => {
      if (socket.destroyed || socket.writableEnded) return;
      tampon = Buffer.concat([tampon, d]);
      const fin = tampon.indexOf(0x0a);
      if (fin < 0) {
        if (tampon.length > TAILLE_REQUETE_MAX) {
          consigner("requete_refusee", { motif: "taille", uid: pair.uid });
          repondre(socket, { accepte: false, code: "requete_invalide", message: `requête au-delà de ${TAILLE_REQUETE_MAX} octets` });
          socket.pause();
        }
        return;
      }
      if (fin > TAILLE_REQUETE_MAX) {
        consigner("requete_refusee", { motif: "taille", uid: pair.uid });
        return repondre(socket, { accepte: false, code: "requete_invalide", message: `requête au-delà de ${TAILLE_REQUETE_MAX} octets` });
      }
      socket.pause();
      try {
        traiter(socket, tampon.subarray(0, fin).toString("utf8"));
      } catch (e) {
        consigner("requete_erreur", { message: String(e?.message ?? e).slice(0, 300) });
        repondre(socket, { accepte: false, code: "requete_invalide", message: "requête non traitée" });
      }
    });
  });

  // Prise : ancienne prise supprimée (jamais un autre type de fichier), écoute, mode 0660, groupe du répertoire.
  try {
    const st = fs.lstatSync(config.prise);
    if (!st.isSocket()) throw new ErreurConfiguration(`${config.prise} existe et n'est pas une prise`);
    fs.unlinkSync(config.prise);
  } catch (e) {
    if (e instanceof ErreurConfiguration) throw e;
  }
  serveur.maxConnections = CONNEXIONS_MAX;
  await new Promise((ok, ko) => {
    serveur.once("error", ko);
    serveur.listen(config.prise, ok);
  });
  fs.chmodSync(config.prise, 0o660);
  const gidRepertoire = fs.statSync(path.dirname(config.prise)).gid;
  if (fs.statSync(config.prise).gid !== gidRepertoire) {
    try {
      fs.chownSync(config.prise, -1, gidRepertoire);
    } catch {
      serveur.close();
      throw new ErreurConfiguration("la prise ne peut pas prendre le groupe de son répertoire (bit setgid du répertoire, EX-7.28)");
    }
  }
  if (prisesIp().length > 0) {
    serveur.close();
    throw new ErreurConfiguration("l'agent a une prise d'écoute AF_INET ou AF_INET6 (EX-7.28)");
  }
  consigner("demarrage", { pid: process.pid, prise: config.prise, nature: instanceDemarrage.nature, evm_chain_id: instanceDemarrage.evmChainId });
  const tache = boucle();

  return {
    prise: config.prise,
    pid: process.pid,
    file,
    /** Attend que la file soit vide et qu'aucun travail ne soit en cours. */
    async attendreFile() {
      while (file.length > 0 || enCours) await new Promise((ok) => setTimeout(ok, 50));
    },
    /** Arrête l'agent après le travail en cours ; les travaux en attente sont abandonnés. */
    async arreter() {
      arret = true;
      await new Promise((ok) => serveur.close(() => ok()));
      if (reveil) reveil();
      while (enCours) await new Promise((ok) => setTimeout(ok, 50));
      for (const { enreg: t } of file.splice(0)) {
        t.etat = "abandonne";
        t.fin = ecrireHorodatage(horloge.murale());
        ecrireTravail(t);
      }
      await tache;
      for (const [evenement, c] of compteursRefus) viderCompteur(evenement, c);
      consigner("arret", { pid: process.pid });
    },
  };
}

export { ErreurConfiguration };
