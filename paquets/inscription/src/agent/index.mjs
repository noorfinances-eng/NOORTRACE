// Agent d'inscription (CT-4 EX-7.23, EX-7.28 ; INTERFACES.md 3) : processus
// séparé et privilégié, seul à résoudre les références de clés et le jeton,
// à signer et envoyer, à écrire les envois, les captures et le dossier. Il
// n'écoute qu'une prise `AF_UNIX` ; à chaque connexion, avant de lire aucun
// octet, il obtient du noyau le compte du pair (`SO_PEERCRED`, par un
// auxiliaire `python3 -I` à qui le descripteur est passé sans être lu) et
// ferme la connexion d'un autre compte que celui de l'interface, en
// consignant le refus. Une requête par connexion, un objet JSON strict sur
// une ligne d'au plus 65 536 octets ; seules la remise d'un travail et celle
// d'une confirmation passent : l'état se lit dans les fichiers (3.6). La file
// est unique et ordonnée, un travail à la fois ; l'agent refait chaque
// vérification avant d'écrire et ne croit pas l'interface.
//
// API programmatique (LISEZMOI.md) : `demarrerAgent(configuration, options)`
// rend `{ prise, pid, arreter(), file }` ; `options.horloge`,
// `options.attendre`, `options.racine` servent aux essais.

import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import { lireJsonStrict } from "@noortrace/approbation";
import { ecrireHorodatage } from "@noortrace/noyau";
import { ErreurChamp } from "../commun/champs.mjs";
import { lireReference, motifRefusReference } from "../commun/references.mjs";
import { lireConfirmation, lireIdentite, lireTravail } from "../commun/travaux.mjs";
import { controlerReferences, controlerRepertoires, ErreurConfiguration, lireConfiguration, prisesIp } from "./configuration.mjs";
import { chargerInstance, ErreurInstance } from "./instance.mjs";
import { ajouterLigne, chemins, creerRepertoire, ecrireAtomique, serialiser } from "./donnees.mjs";
import { clientRpc } from "./reseau.mjs";
import { lireDossier } from "./dossier.mjs";
import { FinCommande, Sortie } from "./sortie.mjs";
import { ConfirmationAbsente, confirmationsPour } from "./commandes/base.mjs";
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

/** Lit la configuration et l'instance, contrôle le démarrage ; rend `{ config, instance, gid }` ou lève `ErreurConfiguration`. */
export function preparerDemarrage(source, { racine = process.cwd(), controlerPrise = true } = {}) {
  const config = lireConfiguration(source);
  let instance;
  try {
    instance = chargerInstance(config.instance, { racine });
  } catch (e) {
    if (e instanceof ErreurInstance) throw new ErreurConfiguration(e.message);
    throw e;
  }
  if (instance.nature !== config.nature) throw new ErreurConfiguration(`nature ${config.nature} différente de celle de l'instance (${instance.nature})`);
  controlerReferences(config, instance);
  const gid = controlerPrise ? controlerRepertoires(config) : null;
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
  const { config, instance: instanceDemarrage } = preparerDemarrage(source, { racine, controlerPrise: options.controlerPrise ?? true });
  const jeton = resoudreJeton(config.jeton);
  const D = chemins(config.donnees);
  const horloge = options.horloge ?? { murale: () => Date.now(), monotone: () => Number(process.hrtime.bigint() / 1000000n) };
  const attendre = options.attendre ?? ((ms) => new Promise((ok) => setTimeout(ok, ms)));
  const consigner = (evenement, champs = {}) => ajouterLigne(D.journal, { instant: ecrireHorodatage(horloge.murale()), evenement, ...champs });
  creerRepertoire(D.travaux);
  creerRepertoire(D.clients);

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
    const instance = chargerInstance(config.instance, { racine });
    let t;
    try {
      lireIdentite(requete.exploitant);
      t = lireTravail(requete.travail, { production: instance.nature === "production" });
    } catch (e) {
      if (e instanceof ErreurChamp) return { code: e.code, message: e.message };
      throw e;
    }
    for (const r of referencesDuTravail(t)) {
      const ref = lireReference(r.role, r.reference);
      const motif = motifRefusReference(ref, { role: r.role, nature: instance.nature, evmChainId: instance.evmChainId });
      if (motif) return { code: "reference_refusee", message: `${r.role} : référence ${ref.forme}: refusée pour une instance de nature ${instance.nature} d'identifiant EVM ${instance.evmChainId} (EX-7.3)` };
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

  /** Exécute un travail de la file : `element` = `{ enreg, travail }` ; l'enregistrement ne porte jamais les paramètres. */
  const executer = async ({ enreg: t, travail: commande }) => {
    t.etat = "en_cours";
    t.debut = ecrireHorodatage(horloge.murale());
    ecrireTravail(t);
    consigner("travail_debut", { id: t.id, commande: t.commande, slug: t.slug, exploitant: t.exploitant });
    let instance;
    try {
      instance = chargerInstance(config.instance, { racine });
    } catch (e) {
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
      if (!connu) return repondre(socket, { accepte: false, code: "client_inconnu", message: `aucun client d'org_id ${c.objet.org_id}` });
      const id = `cnf-${crypto.randomBytes(16).toString("hex")}`;
      ajouterLigne(D.confirmations, { id, ...c, exploitant: requete.exploitant, recu_a: ecrireHorodatage(horloge.murale()) });
      consigner("confirmation_recue", { id, operation: c.operation, org_id: c.objet.org_id, cle_chaine: c.objet.cle_chaine, exploitant: requete.exploitant });
      return repondre(socket, { accepte: true, id });
    }
    return repondre(socket, { accepte: false, code: "requete_invalide", message: "kind travail ou confirmation attendu" });
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
      consigner("arret", { pid: process.pid });
    },
  };
}

export { ErreurConfiguration };
